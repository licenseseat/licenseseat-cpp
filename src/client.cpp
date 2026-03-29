#include "licenseseat/licenseseat.hpp"
#include "licenseseat/crypto.hpp"
#include "licenseseat/device.hpp"
#include "licenseseat/events.hpp"
#include "licenseseat/http.hpp"
#include "licenseseat/json.hpp"
#include "licenseseat/storage.hpp"
#include "licenseseat/telemetry.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>

namespace licenseseat {

// PIMPL implementation
class Client::Impl {
  public:
    explicit Impl(Config config) : config_(std::move(config)) {
        // Auto-generate device ID if not provided
        if (config_.device_id.empty()) {
            device_id_auto_generated_ = true;
            device_id_ = device::generate_device_id();
            if (device_id_.empty()) {
                device_id_ = "unknown-device";
            }
        } else {
            device_id_ = config_.device_id;
        }

        // Initialize HTTP client
        http::HttpClient::Config http_config;
        http_config.base_url = config_.api_url;
        http_config.api_key = config_.api_key;
        http_config.timeout_seconds = config_.timeout_seconds;
        http_config.verify_ssl = config_.verify_ssl;
        http_config.max_retries = config_.max_retries;
        http_config.retry_interval_ms = config_.retry_interval_ms;

        http_client_ = std::make_unique<http::HttpClient>(std::move(http_config));

        // Initialize storage
        if (!config_.storage_path.empty()) {
            storage_ = std::make_unique<FileStorage>(config_.storage_path, config_.storage_prefix);

            // Load cached license
            auto cached = storage_->get_license();
            if (cached) {
                cached_license_ = cached->license_data;
                cached_validation_ = cached->validation;
                event_bus_.emit(events::LICENSE_LOADED, *cached);
            }
        } else {
            storage_ = std::make_unique<MemoryStorage>();
        }
    }

    ~Impl() {
        stop_heartbeat();
        stop_auto_validation();
        stop_network_recheck();
        stop_offline_refresh();

        // Wait for all pending async operations to complete
        wait_for_pending_futures();
    }

    struct LicenseRequestContext {
        bool ok = false;
        ErrorCode error_code = ErrorCode::Unknown;
        std::string error_message;
        std::string product_slug;
        std::string fingerprint;
        bool has_cached_license = false;
        bool was_online = true;
    };

    std::string resolve_fingerprint_unlocked(const std::string& fingerprint_override) const {
        return fingerprint_override.empty() ? device_id_ : fingerprint_override;
    }

    LicenseRequestContext prepare_license_request_context(
        const std::string& license_key, const std::string& fingerprint_override,
        bool require_fingerprint = false, bool capture_validation_state = false,
        bool fallback_to_client_fingerprint = true,
        const char* missing_fingerprint_message = "Fingerprint is required") {
        LicenseRequestContext context;
        std::lock_guard<std::mutex> lock(mutex_);

        if (license_key.empty()) {
            context.error_code = ErrorCode::InvalidLicenseKey;
            context.error_message = "License key cannot be empty";
            return context;
        }

        if (config_.product_slug.empty()) {
            context.error_code = ErrorCode::MissingParameter;
            context.error_message = "Product slug is required in config";
            return context;
        }

        context.product_slug = config_.product_slug;
        context.fingerprint = fallback_to_client_fingerprint
                                  ? resolve_fingerprint_unlocked(fingerprint_override)
                                  : fingerprint_override;

        if (require_fingerprint && context.fingerprint.empty()) {
            context.error_code = ErrorCode::MissingParameter;
            context.error_message = missing_fingerprint_message;
            return context;
        }

        if (capture_validation_state) {
            context.has_cached_license = cached_license_.has_value();
            context.was_online = is_online_;
        }

        context.ok = true;
        return context;
    }

    template <typename T>
    Result<T> request_context_error(const LicenseRequestContext& context) const {
        return Result<T>::error(context.error_code, context.error_message);
    }

    // ========== Synchronous API ==========

    Result<ValidationResult> validate(const std::string& license_key,
                                      const std::string& device_id_param) {
        auto request = prepare_license_request_context(license_key, device_id_param, false, true);
        if (!request.ok) {
            return request_context_error<ValidationResult>(request);
        }

        event_bus_.emit(events::VALIDATION_START,
                        std::map<std::string, std::string>{{"license_key", license_key}});

        // Make HTTP call without holding mutex
        auto body = json::build_validate_request(request.fingerprint);
        auto response = send_post(
            "/products/" + request.product_slug + "/licenses/" + license_key + "/validate", body);

        if (!response.success) {
            // Check for authentication failure (401) - emit auth-failed event (matches Swift SDK)
            if (response.status_code == 401 || response.status_code == 501) {
                auto err = handle_error_response<ValidationResult>(response);
                ValidationResult failed_validation;
                failed_validation.valid = false;
                failed_validation.offline = false;
                failed_validation.message = err.error_message();
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    cached_validation_ = failed_validation;
                }
                event_bus_.emit(events::VALIDATION_AUTH_FAILED,
                                std::map<std::string, std::string>{
                                    {"licenseKey", license_key},
                                    {"error", err.error_message()},
                                    {"cached", request.has_cached_license ? "true" : "false"}});
                event_bus_.emit(events::VALIDATION_ERROR,
                                std::map<std::string, std::string>{{"error", err.error_message()}});
                return err;
            }

            // Check if this is a revocation (4xx error except 401/429)
            if (is_revocation_error(response)) {
                purge_cache_on_revocation();
                auto err = handle_error_response<ValidationResult>(response);
                event_bus_.emit(events::LICENSE_REVOKED,
                                std::map<std::string, std::string>{{"reason", err.error_message()}});
                return err;
            }

            // Check if we should fallback to offline
            if (should_fallback_to_offline(response)) {
                auto offline_result = verify_cached_offline();
                if (offline_result.is_ok() && offline_result.value().valid) {
                    // Update cached state so get_client_status() returns OfflineValid
                    bool should_emit_network_offline = false;
                    {
                        std::lock_guard<std::mutex> lock(mutex_);
                        cached_validation_ = offline_result.value();
                        is_online_ = false;
                        should_emit_network_offline = request.was_online;
                    }
                    if (should_emit_network_offline) {
                        event_bus_.emit(events::NETWORK_OFFLINE,
                                        std::map<std::string, std::string>{});
                    }
                    event_bus_.emit(events::VALIDATION_OFFLINE_SUCCESS, offline_result.value());

                    // Start network recheck to auto-reconnect when server is back
                    if (should_emit_network_offline) {
                        start_network_recheck();
                    }

                    return offline_result;
                } else if (offline_result.is_ok()) {
                    // Emit offline-failed event (matches Swift SDK)
                    event_bus_.emit(events::VALIDATION_OFFLINE_FAILED, offline_result.value());
                }
            }

            if (response.error_message.empty()) {
                auto err = handle_error_response<ValidationResult>(response);
                ValidationResult failed_validation;
                failed_validation.valid = false;
                failed_validation.offline = false;
                failed_validation.message = err.error_message();
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    cached_validation_ = failed_validation;
                }
                event_bus_.emit(events::VALIDATION_ERROR,
                                std::map<std::string, std::string>{{"error", err.error_message()}});
                return err;
            }

            ValidationResult failed_validation;
            failed_validation.valid = false;
            failed_validation.offline = true;
            failed_validation.message = response.error_message;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                cached_validation_ = failed_validation;
                is_online_ = false;
            }
            if (request.was_online) {
                event_bus_.emit(events::NETWORK_OFFLINE, std::map<std::string, std::string>{});
            }
            return Result<ValidationResult>::error(ErrorCode::NetworkError, response.error_message);
        }

        // Success - update state with mutex
        {
            std::lock_guard<std::mutex> lock(mutex_);
            is_online_ = true;
        }

        // Parse response
        try {
            auto j = nlohmann::json::parse(response.body);
            auto result = json::parse_validation_result(j);

            // Check for revocation (valid: false with code: "revoked" or "suspended")
            if (!result.valid && is_revocation_code(result.code)) {
                purge_cache_on_revocation();
                event_bus_.emit(events::LICENSE_REVOKED,
                                std::map<std::string, std::string>{{"code", result.code},
                                                                    {"message", result.message}});
            }

            // Cache the result
            {
                std::lock_guard<std::mutex> lock(mutex_);
                cached_validation_ = result;
                if (result.valid || !is_revocation_code(result.code)) {
                    if (!result.license.key().empty()) {
                        cached_license_ = result.license;
                    }
                }
            }

            if (result.valid) {
                update_storage_license(license_key, request.fingerprint, result);
                event_bus_.emit(events::VALIDATION_SUCCESS, result);
            } else {
                event_bus_.emit(events::VALIDATION_FAILED, result);
            }

            return Result<ValidationResult>::ok(std::move(result));
        } catch (const nlohmann::json::exception& e) {
            return Result<ValidationResult>::error(
                ErrorCode::ParseError, std::string("Failed to parse response: ") + e.what());
        }
    }

    Result<Activation> activate(const std::string& license_key,
                                const std::string& device_id_param,
                                const std::string& device_name,
                                const Metadata& metadata) {
        auto request = prepare_license_request_context(
            license_key, device_id_param, true, false, true, "Device ID is required");
        if (!request.ok) {
            return request_context_error<Activation>(request);
        }

        event_bus_.emit(events::ACTIVATION_START,
                        std::map<std::string, std::string>{{"license_key", license_key},
                                                           {"device_id", request.fingerprint}});

        // Make HTTP call without holding mutex
        auto body = json::build_activate_request(request.fingerprint, device_name, metadata);
        auto response = send_post(
            "/products/" + request.product_slug + "/licenses/" + license_key + "/activate", body);

        if (!response.success) {
            if (response.error_message.empty()) {
                auto err = handle_error_response<Activation>(response);
                event_bus_.emit(events::ACTIVATION_ERROR,
                                std::map<std::string, std::string>{{"error", err.error_message()}});
                return err;
            }
            return Result<Activation>::error(ErrorCode::NetworkError, response.error_message);
        }

        // Parse response
        try {
            auto j = nlohmann::json::parse(response.body);
            auto activation = json::parse_activation(j);

            // Update state with mutex
            {
                std::lock_guard<std::mutex> lock(mutex_);
                current_activation_ = activation;
            }

            event_bus_.emit(events::ACTIVATION_SUCCESS, activation);

            // Sync offline assets AFTER releasing the lock to avoid deadlock
            sync_offline_assets_impl(license_key, request.fingerprint);

            return Result<Activation>::ok(std::move(activation));
        } catch (const nlohmann::json::exception& e) {
            return Result<Activation>::error(ErrorCode::ParseError,
                                             std::string("Failed to parse response: ") + e.what());
        }
    }

    Result<Deactivation> deactivate(const std::string& license_key,
                                    const std::string& device_id) {
        auto request = prepare_license_request_context(
            license_key, device_id, true, false, false, "Device ID is required");
        if (!request.ok) {
            return request_context_error<Deactivation>(request);
        }

        event_bus_.emit(events::DEACTIVATION_START,
                        std::map<std::string, std::string>{{"license_key", license_key}});

        // Make HTTP call without holding mutex
        auto body = json::build_deactivate_request(request.fingerprint);
        auto response = send_post(
            "/products/" + request.product_slug + "/licenses/" + license_key + "/deactivate", body);

        if (!response.success) {
            if (response.error_message.empty()) {
                auto err = handle_error_response<Deactivation>(response);
                event_bus_.emit(events::DEACTIVATION_ERROR,
                                std::map<std::string, std::string>{{"error", err.error_message()}});
                return err;
            }
            return Result<Deactivation>::error(ErrorCode::NetworkError, response.error_message);
        }

        // Parse response
        try {
            auto j = nlohmann::json::parse(response.body);
            auto deactivation = json::parse_deactivation(j);

            // Clear cached state with mutex
            {
                std::lock_guard<std::mutex> lock(mutex_);
                current_activation_.reset();
                cached_license_.reset();
                cached_validation_.reset();
            }
            storage_->clear_license();
            storage_->clear_offline_token();
            storage_->clear_machine_file();

            event_bus_.emit(events::DEACTIVATION_SUCCESS, deactivation);

            return Result<Deactivation>::ok(std::move(deactivation));
        } catch (const nlohmann::json::exception& e) {
            return Result<Deactivation>::error(ErrorCode::ParseError,
                                               std::string("Failed to parse response: ") + e.what());
        }
    }

    // ========== Async API ==========

    void validate_async(const std::string& license_key, AsyncCallback callback,
                        const std::string& device_id) {
        auto future = std::async(std::launch::async, [this, license_key, callback, device_id]() {
            auto result = this->validate(license_key, device_id);
            if (callback) {
                callback(std::move(result));
            }
        });
        store_future(std::move(future));
    }

    void activate_async(const std::string& license_key, ActivationCallback callback,
                        const std::string& device_id, const std::string& device_name,
                        const Metadata& metadata) {
        auto future = std::async(std::launch::async, [this, license_key, callback, device_id, device_name, metadata]() {
            auto result = this->activate(license_key, device_id, device_name, metadata);
            if (callback) {
                callback(std::move(result));
            }
        });
        store_future(std::move(future));
    }

    void deactivate_async(const std::string& license_key, DeactivationCallback callback,
                          const std::string& device_id) {
        auto future = std::async(std::launch::async, [this, license_key, callback, device_id]() {
            auto result = this->deactivate(license_key, device_id);
            if (callback) {
                callback(std::move(result));
            }
        });
        store_future(std::move(future));
    }

    // ========== Heartbeat ==========

    Result<HeartbeatResponse> heartbeat(const std::string& license_key,
                                        const std::string& device_id_param) {
        auto request = prepare_license_request_context(license_key, device_id_param);
        if (!request.ok) {
            return request_context_error<HeartbeatResponse>(request);
        }

        // Make HTTP call without holding mutex
        auto body = json::fingerprint_alias_payload(request.fingerprint, true);
        auto response = send_post(
            "/products/" + request.product_slug + "/licenses/" + license_key + "/heartbeat", body);

        if (!response.success) {
            if (response.error_message.empty()) {
                auto err = handle_error_response<HeartbeatResponse>(response);
                event_bus_.emit(events::HEARTBEAT_ERROR,
                                std::map<std::string, std::string>{{"error", err.error_message()}});
                return err;
            }
            event_bus_.emit(events::HEARTBEAT_ERROR,
                            std::map<std::string, std::string>{{"error", response.error_message}});
            return Result<HeartbeatResponse>::error(ErrorCode::NetworkError, response.error_message);
        }

        try {
            auto j = nlohmann::json::parse(response.body);
            HeartbeatResponse result;
            result.object = j.value("object", "");
            result.received_at = j.value("received_at", "");
            event_bus_.emit(events::HEARTBEAT_SUCCESS, result);
            return Result<HeartbeatResponse>::ok(std::move(result));
        } catch (const nlohmann::json::exception& e) {
            return Result<HeartbeatResponse>::error(
                ErrorCode::ParseError, std::string("Failed to parse response: ") + e.what());
        }
    }

    void heartbeat_async(const std::string& license_key, HeartbeatCallback callback,
                         const std::string& device_id) {
        auto future = std::async(std::launch::async, [this, license_key, callback, device_id]() {
            auto result = this->heartbeat(license_key, device_id);
            if (callback) {
                callback(std::move(result));
            }
        });
        store_future(std::move(future));
    }

    // ========== Offline Tokens ==========

    Result<OfflineToken> generate_offline_token(const std::string& license_key,
                                                const std::string& device_id_param,
                                                int ttl_days) {
        auto request = prepare_license_request_context(license_key, device_id_param);
        if (!request.ok) {
            return request_context_error<OfflineToken>(request);
        }

        // Make HTTP call without holding mutex
        auto body = json::build_offline_token_request(request.fingerprint, ttl_days);
        auto response = send_post(
            "/products/" + request.product_slug + "/licenses/" + license_key + "/offline_token", body);

        if (!response.success) {
            if (response.error_message.empty()) {
                return handle_error_response<OfflineToken>(response);
            }
            return Result<OfflineToken>::error(ErrorCode::NetworkError, response.error_message);
        }

        // Parse response
        try {
            auto j = nlohmann::json::parse(response.body);
            auto offline = json::parse_offline_token(j);

            // Cache it
            storage_->set_offline_token(offline);

            event_bus_.emit(events::OFFLINE_TOKEN_READY, offline);

            return Result<OfflineToken>::ok(std::move(offline));
        } catch (const nlohmann::json::exception& e) {
            return Result<OfflineToken>::error(
                ErrorCode::ParseError, std::string("Failed to parse response: ") + e.what());
        }
    }

    Result<MachineFile> checkout_machine_file(const std::string& license_key,
                                              const std::string& device_id_param,
                                              int ttl_days) {
        auto request = prepare_license_request_context(
            license_key, device_id_param, true, false, true, "Fingerprint is required");
        if (!request.ok) {
            return request_context_error<MachineFile>(request);
        }

        event_bus_.emit(events::MACHINE_FILE_FETCHING,
                        std::map<std::string, std::string>{{"licenseKey", license_key},
                                                           {"fingerprint", request.fingerprint}});

        const auto fingerprint_components = local_fingerprint_components_for(request.fingerprint);
        auto body = json::build_machine_file_request(request.fingerprint, ttl_days, fingerprint_components);
        auto response = send_post(
            "/products/" + request.product_slug + "/licenses/" + license_key + "/machine-file", body);

        if (!response.success) {
            if (response.error_message.empty()) {
                auto err = handle_error_response<MachineFile>(response);
                event_bus_.emit(events::MACHINE_FILE_FETCH_ERROR,
                                std::map<std::string, std::string>{
                                    {"licenseKey", license_key},
                                    {"fingerprint", request.fingerprint},
                                    {"error", err.error_message()}});
                return err;
            }

            event_bus_.emit(events::MACHINE_FILE_FETCH_ERROR,
                            std::map<std::string, std::string>{{"licenseKey", license_key},
                                                               {"fingerprint", request.fingerprint},
                                                               {"error", response.error_message}});
            return Result<MachineFile>::error(ErrorCode::NetworkError, response.error_message);
        }

        try {
            auto j = nlohmann::json::parse(response.body);
            auto machine_file = json::parse_machine_file(j);
            if (machine_file.license_key.empty()) {
                machine_file.license_key = license_key;
            }
            if (machine_file.fingerprint.empty()) {
                machine_file.fingerprint = request.fingerprint;
            }

            storage_->set_machine_file(machine_file);

            auto key_id = extract_machine_file_key_id(machine_file);
            if (key_id.has_value() && !key_id->empty() && config_.signing_public_key.empty()) {
                auto cached_key = storage_->get_signing_key(*key_id);
                if (!cached_key.has_value()) {
                    (void)fetch_signing_key(*key_id);
                }
            }

            event_bus_.emit(events::MACHINE_FILE_FETCHED, machine_file);
            event_bus_.emit(events::MACHINE_FILE_READY, machine_file);
            return Result<MachineFile>::ok(std::move(machine_file));
        } catch (const nlohmann::json::exception& e) {
            event_bus_.emit(events::MACHINE_FILE_FETCH_ERROR,
                            std::map<std::string, std::string>{{"licenseKey", license_key},
                                                               {"fingerprint", request.fingerprint},
                                                               {"error", e.what()}});
            return Result<MachineFile>::error(
                ErrorCode::ParseError, std::string("Failed to parse response: ") + e.what());
        }
    }

    Result<bool> verify_offline_token(const OfflineToken& offline_token,
                                      const std::string& public_key_b64) {
        // Perform basic validity checks first
        if (offline_token.token.license_key.empty()) {
            return Result<bool>::error(ErrorCode::InvalidLicenseKey, "License key is empty");
        }

        if (offline_token.is_expired()) {
            return Result<bool>::error(ErrorCode::LicenseExpired, "Offline token has expired");
        }

        if (offline_token.is_not_yet_valid()) {
            return Result<bool>::error(ErrorCode::LicenseNotStarted, "Offline token is not yet valid");
        }

        const auto token_fingerprint = offline_token.token.fingerprint.has_value()
                                           ? *offline_token.token.fingerprint
                                           : offline_token.token.device_id.value_or("");
        if (!token_fingerprint.empty() && !constant_time_equal(token_fingerprint, device_id_)) {
            return Result<bool>::error(ErrorCode::FingerprintMismatch,
                                       "Offline token fingerprint does not match this device");
        }

        if (offline_token.is_license_expired()) {
            return Result<bool>::error(ErrorCode::LicenseExpired,
                                       "Underlying license has expired");
        }

        // Determine which public key to use
        std::string key_to_use = public_key_b64;
        if (key_to_use.empty()) {
            key_to_use = config_.signing_public_key;
        }
        if (key_to_use.empty()) {
            // Try to get from cache
            auto cached_key = storage_->get_signing_key(offline_token.signature.key_id);
            if (cached_key) {
                key_to_use = *cached_key;
            }
        }

        if (key_to_use.empty()) {
            return Result<bool>::error(ErrorCode::MissingParameter,
                                       "Public key required for offline verification");
        }

        // Verify the Ed25519 signature using the canonical JSON
        auto result = crypto::verify_offline_token_signature(offline_token, key_to_use);
        if (result.is_ok() && result.value()) {
            event_bus_.emit(events::OFFLINE_TOKEN_VERIFIED, offline_token);
        }
        return result;
    }

    Result<MachineFileVerificationResult> verify_machine_file(const MachineFile& machine_file,
                                                              const std::string& public_key_b64,
                                                              const std::string& license_key,
                                                              const std::string& device_id_param) {
        std::string resolved_license_key = license_key;
        if (resolved_license_key.empty()) {
            resolved_license_key = machine_file.license_key;
        }
        if (resolved_license_key.empty()) {
            auto cached_license = storage_->get_license();
            if (cached_license.has_value()) {
                resolved_license_key = cached_license->license_key;
            }
        }

        std::string resolved_fingerprint = device_id_param;
        if (resolved_fingerprint.empty()) {
            resolved_fingerprint = device_id_;
        }

        if (resolved_license_key.empty()) {
            return Result<MachineFileVerificationResult>::error(ErrorCode::InvalidLicenseKey,
                                                                "License key is required");
        }

        if (resolved_fingerprint.empty()) {
            return Result<MachineFileVerificationResult>::error(ErrorCode::MissingParameter,
                                                                "Fingerprint is required");
        }

        auto key_id = extract_machine_file_key_id(machine_file);
        auto public_key = resolve_signing_key(key_id, public_key_b64, false);
        if (public_key.empty()) {
            return Result<MachineFileVerificationResult>::error(
                ErrorCode::MissingParameter,
                "Public key required for machine file verification");
        }

        auto crypto_result = crypto::verify_machine_file(machine_file, resolved_license_key,
                                                         resolved_fingerprint, public_key);

        MachineFileVerificationResult result;
        if (crypto_result.is_error()) {
            result.valid = false;
            result.code = offline_error_code_string(crypto_result.error_code());
            result.message = crypto_result.error_message();
            event_bus_.emit(events::MACHINE_FILE_VERIFICATION_FAILED,
                            std::map<std::string, std::string>{
                                {"fingerprint", resolved_fingerprint},
                                {"licenseKey", resolved_license_key},
                                {"code", result.code},
                                {"error", result.message}});
            return Result<MachineFileVerificationResult>::ok(std::move(result));
        }

        result.valid = true;
        result.payload = std::move(crypto_result.value());
        event_bus_.emit(events::MACHINE_FILE_VERIFIED, *result.payload);

        return Result<MachineFileVerificationResult>::ok(std::move(result));
    }

    Result<std::string> fetch_signing_key(const std::string& key_id) {
        // Validate input without holding mutex for long
        if (key_id.empty()) {
            return Result<std::string>::error(ErrorCode::MissingParameter, "Key ID is required");
        }

        // Make HTTP call without holding mutex
        http::Request request;
        request.method = http::Method::GET;
        request.path = "/signing_keys/" + key_id;

        auto response = http_client_->send(request);

        if (!response.success) {
            if (response.error_message.empty()) {
                return handle_error_response<std::string>(response);
            }
            return Result<std::string>::error(ErrorCode::NetworkError, response.error_message);
        }

        // Parse response
        try {
            auto j = nlohmann::json::parse(response.body);
            auto key = json::parse_signing_key(j);

            // Cache it
            storage_->set_signing_key(key_id, key);

            return Result<std::string>::ok(std::move(key));
        } catch (const nlohmann::json::exception& e) {
            return Result<std::string>::error(
                ErrorCode::ParseError, std::string("Failed to parse response: ") + e.what());
        }
    }

    void sync_offline_assets() {
        if (!cached_license_) {
            return;
        }
        auto license_key = cached_license_->key();
        auto future = std::async(std::launch::async, [this, license_key]() {
            this->sync_offline_assets_impl(license_key, device_id_);
        });
        store_future(std::move(future));
    }

    // ========== Session Restore ==========

    RestoreResult restore_license() {
        // Step 1: Load cached license from storage
        auto cached = storage_->get_license();
        if (!cached || cached->license_key.empty()) {
            RestoreResult result;
            result.success = false;
            result.status = ClientStatus::Inactive;
            result.message = "No cached license found";
            return result;
        }

        std::string license_key = cached->license_key;
        std::string device_id = cached->device_id.empty() ? device_id_ : cached->device_id;

        // Step 2: Check connectivity
        auto health_result = health();
        bool is_network_available = health_result.is_ok() && health_result.value();

        if (is_network_available) {
            // Step 3a: Online - validate with server
            auto validation_result = validate(license_key, device_id);

            RestoreResult result;
            if (validation_result.is_ok() && validation_result.value().valid) {
                result.success = true;
                result.status = ClientStatus::Active;
                result.license = validation_result.value().license;
                result.message = "License restored and validated online";

                // Start timers for ongoing license management
                start_auto_validation(license_key);
                start_heartbeat(license_key);
                start_offline_refresh(license_key);
            } else {
                result.success = false;
                result.status = ClientStatus::Invalid;
                result.message = validation_result.is_ok()
                                     ? validation_result.value().message
                                     : validation_result.error_message();
            }
            return result;
        } else {
            // Step 3b: Offline - verify cached offline token
            auto offline_result = verify_cached_offline();

            RestoreResult result;
            if (offline_result.is_ok() && offline_result.value().valid) {
                result.success = true;
                result.status = ClientStatus::OfflineValid;
                result.license = cached->license_data;
                result.message = "License restored from offline cache";

                // Update cached state
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    cached_license_ = cached->license_data;
                    cached_validation_ = offline_result.value();
                }

                current_auto_license_key_ = license_key;
                current_heartbeat_license_key_ = license_key;
                offline_refresh_license_key_ = license_key;

                // Start network recheck to detect when we come back online
                start_network_recheck();
            } else {
                result.success = false;
                // Use OfflineInvalid (not Invalid) for offline failures (matches Swift SDK)
                result.status = ClientStatus::OfflineInvalid;
                result.message = offline_result.is_ok()
                                     ? "Offline verification failed: " + offline_result.value().code
                                     : offline_result.error_message();

                current_auto_license_key_ = license_key;
                current_heartbeat_license_key_ = license_key;
                offline_refresh_license_key_ = license_key;

                // Start network recheck to detect when we come back online
                start_network_recheck();
            }
            return result;
        }
    }

    void restore_license_async(RestoreCallback callback) {
        auto future = std::async(std::launch::async, [this, callback]() {
            auto result = this->restore_license();
            if (callback) {
                callback(std::move(result));
            }
        });
        store_future(std::move(future));
    }

    // ========== Auto-Validation ==========

    void start_auto_validation(const std::string& license_key) {
        stop_auto_validation();

        if (config_.auto_validate_interval <= 0) {
            return;
        }

        auto_validate_running_ = true;
        current_auto_license_key_ = license_key;

        auto_validate_thread_ = std::thread([this, license_key]() {
            // Emit first cycle information immediately (matches Swift SDK)
            auto next_run = std::chrono::system_clock::now() +
                            std::chrono::duration<double>(config_.auto_validate_interval);
            auto next_run_unix = std::chrono::duration_cast<std::chrono::seconds>(
                                     next_run.time_since_epoch())
                                     .count();
            event_bus_.emit(events::AUTOVALIDATION_CYCLE,
                            std::map<std::string, std::string>{
                                {"license_key", license_key},
                                {"nextRunAt", std::to_string(next_run_unix)}});

            while (auto_validate_running_) {
                std::unique_lock<std::mutex> lock(auto_validate_mutex_);
                auto_validate_cv_.wait_for(
                    lock, std::chrono::duration<double>(config_.auto_validate_interval),
                    [this]() { return !auto_validate_running_; });

                if (!auto_validate_running_) {
                    break;
                }

                // Perform validation
                auto result = this->validate(license_key, "");

                // Emit validation:auto-failed on error (matches Swift SDK)
                if (result.is_error() || (result.is_ok() && !result.value().valid)) {
                    event_bus_.emit(events::VALIDATION_AUTO_FAILED,
                                    std::map<std::string, std::string>{
                                        {"licenseKey", license_key},
                                        {"error", result.is_error() ? result.error_message() : result.value().code}});
                }

                // Piggyback heartbeat (fire-and-forget, ignore errors)
                (void)this->heartbeat(license_key, "");

                // Announce next scheduled run (matches Swift SDK)
                if (auto_validate_running_) {
                    auto next = std::chrono::system_clock::now() +
                                std::chrono::duration<double>(config_.auto_validate_interval);
                    auto next_unix = std::chrono::duration_cast<std::chrono::seconds>(
                                         next.time_since_epoch())
                                         .count();
                    event_bus_.emit(events::AUTOVALIDATION_CYCLE,
                                    std::map<std::string, std::string>{
                                        {"license_key", license_key},
                                        {"nextRunAt", std::to_string(next_unix)}});
                }
            }
        });
    }

    void stop_auto_validation() {
        bool was_running = auto_validate_running_.exchange(false);
        auto_validate_cv_.notify_all();

        // Always check joinable regardless of running flag (race condition safety)
        if (auto_validate_thread_.joinable()) {
            auto_validate_thread_.join();
        }

        if (was_running) {
            event_bus_.emit(events::AUTOVALIDATION_STOPPED, std::map<std::string, std::string>{});
        }
    }

    bool is_auto_validating() const { return auto_validate_running_; }

    // ========== Heartbeat Timer ==========

    void start_heartbeat(const std::string& license_key) {
        stop_heartbeat();

        if (config_.heartbeat_interval <= 0) {
            return;
        }

        current_heartbeat_license_key_ = license_key;
        heartbeat_running_ = true;

        heartbeat_thread_ = std::thread([this, license_key]() {
            while (heartbeat_running_) {
                std::unique_lock<std::mutex> lock(heartbeat_mutex_);
                heartbeat_cv_.wait_for(
                    lock, std::chrono::seconds(config_.heartbeat_interval),
                    [this]() { return !heartbeat_running_; });

                if (!heartbeat_running_) {
                    break;
                }

                // Send heartbeat (fire-and-forget)
                (void)this->heartbeat(license_key, "");
            }
        });
    }

    void stop_heartbeat() {
        heartbeat_running_ = false;
        heartbeat_cv_.notify_all();

        // Always check joinable regardless of running flag (race condition safety)
        if (heartbeat_thread_.joinable()) {
            heartbeat_thread_.join();
        }
    }

    bool is_heartbeat_running() const { return heartbeat_running_; }

    // ========== Status & State ==========

    ValidationResult get_status() const {
        std::lock_guard<std::mutex> lock(mutex_);

        if (cached_validation_) {
            return *cached_validation_;
        }

        ValidationResult result;
        result.valid = false;
        result.message = "No license validated";
        return result;
    }

    std::optional<License> current_license() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return cached_license_;
    }

    EntitlementStatus check_entitlement(const std::string& entitlement_key) const {
        std::lock_guard<std::mutex> lock(mutex_);

        EntitlementStatus status;

        if (!cached_license_) {
            status.active = false;
            status.reason = "no_license";
            return status;
        }

        for (const auto& ent : cached_license_->active_entitlements()) {
            if (ent.key == entitlement_key) {
                if (ent.expires_at) {
                    if (*ent.expires_at < std::chrono::system_clock::now()) {
                        status.active = false;
                        status.reason = "expired";
                        status.expires_at = ent.expires_at;
                        status.entitlement = ent;
                        return status;
                    }
                }
                status.active = true;
                status.expires_at = ent.expires_at;
                status.entitlement = ent;
                return status;
            }
        }

        status.active = false;
        status.reason = "not_found";
        return status;
    }

    bool is_online() const { return is_online_; }

    ClientStatus get_client_status() const {
        std::lock_guard<std::mutex> lock(mutex_);

        if (!cached_validation_) {
            return ClientStatus::Inactive;
        }

        if (cached_validation_->offline) {
            // Differentiate between offline valid and offline invalid (matches Swift SDK)
            return cached_validation_->valid ? ClientStatus::OfflineValid : ClientStatus::OfflineInvalid;
        }

        if (cached_validation_->valid) {
            return ClientStatus::Active;
        }

        return ClientStatus::Invalid;
    }

    // ========== Event Handling ==========

    Subscription on(const std::string& event, EventHandler handler) {
        auto event_sub = event_bus_.on(event, handler);
        // Wrap the EventSubscription's cancel in a Subscription
        return Subscription([sub = std::move(event_sub)]() mutable { sub.cancel(); });
    }

    void emit(const std::string& event, const std::any& data) { event_bus_.emit(event, data); }

    // ========== Releases ==========

    Result<Release> get_latest_release(const std::string& product_slug_param,
                                       const std::string& channel,
                                       const std::string& platform) {
        // Prepare request data while holding mutex briefly
        std::string product_slug;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            product_slug = product_slug_param.empty() ? config_.product_slug : product_slug_param;
        }

        if (product_slug.empty()) {
            return Result<Release>::error(ErrorCode::MissingParameter, "Product slug is required");
        }

        std::string path = "/products/" + product_slug + "/releases/latest";
        std::string query;

        if (!channel.empty()) {
            query += (query.empty() ? "?" : "&") + std::string("channel=") + channel;
        }
        if (!platform.empty()) {
            query += (query.empty() ? "?" : "&") + std::string("platform=") + platform;
        }

        // Make HTTP call without holding mutex
        http::Request request;
        request.method = http::Method::GET;
        request.path = path + query;

        auto response = http_client_->send(request);

        if (!response.success) {
            if (response.error_message.empty()) {
                return handle_error_response<Release>(response);
            }
            return Result<Release>::error(ErrorCode::NetworkError, response.error_message);
        }

        // Parse response
        try {
            auto j = nlohmann::json::parse(response.body);
            auto release = json::parse_release(j);
            return Result<Release>::ok(std::move(release));
        } catch (const nlohmann::json::exception& e) {
            return Result<Release>::error(ErrorCode::ParseError,
                                          std::string("Failed to parse response: ") + e.what());
        }
    }

    Result<std::vector<Release>> list_releases(const std::string& product_slug_param,
                                               const std::string& channel,
                                               const std::string& platform) {
        // Prepare request data while holding mutex briefly
        std::string product_slug;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            product_slug = product_slug_param.empty() ? config_.product_slug : product_slug_param;
        }

        if (product_slug.empty()) {
            return Result<std::vector<Release>>::error(ErrorCode::MissingParameter,
                                                       "Product slug is required");
        }

        std::string path = "/products/" + product_slug + "/releases";
        std::string query;

        if (!channel.empty()) {
            query += (query.empty() ? "?" : "&") + std::string("channel=") + channel;
        }
        if (!platform.empty()) {
            query += (query.empty() ? "?" : "&") + std::string("platform=") + platform;
        }

        // Make HTTP call without holding mutex
        http::Request request;
        request.method = http::Method::GET;
        request.path = path + query;

        auto response = http_client_->send(request);

        if (!response.success) {
            if (response.error_message.empty()) {
                return handle_error_response<std::vector<Release>>(response);
            }
            return Result<std::vector<Release>>::error(ErrorCode::NetworkError,
                                                       response.error_message);
        }

        // Parse response
        try {
            auto j = nlohmann::json::parse(response.body);
            auto releases = json::parse_releases(j);
            return Result<std::vector<Release>>::ok(std::move(releases));
        } catch (const nlohmann::json::exception& e) {
            return Result<std::vector<Release>>::error(
                ErrorCode::ParseError, std::string("Failed to parse response: ") + e.what());
        }
    }

    Result<DownloadToken> generate_download_token(const std::string& version,
                                                  const std::string& license_key,
                                                  const std::string& product_slug_param,
                                                  const std::string& platform) {
        // Validate inputs before mutex
        if (license_key.empty()) {
            return Result<DownloadToken>::error(ErrorCode::InvalidLicenseKey,
                                                "License key is required");
        }

        if (version.empty()) {
            return Result<DownloadToken>::error(ErrorCode::MissingParameter,
                                                "Version is required");
        }

        // Get product_slug while holding mutex briefly
        std::string product_slug;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            product_slug = product_slug_param.empty() ? config_.product_slug : product_slug_param;
        }

        if (product_slug.empty()) {
            return Result<DownloadToken>::error(ErrorCode::MissingParameter,
                                                "Product slug is required");
        }

        // Make HTTP call without holding mutex
        auto body = json::build_download_token_request(license_key, platform);
        auto response = send_post(
            "/products/" + product_slug + "/releases/" + version + "/download_token", body);

        if (!response.success) {
            if (response.error_message.empty()) {
                return handle_error_response<DownloadToken>(response);
            }
            return Result<DownloadToken>::error(ErrorCode::NetworkError, response.error_message);
        }

        // Parse response
        try {
            auto j = nlohmann::json::parse(response.body);
            auto token = json::parse_download_token(j);
            return Result<DownloadToken>::ok(std::move(token));
        } catch (const nlohmann::json::exception& e) {
            return Result<DownloadToken>::error(
                ErrorCode::ParseError, std::string("Failed to parse response: ") + e.what());
        }
    }

    Result<bool> health() {
        bool was_online = is_online_;

        // Make HTTP call without holding mutex
        http::Request request;
        request.method = http::Method::GET;
        request.path = "/health";

        auto response = http_client_->send(request);

        Result<bool> result = Result<bool>::error(ErrorCode::Unknown, "");
        bool should_start_recheck = false;

        if (!response.success) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                is_online_ = false;
            }
            if (was_online) {
                event_bus_.emit(events::NETWORK_OFFLINE, std::map<std::string, std::string>{});
                should_start_recheck = true;
            }
            if (response.error_message.empty()) {
                result = handle_error_response<bool>(response);
            } else {
                result = Result<bool>::error(ErrorCode::NetworkError, response.error_message);
            }
        } else {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                is_online_ = true;
            }
            if (!was_online) {
                event_bus_.emit(events::NETWORK_ONLINE, std::map<std::string, std::string>{});
            }
            result = Result<bool>::ok(true);
        }

        // Start network recheck timer outside the lock to avoid deadlock
        if (should_start_recheck) {
            start_network_recheck();
        }

        return result;
    }

    void reset() {
        stop_heartbeat();
        stop_auto_validation();
        storage_->clear_all();
        cached_license_.reset();
        cached_validation_.reset();
        current_activation_.reset();
        event_bus_.emit(events::SDK_RESET, std::map<std::string, std::string>{});
    }

    const Config& config() const noexcept { return config_; }

    const std::string& device_id() const noexcept { return device_id_; }
    const std::string& fingerprint() const noexcept { return device_id_; }

  private:
    /// Send a POST request, injecting telemetry if enabled
    http::Response send_post(const std::string& path, nlohmann::json body) {
        if (config_.telemetry_enabled) {
            body["telemetry"] = telemetry::collect(VERSION, config_.app_version, config_.app_build);
        }
        http::Request request;
        request.method = http::Method::POST;
        request.path = path;
        request.body = body.dump();
        return http_client_->send(request);
    }

    template <typename T>
    Result<T> handle_error_response(const http::Response& response) {
        // Try to parse error response
        try {
            auto j = nlohmann::json::parse(response.body);
            auto api_error = json::parse_error_response(j);

            ErrorCode code = ErrorCode::Unknown;
            if (!api_error.code.empty()) {
                code = json::error_code_to_error_code(api_error.code);
            } else {
                code = http::status_code_to_error_code(response.status_code);
            }

            std::string message = api_error.message;
            if (message.empty()) {
                message = error_code_to_string(code);
            }

            return Result<T>::error(code, message);
        } catch (const nlohmann::json::exception&) {
            // Couldn't parse as JSON, use status code
            auto code = http::status_code_to_error_code(response.status_code);
            return Result<T>::error(code, error_code_to_string(code));
        }
    }

    bool should_fallback_to_offline(const http::Response& response) const {
        if (config_.offline_fallback_mode == OfflineFallbackMode::Always) {
            return true;
        }

        // NetworkOnly mode - only fallback on transport errors
        if (!response.success && response.status_code == 0) {
            return true;  // Network error
        }
        if (response.status_code >= 500 && response.status_code < 600) {
            return true;  // Server error
        }
        if (response.status_code == 408) {
            return true;  // Timeout
        }

        return false;
    }

    // Check if the validation result code indicates license revocation
    bool is_revocation_code(const std::string& code) const {
        // Match the API's revocation-related codes
        return code == "revoked" || code == "suspended";
    }

    // Check if the HTTP error indicates license revocation (for non-validate endpoints)
    // 422 = unprocessable_entity (license errors like revoked, expired, suspended)
    // But NOT 401 (unauthorized), 404 (not found), 429 (rate limit)
    bool is_revocation_error(const http::Response& response) const {
        // 422 with revocation codes in the body indicates revocation
        if (response.status_code == 422) {
            try {
                auto j = nlohmann::json::parse(response.body);
                if (j.contains("error") && j["error"].contains("code")) {
                    std::string code = j["error"]["code"].get<std::string>();
                    return is_revocation_code(code);
                }
            } catch (...) {
                // If we can't parse, assume not revocation
            }
        }
        return false;
    }

    // Purge all cached data when license is revoked
    void purge_cache_on_revocation() {
        cached_license_.reset();
        cached_validation_.reset();
        current_activation_.reset();
        storage_->clear_license();
        storage_->clear_offline_token();
        storage_->clear_machine_file();

        // Stop all timers - no point continuing without a valid license
        // Note: These are called without lock, so they must be thread-safe
        // The atomic booleans and condition variables handle this
        stop_auto_validation_unlocked();
        stop_heartbeat_unlocked();
        stop_network_recheck_unlocked();
        stop_offline_refresh_unlocked();
    }

    // Unlocked versions of stop methods for use during revocation
    void stop_auto_validation_unlocked() {
        if (auto_validate_running_) {
            auto_validate_running_ = false;
            auto_validate_cv_.notify_all();
            // Don't join here - we're in the middle of validation which may be on the timer thread
        }
    }

    void stop_heartbeat_unlocked() {
        if (heartbeat_running_) {
            heartbeat_running_ = false;
            heartbeat_cv_.notify_all();
        }
    }

    void stop_network_recheck_unlocked() {
        if (network_recheck_running_) {
            network_recheck_running_ = false;
            network_recheck_cv_.notify_all();
        }
    }

    void stop_offline_refresh_unlocked() {
        if (offline_refresh_running_) {
            offline_refresh_running_ = false;
            offline_refresh_cv_.notify_all();
        }
    }

    // Constant-time string comparison (matches Swift SDK)
    bool constant_time_equal(const std::string& a, const std::string& b) const {
        if (a.size() != b.size()) {
            return false;
        }
        int result = 0;
        for (size_t i = 0; i < a.size(); ++i) {
            result |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
        }
        return result == 0;
    }

    std::string offline_error_code_string(ErrorCode code) const {
        switch (code) {
            case ErrorCode::InvalidLicenseKey:
                return "invalid_license_key";
            case ErrorCode::MissingParameter:
                return "missing_parameter";
            case ErrorCode::InvalidParameter:
                return "invalid_parameter";
            case ErrorCode::InvalidSignature:
                return "verification_failed";
            case ErrorCode::LicenseExpired:
                return "license_expired";
            case ErrorCode::LicenseNotStarted:
                return "token_not_yet_valid";
            case ErrorCode::DeviceNotActivated:
                return "device_not_activated";
            case ErrorCode::DecryptionFailed:
                return "decryption_failed";
            case ErrorCode::TokenExpired:
                return "token_expired";
            case ErrorCode::TokenNotYetValid:
                return "token_not_yet_valid";
            case ErrorCode::FingerprintMismatch:
                return "fingerprint_mismatch";
            case ErrorCode::ActivationNotFound:
                return "machine_not_found";
            default:
                return "verification_failed";
        }
    }

    std::optional<std::string> extract_machine_file_key_id(const MachineFile& machine_file) const {
        if (machine_file.certificate.empty()) {
            return std::nullopt;
        }

        std::string cleaned = machine_file.certificate;
        const std::string begin_marker = "-----BEGIN MACHINE FILE-----";
        const std::string end_marker = "-----END MACHINE FILE-----";

        auto begin_pos = cleaned.find(begin_marker);
        if (begin_pos != std::string::npos) {
            cleaned.erase(begin_pos, begin_marker.size());
        }

        auto end_pos = cleaned.find(end_marker);
        if (end_pos != std::string::npos) {
            cleaned.erase(end_pos, end_marker.size());
        }

        cleaned.erase(std::remove_if(cleaned.begin(), cleaned.end(),
                                     [](unsigned char ch) { return std::isspace(ch) != 0; }),
                      cleaned.end());

        auto decoded = crypto::base64_decode(cleaned);
        if (decoded.empty()) {
            return std::nullopt;
        }

        try {
            auto envelope =
                nlohmann::json::parse(std::string(decoded.begin(), decoded.end()));
            auto key_id = envelope.value("kid", std::string{});
            if (key_id.empty()) {
                return std::nullopt;
            }
            return key_id;
        } catch (const nlohmann::json::exception&) {
            return std::nullopt;
        }
    }

    std::string resolve_signing_key(const std::optional<std::string>& key_id,
                                    const std::string& explicit_public_key,
                                    bool allow_fetch) {
        if (!explicit_public_key.empty()) {
            return explicit_public_key;
        }

        if (!config_.signing_public_key.empty()) {
            return config_.signing_public_key;
        }

        auto resolve_by_key_id = [&](const std::string& candidate_key_id) -> std::string {
            if (candidate_key_id.empty()) {
                return "";
            }

            auto cached_key = storage_->get_signing_key(candidate_key_id);
            if (cached_key.has_value()) {
                return *cached_key;
            }

            if (!allow_fetch) {
                return "";
            }

            auto fetched_key = fetch_signing_key(candidate_key_id);
            if (fetched_key.is_ok()) {
                return fetched_key.value();
            }

            return "";
        };

        if (key_id.has_value()) {
            auto key = resolve_by_key_id(*key_id);
            if (!key.empty()) {
                return key;
            }
        }

        if (!config_.signing_key_id.empty()) {
            return resolve_by_key_id(config_.signing_key_id);
        }

        return "";
    }

    std::string reconnect_license_key() const {
        if (!offline_refresh_license_key_.empty()) {
            return offline_refresh_license_key_;
        }

        if (!current_auto_license_key_.empty()) {
            return current_auto_license_key_;
        }

        if (!current_heartbeat_license_key_.empty()) {
            return current_heartbeat_license_key_;
        }

        auto cached_license = storage_->get_license();
        if (cached_license.has_value()) {
            return cached_license->license_key;
        }

        return "";
    }

    bool is_clock_tampered(int64_t now_unix) const {
        auto last_seen = storage_->get_last_seen_timestamp();
        if (!last_seen.has_value()) {
            return false;
        }

        const auto max_skew_sec = config_.max_clock_skew_ms / 1000.0;
        return static_cast<double>(now_unix) + max_skew_sec < *last_seen;
    }

    void update_last_seen(int64_t now_unix) {
        storage_->set_last_seen_timestamp(static_cast<double>(now_unix));
    }

    License fallback_license_for_machine_payload(
        const MachineFilePayload& payload,
        const std::optional<CachedLicense>& cached_license) const {
        if (cached_license.has_value() && cached_license->license_data.has_value()) {
            return *cached_license->license_data;
        }

        std::optional<Timestamp> expires_at;
        if (payload.license_expires_at.has_value()) {
            expires_at = std::chrono::system_clock::from_time_t(
                static_cast<std::time_t>(*payload.license_expires_at));
        }

        Product product;
        if (cached_license.has_value() && cached_license->license_data.has_value()) {
            product = cached_license->license_data->product();
        }

        return License(payload.license_key, LicenseStatus::Active, LicenseMode::Unknown, "",
                       std::nullopt, 0, std::nullopt, expires_at, {}, {}, product);
    }

    Result<ValidationResult> verify_cached_machine_file() {
        auto cached_machine_file = storage_->get_machine_file();
        if (!cached_machine_file.has_value()) {
            ValidationResult result;
            result.valid = false;
            result.offline = true;
            result.code = "no_machine_file";
            return Result<ValidationResult>::ok(std::move(result));
        }

        auto verify_result = verify_machine_file(*cached_machine_file, "", "", "");
        ValidationResult result;
        result.offline = true;

        if (!verify_result.is_ok()) {
            result.valid = false;
            result.code = offline_error_code_string(verify_result.error_code());
            result.message = verify_result.error_message();
            return Result<ValidationResult>::ok(std::move(result));
        }

        if (!verify_result.value().valid || !verify_result.value().payload.has_value()) {
            result.valid = false;
            result.code = verify_result.value().code.empty() ? "verification_failed"
                                                             : verify_result.value().code;
            result.message = verify_result.value().message;
            return Result<ValidationResult>::ok(std::move(result));
        }

        const auto& payload = *verify_result.value().payload;
        auto cached_license = storage_->get_license();

        if (cached_license.has_value() && !cached_license->license_key.empty() &&
            !payload.license_key.empty() &&
            !constant_time_equal(payload.license_key, cached_license->license_key)) {
            result.valid = false;
            result.code = "license_mismatch";
            return Result<ValidationResult>::ok(std::move(result));
        }

        auto now = std::chrono::system_clock::now();
        auto now_unix = std::chrono::duration_cast<std::chrono::seconds>(
                            now.time_since_epoch())
                            .count();

        if (is_clock_tampered(now_unix)) {
            result.valid = false;
            result.code = "clock_tamper";
            return Result<ValidationResult>::ok(std::move(result));
        }

        update_last_seen(now_unix);

        result.valid = true;
        result.license = payload.license.has_value()
                             ? *payload.license
                             : fallback_license_for_machine_payload(payload, cached_license);

        return Result<ValidationResult>::ok(std::move(result));
    }

    Result<ValidationResult> verify_cached_offline_token() {
        auto cached_offline = storage_->get_offline_token();
        if (!cached_offline) {
            ValidationResult result;
            result.valid = false;
            result.offline = true;
            result.code = "no_offline_token";
            return Result<ValidationResult>::ok(result);
        }

        std::string public_key;
        if (!config_.signing_public_key.empty()) {
            public_key = config_.signing_public_key;
        } else {
            auto cached_key = storage_->get_signing_key(cached_offline->signature.key_id);
            if (cached_key) {
                public_key = *cached_key;
            }
        }

        if (public_key.empty()) {
            ValidationResult result;
            result.valid = false;
            result.offline = true;
            result.code = "no_public_key";
            return Result<ValidationResult>::ok(result);
        }

        auto verify_result = verify_offline_token(*cached_offline, public_key);
        ValidationResult result;
        result.offline = true;

        if (!verify_result.is_ok() || !verify_result.value()) {
            result.valid = false;
            result.code = verify_result.is_ok() ? "signature_invalid"
                                                : offline_error_code_string(verify_result.error_code());
            result.message = verify_result.is_ok() ? "" : verify_result.error_message();
            event_bus_.emit(events::OFFLINE_TOKEN_VERIFICATION_FAILED,
                            std::map<std::string, std::string>{{"kid", cached_offline->signature.key_id}});
            return Result<ValidationResult>::ok(result);
        }

        auto cached_license = storage_->get_license();
        if (!cached_license) {
            result.valid = false;
            result.code = "license_mismatch";
            return Result<ValidationResult>::ok(result);
        }

        if (!constant_time_equal(cached_offline->token.license_key, cached_license->license_key)) {
            result.valid = false;
            result.code = "license_mismatch";
            return Result<ValidationResult>::ok(result);
        }

        auto now = std::chrono::system_clock::now();
        auto now_unix = std::chrono::duration_cast<std::chrono::seconds>(
                            now.time_since_epoch())
                            .count();

        if (now_unix > cached_offline->token.exp) {
            result.valid = false;
            result.code = "token_expired";
            return Result<ValidationResult>::ok(result);
        }

        if (now_unix < cached_offline->token.nbf) {
            result.valid = false;
            result.code = "token_not_yet_valid";
            return Result<ValidationResult>::ok(result);
        }

        if (cached_offline->token.license_expires_at.has_value() &&
            now_unix > *cached_offline->token.license_expires_at) {
            result.valid = false;
            result.code = "license_expired";
            return Result<ValidationResult>::ok(result);
        }

        if (config_.max_offline_days > 0) {
            auto last_validated = cached_license->last_validated;
            auto last_validated_unix = std::chrono::duration_cast<std::chrono::seconds>(
                                           last_validated.time_since_epoch())
                                           .count();
            auto days_since_validation = (now_unix - last_validated_unix) / 86400;
            if (days_since_validation > config_.max_offline_days) {
                result.valid = false;
                result.code = "grace_period_expired";
                return Result<ValidationResult>::ok(result);
            }
        }

        if (is_clock_tampered(now_unix)) {
            result.valid = false;
            result.code = "clock_tamper";
            return Result<ValidationResult>::ok(result);
        }

        update_last_seen(now_unix);

        result.valid = true;
        result.code = "";

        std::vector<Entitlement> entitlements = cached_offline->token.entitlements;

        std::optional<Timestamp> license_expires;
        if (cached_offline->token.license_expires_at.has_value()) {
            license_expires = std::chrono::system_clock::from_time_t(
                static_cast<std::time_t>(*cached_offline->token.license_expires_at));
        }

        result.license = License(
            cached_offline->token.license_key,
            result.valid ? LicenseStatus::Active : LicenseStatus::Unknown,
            license_mode_from_string(cached_offline->token.mode),
            cached_offline->token.plan_key,
            cached_offline->token.seat_limit,
            0,
            std::nullopt,
            license_expires,
            entitlements,
            cached_offline->token.metadata,
            Product{cached_offline->token.product_slug, cached_offline->token.product_slug});

        return Result<ValidationResult>::ok(result);
    }

    Result<ValidationResult> verify_cached_offline() {
        auto machine_result = verify_cached_machine_file();
        if (machine_result.is_ok() && machine_result.value().valid) {
            return machine_result;
        }

        auto offline_token_result = verify_cached_offline_token();
        if (offline_token_result.is_ok() && offline_token_result.value().valid) {
            return offline_token_result;
        }

        if (machine_result.is_ok() && machine_result.value().code != "no_machine_file") {
            return machine_result;
        }

        return offline_token_result;
    }

    void sync_offline_assets_impl(const std::string& license_key, const std::string& device_id) {
        if (license_key.empty()) {
            return;
        }

        auto machine_file_result = checkout_machine_file(license_key, device_id, 30);
        if (machine_file_result.is_ok()) {
            auto verify_result = verify_machine_file(machine_file_result.value(), "", "", "");
            if (verify_result.is_ok() && verify_result.value().valid) {
                return;
            }
        }

        if (!config_.enable_legacy_offline_tokens) {
            return;
        }

        event_bus_.emit(events::OFFLINE_TOKEN_FETCHING,
                        std::map<std::string, std::string>{{"licenseKey", license_key}});

        // Fetch offline token
        auto offline_result = generate_offline_token(license_key, device_id, 30);
        if (offline_result.is_ok()) {
            auto& offline = offline_result.value();

            event_bus_.emit(events::OFFLINE_TOKEN_FETCHED,
                            std::map<std::string, std::string>{{"licenseKey", license_key}});

            // Fetch signing key if needed
            if (!offline.signature.key_id.empty()) {
                auto cached_key = storage_->get_signing_key(offline.signature.key_id);
                if (!cached_key) {
                    (void)fetch_signing_key(offline.signature.key_id);
                }
            }

            // Immediately verify offline token locally (matches Swift SDK behavior)
            auto verify_result = verify_cached_offline();
            if (verify_result.is_ok()) {
                auto& result = verify_result.value();
                if (result.valid) {
                    event_bus_.emit(events::VALIDATION_OFFLINE_SUCCESS, result);
                } else {
                    event_bus_.emit(events::VALIDATION_OFFLINE_FAILED, result);
                }
            }
        } else {
            event_bus_.emit(events::OFFLINE_TOKEN_FETCH_ERROR,
                            std::map<std::string, std::string>{
                                {"licenseKey", license_key},
                                {"error", offline_result.error_message()}});
        }
    }

    void update_storage_license(const std::string& license_key, const std::string& device_id,
                                const ValidationResult& validation) {
        CachedLicense cached;
        cached.license_key = license_key;
        cached.device_id = device_id;
        cached.activated_at = std::chrono::system_clock::now();
        cached.last_validated = std::chrono::system_clock::now();
        cached.validation = validation;
        cached.license_data = validation.license;
        storage_->set_license(cached);

        // Update last seen timestamp
        storage_->set_last_seen_timestamp(
            static_cast<double>(std::chrono::duration_cast<std::chrono::seconds>(
                                    std::chrono::system_clock::now().time_since_epoch())
                                    .count()));
    }

    // Store a future and clean up completed ones
    void store_future(std::future<void> future) {
        std::lock_guard<std::mutex> lock(futures_mutex_);
        cleanup_futures_unlocked();
        pending_futures_.push_back(std::move(future));
    }

    // Remove completed futures from the list (must hold futures_mutex_)
    void cleanup_futures_unlocked() {
        pending_futures_.erase(
            std::remove_if(pending_futures_.begin(), pending_futures_.end(),
                           [](std::future<void>& f) {
                               return f.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
                           }),
            pending_futures_.end());
    }

    // Wait for all pending futures to complete
    void wait_for_pending_futures() {
        std::vector<std::future<void>> futures_to_wait;
        {
            std::lock_guard<std::mutex> lock(futures_mutex_);
            futures_to_wait = std::move(pending_futures_);
        }
        for (auto& f : futures_to_wait) {
            if (f.valid()) {
                f.wait();
            }
        }
    }

    // Network recheck timer management
    void start_network_recheck() {
        stop_network_recheck();

        if (config_.network_recheck_interval <= 0) {
            return;
        }

        network_recheck_running_ = true;

        network_recheck_thread_ = std::thread([this]() {
            while (network_recheck_running_) {
                std::unique_lock<std::mutex> lock(network_recheck_mutex_);
                network_recheck_cv_.wait_for(
                    lock, std::chrono::duration<double>(config_.network_recheck_interval),
                    [this]() { return !network_recheck_running_; });

                if (!network_recheck_running_) {
                    break;
                }

                // Check network status by calling health endpoint
                auto result = health_check_unlocked();
                if (result) {
                    // We're back online!
                    is_online_ = true;
                    event_bus_.emit(events::NETWORK_ONLINE, std::map<std::string, std::string>{});

                    // Stop the recheck timer since we're online now
                    network_recheck_running_ = false;

                    auto license_key = reconnect_license_key();
                    if (!license_key.empty()) {
                        auto validation_result = this->validate(license_key, "");
                        if (validation_result.is_ok() && validation_result.value().valid) {
                            this->start_auto_validation(license_key);
                            this->start_heartbeat(license_key);
                            this->start_offline_refresh(license_key);
                        }
                    }
                }
            }
        });
    }

    void stop_network_recheck() {
        network_recheck_running_ = false;
        network_recheck_cv_.notify_all();

        // Always check joinable regardless of running flag (race condition safety)
        if (network_recheck_thread_.joinable()) {
            network_recheck_thread_.join();
        }
    }

    // Offline license refresh timer management
    void start_offline_refresh(const std::string& license_key) {
        stop_offline_refresh();

        if (config_.offline_license_refresh_interval <= 0) {
            return;
        }

        offline_refresh_running_ = true;
        offline_refresh_license_key_ = license_key;

        offline_refresh_thread_ = std::thread([this]() {
            while (offline_refresh_running_) {
                std::unique_lock<std::mutex> lock(offline_refresh_mutex_);
                offline_refresh_cv_.wait_for(
                    lock, std::chrono::duration<double>(config_.offline_license_refresh_interval),
                    [this]() { return !offline_refresh_running_; });

                if (!offline_refresh_running_) {
                    break;
                }

                // Refresh offline assets
                if (!offline_refresh_license_key_.empty()) {
                    sync_offline_assets_impl(offline_refresh_license_key_, device_id_);
                }
            }
        });
    }

    void stop_offline_refresh() {
        offline_refresh_running_ = false;
        offline_refresh_cv_.notify_all();

        // Always check joinable regardless of running flag (race condition safety)
        if (offline_refresh_thread_.joinable()) {
            offline_refresh_thread_.join();
        }
    }

    // Health check without locking (for internal use)
    bool health_check_unlocked() {
        http::Request request;
        request.method = http::Method::GET;
        request.path = "/health";

        auto response = http_client_->send(request);
        return response.success;
    }

    Metadata local_fingerprint_components_for(const std::string& requested_fingerprint) const {
        if (!device_id_auto_generated_ || device_id_ == "unknown-device" ||
            requested_fingerprint != device_id_) {
            return {};
        }

        return device::collect_fingerprint_components();
    }

    Config config_;
    std::string device_id_;
    bool device_id_auto_generated_ = false;
    std::unique_ptr<http::HttpClient> http_client_;
    std::unique_ptr<StorageInterface> storage_;
    std::optional<Activation> current_activation_;
    std::optional<License> cached_license_;
    std::optional<ValidationResult> cached_validation_;
    mutable std::mutex mutex_;

    // Event bus
    EventBus event_bus_;

    // Auto-validation
    std::atomic<bool> auto_validate_running_{false};
    std::thread auto_validate_thread_;
    std::mutex auto_validate_mutex_;
    std::condition_variable auto_validate_cv_;
    std::string current_auto_license_key_;
    std::string current_heartbeat_license_key_;

    // Heartbeat timer
    std::atomic<bool> heartbeat_running_{false};
    std::thread heartbeat_thread_;
    std::mutex heartbeat_mutex_;
    std::condition_variable heartbeat_cv_;

    // Network status
    std::atomic<bool> is_online_{true};

    // Network recheck timer
    std::atomic<bool> network_recheck_running_{false};
    std::thread network_recheck_thread_;
    std::mutex network_recheck_mutex_;
    std::condition_variable network_recheck_cv_;

    // Offline license refresh timer
    std::atomic<bool> offline_refresh_running_{false};
    std::thread offline_refresh_thread_;
    std::mutex offline_refresh_mutex_;
    std::condition_variable offline_refresh_cv_;
    std::string offline_refresh_license_key_;

    // Pending async futures
    std::vector<std::future<void>> pending_futures_;
    std::mutex futures_mutex_;
};

// Client implementation
Client::Client(Config config) : impl_(std::make_unique<Impl>(std::move(config))) {}

Client::~Client() = default;

Client::Client(Client&&) noexcept = default;
Client& Client::operator=(Client&&) noexcept = default;

Result<ValidationResult> Client::validate(const std::string& license_key,
                                          const std::string& device_id) {
    return impl_->validate(license_key, device_id);
}

Result<Activation> Client::activate(const std::string& license_key,
                                    const std::string& device_id,
                                    const std::string& device_name,
                                    const Metadata& metadata) {
    return impl_->activate(license_key, device_id, device_name, metadata);
}

Result<Deactivation> Client::deactivate(const std::string& license_key,
                                        const std::string& device_id) {
    return impl_->deactivate(license_key, device_id);
}

void Client::validate_async(const std::string& license_key, AsyncCallback callback,
                            const std::string& device_id) {
    impl_->validate_async(license_key, std::move(callback), device_id);
}

void Client::activate_async(const std::string& license_key, ActivationCallback callback,
                            const std::string& device_id, const std::string& device_name,
                            const Metadata& metadata) {
    impl_->activate_async(license_key, std::move(callback), device_id, device_name, metadata);
}

void Client::deactivate_async(const std::string& license_key, DeactivationCallback callback,
                              const std::string& device_id) {
    impl_->deactivate_async(license_key, std::move(callback), device_id);
}

Result<HeartbeatResponse> Client::heartbeat(const std::string& license_key,
                                            const std::string& device_id) {
    return impl_->heartbeat(license_key, device_id);
}

void Client::heartbeat_async(const std::string& license_key, HeartbeatCallback callback,
                              const std::string& device_id) {
    impl_->heartbeat_async(license_key, std::move(callback), device_id);
}

Result<OfflineToken> Client::generate_offline_token(const std::string& license_key,
                                                    const std::string& device_id,
                                                    int ttl_days) {
    return impl_->generate_offline_token(license_key, device_id, ttl_days);
}

Result<MachineFile> Client::checkout_machine_file(const std::string& license_key,
                                                  const std::string& device_id,
                                                  int ttl_days) {
    return impl_->checkout_machine_file(license_key, device_id, ttl_days);
}

Result<bool> Client::verify_offline_token(const OfflineToken& offline_token,
                                          const std::string& public_key_b64) {
    return impl_->verify_offline_token(offline_token, public_key_b64);
}

Result<MachineFileVerificationResult> Client::verify_machine_file(
    const MachineFile& machine_file,
    const std::string& public_key_b64,
    const std::string& license_key,
    const std::string& device_id) {
    return impl_->verify_machine_file(machine_file, public_key_b64, license_key, device_id);
}

Result<std::string> Client::fetch_signing_key(const std::string& key_id) {
    return impl_->fetch_signing_key(key_id);
}

void Client::sync_offline_assets() { impl_->sync_offline_assets(); }

void Client::start_auto_validation(const std::string& license_key) {
    impl_->start_auto_validation(license_key);
}

void Client::stop_auto_validation() { impl_->stop_auto_validation(); }

bool Client::is_auto_validating() const { return impl_->is_auto_validating(); }

void Client::start_heartbeat(const std::string& license_key) {
    impl_->start_heartbeat(license_key);
}

void Client::stop_heartbeat() { impl_->stop_heartbeat(); }

bool Client::is_heartbeat_running() const { return impl_->is_heartbeat_running(); }

RestoreResult Client::restore_license() { return impl_->restore_license(); }

void Client::restore_license_async(RestoreCallback callback) {
    impl_->restore_license_async(std::move(callback));
}

ValidationResult Client::get_status() const { return impl_->get_status(); }

std::optional<License> Client::current_license() const { return impl_->current_license(); }

EntitlementStatus Client::check_entitlement(const std::string& entitlement_key) const {
    return impl_->check_entitlement(entitlement_key);
}

bool Client::is_online() const { return impl_->is_online(); }

ClientStatus Client::get_client_status() const { return impl_->get_client_status(); }

Subscription Client::on(const std::string& event, EventHandler handler) {
    return impl_->on(event, std::move(handler));
}

void Client::emit(const std::string& event, const std::any& data) { impl_->emit(event, data); }

Result<Release> Client::get_latest_release(const std::string& product_slug,
                                           const std::string& channel,
                                           const std::string& platform) {
    return impl_->get_latest_release(product_slug, channel, platform);
}

Result<std::vector<Release>> Client::list_releases(const std::string& product_slug,
                                                   const std::string& channel,
                                                   const std::string& platform) {
    return impl_->list_releases(product_slug, channel, platform);
}

Result<DownloadToken> Client::generate_download_token(const std::string& version,
                                                      const std::string& license_key,
                                                      const std::string& product_slug,
                                                      const std::string& platform) {
    return impl_->generate_download_token(version, license_key, product_slug, platform);
}

Result<bool> Client::health() { return impl_->health(); }

void Client::reset() { impl_->reset(); }

const Config& Client::config() const noexcept { return impl_->config(); }

const std::string& Client::device_id() const { return impl_->device_id(); }

const std::string& Client::fingerprint() const { return impl_->fingerprint(); }

}  // namespace licenseseat
