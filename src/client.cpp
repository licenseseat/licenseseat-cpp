#include "licenseseat/crypto.hpp"
#include "licenseseat/device.hpp"
#include "licenseseat/events.hpp"
#include "licenseseat/http.hpp"
#include "licenseseat/json.hpp"
#include "licenseseat/licenseseat.hpp"
#include "licenseseat/storage.hpp"
#include "licenseseat/telemetry.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <unordered_map>

namespace licenseseat {

namespace {

bool is_safe_text(const std::string& value, std::size_t maximum) {
    if (value.empty() || value.size() > maximum)
        return false;
    return std::none_of(value.begin(), value.end(), [](unsigned char character) {
        return character < 0x20 || character > 0x7e;
    });
}

bool is_valid_utf8(std::string_view value) {
    std::size_t index = 0;
    while (index < value.size()) {
        const auto first = static_cast<unsigned char>(value[index]);
        if (first <= 0x7f) {
            ++index;
            continue;
        }

        std::size_t continuation_count = 0;
        std::uint32_t code_point = 0;
        std::uint32_t minimum = 0;
        if (first >= 0xc2 && first <= 0xdf) {
            continuation_count = 1;
            code_point = first & 0x1f;
            minimum = 0x80;
        } else if (first >= 0xe0 && first <= 0xef) {
            continuation_count = 2;
            code_point = first & 0x0f;
            minimum = 0x800;
        } else if (first >= 0xf0 && first <= 0xf4) {
            continuation_count = 3;
            code_point = first & 0x07;
            minimum = 0x10000;
        } else {
            return false;
        }

        if (continuation_count > value.size() - index - 1)
            return false;
        for (std::size_t offset = 1; offset <= continuation_count; ++offset) {
            const auto continuation = static_cast<unsigned char>(value[index + offset]);
            if ((continuation & 0xc0) != 0x80)
                return false;
            code_point = (code_point << 6) | (continuation & 0x3f);
        }
        if (code_point < minimum || code_point > 0x10ffff ||
            (code_point >= 0xd800 && code_point <= 0xdfff) ||
            (code_point >= 0x80 && code_point <= 0x9f)) {
            return false;
        }
        index += continuation_count + 1;
    }
    return true;
}

bool is_safe_user_text(const std::string& value, std::size_t maximum, bool allow_empty = false) {
    if ((!allow_empty && value.empty()) || value.size() > maximum || !is_valid_utf8(value))
        return false;
    return std::none_of(value.begin(), value.end(), [](unsigned char character) {
        return character < 0x20 || character == 0x7f;
    });
}

bool is_safe_metadata(const Metadata& metadata) {
    if (metadata.size() > 100)
        return false;
    std::size_t total_bytes = 0;
    for (const auto& [key, value] : metadata) {
        if (!is_safe_user_text(key, 100) || !is_safe_user_text(value, 16 * 1024, true) ||
            key.size() > 512 * 1024 - total_bytes ||
            value.size() > 512 * 1024 - total_bytes - key.size()) {
            return false;
        }
        total_bytes += key.size() + value.size();
    }
    return true;
}

std::string encode_url_component(const std::string& value) {
    static constexpr char HEX[] = "0123456789ABCDEF";
    std::string encoded;
    encoded.reserve(value.size());
    for (unsigned char character : value) {
        if ((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
            (character >= '0' && character <= '9') || character == '-' || character == '_' ||
            character == '.' || character == '~') {
            encoded.push_back(static_cast<char>(character));
        } else {
            encoded.push_back('%');
            encoded.push_back(HEX[character >> 4]);
            encoded.push_back(HEX[character & 0x0f]);
        }
    }
    return encoded;
}

bool is_valid_ed25519_public_key(const std::string& encoded) {
    auto decoded = crypto::base64_decode(encoded);
    if (decoded.size() != 32)
        decoded = crypto::base64url_decode(encoded);
    return decoded.size() == 32;
}

bool valid_release_response(const Release& release, const std::string& expected_product,
                            const std::string& expected_channel,
                            const std::string& expected_platform) {
    return is_safe_text(release.version, 100) && is_safe_text(release.channel, 100) &&
           is_safe_text(release.platform, 100) && release.product_slug == expected_product &&
           release.published_at.has_value() &&
           (expected_channel.empty() || release.channel == expected_channel) &&
           (expected_platform.empty() || release.platform == expected_platform);
}

constexpr double MAX_TIMER_INTERVAL_SECONDS = 366.0 * 24.0 * 60.0 * 60.0;
constexpr double MAX_CLOCK_SKEW_MS = 24.0 * 60.0 * 60.0 * 1000.0;
constexpr int MAX_OFFLINE_DAYS = 36600;

bool valid_timer_interval(double seconds) {
    return std::isfinite(seconds) && seconds >= 0.0 && seconds <= MAX_TIMER_INTERVAL_SECONDS;
}

struct WorkerSignal final {
    std::atomic<bool> running{true};
    std::mutex mutex;
    std::condition_variable cv;

    bool stop() {
        bool was_running = false;
        {
            // Coordinate the predicate transition with wait_for's mutex so a
            // stop cannot land between its predicate check and sleeping.
            std::lock_guard<std::mutex> lock(mutex);
            was_running = running.exchange(false);
        }
        cv.notify_all();
        return was_running;
    }
};

thread_local const void* auto_validation_worker_owner = nullptr;
thread_local const void* heartbeat_worker_owner = nullptr;
thread_local const void* network_recheck_worker_owner = nullptr;
thread_local const void* offline_refresh_worker_owner = nullptr;
thread_local WorkerSignal* auto_validation_worker_signal = nullptr;
thread_local WorkerSignal* heartbeat_worker_signal = nullptr;
thread_local WorkerSignal* network_recheck_worker_signal = nullptr;
thread_local WorkerSignal* offline_refresh_worker_signal = nullptr;
thread_local const void* async_worker_owner = nullptr;
thread_local std::uint64_t async_worker_id = 0;

class WorkerOwnerScope final {
  public:
    WorkerOwnerScope(const void*& owner_slot, WorkerSignal*& signal_slot, const void* owner,
                     WorkerSignal* signal)
        : owner_slot_(owner_slot), signal_slot_(signal_slot) {
        owner_slot_ = owner;
        signal_slot_ = signal;
    }
    WorkerOwnerScope(const WorkerOwnerScope&) = delete;
    WorkerOwnerScope& operator=(const WorkerOwnerScope&) = delete;
    ~WorkerOwnerScope() {
        signal_slot_ = nullptr;
        owner_slot_ = nullptr;
    }

  private:
    const void*& owner_slot_;
    WorkerSignal*& signal_slot_;
};

class AsyncOwnerScope final {
  public:
    AsyncOwnerScope(const void* owner, std::uint64_t id) {
        async_worker_owner = owner;
        async_worker_id = id;
    }
    AsyncOwnerScope(const AsyncOwnerScope&) = delete;
    AsyncOwnerScope& operator=(const AsyncOwnerScope&) = delete;
    ~AsyncOwnerScope() {
        async_worker_id = 0;
        async_worker_owner = nullptr;
    }
};

} // namespace

// PIMPL implementation
class Client::Impl : public std::enable_shared_from_this<Client::Impl> {
  public:
    explicit Impl(Config config) : config_(std::move(config)) {
        // Auto-generate device ID if not provided
        if (config_.device_id.empty()) {
            device_id_auto_generated_ = true;
            device_id_ = device::generate_device_id();
        } else {
            device_id_ = config_.device_id;
        }

        // Initialize HTTP client
        http::HttpClient::Config http_config;
        http_config.base_url = config_.api_url;
        http_config.api_key = config_.api_key;
        http_config.timeout_seconds = config_.timeout_seconds;
        http_config.verify_ssl = config_.verify_ssl;
        http_config.allow_insecure_http = config_.allow_insecure_http;
        http_config.max_retries = config_.max_retries;
        http_config.retry_interval_ms = config_.retry_interval_ms;
        http_config.max_request_bytes = config_.max_request_bytes;
        http_config.max_response_bytes = config_.max_response_bytes;

        http_client_ = std::make_unique<http::HttpClient>(std::move(http_config));

        // Initialize storage
        if (!config_.storage_path.empty()) {
            storage_ = std::make_unique<FileStorage>(config_.storage_path, config_.storage_prefix);

            // Discover cached state, but do not expose it as authority until
            // restore_license() verifies it online or cryptographically.
            auto cached = storage_->get_license();
            if (cached) {
                event_bus_.emit(events::LICENSE_LOADED, *cached);
            }
        } else {
            storage_ = std::make_unique<MemoryStorage>();
        }
    }

    ~Impl() { shutdown(); }

    void shutdown() {
        bool expected = false;
        if (!shutdown_started_.compare_exchange_strong(expected, true))
            return;

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

    struct PendingFuture {
        std::uint64_t id = 0;
        std::future<void> future;
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

        if (!is_safe_text(license_key, 512)) {
            context.error_code = ErrorCode::InvalidLicenseKey;
            context.error_message = "License key is empty or invalid";
            return context;
        }

        if (!is_safe_text(config_.product_slug, 100)) {
            context.error_code = ErrorCode::MissingParameter;
            context.error_message = "Product slug is missing or invalid in config";
            return context;
        }

        if (config_.api_key.empty() || !http_client_->is_configured()) {
            context.error_code = ErrorCode::InvalidParameter;
            context.error_message = "API client configuration is invalid";
            return context;
        }

        context.product_slug = config_.product_slug;
        context.fingerprint = fallback_to_client_fingerprint
                                  ? resolve_fingerprint_unlocked(fingerprint_override)
                                  : fingerprint_override;

        if ((require_fingerprint && context.fingerprint.empty()) ||
            (!context.fingerprint.empty() && !is_safe_text(context.fingerprint, 255))) {
            context.error_code = ErrorCode::MissingParameter;
            context.error_message = context.fingerprint.empty() ? missing_fingerprint_message
                                                                : "Fingerprint is invalid";
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
        body["license_key"] = license_key;
        auto response = send_post("/products/" + encode_url_component(request.product_slug) +
                                      "/licenses/validate",
                                  body, true);

        if (!response.success) {
            // Check for authentication failure (401) - emit auth-failed event (matches Swift SDK)
            if (response.status_code == 401 || response.status_code == 403) {
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
                event_bus_.emit(events::LICENSE_REVOKED, std::map<std::string, std::string>{
                                                             {"reason", err.error_message()}});
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
            auto j = json::parse_strict(response.body);
            if (!j.is_object() || j.value("object", std::string{}) != "validation_result" ||
                !j.contains("valid") || !j["valid"].is_boolean()) {
                throw std::invalid_argument("Validation response has an invalid schema");
            }
            auto result = json::parse_validation_result(j);
            if (result.valid) {
                if (!constant_time_equal(result.license.key(), license_key) ||
                    result.license.product().slug != request.product_slug ||
                    result.license.status() != LicenseStatus::Active ||
                    result.license.mode() == LicenseMode::Unknown ||
                    result.license.plan_key().empty() || !result.license.is_valid() ||
                    (result.activation.has_value() &&
                     (!constant_time_equal(result.activation->license_key(), license_key) ||
                      !constant_time_equal(result.activation->fingerprint(), request.fingerprint) ||
                      !result.activation->is_active()))) {
                    throw std::invalid_argument("Validation response identity is inconsistent");
                }
            } else if (!is_safe_text(result.code, 100)) {
                throw std::invalid_argument("Invalid validation response is missing a safe code");
            }

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
                if (result.valid)
                    cached_license_ = result.license;
                else
                    cached_license_.reset();
            }

            if (result.valid) {
                update_storage_license(license_key, request.fingerprint, result);
                event_bus_.emit(events::VALIDATION_SUCCESS, result);
            } else {
                event_bus_.emit(events::VALIDATION_FAILED, result);
            }

            return Result<ValidationResult>::ok(std::move(result));
        } catch (const std::exception& e) {
            return Result<ValidationResult>::error(
                ErrorCode::ParseError, std::string("Failed to parse response: ") + e.what());
        }
    }

    Result<Activation> activate(const std::string& license_key, const std::string& device_id_param,
                                const std::string& device_name, const Metadata& metadata) {
        auto request = prepare_license_request_context(license_key, device_id_param, true, false,
                                                       true, "Device ID is required");
        if (!request.ok) {
            return request_context_error<Activation>(request);
        }
        if (!is_safe_user_text(device_name, 255, true)) {
            return Result<Activation>::error(ErrorCode::InvalidParameter,
                                             "Device name is invalid or too long");
        }
        if (!is_safe_metadata(metadata)) {
            return Result<Activation>::error(ErrorCode::InvalidParameter,
                                             "Metadata is invalid or too large");
        }

        event_bus_.emit(events::ACTIVATION_START,
                        std::map<std::string, std::string>{{"license_key", license_key},
                                                           {"device_id", request.fingerprint}});

        // Make HTTP call without holding mutex
        auto body = json::build_activate_request(request.fingerprint, device_name, metadata);
        body["license_key"] = license_key;
        auto response = send_post(
            "/products/" + encode_url_component(request.product_slug) + "/licenses/activate", body);

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
            auto j = json::parse_strict(response.body);
            if (!j.is_object() || j.value("object", std::string{}) != "activation") {
                throw std::invalid_argument("Activation response has an invalid object type");
            }
            auto activation = json::parse_activation(j);
            if (activation.id().empty() ||
                !constant_time_equal(activation.license_key(), license_key) ||
                !constant_time_equal(activation.fingerprint(), request.fingerprint) ||
                !activation.is_active() || activation.activated_at() == Timestamp{}) {
                throw std::invalid_argument("Activation response identity is inconsistent");
            }

            // Update state with mutex
            {
                std::lock_guard<std::mutex> lock(mutex_);
                current_activation_ = activation;
            }

            event_bus_.emit(events::ACTIVATION_SUCCESS, activation);

            // Sync offline assets AFTER releasing the lock to avoid deadlock
            sync_offline_assets_impl(license_key, request.fingerprint);

            return Result<Activation>::ok(std::move(activation));
        } catch (const std::exception& e) {
            return Result<Activation>::error(ErrorCode::ParseError,
                                             std::string("Failed to parse response: ") + e.what());
        }
    }

    Result<Deactivation> deactivate(const std::string& license_key, const std::string& device_id) {
        auto request = prepare_license_request_context(license_key, device_id, true, false, false,
                                                       "Device ID is required");
        if (!request.ok) {
            return request_context_error<Deactivation>(request);
        }

        event_bus_.emit(events::DEACTIVATION_START,
                        std::map<std::string, std::string>{{"license_key", license_key}});

        // Make HTTP call without holding mutex
        auto body = json::build_deactivate_request(request.fingerprint);
        body["license_key"] = license_key;
        auto response = send_post("/products/" + encode_url_component(request.product_slug) +
                                      "/licenses/deactivate",
                                  body);

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
            auto j = json::parse_strict(response.body);
            if (!j.is_object() || j.value("object", std::string{}) != "deactivation") {
                throw std::invalid_argument("Deactivation response has an invalid object type");
            }
            auto deactivation = json::parse_deactivation(j);
            if (deactivation.activation_id.empty() || deactivation.deactivated_at == Timestamp{}) {
                throw std::invalid_argument("Deactivation response is incomplete");
            }

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
        } catch (const std::exception& e) {
            return Result<Deactivation>::error(
                ErrorCode::ParseError, std::string("Failed to parse response: ") + e.what());
        }
    }

    // ========== Async API ==========

    template <typename Operation> void launch_async(Operation&& operation) {
        if (shutdown_started_.load())
            return;
        // Hold the registry lock until the future has been stored. A very fast
        // callback may destroy its Client, and shutdown must see this job before
        // it decides which futures to wait for or hand to a reaper.
        std::lock_guard<std::mutex> lock(futures_mutex_);
        if (shutdown_started_.load())
            return;
        cleanup_futures_unlocked();
        pending_futures_.reserve(pending_futures_.size() + 1);

        const auto id = ++next_async_job_id_;
        auto self = shared_from_this();
        auto future = std::async(
            std::launch::async,
            [self = std::move(self), id, operation = std::forward<Operation>(operation)]() mutable {
                AsyncOwnerScope owner_scope(self.get(), id);
                operation(*self);
            });
        pending_futures_.push_back(PendingFuture{id, std::move(future)});
    }

    void validate_async(const std::string& license_key, AsyncCallback callback,
                        const std::string& device_id) {
        launch_async([license_key, callback = std::move(callback), device_id](Impl& self) mutable {
            auto result = self.validate(license_key, device_id);
            if (callback) {
                callback(std::move(result));
            }
        });
    }

    void activate_async(const std::string& license_key, ActivationCallback callback,
                        const std::string& device_id, const std::string& device_name,
                        const Metadata& metadata) {
        launch_async([license_key, callback = std::move(callback), device_id, device_name,
                      metadata](Impl& self) mutable {
            auto result = self.activate(license_key, device_id, device_name, metadata);
            if (callback)
                callback(std::move(result));
        });
    }

    void deactivate_async(const std::string& license_key, DeactivationCallback callback,
                          const std::string& device_id) {
        launch_async([license_key, callback = std::move(callback), device_id](Impl& self) mutable {
            auto result = self.deactivate(license_key, device_id);
            if (callback)
                callback(std::move(result));
        });
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
        body["license_key"] = license_key;
        auto response = send_post("/products/" + encode_url_component(request.product_slug) +
                                      "/licenses/heartbeat",
                                  body);

        if (!response.success) {
            if (response.error_message.empty()) {
                auto err = handle_error_response<HeartbeatResponse>(response);
                event_bus_.emit(events::HEARTBEAT_ERROR,
                                std::map<std::string, std::string>{{"error", err.error_message()}});
                return err;
            }
            event_bus_.emit(events::HEARTBEAT_ERROR,
                            std::map<std::string, std::string>{{"error", response.error_message}});
            return Result<HeartbeatResponse>::error(ErrorCode::NetworkError,
                                                    response.error_message);
        }

        try {
            auto j = json::parse_strict(response.body);
            HeartbeatResponse result;
            result.object = j.value("object", "");
            result.received_at = j.value("received_at", "");
            if (!j.is_object() || result.object != "heartbeat" ||
                !json::parse_timestamp(result.received_at).has_value()) {
                throw std::invalid_argument("Heartbeat response has an invalid schema");
            }
            event_bus_.emit(events::HEARTBEAT_SUCCESS, result);
            return Result<HeartbeatResponse>::ok(std::move(result));
        } catch (const std::exception& e) {
            return Result<HeartbeatResponse>::error(
                ErrorCode::ParseError, std::string("Failed to parse response: ") + e.what());
        }
    }

    void heartbeat_async(const std::string& license_key, HeartbeatCallback callback,
                         const std::string& device_id) {
        launch_async([license_key, callback = std::move(callback), device_id](Impl& self) mutable {
            auto result = self.heartbeat(license_key, device_id);
            if (callback)
                callback(std::move(result));
        });
    }

    // ========== Offline Tokens ==========

    Result<OfflineToken> generate_offline_token(const std::string& license_key,
                                                const std::string& device_id_param, int ttl_days) {
        if (ttl_days < 0 || ttl_days > 36500) {
            return Result<OfflineToken>::error(ErrorCode::InvalidParameter,
                                               "Offline token TTL is invalid");
        }
        auto request = prepare_license_request_context(license_key, device_id_param);
        if (!request.ok) {
            return request_context_error<OfflineToken>(request);
        }

        // Make HTTP call without holding mutex
        auto body = json::build_offline_token_request(request.fingerprint, ttl_days);
        body["license_key"] = license_key;
        auto response = send_post("/products/" + encode_url_component(request.product_slug) +
                                      "/licenses/offline-token",
                                  body);

        if (!response.success) {
            if (response.error_message.empty()) {
                return handle_error_response<OfflineToken>(response);
            }
            return Result<OfflineToken>::error(ErrorCode::NetworkError, response.error_message);
        }

        // Parse response
        try {
            auto j = json::parse_strict(response.body);
            if (!j.is_object() || j.value("object", std::string{}) != "offline_token") {
                return Result<OfflineToken>::error(
                    ErrorCode::ParseError, "Offline-token response has an invalid object type");
            }
            auto offline = json::parse_offline_token(j);
            if (!constant_time_equal(offline.token.license_key, license_key) ||
                offline.token.product_slug != request.product_slug ||
                !offline.token.fingerprint.has_value() ||
                !constant_time_equal(*offline.token.fingerprint, request.fingerprint)) {
                return Result<OfflineToken>::error(
                    ErrorCode::InvalidSignature,
                    "Offline-token response identity does not match the request");
            }
            auto public_key = resolve_signing_key(offline.signature.key_id, "", true);
            if (public_key.empty()) {
                return Result<OfflineToken>::error(ErrorCode::MissingParameter,
                                                   "Unable to establish a trusted signing key");
            }
            auto verification = crypto::verify_offline_token_signature(offline, public_key);
            if (!verification.is_ok() || !verification.value()) {
                return Result<OfflineToken>::error(
                    verification.is_ok() ? ErrorCode::InvalidSignature : verification.error_code(),
                    verification.is_ok() ? "Offline-token signature is invalid"
                                         : verification.error_message());
            }

            if (constant_time_equal(request.fingerprint, device_id_)) {
                storage_->set_offline_token(offline);
            }

            event_bus_.emit(events::OFFLINE_TOKEN_READY, offline);

            return Result<OfflineToken>::ok(std::move(offline));
        } catch (const std::exception& e) {
            return Result<OfflineToken>::error(
                ErrorCode::ParseError, std::string("Failed to parse response: ") + e.what());
        }
    }

    Result<MachineFile> checkout_machine_file(const std::string& license_key,
                                              const std::string& device_id_param, int ttl_days) {
        if (ttl_days < 0 || ttl_days > 36500) {
            return Result<MachineFile>::error(ErrorCode::InvalidParameter,
                                              "Machine-file TTL is invalid");
        }
        auto request = prepare_license_request_context(license_key, device_id_param, true, false,
                                                       true, "Fingerprint is required");
        if (!request.ok) {
            return request_context_error<MachineFile>(request);
        }

        event_bus_.emit(events::MACHINE_FILE_FETCHING,
                        std::map<std::string, std::string>{{"licenseKey", license_key},
                                                           {"fingerprint", request.fingerprint}});

        const auto fingerprint_components = local_fingerprint_components_for(request.fingerprint);
        auto body =
            json::build_machine_file_request(request.fingerprint, ttl_days, fingerprint_components);
        body["license_key"] = license_key;
        auto response = send_post("/products/" + encode_url_component(request.product_slug) +
                                      "/licenses/machine-file",
                                  body);

        if (!response.success) {
            if (response.error_message.empty()) {
                auto err = handle_error_response<MachineFile>(response);
                event_bus_.emit(
                    events::MACHINE_FILE_FETCH_ERROR,
                    std::map<std::string, std::string>{{"licenseKey", license_key},
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
            auto j = json::parse_strict(response.body);
            if (!j.is_object() || j.size() != 1 || !j.contains("data") || !j["data"].is_object() ||
                j["data"].value("type", std::string{}) != "machine-files" ||
                !j["data"].contains("attributes") || !j["data"]["attributes"].is_object() ||
                !j["data"].contains("relationships") || !j["data"]["relationships"].is_object()) {
                throw std::invalid_argument("Machine-file response has an invalid schema");
            }
            auto machine_file = json::parse_machine_file(j);
            if (machine_file.certificate.empty() ||
                machine_file.certificate.size() > 2 * json::MAX_JSON_BYTES ||
                machine_file.algorithm != "aes-256-gcm+ed25519" || machine_file.ttl <= 0 ||
                machine_file.ttl > 100LL * 366 * 24 * 60 * 60 ||
                !machine_file.issued_at.has_value() || !machine_file.expires_at.has_value() ||
                *machine_file.expires_at <= *machine_file.issued_at ||
                machine_file.license_key.empty() ||
                !constant_time_equal(machine_file.license_key, license_key) ||
                machine_file.fingerprint.empty() ||
                !constant_time_equal(machine_file.fingerprint, request.fingerprint)) {
                return Result<MachineFile>::error(ErrorCode::InvalidSignature,
                                                  "Machine-file response identity is invalid");
            }

            auto key_id = extract_machine_file_key_id(machine_file);
            auto public_key = resolve_signing_key(key_id, "", true);
            if (!key_id.has_value() || public_key.empty()) {
                return Result<MachineFile>::error(ErrorCode::MissingParameter,
                                                  "Unable to establish a trusted signing key");
            }
            auto verification = crypto::verify_machine_file(machine_file, license_key,
                                                            request.fingerprint, public_key);
            if (!verification.is_ok()) {
                return Result<MachineFile>::error(verification.error_code(),
                                                  verification.error_message());
            }
            if (constant_time_equal(request.fingerprint, device_id_)) {
                storage_->set_machine_file(machine_file);
            }

            event_bus_.emit(events::MACHINE_FILE_FETCHED, machine_file);
            event_bus_.emit(events::MACHINE_FILE_READY, machine_file);
            return Result<MachineFile>::ok(std::move(machine_file));
        } catch (const std::exception& e) {
            event_bus_.emit(events::MACHINE_FILE_FETCH_ERROR,
                            std::map<std::string, std::string>{{"licenseKey", license_key},
                                                               {"fingerprint", request.fingerprint},
                                                               {"error", e.what()}});
            return Result<MachineFile>::error(ErrorCode::ParseError,
                                              std::string("Failed to parse response: ") + e.what());
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
            return Result<bool>::error(ErrorCode::LicenseNotStarted,
                                       "Offline token is not yet valid");
        }

        const auto token_fingerprint = offline_token.token.fingerprint.has_value()
                                           ? *offline_token.token.fingerprint
                                           : offline_token.token.device_id.value_or("");
        if (!token_fingerprint.empty() && !constant_time_equal(token_fingerprint, device_id_)) {
            return Result<bool>::error(ErrorCode::FingerprintMismatch,
                                       "Offline token fingerprint does not match this device");
        }

        if (offline_token.is_license_expired()) {
            return Result<bool>::error(ErrorCode::LicenseExpired, "Underlying license has expired");
        }

        // Local storage is attacker-writable and cannot establish signing
        // authority. Use a caller/configuration pin or a key fetched over the
        // authenticated transport during this process.
        auto key_to_use =
            resolve_signing_key(offline_token.signature.key_id, public_key_b64, false);

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
                ErrorCode::MissingParameter, "Public key required for machine file verification");
        }

        auto crypto_result = crypto::verify_machine_file(machine_file, resolved_license_key,
                                                         resolved_fingerprint, public_key);

        MachineFileVerificationResult result;
        if (crypto_result.is_error()) {
            result.valid = false;
            result.code = offline_error_code_string(crypto_result.error_code());
            result.message = crypto_result.error_message();
            event_bus_.emit(
                events::MACHINE_FILE_VERIFICATION_FAILED,
                std::map<std::string, std::string>{{"fingerprint", resolved_fingerprint},
                                                   {"licenseKey", resolved_license_key},
                                                   {"code", result.code},
                                                   {"error", result.message}});
            return Result<MachineFileVerificationResult>::ok(std::move(result));
        }

        if (crypto_result.value().product_slug != config_.product_slug) {
            result.valid = false;
            result.code = "product_mismatch";
            result.message = "Machine file belongs to a different product";
            return Result<MachineFileVerificationResult>::ok(std::move(result));
        }

        result.valid = true;
        result.payload = std::move(crypto_result.value());
        event_bus_.emit(events::MACHINE_FILE_VERIFIED, *result.payload);

        return Result<MachineFileVerificationResult>::ok(std::move(result));
    }

    Result<std::string> fetch_signing_key(const std::string& key_id) {
        // Validate input without holding mutex for long
        if (!is_safe_text(key_id, 255)) {
            return Result<std::string>::error(ErrorCode::MissingParameter, "Key ID is required");
        }

        // Make HTTP call without holding mutex
        http::Request request;
        request.method = http::Method::GET;
        request.path = "/signing_keys/" + encode_url_component(key_id);
        request.authenticated = false;
        request.retryable = true;

        auto response = http_client_->send(request);

        if (!response.success) {
            if (response.error_message.empty()) {
                return handle_error_response<std::string>(response);
            }
            return Result<std::string>::error(ErrorCode::NetworkError, response.error_message);
        }

        // Parse response
        try {
            auto j = json::parse_strict(response.body);
            if (!j.is_object() || j.value("object", std::string{}) != "signing_key" ||
                j.value("key_id", std::string{}) != key_id ||
                j.value("algorithm", std::string{}) != "Ed25519" ||
                j.value("status", std::string{}) != "active") {
                return Result<std::string>::error(ErrorCode::ParseError,
                                                  "Signing-key response has an invalid identity");
            }
            auto key = json::parse_signing_key(j);
            if (!is_valid_ed25519_public_key(key)) {
                return Result<std::string>::error(ErrorCode::ParseError,
                                                  "Signing-key response contains an invalid key");
            }

            {
                std::lock_guard<std::mutex> lock(mutex_);
                const auto existing = trusted_signing_keys_.find(key_id);
                if (existing != trusted_signing_keys_.end() && existing->second != key) {
                    return Result<std::string>::error(ErrorCode::InvalidSignature,
                                                      "Signing key changed for an existing key ID");
                }
                trusted_signing_keys_[key_id] = key;
            }

            return Result<std::string>::ok(std::move(key));
        } catch (const std::exception& e) {
            return Result<std::string>::error(ErrorCode::ParseError,
                                              std::string("Failed to parse response: ") + e.what());
        }
    }

    void sync_offline_assets() {
        if (!offline_policy_is_enabled())
            return;

        std::string license_key;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!cached_license_)
                return;
            license_key = cached_license_->key();
        }
        launch_async([license_key](Impl& self) {
            self.sync_offline_assets_impl(license_key, self.device_id_);
        });
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
        const std::string device_id = device_id_;

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
                result.message = validation_result.is_ok() ? validation_result.value().message
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
                result.license = offline_result.value().license;
                result.message = "License restored from offline cache";

                // Update cached state
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    cached_license_ = offline_result.value().license;
                    cached_validation_ = offline_result.value();
                }

                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    current_auto_license_key_ = license_key;
                    current_heartbeat_license_key_ = license_key;
                    offline_refresh_license_key_ = license_key;
                }

                // Start network recheck to detect when we come back online
                start_network_recheck();
            } else {
                result.success = false;
                // Use OfflineInvalid (not Invalid) for offline failures (matches Swift SDK)
                result.status = ClientStatus::OfflineInvalid;
                result.message = offline_result.is_ok()
                                     ? "Offline verification failed: " + offline_result.value().code
                                     : offline_result.error_message();

                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    current_auto_license_key_ = license_key;
                    current_heartbeat_license_key_ = license_key;
                    offline_refresh_license_key_ = license_key;
                }

                // Start network recheck to detect when we come back online
                start_network_recheck();
            }
            return result;
        }
    }

    void restore_license_async(RestoreCallback callback) {
        launch_async([callback = std::move(callback)](Impl& self) mutable {
            auto result = self.restore_license();
            if (callback)
                callback(std::move(result));
        });
    }

    // ========== Auto-Validation ==========

    void start_auto_validation(const std::string& license_key) {
        if (shutdown_started_.load())
            return;
        if (auto_validation_worker_owner == this) {
            stop_auto_validation();
            return;
        }

        std::thread retired_worker;
        std::uint64_t operation = 0;
        {
            std::lock_guard<std::mutex> lifecycle_lock(auto_validate_lifecycle_mutex_);
            operation = ++auto_validate_operation_;
            auto signal = std::atomic_load(&auto_validate_signal_);
            if (signal)
                signal->stop();
            std::atomic_store(&auto_validate_signal_, std::shared_ptr<WorkerSignal>{});
            if (auto_validate_thread_.joinable()) {
                retired_worker = std::move(auto_validate_thread_);
            }
        }
        if (retired_worker.joinable())
            retired_worker.join();

        std::lock_guard<std::mutex> lifecycle_lock(auto_validate_lifecycle_mutex_);
        if (shutdown_started_.load() || operation != auto_validate_operation_ ||
            !valid_timer_interval(config_.auto_validate_interval) ||
            config_.auto_validate_interval == 0.0 || !is_safe_text(license_key, 512)) {
            return;
        }

        auto signal = std::make_shared<WorkerSignal>();
        std::atomic_store(&auto_validate_signal_, signal);
        {
            std::lock_guard<std::mutex> lock(mutex_);
            current_auto_license_key_ = license_key;
        }

        try {
            auto self = shared_from_this();
            auto_validate_thread_ = std::thread([self = std::move(self), license_key, signal]() {
                WorkerOwnerScope worker_scope(auto_validation_worker_owner,
                                              auto_validation_worker_signal, self.get(),
                                              signal.get());
                // Emit first cycle information immediately (matches Swift SDK)
                auto next_run = std::chrono::system_clock::now() +
                                std::chrono::duration<double>(self->config_.auto_validate_interval);
                auto next_run_unix =
                    std::chrono::duration_cast<std::chrono::seconds>(next_run.time_since_epoch())
                        .count();
                self->event_bus_.emit(events::AUTOVALIDATION_CYCLE,
                                      std::map<std::string, std::string>{
                                          {"license_key", license_key},
                                          {"nextRunAt", std::to_string(next_run_unix)}});

                while (signal->running) {
                    std::unique_lock<std::mutex> lock(signal->mutex);
                    signal->cv.wait_for(
                        lock, std::chrono::duration<double>(self->config_.auto_validate_interval),
                        [signal]() { return !signal->running; });

                    if (!signal->running)
                        break;
                    lock.unlock();

                    // Perform validation
                    auto result = self->validate(license_key, "");

                    // Event handlers invoked by validate may stop the worker or
                    // destroy the public Client. Do not perform another request
                    // after shutdown has been requested.
                    if (!signal->running)
                        break;

                    // Emit validation:auto-failed on error (matches Swift SDK)
                    if (result.is_error() || (result.is_ok() && !result.value().valid)) {
                        self->event_bus_.emit(
                            events::VALIDATION_AUTO_FAILED,
                            std::map<std::string, std::string>{
                                {"licenseKey", license_key},
                                {"error", result.is_error() ? result.error_message()
                                                            : result.value().code}});
                    }

                    // Piggyback heartbeat (fire-and-forget, ignore errors)
                    (void)self->heartbeat(license_key, "");

                    // Announce next scheduled run (matches Swift SDK)
                    if (signal->running) {
                        auto next =
                            std::chrono::system_clock::now() +
                            std::chrono::duration<double>(self->config_.auto_validate_interval);
                        auto next_unix = std::chrono::duration_cast<std::chrono::seconds>(
                                             next.time_since_epoch())
                                             .count();
                        self->event_bus_.emit(events::AUTOVALIDATION_CYCLE,
                                              std::map<std::string, std::string>{
                                                  {"license_key", license_key},
                                                  {"nextRunAt", std::to_string(next_unix)}});
                    }
                }
            });
        } catch (...) {
            signal->stop();
            std::atomic_store(&auto_validate_signal_, std::shared_ptr<WorkerSignal>{});
            throw;
        }
    }

    void stop_auto_validation() {
        if (auto_validation_worker_owner == this) {
            bool was_running =
                auto_validation_worker_signal ? auto_validation_worker_signal->stop() : false;
            {
                std::lock_guard<std::mutex> lifecycle_lock(auto_validate_lifecycle_mutex_);
                ++auto_validate_operation_;
                auto current = std::atomic_load(&auto_validate_signal_);
                if (current.get() == auto_validation_worker_signal) {
                    std::atomic_store(&auto_validate_signal_, std::shared_ptr<WorkerSignal>{});
                }
                if (auto_validate_thread_.joinable() &&
                    auto_validate_thread_.get_id() == std::this_thread::get_id()) {
                    auto_validate_thread_.detach();
                }
            }
            if (was_running) {
                event_bus_.emit(events::AUTOVALIDATION_STOPPED,
                                std::map<std::string, std::string>{});
            }
            return;
        }

        bool was_running = false;
        std::thread retired_worker;
        {
            std::lock_guard<std::mutex> lifecycle_lock(auto_validate_lifecycle_mutex_);
            ++auto_validate_operation_;
            auto signal = std::atomic_load(&auto_validate_signal_);
            was_running = signal ? signal->stop() : false;
            std::atomic_store(&auto_validate_signal_, std::shared_ptr<WorkerSignal>{});
            if (auto_validate_thread_.joinable()) {
                retired_worker = std::move(auto_validate_thread_);
            }
        }
        if (retired_worker.joinable())
            retired_worker.join();

        if (was_running) {
            event_bus_.emit(events::AUTOVALIDATION_STOPPED, std::map<std::string, std::string>{});
        }
    }

    bool is_auto_validating() const {
        auto signal = std::atomic_load(&auto_validate_signal_);
        return signal && signal->running;
    }

    // ========== Heartbeat Timer ==========

    void start_heartbeat(const std::string& license_key) {
        if (shutdown_started_.load())
            return;
        if (heartbeat_worker_owner == this) {
            stop_heartbeat();
            return;
        }

        std::thread retired_worker;
        std::uint64_t operation = 0;
        {
            std::lock_guard<std::mutex> lifecycle_lock(heartbeat_lifecycle_mutex_);
            operation = ++heartbeat_operation_;
            auto signal = std::atomic_load(&heartbeat_signal_);
            if (signal)
                signal->stop();
            std::atomic_store(&heartbeat_signal_, std::shared_ptr<WorkerSignal>{});
            if (heartbeat_thread_.joinable())
                retired_worker = std::move(heartbeat_thread_);
        }
        if (retired_worker.joinable())
            retired_worker.join();

        std::lock_guard<std::mutex> lifecycle_lock(heartbeat_lifecycle_mutex_);
        if (shutdown_started_.load() || operation != heartbeat_operation_ ||
            config_.heartbeat_interval <= 0 ||
            static_cast<double>(config_.heartbeat_interval) > MAX_TIMER_INTERVAL_SECONDS ||
            !is_safe_text(license_key, 512)) {
            return;
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            current_heartbeat_license_key_ = license_key;
        }
        auto signal = std::make_shared<WorkerSignal>();
        std::atomic_store(&heartbeat_signal_, signal);
        try {
            auto self = shared_from_this();
            heartbeat_thread_ = std::thread([self = std::move(self), license_key, signal]() {
                WorkerOwnerScope worker_scope(heartbeat_worker_owner, heartbeat_worker_signal,
                                              self.get(), signal.get());
                while (signal->running) {
                    std::unique_lock<std::mutex> lock(signal->mutex);
                    signal->cv.wait_for(lock,
                                        std::chrono::seconds(self->config_.heartbeat_interval),
                                        [signal]() { return !signal->running; });

                    if (!signal->running)
                        break;
                    lock.unlock();

                    // Send heartbeat (fire-and-forget)
                    (void)self->heartbeat(license_key, "");
                }
            });
        } catch (...) {
            signal->stop();
            std::atomic_store(&heartbeat_signal_, std::shared_ptr<WorkerSignal>{});
            throw;
        }
    }

    void stop_heartbeat() {
        if (heartbeat_worker_owner == this) {
            if (heartbeat_worker_signal)
                heartbeat_worker_signal->stop();
            std::lock_guard<std::mutex> lifecycle_lock(heartbeat_lifecycle_mutex_);
            ++heartbeat_operation_;
            auto current = std::atomic_load(&heartbeat_signal_);
            if (current.get() == heartbeat_worker_signal) {
                std::atomic_store(&heartbeat_signal_, std::shared_ptr<WorkerSignal>{});
            }
            if (heartbeat_thread_.joinable() &&
                heartbeat_thread_.get_id() == std::this_thread::get_id()) {
                heartbeat_thread_.detach();
            }
            return;
        }

        std::thread retired_worker;
        {
            std::lock_guard<std::mutex> lifecycle_lock(heartbeat_lifecycle_mutex_);
            ++heartbeat_operation_;
            auto signal = std::atomic_load(&heartbeat_signal_);
            if (signal)
                signal->stop();
            std::atomic_store(&heartbeat_signal_, std::shared_ptr<WorkerSignal>{});
            if (heartbeat_thread_.joinable())
                retired_worker = std::move(heartbeat_thread_);
        }
        if (retired_worker.joinable())
            retired_worker.join();
    }

    bool is_heartbeat_running() const {
        auto signal = std::atomic_load(&heartbeat_signal_);
        return signal && signal->running;
    }

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
        if (!cached_validation_.has_value() || !cached_validation_->valid ||
            !cached_license_->is_valid()) {
            status.active = false;
            status.reason = "license_inactive";
            return status;
        }

        for (const auto& ent : cached_license_->active_entitlements()) {
            if (ent.key == entitlement_key) {
                if (ent.expires_at) {
                    if (*ent.expires_at <= std::chrono::system_clock::now()) {
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
            return cached_validation_->valid ? ClientStatus::OfflineValid
                                             : ClientStatus::OfflineInvalid;
        }

        if (cached_validation_->valid) {
            return ClientStatus::Active;
        }

        return ClientStatus::Invalid;
    }

    // ========== Event Handling ==========

    Subscription on(const std::string& event, EventHandler handler) {
        return event_bus_.on(event, std::move(handler));
    }

    void emit(const std::string& event, const std::any& data) { event_bus_.emit(event, data); }

    // ========== Releases ==========

    Result<Release> get_latest_release(const std::string& product_slug_param,
                                       const std::string& channel, const std::string& platform) {
        // Prepare request data while holding mutex briefly
        std::string product_slug;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            product_slug = product_slug_param.empty() ? config_.product_slug : product_slug_param;
        }

        if (!is_safe_text(product_slug, 100)) {
            return Result<Release>::error(ErrorCode::MissingParameter, "Product slug is required");
        }
        if ((!channel.empty() && !is_safe_text(channel, 100)) ||
            (!platform.empty() && !is_safe_text(platform, 100))) {
            return Result<Release>::error(ErrorCode::InvalidParameter, "Release filter is invalid");
        }

        std::string path = "/products/" + encode_url_component(product_slug) + "/releases/latest";
        std::string query;

        if (!channel.empty()) {
            query += (query.empty() ? "?" : "&") + std::string("channel=") +
                     encode_url_component(channel);
        }
        if (!platform.empty()) {
            query += (query.empty() ? "?" : "&") + std::string("platform=") +
                     encode_url_component(platform);
        }

        // Make HTTP call without holding mutex
        http::Request request;
        request.method = http::Method::GET;
        request.path = path + query;
        request.authenticated = false;
        request.retryable = true;

        auto response = http_client_->send(request);

        if (!response.success) {
            if (response.error_message.empty()) {
                return handle_error_response<Release>(response);
            }
            return Result<Release>::error(ErrorCode::NetworkError, response.error_message);
        }

        // Parse response
        try {
            auto j = json::parse_strict(response.body);
            if (!j.is_object() || j.value("object", std::string{}) != "release") {
                throw std::invalid_argument("Release response has an invalid schema");
            }
            auto release = json::parse_release(j);
            if (!valid_release_response(release, product_slug, channel, platform)) {
                throw std::invalid_argument("Release response identity is inconsistent");
            }
            return Result<Release>::ok(std::move(release));
        } catch (const std::exception& e) {
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

        if (!is_safe_text(product_slug, 100)) {
            return Result<std::vector<Release>>::error(ErrorCode::MissingParameter,
                                                       "Product slug is required");
        }
        if ((!channel.empty() && !is_safe_text(channel, 100)) ||
            (!platform.empty() && !is_safe_text(platform, 100))) {
            return Result<std::vector<Release>>::error(ErrorCode::InvalidParameter,
                                                       "Release filter is invalid");
        }

        std::string path = "/products/" + encode_url_component(product_slug) + "/releases";
        std::string query;

        if (!channel.empty()) {
            query += (query.empty() ? "?" : "&") + std::string("channel=") +
                     encode_url_component(channel);
        }
        if (!platform.empty()) {
            query += (query.empty() ? "?" : "&") + std::string("platform=") +
                     encode_url_component(platform);
        }

        // Make HTTP call without holding mutex
        http::Request request;
        request.method = http::Method::GET;
        request.path = path + query;
        request.authenticated = false;
        request.retryable = true;

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
            auto j = json::parse_strict(response.body);
            if (!j.is_object() || j.value("object", std::string{}) != "list" ||
                !j.contains("data") || !j["data"].is_array() || j["data"].size() > 100) {
                throw std::invalid_argument("Release list response has an invalid schema");
            }
            for (const auto& item : j["data"]) {
                if (!item.is_object() || item.value("object", std::string{}) != "release") {
                    throw std::invalid_argument("Release list contains an invalid item schema");
                }
            }
            auto releases = json::parse_releases(j);
            for (const auto& release : releases) {
                if (!valid_release_response(release, product_slug, channel, platform)) {
                    throw std::invalid_argument("Release list contains an inconsistent item");
                }
            }
            return Result<std::vector<Release>>::ok(std::move(releases));
        } catch (const std::exception& e) {
            return Result<std::vector<Release>>::error(
                ErrorCode::ParseError, std::string("Failed to parse response: ") + e.what());
        }
    }

    Result<DownloadToken> generate_download_token(const std::string& version,
                                                  const std::string& license_key,
                                                  const std::string& product_slug_param,
                                                  const std::string& platform) {
        // Validate inputs before mutex
        if (!is_safe_text(license_key, 512)) {
            return Result<DownloadToken>::error(ErrorCode::InvalidLicenseKey,
                                                "License key is empty or invalid");
        }

        if (!is_safe_text(version, 100)) {
            return Result<DownloadToken>::error(ErrorCode::MissingParameter, "Version is required");
        }

        // Get product_slug while holding mutex briefly
        std::string product_slug;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            product_slug = product_slug_param.empty() ? config_.product_slug : product_slug_param;
        }

        if (!is_safe_text(product_slug, 100)) {
            return Result<DownloadToken>::error(ErrorCode::MissingParameter,
                                                "Product slug is required");
        }
        if (!platform.empty() && !is_safe_text(platform, 100)) {
            return Result<DownloadToken>::error(ErrorCode::InvalidParameter, "Platform is invalid");
        }

        // Make HTTP call without holding mutex
        auto body = json::build_download_token_request(license_key, platform);
        auto response = send_post("/products/" + encode_url_component(product_slug) + "/releases/" +
                                      encode_url_component(version) + "/download_token",
                                  body);

        if (!response.success) {
            if (response.error_message.empty()) {
                return handle_error_response<DownloadToken>(response);
            }
            return Result<DownloadToken>::error(ErrorCode::NetworkError, response.error_message);
        }

        // Parse response
        try {
            auto j = json::parse_strict(response.body);
            if (!j.is_object() || j.value("object", std::string{}) != "download_token") {
                throw std::invalid_argument("Download token response has an invalid schema");
            }
            auto token = json::parse_download_token(j);
            const auto now = std::chrono::system_clock::now();
            if (!is_safe_text(token.token, 16 * 1024) || !token.expires_at.has_value() ||
                *token.expires_at <= now || *token.expires_at > now + std::chrono::hours(24)) {
                throw std::invalid_argument("Download token response is incomplete or expired");
            }
            return Result<DownloadToken>::ok(std::move(token));
        } catch (const std::exception& e) {
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
        request.authenticated = false;
        request.retryable = true;
        request.expect_json = false;

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
        stop_network_recheck();
        stop_offline_refresh();
        storage_->clear_all();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            cached_license_.reset();
            cached_validation_.reset();
            current_activation_.reset();
            current_auto_license_key_.clear();
            current_heartbeat_license_key_.clear();
            offline_refresh_license_key_.clear();
            trusted_signing_keys_.clear();
        }
        event_bus_.emit(events::SDK_RESET, std::map<std::string, std::string>{});
    }

    const Config& config() const noexcept { return config_; }

    const std::string& device_id() const noexcept { return device_id_; }
    const std::string& fingerprint() const noexcept { return device_id_; }

  private:
    /// Send a POST request, injecting telemetry if enabled
    http::Response send_post(const std::string& path, nlohmann::json body, bool retryable = false) {
        http::Response response;
        try {
            if (config_.telemetry_enabled) {
                body["telemetry"] =
                    telemetry::collect(VERSION, config_.app_version, config_.app_build);
            }
            http::Request request;
            request.method = http::Method::POST;
            request.path = path;
            request.body = body.dump();
            request.retryable = retryable;
            return http_client_->send(request);
        } catch (const std::exception&) {
            response.error_message = "Failed to serialize request";
            return response;
        } catch (...) {
            response.error_message = "Failed to serialize request";
            return response;
        }
    }

    template <typename T> Result<T> handle_error_response(const http::Response& response) {
        // Try to parse error response
        try {
            auto j = json::parse_strict(response.body);
            auto api_error = json::parse_error_response(j);

            ErrorCode code = ErrorCode::Unknown;
            if (!api_error.code.empty()) {
                code = json::error_code_to_error_code(api_error.code);
            }
            // Preserve the authoritative HTTP classification when the server
            // adds a newer machine-readable code this SDK does not know yet.
            if (code == ErrorCode::Unknown) {
                code = http::status_code_to_error_code(response.status_code);
            }

            std::string message = api_error.message;
            if (message.empty()) {
                message = error_code_to_string(code);
            }

            return Result<T>::error(code, message);
        } catch (const std::exception&) {
            // Couldn't parse as JSON, use status code
            auto code = http::status_code_to_error_code(response.status_code);
            return Result<T>::error(code, error_code_to_string(code));
        }
    }

    bool should_fallback_to_offline(const http::Response& response) const {
        // Only transport failures are eligible. A received HTTP response is
        // authoritative, including 408 and 5xx, and must never be masked by a
        // stale local grant.
        return offline_policy_is_enabled() && !response.success && response.status_code == 0;
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
                auto j = json::parse_strict(response.body);
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
        {
            std::lock_guard<std::mutex> lock(mutex_);
            cached_license_.reset();
            cached_validation_.reset();
            current_activation_.reset();
            current_auto_license_key_.clear();
            current_heartbeat_license_key_.clear();
            offline_refresh_license_key_.clear();
        }
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
        std::lock_guard<std::mutex> lifecycle_lock(auto_validate_lifecycle_mutex_);
        ++auto_validate_operation_;
        auto signal = std::atomic_load(&auto_validate_signal_);
        if (signal)
            signal->stop();
        if (!signal || signal.get() == auto_validation_worker_signal) {
            std::atomic_store(&auto_validate_signal_, std::shared_ptr<WorkerSignal>{});
        }
        // Don't join here: revocation may be handled by this worker.
    }

    void stop_heartbeat_unlocked() {
        std::lock_guard<std::mutex> lifecycle_lock(heartbeat_lifecycle_mutex_);
        ++heartbeat_operation_;
        auto signal = std::atomic_load(&heartbeat_signal_);
        if (signal)
            signal->stop();
        if (!signal || signal.get() == heartbeat_worker_signal) {
            std::atomic_store(&heartbeat_signal_, std::shared_ptr<WorkerSignal>{});
        }
    }

    void stop_network_recheck_unlocked() {
        std::lock_guard<std::mutex> lifecycle_lock(network_recheck_lifecycle_mutex_);
        ++network_recheck_operation_;
        auto signal = std::atomic_load(&network_recheck_signal_);
        if (signal)
            signal->stop();
        if (!signal || signal.get() == network_recheck_worker_signal) {
            std::atomic_store(&network_recheck_signal_, std::shared_ptr<WorkerSignal>{});
        }
    }

    void stop_offline_refresh_unlocked() {
        std::lock_guard<std::mutex> lifecycle_lock(offline_refresh_lifecycle_mutex_);
        ++offline_refresh_operation_;
        auto signal = std::atomic_load(&offline_refresh_signal_);
        if (signal)
            signal->stop();
        if (!signal || signal.get() == offline_refresh_worker_signal) {
            std::atomic_store(&offline_refresh_signal_, std::shared_ptr<WorkerSignal>{});
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
        auto key_id = crypto::internal::extract_machine_file_key_id(machine_file);
        return key_id.is_ok() ? std::optional<std::string>(key_id.value()) : std::nullopt;
    }

    std::string resolve_signing_key(const std::optional<std::string>& key_id,
                                    const std::string& explicit_public_key, bool allow_fetch) {
        if (!explicit_public_key.empty()) {
            return is_valid_ed25519_public_key(explicit_public_key) ? explicit_public_key : "";
        }

        if (!config_.signing_public_key.empty()) {
            if (!is_valid_ed25519_public_key(config_.signing_public_key) ||
                (!config_.signing_key_id.empty() && key_id.has_value() &&
                 *key_id != config_.signing_key_id)) {
                return "";
            }
            return config_.signing_public_key;
        }

        auto resolve_by_key_id = [&](const std::string& candidate_key_id) -> std::string {
            if (!is_safe_text(candidate_key_id, 255))
                return "";
            {
                std::lock_guard<std::mutex> lock(mutex_);
                const auto trusted = trusted_signing_keys_.find(candidate_key_id);
                if (trusted != trusted_signing_keys_.end())
                    return trusted->second;
            }
            if (!allow_fetch)
                return "";

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
        std::lock_guard<std::mutex> lock(mutex_);
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

    bool offline_policy_is_valid() const {
        return config_.max_offline_days >= 0 && config_.max_offline_days <= MAX_OFFLINE_DAYS &&
               std::isfinite(config_.max_clock_skew_ms) && config_.max_clock_skew_ms >= 0.0 &&
               config_.max_clock_skew_ms <= MAX_CLOCK_SKEW_MS;
    }

    bool offline_policy_is_enabled() const {
        return offline_policy_is_valid() &&
               config_.offline_fallback_mode != OfflineFallbackMode::Disabled &&
               config_.max_offline_days > 0;
    }

    void update_last_seen(int64_t now_unix) {
        storage_->set_last_seen_timestamp(static_cast<double>(now_unix));
    }

    License fallback_license_for_machine_payload(
        const MachineFilePayload& payload,
        const std::optional<CachedLicense>& cached_license) const {
        std::optional<Timestamp> expires_at;
        if (payload.license_expires_at.has_value()) {
            expires_at = std::chrono::system_clock::from_time_t(
                static_cast<std::time_t>(*payload.license_expires_at));
        }

        return License(payload.license_key, LicenseStatus::Active, LicenseMode::Unknown, "",
                       std::nullopt, 0, std::nullopt, expires_at, {}, {}, {});
    }

    Result<ValidationResult> verify_cached_machine_file() {
        if (!offline_policy_is_valid()) {
            ValidationResult result;
            result.valid = false;
            result.offline = true;
            result.code = "invalid_configuration";
            result.message = "Offline policy configuration is invalid";
            return Result<ValidationResult>::ok(std::move(result));
        }
        if (!offline_policy_is_enabled()) {
            ValidationResult result;
            result.valid = false;
            result.offline = true;
            result.code = "offline_disabled";
            result.message = "Offline validation is disabled by local policy";
            return Result<ValidationResult>::ok(std::move(result));
        }

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
        auto now_unix =
            std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();

        if (is_clock_tampered(now_unix)) {
            result.valid = false;
            result.code = "clock_tamper";
            return Result<ValidationResult>::ok(std::move(result));
        }

        if (now_unix >= payload.iat &&
            now_unix - payload.iat > static_cast<int64_t>(config_.max_offline_days) * 86400) {
            result.valid = false;
            result.code = "grace_period_expired";
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
        if (!offline_policy_is_valid()) {
            ValidationResult result;
            result.valid = false;
            result.offline = true;
            result.code = "invalid_configuration";
            result.message = "Offline policy configuration is invalid";
            return Result<ValidationResult>::ok(std::move(result));
        }
        if (!offline_policy_is_enabled()) {
            ValidationResult result;
            result.valid = false;
            result.offline = true;
            result.code = "offline_disabled";
            result.message = "Offline validation is disabled by local policy";
            return Result<ValidationResult>::ok(std::move(result));
        }

        auto cached_offline = storage_->get_offline_token();
        if (!cached_offline) {
            ValidationResult result;
            result.valid = false;
            result.offline = true;
            result.code = "no_offline_token";
            return Result<ValidationResult>::ok(result);
        }

        auto public_key = resolve_signing_key(cached_offline->signature.key_id, "", false);

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
            result.code = verify_result.is_ok()
                              ? "signature_invalid"
                              : offline_error_code_string(verify_result.error_code());
            result.message = verify_result.is_ok() ? "" : verify_result.error_message();
            event_bus_.emit(
                events::OFFLINE_TOKEN_VERIFICATION_FAILED,
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
        auto now_unix =
            std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();

        if (now_unix >= cached_offline->token.exp) {
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
            now_unix >= *cached_offline->token.license_expires_at) {
            result.valid = false;
            result.code = "license_expired";
            return Result<ValidationResult>::ok(result);
        }

        if (now_unix >= cached_offline->token.iat &&
            now_unix - cached_offline->token.iat >
                static_cast<int64_t>(config_.max_offline_days) * 86400) {
            result.valid = false;
            result.code = "grace_period_expired";
            return Result<ValidationResult>::ok(result);
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
            license_mode_from_string(cached_offline->token.mode), cached_offline->token.plan_key,
            cached_offline->token.seat_limit, 0, std::nullopt, license_expires, entitlements,
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
        if (!offline_policy_is_enabled() || license_key.empty()) {
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
                (void)resolve_signing_key(offline.signature.key_id, "", true);
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
            event_bus_.emit(
                events::OFFLINE_TOKEN_FETCH_ERROR,
                std::map<std::string, std::string>{{"licenseKey", license_key},
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

    // Remove completed futures from the list (must hold futures_mutex_)
    void cleanup_futures_unlocked() {
        pending_futures_.erase(std::remove_if(pending_futures_.begin(), pending_futures_.end(),
                                              [](PendingFuture& pending) {
                                                  return pending.future.wait_for(
                                                             std::chrono::seconds(0)) ==
                                                         std::future_status::ready;
                                              }),
                               pending_futures_.end());
    }

    // Wait for all pending futures to complete
    void wait_for_pending_futures() {
        std::vector<PendingFuture> futures_to_wait;
        {
            std::lock_guard<std::mutex> lock(futures_mutex_);
            futures_to_wait = std::move(pending_futures_);
        }
        for (auto& pending : futures_to_wait) {
            if (!pending.future.valid())
                continue;
            if (async_worker_owner == this && async_worker_id == pending.id) {
                // std::future from std::async waits in its destructor. Hand the
                // current job to a separate reaper so a callback can safely
                // destroy its own Client without waiting on itself.
                std::thread([future = std::move(pending.future)]() mutable {
                    if (future.valid())
                        future.wait();
                }).detach();
            } else {
                pending.future.wait();
            }
        }
    }

    // Network recheck timer management
    void start_network_recheck() {
        if (shutdown_started_.load())
            return;
        if (network_recheck_worker_owner == this) {
            stop_network_recheck();
            return;
        }

        std::thread retired_worker;
        std::uint64_t operation = 0;
        {
            std::lock_guard<std::mutex> lifecycle_lock(network_recheck_lifecycle_mutex_);
            operation = ++network_recheck_operation_;
            auto signal = std::atomic_load(&network_recheck_signal_);
            if (signal)
                signal->stop();
            std::atomic_store(&network_recheck_signal_, std::shared_ptr<WorkerSignal>{});
            if (network_recheck_thread_.joinable()) {
                retired_worker = std::move(network_recheck_thread_);
            }
        }
        if (retired_worker.joinable())
            retired_worker.join();

        std::lock_guard<std::mutex> lifecycle_lock(network_recheck_lifecycle_mutex_);
        if (shutdown_started_.load() || operation != network_recheck_operation_ ||
            !valid_timer_interval(config_.network_recheck_interval) ||
            config_.network_recheck_interval == 0.0) {
            return;
        }

        auto signal = std::make_shared<WorkerSignal>();
        std::atomic_store(&network_recheck_signal_, signal);
        try {
            auto self = shared_from_this();
            network_recheck_thread_ = std::thread([self = std::move(self), signal]() {
                WorkerOwnerScope worker_scope(network_recheck_worker_owner,
                                              network_recheck_worker_signal, self.get(),
                                              signal.get());
                while (signal->running) {
                    std::unique_lock<std::mutex> lock(signal->mutex);
                    signal->cv.wait_for(
                        lock, std::chrono::duration<double>(self->config_.network_recheck_interval),
                        [signal]() { return !signal->running; });

                    if (!signal->running)
                        break;
                    lock.unlock();

                    // Check network status by calling health endpoint
                    auto result = self->health_check_unlocked();
                    if (result) {
                        // We're back online!
                        self->is_online_ = true;
                        self->event_bus_.emit(events::NETWORK_ONLINE,
                                              std::map<std::string, std::string>{});

                        if (!signal->running)
                            break;

                        // Stop the recheck timer since we're online now
                        signal->stop();

                        auto license_key = self->reconnect_license_key();
                        if (!license_key.empty()) {
                            auto validation_result = self->validate(license_key, "");
                            if (validation_result.is_ok() && validation_result.value().valid) {
                                self->start_auto_validation(license_key);
                                self->start_heartbeat(license_key);
                                self->start_offline_refresh(license_key);
                            }
                        }
                    }
                }
            });
        } catch (...) {
            signal->stop();
            std::atomic_store(&network_recheck_signal_, std::shared_ptr<WorkerSignal>{});
            throw;
        }
    }

    void stop_network_recheck() {
        if (network_recheck_worker_owner == this) {
            if (network_recheck_worker_signal)
                network_recheck_worker_signal->stop();
            std::lock_guard<std::mutex> lifecycle_lock(network_recheck_lifecycle_mutex_);
            ++network_recheck_operation_;
            auto current = std::atomic_load(&network_recheck_signal_);
            if (current.get() == network_recheck_worker_signal) {
                std::atomic_store(&network_recheck_signal_, std::shared_ptr<WorkerSignal>{});
            }
            if (network_recheck_thread_.joinable() &&
                network_recheck_thread_.get_id() == std::this_thread::get_id()) {
                network_recheck_thread_.detach();
            }
            return;
        }

        std::thread retired_worker;
        {
            std::lock_guard<std::mutex> lifecycle_lock(network_recheck_lifecycle_mutex_);
            ++network_recheck_operation_;
            auto signal = std::atomic_load(&network_recheck_signal_);
            if (signal)
                signal->stop();
            std::atomic_store(&network_recheck_signal_, std::shared_ptr<WorkerSignal>{});
            if (network_recheck_thread_.joinable()) {
                retired_worker = std::move(network_recheck_thread_);
            }
        }
        if (retired_worker.joinable())
            retired_worker.join();
    }

    // Offline license refresh timer management
    void start_offline_refresh(const std::string& license_key) {
        if (shutdown_started_.load())
            return;
        if (offline_refresh_worker_owner == this) {
            stop_offline_refresh();
            return;
        }

        std::thread retired_worker;
        std::uint64_t operation = 0;
        {
            std::lock_guard<std::mutex> lifecycle_lock(offline_refresh_lifecycle_mutex_);
            operation = ++offline_refresh_operation_;
            auto signal = std::atomic_load(&offline_refresh_signal_);
            if (signal)
                signal->stop();
            std::atomic_store(&offline_refresh_signal_, std::shared_ptr<WorkerSignal>{});
            if (offline_refresh_thread_.joinable()) {
                retired_worker = std::move(offline_refresh_thread_);
            }
        }
        if (retired_worker.joinable())
            retired_worker.join();

        std::lock_guard<std::mutex> lifecycle_lock(offline_refresh_lifecycle_mutex_);
        if (shutdown_started_.load() || operation != offline_refresh_operation_ ||
            !offline_policy_is_enabled() ||
            !valid_timer_interval(config_.offline_license_refresh_interval) ||
            config_.offline_license_refresh_interval == 0.0 || !is_safe_text(license_key, 512)) {
            return;
        }

        auto signal = std::make_shared<WorkerSignal>();
        std::atomic_store(&offline_refresh_signal_, signal);
        {
            std::lock_guard<std::mutex> lock(mutex_);
            offline_refresh_license_key_ = license_key;
        }

        try {
            auto self = shared_from_this();
            offline_refresh_thread_ = std::thread([self = std::move(self), signal]() {
                WorkerOwnerScope worker_scope(offline_refresh_worker_owner,
                                              offline_refresh_worker_signal, self.get(),
                                              signal.get());
                while (signal->running) {
                    std::unique_lock<std::mutex> lock(signal->mutex);
                    signal->cv.wait_for(lock,
                                        std::chrono::duration<double>(
                                            self->config_.offline_license_refresh_interval),
                                        [signal]() { return !signal->running; });

                    if (!signal->running)
                        break;
                    lock.unlock();

                    std::string license_key;
                    {
                        std::lock_guard<std::mutex> state_lock(self->mutex_);
                        license_key = self->offline_refresh_license_key_;
                    }
                    if (!license_key.empty()) {
                        self->sync_offline_assets_impl(license_key, self->device_id_);
                    }
                }
            });
        } catch (...) {
            signal->stop();
            std::atomic_store(&offline_refresh_signal_, std::shared_ptr<WorkerSignal>{});
            throw;
        }
    }

    void stop_offline_refresh() {
        if (offline_refresh_worker_owner == this) {
            if (offline_refresh_worker_signal)
                offline_refresh_worker_signal->stop();
            std::lock_guard<std::mutex> lifecycle_lock(offline_refresh_lifecycle_mutex_);
            ++offline_refresh_operation_;
            auto current = std::atomic_load(&offline_refresh_signal_);
            if (current.get() == offline_refresh_worker_signal) {
                std::atomic_store(&offline_refresh_signal_, std::shared_ptr<WorkerSignal>{});
            }
            if (offline_refresh_thread_.joinable() &&
                offline_refresh_thread_.get_id() == std::this_thread::get_id()) {
                offline_refresh_thread_.detach();
            }
            return;
        }

        std::thread retired_worker;
        {
            std::lock_guard<std::mutex> lifecycle_lock(offline_refresh_lifecycle_mutex_);
            ++offline_refresh_operation_;
            auto signal = std::atomic_load(&offline_refresh_signal_);
            if (signal)
                signal->stop();
            std::atomic_store(&offline_refresh_signal_, std::shared_ptr<WorkerSignal>{});
            if (offline_refresh_thread_.joinable()) {
                retired_worker = std::move(offline_refresh_thread_);
            }
        }
        if (retired_worker.joinable())
            retired_worker.join();
    }

    // Health check without locking (for internal use)
    bool health_check_unlocked() {
        http::Request request;
        request.method = http::Method::GET;
        request.path = "/health";
        request.authenticated = false;
        request.retryable = true;
        request.expect_json = false;

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
    std::unordered_map<std::string, std::string> trusted_signing_keys_;
    mutable std::mutex mutex_;

    // Event bus
    EventBus event_bus_;

    // Auto-validation
    std::shared_ptr<WorkerSignal> auto_validate_signal_;
    std::uint64_t auto_validate_operation_ = 0;
    std::thread auto_validate_thread_;
    std::mutex auto_validate_lifecycle_mutex_;
    std::string current_auto_license_key_;
    std::string current_heartbeat_license_key_;

    // Heartbeat timer
    std::shared_ptr<WorkerSignal> heartbeat_signal_;
    std::uint64_t heartbeat_operation_ = 0;
    std::thread heartbeat_thread_;
    std::mutex heartbeat_lifecycle_mutex_;

    // Network status
    std::atomic<bool> is_online_{true};

    // Network recheck timer
    std::shared_ptr<WorkerSignal> network_recheck_signal_;
    std::uint64_t network_recheck_operation_ = 0;
    std::thread network_recheck_thread_;
    std::mutex network_recheck_lifecycle_mutex_;

    // Offline license refresh timer
    std::shared_ptr<WorkerSignal> offline_refresh_signal_;
    std::uint64_t offline_refresh_operation_ = 0;
    std::thread offline_refresh_thread_;
    std::mutex offline_refresh_lifecycle_mutex_;
    std::string offline_refresh_license_key_;

    // Pending async futures
    std::vector<PendingFuture> pending_futures_;
    std::mutex futures_mutex_;
    std::uint64_t next_async_job_id_ = 0;
    std::atomic<bool> shutdown_started_{false};
};

// Client implementation
Client::Client(Config config) : impl_(std::make_shared<Impl>(std::move(config))) {}

Client::~Client() {
    if (impl_)
        impl_->shutdown();
}

Client::Client(Client&&) noexcept = default;
Client& Client::operator=(Client&& other) noexcept {
    if (this == &other)
        return *this;
    if (impl_)
        impl_->shutdown();
    impl_ = std::move(other.impl_);
    return *this;
}

Result<ValidationResult> Client::validate(const std::string& license_key,
                                          const std::string& device_id) {
    auto impl = impl_;
    return impl->validate(license_key, device_id);
}

Result<Activation> Client::activate(const std::string& license_key, const std::string& device_id,
                                    const std::string& device_name, const Metadata& metadata) {
    auto impl = impl_;
    return impl->activate(license_key, device_id, device_name, metadata);
}

Result<Deactivation> Client::deactivate(const std::string& license_key,
                                        const std::string& device_id) {
    auto impl = impl_;
    return impl->deactivate(license_key, device_id);
}

void Client::validate_async(const std::string& license_key, AsyncCallback callback,
                            const std::string& device_id) {
    auto impl = impl_;
    impl->validate_async(license_key, std::move(callback), device_id);
}

void Client::activate_async(const std::string& license_key, ActivationCallback callback,
                            const std::string& device_id, const std::string& device_name,
                            const Metadata& metadata) {
    auto impl = impl_;
    impl->activate_async(license_key, std::move(callback), device_id, device_name, metadata);
}

void Client::deactivate_async(const std::string& license_key, DeactivationCallback callback,
                              const std::string& device_id) {
    auto impl = impl_;
    impl->deactivate_async(license_key, std::move(callback), device_id);
}

Result<HeartbeatResponse> Client::heartbeat(const std::string& license_key,
                                            const std::string& device_id) {
    auto impl = impl_;
    return impl->heartbeat(license_key, device_id);
}

void Client::heartbeat_async(const std::string& license_key, HeartbeatCallback callback,
                             const std::string& device_id) {
    auto impl = impl_;
    impl->heartbeat_async(license_key, std::move(callback), device_id);
}

Result<OfflineToken> Client::generate_offline_token(const std::string& license_key,
                                                    const std::string& device_id, int ttl_days) {
    auto impl = impl_;
    return impl->generate_offline_token(license_key, device_id, ttl_days);
}

Result<MachineFile> Client::checkout_machine_file(const std::string& license_key,
                                                  const std::string& device_id, int ttl_days) {
    auto impl = impl_;
    return impl->checkout_machine_file(license_key, device_id, ttl_days);
}

Result<bool> Client::verify_offline_token(const OfflineToken& offline_token,
                                          const std::string& public_key_b64) {
    auto impl = impl_;
    return impl->verify_offline_token(offline_token, public_key_b64);
}

Result<MachineFileVerificationResult> Client::verify_machine_file(const MachineFile& machine_file,
                                                                  const std::string& public_key_b64,
                                                                  const std::string& license_key,
                                                                  const std::string& device_id) {
    auto impl = impl_;
    return impl->verify_machine_file(machine_file, public_key_b64, license_key, device_id);
}

Result<std::string> Client::fetch_signing_key(const std::string& key_id) {
    auto impl = impl_;
    return impl->fetch_signing_key(key_id);
}

void Client::sync_offline_assets() {
    auto impl = impl_;
    impl->sync_offline_assets();
}

void Client::start_auto_validation(const std::string& license_key) {
    auto impl = impl_;
    impl->start_auto_validation(license_key);
}

void Client::stop_auto_validation() {
    auto impl = impl_;
    impl->stop_auto_validation();
}

bool Client::is_auto_validating() const {
    auto impl = impl_;
    return impl->is_auto_validating();
}

void Client::start_heartbeat(const std::string& license_key) {
    auto impl = impl_;
    impl->start_heartbeat(license_key);
}

void Client::stop_heartbeat() {
    auto impl = impl_;
    impl->stop_heartbeat();
}

bool Client::is_heartbeat_running() const {
    auto impl = impl_;
    return impl->is_heartbeat_running();
}

RestoreResult Client::restore_license() {
    auto impl = impl_;
    return impl->restore_license();
}

void Client::restore_license_async(RestoreCallback callback) {
    auto impl = impl_;
    impl->restore_license_async(std::move(callback));
}

ValidationResult Client::get_status() const {
    auto impl = impl_;
    return impl->get_status();
}

std::optional<License> Client::current_license() const {
    auto impl = impl_;
    return impl->current_license();
}

EntitlementStatus Client::check_entitlement(const std::string& entitlement_key) const {
    auto impl = impl_;
    return impl->check_entitlement(entitlement_key);
}

bool Client::is_online() const {
    auto impl = impl_;
    return impl->is_online();
}

ClientStatus Client::get_client_status() const {
    auto impl = impl_;
    return impl->get_client_status();
}

Subscription Client::on(const std::string& event, EventHandler handler) {
    auto impl = impl_;
    return impl->on(event, std::move(handler));
}

void Client::emit(const std::string& event, const std::any& data) {
    auto impl = impl_;
    impl->emit(event, data);
}

Result<Release> Client::get_latest_release(const std::string& product_slug,
                                           const std::string& channel,
                                           const std::string& platform) {
    auto impl = impl_;
    return impl->get_latest_release(product_slug, channel, platform);
}

Result<std::vector<Release>> Client::list_releases(const std::string& product_slug,
                                                   const std::string& channel,
                                                   const std::string& platform) {
    auto impl = impl_;
    return impl->list_releases(product_slug, channel, platform);
}

Result<DownloadToken> Client::generate_download_token(const std::string& version,
                                                      const std::string& license_key,
                                                      const std::string& product_slug,
                                                      const std::string& platform) {
    auto impl = impl_;
    return impl->generate_download_token(version, license_key, product_slug, platform);
}

Result<bool> Client::health() {
    auto impl = impl_;
    return impl->health();
}

void Client::reset() {
    auto impl = impl_;
    impl->reset();
}

const Config& Client::config() const noexcept {
    return impl_->config();
}

const std::string& Client::device_id() const {
    return impl_->device_id();
}

const std::string& Client::fingerprint() const {
    return impl_->fingerprint();
}

} // namespace licenseseat
