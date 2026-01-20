#include "licenseseat/licenseseat.hpp"
#include "licenseseat/crypto.hpp"
#include "licenseseat/device.hpp"
#include "licenseseat/events.hpp"
#include "licenseseat/http.hpp"
#include "licenseseat/json.hpp"
#include "licenseseat/storage.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>

namespace licenseseat {

// PIMPL implementation
class Client::Impl {
  public:
    explicit Impl(Config config) : config_(std::move(config)) {
        // Auto-generate device identifier if not provided
        if (config_.device_identifier.empty()) {
            device_identifier_ = device::generate_device_id();
            if (device_identifier_.empty()) {
                device_identifier_ = "unknown-device";
            }
        } else {
            device_identifier_ = config_.device_identifier;
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

    ~Impl() { stop_auto_validation(); }

    // ========== Synchronous API ==========

    Result<ValidationResult> validate(const std::string& license_key,
                                      const std::string& device_identifier) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (license_key.empty()) {
            return Result<ValidationResult>::error(ErrorCode::InvalidLicenseKey,
                                                   "License key cannot be empty");
        }

        std::string device_id = device_identifier.empty() ? device_identifier_ : device_identifier;

        event_bus_.emit(events::VALIDATION_START,
                        std::map<std::string, std::string>{{"license_key", license_key}});

        // Build request
        auto body = json::build_validate_request(license_key, device_id, config_.product_slug);

        http::Request request;
        request.method = http::Method::POST;
        request.path = "/licenses/validate";
        request.body = body.dump();

        auto response = http_client_->send(request);

        if (!response.success) {
            // Check if we should fallback to offline
            if (should_fallback_to_offline(response)) {
                auto offline_result = verify_cached_offline();
                if (offline_result.is_ok() && offline_result.value().valid) {
                    event_bus_.emit(events::VALIDATION_OFFLINE_SUCCESS, offline_result.value());
                    return offline_result;
                }
            }

            if (response.error_message.empty()) {
                auto err = handle_error_response<ValidationResult>(response);
                event_bus_.emit(events::VALIDATION_ERROR,
                                std::map<std::string, std::string>{{"error", err.error_message()}});
                return err;
            }

            is_online_ = false;
            event_bus_.emit(events::NETWORK_OFFLINE, std::map<std::string, std::string>{});
            return Result<ValidationResult>::error(ErrorCode::NetworkError, response.error_message);
        }

        is_online_ = true;

        // Parse response
        try {
            auto j = nlohmann::json::parse(response.body);
            auto result = json::parse_validation_result(j);

            // Cache the result
            if (result.valid) {
                cached_license_ = result.license;
                cached_validation_ = result;
                update_storage_license(license_key, device_id, result);
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
                                const std::string& device_identifier, const Metadata& metadata) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (license_key.empty()) {
            return Result<Activation>::error(ErrorCode::InvalidLicenseKey,
                                             "License key cannot be empty");
        }

        std::string device_id = device_identifier.empty() ? device_identifier_ : device_identifier;
        if (device_id.empty()) {
            return Result<Activation>::error(ErrorCode::MissingParameter,
                                             "Device identifier is required");
        }

        event_bus_.emit(events::ACTIVATION_START,
                        std::map<std::string, std::string>{{"license_key", license_key},
                                                           {"device_id", device_id}});

        // Build request
        auto body = json::build_activate_request(license_key, device_id, metadata);

        http::Request request;
        request.method = http::Method::POST;
        request.path = "/activations/activate";
        request.body = body.dump();

        auto response = http_client_->send(request);

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
            current_activation_ = activation;

            event_bus_.emit(events::ACTIVATION_SUCCESS, activation);

            // Sync offline assets in background
            sync_offline_assets_impl();

            return Result<Activation>::ok(std::move(activation));
        } catch (const nlohmann::json::exception& e) {
            return Result<Activation>::error(ErrorCode::ParseError,
                                             std::string("Failed to parse response: ") + e.what());
        }
    }

    Result<Activation> deactivate(const std::string& license_key,
                                  const std::string& device_identifier) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (license_key.empty()) {
            return Result<Activation>::error(ErrorCode::InvalidLicenseKey,
                                             "License key cannot be empty");
        }

        std::string device_id = device_identifier.empty() ? device_identifier_ : device_identifier;

        event_bus_.emit(events::DEACTIVATION_START,
                        std::map<std::string, std::string>{{"license_key", license_key}});

        // Build request
        auto body = json::build_deactivate_request(license_key, device_id);

        http::Request request;
        request.method = http::Method::POST;
        request.path = "/activations/deactivate";
        request.body = body.dump();

        auto response = http_client_->send(request);

        if (!response.success) {
            if (response.error_message.empty()) {
                auto err = handle_error_response<Activation>(response);
                event_bus_.emit(events::DEACTIVATION_ERROR,
                                std::map<std::string, std::string>{{"error", err.error_message()}});
                return err;
            }
            return Result<Activation>::error(ErrorCode::NetworkError, response.error_message);
        }

        // Parse response
        try {
            auto j = nlohmann::json::parse(response.body);
            auto activation = json::parse_activation(j);
            current_activation_.reset();
            cached_license_.reset();
            cached_validation_.reset();
            storage_->clear_license();
            storage_->clear_offline_license();

            event_bus_.emit(events::DEACTIVATION_SUCCESS, activation);

            return Result<Activation>::ok(std::move(activation));
        } catch (const nlohmann::json::exception& e) {
            return Result<Activation>::error(ErrorCode::ParseError,
                                             std::string("Failed to parse response: ") + e.what());
        }
    }

    // ========== Async API ==========

    void validate_async(const std::string& license_key, AsyncCallback callback,
                        const std::string& device_identifier) {
        std::thread([this, license_key, callback, device_identifier]() {
            auto result = this->validate(license_key, device_identifier);
            if (callback) {
                callback(std::move(result));
            }
        }).detach();
    }

    void activate_async(const std::string& license_key, ActivationCallback callback,
                        const std::string& device_identifier, const Metadata& metadata) {
        std::thread([this, license_key, callback, device_identifier, metadata]() {
            auto result = this->activate(license_key, device_identifier, metadata);
            if (callback) {
                callback(std::move(result));
            }
        }).detach();
    }

    void deactivate_async(const std::string& license_key, ActivationCallback callback,
                          const std::string& device_identifier) {
        std::thread([this, license_key, callback, device_identifier]() {
            auto result = this->deactivate(license_key, device_identifier);
            if (callback) {
                callback(std::move(result));
            }
        }).detach();
    }

    // ========== Offline Licensing ==========

    Result<OfflineLicense> generate_offline_license(const std::string& license_key) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (license_key.empty()) {
            return Result<OfflineLicense>::error(ErrorCode::InvalidLicenseKey,
                                                 "License key cannot be empty");
        }

        http::Request request;
        request.method = http::Method::GET;
        request.path = "/licenses/" + license_key + "/offline_license";

        auto response = http_client_->send(request);

        if (!response.success) {
            if (response.error_message.empty()) {
                return handle_error_response<OfflineLicense>(response);
            }
            return Result<OfflineLicense>::error(ErrorCode::NetworkError, response.error_message);
        }

        // Parse response
        try {
            auto j = nlohmann::json::parse(response.body);
            auto offline = json::parse_offline_license(j);

            // Cache it
            storage_->set_offline_license(offline);

            event_bus_.emit(events::OFFLINE_LICENSE_READY, offline);

            return Result<OfflineLicense>::ok(std::move(offline));
        } catch (const nlohmann::json::exception& e) {
            return Result<OfflineLicense>::error(
                ErrorCode::ParseError, std::string("Failed to parse response: ") + e.what());
        }
    }

    Result<bool> verify_offline_license(const OfflineLicense& offline_license,
                                        const std::string& public_key_b64) {
        // Perform basic validity checks first
        if (offline_license.license_key.empty()) {
            return Result<bool>::error(ErrorCode::InvalidLicenseKey, "License key is empty");
        }

        if (offline_license.is_expired()) {
            return Result<bool>::error(ErrorCode::LicenseExpired, "Offline license has expired");
        }

        // Determine which public key to use
        std::string key_to_use = public_key_b64;
        if (key_to_use.empty()) {
            key_to_use = config_.offline_public_key;
        }
        if (key_to_use.empty()) {
            // Try to get from cache
            auto cached_key = storage_->get_public_key(offline_license.key_id);
            if (cached_key) {
                key_to_use = *cached_key;
            }
        }

        if (key_to_use.empty()) {
            return Result<bool>::error(ErrorCode::MissingParameter,
                                       "Public key required for offline verification");
        }

        // Verify the Ed25519 signature
        auto result = crypto::verify_offline_license_signature(offline_license, key_to_use);
        if (result.is_ok() && result.value()) {
            event_bus_.emit(events::OFFLINE_LICENSE_VERIFIED, offline_license);
        }
        return result;
    }

    Result<std::string> fetch_public_key(const std::string& key_id) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (key_id.empty()) {
            return Result<std::string>::error(ErrorCode::MissingParameter, "Key ID is required");
        }

        http::Request request;
        request.method = http::Method::GET;
        request.path = "/public_keys/" + key_id;

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
            auto key = json::parse_public_key(j);

            // Cache it
            storage_->set_public_key(key_id, key);

            return Result<std::string>::ok(std::move(key));
        } catch (const nlohmann::json::exception& e) {
            return Result<std::string>::error(
                ErrorCode::ParseError, std::string("Failed to parse response: ") + e.what());
        }
    }

    void sync_offline_assets() {
        std::thread([this]() { this->sync_offline_assets_impl(); }).detach();
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

                event_bus_.emit(events::AUTOVALIDATION_CYCLE,
                                std::map<std::string, std::string>{{"license_key", license_key}});
            }
        });
    }

    void stop_auto_validation() {
        if (auto_validate_running_) {
            auto_validate_running_ = false;
            auto_validate_cv_.notify_all();

            if (auto_validate_thread_.joinable()) {
                auto_validate_thread_.join();
            }

            event_bus_.emit(events::AUTOVALIDATION_STOPPED, std::map<std::string, std::string>{});
        }
    }

    bool is_auto_validating() const { return auto_validate_running_; }

    // ========== Status & State ==========

    ValidationResult get_status() const {
        std::lock_guard<std::mutex> lock(mutex_);

        if (cached_validation_) {
            return *cached_validation_;
        }

        ValidationResult result;
        result.valid = false;
        result.reason = "No license validated";
        return result;
    }

    std::optional<License> current_license() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return cached_license_;
    }

    EntitlementStatus check_entitlement(const std::string& entitlement_key) const {
        std::lock_guard<std::mutex> lock(mutex_);

        EntitlementStatus status;

        if (!cached_validation_ || !cached_validation_->valid) {
            status.active = false;
            status.reason = "no_license";
            return status;
        }

        for (const auto& ent : cached_validation_->active_entitlements) {
            if (ent.key == entitlement_key) {
                if (ent.expires) {
                    if (*ent.expires < std::chrono::system_clock::now()) {
                        status.active = false;
                        status.reason = "expired";
                        status.expires_at = ent.expires;
                        status.entitlement = ent;
                        return status;
                    }
                }
                status.active = true;
                status.expires_at = ent.expires;
                status.entitlement = ent;
                return status;
            }
        }

        status.active = false;
        status.reason = "not_found";
        return status;
    }

    bool is_online() const { return is_online_; }

    // ========== Event Handling ==========

    Subscription on(const std::string& event, EventHandler handler) {
        auto event_sub = event_bus_.on(event, handler);
        // Wrap the EventSubscription's cancel in a Subscription
        return Subscription([sub = std::move(event_sub)]() mutable { sub.cancel(); });
    }

    void emit(const std::string& event, const std::any& data) { event_bus_.emit(event, data); }

    // ========== Releases ==========

    Result<Release> get_latest_release(const std::string& product_slug, const std::string& channel,
                                       const std::string& platform) {
        std::lock_guard<std::mutex> lock(mutex_);

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

    Result<std::vector<Release>> list_releases(const std::string& product_slug,
                                               const std::string& channel,
                                               const std::string& platform) {
        std::lock_guard<std::mutex> lock(mutex_);

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

    Result<DownloadToken> generate_download_token(int release_id, const std::string& license_key) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (license_key.empty()) {
            return Result<DownloadToken>::error(ErrorCode::InvalidLicenseKey,
                                                "License key is required");
        }

        auto body = json::build_download_token_request(license_key);

        http::Request request;
        request.method = http::Method::POST;
        request.path = "/releases/" + std::to_string(release_id) + "/generate_download_token";
        request.body = body.dump();

        auto response = http_client_->send(request);

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

    Result<bool> heartbeat() {
        std::lock_guard<std::mutex> lock(mutex_);

        http::Request request;
        request.method = http::Method::GET;
        request.path = "/heartbeat";

        auto response = http_client_->send(request);

        if (!response.success) {
            is_online_ = false;
            if (response.error_message.empty()) {
                return handle_error_response<bool>(response);
            }
            return Result<bool>::error(ErrorCode::NetworkError, response.error_message);
        }

        is_online_ = true;
        event_bus_.emit(events::NETWORK_ONLINE, std::map<std::string, std::string>{});
        return Result<bool>::ok(true);
    }

    void reset() {
        stop_auto_validation();
        storage_->clear_all();
        cached_license_.reset();
        cached_validation_.reset();
        current_activation_.reset();
        event_bus_.emit(events::SDK_RESET, std::map<std::string, std::string>{});
    }

    const Config& config() const noexcept { return config_; }

    const std::string& device_identifier() const noexcept { return device_identifier_; }

  private:
    template <typename T>
    Result<T> handle_error_response(const http::Response& response) {
        // Try to parse error response
        try {
            auto j = nlohmann::json::parse(response.body);
            auto api_error = json::parse_error_response(j);

            ErrorCode code = ErrorCode::Unknown;
            if (!api_error.reason_code.empty()) {
                code = json::reason_code_to_error_code(api_error.reason_code);
            } else {
                code = http::status_code_to_error_code(response.status_code);
            }

            std::string message = api_error.error;
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

    bool should_fallback_to_offline(const http::Response& response) {
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

    Result<ValidationResult> verify_cached_offline() {
        auto cached_offline = storage_->get_offline_license();
        if (!cached_offline) {
            ValidationResult result;
            result.valid = false;
            result.offline = true;
            result.reason_code = "no_offline_license";
            return Result<ValidationResult>::ok(result);
        }

        std::string public_key;
        if (!config_.offline_public_key.empty()) {
            public_key = config_.offline_public_key;
        } else {
            auto cached_key = storage_->get_public_key(cached_offline->key_id);
            if (cached_key) {
                public_key = *cached_key;
            }
        }

        if (public_key.empty()) {
            ValidationResult result;
            result.valid = false;
            result.offline = true;
            result.reason_code = "no_public_key";
            return Result<ValidationResult>::ok(result);
        }

        auto verify_result = verify_offline_license(*cached_offline, public_key);
        ValidationResult result;
        result.offline = true;

        if (verify_result.is_ok() && verify_result.value()) {
            result.valid = true;

            // Extract entitlements
            for (const auto& ent : cached_offline->entitlements) {
                result.active_entitlements.push_back(ent);
            }

            // Check grace period
            auto last_seen = storage_->get_last_seen_timestamp();
            if (last_seen && config_.max_offline_days > 0) {
                auto now = std::chrono::system_clock::now();
                auto last_seen_time = std::chrono::system_clock::from_time_t(
                    static_cast<std::time_t>(*last_seen));
                auto days = std::chrono::duration_cast<std::chrono::hours>(now - last_seen_time)
                                .count() /
                            24;
                if (days > config_.max_offline_days) {
                    result.valid = false;
                    result.reason_code = "grace_period_expired";
                }
            }
        } else {
            result.valid = false;
            result.reason_code = "signature_invalid";
        }

        return Result<ValidationResult>::ok(result);
    }

    void sync_offline_assets_impl() {
        if (!cached_license_) {
            return;
        }

        auto license_key = cached_license_->key();
        if (license_key.empty()) {
            return;
        }

        // Fetch offline license
        auto offline_result = generate_offline_license(license_key);
        if (offline_result.is_ok()) {
            auto& offline = offline_result.value();

            // Fetch public key if needed
            if (!offline.key_id.empty()) {
                auto cached_key = storage_->get_public_key(offline.key_id);
                if (!cached_key) {
                    (void)fetch_public_key(offline.key_id);
                }
            }
        }
    }

    void update_storage_license(const std::string& license_key, const std::string& device_id,
                                const ValidationResult& validation) {
        CachedLicense cached;
        cached.license_key = license_key;
        cached.device_identifier = device_id;
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

    Config config_;
    std::string device_identifier_;
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

    // Network status
    std::atomic<bool> is_online_{true};
};

// Client implementation
Client::Client(Config config) : impl_(std::make_unique<Impl>(std::move(config))) {}

Client::~Client() = default;

Client::Client(Client&&) noexcept = default;
Client& Client::operator=(Client&&) noexcept = default;

Result<ValidationResult> Client::validate(const std::string& license_key,
                                          const std::string& device_identifier) {
    return impl_->validate(license_key, device_identifier);
}

Result<Activation> Client::activate(const std::string& license_key,
                                    const std::string& device_identifier, const Metadata& metadata) {
    return impl_->activate(license_key, device_identifier, metadata);
}

Result<Activation> Client::deactivate(const std::string& license_key,
                                      const std::string& device_identifier) {
    return impl_->deactivate(license_key, device_identifier);
}

void Client::validate_async(const std::string& license_key, AsyncCallback callback,
                            const std::string& device_identifier) {
    impl_->validate_async(license_key, std::move(callback), device_identifier);
}

void Client::activate_async(const std::string& license_key, ActivationCallback callback,
                            const std::string& device_identifier, const Metadata& metadata) {
    impl_->activate_async(license_key, std::move(callback), device_identifier, metadata);
}

void Client::deactivate_async(const std::string& license_key, ActivationCallback callback,
                              const std::string& device_identifier) {
    impl_->deactivate_async(license_key, std::move(callback), device_identifier);
}

Result<OfflineLicense> Client::generate_offline_license(const std::string& license_key) {
    return impl_->generate_offline_license(license_key);
}

Result<bool> Client::verify_offline_license(const OfflineLicense& offline_license,
                                            const std::string& public_key_b64) {
    return impl_->verify_offline_license(offline_license, public_key_b64);
}

Result<std::string> Client::fetch_public_key(const std::string& key_id) {
    return impl_->fetch_public_key(key_id);
}

void Client::sync_offline_assets() { impl_->sync_offline_assets(); }

void Client::start_auto_validation(const std::string& license_key) {
    impl_->start_auto_validation(license_key);
}

void Client::stop_auto_validation() { impl_->stop_auto_validation(); }

bool Client::is_auto_validating() const { return impl_->is_auto_validating(); }

ValidationResult Client::get_status() const { return impl_->get_status(); }

std::optional<License> Client::current_license() const { return impl_->current_license(); }

EntitlementStatus Client::check_entitlement(const std::string& entitlement_key) const {
    return impl_->check_entitlement(entitlement_key);
}

bool Client::is_online() const { return impl_->is_online(); }

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

Result<DownloadToken> Client::generate_download_token(int release_id,
                                                      const std::string& license_key) {
    return impl_->generate_download_token(release_id, license_key);
}

Result<bool> Client::heartbeat() { return impl_->heartbeat(); }

void Client::reset() { impl_->reset(); }

const Config& Client::config() const noexcept { return impl_->config(); }

const std::string& Client::device_identifier() const { return impl_->device_identifier(); }

}  // namespace licenseseat
