#pragma once

/**
 * @file licenseseat.hpp
 * @brief LicenseSeat C++ SDK
 *
 * A minimal-dependency C++ SDK for the LicenseSeat licensing API.
 * Designed for constrained environments like VST plugins, game engines, etc.
 */

#include <any>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace licenseseat {

/// Library version
constexpr const char* VERSION = "0.1.0";

/// Metadata type used throughout the SDK
using Metadata = std::map<std::string, std::string>;

/// Error codes returned by SDK operations (matches API reason_codes)
enum class ErrorCode {
    Success = 0,

    // Network errors
    NetworkError,
    ConnectionTimeout,
    SSLError,

    // License errors
    InvalidLicenseKey,
    LicenseNotFound,
    LicenseExpired,
    LicenseRevoked,
    LicenseSuspended,
    LicenseNotActive,
    LicenseNotStarted,

    // Activation errors
    SeatLimitExceeded,
    ActivationNotFound,
    DeviceAlreadyActivated,

    // Product errors
    ProductNotFound,
    ReleaseNotFound,

    // Authentication/Authorization
    AuthenticationFailed,
    PermissionDenied,

    // Request errors
    MissingParameter,
    InvalidParameter,
    ValidationFailed,

    // Server errors
    ServerError,
    FeatureNotConfigured,
    SigningNotConfigured,

    // Parse errors
    ParseError,
    InvalidSignature,

    // File errors
    FileError,
    FileNotFound,

    Unknown
};

/// Convert error code to string
[[nodiscard]] constexpr const char* error_code_to_string(ErrorCode code) noexcept {
    switch (code) {
        case ErrorCode::Success:
            return "Success";
        case ErrorCode::NetworkError:
            return "Network error";
        case ErrorCode::ConnectionTimeout:
            return "Connection timeout";
        case ErrorCode::SSLError:
            return "SSL/TLS error";
        case ErrorCode::InvalidLicenseKey:
            return "Invalid license key";
        case ErrorCode::LicenseNotFound:
            return "License not found";
        case ErrorCode::LicenseExpired:
            return "License expired";
        case ErrorCode::LicenseRevoked:
            return "License revoked";
        case ErrorCode::LicenseSuspended:
            return "License suspended";
        case ErrorCode::LicenseNotActive:
            return "License not active";
        case ErrorCode::LicenseNotStarted:
            return "License has not started yet";
        case ErrorCode::SeatLimitExceeded:
            return "Seat limit exceeded";
        case ErrorCode::ActivationNotFound:
            return "Activation not found";
        case ErrorCode::DeviceAlreadyActivated:
            return "Device already activated";
        case ErrorCode::ProductNotFound:
            return "Product not found";
        case ErrorCode::ReleaseNotFound:
            return "Release not found";
        case ErrorCode::AuthenticationFailed:
            return "Authentication failed";
        case ErrorCode::PermissionDenied:
            return "Permission denied";
        case ErrorCode::MissingParameter:
            return "Missing required parameter";
        case ErrorCode::InvalidParameter:
            return "Invalid parameter";
        case ErrorCode::ValidationFailed:
            return "Validation failed";
        case ErrorCode::ServerError:
            return "Server error";
        case ErrorCode::FeatureNotConfigured:
            return "Feature not configured";
        case ErrorCode::SigningNotConfigured:
            return "Signing not configured";
        case ErrorCode::ParseError:
            return "Parse error";
        case ErrorCode::InvalidSignature:
            return "Invalid signature";
        case ErrorCode::FileError:
            return "File error";
        case ErrorCode::FileNotFound:
            return "File not found";
        case ErrorCode::Unknown:
            return "Unknown error";
    }
    return "Unknown error";
}

/// License status as returned by the API
enum class LicenseStatus {
    Active,
    Expired,
    Revoked,
    Suspended,
    Pending,  // Not yet started
    Unknown
};

/// Convert license status to string
[[nodiscard]] constexpr const char* license_status_to_string(LicenseStatus status) noexcept {
    switch (status) {
        case LicenseStatus::Active:
            return "active";
        case LicenseStatus::Expired:
            return "expired";
        case LicenseStatus::Revoked:
            return "revoked";
        case LicenseStatus::Suspended:
            return "suspended";
        case LicenseStatus::Pending:
            return "pending";
        case LicenseStatus::Unknown:
            return "unknown";
    }
    return "unknown";
}

/// Parse license status from API string
[[nodiscard]] inline LicenseStatus license_status_from_string(const std::string& str) noexcept {
    if (str == "active")
        return LicenseStatus::Active;
    if (str == "expired")
        return LicenseStatus::Expired;
    if (str == "revoked")
        return LicenseStatus::Revoked;
    if (str == "suspended")
        return LicenseStatus::Suspended;
    if (str == "pending")
        return LicenseStatus::Pending;
    return LicenseStatus::Unknown;
}

/// License mode (how the license is enforced)
enum class LicenseMode {
    HardwareLocked,  // Tied to specific devices
    Floating,        // Concurrent usage limited
    Named,           // Tied to named users
    Unknown
};

/// Convert license mode to string
[[nodiscard]] constexpr const char* license_mode_to_string(LicenseMode mode) noexcept {
    switch (mode) {
        case LicenseMode::HardwareLocked:
            return "hardware_locked";
        case LicenseMode::Floating:
            return "floating";
        case LicenseMode::Named:
            return "named";
        case LicenseMode::Unknown:
            return "unknown";
    }
    return "unknown";
}

/// Parse license mode from API string
[[nodiscard]] inline LicenseMode license_mode_from_string(const std::string& str) noexcept {
    if (str == "hardware_locked")
        return LicenseMode::HardwareLocked;
    if (str == "floating")
        return LicenseMode::Floating;
    if (str == "named")
        return LicenseMode::Named;
    return LicenseMode::Unknown;
}

/**
 * @brief Result type for operations that can fail
 * @tparam T The success value type
 */
template <typename T> class Result {
  public:
    /// Construct a success result
    static Result ok(T value) {
        Result r;
        r.value_ = std::move(value);
        r.error_ = ErrorCode::Success;
        return r;
    }

    /// Construct an error result
    static Result error(ErrorCode code, std::string message = "") {
        Result r;
        r.error_ = code;
        r.error_message_ = std::move(message);
        return r;
    }

    /// Check if the result is successful
    [[nodiscard]] bool is_ok() const noexcept { return error_ == ErrorCode::Success; }

    /// Check if the result is an error
    [[nodiscard]] bool is_error() const noexcept { return error_ != ErrorCode::Success; }

    /// Get the value (undefined behavior if is_error())
    [[nodiscard]] const T& value() const& { return *value_; }
    [[nodiscard]] T& value() & { return *value_; }
    [[nodiscard]] T&& value() && { return std::move(*value_); }

    /// Get the error code
    [[nodiscard]] ErrorCode error_code() const noexcept { return error_; }

    /// Get the error message
    [[nodiscard]] const std::string& error_message() const noexcept { return error_message_; }

  private:
    Result() = default;
    std::optional<T> value_;
    ErrorCode error_ = ErrorCode::Unknown;
    std::string error_message_;
};

/// Specialization for void results
template <> class Result<void> {
  public:
    static Result ok() {
        Result r;
        r.error_ = ErrorCode::Success;
        return r;
    }

    static Result error(ErrorCode code, std::string message = "") {
        Result r;
        r.error_ = code;
        r.error_message_ = std::move(message);
        return r;
    }

    [[nodiscard]] bool is_ok() const noexcept { return error_ == ErrorCode::Success; }
    [[nodiscard]] bool is_error() const noexcept { return error_ != ErrorCode::Success; }
    [[nodiscard]] ErrorCode error_code() const noexcept { return error_; }
    [[nodiscard]] const std::string& error_message() const noexcept { return error_message_; }

  private:
    Result() = default;
    ErrorCode error_ = ErrorCode::Unknown;
    std::string error_message_;
};

/// Timestamp type used throughout the SDK
using Timestamp = std::chrono::system_clock::time_point;

/**
 * @brief Product information nested in license responses
 */
struct Product {
    std::string slug;
    std::string name;
};

/**
 * @brief Represents an entitlement attached to a license
 */
struct Entitlement {
    std::string key;                      // Feature/entitlement key (e.g., "updates")
    std::optional<Timestamp> expires_at;  // Optional per-entitlement expiry
    Metadata metadata;                    // Per-entitlement metadata
};

/**
 * @brief Represents a software license from the API
 *
 * Contains all license information as returned by the LicenseSeat API,
 * including status, dates, seat limits, and metadata.
 */
class License {
  public:
    License() = default;

    /// Full constructor with all fields
    License(std::string key, LicenseStatus status, LicenseMode mode, std::string plan_key,
            std::optional<int> seat_limit, int active_seats, std::optional<Timestamp> starts_at,
            std::optional<Timestamp> expires_at, std::vector<Entitlement> active_entitlements,
            Metadata metadata, Product product)
        : key_(std::move(key)),
          status_(status),
          mode_(mode),
          plan_key_(std::move(plan_key)),
          seat_limit_(seat_limit),
          active_seats_(active_seats),
          starts_at_(starts_at),
          expires_at_(expires_at),
          active_entitlements_(std::move(active_entitlements)),
          metadata_(std::move(metadata)),
          product_(std::move(product)) {}

    /// Get the license key
    [[nodiscard]] const std::string& key() const noexcept { return key_; }

    /// Get the license status
    [[nodiscard]] LicenseStatus status() const noexcept { return status_; }

    /// Get the license mode
    [[nodiscard]] LicenseMode mode() const noexcept { return mode_; }

    /// Get the plan key (e.g., "pro-annual", "starter-monthly")
    [[nodiscard]] const std::string& plan_key() const noexcept { return plan_key_; }

    /// Get the maximum number of concurrent activations allowed (nullopt = unlimited)
    [[nodiscard]] std::optional<int> seat_limit() const noexcept { return seat_limit_; }

    /// Get the current number of active seats
    [[nodiscard]] int active_seats() const noexcept { return active_seats_; }

    /// Get the license start date (when it becomes valid)
    [[nodiscard]] const std::optional<Timestamp>& starts_at() const noexcept { return starts_at_; }

    /// Get the license expiry date
    [[nodiscard]] const std::optional<Timestamp>& expires_at() const noexcept { return expires_at_; }

    /// Get active entitlements for this license
    [[nodiscard]] const std::vector<Entitlement>& active_entitlements() const noexcept {
        return active_entitlements_;
    }

    /// Get custom metadata associated with the license
    [[nodiscard]] const Metadata& metadata() const noexcept { return metadata_; }

    /// Get the product this license belongs to
    [[nodiscard]] const Product& product() const noexcept { return product_; }

    /// Check if the license is currently valid (active and not expired)
    [[nodiscard]] bool is_valid() const noexcept {
        if (status_ != LicenseStatus::Active) {
            return false;
        }
        auto now = std::chrono::system_clock::now();
        if (starts_at_.has_value() && now < *starts_at_) {
            return false;
        }
        if (expires_at_.has_value() && now > *expires_at_) {
            return false;
        }
        return true;
    }

    /// Check if the license has expired
    [[nodiscard]] bool is_expired() const noexcept {
        if (!expires_at_.has_value()) {
            return false;
        }
        return std::chrono::system_clock::now() > *expires_at_;
    }

    /// Check if the license has started (is past its start date)
    [[nodiscard]] bool has_started() const noexcept {
        if (!starts_at_.has_value()) {
            return true;
        }
        return std::chrono::system_clock::now() >= *starts_at_;
    }

    /// Check if there are seats available for activation
    [[nodiscard]] bool has_available_seats() const noexcept {
        if (!seat_limit_.has_value() || *seat_limit_ <= 0) {
            return true;  // Unlimited seats
        }
        return active_seats_ < *seat_limit_;
    }

    /// Get remaining seat count (-1 if unlimited)
    [[nodiscard]] int remaining_seats() const noexcept {
        if (!seat_limit_.has_value() || *seat_limit_ <= 0) {
            return -1;  // Unlimited
        }
        return *seat_limit_ - active_seats_;
    }

  private:
    std::string key_;
    LicenseStatus status_ = LicenseStatus::Unknown;
    LicenseMode mode_ = LicenseMode::Unknown;
    std::string plan_key_;
    std::optional<int> seat_limit_;
    int active_seats_ = 0;
    std::optional<Timestamp> starts_at_;
    std::optional<Timestamp> expires_at_;
    std::vector<Entitlement> active_entitlements_;
    Metadata metadata_;
    Product product_;
};

/**
 * @brief Represents a device activation
 *
 * Contains information about a specific device activation for a license.
 */
class Activation {
  public:
    Activation() = default;

    Activation(int64_t id, std::string device_id, std::string device_name,
               std::string license_key, Timestamp activated_at,
               std::optional<Timestamp> deactivated_at, std::string ip_address, Metadata metadata)
        : id_(id),
          device_id_(std::move(device_id)),
          device_name_(std::move(device_name)),
          license_key_(std::move(license_key)),
          activated_at_(activated_at),
          deactivated_at_(deactivated_at),
          ip_address_(std::move(ip_address)),
          metadata_(std::move(metadata)) {}

    /// Get the activation ID
    [[nodiscard]] int64_t id() const noexcept { return id_; }

    /// Get the device ID
    [[nodiscard]] const std::string& device_id() const noexcept { return device_id_; }

    /// Get the device name
    [[nodiscard]] const std::string& device_name() const noexcept { return device_name_; }

    /// Get the associated license key
    [[nodiscard]] const std::string& license_key() const noexcept { return license_key_; }

    /// Get the activation timestamp
    [[nodiscard]] const Timestamp& activated_at() const noexcept { return activated_at_; }

    /// Get the deactivation timestamp (if deactivated)
    [[nodiscard]] const std::optional<Timestamp>& deactivated_at() const noexcept {
        return deactivated_at_;
    }

    /// Get the IP address used during activation
    [[nodiscard]] const std::string& ip_address() const noexcept { return ip_address_; }

    /// Get custom metadata
    [[nodiscard]] const Metadata& metadata() const noexcept { return metadata_; }

    /// Check if this activation is currently active
    [[nodiscard]] bool is_active() const noexcept { return !deactivated_at_.has_value(); }

  private:
    int64_t id_ = 0;
    std::string device_id_;
    std::string device_name_;
    std::string license_key_;
    Timestamp activated_at_;
    std::optional<Timestamp> deactivated_at_;
    std::string ip_address_;
    Metadata metadata_;
};

/**
 * @brief Token payload for offline license verification
 */
struct OfflineTokenPayload {
    int schema_version = 1;
    std::string license_key;
    std::string product_slug;
    std::string plan_key;
    std::string mode;                   // "hardware_locked", "floating", etc.
    std::optional<int> seat_limit;
    std::optional<std::string> device_id;  // Required for hardware_locked mode
    int64_t iat = 0;                    // Issued at (Unix timestamp)
    int64_t exp = 0;                    // Token expires at (Unix timestamp)
    int64_t nbf = 0;                    // Not before (Unix timestamp)
    std::optional<int64_t> license_expires_at;  // License expiry (Unix timestamp)
    std::string kid;                    // Key ID for signature verification
    std::vector<Entitlement> entitlements;
    Metadata metadata;
};

/**
 * @brief Signature block for offline token
 */
struct OfflineTokenSignature {
    std::string algorithm = "Ed25519";
    std::string key_id;
    std::string value;                  // Base64-encoded signature
};

/**
 * @brief Represents an offline token for air-gapped license validation
 *
 * Used for offline license validation. The token is signed with Ed25519
 * and can be verified without contacting the server.
 */
struct OfflineToken {
    OfflineTokenPayload token;
    OfflineTokenSignature signature;
    std::string canonical;              // Exact JSON string that was signed

    /// Check if the offline token has expired
    [[nodiscard]] bool is_expired() const noexcept {
        auto now = std::chrono::system_clock::now();
        auto exp_time = std::chrono::system_clock::from_time_t(token.exp);
        return now > exp_time;
    }

    /// Check if the token is not yet valid (before nbf)
    [[nodiscard]] bool is_not_yet_valid() const noexcept {
        auto now = std::chrono::system_clock::now();
        auto nbf_time = std::chrono::system_clock::from_time_t(token.nbf);
        return now < nbf_time;
    }

    /// Check if the underlying license has expired
    [[nodiscard]] bool is_license_expired() const noexcept {
        if (!token.license_expires_at.has_value()) {
            return false;  // No expiry means never expires
        }
        auto now = std::chrono::system_clock::now();
        auto exp_time = std::chrono::system_clock::from_time_t(*token.license_expires_at);
        return now > exp_time;
    }

    /// Check if a specific entitlement is present and not expired
    [[nodiscard]] bool has_entitlement(const std::string& entitlement_key) const noexcept {
        auto now = std::chrono::system_clock::now();
        for (const auto& ent : token.entitlements) {
            if (ent.key == entitlement_key) {
                if (!ent.expires_at.has_value()) {
                    return true;
                }
                return now <= *ent.expires_at;
            }
        }
        return false;
    }
};

/**
 * @brief Represents a software release
 */
struct Release {
    std::string version;
    std::string channel;        // stable, beta, alpha
    std::string platform;       // macos, windows, linux
    std::string product_slug;
    std::optional<Timestamp> published_at;
};

/**
 * @brief Download token for gated releases
 */
struct DownloadToken {
    std::string token;
    std::optional<Timestamp> expires_at;
};

/**
 * @brief Deactivation response
 */
struct Deactivation {
    int64_t activation_id = 0;
    Timestamp deactivated_at;
};

/**
 * @brief Warning in validation response
 */
struct ValidationWarning {
    std::string code;
    std::string message;
};

/**
 * @brief Offline fallback mode for network failures
 */
enum class OfflineFallbackMode {
    Always,      // Always try offline fallback on any error
    NetworkOnly  // Only fallback on network/transport errors
};

/**
 * @brief Configuration for the LicenseSeat client
 */
struct Config {
    /// API key for authentication (required)
    std::string api_key;

    /// Base URL for the LicenseSeat API (includes /api/v1)
    std::string api_url = "https://licenseseat.com/api/v1";

    /// Product slug to validate licenses against (required)
    std::string product_slug;

    /// Device ID (auto-generated if empty)
    std::string device_id;

    /// Path for license cache storage (required for persistence)
    std::string storage_path;

    /// Storage prefix for file names
    std::string storage_prefix = "licenseseat";

    /// Ed25519 public key for offline token verification (base64-encoded)
    /// If not provided, will be fetched from API on first use
    std::string signing_public_key;

    /// Key ID for the signing public key
    std::string signing_key_id;

    /// HTTP request timeout in seconds
    int timeout_seconds = 30;

    /// Enable SSL certificate verification (disable only for testing!)
    bool verify_ssl = true;

    /// Number of retry attempts for failed requests
    int max_retries = 3;

    /// Interval between retries in milliseconds
    int retry_interval_ms = 1000;

    // ========== Auto-Validation Settings ==========

    /// Interval for automatic re-validation in seconds (0 to disable)
    double auto_validate_interval = 300.0;  // 5 minutes

    /// Interval for network status checks when offline (seconds)
    double network_recheck_interval = 30.0;

    // ========== Offline Fallback Settings ==========

    /// Offline fallback mode
    OfflineFallbackMode offline_fallback_mode = OfflineFallbackMode::NetworkOnly;

    /// Maximum days to allow offline operation (0 = unlimited)
    int max_offline_days = 30;

    /// Maximum clock skew allowed in milliseconds (for tamper detection)
    double max_clock_skew_ms = 86400000.0;  // 24 hours

    /// Interval for refreshing offline license (seconds)
    double offline_license_refresh_interval = 86400.0;  // 24 hours

    // ========== Debug Settings ==========

    /// Enable debug logging
    bool debug = false;
};

/**
 * @brief Validation response from the API
 */
struct ValidationResult {
    bool valid = false;
    std::string code;              // Machine-readable code (when invalid)
    std::string message;           // Human-readable message (when invalid)
    std::vector<ValidationWarning> warnings;  // Non-fatal advisories
    bool offline = false;          // Whether this was an offline validation
    License license;
    std::optional<Activation> activation;  // Present when device was validated
};

// Forward declarations for callback types
class Subscription;
using EventHandler = std::function<void(const std::any&)>;
using AsyncCallback = std::function<void(Result<ValidationResult>)>;
using ActivationCallback = std::function<void(Result<Activation>)>;
using DeactivationCallback = std::function<void(Result<Deactivation>)>;
using OfflineTokenCallback = std::function<void(Result<OfflineToken>)>;

/**
 * @brief Entitlement check result
 */
struct EntitlementStatus {
    bool active = false;
    std::string reason;  // "no_license", "not_found", "expired", etc.
    std::optional<Timestamp> expires_at;
    std::optional<Entitlement> entitlement;
};

/**
 * @brief Main client for interacting with the LicenseSeat API
 *
 * The Client class provides a high-level interface to the LicenseSeat API.
 * It handles HTTP communication, JSON parsing, caching, auto-validation,
 * and offline fallback internally.
 *
 * Thread Safety: All public methods are thread-safe.
 *
 * ## Event-Driven Architecture
 *
 * Subscribe to SDK events for reactive updates:
 * ```cpp
 * client.on("validation:success", [](const auto& data) {
 *     std::cout << "License validated!" << std::endl;
 * });
 * ```
 *
 * ## Auto-Validation
 *
 * The SDK automatically revalidates licenses periodically. Configure with:
 * ```cpp
 * config.auto_validate_interval = 300.0; // 5 minutes
 * ```
 *
 * ## Offline Fallback
 *
 * When network is unavailable, the SDK automatically falls back to
 * cached offline license verification (Ed25519 signature).
 */
class Client {
  public:
    /// Construct a client with the given configuration
    explicit Client(Config config);

    /// Destructor
    ~Client();

    // Non-copyable
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    // Movable
    Client(Client&&) noexcept;
    Client& operator=(Client&&) noexcept;

    // ========== Synchronous API ==========

    /// Validate a license key
    /// @param license_key The license key to validate
    /// @param device_id Optional device ID (uses config if empty)
    [[nodiscard]] Result<ValidationResult> validate(
        const std::string& license_key,
        const std::string& device_id = "");

    /// Activate a license on this device
    /// @param license_key The license key to activate
    /// @param device_id Optional device ID (uses config if empty)
    /// @param device_name Optional human-readable device name
    /// @param metadata Optional metadata to attach to the activation
    [[nodiscard]] Result<Activation> activate(
        const std::string& license_key,
        const std::string& device_id = "",
        const std::string& device_name = "",
        const Metadata& metadata = {});

    /// Deactivate a license on this device
    /// @param license_key The license key to deactivate
    /// @param device_id Device ID to deactivate (required)
    [[nodiscard]] Result<Deactivation> deactivate(
        const std::string& license_key,
        const std::string& device_id);

    // ========== Asynchronous API ==========

    /// Validate a license key asynchronously
    /// @param license_key The license key to validate
    /// @param callback Called when validation completes
    /// @param device_id Optional device ID (uses config if empty)
    void validate_async(
        const std::string& license_key,
        AsyncCallback callback,
        const std::string& device_id = "");

    /// Activate a license asynchronously
    /// @param license_key The license key to activate
    /// @param callback Called when activation completes
    /// @param device_id Optional device ID (uses config if empty)
    /// @param device_name Optional human-readable device name
    /// @param metadata Optional metadata to attach to the activation
    void activate_async(
        const std::string& license_key,
        ActivationCallback callback,
        const std::string& device_id = "",
        const std::string& device_name = "",
        const Metadata& metadata = {});

    /// Deactivate a license asynchronously
    /// @param license_key The license key to deactivate
    /// @param callback Called when deactivation completes
    /// @param device_id Device ID to deactivate (required)
    void deactivate_async(
        const std::string& license_key,
        DeactivationCallback callback,
        const std::string& device_id);

    // ========== Offline Tokens ==========

    /// Generate an offline token from the server
    /// @param license_key The license key to generate offline token for
    /// @param device_id Optional device ID (required for hardware_locked licenses)
    /// @param ttl_days Token lifetime in days (default: 30, max: 90)
    [[nodiscard]] Result<OfflineToken> generate_offline_token(
        const std::string& license_key,
        const std::string& device_id = "",
        int ttl_days = 30);

    /// Verify an offline token locally (no network required)
    /// @param offline_token The offline token to verify
    /// @param public_key_b64 Base64-encoded Ed25519 public key (uses config if empty)
    [[nodiscard]] Result<bool> verify_offline_token(
        const OfflineToken& offline_token,
        const std::string& public_key_b64 = "");

    /// Fetch a signing key for offline verification from the API
    /// @param key_id The key ID to fetch
    [[nodiscard]] Result<std::string> fetch_signing_key(const std::string& key_id);

    /// Sync offline assets (fetch offline license and public key)
    void sync_offline_assets();

    // ========== Auto-Validation ==========

    /// Start automatic license validation
    /// @param license_key The license key to validate periodically
    void start_auto_validation(const std::string& license_key);

    /// Stop automatic license validation
    void stop_auto_validation();

    /// Check if auto-validation is running
    [[nodiscard]] bool is_auto_validating() const;

    // ========== Status & State ==========

    /// Get the current license status based on cached data
    [[nodiscard]] ValidationResult get_status() const;

    /// Get the currently cached license (if any)
    [[nodiscard]] std::optional<License> current_license() const;

    /// Check if a specific entitlement is active
    /// @param entitlement_key The entitlement key to check
    [[nodiscard]] EntitlementStatus check_entitlement(const std::string& entitlement_key) const;

    /// Check if the client is online (network available)
    [[nodiscard]] bool is_online() const;

    // ========== Event Handling ==========

    /// Subscribe to SDK events
    /// @param event Event name (e.g., "validation:success")
    /// @param handler Callback function
    /// @return Subscription handle (call cancel() to unsubscribe)
    Subscription on(const std::string& event, EventHandler handler);

    /// Emit an event (for testing/integration)
    void emit(const std::string& event, const std::any& data = {});

    // ========== Releases ==========

    /// Get the latest release for a product
    /// @param product_slug Product slug (uses config if empty)
    /// @param channel Filter by channel (stable, beta, alpha)
    /// @param platform Filter by platform (macos, windows, linux)
    [[nodiscard]] Result<Release> get_latest_release(
        const std::string& product_slug = "",
        const std::string& channel = "",
        const std::string& platform = "");

    /// List all releases for a product
    /// @param product_slug Product slug (uses config if empty)
    /// @param channel Filter by channel (stable, beta, alpha)
    /// @param platform Filter by platform (macos, windows, linux)
    [[nodiscard]] Result<std::vector<Release>> list_releases(
        const std::string& product_slug = "",
        const std::string& channel = "",
        const std::string& platform = "");

    /// Generate a download token for a release
    /// @param version Release version string (e.g., "2.1.0")
    /// @param license_key License key for authorization
    /// @param product_slug Product slug (uses config if empty)
    /// @param platform Optional platform filter
    [[nodiscard]] Result<DownloadToken> generate_download_token(
        const std::string& version,
        const std::string& license_key,
        const std::string& product_slug = "",
        const std::string& platform = "");

    // ========== Health & Utility ==========

    /// Check if the API is available (calls /health endpoint)
    [[nodiscard]] Result<bool> health();

    /// Reset SDK state (clear cache, stop timers)
    void reset();

    /// Get the current configuration
    [[nodiscard]] const Config& config() const noexcept;

    /// Get the device ID (auto-generated if not in config)
    [[nodiscard]] const std::string& device_id() const;

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @brief Subscription handle for event unsubscription
 */
class Subscription {
  public:
    Subscription() = default;
    explicit Subscription(std::function<void()> unsubscribe) : unsubscribe_(std::move(unsubscribe)) {}

    /// Cancel this subscription
    void cancel() {
        if (unsubscribe_) {
            unsubscribe_();
            unsubscribe_ = nullptr;
        }
    }

    /// Check if subscription is active
    [[nodiscard]] bool is_active() const { return unsubscribe_ != nullptr; }

  private:
    std::function<void()> unsubscribe_;
};

} // namespace licenseseat
