#pragma once

/**
 * @file json.hpp
 * @brief JSON serialization utilities for LicenseSeat SDK types
 *
 * Uses nlohmann/json for parsing API responses into SDK types.
 */

#include "licenseseat.hpp"

#include <nlohmann/json.hpp>

#include <ctime>
#include <iomanip>
#include <sstream>

namespace licenseseat {
namespace json {

using nlohmann::json;

// ==================== Timestamp Helpers ====================

/// Parse ISO 8601 timestamp string to Timestamp
[[nodiscard]] inline std::optional<Timestamp> parse_timestamp(const std::string& str) {
    if (str.empty()) {
        return std::nullopt;
    }

    // Parse ISO 8601 format: "2026-01-19T12:00:00Z"
    std::tm tm = {};
    std::istringstream ss(str);
    ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");

    if (ss.fail()) {
        return std::nullopt;
    }

    // Handle UTC timezone
    auto time = std::mktime(&tm);
    if (time == -1) {
        return std::nullopt;
    }

    return std::chrono::system_clock::from_time_t(time);
}

/// Parse Unix timestamp (seconds) to Timestamp
[[nodiscard]] inline Timestamp parse_unix_timestamp(int64_t unix_ts) {
    return std::chrono::system_clock::from_time_t(static_cast<std::time_t>(unix_ts));
}

/// Format Timestamp to ISO 8601 string
[[nodiscard]] inline std::string format_timestamp(const Timestamp& ts) {
    auto time = std::chrono::system_clock::to_time_t(ts);
    std::tm tm = {};
#if defined(_MSC_VER)
    gmtime_s(&tm, &time);
#else
    gmtime_r(&time, &tm);
#endif
    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

// ==================== Metadata Helpers ====================

/// Parse JSON object to Metadata map (string values only)
[[nodiscard]] inline Metadata parse_metadata(const json& j) {
    Metadata result;
    if (j.is_object()) {
        for (auto& [key, value] : j.items()) {
            if (value.is_string()) {
                result[key] = value.get<std::string>();
            } else if (value.is_number()) {
                result[key] = std::to_string(value.get<double>());
            } else if (value.is_boolean()) {
                result[key] = value.get<bool>() ? "true" : "false";
            }
        }
    }
    return result;
}

/// Convert Metadata to JSON object
[[nodiscard]] inline json metadata_to_json(const Metadata& meta) {
    json j = json::object();
    for (const auto& [key, value] : meta) {
        j[key] = value;
    }
    return j;
}

// ==================== Entitlement Parsing ====================

/// Parse Entitlement from JSON (new API format)
[[nodiscard]] inline Entitlement parse_entitlement(const json& j) {
    Entitlement ent;

    if (j.contains("key")) {
        ent.key = j["key"].get<std::string>();
    }

    // New API uses expires_at as ISO timestamp string
    if (j.contains("expires_at") && !j["expires_at"].is_null()) {
        if (j["expires_at"].is_string()) {
            ent.expires_at = parse_timestamp(j["expires_at"].get<std::string>());
        } else if (j["expires_at"].is_number()) {
            // Offline tokens use unix timestamp
            ent.expires_at = parse_unix_timestamp(j["expires_at"].get<int64_t>());
        }
    }

    if (j.contains("metadata") && j["metadata"].is_object()) {
        ent.metadata = parse_metadata(j["metadata"]);
    }

    return ent;
}

/// Parse array of entitlements
[[nodiscard]] inline std::vector<Entitlement> parse_entitlements(const json& j) {
    std::vector<Entitlement> result;
    if (j.is_array()) {
        for (const auto& item : j) {
            result.push_back(parse_entitlement(item));
        }
    }
    return result;
}

// ==================== Product Parsing ====================

/// Parse Product from JSON
[[nodiscard]] inline Product parse_product(const json& j) {
    Product product;
    if (j.contains("slug")) {
        product.slug = j["slug"].get<std::string>();
    }
    if (j.contains("name")) {
        product.name = j["name"].get<std::string>();
    }
    return product;
}

// ==================== License Parsing ====================

/// Parse License from JSON response (new API format)
[[nodiscard]] inline License parse_license(const json& j) {
    std::string key;
    // New API uses "key" instead of "license_key"
    if (j.contains("key")) {
        key = j["key"].get<std::string>();
    }

    LicenseStatus status = LicenseStatus::Unknown;
    if (j.contains("status")) {
        status = license_status_from_string(j["status"].get<std::string>());
    }

    LicenseMode mode = LicenseMode::Unknown;
    if (j.contains("mode")) {
        mode = license_mode_from_string(j["mode"].get<std::string>());
    }

    std::string plan_key;
    if (j.contains("plan_key")) {
        plan_key = j["plan_key"].get<std::string>();
    }

    // seat_limit can be null (unlimited)
    std::optional<int> seat_limit;
    if (j.contains("seat_limit") && !j["seat_limit"].is_null()) {
        seat_limit = j["seat_limit"].get<int>();
    }

    // New API uses "active_seats" instead of "active_activations_count"
    int active_seats = 0;
    if (j.contains("active_seats") && j["active_seats"].is_number()) {
        active_seats = j["active_seats"].get<int>();
    }

    std::optional<Timestamp> starts_at;
    if (j.contains("starts_at") && !j["starts_at"].is_null()) {
        starts_at = parse_timestamp(j["starts_at"].get<std::string>());
    }

    // New API uses "expires_at" instead of "ends_at"
    std::optional<Timestamp> expires_at;
    if (j.contains("expires_at") && !j["expires_at"].is_null()) {
        expires_at = parse_timestamp(j["expires_at"].get<std::string>());
    }

    // Parse active_entitlements array
    std::vector<Entitlement> active_entitlements;
    if (j.contains("active_entitlements") && j["active_entitlements"].is_array()) {
        active_entitlements = parse_entitlements(j["active_entitlements"]);
    }

    Metadata metadata;
    if (j.contains("metadata") && j["metadata"].is_object()) {
        metadata = parse_metadata(j["metadata"]);
    }

    // Parse nested product
    Product product;
    if (j.contains("product") && j["product"].is_object()) {
        product = parse_product(j["product"]);
    }

    return License(std::move(key), status, mode, std::move(plan_key), seat_limit,
                   active_seats, starts_at, expires_at, std::move(active_entitlements),
                   std::move(metadata), std::move(product));
}

// ==================== Activation Parsing ====================

/// Parse Activation from JSON response (new API format)
[[nodiscard]] inline Activation parse_activation(const json& j) {
    int64_t id = 0;
    if (j.contains("id") && j["id"].is_number()) {
        id = j["id"].get<int64_t>();
    }

    // New API uses "device_id" instead of "device_identifier"
    std::string device_id;
    if (j.contains("device_id")) {
        device_id = j["device_id"].get<std::string>();
    }

    // New API includes device_name
    std::string device_name;
    if (j.contains("device_name") && !j["device_name"].is_null()) {
        device_name = j["device_name"].get<std::string>();
    }

    std::string license_key;
    if (j.contains("license_key")) {
        license_key = j["license_key"].get<std::string>();
    }

    Timestamp activated_at;
    if (j.contains("activated_at") && !j["activated_at"].is_null()) {
        auto ts = parse_timestamp(j["activated_at"].get<std::string>());
        if (ts.has_value()) {
            activated_at = *ts;
        }
    }

    std::optional<Timestamp> deactivated_at;
    if (j.contains("deactivated_at") && !j["deactivated_at"].is_null()) {
        deactivated_at = parse_timestamp(j["deactivated_at"].get<std::string>());
    }

    std::string ip_address;
    if (j.contains("ip_address") && j["ip_address"].is_string()) {
        ip_address = j["ip_address"].get<std::string>();
    }

    Metadata metadata;
    if (j.contains("metadata") && j["metadata"].is_object()) {
        metadata = parse_metadata(j["metadata"]);
    }

    return Activation(id, std::move(device_id), std::move(device_name), std::move(license_key),
                      activated_at, deactivated_at, std::move(ip_address), std::move(metadata));
}

// ==================== Deactivation Parsing ====================

/// Parse Deactivation from JSON response
[[nodiscard]] inline Deactivation parse_deactivation(const json& j) {
    Deactivation result;

    if (j.contains("activation_id") && j["activation_id"].is_number()) {
        result.activation_id = j["activation_id"].get<int64_t>();
    }

    if (j.contains("deactivated_at") && !j["deactivated_at"].is_null()) {
        auto ts = parse_timestamp(j["deactivated_at"].get<std::string>());
        if (ts.has_value()) {
            result.deactivated_at = *ts;
        }
    }

    return result;
}

// ==================== Validation Warning Parsing ====================

/// Parse ValidationWarning from JSON
[[nodiscard]] inline ValidationWarning parse_validation_warning(const json& j) {
    ValidationWarning warning;
    if (j.contains("code")) {
        warning.code = j["code"].get<std::string>();
    }
    if (j.contains("message")) {
        warning.message = j["message"].get<std::string>();
    }
    return warning;
}

/// Parse array of warnings
[[nodiscard]] inline std::vector<ValidationWarning> parse_validation_warnings(const json& j) {
    std::vector<ValidationWarning> result;
    if (j.is_array()) {
        for (const auto& item : j) {
            result.push_back(parse_validation_warning(item));
        }
    }
    return result;
}

// ==================== Validation Result Parsing ====================

/// Parse ValidationResult from JSON response (new API format)
[[nodiscard]] inline ValidationResult parse_validation_result(const json& j) {
    ValidationResult result;

    if (j.contains("valid") && j["valid"].is_boolean()) {
        result.valid = j["valid"].get<bool>();
    }

    // New API uses "code" instead of "reason_code"
    if (j.contains("code")) {
        result.code = j["code"].get<std::string>();
    }

    // New API uses "message" instead of "reason"
    if (j.contains("message")) {
        result.message = j["message"].get<std::string>();
    }

    // Parse warnings array
    if (j.contains("warnings") && j["warnings"].is_array()) {
        result.warnings = parse_validation_warnings(j["warnings"]);
    }

    if (j.contains("license") && j["license"].is_object()) {
        result.license = parse_license(j["license"]);
    }

    // New API includes activation in validation response
    if (j.contains("activation") && j["activation"].is_object()) {
        result.activation = parse_activation(j["activation"]);
    }

    return result;
}

// ==================== Offline Token Parsing ====================

/// Parse OfflineTokenPayload from JSON
[[nodiscard]] inline OfflineTokenPayload parse_offline_token_payload(const json& j) {
    OfflineTokenPayload payload;

    if (j.contains("schema_version") && j["schema_version"].is_number()) {
        payload.schema_version = j["schema_version"].get<int>();
    }

    if (j.contains("license_key")) {
        payload.license_key = j["license_key"].get<std::string>();
    }

    if (j.contains("product_slug")) {
        payload.product_slug = j["product_slug"].get<std::string>();
    }

    if (j.contains("plan_key")) {
        payload.plan_key = j["plan_key"].get<std::string>();
    }

    if (j.contains("mode")) {
        payload.mode = j["mode"].get<std::string>();
    }

    if (j.contains("seat_limit") && !j["seat_limit"].is_null()) {
        payload.seat_limit = j["seat_limit"].get<int>();
    }

    if (j.contains("device_id") && !j["device_id"].is_null()) {
        payload.device_id = j["device_id"].get<std::string>();
    }

    if (j.contains("iat") && j["iat"].is_number()) {
        payload.iat = j["iat"].get<int64_t>();
    }

    if (j.contains("exp") && j["exp"].is_number()) {
        payload.exp = j["exp"].get<int64_t>();
    }

    if (j.contains("nbf") && j["nbf"].is_number()) {
        payload.nbf = j["nbf"].get<int64_t>();
    }

    if (j.contains("license_expires_at") && !j["license_expires_at"].is_null()) {
        payload.license_expires_at = j["license_expires_at"].get<int64_t>();
    }

    if (j.contains("kid")) {
        payload.kid = j["kid"].get<std::string>();
    }

    if (j.contains("entitlements") && j["entitlements"].is_array()) {
        for (const auto& ent_json : j["entitlements"]) {
            payload.entitlements.push_back(parse_entitlement(ent_json));
        }
    }

    if (j.contains("metadata") && j["metadata"].is_object()) {
        payload.metadata = parse_metadata(j["metadata"]);
    }

    return payload;
}

/// Parse OfflineTokenSignature from JSON
[[nodiscard]] inline OfflineTokenSignature parse_offline_token_signature(const json& j) {
    OfflineTokenSignature sig;

    if (j.contains("algorithm")) {
        sig.algorithm = j["algorithm"].get<std::string>();
    }

    if (j.contains("key_id")) {
        sig.key_id = j["key_id"].get<std::string>();
    }

    if (j.contains("value")) {
        sig.value = j["value"].get<std::string>();
    }

    return sig;
}

/// Parse OfflineToken from JSON response (new API format)
[[nodiscard]] inline OfflineToken parse_offline_token(const json& j) {
    OfflineToken offline;

    if (j.contains("token") && j["token"].is_object()) {
        offline.token = parse_offline_token_payload(j["token"]);
    }

    if (j.contains("signature") && j["signature"].is_object()) {
        offline.signature = parse_offline_token_signature(j["signature"]);
    }

    if (j.contains("canonical") && j["canonical"].is_string()) {
        offline.canonical = j["canonical"].get<std::string>();
    }

    return offline;
}

// ==================== Release Parsing ====================

/// Parse Release from JSON response
[[nodiscard]] inline Release parse_release(const json& j) {
    Release release;

    if (j.contains("version")) {
        release.version = j["version"].get<std::string>();
    }

    if (j.contains("channel")) {
        release.channel = j["channel"].get<std::string>();
    }

    if (j.contains("platform")) {
        release.platform = j["platform"].get<std::string>();
    }

    if (j.contains("product_slug")) {
        release.product_slug = j["product_slug"].get<std::string>();
    }

    if (j.contains("published_at") && !j["published_at"].is_null()) {
        release.published_at = parse_timestamp(j["published_at"].get<std::string>());
    }

    return release;
}

/// Parse list of releases from JSON response (handles list wrapper)
[[nodiscard]] inline std::vector<Release> parse_releases(const json& j) {
    std::vector<Release> releases;

    // Handle new list wrapper format: {"object": "list", "data": [...]}
    const json* data_array = nullptr;
    if (j.is_object() && j.contains("data") && j["data"].is_array()) {
        data_array = &j["data"];
    } else if (j.is_array()) {
        data_array = &j;
    }

    if (data_array) {
        for (const auto& item : *data_array) {
            releases.push_back(parse_release(item));
        }
    }

    return releases;
}

// ==================== Download Token Parsing ====================

/// Parse DownloadToken from JSON response (new API format)
[[nodiscard]] inline DownloadToken parse_download_token(const json& j) {
    DownloadToken token;

    // New API uses "token" instead of "download_token"
    if (j.contains("token")) {
        token.token = j["token"].get<std::string>();
    }

    // New API uses "expires_at" (ISO timestamp) instead of "expires_in_seconds"
    if (j.contains("expires_at") && !j["expires_at"].is_null()) {
        token.expires_at = parse_timestamp(j["expires_at"].get<std::string>());
    }

    return token;
}

// ==================== Signing Key Parsing ====================

/// Parse signing key from JSON response (new API format)
/// Returns the public key value (base64 encoded)
[[nodiscard]] inline std::string parse_signing_key(const json& j) {
    // New API uses "public_key" instead of "public_key_b64"
    if (j.contains("public_key")) {
        return j["public_key"].get<std::string>();
    }
    return "";
}

// ==================== Error Response Parsing ====================

/// API error response structure (new format)
struct ApiError {
    std::string code;
    std::string message;
};

/// Parse error response from JSON (new API format)
/// New format: {"error": {"code": "...", "message": "...", "details": {...}}}
[[nodiscard]] inline ApiError parse_error_response(const json& j) {
    ApiError err;

    if (j.contains("error") && j["error"].is_object()) {
        const auto& error_obj = j["error"];
        if (error_obj.contains("code")) {
            err.code = error_obj["code"].get<std::string>();
        }
        if (error_obj.contains("message")) {
            err.message = error_obj["message"].get<std::string>();
        }
    }

    return err;
}

/// Convert API error code to ErrorCode enum
[[nodiscard]] inline ErrorCode error_code_to_error_code(const std::string& code) {
    // Map common API error codes to our ErrorCode enum
    if (code == "license_not_found")
        return ErrorCode::LicenseNotFound;
    if (code == "license_expired")
        return ErrorCode::LicenseExpired;
    if (code == "license_revoked")
        return ErrorCode::LicenseRevoked;
    if (code == "license_suspended")
        return ErrorCode::LicenseSuspended;
    if (code == "license_not_active")
        return ErrorCode::LicenseNotActive;
    if (code == "license_not_started")
        return ErrorCode::LicenseNotStarted;
    if (code == "seat_limit_exceeded")
        return ErrorCode::SeatLimitExceeded;
    if (code == "activation_not_found")
        return ErrorCode::ActivationNotFound;
    if (code == "device_already_activated")
        return ErrorCode::DeviceAlreadyActivated;
    if (code == "product_not_found")
        return ErrorCode::ProductNotFound;
    if (code == "release_not_found")
        return ErrorCode::ReleaseNotFound;
    if (code == "missing_parameter")
        return ErrorCode::MissingParameter;
    if (code == "invalid_parameter")
        return ErrorCode::InvalidParameter;
    if (code == "invalid_license_key")
        return ErrorCode::InvalidLicenseKey;
    if (code == "validation_failed")
        return ErrorCode::ValidationFailed;
    if (code == "unauthorized")
        return ErrorCode::AuthenticationFailed;
    if (code == "forbidden")
        return ErrorCode::PermissionDenied;
    if (code == "signing_not_configured")
        return ErrorCode::SigningNotConfigured;
    if (code == "feature_not_configured")
        return ErrorCode::FeatureNotConfigured;
    if (code == "server_error")
        return ErrorCode::ServerError;

    return ErrorCode::Unknown;
}

// ==================== Request Body Builders ====================

/// Build JSON body for activation request (new API format)
[[nodiscard]] inline json build_activate_request(const std::string& device_id,
                                                 const std::string& device_name,
                                                 const Metadata& metadata) {
    json body;
    body["device_id"] = device_id;

    if (!device_name.empty()) {
        body["device_name"] = device_name;
    }

    if (!metadata.empty()) {
        body["metadata"] = metadata_to_json(metadata);
    }

    return body;
}

/// Build JSON body for deactivation request (new API format)
[[nodiscard]] inline json build_deactivate_request(const std::string& device_id) {
    json body;
    body["device_id"] = device_id;
    return body;
}

/// Build JSON body for validation request (new API format)
[[nodiscard]] inline json build_validate_request(const std::string& device_id) {
    json body;
    if (!device_id.empty()) {
        body["device_id"] = device_id;
    }
    return body;
}

/// Build JSON body for offline token request (new API format)
[[nodiscard]] inline json build_offline_token_request(const std::string& device_id,
                                                      int ttl_days) {
    json body;
    if (!device_id.empty()) {
        body["device_id"] = device_id;
    }
    if (ttl_days > 0) {
        body["ttl_days"] = ttl_days;
    }
    return body;
}

/// Build JSON body for download token request (new API format)
[[nodiscard]] inline json build_download_token_request(const std::string& license_key,
                                                       const std::string& platform) {
    json body;
    body["license_key"] = license_key;
    if (!platform.empty()) {
        body["platform"] = platform;
    }
    return body;
}

}  // namespace json
}  // namespace licenseseat
