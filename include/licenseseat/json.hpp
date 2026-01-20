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

/// Format Timestamp to ISO 8601 string
[[nodiscard]] inline std::string format_timestamp(const Timestamp& ts) {
    auto time = std::chrono::system_clock::to_time_t(ts);
    std::tm tm = *std::gmtime(&time);
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

// ==================== License Parsing ====================

/// Parse License from JSON response
[[nodiscard]] inline License parse_license(const json& j) {
    std::string key;
    if (j.contains("license_key")) {
        key = j["license_key"].get<std::string>();
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

    int seat_limit = 0;
    if (j.contains("seat_limit") && j["seat_limit"].is_number()) {
        seat_limit = j["seat_limit"].get<int>();
    }

    int active_activations_count = 0;
    if (j.contains("active_activations_count") && j["active_activations_count"].is_number()) {
        active_activations_count = j["active_activations_count"].get<int>();
    }

    std::optional<Timestamp> starts_at;
    if (j.contains("starts_at") && !j["starts_at"].is_null()) {
        starts_at = parse_timestamp(j["starts_at"].get<std::string>());
    }

    std::optional<Timestamp> ends_at;
    if (j.contains("ends_at") && !j["ends_at"].is_null()) {
        ends_at = parse_timestamp(j["ends_at"].get<std::string>());
    }

    Metadata metadata;
    if (j.contains("metadata") && j["metadata"].is_object()) {
        metadata = parse_metadata(j["metadata"]);
    }

    return License(std::move(key), status, mode, std::move(plan_key), seat_limit,
                   active_activations_count, starts_at, ends_at, std::move(metadata));
}

// ==================== Activation Parsing ====================

/// Parse Activation from JSON response
[[nodiscard]] inline Activation parse_activation(const json& j) {
    int64_t id = 0;
    if (j.contains("id") && j["id"].is_number()) {
        id = j["id"].get<int64_t>();
    }

    std::string device_identifier;
    if (j.contains("device_identifier")) {
        device_identifier = j["device_identifier"].get<std::string>();
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

    return Activation(id, std::move(device_identifier), std::move(license_key), activated_at,
                      deactivated_at, std::move(ip_address), std::move(metadata));
}

// ==================== Validation Result Parsing ====================

/// Parse ValidationResult from JSON response
[[nodiscard]] inline ValidationResult parse_validation_result(const json& j) {
    ValidationResult result;

    if (j.contains("valid") && j["valid"].is_boolean()) {
        result.valid = j["valid"].get<bool>();
    }

    if (j.contains("license") && j["license"].is_object()) {
        result.license = parse_license(j["license"]);
    }

    return result;
}

// ==================== Offline License Parsing ====================

/// Parse Entitlement from JSON
[[nodiscard]] inline Entitlement parse_entitlement(const json& j) {
    Entitlement ent;

    if (j.contains("key")) {
        ent.key = j["key"].get<std::string>();
    }

    if (j.contains("exp") && j["exp"].is_number()) {
        auto exp_ts = std::chrono::system_clock::from_time_t(j["exp"].get<int64_t>());
        ent.expires = exp_ts;
    }

    return ent;
}

/// Parse OfflineLicense from JSON response
[[nodiscard]] inline OfflineLicense parse_offline_license(const json& j) {
    OfflineLicense offline;

    // The response has payload and signature_b64u at the top level
    if (j.contains("signature_b64u")) {
        offline.signature_b64u = j["signature_b64u"].get<std::string>();
    }

    json payload;
    if (j.contains("payload") && j["payload"].is_object()) {
        payload = j["payload"];
    } else {
        payload = j;  // Maybe the whole object is the payload
    }

    if (payload.contains("lic_k")) {
        offline.license_key = payload["lic_k"].get<std::string>();
    }

    if (payload.contains("kid")) {
        offline.key_id = payload["kid"].get<std::string>();
    }

    if (payload.contains("iat") && payload["iat"].is_number()) {
        offline.issued_at = payload["iat"].get<int64_t>();
    }

    if (payload.contains("exp") && payload["exp"].is_number()) {
        offline.expires_at = payload["exp"].get<int64_t>();
    }

    if (payload.contains("ent") && payload["ent"].is_array()) {
        for (const auto& ent_json : payload["ent"]) {
            offline.entitlements.push_back(parse_entitlement(ent_json));
        }
    }

    if (payload.contains("meta") && payload["meta"].is_object()) {
        offline.metadata = parse_metadata(payload["meta"]);
    }

    return offline;
}

/// Serialize OfflineLicense payload to canonical JSON for signature verification
[[nodiscard]] inline std::string offline_license_to_canonical_json(const OfflineLicense& offline) {
    json payload;
    payload["lic_k"] = offline.license_key;
    payload["iat"] = offline.issued_at;
    payload["exp"] = offline.expires_at;
    payload["kid"] = offline.key_id;

    json ent_array = json::array();
    for (const auto& ent : offline.entitlements) {
        json ent_obj;
        ent_obj["key"] = ent.key;
        if (ent.expires.has_value()) {
            ent_obj["exp"] = std::chrono::system_clock::to_time_t(*ent.expires);
        }
        ent_array.push_back(ent_obj);
    }
    payload["ent"] = ent_array;

    payload["meta"] = metadata_to_json(offline.metadata);

    // dump with sorted keys for canonical form
    return payload.dump(-1, ' ', false, json::error_handler_t::replace);
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

/// Parse list of releases from JSON array
[[nodiscard]] inline std::vector<Release> parse_releases(const json& j) {
    std::vector<Release> releases;

    if (j.is_array()) {
        for (const auto& item : j) {
            releases.push_back(parse_release(item));
        }
    }

    return releases;
}

// ==================== Download Token Parsing ====================

/// Parse DownloadToken from JSON response
[[nodiscard]] inline DownloadToken parse_download_token(const json& j) {
    DownloadToken token;

    if (j.contains("download_token")) {
        token.token = j["download_token"].get<std::string>();
    }

    if (j.contains("expires_in_seconds") && j["expires_in_seconds"].is_number()) {
        token.expires_in_seconds = j["expires_in_seconds"].get<int>();
    }

    return token;
}

// ==================== Public Key Parsing ====================

/// Parse public key from JSON response
[[nodiscard]] inline std::string parse_public_key(const json& j) {
    if (j.contains("public_key_b64")) {
        return j["public_key_b64"].get<std::string>();
    }
    return "";
}

// ==================== Error Response Parsing ====================

/// API error response structure
struct ApiError {
    std::string error;
    std::string reason_code;
};

/// Parse error response from JSON
[[nodiscard]] inline ApiError parse_error_response(const json& j) {
    ApiError err;

    if (j.contains("error")) {
        err.error = j["error"].get<std::string>();
    }

    if (j.contains("reason_code")) {
        err.reason_code = j["reason_code"].get<std::string>();
    }

    return err;
}

/// Convert API reason_code to ErrorCode
[[nodiscard]] inline ErrorCode reason_code_to_error_code(const std::string& reason_code) {
    // Map common API reason codes to our ErrorCode enum
    if (reason_code == "license_not_found")
        return ErrorCode::LicenseNotFound;
    if (reason_code == "license_expired")
        return ErrorCode::LicenseExpired;
    if (reason_code == "license_revoked")
        return ErrorCode::LicenseRevoked;
    if (reason_code == "license_suspended")
        return ErrorCode::LicenseSuspended;
    if (reason_code == "license_not_active")
        return ErrorCode::LicenseNotActive;
    if (reason_code == "seat_limit_exceeded")
        return ErrorCode::SeatLimitExceeded;
    if (reason_code == "activation_not_found")
        return ErrorCode::ActivationNotFound;
    if (reason_code == "product_not_found")
        return ErrorCode::ProductNotFound;
    if (reason_code == "release_not_found")
        return ErrorCode::ReleaseNotFound;
    if (reason_code == "missing_parameter")
        return ErrorCode::MissingParameter;
    if (reason_code == "invalid_parameter")
        return ErrorCode::InvalidParameter;
    if (reason_code == "validation_failed")
        return ErrorCode::ValidationFailed;
    if (reason_code == "unauthorized")
        return ErrorCode::AuthenticationFailed;
    if (reason_code == "forbidden")
        return ErrorCode::PermissionDenied;
    if (reason_code == "signing_not_configured")
        return ErrorCode::SigningNotConfigured;
    if (reason_code == "feature_not_configured")
        return ErrorCode::FeatureNotConfigured;
    if (reason_code == "server_error")
        return ErrorCode::ServerError;

    return ErrorCode::Unknown;
}

// ==================== Request Body Builders ====================

/// Build JSON body for license validation request
[[nodiscard]] inline json build_validate_request(const std::string& license_key,
                                                 const std::string& device_identifier,
                                                 const std::string& product_slug) {
    json body;
    body["license_key"] = license_key;

    if (!device_identifier.empty()) {
        body["device_identifier"] = device_identifier;
    }

    if (!product_slug.empty()) {
        body["product_slug"] = product_slug;
    }

    return body;
}

/// Build JSON body for activation request
[[nodiscard]] inline json build_activate_request(const std::string& license_key,
                                                 const std::string& device_identifier,
                                                 const Metadata& metadata) {
    json body;
    body["license_key"] = license_key;
    body["device_identifier"] = device_identifier;

    if (!metadata.empty()) {
        body["metadata"] = metadata_to_json(metadata);
    }

    return body;
}

/// Build JSON body for deactivation request
[[nodiscard]] inline json build_deactivate_request(const std::string& license_key,
                                                   const std::string& device_identifier) {
    json body;
    body["license_key"] = license_key;
    body["device_identifier"] = device_identifier;
    return body;
}

/// Build JSON body for download token request
[[nodiscard]] inline json build_download_token_request(const std::string& license_key) {
    json body;
    body["license_key"] = license_key;
    return body;
}

}  // namespace json
}  // namespace licenseseat
