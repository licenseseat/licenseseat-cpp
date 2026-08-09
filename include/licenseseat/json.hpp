#pragma once

/**
 * @file json.hpp
 * @brief JSON serialization utilities for LicenseSeat SDK types
 *
 * Uses nlohmann/json for parsing API responses into SDK types.
 */

#include "licenseseat.hpp"

#include <cstdint>
#include <ctime>
#include <iomanip>
#include <limits>
#include <nlohmann/json.hpp>
#include <sstream>
#include <stdexcept>
#include <unordered_set>
#include <vector>

namespace licenseseat {
namespace json {

using nlohmann::json;

inline constexpr std::size_t MAX_JSON_BYTES = 1024 * 1024;
inline constexpr int MAX_JSON_DEPTH = 32;
inline constexpr std::size_t MAX_JSON_NODES = 10000;
inline constexpr std::size_t MAX_JSON_ARRAY_ITEMS = 5000;
inline constexpr std::size_t MAX_JSON_OBJECT_KEYS = 1000;
inline constexpr std::size_t MAX_JSON_KEY_BYTES = 255;
inline constexpr std::size_t MAX_JSON_STRING_BYTES = 256 * 1024;

[[nodiscard]] inline bool has_unsafe_text(const std::string& value) {
    for (unsigned char byte : value) {
        if (byte <= 0x1f || byte == 0x7f)
            return true;
    }
    return false;
}

/**
 * Parse bounded JSON and reject duplicate object keys. nlohmann/json normally
 * keeps the last duplicate key, which can let different components authorize
 * different interpretations of the same signed or network payload.
 */
[[nodiscard]] inline json parse_strict(const std::string& input,
                                       std::size_t max_bytes = MAX_JSON_BYTES) {
    if (input.size() > max_bytes) {
        throw std::invalid_argument("JSON exceeds the configured size limit");
    }

    std::vector<std::unordered_set<std::string>> object_keys;
    std::size_t nodes = 0;
    json::parser_callback_t callback = [&](int depth, json::parse_event_t event, json& parsed) {
        if (depth > MAX_JSON_DEPTH) {
            throw std::invalid_argument("JSON is too deeply nested");
        }

        if (event == json::parse_event_t::object_start) {
            object_keys.emplace_back();
        } else if (event == json::parse_event_t::key) {
            const auto key = parsed.get<std::string>();
            if (key.empty() || key.size() > MAX_JSON_KEY_BYTES || has_unsafe_text(key)) {
                throw std::invalid_argument("JSON contains an invalid object key");
            }
            if (object_keys.empty()) {
                throw std::invalid_argument("JSON parser entered an invalid object state");
            }
            auto& keys = object_keys.back();
            if (!keys.insert(key).second) {
                throw std::invalid_argument("JSON contains a duplicate object key");
            }
        } else if (event == json::parse_event_t::value) {
            if (++nodes > MAX_JSON_NODES) {
                throw std::invalid_argument("JSON contains too many values");
            }
            if (parsed.is_string() &&
                parsed.get_ref<const std::string&>().size() > MAX_JSON_STRING_BYTES) {
                throw std::invalid_argument("JSON contains an oversized string");
            }
        } else if (event == json::parse_event_t::array_end &&
                   parsed.size() > MAX_JSON_ARRAY_ITEMS) {
            throw std::invalid_argument("JSON contains an oversized array");
        } else if (event == json::parse_event_t::object_end) {
            if (parsed.size() > MAX_JSON_OBJECT_KEYS) {
                throw std::invalid_argument("JSON contains an oversized object");
            }
            if (object_keys.empty()) {
                throw std::invalid_argument("JSON parser entered an invalid object state");
            }
            object_keys.pop_back();
        }
        return true;
    };

    return json::parse(input, callback, true, false);
}

// ==================== Timestamp Helpers ====================

/// Parse ISO 8601 timestamp string to Timestamp
[[nodiscard]] inline std::optional<Timestamp> parse_timestamp(const std::string& str) {
    if (str.size() < 20 || str.size() > 40)
        return std::nullopt;

    auto digits = [&](std::size_t offset, std::size_t count) -> std::optional<int> {
        if (offset + count > str.size())
            return std::nullopt;
        int value = 0;
        for (std::size_t i = 0; i < count; ++i) {
            const char c = str[offset + i];
            if (c < '0' || c > '9')
                return std::nullopt;
            value = value * 10 + (c - '0');
        }
        return value;
    };

    if (str[4] != '-' || str[7] != '-' || str[10] != 'T' || str[13] != ':' || str[16] != ':') {
        return std::nullopt;
    }
    const auto year = digits(0, 4);
    const auto month = digits(5, 2);
    const auto day = digits(8, 2);
    const auto hour = digits(11, 2);
    const auto minute = digits(14, 2);
    const auto second = digits(17, 2);
    if (!year || !month || !day || !hour || !minute || !second)
        return std::nullopt;

    const bool leap = (*year % 4 == 0 && *year % 100 != 0) || *year % 400 == 0;
    const int month_days[] = {0, 31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (*year < 1000 || *month < 1 || *month > 12 || *day < 1 || *day > month_days[*month] ||
        *hour > 23 || *minute > 59 || *second > 59) {
        return std::nullopt;
    }

    std::size_t position = 19;
    int64_t fractional_nanoseconds = 0;
    if (position < str.size() && str[position] == '.') {
        ++position;
        const std::size_t fraction_start = position;
        int digits_seen = 0;
        while (position < str.size() && str[position] >= '0' && str[position] <= '9') {
            if (digits_seen < 9) {
                fractional_nanoseconds = fractional_nanoseconds * 10 + (str[position] - '0');
            }
            ++digits_seen;
            ++position;
        }
        if (position == fraction_start || digits_seen > 9)
            return std::nullopt;
        for (; digits_seen < 9; ++digits_seen)
            fractional_nanoseconds *= 10;
    }

    int offset_seconds = 0;
    if (position < str.size() && str[position] == 'Z') {
        ++position;
    } else if (position < str.size() && (str[position] == '+' || str[position] == '-')) {
        const bool positive = str[position] == '+';
        if (position + 6 != str.size() || str[position + 3] != ':')
            return std::nullopt;
        const auto offset_hour = digits(position + 1, 2);
        const auto offset_minute = digits(position + 4, 2);
        if (!offset_hour || !offset_minute || *offset_hour > 23 || *offset_minute > 59) {
            return std::nullopt;
        }
        offset_seconds = (*offset_hour * 60 + *offset_minute) * 60;
        if (!positive)
            offset_seconds = -offset_seconds;
        position += 6;
    } else {
        return std::nullopt;
    }
    if (position != str.size())
        return std::nullopt;

    // Howard Hinnant's civil-date conversion, yielding days since 1970-01-01.
    int y = *year;
    const unsigned m = static_cast<unsigned>(*month);
    const unsigned d = static_cast<unsigned>(*day);
    y -= m <= 2;
    const int era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned adjusted_month = m > 2 ? m - 3 : m + 9;
    const unsigned doy = (153 * adjusted_month + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    const int64_t days_since_epoch = static_cast<int64_t>(era) * 146097 + doe - 719468;
    const int64_t seconds_since_epoch =
        days_since_epoch * 86400 + *hour * 3600 + *minute * 60 + *second - offset_seconds;
    const auto duration = std::chrono::seconds(seconds_since_epoch) +
                          std::chrono::nanoseconds(fractional_nanoseconds);
    return Timestamp(std::chrono::duration_cast<Timestamp::duration>(duration));
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
            if (!ent.expires_at.has_value()) {
                throw std::invalid_argument("Entitlement expiry timestamp is invalid");
            }
        } else if (j["expires_at"].is_number_integer()) {
            // Offline tokens use unix timestamp
            const auto timestamp = j["expires_at"].get<int64_t>();
            if (timestamp <= 0 || timestamp > 253402300799LL) {
                throw std::invalid_argument("Entitlement expiry timestamp is invalid");
            }
            ent.expires_at = parse_unix_timestamp(timestamp);
        } else {
            throw std::invalid_argument("Entitlement expiry timestamp is invalid");
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
        if (!starts_at.has_value()) {
            throw std::invalid_argument("License start timestamp is invalid");
        }
    }

    // New API uses "expires_at" instead of "ends_at"
    std::optional<Timestamp> expires_at;
    if (j.contains("expires_at") && !j["expires_at"].is_null()) {
        expires_at = parse_timestamp(j["expires_at"].get<std::string>());
        if (!expires_at.has_value()) {
            throw std::invalid_argument("License expiry timestamp is invalid");
        }
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

    return License(std::move(key), status, mode, std::move(plan_key), seat_limit, active_seats,
                   starts_at, expires_at, std::move(active_entitlements), std::move(metadata),
                   std::move(product));
}

/// Serialize License to JSON
[[nodiscard]] inline json license_to_json(const License& license) {
    json j;
    j["key"] = license.key();
    j["status"] = license_status_to_string(license.status());
    j["mode"] = license_mode_to_string(license.mode());
    j["plan_key"] = license.plan_key();

    if (license.seat_limit().has_value()) {
        j["seat_limit"] = *license.seat_limit();
    } else {
        j["seat_limit"] = nullptr;
    }

    j["active_seats"] = license.active_seats();

    if (license.starts_at().has_value()) {
        j["starts_at"] = format_timestamp(*license.starts_at());
    } else {
        j["starts_at"] = nullptr;
    }

    if (license.expires_at().has_value()) {
        j["expires_at"] = format_timestamp(*license.expires_at());
    } else {
        j["expires_at"] = nullptr;
    }

    // Serialize entitlements
    json ents = json::array();
    for (const auto& ent : license.active_entitlements()) {
        json e;
        e["key"] = ent.key;
        if (ent.expires_at.has_value()) {
            e["expires_at"] = format_timestamp(*ent.expires_at);
        } else {
            e["expires_at"] = nullptr;
        }
        if (!ent.metadata.empty()) {
            e["metadata"] = metadata_to_json(ent.metadata);
        }
        ents.push_back(e);
    }
    j["active_entitlements"] = ents;

    if (!license.metadata().empty()) {
        j["metadata"] = metadata_to_json(license.metadata());
    }

    // Serialize product
    json prod;
    prod["slug"] = license.product().slug;
    prod["name"] = license.product().name;
    j["product"] = prod;

    return j;
}

// ==================== Activation Parsing ====================

/// Parse Activation from JSON response (new API format)
[[nodiscard]] inline Activation parse_activation(const json& j) {
    int64_t id = 0;
    if (j.contains("id") && j["id"].is_number()) {
        id = j["id"].get<int64_t>();
    }

    std::string device_id;
    if (j.contains("fingerprint")) {
        device_id = j["fingerprint"].get<std::string>();
    } else if (j.contains("device_id")) {
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
        if (!ts.has_value())
            throw std::invalid_argument("Activation timestamp is invalid");
        activated_at = *ts;
    }

    std::optional<Timestamp> deactivated_at;
    if (j.contains("deactivated_at") && !j["deactivated_at"].is_null()) {
        deactivated_at = parse_timestamp(j["deactivated_at"].get<std::string>());
        if (!deactivated_at.has_value()) {
            throw std::invalid_argument("Deactivation timestamp is invalid");
        }
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
        if (!ts.has_value())
            throw std::invalid_argument("Deactivation timestamp is invalid");
        result.deactivated_at = *ts;
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

    if (j.contains("fingerprint") && !j["fingerprint"].is_null()) {
        payload.fingerprint = j["fingerprint"].get<std::string>();
        payload.device_id = payload.fingerprint;
        if (j.contains("device_id") && !j["device_id"].is_null() &&
            j["device_id"].get<std::string>() != *payload.fingerprint) {
            throw std::invalid_argument("Offline token fingerprint aliases disagree");
        }
    } else if (j.contains("device_id") && !j["device_id"].is_null()) {
        payload.device_id = j["device_id"].get<std::string>();
        payload.fingerprint = payload.device_id;
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
        offline.visible_token_json = j["token"].dump();
    }

    if (j.contains("signature") && j["signature"].is_object()) {
        offline.signature = parse_offline_token_signature(j["signature"]);
    }

    if (j.contains("canonical") && j["canonical"].is_string()) {
        offline.canonical = j["canonical"].get<std::string>();
    }

    return offline;
}

/// Convert Entitlement to JSON (for offline token serialization)
[[nodiscard]] inline json entitlement_to_json(const Entitlement& ent) {
    json j;
    j["key"] = ent.key;
    if (ent.expires_at.has_value()) {
        j["expires_at"] = std::chrono::system_clock::to_time_t(*ent.expires_at);
    } else {
        j["expires_at"] = nullptr;
    }
    if (!ent.metadata.empty()) {
        j["metadata"] = metadata_to_json(ent.metadata);
    }
    return j;
}

/// Reconstruct exactly the signed v1 token payload. Legacy aliases and outer
/// response fields are intentionally excluded from this trust boundary.
[[nodiscard]] inline json offline_token_payload_to_json(const OfflineTokenPayload& token) {
    json payload;
    payload["schema_version"] = token.schema_version;
    payload["license_key"] = token.license_key;
    payload["product_slug"] = token.product_slug;
    payload["plan_key"] = token.plan_key;
    payload["mode"] = token.mode;
    if (token.seat_limit.has_value())
        payload["seat_limit"] = *token.seat_limit;
    if (token.fingerprint.has_value())
        payload["fingerprint"] = *token.fingerprint;
    payload["iat"] = token.iat;
    payload["exp"] = token.exp;
    payload["nbf"] = token.nbf;
    if (token.license_expires_at.has_value()) {
        payload["license_expires_at"] = *token.license_expires_at;
    }
    payload["kid"] = token.kid;
    payload["entitlements"] = json::array();
    for (const auto& entitlement : token.entitlements) {
        payload["entitlements"].push_back(entitlement_to_json(entitlement));
    }
    payload["metadata"] = metadata_to_json(token.metadata);
    return payload;
}

/// Compare the exposed C++ representation with a typed signed JSON payload.
/// Metadata is normalized through the SDK's public string-map representation
/// so non-string JSON values remain bound even though Metadata stores strings.
[[nodiscard]] inline bool offline_token_payload_matches_json(const OfflineTokenPayload& token,
                                                             const json& signed_payload) {
    if (!signed_payload.is_object())
        return false;
    static const std::unordered_set<std::string> allowed = {
        "schema_version",     "license_key", "product_slug", "plan_key", "mode",
        "seat_limit",         "fingerprint", "iat",          "exp",      "nbf",
        "license_expires_at", "kid",         "entitlements", "metadata"};
    for (auto it = signed_payload.begin(); it != signed_payload.end(); ++it) {
        if (allowed.count(it.key()) == 0)
            return false;
    }
    static const std::vector<std::string> required = {
        "schema_version", "license_key", "product_slug", "plan_key", "mode",
        "fingerprint",    "iat",         "exp",          "nbf",      "kid",
        "entitlements",   "metadata"};
    for (const auto& key : required) {
        if (!signed_payload.contains(key))
            return false;
    }

    try {
        const auto parsed = parse_offline_token_payload(signed_payload);
        if (parsed.schema_version != token.schema_version ||
            parsed.license_key != token.license_key || parsed.product_slug != token.product_slug ||
            parsed.plan_key != token.plan_key || parsed.mode != token.mode ||
            parsed.seat_limit != token.seat_limit || parsed.fingerprint != token.fingerprint ||
            parsed.iat != token.iat || parsed.exp != token.exp || parsed.nbf != token.nbf ||
            parsed.license_expires_at != token.license_expires_at || parsed.kid != token.kid ||
            parsed.metadata != token.metadata ||
            parsed.entitlements.size() != token.entitlements.size()) {
            return false;
        }
        if (!signed_payload["entitlements"].is_array() || !signed_payload["metadata"].is_object()) {
            return false;
        }
        for (std::size_t index = 0; index < token.entitlements.size(); ++index) {
            const auto& raw = signed_payload["entitlements"][index];
            if (!raw.is_object() || (raw.size() != 2 && raw.size() != 3) || !raw.contains("key") ||
                !raw.contains("expires_at") || !raw["key"].is_string() ||
                !(raw["expires_at"].is_null() || raw["expires_at"].is_number_integer()) ||
                (raw.size() == 3 && (!raw.contains("metadata") || !raw["metadata"].is_object())) ||
                parsed.entitlements[index].key != token.entitlements[index].key ||
                parsed.entitlements[index].expires_at != token.entitlements[index].expires_at ||
                parsed.entitlements[index].metadata != token.entitlements[index].metadata) {
                return false;
            }
        }
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

/// Convert OfflineToken to JSON string for manual storage
/// Use this when you need to save the offline token to your own storage system.
[[nodiscard]] inline std::string offline_token_to_json(const OfflineToken& offline) {
    json j;

    j["object"] = "offline_token";
    if (!offline.visible_token_json.empty()) {
        j["token"] = parse_strict(offline.visible_token_json);
    } else {
        j["token"] = offline_token_payload_to_json(offline.token);
    }

    // Signature
    j["signature"]["algorithm"] = offline.signature.algorithm;
    j["signature"]["key_id"] = offline.signature.key_id;
    j["signature"]["value"] = offline.signature.value;

    // Canonical (needed for signature verification)
    j["canonical"] = offline.canonical;

    return j.dump();
}

/// Parse OfflineToken from JSON string (for manual storage)
/// Use this when loading a previously saved offline token.
[[nodiscard]] inline OfflineToken offline_token_from_json(const std::string& json_str) {
    auto j = parse_strict(json_str);
    if (!j.is_object() || j.size() != 4 || j.value("object", std::string{}) != "offline_token" ||
        !j.contains("token") || !j["token"].is_object() || !j.contains("signature") ||
        !j["signature"].is_object() || !j.contains("canonical") || !j["canonical"].is_string()) {
        throw std::invalid_argument("Offline token has an invalid outer schema");
    }
    return parse_offline_token(j);
}

// ==================== Machine File Parsing ====================

/// Parse machine-file response from API
[[nodiscard]] inline MachineFile parse_machine_file(const json& j) {
    MachineFile machine_file;

    const json* data = &j;
    if (j.contains("data") && j["data"].is_object()) {
        data = &j["data"];
    }

    if (data->contains("attributes") && (*data)["attributes"].is_object()) {
        const auto& attrs = (*data)["attributes"];
        machine_file.certificate = attrs.value("certificate", "");
        machine_file.algorithm = attrs.value("algorithm", machine_file.algorithm);
        machine_file.ttl = attrs.value("ttl", int64_t{0});
        if (attrs.contains("issued") && attrs["issued"].is_string()) {
            machine_file.issued_at = parse_timestamp(attrs["issued"].get<std::string>());
        }
        if (attrs.contains("expiry") && attrs["expiry"].is_string()) {
            machine_file.expires_at = parse_timestamp(attrs["expiry"].get<std::string>());
        }
    }

    if (data->contains("relationships") && (*data)["relationships"].is_object()) {
        const auto& relationships = (*data)["relationships"];
        if (relationships.contains("license") && relationships["license"].contains("data")) {
            machine_file.license_key = relationships["license"]["data"].value("id", std::string{});
        }
        if (relationships.contains("machine") && relationships["machine"].contains("data")) {
            machine_file.fingerprint = relationships["machine"]["data"].value("id", std::string{});
        }
    }

    return machine_file;
}

/// Parse license data embedded in a machine-file payload
[[nodiscard]] inline License parse_machine_file_license(const json& j) {
    const auto& attrs =
        j.contains("attributes") && j["attributes"].is_object() ? j["attributes"] : j;

    std::string key = attrs.value("key", j.value("id", std::string{}));
    auto status = license_status_from_string(attrs.value("status", std::string{}));
    auto mode = license_mode_from_string(attrs.value("mode", std::string{}));
    std::string plan_key = attrs.value("plan_key", std::string{});

    std::optional<int> seat_limit;
    if (attrs.contains("seat_limit") && !attrs["seat_limit"].is_null()) {
        seat_limit = attrs["seat_limit"].get<int>();
    }

    std::optional<Timestamp> starts_at;
    if (attrs.contains("starts_at") && !attrs["starts_at"].is_null()) {
        starts_at = parse_timestamp(attrs["starts_at"].get<std::string>());
        if (!starts_at.has_value()) {
            throw std::invalid_argument("Embedded license start timestamp is invalid");
        }
    }

    std::optional<Timestamp> expires_at;
    if (attrs.contains("ends_at") && !attrs["ends_at"].is_null()) {
        expires_at = parse_timestamp(attrs["ends_at"].get<std::string>());
        if (!expires_at.has_value()) {
            throw std::invalid_argument("Embedded license expiry timestamp is invalid");
        }
    }

    std::vector<Entitlement> entitlements;
    if (attrs.contains("entitlements") && attrs["entitlements"].is_array()) {
        entitlements = parse_entitlements(attrs["entitlements"]);
    }

    Metadata metadata;
    if (attrs.contains("metadata") && attrs["metadata"].is_object()) {
        metadata = parse_metadata(attrs["metadata"]);
    }

    std::string product_slug = attrs.value("product_slug", std::string{});
    return License(std::move(key), status, mode, std::move(plan_key), seat_limit, 0, starts_at,
                   expires_at, std::move(entitlements), std::move(metadata),
                   Product{product_slug, product_slug});
}

/// Parse decrypted machine-file payload
[[nodiscard]] inline MachineFilePayload parse_machine_file_payload(const json& j) {
    MachineFilePayload payload;

    if (j.contains("meta") && j["meta"].is_object()) {
        const auto& meta = j["meta"];
        payload.schema_version = meta.value("schema_version", 0);
        payload.issued = meta.value("issued", std::string{});
        payload.iat = meta.value("iat", int64_t{0});
        payload.expiry = meta.value("expiry", std::string{});
        payload.exp = meta.value("exp", int64_t{0});
        payload.nbf = meta.value("nbf", int64_t{0});
        payload.ttl = meta.value("ttl", int64_t{0});
        payload.grace_period = meta.value("grace_period", int64_t{0});
        payload.license_key = meta.value("lic", std::string{});
        if (meta.contains("license_exp") && !meta["license_exp"].is_null()) {
            payload.license_expires_at = meta["license_exp"].get<int64_t>();
        }
        payload.key_id = meta.value("kid", std::string{});
        if (meta.contains("sdk_version") && !meta["sdk_version"].is_null()) {
            payload.sdk_version = meta["sdk_version"].get<std::string>();
        }
    }

    if (j.contains("data") && j["data"].is_object()) {
        const auto& data = j["data"];
        payload.machine_id = data.value("id", std::string{});
        if (data.contains("attributes") && data["attributes"].is_object()) {
            const auto& attrs = data["attributes"];
            if (attrs.contains("fingerprint") && attrs["fingerprint"].is_string()) {
                payload.fingerprint = attrs["fingerprint"].get<std::string>();
            }
            if (attrs.contains("fingerprint_components") &&
                attrs["fingerprint_components"].is_object()) {
                payload.fingerprint_components = parse_metadata(attrs["fingerprint_components"]);
            }
            if (attrs.contains("name") && attrs["name"].is_string()) {
                payload.device_name = attrs["name"].get<std::string>();
            }
            if (attrs.contains("platform") && attrs["platform"].is_string()) {
                payload.platform = attrs["platform"].get<std::string>();
            }
            if (attrs.contains("created") && attrs["created"].is_string()) {
                payload.created_at = parse_timestamp(attrs["created"].get<std::string>());
            }
            if (attrs.contains("metadata") && attrs["metadata"].is_object()) {
                payload.metadata = parse_metadata(attrs["metadata"]);
            }
        }
        if (data.contains("relationships") && data["relationships"].is_object()) {
            const auto& relationships = data["relationships"];
            if (relationships.contains("product") && relationships["product"].is_object() &&
                relationships["product"].contains("data") &&
                relationships["product"]["data"].is_object()) {
                payload.product_slug = relationships["product"]["data"].value("id", std::string{});
            }
        }
    }

    if (j.contains("included") && j["included"].is_array()) {
        for (const auto& included : j["included"]) {
            if (included.value("type", std::string{}) == "licenses") {
                payload.license = parse_machine_file_license(included);
                break;
            }
        }
    }

    return payload;
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
/// Machine-file endpoints may also return: {"errors": [{"code": "...", "title": "...", "detail":
/// "..."}]}
[[nodiscard]] inline ApiError parse_error_response(const json& j) {
    ApiError err;

    if (j.contains("errors") && j["errors"].is_array() && !j["errors"].empty() &&
        j["errors"][0].is_object()) {
        const auto& error_obj = j["errors"][0];
        if (error_obj.contains("code")) {
            err.code = error_obj["code"].get<std::string>();
        }
        if (error_obj.contains("detail")) {
            err.message = error_obj["detail"].get<std::string>();
        } else if (error_obj.contains("message")) {
            err.message = error_obj["message"].get<std::string>();
        } else if (error_obj.contains("title")) {
            err.message = error_obj["title"].get<std::string>();
        }
    } else if (j.contains("error") && j["error"].is_object()) {
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
    if (code == "device_not_activated" || code == "DEVICE_NOT_ACTIVATED")
        return ErrorCode::DeviceNotActivated;
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
    if (code == "DECRYPTION_FAILED" || code == "decryption_failed")
        return ErrorCode::DecryptionFailed;
    if (code == "TOKEN_EXPIRED" || code == "token_expired")
        return ErrorCode::TokenExpired;
    if (code == "TOKEN_NOT_YET_VALID" || code == "token_not_yet_valid")
        return ErrorCode::TokenNotYetValid;
    if (code == "FINGERPRINT_MISMATCH" || code == "fingerprint_mismatch")
        return ErrorCode::FingerprintMismatch;
    if (code == "VERIFICATION_FAILED" || code == "verification_failed")
        return ErrorCode::InvalidSignature;
    if (code == "INVALID_FINGERPRINT" || code == "invalid_fingerprint")
        return ErrorCode::InvalidParameter;
    if (code == "MACHINE_NOT_FOUND" || code == "machine_not_found")
        return ErrorCode::ActivationNotFound;
    if (code == "AMBIGUOUS_MACHINE" || code == "ambiguous_machine")
        return ErrorCode::InvalidParameter;

    return ErrorCode::Unknown;
}

// ==================== Request Body Builders ====================

[[nodiscard]] inline json fingerprint_alias_payload(const std::string& fingerprint,
                                                    bool include_when_empty = false) {
    json body;
    if (include_when_empty || !fingerprint.empty()) {
        body["fingerprint"] = fingerprint;
        body["device_id"] = fingerprint;
    }
    return body;
}

/// Build JSON body for activation request (new API format)
[[nodiscard]] inline json build_activate_request(const std::string& device_id,
                                                 const std::string& device_name,
                                                 const Metadata& metadata) {
    json body = fingerprint_alias_payload(device_id, true);

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
    return fingerprint_alias_payload(device_id, true);
}

/// Build JSON body for validation request (new API format)
[[nodiscard]] inline json build_validate_request(const std::string& device_id) {
    return fingerprint_alias_payload(device_id);
}

/// Build JSON body for offline token request (new API format)
[[nodiscard]] inline json build_offline_token_request(const std::string& device_id, int ttl_days) {
    json body = fingerprint_alias_payload(device_id);
    if (ttl_days > 0) {
        body["ttl_days"] = ttl_days;
    }
    return body;
}

/// Build JSON body for machine-file request
[[nodiscard]] inline json build_machine_file_request(const std::string& device_id, int ttl_days,
                                                     const Metadata& fingerprint_components = {}) {
    json body = fingerprint_alias_payload(device_id);
    if (ttl_days > 0) {
        body["ttl"] = ttl_days;
    }
    if (!fingerprint_components.empty()) {
        body["fingerprint_components"] = metadata_to_json(fingerprint_components);
    }
    body["include"] = json::array({"license"});
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

} // namespace json
} // namespace licenseseat
