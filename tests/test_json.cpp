#include <gtest/gtest.h>
#include <licenseseat/json.hpp>

namespace licenseseat {
namespace json {
namespace {

// ==================== Timestamp Tests ====================

TEST(JsonTimestampTest, ParseValidTimestamp) {
    auto ts = parse_timestamp("2026-01-19T12:00:00Z");

    EXPECT_TRUE(ts.has_value());
}

TEST(JsonTimestampTest, ParseEmptyTimestamp) {
    auto ts = parse_timestamp("");

    EXPECT_FALSE(ts.has_value());
}

TEST(JsonTimestampTest, ParseInvalidTimestamp) {
    auto ts = parse_timestamp("invalid");

    EXPECT_FALSE(ts.has_value());
}

TEST(JsonTimestampTest, FormatTimestamp) {
    auto now = std::chrono::system_clock::now();
    auto formatted = format_timestamp(now);

    EXPECT_FALSE(formatted.empty());
    EXPECT_TRUE(formatted.find('T') != std::string::npos);
    EXPECT_TRUE(formatted.find('Z') != std::string::npos);
}

TEST(JsonTimestampTest, ParseUnixTimestamp) {
    auto ts = parse_unix_timestamp(1737280800);

    auto time_t_val = std::chrono::system_clock::to_time_t(ts);
    EXPECT_EQ(time_t_val, 1737280800);
}

// ==================== Metadata Tests ====================

TEST(JsonMetadataTest, ParseEmptyObject) {
    nlohmann::json j = nlohmann::json::object();
    auto meta = parse_metadata(j);

    EXPECT_TRUE(meta.empty());
}

TEST(JsonMetadataTest, ParseStringValues) {
    nlohmann::json j = {{"key1", "value1"}, {"key2", "value2"}};
    auto meta = parse_metadata(j);

    EXPECT_EQ(meta.size(), static_cast<size_t>(2));
    EXPECT_EQ(meta["key1"], "value1");
    EXPECT_EQ(meta["key2"], "value2");
}

TEST(JsonMetadataTest, ParseMixedValues) {
    nlohmann::json j = {{"str", "hello"}, {"num", 42}, {"bool", true}};
    auto meta = parse_metadata(j);

    EXPECT_EQ(meta["str"], "hello");
    EXPECT_EQ(meta["num"], "42.000000");  // number to string
    EXPECT_EQ(meta["bool"], "true");
}

TEST(JsonMetadataTest, MetadataToJson) {
    Metadata meta{{"key1", "value1"}, {"key2", "value2"}};
    auto j = metadata_to_json(meta);

    EXPECT_TRUE(j.is_object());
    EXPECT_EQ(j["key1"], "value1");
    EXPECT_EQ(j["key2"], "value2");
}

// ==================== Entitlement Parsing Tests ====================

TEST(JsonEntitlementTest, ParseEntitlementWithExpiry) {
    nlohmann::json j = {{"key", "updates"}, {"expires_at", "2027-01-01T00:00:00Z"}};

    auto ent = parse_entitlement(j);

    EXPECT_EQ(ent.key, "updates");
    EXPECT_TRUE(ent.expires_at.has_value());
}

TEST(JsonEntitlementTest, ParseEntitlementWithUnixExpiry) {
    nlohmann::json j = {{"key", "support"}, {"expires_at", 1768816800}};

    auto ent = parse_entitlement(j);

    EXPECT_EQ(ent.key, "support");
    EXPECT_TRUE(ent.expires_at.has_value());
}

TEST(JsonEntitlementTest, ParseEntitlementWithMetadata) {
    nlohmann::json j = {{"key", "premium"}, {"metadata", {{"tier", "gold"}}}};

    auto ent = parse_entitlement(j);

    EXPECT_EQ(ent.key, "premium");
    EXPECT_EQ(ent.metadata.at("tier"), "gold");
}

TEST(JsonEntitlementTest, ParseEntitlementsArray) {
    nlohmann::json j = nlohmann::json::array({{{"key", "updates"}}, {{"key", "support"}}});

    auto ents = parse_entitlements(j);

    EXPECT_EQ(ents.size(), static_cast<size_t>(2));
    EXPECT_EQ(ents[0].key, "updates");
    EXPECT_EQ(ents[1].key, "support");
}

// ==================== Product Parsing Tests ====================

TEST(JsonProductTest, ParseProduct) {
    nlohmann::json j = {{"slug", "my-app"}, {"name", "My Application"}};

    auto product = parse_product(j);

    EXPECT_EQ(product.slug, "my-app");
    EXPECT_EQ(product.name, "My Application");
}

// ==================== License Parsing Tests ====================

TEST(JsonLicenseTest, ParseFullLicense) {
    nlohmann::json j = {{"key", "KEY-123"},
                        {"status", "active"},
                        {"mode", "hardware_locked"},
                        {"plan_key", "pro-annual"},
                        {"seat_limit", 5},
                        {"active_seats", 2},
                        {"starts_at", "2026-01-01T00:00:00Z"},
                        {"expires_at", "2027-01-01T00:00:00Z"},
                        {"active_entitlements", {{{"key", "updates"}}}},
                        {"metadata", {{"customer", "test"}}},
                        {"product", {{"slug", "my-app"}, {"name", "My App"}}}};

    auto license = parse_license(j);

    EXPECT_EQ(license.key(), "KEY-123");
    EXPECT_EQ(license.status(), LicenseStatus::Active);
    EXPECT_EQ(license.mode(), LicenseMode::HardwareLocked);
    EXPECT_EQ(license.plan_key(), "pro-annual");
    EXPECT_TRUE(license.seat_limit().has_value());
    EXPECT_EQ(license.seat_limit().value(), 5);
    EXPECT_EQ(license.active_seats(), 2);
    EXPECT_TRUE(license.starts_at().has_value());
    EXPECT_TRUE(license.expires_at().has_value());
    EXPECT_EQ(license.active_entitlements().size(), static_cast<size_t>(1));
    EXPECT_EQ(license.metadata().at("customer"), "test");
    EXPECT_EQ(license.product().slug, "my-app");
}

TEST(JsonLicenseTest, ParsePartialLicense) {
    nlohmann::json j = {{"key", "KEY-456"}, {"status", "expired"}};

    auto license = parse_license(j);

    EXPECT_EQ(license.key(), "KEY-456");
    EXPECT_EQ(license.status(), LicenseStatus::Expired);
    EXPECT_EQ(license.mode(), LicenseMode::Unknown);
    EXPECT_TRUE(license.plan_key().empty());
}

TEST(JsonLicenseTest, ParseLicenseWithNullDates) {
    nlohmann::json j = {
        {"key", "KEY-789"}, {"status", "active"}, {"starts_at", nullptr}, {"expires_at", nullptr}};

    auto license = parse_license(j);

    EXPECT_FALSE(license.starts_at().has_value());
    EXPECT_FALSE(license.expires_at().has_value());
}

TEST(JsonLicenseTest, ParseLicenseWithNullSeatLimit) {
    nlohmann::json j = {{"key", "KEY-ABC"}, {"status", "active"}, {"seat_limit", nullptr}};

    auto license = parse_license(j);

    EXPECT_FALSE(license.seat_limit().has_value());
}

// ==================== Activation Parsing Tests ====================

TEST(JsonActivationTest, ParseFullActivation) {
    nlohmann::json j = {{"id", 42},
                        {"device_id", "device-001"},
                        {"device_name", "My MacBook"},
                        {"license_key", "KEY-123"},
                        {"activated_at", "2026-01-19T12:00:00Z"},
                        {"deactivated_at", nullptr},
                        {"ip_address", "192.168.1.1"},
                        {"metadata", {{"os", "macos"}}}};

    auto activation = parse_activation(j);

    EXPECT_EQ(activation.id(), 42);
    EXPECT_EQ(activation.device_id(), "device-001");
    EXPECT_EQ(activation.device_name(), "My MacBook");
    EXPECT_EQ(activation.license_key(), "KEY-123");
    EXPECT_EQ(activation.ip_address(), "192.168.1.1");
    EXPECT_TRUE(activation.is_active());
    EXPECT_EQ(activation.metadata().at("os"), "macos");
}

TEST(JsonActivationTest, ParseDeactivatedActivation) {
    nlohmann::json j = {{"id", 42},
                        {"device_id", "device-001"},
                        {"license_key", "KEY-123"},
                        {"activated_at", "2026-01-19T12:00:00Z"},
                        {"deactivated_at", "2026-01-20T12:00:00Z"},
                        {"ip_address", "192.168.1.1"},
                        {"metadata", {}}};

    auto activation = parse_activation(j);

    EXPECT_FALSE(activation.is_active());
    EXPECT_TRUE(activation.deactivated_at().has_value());
}

// ==================== Deactivation Parsing Tests ====================

TEST(JsonDeactivationTest, ParseDeactivation) {
    nlohmann::json j = {{"activation_id", 42}, {"deactivated_at", "2026-01-20T12:00:00Z"}};

    auto deactivation = parse_deactivation(j);

    EXPECT_EQ(deactivation.activation_id, 42);
}

// ==================== Validation Warning Tests ====================

TEST(JsonValidationWarningTest, ParseWarning) {
    nlohmann::json j = {{"code", "expiring_soon"}, {"message", "License expires in 7 days"}};

    auto warning = parse_validation_warning(j);

    EXPECT_EQ(warning.code, "expiring_soon");
    EXPECT_EQ(warning.message, "License expires in 7 days");
}

TEST(JsonValidationWarningTest, ParseWarningsArray) {
    nlohmann::json j = nlohmann::json::array(
        {{{"code", "warn1"}, {"message", "Warning 1"}}, {{"code", "warn2"}, {"message", "Warning 2"}}});

    auto warnings = parse_validation_warnings(j);

    EXPECT_EQ(warnings.size(), static_cast<size_t>(2));
    EXPECT_EQ(warnings[0].code, "warn1");
    EXPECT_EQ(warnings[1].code, "warn2");
}

// ==================== Validation Result Tests ====================

TEST(JsonValidationResultTest, ParseValidResult) {
    nlohmann::json j = {{"valid", true},
                        {"code", "license_valid"},
                        {"message", "License is valid"},
                        {"license", {{"key", "KEY-123"}, {"status", "active"}}}};

    auto result = parse_validation_result(j);

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.code, "license_valid");
    EXPECT_EQ(result.message, "License is valid");
    EXPECT_EQ(result.license.key(), "KEY-123");
}

TEST(JsonValidationResultTest, ParseInvalidResult) {
    nlohmann::json j = {{"valid", false},
                        {"code", "license_expired"},
                        {"message", "License has expired"},
                        {"license", {{"key", "KEY-123"}, {"status", "expired"}}}};

    auto result = parse_validation_result(j);

    EXPECT_FALSE(result.valid);
    EXPECT_EQ(result.code, "license_expired");
    EXPECT_EQ(result.license.status(), LicenseStatus::Expired);
}

TEST(JsonValidationResultTest, ParseWithWarnings) {
    nlohmann::json j = {{"valid", true},
                        {"warnings", {{{"code", "expiring_soon"}, {"message", "Expires in 7 days"}}}},
                        {"license", {{"key", "KEY-123"}, {"status", "active"}}}};

    auto result = parse_validation_result(j);

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.warnings.size(), static_cast<size_t>(1));
    EXPECT_EQ(result.warnings[0].code, "expiring_soon");
}

TEST(JsonValidationResultTest, ParseWithActivation) {
    nlohmann::json j = {{"valid", true},
                        {"license", {{"key", "KEY-123"}, {"status", "active"}}},
                        {"activation", {{"id", 42}, {"device_id", "dev-001"}}}};

    auto result = parse_validation_result(j);

    EXPECT_TRUE(result.valid);
    EXPECT_TRUE(result.activation.has_value());
    EXPECT_EQ(result.activation->id(), 42);
}

// ==================== Offline Token Tests ====================

TEST(JsonOfflineTokenTest, ParseFullOfflineToken) {
    nlohmann::json j = {
        {"token",
         {{"schema_version", 1},
          {"license_key", "KEY-123"},
          {"product_slug", "my-app"},
          {"plan_key", "pro"},
          {"mode", "hardware_locked"},
          {"seat_limit", 5},
          {"device_id", "device-001"},
          {"iat", 1737280800},
          {"exp", 1768816800},
          {"nbf", 1737280800},
          {"license_expires_at", 1768816800},
          {"kid", "key-v1"},
          {"entitlements", {{{"key", "updates"}}, {{"key", "support"}}}},
          {"metadata", {{"plan", "pro"}}}}},
        {"signature", {{"algorithm", "Ed25519"}, {"key_id", "key-v1"}, {"value", "base64-signature"}}},
        {"canonical", R"({"license_key":"KEY-123"})"}};

    auto offline = parse_offline_token(j);

    EXPECT_EQ(offline.token.schema_version, 1);
    EXPECT_EQ(offline.token.license_key, "KEY-123");
    EXPECT_EQ(offline.token.product_slug, "my-app");
    EXPECT_EQ(offline.token.plan_key, "pro");
    EXPECT_EQ(offline.token.mode, "hardware_locked");
    EXPECT_TRUE(offline.token.seat_limit.has_value());
    EXPECT_EQ(offline.token.seat_limit.value(), 5);
    EXPECT_TRUE(offline.token.device_id.has_value());
    EXPECT_EQ(offline.token.device_id.value(), "device-001");
    EXPECT_EQ(offline.token.iat, 1737280800);
    EXPECT_EQ(offline.token.exp, 1768816800);
    EXPECT_EQ(offline.token.nbf, 1737280800);
    EXPECT_TRUE(offline.token.license_expires_at.has_value());
    EXPECT_EQ(offline.token.kid, "key-v1");
    EXPECT_EQ(offline.token.entitlements.size(), static_cast<size_t>(2));
    EXPECT_EQ(offline.token.entitlements[0].key, "updates");
    EXPECT_EQ(offline.token.entitlements[1].key, "support");
    EXPECT_EQ(offline.token.metadata.at("plan"), "pro");
    EXPECT_EQ(offline.signature.algorithm, "Ed25519");
    EXPECT_EQ(offline.signature.key_id, "key-v1");
    EXPECT_EQ(offline.signature.value, "base64-signature");
    EXPECT_EQ(offline.canonical, R"({"license_key":"KEY-123"})");
}

TEST(JsonOfflineTokenTest, ParseMinimalOfflineToken) {
    nlohmann::json j = {{"token", {{"license_key", "KEY-123"}, {"iat", 1000}, {"exp", 2000}, {"nbf", 1000}}},
                        {"signature", {{"value", "sig"}}},
                        {"canonical", "{}"}};

    auto offline = parse_offline_token(j);

    EXPECT_EQ(offline.token.license_key, "KEY-123");
    EXPECT_FALSE(offline.token.seat_limit.has_value());
    EXPECT_FALSE(offline.token.device_id.has_value());
}

// ==================== Release Tests ====================

TEST(JsonReleaseTest, ParseFullRelease) {
    nlohmann::json j = {{"version", "1.2.3"},
                        {"channel", "stable"},
                        {"platform", "macos"},
                        {"product_slug", "my-app"},
                        {"published_at", "2026-01-15T00:00:00Z"}};

    auto release = parse_release(j);

    EXPECT_EQ(release.version, "1.2.3");
    EXPECT_EQ(release.channel, "stable");
    EXPECT_EQ(release.platform, "macos");
    EXPECT_EQ(release.product_slug, "my-app");
    EXPECT_TRUE(release.published_at.has_value());
}

TEST(JsonReleaseTest, ParseReleasesListWrapped) {
    nlohmann::json j = {
        {"object", "list"},
        {"data", {{{"version", "1.0.0"}, {"channel", "stable"}}, {{"version", "0.9.0"}, {"channel", "beta"}}}}};

    auto releases = parse_releases(j);

    EXPECT_EQ(releases.size(), static_cast<size_t>(2));
    EXPECT_EQ(releases[0].version, "1.0.0");
    EXPECT_EQ(releases[1].version, "0.9.0");
}

TEST(JsonReleaseTest, ParseReleasesListRaw) {
    nlohmann::json j = nlohmann::json::array({{{"version", "1.0.0"}, {"channel", "stable"}},
                                               {{"version", "0.9.0"}, {"channel", "beta"}}});

    auto releases = parse_releases(j);

    EXPECT_EQ(releases.size(), static_cast<size_t>(2));
    EXPECT_EQ(releases[0].version, "1.0.0");
    EXPECT_EQ(releases[1].version, "0.9.0");
}

// ==================== Download Token Tests ====================

TEST(JsonDownloadTokenTest, ParseToken) {
    nlohmann::json j = {{"token", "token-abc"}, {"expires_at", "2026-01-20T12:00:00Z"}};

    auto token = parse_download_token(j);

    EXPECT_EQ(token.token, "token-abc");
    EXPECT_TRUE(token.expires_at.has_value());
}

// ==================== Signing Key Tests ====================

TEST(JsonSigningKeyTest, ParseSigningKey) {
    nlohmann::json j = {{"key_id", "key-v1"}, {"public_key", "base64-encoded-key"}};

    auto key = parse_signing_key(j);

    EXPECT_EQ(key, "base64-encoded-key");
}

// ==================== Error Response Tests ====================

TEST(JsonErrorResponseTest, ParseError) {
    nlohmann::json j = {{"error", {{"code", "license_not_found"}, {"message", "License not found"}}}};

    auto err = parse_error_response(j);

    EXPECT_EQ(err.code, "license_not_found");
    EXPECT_EQ(err.message, "License not found");
}

TEST(JsonErrorCodeMappingTest, ErrorCodeToErrorCode) {
    EXPECT_EQ(error_code_to_error_code("license_not_found"), ErrorCode::LicenseNotFound);
    EXPECT_EQ(error_code_to_error_code("license_expired"), ErrorCode::LicenseExpired);
    EXPECT_EQ(error_code_to_error_code("seat_limit_exceeded"), ErrorCode::SeatLimitExceeded);
    EXPECT_EQ(error_code_to_error_code("activation_not_found"), ErrorCode::ActivationNotFound);
    EXPECT_EQ(error_code_to_error_code("device_already_activated"), ErrorCode::DeviceAlreadyActivated);
    EXPECT_EQ(error_code_to_error_code("product_not_found"), ErrorCode::ProductNotFound);
    EXPECT_EQ(error_code_to_error_code("release_not_found"), ErrorCode::ReleaseNotFound);
    EXPECT_EQ(error_code_to_error_code("missing_parameter"), ErrorCode::MissingParameter);
    EXPECT_EQ(error_code_to_error_code("invalid_parameter"), ErrorCode::InvalidParameter);
    EXPECT_EQ(error_code_to_error_code("invalid_license_key"), ErrorCode::InvalidLicenseKey);
    EXPECT_EQ(error_code_to_error_code("unauthorized"), ErrorCode::AuthenticationFailed);
    EXPECT_EQ(error_code_to_error_code("signing_not_configured"), ErrorCode::SigningNotConfigured);
    EXPECT_EQ(error_code_to_error_code("unknown_code"), ErrorCode::Unknown);
}

// ==================== Request Body Builder Tests ====================

TEST(JsonRequestBuilderTest, BuildValidateRequest) {
    auto body = build_validate_request("device-001");

    EXPECT_EQ(body["device_id"], "device-001");
}

TEST(JsonRequestBuilderTest, BuildValidateRequestEmpty) {
    auto body = build_validate_request("");

    EXPECT_FALSE(body.contains("device_id"));
}

TEST(JsonRequestBuilderTest, BuildActivateRequest) {
    Metadata meta{{"os", "macos"}};
    auto body = build_activate_request("device-001", "My MacBook", meta);

    EXPECT_EQ(body["device_id"], "device-001");
    EXPECT_EQ(body["device_name"], "My MacBook");
    EXPECT_EQ(body["metadata"]["os"], "macos");
}

TEST(JsonRequestBuilderTest, BuildActivateRequestMinimal) {
    Metadata meta;
    auto body = build_activate_request("device-001", "", meta);

    EXPECT_EQ(body["device_id"], "device-001");
    EXPECT_FALSE(body.contains("device_name"));
    EXPECT_FALSE(body.contains("metadata"));
}

TEST(JsonRequestBuilderTest, BuildDeactivateRequest) {
    auto body = build_deactivate_request("device-001");

    EXPECT_EQ(body["device_id"], "device-001");
}

TEST(JsonRequestBuilderTest, BuildOfflineTokenRequest) {
    auto body = build_offline_token_request("device-001", 30);

    EXPECT_EQ(body["device_id"], "device-001");
    EXPECT_EQ(body["ttl_days"], 30);
}

TEST(JsonRequestBuilderTest, BuildOfflineTokenRequestMinimal) {
    auto body = build_offline_token_request("", 0);

    EXPECT_FALSE(body.contains("device_id"));
    EXPECT_FALSE(body.contains("ttl_days"));
}

TEST(JsonRequestBuilderTest, BuildDownloadTokenRequest) {
    auto body = build_download_token_request("KEY-123", "macos");

    EXPECT_EQ(body["license_key"], "KEY-123");
    EXPECT_EQ(body["platform"], "macos");
}

TEST(JsonRequestBuilderTest, BuildDownloadTokenRequestMinimal) {
    auto body = build_download_token_request("KEY-123", "");

    EXPECT_EQ(body["license_key"], "KEY-123");
    EXPECT_FALSE(body.contains("platform"));
}

}  // namespace
}  // namespace json
}  // namespace licenseseat
