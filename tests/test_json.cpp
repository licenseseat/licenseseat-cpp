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

// ==================== Metadata Tests ====================

TEST(JsonMetadataTest, ParseEmptyObject) {
    nlohmann::json j = nlohmann::json::object();
    auto meta = parse_metadata(j);

    EXPECT_TRUE(meta.empty());
}

TEST(JsonMetadataTest, ParseStringValues) {
    nlohmann::json j = {{"key1", "value1"}, {"key2", "value2"}};
    auto meta = parse_metadata(j);

    EXPECT_EQ(meta.size(), 2);
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

// ==================== License Parsing Tests ====================

TEST(JsonLicenseTest, ParseFullLicense) {
    nlohmann::json j = {{"license_key", "KEY-123"},
                        {"status", "active"},
                        {"mode", "hardware_locked"},
                        {"plan_key", "pro-annual"},
                        {"seat_limit", 5},
                        {"active_activations_count", 2},
                        {"starts_at", "2026-01-01T00:00:00Z"},
                        {"ends_at", "2027-01-01T00:00:00Z"},
                        {"metadata", {{"customer", "test"}}}};

    auto license = parse_license(j);

    EXPECT_EQ(license.key(), "KEY-123");
    EXPECT_EQ(license.status(), LicenseStatus::Active);
    EXPECT_EQ(license.mode(), LicenseMode::HardwareLocked);
    EXPECT_EQ(license.plan_key(), "pro-annual");
    EXPECT_EQ(license.seat_limit(), 5);
    EXPECT_EQ(license.active_activations_count(), 2);
    EXPECT_TRUE(license.starts_at().has_value());
    EXPECT_TRUE(license.ends_at().has_value());
    EXPECT_EQ(license.metadata().at("customer"), "test");
}

TEST(JsonLicenseTest, ParsePartialLicense) {
    nlohmann::json j = {{"license_key", "KEY-456"}, {"status", "expired"}};

    auto license = parse_license(j);

    EXPECT_EQ(license.key(), "KEY-456");
    EXPECT_EQ(license.status(), LicenseStatus::Expired);
    EXPECT_EQ(license.mode(), LicenseMode::Unknown);
    EXPECT_TRUE(license.plan_key().empty());
}

TEST(JsonLicenseTest, ParseLicenseWithNullDates) {
    nlohmann::json j = {
        {"license_key", "KEY-789"}, {"status", "active"}, {"starts_at", nullptr}, {"ends_at", nullptr}};

    auto license = parse_license(j);

    EXPECT_FALSE(license.starts_at().has_value());
    EXPECT_FALSE(license.ends_at().has_value());
}

// ==================== Activation Parsing Tests ====================

TEST(JsonActivationTest, ParseFullActivation) {
    nlohmann::json j = {{"id", 42},
                        {"device_identifier", "device-001"},
                        {"license_key", "KEY-123"},
                        {"activated_at", "2026-01-19T12:00:00Z"},
                        {"deactivated_at", nullptr},
                        {"ip_address", "192.168.1.1"},
                        {"metadata", {{"os", "macos"}}}};

    auto activation = parse_activation(j);

    EXPECT_EQ(activation.id(), 42);
    EXPECT_EQ(activation.device_identifier(), "device-001");
    EXPECT_EQ(activation.license_key(), "KEY-123");
    EXPECT_EQ(activation.ip_address(), "192.168.1.1");
    EXPECT_TRUE(activation.is_active());
    EXPECT_EQ(activation.metadata().at("os"), "macos");
}

TEST(JsonActivationTest, ParseDeactivatedActivation) {
    nlohmann::json j = {{"id", 42},
                        {"device_identifier", "device-001"},
                        {"license_key", "KEY-123"},
                        {"activated_at", "2026-01-19T12:00:00Z"},
                        {"deactivated_at", "2026-01-20T12:00:00Z"},
                        {"ip_address", "192.168.1.1"},
                        {"metadata", {}}};

    auto activation = parse_activation(j);

    EXPECT_FALSE(activation.is_active());
    EXPECT_TRUE(activation.deactivated_at().has_value());
}

// ==================== Validation Result Tests ====================

TEST(JsonValidationResultTest, ParseValidResult) {
    nlohmann::json j = {{"valid", true},
                        {"license", {{"license_key", "KEY-123"}, {"status", "active"}}}};

    auto result = parse_validation_result(j);

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.license.key(), "KEY-123");
}

TEST(JsonValidationResultTest, ParseInvalidResult) {
    nlohmann::json j = {{"valid", false}, {"license", {{"license_key", "KEY-123"}, {"status", "expired"}}}};

    auto result = parse_validation_result(j);

    EXPECT_FALSE(result.valid);
    EXPECT_EQ(result.license.status(), LicenseStatus::Expired);
}

// ==================== Offline License Tests ====================

TEST(JsonOfflineLicenseTest, ParseFullOfflineLicense) {
    nlohmann::json j = {{"payload",
                         {{"lic_k", "KEY-123"},
                          {"kid", "key-v1"},
                          {"iat", 1737280800},
                          {"exp", 1768816800},
                          {"ent", {{{"key", "updates"}}, {{"key", "support"}, {"exp", 1768816800}}}},
                          {"meta", {{"plan", "pro"}}}}},
                        {"signature_b64u", "base64-signature"}};

    auto offline = parse_offline_license(j);

    EXPECT_EQ(offline.license_key, "KEY-123");
    EXPECT_EQ(offline.key_id, "key-v1");
    EXPECT_EQ(offline.issued_at, 1737280800);
    EXPECT_EQ(offline.expires_at, 1768816800);
    EXPECT_EQ(offline.entitlements.size(), 2);
    EXPECT_EQ(offline.entitlements[0].key, "updates");
    EXPECT_EQ(offline.entitlements[1].key, "support");
    EXPECT_EQ(offline.signature_b64u, "base64-signature");
}

TEST(JsonOfflineLicenseTest, CanonicalJsonOutput) {
    OfflineLicense offline;
    offline.license_key = "KEY-123";
    offline.key_id = "key-v1";
    offline.issued_at = 1000;
    offline.expires_at = 2000;

    auto canonical = offline_license_to_canonical_json(offline);

    EXPECT_FALSE(canonical.empty());
    EXPECT_TRUE(canonical.find("lic_k") != std::string::npos);
    EXPECT_TRUE(canonical.find("KEY-123") != std::string::npos);
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

TEST(JsonReleaseTest, ParseReleasesList) {
    nlohmann::json j = nlohmann::json::array({{{"version", "1.0.0"}, {"channel", "stable"}},
                                               {{"version", "0.9.0"}, {"channel", "beta"}}});

    auto releases = parse_releases(j);

    EXPECT_EQ(releases.size(), 2);
    EXPECT_EQ(releases[0].version, "1.0.0");
    EXPECT_EQ(releases[1].version, "0.9.0");
}

// ==================== Download Token Tests ====================

TEST(JsonDownloadTokenTest, ParseToken) {
    nlohmann::json j = {{"download_token", "token-abc"}, {"expires_in_seconds", 300}};

    auto token = parse_download_token(j);

    EXPECT_EQ(token.token, "token-abc");
    EXPECT_EQ(token.expires_in_seconds, 300);
}

// ==================== Public Key Tests ====================

TEST(JsonPublicKeyTest, ParsePublicKey) {
    nlohmann::json j = {{"key_id", "key-v1"}, {"public_key_b64", "base64-encoded-key"}};

    auto key = parse_public_key(j);

    EXPECT_EQ(key, "base64-encoded-key");
}

// ==================== Error Response Tests ====================

TEST(JsonErrorResponseTest, ParseError) {
    nlohmann::json j = {{"error", "License not found"}, {"reason_code", "license_not_found"}};

    auto err = parse_error_response(j);

    EXPECT_EQ(err.error, "License not found");
    EXPECT_EQ(err.reason_code, "license_not_found");
}

TEST(JsonErrorCodeMappingTest, ReasonCodeToErrorCode) {
    EXPECT_EQ(reason_code_to_error_code("license_not_found"), ErrorCode::LicenseNotFound);
    EXPECT_EQ(reason_code_to_error_code("license_expired"), ErrorCode::LicenseExpired);
    EXPECT_EQ(reason_code_to_error_code("seat_limit_exceeded"), ErrorCode::SeatLimitExceeded);
    EXPECT_EQ(reason_code_to_error_code("unknown_code"), ErrorCode::Unknown);
}

// ==================== Request Body Builder Tests ====================

TEST(JsonRequestBuilderTest, BuildValidateRequest) {
    auto body = build_validate_request("KEY-123", "device-001", "my-product");

    EXPECT_EQ(body["license_key"], "KEY-123");
    EXPECT_EQ(body["device_identifier"], "device-001");
    EXPECT_EQ(body["product_slug"], "my-product");
}

TEST(JsonRequestBuilderTest, BuildValidateRequestMinimal) {
    auto body = build_validate_request("KEY-123", "", "");

    EXPECT_EQ(body["license_key"], "KEY-123");
    EXPECT_FALSE(body.contains("device_identifier"));
    EXPECT_FALSE(body.contains("product_slug"));
}

TEST(JsonRequestBuilderTest, BuildActivateRequest) {
    Metadata meta{{"os", "macos"}};
    auto body = build_activate_request("KEY-123", "device-001", meta);

    EXPECT_EQ(body["license_key"], "KEY-123");
    EXPECT_EQ(body["device_identifier"], "device-001");
    EXPECT_EQ(body["metadata"]["os"], "macos");
}

TEST(JsonRequestBuilderTest, BuildDeactivateRequest) {
    auto body = build_deactivate_request("KEY-123", "device-001");

    EXPECT_EQ(body["license_key"], "KEY-123");
    EXPECT_EQ(body["device_identifier"], "device-001");
}

TEST(JsonRequestBuilderTest, BuildDownloadTokenRequest) {
    auto body = build_download_token_request("KEY-123");

    EXPECT_EQ(body["license_key"], "KEY-123");
}

}  // namespace
}  // namespace json
}  // namespace licenseseat
