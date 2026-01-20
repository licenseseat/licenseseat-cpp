#include <gtest/gtest.h>
#include <licenseseat/licenseseat.hpp>

namespace licenseseat {
namespace {

class LicenseTest : public ::testing::Test {
  protected:
    // Helper to create timestamps
    static Timestamp now() { return std::chrono::system_clock::now(); }

    static Timestamp hours_from_now(int hours) {
        return now() + std::chrono::hours(hours);
    }

    static Timestamp hours_ago(int hours) {
        return now() - std::chrono::hours(hours);
    }
};

TEST_F(LicenseTest, DefaultConstructor) {
    License license;

    EXPECT_TRUE(license.key().empty());
    EXPECT_EQ(license.status(), LicenseStatus::Unknown);
    EXPECT_EQ(license.mode(), LicenseMode::Unknown);
    EXPECT_TRUE(license.plan_key().empty());
    EXPECT_EQ(license.seat_limit(), 0);
    EXPECT_EQ(license.active_activations_count(), 0);
    EXPECT_FALSE(license.starts_at().has_value());
    EXPECT_FALSE(license.ends_at().has_value());
    EXPECT_TRUE(license.metadata().empty());
}

TEST_F(LicenseTest, FullConstructor) {
    auto start = hours_ago(1);
    auto end = hours_from_now(24);
    Metadata meta{{"customer", "test"}};

    License license("KEY-123", LicenseStatus::Active, LicenseMode::HardwareLocked, "pro-annual", 5,
                    2, start, end, meta);

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

TEST_F(LicenseTest, IsValidWhenActive) {
    auto start = hours_ago(1);
    auto end = hours_from_now(24);

    License license("KEY-123", LicenseStatus::Active, LicenseMode::HardwareLocked, "pro", 5, 0,
                    start, end, {});

    EXPECT_TRUE(license.is_valid());
}

TEST_F(LicenseTest, IsNotValidWhenExpired) {
    auto start = hours_ago(48);
    auto end = hours_ago(24);  // Expired 24 hours ago

    License license("KEY-123", LicenseStatus::Active, LicenseMode::HardwareLocked, "pro", 5, 0,
                    start, end, {});

    EXPECT_FALSE(license.is_valid());
    EXPECT_TRUE(license.is_expired());
}

TEST_F(LicenseTest, IsNotValidWhenNotStarted) {
    auto start = hours_from_now(24);  // Starts in 24 hours
    auto end = hours_from_now(48);

    License license("KEY-123", LicenseStatus::Active, LicenseMode::HardwareLocked, "pro", 5, 0,
                    start, end, {});

    EXPECT_FALSE(license.is_valid());
    EXPECT_FALSE(license.has_started());
}

TEST_F(LicenseTest, IsNotValidWhenRevoked) {
    auto start = hours_ago(1);
    auto end = hours_from_now(24);

    License license("KEY-123", LicenseStatus::Revoked, LicenseMode::HardwareLocked, "pro", 5, 0,
                    start, end, {});

    EXPECT_FALSE(license.is_valid());
}

TEST_F(LicenseTest, IsNotValidWhenSuspended) {
    auto start = hours_ago(1);
    auto end = hours_from_now(24);

    License license("KEY-123", LicenseStatus::Suspended, LicenseMode::HardwareLocked, "pro", 5, 0,
                    start, end, {});

    EXPECT_FALSE(license.is_valid());
}

TEST_F(LicenseTest, HasAvailableSeats) {
    License license("KEY-123", LicenseStatus::Active, LicenseMode::HardwareLocked, "pro", 5, 2,
                    std::nullopt, std::nullopt, {});

    EXPECT_TRUE(license.has_available_seats());
    EXPECT_EQ(license.remaining_seats(), 3);
}

TEST_F(LicenseTest, NoAvailableSeats) {
    License license("KEY-123", LicenseStatus::Active, LicenseMode::HardwareLocked, "pro", 5, 5,
                    std::nullopt, std::nullopt, {});

    EXPECT_FALSE(license.has_available_seats());
    EXPECT_EQ(license.remaining_seats(), 0);
}

TEST_F(LicenseTest, UnlimitedSeats) {
    License license("KEY-123", LicenseStatus::Active, LicenseMode::HardwareLocked, "pro", 0, 100,
                    std::nullopt, std::nullopt, {});

    EXPECT_TRUE(license.has_available_seats());
    EXPECT_EQ(license.remaining_seats(), -1);  // -1 indicates unlimited
}

TEST_F(LicenseTest, NoExpiryMeansNotExpired) {
    License license("KEY-123", LicenseStatus::Active, LicenseMode::HardwareLocked, "pro", 5, 0,
                    std::nullopt, std::nullopt, {});

    EXPECT_FALSE(license.is_expired());
    EXPECT_TRUE(license.is_valid());
}

// ==================== LicenseStatus Tests ====================

TEST(LicenseStatusTest, ToStringConversion) {
    EXPECT_STREQ(license_status_to_string(LicenseStatus::Active), "active");
    EXPECT_STREQ(license_status_to_string(LicenseStatus::Expired), "expired");
    EXPECT_STREQ(license_status_to_string(LicenseStatus::Revoked), "revoked");
    EXPECT_STREQ(license_status_to_string(LicenseStatus::Suspended), "suspended");
    EXPECT_STREQ(license_status_to_string(LicenseStatus::Pending), "pending");
    EXPECT_STREQ(license_status_to_string(LicenseStatus::Unknown), "unknown");
}

TEST(LicenseStatusTest, FromStringConversion) {
    EXPECT_EQ(license_status_from_string("active"), LicenseStatus::Active);
    EXPECT_EQ(license_status_from_string("expired"), LicenseStatus::Expired);
    EXPECT_EQ(license_status_from_string("revoked"), LicenseStatus::Revoked);
    EXPECT_EQ(license_status_from_string("suspended"), LicenseStatus::Suspended);
    EXPECT_EQ(license_status_from_string("pending"), LicenseStatus::Pending);
    EXPECT_EQ(license_status_from_string("invalid"), LicenseStatus::Unknown);
    EXPECT_EQ(license_status_from_string(""), LicenseStatus::Unknown);
}

// ==================== LicenseMode Tests ====================

TEST(LicenseModeTest, ToStringConversion) {
    EXPECT_STREQ(license_mode_to_string(LicenseMode::HardwareLocked), "hardware_locked");
    EXPECT_STREQ(license_mode_to_string(LicenseMode::Floating), "floating");
    EXPECT_STREQ(license_mode_to_string(LicenseMode::Named), "named");
    EXPECT_STREQ(license_mode_to_string(LicenseMode::Unknown), "unknown");
}

TEST(LicenseModeTest, FromStringConversion) {
    EXPECT_EQ(license_mode_from_string("hardware_locked"), LicenseMode::HardwareLocked);
    EXPECT_EQ(license_mode_from_string("floating"), LicenseMode::Floating);
    EXPECT_EQ(license_mode_from_string("named"), LicenseMode::Named);
    EXPECT_EQ(license_mode_from_string("invalid"), LicenseMode::Unknown);
}

// ==================== Activation Tests ====================

TEST(ActivationTest, DefaultConstructor) {
    Activation activation;

    EXPECT_EQ(activation.id(), 0);
    EXPECT_TRUE(activation.device_identifier().empty());
    EXPECT_TRUE(activation.license_key().empty());
    EXPECT_TRUE(activation.ip_address().empty());
    EXPECT_TRUE(activation.metadata().empty());
    EXPECT_FALSE(activation.deactivated_at().has_value());
}

TEST(ActivationTest, FullConstructor) {
    auto activated = std::chrono::system_clock::now();
    Metadata meta{{"os", "macos"}};

    Activation activation(42, "device-123", "KEY-ABC", activated, std::nullopt, "192.168.1.1",
                          meta);

    EXPECT_EQ(activation.id(), 42);
    EXPECT_EQ(activation.device_identifier(), "device-123");
    EXPECT_EQ(activation.license_key(), "KEY-ABC");
    EXPECT_EQ(activation.ip_address(), "192.168.1.1");
    EXPECT_EQ(activation.metadata().at("os"), "macos");
    EXPECT_TRUE(activation.is_active());
}

TEST(ActivationTest, DeactivatedActivation) {
    auto activated = std::chrono::system_clock::now() - std::chrono::hours(24);
    auto deactivated = std::chrono::system_clock::now();

    Activation activation(42, "device-123", "KEY-ABC", activated, deactivated, "192.168.1.1", {});

    EXPECT_FALSE(activation.is_active());
    EXPECT_TRUE(activation.deactivated_at().has_value());
}

// ==================== OfflineLicense Tests ====================

TEST(OfflineLicenseTest, DefaultState) {
    OfflineLicense offline;

    EXPECT_TRUE(offline.license_key.empty());
    EXPECT_TRUE(offline.key_id.empty());
    EXPECT_EQ(offline.issued_at, 0);
    EXPECT_EQ(offline.expires_at, 0);
    EXPECT_TRUE(offline.entitlements.empty());
    EXPECT_TRUE(offline.metadata.empty());
    EXPECT_TRUE(offline.signature_b64u.empty());
}

TEST(OfflineLicenseTest, IsExpired) {
    OfflineLicense offline;
    offline.license_key = "KEY-123";
    offline.issued_at = std::time(nullptr) - (365 * 24 * 60 * 60);  // 1 year ago
    offline.expires_at = std::time(nullptr) - (24 * 60 * 60);        // Yesterday

    EXPECT_TRUE(offline.is_expired());
}

TEST(OfflineLicenseTest, IsNotExpired) {
    OfflineLicense offline;
    offline.license_key = "KEY-123";
    offline.issued_at = std::time(nullptr);
    offline.expires_at = std::time(nullptr) + (365 * 24 * 60 * 60);  // 1 year from now

    EXPECT_FALSE(offline.is_expired());
}

TEST(OfflineLicenseTest, HasEntitlement) {
    OfflineLicense offline;
    offline.license_key = "KEY-123";
    offline.entitlements.push_back(Entitlement{"updates", std::nullopt, std::nullopt, std::nullopt, {}});
    offline.entitlements.push_back(Entitlement{"support", std::nullopt, std::nullopt, std::nullopt, {}});

    EXPECT_TRUE(offline.has_entitlement("updates"));
    EXPECT_TRUE(offline.has_entitlement("support"));
    EXPECT_FALSE(offline.has_entitlement("premium"));
}

TEST(OfflineLicenseTest, ExpiredEntitlement) {
    OfflineLicense offline;
    offline.license_key = "KEY-123";

    auto expired_time = std::chrono::system_clock::now() - std::chrono::hours(24);
    offline.entitlements.push_back(Entitlement{"updates", std::nullopt, std::nullopt, expired_time, {}});

    EXPECT_FALSE(offline.has_entitlement("updates"));
}

// ==================== Release Tests ====================

TEST(ReleaseTest, DefaultState) {
    Release release;

    EXPECT_TRUE(release.version.empty());
    EXPECT_TRUE(release.channel.empty());
    EXPECT_TRUE(release.platform.empty());
    EXPECT_TRUE(release.product_slug.empty());
    EXPECT_FALSE(release.published_at.has_value());
}

// ==================== DownloadToken Tests ====================

TEST(DownloadTokenTest, DefaultState) {
    DownloadToken token;

    EXPECT_TRUE(token.token.empty());
    EXPECT_EQ(token.expires_in_seconds, 0);
}

// ==================== Config Tests ====================

TEST(ConfigTest, DefaultValues) {
    Config config;

    EXPECT_TRUE(config.api_key.empty());
    EXPECT_EQ(config.api_url, "https://licenseseat.com/api");
    EXPECT_TRUE(config.product_slug.empty());
    EXPECT_TRUE(config.device_identifier.empty());
    EXPECT_TRUE(config.storage_path.empty());
    EXPECT_TRUE(config.offline_public_key.empty());
    EXPECT_TRUE(config.offline_key_id.empty());
    EXPECT_EQ(config.timeout_seconds, 30);
    EXPECT_TRUE(config.verify_ssl);
    EXPECT_EQ(config.max_retries, 3);
    EXPECT_EQ(config.retry_interval_ms, 1000);
}

TEST(ConfigTest, CustomValues) {
    Config config;
    config.api_key = "my_api_key";
    config.api_url = "https://custom.api.com";
    config.product_slug = "my_product";
    config.device_identifier = "device-123";
    config.timeout_seconds = 60;
    config.verify_ssl = false;
    config.max_retries = 5;

    EXPECT_EQ(config.api_key, "my_api_key");
    EXPECT_EQ(config.api_url, "https://custom.api.com");
    EXPECT_EQ(config.product_slug, "my_product");
    EXPECT_EQ(config.device_identifier, "device-123");
    EXPECT_EQ(config.timeout_seconds, 60);
    EXPECT_FALSE(config.verify_ssl);
    EXPECT_EQ(config.max_retries, 5);
}

}  // namespace
}  // namespace licenseseat
