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

    // Helper to create a license with defaults
    static License make_license(const std::string& key = "KEY-123",
                                LicenseStatus status = LicenseStatus::Active,
                                LicenseMode mode = LicenseMode::HardwareLocked,
                                std::optional<int> seat_limit = 5,
                                int active_seats = 0,
                                std::optional<Timestamp> starts_at = std::nullopt,
                                std::optional<Timestamp> expires_at = std::nullopt) {
        Product product{"test-product", "Test Product"};
        return License(key, status, mode, "pro-annual", seat_limit, active_seats,
                       starts_at, expires_at, {}, {}, product);
    }
};

TEST_F(LicenseTest, DefaultConstructor) {
    License license;

    EXPECT_TRUE(license.key().empty());
    EXPECT_EQ(license.status(), LicenseStatus::Unknown);
    EXPECT_EQ(license.mode(), LicenseMode::Unknown);
    EXPECT_TRUE(license.plan_key().empty());
    EXPECT_FALSE(license.seat_limit().has_value());
    EXPECT_EQ(license.active_seats(), 0);
    EXPECT_FALSE(license.starts_at().has_value());
    EXPECT_FALSE(license.expires_at().has_value());
    EXPECT_TRUE(license.metadata().empty());
    EXPECT_TRUE(license.active_entitlements().empty());
}

TEST_F(LicenseTest, FullConstructor) {
    auto start = hours_ago(1);
    auto end = hours_from_now(24);
    Metadata meta{{"customer", "test"}};
    Product product{"my-product", "My Product"};
    std::vector<Entitlement> entitlements{{"updates", std::nullopt, {}}};

    License license("KEY-123", LicenseStatus::Active, LicenseMode::HardwareLocked, "pro-annual",
                    5, 2, start, end, entitlements, meta, product);

    EXPECT_EQ(license.key(), "KEY-123");
    EXPECT_EQ(license.status(), LicenseStatus::Active);
    EXPECT_EQ(license.mode(), LicenseMode::HardwareLocked);
    EXPECT_EQ(license.plan_key(), "pro-annual");
    EXPECT_TRUE(license.seat_limit().has_value());
    EXPECT_EQ(*license.seat_limit(), 5);
    EXPECT_EQ(license.active_seats(), 2);
    EXPECT_TRUE(license.starts_at().has_value());
    EXPECT_TRUE(license.expires_at().has_value());
    EXPECT_EQ(license.metadata().at("customer"), "test");
    EXPECT_EQ(license.active_entitlements().size(), 1);
    EXPECT_EQ(license.product().slug, "my-product");
    EXPECT_EQ(license.product().name, "My Product");
}

TEST_F(LicenseTest, IsValidWhenActive) {
    auto start = hours_ago(1);
    auto end = hours_from_now(24);

    auto license = make_license("KEY-123", LicenseStatus::Active, LicenseMode::HardwareLocked,
                                5, 0, start, end);

    EXPECT_TRUE(license.is_valid());
}

TEST_F(LicenseTest, IsNotValidWhenExpired) {
    auto start = hours_ago(48);
    auto end = hours_ago(24);  // Expired 24 hours ago

    auto license = make_license("KEY-123", LicenseStatus::Active, LicenseMode::HardwareLocked,
                                5, 0, start, end);

    EXPECT_FALSE(license.is_valid());
    EXPECT_TRUE(license.is_expired());
}

TEST_F(LicenseTest, IsNotValidWhenNotStarted) {
    auto start = hours_from_now(24);  // Starts in 24 hours
    auto end = hours_from_now(48);

    auto license = make_license("KEY-123", LicenseStatus::Active, LicenseMode::HardwareLocked,
                                5, 0, start, end);

    EXPECT_FALSE(license.is_valid());
    EXPECT_FALSE(license.has_started());
}

TEST_F(LicenseTest, IsNotValidWhenRevoked) {
    auto start = hours_ago(1);
    auto end = hours_from_now(24);

    auto license = make_license("KEY-123", LicenseStatus::Revoked, LicenseMode::HardwareLocked,
                                5, 0, start, end);

    EXPECT_FALSE(license.is_valid());
}

TEST_F(LicenseTest, IsNotValidWhenSuspended) {
    auto start = hours_ago(1);
    auto end = hours_from_now(24);

    auto license = make_license("KEY-123", LicenseStatus::Suspended, LicenseMode::HardwareLocked,
                                5, 0, start, end);

    EXPECT_FALSE(license.is_valid());
}

TEST_F(LicenseTest, HasAvailableSeats) {
    auto license = make_license("KEY-123", LicenseStatus::Active, LicenseMode::HardwareLocked,
                                5, 2);

    EXPECT_TRUE(license.has_available_seats());
    EXPECT_EQ(license.remaining_seats(), 3);
}

TEST_F(LicenseTest, NoAvailableSeats) {
    auto license = make_license("KEY-123", LicenseStatus::Active, LicenseMode::HardwareLocked,
                                5, 5);

    EXPECT_FALSE(license.has_available_seats());
    EXPECT_EQ(license.remaining_seats(), 0);
}

TEST_F(LicenseTest, UnlimitedSeats) {
    auto license = make_license("KEY-123", LicenseStatus::Active, LicenseMode::HardwareLocked,
                                std::nullopt, 100);  // nullopt = unlimited

    EXPECT_TRUE(license.has_available_seats());
    EXPECT_EQ(license.remaining_seats(), -1);  // -1 indicates unlimited
}

TEST_F(LicenseTest, NoExpiryMeansNotExpired) {
    auto license = make_license("KEY-123", LicenseStatus::Active, LicenseMode::HardwareLocked,
                                5, 0, std::nullopt, std::nullopt);

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
    EXPECT_TRUE(activation.device_id().empty());
    EXPECT_TRUE(activation.device_name().empty());
    EXPECT_TRUE(activation.license_key().empty());
    EXPECT_TRUE(activation.ip_address().empty());
    EXPECT_TRUE(activation.metadata().empty());
    EXPECT_FALSE(activation.deactivated_at().has_value());
}

TEST(ActivationTest, FullConstructor) {
    auto activated = std::chrono::system_clock::now();
    Metadata meta{{"os", "macos"}};

    Activation activation(42, "device-123", "My MacBook", "KEY-ABC", activated, std::nullopt,
                          "192.168.1.1", meta);

    EXPECT_EQ(activation.id(), 42);
    EXPECT_EQ(activation.device_id(), "device-123");
    EXPECT_EQ(activation.device_name(), "My MacBook");
    EXPECT_EQ(activation.license_key(), "KEY-ABC");
    EXPECT_EQ(activation.ip_address(), "192.168.1.1");
    EXPECT_EQ(activation.metadata().at("os"), "macos");
    EXPECT_TRUE(activation.is_active());
}

TEST(ActivationTest, DeactivatedActivation) {
    auto activated = std::chrono::system_clock::now() - std::chrono::hours(24);
    auto deactivated = std::chrono::system_clock::now();

    Activation activation(42, "device-123", "", "KEY-ABC", activated, deactivated, "192.168.1.1",
                          {});

    EXPECT_FALSE(activation.is_active());
    EXPECT_TRUE(activation.deactivated_at().has_value());
}

// ==================== OfflineToken Tests ====================

TEST(OfflineTokenTest, DefaultState) {
    OfflineToken offline;

    EXPECT_TRUE(offline.token.license_key.empty());
    EXPECT_TRUE(offline.token.kid.empty());
    EXPECT_EQ(offline.token.iat, 0);
    EXPECT_EQ(offline.token.exp, 0);
    EXPECT_TRUE(offline.token.entitlements.empty());
    EXPECT_TRUE(offline.token.metadata.empty());
    EXPECT_TRUE(offline.signature.value.empty());
    EXPECT_TRUE(offline.canonical.empty());
}

TEST(OfflineTokenTest, IsExpired) {
    OfflineToken offline;
    offline.token.license_key = "KEY-123";
    offline.token.iat = std::time(nullptr) - (365 * 24 * 60 * 60);  // 1 year ago
    offline.token.exp = std::time(nullptr) - (24 * 60 * 60);        // Yesterday
    offline.token.nbf = offline.token.iat;

    EXPECT_TRUE(offline.is_expired());
}

TEST(OfflineTokenTest, IsNotExpired) {
    OfflineToken offline;
    offline.token.license_key = "KEY-123";
    offline.token.iat = std::time(nullptr);
    offline.token.exp = std::time(nullptr) + (365 * 24 * 60 * 60);  // 1 year from now
    offline.token.nbf = offline.token.iat;

    EXPECT_FALSE(offline.is_expired());
}

TEST(OfflineTokenTest, HasEntitlement) {
    OfflineToken offline;
    offline.token.license_key = "KEY-123";
    offline.token.entitlements.push_back(Entitlement{"updates", std::nullopt, {}});
    offline.token.entitlements.push_back(Entitlement{"support", std::nullopt, {}});

    EXPECT_TRUE(offline.has_entitlement("updates"));
    EXPECT_TRUE(offline.has_entitlement("support"));
    EXPECT_FALSE(offline.has_entitlement("premium"));
}

TEST(OfflineTokenTest, ExpiredEntitlement) {
    OfflineToken offline;
    offline.token.license_key = "KEY-123";

    auto expired_time = std::chrono::system_clock::now() - std::chrono::hours(24);
    offline.token.entitlements.push_back(Entitlement{"updates", expired_time, {}});

    EXPECT_FALSE(offline.has_entitlement("updates"));
}

TEST(OfflineTokenTest, IsNotYetValid) {
    OfflineToken offline;
    offline.token.license_key = "KEY-123";
    offline.token.iat = std::time(nullptr) + (24 * 60 * 60);  // Tomorrow
    offline.token.nbf = offline.token.iat;
    offline.token.exp = std::time(nullptr) + (365 * 24 * 60 * 60);

    EXPECT_TRUE(offline.is_not_yet_valid());
}

TEST(OfflineTokenTest, LicenseExpired) {
    OfflineToken offline;
    offline.token.license_key = "KEY-123";
    offline.token.iat = std::time(nullptr) - (24 * 60 * 60);
    offline.token.nbf = offline.token.iat;
    offline.token.exp = std::time(nullptr) + (30 * 24 * 60 * 60);  // Token valid for 30 days
    offline.token.license_expires_at = std::time(nullptr) - (24 * 60 * 60);  // License expired yesterday

    EXPECT_FALSE(offline.is_expired());  // Token not expired
    EXPECT_TRUE(offline.is_license_expired());  // But license is expired
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
    EXPECT_FALSE(token.expires_at.has_value());
}

// ==================== Deactivation Tests ====================

TEST(DeactivationTest, DefaultState) {
    Deactivation deactivation;

    EXPECT_EQ(deactivation.activation_id, 0);
}

// ==================== Config Tests ====================

TEST(ConfigTest, DefaultValues) {
    Config config;

    EXPECT_TRUE(config.api_key.empty());
    EXPECT_EQ(config.api_url, "https://licenseseat.com/api/v1");
    EXPECT_TRUE(config.product_slug.empty());
    EXPECT_TRUE(config.device_id.empty());
    EXPECT_TRUE(config.storage_path.empty());
    EXPECT_TRUE(config.signing_public_key.empty());
    EXPECT_TRUE(config.signing_key_id.empty());
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
    config.device_id = "device-123";
    config.timeout_seconds = 60;
    config.verify_ssl = false;
    config.max_retries = 5;

    EXPECT_EQ(config.api_key, "my_api_key");
    EXPECT_EQ(config.api_url, "https://custom.api.com");
    EXPECT_EQ(config.product_slug, "my_product");
    EXPECT_EQ(config.device_id, "device-123");
    EXPECT_EQ(config.timeout_seconds, 60);
    EXPECT_FALSE(config.verify_ssl);
    EXPECT_EQ(config.max_retries, 5);
}

// ==================== Entitlement Tests ====================

TEST(EntitlementTest, DefaultState) {
    Entitlement ent;

    EXPECT_TRUE(ent.key.empty());
    EXPECT_FALSE(ent.expires_at.has_value());
    EXPECT_TRUE(ent.metadata.empty());
}

TEST(EntitlementTest, WithExpiry) {
    auto expiry = std::chrono::system_clock::now() + std::chrono::hours(24);
    Entitlement ent{"updates", expiry, {{"tier", "premium"}}};

    EXPECT_EQ(ent.key, "updates");
    EXPECT_TRUE(ent.expires_at.has_value());
    EXPECT_EQ(ent.metadata.at("tier"), "premium");
}

// ==================== Product Tests ====================

TEST(ProductTest, DefaultState) {
    Product product;

    EXPECT_TRUE(product.slug.empty());
    EXPECT_TRUE(product.name.empty());
}

// ==================== ValidationWarning Tests ====================

TEST(ValidationWarningTest, DefaultState) {
    ValidationWarning warning;

    EXPECT_TRUE(warning.code.empty());
    EXPECT_TRUE(warning.message.empty());
}

}  // namespace
}  // namespace licenseseat
