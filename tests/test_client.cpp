#include <gtest/gtest.h>
#include <licenseseat/licenseseat.hpp>

#include <atomic>
#include <chrono>
#include <thread>

namespace licenseseat {
namespace {

class ClientTest : public ::testing::Test {
  protected:
    void SetUp() override {
        config_.api_key = "test_api_key";
        config_.product_slug = "test_product";
        config_.device_identifier = "test-device-001";
        // Use a non-existent URL so network calls fail fast
        config_.api_url = "http://localhost:1";
        config_.timeout_seconds = 1;
        config_.max_retries = 0;
    }

    Config config_;
};

// ==================== Construction Tests ====================

TEST_F(ClientTest, CanBeConstructed) {
    Client client(config_);

    EXPECT_EQ(client.config().api_key, "test_api_key");
    EXPECT_EQ(client.config().product_slug, "test_product");
    EXPECT_EQ(client.device_identifier(), "test-device-001");
}

TEST_F(ClientTest, GeneratesDeviceIdIfNotProvided) {
    Config config;
    config.api_key = "key";
    config.api_url = "http://localhost:1";
    // No device_identifier set

    Client client(config);

    EXPECT_FALSE(client.device_identifier().empty());
}

// ==================== Validation Input Validation ====================

TEST_F(ClientTest, ValidateWithEmptyKeyFails) {
    Client client(config_);
    auto result = client.validate("");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidLicenseKey);
    EXPECT_FALSE(result.error_message().empty());
}

// Network calls will fail, but we can test error handling
TEST_F(ClientTest, ValidateReturnsNetworkErrorWhenNoServer) {
    Client client(config_);
    auto result = client.validate("VALID-KEY");

    // Should fail because no server is running
    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::NetworkError);
}

// ==================== Activation Input Validation ====================

TEST_F(ClientTest, ActivateWithEmptyKeyFails) {
    Client client(config_);
    auto result = client.activate("");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidLicenseKey);
    EXPECT_FALSE(result.error_message().empty());
}

TEST_F(ClientTest, ActivateReturnsNetworkErrorWhenNoServer) {
    Client client(config_);
    auto result = client.activate("VALID-KEY");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::NetworkError);
}

// ==================== Deactivation Input Validation ====================

TEST_F(ClientTest, DeactivateWithEmptyKeyFails) {
    Client client(config_);
    auto result = client.deactivate("");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidLicenseKey);
}

TEST_F(ClientTest, DeactivateReturnsNetworkErrorWhenNoServer) {
    Client client(config_);
    auto result = client.deactivate("VALID-KEY");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::NetworkError);
}

// ==================== Offline License Input Validation ====================

TEST_F(ClientTest, GenerateOfflineLicenseWithEmptyKeyFails) {
    Client client(config_);
    auto result = client.generate_offline_license("");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidLicenseKey);
}

TEST_F(ClientTest, VerifyOfflineLicenseWithEmptyKeyFails) {
    Client client(config_);

    OfflineLicense offline;
    offline.license_key = "";

    auto result = client.verify_offline_license(offline);

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidLicenseKey);
}

TEST_F(ClientTest, VerifyExpiredOfflineLicenseFails) {
    Client client(config_);

    OfflineLicense offline;
    offline.license_key = "KEY-123";
    offline.issued_at = std::time(nullptr) - (365 * 24 * 60 * 60);
    offline.expires_at = std::time(nullptr) - (24 * 60 * 60);  // Expired

    auto result = client.verify_offline_license(offline);

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::LicenseExpired);
}

TEST_F(ClientTest, VerifyOfflineLicenseWithInvalidSignature) {
    Client client(config_);

    OfflineLicense offline;
    offline.license_key = "KEY-123";
    offline.key_id = "key-v1";
    offline.issued_at = std::time(nullptr);
    offline.expires_at = std::time(nullptr) + (365 * 24 * 60 * 60);
    offline.signature_b64u = "invalid-signature";  // Not a valid signature

    // Valid Ed25519 public key (32 bytes base64)
    const std::string public_key = "PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=";
    auto result = client.verify_offline_license(offline, public_key);

    // Invalid signature should fail verification
    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidSignature);
}

TEST_F(ClientTest, FetchPublicKeyWithEmptyIdFails) {
    Client client(config_);
    auto result = client.fetch_public_key("");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::MissingParameter);
}

// ==================== Release Input Validation ====================

TEST_F(ClientTest, GetLatestReleaseWithEmptySlugFails) {
    Client client(config_);
    auto result = client.get_latest_release("");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::MissingParameter);
}

TEST_F(ClientTest, ListReleasesWithEmptySlugFails) {
    Client client(config_);
    auto result = client.list_releases("");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::MissingParameter);
}

TEST_F(ClientTest, GenerateDownloadTokenWithEmptyKeyFails) {
    Client client(config_);
    auto result = client.generate_download_token(123, "");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidLicenseKey);
}

// ==================== Health Check ====================

TEST_F(ClientTest, HeartbeatReturnsNetworkErrorWhenNoServer) {
    Client client(config_);
    auto result = client.heartbeat();

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::NetworkError);
}

// ==================== Move Semantics ====================

TEST_F(ClientTest, CanBeMoved) {
    Client client1(config_);

    Client client2 = std::move(client1);

    // client2 should work
    EXPECT_EQ(client2.config().api_key, "test_api_key");
}

// ==================== Event Handling ====================

TEST_F(ClientTest, CanSubscribeToEvents) {
    Client client(config_);
    bool called = false;

    auto sub = client.on("test:event", [&](const std::any& /*data*/) { called = true; });

    client.emit("test:event");

    EXPECT_TRUE(called);
}

TEST_F(ClientTest, SubscriptionCanBeCancelled) {
    Client client(config_);
    int call_count = 0;

    auto sub = client.on("test:event", [&](const std::any& /*data*/) { call_count++; });

    client.emit("test:event");
    EXPECT_EQ(call_count, 1);

    sub.cancel();

    client.emit("test:event");
    EXPECT_EQ(call_count, 1);  // Should not increase
}

TEST_F(ClientTest, EventsReceiveData) {
    Client client(config_);
    std::string received_data;

    client.on("test:event", [&](const std::any& data) {
        if (data.has_value()) {
            received_data = std::any_cast<std::string>(data);
        }
    });

    client.emit("test:event", std::string("hello world"));

    EXPECT_EQ(received_data, "hello world");
}

// ==================== Status Methods ====================

TEST_F(ClientTest, GetStatusReturnsInvalidWhenNoLicense) {
    Client client(config_);

    auto status = client.get_status();

    EXPECT_FALSE(status.valid);
}

TEST_F(ClientTest, CurrentLicenseReturnsNulloptWhenNoLicense) {
    Client client(config_);

    auto license = client.current_license();

    EXPECT_FALSE(license.has_value());
}

TEST_F(ClientTest, CheckEntitlementReturnsInactiveWhenNoLicense) {
    Client client(config_);

    auto status = client.check_entitlement("updates");

    EXPECT_FALSE(status.active);
    EXPECT_EQ(status.reason, "no_license");
}

TEST_F(ClientTest, IsOnlineDefaultsToTrue) {
    Client client(config_);

    // Starts as online until we know otherwise
    EXPECT_TRUE(client.is_online());
}

// ==================== Auto-Validation ====================

TEST_F(ClientTest, AutoValidationNotRunningByDefault) {
    Client client(config_);

    EXPECT_FALSE(client.is_auto_validating());
}

TEST_F(ClientTest, StartAndStopAutoValidation) {
    Client client(config_);

    client.start_auto_validation("TEST-KEY");
    EXPECT_TRUE(client.is_auto_validating());

    client.stop_auto_validation();
    EXPECT_FALSE(client.is_auto_validating());
}

TEST_F(ClientTest, StartAutoValidationTwiceDoesNotCrash) {
    Client client(config_);

    client.start_auto_validation("TEST-KEY");
    client.start_auto_validation("TEST-KEY-2");  // Should not crash

    EXPECT_TRUE(client.is_auto_validating());

    client.stop_auto_validation();
}

TEST_F(ClientTest, StopAutoValidationWhenNotRunningDoesNotCrash) {
    Client client(config_);

    // Should not crash
    client.stop_auto_validation();
    client.stop_auto_validation();

    EXPECT_FALSE(client.is_auto_validating());
}

// ==================== Reset ====================

TEST_F(ClientTest, ResetStopsAutoValidation) {
    Client client(config_);

    client.start_auto_validation("TEST-KEY");
    EXPECT_TRUE(client.is_auto_validating());

    client.reset();

    EXPECT_FALSE(client.is_auto_validating());
}

// ==================== Async API ====================

TEST_F(ClientTest, ValidateAsyncCallsCallback) {
    Client client(config_);
    std::atomic<bool> callback_called{false};
    ErrorCode received_error = ErrorCode::Success;

    client.validate_async(
        "TEST-KEY",
        [&](Result<ValidationResult> result) {
            callback_called = true;
            if (result.is_error()) {
                received_error = result.error_code();
            }
        });

    // Wait for callback (should fail with network error)
    int attempts = 0;
    while (!callback_called && attempts++ < 100) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    EXPECT_TRUE(callback_called);
    EXPECT_EQ(received_error, ErrorCode::NetworkError);
}

TEST_F(ClientTest, ActivateAsyncCallsCallback) {
    Client client(config_);
    std::atomic<bool> callback_called{false};

    client.activate_async("TEST-KEY", [&](Result<Activation> /*result*/) { callback_called = true; });

    int attempts = 0;
    while (!callback_called && attempts++ < 100) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    EXPECT_TRUE(callback_called);
}

TEST_F(ClientTest, DeactivateAsyncCallsCallback) {
    Client client(config_);
    std::atomic<bool> callback_called{false};

    client.deactivate_async("TEST-KEY",
                            [&](Result<Activation> /*result*/) { callback_called = true; });

    int attempts = 0;
    while (!callback_called && attempts++ < 100) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    EXPECT_TRUE(callback_called);
}

// ==================== Version ====================

TEST(VersionTest, VersionIsSet) {
    EXPECT_STREQ(VERSION, "0.1.0");
}

}  // namespace
}  // namespace licenseseat
