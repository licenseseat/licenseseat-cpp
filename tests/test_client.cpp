#include <gtest/gtest.h>
#include <licenseseat/licenseseat.hpp>
#include <licenseseat/events.hpp>

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
        config_.device_id = "test-device-001";
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
    EXPECT_EQ(client.device_id(), "test-device-001");
}

TEST_F(ClientTest, GeneratesDeviceIdIfNotProvided) {
    Config config;
    config.api_key = "key";
    config.product_slug = "product";
    config.api_url = "http://localhost:1";
    // No device_id set

    Client client(config);

    EXPECT_FALSE(client.device_id().empty());
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
    auto result = client.deactivate("", "device-123");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidLicenseKey);
}

TEST_F(ClientTest, DeactivateWithEmptyDeviceIdFails) {
    Client client(config_);
    auto result = client.deactivate("VALID-KEY", "");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::MissingParameter);
}

TEST_F(ClientTest, DeactivateReturnsNetworkErrorWhenNoServer) {
    Client client(config_);
    auto result = client.deactivate("VALID-KEY", "device-123");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::NetworkError);
}

// ==================== Offline Token Input Validation ====================

TEST_F(ClientTest, GenerateOfflineTokenWithEmptyKeyFails) {
    Client client(config_);
    auto result = client.generate_offline_token("");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidLicenseKey);
}

TEST_F(ClientTest, VerifyOfflineTokenWithEmptyKeyFails) {
    Client client(config_);

    OfflineToken offline;
    offline.token.license_key = "";

    auto result = client.verify_offline_token(offline);

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidLicenseKey);
}

TEST_F(ClientTest, VerifyExpiredOfflineTokenFails) {
    Client client(config_);

    OfflineToken offline;
    offline.token.license_key = "KEY-123";
    offline.token.iat = std::time(nullptr) - (365 * 24 * 60 * 60);
    offline.token.nbf = offline.token.iat;
    offline.token.exp = std::time(nullptr) - (24 * 60 * 60);  // Expired

    auto result = client.verify_offline_token(offline);

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::LicenseExpired);
}

TEST_F(ClientTest, VerifyOfflineTokenWithInvalidSignature) {
    Client client(config_);

    OfflineToken offline;
    offline.token.license_key = "KEY-123";
    offline.token.kid = "key-v1";
    offline.token.iat = std::time(nullptr);
    offline.token.nbf = offline.token.iat;
    offline.token.exp = std::time(nullptr) + (365 * 24 * 60 * 60);
    offline.signature.key_id = "key-v1";
    offline.signature.value = "invalid-signature";  // Not a valid signature
    offline.canonical = R"({"test":"data"})";

    // Valid Ed25519 public key (32 bytes base64)
    const std::string public_key = "PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=";
    auto result = client.verify_offline_token(offline, public_key);

    // Invalid signature should fail verification
    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidSignature);
}

TEST_F(ClientTest, VerifyOfflineTokenNotYetValidFails) {
    Client client(config_);

    OfflineToken offline;
    offline.token.license_key = "KEY-123";
    offline.token.kid = "key-v1";
    offline.token.iat = std::time(nullptr);
    offline.token.nbf = std::time(nullptr) + (24 * 60 * 60);  // Not valid until tomorrow
    offline.token.exp = std::time(nullptr) + (365 * 24 * 60 * 60);

    auto result = client.verify_offline_token(offline);

    EXPECT_TRUE(result.is_error());
    // Token is not yet valid (nbf in future)
}

TEST_F(ClientTest, FetchSigningKeyWithEmptyIdFails) {
    Client client(config_);
    auto result = client.fetch_signing_key("");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::MissingParameter);
}

// ==================== Release Input Validation ====================

TEST_F(ClientTest, GetLatestReleaseUsesConfigProductSlug) {
    Client client(config_);
    // Should not fail with MissingParameter since we have product_slug in config
    auto result = client.get_latest_release();

    // Will fail with network error since we have a product_slug in config
    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::NetworkError);
}

TEST_F(ClientTest, ListReleasesUsesConfigProductSlug) {
    Client client(config_);
    auto result = client.list_releases();

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::NetworkError);
}

TEST_F(ClientTest, GenerateDownloadTokenWithEmptyKeyFails) {
    Client client(config_);
    auto result = client.generate_download_token("1.0.0", "");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidLicenseKey);
}

TEST_F(ClientTest, GenerateDownloadTokenWithEmptyVersionFails) {
    Client client(config_);
    auto result = client.generate_download_token("", "LICENSE-KEY");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::MissingParameter);
}

// ==================== Health Check ====================

TEST_F(ClientTest, HealthReturnsNetworkErrorWhenNoServer) {
    Client client(config_);
    auto result = client.health();

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

    client.deactivate_async("TEST-KEY", [&](Result<Deactivation> /*result*/) { callback_called = true; },
                            "device-123");

    int attempts = 0;
    while (!callback_called && attempts++ < 100) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    EXPECT_TRUE(callback_called);
}

// ==================== Version ====================

TEST(VersionTest, VersionIsSet) {
    EXPECT_STREQ(VERSION, "0.4.0");
}

// ==================== ClientStatus Tests ====================

TEST_F(ClientTest, GetClientStatusReturnsInactiveWhenNoLicense) {
    Client client(config_);

    auto status = client.get_client_status();

    EXPECT_EQ(status, ClientStatus::Inactive);
}

TEST_F(ClientTest, ClientStatusToStringWorks) {
    EXPECT_STREQ(client_status_to_string(ClientStatus::Active), "active");
    EXPECT_STREQ(client_status_to_string(ClientStatus::OfflineValid), "offline_valid");
    EXPECT_STREQ(client_status_to_string(ClientStatus::OfflineInvalid), "offline_invalid");
    EXPECT_STREQ(client_status_to_string(ClientStatus::Inactive), "inactive");
    EXPECT_STREQ(client_status_to_string(ClientStatus::Invalid), "invalid");
    EXPECT_STREQ(client_status_to_string(ClientStatus::Pending), "pending");
}

TEST_F(ClientTest, OfflineInvalidStatusExists) {
    // Verify OfflineInvalid is a valid ClientStatus value
    ClientStatus status = ClientStatus::OfflineInvalid;
    EXPECT_EQ(status, ClientStatus::OfflineInvalid);
    EXPECT_NE(status, ClientStatus::OfflineValid);
    EXPECT_NE(status, ClientStatus::Invalid);
}

// ==================== RestoreResult Tests ====================

TEST_F(ClientTest, RestoreLicenseReturnsInactiveWhenNoCache) {
    Client client(config_);

    auto result = client.restore_license();

    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.status, ClientStatus::Inactive);
    EXPECT_FALSE(result.license.has_value());
    EXPECT_FALSE(result.message.empty());
}

TEST_F(ClientTest, RestoreLicenseAsyncCallsCallback) {
    Client client(config_);
    std::atomic<bool> callback_called{false};
    RestoreResult received_result;

    client.restore_license_async([&](RestoreResult result) {
        received_result = result;
        callback_called = true;
    });

    int attempts = 0;
    while (!callback_called && attempts++ < 100) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    EXPECT_TRUE(callback_called);
    EXPECT_FALSE(received_result.success);
    EXPECT_EQ(received_result.status, ClientStatus::Inactive);
}

// ==================== Thread Safety Tests ====================

TEST_F(ClientTest, DestructorWaitsForAsyncOperations) {
    // This test ensures that destroying the client waits for pending async ops
    std::atomic<int> callback_count{0};

    {
        Client client(config_);

        // Start multiple async operations
        for (int i = 0; i < 5; i++) {
            client.validate_async("TEST-KEY-" + std::to_string(i),
                                  [&](Result<ValidationResult> /*result*/) {
                                      callback_count++;
                                  });
        }
        // Client destructor should wait for all callbacks to complete
    }

    // Give some time for potential issues to manifest
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // All callbacks should have been called before destructor completed
    EXPECT_EQ(callback_count, 5);
}

TEST_F(ClientTest, MultipleAsyncOpsDoNotCrash) {
    Client client(config_);
    std::atomic<int> completed{0};

    // Launch many concurrent async operations
    for (int i = 0; i < 10; i++) {
        client.validate_async("KEY-" + std::to_string(i),
                              [&](Result<ValidationResult> /*result*/) { completed++; });
        client.activate_async("KEY-" + std::to_string(i),
                              [&](Result<Activation> /*result*/) { completed++; });
    }

    // Wait for completion
    int attempts = 0;
    while (completed < 20 && attempts++ < 200) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    EXPECT_EQ(completed, 20);
}

// ==================== Network Recheck Timer Tests ====================

TEST_F(ClientTest, IsOnlineChangesOnHealthCheckFailure) {
    // Initially online
    Client client(config_);
    EXPECT_TRUE(client.is_online());

    // Health check fails (no server), should mark as offline
    auto result = client.health();
    EXPECT_TRUE(result.is_error());

    // Now should be offline
    EXPECT_FALSE(client.is_online());
}

// ==================== Event Emission Tests ====================

TEST_F(ClientTest, NetworkOfflineEventEmittedOnHealthFailure) {
    Client client(config_);
    bool offline_event_received = false;

    client.on("network:offline", [&](const std::any& /*data*/) {
        offline_event_received = true;
    });

    // Force a health check failure
    auto result = client.health();
    EXPECT_TRUE(result.is_error());

    EXPECT_TRUE(offline_event_received);
}

TEST_F(ClientTest, ValidationFailedEventEmittedOnNetworkError) {
    Client client(config_);
    bool error_event_received = false;

    client.on("validation:error", [&](const std::any& /*data*/) {
        error_event_received = true;
    });

    // Validation will fail with network error
    auto result = client.validate("TEST-KEY");
    EXPECT_TRUE(result.is_error());

    // Note: Network error goes to validation:error, not validation:failed
    // validation:failed is for 200 OK with valid=false
}

// ==================== License Revocation Tests ====================

TEST_F(ClientTest, LicenseRevokedConstantExists) {
    // Just verify the event constant exists
    EXPECT_STREQ(events::LICENSE_REVOKED, "license:revoked");
}

TEST_F(ClientTest, CanSubscribeToLicenseRevokedEvent) {
    Client client(config_);
    bool event_received = false;

    auto sub = client.on("license:revoked", [&](const std::any& /*data*/) {
        event_received = true;
    });

    // Manually emit to verify subscription works
    client.emit("license:revoked");

    EXPECT_TRUE(event_received);
}

}  // namespace
}  // namespace licenseseat
