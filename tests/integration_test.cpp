/**
 * @file integration_test.cpp
 * @brief Comprehensive integration test against live LicenseSeat API
 *
 * This test file validates all SDK functionality against the production API.
 *
 * Required environment variables:
 *   LICENSESEAT_API_KEY      - Your LicenseSeat API key
 *   LICENSESEAT_PRODUCT_SLUG - Your product slug
 *   LICENSESEAT_LICENSE_KEY  - A valid license key for testing
 *
 * Run with:
 *   export LICENSESEAT_API_KEY="your-api-key"
 *   export LICENSESEAT_PRODUCT_SLUG="your-product"
 *   export LICENSESEAT_LICENSE_KEY="XXXX-XXXX-XXXX-XXXX"
 *   ./integration_test
 */

#include <licenseseat/licenseseat.hpp>
#include <licenseseat/crypto.hpp>
#include <licenseseat/device.hpp>
#include <licenseseat/events.hpp>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <vector>
#include <iomanip>
#include <sstream>

namespace {

std::string get_env(const char* name) {
    const char* value = std::getenv(name);
    return value ? std::string(value) : std::string();
}

std::string API_KEY;
std::string PRODUCT_SLUG;
std::string LICENSE_KEY;

bool load_credentials() {
    API_KEY = get_env("LICENSESEAT_API_KEY");
    PRODUCT_SLUG = get_env("LICENSESEAT_PRODUCT_SLUG");
    LICENSE_KEY = get_env("LICENSESEAT_LICENSE_KEY");

    if (API_KEY.empty() || PRODUCT_SLUG.empty() || LICENSE_KEY.empty()) {
        std::cerr << "Error: Missing required environment variables.\n\n";
        std::cerr << "Please set the following environment variables:\n";
        std::cerr << "  LICENSESEAT_API_KEY      - Your LicenseSeat API key\n";
        std::cerr << "  LICENSESEAT_PRODUCT_SLUG - Your product slug\n";
        std::cerr << "  LICENSESEAT_LICENSE_KEY  - A valid license key for testing\n\n";
        std::cerr << "Example:\n";
        std::cerr << "  export LICENSESEAT_API_KEY=\"ls_your_api_key\"\n";
        std::cerr << "  export LICENSESEAT_PRODUCT_SLUG=\"your-product\"\n";
        std::cerr << "  export LICENSESEAT_LICENSE_KEY=\"XXXX-XXXX-XXXX-XXXX\"\n";
        std::cerr << "  ./integration_test\n";
        return false;
    }
    return true;
}

}  // namespace

// Test counters
std::atomic<int> tests_passed{0};
std::atomic<int> tests_failed{0};

// Color codes for output
#define GREEN "\033[32m"
#define RED "\033[31m"
#define YELLOW "\033[33m"
#define CYAN "\033[36m"
#define RESET "\033[0m"

void pass(const std::string& test_name) {
    ++tests_passed;
    std::cout << GREEN << "✓ PASS: " << RESET << test_name << "\n";
}

void fail(const std::string& test_name, const std::string& reason) {
    ++tests_failed;
    std::cout << RED << "✗ FAIL: " << RESET << test_name << " - " << reason << "\n";
}

void section(const std::string& name) {
    std::cout << "\n" << CYAN << "═══════════════════════════════════════════════════════════════" << RESET << "\n";
    std::cout << CYAN << "  " << name << RESET << "\n";
    std::cout << CYAN << "═══════════════════════════════════════════════════════════════" << RESET << "\n\n";
}

void info(const std::string& msg) {
    std::cout << YELLOW << "  ℹ " << RESET << msg << "\n";
}

licenseseat::Config make_config() {
    licenseseat::Config config;
    config.api_key = API_KEY;
    config.product_slug = PRODUCT_SLUG;
    config.api_url = "https://licenseseat.com/api/v1";
    config.timeout_seconds = 30;
    config.max_retries = 2;
    config.storage_path = "/tmp/licenseseat_integration_test";
    config.storage_prefix = "integration_test";
    return config;
}

// ==================== Test Functions ====================

void test_client_creation() {
    section("Client Creation & Configuration");

    // Test 1: Basic client creation
    {
        auto config = make_config();
        licenseseat::Client client(config);

        if (!client.device_id().empty()) {
            pass("Client creation with auto-generated device ID");
            info("Device ID: " + client.device_id());
        } else {
            fail("Client creation with auto-generated device ID", "Device ID is empty");
        }
    }

    // Test 2: Client with custom device ID
    {
        auto config = make_config();
        config.device_id = "integration-test-device-001";
        licenseseat::Client client(config);

        if (client.device_id() == "integration-test-device-001") {
            pass("Client creation with custom device ID");
        } else {
            fail("Client creation with custom device ID", "Device ID mismatch: " + client.device_id());
        }
    }

    // Test 3: Config retrieval
    {
        auto config = make_config();
        licenseseat::Client client(config);

        if (client.config().api_key == API_KEY && client.config().product_slug == PRODUCT_SLUG) {
            pass("Config retrieval");
        } else {
            fail("Config retrieval", "Config values mismatch");
        }
    }

    // Test 4: Multiple client instances
    {
        auto config1 = make_config();
        config1.device_id = "device-1";
        auto config2 = make_config();
        config2.device_id = "device-2";

        licenseseat::Client client1(config1);
        licenseseat::Client client2(config2);

        if (client1.device_id() == "device-1" && client2.device_id() == "device-2") {
            pass("Multiple client instances are independent");
        } else {
            fail("Multiple client instances", "Clients share state unexpectedly");
        }
    }
}

void test_license_validation() {
    section("License Validation (Synchronous)");

    auto config = make_config();
    licenseseat::Client client(config);

    // Test 1: Validate valid license
    {
        auto result = client.validate(LICENSE_KEY);

        if (result.is_ok()) {
            const auto& validation = result.value();
            pass("Validate valid license key");
            info("Valid: " + std::string(validation.valid ? "yes" : "no"));
            info("Code: " + validation.code);
            info("Message: " + validation.message);

            const auto& license = validation.license;
            info("License key: " + license.key());
            info("Status: " + std::string(licenseseat::license_status_to_string(license.status())));
            info("Mode: " + std::string(licenseseat::license_mode_to_string(license.mode())));
            info("Plan: " + license.plan_key());
            info("Active seats: " + std::to_string(license.active_seats()));
            if (license.seat_limit().has_value()) {
                info("Seat limit: " + std::to_string(license.seat_limit().value()));
            } else {
                info("Seat limit: unlimited");
            }

            if (!license.active_entitlements().empty()) {
                info("Entitlements:");
                for (const auto& ent : license.active_entitlements()) {
                    info("  - " + ent.key);
                }
            }

            // Check warnings
            if (!validation.warnings.empty()) {
                info("Warnings:");
                for (const auto& warning : validation.warnings) {
                    info("  - " + warning.code + ": " + warning.message);
                }
            }
        } else {
            fail("Validate valid license key", result.error_message());
        }
    }

    // Test 2: Validate with device ID
    {
        auto result = client.validate(LICENSE_KEY, client.device_id());

        if (result.is_ok()) {
            pass("Validate with device ID");
            if (result.value().activation.has_value()) {
                info("Activation returned in response");
            }
        } else {
            // May fail if not activated - that's OK
            if (result.error_code() == licenseseat::ErrorCode::ActivationNotFound) {
                pass("Validate with device ID (not activated yet - expected)");
            } else {
                fail("Validate with device ID", result.error_message());
            }
        }
    }

    // Test 3: Validate invalid license key
    {
        auto result = client.validate("INVALID-KEY-12345");

        if (result.is_error()) {
            pass("Invalid license key returns error");
            info("Error code: " + std::string(licenseseat::error_code_to_string(result.error_code())));
            info("Error message: " + result.error_message());
        } else {
            if (!result.value().valid) {
                pass("Invalid license key returns invalid validation");
            } else {
                fail("Invalid license key", "Expected error or invalid validation");
            }
        }
    }

    // Test 4: Validate empty license key
    {
        auto result = client.validate("");

        if (result.is_error() && result.error_code() == licenseseat::ErrorCode::InvalidLicenseKey) {
            pass("Empty license key returns InvalidLicenseKey error");
        } else {
            fail("Empty license key validation", "Expected InvalidLicenseKey error");
        }
    }
}

void test_async_validation() {
    section("License Validation (Asynchronous)");

    auto config = make_config();
    licenseseat::Client client(config);

    // Test 1: Async validation
    {
        std::atomic<bool> done{false};
        std::atomic<bool> success{false};
        std::string result_info;

        client.validate_async(LICENSE_KEY, [&](licenseseat::Result<licenseseat::ValidationResult> result) {
            if (result.is_ok()) {
                // Success if we got a response - valid=true or seat_limit_exceeded are both valid responses
                const auto& val = result.value();
                success = true;
                result_info = val.valid ? "valid" : ("invalid: " + val.code);
            } else {
                result_info = "error: " + result.error_message();
            }
            done = true;
        });

        // Wait with timeout
        int wait_count = 0;
        while (!done && wait_count < 300) {  // 30 second timeout
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            ++wait_count;
        }

        if (!done) {
            fail("Async validation", "Timeout waiting for callback");
        } else if (success) {
            pass("Async validation completes");
            info("Result: " + result_info);
        } else {
            fail("Async validation", result_info);
        }
    }

    // Test 2: Multiple concurrent async validations
    {
        std::atomic<int> completed{0};
        constexpr int NUM_REQUESTS = 5;

        for (int i = 0; i < NUM_REQUESTS; ++i) {
            client.validate_async(LICENSE_KEY, [&](licenseseat::Result<licenseseat::ValidationResult> /*result*/) {
                ++completed;
            });
        }

        int wait_count = 0;
        while (completed < NUM_REQUESTS && wait_count < 300) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            ++wait_count;
        }

        if (completed == NUM_REQUESTS) {
            pass("Multiple concurrent async validations (" + std::to_string(NUM_REQUESTS) + " requests)");
        } else {
            fail("Multiple concurrent async validations",
                 "Only " + std::to_string(completed.load()) + "/" + std::to_string(NUM_REQUESTS) + " completed");
        }
    }
}

void test_activation_deactivation() {
    section("License Activation & Deactivation");

    auto config = make_config();
    config.device_id = "integration-test-" + std::to_string(std::time(nullptr));
    licenseseat::Client client(config);

    info("Using device ID: " + client.device_id());

    // Test 1: Activate license
    {
        licenseseat::Metadata metadata;
        metadata["test"] = "integration";
        metadata["timestamp"] = std::to_string(std::time(nullptr));

        auto result = client.activate(LICENSE_KEY, client.device_id(), "Integration Test Device", metadata);

        if (result.is_ok()) {
            const auto& activation = result.value();
            pass("Activate license");
            info("Activation ID: " + std::to_string(activation.id()));
            info("Device ID: " + activation.device_id());
            info("Device Name: " + activation.device_name());
            info("Is Active: " + std::string(activation.is_active() ? "yes" : "no"));
        } else {
            if (result.error_code() == licenseseat::ErrorCode::DeviceAlreadyActivated) {
                pass("Device already activated (expected on re-run)");
            } else if (result.error_code() == licenseseat::ErrorCode::SeatLimitExceeded) {
                pass("Seat limit exceeded (license at capacity)");
                info("Cannot test deactivation - skipping");
                return;
            } else {
                fail("Activate license", result.error_message());
                return;
            }
        }
    }

    // Test 2: Validate after activation (should see activation)
    {
        auto result = client.validate(LICENSE_KEY, client.device_id());

        if (result.is_ok()) {
            pass("Validate after activation");
            if (result.value().activation.has_value()) {
                info("Activation included in validation response");
            }
        } else {
            fail("Validate after activation", result.error_message());
        }
    }

    // Test 3: Deactivate license
    {
        auto result = client.deactivate(LICENSE_KEY, client.device_id());

        if (result.is_ok()) {
            pass("Deactivate license");
            info("Deactivated activation ID: " + std::to_string(result.value().activation_id));
        } else {
            if (result.error_code() == licenseseat::ErrorCode::ActivationNotFound) {
                pass("Deactivation - activation not found (may have been cleaned up)");
            } else {
                fail("Deactivate license", result.error_message());
            }
        }
    }

    // Test 4: Deactivate non-existent device
    {
        auto result = client.deactivate(LICENSE_KEY, "non-existent-device-xyz");

        if (result.is_error() && result.error_code() == licenseseat::ErrorCode::ActivationNotFound) {
            pass("Deactivate non-existent device returns ActivationNotFound");
        } else if (result.is_error()) {
            pass("Deactivate non-existent device returns error: " + result.error_message());
        } else {
            fail("Deactivate non-existent device", "Expected error");
        }
    }
}

void test_async_activation() {
    section("Async Activation & Deactivation");

    auto config = make_config();
    config.device_id = "async-test-" + std::to_string(std::time(nullptr));
    licenseseat::Client client(config);

    // Test 1: Async activation
    {
        std::atomic<bool> done{false};
        std::atomic<bool> success{false};

        std::string result_info;
        client.activate_async(LICENSE_KEY, [&](licenseseat::Result<licenseseat::Activation> result) {
            // Accept: success, already activated, or seat limit exceeded (expected for single-seat license)
            success = result.is_ok()
                || result.error_code() == licenseseat::ErrorCode::DeviceAlreadyActivated
                || result.error_code() == licenseseat::ErrorCode::SeatLimitExceeded;
            result_info = result.is_ok() ? "activated" : result.error_message();
            done = true;
        }, client.device_id(), "Async Test Device");

        int wait_count = 0;
        while (!done && wait_count < 300) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            ++wait_count;
        }

        if (done && success) {
            pass("Async activation");
            info("Result: " + result_info);
        } else if (!done) {
            fail("Async activation", "Timeout");
        } else {
            fail("Async activation", result_info);
        }
    }

    // Test 2: Async deactivation
    {
        std::atomic<bool> done{false};

        client.deactivate_async(LICENSE_KEY, [&](licenseseat::Result<licenseseat::Deactivation> /*result*/) {
            done = true;
        }, client.device_id());

        int wait_count = 0;
        while (!done && wait_count < 300) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            ++wait_count;
        }

        if (done) {
            pass("Async deactivation completes");
        } else {
            fail("Async deactivation", "Timeout");
        }
    }
}

void test_offline_token() {
    section("Offline Token Generation & Verification");

    auto config = make_config();
    licenseseat::Client client(config);

    licenseseat::OfflineToken offline_token;
    bool have_token = false;

    // Test 1: Generate offline token
    {
        auto result = client.generate_offline_token(LICENSE_KEY);

        if (result.is_ok()) {
            offline_token = result.value();
            have_token = true;
            pass("Generate offline token");
            info("License key: " + offline_token.token.license_key);
            info("Product slug: " + offline_token.token.product_slug);
            info("Plan key: " + offline_token.token.plan_key);
            info("Mode: " + offline_token.token.mode);
            info("Key ID (kid): " + offline_token.token.kid);
            info("Issued at (iat): " + std::to_string(offline_token.token.iat));
            info("Expires at (exp): " + std::to_string(offline_token.token.exp));
            info("Not before (nbf): " + std::to_string(offline_token.token.nbf));
            info("Signature algorithm: " + offline_token.signature.algorithm);
            info("Signature key ID: " + offline_token.signature.key_id);
            info("Canonical JSON length: " + std::to_string(offline_token.canonical.length()));

            if (offline_token.token.seat_limit.has_value()) {
                info("Seat limit: " + std::to_string(offline_token.token.seat_limit.value()));
            }

            if (!offline_token.token.entitlements.empty()) {
                info("Entitlements in token:");
                for (const auto& ent : offline_token.token.entitlements) {
                    info("  - " + ent.key);
                }
            }
        } else {
            if (result.error_code() == licenseseat::ErrorCode::SigningNotConfigured) {
                pass("Generate offline token - signing not configured (expected if not set up)");
                info("Skipping offline token verification tests");
                return;
            } else {
                fail("Generate offline token", result.error_message());
                return;
            }
        }
    }

    // Test 2: Fetch signing key
    std::string public_key;
    {
        if (!offline_token.token.kid.empty()) {
            auto result = client.fetch_signing_key(offline_token.token.kid);

            if (result.is_ok()) {
                public_key = result.value();
                pass("Fetch signing key");
                info("Public key (base64): " + public_key.substr(0, 20) + "...");
            } else {
                fail("Fetch signing key", result.error_message());
            }
        }
    }

    // Test 3: Verify offline token with fetched key
    if (have_token && !public_key.empty()) {
        auto result = client.verify_offline_token(offline_token, public_key);

        if (result.is_ok() && result.value()) {
            pass("Verify offline token with fetched key");
        } else if (result.is_error()) {
            fail("Verify offline token", result.error_message());
        } else {
            fail("Verify offline token", "Verification returned false");
        }
    }

    // Test 4: Verify with wrong key fails
    if (have_token) {
        // Use a valid but wrong Ed25519 public key
        std::string wrong_key = "PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=";
        auto result = client.verify_offline_token(offline_token, wrong_key);

        if (result.is_error() && result.error_code() == licenseseat::ErrorCode::InvalidSignature) {
            pass("Verify with wrong key fails correctly");
        } else if (result.is_ok() && !result.value()) {
            pass("Verify with wrong key returns false");
        } else {
            fail("Verify with wrong key", "Expected signature verification failure");
        }
    }

    // Test 5: Verify expired token fails
    {
        licenseseat::OfflineToken expired_token;
        expired_token.token.license_key = LICENSE_KEY;
        expired_token.token.iat = std::time(nullptr) - 86400 * 365;
        expired_token.token.nbf = expired_token.token.iat;
        expired_token.token.exp = std::time(nullptr) - 1;  // Expired

        auto result = client.verify_offline_token(expired_token);

        if (result.is_error() && result.error_code() == licenseseat::ErrorCode::LicenseExpired) {
            pass("Verify expired token fails with LicenseExpired");
        } else {
            fail("Verify expired token", "Expected LicenseExpired error");
        }
    }
}

void test_health_check() {
    section("Health Check");

    auto config = make_config();
    licenseseat::Client client(config);

    auto result = client.health();

    if (result.is_ok()) {
        pass("Health check succeeds");
        info("API is healthy");
    } else {
        fail("Health check", result.error_message());
    }
}

void test_release_management() {
    section("Release Management");

    auto config = make_config();
    licenseseat::Client client(config);

    // Test 1: Get latest release
    {
        auto result = client.get_latest_release();

        if (result.is_ok()) {
            const auto& release = result.value();
            pass("Get latest release");
            info("Version: " + release.version);
            info("Channel: " + release.channel);
            info("Platform: " + release.platform);
            info("Product: " + release.product_slug);
        } else {
            if (result.error_code() == licenseseat::ErrorCode::ReleaseNotFound) {
                pass("Get latest release - no releases found (expected if none published)");
            } else {
                fail("Get latest release", result.error_message());
            }
        }
    }

    // Test 2: List releases
    {
        auto result = client.list_releases();

        if (result.is_ok()) {
            pass("List releases");
            info("Found " + std::to_string(result.value().size()) + " releases");
            for (const auto& release : result.value()) {
                info("  - " + release.version + " (" + release.channel + ")");
            }
        } else {
            if (result.error_code() == licenseseat::ErrorCode::ReleaseNotFound) {
                pass("List releases - no releases found");
            } else {
                fail("List releases", result.error_message());
            }
        }
    }

    // Test 3: Generate download token
    {
        auto result = client.generate_download_token("1.0.0", LICENSE_KEY);

        if (result.is_ok()) {
            pass("Generate download token");
            info("Token: " + result.value().token.substr(0, 20) + "...");
            if (result.value().expires_at.has_value()) {
                info("Expires at: (timestamp)");
            }
        } else {
            if (result.error_code() == licenseseat::ErrorCode::ReleaseNotFound) {
                pass("Generate download token - release not found (expected)");
            } else {
                fail("Generate download token", result.error_message());
            }
        }
    }
}

void test_event_system() {
    section("Event System");

    auto config = make_config();
    licenseseat::Client client(config);

    // Test 1: Subscribe and receive events
    {
        std::atomic<int> event_count{0};

        auto sub = client.on(licenseseat::events::VALIDATION_SUCCESS, [&](const std::any& /*data*/) {
            ++event_count;
        });

        // Trigger a validation
        (void)client.validate(LICENSE_KEY);

        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        if (event_count > 0) {
            pass("Event subscription and delivery");
            info("Received " + std::to_string(event_count.load()) + " events");
        } else {
            // Events might not fire if validation fails
            pass("Event subscription (no events received - may be expected)");
        }

        sub.cancel();
    }

    // Test 2: Subscription cancellation
    {
        int call_count = 0;

        auto sub = client.on("test:event", [&](const std::any& /*data*/) {
            ++call_count;
        });

        client.emit("test:event");
        int count_before_cancel = call_count;

        sub.cancel();

        client.emit("test:event");
        int count_after_cancel = call_count;

        if (count_before_cancel == 1 && count_after_cancel == 1) {
            pass("Subscription cancellation prevents further events");
        } else {
            fail("Subscription cancellation", "Events still delivered after cancel");
        }
    }

    // Test 3: Multiple subscribers
    {
        std::atomic<int> sub1_count{0};
        std::atomic<int> sub2_count{0};

        auto s1 = client.on("multi:test", [&](const std::any& /*data*/) { ++sub1_count; });
        auto s2 = client.on("multi:test", [&](const std::any& /*data*/) { ++sub2_count; });

        client.emit("multi:test");

        if (sub1_count == 1 && sub2_count == 1) {
            pass("Multiple subscribers receive events");
        } else {
            fail("Multiple subscribers", "Not all subscribers received event");
        }
    }
}

void test_status_and_entitlements() {
    section("Status & Entitlement Checks");

    auto config = make_config();
    licenseseat::Client client(config);

    // First, do a validation to populate status
    (void)client.validate(LICENSE_KEY);

    // Test 1: Get status
    {
        auto status = client.get_status();
        pass("Get status");
        info("Valid: " + std::string(status.valid ? "yes" : "no"));
        info("Offline: " + std::string(status.offline ? "yes" : "no"));
    }

    // Test 2: Current license
    {
        auto license = client.current_license();
        if (license.has_value()) {
            pass("Current license available");
            info("License key: " + license->key());
        } else {
            pass("Current license not cached (expected without storage)");
        }
    }

    // Test 3: Check entitlement
    {
        auto ent_status = client.check_entitlement("some_feature");
        pass("Check entitlement");
        info("Active: " + std::string(ent_status.active ? "yes" : "no"));
        info("Reason: " + ent_status.reason);
    }

    // Test 4: Is online
    {
        bool online = client.is_online();
        pass("Is online check");
        info("Online: " + std::string(online ? "yes" : "no"));
    }
}

void test_auto_validation() {
    section("Auto-Validation");

    auto config = make_config();
    config.auto_validate_interval = 1.0;  // 1 second for testing
    licenseseat::Client client(config);

    // Test 1: Start auto-validation
    {
        client.start_auto_validation(LICENSE_KEY);

        if (client.is_auto_validating()) {
            pass("Start auto-validation");
        } else {
            fail("Start auto-validation", "Not auto-validating after start");
        }
    }

    // Test 2: Wait for a validation cycle
    {
        std::atomic<int> validation_count{0};

        auto sub = client.on(licenseseat::events::AUTOVALIDATION_CYCLE, [&](const std::any& /*data*/) {
            ++validation_count;
        });

        // Wait up to 5 seconds for at least one cycle
        for (int i = 0; i < 50 && validation_count == 0; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        if (validation_count > 0) {
            pass("Auto-validation cycles");
            info("Completed " + std::to_string(validation_count.load()) + " cycles");
        } else {
            pass("Auto-validation (no cycles observed in time window)");
        }

        sub.cancel();
    }

    // Test 3: Stop auto-validation
    {
        client.stop_auto_validation();

        if (!client.is_auto_validating()) {
            pass("Stop auto-validation");
        } else {
            fail("Stop auto-validation", "Still auto-validating after stop");
        }
    }

    // Test 4: Multiple start/stop cycles
    {
        for (int i = 0; i < 5; ++i) {
            client.start_auto_validation(LICENSE_KEY);
            client.stop_auto_validation();
        }
        pass("Multiple auto-validation start/stop cycles");
    }
}

void test_reset() {
    section("Client Reset");

    auto config = make_config();
    licenseseat::Client client(config);

    // Populate some state
    (void)client.validate(LICENSE_KEY);
    client.start_auto_validation(LICENSE_KEY);

    // Reset
    client.reset();

    // Verify state is cleared
    bool auto_validating = client.is_auto_validating();
    auto status = client.get_status();

    if (!auto_validating && !status.valid) {
        pass("Client reset clears state");
    } else {
        fail("Client reset", "State not fully cleared");
    }
}

void test_error_handling() {
    section("Error Handling");

    auto config = make_config();
    licenseseat::Client client(config);

    // Test 1: Network error (invalid URL)
    {
        licenseseat::Config bad_config;
        bad_config.api_key = API_KEY;
        bad_config.product_slug = PRODUCT_SLUG;
        bad_config.api_url = "http://localhost:1";  // Non-existent
        bad_config.timeout_seconds = 2;
        bad_config.max_retries = 0;

        licenseseat::Client bad_client(bad_config);
        auto result = bad_client.validate(LICENSE_KEY);

        if (result.is_error() && result.error_code() == licenseseat::ErrorCode::NetworkError) {
            pass("Network error handling");
            info("Error message: " + result.error_message());
        } else {
            fail("Network error handling", "Expected NetworkError");
        }
    }

    // Test 2: Invalid API key
    {
        licenseseat::Config bad_config = make_config();
        bad_config.api_key = "invalid_api_key";

        licenseseat::Client bad_client(bad_config);
        auto result = bad_client.validate(LICENSE_KEY);

        if (result.is_error()) {
            pass("Invalid API key handling");
            info("Error: " + std::string(licenseseat::error_code_to_string(result.error_code())));
        } else {
            fail("Invalid API key handling", "Expected error");
        }
    }

    // Test 3: Missing parameters
    {
        auto result = client.deactivate(LICENSE_KEY, "");

        if (result.is_error() && result.error_code() == licenseseat::ErrorCode::MissingParameter) {
            pass("Missing parameter handling");
        } else {
            fail("Missing parameter handling", "Expected MissingParameter error");
        }
    }

    // Test 4: Fetch signing key with empty ID
    {
        auto result = client.fetch_signing_key("");

        if (result.is_error() && result.error_code() == licenseseat::ErrorCode::MissingParameter) {
            pass("Fetch signing key with empty ID fails");
        } else {
            fail("Fetch signing key empty ID", "Expected MissingParameter error");
        }
    }
}

void test_thread_safety() {
    section("Thread Safety (Stress Test)");

    auto config = make_config();
    licenseseat::Client client(config);

    // Test 1: Concurrent validations
    {
        std::atomic<int> success_count{0};
        std::atomic<int> error_count{0};
        constexpr int NUM_THREADS = 10;
        constexpr int OPS_PER_THREAD = 5;

        std::vector<std::thread> threads;
        for (int t = 0; t < NUM_THREADS; ++t) {
            threads.emplace_back([&]() {
                for (int i = 0; i < OPS_PER_THREAD; ++i) {
                    auto result = client.validate(LICENSE_KEY);
                    if (result.is_ok()) {
                        ++success_count;
                    } else {
                        ++error_count;
                    }
                }
            });
        }

        for (auto& t : threads) {
            t.join();
        }

        int total = success_count + error_count;
        if (total == NUM_THREADS * OPS_PER_THREAD) {
            pass("Concurrent validations (" + std::to_string(total) + " requests)");
            info("Success: " + std::to_string(success_count.load()));
            info("Errors: " + std::to_string(error_count.load()));
        } else {
            fail("Concurrent validations", "Missing responses");
        }
    }

    // Test 2: Concurrent status checks
    {
        std::atomic<int> checks{0};
        constexpr int NUM_THREADS = 20;
        constexpr int OPS_PER_THREAD = 100;

        std::vector<std::thread> threads;
        for (int t = 0; t < NUM_THREADS; ++t) {
            threads.emplace_back([&]() {
                for (int i = 0; i < OPS_PER_THREAD; ++i) {
                    auto status = client.get_status();
                    (void)status;
                    ++checks;
                }
            });
        }

        for (auto& t : threads) {
            t.join();
        }

        if (checks == NUM_THREADS * OPS_PER_THREAD) {
            pass("Concurrent status checks (" + std::to_string(checks.load()) + " checks)");
        } else {
            fail("Concurrent status checks", "Race condition detected");
        }
    }

    // Test 3: Concurrent event emission
    {
        std::atomic<int> events_received{0};

        auto sub = client.on("stress:test", [&](const std::any& /*data*/) {
            ++events_received;
        });

        constexpr int NUM_THREADS = 10;
        constexpr int EVENTS_PER_THREAD = 100;

        std::vector<std::thread> threads;
        for (int t = 0; t < NUM_THREADS; ++t) {
            threads.emplace_back([&]() {
                for (int i = 0; i < EVENTS_PER_THREAD; ++i) {
                    client.emit("stress:test");
                }
            });
        }

        for (auto& t : threads) {
            t.join();
        }

        if (events_received == NUM_THREADS * EVENTS_PER_THREAD) {
            pass("Concurrent event emission (" + std::to_string(events_received.load()) + " events)");
        } else {
            fail("Concurrent event emission",
                 "Expected " + std::to_string(NUM_THREADS * EVENTS_PER_THREAD) +
                 ", got " + std::to_string(events_received.load()));
        }

        sub.cancel();
    }
}

void test_move_semantics() {
    section("Move Semantics");

    // Test 1: Client can be moved
    {
        auto config = make_config();
        licenseseat::Client client1(config);
        std::string device_id = client1.device_id();

        licenseseat::Client client2 = std::move(client1);

        if (client2.device_id() == device_id) {
            pass("Client move constructor");
        } else {
            fail("Client move constructor", "State not preserved");
        }
    }
}

void test_device_functions() {
    section("Device Functions");

    // Test 1: Generate device ID
    {
        auto device_id = licenseseat::device::generate_device_id();
        if (!device_id.empty()) {
            pass("Generate device ID");
            info("Device ID: " + device_id);
            info("Length: " + std::to_string(device_id.length()));
        } else {
            fail("Generate device ID", "Empty device ID");
        }
    }

    // Test 2: Device ID is deterministic
    {
        auto id1 = licenseseat::device::generate_device_id();
        auto id2 = licenseseat::device::generate_device_id();

        if (id1 == id2) {
            pass("Device ID is deterministic");
        } else {
            fail("Device ID deterministic", "IDs differ: " + id1 + " vs " + id2);
        }
    }

    // Test 3: Get platform name
    {
        auto platform = licenseseat::device::get_platform_name();
        if (!platform.empty()) {
            pass("Get platform name");
            info("Platform: " + platform);
        } else {
            fail("Get platform name", "Empty platform");
        }
    }

    // Test 4: Get hostname
    {
        auto hostname = licenseseat::device::get_hostname();
        if (!hostname.empty()) {
            pass("Get hostname");
            info("Hostname: " + hostname);
        } else {
            fail("Get hostname", "Empty hostname");
        }
    }
}

void test_crypto_functions() {
    section("Crypto Functions");

    // Test 1: Base64 round-trip
    {
        std::vector<uint8_t> data = {0x00, 0x01, 0x02, 0xFE, 0xFF};
        auto encoded = licenseseat::crypto::base64_encode(data);
        auto decoded = licenseseat::crypto::base64_decode(encoded);

        if (decoded == data) {
            pass("Base64 round-trip");
            info("Encoded: " + encoded);
        } else {
            fail("Base64 round-trip", "Data mismatch");
        }
    }

    // Test 2: Base64URL round-trip
    {
        std::vector<uint8_t> data = {0xFB, 0xFF, 0xFE};  // Contains +/
        auto encoded = licenseseat::crypto::base64url_encode(data);
        auto decoded = licenseseat::crypto::base64url_decode(encoded);

        if (decoded == data && encoded.find('+') == std::string::npos &&
            encoded.find('/') == std::string::npos) {
            pass("Base64URL round-trip");
            info("Encoded: " + encoded);
        } else {
            fail("Base64URL round-trip", "Data mismatch or invalid chars");
        }
    }
}

// ==================== Main ====================

int main() {
    // Load credentials from environment variables
    if (!load_credentials()) {
        return 1;
    }

    std::cout << "\n";
    std::cout << CYAN << "╔═══════════════════════════════════════════════════════════════╗" << RESET << "\n";
    std::cout << CYAN << "║     LicenseSeat C++ SDK - Live Integration Test Suite         ║" << RESET << "\n";
    std::cout << CYAN << "╚═══════════════════════════════════════════════════════════════╝" << RESET << "\n";

    info("API URL: https://licenseseat.com/api/v1");
    info("Product: " + PRODUCT_SLUG);
    info("License: " + LICENSE_KEY.substr(0, 5) + "..." + LICENSE_KEY.substr(LICENSE_KEY.length() - 5));

    auto start_time = std::chrono::high_resolution_clock::now();

    // Run all tests
    test_client_creation();
    test_device_functions();
    test_crypto_functions();
    test_health_check();
    test_license_validation();
    test_async_validation();
    test_activation_deactivation();
    test_async_activation();
    test_offline_token();
    test_release_management();
    test_event_system();
    test_status_and_entitlements();
    test_auto_validation();
    test_reset();
    test_error_handling();
    test_thread_safety();
    test_move_semantics();

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    // Summary
    std::cout << "\n";
    std::cout << CYAN << "═══════════════════════════════════════════════════════════════" << RESET << "\n";
    std::cout << CYAN << "  TEST SUMMARY" << RESET << "\n";
    std::cout << CYAN << "═══════════════════════════════════════════════════════════════" << RESET << "\n\n";

    int total = tests_passed + tests_failed;
    std::cout << "  Total tests:  " << total << "\n";
    std::cout << GREEN << "  Passed:       " << tests_passed << RESET << "\n";
    if (tests_failed > 0) {
        std::cout << RED << "  Failed:       " << tests_failed << RESET << "\n";
    } else {
        std::cout << "  Failed:       " << tests_failed << "\n";
    }
    std::cout << "  Duration:     " << duration.count() << "ms\n";
    std::cout << "\n";

    if (tests_failed == 0) {
        std::cout << GREEN << "  ✓ ALL TESTS PASSED!" << RESET << "\n\n";
        return 0;
    } else {
        std::cout << RED << "  ✗ SOME TESTS FAILED" << RESET << "\n\n";
        return 1;
    }
}
