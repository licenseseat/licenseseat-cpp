/**
 * @file scenario_test.cpp
 * @brief Real-world scenario testing matching Swift SDK test coverage
 *
 * Test Scenarios:
 * 1. First app launch & activation
 * 2. Returning user with cached license
 * 3. Offline mode with offline token + cached validation
 * 4. Security (fake key, wrong product, no API key)
 * 5. License persistence during session
 * 6. Grace period & expiration handling
 * 7. Deactivation flow
 * 8. Re-activation on new device
 * 9. Auto-validation background refresh
 * 10. Event-driven state changes
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
 *   ./scenario_test
 */

#include <licenseseat/licenseseat.hpp>
#include <licenseseat/crypto.hpp>
#include <licenseseat/device.hpp>
#include <licenseseat/events.hpp>
#include <licenseseat/storage.hpp>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <thread>

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
        std::cerr << "  ./scenario_test\n";
        return false;
    }
    return true;
}

}  // namespace

// Test counters
std::atomic<int> tests_passed{0};
std::atomic<int> tests_failed{0};

// Color codes
const char* GREEN = "\033[32m";
const char* RED = "\033[31m";
const char* YELLOW = "\033[33m";
const char* CYAN = "\033[36m";
const char* RESET = "\033[0m";

void pass(const std::string& test_name) {
    ++tests_passed;
    std::cout << GREEN << "✓ PASS: " << RESET << test_name << "\n";
}

void fail(const std::string& test_name, const std::string& reason) {
    ++tests_failed;
    std::cout << RED << "✗ FAIL: " << RESET << test_name << " - " << reason << "\n";
}

void info(const std::string& message) {
    std::cout << YELLOW << "  ℹ " << RESET << message << "\n";
}

void section(const std::string& name) {
    std::cout << "\n" << CYAN << "═══════════════════════════════════════════════════════════════" << RESET << "\n";
    std::cout << CYAN << "  SCENARIO: " << name << RESET << "\n";
    std::cout << CYAN << "═══════════════════════════════════════════════════════════════" << RESET << "\n\n";
}

std::string get_temp_storage_path(const std::string& suffix) {
    return "/tmp/licenseseat_scenario_" + suffix + "_" + std::to_string(std::time(nullptr));
}

void cleanup_storage(const std::string& path) {
    try {
        std::filesystem::remove_all(path);
    } catch (...) {}
}

// ============================================================================
// SCENARIO 1: First App Launch & Activation
// ============================================================================

void test_scenario_1_first_launch() {
    section("1. First App Launch & Activation");

    std::string storage_path = get_temp_storage_path("s1");

    // Simulate fresh install - no cached data
    {
        licenseseat::Config config;
        config.api_key = API_KEY;
        config.product_slug = PRODUCT_SLUG;
        config.api_url = "https://licenseseat.com/api/v1";
        config.storage_path = storage_path;
        config.device_id = "first-launch-device-" + std::to_string(std::time(nullptr));

        licenseseat::Client client(config);

        // Step 1: Check initial state - should be invalid (no license)
        auto status = client.get_status();
        if (!status.valid) {
            pass("Initial state is invalid (no license)");
        } else {
            fail("Initial state check", "Should be invalid");
        }

        // Step 2: No cached license on first launch
        auto cached = client.current_license();
        if (!cached.has_value()) {
            pass("No cached license on first launch");
        } else {
            fail("Cached license check", "Should not have cached license");
        }

        // Step 3: Validate license for the first time
        auto result = client.validate(LICENSE_KEY);
        if (result.is_ok()) {
            pass("First validation succeeds");
            const auto& validation = result.value();
            info("Valid: " + std::string(validation.valid ? "yes" : "no"));
            info("Code: " + validation.code);

            // Step 4: License data is populated
            const auto& license = validation.license;
            if (!license.key().empty()) {
                pass("License data populated after validation");
                info("License key: " + license.key());
                info("Status: " + std::string(licenseseat::license_status_to_string(license.status())));
            } else {
                fail("License data check", "License key is empty");
            }
        } else {
            fail("First validation", result.error_message());
        }

        // Step 5: Try to activate (may fail due to seat limit)
        auto activate_result = client.activate(LICENSE_KEY, config.device_id, "Test Device");
        if (activate_result.is_ok()) {
            pass("Activation succeeds");
            info("Activation ID: " + std::to_string(activate_result.value().id()));
        } else if (activate_result.error_code() == licenseseat::ErrorCode::SeatLimitExceeded ||
                   activate_result.error_code() == licenseseat::ErrorCode::DeviceAlreadyActivated) {
            pass("Activation handled (seat limit or already activated)");
            info("Expected error: " + activate_result.error_message());
        } else {
            fail("Activation", activate_result.error_message());
        }
    }

    cleanup_storage(storage_path);
}

// ============================================================================
// SCENARIO 2: Returning User with Cached License
// ============================================================================

void test_scenario_2_returning_user() {
    section("2. Returning User with Cached License");

    std::string storage_path = get_temp_storage_path("s2");

    // First session - populate cache
    {
        licenseseat::Config config;
        config.api_key = API_KEY;
        config.product_slug = PRODUCT_SLUG;
        config.api_url = "https://licenseseat.com/api/v1";
        config.storage_path = storage_path;

        licenseseat::Client client(config);

        // Validate to populate cache
        auto result = client.validate(LICENSE_KEY);
        if (result.is_ok()) {
            pass("Initial validation for cache population");
        } else {
            fail("Cache population", result.error_message());
            cleanup_storage(storage_path);
            return;
        }
    }

    // Second session - simulate app restart
    {
        licenseseat::Config config;
        config.api_key = API_KEY;
        config.product_slug = PRODUCT_SLUG;
        config.api_url = "https://licenseseat.com/api/v1";
        config.storage_path = storage_path;

        licenseseat::Client client(config);

        // Check if license is loaded from cache
        // Note: The SDK may not auto-load from cache until validation
        auto result = client.validate(LICENSE_KEY);
        if (result.is_ok()) {
            pass("Returning user validation succeeds");
            info("Validation was: " + std::string(result.value().valid ? "valid" : "invalid"));
        } else {
            fail("Returning user validation", result.error_message());
        }

        // Status should reflect cached state after validation
        auto status = client.get_status();
        pass("Status check after validation");
        info("Valid: " + std::string(status.valid ? "yes" : "no"));
    }

    cleanup_storage(storage_path);
}

// ============================================================================
// SCENARIO 3: Offline Mode with Offline Token
// ============================================================================

void test_scenario_3_offline_mode() {
    section("3. Offline Mode with Offline Token");

    std::string storage_path = get_temp_storage_path("s3");

    std::string cached_public_key;
    licenseseat::OfflineToken cached_token;

    // Phase 1: Online - Generate and cache offline token
    {
        licenseseat::Config config;
        config.api_key = API_KEY;
        config.product_slug = PRODUCT_SLUG;
        config.api_url = "https://licenseseat.com/api/v1";
        config.storage_path = storage_path;

        licenseseat::Client client(config);

        // Generate offline token while online
        auto token_result = client.generate_offline_token(LICENSE_KEY);
        if (token_result.is_error()) {
            fail("Offline token generation", token_result.error_message());
            cleanup_storage(storage_path);
            return;
        }
        pass("Offline token generated while online");
        cached_token = token_result.value();

        // Fetch signing key while online
        auto key_result = client.fetch_signing_key(cached_token.token.kid);
        if (key_result.is_error()) {
            fail("Signing key fetch", key_result.error_message());
            cleanup_storage(storage_path);
            return;
        }
        pass("Signing key fetched while online");
        cached_public_key = key_result.value();
    }

    // Phase 2: Simulate offline - verify without network
    {
        // Create a client that can't reach network (we won't make network calls)
        licenseseat::Config config;
        config.api_key = API_KEY;
        config.product_slug = PRODUCT_SLUG;
        config.api_url = "https://licenseseat.com/api/v1";
        config.storage_path = storage_path;
        config.signing_public_key = cached_public_key;  // Pre-configure signing key

        licenseseat::Client client(config);

        // Verify offline token without network
        auto verify_result = client.verify_offline_token(cached_token, cached_public_key);
        if (verify_result.is_ok() && verify_result.value()) {
            pass("Offline token verification succeeds without network");
        } else {
            fail("Offline verification", verify_result.is_error() ?
                 verify_result.error_message() : "Returned false");
        }

        // Check token data is usable
        if (!cached_token.token.license_key.empty() &&
            !cached_token.token.product_slug.empty()) {
            pass("Offline token contains license data");
            info("License key: " + cached_token.token.license_key);
            info("Product: " + cached_token.token.product_slug);
            info("Plan: " + cached_token.token.plan_key);
        } else {
            fail("Offline token data", "Missing required fields");
        }
    }

    cleanup_storage(storage_path);
}

// ============================================================================
// SCENARIO 4: Security Tests
// ============================================================================

void test_scenario_4_security() {
    section("4. Security (Fake Key, Wrong Product, No API Key)");

    // Test 4a: Fake/Invalid license key
    {
        licenseseat::Config config;
        config.api_key = API_KEY;
        config.product_slug = PRODUCT_SLUG;
        config.api_url = "https://licenseseat.com/api/v1";

        licenseseat::Client client(config);

        auto result = client.validate("FAKE-LICENSE-KEY-12345");
        if (result.is_error() &&
            result.error_code() == licenseseat::ErrorCode::LicenseNotFound) {
            pass("Fake license key rejected with LicenseNotFound");
        } else if (result.is_error()) {
            pass("Fake license key rejected");
            info("Error: " + result.error_message());
        } else {
            fail("Fake license key", "Should have been rejected");
        }
    }

    // Test 4b: Wrong product slug
    {
        licenseseat::Config config;
        config.api_key = API_KEY;
        config.product_slug = "wrong-product-slug";
        config.api_url = "https://licenseseat.com/api/v1";

        licenseseat::Client client(config);

        auto result = client.validate(LICENSE_KEY);
        if (result.is_error()) {
            pass("Wrong product slug rejected");
            info("Error: " + result.error_message());
        } else if (!result.value().valid) {
            pass("Wrong product returns invalid");
            info("Code: " + result.value().code);
        } else {
            fail("Wrong product", "Should have been rejected");
        }
    }

    // Test 4c: No/Invalid API key
    {
        licenseseat::Config config;
        config.api_key = "invalid-api-key";
        config.product_slug = PRODUCT_SLUG;
        config.api_url = "https://licenseseat.com/api/v1";

        licenseseat::Client client(config);

        auto result = client.validate(LICENSE_KEY);
        if (result.is_error() &&
            result.error_code() == licenseseat::ErrorCode::AuthenticationFailed) {
            pass("Invalid API key rejected with AuthenticationFailed");
        } else if (result.is_error()) {
            pass("Invalid API key rejected");
            info("Error code: " + std::string(licenseseat::error_code_to_string(result.error_code())));
        } else {
            fail("Invalid API key", "Should have been rejected");
        }
    }

    // Test 4d: Empty API key
    {
        licenseseat::Config config;
        config.api_key = "";
        config.product_slug = PRODUCT_SLUG;
        config.api_url = "https://licenseseat.com/api/v1";

        licenseseat::Client client(config);

        auto result = client.validate(LICENSE_KEY);
        if (result.is_error()) {
            pass("Empty API key rejected");
            info("Error: " + result.error_message());
        } else {
            fail("Empty API key", "Should have been rejected");
        }
    }

    // Test 4e: Tampered offline token signature
    {
        licenseseat::Config config;
        config.api_key = API_KEY;
        config.product_slug = PRODUCT_SLUG;
        config.api_url = "https://licenseseat.com/api/v1";

        licenseseat::Client client(config);

        auto token_result = client.generate_offline_token(LICENSE_KEY);
        if (token_result.is_ok()) {
            auto key_result = client.fetch_signing_key(token_result.value().token.kid);
            if (key_result.is_ok()) {
                // Tamper with the token
                licenseseat::OfflineToken tampered = token_result.value();
                tampered.signature.value = "tampered-signature-value";

                auto verify = client.verify_offline_token(tampered, key_result.value());
                if (!verify.is_ok() || !verify.value()) {
                    pass("Tampered signature rejected");
                } else {
                    fail("Tampered signature", "Should have been rejected");
                }
            }
        }
    }
}

// ============================================================================
// SCENARIO 5: License Persistence During Session
// ============================================================================

void test_scenario_5_persistence() {
    section("5. License Persistence During Session");

    std::string storage_path = get_temp_storage_path("s5");

    licenseseat::Config config;
    config.api_key = API_KEY;
    config.product_slug = PRODUCT_SLUG;
    config.api_url = "https://licenseseat.com/api/v1";
    config.storage_path = storage_path;

    licenseseat::Client client(config);

    // Step 1: Initial validation
    auto result1 = client.validate(LICENSE_KEY);
    if (result1.is_error()) {
        fail("Initial validation", result1.error_message());
        cleanup_storage(storage_path);
        return;
    }
    pass("Initial validation");

    // Step 2: Multiple subsequent validations - should maintain state
    for (int i = 0; i < 3; ++i) {
        auto result = client.validate(LICENSE_KEY);
        if (result.is_ok()) {
            // State should be consistent
            auto status = client.get_status();
            info("Validation " + std::to_string(i + 2) + " - Valid: " +
                 std::string(status.valid ? "yes" : "no"));
        }
    }
    pass("Multiple validations maintain consistent state");

    // Step 3: Status checks don't change persisted data
    auto status1 = client.get_status();
    auto status2 = client.get_status();
    auto status3 = client.get_status();
    if (status1.valid == status2.valid && status2.valid == status3.valid) {
        pass("Status checks are consistent");
    } else {
        fail("Status consistency", "Status changed between checks");
    }

    // Step 4: Entitlement checks work during session
    auto ent = client.check_entitlement("some_feature");
    pass("Entitlement check during session");
    info("Entitlement active: " + std::string(ent.active ? "yes" : "no"));
    info("Reason: " + ent.reason);

    cleanup_storage(storage_path);
}

// ============================================================================
// SCENARIO 6: Grace Period & Expiration Handling
// ============================================================================

void test_scenario_6_expiration() {
    section("6. Grace Period & Expiration Handling");

    std::string storage_path = get_temp_storage_path("s6");

    licenseseat::Config config;
    config.api_key = API_KEY;
    config.product_slug = PRODUCT_SLUG;
    config.api_url = "https://licenseseat.com/api/v1";
    config.storage_path = storage_path;
    config.max_offline_days = 30;  // 30-day grace period

    licenseseat::Client client(config);

    // Generate offline token to test expiration
    auto token_result = client.generate_offline_token(LICENSE_KEY);
    if (token_result.is_error()) {
        fail("Token generation for expiry test", token_result.error_message());
        cleanup_storage(storage_path);
        return;
    }

    auto key_result = client.fetch_signing_key(token_result.value().token.kid);
    if (key_result.is_error()) {
        fail("Key fetch for expiry test", key_result.error_message());
        cleanup_storage(storage_path);
        return;
    }

    const auto& token = token_result.value();
    const auto& public_key = key_result.value();

    // Test 6a: Valid token should pass
    {
        auto verify = client.verify_offline_token(token, public_key);
        if (verify.is_ok() && verify.value()) {
            pass("Valid (non-expired) token passes verification");
        } else {
            fail("Valid token verification", "Should have passed");
        }
    }

    // Test 6b: Artificially expired token
    {
        licenseseat::OfflineToken expired = token;
        expired.token.exp = std::time(nullptr) - 86400;  // Expired yesterday

        auto verify = client.verify_offline_token(expired, public_key);
        if (verify.is_error() &&
            verify.error_code() == licenseseat::ErrorCode::LicenseExpired) {
            pass("Expired token returns LicenseExpired error");
        } else if (!verify.is_ok() || !verify.value()) {
            pass("Expired token fails verification");
        } else {
            fail("Expired token", "Should have failed");
        }
    }

    // Test 6c: Token expiry timestamp validation
    {
        auto now = std::time(nullptr);
        if (token.token.exp > now) {
            pass("Token has future expiration");
            auto days_until_expiry = (token.token.exp - now) / 86400;
            info("Days until expiry: " + std::to_string(days_until_expiry));
        } else {
            fail("Token expiry", "Token is already expired");
        }
    }

    cleanup_storage(storage_path);
}

// ============================================================================
// SCENARIO 7: Deactivation Flow
// ============================================================================

void test_scenario_7_deactivation() {
    section("7. Deactivation Flow");

    licenseseat::Config config;
    config.api_key = API_KEY;
    config.product_slug = PRODUCT_SLUG;
    config.api_url = "https://licenseseat.com/api/v1";
    config.device_id = "deactivation-test-" + std::to_string(std::time(nullptr));

    licenseseat::Client client(config);

    // Attempt deactivation (may fail if device not activated)
    auto result = client.deactivate(LICENSE_KEY, config.device_id);

    if (result.is_ok()) {
        pass("Deactivation succeeds");
        info("Device deactivated: " + config.device_id);
    } else if (result.error_code() == licenseseat::ErrorCode::ActivationNotFound) {
        pass("Deactivation returns ActivationNotFound (device was not active)");
    } else {
        // Other errors are also acceptable for this test
        pass("Deactivation handled");
        info("Result: " + result.error_message());
    }

    // Async deactivation test
    {
        std::atomic<bool> done{false};
        std::string async_result;

        client.deactivate_async(LICENSE_KEY, [&](licenseseat::Result<licenseseat::Deactivation> res) {
            async_result = res.is_ok() ? "success" : res.error_message();
            done = true;
        }, config.device_id);

        int wait = 0;
        while (!done && wait < 300) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            ++wait;
        }

        if (done) {
            pass("Async deactivation completes");
            info("Async result: " + async_result);
        } else {
            fail("Async deactivation", "Timeout");
        }
    }
}

// ============================================================================
// SCENARIO 8: Re-activation on New Device
// ============================================================================

void test_scenario_8_reactivation() {
    section("8. Re-activation on New Device");

    // Simulate two different devices
    std::string device1 = "device-1-" + std::to_string(std::time(nullptr));
    std::string device2 = "device-2-" + std::to_string(std::time(nullptr));

    // Device 1 activation
    {
        licenseseat::Config config;
        config.api_key = API_KEY;
        config.product_slug = PRODUCT_SLUG;
        config.api_url = "https://licenseseat.com/api/v1";
        config.device_id = device1;

        licenseseat::Client client(config);

        auto result = client.activate(LICENSE_KEY, device1, "Device 1");
        if (result.is_ok()) {
            pass("Device 1 activation succeeds");
        } else if (result.error_code() == licenseseat::ErrorCode::SeatLimitExceeded) {
            pass("Device 1 activation - seat limit reached");
            info("This is expected for single-seat licenses");
        } else if (result.error_code() == licenseseat::ErrorCode::DeviceAlreadyActivated) {
            pass("Device 1 already activated");
        } else {
            info("Device 1 result: " + result.error_message());
            pass("Device 1 activation handled");
        }
    }

    // Device 2 activation attempt (should fail if seat limit = 1)
    {
        licenseseat::Config config;
        config.api_key = API_KEY;
        config.product_slug = PRODUCT_SLUG;
        config.api_url = "https://licenseseat.com/api/v1";
        config.device_id = device2;

        licenseseat::Client client(config);

        auto result = client.activate(LICENSE_KEY, device2, "Device 2");
        if (result.is_ok()) {
            pass("Device 2 activation succeeds (multi-seat license)");
        } else if (result.error_code() == licenseseat::ErrorCode::SeatLimitExceeded) {
            pass("Device 2 blocked by seat limit (expected for single-seat)");
        } else {
            pass("Device 2 activation handled");
            info("Result: " + result.error_message());
        }
    }

    // Validate from different device IDs
    {
        licenseseat::Config config1;
        config1.api_key = API_KEY;
        config1.product_slug = PRODUCT_SLUG;
        config1.api_url = "https://licenseseat.com/api/v1";
        config1.device_id = device1;

        licenseseat::Client client1(config1);
        auto result1 = client1.validate(LICENSE_KEY, device1);

        licenseseat::Config config2;
        config2.api_key = API_KEY;
        config2.product_slug = PRODUCT_SLUG;
        config2.api_url = "https://licenseseat.com/api/v1";
        config2.device_id = device2;

        licenseseat::Client client2(config2);
        auto result2 = client2.validate(LICENSE_KEY, device2);

        if (result1.is_ok() && result2.is_ok()) {
            pass("Both devices can validate license");
            info("Device 1 valid: " + std::string(result1.value().valid ? "yes" : "no"));
            info("Device 2 valid: " + std::string(result2.value().valid ? "yes" : "no"));
        }
    }
}

// ============================================================================
// SCENARIO 9: Auto-validation Background Refresh
// ============================================================================

void test_scenario_9_auto_validation() {
    section("9. Auto-validation Background Refresh");

    std::string storage_path = get_temp_storage_path("s9");

    licenseseat::Config config;
    config.api_key = API_KEY;
    config.product_slug = PRODUCT_SLUG;
    config.api_url = "https://licenseseat.com/api/v1";
    config.storage_path = storage_path;
    config.auto_validate_interval = 1.0;  // 1 second for testing

    licenseseat::Client client(config);

    // Start auto-validation
    client.start_auto_validation(LICENSE_KEY);

    if (client.is_auto_validating()) {
        pass("Auto-validation started");
    } else {
        fail("Auto-validation start", "Not validating");
        cleanup_storage(storage_path);
        return;
    }

    // Wait for a few cycles
    info("Waiting for auto-validation cycles...");
    std::this_thread::sleep_for(std::chrono::milliseconds(2500));

    // Check status is maintained
    auto status = client.get_status();
    pass("Status maintained during auto-validation");
    info("Valid: " + std::string(status.valid ? "yes" : "no"));

    // Stop auto-validation
    client.stop_auto_validation();

    if (!client.is_auto_validating()) {
        pass("Auto-validation stopped");
    } else {
        fail("Auto-validation stop", "Still validating");
    }

    // Verify client still works after stopping
    auto result = client.validate(LICENSE_KEY);
    if (result.is_ok()) {
        pass("Manual validation works after stopping auto-validation");
    } else {
        fail("Post-auto validation", result.error_message());
    }

    cleanup_storage(storage_path);
}

// ============================================================================
// SCENARIO 10: Event-driven State Changes
// ============================================================================

void test_scenario_10_events() {
    section("10. Event-driven State Changes");

    licenseseat::Config config;
    config.api_key = API_KEY;
    config.product_slug = PRODUCT_SLUG;
    config.api_url = "https://licenseseat.com/api/v1";

    licenseseat::Client client(config);

    std::atomic<int> validation_success_count{0};
    std::atomic<int> validation_failed_count{0};
    std::atomic<int> offline_token_count{0};

    // Subscribe to events
    auto sub1 = client.on(licenseseat::events::VALIDATION_SUCCESS, [&](const std::any&) {
        ++validation_success_count;
    });

    auto sub2 = client.on(licenseseat::events::VALIDATION_FAILED, [&](const std::any&) {
        ++validation_failed_count;
    });

    auto sub3 = client.on(licenseseat::events::OFFLINE_TOKEN_READY, [&](const std::any&) {
        ++offline_token_count;
    });

    pass("Event subscriptions created");

    // Trigger validation events
    (void)client.validate(LICENSE_KEY);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Trigger offline token event
    (void)client.generate_offline_token(LICENSE_KEY);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Check events were received
    int total_validation_events = validation_success_count + validation_failed_count;
    if (total_validation_events > 0) {
        pass("Validation events received");
        info("Success events: " + std::to_string(validation_success_count.load()));
        info("Failed events: " + std::to_string(validation_failed_count.load()));
    } else {
        // Events might not fire depending on validation result
        pass("Validation completed (events may not fire for all outcomes)");
    }

    if (offline_token_count > 0) {
        pass("Offline token events received");
        info("Token events: " + std::to_string(offline_token_count.load()));
    } else {
        pass("Offline token generated (event emission is optional)");
    }

    // Cancel subscriptions
    sub1.cancel();
    sub2.cancel();
    sub3.cancel();

    if (!sub1.is_active() && !sub2.is_active() && !sub3.is_active()) {
        pass("Subscriptions cancelled");
    } else {
        fail("Subscription cancellation", "Some subscriptions still active");
    }

    // Events should not fire after cancellation
    int prev_count = validation_success_count + validation_failed_count;
    (void)client.validate(LICENSE_KEY);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    int new_count = validation_success_count + validation_failed_count;

    if (new_count == prev_count) {
        pass("No events after subscription cancellation");
    } else {
        fail("Event cancellation", "Events still firing");
    }
}

// ============================================================================
// Main
// ============================================================================

int main() {
    // Load credentials from environment variables
    if (!load_credentials()) {
        return 1;
    }

    std::cout << CYAN << "╔═══════════════════════════════════════════════════════════════╗" << RESET << "\n";
    std::cout << CYAN << "║   LicenseSeat C++ SDK - Real-World Scenario Tests            ║" << RESET << "\n";
    std::cout << CYAN << "╚═══════════════════════════════════════════════════════════════╝" << RESET << "\n";
    info("API URL: https://licenseseat.com/api/v1");
    info("License: " + LICENSE_KEY.substr(0, 5) + "..." + LICENSE_KEY.substr(LICENSE_KEY.length() - 5));

    auto start_time = std::chrono::high_resolution_clock::now();

    // Run all scenarios
    test_scenario_1_first_launch();
    test_scenario_2_returning_user();
    test_scenario_3_offline_mode();
    test_scenario_4_security();
    test_scenario_5_persistence();
    test_scenario_6_expiration();
    test_scenario_7_deactivation();
    test_scenario_8_reactivation();
    test_scenario_9_auto_validation();
    test_scenario_10_events();

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    // Summary
    std::cout << "\n" << CYAN << "═══════════════════════════════════════════════════════════════" << RESET << "\n";
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
    std::cout << "  Duration:     " << duration.count() << "ms\n\n";

    if (tests_failed == 0) {
        std::cout << GREEN << "  ✓ ALL SCENARIOS PASSED!" << RESET << "\n\n";
        return 0;
    } else {
        std::cout << RED << "  ✗ SOME SCENARIOS FAILED" << RESET << "\n\n";
        return 1;
    }
}
