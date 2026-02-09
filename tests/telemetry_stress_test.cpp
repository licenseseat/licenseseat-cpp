/**
 * @file telemetry_stress_test.cpp
 * @brief Telemetry & heartbeat stress test for LicenseSeat C++ SDK
 *
 * Mirrors the Swift and JS stress tests exactly (7 scenarios).
 *
 * Required environment variables (defaults to local dev server):
 *   LICENSESEAT_API_URL      - API base URL
 *   LICENSESEAT_API_KEY      - API key
 *   LICENSESEAT_PRODUCT_SLUG - Product slug
 *   LICENSESEAT_LICENSE_KEY  - License key
 *
 * Build:
 *   cd build && cmake .. -DLICENSESEAT_BUILD_TESTS=ON && make telemetry_stress_test
 *
 * Run:
 *   ./tests/telemetry_stress_test
 */

#include <licenseseat/licenseseat.hpp>
#include <licenseseat/device.hpp>
#include <licenseseat/events.hpp>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <future>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// ==================== Globals ====================

static std::string API_URL;
static std::string API_KEY;
static std::string PRODUCT_SLUG;
static std::string LICENSE_KEY;

static std::atomic<int> total_passed{0};
static std::atomic<int> total_failed{0};
static int scenario_counter = 0;

// ==================== Colors ====================

#define GREEN  "\033[32m"
#define RED    "\033[31m"
#define YELLOW "\033[33m"
#define CYAN   "\033[36m"
#define BOLD   "\033[1m"
#define RESET  "\033[0m"

// ==================== Helpers ====================

static std::string get_env(const char* name, const char* fallback) {
    const char* val = std::getenv(name);
    return (val && val[0] != '\0') ? std::string(val) : std::string(fallback);
}

static void printHeader(const std::string& title) {
    ++scenario_counter;
    std::cout << "\n"
              << CYAN << BOLD
              << "========================================================"
              << RESET << "\n"
              << CYAN << BOLD << "  Scenario " << scenario_counter << ": " << title
              << RESET << "\n"
              << CYAN << BOLD
              << "========================================================"
              << RESET << "\n\n";
}

static void printTest(bool condition, const std::string& name, const std::string& detail = "") {
    if (condition) {
        ++total_passed;
        std::cout << GREEN << "  PASS " << RESET << name;
    } else {
        ++total_failed;
        std::cout << RED << "  FAIL " << RESET << name;
    }
    if (!detail.empty()) {
        std::cout << " -- " << detail;
    }
    std::cout << "\n";
}

static void logInfo(const std::string& msg) {
    std::cout << YELLOW << "  -> " << RESET << msg << "\n";
}

static licenseseat::Config makeConfig(const std::string& prefix,
                                       bool telemetry = true,
                                       double autoValidateInterval = 0) {
    licenseseat::Config config;
    config.api_key = API_KEY;
    config.api_url = API_URL;
    config.product_slug = PRODUCT_SLUG;
    config.auto_validate_interval = autoValidateInterval;
    config.telemetry_enabled = telemetry;
    config.debug = false;
    config.verify_ssl = false;
    config.timeout_seconds = 15;
    config.max_retries = 1;
    config.retry_interval_ms = 500;
    config.storage_path = "/tmp/licenseseat_stress_test_" + prefix;
    config.storage_prefix = prefix;
    return config;
}

// ==================== Scenario 1 ====================
// Activation WITH Telemetry (default)

static void scenario1_activation_with_telemetry() {
    printHeader("Activation WITH Telemetry (default)");

    auto config = makeConfig("s1_telemetry");
    auto sdk = std::make_unique<licenseseat::Client>(config);
    sdk->reset();

    auto result = sdk->activate(LICENSE_KEY);

    if (result.is_ok()) {
        printTest(true, "Activation succeeded");
        logInfo("device_id: " + result.value().device_id());
        logInfo("activation_id: " + std::to_string(result.value().id()));
    } else if (result.error_code() == licenseseat::ErrorCode::DeviceAlreadyActivated) {
        printTest(true, "Activation returned already_activated (expected, passing)");
        logInfo("device_id: " + sdk->device_id());
    } else {
        printTest(false, "Activation failed", result.error_message());
    }

    // Clean up: deactivate so other scenarios can use the seat
    (void)sdk->deactivate(LICENSE_KEY, sdk->device_id());
    sdk->reset();
}

// ==================== Scenario 2 ====================
// Validation WITH Telemetry

static void scenario2_validation_with_telemetry() {
    printHeader("Validation WITH Telemetry");

    auto config = makeConfig("s2_validation");
    auto sdk = std::make_unique<licenseseat::Client>(config);
    sdk->reset();

    // Activate first
    auto act = sdk->activate(LICENSE_KEY);
    if (act.is_error() && act.error_code() != licenseseat::ErrorCode::DeviceAlreadyActivated) {
        printTest(false, "Pre-activation failed", act.error_message());
        sdk->reset();
        return;
    }

    // Validate
    auto val = sdk->validate(LICENSE_KEY);
    printTest(val.is_ok(), "Validation succeeded");

    if (val.is_ok()) {
        printTest(val.value().valid, "License is valid");
        logInfo("plan_key: " + val.value().license.plan_key());
        logInfo("mode: " + std::string(licenseseat::license_mode_to_string(val.value().license.mode())));
        auto seat_limit = val.value().license.seat_limit();
        logInfo("seats: " + (seat_limit ? std::to_string(*seat_limit) : "unlimited"));
    }

    // Clean up
    (void)sdk->deactivate(LICENSE_KEY, sdk->device_id());
    sdk->reset();
}

// ==================== Scenario 3 ====================
// Heartbeat Endpoint

static void scenario3_heartbeat() {
    printHeader("Heartbeat Endpoint");

    auto config = makeConfig("s3_heartbeat");
    auto sdk = std::make_unique<licenseseat::Client>(config);
    sdk->reset();

    // Activate first
    auto act = sdk->activate(LICENSE_KEY);
    if (act.is_error() && act.error_code() != licenseseat::ErrorCode::DeviceAlreadyActivated) {
        printTest(false, "Pre-activation failed", act.error_message());
        sdk->reset();
        return;
    }

    // 1 initial heartbeat
    {
        auto hb = sdk->heartbeat(LICENSE_KEY);
        printTest(hb.is_ok() && !hb.value().received_at.empty(),
                  "Initial heartbeat succeeded",
                  hb.is_ok() ? ("received_at: " + hb.value().received_at) : hb.error_message());
    }

    // 5 rapid heartbeats
    {
        int rapid_ok = 0;
        for (int i = 0; i < 5; ++i) {
            auto hb = sdk->heartbeat(LICENSE_KEY);
            if (hb.is_ok() && !hb.value().received_at.empty()) {
                ++rapid_ok;
            }
        }
        printTest(rapid_ok == 5, "5 rapid heartbeats",
                  std::to_string(rapid_ok) + "/5 succeeded");
    }

    // 3 spaced heartbeats (0.5s apart)
    {
        int spaced_ok = 0;
        for (int i = 0; i < 3; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            auto hb = sdk->heartbeat(LICENSE_KEY);
            if (hb.is_ok() && !hb.value().received_at.empty()) {
                ++spaced_ok;
            }
        }
        printTest(spaced_ok == 3, "3 spaced heartbeats (0.5s apart)",
                  std::to_string(spaced_ok) + "/3 succeeded");
    }

    // Clean up
    (void)sdk->deactivate(LICENSE_KEY, sdk->device_id());
    sdk->reset();
}

// ==================== Scenario 4 ====================
// Telemetry DISABLED

static void scenario4_telemetry_disabled() {
    printHeader("Telemetry DISABLED");

    auto config = makeConfig("s4_notelemetry", /*telemetry=*/false);
    auto sdk = std::make_unique<licenseseat::Client>(config);
    sdk->reset();

    // Activate
    auto act = sdk->activate(LICENSE_KEY);
    bool act_ok = act.is_ok() || act.error_code() == licenseseat::ErrorCode::DeviceAlreadyActivated;
    printTest(act_ok, "Activation without telemetry");

    // Validate
    auto val = sdk->validate(LICENSE_KEY);
    printTest(val.is_ok(), "Validation without telemetry");

    // Heartbeat
    auto hb = sdk->heartbeat(LICENSE_KEY);
    printTest(hb.is_ok() && !hb.value().received_at.empty(), "Heartbeat without telemetry");

    // Clean up
    (void)sdk->deactivate(LICENSE_KEY, sdk->device_id());
    sdk->reset();
}

// ==================== Scenario 5 ====================
// Auto-Validation + Heartbeat Cycles

static void scenario5_auto_validation() {
    printHeader("Auto-Validation + Heartbeat Cycles");

    auto config = makeConfig("s5_autovalidate", /*telemetry=*/true, /*autoValidateInterval=*/3.0);
    auto sdk = std::make_unique<licenseseat::Client>(config);
    sdk->reset();

    std::atomic<int> cycle_count{0};
    auto sub = sdk->on(licenseseat::events::AUTOVALIDATION_CYCLE, [&](const std::any&) {
        ++cycle_count;
        logInfo("Auto-validation cycle #" + std::to_string(cycle_count.load()));
    });

    // Activate
    auto act = sdk->activate(LICENSE_KEY);
    bool act_ok = act.is_ok() || act.error_code() == licenseseat::ErrorCode::DeviceAlreadyActivated;
    printTest(act_ok, "Activation for auto-validation");

    // Start auto-validation
    sdk->start_auto_validation(LICENSE_KEY);
    printTest(sdk->is_auto_validating(), "Auto-validation started");

    // Wait ~12 seconds for at least 2 cycles (3s interval => cycles at ~3s, ~6s, ~9s, ~12s)
    logInfo("Waiting 12 seconds for auto-validation cycles...");
    std::this_thread::sleep_for(std::chrono::seconds(12));

    // CRITICAL: Stop auto-validation BEFORE moving to scenario 6
    sdk->stop_auto_validation();
    printTest(!sdk->is_auto_validating(), "Auto-validation stopped");

    int cycles = cycle_count.load();
    printTest(cycles >= 2, "At least 2 auto-validation cycles fired",
              std::to_string(cycles) + " cycles observed");

    // Clean up
    sub.cancel();
    (void)sdk->deactivate(LICENSE_KEY, sdk->device_id());
    sdk->reset();
    sdk.reset();  // destroy SDK instance
}

// ==================== Scenario 6 ====================
// Concurrent Validation Stress

static void scenario6_concurrent_stress() {
    printHeader("Concurrent Validation Stress");

    auto config = makeConfig("s6_concurrent");
    auto sdk = std::make_unique<licenseseat::Client>(config);
    sdk->reset();

    // Activate
    auto act = sdk->activate(LICENSE_KEY);
    bool act_ok = act.is_ok() || act.error_code() == licenseseat::ErrorCode::DeviceAlreadyActivated;
    printTest(act_ok, "Activation for concurrent stress");

    // Fire 5 concurrent validations
    {
        std::vector<std::future<bool>> futures;
        for (int i = 0; i < 5; ++i) {
            futures.push_back(std::async(std::launch::async, [&sdk]() {
                auto val = sdk->validate(LICENSE_KEY);
                return val.is_ok();
            }));
        }

        int val_ok = 0;
        for (auto& f : futures) {
            if (f.get()) {
                ++val_ok;
            }
        }
        printTest(val_ok >= 4, "Concurrent validations",
                  std::to_string(val_ok) + "/5 succeeded (need >= 4)");
    }

    // Fire 3 concurrent heartbeats
    {
        std::vector<std::future<bool>> futures;
        for (int i = 0; i < 3; ++i) {
            futures.push_back(std::async(std::launch::async, [&sdk]() {
                auto hb = sdk->heartbeat(LICENSE_KEY);
                return hb.is_ok() && !hb.value().received_at.empty();
            }));
        }

        int hb_ok = 0;
        for (auto& f : futures) {
            if (f.get()) {
                ++hb_ok;
            }
        }
        printTest(hb_ok >= 2, "Concurrent heartbeats",
                  std::to_string(hb_ok) + "/3 succeeded (need >= 2)");
    }

    // Clean up
    (void)sdk->deactivate(LICENSE_KEY, sdk->device_id());
    sdk->reset();
    sdk.reset();
}

// ==================== Scenario 7 ====================
// Full Lifecycle

static void scenario7_full_lifecycle() {
    printHeader("Full Lifecycle");

    auto config = makeConfig("s7_lifecycle");
    auto sdk = std::make_unique<licenseseat::Client>(config);
    sdk->reset();

    // Subscribe to events
    std::mutex event_mtx;
    std::vector<std::string> event_log;

    auto sub_act = sdk->on(licenseseat::events::ACTIVATION_SUCCESS, [&](const std::any&) {
        std::lock_guard<std::mutex> lock(event_mtx);
        event_log.push_back("activation:success");
    });
    auto sub_val = sdk->on(licenseseat::events::VALIDATION_SUCCESS, [&](const std::any&) {
        std::lock_guard<std::mutex> lock(event_mtx);
        event_log.push_back("validation:success");
    });
    auto sub_deact = sdk->on(licenseseat::events::DEACTIVATION_SUCCESS, [&](const std::any&) {
        std::lock_guard<std::mutex> lock(event_mtx);
        event_log.push_back("deactivation:success");
    });

    // Step 1: Activate
    auto act = sdk->activate(LICENSE_KEY);
    bool act_ok = act.is_ok() || act.error_code() == licenseseat::ErrorCode::DeviceAlreadyActivated;
    printTest(act_ok, "Step 1: Activate");

    // Step 2: Validate
    auto val = sdk->validate(LICENSE_KEY);
    printTest(val.is_ok() && val.value().valid, "Step 2: Validate");

    // Step 3: Heartbeat
    auto hb = sdk->heartbeat(LICENSE_KEY);
    printTest(hb.is_ok() && !hb.value().received_at.empty(), "Step 3: Heartbeat");

    // Step 4: Deactivate
    auto deact = sdk->deactivate(LICENSE_KEY, sdk->device_id());
    printTest(deact.is_ok(), "Step 4: Deactivate");

    // Cache should be cleared
    auto cached = sdk->current_license();
    printTest(!cached.has_value(), "Cache cleared after deactivation");

    // Check event log
    {
        std::lock_guard<std::mutex> lock(event_mtx);
        bool has_val = false, has_deact = false;
        for (const auto& ev : event_log) {
            if (ev == "validation:success") has_val = true;
            if (ev == "deactivation:success") has_deact = true;
        }

        logInfo("Event log: [" + [&]() {
            std::string s;
            for (size_t i = 0; i < event_log.size(); ++i) {
                if (i > 0) s += ", ";
                s += event_log[i];
            }
            return s;
        }() + "]");

        printTest(has_val, "Event: validation:success fired");
        printTest(has_deact, "Event: deactivation:success fired");
    }

    // Unsubscribe
    sub_act.cancel();
    sub_val.cancel();
    sub_deact.cancel();
    sdk->reset();
    sdk.reset();
}

// ==================== Main ====================

int main() {
    // Force unbuffered stdout for real-time output
    std::cout << std::unitbuf;

    std::cout << "\n"
              << BOLD << CYAN
              << "============================================================\n"
              << "  LicenseSeat C++ SDK -- Telemetry & Heartbeat Stress Test\n"
              << "============================================================"
              << RESET << "\n";

    // Load credentials
    API_URL = get_env("LICENSESEAT_API_URL", "http://localhost:3000/api/v1");
    API_KEY = get_env("LICENSESEAT_API_KEY", "pk_test_JcS9mnL84P4jgV1uS7Z6BHXt5P8fXTPnf");
    PRODUCT_SLUG = get_env("LICENSESEAT_PRODUCT_SLUG", "ahjsffj");
    LICENSE_KEY = get_env("LICENSESEAT_LICENSE_KEY", "AULRP-E4KPJ-HW6R3-MGJPT");

    logInfo("API URL:      " + API_URL);
    logInfo("Product Slug: " + PRODUCT_SLUG);
    logInfo("License Key:  " + LICENSE_KEY);
    logInfo("API Key:      " + API_KEY.substr(0, 12) + "...");

    // Run all scenarios sequentially
    scenario1_activation_with_telemetry();
    scenario2_validation_with_telemetry();
    scenario3_heartbeat();
    scenario4_telemetry_disabled();
    scenario5_auto_validation();
    scenario6_concurrent_stress();
    scenario7_full_lifecycle();

    // Summary
    int passed = total_passed.load();
    int failed = total_failed.load();

    std::cout << "\n"
              << BOLD << CYAN
              << "============================================================\n"
              << "  SUMMARY\n"
              << "============================================================"
              << RESET << "\n\n";

    std::cout << GREEN << "  Passed: " << passed << RESET << "\n";
    std::cout << RED << "  Failed: " << failed << RESET << "\n";
    std::cout << "  Total:  " << (passed + failed) << "\n\n";

    if (failed == 0) {
        std::cout << GREEN << BOLD << "  ALL TESTS PASSED" << RESET << "\n\n";
    } else {
        std::cout << RED << BOLD << "  SOME TESTS FAILED" << RESET << "\n\n";
    }

    return failed > 0 ? 1 : 0;
}
