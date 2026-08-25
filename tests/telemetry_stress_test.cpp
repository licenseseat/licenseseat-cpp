/**
 * @file telemetry_stress_test.cpp
 * @brief Telemetry & heartbeat stress test for LicenseSeat C++ SDK
 *
 * Mirrors the Swift and JS stress tests (9 scenarios).
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
#include <licenseseat/telemetry.hpp>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <future>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "test_env.hpp"

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
    return test_env::get(name, fallback);
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
        logInfo("activation_id: " + result.value().id());
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

// ==================== Scenario 8 ====================
// Enriched Telemetry Fields

static void scenario8_enriched_telemetry() {
    printHeader("Enriched Telemetry Fields");

    // Collect telemetry locally and verify all expected fields
    auto telemetry = licenseseat::telemetry::collect(licenseseat::VERSION, "2.0.0", "42");

    // Always-present fields
    printTest(telemetry.contains("sdk_version") && telemetry["sdk_version"] == licenseseat::VERSION,
              "sdk_version present and correct");

    printTest(telemetry.contains("os_name") && !telemetry["os_name"].get<std::string>().empty(),
              "os_name present",
              telemetry.value("os_name", ""));

    printTest(telemetry.contains("os_version") && !telemetry["os_version"].get<std::string>().empty(),
              "os_version present",
              telemetry.value("os_version", ""));

    printTest(telemetry.contains("platform") && telemetry["platform"] == "native",
              "platform is 'native' (not duplicating os_name)",
              telemetry.value("platform", ""));

    // User-provided fields
    printTest(telemetry.contains("app_version") && telemetry["app_version"] == "2.0.0",
              "app_version included from config",
              telemetry.value("app_version", ""));

    printTest(telemetry.contains("app_build") && telemetry["app_build"] == "42",
              "app_build included from config",
              telemetry.value("app_build", ""));

    // New enriched fields
    printTest(telemetry.contains("device_type"),
              "device_type present",
              telemetry.value("device_type", "(missing)"));

    {
        auto dt = telemetry.value("device_type", "");
        printTest(dt == "desktop" || dt == "server" || dt == "unknown",
                  "device_type is valid value",
                  dt);
    }

    printTest(telemetry.contains("architecture"),
              "architecture present",
              telemetry.value("architecture", "(missing)"));

    {
        auto arch = telemetry.value("architecture", "");
        printTest(arch == "arm64" || arch == "x64" || arch == "x86" || arch == "arm",
                  "architecture is valid value",
                  arch);
    }

    printTest(telemetry.contains("cpu_cores") && telemetry["cpu_cores"].get<int>() > 0,
              "cpu_cores present and > 0",
              std::to_string(telemetry.value("cpu_cores", 0)));

    printTest(telemetry.contains("memory_gb") && telemetry["memory_gb"].get<int>() > 0,
              "memory_gb present and > 0",
              std::to_string(telemetry.value("memory_gb", 0)) + " GB");

    if (telemetry.contains("language")) {
        auto lang = telemetry["language"].get<std::string>();
        printTest(lang.length() == 2, "language is 2-char code", lang);
    } else {
        logInfo("language not available (LANG env not set)");
    }

    if (telemetry.contains("screen_resolution")) {
        auto res = telemetry["screen_resolution"].get<std::string>();
        printTest(res.find('x') != std::string::npos,
                  "screen_resolution in WIDTHxHEIGHT format", res);
    } else {
        logInfo("screen_resolution not available (headless/CI)");
    }

    // Verify enriched telemetry reaches server via activation
    auto config = makeConfig("s8_enriched");
    config.app_version = "2.0.0";
    config.app_build = "42";
    auto sdk = std::make_unique<licenseseat::Client>(config);
    sdk->reset();

    auto act = sdk->activate(LICENSE_KEY);
    bool act_ok = act.is_ok() || act.error_code() == licenseseat::ErrorCode::DeviceAlreadyActivated;
    printTest(act_ok, "Activation with enriched telemetry sent to server");

    if (act_ok) {
        auto val = sdk->validate(LICENSE_KEY);
        printTest(val.is_ok(), "Validation with enriched telemetry sent to server");
    }

    // Clean up
    (void)sdk->deactivate(LICENSE_KEY, sdk->device_id());
    sdk->reset();
    sdk.reset();
}

// ==================== Scenario 9 ====================
// Separate Heartbeat Timer

static void scenario9_heartbeat_timer() {
    printHeader("Separate Heartbeat Timer");

    auto config = makeConfig("s9_hb_timer", /*telemetry=*/true, /*autoValidateInterval=*/0);
    config.heartbeat_interval = 3;  // 3 seconds for fast testing
    auto sdk = std::make_unique<licenseseat::Client>(config);
    sdk->reset();

    // Activate first
    auto act = sdk->activate(LICENSE_KEY);
    bool act_ok = act.is_ok() || act.error_code() == licenseseat::ErrorCode::DeviceAlreadyActivated;
    printTest(act_ok, "Activation for heartbeat timer test");

    if (!act_ok) {
        sdk->reset();
        sdk.reset();
        return;
    }

    // Track heartbeat events
    std::atomic<int> hb_success_count{0};
    std::atomic<int> hb_error_count{0};
    auto sub_ok = sdk->on(licenseseat::events::HEARTBEAT_SUCCESS, [&](const std::any&) {
        ++hb_success_count;
        logInfo("Heartbeat timer fired #" + std::to_string(hb_success_count.load()));
    });
    auto sub_err = sdk->on(licenseseat::events::HEARTBEAT_ERROR, [&](const std::any&) {
        ++hb_error_count;
    });

    // Start heartbeat timer (auto-validation is OFF)
    sdk->start_heartbeat(LICENSE_KEY);
    printTest(sdk->is_heartbeat_running(), "Heartbeat timer started");
    printTest(!sdk->is_auto_validating(), "Auto-validation is NOT running (independent)");

    // Wait ~10 seconds for at least 2 heartbeat cycles (3s interval)
    logInfo("Waiting 10 seconds for heartbeat timer cycles (3s interval)...");
    std::this_thread::sleep_for(std::chrono::seconds(10));

    sdk->stop_heartbeat();
    printTest(!sdk->is_heartbeat_running(), "Heartbeat timer stopped");

    int hb_ok = hb_success_count.load();
    int hb_err = hb_error_count.load();
    printTest(hb_ok >= 2, "At least 2 heartbeat timer cycles fired",
              std::to_string(hb_ok) + " successes, " + std::to_string(hb_err) + " errors");

    // Test heartbeat timer disabled when interval = 0
    {
        auto config2 = makeConfig("s9_hb_disabled", /*telemetry=*/true, /*autoValidateInterval=*/0);
        config2.heartbeat_interval = 0;
        auto sdk2 = std::make_unique<licenseseat::Client>(config2);
        sdk2->start_heartbeat(LICENSE_KEY);
        printTest(!sdk2->is_heartbeat_running(), "Heartbeat timer does NOT start when interval=0");
        sdk2.reset();
    }

    // Clean up
    sub_ok.cancel();
    sub_err.cancel();
    (void)sdk->deactivate(LICENSE_KEY, sdk->device_id());
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
    scenario8_enriched_telemetry();
    scenario9_heartbeat_timer();

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
