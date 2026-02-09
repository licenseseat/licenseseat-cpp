#include <gtest/gtest.h>
#include <licenseseat/licenseseat.hpp>
#include <licenseseat/telemetry.hpp>

#include <atomic>
#include <chrono>
#include <thread>

namespace licenseseat {
namespace {

// ==================== Telemetry Collection Tests ====================

TEST(TelemetryTest, CollectReturnsSdkVersion) {
    auto result = telemetry::collect("1.2.3");

    ASSERT_TRUE(result.contains("sdk_version"));
    EXPECT_EQ(result["sdk_version"].get<std::string>(), "1.2.3");
}

TEST(TelemetryTest, CollectReturnsOsName) {
    auto result = telemetry::collect("1.0.0");

    ASSERT_TRUE(result.contains("os_name"));
    auto os_name = result["os_name"].get<std::string>();
    EXPECT_FALSE(os_name.empty());

#if defined(__APPLE__)
    EXPECT_EQ(os_name, "macOS");
#elif defined(__linux__)
    EXPECT_EQ(os_name, "Linux");
#elif defined(_WIN32) || defined(_WIN64)
    EXPECT_EQ(os_name, "Windows");
#endif
}

TEST(TelemetryTest, CollectReturnsOsVersion) {
    auto result = telemetry::collect("1.0.0");

    ASSERT_TRUE(result.contains("os_version"));
    EXPECT_FALSE(result["os_version"].get<std::string>().empty());
}

TEST(TelemetryTest, CollectReturnsPlatformAsNative) {
    auto result = telemetry::collect("1.0.0");

    ASSERT_TRUE(result.contains("platform"));
    EXPECT_EQ(result["platform"].get<std::string>(), "native");
}

TEST(TelemetryTest, CollectReturnsDeviceModel) {
    auto result = telemetry::collect("1.0.0");

    // device_model may or may not be available depending on the system
    if (result.contains("device_model")) {
        EXPECT_FALSE(result["device_model"].get<std::string>().empty());
    }
}

TEST(TelemetryTest, CollectReturnsTimezone) {
    auto result = telemetry::collect("1.0.0");

    // timezone should be available on most systems
    if (result.contains("timezone")) {
        EXPECT_FALSE(result["timezone"].get<std::string>().empty());
    }
}

// ==================== New Telemetry Fields ====================

TEST(TelemetryTest, CollectReturnsDeviceType) {
    auto result = telemetry::collect("1.0.0");

    ASSERT_TRUE(result.contains("device_type"));
    auto device_type = result["device_type"].get<std::string>();
    EXPECT_TRUE(device_type == "desktop" || device_type == "server" || device_type == "unknown");

#if defined(__APPLE__) || defined(_WIN32) || defined(_WIN64)
    EXPECT_EQ(device_type, "desktop");
#endif
}

TEST(TelemetryTest, CollectReturnsArchitecture) {
    auto result = telemetry::collect("1.0.0");

    ASSERT_TRUE(result.contains("architecture"));
    auto arch = result["architecture"].get<std::string>();
    EXPECT_TRUE(arch == "arm64" || arch == "x64" || arch == "x86" || arch == "arm");

#if defined(__aarch64__) || defined(_M_ARM64)
    EXPECT_EQ(arch, "arm64");
#elif defined(__x86_64__) || defined(_M_X64) || defined(_M_AMD64)
    EXPECT_EQ(arch, "x64");
#elif defined(__i386__) || defined(_M_IX86)
    EXPECT_EQ(arch, "x86");
#elif defined(__arm__) || defined(_M_ARM)
    EXPECT_EQ(arch, "arm");
#endif
}

TEST(TelemetryTest, CollectReturnsCpuCores) {
    auto result = telemetry::collect("1.0.0");

    ASSERT_TRUE(result.contains("cpu_cores"));
    auto cores = result["cpu_cores"].get<int>();
    EXPECT_GT(cores, 0);
    EXPECT_LE(cores, 1024);  // Sanity upper bound
}

TEST(TelemetryTest, CollectReturnsMemoryGb) {
    auto result = telemetry::collect("1.0.0");

    ASSERT_TRUE(result.contains("memory_gb"));
    auto memory = result["memory_gb"].get<int>();
    EXPECT_GT(memory, 0);
    EXPECT_LE(memory, 4096);  // Sanity upper bound
}

TEST(TelemetryTest, CollectReturnsLanguageWhenLangEnvSet) {
    // LANG is typically set on macOS and Linux
    auto result = telemetry::collect("1.0.0");

    if (result.contains("language")) {
        auto lang = result["language"].get<std::string>();
        EXPECT_EQ(lang.length(), 2u);
        // Should be lowercase alphabetic
        EXPECT_TRUE(std::isalpha(static_cast<unsigned char>(lang[0])));
        EXPECT_TRUE(std::isalpha(static_cast<unsigned char>(lang[1])));
    }
}

TEST(TelemetryTest, CollectReturnsScreenResolution) {
    auto result = telemetry::collect("1.0.0");

    // screen_resolution is optional (may not be available on headless/CI)
    if (result.contains("screen_resolution")) {
        auto res = result["screen_resolution"].get<std::string>();
        EXPECT_FALSE(res.empty());
        // Should be in "WIDTHxHEIGHT" format
        EXPECT_NE(res.find('x'), std::string::npos);
    }
}

// ==================== User-Provided Fields ====================

TEST(TelemetryTest, CollectIncludesAppVersion) {
    auto result = telemetry::collect("1.0.0", "2.5.0");

    ASSERT_TRUE(result.contains("app_version"));
    EXPECT_EQ(result["app_version"].get<std::string>(), "2.5.0");
}

TEST(TelemetryTest, CollectIncludesAppBuild) {
    auto result = telemetry::collect("1.0.0", "", "42");

    ASSERT_TRUE(result.contains("app_build"));
    EXPECT_EQ(result["app_build"].get<std::string>(), "42");
}

TEST(TelemetryTest, CollectIncludesBothAppVersionAndBuild) {
    auto result = telemetry::collect("1.0.0", "3.0.0", "100");

    ASSERT_TRUE(result.contains("app_version"));
    ASSERT_TRUE(result.contains("app_build"));
    EXPECT_EQ(result["app_version"].get<std::string>(), "3.0.0");
    EXPECT_EQ(result["app_build"].get<std::string>(), "100");
}

TEST(TelemetryTest, CollectOmitsEmptyAppVersion) {
    auto result = telemetry::collect("1.0.0", "");

    EXPECT_FALSE(result.contains("app_version"));
}

TEST(TelemetryTest, CollectOmitsEmptyAppBuild) {
    auto result = telemetry::collect("1.0.0", "", "");

    EXPECT_FALSE(result.contains("app_build"));
}

// ==================== Telemetry Payload Completeness ====================

TEST(TelemetryTest, CollectReturnsAllExpectedFields) {
    auto result = telemetry::collect("0.4.0", "1.0.0", "99");

    // These should always be present
    EXPECT_TRUE(result.contains("sdk_version"));
    EXPECT_TRUE(result.contains("os_name"));
    EXPECT_TRUE(result.contains("os_version"));
    EXPECT_TRUE(result.contains("platform"));
    EXPECT_TRUE(result.contains("device_type"));
    EXPECT_TRUE(result.contains("architecture"));
    EXPECT_TRUE(result.contains("cpu_cores"));
    EXPECT_TRUE(result.contains("memory_gb"));
    EXPECT_TRUE(result.contains("app_version"));
    EXPECT_TRUE(result.contains("app_build"));

    // Verify the result is a JSON object
    EXPECT_TRUE(result.is_object());
}

TEST(TelemetryTest, CollectNeverCrashes) {
    // Call collect many times to verify it never crashes
    for (int i = 0; i < 100; ++i) {
        auto result = telemetry::collect("1.0.0");
        EXPECT_TRUE(result.is_object());
    }
}

// ==================== Config Fields ====================

TEST(TelemetryConfigTest, ConfigHasAppVersionField) {
    Config config;
    EXPECT_TRUE(config.app_version.empty());

    config.app_version = "2.0.0";
    EXPECT_EQ(config.app_version, "2.0.0");
}

TEST(TelemetryConfigTest, ConfigHasAppBuildField) {
    Config config;
    EXPECT_TRUE(config.app_build.empty());

    config.app_build = "42";
    EXPECT_EQ(config.app_build, "42");
}

TEST(TelemetryConfigTest, ConfigHasHeartbeatInterval) {
    Config config;
    EXPECT_EQ(config.heartbeat_interval, 300);  // Default 5 minutes

    config.heartbeat_interval = 60;
    EXPECT_EQ(config.heartbeat_interval, 60);
}

TEST(TelemetryConfigTest, ConfigHeartbeatIntervalCanBeDisabled) {
    Config config;
    config.heartbeat_interval = 0;
    EXPECT_EQ(config.heartbeat_interval, 0);
}

// ==================== Heartbeat Timer Tests ====================

class HeartbeatTimerTest : public ::testing::Test {
  protected:
    void SetUp() override {
        config_.api_key = "test_api_key";
        config_.product_slug = "test_product";
        config_.device_id = "test-device-001";
        config_.api_url = "http://localhost:1";
        config_.timeout_seconds = 1;
        config_.max_retries = 0;
    }

    Config config_;
};

TEST_F(HeartbeatTimerTest, NotRunningByDefault) {
    Client client(config_);

    EXPECT_FALSE(client.is_heartbeat_running());
}

TEST_F(HeartbeatTimerTest, StartAndStopHeartbeat) {
    config_.heartbeat_interval = 60;
    Client client(config_);

    client.start_heartbeat("TEST-KEY");
    EXPECT_TRUE(client.is_heartbeat_running());

    client.stop_heartbeat();
    EXPECT_FALSE(client.is_heartbeat_running());
}

TEST_F(HeartbeatTimerTest, DoesNotStartWhenIntervalIsZero) {
    config_.heartbeat_interval = 0;
    Client client(config_);

    client.start_heartbeat("TEST-KEY");
    EXPECT_FALSE(client.is_heartbeat_running());
}

TEST_F(HeartbeatTimerTest, DoesNotStartWhenIntervalIsNegative) {
    config_.heartbeat_interval = -1;
    Client client(config_);

    client.start_heartbeat("TEST-KEY");
    EXPECT_FALSE(client.is_heartbeat_running());
}

TEST_F(HeartbeatTimerTest, StartTwiceDoesNotCrash) {
    config_.heartbeat_interval = 60;
    Client client(config_);

    client.start_heartbeat("TEST-KEY");
    client.start_heartbeat("TEST-KEY-2");  // Should stop first, then start

    EXPECT_TRUE(client.is_heartbeat_running());

    client.stop_heartbeat();
}

TEST_F(HeartbeatTimerTest, StopWhenNotRunningDoesNotCrash) {
    Client client(config_);

    // Should not crash
    client.stop_heartbeat();
    client.stop_heartbeat();

    EXPECT_FALSE(client.is_heartbeat_running());
}

TEST_F(HeartbeatTimerTest, ResetStopsHeartbeat) {
    config_.heartbeat_interval = 60;
    Client client(config_);

    client.start_heartbeat("TEST-KEY");
    EXPECT_TRUE(client.is_heartbeat_running());

    client.reset();

    EXPECT_FALSE(client.is_heartbeat_running());
}

TEST_F(HeartbeatTimerTest, DestructorStopsHeartbeat) {
    config_.heartbeat_interval = 60;

    {
        Client client(config_);
        client.start_heartbeat("TEST-KEY");
        EXPECT_TRUE(client.is_heartbeat_running());
        // Destructor should stop heartbeat cleanly
    }
    // If we reach here without hanging, the test passes
    SUCCEED();
}

TEST_F(HeartbeatTimerTest, HeartbeatRunsIndependentlyOfAutoValidation) {
    config_.heartbeat_interval = 60;
    config_.auto_validate_interval = 60.0;
    Client client(config_);

    client.start_heartbeat("TEST-KEY");
    client.start_auto_validation("TEST-KEY");

    EXPECT_TRUE(client.is_heartbeat_running());
    EXPECT_TRUE(client.is_auto_validating());

    // Stop only heartbeat
    client.stop_heartbeat();
    EXPECT_FALSE(client.is_heartbeat_running());
    EXPECT_TRUE(client.is_auto_validating());

    // Stop auto-validation
    client.stop_auto_validation();
    EXPECT_FALSE(client.is_auto_validating());
}

}  // namespace
}  // namespace licenseseat
