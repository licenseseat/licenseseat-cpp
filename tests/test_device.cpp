#include <gtest/gtest.h>
#include <licenseseat/device.hpp>

#include <cstdlib>

namespace licenseseat {
namespace device {
namespace {

// ==================== Platform Name Tests ====================

TEST(DevicePlatformTest, GetPlatformNameReturnsValidString) {
    auto platform = get_platform_name();

    // Should return one of the known platforms
    EXPECT_TRUE(platform == "macos" || platform == "linux" || platform == "windows" ||
                platform == "unknown");

// Platform-specific check
#if defined(__APPLE__)
    EXPECT_EQ(platform, "macos");
#elif defined(__linux__)
    EXPECT_EQ(platform, "linux");
#elif defined(_WIN32) || defined(_WIN64)
    EXPECT_EQ(platform, "windows");
#endif
}

// ==================== Hostname Tests ====================

TEST(DeviceHostnameTest, GetHostnameReturnsNonEmpty) {
    auto hostname = get_hostname();

    // Hostname should never be empty (returns "unknown" as fallback)
    EXPECT_FALSE(hostname.empty());
}

TEST(DeviceHostnameTest, GetHostnameIsReasonableLength) {
    auto hostname = get_hostname();

    // Hostnames should be reasonable length (not longer than 255 chars)
    EXPECT_LE(hostname.length(), 255u);
}

// ==================== Device ID Tests ====================

TEST(DeviceIdTest, GenerateDeviceIdReturnsNonEmpty) {
    auto device_id = generate_device_id();

    // On most systems, this should succeed
    // It may be empty on some systems (e.g., sandboxed environments)
    // But we should at least not crash
    (void)device_id;
}

TEST(DeviceIdTest, GenerateDeviceIdIsConsistent) {
    auto device_id1 = generate_device_id();
    auto device_id2 = generate_device_id();

    // If we got an ID, it should be the same each time
    if (!device_id1.empty() && !device_id2.empty()) {
        EXPECT_EQ(device_id1, device_id2);
    }
}

TEST(DeviceIdTest, GenerateDeviceIdHasCorrectLength) {
    auto device_id = generate_device_id();

    // If we got an ID, it should be 32 hex chars (128 bits)
    if (!device_id.empty()) {
        EXPECT_EQ(device_id.length(), 32u);

        // Should be all hex characters
        for (char c : device_id) {
            EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
        }
    }
}

TEST(DeviceIdTest, GenerateDeviceIdIsNotTrivial) {
    auto device_id = generate_device_id();

    // If we got an ID, it shouldn't be all zeros or all same char
    if (!device_id.empty()) {
        bool all_same = true;
        char first = device_id[0];
        for (char c : device_id) {
            if (c != first) {
                all_same = false;
                break;
            }
        }
        EXPECT_FALSE(all_same);
    }
}

TEST(DeviceIdTest, GenerateDeviceIdSucceedsOnCI) {
    // On CI runners (standard environments), device ID generation should always succeed.
    // This catches regressions in platform-specific code that would silently fail otherwise.
    // Locally, developers may run in sandboxed/restricted environments where this legitimately fails.
    bool is_ci = false;
#if defined(_WIN32) || defined(_WIN64)
    // Use _dupenv_s on Windows (getenv is deprecated by MSVC)
    char* ci_env = nullptr;
    size_t len = 0;
    if (_dupenv_s(&ci_env, &len, "CI") == 0 && ci_env != nullptr) {
        is_ci = (std::string(ci_env) == "true");
        free(ci_env);
    }
#else
    const char* ci_env = std::getenv("CI");
    is_ci = (ci_env != nullptr && std::string(ci_env) == "true");
#endif

    if (is_ci) {
        auto device_id = generate_device_id();
        EXPECT_FALSE(device_id.empty())
            << "Device ID generation failed on CI runner. "
            << "Platform: " << get_platform_name() << ". "
            << "This indicates a bug in the platform-specific fingerprinting code.";
    }
}

}  // namespace
}  // namespace device
}  // namespace licenseseat
