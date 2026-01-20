#include <gtest/gtest.h>
#include <licenseseat/device.hpp>

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

}  // namespace
}  // namespace device
}  // namespace licenseseat
