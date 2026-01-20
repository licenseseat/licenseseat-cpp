#pragma once

/**
 * @file device.hpp
 * @brief Device identification utilities for LicenseSeat SDK
 *
 * Provides cross-platform device fingerprinting functionality.
 */

#include <string>

namespace licenseseat {
namespace device {

/**
 * @brief Generate a unique device identifier based on hardware
 *
 * This function generates a stable, unique identifier for the current device
 * based on available hardware information:
 * - macOS: IOPlatformUUID from IOKit
 * - Linux: /etc/machine-id or DMI system UUID
 * - Windows: SMBIOS system UUID
 *
 * The identifier is hashed to a consistent format for privacy.
 *
 * @return A stable device identifier string, or empty string on failure
 */
[[nodiscard]] std::string generate_device_id();

/**
 * @brief Get the platform name
 *
 * @return "macos", "linux", "windows", or "unknown"
 */
[[nodiscard]] std::string get_platform_name();

/**
 * @brief Get a human-readable hostname
 *
 * @return The system hostname or "unknown" on failure
 */
[[nodiscard]] std::string get_hostname();

}  // namespace device
}  // namespace licenseseat
