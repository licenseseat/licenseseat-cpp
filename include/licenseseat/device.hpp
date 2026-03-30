#pragma once

/**
 * @file device.hpp
 * @brief Device identification utilities for LicenseSeat SDK
 *
 * Provides cross-platform device fingerprinting functionality.
 */

#include <map>
#include <string>

namespace licenseseat {
namespace device {

/**
 * @brief Generate a stable device fingerprint based on hardware
 *
 * This function generates a stable, unique fingerprint for the current device
 * based on available hardware information:
 * - macOS: IOPlatformUUID from IOKit
 * - Linux: /etc/machine-id, D-Bus machine-id, DMI UUID, or hostname fallback
 * - Windows: platform machine ID / machine GUID
 *
 * The identifier is hashed to a consistent format for privacy.
 *
 * @return A stable device fingerprint string, or empty string on failure
 */
[[nodiscard]] std::string generate_device_id();

/**
 * @brief Collect structured fingerprint components for diagnostics/future matching
 *
 * The SDK still uses a single stable fingerprint for binding. This helper exposes
 * the underlying signals that were available when that fingerprint was generated
 * so the server can persist them for future analytics or carefully versioned
 * matching policies.
 *
 * @return Flat key/value component map (all values are strings for JSON transport)
 */
[[nodiscard]] std::map<std::string, std::string> collect_fingerprint_components();

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
