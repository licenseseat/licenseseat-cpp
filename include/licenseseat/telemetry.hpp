#pragma once

/**
 * @file telemetry.hpp
 * @brief Telemetry collection for LicenseSeat SDK
 *
 * Collects anonymous platform information to help developers understand
 * their user base. Can be disabled via Config::telemetry_enabled = false.
 */

#include <nlohmann/json.hpp>

#include <string>

namespace licenseseat {
namespace telemetry {

/**
 * @brief Collect telemetry data for the current device
 *
 * Gathers platform information including OS name, version, device model,
 * locale, and timezone. Null/empty values are omitted from the result.
 *
 * @param sdk_version The SDK version string
 * @return JSON object with telemetry fields
 */
[[nodiscard]] nlohmann::json collect(const std::string& sdk_version);

}  // namespace telemetry
}  // namespace licenseseat
