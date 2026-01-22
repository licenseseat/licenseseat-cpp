/**
 * @file basic_usage.cpp
 * @brief Basic usage example for the LicenseSeat C++ SDK
 *
 * This example demonstrates how to:
 * - Create a client with configuration
 * - Subscribe to events
 * - Validate a license key (sync and async)
 * - Activate a license on a device
 * - Use auto-validation
 * - Verify an offline token
 * - Handle errors using the Result type
 */

#include <licenseseat/licenseseat.hpp>

#include <atomic>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

int main() {
    // Configure the client
    licenseseat::Config config;
    config.api_key = "your-api-key";
    config.api_url = "https://licenseseat.com/api/v1";
    config.product_slug = "your-product";
    // Device ID is auto-generated if not provided
    // config.device_id = "custom-device-id";

    // Storage path for license caching (enables offline fallback)
    config.storage_path = "/tmp/licenseseat_cache";

    // Auto-validation settings
    config.auto_validate_interval = 300.0;  // Revalidate every 5 minutes

    // Offline fallback settings
    config.max_offline_days = 30;  // Allow 30 days offline operation

    // Create the client
    licenseseat::Client client(config);

    // The client auto-generates a unique device identifier based on hardware
    std::cout << "Device ID: " << client.device_id() << "\n";

    // Example 0: Subscribe to SDK events
    std::cout << "\n=== Event Subscription ===\n";
    {
        // Subscribe to validation events
        auto sub1 = client.on("validation:success", [](const std::any& /*data*/) {
            std::cout << "[Event] License validated successfully!\n";
        });

        auto sub2 = client.on("validation:failed", [](const std::any& /*data*/) {
            std::cout << "[Event] License validation failed.\n";
        });

        auto sub3 = client.on("network:offline", [](const std::any& /*data*/) {
            std::cout << "[Event] Network went offline, falling back to cached license.\n";
        });

        auto sub4 = client.on("network:online", [](const std::any& /*data*/) {
            std::cout << "[Event] Network is back online.\n";
        });

        std::cout << "Subscribed to validation and network events.\n";
        // Subscriptions are automatically cancelled when they go out of scope,
        // or you can call sub.cancel() to unsubscribe early.
    }

    // Example 1: Validate a license key
    std::cout << "\n=== License Validation ===\n";
    {
        auto result = client.validate("LICENSE-KEY-HERE");

        if (result.is_ok()) {
            const auto& validation = result.value();
            std::cout << "License valid: " << (validation.valid ? "yes" : "no") << "\n";

            const auto& license = validation.license;
            std::cout << "License key: " << license.key() << "\n";
            std::cout << "Status: " << licenseseat::license_status_to_string(license.status())
                      << "\n";
            std::cout << "Seats used: " << license.active_seats() << "/";
            if (license.seat_limit().has_value()) {
                std::cout << license.seat_limit().value();
            } else {
                std::cout << "unlimited";
            }
            std::cout << "\n";
        } else {
            std::cerr << "Validation failed: " << result.error_message() << "\n";
            std::cerr << "Error code: " << licenseseat::error_code_to_string(result.error_code())
                      << "\n";
        }
    }

    // Example 1.5: Async validation (non-blocking)
    std::cout << "\n=== Async License Validation ===\n";
    {
        std::atomic<bool> done{false};

        client.validate_async(
            "LICENSE-KEY-HERE", [&done](licenseseat::Result<licenseseat::ValidationResult> result) {
                if (result.is_ok()) {
                    std::cout << "[Async] License valid: "
                              << (result.value().valid ? "yes" : "no") << "\n";
                } else {
                    std::cout << "[Async] Validation failed: " << result.error_message() << "\n";
                }
                done = true;
            });

        std::cout << "Validation running in background...\n";

        // Wait for completion (in real apps, you'd do other work here)
        while (!done) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

    // Example 2: Activate a license
    std::cout << "\n=== License Activation ===\n";
    {
        // Optional metadata about the device
        licenseseat::Metadata metadata;
        metadata["app_version"] = "1.0.0";
        metadata["os_version"] = "macOS 14.0";

        // activate(license_key, device_id, device_name, metadata)
        // Empty device_id = use auto-generated device ID from config
        auto result = client.activate("LICENSE-KEY-HERE", "", "My Device", metadata);

        if (result.is_ok()) {
            const auto& activation = result.value();
            std::cout << "Activation ID: " << activation.id() << "\n";
            std::cout << "Device: " << activation.device_id() << "\n";
            std::cout << "Active: " << (activation.is_active() ? "yes" : "no") << "\n";
        } else {
            std::cerr << "Activation failed: " << result.error_message() << "\n";

            // Handle specific error codes
            switch (result.error_code()) {
                case licenseseat::ErrorCode::SeatLimitExceeded:
                    std::cerr << "No more seats available on this license.\n";
                    break;
                case licenseseat::ErrorCode::LicenseExpired:
                    std::cerr << "The license has expired.\n";
                    break;
                case licenseseat::ErrorCode::NetworkError:
                    std::cerr << "Network error - check your connection.\n";
                    break;
                default:
                    break;
            }
        }
    }

    // Example 3: Offline token verification
    std::cout << "\n=== Offline Token Verification ===\n";
    {
        // First, fetch the offline token (requires network)
        auto offline_result = client.generate_offline_token("LICENSE-KEY-HERE");

        if (offline_result.is_ok()) {
            const auto& offline = offline_result.value();
            std::cout << "Offline token obtained.\n";
            std::cout << "Key ID: " << offline.token.kid << "\n";

            // Later, verify offline (no network needed)
            // The public key can be embedded in your app or fetched once
            std::string public_key_b64 = "your-public-key-base64";
            auto verify_result = client.verify_offline_token(offline, public_key_b64);

            if (verify_result.is_ok() && verify_result.value()) {
                std::cout << "Offline token is valid!\n";

                // Check entitlements
                for (const auto& entitlement : offline.token.entitlements) {
                    std::cout << "Entitlement: " << entitlement.key;
                    if (entitlement.expires_at.has_value()) {
                        auto now = std::chrono::system_clock::now();
                        if (entitlement.expires_at.value() > now) {
                            std::cout << " (active)\n";
                        } else {
                            std::cout << " (expired)\n";
                        }
                    } else {
                        std::cout << " (no expiry)\n";
                    }
                }
            } else {
                std::cerr << "Offline token verification failed.\n";
            }
        } else {
            std::cerr << "Failed to get offline token: " << offline_result.error_message()
                      << "\n";
        }
    }

    // Example 4: Check for updates
    std::cout << "\n=== Release Management ===\n";
    {
        auto result = client.get_latest_release(config.product_slug);

        if (result.is_ok()) {
            const auto& release = result.value();
            std::cout << "Latest version: " << release.version << "\n";
            std::cout << "Channel: " << release.channel << "\n";
            std::cout << "Platform: " << release.platform << "\n";
        } else {
            std::cerr << "Failed to check for updates: " << result.error_message() << "\n";
        }
    }

    // Example 5: Auto-validation (validates periodically in background)
    std::cout << "\n=== Auto-Validation ===\n";
    {
        // Start auto-validation - will revalidate every 5 minutes (per config)
        client.start_auto_validation("LICENSE-KEY-HERE");
        std::cout << "Auto-validation started: " << (client.is_auto_validating() ? "yes" : "no")
                  << "\n";

        // Check current status without making a network call
        auto status = client.get_status();
        std::cout << "Current status - valid: " << (status.valid ? "yes" : "no");
        if (status.offline) {
            std::cout << " (offline)";
        }
        std::cout << "\n";

        // Check specific entitlements
        auto ent_status = client.check_entitlement("premium_features");
        std::cout << "Premium features: " << (ent_status.active ? "active" : "inactive");
        if (!ent_status.active) {
            std::cout << " (" << ent_status.reason << ")";
        }
        std::cout << "\n";

        // Stop auto-validation when no longer needed
        client.stop_auto_validation();
        std::cout << "Auto-validation stopped.\n";
    }

    // Example 6: Deactivate when done
    std::cout << "\n=== Deactivation ===\n";
    {
        // deactivate requires both license_key and device_id
        auto result = client.deactivate("LICENSE-KEY-HERE", client.device_id());

        if (result.is_ok()) {
            std::cout << "Successfully deactivated.\n";
        } else {
            std::cerr << "Deactivation failed: " << result.error_message() << "\n";
        }
    }

    // Reset clears all cached data and stops timers
    client.reset();
    std::cout << "\nSDK reset complete.\n";

    return 0;
}
