/*
 * LicenseSeat JUCE Integration Helper
 *
 * A convenience wrapper for using LicenseSeat in JUCE audio plugins.
 * Thread-safe, async-first design for audio plugin requirements.
 *
 * Usage:
 *   LicenseSeatJuce license("your-api-key", "your-product");
 *   license.validateAsync("LICENSE-KEY", [](bool valid) { ... });
 *   if (license.isValid()) { // Allow full features }
 */

#pragma once

#include <JuceHeader.h>
#include "licenseseat/licenseseat.hpp"
#include <memory>
#include <atomic>
#include <functional>

class LicenseSeatJuce
{
public:
    using ValidationCallback = std::function<void(bool valid, const juce::String& message)>;
    using ActivationCallback = std::function<void(bool success, const juce::String& message)>;

    /**
     * Create a license manager
     * @param apiKey Your LicenseSeat API key
     * @param productSlug Your product identifier
     * @param apiUrl Optional custom API URL
     */
    LicenseSeatJuce(const juce::String& apiKey,
                    const juce::String& productSlug,
                    const juce::String& apiUrl = "https://licenseseat.com/api")
    {
        licenseseat::Config config;
        config.api_key = apiKey.toStdString();
        config.product_slug = productSlug.toStdString();
        config.api_url = apiUrl.toStdString();
        config.timeout_seconds = 10;
        config.max_retries = 1;

        client = std::make_unique<licenseseat::Client>(config);
    }

    ~LicenseSeatJuce() = default;

    // Non-copyable
    LicenseSeatJuce(const LicenseSeatJuce&) = delete;
    LicenseSeatJuce& operator=(const LicenseSeatJuce&) = delete;

    /**
     * Check if license is currently valid (cached result)
     * Safe to call from audio thread
     */
    bool isValid() const noexcept
    {
        return valid.load(std::memory_order_relaxed);
    }

    /**
     * Get the current license key
     */
    juce::String getLicenseKey() const
    {
        return juce::String(currentLicenseKey);
    }

    /**
     * Get the device identifier
     */
    juce::String getDeviceId() const
    {
        return juce::String(client->device_identifier());
    }

    /**
     * Validate a license key asynchronously
     * Callback will be invoked on the message thread
     */
    void validateAsync(const juce::String& licenseKey, ValidationCallback callback)
    {
        auto keyStr = licenseKey.toStdString();

        // Run in background thread
        std::thread([this, keyStr, callback]()
        {
            auto result = client->validate(keyStr);

            bool isValid = result.is_ok() && result.value().valid;
            juce::String message;

            if (result.is_error())
            {
                message = juce::String(result.error_message());
            }
            else if (!result.value().valid)
            {
                message = juce::String(result.value().reason);
            }
            else
            {
                message = "License validated successfully";
                currentLicenseKey = keyStr;
            }

            valid.store(isValid, std::memory_order_relaxed);

            // Callback on message thread
            juce::MessageManager::callAsync([callback, isValid, message]()
            {
                if (callback)
                    callback(isValid, message);
            });
        }).detach();
    }

    /**
     * Activate a license key asynchronously
     * Callback will be invoked on the message thread
     */
    void activateAsync(const juce::String& licenseKey, ActivationCallback callback)
    {
        auto keyStr = licenseKey.toStdString();

        std::thread([this, keyStr, callback]()
        {
            auto result = client->activate(keyStr);

            bool success = result.is_ok();
            juce::String message;

            if (result.is_error())
            {
                message = juce::String(result.error_message());
            }
            else
            {
                message = "Activation successful";
                currentLicenseKey = keyStr;

                // Also validate after activation
                auto validateResult = client->validate(keyStr);
                valid.store(validateResult.is_ok() && validateResult.value().valid,
                           std::memory_order_relaxed);
            }

            juce::MessageManager::callAsync([callback, success, message]()
            {
                if (callback)
                    callback(success, message);
            });
        }).detach();
    }

    /**
     * Deactivate the current license asynchronously
     */
    void deactivateAsync(ActivationCallback callback)
    {
        if (currentLicenseKey.empty())
        {
            if (callback)
            {
                juce::MessageManager::callAsync([callback]()
                {
                    callback(false, "No license to deactivate");
                });
            }
            return;
        }

        auto keyStr = currentLicenseKey;

        std::thread([this, keyStr, callback]()
        {
            auto result = client->deactivate(keyStr);

            bool success = result.is_ok();
            juce::String message;

            if (result.is_error())
            {
                message = juce::String(result.error_message());
            }
            else
            {
                message = "Deactivation successful";
                currentLicenseKey.clear();
                valid.store(false, std::memory_order_relaxed);
            }

            juce::MessageManager::callAsync([callback, success, message]()
            {
                if (callback)
                    callback(success, message);
            });
        }).detach();
    }

    /**
     * Reset the license state
     */
    void reset()
    {
        client->reset();
        valid.store(false, std::memory_order_relaxed);
        currentLicenseKey.clear();
    }

    /**
     * Set offline public key for signature verification
     */
    void setOfflinePublicKey(const juce::String& publicKeyBase64)
    {
        // Note: This would need to be set in config before client creation
        // For now, store for reference
        offlinePublicKey = publicKeyBase64.toStdString();
    }

private:
    std::unique_ptr<licenseseat::Client> client;
    std::atomic<bool> valid{false};
    std::string currentLicenseKey;
    std::string offlinePublicKey;
};
