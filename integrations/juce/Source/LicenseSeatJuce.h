/*
 * LicenseSeat JUCE Integration Helper
 *
 * A lifetime-safe adapter around the hardened LicenseSeat C++ client. Network
 * work runs on the core client's managed workers and user callbacks are
 * marshalled to JUCE's message thread.
 */

#pragma once

#include "licenseseat/licenseseat.hpp"

#include <JuceHeader.h>
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

class LicenseSeatJuce {
  private:
    struct SharedState {
        explicit SharedState(licenseseat::Config config) : client(std::move(config)) {}

        licenseseat::Client client;
        std::atomic<bool> valid{false};
        std::atomic<bool> shuttingDown{false};
        mutable std::mutex mutex;
        std::string currentLicenseKey;
    };

  public:
    using ValidationCallback = std::function<void(bool valid, const juce::String& message)>;
    using ActivationCallback = std::function<void(bool success, const juce::String& message)>;

    LicenseSeatJuce(const juce::String& apiKey, const juce::String& productSlug,
                    const juce::String& apiUrl = "https://licenseseat.com/api/v1") {
        licenseseat::Config config;
        config.api_key = apiKey.toStdString();
        config.product_slug = productSlug.toStdString();
        config.api_url = apiUrl.toStdString();
        config.timeout_seconds = 10;
        config.max_retries = 1;
        state = std::make_shared<SharedState>(std::move(config));
    }

    ~LicenseSeatJuce() {
        auto current = std::move(state);
        if (current != nullptr)
            current->shuttingDown.store(true, std::memory_order_release);
    }

    LicenseSeatJuce(const LicenseSeatJuce&) = delete;
    LicenseSeatJuce& operator=(const LicenseSeatJuce&) = delete;
    LicenseSeatJuce(LicenseSeatJuce&&) = delete;
    LicenseSeatJuce& operator=(LicenseSeatJuce&&) = delete;

    /** Lock-free cached status; safe to call from the audio thread. */
    bool isValid() const noexcept {
        const auto current = state;
        return current != nullptr && current->valid.load(std::memory_order_acquire);
    }

    juce::String getLicenseKey() const {
        const auto current = state;
        if (current == nullptr)
            return {};
        const std::lock_guard<std::mutex> lock(current->mutex);
        return juce::String(current->currentLicenseKey);
    }

    juce::String getDeviceId() const {
        const auto current = state;
        return current == nullptr ? juce::String{} : juce::String(current->client.fingerprint());
    }

    void validateAsync(const juce::String& licenseKey, ValidationCallback callback) {
        const auto current = state;
        if (current == nullptr || current->shuttingDown.load(std::memory_order_acquire))
            return;
        const auto key = licenseKey.toStdString();
        const std::weak_ptr<SharedState> weakState = current;

        current->client.validate_async(
            key, [current, weakState, key, callback = std::move(callback)](
                     licenseseat::Result<licenseseat::ValidationResult> result) mutable {
                const bool isValid = result.is_ok() && result.value().valid;
                juce::String message;
                if (result.is_error())
                    message = juce::String(result.error_message());
                else if (!result.value().valid)
                    message = juce::String(result.value().message.empty() ? result.value().code
                                                                          : result.value().message);
                else
                    message = "License validated successfully";

                if (isValid) {
                    const std::lock_guard<std::mutex> lock(current->mutex);
                    current->currentLicenseKey = key;
                }
                current->valid.store(isValid, std::memory_order_release);
                postValidationCallback(weakState, std::move(callback), isValid, message);
            });
    }

    void activateAsync(const juce::String& licenseKey, ActivationCallback callback) {
        const auto current = state;
        if (current == nullptr || current->shuttingDown.load(std::memory_order_acquire))
            return;
        const auto key = licenseKey.toStdString();
        const std::weak_ptr<SharedState> weakState = current;

        current->client.activate_async(
            key, [current, weakState, key, callback = std::move(callback)](
                     licenseseat::Result<licenseseat::Activation> result) mutable {
                if (result.is_error()) {
                    postActivationCallback(weakState, std::move(callback), false,
                                           juce::String(result.error_message()));
                    return;
                }

                {
                    const std::lock_guard<std::mutex> lock(current->mutex);
                    current->currentLicenseKey = key;
                }
                current->client.validate_async(
                    key,
                    [current, weakState, callback = std::move(callback)](
                        licenseseat::Result<licenseseat::ValidationResult> validation) mutable {
                        const bool valid = validation.is_ok() && validation.value().valid;
                        current->valid.store(valid, std::memory_order_release);
                        const juce::String message =
                            valid
                                ? juce::String("Activation successful")
                                : juce::String(validation.is_error() ? validation.error_message()
                                                                     : validation.value().message);
                        postActivationCallback(weakState, std::move(callback), valid, message);
                    });
            });
    }

    void deactivateAsync(ActivationCallback callback) {
        const auto current = state;
        if (current == nullptr || current->shuttingDown.load(std::memory_order_acquire))
            return;

        std::string key;
        {
            const std::lock_guard<std::mutex> lock(current->mutex);
            key = current->currentLicenseKey;
        }
        const std::weak_ptr<SharedState> weakState = current;
        if (key.empty()) {
            postActivationCallback(weakState, std::move(callback), false,
                                   "No license to deactivate");
            return;
        }

        const auto fingerprint = current->client.fingerprint();
        current->client.deactivate_async(
            key,
            [current, weakState, callback = std::move(callback)](
                licenseseat::Result<licenseseat::Deactivation> result) mutable {
                const bool success = result.is_ok();
                if (success) {
                    const std::lock_guard<std::mutex> lock(current->mutex);
                    current->currentLicenseKey.clear();
                    current->valid.store(false, std::memory_order_release);
                }
                postActivationCallback(weakState, std::move(callback), success,
                                       success ? juce::String("Deactivation successful")
                                               : juce::String(result.error_message()));
            },
            fingerprint);
    }

    void reset() {
        const auto current = state;
        if (current == nullptr)
            return;
        current->client.reset();
        current->valid.store(false, std::memory_order_release);
        const std::lock_guard<std::mutex> lock(current->mutex);
        current->currentLicenseKey.clear();
    }

  private:
    static void postValidationCallback(const std::weak_ptr<SharedState>& weakState,
                                       ValidationCallback callback, bool valid,
                                       juce::String message) {
        if (!callback)
            return;
        juce::MessageManager::callAsync([weakState, callback = std::move(callback), valid,
                                         message = std::move(message)]() mutable {
            const auto current = weakState.lock();
            if (current != nullptr && !current->shuttingDown.load(std::memory_order_acquire))
                callback(valid, message);
        });
    }

    static void postActivationCallback(const std::weak_ptr<SharedState>& weakState,
                                       ActivationCallback callback, bool success,
                                       juce::String message) {
        if (!callback)
            return;
        juce::MessageManager::callAsync([weakState, callback = std::move(callback), success,
                                         message = std::move(message)]() mutable {
            const auto current = weakState.lock();
            if (current != nullptr && !current->shuttingDown.load(std::memory_order_acquire))
                callback(success, message);
        });
    }

    std::shared_ptr<SharedState> state;
};
