/*
 * LicenseSeat JUCE Compatibility Adapter
 *
 * This adapter intentionally delegates protocol, HTTP, JSON, storage, and
 * cryptographic decisions to the hardened LicenseSeat C++ client. The earlier
 * JUCE-only implementation duplicated those security boundaries and could not
 * safely enforce response limits, duplicate-key rejection, redirect policy,
 * or object lifetime during detached network work.
 *
 * Existing JUCE-facing types are retained, but linking the LicenseSeat core
 * library (and therefore OpenSSL) is now required.
 */

#pragma once

#include "licenseseat/licenseseat.hpp"

#include <JuceHeader.h>
#include <atomic>
#include <functional>
#include <memory>
#include <utility>

class LicenseSeatJuceStandalone {
  public:
    struct ValidationResult {
        bool valid = false;
        juce::String reason;
        juce::String licensee;
        juce::String licenseType;
        juce::StringPairArray metadata;
        juce::StringArray entitlements;
    };

    struct ActivationResult {
        bool success = false;
        juce::String message;
        juce::String activationId;
        int seatsUsed = 0;
        int seatsTotal = 0;
    };

    using ValidationCallback = std::function<void(const ValidationResult& result)>;
    using ActivationCallback = std::function<void(const ActivationResult& result)>;
    using SimpleCallback = std::function<void(bool success, const juce::String& message)>;

    struct Config {
        juce::String apiKey;
        juce::String productSlug;
        juce::String apiUrl = "https://licenseseat.com/api/v1";
        int timeoutMs = 10000;
        int maxRetries = 1;
        juce::String offlinePublicKeyBase64;
        int maxOfflineDays = 0;
        juce::String storagePath;
        bool allowInsecureLoopback = false;
    };

  private:
    struct SharedState {
        explicit SharedState(const Config& config) : client(makeCoreConfig(config)) {}

        static licenseseat::Config makeCoreConfig(const Config& source) {
            licenseseat::Config result;
            result.api_key = source.apiKey.toStdString();
            result.product_slug = source.productSlug.toStdString();
            result.api_url = source.apiUrl.toStdString();
            result.device_id = generateDeviceId().toStdString();
            result.timeout_seconds =
                source.timeoutMs > 0 ? (source.timeoutMs + 999) / 1000 : source.timeoutMs;
            result.max_retries = source.maxRetries;
            result.signing_public_key = source.offlinePublicKeyBase64.toStdString();
            result.max_offline_days = source.maxOfflineDays;
            result.offline_fallback_mode =
                source.maxOfflineDays > 0 ? licenseseat::OfflineFallbackMode::NetworkOnly
                                          : licenseseat::OfflineFallbackMode::Disabled;
            result.storage_path = source.storagePath.toStdString();
            result.allow_insecure_http = source.allowInsecureLoopback;
            return result;
        }

        licenseseat::Client client;
        mutable juce::ReadWriteLock stateLock;
        juce::String currentLicenseKey;
        ValidationResult cachedResult;
        std::atomic<bool> valid{false};
        std::atomic<bool> shuttingDown{false};
    };

  public:
    explicit LicenseSeatJuceStandalone(const Config& config)
        : state(std::make_shared<SharedState>(config)) {}

    LicenseSeatJuceStandalone(const juce::String& apiKey, const juce::String& productSlug,
                              const juce::String& apiUrl = "https://licenseseat.com/api/v1") {
        Config config;
        config.apiKey = apiKey;
        config.productSlug = productSlug;
        config.apiUrl = apiUrl;
        state = std::make_shared<SharedState>(config);
    }

    ~LicenseSeatJuceStandalone() {
        auto current = std::move(state);
        if (current != nullptr)
            current->shuttingDown.store(true, std::memory_order_release);
    }

    LicenseSeatJuceStandalone(const LicenseSeatJuceStandalone&) = delete;
    LicenseSeatJuceStandalone& operator=(const LicenseSeatJuceStandalone&) = delete;
    LicenseSeatJuceStandalone(LicenseSeatJuceStandalone&&) = delete;
    LicenseSeatJuceStandalone& operator=(LicenseSeatJuceStandalone&&) = delete;

    bool isValid() const noexcept {
        const auto current = state;
        return current != nullptr && current->valid.load(std::memory_order_acquire);
    }

    juce::String getDeviceId() const {
        const auto current = state;
        return current == nullptr ? juce::String{} : juce::String(current->client.fingerprint());
    }

    juce::String getLicenseKey() const {
        const auto current = state;
        if (current == nullptr)
            return {};
        const juce::ScopedReadLock lock(current->stateLock);
        return current->currentLicenseKey;
    }

    ValidationResult getCachedResult() const {
        const auto current = state;
        if (current == nullptr)
            return {};
        const juce::ScopedReadLock lock(current->stateLock);
        return current->cachedResult;
    }

    void validateAsync(const juce::String& licenseKey, ValidationCallback callback) {
        const auto current = state;
        if (!canStart(current))
            return;
        const auto key = licenseKey.toStdString();
        const std::weak_ptr<SharedState> weakState = current;
        current->client.validate_async(
            key, [current, weakState, key, callback = std::move(callback)](
                     licenseseat::Result<licenseseat::ValidationResult> result) mutable {
                auto converted = applyValidation(current, key, result);
                postValidation(weakState, std::move(callback), std::move(converted));
            });
    }

    void activateAsync(const juce::String& licenseKey, ActivationCallback callback) {
        const auto current = state;
        if (!canStart(current))
            return;
        const auto key = licenseKey.toStdString();
        const std::weak_ptr<SharedState> weakState = current;
        current->client.activate_async(
            key, [current, weakState, key, callback = std::move(callback)](
                     licenseseat::Result<licenseseat::Activation> activation) mutable {
                if (activation.is_error()) {
                    ActivationResult converted;
                    converted.message = juce::String(activation.error_message());
                    postActivation(weakState, std::move(callback), std::move(converted));
                    return;
                }

                const auto activationId = activation.value().id();
                current->client.validate_async(
                    key,
                    [current, weakState, activationId, callback = std::move(callback),
                     key](licenseseat::Result<licenseseat::ValidationResult> validation) mutable {
                        const auto convertedValidation = applyValidation(current, key, validation);
                        ActivationResult converted;
                        converted.success = convertedValidation.valid;
                        converted.message = converted.success
                                                ? juce::String("Activation successful")
                                                : convertedValidation.reason;
                        converted.activationId = juce::String(activationId);
                        populateSeats(current, converted);
                        postActivation(weakState, std::move(callback), std::move(converted));
                    });
            });
    }

    void deactivateAsync(SimpleCallback callback) {
        const auto current = state;
        if (!canStart(current))
            return;
        juce::String key;
        {
            const juce::ScopedReadLock lock(current->stateLock);
            key = current->currentLicenseKey;
        }
        const std::weak_ptr<SharedState> weakState = current;
        if (key.isEmpty()) {
            postSimple(weakState, std::move(callback), false, "No license to deactivate");
            return;
        }

        const auto fingerprint = current->client.fingerprint();
        current->client.deactivate_async(
            key.toStdString(),
            [current, weakState, callback = std::move(callback)](
                licenseseat::Result<licenseseat::Deactivation> result) mutable {
                const bool success = result.is_ok();
                if (success)
                    clearState(current);
                postSimple(weakState, std::move(callback), success,
                           success ? juce::String("Deactivation successful")
                                   : juce::String(result.error_message()));
            },
            fingerprint);
    }

    void checkEntitlementAsync(const juce::String& licenseKey, const juce::String& entitlementKey,
                               SimpleCallback callback) {
        const auto current = state;
        if (!canStart(current))
            return;
        const auto key = licenseKey.toStdString();
        const auto entitlement = entitlementKey.toStdString();
        const std::weak_ptr<SharedState> weakState = current;
        current->client.validate_async(
            key, [current, weakState, key, entitlement, callback = std::move(callback)](
                     licenseseat::Result<licenseseat::ValidationResult> result) mutable {
                const auto converted = applyValidation(current, key, result);
                bool granted = false;
                if (result.is_ok() && result.value().valid) {
                    for (const auto& item : result.value().license.active_entitlements()) {
                        if (item.key == entitlement) {
                            granted = true;
                            break;
                        }
                    }
                }
                postSimple(weakState, std::move(callback), granted,
                           granted ? juce::String("Entitlement granted")
                                   : (converted.reason.isNotEmpty()
                                          ? converted.reason
                                          : juce::String("Entitlement not available")));
            });
    }

    ValidationResult validate(const juce::String& licenseKey) {
        const auto current = state;
        if (!canStart(current))
            return {};
        const auto key = licenseKey.toStdString();
        return applyValidation(current, key, current->client.validate(key));
    }

    ActivationResult activate(const juce::String& licenseKey) {
        const auto current = state;
        ActivationResult converted;
        if (!canStart(current))
            return converted;
        const auto key = licenseKey.toStdString();
        const auto activation = current->client.activate(key);
        if (activation.is_error()) {
            converted.message = juce::String(activation.error_message());
            return converted;
        }

        const auto validation = applyValidation(current, key, current->client.validate(key));
        converted.success = validation.valid;
        converted.message =
            converted.success ? juce::String("Activation successful") : validation.reason;
        converted.activationId = juce::String(activation.value().id());
        populateSeats(current, converted);
        return converted;
    }

    void reset() {
        const auto current = state;
        if (current == nullptr)
            return;
        current->client.reset();
        clearState(current);
    }

  private:
    static bool canStart(const std::shared_ptr<SharedState>& current) {
        return current != nullptr && !current->shuttingDown.load(std::memory_order_acquire);
    }

    static juce::String generateDeviceId() {
        juce::Array<juce::MACAddress> macs;
        juce::MACAddress::findAllAddresses(macs);
        juce::String combined = juce::SystemStats::getComputerName();
#if JUCE_MAC
        combined += "_mac_";
#elif JUCE_WINDOWS
        combined += "_win_";
#else
        combined += "_linux_";
#endif
        if (!macs.isEmpty())
            combined += macs[0].toString().removeCharacters(":-");
        for (const auto& identifier : juce::SystemStats::getDeviceIdentifiers())
            combined += identifier;
        return juce::SHA256(combined.toUTF8()).toHexString();
    }

    static ValidationResult applyValidation(
        const std::shared_ptr<SharedState>& current, const std::string& requestedKey,
        const licenseseat::Result<licenseseat::ValidationResult>& source) {
        ValidationResult converted;
        if (source.is_error()) {
            converted.reason = juce::String(source.error_message());
        } else {
            converted.valid = source.value().valid;
            converted.reason = juce::String(
                source.value().message.empty() ? source.value().code : source.value().message);
            if (converted.valid) {
                const auto& license = source.value().license;
                converted.licensee = juce::String(license.key());
                converted.licenseType = juce::String(license.plan_key());
                for (const auto& entry : license.metadata())
                    converted.metadata.set(juce::String(entry.first), juce::String(entry.second));
                for (const auto& entitlement : license.active_entitlements())
                    converted.entitlements.add(juce::String(entitlement.key));
            }
        }

        {
            const juce::ScopedWriteLock lock(current->stateLock);
            current->cachedResult = converted;
            if (converted.valid)
                current->currentLicenseKey = juce::String(requestedKey);
            else
                current->currentLicenseKey.clear();
        }
        current->valid.store(converted.valid, std::memory_order_release);
        return converted;
    }

    static void populateSeats(const std::shared_ptr<SharedState>& current,
                              ActivationResult& result) {
        const auto license = current->client.current_license();
        if (!license.has_value())
            return;
        result.seatsUsed = license->active_seats();
        result.seatsTotal = license->seat_limit().value_or(0);
    }

    static void clearState(const std::shared_ptr<SharedState>& current) {
        {
            const juce::ScopedWriteLock lock(current->stateLock);
            current->currentLicenseKey.clear();
            current->cachedResult = ValidationResult{};
        }
        current->valid.store(false, std::memory_order_release);
    }

    template <typename Callback, typename Invoke>
    static void post(const std::weak_ptr<SharedState>& weakState, Callback callback,
                     Invoke invoke) {
        if (!callback)
            return;
        juce::MessageManager::callAsync(
            [weakState, callback = std::move(callback), invoke = std::move(invoke)]() mutable {
                const auto current = weakState.lock();
                if (current != nullptr && !current->shuttingDown.load(std::memory_order_acquire))
                    invoke(callback);
            });
    }

    static void postValidation(const std::weak_ptr<SharedState>& weakState,
                               ValidationCallback callback, ValidationResult result) {
        post(weakState, std::move(callback),
             [result = std::move(result)](ValidationCallback& cb) { cb(result); });
    }

    static void postActivation(const std::weak_ptr<SharedState>& weakState,
                               ActivationCallback callback, ActivationResult result) {
        post(weakState, std::move(callback),
             [result = std::move(result)](ActivationCallback& cb) { cb(result); });
    }

    static void postSimple(const std::weak_ptr<SharedState>& weakState, SimpleCallback callback,
                           bool success, juce::String message) {
        post(weakState, std::move(callback),
             [success, message = std::move(message)](SimpleCallback& cb) { cb(success, message); });
    }

    std::shared_ptr<SharedState> state;

    JUCE_LEAK_DETECTOR(LicenseSeatJuceStandalone)
};
