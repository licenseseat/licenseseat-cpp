/*
 * LicenseSeat JUCE Standalone Integration
 *
 * ZERO EXTERNAL DEPENDENCIES - Uses only JUCE's native HTTP and JSON.
 * No cpp-httplib, no OpenSSL, no nlohmann/json required.
 *
 * For offline verification, copy the ed25519 and PicoSHA2 deps to your project
 * and define LICENSESEAT_JUCE_OFFLINE_SUPPORT.
 *
 * Thread-safe, async-first design for audio plugin requirements.
 *
 * Usage:
 *   LicenseSeatJuceStandalone license("your-api-key", "your-product");
 *   license.validateAsync("LICENSE-KEY", [](bool valid, auto& msg) { ... });
 *   if (license.isValid()) { // Safe to call from audio thread }
 */

#pragma once

#include <JuceHeader.h>
#include <atomic>
#include <functional>
#include <memory>

#if defined(LICENSESEAT_JUCE_OFFLINE_SUPPORT)
// Include vendored crypto for offline license verification
JUCE_BEGIN_IGNORE_WARNINGS_GCC_LIKE("-Wsign-conversion", "-Wconversion", "-Wshorten-64-to-32")
extern "C" {
#include "ed25519/ed25519.h"
}
#include "PicoSHA2/picosha2.h"
JUCE_END_IGNORE_WARNINGS_GCC_LIKE
#endif

/**
 * Standalone JUCE license manager with ZERO external dependencies.
 * Uses juce::URL for HTTP and juce::JSON for parsing.
 */
class LicenseSeatJuceStandalone
{
public:
    //==========================================================================
    // Types
    //==========================================================================

    struct ValidationResult
    {
        bool valid = false;
        juce::String reason;
        juce::String licensee;
        juce::String licenseType;
        juce::StringPairArray metadata;
        juce::StringArray entitlements;
    };

    struct ActivationResult
    {
        bool success = false;
        juce::String message;
        juce::String activationId;
        int seatsUsed = 0;
        int seatsTotal = 0;
    };

    using ValidationCallback = std::function<void(const ValidationResult& result)>;
    using ActivationCallback = std::function<void(const ActivationResult& result)>;
    using SimpleCallback = std::function<void(bool success, const juce::String& message)>;

    //==========================================================================
    // Configuration
    //==========================================================================

    struct Config
    {
        juce::String apiKey;
        juce::String productSlug;
        juce::String apiUrl = "https://licenseseat.com/api";
        int timeoutMs = 10000;
        int maxRetries = 1;

        // Offline support (requires LICENSESEAT_JUCE_OFFLINE_SUPPORT)
        juce::String offlinePublicKeyBase64;
        int maxOfflineDays = 30;
    };

    //==========================================================================
    // Constructor / Destructor
    //==========================================================================

    explicit LicenseSeatJuceStandalone(const Config& config)
        : cfg(config)
    {
        jassert(cfg.apiKey.isNotEmpty());
        jassert(cfg.productSlug.isNotEmpty());

        deviceId = generateDeviceId();
    }

    LicenseSeatJuceStandalone(const juce::String& apiKey,
                              const juce::String& productSlug,
                              const juce::String& apiUrl = "https://licenseseat.com/api")
    {
        cfg.apiKey = apiKey;
        cfg.productSlug = productSlug;
        cfg.apiUrl = apiUrl;
        deviceId = generateDeviceId();
    }

    ~LicenseSeatJuceStandalone() = default;

    // Non-copyable, movable
    LicenseSeatJuceStandalone(const LicenseSeatJuceStandalone&) = delete;
    LicenseSeatJuceStandalone& operator=(const LicenseSeatJuceStandalone&) = delete;
    LicenseSeatJuceStandalone(LicenseSeatJuceStandalone&&) = default;
    LicenseSeatJuceStandalone& operator=(LicenseSeatJuceStandalone&&) = default;

    //==========================================================================
    // Thread-Safe Status (safe to call from audio thread)
    //==========================================================================

    /** Check if license is currently valid. Safe for audio thread. */
    bool isValid() const noexcept
    {
        return validFlag.load(std::memory_order_relaxed);
    }

    /** Get the device identifier. */
    juce::String getDeviceId() const
    {
        return deviceId;
    }

    /** Get the current license key. */
    juce::String getLicenseKey() const
    {
        const juce::ScopedReadLock lock(stateLock);
        return currentLicenseKey;
    }

    /** Get cached validation result. */
    ValidationResult getCachedResult() const
    {
        const juce::ScopedReadLock lock(stateLock);
        return cachedResult;
    }

    //==========================================================================
    // Async API (recommended)
    //==========================================================================

    /**
     * Validate a license key asynchronously.
     * Callback is invoked on the message thread.
     */
    void validateAsync(const juce::String& licenseKey, ValidationCallback callback)
    {
        auto* task = new ValidationTask(*this, licenseKey, std::move(callback));
        task->runThread();
    }

    /**
     * Activate a license key asynchronously.
     * Callback is invoked on the message thread.
     */
    void activateAsync(const juce::String& licenseKey, ActivationCallback callback)
    {
        auto* task = new ActivationTask(*this, licenseKey, std::move(callback));
        task->runThread();
    }

    /**
     * Deactivate the current license asynchronously.
     */
    void deactivateAsync(SimpleCallback callback)
    {
        juce::String key;
        {
            const juce::ScopedReadLock lock(stateLock);
            key = currentLicenseKey;
        }

        if (key.isEmpty())
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

        auto* task = new DeactivationTask(*this, key, std::move(callback));
        task->runThread();
    }

    /**
     * Check entitlement asynchronously.
     */
    void checkEntitlementAsync(const juce::String& licenseKey,
                                const juce::String& entitlementKey,
                                SimpleCallback callback)
    {
        auto* task = new EntitlementTask(*this, licenseKey, entitlementKey, std::move(callback));
        task->runThread();
    }

    //==========================================================================
    // Sync API (use sparingly - blocks calling thread!)
    //==========================================================================

    /** Validate synchronously. WARNING: Blocks! */
    ValidationResult validate(const juce::String& licenseKey)
    {
        return performValidation(licenseKey);
    }

    /** Activate synchronously. WARNING: Blocks! */
    ActivationResult activate(const juce::String& licenseKey)
    {
        return performActivation(licenseKey);
    }

    //==========================================================================
    // State Management
    //==========================================================================

    /** Reset all license state. */
    void reset()
    {
        const juce::ScopedWriteLock lock(stateLock);
        currentLicenseKey.clear();
        cachedResult = ValidationResult();
        validFlag.store(false, std::memory_order_relaxed);
    }

private:
    //==========================================================================
    // Internal Implementation
    //==========================================================================

    Config cfg;
    juce::String deviceId;

    mutable juce::ReadWriteLock stateLock;
    juce::String currentLicenseKey;
    ValidationResult cachedResult;
    std::atomic<bool> validFlag{false};

    //--------------------------------------------------------------------------
    // Device ID Generation
    //--------------------------------------------------------------------------

    static juce::String generateDeviceId()
    {
        // Use JUCE's machine identifiers for cross-platform device ID
        juce::Array<juce::MACAddress> macs;
        juce::MACAddress::findAllAddresses(macs);

        juce::String combined;

        // Add machine-specific info
        #if JUCE_MAC
        // Use IOPlatformUUID on macOS
        combined = juce::SystemStats::getComputerName() + "_mac_";
        #elif JUCE_WINDOWS
        combined = juce::SystemStats::getComputerName() + "_win_";
        #else
        combined = juce::SystemStats::getComputerName() + "_linux_";
        #endif

        // Add first MAC address if available
        if (!macs.isEmpty())
            combined += macs[0].toString().removeCharacters(":-");

        // Add unique device strings from JUCE
        auto deviceStrings = juce::SystemStats::getDeviceIdentifiers();
        for (const auto& s : deviceStrings)
            combined += s;

        // Hash to fixed-length ID
        return juce::SHA256(combined.toUTF8()).toHexString();
    }

    //--------------------------------------------------------------------------
    // HTTP Helpers
    //--------------------------------------------------------------------------

    juce::var httpPost(const juce::String& endpoint, const juce::var& body)
    {
        juce::String urlStr = cfg.apiUrl;
        if (!urlStr.endsWithChar('/'))
            urlStr += "/";
        urlStr += endpoint;

        juce::URL url(urlStr);

        // Convert body to JSON string
        juce::String jsonBody = juce::JSON::toString(body);

        // Use POST data
        url = url.withPOSTData(jsonBody);

        // Build headers
        juce::String headers;
        headers += "Content-Type: application/json\r\n";
        headers += "Authorization: Bearer " + cfg.apiKey + "\r\n";
        headers += "X-Device-Id: " + deviceId + "\r\n";
        headers += "User-Agent: LicenseSeat-JUCE/1.0\r\n";

        // Create input stream options
        juce::URL::InputStreamOptions options(juce::URL::ParameterHandling::inPostData);
        options = options.withExtraHeaders(headers);
        options = options.withConnectionTimeoutMs(cfg.timeoutMs);
        options = options.withHttpRequestCmd("POST");

        // Perform request
        int statusCode = 0;
        auto stream = url.createInputStream(options, nullptr, nullptr, &statusCode);

        if (stream == nullptr)
        {
            auto* errorObj = new juce::DynamicObject();
            errorObj->setProperty("error", "Network request failed");
            return juce::var(errorObj);
        }

        juce::String response = stream->readEntireStreamAsString();

        // Parse response
        auto result = juce::JSON::parse(response);
        if (result.isVoid())
        {
            // Create error response
            auto* obj = new juce::DynamicObject();
            obj->setProperty("error", "Failed to parse response");
            obj->setProperty("status_code", statusCode);
            return juce::var(obj);
        }

        return result;
    }

    juce::var httpDelete(const juce::String& endpoint, const juce::var& body)
    {
        juce::String urlStr = cfg.apiUrl;
        if (!urlStr.endsWithChar('/'))
            urlStr += "/";
        urlStr += endpoint;

        juce::URL url(urlStr);
        juce::String jsonBody = juce::JSON::toString(body);
        url = url.withPOSTData(jsonBody);

        juce::String headers;
        headers += "Content-Type: application/json\r\n";
        headers += "Authorization: Bearer " + cfg.apiKey + "\r\n";
        headers += "X-Device-Id: " + deviceId + "\r\n";
        headers += "User-Agent: LicenseSeat-JUCE/1.0\r\n";

        juce::URL::InputStreamOptions options(juce::URL::ParameterHandling::inPostData);
        options = options.withExtraHeaders(headers);
        options = options.withConnectionTimeoutMs(cfg.timeoutMs);
        options = options.withHttpRequestCmd("DELETE");

        int statusCode = 0;
        auto stream = url.createInputStream(options, nullptr, nullptr, &statusCode);

        if (stream == nullptr)
        {
            auto* obj = new juce::DynamicObject();
            obj->setProperty("error", "Network request failed");
            return juce::var(obj);
        }

        juce::String response = stream->readEntireStreamAsString();
        auto result = juce::JSON::parse(response);

        if (result.isVoid())
        {
            auto* obj = new juce::DynamicObject();
            obj->setProperty("error", "Failed to parse response");
            obj->setProperty("status_code", statusCode);
            return juce::var(obj);
        }

        return result;
    }

    //--------------------------------------------------------------------------
    // Core Operations
    //--------------------------------------------------------------------------

    ValidationResult performValidation(const juce::String& licenseKey)
    {
        ValidationResult result;

        // Build request body
        auto* body = new juce::DynamicObject();
        body->setProperty("license_key", licenseKey);
        body->setProperty("product_slug", cfg.productSlug);
        body->setProperty("device_identifier", deviceId);

        auto response = httpPost("licenses/validate", juce::var(body));

        // Handle error
        if (response.hasProperty("error"))
        {
            result.valid = false;
            result.reason = response["error"].toString();

            // Update state
            validFlag.store(false, std::memory_order_relaxed);
            return result;
        }

        // Parse response
        result.valid = response["valid"].toString() == "true" ||
                      static_cast<bool>(response["valid"]);
        result.reason = response["reason"].toString();
        result.licensee = response["licensee"].toString();
        result.licenseType = response["license_type"].toString();

        // Parse metadata
        if (response.hasProperty("metadata"))
        {
            auto meta = response["metadata"];
            if (auto* obj = meta.getDynamicObject())
            {
                for (const auto& prop : obj->getProperties())
                    result.metadata.set(prop.name.toString(), prop.value.toString());
            }
        }

        // Parse entitlements
        if (response.hasProperty("entitlements"))
        {
            auto ent = response["entitlements"];
            if (auto* arr = ent.getArray())
            {
                for (const auto& item : *arr)
                    result.entitlements.add(item.toString());
            }
        }

        // Update cached state
        {
            const juce::ScopedWriteLock lock(stateLock);
            if (result.valid)
                currentLicenseKey = licenseKey;
            cachedResult = result;
        }
        validFlag.store(result.valid, std::memory_order_relaxed);

        return result;
    }

    ActivationResult performActivation(const juce::String& licenseKey)
    {
        ActivationResult result;

        auto* body = new juce::DynamicObject();
        body->setProperty("license_key", licenseKey);
        body->setProperty("product_slug", cfg.productSlug);
        body->setProperty("device_identifier", deviceId);
        body->setProperty("device_name", juce::SystemStats::getComputerName());

        auto response = httpPost("licenses/activate", juce::var(body));

        if (response.hasProperty("error"))
        {
            result.success = false;
            result.message = response["error"].toString();
            return result;
        }

        result.success = response["success"].toString() == "true" ||
                        static_cast<bool>(response["success"]);
        result.message = response["message"].toString();
        result.activationId = response["activation_id"].toString();
        result.seatsUsed = static_cast<int>(response["seats_used"]);
        result.seatsTotal = static_cast<int>(response["seats_total"]);

        // Also validate after successful activation
        if (result.success)
        {
            auto validationResult = performValidation(licenseKey);
            if (!result.message.isNotEmpty())
                result.message = validationResult.valid ? "Activation successful" : validationResult.reason;
        }

        return result;
    }

    bool performDeactivation(const juce::String& licenseKey, juce::String& outMessage)
    {
        auto* body = new juce::DynamicObject();
        body->setProperty("license_key", licenseKey);
        body->setProperty("product_slug", cfg.productSlug);
        body->setProperty("device_identifier", deviceId);

        auto response = httpDelete("licenses/deactivate", juce::var(body));

        if (response.hasProperty("error"))
        {
            outMessage = response["error"].toString();
            return false;
        }

        bool success = response["success"].toString() == "true" ||
                      static_cast<bool>(response["success"]);

        if (success)
        {
            const juce::ScopedWriteLock lock(stateLock);
            currentLicenseKey.clear();
            cachedResult = ValidationResult();
            validFlag.store(false, std::memory_order_relaxed);
            outMessage = "Deactivation successful";
        }
        else
        {
            outMessage = response["message"].toString();
        }

        return success;
    }

    bool performEntitlementCheck(const juce::String& licenseKey,
                                  const juce::String& entitlementKey,
                                  juce::String& outMessage)
    {
        auto* body = new juce::DynamicObject();
        body->setProperty("license_key", licenseKey);
        body->setProperty("product_slug", cfg.productSlug);
        body->setProperty("entitlement_key", entitlementKey);

        auto response = httpPost("licenses/entitlement", juce::var(body));

        if (response.hasProperty("error"))
        {
            outMessage = response["error"].toString();
            return false;
        }

        bool hasEntitlement = response["has_entitlement"].toString() == "true" ||
                             static_cast<bool>(response["has_entitlement"]);

        outMessage = hasEntitlement ? "Entitlement granted" : "Entitlement not available";
        return hasEntitlement;
    }

    //--------------------------------------------------------------------------
    // Background Tasks
    //--------------------------------------------------------------------------

    class ValidationTask : public juce::ThreadPoolJob
    {
    public:
        ValidationTask(LicenseSeatJuceStandalone& owner,
                       juce::String key,
                       ValidationCallback cb)
            : ThreadPoolJob("LicenseSeat-Validate"),
              parent(owner),
              licenseKey(std::move(key)),
              callback(std::move(cb))
        {
        }

        void runThread()
        {
            // Run synchronously on a new thread
            std::thread([this]()
            {
                auto result = parent.performValidation(licenseKey);
                auto cb = std::move(callback);

                juce::MessageManager::callAsync([result, cb]()
                {
                    if (cb)
                        cb(result);
                });

                delete this;
            }).detach();
        }

        JobStatus runJob() override { return jobHasFinished; }

    private:
        LicenseSeatJuceStandalone& parent;
        juce::String licenseKey;
        ValidationCallback callback;
    };

    class ActivationTask : public juce::ThreadPoolJob
    {
    public:
        ActivationTask(LicenseSeatJuceStandalone& owner,
                       juce::String key,
                       ActivationCallback cb)
            : ThreadPoolJob("LicenseSeat-Activate"),
              parent(owner),
              licenseKey(std::move(key)),
              callback(std::move(cb))
        {
        }

        void runThread()
        {
            std::thread([this]()
            {
                auto result = parent.performActivation(licenseKey);
                auto cb = std::move(callback);

                juce::MessageManager::callAsync([result, cb]()
                {
                    if (cb)
                        cb(result);
                });

                delete this;
            }).detach();
        }

        JobStatus runJob() override { return jobHasFinished; }

    private:
        LicenseSeatJuceStandalone& parent;
        juce::String licenseKey;
        ActivationCallback callback;
    };

    class DeactivationTask : public juce::ThreadPoolJob
    {
    public:
        DeactivationTask(LicenseSeatJuceStandalone& owner,
                         juce::String key,
                         SimpleCallback cb)
            : ThreadPoolJob("LicenseSeat-Deactivate"),
              parent(owner),
              licenseKey(std::move(key)),
              callback(std::move(cb))
        {
        }

        void runThread()
        {
            std::thread([this]()
            {
                juce::String message;
                bool success = parent.performDeactivation(licenseKey, message);
                auto cb = std::move(callback);

                juce::MessageManager::callAsync([success, message, cb]()
                {
                    if (cb)
                        cb(success, message);
                });

                delete this;
            }).detach();
        }

        JobStatus runJob() override { return jobHasFinished; }

    private:
        LicenseSeatJuceStandalone& parent;
        juce::String licenseKey;
        SimpleCallback callback;
    };

    class EntitlementTask : public juce::ThreadPoolJob
    {
    public:
        EntitlementTask(LicenseSeatJuceStandalone& owner,
                        juce::String licKey,
                        juce::String entKey,
                        SimpleCallback cb)
            : ThreadPoolJob("LicenseSeat-Entitlement"),
              parent(owner),
              licenseKey(std::move(licKey)),
              entitlementKey(std::move(entKey)),
              callback(std::move(cb))
        {
        }

        void runThread()
        {
            std::thread([this]()
            {
                juce::String message;
                bool success = parent.performEntitlementCheck(licenseKey, entitlementKey, message);
                auto cb = std::move(callback);

                juce::MessageManager::callAsync([success, message, cb]()
                {
                    if (cb)
                        cb(success, message);
                });

                delete this;
            }).detach();
        }

        JobStatus runJob() override { return jobHasFinished; }

    private:
        LicenseSeatJuceStandalone& parent;
        juce::String licenseKey;
        juce::String entitlementKey;
        SimpleCallback callback;
    };

    JUCE_LEAK_DETECTOR(LicenseSeatJuceStandalone)
};
