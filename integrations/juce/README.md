# LicenseSeat JUCE integration

These adapters expose JUCE-friendly types and message-thread callbacks while delegating all protocol, HTTP, JSON, storage, and cryptographic work to the hardened LicenseSeat C++ client.

Both headers require the core `licenseseat::licenseseat` target and OpenSSL. The class name `LicenseSeatJuceStandalone` is retained for source compatibility; it is no longer a separate JUCE-only protocol implementation. Maintaining a second security boundary without strict JSON parsing, bounded responses, redirect control, and authenticated offline verification was not safe.

## Requirements

- C++17
- JUCE 6.1 or newer
- LicenseSeat C++ SDK
- OpenSSL, as required by the core SDK

Add the SDK with CMake and link it to the target that includes the adapter:

```cmake
add_subdirectory(path/to/licenseseat-cpp)
target_link_libraries(MyPlugin PRIVATE licenseseat::licenseseat)
```

## Recommended adapter

```cpp
#include "LicenseSeatJuce.h"

class PluginLicenseState
{
public:
    PluginLicenseState()
        : license("YOUR_API_KEY", "your-product")
    {
    }

    void validate(const juce::String& key)
    {
        license.validateAsync(key, [](bool valid, const juce::String& message)
        {
            // Runs on the JUCE message thread.
            juce::Logger::writeToLog(message);
        });
    }

    bool mayProcessAudio() const noexcept
    {
        // Cached atomic state only; no allocation, lock, disk, or network I/O.
        return license.isValid();
    }

private:
    LicenseSeatJuce license;
};
```

`validateAsync`, `activateAsync`, and `deactivateAsync` run through the core client's managed workers. Queued JUCE callbacks are suppressed after the adapter is destroyed.

## Compatibility adapter

Existing code using `LicenseSeatJuceStandalone` can keep its JUCE-facing result types:

```cpp
#include "LicenseSeatJuceStandalone.h"

LicenseSeatJuceStandalone::Config config;
config.apiKey = "YOUR_API_KEY";
config.productSlug = "your-product";
config.storagePath = userDataDirectory.getFullPathName();
config.offlinePublicKeyBase64 = "YOUR_ED25519_PUBLIC_KEY";
config.maxOfflineDays = 30;

LicenseSeatJuceStandalone license(config);

license.validateAsync(key, [](const auto& result)
{
    if (!result.valid)
        juce::Logger::writeToLog(result.reason);
});
```

The compatibility adapter supports:

- `validateAsync` / `validate`
- `activateAsync` / `activate`
- `deactivateAsync`
- `checkEntitlementAsync`
- cached `isValid`, `getLicenseKey`, and `getCachedResult`
- core-backed secure storage and offline verification when configured

## Security requirements

- Production API URLs must use HTTPS. Plain HTTP is accepted only for loopback development when `allowInsecureLoopback` is explicitly enabled.
- Never log or place license keys or API keys in URLs. The core client sends license keys in bounded JSON request bodies.
- Do not perform synchronous validation or activation on the audio or message thread.
- Keep TLS verification enabled. The adapters do not expose an option to disable it for remote hosts.
- Use an application-private, user-writable directory for `storagePath`; the core storage layer applies owner-only permissions and rejects symlinks.
- Treat `isValid()` as cached authorization state. It performs no network refresh by itself.

## Lifetime behavior

The adapters use shared operation state instead of detached threads that capture raw owner pointers. Destruction marks the state as shutting down, prevents new work, and suppresses callbacks already queued for the JUCE message thread. The core client safely drains or reaps in-flight work, including destruction initiated by one of its own callbacks.
