# LicenseSeat JUCE Integration

License management for JUCE-based audio plugins (VST3, AU, AAX).

## Features

- **Zero External Dependencies** - Uses only JUCE's native HTTP and JSON
- **Single Header** - Drop `LicenseSeatJuceStandalone.h` into your project
- **Thread-Safe** - `std::atomic<bool>` for audio-thread-safe status checks
- **Async-First** - Non-blocking API with message thread callbacks
- **Multi-Instance Safe** - No global state, each instance is independent
- **Offline Support** - Optional Ed25519 signature verification
- **Cross-Platform** - Windows, macOS, Linux

## Quick Start

### 1. Add the Header

Copy `Source/LicenseSeatJuceStandalone.h` to your JUCE project. That's it - no other files needed!

```
YourPlugin/
├── Source/
│   ├── PluginProcessor.cpp
│   ├── PluginProcessor.h
│   └── LicenseSeatJuceStandalone.h   // <-- Just this one file!
```

### 2. Use in Your Plugin

```cpp
// PluginProcessor.h
#pragma once

#include <JuceHeader.h>
#include "LicenseSeatJuceStandalone.h"

class MyPluginProcessor : public juce::AudioProcessor
{
public:
    MyPluginProcessor();

    // Safe to call from audio thread!
    bool isLicenseValid() const { return license.isValid(); }

    void validateLicense(const juce::String& key);

private:
    LicenseSeatJuceStandalone license;

    JUCE_DECLARE_NON_COPYABLE_WITH_LEAK_DETECTOR(MyPluginProcessor)
};
```

```cpp
// PluginProcessor.cpp
#include "PluginProcessor.h"

MyPluginProcessor::MyPluginProcessor()
    : license("your-api-key", "your-product-slug")
{
    // Optionally validate stored license on startup
    auto savedKey = loadLicenseFromSettings();
    if (savedKey.isNotEmpty())
        validateLicense(savedKey);
}

void MyPluginProcessor::validateLicense(const juce::String& key)
{
    license.validateAsync(key, [this](const auto& result)
    {
        // This callback runs on the message thread
        if (result.valid)
        {
            saveLicenseToSettings(key);
            // Update UI to show "Licensed to: " + result.licensee
        }
        else
        {
            // Show error: result.reason
        }
    });
}
```

### 3. Use in processBlock (Audio Thread Safe!)

```cpp
void MyPluginProcessor::processBlock(juce::AudioBuffer<float>& buffer, juce::MidiBuffer&)
{
    // isValid() uses std::atomic - safe for audio thread!
    if (!license.isValid())
    {
        // Demo mode: output silence or add periodic noise
        buffer.clear();
        return;
    }

    // Full processing for licensed users
    // ...
}
```

## Complete Example with License Dialog

```cpp
// LicenseComponent.h
class LicenseComponent : public juce::Component
{
public:
    LicenseComponent(LicenseSeatJuceStandalone& lic)
        : license(lic)
    {
        addAndMakeVisible(keyInput);
        keyInput.setTextToShowWhenEmpty("Enter license key...", juce::Colours::grey);

        addAndMakeVisible(activateButton);
        activateButton.setButtonText("Activate");
        activateButton.onClick = [this]() { onActivate(); };

        addAndMakeVisible(statusLabel);
        updateStatus();

        setSize(400, 150);
    }

    void resized() override
    {
        auto area = getLocalBounds().reduced(20);
        keyInput.setBounds(area.removeFromTop(30));
        area.removeFromTop(10);
        activateButton.setBounds(area.removeFromTop(30).withWidth(100));
        area.removeFromTop(10);
        statusLabel.setBounds(area);
    }

private:
    void onActivate()
    {
        statusLabel.setText("Activating...", juce::dontSendNotification);
        activateButton.setEnabled(false);

        license.activateAsync(keyInput.getText(),
            [this](const LicenseSeatJuceStandalone::ActivationResult& result)
            {
                activateButton.setEnabled(true);

                if (result.success)
                {
                    statusLabel.setText("Licensed! Seats: " +
                        juce::String(result.seatsUsed) + "/" +
                        juce::String(result.seatsTotal),
                        juce::dontSendNotification);
                    statusLabel.setColour(juce::Label::textColourId, juce::Colours::green);
                }
                else
                {
                    statusLabel.setText("Error: " + result.message,
                        juce::dontSendNotification);
                    statusLabel.setColour(juce::Label::textColourId, juce::Colours::red);
                }
            });
    }

    void updateStatus()
    {
        if (license.isValid())
        {
            auto result = license.getCachedResult();
            statusLabel.setText("Licensed to: " + result.licensee,
                juce::dontSendNotification);
            statusLabel.setColour(juce::Label::textColourId, juce::Colours::green);
        }
        else
        {
            statusLabel.setText("Not licensed", juce::dontSendNotification);
            statusLabel.setColour(juce::Label::textColourId, juce::Colours::grey);
        }
    }

    LicenseSeatJuceStandalone& license;
    juce::TextEditor keyInput;
    juce::TextButton activateButton;
    juce::Label statusLabel;
};
```

## API Reference

### Configuration

```cpp
LicenseSeatJuceStandalone::Config config;
config.apiKey = "your-api-key";
config.productSlug = "your-product";
config.apiUrl = "https://licenseseat.com/api";  // Optional
config.timeoutMs = 10000;                        // Optional (default: 10s)
config.maxRetries = 1;                           // Optional

// For offline support (requires LICENSESEAT_JUCE_OFFLINE_SUPPORT define)
config.offlinePublicKeyBase64 = "your-ed25519-public-key";
config.maxOfflineDays = 30;

LicenseSeatJuceStandalone license(config);
```

### Methods

| Method                                              | Thread Safety | Description                                   |
| --------------------------------------------------- | ------------- | --------------------------------------------- |
| `isValid()`                                         | Audio-safe    | Check if license is valid (atomic read)       |
| `getDeviceId()`                                     | Safe          | Get device identifier                         |
| `getLicenseKey()`                                   | Safe          | Get current license key                       |
| `getCachedResult()`                                 | Safe          | Get cached validation result                  |
| `validateAsync(key, callback)`                      | Safe          | Async validation (callback on message thread) |
| `activateAsync(key, callback)`                      | Safe          | Async activation (callback on message thread) |
| `deactivateAsync(callback)`                         | Safe          | Async deactivation                            |
| `checkEntitlementAsync(key, entitlement, callback)` | Safe          | Check specific entitlement                    |
| `validate(key)`                                     | **Blocks!**   | Sync validation (avoid in plugins!)           |
| `activate(key)`                                     | **Blocks!**   | Sync activation (avoid in plugins!)           |
| `reset()`                                           | Safe          | Clear all license state                       |

### Result Types

```cpp
struct ValidationResult {
    bool valid;
    juce::String reason;
    juce::String licensee;
    juce::String licenseType;
    juce::StringPairArray metadata;
    juce::StringArray entitlements;
};

struct ActivationResult {
    bool success;
    juce::String message;
    juce::String activationId;
    int seatsUsed;
    int seatsTotal;
};
```

## Best Practices for Audio Plugins

### 1. Never Block the Audio Thread

```cpp
// WRONG - blocks audio thread!
void processBlock(...) {
    auto result = license.validate(key);  // BLOCKS!
}

// RIGHT - read atomic flag
void processBlock(...) {
    if (!license.isValid()) {  // Just reads std::atomic
        buffer.clear();
        return;
    }
}
```

### 2. Validate on Startup

```cpp
MyPluginProcessor()
    : license("api-key", "product")
{
    auto savedKey = loadKey();
    if (savedKey.isNotEmpty()) {
        license.validateAsync(savedKey, [](auto& result) {
            // Update UI if needed
        });
    }
}
```

### 3. Multiple Plugin Instances Work Fine

```cpp
// Each instance has its own LicenseSeatJuceStandalone
// No global state, no conflicts between instances
// Safe to run 10+ instances in the same DAW
```

### 4. Handle Demo Mode Gracefully

```cpp
void processBlock(juce::AudioBuffer<float>& buffer, ...) {
    if (!license.isValid()) {
        // Option 1: Output silence
        buffer.clear();

        // Option 2: Add periodic noise reminder
        static int counter = 0;
        if (++counter % 44100 == 0) {  // Every second at 44.1kHz
            for (int ch = 0; ch < buffer.getNumChannels(); ++ch)
                buffer.setSample(ch, 0, 0.1f * (rand() / (float)RAND_MAX));
        }

        // Option 3: Limit to 30 seconds
        // Option 4: Disable premium features only
        return;
    }
    // Full processing
}
```

### 5. Store License Key Securely

```cpp
void saveLicenseToSettings(const juce::String& key) {
    auto appProps = juce::ApplicationProperties();
    appProps.getUserSettings()->setValue("license_key", key);
    appProps.saveIfNeeded();
}

juce::String loadLicenseFromSettings() {
    auto appProps = juce::ApplicationProperties();
    return appProps.getUserSettings()->getValue("license_key", "");
}
```

## Offline License Support

For offline verification (requires vendored crypto):

1. Define `LICENSESEAT_JUCE_OFFLINE_SUPPORT` before including the header
2. Add `ed25519/` and `PicoSHA2/` to your project
3. Configure your offline public key

```cpp
#define LICENSESEAT_JUCE_OFFLINE_SUPPORT
#include "LicenseSeatJuceStandalone.h"

LicenseSeatJuceStandalone::Config config;
config.apiKey = "your-api-key";
config.productSlug = "your-product";
config.offlinePublicKeyBase64 = "your-ed25519-public-key";
config.maxOfflineDays = 30;

LicenseSeatJuceStandalone license(config);
```

## Comparison: Standalone vs Full SDK

| Feature      | LicenseSeatJuceStandalone | Full SDK (LicenseSeatJuce.h)        |
| ------------ | ------------------------- | ----------------------------------- |
| Dependencies | **JUCE only**             | cpp-httplib, nlohmann/json, OpenSSL |
| Setup        | Single header             | Multiple files + libraries          |
| HTTP         | juce::URL                 | cpp-httplib                         |
| JSON         | juce::JSON                | nlohmann/json                       |
| Best for     | **Audio plugins**         | Desktop apps, games                 |

**For VST/AU/AAX plugins, use LicenseSeatJuceStandalone.h** - it's specifically designed for the plugin ecosystem where symbol conflicts and dependency hell are common problems.

## Troubleshooting

### "juce::URL request failed"

1. Check your API key is correct
2. Verify internet connectivity
3. Try the sync `validate()` method to debug (in non-audio code)

### "License not persisting between sessions"

Implement save/load using `juce::ApplicationProperties` or `juce::PropertiesFile`.

### "Multiple instances show different license states"

This is by design - each instance is independent. If you need shared state, implement a singleton license manager or use inter-process communication.

### "Build errors on Windows"

Ensure you're using a recent JUCE version (6.1+) with working juce::URL.

## Migration from Full SDK

If you're currently using `LicenseSeatJuce.h` (the wrapper around the full SDK):

```cpp
// Before (full SDK)
#include "licenseseat/licenseseat.hpp"
licenseseat::Client client(config);
client.validate(key);

// After (standalone)
#include "LicenseSeatJuceStandalone.h"
LicenseSeatJuceStandalone license(apiKey, productSlug);
license.validateAsync(key, callback);
```

The API is similar but the standalone version uses JUCE types (juce::String) throughout.

## Support

- Documentation: https://licenseseat.com/docs/sdks/juce
- Issues: https://github.com/licenseseat/licenseseat-cpp/issues
