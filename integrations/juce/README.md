# LicenseSeat JUCE Integration

License management for JUCE-based audio plugins (VST3, AU, AAX).

## Features

- **Single-File Integration** - Drop in and go
- **No External Dependencies** - Self-contained crypto
- **Thread-Safe** - Safe for audio threads
- **Offline Support** - Works without internet
- **Cross-Platform** - Windows, macOS, Linux

## Quick Start

### 1. Add Files to Your Project

Copy these files to your JUCE project:

```
YourPlugin/
├── Source/
│   ├── PluginProcessor.cpp
│   ├── PluginProcessor.h
│   └── LicenseSeat/
│       ├── licenseseat/          # Copy from dist/licenseseat-minimal/include/licenseseat
│       │   ├── licenseseat.hpp
│       │   ├── crypto.hpp
│       │   ├── device.hpp
│       │   └── ...
│       ├── src/                  # Copy from dist/licenseseat-minimal/src
│       │   ├── client.cpp
│       │   ├── crypto_minimal.cpp
│       │   ├── device.cpp
│       │   ├── http.cpp
│       │   └── storage.cpp
│       └── deps/                 # Copy from dist/licenseseat-minimal/deps
│           ├── ed25519/
│           └── PicoSHA2/
└── JuceLibraryCode/
```

### 2. Configure Projucer

**Header Search Paths:**
```
Source/LicenseSeat
Source/LicenseSeat/deps
Source/LicenseSeat/deps/ed25519
```

**Add to Source Files:**
- `Source/LicenseSeat/src/*.cpp`
- `Source/LicenseSeat/deps/ed25519/*.c`

**External Libraries (for HTTP):**
You'll also need nlohmann/json and cpp-httplib headers.

### 3. Use in Your Plugin

```cpp
// PluginProcessor.h
#pragma once

#include <JuceHeader.h>
#include "LicenseSeat/licenseseat/licenseseat.hpp"

class MyPluginProcessor : public juce::AudioProcessor
{
public:
    MyPluginProcessor();
    ~MyPluginProcessor() override;

    // ... other methods ...

    bool isLicenseValid() const { return licenseValid; }
    void checkLicense(const juce::String& key);

private:
    std::unique_ptr<licenseseat::Client> licenseClient;
    bool licenseValid = false;

    JUCE_DECLARE_NON_COPYABLE_WITH_LEAK_DETECTOR(MyPluginProcessor)
};
```

```cpp
// PluginProcessor.cpp
#include "PluginProcessor.h"

MyPluginProcessor::MyPluginProcessor()
{
    // Initialize license client
    licenseseat::Config config;
    config.api_key = "your-api-key";
    config.product_slug = "your-plugin";
    config.timeout_seconds = 10;
    config.max_retries = 1;

    licenseClient = std::make_unique<licenseseat::Client>(config);

    // Check stored license on startup
    auto status = licenseClient->get_status();
    licenseValid = status.valid;
}

MyPluginProcessor::~MyPluginProcessor()
{
    // Client cleanup handled automatically
}

void MyPluginProcessor::checkLicense(const juce::String& key)
{
    // Run validation in background thread
    std::thread([this, key]()
    {
        auto result = licenseClient->validate(key.toStdString());
        if (result.is_ok())
        {
            licenseValid = result.value().valid;

            // Update UI on message thread
            juce::MessageManager::callAsync([this]()
            {
                // Notify UI of license status change
            });
        }
    }).detach();
}
```

## License Dialog Example

```cpp
// LicenseDialog.h
class LicenseDialog : public juce::Component,
                      public juce::Button::Listener
{
public:
    LicenseDialog(MyPluginProcessor& p)
        : processor(p)
    {
        addAndMakeVisible(licenseKeyInput);
        licenseKeyInput.setTextToShowWhenEmpty("Enter license key...",
            juce::Colours::grey);

        addAndMakeVisible(activateButton);
        activateButton.setButtonText("Activate");
        activateButton.addListener(this);

        addAndMakeVisible(statusLabel);
        updateStatus();

        setSize(400, 200);
    }

    void buttonClicked(juce::Button* button) override
    {
        if (button == &activateButton)
        {
            statusLabel.setText("Activating...", juce::dontSendNotification);
            processor.checkLicense(licenseKeyInput.getText());
        }
    }

    void updateStatus()
    {
        if (processor.isLicenseValid())
        {
            statusLabel.setText("License: Active",
                juce::dontSendNotification);
            statusLabel.setColour(juce::Label::textColourId,
                juce::Colours::green);
        }
        else
        {
            statusLabel.setText("License: Not Active",
                juce::dontSendNotification);
            statusLabel.setColour(juce::Label::textColourId,
                juce::Colours::red);
        }
    }

private:
    MyPluginProcessor& processor;
    juce::TextEditor licenseKeyInput;
    juce::TextButton activateButton;
    juce::Label statusLabel;

    JUCE_DECLARE_NON_COPYABLE_WITH_LEAK_DETECTOR(LicenseDialog)
};
```

## Best Practices

### 1. Never Block Audio Thread

```cpp
// WRONG - Don't do this in processBlock!
void processBlock(juce::AudioBuffer<float>& buffer, juce::MidiBuffer&) override
{
    if (!licenseClient->validate(key).is_ok())  // BLOCKS!
        return;
    // ...
}

// RIGHT - Check cached status
void processBlock(juce::AudioBuffer<float>& buffer, juce::MidiBuffer&) override
{
    if (!licenseValid)  // Just read a bool
    {
        buffer.clear();
        return;
    }
    // ...
}
```

### 2. Validate on Startup, Cache Result

```cpp
MyPluginProcessor()
{
    // Load saved license from settings
    auto savedKey = loadLicenseFromSettings();
    if (!savedKey.empty())
    {
        // Validate in background
        std::thread([this, savedKey]()
        {
            auto result = licenseClient->validate(savedKey);
            licenseValid = result.is_ok() && result.value().valid;
        }).detach();
    }
}
```

### 3. Handle Offline Gracefully

```cpp
licenseseat::Config config;
config.offline_fallback_mode = licenseseat::OfflineFallbackMode::PreferOffline;
config.max_offline_days = 30;  // Allow 30 days offline
config.offline_public_key = "your-ed25519-public-key-base64";
```

### 4. Limit Features, Don't Crash

```cpp
void processBlock(juce::AudioBuffer<float>& buffer, juce::MidiBuffer&)
{
    if (!licenseValid)
    {
        // Demo mode: add noise or limit time
        for (int ch = 0; ch < buffer.getNumChannels(); ++ch)
        {
            for (int s = 0; s < buffer.getNumSamples(); ++s)
            {
                // Add periodic noise as demo reminder
                if (rand() % 10000 < 10)
                    buffer.setSample(ch, s, (rand() / (float)RAND_MAX) * 0.1f);
            }
        }
    }
    else
    {
        // Full processing
        // ...
    }
}
```

## Multiple Plugin Instances

LicenseSeat is designed to work with multiple instances:

```cpp
// Each plugin instance has its own Client
// They don't share state - safe for multiple instances in same DAW

MyPluginProcessor::MyPluginProcessor()
{
    // This creates an independent client for this instance
    licenseClient = std::make_unique<licenseseat::Client>(config);
}
```

## Troubleshooting

### Build Errors

**"nlohmann/json.hpp not found"**
- Download from https://github.com/nlohmann/json
- Add to Header Search Paths

**"httplib.h not found"**
- Download from https://github.com/yhirose/cpp-httplib
- Add to Header Search Paths

### Runtime Issues

**"Network error" on all requests**
- Check API key is correct
- Verify internet connectivity
- Try curl to test API manually

**License not persisting**
- Implement save/load using `juce::PropertiesFile`
- Store license key securely

## Support

- Documentation: https://docs.licenseseat.com/sdks/juce
- Issues: https://github.com/licenseseat/licenseseat-cpp/issues
