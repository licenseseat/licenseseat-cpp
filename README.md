# LicenseSeat C++ SDK

[![CI](https://github.com/licenseseat/licenseseat-cpp/actions/workflows/ci.yml/badge.svg)](https://github.com/licenseseat/licenseseat-cpp/actions/workflows/ci.yml)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![Tests](https://img.shields.io/badge/Tests-208%20passing-brightgreen.svg)](#testing)
[![Platforms](https://img.shields.io/badge/Platforms-Windows%20|%20macOS%20|%20Linux-green.svg)](#platform-support)

**The licensing SDK that doesn't get in your way.** Built for game developers, audio plugin makers, and desktop app creators who want licensing to *just work*.

> [!TIP]
> **Building a VST/AU plugin or Unreal Engine game?** Jump straight to our [zero-dependency integrations](#-zero-dependency-integrations) – single-header, no OpenSSL conflicts, no linking nightmares.

---

## Why LicenseSeat?

We analyzed hundreds of GitHub issues and forum posts from developers using competitor SDKs. The same problems appeared over and over:

| 😤 Common Pain Points                    | ✅ How We Solved It                                     |
| --------------------------------------- | ------------------------------------------------------ |
| OpenSSL symbol conflicts crash DAWs     | **Zero OpenSSL** – vendored Ed25519 + SHA-256          |
| Thread safety bugs cause random crashes | **Battle-tested** – 200 concurrent clients, 10 threads |
| Global singletons break multi-instance  | **No global state** – each instance is independent     |
| Complex dependencies = build failures   | **Single header** options for UE & JUCE                |
| Static destructors crash on shutdown    | **Clean RAII** – no static initialization              |

---

## 🚀 Zero-Dependency Integrations

### Unreal Engine Plugin

> [!IMPORTANT]
> **ThirdParty folder comes pre-populated** – no manual setup, no hunting for dependencies.

Drop-in plugin with Blueprint support. Uses native UE HTTP and JSON modules.

```cpp
// Get the subsystem (automatic lifecycle management)
auto* LicenseSeat = GetGameInstance()->GetSubsystem<ULicenseSeatSubsystem>();

// Configure once
FLicenseSeatConfig Config;
Config.ApiKey = TEXT("your-api-key");
Config.ProductSlug = TEXT("your-game");
LicenseSeat->InitializeWithConfig(Config);

// Validate (non-blocking!)
LicenseSeat->ValidateAsync(TEXT("LICENSE-KEY"),
    FOnValidationComplete::CreateLambda([](const FLicenseValidationResult& Result)
    {
        if (Result.bValid)
            UE_LOG(LogTemp, Log, TEXT("Welcome, %s!"), *Result.Licensee);
    }));
```

📁 **Location:** [`integrations/unreal/LicenseSeat/`](integrations/unreal/)

**Features:**
- ✅ Full Blueprint support via `UFUNCTION`/`UPROPERTY`
- ✅ `GameInstanceSubsystem` for automatic lifecycle
- ✅ Async-first API – never blocks the game thread
- ✅ Auto-validation timer for long play sessions
- ✅ Ed25519 offline verification included

---

### VST/AU/AAX Plugins (JUCE)

> [!TIP]
> **One header file. Zero external dependencies.** Just copy and go.

```cpp
#include "LicenseSeatJuceStandalone.h"

// That's it. No cpp-httplib, no nlohmann/json, no OpenSSL.
LicenseSeatJuceStandalone license("your-api-key", "your-plugin");

// Safe to call from audio thread (just reads std::atomic)
void processBlock(juce::AudioBuffer<float>& buffer, juce::MidiBuffer&)
{
    if (!license.isValid())
    {
        buffer.clear();  // Demo mode
        return;
    }
    // Full processing for licensed users
}

// Async validation – callback runs on message thread
license.validateAsync("LICENSE-KEY", [](auto& result)
{
    if (result.valid)
        showMessage("Licensed to: " + result.licensee);
});
```

📁 **Location:** [`integrations/juce/Source/LicenseSeatJuceStandalone.h`](integrations/juce/)

**Features:**
- ✅ Uses `juce::URL` for HTTP (native JUCE, no OpenSSL!)
- ✅ Uses `juce::JSON` for parsing (no nlohmann!)
- ✅ `std::atomic<bool>` for audio-thread-safe status checks
- ✅ `MessageManager::callAsync` for UI callbacks
- ✅ Multi-instance safe – run 10+ plugins in the same DAW

> [!NOTE]
> **Why this matters:** Other SDKs cause crashes when multiple plugins link different OpenSSL versions. Our standalone integration has *zero* symbol conflicts.

---

## 📦 Standard Installation

For desktop apps and games that aren't using UE or JUCE:

### CMake (FetchContent)

```cmake
include(FetchContent)

FetchContent_Declare(
    licenseseat
    GIT_REPOSITORY https://github.com/licenseseat/licenseseat-cpp.git
    GIT_TAG        main
)
FetchContent_MakeAvailable(licenseseat)

target_link_libraries(your_target PRIVATE licenseseat::licenseseat)
```

### Manual Build

```bash
git clone https://github.com/licenseseat/licenseseat-cpp.git
cd licenseseat-cpp
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
sudo cmake --install build
```

**Dependencies:** nlohmann/json, cpp-httplib (with OpenSSL for HTTPS)

> [!NOTE]
> Cryptographic operations (Ed25519, SHA-256) use vendored libraries – no external crypto dependencies.

---

## ⚡ Quick Start

```cpp
#include <licenseseat/licenseseat.hpp>

int main()
{
    // 1. Configure
    licenseseat::Config config;
    config.api_key = "your-api-key";
    config.product_slug = "your-product";

    licenseseat::Client client(config);

    // 2. Activate
    auto result = client.activate("XXXX-XXXX-XXXX-XXXX");

    if (result.is_ok()) {
        std::cout << "Licensed to: " << result.value().licensee << "\n";
    } else {
        std::cerr << "Error: " << result.error_message() << "\n";
    }

    // 3. Check entitlements
    if (client.has_entitlement("pro-features")) {
        enable_pro_mode();
    }

    // 4. Quick status check
    if (client.is_valid()) {
        // License is active
    }

    return 0;
}
```

---

## 🔧 Configuration

```cpp
licenseseat::Config config;

// Required
config.api_key = "your-api-key";
config.product_slug = "your-product";

// Optional
config.api_url = "https://licenseseat.com/api";  // Custom API URL
config.timeout_seconds = 10;                      // Request timeout
config.max_retries = 3;                           // Retry on failure

// Offline Support
config.offline_public_key = "base64-ed25519-key"; // For offline verification
config.max_offline_days = 30;                      // Days license works offline
```

| Option               | Type   | Default                       | Description                        |
| -------------------- | ------ | ----------------------------- | ---------------------------------- |
| `api_key`            | string | *required*                    | Your LicenseSeat API key           |
| `product_slug`       | string | *required*                    | Product identifier                 |
| `api_url`            | string | `https://licenseseat.com/api` | API endpoint                       |
| `timeout_seconds`    | int    | `30`                          | HTTP timeout                       |
| `max_retries`        | int    | `3`                           | Retry attempts                     |
| `offline_public_key` | string | `""`                          | Ed25519 public key for offline     |
| `max_offline_days`   | int    | `0`                           | Max offline days (0 = online only) |

---

## 🛡️ Offline License Verification

> [!IMPORTANT]
> Offline licenses use **Ed25519 cryptographic signatures** – the same algorithm used by SSH and cryptocurrency.

```cpp
licenseseat::Config config;
config.api_key = "your-api-key";
config.product_slug = "your-product";
config.offline_public_key = "MCowBQYDK2VwAyEA...";  // Your Ed25519 public key
config.max_offline_days = 30;

licenseseat::Client client(config);

// Works even without internet!
auto result = client.validate_offline("LICENSE-KEY");
if (result.is_ok() && result.value().valid) {
    // Signature verified, license is legit
}
```

**How it works:**
1. Server signs license data with Ed25519 private key
2. SDK verifies signature locally with public key
3. No network required after initial activation
4. Clock tampering detection prevents bypassing expiration

---

## 🎯 API Reference

### Activation

```cpp
auto result = client.activate("LICENSE-KEY");

if (result.is_ok()) {
    auto& data = result.value();
    std::cout << "Licensee: " << data.licensee << "\n";
    std::cout << "Type: " << data.license_type << "\n";
    std::cout << "Seats: " << data.seats_used << "/" << data.seats_total << "\n";
}
```

### Validation

```cpp
auto result = client.validate("LICENSE-KEY");

if (result.is_ok()) {
    auto& data = result.value();
    if (data.valid) {
        // License is valid
    } else {
        std::cerr << "Invalid: " << data.reason << "\n";
    }
}
```

### Deactivation

```cpp
auto result = client.deactivate("LICENSE-KEY");

if (result.is_ok()) {
    std::cout << "Seat freed up\n";
}
```

### Entitlement Checks

```cpp
// Quick check
if (client.has_entitlement("pro")) {
    enable_pro_features();
}

// Detailed check
auto result = client.check_entitlement("LICENSE-KEY", "pro");
if (result.is_ok()) {
    if (result.value().has_entitlement) {
        // Feature unlocked
    }
}
```

### Status

```cpp
auto status = client.get_status();

std::cout << "Valid: " << status.valid << "\n";
std::cout << "Licensee: " << status.licensee << "\n";
std::cout << "Type: " << status.license_type << "\n";
```

---

## 🧵 Thread Safety

> [!TIP]
> **Tested with 200 concurrent clients across 10 threads.** Race conditions? Not here.

```cpp
// Safe from any thread
std::thread validator([&client]() {
    client.validate("KEY");
});

std::thread checker([&client]() {
    bool valid = client.is_valid();  // Reads std::atomic
});

// For JUCE audio plugins specifically:
void processBlock(...) {
    if (!license.isValid()) {  // std::atomic – lock-free!
        return;
    }
}
```

**Thread safety guarantees:**
- ✅ All public methods are thread-safe
- ✅ `is_valid()` / `isValid()` use `std::atomic` – safe for real-time audio
- ✅ No global state – multiple instances don't interfere
- ✅ RAII cleanup – no static destruction order issues

---

## 🧪 Testing

```bash
# Build and run tests
cmake -B build -DLICENSESEAT_BUILD_TESTS=ON
cmake --build build
./build/tests/licenseseat_tests
```

```
[==========] 208 tests from 59 test suites ran. (195 ms total)
[  PASSED  ] 208 tests.
```

**Test coverage includes:**
- RFC 8032 Ed25519 test vectors
- Thread safety (200 concurrent clients)
- Rapid create/destroy cycles (memory safety)
- Large data handling (10KB keys, 100KB metadata)
- Platform-specific device ID generation
- Offline license verification
- Clock tampering detection

---

## 🖥️ Platform Support

| Platform | Compiler                      | Status         |
| -------- | ----------------------------- | -------------- |
| Linux    | GCC 9+, Clang 10+             | ✅ Full support |
| macOS    | Apple Clang 12+ (ARM & Intel) | ✅ Full support |
| Windows  | MSVC 2019+                    | ✅ Full support |

**Device identification:**
- **macOS:** IOKit Platform UUID
- **Windows:** Machine GUID from registry
- **Linux:** `/etc/machine-id` or hostname-based fallback

---

## 📁 Project Structure

```
licenseseat-cpp/
├── include/licenseseat/     # Public headers
├── src/                     # Core implementation
├── deps/                    # Vendored dependencies
│   ├── ed25519/            # Ed25519 signatures (public domain)
│   └── PicoSHA2/           # SHA-256 (header-only, MIT)
├── integrations/
│   ├── unreal/             # 🎮 Unreal Engine plugin
│   │   └── LicenseSeat/    # Drop into YourGame/Plugins/
│   └── juce/               # 🎵 JUCE/VST integration
│       └── Source/         # Single-header standalone
├── tests/                   # 208 unit tests
└── examples/               # Usage examples
```

---

## 🔒 Security

> [!WARNING]
> **Never commit your API key to source control.** Use environment variables or secure vaults.

```cpp
// Good: Load from environment
const char* api_key = std::getenv("LICENSESEAT_API_KEY");

// Good: Load from secure storage
std::string api_key = secure_vault.get("licenseseat_key");

// Bad: Hardcoded in source
config.api_key = "sk_live_abc123";  // Don't do this!
```

**Security features:**
- Ed25519 signatures (128-bit security level)
- SHA-256 hashing for data integrity
- Clock tampering detection
- Device fingerprinting

---

## 📄 License

MIT License – see [LICENSE](LICENSE) for details.

---

## 🔗 Links

- **Website:** [licenseseat.com](https://licenseseat.com)
- **Documentation:** [licenseseat.com/docs](https://licenseseat.com/docs)
- **Issues:** [GitHub Issues](https://github.com/licenseseat/licenseseat-cpp/issues)

---

<p align="center">
  <b>Built with ❤️ for developers who ship</b>
</p>
