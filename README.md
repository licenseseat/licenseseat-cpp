# LicenseSeat C++ SDK

[![CI](https://github.com/licenseseat/licenseseat-cpp/actions/workflows/ci.yml/badge.svg)](https://github.com/licenseseat/licenseseat-cpp/actions/workflows/ci.yml)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![Platforms](https://img.shields.io/badge/Platforms-Windows%20|%20macOS%20|%20Linux-green.svg)](#platform-support)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

The official C++ SDK for [LicenseSeat](https://licenseseat.com) – the licensing platform for apps, games, and plugins.

> [!TIP]
> Building a **VST/AU plugin** or **Unreal Engine** game? We provide a [Unreal Engine plugin](#unreal-engine-plugin) and a [single-header integration for JUCE VST/AU plugins](#juce-vst--au--aax).

---

## Features

- **License activation & deactivation** – Activate licenses with automatic device fingerprinting
- **Online & offline validation** – Validate licenses with Ed25519 cryptographic verification
- **Entitlement checking** – Check feature access with `has_entitlement()` and `check_entitlement()`
- **Local caching** – File-based caching with clock tamper detection
- **Auto-validation** – Background validation with configurable intervals
- **Thread-safe** – All public methods are safe to call from multiple threads
- **Cross-platform** – Windows, macOS, and Linux support
- **Exception-free** – Uses `Result<T, Error>` pattern for error handling

---

## Special Packaging

The SDK includes zero-dependency integrations for platforms where dependency management is particularly challenging.

### Unreal Engine Plugin

A complete UE plugin using native `FHttpModule` and `FJsonObject`. No external dependencies.

```cpp
auto* LicenseSeat = GetGameInstance()->GetSubsystem<ULicenseSeatSubsystem>();

FLicenseSeatConfig Config;
Config.ApiKey = TEXT("your-api-key");
Config.ProductSlug = TEXT("your-game");
LicenseSeat->InitializeWithConfig(Config);

LicenseSeat->ValidateAsync(TEXT("LICENSE-KEY"),
    FOnValidationComplete::CreateLambda([](const FLicenseValidationResult& Result)
    {
        if (Result.bValid)
        {
            // License valid
        }
    }));
```

**Location:** [`integrations/unreal/LicenseSeat/`](integrations/unreal/)

- Blueprint support via `UFUNCTION`/`UPROPERTY`/`USTRUCT`
- `GameInstanceSubsystem` for automatic lifecycle management
- Async API (non-blocking)
- Auto-validation timer
- Ed25519 offline verification (ThirdParty folder pre-populated)

---

### JUCE: VST / AU / AAX

A single-header integration using only JUCE's native HTTP (`juce::URL`) and JSON (`juce::JSON`), without any dependency on cpp-httplib, nlohmann/json, or OpenSSL.

```cpp
#include "LicenseSeatJuceStandalone.h"

LicenseSeatJuceStandalone license("your-api-key", "your-plugin");

// Audio thread safe (reads std::atomic)
void processBlock(juce::AudioBuffer<float>& buffer, juce::MidiBuffer&)
{
    if (!license.isValid())
    {
        buffer.clear();
        return;
    }
    // Process audio
}

// Async validation (callback on message thread)
license.validateAsync("LICENSE-KEY", [](auto& result)
{
    if (result.valid)
    {
        // Update UI
    }
});
```

**Location:** [`integrations/juce/Source/LicenseSeatJuceStandalone.h`](integrations/juce/)

- Single header file
- `std::atomic<bool>` for lock-free status checks in audio thread
- `MessageManager::callAsync` for thread-safe UI callbacks
- Multi-instance safe (no global state)

> [!NOTE]
> The standalone integration avoids OpenSSL symbol conflicts that occur when multiple plugins in the same DAW link different OpenSSL versions.

---

## Installation

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

### Dependencies

- **nlohmann/json** – JSON parsing
- **cpp-httplib** – HTTP client (with OpenSSL for HTTPS)

Cryptographic operations (Ed25519, SHA-256) use vendored libraries with no external dependencies.

---

## Quick Start

```cpp
#include <licenseseat/licenseseat.hpp>

int main()
{
    licenseseat::Config config;
    config.api_key = "your-api-key";
    config.product_slug = "your-product";

    licenseseat::Client client(config);

    // Activate
    auto result = client.activate("XXXX-XXXX-XXXX-XXXX");

    if (result.is_ok()) {
        std::cout << "Licensed to: " << result.value().licensee << "\n";
    } else {
        std::cerr << "Error: " << result.error_message() << "\n";
    }

    // Check entitlements
    if (client.has_entitlement("pro")) {
        // Enable pro features
    }

    return 0;
}
```

---

## Configuration

```cpp
licenseseat::Config config;

// Required
config.api_key = "your-api-key";
config.product_slug = "your-product";

// Optional
config.api_url = "https://licenseseat.com/api";
config.timeout_seconds = 30;
config.max_retries = 3;

// Offline support
config.offline_public_key = "base64-ed25519-public-key";
config.max_offline_days = 30;
```

### Configuration Options

| Option               | Type   | Default                       | Description                                       |
| -------------------- | ------ | ----------------------------- | ------------------------------------------------- |
| `api_key`            | string | *required*                    | API key for authentication                        |
| `product_slug`       | string | *required*                    | Product identifier                                |
| `api_url`            | string | `https://licenseseat.com/api` | API endpoint                                      |
| `timeout_seconds`    | int    | `30`                          | HTTP request timeout                              |
| `max_retries`        | int    | `3`                           | Retry attempts for failed requests                |
| `offline_public_key` | string | `""`                          | Ed25519 public key for offline verification       |
| `max_offline_days`   | int    | `0`                           | Maximum days license works offline (0 = disabled) |

---

## API Reference

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
    std::cout << "License deactivated\n";
}
```

### Entitlement Checks

```cpp
// Simple boolean check
if (client.has_entitlement("pro")) {
    enable_pro_features();
}

// Detailed check
auto result = client.check_entitlement("LICENSE-KEY", "pro");
if (result.is_ok() && result.value().has_entitlement) {
    // Feature unlocked
}
```

### Status

```cpp
auto status = client.get_status();

std::cout << "Valid: " << status.valid << "\n";
std::cout << "Licensee: " << status.licensee << "\n";
std::cout << "Type: " << status.license_type << "\n";
```

### Reset

```cpp
client.reset();  // Clear all cached data
```

---

## Offline Support

The SDK supports offline license validation using Ed25519 cryptographic signatures.

```cpp
licenseseat::Config config;
config.api_key = "your-api-key";
config.product_slug = "your-product";
config.offline_public_key = "MCowBQYDK2VwAyEA...";
config.max_offline_days = 30;

licenseseat::Client client(config);

// Works without network after initial activation
auto result = client.validate_offline("LICENSE-KEY");
if (result.is_ok() && result.value().valid) {
    // Signature verified locally
}
```

How it works:
1. Server signs license data with Ed25519 private key
2. SDK verifies signature locally with public key
3. No network required after initial activation
4. Clock tampering detection prevents bypassing expiration

---

## Thread Safety

All public methods are thread-safe. The SDK uses internal mutexes to protect shared state.

```cpp
// Safe from multiple threads
std::thread t1([&client]() {
    client.validate("KEY");
});

std::thread t2([&client]() {
    bool valid = client.is_valid();
});
```

For audio plugins, `isValid()` uses `std::atomic<bool>` for lock-free reads in real-time contexts.

---

## Error Handling

The SDK uses a `Result<T, Error>` pattern instead of exceptions.

```cpp
auto result = client.activate("LICENSE-KEY");

if (result.is_ok()) {
    auto& activation = result.value();
    // Success
} else {
    auto& error = result.error();
    std::cerr << "Error: " << error.message << "\n";

    switch (error.code) {
        case ErrorCode::NetworkError:
            // Network issue
            break;
        case ErrorCode::LicenseNotFound:
            // Invalid key
            break;
        case ErrorCode::LicenseExpired:
            // Expired
            break;
        case ErrorCode::SeatLimitExceeded:
            // Too many activations
            break;
    }
}
```

### Error Codes

| Code                | Description                        |
| ------------------- | ---------------------------------- |
| `NetworkError`      | HTTP request failed                |
| `Timeout`           | Request timed out                  |
| `LicenseNotFound`   | License key not found              |
| `LicenseExpired`    | License has expired                |
| `LicenseInactive`   | License is not active              |
| `SeatLimitExceeded` | Maximum activations reached        |
| `DeviceMismatch`    | Device identifier mismatch         |
| `InvalidSignature`  | Cryptographic verification failed  |
| `ClockTamper`       | System clock manipulation detected |
| `StorageError`      | Failed to read/write cache         |

---

## Platform Support

| Platform | Compiler                      | Status    |
| -------- | ----------------------------- | --------- |
| Linux    | GCC 9+, Clang 10+             | Supported |
| macOS    | Apple Clang 12+ (ARM & Intel) | Supported |
| Windows  | MSVC 2019+                    | Supported |

### Device Identification

The SDK automatically generates a unique device identifier:

- **macOS**: IOKit Platform UUID
- **Windows**: Machine GUID from registry
- **Linux**: `/etc/machine-id` or hostname-based fallback

---

## Testing

```bash
cmake -B build -DLICENSESEAT_BUILD_TESTS=ON
cmake --build build
./build/tests/licenseseat_tests
```

```
[==========] 208 tests from 59 test suites ran. (195 ms total)
[  PASSED  ] 208 tests.
```

Test coverage includes:
- RFC 8032 Ed25519 test vectors
- Thread safety (200 concurrent clients)
- Rapid create/destroy cycles
- Large data handling (10KB keys, 100KB metadata)
- Platform-specific device ID generation
- Offline license verification

---

## Project Structure

```
licenseseat-cpp/
├── include/licenseseat/     # Public headers
├── src/                     # Implementation
├── deps/                    # Vendored dependencies
│   ├── ed25519/            # Ed25519 signatures
│   └── PicoSHA2/           # SHA-256 (header-only)
├── integrations/
│   ├── unreal/             # Unreal Engine plugin
│   └── juce/               # JUCE/VST integration
├── tests/                   # Unit tests
└── examples/               # Usage examples
```

---

## License

MIT License – see [LICENSE](LICENSE) for details.

---

## Links

- [LicenseSeat Website](https://licenseseat.com)
- [Documentation](https://licenseseat.com/docs)
- [API Reference](https://licenseseat.com/docs/api)
- [GitHub Issues](https://github.com/licenseseat/licenseseat-cpp/issues)
