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
- **Event system** – Subscribe to license events (validation success/failure, offline token ready, etc.)
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

    // Validate a license
    auto result = client.validate("XXXX-XXXX-XXXX-XXXX");

    if (result.is_ok()) {
        const auto& validation = result.value();
        if (validation.valid) {
            std::cout << "License is valid!\n";
            std::cout << "Plan: " << validation.license.plan_key() << "\n";
        } else {
            // License exists but validation failed (e.g., expired, seat limit)
            std::cout << "Invalid: " << validation.code << " - " << validation.message << "\n";
        }
    } else {
        // Network error, license not found, etc.
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

// Optional - API settings
config.api_url = "https://licenseseat.com/api/v1";  // Default
config.timeout_seconds = 30;
config.max_retries = 3;

// Optional - Device identification
config.device_id = "";  // Auto-generated if empty

// Optional - Offline support
config.signing_public_key = "base64-ed25519-public-key";  // Pre-configure for offline
config.max_offline_days = 30;

// Optional - Caching
config.storage_path = "";  // Path for license cache (empty = no persistence)

// Optional - Auto-validation
config.auto_validate_interval = 3600.0;  // Seconds between background validations
```

### Configuration Options

| Option                   | Type   | Default                            | Description                                        |
| ------------------------ | ------ | ---------------------------------- | -------------------------------------------------- |
| `api_key`                | string | *required*                         | API key for authentication                         |
| `product_slug`           | string | *required*                         | Product identifier                                 |
| `api_url`                | string | `https://licenseseat.com/api/v1`   | API endpoint                                       |
| `timeout_seconds`        | int    | `30`                               | HTTP request timeout                               |
| `max_retries`            | int    | `3`                                | Retry attempts for failed requests                 |
| `device_id`              | string | `""`                               | Device identifier (auto-generated if empty)        |
| `signing_public_key`     | string | `""`                               | Ed25519 public key for offline verification        |
| `max_offline_days`       | int    | `0`                                | Maximum days license works offline (0 = disabled)  |
| `storage_path`           | string | `""`                               | Path for license cache (empty = no persistence)    |
| `auto_validate_interval` | double | `3600.0`                           | Seconds between auto-validation cycles             |

---

## API Reference

### Validation

Validation checks if a license is valid. **Important:** The API always returns HTTP 200 for validation – check the `valid` field to determine validity.

```cpp
auto result = client.validate("LICENSE-KEY");

if (result.is_ok()) {
    const auto& validation = result.value();

    if (validation.valid) {
        // License is valid and usable
        std::cout << "Valid! Plan: " << validation.license.plan_key() << "\n";
    } else {
        // License exists but isn't valid for use
        // Common codes: expired, revoked, suspended, seat_limit_exceeded
        std::cout << "Code: " << validation.code << "\n";
        std::cout << "Message: " << validation.message << "\n";
    }

    // License data is always available (even when invalid)
    const auto& license = validation.license;
    std::cout << "Key: " << license.key() << "\n";
    std::cout << "Status: " << license_status_to_string(license.status()) << "\n";
    std::cout << "Seats: " << license.active_seats() << "/" << license.seat_limit() << "\n";
} else {
    // API error (license not found, network error, auth failed)
    std::cerr << "Error: " << result.error_message() << "\n";
}
```

> [!IMPORTANT]
> For **hardware-locked** licenses, you must provide a `device_id` to validate:
> ```cpp
> auto result = client.validate("LICENSE-KEY", device_id);
> ```
> Without it, validation may return `valid: false` with code `device_not_activated`.

### Async Validation

```cpp
client.validate_async("LICENSE-KEY", [](licenseseat::Result<licenseseat::Validation> result) {
    if (result.is_ok() && result.value().valid) {
        // License is valid
    }
});
```

### Activation

Activation binds a license to a device, consuming a seat.

```cpp
auto result = client.activate("LICENSE-KEY", device_id, "My MacBook Pro");

if (result.is_ok()) {
    const auto& activation = result.value();
    std::cout << "Activation ID: " << activation.id() << "\n";
    std::cout << "Device: " << activation.device_name() << "\n";
} else {
    switch (result.error_code()) {
        case licenseseat::ErrorCode::SeatLimitExceeded:
            std::cerr << "No seats available\n";
            break;
        case licenseseat::ErrorCode::DeviceAlreadyActivated:
            std::cerr << "Device already activated\n";
            break;
        default:
            std::cerr << "Error: " << result.error_message() << "\n";
    }
}
```

### Deactivation

Deactivation removes a device from a license, freeing a seat.

```cpp
auto result = client.deactivate("LICENSE-KEY", device_id);

if (result.is_ok()) {
    std::cout << "Device deactivated\n";
} else if (result.error_code() == licenseseat::ErrorCode::ActivationNotFound) {
    std::cout << "Device was not activated\n";
}
```

### Entitlement Checks

```cpp
// Simple boolean check (uses cached license data)
if (client.has_entitlement("pro")) {
    enable_pro_features();
}

// Detailed check with reason
auto entitlement = client.check_entitlement("feature-key");
if (entitlement.active) {
    // Feature unlocked
} else {
    std::cout << "Not available: " << entitlement.reason << "\n";
}
```

### Status

Get the current cached license status without making a network request.

```cpp
auto status = client.get_status();

std::cout << "Valid: " << (status.valid ? "yes" : "no") << "\n";
std::cout << "Code: " << status.code << "\n";
```

### Reset

Clear all cached data (license, offline tokens, etc.).

```cpp
client.reset();
```

---

## Offline Support

The SDK supports offline license validation using Ed25519 cryptographic signatures. This allows your application to work without network access after initial setup.

### Offline Token Workflow

**Step 1: Generate and cache offline token while online**

```cpp
// Generate offline token (requires network)
auto token_result = client.generate_offline_token("LICENSE-KEY");
if (token_result.is_error()) {
    std::cerr << "Failed to generate token: " << token_result.error_message() << "\n";
    return;
}
auto offline_token = token_result.value();

// Fetch signing key (requires network)
auto key_result = client.fetch_signing_key(offline_token.token.kid);
if (key_result.is_error()) {
    std::cerr << "Failed to fetch key: " << key_result.error_message() << "\n";
    return;
}
std::string public_key = key_result.value();

// Store both for offline use
save_to_disk(offline_token, public_key);
```

**Step 2: Verify offline (no network required)**

```cpp
// Load cached data
auto [offline_token, public_key] = load_from_disk();

// Verify signature locally
auto verify_result = client.verify_offline_token(offline_token, public_key);
if (verify_result.is_ok() && verify_result.value()) {
    // Token is valid - license data available in offline_token.token
    std::cout << "License: " << offline_token.token.license_key << "\n";
    std::cout << "Plan: " << offline_token.token.plan_key << "\n";
    std::cout << "Expires: " << offline_token.token.exp << "\n";

    // Check entitlements from token
    for (const auto& ent : offline_token.token.entitlements) {
        std::cout << "Entitlement: " << ent.key << "\n";
    }
}
```

### Pre-configured Public Key

For simpler deployments, you can pre-configure the signing public key:

```cpp
licenseseat::Config config;
config.api_key = "your-api-key";
config.product_slug = "your-product";
config.signing_public_key = "MCowBQYDK2VwAyEA...";  // Your public key
config.max_offline_days = 30;

licenseseat::Client client(config);

// Now verify_offline_token can use the pre-configured key
auto result = client.verify_offline_token(offline_token);  // No key param needed
```

### Offline Token Fields

| Field              | Type     | Description                                      |
| ------------------ | -------- | ------------------------------------------------ |
| `license_key`      | string   | The license key                                  |
| `product_slug`     | string   | Product identifier                               |
| `plan_key`         | string   | Plan identifier (e.g., "pro-annual")             |
| `mode`             | string   | License mode ("hardware_locked" or "floating")   |
| `seat_limit`       | int      | Maximum allowed activations                      |
| `device_id`        | string   | Device this token is bound to (if hardware_locked) |
| `iat`              | int64    | Issued at (Unix timestamp)                       |
| `exp`              | int64    | Expires at (Unix timestamp)                      |
| `nbf`              | int64    | Not valid before (Unix timestamp)                |
| `license_expires_at` | int64  | License expiration (Unix timestamp, may be 0)    |
| `kid`              | string   | Key ID for fetching the signing public key       |
| `entitlements`     | array    | List of entitlements with keys and expiration    |
| `metadata`         | object   | Custom metadata attached to the license          |

---

## Auto-Validation

The SDK can automatically validate licenses in the background at configurable intervals.

```cpp
// Configure interval (in seconds)
config.auto_validate_interval = 3600.0;  // Every hour

licenseseat::Client client(config);

// Start auto-validation
client.start_auto_validation("LICENSE-KEY");

// Check if running
if (client.is_auto_validating()) {
    std::cout << "Auto-validation is active\n";
}

// Stop when done
client.stop_auto_validation();
```

---

## Events

Subscribe to license events for reactive updates.

```cpp
#include <licenseseat/events.hpp>

// Subscribe to validation success
auto sub1 = client.on(licenseseat::events::VALIDATION_SUCCESS, [](const std::any& data) {
    std::cout << "License validated successfully!\n";
});

// Subscribe to validation failure
auto sub2 = client.on(licenseseat::events::VALIDATION_FAILED, [](const std::any& data) {
    std::cout << "License validation failed\n";
});

// Subscribe to offline token ready
auto sub3 = client.on(licenseseat::events::OFFLINE_TOKEN_READY, [](const std::any& data) {
    std::cout << "Offline token generated\n";
});

// Later: cancel subscriptions
sub1.cancel();
sub2.cancel();
sub3.cancel();
```

### Available Events

| Event Name               | Description                                  |
| ------------------------ | -------------------------------------------- |
| `LICENSE_LOADED`         | License data loaded from cache               |
| `ACTIVATION_START`       | Activation request starting                  |
| `ACTIVATION_SUCCESS`     | Device activated successfully                |
| `ACTIVATION_ERROR`       | Activation failed                            |
| `VALIDATION_START`       | Validation request starting                  |
| `VALIDATION_SUCCESS`     | License validated successfully               |
| `VALIDATION_FAILED`      | License validation returned invalid          |
| `VALIDATION_ERROR`       | Validation request failed (network, etc.)    |
| `VALIDATION_OFFLINE_SUCCESS` | Offline token verified successfully      |
| `VALIDATION_OFFLINE_FAILED`  | Offline token verification failed        |
| `DEACTIVATION_START`     | Deactivation request starting                |
| `DEACTIVATION_SUCCESS`   | Device deactivated successfully              |
| `DEACTIVATION_ERROR`     | Deactivation failed                          |
| `NETWORK_ONLINE`         | Network connectivity restored                |
| `NETWORK_OFFLINE`        | Network connectivity lost                    |
| `AUTOVALIDATION_CYCLE`   | Auto-validation cycle completed              |
| `AUTOVALIDATION_STOPPED` | Auto-validation stopped                      |
| `OFFLINE_TOKEN_READY`    | Offline token generated                      |
| `OFFLINE_TOKEN_VERIFIED` | Offline token verified                       |
| `SDK_RESET`              | SDK state reset                              |

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
auto result = client.validate("LICENSE-KEY");

if (result.is_ok()) {
    auto& validation = result.value();
    // Success - check validation.valid for license validity
} else {
    // Error - network, auth, or API error
    std::cerr << "Error: " << result.error_message() << "\n";

    switch (result.error_code()) {
        case licenseseat::ErrorCode::NetworkError:
            // No network connectivity
            break;
        case licenseseat::ErrorCode::LicenseNotFound:
            // Invalid license key
            break;
        case licenseseat::ErrorCode::AuthenticationFailed:
            // Invalid API key
            break;
        case licenseseat::ErrorCode::SeatLimitExceeded:
            // Too many activations
            break;
        // ... handle other cases
    }
}
```

### Error Codes

| Code                    | Description                                 |
| ----------------------- | ------------------------------------------- |
| `Success`               | Operation completed successfully            |
| `NetworkError`          | HTTP request failed (no connectivity)       |
| `ConnectionTimeout`     | Request timed out                           |
| `SSLError`              | SSL/TLS error                               |
| `InvalidLicenseKey`     | License key format is invalid               |
| `LicenseNotFound`       | License key not found in system             |
| `LicenseExpired`        | License has expired                         |
| `LicenseRevoked`        | License has been revoked                    |
| `LicenseSuspended`      | License is suspended                        |
| `LicenseNotActive`      | License is not active                       |
| `LicenseNotStarted`     | License hasn't started yet                  |
| `SeatLimitExceeded`     | Maximum activations reached                 |
| `ActivationNotFound`    | Device activation not found                 |
| `DeviceAlreadyActivated`| Device is already activated                 |
| `ProductNotFound`       | Product slug not found                      |
| `ReleaseNotFound`       | Software release not found                  |
| `AuthenticationFailed`  | Invalid or missing API key                  |
| `PermissionDenied`      | API key lacks required permissions          |
| `MissingParameter`      | Required parameter not provided             |
| `InvalidParameter`      | Parameter value is invalid                  |
| `ValidationFailed`      | Generic validation failure                  |
| `ServerError`           | Server-side error (5xx)                     |
| `FeatureNotConfigured`  | Feature not enabled for product             |
| `SigningNotConfigured`  | Offline signing not configured              |
| `ParseError`            | Failed to parse response                    |
| `InvalidSignature`      | Cryptographic signature invalid             |
| `FileError`             | File read/write error                       |
| `FileNotFound`          | File not found                              |
| `Unknown`               | Unknown error                               |

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
[==========] 236 tests from 67 test suites ran. (210 ms total)
[  PASSED  ] 236 tests.
```

### Test Suites

The SDK includes comprehensive tests:

| Test Suite           | Tests | Network | Description                                 |
| -------------------- | ----- | ------- | ------------------------------------------- |
| Unit tests           | 236   | No      | Core functionality, parsing, crypto         |
| Crypto stress tests  | 44    | Yes     | Ed25519, Base64, offline token verification |
| Integration tests    | 48    | Yes     | Full API testing                            |
| Scenario tests       | 38    | Yes     | Real-world workflows (10 scenarios)         |

### Running Integration Tests

The integration, crypto stress, and scenario tests require a live LicenseSeat account. Configure credentials via environment variables:

```bash
# Set your credentials
export LICENSESEAT_API_KEY="ls_your_api_key"
export LICENSESEAT_PRODUCT_SLUG="your-product"
export LICENSESEAT_LICENSE_KEY="XXXX-XXXX-XXXX-XXXX"

# Build the tests
cmake -B build -DLICENSESEAT_BUILD_TESTS=ON
cmake --build build

# Run integration tests
./build/tests/integration_test      # 48 tests - Full API coverage
./build/tests/crypto_stress_test    # 44 tests - Crypto & offline tokens
./build/tests/scenario_test         # 38 tests - Real-world scenarios
```

### Scenario Test Coverage

The scenario tests validate 10 real-world use cases matching the Swift SDK test coverage:

1. **First app launch & activation** – Fresh install, validation, activation
2. **Returning user** – Cached license, session persistence
3. **Offline mode** – Offline token generation and verification
4. **Security** – Fake keys, wrong product, invalid API key, tampered signatures
5. **License persistence** – State consistency during session
6. **Grace period & expiration** – Token expiry handling
7. **Deactivation flow** – Device removal, seat freeing
8. **Re-activation** – Multi-device scenarios, seat limits
9. **Auto-validation** – Background refresh cycles
10. **Event system** – Event subscriptions and callbacks

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
