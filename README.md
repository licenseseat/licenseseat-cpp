# LicenseSeat - C++ SDK

[![CI](https://github.com/licenseseat/licenseseat-cpp/actions/workflows/ci.yml/badge.svg)](https://github.com/licenseseat/licenseseat-cpp/actions/workflows/ci.yml)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![Platforms](https://img.shields.io/badge/Platforms-Windows%20|%20macOS%20|%20Linux-green.svg)](#platform-support)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

The official C++ SDK for [LicenseSeat](https://licenseseat.com) – the simple, secure licensing platform for apps, games, and plugins.

---

## Features

- **License activation & deactivation** – Activate licenses with automatic device fingerprinting
- **Online & offline validation** – Validate licenses with Ed25519 cryptographic verification
- **Entitlement checking** – Check feature access with `has_entitlement()` and `check_entitlement()`
- **Local caching** – Secure file-based caching with clock tamper detection
- **Auto-validation** – Background validation with configurable intervals
- **Event-driven architecture** – Subscribe to SDK lifecycle events
- **Cross-platform** – Windows, macOS, and Linux support
- **Exception-free** – Uses `Result<T, Error>` pattern for error handling

---

## Installation

### CMake (FetchContent)

Add to your `CMakeLists.txt`:

```cmake
include(FetchContent)

FetchContent_Declare(
    licenseseat
    GIT_REPOSITORY https://github.com/licenseseat/licenseseat-cpp.git
    GIT_TAG        v0.1.0
)
FetchContent_MakeAvailable(licenseseat)

target_link_libraries(your_target PRIVATE licenseseat::licenseseat)
```

### vcpkg

```bash
vcpkg install licenseseat
```

Then in your `CMakeLists.txt`:

```cmake
find_package(licenseseat CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE licenseseat::licenseseat)
```

### Manual Installation

```bash
git clone https://github.com/licenseseat/licenseseat-cpp.git
cd licenseseat-cpp
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
sudo cmake --install build
```

### Dependencies

- **OpenSSL 3.0+** – Cryptographic operations (Ed25519, SHA256)
- **nlohmann/json** – JSON parsing
- **cpp-httplib** – HTTP client

---

## Quick Start

```cpp
#include <licenseseat/licenseseat.hpp>

int main() {
    using namespace licenseseat;

    // 1. Create SDK instance
    ClientConfig config;
    config.api_key = "your-api-key";

    Client sdk(config);

    // 2. Activate a license
    auto result = sdk.activate("YOUR-LICENSE-KEY");
    if (result.is_ok()) {
        std::cout << "License activated!\n";
    } else {
        std::cerr << "Activation failed: " << result.error().message << "\n";
    }

    // 3. Check entitlements
    if (sdk.has_entitlement("pro")) {
        // Enable pro features
    }

    // 4. Get current status
    auto status = sdk.get_status();
    if (status == LicenseStatusType::Active) {
        std::cout << "License is active\n";
    }

    return 0;
}
```

---

## Configuration

```cpp
#include <licenseseat/licenseseat.hpp>

licenseseat::ClientConfig config;

// Required
config.api_key = "your-api-key";

// API Configuration
config.api_base_url = "https://licenseseat.com/api";  // Default

// Storage
config.storage_path = "/path/to/cache";    // License cache directory
config.storage_prefix = "myapp";           // File prefix for multi-product support

// Auto-Validation
config.auto_validate_interval = 3600;      // Seconds (1 hour)

// Offline Support
config.offline_fallback_enabled = true;    // Enable offline validation
config.max_offline_days = 7;               // Max days without online validation
config.max_clock_skew_seconds = 300;       // 5 minutes clock tolerance

// Network
config.max_retries = 3;                    // Retry attempts for failed requests
config.retry_delay_ms = 1000;              // Initial retry delay (exponential backoff)
config.timeout_ms = 30000;                 // Request timeout

// Debug
config.debug = false;                      // Enable debug logging

licenseseat::Client sdk(config);
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `api_key` | `string` | `""` | API key for authentication (required) |
| `api_base_url` | `string` | `"https://licenseseat.com/api"` | API base URL |
| `storage_path` | `string` | System temp dir | Directory for license cache |
| `storage_prefix` | `string` | `"licenseseat"` | Prefix for cache files |
| `auto_validate_interval` | `int` | `3600` | Auto-validation interval in seconds |
| `offline_fallback_enabled` | `bool` | `false` | Enable offline validation on network errors |
| `max_offline_days` | `int` | `0` | Maximum days license works offline (0 = disabled) |
| `max_retries` | `int` | `3` | Max retry attempts for failed API calls |
| `timeout_ms` | `int` | `30000` | Request timeout in milliseconds |
| `debug` | `bool` | `false` | Enable debug logging |

---

## API Reference

### Core Methods

#### `sdk.activate(license_key, options)`

Activates a license key on this device.

```cpp
ActivationOptions options;
options.device_identifier = "custom-device-id";  // Optional: auto-generated if empty
options.metadata = {{"version", "1.0.0"}};       // Optional: custom metadata

auto result = sdk.activate("LICENSE-KEY", options);

if (result.is_ok()) {
    auto& activation = result.value();
    std::cout << "Activated: " << activation.license_key() << "\n";
    std::cout << "Device: " << activation.device_identifier() << "\n";
}
```

#### `sdk.deactivate()`

Deactivates the current license and clears cached data.

```cpp
auto result = sdk.deactivate();
if (result.is_ok()) {
    std::cout << "License deactivated\n";
}
```

#### `sdk.validate(license_key, options)`

Validates a license with the server.

```cpp
ValidationOptions options;
options.device_identifier = "device-id";  // Optional
options.product_slug = "my-product";      // Optional

auto result = sdk.validate("LICENSE-KEY", options);

if (result.is_ok()) {
    auto& validation = result.value();
    if (validation.valid) {
        std::cout << "License is valid\n";
    }
}
```

### Entitlement Methods

#### `sdk.has_entitlement(key)`

Check if an entitlement is active. Returns a simple boolean.

```cpp
if (sdk.has_entitlement("pro")) {
    enable_pro_features();
}

if (sdk.has_entitlement("beta")) {
    show_beta_ui();
}
```

#### `sdk.check_entitlement(key)`

Check entitlement with detailed information.

```cpp
auto result = sdk.check_entitlement("pro");

if (result.active) {
    std::cout << "Entitlement active\n";
    if (result.entitlement) {
        std::cout << "Expires: " << result.entitlement->expires_at << "\n";
    }
} else {
    switch (result.reason) {
        case EntitlementReason::NoLicense:
            std::cout << "No license activated\n";
            break;
        case EntitlementReason::NotFound:
            std::cout << "Entitlement not found\n";
            break;
        case EntitlementReason::Expired:
            std::cout << "Entitlement expired\n";
            break;
    }
}
```

### Status Methods

#### `sdk.get_status()`

Get current license status.

```cpp
auto status = sdk.get_status();

switch (status) {
    case LicenseStatusType::Inactive:
        std::cout << "No license activated\n";
        break;
    case LicenseStatusType::Pending:
        std::cout << "Validation in progress\n";
        break;
    case LicenseStatusType::Active:
        std::cout << "License valid (online)\n";
        break;
    case LicenseStatusType::Invalid:
        std::cout << "License invalid\n";
        break;
    case LicenseStatusType::OfflineValid:
        std::cout << "License valid (offline)\n";
        break;
    case LicenseStatusType::OfflineInvalid:
        std::cout << "License invalid (offline)\n";
        break;
}
```

#### `sdk.get_cached_license()`

Get the cached license information.

```cpp
auto cached = sdk.get_cached_license();
if (cached) {
    std::cout << "License: " << cached->license_key << "\n";
    std::cout << "Device: " << cached->device_identifier << "\n";
}
```

#### `sdk.reset()`

Clear all cached data and reset SDK state.

```cpp
sdk.reset();
```

---

## Events

Subscribe to SDK lifecycle events for reactive updates.

```cpp
// Subscribe to an event
auto subscription = sdk.on("activation:success", [](const EventData& data) {
    std::cout << "License activated!\n";
});

// Unsubscribe
subscription.cancel();
```

### Available Events

| Event | Description |
|-------|-------------|
| **Lifecycle** | |
| `license:loaded` | Cached license loaded on init |
| `sdk:reset` | SDK was reset |
| **Activation** | |
| `activation:start` | Activation started |
| `activation:success` | Activation succeeded |
| `activation:error` | Activation failed |
| **Deactivation** | |
| `deactivation:start` | Deactivation started |
| `deactivation:success` | Deactivation succeeded |
| `deactivation:error` | Deactivation failed |
| **Validation** | |
| `validation:start` | Validation started |
| `validation:success` | Online validation succeeded |
| `validation:failed` | Validation failed (invalid license) |
| `validation:error` | Validation error (network, etc.) |
| `validation:offline-success` | Offline validation succeeded |
| `validation:offline-failed` | Offline validation failed |
| **Auto-Validation** | |
| `autovalidation:cycle` | Auto-validation completed |
| `autovalidation:stopped` | Auto-validation stopped |
| **Network** | |
| `network:online` | Network connectivity restored |
| `network:offline` | Network connectivity lost |
| **Offline License** | |
| `offlineLicense:ready` | Offline license synced |
| `offlineLicense:verified` | Offline signature verified |

---

## Offline Support

The SDK supports offline license validation using cryptographically signed licenses (Ed25519).

```cpp
ClientConfig config;
config.api_key = "your-key";
config.offline_fallback_enabled = true;  // Enable offline fallback
config.max_offline_days = 7;             // Allow 7 days offline

Client sdk(config);

// After activation, offline assets are automatically synced
auto result = sdk.activate("LICENSE-KEY");

// Later, even offline, validation will work using cached data
auto validation = sdk.validate("LICENSE-KEY");
if (validation.is_ok() && validation.value().valid) {
    // License is valid (may be offline)
}
```

### How Offline Validation Works

1. On activation, the SDK fetches a signed offline license from the server
2. The offline license contains license data + Ed25519 signature
3. When offline, the SDK verifies the signature locally using the public key
4. Clock tamper detection prevents users from bypassing expiration

---

## Error Handling

The SDK uses a `Result<T, Error>` pattern instead of exceptions:

```cpp
auto result = sdk.activate("LICENSE-KEY");

if (result.is_ok()) {
    // Success
    auto& activation = result.value();
    std::cout << "Activated: " << activation.license_key() << "\n";
} else {
    // Error
    auto& error = result.error();
    std::cerr << "Error: " << error.message << "\n";

    switch (error.code) {
        case ErrorCode::NetworkError:
            std::cerr << "Network issue - check connection\n";
            break;
        case ErrorCode::LicenseNotFound:
            std::cerr << "Invalid license key\n";
            break;
        case ErrorCode::LicenseExpired:
            std::cerr << "License has expired\n";
            break;
        case ErrorCode::SeatLimitExceeded:
            std::cerr << "Too many activations\n";
            break;
        case ErrorCode::InvalidSignature:
            std::cerr << "Signature verification failed\n";
            break;
        default:
            std::cerr << "Unknown error\n";
            break;
    }
}
```

### Error Codes

| Code | Description |
|------|-------------|
| `NetworkError` | HTTP request failed |
| `Timeout` | Request timed out |
| `LicenseNotFound` | License key not found |
| `LicenseExpired` | License has expired |
| `LicenseInactive` | License is not active |
| `SeatLimitExceeded` | Maximum activations reached |
| `DeviceMismatch` | Device identifier mismatch |
| `InvalidSignature` | Cryptographic verification failed |
| `ClockTamper` | System clock manipulation detected |
| `StorageError` | Failed to read/write cache |
| `ConfigurationError` | Invalid SDK configuration |

---

## Platform Support

| Platform | Compiler | Status |
|----------|----------|--------|
| **Linux** | GCC 9+, Clang 10+ | Full support |
| **macOS** | Apple Clang 12+ | Full support |
| **Windows** | MSVC 2019+ | Full support |

### Device Identification

The SDK automatically generates a unique device identifier:

- **macOS**: IOKit Platform UUID
- **Linux**: `/etc/machine-id` or `/var/lib/dbus/machine-id`
- **Windows**: `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`

---

## Thread Safety

The SDK is designed to be thread-safe:

- All public methods are safe to call from multiple threads
- Internal state is protected by mutexes
- Event callbacks are invoked from the calling thread

```cpp
// Safe to use from multiple threads
std::thread t1([&sdk]() {
    auto status = sdk.get_status();
});

std::thread t2([&sdk]() {
    auto has_pro = sdk.has_entitlement("pro");
});
```

---

## Examples

### Basic Usage

See [`examples/basic_usage.cpp`](examples/basic_usage.cpp) for a complete example.

```bash
# Build examples
cmake -B build -DLICENSESEAT_BUILD_EXAMPLES=ON
cmake --build build

# Run
./build/examples/basic_usage
```

### CMake Integration

```cmake
cmake_minimum_required(VERSION 3.16)
project(my_app)

find_package(licenseseat REQUIRED)

add_executable(my_app main.cpp)
target_link_libraries(my_app PRIVATE licenseseat::licenseseat)
```

---

## Development

### Building from Source

```bash
git clone https://github.com/licenseseat/licenseseat-cpp.git
cd licenseseat-cpp

# Install dependencies (example for macOS)
brew install openssl@3 nlohmann-json cpp-httplib googletest

# Configure and build
cmake -B build \
    -DCMAKE_BUILD_TYPE=Debug \
    -DLICENSESEAT_BUILD_TESTS=ON \
    -DLICENSESEAT_BUILD_EXAMPLES=ON

cmake --build build

# Run tests
cd build && ctest --output-on-failure
```

### Project Structure

```
licenseseat-cpp/
├── include/licenseseat/     # Public headers
│   ├── licenseseat.hpp      # Main include
│   ├── client.hpp           # Client class
│   ├── result.hpp           # Result<T> type
│   ├── license.hpp          # License types
│   ├── events.hpp           # Event system
│   ├── storage.hpp          # Caching
│   ├── crypto.hpp           # Ed25519 verification
│   └── ...
├── src/                     # Implementation
├── tests/                   # Unit tests
├── examples/                # Usage examples
├── CMakeLists.txt
└── vcpkg.json               # vcpkg manifest
```

---

## License

MIT License – see [LICENSE](LICENSE) for details.

---

## Links

- [LicenseSeat Website](https://licenseseat.com)
- [Documentation](https://licenseseat.com/docs)
- [API Reference](https://licenseseat.com/docs/api)
- [GitHub Repository](https://github.com/licenseseat/licenseseat-cpp)
- [Report Issues](https://github.com/licenseseat/licenseseat-cpp/issues)
