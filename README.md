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
- **Session restore** – `restore_license()` handles startup logic (check cache, validate, fallback to offline)
- **Client status** – `get_client_status()` returns `Active`, `OfflineValid`, `Inactive`, `Invalid`, or `Pending`
- **Entitlement checking** – Check feature access with `has_entitlement()` and `check_entitlement()`
- **Local caching** – File-based caching with automatic offline fallback
- **Auto-validation** – Background validation with configurable intervals
- **Heartbeat** – Track active device usage with manual or automatic heartbeats
- **Network recovery** – Auto-restarts validation/heartbeat when connectivity returns
- **Event system** – Subscribe to license events (validation, heartbeat, revocation, network status, etc.)
- **Thread-safe** – All public methods safe to call from multiple threads
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

### Demo App (SynthDemo)

A compact audio synthesizer demo showing LicenseSeat integration. Built with raylib + raygui.

**Features demonstrated:**
- License activation with auto-closing modal
- Feature gating (free: sine wave, Pro: sawtooth/square/noise)
- Session restore on app restart
- Network status indicators
- Toast notifications

**Location:** [`demo/`](demo/)

#### Prerequisites

- CMake 3.16+
- C++17 compiler (Clang, GCC, or MSVC)
- OpenSSL (for HTTPS)

```bash
# macOS
brew install cmake openssl

# Ubuntu/Debian
sudo apt install cmake libssl-dev libgl1-mesa-dev libx11-dev libxrandr-dev libxinerama-dev libxcursor-dev libxi-dev

# Alpine Linux
apk add build-base cmake openssl-dev mesa-dev libx11-dev libxrandr-dev libxinerama-dev libxcursor-dev libxi-dev

# Windows (with vcpkg)
vcpkg install openssl
```

#### Build & Run

```bash
cd demo

# Configure (downloads raylib automatically via FetchContent)
cmake -B build

# Build
cmake --build build

# Run
open build/synthdemo.app                  # macOS
./build/synthdemo                         # Linux
.\build\Debug\synthdemo.exe               # Windows
```

#### Build Options

```bash
# Release build (faster, smaller binary)
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release

# Specify OpenSSL path (if not found automatically)
cmake -B build -DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3
```

> [!NOTE]
> **macOS users:** Window management apps like Magnet or Rectangle can cause click delays due to how they intercept mouse events. If you experience slow button responses, try excluding the app from your window manager's settings.

---

## Single-Header Distribution

For projects where adding dependencies is painful (VST plugins, Unreal Engine, embedded systems), we provide an **amalgamated single-header** version of the SDK.

### Download

Download `licenseseat_single.hpp` from the [latest release](https://github.com/licenseseat/licenseseat-cpp/releases).

### Usage

```cpp
// In exactly ONE .cpp file, define LICENSESEAT_IMPLEMENTATION before including:
#define LICENSESEAT_IMPLEMENTATION
#include "licenseseat_single.hpp"

// In all other files, just include normally:
#include "licenseseat_single.hpp"
```

### Requirements

The single-header still requires two external header-only libraries:

- **[nlohmann/json](https://github.com/nlohmann/json)** – JSON parsing (single header)
- **[cpp-httplib](https://github.com/yhirose/cpp-httplib)** – HTTP client (single header, optional for offline-only)

The single-header does **NOT** require OpenSSL – it uses vendored ed25519 and PicoSHA2.

### Generate Locally

The single-header is auto-generated by CI on every release. To generate locally:

```bash
python3 scripts/amalgamate.py > dist/licenseseat_single.hpp
```

> [!NOTE]
> The `dist/licenseseat_single.hpp` file in the repo may be empty or stale – CI generates the real one during releases. Always download from [releases](https://github.com/licenseseat/licenseseat-cpp/releases) for production use.

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

**Bundled (no installation needed):**
- nlohmann/json – JSON parsing
- cpp-httplib – HTTP client
- ed25519 – Cryptographic signatures
- PicoSHA2 – SHA-256 hashing

**External (the only thing you need to install):**
- OpenSSL – for HTTPS

```bash
# Ubuntu/Debian
sudo apt install libssl-dev

# macOS (usually pre-installed, or:)
brew install openssl

# Windows
# vcpkg install openssl
```

That's it. No other dependencies to install.

---

## Quick Start

```cpp
#include <licenseseat/licenseseat.hpp>

int main()
{
    licenseseat::Config config;
    config.api_key = "pk_live_xxx";
    config.product_slug = "your-product";
    config.storage_path = "~/.myapp/license";  // Enable caching

    licenseseat::Client client(config);

    // Restore session (handles online/offline automatically)
    auto restore = client.restore_license();

    if (restore.status == ClientStatus::Active ||
        restore.status == ClientStatus::OfflineValid) {
        std::cout << "Licensed!\n";

        // Check entitlements
        if (client.has_entitlement("pro")) {
            enable_pro_features();
        }
    } else {
        // Show activation UI
        std::string key = get_license_key_from_user();

        auto result = client.activate(key);
        if (result.is_ok()) {
            std::cout << "Activated!\n";
        }
    }

    return 0;
}
```

---

## Session Restore

The SDK handles the complex startup logic for you with `restore_license()`:

```cpp
licenseseat::Config config;
config.api_key = "pk_live_xxx";
config.product_slug = "your-product";
config.storage_path = "/path/to/cache";

licenseseat::Client client(config);

// One call handles: load cache → check network → validate or verify offline
auto result = client.restore_license();

switch (result.status) {
    case ClientStatus::Active:
        // Online, license valid
        enable_full_features();
        break;
    case ClientStatus::OfflineValid:
        // Offline but cached token valid
        enable_full_features();
        show_offline_indicator();
        break;
    case ClientStatus::Inactive:
        // No cached license, show activation UI
        show_license_prompt();
        break;
    case ClientStatus::Invalid:
        // License revoked or expired
        show_reactivation_prompt();
        break;
}

// Subscribe to changes
client.on(events::LICENSE_REVOKED, [](auto) { show_license_revoked_dialog(); });
client.on(events::NETWORK_ONLINE, [](auto) { hide_offline_indicator(); });
```

---

## Integration Guide

Step-by-step guide to integrating LicenseSeat into your C++ application.

### 1. Get Your Credentials

From your [LicenseSeat Dashboard](https://licenseseat.com/dashboard):

1. **API Key** — Go to Settings → API Keys → Copy your `pk_live_*` key
2. **Product Slug** — Go to Products → Click your product → Copy the slug from the URL

> [!NOTE]
> Use `pk_*` (publishable) keys in client applications. They're safe to embed. Keep `sk_*` (secret) keys server-side only.

### 2. Add the SDK

**CMake FetchContent (recommended):**
```cmake
include(FetchContent)
FetchContent_Declare(licenseseat
    GIT_REPOSITORY https://github.com/licenseseat/licenseseat-cpp.git
    GIT_TAG main)
FetchContent_MakeAvailable(licenseseat)
target_link_libraries(your_target PRIVATE licenseseat::licenseseat)
```

### 3. Initialize & Validate

```cpp
#include <licenseseat/licenseseat.hpp>

licenseseat::Config config;
config.api_key = "pk_live_xxxxxxxx";
config.product_slug = "your-product";
config.storage_path = "/path/to/cache";  // Enables offline fallback
config.app_version = "1.0.0";

licenseseat::Client client(config);

auto result = client.validate("XXXX-XXXX-XXXX-XXXX");
if (result.is_ok() && result.value().valid) {
    // License valid — enable features
    if (client.has_entitlement("pro")) {
        enable_pro_mode();
    }
}
```

### 4. Activate Device (for hardware-locked licenses)

```cpp
std::string device_id = licenseseat::generate_device_id();
auto result = client.activate("LICENSE-KEY", device_id, "User's MacBook");

if (result.is_ok()) {
    std::cout << "Activated!\n";
} else if (result.error_code() == licenseseat::ErrorCode::SeatLimitExceeded) {
    std::cout << "No seats available\n";
}
```

### 5. Enable Offline Support (optional)

```cpp
// Generate and save offline token while online
auto token = client.generate_offline_token("LICENSE-KEY").value();
auto key = client.fetch_signing_key(token.token.kid).value();
std::string json = licenseseat::json::offline_token_to_json(token);
save_to_disk(json, key);

// Later, verify offline
auto [loaded, pub_key] = load_from_disk();
if (client.verify_offline_token(loaded, pub_key).value()) {
    // Valid! Access: loaded.token.plan_key, .metadata, .entitlements
}
```

### 6. Background Validation

```cpp
// Keep license fresh with background checks
client.start_auto_validation("LICENSE-KEY");

// Subscribe to changes
client.on(licenseseat::events::VALIDATION_FAILED, [](auto) {
    show_license_expired_dialog();
});
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

// Optional - Heartbeat
config.heartbeat_interval = 300;  // Seconds between auto-heartbeats (0 to disable)

// Optional - Telemetry
config.telemetry_enabled = true;   // Set false to disable
config.app_version = "2.1.0";     // Included in telemetry
config.app_build = "142";         // Included in telemetry
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
| `telemetry_enabled`      | bool   | `true`                             | Enable anonymous telemetry collection              |
| `app_version`            | string | `""`                               | App version included in telemetry                  |
| `app_build`              | string | `""`                               | Build number included in telemetry                 |
| `heartbeat_interval`     | int    | `300`                              | Seconds between auto-heartbeats (0 to disable)     |

---

## Telemetry & Privacy

The SDK collects anonymous platform telemetry to help developers understand their user base. This data is sent alongside every API request (validation, activation, heartbeat, etc.) and includes the following fields:

| Field               | Type   | Example                  | Description                                            |
| ------------------- | ------ | ------------------------ | ------------------------------------------------------ |
| `sdk_name`          | string | `"cpp"`                  | Always `"cpp"` for this SDK                            |
| `sdk_version`       | string | `"0.4.1"`               | SDK version                                            |
| `os_name`           | string | `"macOS"`                | Operating system (`"macOS"`, `"Windows"`, `"Linux"`)   |
| `os_version`        | string | `"15.3"`                 | OS version string                                      |
| `platform`          | string | `"native"`               | Always `"native"` for this SDK                         |
| `device_model`      | string | `"Mac14,2"`              | Hardware model identifier                              |
| `device_type`       | string | `"desktop"`              | Device type (`"desktop"`, `"server"`, `"unknown"`)     |
| `architecture`      | string | `"arm64"`                | CPU architecture (`"arm64"`, `"x64"`, `"x86"`, `"arm"`) |
| `cpu_cores`         | int    | `10`                     | Number of logical CPU cores                            |
| `memory_gb`         | int    | `16`                     | Total system RAM in GB (rounded)                       |
| `locale`            | string | `"en_US.UTF-8"`          | System locale string                                   |
| `language`           | string | `"en"`                   | Two-letter language code extracted from locale          |
| `timezone`          | string | `"America/New_York"`     | System timezone                                        |
| `screen_resolution` | string | `"1920x1080"`            | Primary display resolution                             |
| `app_version`       | string | `"2.1.0"`               | User-provided via `config.app_version`                 |
| `app_build`         | string | `"142"`                  | User-provided via `config.app_build`                   |

No personally identifiable information is collected. Fields that cannot be determined on a given platform are omitted from the payload.

To include your application version in telemetry:

```cpp
config.app_version = "2.1.0";
config.app_build = "142";
```

To disable telemetry entirely:

```cpp
config.telemetry_enabled = false;
```

---

## Heartbeat

Heartbeats let the server know a device is actively using a license. This powers the "last seen" timestamp and active-device analytics in the LicenseSeat dashboard.

### Manual Heartbeat

Send a one-off heartbeat at any time:

```cpp
auto result = client.heartbeat("LICENSE-KEY");

if (result.is_ok()) {
    std::cout << "Heartbeat received at: " << result.value().received_at << "\n";
}

// Async variant
client.heartbeat_async("LICENSE-KEY", [](auto result) {
    if (result.is_ok()) {
        std::cout << "Heartbeat sent\n";
    }
});
```

### Auto-Heartbeat Timer

Start a background timer that sends heartbeats at a regular interval:

```cpp
// Configure interval (default is 300 seconds / 5 minutes)
config.heartbeat_interval = 600;  // Every 10 minutes (0 to disable)

licenseseat::Client client(config);

// Start the timer
client.start_heartbeat("LICENSE-KEY");

// Check if running
if (client.is_heartbeat_running()) {
    std::cout << "Heartbeat timer is active\n";
}

// Stop when done (also stops automatically on destruction)
client.stop_heartbeat();
```

Heartbeats are also sent automatically as part of each auto-validation cycle, so if you are already using `start_auto_validation()` you may not need a separate heartbeat timer.

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

### Metadata Access

Licenses can have custom key-value metadata attached. Access it from the `License` object:

```cpp
auto result = client.validate("LICENSE-KEY");
if (result.is_ok() && result.value().valid) {
    const auto& license = result.value().license;

    // Access license-level metadata
    const auto& metadata = license.metadata();  // std::map<std::string, std::string>

    // Check for a specific key
    if (metadata.count("customer_id")) {
        std::string customer_id = metadata.at("customer_id");
        std::cout << "Customer ID: " << customer_id << "\n";
    }

    // Iterate all metadata
    for (const auto& [key, value] : metadata) {
        std::cout << key << " = " << value << "\n";
    }
}
```

Entitlements can also have their own per-feature metadata:

```cpp
for (const auto& ent : license.active_entitlements()) {
    std::cout << "Entitlement: " << ent.key << "\n";

    // Per-entitlement metadata
    for (const auto& [key, value] : ent.metadata) {
        std::cout << "  " << key << " = " << value << "\n";
    }
}
```

From offline tokens, metadata is accessed directly:

```cpp
// License metadata from offline token
for (const auto& [key, value] : offline_token.token.metadata) {
    std::cout << key << " = " << value << "\n";
}

// Entitlement metadata from offline token
for (const auto& ent : offline_token.token.entitlements) {
    for (const auto& [key, value] : ent.metadata) {
        std::cout << "  " << key << " = " << value << "\n";
    }
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

The SDK supports offline license validation using Ed25519 cryptographic signatures.

### Automatic (Recommended)

Just set `storage_path` and call `activate()` — the SDK handles everything:

```cpp
config.storage_path = "/path/to/cache";
licenseseat::Client client(config);

client.activate("LICENSE-KEY");  // Automatically syncs offline assets

// If network fails later, validation automatically falls back to cached offline token
auto result = client.validate("LICENSE-KEY");  // Works offline!
```

### Manual Storage

For custom storage (encrypted, database, etc.), use the serialization helpers:

```cpp
#include <licenseseat/json.hpp>

// Save (online)
auto token = client.generate_offline_token("LICENSE-KEY").value();
auto key = client.fetch_signing_key(token.token.kid).value();

std::string token_json = licenseseat::json::offline_token_to_json(token);
// Save token_json and key to your storage

// Load and verify (offline)
auto loaded = licenseseat::json::offline_token_from_json(token_json);
if (client.verify_offline_token(loaded, key).value()) {
    // Access license data
    std::cout << "Plan: " << loaded.token.plan_key << "\n";
    for (const auto& [k, v] : loaded.token.metadata) {
        std::cout << k << " = " << v << "\n";
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

| Event Name                       | Description                                  |
| -------------------------------- | -------------------------------------------- |
| `LICENSE_LOADED`                 | License data loaded from cache               |
| `LICENSE_REVOKED`                | License has been revoked by server           |
| `ACTIVATION_START`               | Activation request starting                  |
| `ACTIVATION_SUCCESS`             | Device activated successfully                |
| `ACTIVATION_ERROR`               | Activation failed                            |
| `VALIDATION_START`               | Validation request starting                  |
| `VALIDATION_SUCCESS`             | License validated successfully (online)      |
| `VALIDATION_FAILED`              | License validation returned invalid          |
| `VALIDATION_ERROR`               | Validation request failed (network, etc.)    |
| `VALIDATION_AUTH_FAILED`         | Authentication failed (invalid API key)      |
| `VALIDATION_OFFLINE_SUCCESS`     | Offline token verified successfully          |
| `VALIDATION_OFFLINE_FAILED`      | Offline token verification failed            |
| `VALIDATION_AUTO_FAILED`         | Auto-validation cycle failed                 |
| `DEACTIVATION_START`             | Deactivation request starting                |
| `DEACTIVATION_SUCCESS`           | Device deactivated successfully              |
| `DEACTIVATION_ERROR`             | Deactivation failed                          |
| `NETWORK_ONLINE`                 | Network connectivity restored                |
| `NETWORK_OFFLINE`                | Network connectivity lost                    |
| `AUTOVALIDATION_CYCLE`           | Auto-validation cycle completed              |
| `AUTOVALIDATION_STOPPED`         | Auto-validation stopped                      |
| `OFFLINE_TOKEN_FETCHING`         | Fetching offline token from server           |
| `OFFLINE_TOKEN_FETCHED`          | Offline token fetched successfully           |
| `OFFLINE_TOKEN_FETCH_ERROR`      | Failed to fetch offline token                |
| `OFFLINE_TOKEN_READY`            | Offline token ready for use                  |
| `OFFLINE_TOKEN_VERIFIED`         | Offline token verified locally               |
| `OFFLINE_TOKEN_VERIFICATION_FAILED` | Offline token local verification failed   |
| `HEARTBEAT_SUCCESS`              | Heartbeat sent successfully                  |
| `HEARTBEAT_ERROR`                | Heartbeat request failed                     |
| `SDK_RESET`                      | SDK state reset                              |
| `SDK_ERROR`                      | SDK encountered an error                     |

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

---

## Docker

Docker images are provided for testing and building in clean environments.

### Alpine (Recommended)

Smallest image, all dependencies bundled except OpenSSL:

```bash
# Build
docker build -f docker/Dockerfile.alpine -t licenseseat-cpp .

# Run tests
docker run --rm licenseseat-cpp

# Interactive shell
docker run -it --rm licenseseat-cpp sh
```

### Docker Compose

```bash
# Run all unit tests
docker compose -f docker/docker-compose.yml up unit-tests --build

# Run integration tests (requires credentials)
LICENSESEAT_API_KEY=pk_xxx LICENSESEAT_PRODUCT_SLUG=your-product LICENSESEAT_LICENSE_KEY=XXXX-XXXX \
  docker compose -f docker/docker-compose.yml run integration-tests
```

---

## Testing

```bash
cmake -B build -DLICENSESEAT_BUILD_TESTS=ON
cmake --build build
./build/tests/licenseseat_tests
```

```
[==========] 298 tests from 69 test suites ran. (636 ms total)
[  PASSED  ] 298 tests.
```

### Test Suites

The SDK includes comprehensive tests:

| Test Suite           | Tests | Network | Description                                 |
| -------------------- | ----- | ------- | ------------------------------------------- |
| Unit tests           | 298   | No      | Core functionality, parsing, crypto         |
| Crypto stress tests  | 44    | Yes     | Ed25519, Base64, offline token verification |
| Integration tests    | 48    | Yes     | Full API testing                            |
| Scenario tests       | 38    | Yes     | Real-world workflows (10 scenarios)         |
| Offline workflow     | 4     | Yes     | Manual & automatic offline storage          |

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
│   ├── nlohmann/           # JSON parser
│   ├── httplib/            # HTTP client
│   └── PicoSHA2/           # SHA-256 (header-only)
├── integrations/
│   ├── unreal/             # Unreal Engine plugin
│   └── juce/               # JUCE/VST integration
├── dist/                    # Distribution builds
│   └── licenseseat_single.hpp  # Single-header (auto-generated)
├── docker/                  # Docker build environments
├── scripts/
│   └── amalgamate.py       # Single-header generator
├── tests/                   # Unit & integration tests
├── demo/                    # ImageTool Pro demo app
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
