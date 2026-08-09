# LicenseSeat Unreal Engine plugin

The plugin provides online license validation and activation through Unreal Engine's HTTP and JSON modules, with Blueprint support and periodic revalidation. Unreal Engine 5.4 or newer is required so redirected requests can be detected through `GetEffectiveURL()`.

Offline authorization is not implemented in this plugin. `OfflinePublicKey` and `MaxOfflineDays` remain reserved configuration fields for source compatibility, but they do not grant offline authority. Do not treat a cached Blueprint value as a verified offline license.

## Installation

Copy `integrations/unreal/LicenseSeat` into the project's `Plugins` directory and enable the plugin in the `.uproject` file:

```json
{
  "Plugins": [
    { "Name": "LicenseSeat", "Enabled": true }
  ]
}
```

## Usage

```cpp
#include "LicenseSeatSubsystem.h"

void AMyGameMode::BeginPlay()
{
    Super::BeginPlay();

    auto* LicenseSeat = GetGameInstance()->GetSubsystem<ULicenseSeatSubsystem>();
    FLicenseSeatConfig Config;
    Config.ApiKey = TEXT("your-api-key");
    Config.ProductSlug = TEXT("your-product");
    Config.ApiUrl = TEXT("https://licenseseat.com/api/v1");
    Config.RequestTimeoutSeconds = 30.0f;
    Config.MaxResponseBytes = 1024 * 1024;
    LicenseSeat->InitializeWithConfig(Config);

    LicenseSeat->ValidateAsync(
        TEXT("LICENSE-KEY-HERE"),
        FOnValidationComplete::CreateLambda([](const FLicenseValidationResult& Result)
        {
            if (!Result.bValid)
                UE_LOG(LogTemp, Warning, TEXT("License invalid: %s"), *Result.Reason);
        }));
}
```

The asynchronous APIs are recommended. The synchronous methods block and must not be called from latency-sensitive game or render paths.

## API

| Method | Purpose |
| --- | --- |
| `ValidateAsync` / `Validate` | Validate a key and bind the returned license identity to the request |
| `ActivateAsync` / `Activate` | Activate the current device |
| `Deactivate` | Deactivate the current device |
| `GetStatus` / `IsLicenseValid` | Read the most recent in-memory result |
| `GetDeviceId` | Read the stable device fingerprint generated at subsystem initialization |
| `StartAutoValidation` / `StopAutoValidation` | Manage bounded periodic revalidation |

## Security behavior

- Production configuration requires an `https://` API URL. Plain HTTP is accepted only for `localhost`, `127.0.0.1`, or `[::1]` when `bAllowInsecureLoopback` is explicitly enabled.
- API keys and license keys containing control characters are rejected.
- License keys are sent in bounded JSON bodies, not URL paths, so proxies and access logs do not receive them in request targets.
- Redirect handling remains under Unreal's HTTP implementation; configure the platform HTTP stack not to follow cross-origin redirects for this plugin in production.
- Successful responses must be bounded JSON with a 2xx status and `application/json` content type.
- Validation and activation responses are checked for object type, requested license key, device fingerprint, product slug, active status, known mode, plan, and valid timestamps before they become authoritative.
- Async callbacks use a weak subsystem reference and are suppressed after deinitialization.
- Auto-validation intervals, request timeouts, and response sizes are finite and bounded.

## Platform notes

The plugin uses Unreal's platform machine identifier and the vendored PicoSHA2 header to preserve its existing stable device fingerprint. The unused vendored Ed25519 implementation was removed; no offline signature verifier is exposed by the current plugin.
