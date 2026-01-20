# LicenseSeat Unreal Engine Plugin

Native license management for Unreal Engine games.

## Features

- **Zero External Dependencies** - Uses UE's HTTP and JSON modules
- **Blueprint Support** - Full Blueprint API for rapid prototyping
- **Async Operations** - Non-blocking API for smooth gameplay
- **Offline Support** - Ed25519 signature verification for offline licenses
- **Auto-Validation** - Automatic periodic license re-validation
- **Cross-Platform** - Windows, macOS, Linux support

## Quick Start

### 1. Install the Plugin

Copy the `LicenseSeat` folder to your project's `Plugins` directory:

```
YourProject/
├── Content/
├── Source/
└── Plugins/
    └── LicenseSeat/
        ├── LicenseSeat.uplugin
        └── Source/
```

### 2. Add Third-Party Dependencies

Copy the vendored crypto libraries to the plugin's ThirdParty folder:

```
LicenseSeat/Source/LicenseSeat/Private/ThirdParty/
├── ed25519/          # Copy from deps/ed25519
│   ├── ed25519.h
│   ├── *.c files
│   └── *.h files
└── picosha2.h        # Copy from deps/PicoSHA2/picosha2.h
```

### 3. Enable the Plugin

Edit your `.uproject` file:

```json
{
    "Plugins": [
        {
            "Name": "LicenseSeat",
            "Enabled": true
        }
    ]
}
```

### 4. Configure and Use

**In C++:**

```cpp
#include "LicenseSeatSubsystem.h"

void AMyGameMode::BeginPlay()
{
    Super::BeginPlay();

    // Get the subsystem
    auto* LicenseSeat = GetGameInstance()->GetSubsystem<ULicenseSeatSubsystem>();

    // Configure
    FLicenseSeatConfig Config;
    Config.ApiKey = TEXT("your-api-key");
    Config.ProductSlug = TEXT("your-product");
    LicenseSeat->InitializeWithConfig(Config);

    // Validate async
    LicenseSeat->ValidateAsync(TEXT("LICENSE-KEY-HERE"),
        FOnValidationComplete::CreateLambda([](const FLicenseValidationResult& Result)
        {
            if (Result.bValid)
            {
                UE_LOG(LogTemp, Log, TEXT("License valid!"));
            }
            else
            {
                UE_LOG(LogTemp, Warning, TEXT("License invalid: %s"), *Result.Reason);
            }
        }));
}
```

**In Blueprints:**

1. Get the LicenseSeat Subsystem node
2. Call "Initialize With Config" with your API key
3. Call "Validate Async" with your license key
4. Handle the callback

## API Reference

### Configuration

| Property | Type | Description |
|----------|------|-------------|
| ApiKey | FString | Your LicenseSeat API key |
| ProductSlug | FString | Product identifier |
| ApiUrl | FString | API base URL (default: https://licenseseat.com/api) |
| OfflinePublicKey | FString | Ed25519 public key for offline verification |
| MaxOfflineDays | int32 | Maximum offline operation days |
| AutoValidateInterval | float | Auto-validation interval in seconds |

### Methods

| Method | Description |
|--------|-------------|
| `Validate(LicenseKey)` | Synchronous validation (blocks!) |
| `ValidateAsync(LicenseKey, Callback)` | Async validation (recommended) |
| `Activate(LicenseKey)` | Synchronous activation |
| `ActivateAsync(LicenseKey, Callback)` | Async activation |
| `Deactivate(LicenseKey)` | Deactivate current device |
| `GetStatus()` | Get current license status |
| `IsLicenseValid()` | Quick validity check |
| `GetDeviceId()` | Get device identifier |
| `StartAutoValidation(LicenseKey)` | Start periodic validation |
| `StopAutoValidation()` | Stop periodic validation |

### Events

| Event | Description |
|-------|-------------|
| `OnLicenseStatusChanged` | Fired when license status changes |

## Best Practices

1. **Use Async Methods** - Sync methods block the game thread
2. **Handle Offline** - Implement offline license for reliability
3. **Cache Results** - Don't validate on every frame
4. **Auto-Validation** - Use auto-validation for long sessions
5. **Graceful Degradation** - Allow limited functionality when offline

## Platform Notes

### Windows
Device ID uses Windows Machine GUID.

### macOS
Device ID uses hardware UUID. Requires IOKit framework (auto-linked).

### Linux
Device ID uses login ID + hostname combination.

## Troubleshooting

### "Module not found" error
Ensure the plugin folder name matches "LicenseSeat" exactly.

### Build errors about missing headers
Copy the ThirdParty dependencies as described in step 2.

### Network errors
Check API key and ensure internet connectivity.
Try the synchronous `Validate()` method to debug.

## Support

- Documentation: https://docs.licenseseat.com/sdks/unreal
- Issues: https://github.com/licenseseat/licenseseat-cpp/issues
- Email: support@licenseseat.com
