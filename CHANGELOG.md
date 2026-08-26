# Changelog

All notable changes to the LicenseSeat C++ SDK will be documented in this file.

## [Unreleased]

## [0.6.1] - 2026-08-26

### Fixed

- The WebAssembly demo no longer takes the whole page down when the browser
  refuses a WebGL context. `InitWindow()` only warns when its platform backend
  fails, so the demo went on to call `BeginDrawing()`, which writes the identity
  matrix through rlgl's still-NULL current-matrix pointer: the store lands on
  address zero and Emscripten aborts the module with "The application has
  corrupted its heap memory area (address zero)!". Reported on Chromium/Linux,
  where a missing or blocklisted GPU is common. The demo now checks
  `IsWindowReady()`, tells the embedding page through `Module.onDemoUnsupported`,
  and exits before touching graphics or audio.
- The standalone `synthdemo.html` shell explains that the browser cannot run the
  demo instead of leaving a permanent spinner.

### Changed

- Pinned raylib and raygui to exact commits, and made the raylib web-backend
  patch idempotent, so the shipped WASM bundle rebuilds reproducibly instead of
  tracking whatever `master` happened to be that day.

## [0.6.0] - 2026-08-10

### Security

- Hardened URL, request, response, JSON, identifier, timestamp, and offline-artifact validation with explicit size and complexity bounds.
- Bound offline tokens and machine files to the requested license and local fingerprint, and made unsupported or inconsistent signed claims fail closed.
- Replaced the legacy vendored Ed25519 implementation with OpenSSL EVP verification and strict canonical Base64 handling.
- Upgraded the vendored HTTP transport from cpp-httplib 0.15.3 to 0.52.0, which includes fixes for published client-side credential-leakage, TLS-verification, response-parsing, and denial-of-service advisories.
- Upgraded nlohmann/json to 3.12.0 and added exact source hashes, upstream commit provenance, and fail-closed OSV checks for all vendored dependencies.
- Hardened file persistence against symlink attacks, partial writes, unbounded reads, unsafe names, and concurrent snapshot corruption.
- Pinned CI and release actions to immutable commits and added release checksums and signed build-provenance attestations.
- Made offline authorization fail closed by default: both an explicit fallback mode and a positive bounded grace period are now required, and disabled clients no longer fetch or refresh offline credentials.

### Changed

- Unified event subscription ownership and strengthened client timer, callback, and teardown concurrency behavior.
- Aligned the JUCE and Unreal integrations with the same secret-safe request and response-binding rules as the core SDK.

## [0.4.0] - 2026-02-09

### Added

- **Telemetry**: Collect 16 anonymous platform fields (up from 7) sent alongside API requests:
  - `sdk_name`, `sdk_version` -- SDK identification
  - `os_name`, `os_version`, `platform` -- Operating system
  - `device_model`, `device_type`, `architecture` -- Hardware
  - `cpu_cores`, `memory_gb` -- System resources
  - `locale`, `language`, `timezone` -- Locale and region
  - `screen_resolution` -- Display
  - `app_version`, `app_build` -- User-provided application version
- **Heartbeat**: New `heartbeat()` and `heartbeat_async()` methods to signal active device usage
- **Auto-heartbeat timer**: `start_heartbeat()` / `stop_heartbeat()` for periodic background heartbeats
- **Heartbeat config**: `heartbeat_interval` option (default 300 seconds, 0 to disable)
- **Heartbeat events**: `heartbeat:success` and `heartbeat:error` event callbacks
- **Telemetry config**: `app_version` and `app_build` config options for user-provided version info
- Heartbeats are also sent automatically during auto-validation cycles

## [0.3.0] - 2026-01-21

### Added

- Initial public release with activation, validation, deactivation, offline tokens, auto-validation, and event system
