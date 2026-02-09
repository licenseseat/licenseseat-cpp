# Changelog

All notable changes to the LicenseSeat C++ SDK will be documented in this file.

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
