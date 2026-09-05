# C++ offline integration

This guide covers the v0.7.0 API with application-pinned signing keys. Keep the
trusted public key in your application's configuration so it can verify licenses
without an internet connection, including after a restart.

## Configure the application

Fetch the organization's public key from its HTTPS signing-key endpoint during
integration and embed the exact `public_key` value in trusted application configuration.
Use the raw 32-byte key encoded as standard Base64, not PEM or DER. A key supplied by
an end user alongside a machine file is not an independent trust anchor.

```cpp
licenseseat::Config config;
config.api_key = "YOUR_PUBLISHABLE_KEY";
config.product_slug = "YOUR_PRODUCT_SLUG";
config.storage_path = "/YOUR_WRITABLE_APPLICATION_CACHE";
config.signing_public_key = "YOUR_BASE64_RAW_ED25519_PUBLIC_KEY";
config.signing_key_id = "YOUR_ORGANIZATION_SIGNING_KEY_ID";
config.offline_fallback_mode = licenseseat::OfflineFallbackMode::NetworkOnly;
config.max_offline_days = 30; // Choose your product's permitted offline duration.
```

Keep this configuration, product, cache path and device fingerprint consistent across
restarts. Offline support defaults to disabled; setting only `storage_path` is insufficient.
Thirty days is a local maximum, not a promise that an expired/revoked artifact remains
usable for that long. Verification also checks signed artifact and license expiry.

## Online provisioning, then offline restart

Check every result. `activate()` succeeding does not prove an offline artifact was
saved: its automatic sync is best effort. The explicit checkout makes a failure visible.
Successful local activation saves the session identity needed by `restore_license()`.
Online validation is optional at provisioning time and retrieves current entitlements.

```cpp
licenseseat::Client client(config);
auto activated = client.activate(license_key);
if (activated.is_error()) throw std::runtime_error(activated.error_message());
auto validated = client.validate(license_key);
if (validated.is_error()) throw std::runtime_error(validated.error_message());
if (!validated.value().valid) throw std::runtime_error(validated.value().message);
auto machine = client.checkout_machine_file(license_key);
if (machine.is_error()) throw std::runtime_error(machine.error_message());
```

On subsequent runs, construct a fresh Client with the same config and check
`restore_license().success`. Treat `OfflineValid` as successful offline verification.
Do not ask the user to activate again on every app launch. `restore_license()` performs
a connectivity check; use `verify_machine_file()` when a strictly local operation is needed.

## Import a certificate fetched using curl

The online provisioning machine must activate and request the machine file using the
TARGET machine's exact fingerprint, collected from `client.fingerprint()` there. The
online helper's own fingerprint is irrelevant. Include `"include": ["license"]` in the
machine-file request if the app needs license details. Transfer the certificate from
`data.attributes.certificate`, not the enclosing JSON response.

A plain certificate can be loaded directly using the public SDK type; no private
`crypto::internal` API or custom certificate parser is necessary when the key is pinned.

```cpp
licenseseat::Client client(config);
licenseseat::MachineFile imported;
imported.certificate = certificate_text;
auto verified = client.verify_machine_file(imported, "", license_key, client.fingerprint());
if (verified.is_error()) throw std::runtime_error(verified.error_message());
if (!verified.value().valid || !verified.value().payload)
    throw std::runtime_error(verified.value().message);
const auto& payload = *verified.value().payload;
if (payload.license) {
    // Use authenticated license details here.
}
```

This verifies independently of a preexisting cached license record. If the application
manages certificate storage itself, persist and reload the certificate there and run
this verification on each startup. Direct verification does not import a session for
`restore_license()`. Do not infer automatic storage or fallback-policy enforcement from
calling the lower-level verifier.

## Dependencies and migration

Both `Activation::id()` and `Deactivation::activation_id` are strings in v0.7.0.
Change integer variables and remove `std::to_string` calls around these fields.
Both JUCE adapters delegate to the core SDK and require OpenSSL.
