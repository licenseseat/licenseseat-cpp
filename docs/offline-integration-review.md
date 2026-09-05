# C++ offline integration recipe verified during the 2026-09-05 review

This is a proposed integration guide, not a claim that a new release is available.
Verified locally against SDK commit ddacd678 with real Ed25519 signatures and
AES-GCM certificates through an HTTP loopback server. This guide explicitly chooses
application-pinned signing keys as the offline trust model. An unsigned local key
cache must not become a trust anchor.

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
On this SDK version, `validate()` must run successfully online to populate the license
record used by `restore_license()`.

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

The review's `SupportedProvisioningValidateThenRestartWorks` test destroys the first
Client, stops its server, and successfully restores from the disk cache in a new Client.

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

The review's `CurlCertificateOnlyVerifiesWithPinnedKeyAndRejectsTampering` test covers
this import and rejects altered bytes, a different license key, and a different device.

## Release checks still outstanding

The proposed v0.7.0 branch has a merge conflict and fails its release-version validator.
Its UUID path works locally, but do not tell users to fetch that tag until the release
actually exists and its published package is tested. Windows and Unreal require native
build verification. The root README's zero-OpenSSL JUCE claim is obsolete: both JUCE
adapters delegate to the core SDK and require OpenSSL.
