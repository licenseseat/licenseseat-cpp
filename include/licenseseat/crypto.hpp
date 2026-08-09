#pragma once

/**
 * @file crypto.hpp
 * @brief Cryptographic utilities for LicenseSeat SDK
 *
 * Provides Ed25519 signature verification through OpenSSL EVP, together with
 * strict Base64/Base64URL handling and machine-file cryptography.
 */

#include "licenseseat.hpp"

#include <string>
#include <vector>

namespace licenseseat {
namespace crypto {

// ==================== Base64 Encoding/Decoding ====================

/// Encode bytes to standard Base64
[[nodiscard]] std::string base64_encode(const std::vector<uint8_t>& data);

/// Encode bytes to Base64URL (RFC 4648)
[[nodiscard]] std::string base64url_encode(const std::vector<uint8_t>& data);

/// Decode standard Base64 to bytes
[[nodiscard]] std::vector<uint8_t> base64_decode(const std::string& encoded);

/// Decode Base64URL to bytes
[[nodiscard]] std::vector<uint8_t> base64url_decode(const std::string& encoded);

// ==================== Ed25519 Signature Verification ====================

/**
 * @brief Verify an Ed25519 signature
 *
 * @param message The message that was signed
 * @param signature_b64 Base64URL-encoded signature (64 bytes when decoded)
 * @param public_key_b64 Base64-encoded Ed25519 public key (32 bytes when decoded)
 * @return Result<bool> True if signature is valid, error otherwise
 */
[[nodiscard]] Result<bool> verify_ed25519_signature(const std::string& message,
                                                    const std::string& signature_b64,
                                                    const std::string& public_key_b64);

/**
 * @brief Verify an offline token signature
 *
 * Verifies the Ed25519 signature against the canonical JSON string.
 *
 * @param offline_token The offline token to verify
 * @param public_key_b64 Base64-encoded Ed25519 public key
 * @return Result<bool> True if valid, error otherwise
 */
[[nodiscard]] Result<bool> verify_offline_token_signature(const OfflineToken& offline_token,
                                                          const std::string& public_key_b64);

/**
 * @brief Verify and decrypt a machine file certificate
 *
 * @param machine_file The machine file to verify
 * @param license_key The license key used to derive the AES key
 * @param fingerprint The local device fingerprint used to derive the AES key
 * @param public_key_b64 Base64-encoded Ed25519 public key
 * @return Result<MachineFilePayload> Decrypted machine-file payload on success
 */
[[nodiscard]] Result<MachineFilePayload> verify_machine_file(const MachineFile& machine_file,
                                                             const std::string& license_key,
                                                             const std::string& fingerprint,
                                                             const std::string& public_key_b64);

namespace internal {

/// Parse a machine-file envelope using the same strict framing rules as
/// verification and return its untrusted key identifier for key selection.
[[nodiscard]] Result<std::string> extract_machine_file_key_id(const MachineFile& machine_file);

} // namespace internal

} // namespace crypto
} // namespace licenseseat
