#pragma once

/**
 * @file crypto.hpp
 * @brief Cryptographic utilities for LicenseSeat SDK
 *
 * Provides Ed25519 signature verification and Base64/Base64URL encoding
 * using vendored libraries (orlp/ed25519 and PicoSHA2).
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
 * @brief Verify an offline license signature
 *
 * Reconstructs the canonical JSON payload and verifies the Ed25519 signature.
 *
 * @param offline_license The offline license to verify
 * @param public_key_b64 Base64-encoded Ed25519 public key
 * @return Result<bool> True if valid, error otherwise
 */
[[nodiscard]] Result<bool> verify_offline_license_signature(const OfflineLicense& offline_license,
                                                            const std::string& public_key_b64);

}  // namespace crypto
}  // namespace licenseseat
