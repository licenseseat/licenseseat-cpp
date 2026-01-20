/**
 * @file crypto_minimal.cpp
 * @brief Minimal crypto implementation without OpenSSL dependency
 *
 * Uses vendored libraries:
 * - orlp/ed25519 for Ed25519 signature verification
 * - PicoSHA2 for SHA-256 hashing
 *
 * This file is compiled when LICENSESEAT_USE_OPENSSL=OFF
 */

#ifndef LICENSESEAT_USE_OPENSSL

#include "licenseseat/crypto.hpp"
#include "licenseseat/json.hpp"

// Vendored ed25519 library
extern "C" {
#include "ed25519/ed25519.h"
}

// Vendored PicoSHA2 library (header-only)
#include "PicoSHA2/picosha2.h"

#include <algorithm>
#include <cstring>

namespace licenseseat {
namespace crypto {

// ==================== Base64 Encoding/Decoding ====================
// Pure C++ implementation without OpenSSL

namespace {

const char BASE64_CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

inline int base64_char_value(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

}  // namespace

std::string base64_encode(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return "";
    }

    std::string result;
    result.reserve(((data.size() + 2) / 3) * 4);

    size_t i = 0;
    while (i < data.size()) {
        uint32_t octet_a = i < data.size() ? data[i++] : 0;
        uint32_t octet_b = i < data.size() ? data[i++] : 0;
        uint32_t octet_c = i < data.size() ? data[i++] : 0;

        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        result += BASE64_CHARS[(triple >> 18) & 0x3F];
        result += BASE64_CHARS[(triple >> 12) & 0x3F];
        result += BASE64_CHARS[(triple >> 6) & 0x3F];
        result += BASE64_CHARS[triple & 0x3F];
    }

    // Add padding
    size_t mod = data.size() % 3;
    if (mod == 1) {
        result[result.size() - 1] = '=';
        result[result.size() - 2] = '=';
    } else if (mod == 2) {
        result[result.size() - 1] = '=';
    }

    return result;
}

std::string base64url_encode(const std::vector<uint8_t>& data) {
    std::string encoded = base64_encode(data);

    // Convert to Base64URL: replace + with -, / with _, remove padding
    std::replace(encoded.begin(), encoded.end(), '+', '-');
    std::replace(encoded.begin(), encoded.end(), '/', '_');

    // Remove padding
    while (!encoded.empty() && encoded.back() == '=') {
        encoded.pop_back();
    }

    return encoded;
}

std::vector<uint8_t> base64_decode(const std::string& encoded) {
    if (encoded.empty()) {
        return {};
    }

    // Add padding if necessary
    std::string padded = encoded;
    while (padded.size() % 4 != 0) {
        padded += '=';
    }

    std::vector<uint8_t> result;
    result.reserve((padded.size() / 4) * 3);

    size_t i = 0;
    while (i < padded.size()) {
        int sextet_a = padded[i] == '=' ? 0 : base64_char_value(static_cast<unsigned char>(padded[i]));
        int sextet_b = padded[i + 1] == '=' ? 0 : base64_char_value(static_cast<unsigned char>(padded[i + 1]));
        int sextet_c = padded[i + 2] == '=' ? 0 : base64_char_value(static_cast<unsigned char>(padded[i + 2]));
        int sextet_d = padded[i + 3] == '=' ? 0 : base64_char_value(static_cast<unsigned char>(padded[i + 3]));

        if (sextet_a < 0 || sextet_b < 0 || sextet_c < 0 || sextet_d < 0) {
            // Invalid base64 character
            return {};
        }

        uint32_t triple = (static_cast<uint32_t>(sextet_a) << 18) +
                          (static_cast<uint32_t>(sextet_b) << 12) +
                          (static_cast<uint32_t>(sextet_c) << 6) +
                          static_cast<uint32_t>(sextet_d);

        result.push_back(static_cast<uint8_t>((triple >> 16) & 0xFF));
        if (padded[i + 2] != '=') {
            result.push_back(static_cast<uint8_t>((triple >> 8) & 0xFF));
        }
        if (padded[i + 3] != '=') {
            result.push_back(static_cast<uint8_t>(triple & 0xFF));
        }

        i += 4;
    }

    return result;
}

std::vector<uint8_t> base64url_decode(const std::string& encoded) {
    // Convert from Base64URL to standard Base64
    std::string standard = encoded;
    std::replace(standard.begin(), standard.end(), '-', '+');
    std::replace(standard.begin(), standard.end(), '_', '/');

    return base64_decode(standard);
}

// ==================== Ed25519 Signature Verification ====================

Result<bool> verify_ed25519_signature(const std::string& message,
                                      const std::string& signature_b64,
                                      const std::string& public_key_b64) {
    // Decode signature (Base64URL)
    std::vector<uint8_t> signature = base64url_decode(signature_b64);
    if (signature.size() != 64) {
        return Result<bool>::error(ErrorCode::InvalidSignature,
                                   "Invalid signature length (expected 64 bytes, got " +
                                       std::to_string(signature.size()) + ")");
    }

    // Decode public key (standard Base64)
    std::vector<uint8_t> public_key = base64_decode(public_key_b64);
    if (public_key.size() != 32) {
        return Result<bool>::error(ErrorCode::InvalidParameter,
                                   "Invalid public key length (expected 32 bytes, got " +
                                       std::to_string(public_key.size()) + ")");
    }

    // Verify using orlp/ed25519
    int result = ed25519_verify(signature.data(),
                                reinterpret_cast<const unsigned char*>(message.data()),
                                message.size(),
                                public_key.data());

    if (result == 1) {
        return Result<bool>::ok(true);
    } else {
        return Result<bool>::error(ErrorCode::InvalidSignature, "Signature verification failed");
    }
}

Result<bool> verify_offline_license_signature(const OfflineLicense& offline_license,
                                              const std::string& public_key_b64) {
    // Check basic validity first
    if (offline_license.license_key.empty()) {
        return Result<bool>::error(ErrorCode::InvalidLicenseKey, "License key is empty");
    }

    if (offline_license.signature_b64u.empty()) {
        return Result<bool>::error(ErrorCode::InvalidSignature, "Signature is empty");
    }

    if (public_key_b64.empty()) {
        return Result<bool>::error(ErrorCode::MissingParameter, "Public key is required");
    }

    // Reconstruct canonical JSON payload for verification
    std::string canonical_payload = json::offline_license_to_canonical_json(offline_license);

    // Verify the signature
    return verify_ed25519_signature(canonical_payload, offline_license.signature_b64u,
                                    public_key_b64);
}

}  // namespace crypto

// ==================== SHA-256 for Device ID ====================
// This is used by device.cpp for hashing the device identifier

namespace device {
namespace internal {

std::string sha256_hex(const std::string& input) {
    if (input.empty()) {
        return "";
    }

    std::string hash_hex;
    picosha2::hash256_hex_string(input, hash_hex);
    return hash_hex;
}

}  // namespace internal
}  // namespace device

}  // namespace licenseseat

#endif  // !LICENSESEAT_USE_OPENSSL
