/**
 * @file crypto.cpp
 * @brief Crypto implementation for signatures, hashing, and machine files
 *
 * Uses vendored libraries:
 * - orlp/ed25519 for Ed25519 signature verification
 * - PicoSHA2 for SHA-256 hashing
 *
 * AES-256-GCM machine-file decryption currently uses OpenSSL EVP.
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

#include <openssl/evp.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <memory>

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

struct ParsedMachineFileEnvelope {
    std::string enc;
    std::string sig;
    std::string alg;
    std::string kid;
};

std::vector<uint8_t> sha256_bytes(const std::string& input) {
    std::vector<uint8_t> hash(picosha2::k_digest_size);
    picosha2::hash256(input.begin(), input.end(), hash.begin(), hash.end());
    return hash;
}

Result<ParsedMachineFileEnvelope> parse_machine_file_envelope(const std::string& certificate) {
    if (certificate.empty()) {
        return Result<ParsedMachineFileEnvelope>::error(ErrorCode::MissingParameter,
                                                        "Machine file certificate is empty");
    }

    std::string cleaned = certificate;
    const std::string begin_marker = "-----BEGIN MACHINE FILE-----";
    const std::string end_marker = "-----END MACHINE FILE-----";

    auto begin_pos = cleaned.find(begin_marker);
    if (begin_pos != std::string::npos) {
        cleaned.erase(begin_pos, begin_marker.size());
    }

    auto end_pos = cleaned.find(end_marker);
    if (end_pos != std::string::npos) {
        cleaned.erase(end_pos, end_marker.size());
    }

    cleaned.erase(std::remove_if(cleaned.begin(), cleaned.end(),
                                 [](unsigned char ch) { return std::isspace(ch) != 0; }),
                  cleaned.end());

    auto decoded = base64_decode(cleaned);
    if (decoded.empty() && !cleaned.empty()) {
        return Result<ParsedMachineFileEnvelope>::error(ErrorCode::ParseError,
                                                        "Invalid machine file encoding");
    }

    try {
        auto envelope_json = nlohmann::json::parse(std::string(decoded.begin(), decoded.end()));
        ParsedMachineFileEnvelope envelope;
        envelope.enc = envelope_json.value("enc", std::string{});
        envelope.sig = envelope_json.value("sig", std::string{});
        envelope.alg = envelope_json.value("alg", std::string{});
        envelope.kid = envelope_json.value("kid", std::string{});

        if (envelope.enc.empty() || envelope.sig.empty() || envelope.kid.empty()) {
            return Result<ParsedMachineFileEnvelope>::error(ErrorCode::ParseError,
                                                            "Machine file envelope is incomplete");
        }

        return Result<ParsedMachineFileEnvelope>::ok(std::move(envelope));
    } catch (const nlohmann::json::exception&) {
        return Result<ParsedMachineFileEnvelope>::error(ErrorCode::ParseError,
                                                        "Invalid machine file JSON");
    }
}

bool constant_time_equal(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) {
        return false;
    }

    int diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
    }
    return diff == 0;
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

Result<bool> verify_offline_token_signature(const OfflineToken& offline_token,
                                            const std::string& public_key_b64) {
    // Check basic validity first
    if (offline_token.token.license_key.empty()) {
        return Result<bool>::error(ErrorCode::InvalidLicenseKey, "License key is empty");
    }

    if (offline_token.signature.value.empty()) {
        return Result<bool>::error(ErrorCode::InvalidSignature, "Signature is empty");
    }

    if (offline_token.canonical.empty()) {
        return Result<bool>::error(ErrorCode::InvalidParameter, "Canonical JSON is empty");
    }

    if (public_key_b64.empty()) {
        return Result<bool>::error(ErrorCode::MissingParameter, "Public key is required");
    }

    // The canonical JSON string is provided by the server and is what was signed
    // Verify the signature against the canonical JSON
    return verify_ed25519_signature(offline_token.canonical, offline_token.signature.value,
                                    public_key_b64);
}

Result<MachineFilePayload> verify_machine_file(const MachineFile& machine_file,
                                               const std::string& license_key,
                                               const std::string& fingerprint,
                                               const std::string& public_key_b64) {
    if (license_key.empty()) {
        return Result<MachineFilePayload>::error(ErrorCode::InvalidLicenseKey,
                                                 "License key is required");
    }

    if (fingerprint.empty()) {
        return Result<MachineFilePayload>::error(ErrorCode::MissingParameter,
                                                 "Fingerprint is required");
    }

    if (public_key_b64.empty()) {
        return Result<MachineFilePayload>::error(ErrorCode::MissingParameter,
                                                 "Public key is required");
    }

    auto envelope_result = parse_machine_file_envelope(machine_file.certificate);
    if (envelope_result.is_error()) {
        return Result<MachineFilePayload>::error(envelope_result.error_code(),
                                                 envelope_result.error_message());
    }

    auto envelope = envelope_result.value();
    if (!envelope.alg.empty() && envelope.alg != "aes-256-gcm+ed25519") {
        return Result<MachineFilePayload>::error(ErrorCode::InvalidParameter,
                                                 "Unsupported machine file algorithm");
    }

    auto signature_result =
        verify_ed25519_signature("machine/" + envelope.enc, envelope.sig, public_key_b64);
    if (signature_result.is_error()) {
        return Result<MachineFilePayload>::error(signature_result.error_code(),
                                                 signature_result.error_message());
    }

    size_t first_dot = envelope.enc.find('.');
    size_t second_dot = envelope.enc.find('.', first_dot == std::string::npos ? first_dot : first_dot + 1);
    if (first_dot == std::string::npos || second_dot == std::string::npos) {
        return Result<MachineFilePayload>::error(ErrorCode::ParseError,
                                                 "Invalid encrypted machine file format");
    }

    const std::string ciphertext_part = envelope.enc.substr(0, first_dot);
    const std::string nonce_part = envelope.enc.substr(first_dot + 1, second_dot - first_dot - 1);
    const std::string tag_part = envelope.enc.substr(second_dot + 1);

    auto ciphertext = base64url_decode(ciphertext_part);
    auto nonce = base64url_decode(nonce_part);
    auto tag = base64url_decode(tag_part);

    if (ciphertext.empty() || nonce.size() != 12 || tag.size() != 16) {
        return Result<MachineFilePayload>::error(ErrorCode::ParseError,
                                                 "Invalid encrypted machine file payload");
    }

    auto key = sha256_bytes(license_key + fingerprint);

    using EvpCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
    EvpCtxPtr ctx(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
    if (!ctx) {
        return Result<MachineFilePayload>::error(ErrorCode::ServerError,
                                                 "Failed to initialize crypto context");
    }

    std::vector<uint8_t> plaintext(ciphertext.size() + 16);
    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1 ||
        EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, ciphertext.data(),
                          static_cast<int>(ciphertext.size())) != 1) {
        return Result<MachineFilePayload>::error(ErrorCode::DecryptionFailed,
                                                 "Machine file decryption setup failed");
    }

    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()),
                            tag.data()) != 1) {
        return Result<MachineFilePayload>::error(ErrorCode::DecryptionFailed,
                                                 "Machine file tag validation failed");
    }

    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + plaintext_len, &len) != 1) {
        return Result<MachineFilePayload>::error(ErrorCode::DecryptionFailed,
                                                 "Machine file decryption failed");
    }

    plaintext_len += len;
    plaintext.resize(static_cast<size_t>(plaintext_len));

    try {
        auto payload_json = nlohmann::json::parse(std::string(plaintext.begin(), plaintext.end()));
        auto payload = json::parse_machine_file_payload(payload_json);
        const auto now = std::time(nullptr);

        if (payload.nbf > 0 && payload.nbf > now + 300) {
            return Result<MachineFilePayload>::error(ErrorCode::TokenNotYetValid,
                                                     "Machine file is not yet valid");
        }

        if (payload.exp > 0 && now > payload.exp + payload.grace_period) {
            return Result<MachineFilePayload>::error(ErrorCode::TokenExpired,
                                                     "Machine file has expired");
        }

        if (payload.license_expires_at.has_value() && now > *payload.license_expires_at) {
            return Result<MachineFilePayload>::error(ErrorCode::LicenseExpired,
                                                     "Underlying license has expired");
        }

        if (!payload.fingerprint.empty() &&
            !constant_time_equal(payload.fingerprint, fingerprint)) {
            return Result<MachineFilePayload>::error(ErrorCode::FingerprintMismatch,
                                                     "Machine file fingerprint does not match this device");
        }

        return Result<MachineFilePayload>::ok(std::move(payload));
    } catch (const nlohmann::json::exception& e) {
        return Result<MachineFilePayload>::error(ErrorCode::ParseError,
                                                 std::string("Failed to parse decrypted machine file payload: ") +
                                                     e.what());
    }
}

}  // namespace crypto

// ==================== SHA-256 for Device ID ====================
// Used by device.cpp to hash the stable device fingerprint into the legacy
// public `device_id` string exposed by the C++ API.

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
