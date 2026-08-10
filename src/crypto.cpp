/**
 * @file crypto.cpp
 * @brief Crypto implementation for signatures, hashing, and machine files
 *
 * Uses OpenSSL EVP for Ed25519 verification and AES-256-GCM machine-file
 * decryption. PicoSHA2 is retained for protocol-compatible SHA-256 hashing.
 *
 * AES-256-GCM machine-file decryption currently uses OpenSSL EVP.
 */

#include "licenseseat/crypto.hpp"

#include "licenseseat/json.hpp"

// Vendored PicoSHA2 library (header-only)
#include "PicoSHA2/picosha2.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <limits>
#include <memory>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <unordered_set>

namespace licenseseat {
namespace crypto {

// ==================== Base64 Encoding/Decoding ====================
// Pure C++ implementation without OpenSSL

namespace {

const char BASE64_CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
constexpr int64_t MAX_UNIX_TIMESTAMP = 253402300799LL; // 9999-12-31T23:59:59Z
constexpr int64_t MAX_OFFLINE_LIFETIME_SECONDS = 100LL * 366 * 24 * 60 * 60;
constexpr int64_t MAX_GRACE_PERIOD_SECONDS = 30LL * 24 * 60 * 60;
constexpr std::size_t MAX_CERTIFICATE_BYTES = 1024 * 1024;
constexpr std::size_t MAX_ENCRYPTED_TEXT_BYTES = 768 * 1024;

class SensitiveBytes final {
  public:
    explicit SensitiveBytes(std::vector<uint8_t>& bytes) noexcept : bytes_(bytes) {}
    SensitiveBytes(const SensitiveBytes&) = delete;
    SensitiveBytes& operator=(const SensitiveBytes&) = delete;
    ~SensitiveBytes() {
        if (!bytes_.empty())
            OPENSSL_cleanse(bytes_.data(), bytes_.size());
    }

  private:
    std::vector<uint8_t>& bytes_;
};

inline int base64_char_value(unsigned char c) {
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
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
    if (certificate.empty() || certificate.size() > MAX_CERTIFICATE_BYTES) {
        return Result<ParsedMachineFileEnvelope>::error(
            ErrorCode::MissingParameter, "Machine file certificate is empty or too large");
    }

    const std::string begin_marker = "-----BEGIN MACHINE FILE-----";
    const std::string end_marker = "-----END MACHINE FILE-----";

    const auto is_ascii_whitespace = [](char ch) {
        return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '\f' || ch == '\v';
    };
    const auto trim_ascii = [&](std::string value) {
        const auto begin = std::find_if_not(value.begin(), value.end(), is_ascii_whitespace);
        const auto end = std::find_if_not(value.rbegin(), value.rend(), is_ascii_whitespace).base();
        if (begin >= end)
            return std::string{};
        return std::string(begin, end);
    };

    const auto normalized = trim_ascii(certificate);
    std::vector<std::string> lines;
    std::size_t offset = 0;
    while (offset <= normalized.size()) {
        const auto newline = normalized.find('\n', offset);
        lines.push_back(trim_ascii(normalized.substr(
            offset, newline == std::string::npos ? std::string::npos : newline - offset)));
        if (newline == std::string::npos)
            break;
        offset = newline + 1;
    }

    if (lines.size() < 3 || lines.front() != begin_marker || lines.back() != end_marker) {
        return Result<ParsedMachineFileEnvelope>::error(ErrorCode::ParseError,
                                                        "Invalid machine file framing");
    }

    std::string cleaned;
    cleaned.reserve(normalized.size());
    for (std::size_t index = 1; index + 1 < lines.size(); ++index) {
        const auto& line = lines[index];
        if (line.empty() || line.size() > 64 ||
            !std::all_of(line.begin(), line.end(), [](unsigned char ch) {
                return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                       (ch >= '0' && ch <= '9') || ch == '+' || ch == '/' || ch == '=';
            })) {
            return Result<ParsedMachineFileEnvelope>::error(ErrorCode::ParseError,
                                                            "Invalid machine file framing");
        }
        cleaned += line;
    }

    auto decoded = base64_decode(cleaned);
    if (decoded.empty() || decoded.size() > MAX_ENCRYPTED_TEXT_BYTES) {
        return Result<ParsedMachineFileEnvelope>::error(ErrorCode::ParseError,
                                                        "Invalid machine file encoding");
    }

    try {
        auto envelope_json = json::parse_strict(std::string(decoded.begin(), decoded.end()));
        if (!envelope_json.is_object() || envelope_json.size() != 4 ||
            !envelope_json.contains("enc") || !envelope_json.contains("sig") ||
            !envelope_json.contains("alg") || !envelope_json.contains("kid")) {
            return Result<ParsedMachineFileEnvelope>::error(
                ErrorCode::ParseError, "Machine file envelope has an invalid schema");
        }
        ParsedMachineFileEnvelope envelope;
        envelope.enc = envelope_json.value("enc", std::string{});
        envelope.sig = envelope_json.value("sig", std::string{});
        envelope.alg = envelope_json.value("alg", std::string{});
        envelope.kid = envelope_json.value("kid", std::string{});

        if (envelope.enc.empty() || envelope.enc.size() > MAX_ENCRYPTED_TEXT_BYTES ||
            envelope.sig.empty() || envelope.sig.size() > 128 || envelope.kid.empty() ||
            envelope.kid.size() > 255 || json::has_unsafe_text(envelope.kid)) {
            return Result<ParsedMachineFileEnvelope>::error(ErrorCode::ParseError,
                                                            "Machine file envelope is incomplete");
        }

        return Result<ParsedMachineFileEnvelope>::ok(std::move(envelope));
    } catch (const std::exception&) {
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

bool timestamp_matches_unix_seconds(const std::string& encoded, int64_t expected) {
    const auto parsed = json::parse_timestamp(encoded);
    if (!parsed.has_value())
        return false;
    return parsed->time_since_epoch() == std::chrono::seconds(expected);
}

} // namespace

namespace internal {

Result<std::string> extract_machine_file_key_id(const MachineFile& machine_file) {
    auto envelope = parse_machine_file_envelope(machine_file.certificate);
    if (envelope.is_error()) {
        return Result<std::string>::error(envelope.error_code(), envelope.error_message());
    }
    return Result<std::string>::ok(envelope.value().kid);
}

} // namespace internal

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
    if (encoded.empty() || encoded.size() > 2 * json::MAX_JSON_BYTES)
        return {};

    const auto padding_pos = encoded.find('=');
    const std::size_t padding = padding_pos == std::string::npos ? 0 : encoded.size() - padding_pos;
    if (padding > 2 ||
        (padding_pos != std::string::npos &&
         (encoded.size() % 4 != 0 ||
          encoded.find_first_not_of('=', padding_pos) != std::string::npos)) ||
        (padding_pos == std::string::npos && encoded.size() % 4 == 1)) {
        return {};
    }
    const std::size_t data_size = encoded.size() - padding;
    for (std::size_t index = 0; index < data_size; ++index) {
        if (base64_char_value(static_cast<unsigned char>(encoded[index])) < 0)
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
        int sextet_a =
            padded[i] == '=' ? 0 : base64_char_value(static_cast<unsigned char>(padded[i]));
        int sextet_b =
            padded[i + 1] == '=' ? 0 : base64_char_value(static_cast<unsigned char>(padded[i + 1]));
        int sextet_c =
            padded[i + 2] == '=' ? 0 : base64_char_value(static_cast<unsigned char>(padded[i + 2]));
        int sextet_d =
            padded[i + 3] == '=' ? 0 : base64_char_value(static_cast<unsigned char>(padded[i + 3]));

        if (sextet_a < 0 || sextet_b < 0 || sextet_c < 0 || sextet_d < 0) {
            // Invalid base64 character
            return {};
        }

        uint32_t triple = (static_cast<uint32_t>(sextet_a) << 18) +
                          (static_cast<uint32_t>(sextet_b) << 12) +
                          (static_cast<uint32_t>(sextet_c) << 6) + static_cast<uint32_t>(sextet_d);

        result.push_back(static_cast<uint8_t>((triple >> 16) & 0xFF));
        if (padded[i + 2] != '=') {
            result.push_back(static_cast<uint8_t>((triple >> 8) & 0xFF));
        }
        if (padded[i + 3] != '=') {
            result.push_back(static_cast<uint8_t>(triple & 0xFF));
        }

        i += 4;
    }

    const auto canonical = base64_encode(result);
    auto unpadded = canonical;
    while (!unpadded.empty() && unpadded.back() == '=')
        unpadded.pop_back();
    if (encoded != canonical && encoded != unpadded)
        return {};
    return result;
}

std::vector<uint8_t> base64url_decode(const std::string& encoded) {
    if (encoded.empty() || encoded.size() > 2 * json::MAX_JSON_BYTES)
        return {};
    for (char character : encoded) {
        const auto byte = static_cast<unsigned char>(character);
        if (!((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
              (byte >= '0' && byte <= '9') || character == '-' || character == '_' ||
              character == '=')) {
            return {};
        }
    }
    // Convert from Base64URL to standard Base64
    std::string standard = encoded;
    std::replace(standard.begin(), standard.end(), '-', '+');
    std::replace(standard.begin(), standard.end(), '_', '/');

    auto decoded = base64_decode(standard);
    if (decoded.empty())
        return {};
    const auto canonical = base64url_encode(decoded);
    auto supplied = encoded;
    while (!supplied.empty() && supplied.back() == '=')
        supplied.pop_back();
    return supplied == canonical ? decoded : std::vector<uint8_t>{};
}

// ==================== Ed25519 Signature Verification ====================

Result<bool> verify_ed25519_signature(const std::string& message, const std::string& signature_b64,
                                      const std::string& public_key_b64) {
    if (message.size() > json::MAX_JSON_BYTES || signature_b64.size() > 128 ||
        public_key_b64.size() > 64) {
        return Result<bool>::error(ErrorCode::InvalidParameter,
                                   "Cryptographic input exceeds its size limit");
    }

    // Current servers emit standard Base64. Accept canonical Base64URL as a
    // compatibility format, but reject malformed or mixed alphabets.
    std::vector<uint8_t> signature = base64_decode(signature_b64);
    if (signature.size() != 64)
        signature = base64url_decode(signature_b64);
    if (signature.size() != 64) {
        return Result<bool>::error(ErrorCode::InvalidSignature,
                                   "Invalid signature length (expected 64 bytes, got " +
                                       std::to_string(signature.size()) + ")");
    }

    // Decode public key (standard Base64)
    std::vector<uint8_t> public_key = base64_decode(public_key_b64);
    if (public_key.size() != 32)
        public_key = base64url_decode(public_key_b64);
    if (public_key.size() != 32) {
        return Result<bool>::error(ErrorCode::InvalidParameter,
                                   "Invalid public key length (expected 32 bytes, got " +
                                       std::to_string(public_key.size()) + ")");
    }

    using EvpKeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using EvpMdPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    EvpKeyPtr key(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, public_key.data(),
                                              public_key.size()),
                  &EVP_PKEY_free);
    EvpMdPtr context(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (!key || !context ||
        EVP_DigestVerifyInit(context.get(), nullptr, nullptr, nullptr, key.get()) != 1) {
        return Result<bool>::error(ErrorCode::InvalidParameter,
                                   "Failed to initialize Ed25519 verification");
    }
    const int verification =
        EVP_DigestVerify(context.get(), signature.data(), signature.size(),
                         reinterpret_cast<const unsigned char*>(message.data()), message.size());

    if (verification == 1) {
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

    const auto& token = offline_token.token;
    const auto safe_text = [](const std::string& value, std::size_t maximum) {
        return !value.empty() && value.size() <= maximum && !json::has_unsafe_text(value);
    };
    if (token.schema_version != 1 || !safe_text(token.license_key, 512) ||
        !safe_text(token.product_slug, 100) || !safe_text(token.plan_key, 255) ||
        (token.mode != "hardware_locked" && token.mode != "floating" &&
         token.mode != "named_user") ||
        !token.fingerprint.has_value() || token.fingerprint->size() < 8 ||
        !safe_text(*token.fingerprint, 255) || !safe_text(token.kid, 255) || token.iat <= 0 ||
        token.iat > MAX_UNIX_TIMESTAMP || token.nbf <= 0 || token.nbf > MAX_UNIX_TIMESTAMP ||
        token.exp <= 0 || token.exp > MAX_UNIX_TIMESTAMP || token.nbf < token.iat ||
        token.nbf > token.exp || token.exp - token.iat > MAX_OFFLINE_LIFETIME_SECONDS ||
        token.entitlements.size() > 500 || offline_token.signature.algorithm != "Ed25519" ||
        offline_token.signature.key_id != token.kid) {
        return Result<bool>::error(ErrorCode::InvalidParameter, "Offline token claims are invalid");
    }
    if (token.seat_limit.has_value() && *token.seat_limit <= 0) {
        return Result<bool>::error(ErrorCode::InvalidParameter,
                                   "Offline token seat limit is invalid");
    }
    if (token.license_expires_at.has_value() &&
        (*token.license_expires_at <= 0 || *token.license_expires_at > MAX_UNIX_TIMESTAMP)) {
        return Result<bool>::error(ErrorCode::InvalidParameter,
                                   "Offline token license expiry is invalid");
    }
    std::unordered_set<std::string> entitlement_keys;
    for (const auto& entitlement : token.entitlements) {
        if (!safe_text(entitlement.key, 100) || !entitlement_keys.insert(entitlement.key).second ||
            (entitlement.expires_at.has_value() &&
             (std::chrono::system_clock::to_time_t(*entitlement.expires_at) <= 0 ||
              std::chrono::system_clock::to_time_t(*entitlement.expires_at) >
                  MAX_UNIX_TIMESTAMP))) {
            return Result<bool>::error(ErrorCode::InvalidParameter,
                                       "Offline token entitlements are invalid");
        }
    }

    try {
        const auto signed_claims = json::parse_strict(offline_token.canonical);
        if (!json::offline_token_payload_matches_json(token, signed_claims)) {
            return Result<bool>::error(ErrorCode::InvalidSignature,
                                       "Visible offline token claims do not match signed data");
        }
        if (!offline_token.visible_token_json.empty() &&
            json::parse_strict(offline_token.visible_token_json) != signed_claims) {
            return Result<bool>::error(ErrorCode::InvalidSignature,
                                       "Offline token sibling claims do not match signed data");
        }
    } catch (const std::exception&) {
        return Result<bool>::error(ErrorCode::InvalidParameter,
                                   "Canonical offline token JSON is invalid");
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
    if (envelope.alg != "aes-256-gcm+ed25519") {
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
    size_t second_dot =
        envelope.enc.find('.', first_dot == std::string::npos ? first_dot : first_dot + 1);
    if (first_dot == std::string::npos || second_dot == std::string::npos) {
        return Result<MachineFilePayload>::error(ErrorCode::ParseError,
                                                 "Invalid encrypted machine file format");
    }

    const std::string ciphertext_part = envelope.enc.substr(0, first_dot);
    const std::string nonce_part = envelope.enc.substr(first_dot + 1, second_dot - first_dot - 1);
    const std::string tag_part = envelope.enc.substr(second_dot + 1);

    if (envelope.enc.find('.', second_dot + 1) != std::string::npos) {
        return Result<MachineFilePayload>::error(ErrorCode::ParseError,
                                                 "Invalid encrypted machine file format");
    }

    auto ciphertext = base64url_decode(ciphertext_part);
    auto nonce = base64url_decode(nonce_part);
    auto tag = base64url_decode(tag_part);

    if (ciphertext.empty() || nonce.size() != 12 || tag.size() != 16) {
        return Result<MachineFilePayload>::error(ErrorCode::ParseError,
                                                 "Invalid encrypted machine file payload");
    }

    if (ciphertext.size() > json::MAX_JSON_BYTES) {
        return Result<MachineFilePayload>::error(ErrorCode::ParseError,
                                                 "Encrypted machine file is too large");
    }

    auto key = sha256_bytes(license_key + fingerprint);
    SensitiveBytes cleanse_key(key);

    using EvpCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
    EvpCtxPtr ctx(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
    if (!ctx) {
        return Result<MachineFilePayload>::error(ErrorCode::ServerError,
                                                 "Failed to initialize crypto context");
    }

    std::vector<uint8_t> plaintext(ciphertext.size() + 16);
    SensitiveBytes cleanse_plaintext(plaintext);
    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()),
                            nullptr) != 1 ||
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
        auto payload_json = json::parse_strict(std::string(plaintext.begin(), plaintext.end()));
        if (!payload_json.is_object() || !payload_json.contains("meta") ||
            !payload_json["meta"].is_object() || !payload_json.contains("data") ||
            !payload_json["data"].is_object()) {
            return Result<MachineFilePayload>::error(ErrorCode::ParseError,
                                                     "Machine file payload has an invalid schema");
        }
        const auto& data_json = payload_json["data"];
        if (data_json.value("type", std::string{}) != "machines" ||
            !data_json.contains("attributes") || !data_json["attributes"].is_object() ||
            !data_json.contains("relationships") || !data_json["relationships"].is_object()) {
            return Result<MachineFilePayload>::error(ErrorCode::ParseError,
                                                     "Machine file resource has an invalid schema");
        }
        const auto& relationships = data_json["relationships"];
        if (!relationships.contains("license") || !relationships["license"].is_object() ||
            !relationships["license"].contains("data") ||
            !relationships["license"]["data"].is_object() || !relationships.contains("product") ||
            !relationships["product"].is_object() || !relationships["product"].contains("data") ||
            !relationships["product"]["data"].is_object() ||
            relationships["license"]["data"].value("type", std::string{}) != "licenses" ||
            relationships["product"]["data"].value("type", std::string{}) != "products" ||
            !constant_time_equal(relationships["license"]["data"].value("id", std::string{}),
                                 license_key)) {
            return Result<MachineFilePayload>::error(ErrorCode::InvalidParameter,
                                                     "Machine file relationships are invalid");
        }
        auto payload = json::parse_machine_file_payload(payload_json);
        const auto now = std::time(nullptr);

        if (payload.schema_version != 2 || payload.license_key.empty() ||
            payload.license_key.size() > 512 || json::has_unsafe_text(payload.license_key) ||
            !constant_time_equal(payload.license_key, license_key) ||
            payload.fingerprint.size() < 8 || payload.fingerprint.size() > 255 ||
            json::has_unsafe_text(payload.fingerprint) ||
            !constant_time_equal(payload.fingerprint, fingerprint) || payload.key_id.empty() ||
            payload.key_id.size() > 255 || json::has_unsafe_text(payload.key_id) ||
            payload.key_id != envelope.kid || payload.iat <= 0 ||
            payload.iat > MAX_UNIX_TIMESTAMP || payload.nbf <= 0 ||
            payload.nbf > MAX_UNIX_TIMESTAMP || payload.exp <= 0 ||
            payload.exp > MAX_UNIX_TIMESTAMP || payload.nbf < payload.iat ||
            payload.nbf > payload.exp || payload.exp < payload.iat || payload.ttl <= 0 ||
            payload.ttl > MAX_OFFLINE_LIFETIME_SECONDS ||
            payload.exp - payload.iat != payload.ttl || payload.grace_period < 0 ||
            payload.grace_period > MAX_GRACE_PERIOD_SECONDS ||
            payload.exp > MAX_UNIX_TIMESTAMP - payload.grace_period || payload.machine_id.empty() ||
            payload.machine_id.size() > 255 || json::has_unsafe_text(payload.machine_id) ||
            payload.product_slug.empty() || payload.product_slug.size() > 100 ||
            json::has_unsafe_text(payload.product_slug) ||
            (payload.license_expires_at.has_value() &&
             (*payload.license_expires_at <= 0 ||
              *payload.license_expires_at > MAX_UNIX_TIMESTAMP))) {
            return Result<MachineFilePayload>::error(ErrorCode::InvalidParameter,
                                                     "Machine file claims are invalid");
        }

        if (payload.issued.empty() ||
            !timestamp_matches_unix_seconds(payload.issued, payload.iat)) {
            return Result<MachineFilePayload>::error(
                ErrorCode::InvalidParameter, "Machine file issued timestamp is inconsistent");
        }
        if (payload.expiry.empty() ||
            !timestamp_matches_unix_seconds(payload.expiry, payload.exp)) {
            return Result<MachineFilePayload>::error(
                ErrorCode::InvalidParameter, "Machine file expiry timestamp is inconsistent");
        }

        if (payload.license.has_value()) {
            const auto& license = *payload.license;
            if (!constant_time_equal(license.key(), license_key) ||
                license.product().slug != payload.product_slug ||
                license.status() != LicenseStatus::Active ||
                license.mode() == LicenseMode::Unknown || license.plan_key().empty() ||
                (payload.license_expires_at.has_value() &&
                 (!license.expires_at().has_value() ||
                  license.expires_at()->time_since_epoch() !=
                      std::chrono::seconds(*payload.license_expires_at))) ||
                (!payload.license_expires_at.has_value() && license.expires_at().has_value()) ||
                !license.is_valid()) {
                return Result<MachineFilePayload>::error(
                    ErrorCode::InvalidParameter,
                    "Embedded machine-file license is invalid or inconsistent");
            }
            std::unordered_set<std::string> embedded_entitlements;
            for (const auto& entitlement : license.active_entitlements()) {
                if (entitlement.key.empty() || entitlement.key.size() > 100 ||
                    !embedded_entitlements.insert(entitlement.key).second) {
                    return Result<MachineFilePayload>::error(
                        ErrorCode::InvalidParameter,
                        "Embedded machine-file entitlements are invalid");
                }
            }
        }

        if (payload.nbf > 0 && payload.nbf > now + 300) {
            return Result<MachineFilePayload>::error(ErrorCode::TokenNotYetValid,
                                                     "Machine file is not yet valid");
        }

        if (payload.exp > 0 && now >= payload.exp + payload.grace_period) {
            return Result<MachineFilePayload>::error(ErrorCode::TokenExpired,
                                                     "Machine file has expired");
        }

        if (payload.license_expires_at.has_value() && now >= *payload.license_expires_at) {
            return Result<MachineFilePayload>::error(ErrorCode::LicenseExpired,
                                                     "Underlying license has expired");
        }

        return Result<MachineFilePayload>::ok(std::move(payload));
    } catch (const std::exception& e) {
        return Result<MachineFilePayload>::error(
            ErrorCode::ParseError,
            std::string("Failed to parse decrypted machine file payload: ") + e.what());
    }
}

} // namespace crypto

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

} // namespace internal
} // namespace device

} // namespace licenseseat
