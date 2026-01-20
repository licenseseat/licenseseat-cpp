#include "licenseseat/crypto.hpp"
#include "licenseseat/json.hpp"

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <algorithm>
#include <cstring>
#include <memory>

namespace licenseseat {
namespace crypto {

// ==================== Base64 Encoding/Decoding ====================

std::string base64_encode(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return "";
    }

    // Create BIO chain for base64 encoding
    std::unique_ptr<BIO, decltype(&BIO_free_all)> b64(BIO_new(BIO_f_base64()), BIO_free_all);
    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);

    BIO* bmem = BIO_new(BIO_s_mem());
    BIO_push(b64.get(), bmem);

    BIO_write(b64.get(), data.data(), static_cast<int>(data.size()));
    (void)BIO_flush(b64.get());

    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(b64.get(), &bptr);

    std::string result(bptr->data, bptr->length);
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

    // Create BIO chain for base64 decoding
    std::unique_ptr<BIO, decltype(&BIO_free_all)> b64(BIO_new(BIO_f_base64()), BIO_free_all);
    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);

    std::unique_ptr<BIO, decltype(&BIO_free)> bmem(
        BIO_new_mem_buf(padded.data(), static_cast<int>(padded.size())), BIO_free);
    BIO_push(b64.get(), bmem.release());

    // Allocate buffer (base64 expands by ~4/3, so decoding shrinks by ~3/4)
    std::vector<uint8_t> result(padded.size() * 3 / 4 + 1);

    int decoded_len = BIO_read(b64.get(), result.data(), static_cast<int>(result.size()));
    if (decoded_len > 0) {
        result.resize(static_cast<size_t>(decoded_len));
    } else {
        result.clear();
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
                                   "Invalid signature length (expected 64 bytes)");
    }

    // Decode public key (standard Base64)
    std::vector<uint8_t> public_key = base64_decode(public_key_b64);
    if (public_key.size() != 32) {
        return Result<bool>::error(ErrorCode::InvalidParameter,
                                   "Invalid public key length (expected 32 bytes)");
    }

    // Create EVP_PKEY from raw public key
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(
        EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, public_key.data(), public_key.size()),
        EVP_PKEY_free);

    if (!pkey) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        return Result<bool>::error(ErrorCode::InvalidParameter,
                                   std::string("Failed to create public key: ") + err_buf);
    }

    // Create verification context
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);

    if (!ctx) {
        return Result<bool>::error(ErrorCode::Unknown, "Failed to create verification context");
    }

    // Initialize verification
    if (EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get()) != 1) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        return Result<bool>::error(ErrorCode::Unknown,
                                   std::string("Failed to initialize verification: ") + err_buf);
    }

    // Verify signature
    int result = EVP_DigestVerify(ctx.get(), signature.data(), signature.size(),
                                  reinterpret_cast<const unsigned char*>(message.data()),
                                  message.size());

    if (result == 1) {
        return Result<bool>::ok(true);
    } else if (result == 0) {
        return Result<bool>::error(ErrorCode::InvalidSignature, "Signature verification failed");
    } else {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        return Result<bool>::error(ErrorCode::Unknown,
                                   std::string("Verification error: ") + err_buf);
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
}  // namespace licenseseat
