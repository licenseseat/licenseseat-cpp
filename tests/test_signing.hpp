#pragma once

#include <array>
#include <memory>
#include <openssl/evp.h>
#include <string>

namespace licenseseat::test_signing {

inline bool sign_ed25519(const std::array<unsigned char, 32>& seed, const std::string& message,
                         std::array<unsigned char, 32>& public_key,
                         std::array<unsigned char, 64>& signature) {
    using KeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using ContextPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

    KeyPtr key(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), seed.size()),
               &EVP_PKEY_free);
    if (!key)
        return false;

    std::size_t public_key_size = public_key.size();
    if (EVP_PKEY_get_raw_public_key(key.get(), public_key.data(), &public_key_size) != 1 ||
        public_key_size != public_key.size()) {
        return false;
    }

    ContextPtr context(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (!context || EVP_DigestSignInit(context.get(), nullptr, nullptr, nullptr, key.get()) != 1)
        return false;

    std::size_t signature_size = signature.size();
    return EVP_DigestSign(context.get(), signature.data(), &signature_size,
                          reinterpret_cast<const unsigned char*>(message.data()),
                          message.size()) == 1 &&
           signature_size == signature.size();
}

} // namespace licenseseat::test_signing
