#include "PicoSHA2/picosha2.h"
#include "test_signing.hpp"

#include <array>
#include <fstream>
#include <gtest/gtest.h>
#include <licenseseat/crypto.hpp>
#include <licenseseat/json.hpp>
#include <memory>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>

namespace licenseseat {
namespace crypto {
namespace {

TEST(CrossLanguageContractTest, VerifiesRubySignedOfflineTokenFixture) {
    std::ifstream input(std::string(LICENSESEAT_TEST_FIXTURE_DIR) +
                        "/ruby_signed_offline_token.json");
    ASSERT_TRUE(input.is_open());

    const auto fixture = nlohmann::json::parse(input);
    const auto offline = json::offline_token_from_json(fixture.at("offline_token").dump());
    const auto result =
        verify_offline_token_signature(offline, fixture.at("public_key").get<std::string>());

    ASSERT_TRUE(result.is_ok()) << result.error_message();
    EXPECT_TRUE(result.value());
}

std::vector<uint8_t> sha256_test_bytes(const std::string& input) {
    std::vector<uint8_t> hash(picosha2::k_digest_size);
    picosha2::hash256(input.begin(), input.end(), hash.begin(), hash.end());
    return hash;
}

std::string wrap_machine_file_certificate(const std::string& encoded) {
    std::string certificate = "-----BEGIN MACHINE FILE-----\n";
    for (std::size_t offset = 0; offset < encoded.size(); offset += 64) {
        certificate += encoded.substr(offset, 64);
        certificate += '\n';
    }
    certificate += "-----END MACHINE FILE-----";
    return certificate;
}

std::string build_machine_file_certificate(const std::string& license_key,
                                           const std::string& fingerprint,
                                           const nlohmann::json& payload_json,
                                           std::string* public_key_b64_out) {
    const std::array<unsigned char, 32> seed = {0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
                                                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                                0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12,
                                                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22};

    std::array<unsigned char, 32> public_key{};

    const auto key = sha256_test_bytes(license_key + fingerprint);
    const std::array<unsigned char, 12> nonce = {0x01, 0x03, 0x05, 0x07, 0x09, 0x0b,
                                                 0x0d, 0x0f, 0x11, 0x13, 0x15, 0x17};

    using EvpCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
    EvpCtxPtr ctx(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
    if (!ctx) {
        return "";
    }

    const auto plaintext = payload_json.dump();
    std::vector<uint8_t> ciphertext(plaintext.size() + 16);
    int len = 0;
    int ciphertext_len = 0;

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()),
                            nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1 ||
        EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len,
                          reinterpret_cast<const unsigned char*>(plaintext.data()),
                          static_cast<int>(plaintext.size())) != 1) {
        return "";
    }
    ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + ciphertext_len, &len) != 1) {
        return "";
    }
    ciphertext_len += len;
    ciphertext.resize(static_cast<size_t>(ciphertext_len));

    std::array<unsigned char, 16> tag{};
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()),
                            tag.data()) != 1) {
        return "";
    }

    const auto enc = base64url_encode(ciphertext) + "." +
                     base64url_encode(std::vector<uint8_t>(nonce.begin(), nonce.end())) + "." +
                     base64url_encode(std::vector<uint8_t>(tag.begin(), tag.end()));

    std::array<unsigned char, 64> signature{};
    const auto message = std::string("machine/") + enc;
    if (!test_signing::sign_ed25519(seed, message, public_key, signature))
        return "";
    if (public_key_b64_out != nullptr) {
        *public_key_b64_out =
            base64_encode(std::vector<uint8_t>(public_key.begin(), public_key.end()));
    }

    nlohmann::json envelope = {
        {"enc", enc},
        {"sig", base64url_encode(std::vector<uint8_t>(signature.begin(), signature.end()))},
        {"alg", "aes-256-gcm+ed25519"},
        {"kid", "test-kid"}};

    const auto envelope_dump = envelope.dump();
    const auto encoded =
        base64_encode(std::vector<uint8_t>(envelope_dump.begin(), envelope_dump.end()));

    return wrap_machine_file_certificate(encoded);
}

nlohmann::json build_minimal_machine_payload(const std::string& license_key,
                                             const std::string& fingerprint, int64_t issued_at,
                                             int64_t expires_at, int64_t grace_period = 0) {
    return {{"meta",
             {{"schema_version", 2},
              {"issued", json::format_timestamp(json::parse_unix_timestamp(issued_at))},
              {"iat", issued_at},
              {"expiry", json::format_timestamp(json::parse_unix_timestamp(expires_at))},
              {"exp", expires_at},
              {"nbf", issued_at},
              {"ttl", expires_at - issued_at},
              {"grace_period", grace_period},
              {"lic", license_key},
              {"license_exp", nullptr},
              {"kid", "test-kid"}}},
            {"data",
             {{"type", "machines"},
              {"id", "42"},
              {"attributes", {{"fingerprint", fingerprint}}},
              {"relationships",
               {{"license", {{"data", {{"type", "licenses"}, {"id", license_key}}}}},
                {"product", {{"data", {{"type", "products"}, {"id", "my-app"}}}}}}}}}};
}

// ==================== Base64 Encoding Tests ====================

TEST(Base64Test, EncodeEmpty) {
    std::vector<uint8_t> data;
    auto encoded = base64_encode(data);

    EXPECT_TRUE(encoded.empty());
}

TEST(Base64Test, EncodeHelloWorld) {
    // "Hello, World!" in Base64 is "SGVsbG8sIFdvcmxkIQ=="
    std::vector<uint8_t> data = {'H', 'e', 'l', 'l', 'o', ',', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
    auto encoded = base64_encode(data);

    EXPECT_EQ(encoded, "SGVsbG8sIFdvcmxkIQ==");
}

TEST(Base64Test, DecodeEmpty) {
    auto decoded = base64_decode("");

    EXPECT_TRUE(decoded.empty());
}

TEST(Base64Test, DecodeHelloWorld) {
    auto decoded = base64_decode("SGVsbG8sIFdvcmxkIQ==");

    std::vector<uint8_t> expected = {'H', 'e', 'l', 'l', 'o', ',', ' ',
                                     'W', 'o', 'r', 'l', 'd', '!'};
    EXPECT_EQ(decoded, expected);
}

TEST(Base64Test, RoundTrip) {
    std::vector<uint8_t> original = {0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD};
    auto encoded = base64_encode(original);
    auto decoded = base64_decode(encoded);

    EXPECT_EQ(decoded, original);
}

TEST(Base64Test, RejectsMalformedNonCanonicalAndOversizedInput) {
    EXPECT_TRUE(base64_decode("A").empty());
    EXPECT_TRUE(base64_decode("AB==").empty());
    EXPECT_TRUE(base64_decode("A===").empty());
    EXPECT_TRUE(base64_decode("A=AA").empty());
    EXPECT_TRUE(base64_decode("Z g==").empty());
    EXPECT_TRUE(base64_decode(std::string(2 * json::MAX_JSON_BYTES + 1, 'A')).empty());
}

// ==================== Base64URL Encoding Tests ====================

TEST(Base64UrlTest, EncodeEmpty) {
    std::vector<uint8_t> data;
    auto encoded = base64url_encode(data);

    EXPECT_TRUE(encoded.empty());
}

TEST(Base64UrlTest, EncodeWithSpecialChars) {
    // Test data that produces + and / in standard Base64
    std::vector<uint8_t> data = {0xfb, 0xff, 0xfe};
    auto standard = base64_encode(data);
    auto url_safe = base64url_encode(data);

    // Standard Base64 might have + or /
    // Base64URL replaces them with - and _
    EXPECT_TRUE(url_safe.find('+') == std::string::npos);
    EXPECT_TRUE(url_safe.find('/') == std::string::npos);
    EXPECT_TRUE(url_safe.find('=') == std::string::npos); // No padding
}

TEST(Base64UrlTest, DecodeWithSpecialChars) {
    // "-_" in Base64URL corresponds to "+/" in standard Base64
    std::string url_encoded = "-_8"; // Base64URL for some bytes

    auto decoded = base64url_decode(url_encoded);

    EXPECT_FALSE(decoded.empty());
}

TEST(Base64UrlTest, RoundTrip) {
    std::vector<uint8_t> original = {0xfb, 0xff, 0xfe, 0x00, 0x01, 0x02};
    auto encoded = base64url_encode(original);
    auto decoded = base64url_decode(encoded);

    EXPECT_EQ(decoded, original);
}

TEST(Base64UrlTest, RejectsStandardOrMixedAlphabetAndBadPadding) {
    EXPECT_TRUE(base64url_decode("+/8=").empty());
    EXPECT_TRUE(base64url_decode("-_8===").empty());
    EXPECT_TRUE(base64url_decode("-_9").empty()); // Non-zero unused pad bits.
    EXPECT_TRUE(base64url_decode("-_8.ignored").empty());
}

// ==================== Ed25519 Signature Tests ====================

// Known test vectors for Ed25519 (from RFC 8032)
// Public key (32 bytes, base64): PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=
constexpr const char* TEST_PUBLIC_KEY_B64 = "PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=";

TEST(Ed25519Test, EmptyPublicKeyFails) {
    // Use a valid-length signature (64 bytes base64-encoded = 88 chars with padding)
    // 64 bytes of zeros in base64
    std::string valid_length_sig =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";

    auto result = verify_ed25519_signature("test message", valid_length_sig, "");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidParameter);
}

TEST(Ed25519Test, InvalidPublicKeyLengthFails) {
    // Use a valid-length signature (64 bytes)
    std::string valid_length_sig =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";

    // Too short public key (should be 32 bytes = 44 base64 chars with padding)
    auto result = verify_ed25519_signature("test message", valid_length_sig, "dG9vc2hvcnQ=");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidParameter);
}

TEST(Ed25519Test, EmptySignatureFails) {
    auto result = verify_ed25519_signature("test message", "", TEST_PUBLIC_KEY_B64);

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidSignature);
}

TEST(Ed25519Test, InvalidSignatureLengthFails) {
    // Too short signature
    auto result = verify_ed25519_signature("test message", "dG9vc2hvcnQ", TEST_PUBLIC_KEY_B64);

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidSignature);
}

// Test with a known good signature (generated with real Ed25519 keys)
// Public key (32 bytes, base64): PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=
// This corresponds to the test vector from RFC 8032

TEST(Ed25519Test, WrongSignatureFails) {
    // A valid-length but incorrect signature
    std::string fake_signature =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    auto result = verify_ed25519_signature("test message", fake_signature, TEST_PUBLIC_KEY_B64);

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidSignature);
}

// ==================== Offline Token Verification Tests ====================

TEST(OfflineTokenVerificationTest, EmptyLicenseKeyFails) {
    OfflineToken offline;
    offline.token.license_key = "";

    auto result = verify_offline_token_signature(offline, TEST_PUBLIC_KEY_B64);

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidLicenseKey);
}

TEST(OfflineTokenVerificationTest, EmptySignatureFails) {
    OfflineToken offline;
    offline.token.license_key = "KEY-123";
    offline.signature.value = "";

    auto result = verify_offline_token_signature(offline, TEST_PUBLIC_KEY_B64);

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidSignature);
}

TEST(OfflineTokenVerificationTest, EmptyCanonicalFails) {
    OfflineToken offline;
    offline.token.license_key = "KEY-123";
    offline.signature.value = "some-signature";
    offline.canonical = "";

    auto result = verify_offline_token_signature(offline, TEST_PUBLIC_KEY_B64);

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidParameter);
}

TEST(OfflineTokenVerificationTest, EmptyPublicKeyFails) {
    OfflineToken offline;
    offline.token.license_key = "KEY-123";
    offline.signature.value = "some-signature";
    offline.canonical = R"({"license_key":"KEY-123"})";

    auto result = verify_offline_token_signature(offline, "");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::MissingParameter);
}

// ==================== RFC 8032 Test Vectors ====================
// https://datatracker.ietf.org/doc/html/rfc8032#section-7.1
//
// These are the official Ed25519 test vectors from RFC 8032.
// The test vectors include secret key, public key, message, and signature.

namespace rfc8032 {

// Helper to convert hex character to value
inline uint8_t hex_char_to_value(char c) {
    if (c >= '0' && c <= '9')
        return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f')
        return static_cast<uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F')
        return static_cast<uint8_t>(c - 'A' + 10);
    return 0;
}

// Helper to convert hex string to bytes (portable, no sscanf)
std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.length() / 2);
    for (size_t i = 0; i + 1 < hex.length(); i += 2) {
        uint8_t high = hex_char_to_value(hex[i]);
        uint8_t low = hex_char_to_value(hex[i + 1]);
        bytes.push_back(static_cast<uint8_t>((high << 4) | low));
    }
    return bytes;
}

// RFC 8032 Section 7.1 - Test Vector 1 (Empty message)
// PUBLIC KEY: d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
// MESSAGE: (empty)
// SIGNATURE:
// e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b

TEST(RFC8032Test, TestVector1_EmptyMessage) {
    // Public key in hex and base64
    const std::string pub_key_hex =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    auto pub_key_bytes = hex_to_bytes(pub_key_hex);
    std::string pub_key_b64 = base64_encode(pub_key_bytes);

    // Signature in hex, convert to base64url
    const std::string sig_hex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
                                "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
    auto sig_bytes = hex_to_bytes(sig_hex);
    std::string sig_b64url = base64url_encode(sig_bytes);

    // Empty message
    const std::string message = "";

    auto result = verify_ed25519_signature(message, sig_b64url, pub_key_b64);

    EXPECT_TRUE(result.is_ok()) << "RFC 8032 Test Vector 1 failed: " << result.error_message();
    if (result.is_ok()) {
        EXPECT_TRUE(result.value());
    }
}

// RFC 8032 Section 7.1 - Test Vector 2 (1-byte message: 0x72)
// PUBLIC KEY: 3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
// MESSAGE: 72 (hex) = "r" (ASCII)
// SIGNATURE:
// 92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00

TEST(RFC8032Test, TestVector2_OneByteMessage) {
    const std::string pub_key_hex =
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    auto pub_key_bytes = hex_to_bytes(pub_key_hex);
    std::string pub_key_b64 = base64_encode(pub_key_bytes);

    const std::string sig_hex = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da08"
                                "5ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";
    auto sig_bytes = hex_to_bytes(sig_hex);
    std::string sig_b64url = base64url_encode(sig_bytes);

    // Message: 0x72 = 'r'
    const std::string message = "r";

    auto result = verify_ed25519_signature(message, sig_b64url, pub_key_b64);

    EXPECT_TRUE(result.is_ok()) << "RFC 8032 Test Vector 2 failed: " << result.error_message();
    if (result.is_ok()) {
        EXPECT_TRUE(result.value());
    }
}

// RFC 8032 Section 7.1 - Test Vector 3 (2-byte message: 0xaf82)
// PUBLIC KEY: fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025
// MESSAGE: af82 (hex)
// SIGNATURE:
// 6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a

TEST(RFC8032Test, TestVector3_TwoByteMessage) {
    const std::string pub_key_hex =
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
    auto pub_key_bytes = hex_to_bytes(pub_key_hex);
    std::string pub_key_b64 = base64_encode(pub_key_bytes);

    const std::string sig_hex = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18"
                                "ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a";
    auto sig_bytes = hex_to_bytes(sig_hex);
    std::string sig_b64url = base64url_encode(sig_bytes);

    // Message: 0xaf82 (2 bytes)
    std::string message;
    message.push_back(static_cast<char>(0xaf));
    message.push_back(static_cast<char>(0x82));

    auto result = verify_ed25519_signature(message, sig_b64url, pub_key_b64);

    EXPECT_TRUE(result.is_ok()) << "RFC 8032 Test Vector 3 failed: " << result.error_message();
    if (result.is_ok()) {
        EXPECT_TRUE(result.value());
    }
}

// Test that a modified message fails verification (security test)
TEST(RFC8032Test, ModifiedMessageFails) {
    const std::string pub_key_hex =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    auto pub_key_bytes = hex_to_bytes(pub_key_hex);
    std::string pub_key_b64 = base64_encode(pub_key_bytes);

    const std::string sig_hex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
                                "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
    auto sig_bytes = hex_to_bytes(sig_hex);
    std::string sig_b64url = base64url_encode(sig_bytes);

    // Original signature is for empty message, try with "a"
    const std::string modified_message = "a";

    auto result = verify_ed25519_signature(modified_message, sig_b64url, pub_key_b64);

    EXPECT_TRUE(result.is_error()) << "Modified message should fail verification";
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidSignature);
}

// Test that a modified signature fails verification (security test)
TEST(RFC8032Test, ModifiedSignatureFails) {
    const std::string pub_key_hex =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    auto pub_key_bytes = hex_to_bytes(pub_key_hex);
    std::string pub_key_b64 = base64_encode(pub_key_bytes);

    // Modified signature (changed first byte from e5 to e6)
    const std::string modified_sig_hex =
        "e6564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701c"
        "f9b46bd25bf5f0595bbe24655141438e7a100b";
    auto sig_bytes = hex_to_bytes(modified_sig_hex);
    std::string sig_b64url = base64url_encode(sig_bytes);

    const std::string message = "";

    auto result = verify_ed25519_signature(message, sig_b64url, pub_key_b64);

    EXPECT_TRUE(result.is_error()) << "Modified signature should fail verification";
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidSignature);
}

// Test that wrong public key fails verification (security test)
TEST(RFC8032Test, WrongPublicKeyFails) {
    // Use Test Vector 2's public key with Test Vector 1's signature/message
    const std::string wrong_pub_key_hex =
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    auto pub_key_bytes = hex_to_bytes(wrong_pub_key_hex);
    std::string pub_key_b64 = base64_encode(pub_key_bytes);

    // Test Vector 1's signature
    const std::string sig_hex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
                                "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
    auto sig_bytes = hex_to_bytes(sig_hex);
    std::string sig_b64url = base64url_encode(sig_bytes);

    const std::string message = "";

    auto result = verify_ed25519_signature(message, sig_b64url, pub_key_b64);

    EXPECT_TRUE(result.is_error()) << "Wrong public key should fail verification";
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidSignature);
}

// ==================== Machine File Verification Tests ====================

TEST(MachineFileVerificationTest, ValidMachineFileDecryptsAndVerifies) {
    const auto now = std::time(nullptr);
    const auto license_expiry = now + 86400 * 30;
    const std::string license_key = "KEY-123";
    const std::string fingerprint = "fp-12345";

    nlohmann::json payload = {
        {"meta",
         {{"schema_version", 2},
          {"issued", json::format_timestamp(json::parse_unix_timestamp(now))},
          {"iat", now},
          {"expiry", json::format_timestamp(json::parse_unix_timestamp(now + 86400))},
          {"exp", now + 86400},
          {"nbf", now},
          {"ttl", 86400},
          {"grace_period", 3600},
          {"lic", license_key},
          {"license_exp", license_expiry},
          {"kid", "test-kid"}}},
        {"data",
         {{"type", "machines"},
          {"id", "42"},
          {"attributes",
           {{"fingerprint", fingerprint},
            {"name", "Studio Mac"},
            {"platform", "darwin"},
            {"created", "2026-03-24T10:00:00Z"},
            {"metadata", {{"device_name", "Studio Mac"}}}}},
          {"relationships",
           {{"license", {{"data", {{"type", "licenses"}, {"id", license_key}}}}},
            {"product", {{"data", {{"type", "products"}, {"id", "my-app"}}}}}}}}},
        {"included",
         nlohmann::json::array(
             {{{"type", "licenses"},
               {"id", license_key},
               {"attributes",
                {{"key", license_key},
                 {"status", "active"},
                 {"mode", "hardware_locked"},
                 {"plan_key", "pro"},
                 {"ends_at", json::format_timestamp(json::parse_unix_timestamp(license_expiry))},
                 {"product_slug", "my-app"}}}}})}};

    std::string public_key_b64;
    MachineFile machine_file;
    machine_file.certificate =
        build_machine_file_certificate(license_key, fingerprint, payload, &public_key_b64);

    auto result = verify_machine_file(machine_file, license_key, fingerprint, public_key_b64);

    ASSERT_TRUE(result.is_ok()) << result.error_message();
    EXPECT_EQ(result.value().license_key, license_key);
    EXPECT_EQ(result.value().fingerprint, fingerprint);
    ASSERT_TRUE(result.value().license.has_value());
    EXPECT_EQ(result.value().license->plan_key(), "pro");
}

TEST(MachineFileVerificationTest, WrongFingerprintFailsDecryption) {
    const auto now = std::time(nullptr);
    const std::string license_key = "KEY-123";
    const std::string fingerprint = "fp-12345";

    nlohmann::json payload = {
        {"meta",
         {{"schema_version", 2},
          {"issued", json::format_timestamp(json::parse_unix_timestamp(now))},
          {"iat", now},
          {"expiry", json::format_timestamp(json::parse_unix_timestamp(now + 86400))},
          {"exp", now + 86400},
          {"nbf", now},
          {"ttl", 86400},
          {"grace_period", 0},
          {"lic", license_key},
          {"kid", "test-kid"}}},
        {"data",
         {{"type", "machines"},
          {"id", "42"},
          {"attributes", {{"fingerprint", fingerprint}}},
          {"relationships",
           {{"license", {{"data", {{"type", "licenses"}, {"id", license_key}}}}},
            {"product", {{"data", {{"type", "products"}, {"id", "my-app"}}}}}}}}}};

    std::string public_key_b64;
    MachineFile machine_file;
    machine_file.certificate =
        build_machine_file_certificate(license_key, fingerprint, payload, &public_key_b64);

    auto result =
        verify_machine_file(machine_file, license_key, "different-fingerprint", public_key_b64);

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::DecryptionFailed);
}

TEST(MachineFileVerificationTest, ExpiredMachineFileFails) {
    const auto now = std::time(nullptr);
    const std::string license_key = "KEY-123";
    const std::string fingerprint = "fp-12345";

    nlohmann::json payload = {
        {"meta",
         {{"schema_version", 2},
          {"issued", json::format_timestamp(json::parse_unix_timestamp(now - 90000))},
          {"iat", now - 90000},
          {"expiry", json::format_timestamp(json::parse_unix_timestamp(now - 3600))},
          {"exp", now - 3600},
          {"nbf", now - 90000},
          {"ttl", 86400},
          {"grace_period", 0},
          {"lic", license_key},
          {"kid", "test-kid"}}},
        {"data",
         {{"type", "machines"},
          {"id", "42"},
          {"attributes", {{"fingerprint", fingerprint}}},
          {"relationships",
           {{"license", {{"data", {{"type", "licenses"}, {"id", license_key}}}}},
            {"product", {{"data", {{"type", "products"}, {"id", "my-app"}}}}}}}}}};

    std::string public_key_b64;
    MachineFile machine_file;
    machine_file.certificate =
        build_machine_file_certificate(license_key, fingerprint, payload, &public_key_b64);

    auto result = verify_machine_file(machine_file, license_key, fingerprint, public_key_b64);

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::TokenExpired);
}

TEST(MachineFileVerificationTest, HumanReadableTimesMustMatchSignedUnixClaims) {
    const auto now = std::time(nullptr);
    const std::string license_key = "KEY-123";
    const std::string fingerprint = "fp-12345";
    auto payload = build_minimal_machine_payload(license_key, fingerprint, now, now + 86400);
    payload["meta"]["issued"] = json::format_timestamp(json::parse_unix_timestamp(now - 1));

    std::string public_key_b64;
    MachineFile machine_file;
    machine_file.certificate =
        build_machine_file_certificate(license_key, fingerprint, payload, &public_key_b64);
    auto result = verify_machine_file(machine_file, license_key, fingerprint, public_key_b64);
    ASSERT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidParameter);

    payload = build_minimal_machine_payload(license_key, fingerprint, now, now + 86400);
    payload["meta"]["expiry"] = json::format_timestamp(json::parse_unix_timestamp(now + 86401));
    machine_file.certificate =
        build_machine_file_certificate(license_key, fingerprint, payload, &public_key_b64);
    result = verify_machine_file(machine_file, license_key, fingerprint, public_key_b64);
    ASSERT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidParameter);
}

TEST(MachineFileVerificationTest, RejectsUnsupportedLifetimeAndGracePeriod) {
    const auto now = std::time(nullptr);
    const std::string license_key = "KEY-123";
    const std::string fingerprint = "fp-12345";
    std::string public_key_b64;
    MachineFile machine_file;

    auto payload =
        build_minimal_machine_payload(license_key, fingerprint, now, now + 86400, 30LL * 86400 + 1);
    machine_file.certificate =
        build_machine_file_certificate(license_key, fingerprint, payload, &public_key_b64);
    auto result = verify_machine_file(machine_file, license_key, fingerprint, public_key_b64);
    ASSERT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidParameter);

    constexpr int64_t excessive_lifetime = 100LL * 366 * 86400 + 1;
    payload =
        build_minimal_machine_payload(license_key, fingerprint, now, now + excessive_lifetime);
    machine_file.certificate =
        build_machine_file_certificate(license_key, fingerprint, payload, &public_key_b64);
    result = verify_machine_file(machine_file, license_key, fingerprint, public_key_b64);
    ASSERT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidParameter);
}

TEST(MachineFileVerificationTest, ExactExpiryInstantIsExpired) {
    const auto now = std::time(nullptr);
    const std::string license_key = "KEY-123";
    const std::string fingerprint = "fp-12345";
    auto payload = build_minimal_machine_payload(license_key, fingerprint, now - 1, now);

    std::string public_key_b64;
    MachineFile machine_file;
    machine_file.certificate =
        build_machine_file_certificate(license_key, fingerprint, payload, &public_key_b64);
    auto result = verify_machine_file(machine_file, license_key, fingerprint, public_key_b64);

    ASSERT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::TokenExpired);
}

TEST(MachineFileVerificationTest, EmbeddedLicenseExpiryMustMatchTopLevelClaim) {
    const auto now = std::time(nullptr);
    const auto license_expiry = now + 86400;
    const std::string license_key = "KEY-123";
    const std::string fingerprint = "fp-12345";
    auto payload = build_minimal_machine_payload(license_key, fingerprint, now, now + 3600);
    payload["meta"]["license_exp"] = license_expiry;
    payload["included"] = nlohmann::json::array(
        {{{"type", "licenses"},
          {"id", license_key},
          {"attributes",
           {{"key", license_key},
            {"status", "active"},
            {"mode", "hardware_locked"},
            {"plan_key", "pro"},
            {"product_slug", "my-app"},
            {"ends_at",
             json::format_timestamp(json::parse_unix_timestamp(license_expiry + 1))}}}}});

    std::string public_key_b64;
    MachineFile machine_file;
    machine_file.certificate =
        build_machine_file_certificate(license_key, fingerprint, payload, &public_key_b64);
    auto result = verify_machine_file(machine_file, license_key, fingerprint, public_key_b64);

    ASSERT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidParameter);
}

TEST(MachineFileVerificationTest, CertificateFramingIsStrictAndBounded) {
    const auto now = std::time(nullptr);
    const std::string license_key = "KEY-123";
    const std::string fingerprint = "fp-12345";
    const auto payload = build_minimal_machine_payload(license_key, fingerprint, now, now + 3600);
    std::string public_key_b64;
    MachineFile machine_file;
    const auto valid =
        build_machine_file_certificate(license_key, fingerprint, payload, &public_key_b64);

    const auto expect_parse_error = [&](const std::string& certificate) {
        machine_file.certificate = certificate;
        const auto result =
            verify_machine_file(machine_file, license_key, fingerprint, public_key_b64);
        ASSERT_TRUE(result.is_error());
        EXPECT_EQ(result.error_code(), ErrorCode::ParseError);
    };

    expect_parse_error("untrusted-prefix\n" + valid);
    expect_parse_error(valid + "\nuntrusted-suffix");
    expect_parse_error(valid.substr(valid.find('\n') + 1));
    expect_parse_error(valid.substr(0, valid.rfind('\n')));

    const auto body_begin = valid.find('\n') + 1;
    const auto body_end = valid.rfind('\n');
    auto unwrapped = valid.substr(body_begin, body_end - body_begin);
    unwrapped.erase(std::remove(unwrapped.begin(), unwrapped.end(), '\n'), unwrapped.end());
    ASSERT_GT(unwrapped.size(), 64U);
    expect_parse_error("-----BEGIN MACHINE FILE-----\n" + unwrapped +
                       "\n-----END MACHINE FILE-----");
    expect_parse_error("-----BEGIN MACHINE FILE-----\n\n" + unwrapped.substr(0, 64) +
                       "\n-----END MACHINE FILE-----");

    machine_file.certificate = " \r\n" + valid + "\r\n\t";
    const auto accepted =
        verify_machine_file(machine_file, license_key, fingerprint, public_key_b64);
    ASSERT_TRUE(accepted.is_ok()) << accepted.error_message();
}

} // namespace rfc8032

} // namespace
} // namespace crypto
} // namespace licenseseat
