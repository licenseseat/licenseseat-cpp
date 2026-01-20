#include <gtest/gtest.h>
#include <licenseseat/crypto.hpp>

namespace licenseseat {
namespace crypto {
namespace {

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

    std::vector<uint8_t> expected = {'H', 'e', 'l', 'l', 'o', ',', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
    EXPECT_EQ(decoded, expected);
}

TEST(Base64Test, RoundTrip) {
    std::vector<uint8_t> original = {0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD};
    auto encoded = base64_encode(original);
    auto decoded = base64_decode(encoded);

    EXPECT_EQ(decoded, original);
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
    EXPECT_TRUE(url_safe.find('=') == std::string::npos);  // No padding
}

TEST(Base64UrlTest, DecodeWithSpecialChars) {
    // "-_" in Base64URL corresponds to "+/" in standard Base64
    std::string url_encoded = "-_8";  // Base64URL for some bytes

    auto decoded = base64url_decode(url_encoded);

    EXPECT_FALSE(decoded.empty());
}

TEST(Base64UrlTest, RoundTrip) {
    std::vector<uint8_t> original = {0xfb, 0xff, 0xfe, 0x00, 0x01, 0x02};
    auto encoded = base64url_encode(original);
    auto decoded = base64url_decode(encoded);

    EXPECT_EQ(decoded, original);
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

// ==================== Offline License Verification Tests ====================

TEST(OfflineLicenseVerificationTest, EmptyLicenseKeyFails) {
    OfflineLicense offline;
    offline.license_key = "";

    auto result = verify_offline_license_signature(offline, TEST_PUBLIC_KEY_B64);

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidLicenseKey);
}

TEST(OfflineLicenseVerificationTest, EmptySignatureFails) {
    OfflineLicense offline;
    offline.license_key = "KEY-123";
    offline.signature_b64u = "";

    auto result = verify_offline_license_signature(offline, TEST_PUBLIC_KEY_B64);

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidSignature);
}

TEST(OfflineLicenseVerificationTest, EmptyPublicKeyFails) {
    OfflineLicense offline;
    offline.license_key = "KEY-123";
    offline.signature_b64u = "some-signature";

    auto result = verify_offline_license_signature(offline, "");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::MissingParameter);
}

// Note: Testing with actual valid signatures would require generating
// real Ed25519 key pairs and signatures at test time or using fixed test vectors.

}  // namespace
}  // namespace crypto
}  // namespace licenseseat
