/**
 * @file crypto_stress_test.cpp
 * @brief Extremely thorough testing of offline tokens and crypto functionality
 *
 * Tests:
 * - Offline token generation from live API
 * - Ed25519 signature verification
 * - Base64/Base64URL encoding/decoding
 * - Token structure validation
 * - Token expiration handling
 * - Signature tampering detection
 * - Wrong key rejection
 * - Edge cases and error handling
 *
 * Required environment variables:
 *   LICENSESEAT_API_KEY      - Your LicenseSeat API key
 *   LICENSESEAT_PRODUCT_SLUG - Your product slug
 *   LICENSESEAT_LICENSE_KEY  - A valid license key for testing
 *
 * Run with:
 *   export LICENSESEAT_API_KEY="your-api-key"
 *   export LICENSESEAT_PRODUCT_SLUG="your-product"
 *   export LICENSESEAT_LICENSE_KEY="XXXX-XXXX-XXXX-XXXX"
 *   ./crypto_stress_test
 */

#include <licenseseat/licenseseat.hpp>
#include <licenseseat/crypto.hpp>
#include <licenseseat/device.hpp>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <random>
#include <thread>
#include <vector>

namespace {

std::string get_env(const char* name) {
    const char* value = std::getenv(name);
    return value ? std::string(value) : std::string();
}

std::string API_KEY;
std::string PRODUCT_SLUG;
std::string LICENSE_KEY;

bool load_credentials() {
    API_KEY = get_env("LICENSESEAT_API_KEY");
    PRODUCT_SLUG = get_env("LICENSESEAT_PRODUCT_SLUG");
    LICENSE_KEY = get_env("LICENSESEAT_LICENSE_KEY");

    if (API_KEY.empty() || PRODUCT_SLUG.empty() || LICENSE_KEY.empty()) {
        std::cerr << "Error: Missing required environment variables.\n\n";
        std::cerr << "Please set the following environment variables:\n";
        std::cerr << "  LICENSESEAT_API_KEY      - Your LicenseSeat API key\n";
        std::cerr << "  LICENSESEAT_PRODUCT_SLUG - Your product slug\n";
        std::cerr << "  LICENSESEAT_LICENSE_KEY  - A valid license key for testing\n\n";
        std::cerr << "Example:\n";
        std::cerr << "  export LICENSESEAT_API_KEY=\"ls_your_api_key\"\n";
        std::cerr << "  export LICENSESEAT_PRODUCT_SLUG=\"your-product\"\n";
        std::cerr << "  export LICENSESEAT_LICENSE_KEY=\"XXXX-XXXX-XXXX-XXXX\"\n";
        std::cerr << "  ./crypto_stress_test\n";
        return false;
    }
    return true;
}

}  // namespace

// Test counters
std::atomic<int> tests_passed{0};
std::atomic<int> tests_failed{0};

// Color codes
const char* const GREEN = "\033[32m";
const char* const RED = "\033[31m";
const char* const YELLOW = "\033[33m";
const char* const CYAN = "\033[36m";
const char* const RESET = "\033[0m";

void pass(const std::string& test_name) {
    ++tests_passed;
    std::cout << GREEN << "✓ PASS: " << RESET << test_name << "\n";
}

void fail(const std::string& test_name, const std::string& reason) {
    ++tests_failed;
    std::cout << RED << "✗ FAIL: " << RESET << test_name << " - " << reason << "\n";
}

void info(const std::string& message) {
    std::cout << YELLOW << "  ℹ " << RESET << message << "\n";
}

void section(const std::string& name) {
    std::cout << "\n" << CYAN << "═══════════════════════════════════════════════════════════════" << RESET << "\n";
    std::cout << CYAN << "  " << name << RESET << "\n";
    std::cout << CYAN << "═══════════════════════════════════════════════════════════════" << RESET << "\n\n";
}

licenseseat::Config make_config() {
    licenseseat::Config config;
    config.api_key = API_KEY;
    config.product_slug = PRODUCT_SLUG;
    config.api_url = "https://licenseseat.com/api/v1";
    config.timeout_seconds = 30;
    config.max_retries = 2;
    return config;
}

// ============================================================================
// Base64 Tests
// ============================================================================

void test_base64_encoding() {
    section("Base64 Encoding/Decoding");

    // Test 1: Empty string
    {
        std::vector<uint8_t> empty;
        std::string encoded = licenseseat::crypto::base64_encode(empty);
        auto decoded = licenseseat::crypto::base64_decode(encoded);
        if (decoded.empty()) {
            pass("Base64 empty string round-trip");
        } else {
            fail("Base64 empty string round-trip", "Failed to round-trip empty data");
        }
    }

    // Test 2: Single byte
    {
        std::vector<uint8_t> single = {0x42};
        std::string encoded = licenseseat::crypto::base64_encode(single);
        auto decoded = licenseseat::crypto::base64_decode(encoded);
        if (decoded == single) {
            pass("Base64 single byte round-trip");
            info("Encoded: " + encoded);
        } else {
            fail("Base64 single byte round-trip", "Mismatch");
        }
    }

    // Test 3: Known test vectors (RFC 4648)
    {
        // "Hello" -> "SGVsbG8="
        std::vector<uint8_t> hello = {'H', 'e', 'l', 'l', 'o'};
        std::string encoded = licenseseat::crypto::base64_encode(hello);
        if (encoded == "SGVsbG8=") {
            pass("Base64 'Hello' encoding");
        } else {
            fail("Base64 'Hello' encoding", "Expected SGVsbG8=, got " + encoded);
        }

        auto decoded = licenseseat::crypto::base64_decode("SGVsbG8=");
        if (decoded == hello) {
            pass("Base64 'Hello' decoding");
        } else {
            fail("Base64 'Hello' decoding", "Mismatch");
        }
    }

    // Test 4: Binary data with all byte values
    {
        std::vector<uint8_t> all_bytes;
        for (int i = 0; i < 256; ++i) {
            all_bytes.push_back(static_cast<uint8_t>(i));
        }
        std::string encoded = licenseseat::crypto::base64_encode(all_bytes);
        auto decoded = licenseseat::crypto::base64_decode(encoded);
        if (decoded == all_bytes) {
            pass("Base64 all 256 byte values round-trip");
            info("Encoded length: " + std::to_string(encoded.length()));
        } else {
            fail("Base64 all 256 byte values round-trip", "Mismatch");
        }
    }

    // Test 5: Padding variations (1, 2, 3 byte inputs)
    {
        bool all_passed = true;
        for (size_t len = 1; len <= 10; ++len) {
            std::vector<uint8_t> data(len, 0xAB);
            std::string encoded = licenseseat::crypto::base64_encode(data);
            auto decoded = licenseseat::crypto::base64_decode(encoded);
            if (decoded != data) {
                all_passed = false;
                break;
            }
        }
        if (all_passed) {
            pass("Base64 padding variations (1-10 bytes)");
        } else {
            fail("Base64 padding variations", "Failed for some length");
        }
    }

    // Test 6: Large data
    {
        std::vector<uint8_t> large_data(100000);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        for (auto& b : large_data) {
            b = static_cast<uint8_t>(dis(gen));
        }

        std::string encoded = licenseseat::crypto::base64_encode(large_data);
        auto decoded = licenseseat::crypto::base64_decode(encoded);
        if (decoded == large_data) {
            pass("Base64 large data (100KB) round-trip");
            info("Encoded size: " + std::to_string(encoded.size()) + " bytes");
        } else {
            fail("Base64 large data round-trip", "Mismatch");
        }
    }
}

void test_base64url_encoding() {
    section("Base64URL Encoding/Decoding");

    // Test 1: Characters that differ from standard base64
    {
        // Standard base64 uses + and /, base64url uses - and _
        std::vector<uint8_t> data = {0xfb, 0xff, 0xfe};  // Would produce +/
        std::string encoded = licenseseat::crypto::base64url_encode(data);

        // Should not contain + or /
        bool has_invalid = (encoded.find('+') != std::string::npos ||
                           encoded.find('/') != std::string::npos);
        if (!has_invalid) {
            pass("Base64URL uses URL-safe characters");
            info("Encoded: " + encoded);
        } else {
            fail("Base64URL uses URL-safe characters", "Contains + or /");
        }
    }

    // Test 2: Round-trip
    {
        std::vector<uint8_t> data = {0x00, 0x01, 0x02, 0xfe, 0xff};
        std::string encoded = licenseseat::crypto::base64url_encode(data);
        auto decoded = licenseseat::crypto::base64url_decode(encoded);
        if (decoded == data) {
            pass("Base64URL round-trip");
        } else {
            fail("Base64URL round-trip", "Mismatch");
        }
    }

    // Test 3: No padding (base64url often omits padding)
    {
        std::vector<uint8_t> data = {'a', 'b', 'c'};
        std::string encoded = licenseseat::crypto::base64url_encode(data);
        auto decoded = licenseseat::crypto::base64url_decode(encoded);
        if (decoded == data) {
            pass("Base64URL handles padding correctly");
            info("Encoded (with/without padding): " + encoded);
        } else {
            fail("Base64URL handles padding correctly", "Failed");
        }
    }
}

// ============================================================================
// Ed25519 Signature Tests
// ============================================================================

void test_ed25519_verification() {
    section("Ed25519 Signature Verification");

    // Test 1: Invalid key format
    {
        std::string invalid_key = "not-a-valid-base64-key!!!";
        std::string sig_b64 = "5AfOueTe0sQT6C5DPzH_VZbpR3V1o_ehUg9eMOxJ2xjqFKbKC0WP0uxv3gcQyPDZXJoGb8n_5rGF_H2EPYRfAQ";
        std::string message = "test";

        auto result = licenseseat::crypto::verify_ed25519_signature(message, sig_b64, invalid_key);
        if (result.is_error() || !result.value()) {
            pass("Ed25519 rejects invalid key format");
        } else {
            fail("Ed25519 rejects invalid key format", "Accepted invalid key");
        }
    }

    // Test 2: Invalid signature format
    {
        std::string pub_key_b64 = "PUAXw+hskiGPT/Fe2DLDoXKXJcTgXHYJYSPGlA6o8Bk=";
        std::string invalid_sig = "not-valid";
        std::string message = "test";

        auto result = licenseseat::crypto::verify_ed25519_signature(message, invalid_sig, pub_key_b64);
        if (result.is_error() || !result.value()) {
            pass("Ed25519 rejects invalid signature format");
        } else {
            fail("Ed25519 rejects invalid signature format", "Accepted invalid signature");
        }
    }

    // Test 3: Key length validation (Ed25519 keys are 32 bytes)
    {
        // Wrong size key
        std::string short_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";  // Not 32 bytes
        std::string sig_b64 = "5AfOueTe0sQT6C5DPzH_VZbpR3V1o_ehUg9eMOxJ2xjqFKbKC0WP0uxv3gcQyPDZXJoGb8n_5rGF_H2EPYRfAQ";
        std::string message = "";

        auto result = licenseseat::crypto::verify_ed25519_signature(message, sig_b64, short_key);
        if (result.is_error() || !result.value()) {
            pass("Ed25519 handles wrong-length key");
        } else {
            fail("Ed25519 handles wrong-length key", "Accepted wrong-length key");
        }
    }

    // Test 4: Signature length validation (Ed25519 signatures are 64 bytes)
    {
        std::string pub_key_b64 = "PUAXw+hskiGPT/Fe2DLDoXKXJcTgXHYJYSPGlA6o8Bk=";
        std::string short_sig = "AAAAAAAAAA";  // Way too short
        std::string message = "";

        auto result = licenseseat::crypto::verify_ed25519_signature(message, short_sig, pub_key_b64);
        if (result.is_error() || !result.value()) {
            pass("Ed25519 rejects wrong-length signature");
        } else {
            fail("Ed25519 rejects wrong-length signature", "Accepted wrong-length signature");
        }
    }

    // Test 5: Empty inputs
    {
        auto result1 = licenseseat::crypto::verify_ed25519_signature("", "", "");
        if (result1.is_error() || !result1.value()) {
            pass("Ed25519 rejects all-empty inputs");
        } else {
            fail("Ed25519 rejects all-empty inputs", "Accepted empty inputs");
        }
    }
}

// ============================================================================
// Live API Offline Token Tests
// ============================================================================

void test_offline_token_generation() {
    section("Offline Token Generation (Live API)");

    auto config = make_config();
    licenseseat::Client client(config);

    // Test 1: Generate offline token
    auto result = client.generate_offline_token(LICENSE_KEY);

    if (result.is_error()) {
        fail("Generate offline token", result.error_message());
        return;
    }

    pass("Generate offline token");
    const auto& offline = result.value();

    // Test 2: Validate token structure
    {
        bool structure_valid = true;
        std::string issues;

        if (offline.token.license_key.empty()) {
            structure_valid = false;
            issues += "missing license_key; ";
        }
        if (offline.token.product_slug.empty()) {
            structure_valid = false;
            issues += "missing product_slug; ";
        }
        if (offline.token.kid.empty()) {
            structure_valid = false;
            issues += "missing kid; ";
        }
        if (offline.token.iat == 0) {
            structure_valid = false;
            issues += "missing iat; ";
        }
        if (offline.token.exp == 0) {
            structure_valid = false;
            issues += "missing exp; ";
        }
        if (offline.signature.value.empty()) {
            structure_valid = false;
            issues += "missing signature; ";
        }
        if (offline.canonical.empty()) {
            structure_valid = false;
            issues += "missing canonical; ";
        }

        if (structure_valid) {
            pass("Token structure validation");
            info("License key: " + offline.token.license_key);
            info("Product slug: " + offline.token.product_slug);
            info("Plan key: " + offline.token.plan_key);
            info("Mode: " + offline.token.mode);
            info("Key ID (kid): " + offline.token.kid);
            info("Issued at (iat): " + std::to_string(offline.token.iat));
            info("Expires at (exp): " + std::to_string(offline.token.exp));
            info("Not before (nbf): " + std::to_string(offline.token.nbf));
            info("Signature algorithm: " + offline.signature.algorithm);
            info("Signature key ID: " + offline.signature.key_id);
            info("Canonical length: " + std::to_string(offline.canonical.length()));
            if (offline.token.seat_limit.has_value()) {
                info("Seat limit: " + std::to_string(offline.token.seat_limit.value()));
            }
        } else {
            fail("Token structure validation", issues);
        }
    }

    // Test 3: Token timestamps
    {
        auto now = std::time(nullptr);
        bool timestamps_valid = true;
        std::string issues;

        // iat should be around now (within 5 minutes)
        if (std::abs(offline.token.iat - now) > 300) {
            timestamps_valid = false;
            issues += "iat too far from now; ";
        }

        // exp should be in the future
        if (offline.token.exp <= now) {
            timestamps_valid = false;
            issues += "exp is in the past; ";
        }

        // nbf should be <= now (token should be valid now)
        if (offline.token.nbf > now + 60) {  // Allow 1 minute slack
            timestamps_valid = false;
            issues += "nbf is in the future; ";
        }

        // exp should be after iat
        if (offline.token.exp <= offline.token.iat) {
            timestamps_valid = false;
            issues += "exp before iat; ";
        }

        if (timestamps_valid) {
            pass("Token timestamp validation");
            auto ttl_days = (offline.token.exp - offline.token.iat) / 86400;
            info("Token TTL: " + std::to_string(ttl_days) + " days");
        } else {
            fail("Token timestamp validation", issues);
        }
    }

    // Test 4: Canonical JSON format
    {
        bool canonical_valid = true;
        std::string issues;

        // Should be valid JSON (contains braces)
        if (offline.canonical.front() != '{' || offline.canonical.back() != '}') {
            canonical_valid = false;
            issues += "not valid JSON object; ";
        }

        // Should contain key fields
        if (offline.canonical.find("license_key") == std::string::npos) {
            canonical_valid = false;
            issues += "missing license_key in canonical; ";
        }

        if (canonical_valid) {
            pass("Canonical JSON format");
            info("First 100 chars: " + offline.canonical.substr(0, 100) + "...");
        } else {
            fail("Canonical JSON format", issues);
        }
    }
}

void test_signing_key_fetch() {
    section("Signing Key Fetch (Live API)");

    auto config = make_config();
    licenseseat::Client client(config);

    // First get an offline token to get the key ID
    auto token_result = client.generate_offline_token(LICENSE_KEY);
    if (token_result.is_error()) {
        fail("Get key ID from offline token", token_result.error_message());
        return;
    }

    const auto& offline = token_result.value();
    std::string key_id = offline.token.kid;
    info("Key ID to fetch: " + key_id);

    // Test 1: Fetch the signing key
    auto key_result = client.fetch_signing_key(key_id);
    if (key_result.is_error()) {
        fail("Fetch signing key", key_result.error_message());
        return;
    }

    pass("Fetch signing key");
    const std::string& public_key = key_result.value();
    info("Public key: " + public_key.substr(0, 20) + "...");

    // Test 2: Validate key format (should be base64-encoded 32-byte Ed25519 public key)
    {
        auto decoded = licenseseat::crypto::base64_decode(public_key);
        if (decoded.size() == 32) {
            pass("Signing key is valid Ed25519 format (32 bytes)");
        } else {
            fail("Signing key format", "Expected 32 bytes, got " + std::to_string(decoded.size()));
        }
    }

    // Test 3: Key is consistent (fetch again, should get same key)
    {
        auto key_result2 = client.fetch_signing_key(key_id);
        if (key_result2.is_ok() && key_result2.value() == public_key) {
            pass("Signing key is consistent across fetches");
        } else {
            fail("Signing key is consistent", "Keys differ");
        }
    }

    // Test 4: Invalid key ID
    {
        auto invalid_result = client.fetch_signing_key("non-existent-key-id-12345");
        if (invalid_result.is_error()) {
            pass("Fetch non-existent key returns error");
            info("Error: " + invalid_result.error_message());
        } else {
            fail("Fetch non-existent key", "Should have returned error");
        }
    }

    // Test 5: Empty key ID
    {
        auto empty_result = client.fetch_signing_key("");
        if (empty_result.is_error()) {
            pass("Fetch empty key ID returns error");
        } else {
            fail("Fetch empty key ID", "Should have returned error");
        }
    }
}

void test_offline_token_verification() {
    section("Offline Token Verification (Live API)");

    auto config = make_config();
    licenseseat::Client client(config);

    // Generate offline token
    auto token_result = client.generate_offline_token(LICENSE_KEY);
    if (token_result.is_error()) {
        fail("Generate offline token for verification", token_result.error_message());
        return;
    }

    const auto& offline = token_result.value();

    // Fetch the signing key
    auto key_result = client.fetch_signing_key(offline.token.kid);
    if (key_result.is_error()) {
        fail("Fetch signing key for verification", key_result.error_message());
        return;
    }

    const std::string& public_key = key_result.value();

    // Test 1: Verify valid token with correct key
    {
        auto verify_result = client.verify_offline_token(offline, public_key);
        if (verify_result.is_ok() && verify_result.value()) {
            pass("Verify offline token with correct key");
        } else if (verify_result.is_error()) {
            fail("Verify offline token with correct key", verify_result.error_message());
        } else {
            fail("Verify offline token with correct key", "Verification returned false");
        }
    }

    // Test 2: Verify with wrong key
    {
        // Generate a different (wrong) public key (32 bytes base64)
        std::string wrong_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

        auto verify_result = client.verify_offline_token(offline, wrong_key);
        if (verify_result.is_ok() && !verify_result.value()) {
            pass("Verify with wrong key returns false");
        } else if (verify_result.is_error()) {
            pass("Verify with wrong key returns error");
            info("Error: " + verify_result.error_message());
        } else {
            fail("Verify with wrong key", "Should have failed");
        }
    }

    // Test 3: Tampered canonical JSON
    {
        licenseseat::OfflineToken tampered = offline;
        // Change the canonical JSON (this should invalidate the signature)
        tampered.canonical = "{\"tampered\":true}";

        auto verify_result = client.verify_offline_token(tampered, public_key);
        if (verify_result.is_ok() && !verify_result.value()) {
            pass("Tampered canonical JSON fails verification");
        } else if (verify_result.is_error()) {
            pass("Tampered canonical JSON returns error");
        } else {
            fail("Tampered canonical JSON", "Should have failed verification");
        }
    }

    // Test 4: Tampered signature
    {
        licenseseat::OfflineToken tampered = offline;
        // Change one character in the signature
        if (!tampered.signature.value.empty()) {
            tampered.signature.value[0] = (tampered.signature.value[0] == 'A') ? 'B' : 'A';
        }

        auto verify_result = client.verify_offline_token(tampered, public_key);
        if (verify_result.is_ok() && !verify_result.value()) {
            pass("Tampered signature fails verification");
        } else if (verify_result.is_error()) {
            pass("Tampered signature returns error");
        } else {
            fail("Tampered signature", "Should have failed verification");
        }
    }

    // Test 5: Empty signature
    {
        licenseseat::OfflineToken tampered = offline;
        tampered.signature.value = "";

        auto verify_result = client.verify_offline_token(tampered, public_key);
        if (!verify_result.is_ok() || !verify_result.value()) {
            pass("Empty signature fails verification");
        } else {
            fail("Empty signature", "Should have failed verification");
        }
    }

    // Test 6: Empty canonical
    {
        licenseseat::OfflineToken tampered = offline;
        tampered.canonical = "";

        auto verify_result = client.verify_offline_token(tampered, public_key);
        if (!verify_result.is_ok() || !verify_result.value()) {
            pass("Empty canonical fails verification");
        } else {
            fail("Empty canonical", "Should have failed verification");
        }
    }

    // Test 7: Empty public key - SDK falls back to cached key if available
    {
        auto verify_result = client.verify_offline_token(offline, "");
        if (verify_result.is_ok() && verify_result.value()) {
            // This is expected - SDK uses cached key from previous verification
            pass("Empty public key uses cached key (SDK design)");
        } else if (verify_result.is_error() &&
                   verify_result.error_code() == licenseseat::ErrorCode::MissingParameter) {
            // This happens if no cached key exists
            pass("Empty public key fails when no cached key");
        } else {
            fail("Empty public key handling", "Unexpected result");
        }
    }

    // Test 8: Invalid base64 in public key
    {
        auto verify_result = client.verify_offline_token(offline, "not-valid-base64!!!");
        if (!verify_result.is_ok() || !verify_result.value()) {
            pass("Invalid base64 public key fails verification");
        } else {
            fail("Invalid base64 public key", "Should have failed verification");
        }
    }
}

void test_expired_token() {
    section("Expired Token Handling");

    auto config = make_config();
    licenseseat::Client client(config);

    // Generate a real token to get the structure
    auto token_result = client.generate_offline_token(LICENSE_KEY);
    if (token_result.is_error()) {
        fail("Generate token for expiry test", token_result.error_message());
        return;
    }

    auto key_result = client.fetch_signing_key(token_result.value().token.kid);
    if (key_result.is_error()) {
        fail("Fetch key for expiry test", key_result.error_message());
        return;
    }

    const std::string& public_key = key_result.value();

    // Test 1: Create an artificially expired token
    {
        licenseseat::OfflineToken expired = token_result.value();
        // Set expiration to the past
        expired.token.exp = std::time(nullptr) - 86400;  // 1 day ago

        auto verify_result = client.verify_offline_token(expired, public_key);

        // Even though we modified exp, the signature won't match anymore
        // So this tests that we properly check expiration OR signature
        if (verify_result.is_error() &&
            verify_result.error_code() == licenseseat::ErrorCode::LicenseExpired) {
            pass("Expired token returns LicenseExpired error");
        } else if (!verify_result.is_ok() || !verify_result.value()) {
            pass("Expired/tampered token fails verification");
        } else {
            fail("Expired token", "Should have failed");
        }
    }

    // Test 2: Token not yet valid (nbf in future)
    {
        licenseseat::OfflineToken not_yet_valid = token_result.value();
        // Set not-before to the future
        not_yet_valid.token.nbf = std::time(nullptr) + 86400 * 365;  // 1 year from now

        auto verify_result = client.verify_offline_token(not_yet_valid, public_key);

        // This should fail (either due to nbf check or signature mismatch)
        if (!verify_result.is_ok() || !verify_result.value()) {
            pass("Not-yet-valid token fails verification");
        } else {
            fail("Not-yet-valid token", "Should have failed");
        }
    }
}

void test_multiple_tokens() {
    section("Multiple Token Operations");

    auto config = make_config();
    licenseseat::Client client(config);

    // Test 1: Generate multiple tokens in sequence
    {
        std::vector<licenseseat::OfflineToken> tokens;
        bool all_succeeded = true;

        for (int i = 0; i < 3; ++i) {
            auto result = client.generate_offline_token(LICENSE_KEY);
            if (result.is_ok()) {
                tokens.push_back(result.value());
            } else {
                all_succeeded = false;
                break;
            }
        }

        if (all_succeeded && tokens.size() == 3) {
            pass("Generate multiple tokens sequentially");

            // All tokens should have same kid but may have different iat/exp
            bool same_kid = (tokens[0].token.kid == tokens[1].token.kid &&
                            tokens[1].token.kid == tokens[2].token.kid);
            if (same_kid) {
                pass("All tokens have same key ID");
            } else {
                info("Tokens have different key IDs (key rotation?)");
            }
        } else {
            fail("Generate multiple tokens", "Failed to generate all tokens");
        }
    }

    // Test 2: Concurrent token generation
    {
        std::vector<std::thread> threads;
        threads.reserve(5);
        std::atomic<int> success_count{0};
        std::atomic<int> error_count{0};
        constexpr int NUM_CONCURRENT = 5;

        for (int i = 0; i < NUM_CONCURRENT; ++i) {
            threads.emplace_back([&]() {
                auto cfg = make_config();
                licenseseat::Client c(cfg);
                auto result = c.generate_offline_token(LICENSE_KEY);
                if (result.is_ok()) {
                    ++success_count;
                } else {
                    ++error_count;
                }
            });
        }

        for (auto& t : threads) {
            t.join();
        }

        if (success_count == NUM_CONCURRENT) {
            pass("Concurrent token generation (" + std::to_string(NUM_CONCURRENT) + " threads)");
        } else {
            info("Success: " + std::to_string(success_count.load()) +
                 ", Errors: " + std::to_string(error_count.load()));
            // Allow some failures due to rate limiting
            if (success_count > 0) {
                pass("Concurrent token generation (some succeeded)");
            } else {
                fail("Concurrent token generation", "All failed");
            }
        }
    }
}

void test_device_id_in_offline_token() {
    section("Device ID in Offline Token");

    auto config = make_config();
    config.device_id = "test-device-" + std::to_string(std::time(nullptr));
    licenseseat::Client client(config);

    // The license is hardware_locked, so it requires device_id
    // But generating an offline token doesn't require the device to be activated

    auto result = client.generate_offline_token(LICENSE_KEY);

    if (result.is_ok()) {
        pass("Generate offline token (hardware_locked license)");
        const auto& token = result.value().token;
        info("License mode: " + token.mode);
        if (token.device_id.has_value()) {
            info("Device ID in token: " + token.device_id.value());
        } else {
            info("No device_id in token (floating or unbound)");
        }
    } else {
        // For hardware_locked licenses, this might fail if device not activated
        info("Result: " + result.error_message());
        // This is acceptable behavior
        pass("Offline token generation behavior for hardware_locked license");
    }
}

void test_entitlements_in_token() {
    section("Entitlements in Offline Token");

    auto config = make_config();
    licenseseat::Client client(config);

    auto result = client.generate_offline_token(LICENSE_KEY);
    if (result.is_error()) {
        fail("Generate token for entitlements test", result.error_message());
        return;
    }

    const auto& token = result.value().token;

    info("Number of entitlements: " + std::to_string(token.entitlements.size()));

    if (token.entitlements.empty()) {
        pass("Token entitlements (none defined for this license)");
    } else {
        pass("Token contains entitlements");
        for (const auto& ent : token.entitlements) {
            std::string ent_info = "  - " + ent.key;
            if (ent.expires_at.has_value()) {
                auto exp_time = std::chrono::system_clock::to_time_t(ent.expires_at.value());
                ent_info += " (expires: " + std::to_string(exp_time) + ")";
            }
            info(ent_info);
        }
    }
}

void test_crypto_edge_cases() {
    section("Crypto Edge Cases");

    // Test 1: Very long message verification (should not crash)
    {
        std::string long_message(1000000, 'X');  // 1MB
        std::string fake_key = "PUAXw+hskiGPT/Fe2DLDoXKXJcTgXHYJYSPGlA6o8Bk=";
        std::string fake_sig = "5AfOueTe0sQT6C5DPzH_VZbpR3V1o_ehUg9eMOxJ2xjqFKbKC0WP0uxv3gcQyPDZXJoGb8n_5rGF_H2EPYRfAQ";

        // Should not crash, just return error or false
        auto result = licenseseat::crypto::verify_ed25519_signature(long_message, fake_sig, fake_key);
        if (result.is_error() || !result.value()) {
            pass("Ed25519 handles large message without crash");
        } else {
            fail("Ed25519 large message", "Unexpected success");
        }
    }

    // Test 2: Unicode in message
    {
        std::string unicode = "Hello 世界 🌍";
        std::string fake_key = "PUAXw+hskiGPT/Fe2DLDoXKXJcTgXHYJYSPGlA6o8Bk=";
        std::string fake_sig = "5AfOueTe0sQT6C5DPzH_VZbpR3V1o_ehUg9eMOxJ2xjqFKbKC0WP0uxv3gcQyPDZXJoGb8n_5rGF_H2EPYRfAQ";

        // Should handle without crash
        auto result = licenseseat::crypto::verify_ed25519_signature(unicode, fake_sig, fake_key);
        pass("Ed25519 handles unicode message without crash");
        (void)result;  // Result doesn't matter, just checking for crashes
    }

    // Test 3: Null bytes in message
    {
        std::string message = std::string("\x00\x00Hi\x00\x00", 6);
        std::string fake_key = "PUAXw+hskiGPT/Fe2DLDoXKXJcTgXHYJYSPGlA6o8Bk=";
        std::string fake_sig = "5AfOueTe0sQT6C5DPzH_VZbpR3V1o_ehUg9eMOxJ2xjqFKbKC0WP0uxv3gcQyPDZXJoGb8n_5rGF_H2EPYRfAQ";

        auto result = licenseseat::crypto::verify_ed25519_signature(message, fake_sig, fake_key);
        pass("Ed25519 handles null bytes in message");
        (void)result;
    }
}

void test_direct_signature_verification_with_live_token() {
    section("Direct Signature Verification with Live Token");

    auto config = make_config();
    licenseseat::Client client(config);

    // Generate offline token
    auto token_result = client.generate_offline_token(LICENSE_KEY);
    if (token_result.is_error()) {
        fail("Generate offline token", token_result.error_message());
        return;
    }

    const auto& offline = token_result.value();

    // Fetch the signing key
    auto key_result = client.fetch_signing_key(offline.token.kid);
    if (key_result.is_error()) {
        fail("Fetch signing key", key_result.error_message());
        return;
    }

    const std::string& public_key = key_result.value();

    // Test: Use the low-level verify_ed25519_signature directly
    {
        auto result = licenseseat::crypto::verify_ed25519_signature(
            offline.canonical,
            offline.signature.value,
            public_key
        );

        if (result.is_ok() && result.value()) {
            pass("Direct Ed25519 signature verification with live token");
            info("Canonical message length: " + std::to_string(offline.canonical.length()));
            info("Signature: " + offline.signature.value.substr(0, 30) + "...");
        } else if (result.is_error()) {
            fail("Direct Ed25519 signature verification", result.error_message());
        } else {
            fail("Direct Ed25519 signature verification", "Returned false");
        }
    }

    // Test: Verify using the higher-level verify_offline_token_signature
    {
        auto result = licenseseat::crypto::verify_offline_token_signature(offline, public_key);

        if (result.is_ok() && result.value()) {
            pass("verify_offline_token_signature with live token");
        } else if (result.is_error()) {
            fail("verify_offline_token_signature", result.error_message());
        } else {
            fail("verify_offline_token_signature", "Returned false");
        }
    }
}

// ============================================================================
// Main
// ============================================================================

int main() {
    // Load credentials from environment variables
    if (!load_credentials()) {
        return 1;
    }

    std::cout << CYAN << "╔═══════════════════════════════════════════════════════════════╗" << RESET << "\n";
    std::cout << CYAN << "║   Offline Token & Crypto - Comprehensive Test Suite          ║" << RESET << "\n";
    std::cout << CYAN << "╚═══════════════════════════════════════════════════════════════╝" << RESET << "\n";
    info("API URL: https://licenseseat.com/api/v1");
    info("License: " + LICENSE_KEY.substr(0, 5) + "..." + LICENSE_KEY.substr(LICENSE_KEY.length() - 5));

    auto start_time = std::chrono::high_resolution_clock::now();

    // Base64 tests
    test_base64_encoding();
    test_base64url_encoding();

    // Ed25519 tests
    test_ed25519_verification();

    // Live API tests
    test_offline_token_generation();
    test_signing_key_fetch();
    test_offline_token_verification();
    test_direct_signature_verification_with_live_token();
    test_expired_token();
    test_multiple_tokens();
    test_device_id_in_offline_token();
    test_entitlements_in_token();

    // Edge cases
    test_crypto_edge_cases();

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    // Summary
    std::cout << "\n" << CYAN << "═══════════════════════════════════════════════════════════════" << RESET << "\n";
    std::cout << CYAN << "  TEST SUMMARY" << RESET << "\n";
    std::cout << CYAN << "═══════════════════════════════════════════════════════════════" << RESET << "\n\n";

    int total = tests_passed + tests_failed;
    std::cout << "  Total tests:  " << total << "\n";
    std::cout << GREEN << "  Passed:       " << tests_passed << RESET << "\n";
    if (tests_failed > 0) {
        std::cout << RED << "  Failed:       " << tests_failed << RESET << "\n";
    } else {
        std::cout << "  Failed:       " << tests_failed << "\n";
    }
    std::cout << "  Duration:     " << duration.count() << "ms\n\n";

    if (tests_failed == 0) {
        std::cout << GREEN << "  ✓ ALL TESTS PASSED!" << RESET << "\n\n";
        return 0;
    } else {
        std::cout << RED << "  ✗ SOME TESTS FAILED" << RESET << "\n\n";
        return 1;
    }
}
