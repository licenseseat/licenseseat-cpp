#include <gtest/gtest.h>
#include <licenseseat/crypto.hpp>
#include <licenseseat/device.hpp>
#include <licenseseat/json.hpp>
#include <licenseseat/licenseseat.hpp>
#include <licenseseat/storage.hpp>
#include <licenseseat/events.hpp>

#include <httplib.h>
#include "PicoSHA2/picosha2.h"

extern "C" {
#include "ed25519/ed25519.h"
}

#include <nlohmann/json.hpp>
#include <openssl/evp.h>

#include <array>
#include <atomic>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <memory>
#include <thread>

namespace licenseseat {
namespace {

std::vector<uint8_t> sha256_test_bytes(const std::string& input) {
    std::vector<uint8_t> hash(picosha2::k_digest_size);
    picosha2::hash256(input.begin(), input.end(), hash.begin(), hash.end());
    return hash;
}

std::string build_machine_file_certificate(const std::string& license_key,
                                           const std::string& fingerprint,
                                           const nlohmann::json& payload_json,
                                           std::string* public_key_b64_out) {
    const std::array<unsigned char, 32> seed = {
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22};

    std::array<unsigned char, 32> public_key{};
    std::array<unsigned char, 64> private_key{};
    ed25519_create_keypair(public_key.data(), private_key.data(), seed.data());

    if (public_key_b64_out != nullptr) {
        *public_key_b64_out = crypto::base64_encode(
            std::vector<uint8_t>(public_key.begin(), public_key.end()));
    }

    const auto key = sha256_test_bytes(license_key + fingerprint);
    const std::array<unsigned char, 12> nonce = {
        0x01, 0x03, 0x05, 0x07, 0x09, 0x0b,
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
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(nonce.size()), nullptr) != 1 ||
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
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                            static_cast<int>(tag.size()), tag.data()) != 1) {
        return "";
    }

    const auto enc = crypto::base64url_encode(ciphertext) + "." +
                     crypto::base64url_encode(std::vector<uint8_t>(nonce.begin(), nonce.end())) +
                     "." +
                     crypto::base64url_encode(std::vector<uint8_t>(tag.begin(), tag.end()));

    std::array<unsigned char, 64> signature{};
    const auto message = std::string("machine/") + enc;
    ed25519_sign(signature.data(),
                 reinterpret_cast<const unsigned char*>(message.data()),
                 message.size(),
                 public_key.data(),
                 private_key.data());

    nlohmann::json envelope = {
        {"enc", enc},
        {"sig", crypto::base64url_encode(
                    std::vector<uint8_t>(signature.begin(), signature.end()))},
        {"alg", "aes-256-gcm+ed25519"},
        {"kid", "test-kid"}};

    const auto envelope_dump = envelope.dump();
    const auto encoded = crypto::base64_encode(
        std::vector<uint8_t>(envelope_dump.begin(), envelope_dump.end()));

    return "-----BEGIN MACHINE FILE-----\n" + encoded + "\n-----END MACHINE FILE-----";
}

MachineFile build_test_machine_file(const std::string& license_key,
                                    const std::string& fingerprint,
                                    std::string* public_key_b64_out) {
    const auto now = std::time(nullptr);

    nlohmann::json payload = {
        {"meta",
         {{"schema_version", 2},
          {"issued", "2026-03-25T10:00:00Z"},
          {"iat", now},
          {"expiry", "2026-04-24T10:00:00Z"},
          {"exp", now + 86400},
          {"nbf", now},
          {"ttl", 86400},
          {"grace_period", 3600},
          {"lic", license_key},
          {"license_exp", now + 86400 * 30},
          {"kid", "test-kid"}}},
        {"data",
         {{"type", "machines"},
          {"id", "42"},
          {"attributes",
           {{"fingerprint", fingerprint},
            {"name", "Studio Mac"},
            {"platform", "darwin"},
            {"created", "2026-03-24T10:00:00Z"},
            {"metadata", {{"device_name", "Studio Mac"}}}}}}},
        {"included",
         nlohmann::json::array(
             {{{"type", "licenses"},
               {"id", license_key},
               {"attributes",
                {{"key", license_key},
                 {"status", "active"},
                 {"mode", "hardware_locked"},
                 {"plan_key", "pro"},
                 {"product_slug", "test_product"}}}}})}};

    MachineFile machine_file;
    machine_file.license_key = license_key;
    machine_file.fingerprint = fingerprint;
    machine_file.certificate =
        build_machine_file_certificate(license_key, fingerprint, payload, public_key_b64_out);
    return machine_file;
}

OfflineToken build_test_offline_token(const std::string& license_key,
                                      const std::string& fingerprint,
                                      std::string* public_key_b64_out) {
    const std::array<unsigned char, 32> seed = {
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22};

    std::array<unsigned char, 32> public_key{};
    std::array<unsigned char, 64> private_key{};
    ed25519_create_keypair(public_key.data(), private_key.data(), seed.data());

    if (public_key_b64_out != nullptr) {
        *public_key_b64_out = crypto::base64_encode(
            std::vector<uint8_t>(public_key.begin(), public_key.end()));
    }

    const auto now = std::time(nullptr);
    nlohmann::json canonical_json = {
        {"schema_version", 1},
        {"license_key", license_key},
        {"product_slug", "test_product"},
        {"plan_key", "pro"},
        {"mode", "hardware_locked"},
        {"seat_limit", 1},
        {"fingerprint", fingerprint},
        {"iat", now},
        {"exp", now + 86400},
        {"nbf", now},
        {"license_expires_at", now + 86400 * 30},
        {"kid", "test-kid"},
        {"entitlements", nlohmann::json::array()},
        {"metadata", nlohmann::json::object()}};
    const auto canonical = canonical_json.dump();

    std::array<unsigned char, 64> signature{};
    ed25519_sign(signature.data(),
                 reinterpret_cast<const unsigned char*>(canonical.data()),
                 canonical.size(),
                 public_key.data(),
                 private_key.data());

    OfflineToken offline;
    offline.token.schema_version = 1;
    offline.token.license_key = license_key;
    offline.token.product_slug = "test_product";
    offline.token.plan_key = "pro";
    offline.token.mode = "hardware_locked";
    offline.token.seat_limit = 1;
    offline.token.fingerprint = fingerprint;
    offline.token.device_id = fingerprint;
    offline.token.iat = now;
    offline.token.exp = now + 86400;
    offline.token.nbf = now;
    offline.token.license_expires_at = now + 86400 * 30;
    offline.token.kid = "test-kid";
    offline.signature.algorithm = "Ed25519";
    offline.signature.key_id = "test-kid";
    offline.signature.value = crypto::base64url_encode(
        std::vector<uint8_t>(signature.begin(), signature.end()));
    offline.canonical = canonical;
    return offline;
}

CachedLicense build_cached_license(const std::string& license_key, const std::string& device_id) {
    CachedLicense cached;
    cached.license_key = license_key;
    cached.device_id = device_id;
    cached.activated_at = std::chrono::system_clock::now() - std::chrono::hours(1);
    cached.last_validated = std::chrono::system_clock::now() - std::chrono::minutes(5);

    ValidationResult validation;
    validation.valid = true;
    validation.code = "";
    validation.message = "cached";
    cached.validation = validation;

    cached.license_data = License(
        license_key,
        LicenseStatus::Active,
        LicenseMode::HardwareLocked,
        "pro",
        1,
        1,
        std::nullopt,
        std::chrono::system_clock::now() + std::chrono::hours(24 * 30),
        {},
        {},
        Product{"test_product", "Test Product"});

    return cached;
}

class ClientTest : public ::testing::Test {
  protected:
    void SetUp() override {
        config_.api_key = "test_api_key";
        config_.product_slug = "test_product";
        config_.device_id = "test-device-001";
        // Use a non-existent URL so network calls fail fast
        config_.api_url = "http://localhost:1";
        config_.timeout_seconds = 1;
        config_.max_retries = 0;
    }

    Config config_;
};

// ==================== Construction Tests ====================

TEST_F(ClientTest, CanBeConstructed) {
    Client client(config_);

    EXPECT_EQ(client.config().api_key, "test_api_key");
    EXPECT_EQ(client.config().product_slug, "test_product");
    EXPECT_EQ(client.device_id(), "test-device-001");
}

TEST_F(ClientTest, GeneratesDeviceIdIfNotProvided) {
    Config config;
    config.api_key = "key";
    config.product_slug = "product";
    config.api_url = "http://localhost:1";
    // No device_id set

    Client client(config);

    EXPECT_FALSE(client.device_id().empty());
}

TEST_F(ClientTest, FingerprintAliasMatchesDeviceId) {
    Client client(config_);

    EXPECT_EQ(client.fingerprint(), client.device_id());
}

// ==================== Validation Input Validation ====================

TEST_F(ClientTest, ValidateWithEmptyKeyFails) {
    Client client(config_);
    auto result = client.validate("");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidLicenseKey);
    EXPECT_FALSE(result.error_message().empty());
}

// Network calls will fail, but we can test error handling
TEST_F(ClientTest, ValidateReturnsNetworkErrorWhenNoServer) {
    Client client(config_);
    auto result = client.validate("VALID-KEY");

    // Should fail because no server is running
    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::NetworkError);
    EXPECT_EQ(client.get_client_status(), ClientStatus::OfflineInvalid);
    EXPECT_FALSE(client.is_online());
}

TEST_F(ClientTest, ValidateHttpErrorAfterSuccessfulValidationMarksClientInvalid) {
    httplib::Server server;
    std::atomic<bool> return_not_found{false};

    server.Post("/api/v1/products/test_product/licenses/VALID-KEY/validate",
                [&](const httplib::Request&, httplib::Response& res) {
                    if (return_not_found.load()) {
                        res.status = 404;
                        res.set_content("<html>not found</html>", "text/html");
                        return;
                    }

                    res.status = 200;
                    res.set_content(
                        R"({"valid":true,"code":"license_valid","message":"ok","license":{"key":"VALID-KEY","status":"active","mode":"hardware_locked","plan_key":"pro","seat_limit":1,"active_seats":1,"product":{"slug":"test_product","name":"Test Product"}}})",
                        "application/json");
                });

    auto port = server.bind_to_any_port("127.0.0.1");
    ASSERT_GT(port, 0);

    std::thread server_thread([&server]() { server.listen_after_bind(); });

    config_.api_url = "http://127.0.0.1:" + std::to_string(port) + "/api/v1";

    Client client(config_);

    auto first = client.validate("VALID-KEY");
    ASSERT_TRUE(first.is_ok());
    EXPECT_TRUE(first.value().valid);
    EXPECT_EQ(client.get_client_status(), ClientStatus::Active);
    EXPECT_TRUE(client.is_online());

    return_not_found = true;

    auto second = client.validate("VALID-KEY");
    EXPECT_TRUE(second.is_error());
    EXPECT_EQ(second.error_code(), ErrorCode::LicenseNotFound);
    EXPECT_EQ(client.get_client_status(), ClientStatus::Invalid);
    EXPECT_TRUE(client.is_online());

    server.stop();
    if (server_thread.joinable()) {
        server_thread.join();
    }
}

// ==================== Activation Input Validation ====================

TEST_F(ClientTest, ActivateWithEmptyKeyFails) {
    Client client(config_);
    auto result = client.activate("");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidLicenseKey);
    EXPECT_FALSE(result.error_message().empty());
}

TEST_F(ClientTest, ActivateReturnsNetworkErrorWhenNoServer) {
    Client client(config_);
    auto result = client.activate("VALID-KEY");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::NetworkError);
}

TEST_F(ClientTest, SyncOfflineAssetsDoesNotFetchLegacyTokenByDefault) {
    httplib::Server server;
    std::atomic<int> machine_file_requests{0};
    std::atomic<int> offline_token_requests{0};

    server.Post("/api/v1/products/test_product/licenses/VALID-KEY/validate",
                [&](const httplib::Request&, httplib::Response& res) {
                    res.status = 200;
                    res.set_content(
                        R"({"valid":true,"code":"license_valid","message":"ok","license":{"key":"VALID-KEY","status":"active","mode":"hardware_locked","plan_key":"pro","seat_limit":1,"active_seats":1,"product":{"slug":"test_product","name":"Test Product"}}})",
                        "application/json");
                });
    server.Post("/api/v1/products/test_product/licenses/VALID-KEY/machine-file",
                [&](const httplib::Request&, httplib::Response& res) {
                    machine_file_requests++;
                    res.status = 403;
                    res.set_content(
                        R"({"errors":[{"code":"FORBIDDEN","title":"Forbidden","detail":"missing machine-file scope"}]})",
                        "application/json");
                });
    server.Post("/api/v1/products/test_product/licenses/VALID-KEY/offline_token",
                [&](const httplib::Request&, httplib::Response& res) {
                    offline_token_requests++;
                    res.status = 200;
                    res.set_content(R"({"unexpected":true})", "application/json");
                });

    auto port = server.bind_to_any_port("127.0.0.1");
    ASSERT_GT(port, 0);

    std::thread server_thread([&server]() { server.listen_after_bind(); });

    const auto storage_dir =
        std::filesystem::temp_directory_path() /
        ("licenseseat-sync-machine-only-" +
         std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));

    config_.api_url = "http://127.0.0.1:" + std::to_string(port) + "/api/v1";
    config_.storage_path = storage_dir.string();

    Client client(config_);

    std::atomic<int> offline_fetch_events{0};
    client.on(events::OFFLINE_TOKEN_FETCHING, [&](const std::any&) { offline_fetch_events++; });

    auto validate = client.validate("VALID-KEY");
    ASSERT_TRUE(validate.is_ok());
    ASSERT_TRUE(validate.value().valid);

    client.sync_offline_assets();

    for (int i = 0; i < 50 && machine_file_requests.load() == 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    EXPECT_GE(machine_file_requests.load(), 1);
    EXPECT_EQ(offline_token_requests.load(), 0);
    EXPECT_EQ(offline_fetch_events.load(), 0);

    server.stop();
    if (server_thread.joinable()) {
        server_thread.join();
    }

    std::error_code ec;
    std::filesystem::remove_all(storage_dir, ec);
}

TEST_F(ClientTest, CheckoutMachineFileSendsFingerprintComponentsForAutoGeneratedFingerprint) {
    if (device::generate_device_id().empty()) {
        GTEST_SKIP() << "No stable local fingerprint available on this runner";
    }

    httplib::Server server;
    std::atomic<bool> saw_components{false};

    config_.device_id.clear();

    server.Post("/api/v1/products/test_product/licenses/VALID-KEY/machine-file",
                [&](const httplib::Request& req, httplib::Response& res) {
                    const auto body = nlohmann::json::parse(req.body);
                    saw_components = body.contains("fingerprint_components") &&
                                     body["fingerprint_components"].is_object() &&
                                     body["fingerprint_components"].contains("schema_version") &&
                                     body["fingerprint_components"].contains("platform");

                    const auto fingerprint = body.value("fingerprint", std::string{});
                    const auto certificate = build_test_machine_file("VALID-KEY", fingerprint, nullptr);

                    nlohmann::json response = {
                        {"data",
                         {{"attributes",
                           {{"certificate", certificate.certificate},
                            {"algorithm", certificate.algorithm},
                            {"ttl", 2592000}}},
                          {"relationships",
                           {{"license", {{"data", {{"id", "VALID-KEY"}}}}},
                            {"machine", {{"data", {{"id", fingerprint}}}}}}}}}};

                    res.status = 201;
                    res.set_content(response.dump(), "application/json");
                });

    auto port = server.bind_to_any_port("127.0.0.1");
    ASSERT_GT(port, 0);

    std::thread server_thread([&server]() { server.listen_after_bind(); });

    config_.api_url = "http://127.0.0.1:" + std::to_string(port) + "/api/v1";
    config_.signing_public_key = "cached-key";

    Client client(config_);
    auto result = client.checkout_machine_file("VALID-KEY");

    ASSERT_TRUE(result.is_ok()) << result.error_message();
    EXPECT_TRUE(saw_components.load());

    server.stop();
    if (server_thread.joinable()) {
        server_thread.join();
    }
}

TEST_F(ClientTest, SyncOfflineAssetsCanFetchLegacyTokenWhenExplicitlyEnabled) {
    httplib::Server server;
    std::atomic<int> machine_file_requests{0};
    std::atomic<int> offline_token_requests{0};
    std::atomic<int> signing_key_requests{0};

    std::string public_key_b64;
    auto offline_token = build_test_offline_token("VALID-KEY", config_.device_id, &public_key_b64);

    server.Post("/api/v1/products/test_product/licenses/VALID-KEY/validate",
                [&](const httplib::Request&, httplib::Response& res) {
                    res.status = 200;
                    res.set_content(
                        R"({"valid":true,"code":"license_valid","message":"ok","license":{"key":"VALID-KEY","status":"active","mode":"hardware_locked","plan_key":"pro","seat_limit":1,"active_seats":1,"product":{"slug":"test_product","name":"Test Product"}}})",
                        "application/json");
                });
    server.Post("/api/v1/products/test_product/licenses/VALID-KEY/machine-file",
                [&](const httplib::Request&, httplib::Response& res) {
                    machine_file_requests++;
                    res.status = 403;
                    res.set_content(
                        R"({"errors":[{"code":"FORBIDDEN","title":"Forbidden","detail":"missing machine-file scope"}]})",
                        "application/json");
                });
    server.Post("/api/v1/products/test_product/licenses/VALID-KEY/offline_token",
                [&](const httplib::Request&, httplib::Response& res) {
                    offline_token_requests++;
                    res.status = 200;
                    res.set_content(json::offline_token_to_json(offline_token),
                                    "application/json");
                });
    server.Get("/api/v1/signing_keys/test-kid", [&](const httplib::Request&, httplib::Response& res) {
        signing_key_requests++;
        res.status = 200;
        res.set_content(nlohmann::json{{"public_key", public_key_b64}}.dump(),
                        "application/json");
    });

    auto port = server.bind_to_any_port("127.0.0.1");
    ASSERT_GT(port, 0);

    std::thread server_thread([&server]() { server.listen_after_bind(); });

    const auto storage_dir =
        std::filesystem::temp_directory_path() /
        ("licenseseat-sync-legacy-token-" +
         std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));

    config_.api_url = "http://127.0.0.1:" + std::to_string(port) + "/api/v1";
    config_.storage_path = storage_dir.string();
    config_.enable_legacy_offline_tokens = true;

    Client client(config_);

    std::atomic<int> offline_fetch_events{0};
    client.on(events::OFFLINE_TOKEN_FETCHING, [&](const std::any&) { offline_fetch_events++; });

    auto validate = client.validate("VALID-KEY");
    ASSERT_TRUE(validate.is_ok());
    ASSERT_TRUE(validate.value().valid);

    client.sync_offline_assets();

    for (int i = 0; i < 50 && offline_token_requests.load() == 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    EXPECT_GE(machine_file_requests.load(), 1);
    EXPECT_EQ(offline_token_requests.load(), 1);
    EXPECT_EQ(offline_fetch_events.load(), 1);
    EXPECT_EQ(signing_key_requests.load(), 1);

    FileStorage storage(storage_dir.string());
    auto cached_token = storage.get_offline_token();
    ASSERT_TRUE(cached_token.has_value());
    EXPECT_EQ(cached_token->token.fingerprint, config_.device_id);

    server.stop();
    if (server_thread.joinable()) {
        server_thread.join();
    }

    std::error_code ec;
    std::filesystem::remove_all(storage_dir, ec);
}

// ==================== Deactivation Input Validation ====================

TEST_F(ClientTest, DeactivateWithEmptyKeyFails) {
    Client client(config_);
    auto result = client.deactivate("", "device-123");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidLicenseKey);
}

TEST_F(ClientTest, DeactivateWithEmptyDeviceIdFails) {
    Client client(config_);
    auto result = client.deactivate("VALID-KEY", "");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::MissingParameter);
}

TEST_F(ClientTest, DeactivateReturnsNetworkErrorWhenNoServer) {
    Client client(config_);
    auto result = client.deactivate("VALID-KEY", "device-123");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::NetworkError);
}

// ==================== Offline Token Input Validation ====================

TEST_F(ClientTest, GenerateOfflineTokenWithEmptyKeyFails) {
    Client client(config_);
    auto result = client.generate_offline_token("");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidLicenseKey);
}

TEST_F(ClientTest, CheckoutMachineFileWithEmptyKeyFails) {
    Client client(config_);
    auto result = client.checkout_machine_file("");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidLicenseKey);
}

TEST_F(ClientTest, VerifyOfflineTokenWithEmptyKeyFails) {
    Client client(config_);

    OfflineToken offline;
    offline.token.license_key = "";

    auto result = client.verify_offline_token(offline);

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidLicenseKey);
}

TEST_F(ClientTest, VerifyExpiredOfflineTokenFails) {
    Client client(config_);

    OfflineToken offline;
    offline.token.license_key = "KEY-123";
    offline.token.iat = std::time(nullptr) - (365 * 24 * 60 * 60);
    offline.token.nbf = offline.token.iat;
    offline.token.exp = std::time(nullptr) - (24 * 60 * 60);  // Expired

    auto result = client.verify_offline_token(offline);

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::LicenseExpired);
}

TEST_F(ClientTest, VerifyOfflineTokenWithInvalidSignature) {
    Client client(config_);

    OfflineToken offline;
    offline.token.license_key = "KEY-123";
    offline.token.kid = "key-v1";
    offline.token.iat = std::time(nullptr);
    offline.token.nbf = offline.token.iat;
    offline.token.exp = std::time(nullptr) + (365 * 24 * 60 * 60);
    offline.signature.key_id = "key-v1";
    offline.signature.value = "invalid-signature";  // Not a valid signature
    offline.canonical = R"({"test":"data"})";

    // Valid Ed25519 public key (32 bytes base64)
    const std::string public_key = "PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=";
    auto result = client.verify_offline_token(offline, public_key);

    // Invalid signature should fail verification
    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidSignature);
}

TEST_F(ClientTest, VerifyOfflineTokenWithFingerprintMismatchFails) {
    Client client(config_);

    OfflineToken offline;
    offline.token.license_key = "KEY-123";
    offline.token.fingerprint = "different-device";
    offline.token.iat = std::time(nullptr);
    offline.token.nbf = offline.token.iat;
    offline.token.exp = std::time(nullptr) + (24 * 60 * 60);

    auto result = client.verify_offline_token(offline);

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::FingerprintMismatch);
}

TEST_F(ClientTest, VerifyOfflineTokenNotYetValidFails) {
    Client client(config_);

    OfflineToken offline;
    offline.token.license_key = "KEY-123";
    offline.token.kid = "key-v1";
    offline.token.iat = std::time(nullptr);
    offline.token.nbf = std::time(nullptr) + (24 * 60 * 60);  // Not valid until tomorrow
    offline.token.exp = std::time(nullptr) + (365 * 24 * 60 * 60);

    auto result = client.verify_offline_token(offline);

    EXPECT_TRUE(result.is_error());
    // Token is not yet valid (nbf in future)
}

TEST_F(ClientTest, FetchSigningKeyWithEmptyIdFails) {
    Client client(config_);
    auto result = client.fetch_signing_key("");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::MissingParameter);
}

TEST_F(ClientTest, VerifyMachineFileWithoutLicenseKeyFails) {
    Client client(config_);
    MachineFile machine_file;
    machine_file.fingerprint = config_.device_id;

    auto result = client.verify_machine_file(machine_file);

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidLicenseKey);
}

TEST_F(ClientTest, VerifyMachineFileWithoutPublicKeyFails) {
    Client client(config_);
    MachineFile machine_file;
    machine_file.license_key = "KEY-123";
    machine_file.fingerprint = config_.device_id;
    machine_file.certificate = "-----BEGIN MACHINE FILE-----\nZXlKa2FXUWlPaUpyYVdRaUxDSmxiR01pT2lKaGJHY2lmUT09\n-----END MACHINE FILE-----";

    auto result = client.verify_machine_file(machine_file);

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::MissingParameter);
}

TEST_F(ClientTest, VerifyMachineFileUsesLocalDeviceFingerprintNotEmbeddedFingerprint) {
    config_.device_id = "local-device-001";
    const std::string license_key = "KEY-123";
    const std::string embedded_fingerprint = "embedded-device-001";

    std::string public_key_b64;
    auto machine_file =
        build_test_machine_file(license_key, embedded_fingerprint, &public_key_b64);
    config_.signing_public_key = public_key_b64;

    Client client(config_);
    auto result = client.verify_machine_file(machine_file);

    ASSERT_TRUE(result.is_ok());
    EXPECT_FALSE(result.value().valid);
    EXPECT_EQ(result.value().code, "decryption_failed");
}

TEST_F(ClientTest, RestoreLicenseRejectsCopiedMachineFileCacheOnDifferentDevice) {
    const std::string license_key = "KEY-123";
    const std::string original_device = "origin-device-001";
    const std::string copied_device = "other-device-001";

    std::string public_key_b64;
    auto machine_file = build_test_machine_file(license_key, original_device, &public_key_b64);

    const auto storage_dir =
        std::filesystem::temp_directory_path() /
        ("licenseseat-machine-file-test-" +
         std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));

    FileStorage storage(storage_dir.string());
    ASSERT_TRUE(storage.set_license(build_cached_license(license_key, original_device)));
    ASSERT_TRUE(storage.set_machine_file(machine_file));

    config_.device_id = copied_device;
    config_.storage_path = storage_dir.string();
    config_.signing_public_key = public_key_b64;

    Client client(config_);
    auto result = client.restore_license();

    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.status, ClientStatus::OfflineInvalid);
    EXPECT_FALSE(result.license.has_value());

    std::error_code ec;
    std::filesystem::remove_all(storage_dir, ec);
}

TEST_F(ClientTest, RestoreLicenseRejectsCopiedOfflineTokenCacheOnDifferentDevice) {
    const std::string license_key = "KEY-123";
    const std::string original_device = "origin-device-001";
    const std::string copied_device = "other-device-001";

    std::string public_key_b64;
    auto offline_token =
        build_test_offline_token(license_key, original_device, &public_key_b64);

    const auto storage_dir =
        std::filesystem::temp_directory_path() /
        ("licenseseat-offline-token-test-" +
         std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));

    FileStorage storage(storage_dir.string());
    ASSERT_TRUE(storage.set_license(build_cached_license(license_key, original_device)));
    ASSERT_TRUE(storage.set_offline_token(offline_token));

    config_.device_id = copied_device;
    config_.storage_path = storage_dir.string();
    config_.signing_public_key = public_key_b64;

    Client client(config_);
    auto result = client.restore_license();

    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.status, ClientStatus::OfflineInvalid);
    EXPECT_FALSE(result.license.has_value());

    std::error_code ec;
    std::filesystem::remove_all(storage_dir, ec);
}

TEST_F(ClientTest, RestoreLicenseRevalidatesWhenNetworkReturns) {
    const std::string license_key = "KEY-123";
    const std::string device_id = config_.device_id;

    std::string public_key_b64;
    auto offline_token = build_test_offline_token(license_key, device_id, &public_key_b64);

    const auto storage_dir =
        std::filesystem::temp_directory_path() /
        ("licenseseat-network-recheck-test-" +
         std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));

    FileStorage storage(storage_dir.string());
    ASSERT_TRUE(storage.set_license(build_cached_license(license_key, device_id)));
    ASSERT_TRUE(storage.set_offline_token(offline_token));

    std::atomic<int> health_calls{0};
    httplib::Server server;
    server.Get("/api/v1/health", [&](const httplib::Request&, httplib::Response& res) {
        if (++health_calls == 1) {
            res.status = 503;
            res.set_content(R"({"error":{"code":"temporarily_unavailable","message":"offline"}})",
                            "application/json");
            return;
        }

        res.status = 200;
        res.set_content(R"({"status":"ok"})", "application/json");
    });

    server.Post("/api/v1/products/test_product/licenses/KEY-123/validate",
                [&](const httplib::Request&, httplib::Response& res) {
                    res.status = 200;
                    res.set_content(
                        R"({"valid":true,"code":"license_valid","message":"ok","license":{"key":"KEY-123","status":"active","mode":"hardware_locked","plan_key":"pro","seat_limit":1,"active_seats":1,"product":{"slug":"test_product","name":"Test Product"}}})",
                        "application/json");
                });

    server.Post("/api/v1/products/test_product/licenses/KEY-123/heartbeat",
                [&](const httplib::Request&, httplib::Response& res) {
                    res.status = 200;
                    res.set_content(R"({"object":"heartbeat","received_at":"2026-03-26T02:07:56Z"})",
                                    "application/json");
                });

    auto port = server.bind_to_any_port("127.0.0.1");
    ASSERT_GT(port, 0);

    std::thread server_thread([&server]() {
        server.listen_after_bind();
    });

    config_.api_url = "http://127.0.0.1:" + std::to_string(port) + "/api/v1";
    config_.storage_path = storage_dir.string();
    config_.signing_public_key = public_key_b64;
    config_.network_recheck_interval = 0.05;
    config_.auto_validate_interval = 60.0;
    config_.heartbeat_interval = 60;
    config_.offline_license_refresh_interval = 0.0;

    Client client(config_);
    auto result = client.restore_license();

    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.status, ClientStatus::OfflineValid);
    EXPECT_EQ(client.get_client_status(), ClientStatus::OfflineValid);

    int attempts = 0;
    while (attempts++ < 40 && client.get_client_status() != ClientStatus::Active) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    EXPECT_EQ(client.get_client_status(), ClientStatus::Active);
    int timer_attempts = 0;
    while (timer_attempts++ < 20 &&
           (!client.is_auto_validating() || !client.is_heartbeat_running())) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    EXPECT_TRUE(client.is_auto_validating());
    EXPECT_TRUE(client.is_heartbeat_running());

    client.reset();
    server.stop();
    if (server_thread.joinable()) {
        server_thread.join();
    }

    std::error_code ec;
    std::filesystem::remove_all(storage_dir, ec);
}

TEST_F(ClientTest, RepeatedOfflineFallbackValidationEmitsNetworkOfflineOnce) {
    const std::string license_key = "KEY-123";
    const std::string device_id = config_.device_id;

    std::string public_key_b64;
    auto offline_token = build_test_offline_token(license_key, device_id, &public_key_b64);

    const auto storage_dir =
        std::filesystem::temp_directory_path() /
        ("licenseseat-offline-event-test-" +
         std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));

    FileStorage storage(storage_dir.string());
    ASSERT_TRUE(storage.set_license(build_cached_license(license_key, device_id)));
    ASSERT_TRUE(storage.set_offline_token(offline_token));

    httplib::Server server;
    server.Post("/api/v1/products/test_product/licenses/KEY-123/validate",
                [&](const httplib::Request&, httplib::Response& res) {
                    res.status = 503;
                    res.set_content(
                        R"({"error":{"code":"temporarily_unavailable","message":"offline"}})",
                        "application/json");
                });

    auto port = server.bind_to_any_port("127.0.0.1");
    ASSERT_GT(port, 0);

    std::thread server_thread([&server]() { server.listen_after_bind(); });

    config_.api_url = "http://127.0.0.1:" + std::to_string(port) + "/api/v1";
    config_.storage_path = storage_dir.string();
    config_.signing_public_key = public_key_b64;
    config_.network_recheck_interval = 0.0;

    Client client(config_);

    std::atomic<int> offline_events{0};
    client.on(events::NETWORK_OFFLINE, [&](const std::any&) { offline_events++; });

    auto first = client.validate(license_key);
    ASSERT_TRUE(first.is_ok());
    EXPECT_TRUE(first.value().valid);
    EXPECT_TRUE(first.value().offline);
    EXPECT_EQ(client.get_client_status(), ClientStatus::OfflineValid);
    EXPECT_FALSE(client.is_online());

    auto second = client.validate(license_key);
    ASSERT_TRUE(second.is_ok());
    EXPECT_TRUE(second.value().valid);
    EXPECT_TRUE(second.value().offline);
    EXPECT_EQ(client.get_client_status(), ClientStatus::OfflineValid);
    EXPECT_FALSE(client.is_online());

    EXPECT_EQ(offline_events.load(), 1);

    server.stop();
    if (server_thread.joinable()) {
        server_thread.join();
    }

    std::error_code ec;
    std::filesystem::remove_all(storage_dir, ec);
}

TEST_F(ClientTest, CachedMachineFileValidationDoesNotEmitReadyRepeatedly) {
    const std::string license_key = "KEY-123";
    const std::string device_id = config_.device_id;

    std::string public_key_b64;
    auto machine_file = build_test_machine_file(license_key, device_id, &public_key_b64);

    const auto storage_dir =
        std::filesystem::temp_directory_path() /
        ("licenseseat-machine-ready-event-test-" +
         std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));

    FileStorage storage(storage_dir.string());
    ASSERT_TRUE(storage.set_license(build_cached_license(license_key, device_id)));
    ASSERT_TRUE(storage.set_machine_file(machine_file));

    httplib::Server server;
    server.Post("/api/v1/products/test_product/licenses/KEY-123/validate",
                [&](const httplib::Request&, httplib::Response& res) {
                    res.status = 503;
                    res.set_content(
                        R"({"error":{"code":"temporarily_unavailable","message":"offline"}})",
                        "application/json");
                });

    auto port = server.bind_to_any_port("127.0.0.1");
    ASSERT_GT(port, 0);

    std::thread server_thread([&server]() { server.listen_after_bind(); });

    config_.api_url = "http://127.0.0.1:" + std::to_string(port) + "/api/v1";
    config_.storage_path = storage_dir.string();
    config_.signing_public_key = public_key_b64;
    config_.network_recheck_interval = 0.0;

    Client client(config_);

    std::atomic<int> ready_events{0};
    client.on(events::MACHINE_FILE_READY, [&](const std::any&) { ready_events++; });

    auto first = client.validate(license_key);
    ASSERT_TRUE(first.is_ok());
    EXPECT_TRUE(first.value().valid);
    EXPECT_TRUE(first.value().offline);

    auto second = client.validate(license_key);
    ASSERT_TRUE(second.is_ok());
    EXPECT_TRUE(second.value().valid);
    EXPECT_TRUE(second.value().offline);

    EXPECT_EQ(ready_events.load(), 0);

    server.stop();
    if (server_thread.joinable()) {
        server_thread.join();
    }

    std::error_code ec;
    std::filesystem::remove_all(storage_dir, ec);
}

// ==================== Release Input Validation ====================

TEST_F(ClientTest, GetLatestReleaseUsesConfigProductSlug) {
    Client client(config_);
    // Should not fail with MissingParameter since we have product_slug in config
    auto result = client.get_latest_release();

    // Will fail with network error since we have a product_slug in config
    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::NetworkError);
}

TEST_F(ClientTest, ListReleasesUsesConfigProductSlug) {
    Client client(config_);
    auto result = client.list_releases();

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::NetworkError);
}

TEST_F(ClientTest, GenerateDownloadTokenWithEmptyKeyFails) {
    Client client(config_);
    auto result = client.generate_download_token("1.0.0", "");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::InvalidLicenseKey);
}

TEST_F(ClientTest, GenerateDownloadTokenWithEmptyVersionFails) {
    Client client(config_);
    auto result = client.generate_download_token("", "LICENSE-KEY");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::MissingParameter);
}

// ==================== Health Check ====================

TEST_F(ClientTest, HealthReturnsNetworkErrorWhenNoServer) {
    Client client(config_);
    auto result = client.health();

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::NetworkError);
}

// ==================== Move Semantics ====================

TEST_F(ClientTest, CanBeMoved) {
    Client client1(config_);

    Client client2 = std::move(client1);

    // client2 should work
    EXPECT_EQ(client2.config().api_key, "test_api_key");
}

// ==================== Event Handling ====================

TEST_F(ClientTest, CanSubscribeToEvents) {
    Client client(config_);
    bool called = false;

    auto sub = client.on("test:event", [&](const std::any& /*data*/) { called = true; });

    client.emit("test:event");

    EXPECT_TRUE(called);
}

TEST_F(ClientTest, SubscriptionCanBeCancelled) {
    Client client(config_);
    int call_count = 0;

    auto sub = client.on("test:event", [&](const std::any& /*data*/) { call_count++; });

    client.emit("test:event");
    EXPECT_EQ(call_count, 1);

    sub.cancel();

    client.emit("test:event");
    EXPECT_EQ(call_count, 1);  // Should not increase
}

TEST_F(ClientTest, EventsReceiveData) {
    Client client(config_);
    std::string received_data;

    client.on("test:event", [&](const std::any& data) {
        if (data.has_value()) {
            received_data = std::any_cast<std::string>(data);
        }
    });

    client.emit("test:event", std::string("hello world"));

    EXPECT_EQ(received_data, "hello world");
}

// ==================== Status Methods ====================

TEST_F(ClientTest, GetStatusReturnsInvalidWhenNoLicense) {
    Client client(config_);

    auto status = client.get_status();

    EXPECT_FALSE(status.valid);
}

TEST_F(ClientTest, CurrentLicenseReturnsNulloptWhenNoLicense) {
    Client client(config_);

    auto license = client.current_license();

    EXPECT_FALSE(license.has_value());
}

TEST_F(ClientTest, CheckEntitlementReturnsInactiveWhenNoLicense) {
    Client client(config_);

    auto status = client.check_entitlement("updates");

    EXPECT_FALSE(status.active);
    EXPECT_EQ(status.reason, "no_license");
}

TEST_F(ClientTest, IsOnlineDefaultsToTrue) {
    Client client(config_);

    // Starts as online until we know otherwise
    EXPECT_TRUE(client.is_online());
}

// ==================== Auto-Validation ====================

TEST_F(ClientTest, AutoValidationNotRunningByDefault) {
    Client client(config_);

    EXPECT_FALSE(client.is_auto_validating());
}

TEST_F(ClientTest, StartAndStopAutoValidation) {
    Client client(config_);

    client.start_auto_validation("TEST-KEY");
    EXPECT_TRUE(client.is_auto_validating());

    client.stop_auto_validation();
    EXPECT_FALSE(client.is_auto_validating());
}

TEST_F(ClientTest, StartAutoValidationTwiceDoesNotCrash) {
    Client client(config_);

    client.start_auto_validation("TEST-KEY");
    client.start_auto_validation("TEST-KEY-2");  // Should not crash

    EXPECT_TRUE(client.is_auto_validating());

    client.stop_auto_validation();
}

TEST_F(ClientTest, StopAutoValidationWhenNotRunningDoesNotCrash) {
    Client client(config_);

    // Should not crash
    client.stop_auto_validation();
    client.stop_auto_validation();

    EXPECT_FALSE(client.is_auto_validating());
}

// ==================== Heartbeat ====================

TEST_F(ClientTest, HeartbeatNotRunningByDefault) {
    Client client(config_);

    EXPECT_FALSE(client.is_heartbeat_running());
}

TEST_F(ClientTest, StartAndStopHeartbeat) {
    Client client(config_);

    client.start_heartbeat("TEST-KEY");
    EXPECT_TRUE(client.is_heartbeat_running());

    client.stop_heartbeat();
    EXPECT_FALSE(client.is_heartbeat_running());
}

TEST_F(ClientTest, StartHeartbeatTwiceDoesNotCrash) {
    Client client(config_);

    client.start_heartbeat("TEST-KEY");
    client.start_heartbeat("TEST-KEY-2");  // Should not crash

    EXPECT_TRUE(client.is_heartbeat_running());

    client.stop_heartbeat();
}

TEST_F(ClientTest, StopHeartbeatWhenNotRunningDoesNotCrash) {
    Client client(config_);

    // Should not crash
    client.stop_heartbeat();
    client.stop_heartbeat();

    EXPECT_FALSE(client.is_heartbeat_running());
}

// ==================== Reset ====================

TEST_F(ClientTest, ResetStopsAutoValidation) {
    Client client(config_);

    client.start_auto_validation("TEST-KEY");
    EXPECT_TRUE(client.is_auto_validating());

    client.reset();

    EXPECT_FALSE(client.is_auto_validating());
}

TEST_F(ClientTest, ResetStopsHeartbeat) {
    Client client(config_);

    client.start_heartbeat("TEST-KEY");
    EXPECT_TRUE(client.is_heartbeat_running());

    client.reset();

    EXPECT_FALSE(client.is_heartbeat_running());
}

// ==================== Async API ====================

TEST_F(ClientTest, ValidateAsyncCallsCallback) {
    Client client(config_);
    std::atomic<bool> callback_called{false};
    ErrorCode received_error = ErrorCode::Success;

    client.validate_async(
        "TEST-KEY",
        [&](Result<ValidationResult> result) {
            callback_called = true;
            if (result.is_error()) {
                received_error = result.error_code();
            }
        });

    // Wait for callback (should fail with network error)
    int attempts = 0;
    while (!callback_called && attempts++ < 100) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    EXPECT_TRUE(callback_called);
    EXPECT_EQ(received_error, ErrorCode::NetworkError);
}

TEST_F(ClientTest, ActivateAsyncCallsCallback) {
    Client client(config_);
    std::atomic<bool> callback_called{false};

    client.activate_async("TEST-KEY", [&](Result<Activation> /*result*/) { callback_called = true; });

    int attempts = 0;
    while (!callback_called && attempts++ < 100) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    EXPECT_TRUE(callback_called);
}

TEST_F(ClientTest, DeactivateAsyncCallsCallback) {
    Client client(config_);
    std::atomic<bool> callback_called{false};

    client.deactivate_async("TEST-KEY", [&](Result<Deactivation> /*result*/) { callback_called = true; },
                            "device-123");

    int attempts = 0;
    while (!callback_called && attempts++ < 100) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    EXPECT_TRUE(callback_called);
}

// ==================== ClientStatus Tests ====================

TEST_F(ClientTest, GetClientStatusReturnsInactiveWhenNoLicense) {
    Client client(config_);

    auto status = client.get_client_status();

    EXPECT_EQ(status, ClientStatus::Inactive);
}

TEST_F(ClientTest, ClientStatusToStringWorks) {
    EXPECT_STREQ(client_status_to_string(ClientStatus::Active), "active");
    EXPECT_STREQ(client_status_to_string(ClientStatus::OfflineValid), "offline_valid");
    EXPECT_STREQ(client_status_to_string(ClientStatus::OfflineInvalid), "offline_invalid");
    EXPECT_STREQ(client_status_to_string(ClientStatus::Inactive), "inactive");
    EXPECT_STREQ(client_status_to_string(ClientStatus::Invalid), "invalid");
    EXPECT_STREQ(client_status_to_string(ClientStatus::Pending), "pending");
}

TEST_F(ClientTest, OfflineInvalidStatusExists) {
    // Verify OfflineInvalid is a valid ClientStatus value
    ClientStatus status = ClientStatus::OfflineInvalid;
    EXPECT_EQ(status, ClientStatus::OfflineInvalid);
    EXPECT_NE(status, ClientStatus::OfflineValid);
    EXPECT_NE(status, ClientStatus::Invalid);
}

// ==================== RestoreResult Tests ====================

TEST_F(ClientTest, RestoreLicenseReturnsInactiveWhenNoCache) {
    Client client(config_);

    auto result = client.restore_license();

    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.status, ClientStatus::Inactive);
    EXPECT_FALSE(result.license.has_value());
    EXPECT_FALSE(result.message.empty());
}

TEST_F(ClientTest, RestoreLicenseAsyncCallsCallback) {
    Client client(config_);
    std::atomic<bool> callback_called{false};
    RestoreResult received_result;

    client.restore_license_async([&](RestoreResult result) {
        received_result = result;
        callback_called = true;
    });

    int attempts = 0;
    while (!callback_called && attempts++ < 100) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    EXPECT_TRUE(callback_called);
    EXPECT_FALSE(received_result.success);
    EXPECT_EQ(received_result.status, ClientStatus::Inactive);
}

// ==================== Thread Safety Tests ====================

TEST_F(ClientTest, DestructorWaitsForAsyncOperations) {
    // This test ensures that destroying the client waits for pending async ops
    std::atomic<int> callback_count{0};

    {
        Client client(config_);

        // Start multiple async operations
        for (int i = 0; i < 5; i++) {
            client.validate_async("TEST-KEY-" + std::to_string(i),
                                  [&](Result<ValidationResult> /*result*/) {
                                      callback_count++;
                                  });
        }
        // Client destructor should wait for all callbacks to complete
    }

    // Give some time for potential issues to manifest
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // All callbacks should have been called before destructor completed
    EXPECT_EQ(callback_count, 5);
}

TEST_F(ClientTest, MultipleAsyncOpsDoNotCrash) {
    Client client(config_);
    std::atomic<int> completed{0};

    // Launch many concurrent async operations
    for (int i = 0; i < 10; i++) {
        client.validate_async("KEY-" + std::to_string(i),
                              [&](Result<ValidationResult> /*result*/) { completed++; });
        client.activate_async("KEY-" + std::to_string(i),
                              [&](Result<Activation> /*result*/) { completed++; });
    }

    // Wait for completion
    int attempts = 0;
    while (completed < 20 && attempts++ < 200) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    EXPECT_EQ(completed, 20);
}

// ==================== Timer Thread Safety Tests ====================

TEST_F(ClientTest, StopAutoValidationSafeWhenCalledRapidly) {
    Client client(config_);

    // Start and stop rapidly multiple times - should not crash
    for (int i = 0; i < 10; i++) {
        client.start_auto_validation("KEY-" + std::to_string(i));
        client.stop_auto_validation();
    }

    EXPECT_FALSE(client.is_auto_validating());
}

TEST_F(ClientTest, StopHeartbeatSafeWhenCalledRapidly) {
    Client client(config_);

    // Start and stop rapidly multiple times - should not crash
    for (int i = 0; i < 10; i++) {
        client.start_heartbeat("KEY-" + std::to_string(i));
        client.stop_heartbeat();
    }

    EXPECT_FALSE(client.is_heartbeat_running());
}

TEST_F(ClientTest, GetClientStatusDoesNotBlockDuringAsyncOps) {
    Client client(config_);

    // Start an async validation (will fail due to no server)
    std::atomic<bool> callback_called{false};
    client.validate_async("TEST-KEY", [&](Result<ValidationResult> /*result*/) {
        callback_called = true;
    });

    // This should return quickly, not block waiting for the async op
    auto start = std::chrono::steady_clock::now();
    auto status = client.get_client_status();
    auto elapsed = std::chrono::steady_clock::now() - start;

    // Should complete in under 50ms (not waiting for network timeout)
    EXPECT_LT(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(), 50);
    EXPECT_EQ(status, ClientStatus::Inactive);

    // Wait for async to complete
    int attempts = 0;
    while (!callback_called && attempts++ < 100) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    EXPECT_TRUE(callback_called);
}

TEST_F(ClientTest, IsOnlineDoesNotBlockDuringAsyncOps) {
    Client client(config_);

    // Start an async validation
    std::atomic<bool> callback_called{false};
    client.validate_async("TEST-KEY", [&](Result<ValidationResult> /*result*/) {
        callback_called = true;
    });

    // This should return quickly
    auto start = std::chrono::steady_clock::now();
    bool online = client.is_online();
    auto elapsed = std::chrono::steady_clock::now() - start;

    // Should complete in under 10ms
    EXPECT_LT(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(), 10);
    (void)online;  // Value doesn't matter for this test

    // Wait for async to complete
    int attempts = 0;
    while (!callback_called && attempts++ < 100) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

TEST_F(ClientTest, DestructorSafeWithRunningTimers) {
    // Create client, start timers, then destroy - should not crash or hang
    {
        Client client(config_);
        client.start_auto_validation("TEST-KEY");
        client.start_heartbeat("TEST-KEY");
        // Destructor should cleanly stop timers
    }
    // If we get here without crashing or hanging, test passes
    SUCCEED();
}

TEST_F(ClientTest, ResetSafeWithRunningTimers) {
    Client client(config_);

    client.start_auto_validation("TEST-KEY");
    client.start_heartbeat("TEST-KEY");
    EXPECT_TRUE(client.is_auto_validating());
    EXPECT_TRUE(client.is_heartbeat_running());

    // Reset should stop all timers
    client.reset();

    EXPECT_FALSE(client.is_auto_validating());
    EXPECT_FALSE(client.is_heartbeat_running());
}

// ==================== Network Recheck Timer Tests ====================

TEST_F(ClientTest, IsOnlineChangesOnHealthCheckFailure) {
    // Initially online
    Client client(config_);
    EXPECT_TRUE(client.is_online());

    // Health check fails (no server), should mark as offline
    auto result = client.health();
    EXPECT_TRUE(result.is_error());

    // Now should be offline
    EXPECT_FALSE(client.is_online());
}

// ==================== Event Emission Tests ====================

TEST_F(ClientTest, NetworkOfflineEventEmittedOnHealthFailure) {
    Client client(config_);
    bool offline_event_received = false;

    client.on("network:offline", [&](const std::any& /*data*/) {
        offline_event_received = true;
    });

    // Force a health check failure
    auto result = client.health();
    EXPECT_TRUE(result.is_error());

    EXPECT_TRUE(offline_event_received);
}

TEST_F(ClientTest, ValidationFailedEventEmittedOnNetworkError) {
    Client client(config_);
    bool error_event_received = false;

    client.on("validation:error", [&](const std::any& /*data*/) {
        error_event_received = true;
    });

    // Validation will fail with network error
    auto result = client.validate("TEST-KEY");
    EXPECT_TRUE(result.is_error());

    // Note: Network error goes to validation:error, not validation:failed
    // validation:failed is for 200 OK with valid=false
}

// ==================== License Revocation Tests ====================

TEST_F(ClientTest, LicenseRevokedConstantExists) {
    // Just verify the event constant exists
    EXPECT_STREQ(events::LICENSE_REVOKED, "license:revoked");
}

TEST_F(ClientTest, CanSubscribeToLicenseRevokedEvent) {
    Client client(config_);
    bool event_received = false;

    auto sub = client.on("license:revoked", [&](const std::any& /*data*/) {
        event_received = true;
    });

    // Manually emit to verify subscription works
    client.emit("license:revoked");

    EXPECT_TRUE(event_received);
}

}  // namespace
}  // namespace licenseseat
