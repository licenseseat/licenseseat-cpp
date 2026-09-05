#include "PicoSHA2/picosha2.h"
#include "test_signing.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <ctime>
#include <filesystem>
#include <future>
#include <gtest/gtest.h>
#include <httplib.h>
#include <licenseseat/crypto.hpp>
#include <licenseseat/device.hpp>
#include <licenseseat/events.hpp>
#include <licenseseat/json.hpp>
#include <licenseseat/licenseseat.hpp>
#include <licenseseat/storage.hpp>
#include <limits>
#include <memory>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <thread>

namespace licenseseat {
namespace {

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

    const auto enc = crypto::base64url_encode(ciphertext) + "." +
                     crypto::base64url_encode(std::vector<uint8_t>(nonce.begin(), nonce.end())) +
                     "." + crypto::base64url_encode(std::vector<uint8_t>(tag.begin(), tag.end()));

    std::array<unsigned char, 64> signature{};
    const auto message = std::string("machine/") + enc;
    if (!test_signing::sign_ed25519(seed, message, public_key, signature))
        return "";
    if (public_key_b64_out != nullptr) {
        *public_key_b64_out =
            crypto::base64_encode(std::vector<uint8_t>(public_key.begin(), public_key.end()));
    }

    nlohmann::json envelope = {
        {"enc", enc},
        {"sig", crypto::base64url_encode(std::vector<uint8_t>(signature.begin(), signature.end()))},
        {"alg", "aes-256-gcm+ed25519"},
        {"kid", "test-kid"}};

    const auto envelope_dump = envelope.dump();
    const auto encoded =
        crypto::base64_encode(std::vector<uint8_t>(envelope_dump.begin(), envelope_dump.end()));

    return wrap_machine_file_certificate(encoded);
}

MachineFile build_test_machine_file(const std::string& license_key, const std::string& fingerprint,
                                    std::string* public_key_b64_out) {
    const auto now = std::time(nullptr);
    const auto license_expiry = now + 86400 * 30;

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
            {"product", {{"data", {{"type", "products"}, {"id", "test_product"}}}}}}}}},
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
    const std::array<unsigned char, 32> seed = {0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
                                                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                                0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12,
                                                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22};

    std::array<unsigned char, 32> public_key{};

    const auto now = std::time(nullptr);
    nlohmann::json canonical_json = {{"schema_version", 1},
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
    if (!test_signing::sign_ed25519(seed, canonical, public_key, signature))
        return {};
    if (public_key_b64_out != nullptr) {
        *public_key_b64_out =
            crypto::base64_encode(std::vector<uint8_t>(public_key.begin(), public_key.end()));
    }

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
    offline.signature.value =
        crypto::base64url_encode(std::vector<uint8_t>(signature.begin(), signature.end()));
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

    cached.license_data =
        License(license_key, LicenseStatus::Active, LicenseMode::HardwareLocked, "pro", 1, 1,
                std::nullopt, std::chrono::system_clock::now() + std::chrono::hours(24 * 30), {},
                {}, Product{"test_product", "Test Product"});

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
        config_.allow_insecure_http = true;
        config_.timeout_seconds = 1;
        config_.max_retries = 0;
        // Tests that exercise offline behavior opt in explicitly. Production
        // defaults remain fail-closed.
        config_.offline_fallback_mode = OfflineFallbackMode::NetworkOnly;
        config_.max_offline_days = 30;
    }

    Config config_;
};

// Customer-workflow review: loopback only, real signed/encrypted machine files.
class CustomerWorkflowReview : public ClientTest {
  protected:
    void SetUp() override {
        ClientTest::SetUp();
        path_ = std::filesystem::temp_directory_path() /
                ("ls-customer-review-" + std::to_string(
                    std::chrono::steady_clock::now().time_since_epoch().count()));
        config_.storage_path = path_.string();
        config_.network_recheck_interval = 3600;
        machine_ = build_test_machine_file("KEY-123", config_.device_id, &public_key_);
        server_.Post("/api/v1/products/test_product/licenses/activate",
                     [&](const httplib::Request&, httplib::Response& res) {
            nlohmann::json j = {{"object", "activation"}, {"id", id_},
                {"license_key", "KEY-123"}, {"fingerprint", config_.device_id},
                {"activated_at", "2026-09-01T12:00:00Z"}};
            res.status = 201;
            res.set_content(j.dump(), "application/json");
        });
        server_.Post("/api/v1/products/test_product/licenses/deactivate",
                     [&](const httplib::Request&, httplib::Response& res) {
            nlohmann::json j = {{"object", "deactivation"}, {"activation_id", id_},
                {"deactivated_at", "2026-09-05T12:00:00Z"}};
            res.set_content(j.dump(), "application/json");
        });
        server_.Get("/api/v1/signing_keys/test-kid",
                    [&](const httplib::Request&, httplib::Response& res) {
            nlohmann::json j = {{"object", "signing_key"}, {"key_id", "test-kid"},
                {"algorithm", "Ed25519"}, {"status", "active"}, {"public_key", public_key_}};
            res.set_content(j.dump(), "application/json");
        });
        server_.Post("/api/v1/products/test_product/licenses/validate",
                     [&](const httplib::Request&, httplib::Response& res) {
            nlohmann::json j = {{"object", "validation_result"}, {"valid", true},
                {"license", {{"object", "license"}, {"key", "KEY-123"},
                    {"status", "active"}, {"mode", "hardware_locked"}, {"plan_key", "pro"},
                    {"seat_limit", 1}, {"active_seats", 1},
                    {"product", {{"slug", "test_product"}, {"name", "Test Product"}}}}},
                {"activation", {{"object", "activation"}, {"id", id_},
                    {"license_key", "KEY-123"}, {"fingerprint", config_.device_id},
                    {"activated_at", "2026-09-01T12:00:00Z"}}}};
            res.set_content(j.dump(), "application/json");
        });
        server_.Post("/api/v1/products/test_product/licenses/machine-file",
                     [&](const httplib::Request&, httplib::Response& res) {
            ++checkouts_;
            const auto now = std::chrono::system_clock::now();
            nlohmann::json j = {{"data", {{"type", "machine-files"},
                {"attributes", {{"certificate", machine_.certificate},
                    {"algorithm", "aes-256-gcm+ed25519"}, {"ttl", 86400},
                    {"issued", json::format_timestamp(now)},
                    {"expiry", json::format_timestamp(now + std::chrono::hours(24))}}},
                {"relationships", {
                    {"license", {{"data", {{"type", "licenses"}, {"id", "KEY-123"}}}}},
                    {"machine", {{"data", {{"type", "machines"}, {"id", config_.device_id}}}}}
                }}}}};
            res.status = 201;
            res.set_content(j.dump(), "application/json");
        });
        const auto port = server_.bind_to_any_port("127.0.0.1");
        ASSERT_GT(port, 0);
        config_.api_url = "http://127.0.0.1:" + std::to_string(port) + "/api/v1";
        thread_ = std::thread([this] { server_.listen_after_bind(); });
    }
    void TearDown() override {
        server_.stop();
        if (thread_.joinable()) thread_.join();
        // Keep the task-specific temp cache as review evidence.
    }
    httplib::Server server_;
    std::thread thread_;
    std::filesystem::path path_;
    MachineFile machine_;
    std::string public_key_;
    nlohmann::json id_ = "9d063849-d144-49a5-bf91-2af06e700421";
    std::atomic<int> checkouts_{0};
};

TEST_F(CustomerWorkflowReview, UuidActivateVerifyAndDeactivateClearArtifacts) {
    config_.signing_public_key = public_key_;
    Client client(config_);
    auto activated = client.activate("KEY-123");
    ASSERT_TRUE(activated.is_ok()) << activated.error_message();
    EXPECT_EQ(activated.value().id(), id_.get<std::string>());
    FileStorage storage(path_.string());
    ASSERT_TRUE(storage.get_machine_file().has_value());
    ASSERT_TRUE(storage.set_license(build_cached_license("KEY-123", config_.device_id)));
    auto verified = client.verify_machine_file(*storage.get_machine_file());
    ASSERT_TRUE(verified.is_ok());
    EXPECT_TRUE(verified.value().valid);
    auto deactivated = client.deactivate("KEY-123", config_.device_id);
    ASSERT_TRUE(deactivated.is_ok()) << deactivated.error_message();
    EXPECT_EQ(deactivated.value().activation_id, activated.value().id());
    EXPECT_FALSE(storage.get_license().has_value());
    EXPECT_FALSE(storage.get_machine_file().has_value());
}

TEST_F(CustomerWorkflowReview, ReadmeAutomaticDefaultsShouldCacheMachineFile) {
    config_.offline_fallback_mode = Config{}.offline_fallback_mode;
    config_.max_offline_days = Config{}.max_offline_days;
    Client client(config_);
    ASSERT_TRUE(client.activate("KEY-123").is_ok());
    EXPECT_GT(checkouts_.load(), 0);
    EXPECT_TRUE(FileStorage(path_.string()).get_machine_file().has_value());
}

TEST_F(CustomerWorkflowReview, ActivateWithPinAndOfflinePolicyShouldRestoreAfterRestart) {
    config_.signing_public_key = public_key_;
    {
        Client client(config_);
        ASSERT_TRUE(client.activate("KEY-123").is_ok());
        ASSERT_TRUE(FileStorage(path_.string()).get_machine_file().has_value());
    }
    server_.stop();
    Client restarted(config_);
    auto result = restarted.restore_license();
    EXPECT_TRUE(result.success) << result.message;
    EXPECT_EQ(result.status, ClientStatus::OfflineValid);
}

TEST_F(CustomerWorkflowReview, WarmFetchedKeyShouldSurviveRestartForAutomaticWorkflow) {
    {
        Client client(config_);
        ASSERT_TRUE(client.activate("KEY-123").is_ok());
        ASSERT_TRUE(FileStorage(path_.string()).set_license(
            build_cached_license("KEY-123", config_.device_id)));
        auto verified = client.verify_machine_file(machine_);
        ASSERT_TRUE(verified.is_ok());
        ASSERT_TRUE(verified.value().valid);
    }
    server_.stop();
    Client restarted(config_);
    auto result = restarted.restore_license();
    EXPECT_TRUE(result.success) << result.message;
    EXPECT_EQ(result.status, ClientStatus::OfflineValid);
}

TEST_F(CustomerWorkflowReview, PinnedKeyWithCompleteCacheRestoresOffline) {
    config_.signing_public_key = public_key_;
    {
        Client client(config_);
        ASSERT_TRUE(client.activate("KEY-123").is_ok());
        ASSERT_TRUE(FileStorage(path_.string()).set_license(
            build_cached_license("KEY-123", config_.device_id)));
    }
    server_.stop();
    Client restarted(config_);
    auto result = restarted.restore_license();
    EXPECT_TRUE(result.success) << result.message;
    EXPECT_EQ(result.status, ClientStatus::OfflineValid);
}

TEST_F(CustomerWorkflowReview, SupportedProvisioningValidateThenRestartWorks) {
    config_.signing_public_key = public_key_;
    config_.signing_key_id = "test-kid";
    {
        Client client(config_);
        ASSERT_TRUE(client.activate("KEY-123").is_ok());
        auto validated = client.validate("KEY-123");
        ASSERT_TRUE(validated.is_ok()) << validated.error_message();
        ASSERT_TRUE(validated.value().valid);
        ASSERT_TRUE(validated.value().activation.has_value());
        EXPECT_EQ(validated.value().activation->id(), id_.get<std::string>());
        auto machine = client.checkout_machine_file("KEY-123");
        ASSERT_TRUE(machine.is_ok()) << machine.error_message();
    }
    server_.stop();
    Client restarted(config_);
    auto restored = restarted.restore_license();
    EXPECT_TRUE(restored.success) << restored.message;
    EXPECT_EQ(restored.status, ClientStatus::OfflineValid);
}

TEST_F(CustomerWorkflowReview, CurlCertificateOnlyVerifiesWithPinnedKeyAndRejectsTampering) {
    config_.signing_public_key = public_key_;
    Client client(config_);
    MachineFile imported;
    imported.certificate = machine_.certificate;
    auto valid = client.verify_machine_file(imported, "", "KEY-123", config_.device_id);
    ASSERT_TRUE(valid.is_ok()) << valid.error_message();
    ASSERT_TRUE(valid.value().valid);
    ASSERT_TRUE(valid.value().payload.has_value());
    ASSERT_TRUE(valid.value().payload->license.has_value());
    EXPECT_EQ(valid.value().payload->license->key(), "KEY-123");
    auto wrong_device = client.verify_machine_file(imported, "", "KEY-123", "wrong-device");
    EXPECT_TRUE(wrong_device.is_error() || !wrong_device.value().valid);
    auto wrong_license = client.verify_machine_file(imported, "", "WRONG-KEY", config_.device_id);
    EXPECT_TRUE(wrong_license.is_error() || !wrong_license.value().valid);
    imported.certificate[40] = imported.certificate[40] == 'A' ? 'B' : 'A';
    auto tampered = client.verify_machine_file(imported, "", "KEY-123", config_.device_id);
    EXPECT_TRUE(tampered.is_error() || !tampered.value().valid);
}

TEST_F(CustomerWorkflowReview, RejectNonpositiveNumericActivationIds) {
    config_.offline_fallback_mode = OfflineFallbackMode::Disabled;
    Client client(config_);
    for (auto invalid : {0, -1}) {
        id_ = invalid;
        auto result = client.activate("KEY-123");
        EXPECT_TRUE(result.is_error()) << "Accepted id=" << invalid;
        auto deactivation = client.deactivate("KEY-123", config_.device_id);
        EXPECT_TRUE(deactivation.is_error()) << "Accepted activation_id=" << invalid;
    }
}

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
    config.allow_insecure_http = true;
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

    server.Post("/api/v1/products/test_product/licenses/validate", [&](const httplib::Request&,
                                                                       httplib::Response& res) {
        if (return_not_found.load()) {
            res.status = 404;
            res.set_content("<html>not found</html>", "text/html");
            return;
        }

        res.status = 200;
        res.set_content(
            R"({"object":"validation_result","valid":true,"code":"license_valid","message":"ok","license":{"key":"VALID-KEY","status":"active","mode":"hardware_locked","plan_key":"pro","seat_limit":1,"active_seats":1,"product":{"slug":"test_product","name":"Test Product"}}})",
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

TEST_F(ClientTest, ValidateForbiddenEmitsAuthenticationFailureEvent) {
    httplib::Server server;
    server.Post("/api/v1/products/test_product/licenses/validate",
                [](const httplib::Request&, httplib::Response& res) {
                    res.status = 403;
                    res.set_content(
                        R"({"errors":[{"code":"FORBIDDEN","title":"Forbidden","detail":"invalid API credential scope"}]})",
                        "application/json");
                });

    const auto port = server.bind_to_any_port("127.0.0.1");
    ASSERT_GT(port, 0);
    std::thread server_thread([&server]() { server.listen_after_bind(); });

    config_.api_url = "http://127.0.0.1:" + std::to_string(port) + "/api/v1";
    Client client(config_);
    std::atomic<int> auth_failure_events{0};
    auto subscription = client.on(events::VALIDATION_AUTH_FAILED,
                                  [&](const std::any&) { auth_failure_events++; });

    const auto result = client.validate("VALID-KEY");

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::PermissionDenied);
    EXPECT_EQ(auth_failure_events.load(), 1);

    server.stop();
    if (server_thread.joinable())
        server_thread.join();
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

TEST_F(ClientTest, RejectsMalformedUtf8IdentifiersBeforeNetwork) {
    const std::string invalid_utf8{static_cast<char>(0xc3), static_cast<char>(0x28)};

    Client client(config_);
    auto invalid_key = client.activate(invalid_utf8);
    EXPECT_TRUE(invalid_key.is_error());
    EXPECT_EQ(invalid_key.error_code(), ErrorCode::InvalidLicenseKey);

    auto invalid_device = client.activate("VALID-KEY", invalid_utf8);
    EXPECT_TRUE(invalid_device.is_error());
    EXPECT_EQ(invalid_device.error_code(), ErrorCode::MissingParameter);

    Config invalid_product_config = config_;
    invalid_product_config.product_slug = invalid_utf8;
    Client invalid_product(invalid_product_config);
    auto invalid_product_result = invalid_product.activate("VALID-KEY");
    EXPECT_TRUE(invalid_product_result.is_error());
    EXPECT_EQ(invalid_product_result.error_code(), ErrorCode::MissingParameter);
}

TEST_F(ClientTest, RejectsUnsafeActivationTextAndMetadataWithoutThrowing) {
    const std::string invalid_utf8{static_cast<char>(0xc3), static_cast<char>(0x28)};
    const Metadata metadata{{"unsafe", invalid_utf8}};
    Client client(config_);

    EXPECT_NO_THROW({
        const auto result = client.activate("VALID-KEY", "test-device", invalid_utf8);
        EXPECT_TRUE(result.is_error());
        EXPECT_EQ(result.error_code(), ErrorCode::InvalidParameter);
    });

    EXPECT_NO_THROW({
        const auto result = client.activate("VALID-KEY", "test-device", "", metadata);
        EXPECT_TRUE(result.is_error());
        EXPECT_EQ(result.error_code(), ErrorCode::InvalidParameter);
    });
}

TEST_F(ClientTest, RejectsOversizedActivationMetadata) {
    Client client(config_);

    Metadata too_many_entries;
    for (int index = 0; index < 101; ++index)
        too_many_entries.emplace("key-" + std::to_string(index), "value");
    auto too_many = client.activate("VALID-KEY", "test-device", "", too_many_entries);
    EXPECT_TRUE(too_many.is_error());
    EXPECT_EQ(too_many.error_code(), ErrorCode::InvalidParameter);

    const Metadata oversized_value{{"key", std::string(16 * 1024 + 1, 'x')}};
    auto large_value = client.activate("VALID-KEY", "test-device", "", oversized_value);
    EXPECT_TRUE(large_value.is_error());
    EXPECT_EQ(large_value.error_code(), ErrorCode::InvalidParameter);

    Metadata oversized_aggregate;
    for (int index = 0; index < 33; ++index)
        oversized_aggregate.emplace("aggregate-key-" + std::to_string(index),
                                    std::string(16 * 1024, 'x'));
    auto large_aggregate = client.activate("VALID-KEY", "test-device", "", oversized_aggregate);
    EXPECT_TRUE(large_aggregate.is_error());
    EXPECT_EQ(large_aggregate.error_code(), ErrorCode::InvalidParameter);
}

TEST_F(ClientTest, AcceptsBoundedUnicodeActivationText) {
    Client client(config_);
    const Metadata metadata{{"region", "Lisboa"}, {"owner", "Jos\xC3\xA9"}};

    const auto result =
        client.activate("VALID-KEY", "test-device", "Esta\xC3\xA7\xC3\xA3o", metadata);

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::NetworkError);
}

TEST_F(ClientTest, SyncOfflineAssetsDoesNotFetchLegacyTokenByDefault) {
    httplib::Server server;
    std::atomic<int> machine_file_requests{0};
    std::atomic<int> offline_token_requests{0};

    server.Post("/api/v1/products/test_product/licenses/validate", [&](const httplib::Request&,
                                                                       httplib::Response& res) {
        res.status = 200;
        res.set_content(
            R"({"object":"validation_result","valid":true,"code":"license_valid","message":"ok","license":{"key":"VALID-KEY","status":"active","mode":"hardware_locked","plan_key":"pro","seat_limit":1,"active_seats":1,"product":{"slug":"test_product","name":"Test Product"}}})",
            "application/json");
    });
    server.Post("/api/v1/products/test_product/licenses/machine-file", [&](const httplib::Request&,
                                                                           httplib::Response& res) {
        machine_file_requests++;
        res.status = 403;
        res.set_content(
            R"({"errors":[{"code":"FORBIDDEN","title":"Forbidden","detail":"missing machine-file scope"}]})",
            "application/json");
    });
    server.Post("/api/v1/products/test_product/licenses/offline-token",
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

TEST_F(ClientTest, ZeroDayOfflinePolicyDoesNotFetchArtifacts) {
    httplib::Server server;
    std::atomic<int> machine_file_requests{0};

    server.Post("/api/v1/products/test_product/licenses/validate",
                [](const httplib::Request&, httplib::Response& res) {
                    res.status = 200;
                    res.set_content(
                        R"({"object":"validation_result","valid":true,"code":"license_valid","message":"ok","license":{"key":"VALID-KEY","status":"active","mode":"hardware_locked","plan_key":"pro","seat_limit":1,"active_seats":1,"product":{"slug":"test_product","name":"Test Product"}}})",
                        "application/json");
                });
    server.Post("/api/v1/products/test_product/licenses/machine-file",
                [&](const httplib::Request&, httplib::Response& res) {
                    machine_file_requests++;
                    res.status = 500;
                });

    const auto port = server.bind_to_any_port("127.0.0.1");
    ASSERT_GT(port, 0);
    std::thread server_thread([&server]() { server.listen_after_bind(); });

    config_.api_url = "http://127.0.0.1:" + std::to_string(port) + "/api/v1";
    config_.max_offline_days = 0;
    Client client(config_);
    ASSERT_TRUE(client.validate("VALID-KEY").is_ok());

    client.sync_offline_assets();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_EQ(machine_file_requests.load(), 0);

    server.stop();
    if (server_thread.joinable())
        server_thread.join();
}

TEST_F(ClientTest, CheckoutMachineFileSendsFingerprintComponentsForAutoGeneratedFingerprint) {
    if (device::generate_device_id().empty()) {
        GTEST_SKIP() << "No stable local fingerprint available on this runner";
    }

    httplib::Server server;
    std::atomic<bool> saw_components{false};

    config_.device_id.clear();

    server.Post(
        "/api/v1/products/test_product/licenses/machine-file",
        [&](const httplib::Request& req, httplib::Response& res) {
            const auto body = nlohmann::json::parse(req.body);
            saw_components = body.contains("fingerprint_components") &&
                             body["fingerprint_components"].is_object() &&
                             body["fingerprint_components"].contains("schema_version") &&
                             body["fingerprint_components"].contains("platform");

            const auto fingerprint = body.value("fingerprint", std::string{});
            std::string public_key;
            const auto certificate = build_test_machine_file("VALID-KEY", fingerprint, &public_key);

            nlohmann::json response = {
                {"data",
                 {{"type", "machine-files"},
                  {"attributes",
                   {{"certificate", certificate.certificate},
                    {"algorithm", certificate.algorithm},
                    {"ttl", 2592000},
                    {"issued", "2026-08-01T00:00:00Z"},
                    {"expiry", "2026-08-31T00:00:00Z"}}},
                  {"relationships",
                   {{"license", {{"data", {{"type", "licenses"}, {"id", "VALID-KEY"}}}}},
                    {"machine", {{"data", {{"type", "machines"}, {"id", fingerprint}}}}}}}}}};

            res.status = 201;
            res.set_content(response.dump(), "application/json");
        });

    auto port = server.bind_to_any_port("127.0.0.1");
    ASSERT_GT(port, 0);

    std::thread server_thread([&server]() { server.listen_after_bind(); });

    config_.api_url = "http://127.0.0.1:" + std::to_string(port) + "/api/v1";
    std::string checkout_public_key;
    (void)build_test_machine_file("VALID-KEY", device::generate_device_id(), &checkout_public_key);
    config_.signing_public_key = checkout_public_key;

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

    server.Post("/api/v1/products/test_product/licenses/validate", [&](const httplib::Request&,
                                                                       httplib::Response& res) {
        res.status = 200;
        res.set_content(
            R"({"object":"validation_result","valid":true,"code":"license_valid","message":"ok","license":{"key":"VALID-KEY","status":"active","mode":"hardware_locked","plan_key":"pro","seat_limit":1,"active_seats":1,"product":{"slug":"test_product","name":"Test Product"}}})",
            "application/json");
    });
    server.Post("/api/v1/products/test_product/licenses/machine-file", [&](const httplib::Request&,
                                                                           httplib::Response& res) {
        machine_file_requests++;
        res.status = 403;
        res.set_content(
            R"({"errors":[{"code":"FORBIDDEN","title":"Forbidden","detail":"missing machine-file scope"}]})",
            "application/json");
    });
    server.Post("/api/v1/products/test_product/licenses/offline-token",
                [&](const httplib::Request&, httplib::Response& res) {
                    offline_token_requests++;
                    res.status = 200;
                    res.set_content(json::offline_token_to_json(offline_token), "application/json");
                });
    server.Get("/api/v1/signing_keys/test-kid",
               [&](const httplib::Request&, httplib::Response& res) {
                   signing_key_requests++;
                   res.status = 200;
                   res.set_content(nlohmann::json{{"object", "signing_key"},
                                                  {"key_id", "test-kid"},
                                                  {"algorithm", "Ed25519"},
                                                  {"public_key", public_key_b64},
                                                  {"created_at", nullptr},
                                                  {"status", "active"}}
                                       .dump(),
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

    FileStorage storage(storage_dir.string());
    for (int i = 0;
         i < 100 && (offline_token_requests.load() == 0 || signing_key_requests.load() == 0 ||
                     !storage.get_offline_token().has_value());
         ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    EXPECT_GE(machine_file_requests.load(), 1);
    EXPECT_EQ(offline_token_requests.load(), 1);
    EXPECT_EQ(offline_fetch_events.load(), 1);
    EXPECT_EQ(signing_key_requests.load(), 1);

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
    offline.token.exp = std::time(nullptr) - (24 * 60 * 60); // Expired

    auto result = client.verify_offline_token(offline);

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::LicenseExpired);
}

TEST_F(ClientTest, VerifyOfflineTokenWithInvalidSignature) {
    Client client(config_);

    std::string public_key;
    auto offline = build_test_offline_token("KEY-123", config_.device_id, &public_key);
    offline.signature.value = "invalid-signature"; // Not a valid signature

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
    offline.token.nbf = std::time(nullptr) + (24 * 60 * 60); // Not valid until tomorrow
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
    machine_file.certificate =
        "-----BEGIN MACHINE FILE-----\nZXlKa2FXUWlPaUpyYVdRaUxDSmxiR01pT2lKaGJHY2lmUT09\n-----END "
        "MACHINE FILE-----";

    auto result = client.verify_machine_file(machine_file);

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::MissingParameter);
}

TEST_F(ClientTest, VerifyMachineFileUsesLocalDeviceFingerprintNotEmbeddedFingerprint) {
    config_.device_id = "local-device-001";
    const std::string license_key = "KEY-123";
    const std::string embedded_fingerprint = "embedded-device-001";

    std::string public_key_b64;
    auto machine_file = build_test_machine_file(license_key, embedded_fingerprint, &public_key_b64);
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
    auto offline_token = build_test_offline_token(license_key, original_device, &public_key_b64);

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

TEST_F(ClientTest, InvalidOfflinePolicyCannotAuthorizeCachedArtifacts) {
    const std::string license_key = "KEY-123";
    std::string public_key_b64;
    auto machine_file = build_test_machine_file(license_key, config_.device_id, &public_key_b64);
    const auto storage_dir =
        std::filesystem::temp_directory_path() /
        ("licenseseat-invalid-offline-policy-" +
         std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    FileStorage storage(storage_dir.string());
    ASSERT_TRUE(storage.set_license(build_cached_license(license_key, config_.device_id)));
    ASSERT_TRUE(storage.set_machine_file(machine_file));

    config_.storage_path = storage_dir.string();
    config_.signing_public_key = public_key_b64;
    config_.network_recheck_interval = 0.0;

    config_.max_offline_days = -1;
    {
        Client client(config_);
        const auto result = client.restore_license();
        EXPECT_FALSE(result.success);
        EXPECT_EQ(result.status, ClientStatus::OfflineInvalid);
        EXPECT_NE(result.message.find("invalid_configuration"), std::string::npos);
    }

    config_.max_offline_days = 0;
    {
        Client client(config_);
        const auto result = client.restore_license();
        EXPECT_FALSE(result.success);
        EXPECT_EQ(result.status, ClientStatus::OfflineInvalid);
        EXPECT_NE(result.message.find("offline_disabled"), std::string::npos);
    }

    config_.max_offline_days = 30;
    config_.offline_fallback_mode = OfflineFallbackMode::Disabled;
    {
        Client client(config_);
        const auto result = client.restore_license();
        EXPECT_FALSE(result.success);
        EXPECT_EQ(result.status, ClientStatus::OfflineInvalid);
        EXPECT_NE(result.message.find("offline_disabled"), std::string::npos);
    }

    config_.offline_fallback_mode = OfflineFallbackMode::NetworkOnly;
    config_.max_offline_days = 30;
    config_.max_clock_skew_ms = std::numeric_limits<double>::quiet_NaN();
    {
        Client client(config_);
        const auto result = client.restore_license();
        EXPECT_FALSE(result.success);
        EXPECT_EQ(result.status, ClientStatus::OfflineInvalid);
        EXPECT_NE(result.message.find("invalid_configuration"), std::string::npos);
    }

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

    server.Post("/api/v1/products/test_product/licenses/validate", [&](const httplib::Request&,
                                                                       httplib::Response& res) {
        res.status = 200;
        res.set_content(
            R"({"object":"validation_result","valid":true,"code":"license_valid","message":"ok","license":{"key":"KEY-123","status":"active","mode":"hardware_locked","plan_key":"pro","seat_limit":1,"active_seats":1,"product":{"slug":"test_product","name":"Test Product"}}})",
            "application/json");
    });

    server.Post("/api/v1/products/test_product/licenses/heartbeat", [&](const httplib::Request&,
                                                                        httplib::Response& res) {
        res.status = 200;
        res.set_content(R"({"object":"heartbeat","received_at":"2026-03-26T02:07:56Z"})",
                        "application/json");
    });

    auto port = server.bind_to_any_port("127.0.0.1");
    ASSERT_GT(port, 0);

    std::thread server_thread([&server]() { server.listen_after_bind(); });

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
    server.Post("/api/v1/products/test_product/licenses/validate", [&](const httplib::Request&,
                                                                       httplib::Response& res) {
        res.status = 503;
        res.set_content(R"({"error":{"code":"temporarily_unavailable","message":"offline"}})",
                        "application/json");
    });

    auto port = server.bind_to_any_port("127.0.0.1");
    ASSERT_GT(port, 0);

    std::thread server_thread([&server]() { server.listen_after_bind(); });

    config_.api_url = "http://127.0.0.1:" + std::to_string(port) + "/api/v1";
    config_.storage_path = storage_dir.string();
    config_.signing_public_key = public_key_b64;
    config_.network_recheck_interval = 0.0;

    // A transport failure, rather than an authoritative HTTP error, is the
    // only condition eligible for offline fallback.
    for (int i = 0; i < 100 && !server.is_running(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    server.stop();
    if (server_thread.joinable())
        server_thread.join();

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

TEST_F(ClientTest, AuthoritativeServerErrorNeverFallsBackToCachedLicense) {
    const std::string license_key = "KEY-123";
    const std::string device_id = config_.device_id;
    std::string public_key_b64;
    const auto offline_token = build_test_offline_token(license_key, device_id, &public_key_b64);
    const auto storage_dir =
        std::filesystem::temp_directory_path() /
        ("licenseseat-authoritative-error-test-" +
         std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));

    FileStorage storage(storage_dir.string());
    ASSERT_TRUE(storage.set_license(build_cached_license(license_key, device_id)));
    ASSERT_TRUE(storage.set_offline_token(offline_token));

    httplib::Server server;
    server.Post("/api/v1/products/test_product/licenses/validate", [](const httplib::Request&,
                                                                      httplib::Response& res) {
        res.status = 503;
        res.set_content(R"({"error":{"code":"new_outage_code","message":"unavailable"}})",
                        "application/json");
    });
    const auto port = server.bind_to_any_port("127.0.0.1");
    ASSERT_GT(port, 0);
    std::thread server_thread([&server]() { server.listen_after_bind(); });

    config_.api_url = "http://127.0.0.1:" + std::to_string(port) + "/api/v1";
    config_.storage_path = storage_dir.string();
    config_.signing_public_key = public_key_b64;
    config_.network_recheck_interval = 0.0;
    Client client(config_);

    std::atomic<int> offline_success_events{0};
    client.on(events::VALIDATION_OFFLINE_SUCCESS,
              [&](const std::any&) { ++offline_success_events; });
    const auto result = client.validate(license_key);

    EXPECT_TRUE(result.is_error());
    EXPECT_EQ(result.error_code(), ErrorCode::ServerError);
    EXPECT_EQ(client.get_client_status(), ClientStatus::Invalid);
    EXPECT_TRUE(client.is_online());
    EXPECT_EQ(offline_success_events.load(), 0);

    server.stop();
    if (server_thread.joinable())
        server_thread.join();
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
    server.Post("/api/v1/products/test_product/licenses/validate", [&](const httplib::Request&,
                                                                       httplib::Response& res) {
        res.status = 503;
        res.set_content(R"({"error":{"code":"temporarily_unavailable","message":"offline"}})",
                        "application/json");
    });

    auto port = server.bind_to_any_port("127.0.0.1");
    ASSERT_GT(port, 0);

    std::thread server_thread([&server]() { server.listen_after_bind(); });

    config_.api_url = "http://127.0.0.1:" + std::to_string(port) + "/api/v1";
    config_.storage_path = storage_dir.string();
    config_.signing_public_key = public_key_b64;
    config_.network_recheck_interval = 0.0;

    for (int i = 0; i < 100 && !server.is_running(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    server.stop();
    if (server_thread.joinable())
        server_thread.join();

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

TEST_F(ClientTest, ReleaseAndDownloadResponsesAreBoundToTheRequest) {
    httplib::Server server;
    std::atomic<bool> public_request_had_auth{false};
    std::atomic<bool> download_request_had_auth{false};
    std::atomic<bool> download_body_was_bound{false};
    const auto published_at =
        json::format_timestamp(std::chrono::system_clock::now() - std::chrono::hours(1));
    const auto token_expiry =
        json::format_timestamp(std::chrono::system_clock::now() + std::chrono::minutes(5));

    server.Get("/api/v1/products/test_product/releases/latest",
               [&](const httplib::Request& req, httplib::Response& res) {
                   public_request_had_auth = req.has_header("Authorization");
                   EXPECT_EQ(req.get_param_value("channel"), "stable");
                   EXPECT_EQ(req.get_param_value("platform"), "macos");
                   res.set_content(nlohmann::json({{"object", "release"},
                                                   {"version", "1.2.3"},
                                                   {"channel", "stable"},
                                                   {"platform", "macos"},
                                                   {"product_slug", "test_product"},
                                                   {"published_at", published_at}})
                                       .dump(),
                                   "application/json");
               });
    server.Get("/api/v1/products/test_product/releases", [&](const httplib::Request& req,
                                                             httplib::Response& res) {
        public_request_had_auth = public_request_had_auth.load() || req.has_header("Authorization");
        nlohmann::json release = {{"object", "release"},
                                  {"version", "1.2.3"},
                                  {"channel", "stable"},
                                  {"platform", "macos"},
                                  {"product_slug", "test_product"},
                                  {"published_at", published_at}};
        res.set_content(nlohmann::json({{"object", "list"},
                                        {"data", nlohmann::json::array({release})},
                                        {"has_more", false}})
                            .dump(),
                        "application/json");
    });
    server.Post("/api/v1/products/test_product/releases/1.2.3/download_token",
                [&](const httplib::Request& req, httplib::Response& res) {
                    download_request_had_auth =
                        req.get_header_value("Authorization") == "Bearer test_api_key";
                    const auto body = nlohmann::json::parse(req.body);
                    download_body_was_bound =
                        body.value("license_key", std::string{}) == "LICENSE-KEY" &&
                        body.value("platform", std::string{}) == "macos";
                    res.set_content(nlohmann::json({{"object", "download_token"},
                                                    {"token", "opaque-token"},
                                                    {"expires_at", token_expiry}})
                                        .dump(),
                                    "application/json");
                });

    const auto port = server.bind_to_any_port("127.0.0.1");
    ASSERT_GT(port, 0);
    std::thread server_thread([&server]() { server.listen_after_bind(); });
    config_.api_url = "http://127.0.0.1:" + std::to_string(port) + "/api/v1";
    config_.max_retries = 0;
    Client client(config_);

    const auto latest = client.get_latest_release("", "stable", "macos");
    ASSERT_TRUE(latest.is_ok()) << latest.error_message();
    EXPECT_EQ(latest.value().version, "1.2.3");

    const auto releases = client.list_releases("", "stable", "macos");
    ASSERT_TRUE(releases.is_ok()) << releases.error_message();
    ASSERT_EQ(releases.value().size(), 1U);

    const auto token = client.generate_download_token("1.2.3", "LICENSE-KEY", "", "macos");
    ASSERT_TRUE(token.is_ok()) << token.error_message();
    EXPECT_EQ(token.value().token, "opaque-token");
    EXPECT_FALSE(public_request_had_auth.load());
    EXPECT_TRUE(download_request_had_auth.load());
    EXPECT_TRUE(download_body_was_bound.load());

    server.stop();
    if (server_thread.joinable())
        server_thread.join();
}

TEST_F(ClientTest, ReleaseDiscoveryRejectsUntrustedItemIdentityAndSchema) {
    httplib::Server server;
    std::string latest_body;
    std::string list_body;
    server.Get("/api/v1/products/test_product/releases/latest",
               [&](const httplib::Request&, httplib::Response& res) {
                   res.set_content(latest_body, "application/json");
               });
    server.Get("/api/v1/products/test_product/releases",
               [&](const httplib::Request&, httplib::Response& res) {
                   res.set_content(list_body, "application/json");
               });
    const auto port = server.bind_to_any_port("127.0.0.1");
    ASSERT_GT(port, 0);
    std::thread server_thread([&server]() { server.listen_after_bind(); });
    config_.api_url = "http://127.0.0.1:" + std::to_string(port) + "/api/v1";
    config_.max_retries = 0;
    Client client(config_);
    const auto published_at =
        json::format_timestamp(std::chrono::system_clock::now() - std::chrono::hours(1));

    latest_body = nlohmann::json({{"object", "release"},
                                  {"version", "1.2.3"},
                                  {"channel", "stable"},
                                  {"platform", "macos"},
                                  {"product_slug", "other_product"},
                                  {"published_at", published_at}})
                      .dump();
    auto latest = client.get_latest_release("", "stable", "macos");
    ASSERT_TRUE(latest.is_error());
    EXPECT_EQ(latest.error_code(), ErrorCode::ParseError);

    latest_body = nlohmann::json({{"object", "release"},
                                  {"version", "1.2.3"},
                                  {"channel", "beta"},
                                  {"platform", "macos"},
                                  {"product_slug", "test_product"},
                                  {"published_at", published_at}})
                      .dump();
    latest = client.get_latest_release("", "stable", "macos");
    ASSERT_TRUE(latest.is_error());
    EXPECT_EQ(latest.error_code(), ErrorCode::ParseError);

    nlohmann::json release = {{"version", "1.2.3"},
                              {"channel", "stable"},
                              {"platform", "macos"},
                              {"product_slug", "test_product"},
                              {"published_at", published_at}};
    list_body =
        nlohmann::json({{"object", "list"}, {"data", nlohmann::json::array({release})}}).dump();
    auto releases = client.list_releases("", "stable", "macos");
    ASSERT_TRUE(releases.is_error());
    EXPECT_EQ(releases.error_code(), ErrorCode::ParseError);

    release["object"] = "release";
    release["published_at"] = "not-a-time";
    list_body =
        nlohmann::json({{"object", "list"}, {"data", nlohmann::json::array({release})}}).dump();
    releases = client.list_releases("", "stable", "macos");
    ASSERT_TRUE(releases.is_error());
    EXPECT_EQ(releases.error_code(), ErrorCode::ParseError);

    server.stop();
    if (server_thread.joinable())
        server_thread.join();
}

TEST_F(ClientTest, DownloadTokenRejectsMalformedOrUnboundedAuthority) {
    httplib::Server server;
    std::string response_body;
    server.Post("/api/v1/products/test_product/releases/1.2.3/download_token",
                [&](const httplib::Request&, httplib::Response& res) {
                    res.set_content(response_body, "application/json");
                });
    const auto port = server.bind_to_any_port("127.0.0.1");
    ASSERT_GT(port, 0);
    std::thread server_thread([&server]() { server.listen_after_bind(); });
    config_.api_url = "http://127.0.0.1:" + std::to_string(port) + "/api/v1";
    config_.max_retries = 0;
    Client client(config_);

    const auto invoke = [&]() {
        return client.generate_download_token("1.2.3", "LICENSE-KEY", "", "macos");
    };
    response_body =
        nlohmann::json({{"object", "download_token"},
                        {"token", "token"},
                        {"expires_at", json::format_timestamp(std::chrono::system_clock::now() -
                                                              std::chrono::seconds(1))}})
            .dump();
    EXPECT_EQ(invoke().error_code(), ErrorCode::ParseError);

    response_body =
        nlohmann::json({{"object", "download_token"},
                        {"token", "token"},
                        {"expires_at", json::format_timestamp(std::chrono::system_clock::now() +
                                                              std::chrono::hours(25))}})
            .dump();
    EXPECT_EQ(invoke().error_code(), ErrorCode::ParseError);

    response_body =
        nlohmann::json({{"object", "download_token"},
                        {"token", std::string(16 * 1024 + 1, 'x')},
                        {"expires_at", json::format_timestamp(std::chrono::system_clock::now() +
                                                              std::chrono::minutes(5))}})
            .dump();
    EXPECT_EQ(invoke().error_code(), ErrorCode::ParseError);

    response_body =
        nlohmann::json({{"object", "download_token"},
                        {"token", "unsafe\ntoken"},
                        {"expires_at", json::format_timestamp(std::chrono::system_clock::now() +
                                                              std::chrono::minutes(5))}})
            .dump();
    EXPECT_EQ(invoke().error_code(), ErrorCode::ParseError);

    server.stop();
    if (server_thread.joinable())
        server_thread.join();
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
    EXPECT_EQ(call_count, 1); // Should not increase
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
    client.start_auto_validation("TEST-KEY-2"); // Should not crash

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

TEST_F(ClientTest, InvalidAutoValidationIntervalsFailClosed) {
    for (double interval :
         {std::numeric_limits<double>::quiet_NaN(), std::numeric_limits<double>::infinity(), -1.0,
          367.0 * 24.0 * 60.0 * 60.0}) {
        auto config = config_;
        config.auto_validate_interval = interval;
        Client client(config);
        client.start_auto_validation("TEST-KEY");
        EXPECT_FALSE(client.is_auto_validating());
    }
}

TEST_F(ClientTest, AutoValidationHandlerCanStopItsOwnWorker) {
    config_.auto_validate_interval = 60.0;
    Client client(config_);
    std::atomic<bool> handler_returned{false};
    auto subscription = client.on(events::AUTOVALIDATION_CYCLE, [&](const std::any&) {
        client.stop_auto_validation();
        handler_returned = true;
    });

    client.start_auto_validation("TEST-KEY");
    for (int i = 0; i < 100 && !handler_returned.load(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    EXPECT_TRUE(handler_returned.load());
    EXPECT_FALSE(client.is_auto_validating());
    client.stop_auto_validation(); // Reap the completed worker from another thread.
}

TEST_F(ClientTest, ConcurrentTimerLifecycleCallsAreSerialized) {
    config_.auto_validate_interval = 60.0;
    config_.heartbeat_interval = 60;
    Client client(config_);
    std::vector<std::thread> callers;
    for (int worker = 0; worker < 4; ++worker) {
        callers.emplace_back([&, worker]() {
            for (int iteration = 0; iteration < 20; ++iteration) {
                client.start_auto_validation("AUTO-" + std::to_string(worker));
                client.start_heartbeat("HEARTBEAT-" + std::to_string(worker));
                client.stop_auto_validation();
                client.stop_heartbeat();
            }
        });
    }
    for (auto& caller : callers)
        caller.join();

    client.stop_auto_validation();
    client.stop_heartbeat();
    EXPECT_FALSE(client.is_auto_validating());
    EXPECT_FALSE(client.is_heartbeat_running());
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
    client.start_heartbeat("TEST-KEY-2"); // Should not crash

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

TEST_F(ClientTest, InvalidHeartbeatInputsFailClosed) {
    auto config = config_;
    config.heartbeat_interval = 367 * 24 * 60 * 60;
    Client client(config);
    client.start_heartbeat("TEST-KEY");
    EXPECT_FALSE(client.is_heartbeat_running());

    config.heartbeat_interval = 60;
    Client empty_key_client(config);
    empty_key_client.start_heartbeat("");
    EXPECT_FALSE(empty_key_client.is_heartbeat_running());
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

    client.validate_async("TEST-KEY", [&](Result<ValidationResult> result) {
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

    client.activate_async("TEST-KEY",
                          [&](Result<Activation> /*result*/) { callback_called = true; });

    int attempts = 0;
    while (!callback_called && attempts++ < 100) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    EXPECT_TRUE(callback_called);
}

TEST_F(ClientTest, DeactivateAsyncCallsCallback) {
    Client client(config_);
    std::atomic<bool> callback_called{false};

    client.deactivate_async(
        "TEST-KEY", [&](Result<Deactivation> /*result*/) { callback_called = true; }, "device-123");

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
                                  [&](Result<ValidationResult> /*result*/) { callback_count++; });
        }
        // Client destructor should wait for all callbacks to complete
    }

    // Give some time for potential issues to manifest
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // All callbacks should have been called before destructor completed
    EXPECT_EQ(callback_count, 5);
}

TEST_F(ClientTest, AsyncCallbackCanDestroyItsClient) {
    httplib::Server server;
    std::mutex gate_mutex;
    std::condition_variable gate_cv;
    bool release_response = false;
    server.Post("/api/v1/products/test_product/licenses/validate", [&](const httplib::Request&,
                                                                       httplib::Response& res) {
        std::unique_lock<std::mutex> lock(gate_mutex);
        gate_cv.wait(lock, [&]() { return release_response; });
        res.set_content(
            R"({"object":"validation_result","valid":true,"code":"license_valid","message":"ok","license":{"key":"VALID-KEY","status":"active","mode":"hardware_locked","plan_key":"pro","seat_limit":1,"active_seats":1,"product":{"slug":"test_product","name":"Test Product"}}})",
            "application/json");
    });
    const auto port = server.bind_to_any_port("127.0.0.1");
    ASSERT_GT(port, 0);
    std::thread server_thread([&server]() { server.listen_after_bind(); });

    auto config = config_;
    config.api_url = "http://127.0.0.1:" + std::to_string(port) + "/api/v1";
    auto holder =
        std::make_shared<std::unique_ptr<Client>>(std::make_unique<Client>(std::move(config)));
    auto destroyed = std::make_shared<std::promise<void>>();
    auto destroyed_future = destroyed->get_future();

    (*holder)->validate_async("VALID-KEY", [holder, destroyed](Result<ValidationResult>) {
        holder->reset();
        destroyed->set_value();
    });
    {
        std::lock_guard<std::mutex> lock(gate_mutex);
        release_response = true;
    }
    gate_cv.notify_all();

    const auto status = destroyed_future.wait_for(std::chrono::seconds(3));
    EXPECT_EQ(status, std::future_status::ready);

    server.stop();
    if (server_thread.joinable())
        server_thread.join();
}

TEST_F(ClientTest, MultipleAsyncOpsDoNotCrash) {
    std::atomic<int> completed{0};

    {
        Client client(config_);

        // Launch many concurrent async operations
        for (int i = 0; i < 10; i++) {
            client.validate_async("KEY-" + std::to_string(i),
                                  [&](Result<ValidationResult> /*result*/) { completed++; });
            client.activate_async("KEY-" + std::to_string(i),
                                  [&](Result<Activation> /*result*/) { completed++; });
        }

        // Give the operations a chance to complete before destructor-driven draining.
        int attempts = 0;
        while (completed < 20 && attempts++ < 200) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
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
    client.validate_async("TEST-KEY",
                          [&](Result<ValidationResult> /*result*/) { callback_called = true; });

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
    client.validate_async("TEST-KEY",
                          [&](Result<ValidationResult> /*result*/) { callback_called = true; });

    // This should return quickly
    auto start = std::chrono::steady_clock::now();
    bool online = client.is_online();
    auto elapsed = std::chrono::steady_clock::now() - start;

    // Should complete in under 10ms
    EXPECT_LT(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(), 10);
    (void)online; // Value doesn't matter for this test

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

TEST_F(ClientTest, TimerEventHandlerCanDestroyItsClient) {
    httplib::Server server;
    server.Post("/api/v1/products/test_product/licenses/validate", [](const httplib::Request&,
                                                                      httplib::Response& res) {
        res.set_content(
            R"({"object":"validation_result","valid":true,"code":"license_valid","message":"ok","license":{"key":"VALID-KEY","status":"active","mode":"hardware_locked","plan_key":"pro","seat_limit":1,"active_seats":1,"product":{"slug":"test_product","name":"Test Product"}}})",
            "application/json");
    });
    server.Post("/api/v1/products/test_product/licenses/heartbeat", [](const httplib::Request&,
                                                                       httplib::Response& res) {
        res.set_content(R"({"object":"heartbeat","received_at":"2026-08-09T12:00:00Z"})",
                        "application/json");
    });
    const auto port = server.bind_to_any_port("127.0.0.1");
    ASSERT_GT(port, 0);
    std::thread server_thread([&server]() { server.listen_after_bind(); });

    auto config = config_;
    config.api_url = "http://127.0.0.1:" + std::to_string(port) + "/api/v1";
    config.auto_validate_interval = 0.01;
    config.heartbeat_interval = 0;
    auto holder =
        std::make_shared<std::unique_ptr<Client>>(std::make_unique<Client>(std::move(config)));
    auto destroyed = std::make_shared<std::promise<void>>();
    auto destroyed_future = destroyed->get_future();
    auto subscription =
        (*holder)->on(events::VALIDATION_SUCCESS, [holder, destroyed](const std::any&) {
            holder->reset();
            destroyed->set_value();
        });

    (*holder)->start_auto_validation("VALID-KEY");
    const auto status = destroyed_future.wait_for(std::chrono::seconds(3));
    EXPECT_EQ(status, std::future_status::ready);

    subscription.cancel();
    server.stop();
    if (server_thread.joinable())
        server_thread.join();
}

TEST_F(ClientTest, SynchronousEventHandlerCanDestroyItsClient) {
    auto holder = std::make_shared<std::unique_ptr<Client>>(std::make_unique<Client>(config_));
    auto subscription =
        (*holder)->on("test:self-destruct", [holder](const std::any&) { holder->reset(); });

    (*holder)->emit("test:self-destruct");

    EXPECT_EQ(holder->get(), nullptr);
    subscription.cancel();
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

    client.on("network:offline", [&](const std::any& /*data*/) { offline_event_received = true; });

    // Force a health check failure
    auto result = client.health();
    EXPECT_TRUE(result.is_error());

    EXPECT_TRUE(offline_event_received);
}

TEST_F(ClientTest, ValidationFailedEventEmittedOnNetworkError) {
    Client client(config_);
    bool error_event_received = false;

    client.on("validation:error", [&](const std::any& /*data*/) { error_event_received = true; });

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

    auto sub =
        client.on("license:revoked", [&](const std::any& /*data*/) { event_received = true; });

    // Manually emit to verify subscription works
    client.emit("license:revoked");

    EXPECT_TRUE(event_received);
}

} // namespace
} // namespace licenseseat
