#include <gtest/gtest.h>
#include <licenseseat/storage.hpp>

#include <chrono>
#include <filesystem>
#include <thread>

namespace licenseseat {
namespace {

// Helper to create a temporary directory for tests
class TempDirectory {
  public:
    TempDirectory() {
        path_ = std::filesystem::temp_directory_path() / ("licenseseat_test_" + std::to_string(
                                                              std::chrono::system_clock::now()
                                                                  .time_since_epoch()
                                                                  .count()));
        std::filesystem::create_directories(path_);
    }

    ~TempDirectory() {
        try {
            std::filesystem::remove_all(path_);
        } catch (...) {
        }
    }

    const std::filesystem::path& path() const { return path_; }

  private:
    std::filesystem::path path_;
};

// ==================== MemoryStorage Tests ====================

class MemoryStorageTest : public ::testing::Test {
  protected:
    MemoryStorage storage;
};

TEST_F(MemoryStorageTest, InitiallyEmpty) {
    EXPECT_FALSE(storage.get_license().has_value());
    EXPECT_FALSE(storage.get_offline_token().has_value());
    EXPECT_FALSE(storage.get_signing_key("any").has_value());
    EXPECT_FALSE(storage.get_last_seen_timestamp().has_value());
}

TEST_F(MemoryStorageTest, SetAndGetLicense) {
    CachedLicense license;
    license.license_key = "KEY-123";
    license.device_id = "device-abc";
    license.activated_at = std::chrono::system_clock::now();
    license.last_validated = std::chrono::system_clock::now();

    EXPECT_TRUE(storage.set_license(license));

    auto retrieved = storage.get_license();
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved->license_key, "KEY-123");
    EXPECT_EQ(retrieved->device_id, "device-abc");
}

TEST_F(MemoryStorageTest, ClearLicense) {
    CachedLicense license;
    license.license_key = "KEY-123";
    storage.set_license(license);

    storage.clear_license();

    EXPECT_FALSE(storage.get_license().has_value());
}

TEST_F(MemoryStorageTest, SetAndGetOfflineToken) {
    OfflineToken offline;
    offline.token.license_key = "KEY-456";
    offline.token.product_slug = "my-product";
    offline.token.plan_key = "pro";
    offline.token.seat_limit = 5;
    offline.token.iat = std::time(nullptr);
    offline.token.exp = std::time(nullptr) + 86400;
    offline.token.nbf = offline.token.iat;
    offline.signature.value = "test-signature";
    offline.canonical = R"({"license_key":"KEY-456"})";

    EXPECT_TRUE(storage.set_offline_token(offline));

    auto retrieved = storage.get_offline_token();
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved->token.license_key, "KEY-456");
    EXPECT_EQ(retrieved->token.product_slug, "my-product");
    EXPECT_TRUE(retrieved->token.seat_limit.has_value());
    EXPECT_EQ(retrieved->token.seat_limit.value(), 5);
}

TEST_F(MemoryStorageTest, ClearOfflineToken) {
    OfflineToken offline;
    offline.token.license_key = "KEY-456";
    storage.set_offline_token(offline);

    storage.clear_offline_token();

    EXPECT_FALSE(storage.get_offline_token().has_value());
}

TEST_F(MemoryStorageTest, SetAndGetMachineFile) {
    MachineFile machine_file;
    machine_file.certificate = "-----BEGIN MACHINE FILE-----\nabc\n-----END MACHINE FILE-----";
    machine_file.license_key = "KEY-789";
    machine_file.fingerprint = "fp-123";
    machine_file.ttl = 2592000;

    EXPECT_TRUE(storage.set_machine_file(machine_file));

    auto retrieved = storage.get_machine_file();
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved->license_key, "KEY-789");
    EXPECT_EQ(retrieved->fingerprint, "fp-123");
    EXPECT_EQ(retrieved->ttl, 2592000);
}

TEST_F(MemoryStorageTest, ClearMachineFile) {
    MachineFile machine_file;
    machine_file.license_key = "KEY-789";
    storage.set_machine_file(machine_file);

    storage.clear_machine_file();

    EXPECT_FALSE(storage.get_machine_file().has_value());
}

TEST_F(MemoryStorageTest, SetAndGetSigningKey) {
    EXPECT_TRUE(storage.set_signing_key("key-id-1", "base64-encoded-key"));

    auto retrieved = storage.get_signing_key("key-id-1");
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(*retrieved, "base64-encoded-key");

    // Different key ID should not exist
    EXPECT_FALSE(storage.get_signing_key("key-id-2").has_value());
}

TEST_F(MemoryStorageTest, MultipleSigningKeys) {
    storage.set_signing_key("key-1", "pk-1");
    storage.set_signing_key("key-2", "pk-2");

    EXPECT_EQ(*storage.get_signing_key("key-1"), "pk-1");
    EXPECT_EQ(*storage.get_signing_key("key-2"), "pk-2");
}

TEST_F(MemoryStorageTest, SetAndGetTimestamp) {
    double timestamp = 1704067200.123;

    EXPECT_TRUE(storage.set_last_seen_timestamp(timestamp));

    auto retrieved = storage.get_last_seen_timestamp();
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_DOUBLE_EQ(*retrieved, timestamp);
}

TEST_F(MemoryStorageTest, ClearAll) {
    CachedLicense license;
    license.license_key = "KEY-123";
    storage.set_license(license);

    OfflineToken offline;
    offline.token.license_key = "KEY-456";
    storage.set_offline_token(offline);

    MachineFile machine_file;
    machine_file.license_key = "KEY-789";
    storage.set_machine_file(machine_file);

    storage.set_signing_key("key-1", "pk-1");
    storage.set_last_seen_timestamp(123.456);

    storage.clear_all();

    EXPECT_FALSE(storage.get_license().has_value());
    EXPECT_FALSE(storage.get_offline_token().has_value());
    EXPECT_FALSE(storage.get_machine_file().has_value());
    EXPECT_FALSE(storage.get_signing_key("key-1").has_value());
    EXPECT_FALSE(storage.get_last_seen_timestamp().has_value());
}

TEST_F(MemoryStorageTest, ThreadSafety) {
    std::vector<std::thread> threads;

    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&, i]() {
            CachedLicense license;
            license.license_key = "KEY-" + std::to_string(i);
            storage.set_license(license);
            storage.get_license();
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // Just verifying no crashes/deadlocks
    SUCCEED();
}

// ==================== FileStorage Tests ====================

class FileStorageTest : public ::testing::Test {
  protected:
    TempDirectory temp_dir;
};

TEST_F(FileStorageTest, InitiallyEmpty) {
    FileStorage storage(temp_dir.path().string());

    EXPECT_FALSE(storage.get_license().has_value());
    EXPECT_FALSE(storage.get_offline_token().has_value());
    EXPECT_FALSE(storage.get_signing_key("any").has_value());
    EXPECT_FALSE(storage.get_last_seen_timestamp().has_value());
}

TEST_F(FileStorageTest, SetAndGetLicense) {
    FileStorage storage(temp_dir.path().string());

    CachedLicense license;
    license.license_key = "KEY-FILE-123";
    license.device_id = "device-file-abc";
    license.activated_at = std::chrono::system_clock::now();
    license.last_validated = std::chrono::system_clock::now();

    ValidationResult validation;
    validation.valid = true;
    validation.message = "Success";
    validation.code = "ok";
    license.validation = validation;

    EXPECT_TRUE(storage.set_license(license));

    auto retrieved = storage.get_license();
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved->license_key, "KEY-FILE-123");
    EXPECT_EQ(retrieved->device_id, "device-file-abc");
    ASSERT_TRUE(retrieved->validation.has_value());
    EXPECT_TRUE(retrieved->validation->valid);
}

TEST_F(FileStorageTest, LicensePersistsAcrossInstances) {
    {
        FileStorage storage(temp_dir.path().string());

        CachedLicense license;
        license.license_key = "PERSISTENT-KEY";
        storage.set_license(license);
    }

    // Create new instance
    FileStorage storage2(temp_dir.path().string());
    auto retrieved = storage2.get_license();

    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved->license_key, "PERSISTENT-KEY");
}

TEST_F(FileStorageTest, ClearLicense) {
    FileStorage storage(temp_dir.path().string());

    CachedLicense license;
    license.license_key = "KEY-TO-CLEAR";
    storage.set_license(license);

    storage.clear_license();

    EXPECT_FALSE(storage.get_license().has_value());
}

TEST_F(FileStorageTest, SetAndGetOfflineToken) {
    FileStorage storage(temp_dir.path().string());

    OfflineToken offline;
    offline.token.license_key = "OFFLINE-KEY";
    offline.token.product_slug = "test-product";
    offline.token.plan_key = "enterprise";
    offline.token.kid = "key-123";
    offline.token.seat_limit = 10;
    offline.token.iat = std::time(nullptr);
    offline.token.exp = std::time(nullptr) + 86400 * 365;
    offline.token.nbf = offline.token.iat;
    offline.signature.key_id = "key-123";
    offline.signature.value = "base64-signature";
    offline.canonical = R"({"license_key":"OFFLINE-KEY"})";

    Entitlement ent;
    ent.key = "updates";
    offline.token.entitlements.push_back(ent);

    EXPECT_TRUE(storage.set_offline_token(offline));

    auto retrieved = storage.get_offline_token();
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved->token.license_key, "OFFLINE-KEY");
    EXPECT_EQ(retrieved->token.product_slug, "test-product");
    EXPECT_TRUE(retrieved->token.seat_limit.has_value());
    EXPECT_EQ(retrieved->token.seat_limit.value(), 10);
    ASSERT_EQ(retrieved->token.entitlements.size(), static_cast<size_t>(1));
    EXPECT_EQ(retrieved->token.entitlements[0].key, "updates");
}

TEST_F(FileStorageTest, SetAndGetMachineFile) {
    FileStorage storage(temp_dir.path().string());

    MachineFile machine_file;
    machine_file.certificate = "-----BEGIN MACHINE FILE-----\nabc\n-----END MACHINE FILE-----";
    machine_file.algorithm = "aes-256-gcm+ed25519";
    machine_file.ttl = 2592000;
    machine_file.license_key = "KEY-789";
    machine_file.fingerprint = "fp-123";
    machine_file.issued_at = std::chrono::system_clock::now();
    machine_file.expires_at = std::chrono::system_clock::now() + std::chrono::hours(24);

    EXPECT_TRUE(storage.set_machine_file(machine_file));

    auto retrieved = storage.get_machine_file();
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved->license_key, "KEY-789");
    EXPECT_EQ(retrieved->fingerprint, "fp-123");
    EXPECT_EQ(retrieved->algorithm, "aes-256-gcm+ed25519");
    EXPECT_EQ(retrieved->ttl, 2592000);
    EXPECT_TRUE(retrieved->issued_at.has_value());
    EXPECT_TRUE(retrieved->expires_at.has_value());
}

TEST_F(FileStorageTest, SetAndGetSigningKey) {
    FileStorage storage(temp_dir.path().string());

    std::string public_key_b64 = "MCowBQYDK2VwAyEA+test+public+key+";

    EXPECT_TRUE(storage.set_signing_key("signing-key-1", public_key_b64));

    auto retrieved = storage.get_signing_key("signing-key-1");
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(*retrieved, public_key_b64);
}

TEST_F(FileStorageTest, SetAndGetTimestamp) {
    FileStorage storage(temp_dir.path().string());

    double timestamp = 1704067200.5;

    EXPECT_TRUE(storage.set_last_seen_timestamp(timestamp));

    auto retrieved = storage.get_last_seen_timestamp();
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_DOUBLE_EQ(*retrieved, timestamp);
}

TEST_F(FileStorageTest, ClearAll) {
    FileStorage storage(temp_dir.path().string());

    CachedLicense license;
    license.license_key = "KEY";
    storage.set_license(license);

    OfflineToken offline;
    offline.token.license_key = "OFFLINE";
    storage.set_offline_token(offline);

    MachineFile machine_file;
    machine_file.license_key = "MACHINE";
    storage.set_machine_file(machine_file);

    storage.set_signing_key("key-1", "pk-1");
    storage.set_last_seen_timestamp(123.0);

    storage.clear_all();

    EXPECT_FALSE(storage.get_license().has_value());
    EXPECT_FALSE(storage.get_offline_token().has_value());
    EXPECT_FALSE(storage.get_machine_file().has_value());
    EXPECT_FALSE(storage.get_signing_key("key-1").has_value());
    EXPECT_FALSE(storage.get_last_seen_timestamp().has_value());
}

TEST_F(FileStorageTest, CustomPrefix) {
    FileStorage storage1(temp_dir.path().string(), "app1");
    FileStorage storage2(temp_dir.path().string(), "app2");

    CachedLicense license1;
    license1.license_key = "KEY-APP1";
    storage1.set_license(license1);

    CachedLicense license2;
    license2.license_key = "KEY-APP2";
    storage2.set_license(license2);

    auto retrieved1 = storage1.get_license();
    auto retrieved2 = storage2.get_license();

    ASSERT_TRUE(retrieved1.has_value());
    ASSERT_TRUE(retrieved2.has_value());
    EXPECT_EQ(retrieved1->license_key, "KEY-APP1");
    EXPECT_EQ(retrieved2->license_key, "KEY-APP2");
}

TEST_F(FileStorageTest, HandlesCorruptedFile) {
    // Write garbage to the license file
    auto license_path = temp_dir.path() / "licenseseat_license.json";
    std::ofstream file(license_path);
    file << "this is not valid json {{{";
    file.close();

    FileStorage storage(temp_dir.path().string());

    // Should return nullopt, not crash
    auto result = storage.get_license();
    EXPECT_FALSE(result.has_value());
}

TEST_F(FileStorageTest, CreatesDirectoryIfNotExists) {
    auto new_dir = temp_dir.path() / "nested" / "directory";

    FileStorage storage(new_dir.string());

    CachedLicense license;
    license.license_key = "KEY";

    EXPECT_TRUE(storage.set_license(license));
    EXPECT_TRUE(std::filesystem::exists(new_dir));
}

// ==================== Full License Data Serialization Tests ====================

TEST_F(FileStorageTest, SerializesFullLicenseData) {
    FileStorage storage(temp_dir.path().string());

    // Create a full license
    License license(
        "LS-TEST-KEY",
        LicenseStatus::Active,
        LicenseMode::HardwareLocked,
        "pro-annual",
        std::optional<int>(5),
        2,
        std::nullopt,
        std::nullopt,
        std::vector<Entitlement>{},
        Metadata{{"customer_id", "cust_123"}},
        Product{"test-product", "Test Product"}
    );

    CachedLicense cached;
    cached.license_key = "LS-TEST-KEY";
    cached.device_id = "device-001";
    cached.activated_at = std::chrono::system_clock::now();
    cached.last_validated = std::chrono::system_clock::now();
    cached.license_data = license;

    ValidationResult validation;
    validation.valid = true;
    validation.offline = false;
    cached.validation = validation;

    EXPECT_TRUE(storage.set_license(cached));

    auto result = storage.get_license();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->license_key, "LS-TEST-KEY");
    EXPECT_EQ(result->device_id, "device-001");

    // Verify full license data is restored
    ASSERT_TRUE(result->license_data.has_value());
    EXPECT_EQ(result->license_data->key(), "LS-TEST-KEY");
    EXPECT_EQ(result->license_data->status(), LicenseStatus::Active);
    EXPECT_EQ(result->license_data->mode(), LicenseMode::HardwareLocked);
    EXPECT_EQ(result->license_data->plan_key(), "pro-annual");
    ASSERT_TRUE(result->license_data->seat_limit().has_value());
    EXPECT_EQ(*result->license_data->seat_limit(), 5);
    EXPECT_EQ(result->license_data->active_seats(), 2);
    EXPECT_EQ(result->license_data->product().slug, "test-product");
    EXPECT_EQ(result->license_data->product().name, "Test Product");

    // Verify metadata is restored
    auto& meta = result->license_data->metadata();
    ASSERT_TRUE(meta.count("customer_id") > 0);
    EXPECT_EQ(meta.at("customer_id"), "cust_123");
}

TEST_F(FileStorageTest, SerializesValidationOfflineFlag) {
    FileStorage storage(temp_dir.path().string());

    CachedLicense cached;
    cached.license_key = "KEY";
    cached.device_id = "device";
    cached.activated_at = std::chrono::system_clock::now();
    cached.last_validated = std::chrono::system_clock::now();

    ValidationResult validation;
    validation.valid = true;
    validation.offline = true;
    validation.code = "offline_verified";
    validation.message = "Verified offline";
    cached.validation = validation;

    EXPECT_TRUE(storage.set_license(cached));

    auto result = storage.get_license();
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->validation.has_value());
    EXPECT_TRUE(result->validation->valid);
    EXPECT_TRUE(result->validation->offline);
    EXPECT_EQ(result->validation->code, "offline_verified");
    EXPECT_EQ(result->validation->message, "Verified offline");
}

TEST_F(FileStorageTest, HandlesLicenseWithEntitlements) {
    FileStorage storage(temp_dir.path().string());

    std::vector<Entitlement> entitlements = {
        {"updates", std::nullopt, {}},
        {"premium", std::nullopt, {{"tier", "gold"}}}
    };

    License license(
        "LS-ENT-KEY",
        LicenseStatus::Active,
        LicenseMode::HardwareLocked,
        "pro",
        std::nullopt,
        1,
        std::nullopt,
        std::nullopt,
        entitlements,
        {},
        Product{"prod", "Product"}
    );

    CachedLicense cached;
    cached.license_key = "LS-ENT-KEY";
    cached.device_id = "device";
    cached.activated_at = std::chrono::system_clock::now();
    cached.last_validated = std::chrono::system_clock::now();
    cached.license_data = license;

    EXPECT_TRUE(storage.set_license(cached));

    auto result = storage.get_license();
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->license_data.has_value());

    auto& ents = result->license_data->active_entitlements();
    EXPECT_EQ(ents.size(), static_cast<size_t>(2));
    EXPECT_EQ(ents[0].key, "updates");
    EXPECT_EQ(ents[1].key, "premium");
    ASSERT_TRUE(ents[1].metadata.count("tier") > 0);
    EXPECT_EQ(ents[1].metadata.at("tier"), "gold");
}

}  // namespace
}  // namespace licenseseat
