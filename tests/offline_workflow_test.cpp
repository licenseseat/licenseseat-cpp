/**
 * Offline Workflow Test
 *
 * Demonstrates automatic and manual offline workflows with machine files
 * as the preferred artifact and offline tokens as a compatibility fallback.
 *
 * Environment variables:
 *   LICENSESEAT_API_KEY        - API key
 *   LICENSESEAT_PRODUCT_SLUG   - Product slug
 *   LICENSESEAT_LICENSE_KEY    - License key to test
 */

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <licenseseat/json.hpp>
#include <licenseseat/licenseseat.hpp>

namespace fs = std::filesystem;

struct TestConfig {
    std::string api_key;
    std::string product_slug;
    std::string license_key;
    std::string storage_path;

    static TestConfig from_env() {
        TestConfig cfg;
        auto get_env = [](const char* name) -> std::string {
            const char* val = std::getenv(name);
            return val ? val : "";
        };

        cfg.api_key = get_env("LICENSESEAT_API_KEY");
        cfg.product_slug = get_env("LICENSESEAT_PRODUCT_SLUG");
        cfg.license_key = get_env("LICENSESEAT_LICENSE_KEY");

        if (cfg.api_key.empty() || cfg.product_slug.empty() || cfg.license_key.empty()) {
            std::cerr << "Missing: LICENSESEAT_API_KEY, LICENSESEAT_PRODUCT_SLUG, LICENSESEAT_LICENSE_KEY\n";
            std::exit(1);
        }

        cfg.storage_path = fs::temp_directory_path() / "licenseseat_test";
        fs::create_directories(cfg.storage_path);
        return cfg;
    }
};

// Test 1: Automatic storage (recommended)
bool test_automatic() {
    std::cout << "\n=== Test: Automatic Storage (Machine File Preferred) ===\n";
    auto cfg = TestConfig::from_env();

    licenseseat::Config client_cfg;
    client_cfg.api_key = cfg.api_key;
    client_cfg.product_slug = cfg.product_slug;
    client_cfg.storage_path = cfg.storage_path;

    licenseseat::Client client(client_cfg);

    // Just activate - SDK handles offline sync automatically
    auto result = client.activate(cfg.license_key);
    if (result.is_error()) {
        std::cerr << "FAIL: " << result.error_message() << "\n";
        return false;
    }

    std::cout << "OK: Activated. Offline assets synced automatically.\n";

    // Verify files were created
    for (const auto& entry : fs::directory_iterator(cfg.storage_path)) {
        std::cout << "  Cached: " << entry.path().filename().string() << "\n";
    }

    return true;
}

// Test 2: Manual storage with explicit machine-file checkout and token fallback
bool test_manual() {
    std::cout << "\n=== Test: Manual Storage ===\n";
    auto cfg = TestConfig::from_env();

    licenseseat::Config client_cfg;
    client_cfg.api_key = cfg.api_key;
    client_cfg.product_slug = cfg.product_slug;

    licenseseat::Client client(client_cfg);

    // Manual offline issuance still requires an activation first.
    auto activation_result = client.activate(cfg.license_key);
    if (activation_result.is_error() &&
        activation_result.error_code() != licenseseat::ErrorCode::DeviceAlreadyActivated) {
        std::cerr << "FAIL: " << activation_result.error_message() << "\n";
        return false;
    }

    // Preferred path: checkout and persist a machine file
    auto machine_result = client.checkout_machine_file(cfg.license_key);
    if (machine_result.is_error()) {
        std::cerr << "FAIL: " << machine_result.error_message() << "\n";
        return false;
    }
    auto machine_file = machine_result.value();

    std::ofstream machine_out(fs::path(cfg.storage_path) / "machine_file.cert");
    machine_out << machine_file.certificate;
    machine_out.close();

    licenseseat::MachineFile loaded_machine_file = machine_file;
    std::ifstream machine_in(fs::path(cfg.storage_path) / "machine_file.cert");
    loaded_machine_file.certificate.assign(std::istreambuf_iterator<char>(machine_in),
                                           std::istreambuf_iterator<char>());

    auto machine_verify = client.verify_machine_file(loaded_machine_file);
    if (machine_verify.is_error() || !machine_verify.value().valid ||
        !machine_verify.value().payload.has_value()) {
        std::cerr << "FAIL: Machine file verification failed\n";
        return false;
    }

    std::cout << "OK: Verified machine file offline\n";
    std::cout << "  License: " << machine_verify.value().payload->license_key << "\n";
    if (machine_verify.value().payload->license) {
        std::cout << "  Plan: " << machine_verify.value().payload->license->plan_key() << "\n";
    }

    // Compatibility fallback: generate and serialize an offline token too
    auto token_result = client.generate_offline_token(cfg.license_key);
    if (token_result.is_error()) {
        std::cerr << "FAIL: " << token_result.error_message() << "\n";
        return false;
    }
    auto token = token_result.value();

    auto key_result = client.fetch_signing_key(token.token.kid);
    if (key_result.is_error()) {
        std::cerr << "FAIL: " << key_result.error_message() << "\n";
        return false;
    }
    auto public_key = key_result.value();

    std::string json_str = licenseseat::json::offline_token_to_json(token);
    std::cout << "OK: Serialized fallback token (" << json_str.size() << " bytes)\n";

    auto loaded = licenseseat::json::offline_token_from_json(json_str);

    auto verify = client.verify_offline_token(loaded, public_key);
    if (verify.is_error() || !verify.value()) {
        std::cerr << "FAIL: Fallback token verification failed\n";
        return false;
    }

    std::cout << "OK: Verified fallback token offline\n";
    std::cout << "  License: " << loaded.token.license_key << "\n";
    std::cout << "  Plan: " << loaded.token.plan_key << "\n";

    // Access metadata
    for (const auto& [k, v] : loaded.token.metadata) {
        std::cout << "  Metadata: " << k << " = " << v << "\n";
    }

    return true;
}

int main() {
    std::cout << "LicenseSeat C++ SDK - Offline Workflow Test\n";

    int passed = 0, failed = 0;

    test_automatic() ? passed++ : failed++;
    test_manual() ? passed++ : failed++;

    std::cout << "\nResult: " << passed << " passed, " << failed << " failed\n";

    // Cleanup
    auto cfg = TestConfig::from_env();
    fs::remove_all(cfg.storage_path);

    return failed == 0 ? 0 : 1;
}
