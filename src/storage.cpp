#include "licenseseat/storage.hpp"
#include "licenseseat/json.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <fstream>

namespace licenseseat {

// ==================== FileStorage Implementation ====================

FileStorage::FileStorage(const std::string& storage_path, const std::string& prefix)
    : storage_path_(storage_path), prefix_(prefix) {
    ensure_directory();
}

std::filesystem::path FileStorage::get_license_path() const {
    return storage_path_ / (prefix_ + "_license.json");
}

std::filesystem::path FileStorage::get_offline_token_path() const {
    return storage_path_ / (prefix_ + "_offline_token.json");
}

std::filesystem::path FileStorage::get_signing_key_path(const std::string& key_id) const {
    // Sanitize key_id for filename
    std::string safe_key_id = key_id;
    for (char& c : safe_key_id) {
        if (!std::isalnum(c) && c != '_' && c != '-') {
            c = '_';
        }
    }
    return storage_path_ / (prefix_ + "_signing_key_" + safe_key_id + ".json");
}

std::filesystem::path FileStorage::get_timestamp_path() const {
    return storage_path_ / (prefix_ + "_timestamp.json");
}

bool FileStorage::ensure_directory() const {
    try {
        if (!std::filesystem::exists(storage_path_)) {
            return std::filesystem::create_directories(storage_path_);
        }
        return true;
    } catch (...) {
        return false;
    }
}

bool FileStorage::write_file(const std::filesystem::path& path, const std::string& content) {
    try {
        std::ofstream file(path);
        if (!file.is_open()) {
            return false;
        }
        file << content;
        return true;
    } catch (...) {
        return false;
    }
}

std::optional<std::string> FileStorage::read_file(const std::filesystem::path& path) {
    try {
        if (!std::filesystem::exists(path)) {
            return std::nullopt;
        }
        std::ifstream file(path);
        if (!file.is_open()) {
            return std::nullopt;
        }
        std::string content((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
        return content;
    } catch (...) {
        return std::nullopt;
    }
}

bool FileStorage::set_license(const CachedLicense& license) {
    std::lock_guard<std::mutex> lock(mutex_);

    try {
        nlohmann::json j;
        j["license_key"] = license.license_key;
        j["device_id"] = license.device_id;
        j["activated_at"] =
            std::chrono::duration_cast<std::chrono::seconds>(license.activated_at.time_since_epoch())
                .count();
        j["last_validated"] = std::chrono::duration_cast<std::chrono::seconds>(
                                  license.last_validated.time_since_epoch())
                                  .count();

        if (license.validation) {
            j["validation"]["valid"] = license.validation->valid;
            j["validation"]["code"] = license.validation->code;
            j["validation"]["message"] = license.validation->message;
        }

        return write_file(get_license_path(), j.dump(2));
    } catch (...) {
        return false;
    }
}

std::optional<CachedLicense> FileStorage::get_license() {
    std::lock_guard<std::mutex> lock(mutex_);

    auto content = read_file(get_license_path());
    if (!content) {
        return std::nullopt;
    }

    try {
        auto j = nlohmann::json::parse(*content);

        CachedLicense license;
        license.license_key = j.value("license_key", "");
        license.device_id = j.value("device_id", "");

        auto activated_secs = j.value("activated_at", int64_t{0});
        license.activated_at = std::chrono::system_clock::time_point(
            std::chrono::seconds(activated_secs));

        auto validated_secs = j.value("last_validated", int64_t{0});
        license.last_validated = std::chrono::system_clock::time_point(
            std::chrono::seconds(validated_secs));

        if (j.contains("validation")) {
            ValidationResult validation;
            validation.valid = j["validation"].value("valid", false);
            validation.code = j["validation"].value("code", "");
            validation.message = j["validation"].value("message", "");
            license.validation = validation;
        }

        return license;
    } catch (...) {
        return std::nullopt;
    }
}

void FileStorage::clear_license() {
    std::lock_guard<std::mutex> lock(mutex_);
    try {
        std::filesystem::remove(get_license_path());
    } catch (...) {
    }
}

bool FileStorage::set_offline_token(const OfflineToken& offline) {
    std::lock_guard<std::mutex> lock(mutex_);

    try {
        nlohmann::json j;

        // Token payload
        j["token"]["schema_version"] = offline.token.schema_version;
        j["token"]["license_key"] = offline.token.license_key;
        j["token"]["product_slug"] = offline.token.product_slug;
        j["token"]["plan_key"] = offline.token.plan_key;
        j["token"]["mode"] = offline.token.mode;

        if (offline.token.seat_limit) {
            j["token"]["seat_limit"] = *offline.token.seat_limit;
        } else {
            j["token"]["seat_limit"] = nullptr;
        }

        if (offline.token.device_id) {
            j["token"]["device_id"] = *offline.token.device_id;
        } else {
            j["token"]["device_id"] = nullptr;
        }

        j["token"]["iat"] = offline.token.iat;
        j["token"]["exp"] = offline.token.exp;
        j["token"]["nbf"] = offline.token.nbf;

        if (offline.token.license_expires_at) {
            j["token"]["license_expires_at"] = *offline.token.license_expires_at;
        } else {
            j["token"]["license_expires_at"] = nullptr;
        }

        j["token"]["kid"] = offline.token.kid;

        // Serialize entitlements
        nlohmann::json ents = nlohmann::json::array();
        for (const auto& e : offline.token.entitlements) {
            nlohmann::json ent;
            ent["key"] = e.key;
            if (e.expires_at) {
                ent["expires_at"] = std::chrono::duration_cast<std::chrono::seconds>(
                                        e.expires_at->time_since_epoch())
                                        .count();
            } else {
                ent["expires_at"] = nullptr;
            }
            if (!e.metadata.empty()) {
                ent["metadata"] = json::metadata_to_json(e.metadata);
            }
            ents.push_back(ent);
        }
        j["token"]["entitlements"] = ents;

        if (!offline.token.metadata.empty()) {
            j["token"]["metadata"] = json::metadata_to_json(offline.token.metadata);
        }

        // Signature
        j["signature"]["algorithm"] = offline.signature.algorithm;
        j["signature"]["key_id"] = offline.signature.key_id;
        j["signature"]["value"] = offline.signature.value;

        // Canonical JSON (store as-is)
        j["canonical"] = offline.canonical;

        return write_file(get_offline_token_path(), j.dump(2));
    } catch (...) {
        return false;
    }
}

std::optional<OfflineToken> FileStorage::get_offline_token() {
    std::lock_guard<std::mutex> lock(mutex_);

    auto content = read_file(get_offline_token_path());
    if (!content) {
        return std::nullopt;
    }

    try {
        auto j = nlohmann::json::parse(*content);
        return json::parse_offline_token(j);
    } catch (...) {
        return std::nullopt;
    }
}

void FileStorage::clear_offline_token() {
    std::lock_guard<std::mutex> lock(mutex_);
    try {
        std::filesystem::remove(get_offline_token_path());
    } catch (...) {
    }
}

bool FileStorage::set_signing_key(const std::string& key_id, const std::string& public_key_b64) {
    std::lock_guard<std::mutex> lock(mutex_);

    try {
        nlohmann::json j;
        j["key_id"] = key_id;
        j["public_key"] = public_key_b64;
        return write_file(get_signing_key_path(key_id), j.dump(2));
    } catch (...) {
        return false;
    }
}

std::optional<std::string> FileStorage::get_signing_key(const std::string& key_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto content = read_file(get_signing_key_path(key_id));
    if (!content) {
        return std::nullopt;
    }

    try {
        auto j = nlohmann::json::parse(*content);
        return j.value("public_key", "");
    } catch (...) {
        return std::nullopt;
    }
}

bool FileStorage::set_last_seen_timestamp(double timestamp) {
    std::lock_guard<std::mutex> lock(mutex_);

    try {
        nlohmann::json j;
        j["timestamp"] = timestamp;
        return write_file(get_timestamp_path(), j.dump());
    } catch (...) {
        return false;
    }
}

std::optional<double> FileStorage::get_last_seen_timestamp() {
    std::lock_guard<std::mutex> lock(mutex_);

    auto content = read_file(get_timestamp_path());
    if (!content) {
        return std::nullopt;
    }

    try {
        auto j = nlohmann::json::parse(*content);
        return j.value("timestamp", 0.0);
    } catch (...) {
        return std::nullopt;
    }
}

void FileStorage::clear_all() {
    std::lock_guard<std::mutex> lock(mutex_);

    try {
        // Remove all files with our prefix
        for (const auto& entry : std::filesystem::directory_iterator(storage_path_)) {
            if (entry.path().filename().string().find(prefix_) == 0) {
                std::filesystem::remove(entry.path());
            }
        }
    } catch (...) {
    }
}

// ==================== MemoryStorage Implementation ====================

bool MemoryStorage::set_license(const CachedLicense& license) {
    std::lock_guard<std::mutex> lock(mutex_);
    license_ = license;
    return true;
}

std::optional<CachedLicense> MemoryStorage::get_license() {
    std::lock_guard<std::mutex> lock(mutex_);
    return license_;
}

void MemoryStorage::clear_license() {
    std::lock_guard<std::mutex> lock(mutex_);
    license_.reset();
}

bool MemoryStorage::set_offline_token(const OfflineToken& offline) {
    std::lock_guard<std::mutex> lock(mutex_);
    offline_token_ = offline;
    return true;
}

std::optional<OfflineToken> MemoryStorage::get_offline_token() {
    std::lock_guard<std::mutex> lock(mutex_);
    return offline_token_;
}

void MemoryStorage::clear_offline_token() {
    std::lock_guard<std::mutex> lock(mutex_);
    offline_token_.reset();
}

bool MemoryStorage::set_signing_key(const std::string& key_id, const std::string& public_key_b64) {
    std::lock_guard<std::mutex> lock(mutex_);
    signing_keys_[key_id] = public_key_b64;
    return true;
}

std::optional<std::string> MemoryStorage::get_signing_key(const std::string& key_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = signing_keys_.find(key_id);
    if (it != signing_keys_.end()) {
        return it->second;
    }
    return std::nullopt;
}

bool MemoryStorage::set_last_seen_timestamp(double timestamp) {
    std::lock_guard<std::mutex> lock(mutex_);
    last_seen_timestamp_ = timestamp;
    return true;
}

std::optional<double> MemoryStorage::get_last_seen_timestamp() {
    std::lock_guard<std::mutex> lock(mutex_);
    return last_seen_timestamp_;
}

void MemoryStorage::clear_all() {
    std::lock_guard<std::mutex> lock(mutex_);
    license_.reset();
    offline_token_.reset();
    signing_keys_.clear();
    last_seen_timestamp_.reset();
}

}  // namespace licenseseat
