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

std::filesystem::path FileStorage::get_offline_license_path() const {
    return storage_path_ / (prefix_ + "_offline.json");
}

std::filesystem::path FileStorage::get_public_key_path(const std::string& key_id) const {
    // Sanitize key_id for filename
    std::string safe_key_id = key_id;
    for (char& c : safe_key_id) {
        if (!std::isalnum(c) && c != '_' && c != '-') {
            c = '_';
        }
    }
    return storage_path_ / (prefix_ + "_pubkey_" + safe_key_id + ".json");
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
        j["device_identifier"] = license.device_identifier;
        j["activated_at"] =
            std::chrono::duration_cast<std::chrono::seconds>(license.activated_at.time_since_epoch())
                .count();
        j["last_validated"] = std::chrono::duration_cast<std::chrono::seconds>(
                                  license.last_validated.time_since_epoch())
                                  .count();

        if (license.validation) {
            j["validation"]["valid"] = license.validation->valid;
            j["validation"]["reason"] = license.validation->reason;
            j["validation"]["reason_code"] = license.validation->reason_code;
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
        license.device_identifier = j.value("device_identifier", "");

        auto activated_secs = j.value("activated_at", int64_t{0});
        license.activated_at = std::chrono::system_clock::time_point(
            std::chrono::seconds(activated_secs));

        auto validated_secs = j.value("last_validated", int64_t{0});
        license.last_validated = std::chrono::system_clock::time_point(
            std::chrono::seconds(validated_secs));

        if (j.contains("validation")) {
            ValidationResult validation;
            validation.valid = j["validation"].value("valid", false);
            validation.reason = j["validation"].value("reason", "");
            validation.reason_code = j["validation"].value("reason_code", "");
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

bool FileStorage::set_offline_license(const OfflineLicense& offline) {
    std::lock_guard<std::mutex> lock(mutex_);

    try {
        nlohmann::json j;
        j["license_key"] = offline.license_key;
        j["product_slug"] = offline.product_slug;
        j["plan_key"] = offline.plan_key;
        j["key_id"] = offline.key_id;
        j["signature_b64u"] = offline.signature_b64u;
        j["seat_limit"] = offline.seat_limit;

        if (offline.issued_at > 0) {
            j["issued_at"] = offline.issued_at;
        }
        if (offline.expires_at > 0) {
            j["expires_at"] = offline.expires_at;
        }

        // Serialize entitlements
        nlohmann::json ents = nlohmann::json::array();
        for (const auto& e : offline.entitlements) {
            nlohmann::json ent;
            ent["key"] = e.key;
            if (e.name) ent["name"] = *e.name;
            if (e.description) ent["description"] = *e.description;
            if (e.expires) {
                ent["expires_at"] = std::chrono::duration_cast<std::chrono::seconds>(
                                        e.expires->time_since_epoch())
                                        .count();
            }
            ents.push_back(ent);
        }
        j["entitlements"] = ents;

        return write_file(get_offline_license_path(), j.dump(2));
    } catch (...) {
        return false;
    }
}

std::optional<OfflineLicense> FileStorage::get_offline_license() {
    std::lock_guard<std::mutex> lock(mutex_);

    auto content = read_file(get_offline_license_path());
    if (!content) {
        return std::nullopt;
    }

    try {
        auto j = nlohmann::json::parse(*content);

        OfflineLicense offline;
        offline.license_key = j.value("license_key", "");
        offline.product_slug = j.value("product_slug", "");
        offline.plan_key = j.value("plan_key", "");
        offline.key_id = j.value("key_id", "");
        offline.signature_b64u = j.value("signature_b64u", "");
        offline.seat_limit = j.value("seat_limit", 0);
        offline.issued_at = j.value("issued_at", std::time_t{0});
        offline.expires_at = j.value("expires_at", std::time_t{0});

        if (j.contains("entitlements") && j["entitlements"].is_array()) {
            for (const auto& ent : j["entitlements"]) {
                Entitlement e;
                e.key = ent.value("key", "");
                if (ent.contains("name")) e.name = ent["name"].get<std::string>();
                if (ent.contains("description")) e.description = ent["description"].get<std::string>();
                if (ent.contains("expires_at")) {
                    auto secs = ent["expires_at"].get<int64_t>();
                    e.expires = std::chrono::system_clock::time_point(std::chrono::seconds(secs));
                }
                offline.entitlements.push_back(e);
            }
        }

        return offline;
    } catch (...) {
        return std::nullopt;
    }
}

void FileStorage::clear_offline_license() {
    std::lock_guard<std::mutex> lock(mutex_);
    try {
        std::filesystem::remove(get_offline_license_path());
    } catch (...) {
    }
}

bool FileStorage::set_public_key(const std::string& key_id, const std::string& public_key_b64) {
    std::lock_guard<std::mutex> lock(mutex_);

    try {
        nlohmann::json j;
        j["key_id"] = key_id;
        j["public_key_b64"] = public_key_b64;
        return write_file(get_public_key_path(key_id), j.dump(2));
    } catch (...) {
        return false;
    }
}

std::optional<std::string> FileStorage::get_public_key(const std::string& key_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto content = read_file(get_public_key_path(key_id));
    if (!content) {
        return std::nullopt;
    }

    try {
        auto j = nlohmann::json::parse(*content);
        return j.value("public_key_b64", "");
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

bool MemoryStorage::set_offline_license(const OfflineLicense& offline) {
    std::lock_guard<std::mutex> lock(mutex_);
    offline_license_ = offline;
    return true;
}

std::optional<OfflineLicense> MemoryStorage::get_offline_license() {
    std::lock_guard<std::mutex> lock(mutex_);
    return offline_license_;
}

void MemoryStorage::clear_offline_license() {
    std::lock_guard<std::mutex> lock(mutex_);
    offline_license_.reset();
}

bool MemoryStorage::set_public_key(const std::string& key_id, const std::string& public_key_b64) {
    std::lock_guard<std::mutex> lock(mutex_);
    public_keys_[key_id] = public_key_b64;
    return true;
}

std::optional<std::string> MemoryStorage::get_public_key(const std::string& key_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = public_keys_.find(key_id);
    if (it != public_keys_.end()) {
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
    offline_license_.reset();
    public_keys_.clear();
    last_seen_timestamp_.reset();
}

}  // namespace licenseseat
