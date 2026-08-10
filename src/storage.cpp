#include "licenseseat/storage.hpp"

#include "licenseseat/json.hpp"

#include "PicoSHA2/picosha2.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
#include <fstream>
#include <nlohmann/json.hpp>
#include <random>

#ifndef _WIN32
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

constexpr std::uintmax_t MAX_STORAGE_FILE_BYTES = 2 * 1024 * 1024;

bool safe_storage_name(const std::string& value, std::size_t maximum) {
    return !value.empty() && value.size() <= maximum &&
           std::all_of(value.begin(), value.end(), [](unsigned char character) {
               return (character >= 'a' && character <= 'z') ||
                      (character >= 'A' && character <= 'Z') ||
                      (character >= '0' && character <= '9') || character == '_' ||
                      character == '-';
           });
}

bool safe_text(const std::string& value, std::size_t minimum, std::size_t maximum) {
    return value.size() >= minimum && value.size() <= maximum &&
           std::none_of(value.begin(), value.end(), [](unsigned char character) {
               return character <= 0x1f || character == 0x7f;
           });
}

bool safe_key_id(const std::string& value) {
    return safe_text(value, 1, 255) &&
           std::all_of(value.begin(), value.end(), [](unsigned char character) {
               return (character >= 'a' && character <= 'z') ||
                      (character >= 'A' && character <= 'Z') ||
                      (character >= '0' && character <= '9') || character == '.' ||
                      character == '_' || character == ':' || character == '-';
           });
}

std::string key_id_digest(const std::string& key_id) {
    std::string digest;
    picosha2::hash256_hex_string(key_id, digest);
    return digest;
}

} // namespace

namespace licenseseat {

// ==================== FileStorage Implementation ====================

FileStorage::FileStorage(const std::string& storage_path, const std::string& prefix)
    : storage_path_(storage_path), prefix_(prefix) {
    if (!safe_storage_name(prefix_, 64))
        prefix_ = "licenseseat";
    ensure_directory();
}

std::filesystem::path FileStorage::get_license_path() const {
    return storage_path_ / (prefix_ + "_license.json");
}

std::filesystem::path FileStorage::get_offline_token_path() const {
    return storage_path_ / (prefix_ + "_offline_token.json");
}

std::filesystem::path FileStorage::get_machine_file_path() const {
    return storage_path_ / (prefix_ + "_machine_file.json");
}

std::filesystem::path FileStorage::get_signing_key_path(const std::string& key_id) const {
    return storage_path_ / (prefix_ + "_signing_key_" + key_id_digest(key_id) + ".json");
}

std::filesystem::path FileStorage::get_timestamp_path() const {
    return storage_path_ / (prefix_ + "_timestamp.json");
}

bool FileStorage::ensure_directory() const {
    try {
        const auto status = std::filesystem::symlink_status(storage_path_);
        if (std::filesystem::is_symlink(status))
            return false;
        if (!std::filesystem::exists(status)) {
            if (!std::filesystem::create_directories(storage_path_))
                return false;
        } else if (!std::filesystem::is_directory(status)) {
            return false;
        }
        std::error_code permissions_error;
        std::filesystem::permissions(storage_path_, std::filesystem::perms::owner_all,
                                     std::filesystem::perm_options::replace, permissions_error);
#ifndef _WIN32
        if (permissions_error)
            return false;
#endif
        return true;
    } catch (...) {
        return false;
    }
}

bool FileStorage::write_file(const std::filesystem::path& path, const std::string& content) {
    try {
        if (content.size() > MAX_STORAGE_FILE_BYTES || !ensure_directory())
            return false;
        const auto existing = std::filesystem::symlink_status(path);
        if (std::filesystem::is_symlink(existing) ||
            (std::filesystem::exists(existing) && !std::filesystem::is_regular_file(existing))) {
            return false;
        }

        std::random_device random;
        auto temporary = path;
#ifndef _WIN32
        int descriptor = -1;
        for (int attempt = 0; attempt < 16; ++attempt) {
            temporary = path;
            temporary += ".tmp." + std::to_string(random()) + "." + std::to_string(random());
            descriptor = ::open(temporary.c_str(),
                                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
            if (descriptor >= 0)
                break;
            if (errno != EEXIST)
                return false;
        }
        if (descriptor < 0)
            return false;

        bool write_succeeded = true;
        std::size_t written = 0;
        while (written < content.size()) {
            const auto result =
                ::write(descriptor, content.data() + written, content.size() - written);
            if (result > 0) {
                written += static_cast<std::size_t>(result);
            } else if (result < 0 && errno == EINTR) {
                continue;
            } else {
                write_succeeded = false;
                break;
            }
        }
        if (write_succeeded && ::fsync(descriptor) != 0)
            write_succeeded = false;
        if (::close(descriptor) != 0)
            write_succeeded = false;
        if (!write_succeeded) {
            std::filesystem::remove(temporary);
            return false;
        }

        if (::rename(temporary.c_str(), path.c_str()) != 0) {
            std::filesystem::remove(temporary);
            return false;
        }

        // Best-effort directory synchronization makes the atomic rename durable
        // across a sudden power loss on filesystems that support directory fsync.
        const int directory = ::open(storage_path_.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY);
        if (directory >= 0) {
            (void)::fsync(directory);
            (void)::close(directory);
        }
        return true;
#else
        temporary += ".tmp." + std::to_string(random()) + "." + std::to_string(random());
        std::ofstream file(temporary, std::ios::binary | std::ios::trunc);
        if (!file.is_open()) {
            return false;
        }
        file.write(content.data(), static_cast<std::streamsize>(content.size()));
        file.flush();
        if (!file.good()) {
            file.close();
            std::filesystem::remove(temporary);
            return false;
        }
        file.close();

        std::error_code permissions_error;
        std::filesystem::permissions(
            temporary, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace, permissions_error);
#ifndef _WIN32
        if (permissions_error) {
            std::filesystem::remove(temporary);
            return false;
        }
#endif

        std::error_code rename_error;
        std::filesystem::rename(temporary, path, rename_error);
#ifdef _WIN32
        if (rename_error) {
            std::error_code remove_error;
            std::filesystem::remove(path, remove_error);
            rename_error.clear();
            std::filesystem::rename(temporary, path, rename_error);
        }
#endif
        if (rename_error) {
            std::filesystem::remove(temporary);
            return false;
        }
        return true;
#endif
    } catch (...) {
        return false;
    }
}

std::optional<std::string> FileStorage::read_file(const std::filesystem::path& path) {
    try {
        const auto status = std::filesystem::symlink_status(path);
        if (!std::filesystem::exists(status) || std::filesystem::is_symlink(status) ||
            !std::filesystem::is_regular_file(status))
            return std::nullopt;

#ifndef _WIN32
        const int descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (descriptor < 0)
            return std::nullopt;

        struct stat file_status{};
        if (::fstat(descriptor, &file_status) != 0 || !S_ISREG(file_status.st_mode) ||
            file_status.st_size < 0 ||
            static_cast<std::uintmax_t>(file_status.st_size) > MAX_STORAGE_FILE_BYTES) {
            (void)::close(descriptor);
            return std::nullopt;
        }

        std::string content(static_cast<std::size_t>(file_status.st_size), '\0');
        std::size_t received = 0;
        while (received < content.size()) {
            const auto result =
                ::read(descriptor, content.data() + received, content.size() - received);
            if (result > 0) {
                received += static_cast<std::size_t>(result);
            } else if (result < 0 && errno == EINTR) {
                continue;
            } else {
                (void)::close(descriptor);
                return std::nullopt;
            }
        }

        char unexpected = '\0';
        ssize_t extra = 0;
        do {
            extra = ::read(descriptor, &unexpected, 1);
        } while (extra < 0 && errno == EINTR);
        if (::close(descriptor) != 0 || extra != 0)
            return std::nullopt;
        return content;
#else
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            return std::nullopt;
        }

        // Size the already-open stream, rather than trusting a separate file_size()
        // result. Read only the measured number of bytes and reject a concurrently
        // growing file instead of letting an iterator allocate without a bound.
        const auto end = file.tellg();
        if (end < 0 || static_cast<std::uintmax_t>(end) > MAX_STORAGE_FILE_BYTES) {
            return std::nullopt;
        }
        file.seekg(0, std::ios::beg);
        if (!file.good())
            return std::nullopt;

        std::string content(static_cast<std::size_t>(end), '\0');
        if (!content.empty()) {
            file.read(content.data(), static_cast<std::streamsize>(content.size()));
            if (file.gcount() != static_cast<std::streamsize>(content.size())) {
                return std::nullopt;
            }
        }

        char unexpected = '\0';
        if (file.get(unexpected))
            return std::nullopt;
        return content;
#endif
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
        j["activated_at"] = std::chrono::duration_cast<std::chrono::seconds>(
                                license.activated_at.time_since_epoch())
                                .count();
        j["last_validated"] = std::chrono::duration_cast<std::chrono::seconds>(
                                  license.last_validated.time_since_epoch())
                                  .count();

        if (license.validation) {
            j["validation"]["valid"] = license.validation->valid;
            j["validation"]["code"] = license.validation->code;
            j["validation"]["message"] = license.validation->message;
            j["validation"]["offline"] = license.validation->offline;
        }

        // Serialize the full license data for session restore
        if (license.license_data) {
            j["license_data"] = json::license_to_json(*license.license_data);
        }

        return write_file(get_license_path(), j.dump(2));
    } catch (...) {
        return false;
    }
}

std::optional<CachedLicense> FileStorage::get_license() {
#ifdef _WIN32
    // The C++17 Windows fallback replaces an existing destination via a
    // remove/rename sequence. Keep same-instance readers serialized with that
    // sequence. POSIX readers intentionally remain lock-free: rename(2) is
    // atomic and an already-open descriptor continues to name a complete old
    // snapshot, so no blocking filesystem read needs to hold the mutex.
    std::lock_guard<std::mutex> lock(mutex_);
#endif

    auto content = read_file(get_license_path());
    if (!content) {
        return std::nullopt;
    }

    try {
        auto j = json::parse_strict(*content);
        if (!j.is_object())
            return std::nullopt;

        CachedLicense license;
        license.license_key = j.value("license_key", "");
        license.device_id = j.value("device_id", "");
        if (!safe_text(license.license_key, 1, 512) ||
            (!license.device_id.empty() && !safe_text(license.device_id, 1, 255)))
            return std::nullopt;

        auto activated_secs = j.value("activated_at", int64_t{0});
        auto validated_secs = j.value("last_validated", int64_t{0});
        constexpr int64_t max_unix_timestamp = 253402300799LL;
        if (activated_secs < 0 || activated_secs > max_unix_timestamp || validated_secs < 0 ||
            validated_secs > max_unix_timestamp)
            return std::nullopt;
        license.activated_at =
            std::chrono::system_clock::time_point(std::chrono::seconds(activated_secs));

        license.last_validated =
            std::chrono::system_clock::time_point(std::chrono::seconds(validated_secs));

        if (j.contains("validation")) {
            ValidationResult validation;
            validation.valid = j["validation"].value("valid", false);
            validation.code = j["validation"].value("code", "");
            validation.message = j["validation"].value("message", "");
            validation.offline = j["validation"].value("offline", false);
            license.validation = validation;
        }

        // Deserialize the full license data for session restore
        if (j.contains("license_data") && j["license_data"].is_object()) {
            license.license_data = json::parse_license(j["license_data"]);
            if (license.license_data->key() != license.license_key)
                return std::nullopt;
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
    } catch (...) {}
}

bool FileStorage::set_offline_token(const OfflineToken& offline) {
    std::lock_guard<std::mutex> lock(mutex_);

    try {
        return write_file(get_offline_token_path(), json::offline_token_to_json(offline));
    } catch (...) {
        return false;
    }
}

std::optional<OfflineToken> FileStorage::get_offline_token() {
#ifdef _WIN32
    std::lock_guard<std::mutex> lock(mutex_);
#endif

    auto content = read_file(get_offline_token_path());
    if (!content) {
        return std::nullopt;
    }

    try {
        return json::offline_token_from_json(*content);
    } catch (...) {
        return std::nullopt;
    }
}

void FileStorage::clear_offline_token() {
    std::lock_guard<std::mutex> lock(mutex_);
    try {
        std::filesystem::remove(get_offline_token_path());
    } catch (...) {}
}

bool FileStorage::set_machine_file(const MachineFile& machine_file) {
    std::lock_guard<std::mutex> lock(mutex_);

    try {
        if (machine_file.certificate.size() > MAX_STORAGE_FILE_BYTES ||
            (!machine_file.license_key.empty() && !safe_text(machine_file.license_key, 1, 512)) ||
            (!machine_file.fingerprint.empty() && !safe_text(machine_file.fingerprint, 1, 255)))
            return false;
        nlohmann::json j;
        j["certificate"] = machine_file.certificate;
        j["algorithm"] = machine_file.algorithm;
        j["ttl"] = machine_file.ttl;
        j["license_key"] = machine_file.license_key;
        j["fingerprint"] = machine_file.fingerprint;
        if (machine_file.issued_at.has_value()) {
            j["issued_at"] = json::format_timestamp(*machine_file.issued_at);
        } else {
            j["issued_at"] = nullptr;
        }
        if (machine_file.expires_at.has_value()) {
            j["expires_at"] = json::format_timestamp(*machine_file.expires_at);
        } else {
            j["expires_at"] = nullptr;
        }

        return write_file(get_machine_file_path(), j.dump(2));
    } catch (...) {
        return false;
    }
}

std::optional<MachineFile> FileStorage::get_machine_file() {
#ifdef _WIN32
    std::lock_guard<std::mutex> lock(mutex_);
#endif

    auto content = read_file(get_machine_file_path());
    if (!content) {
        return std::nullopt;
    }

    try {
        auto j = json::parse_strict(*content);
        if (!j.is_object())
            return std::nullopt;
        MachineFile machine_file;
        machine_file.certificate = j.value("certificate", "");
        machine_file.algorithm = j.value("algorithm", machine_file.algorithm);
        machine_file.ttl = j.value("ttl", int64_t{0});
        machine_file.license_key = j.value("license_key", "");
        machine_file.fingerprint = j.value("fingerprint", "");
        if (machine_file.certificate.size() > MAX_STORAGE_FILE_BYTES ||
            machine_file.algorithm != "aes-256-gcm+ed25519" || machine_file.ttl < 0 ||
            (!machine_file.license_key.empty() && !safe_text(machine_file.license_key, 1, 512)) ||
            (!machine_file.fingerprint.empty() && !safe_text(machine_file.fingerprint, 1, 255)))
            return std::nullopt;
        if (j.contains("issued_at") && !j["issued_at"].is_null()) {
            machine_file.issued_at = json::parse_timestamp(j["issued_at"].get<std::string>());
            if (!machine_file.issued_at.has_value())
                return std::nullopt;
        }
        if (j.contains("expires_at") && !j["expires_at"].is_null()) {
            machine_file.expires_at = json::parse_timestamp(j["expires_at"].get<std::string>());
            if (!machine_file.expires_at.has_value())
                return std::nullopt;
        }
        return machine_file;
    } catch (...) {
        return std::nullopt;
    }
}

void FileStorage::clear_machine_file() {
    std::lock_guard<std::mutex> lock(mutex_);
    try {
        std::filesystem::remove(get_machine_file_path());
    } catch (...) {}
}

bool FileStorage::set_signing_key(const std::string& key_id, const std::string& public_key_b64) {
    std::lock_guard<std::mutex> lock(mutex_);

    try {
        if (!safe_key_id(key_id) || !safe_text(public_key_b64, 1, 1024))
            return false;
        nlohmann::json j;
        j["key_id"] = key_id;
        j["public_key"] = public_key_b64;
        return write_file(get_signing_key_path(key_id), j.dump(2));
    } catch (...) {
        return false;
    }
}

std::optional<std::string> FileStorage::get_signing_key(const std::string& key_id) {
#ifdef _WIN32
    std::lock_guard<std::mutex> lock(mutex_);
#endif

    if (!safe_key_id(key_id))
        return std::nullopt;

    auto content = read_file(get_signing_key_path(key_id));
    if (!content) {
        return std::nullopt;
    }

    try {
        auto j = json::parse_strict(*content);
        if (!j.is_object() || j.value("key_id", std::string{}) != key_id)
            return std::nullopt;
        const auto key = j.value("public_key", std::string{});
        return safe_text(key, 1, 1024) ? std::optional<std::string>(key) : std::nullopt;
    } catch (...) {
        return std::nullopt;
    }
}

bool FileStorage::set_last_seen_timestamp(double timestamp) {
    std::lock_guard<std::mutex> lock(mutex_);

    try {
        if (!std::isfinite(timestamp) || timestamp < 0.0 || timestamp > 253402300799.0) {
            return false;
        }
        nlohmann::json j;
        j["timestamp"] = timestamp;
        return write_file(get_timestamp_path(), j.dump());
    } catch (...) {
        return false;
    }
}

std::optional<double> FileStorage::get_last_seen_timestamp() {
#ifdef _WIN32
    std::lock_guard<std::mutex> lock(mutex_);
#endif

    auto content = read_file(get_timestamp_path());
    if (!content) {
        return std::nullopt;
    }

    try {
        auto j = json::parse_strict(*content);
        const auto timestamp = j.value("timestamp", -1.0);
        if (!std::isfinite(timestamp) || timestamp < 0.0 || timestamp > 253402300799.0) {
            return std::nullopt;
        }
        return timestamp;
    } catch (...) {
        return std::nullopt;
    }
}

void FileStorage::clear_all() {
    std::lock_guard<std::mutex> lock(mutex_);

    try {
        const std::string signing_prefix = prefix_ + "_signing_key_";
        for (const auto& entry : std::filesystem::directory_iterator(storage_path_)) {
            const auto filename = entry.path().filename().string();
            const bool fixed_file = filename == prefix_ + "_license.json" ||
                                    filename == prefix_ + "_offline_token.json" ||
                                    filename == prefix_ + "_machine_file.json" ||
                                    filename == prefix_ + "_timestamp.json";
            const bool signing_file =
                filename.size() == signing_prefix.size() + 64 + 5 &&
                filename.compare(0, signing_prefix.size(), signing_prefix) == 0 &&
                filename.compare(filename.size() - 5, 5, ".json") == 0;
            if (fixed_file || signing_file) {
                std::filesystem::remove(entry.path());
            }
        }
    } catch (...) {}
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

bool MemoryStorage::set_machine_file(const MachineFile& machine_file) {
    std::lock_guard<std::mutex> lock(mutex_);
    machine_file_ = machine_file;
    return true;
}

std::optional<MachineFile> MemoryStorage::get_machine_file() {
    std::lock_guard<std::mutex> lock(mutex_);
    return machine_file_;
}

void MemoryStorage::clear_machine_file() {
    std::lock_guard<std::mutex> lock(mutex_);
    machine_file_.reset();
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
    machine_file_.reset();
    signing_keys_.clear();
    last_seen_timestamp_.reset();
}

} // namespace licenseseat
