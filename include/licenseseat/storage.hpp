#pragma once

/**
 * @file storage.hpp
 * @brief License storage and caching for LicenseSeat SDK
 *
 * Provides persistent storage for licenses and offline assets.
 */

#include "licenseseat/licenseseat.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <string>

namespace licenseseat {

/**
 * @brief Cached license data with validation state
 */
struct CachedLicense {
    std::string license_key;
    std::string device_identifier;
    std::chrono::system_clock::time_point activated_at;
    std::chrono::system_clock::time_point last_validated;

    /// Last validation result
    std::optional<ValidationResult> validation;

    /// The full license data
    std::optional<License> license_data;
};

/**
 * @brief Storage interface for license persistence
 */
class StorageInterface {
  public:
    virtual ~StorageInterface() = default;

    /// Store a license
    virtual bool set_license(const CachedLicense& license) = 0;

    /// Retrieve stored license
    virtual std::optional<CachedLicense> get_license() = 0;

    /// Clear stored license
    virtual void clear_license() = 0;

    /// Store offline license data
    virtual bool set_offline_license(const OfflineLicense& offline) = 0;

    /// Retrieve offline license
    virtual std::optional<OfflineLicense> get_offline_license() = 0;

    /// Clear offline license
    virtual void clear_offline_license() = 0;

    /// Store public key
    virtual bool set_public_key(const std::string& key_id, const std::string& public_key_b64) = 0;

    /// Retrieve public key
    virtual std::optional<std::string> get_public_key(const std::string& key_id) = 0;

    /// Store last seen timestamp (for clock tamper detection)
    virtual bool set_last_seen_timestamp(double timestamp) = 0;

    /// Get last seen timestamp
    virtual std::optional<double> get_last_seen_timestamp() = 0;

    /// Clear all stored data
    virtual void clear_all() = 0;
};

/**
 * @brief File-based storage implementation
 *
 * Stores license data in JSON files in a specified directory.
 */
class FileStorage : public StorageInterface {
  public:
    /**
     * @brief Construct file storage
     *
     * @param storage_path Directory path for storage
     * @param prefix Optional prefix for file names
     */
    explicit FileStorage(const std::string& storage_path, const std::string& prefix = "licenseseat");

    bool set_license(const CachedLicense& license) override;
    std::optional<CachedLicense> get_license() override;
    void clear_license() override;

    bool set_offline_license(const OfflineLicense& offline) override;
    std::optional<OfflineLicense> get_offline_license() override;
    void clear_offline_license() override;

    bool set_public_key(const std::string& key_id, const std::string& public_key_b64) override;
    std::optional<std::string> get_public_key(const std::string& key_id) override;

    bool set_last_seen_timestamp(double timestamp) override;
    std::optional<double> get_last_seen_timestamp() override;

    void clear_all() override;

  private:
    std::filesystem::path get_license_path() const;
    std::filesystem::path get_offline_license_path() const;
    std::filesystem::path get_public_key_path(const std::string& key_id) const;
    std::filesystem::path get_timestamp_path() const;

    bool ensure_directory() const;
    bool write_file(const std::filesystem::path& path, const std::string& content);
    std::optional<std::string> read_file(const std::filesystem::path& path);

    std::filesystem::path storage_path_;
    std::string prefix_;
    mutable std::mutex mutex_;
};

/**
 * @brief In-memory storage implementation (for testing or no persistence)
 */
class MemoryStorage : public StorageInterface {
  public:
    bool set_license(const CachedLicense& license) override;
    std::optional<CachedLicense> get_license() override;
    void clear_license() override;

    bool set_offline_license(const OfflineLicense& offline) override;
    std::optional<OfflineLicense> get_offline_license() override;
    void clear_offline_license() override;

    bool set_public_key(const std::string& key_id, const std::string& public_key_b64) override;
    std::optional<std::string> get_public_key(const std::string& key_id) override;

    bool set_last_seen_timestamp(double timestamp) override;
    std::optional<double> get_last_seen_timestamp() override;

    void clear_all() override;

  private:
    std::optional<CachedLicense> license_;
    std::optional<OfflineLicense> offline_license_;
    std::unordered_map<std::string, std::string> public_keys_;
    std::optional<double> last_seen_timestamp_;
    mutable std::mutex mutex_;
};

}  // namespace licenseseat
