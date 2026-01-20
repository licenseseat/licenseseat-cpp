#include "licenseseat/device.hpp"

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>

// Platform detection
#if defined(__APPLE__)
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#define LICENSESEAT_PLATFORM_MACOS 1
#elif defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#define LICENSESEAT_PLATFORM_WINDOWS 1
#elif defined(__linux__)
#define LICENSESEAT_PLATFORM_LINUX 1
#endif

// For hostname
#if defined(LICENSESEAT_PLATFORM_WINDOWS)
// Windows headers already included
#else
#include <unistd.h>
#endif

namespace licenseseat {
namespace device {

namespace {

// Hash a string using SHA-256 and return hex string
std::string sha256_hex(const std::string& input) {
    if (input.empty()) {
        return "";
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    if (ctx == nullptr) {
        return "";
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    if (EVP_DigestUpdate(ctx, input.c_str(), input.length()) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    unsigned int len = 0;
    if (EVP_DigestFinal_ex(ctx, hash, &len) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    EVP_MD_CTX_free(ctx);

    std::ostringstream ss;
    for (unsigned int i = 0; i < len; i++) {
        ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(hash[i]);
    }

    return ss.str();
}

#if defined(LICENSESEAT_PLATFORM_MACOS)

std::string get_macos_platform_uuid() {
    io_registry_entry_t entry = IORegistryEntryFromPath(kIOMainPortDefault, "IOService:/");
    if (entry == 0) {
        return "";
    }

    CFTypeRef uuid_ref =
        IORegistryEntryCreateCFProperty(entry, CFSTR(kIOPlatformUUIDKey), kCFAllocatorDefault, 0);

    IOObjectRelease(entry);

    if (uuid_ref == nullptr) {
        return "";
    }

    std::string result;
    if (CFGetTypeID(uuid_ref) == CFStringGetTypeID()) {
        CFStringRef uuid_string = static_cast<CFStringRef>(uuid_ref);
        CFIndex length = CFStringGetLength(uuid_string);
        CFIndex max_size = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;

        std::vector<char> buffer(static_cast<size_t>(max_size));
        if (CFStringGetCString(uuid_string, buffer.data(), max_size, kCFStringEncodingUTF8)) {
            result = buffer.data();
        }
    }

    CFRelease(uuid_ref);
    return result;
}

#elif defined(LICENSESEAT_PLATFORM_LINUX)

std::string get_linux_machine_id() {
    // Try /etc/machine-id first (systemd)
    std::ifstream machine_id_file("/etc/machine-id");
    if (machine_id_file.is_open()) {
        std::string machine_id;
        std::getline(machine_id_file, machine_id);
        if (!machine_id.empty()) {
            return machine_id;
        }
    }

    // Fallback to /var/lib/dbus/machine-id
    std::ifstream dbus_file("/var/lib/dbus/machine-id");
    if (dbus_file.is_open()) {
        std::string machine_id;
        std::getline(dbus_file, machine_id);
        if (!machine_id.empty()) {
            return machine_id;
        }
    }

    // Fallback to DMI product UUID (requires root)
    std::ifstream dmi_file("/sys/class/dmi/id/product_uuid");
    if (dmi_file.is_open()) {
        std::string uuid;
        std::getline(dmi_file, uuid);
        if (!uuid.empty()) {
            return uuid;
        }
    }

    return "";
}

#elif defined(LICENSESEAT_PLATFORM_WINDOWS)

std::string get_windows_machine_guid() {
    HKEY hKey;
    LONG result =
        RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ, &hKey);

    if (result != ERROR_SUCCESS) {
        return "";
    }

    char guid[256] = {0};
    DWORD size = sizeof(guid);
    DWORD type = REG_SZ;

    result = RegQueryValueExA(hKey, "MachineGuid", nullptr, &type,
                              reinterpret_cast<LPBYTE>(guid), &size);

    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        return "";
    }

    return std::string(guid);
}

#endif

}  // namespace

std::string generate_device_id() {
    std::string raw_id;

#if defined(LICENSESEAT_PLATFORM_MACOS)
    raw_id = get_macos_platform_uuid();
#elif defined(LICENSESEAT_PLATFORM_LINUX)
    raw_id = get_linux_machine_id();
#elif defined(LICENSESEAT_PLATFORM_WINDOWS)
    raw_id = get_windows_machine_guid();
#endif

    if (raw_id.empty()) {
        return "";
    }

    // Hash the raw ID for privacy and consistent format
    std::string hash = sha256_hex(raw_id);

    // Return first 32 chars (128 bits) for a reasonable identifier length
    if (hash.length() > 32) {
        return hash.substr(0, 32);
    }

    return hash;
}

std::string get_platform_name() {
#if defined(LICENSESEAT_PLATFORM_MACOS)
    return "macos";
#elif defined(LICENSESEAT_PLATFORM_LINUX)
    return "linux";
#elif defined(LICENSESEAT_PLATFORM_WINDOWS)
    return "windows";
#else
    return "unknown";
#endif
}

std::string get_hostname() {
#if defined(LICENSESEAT_PLATFORM_WINDOWS)
    char hostname[256] = {0};
    DWORD size = sizeof(hostname);
    if (GetComputerNameA(hostname, &size)) {
        return std::string(hostname);
    }
#else
    char hostname[256] = {0};
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        return std::string(hostname);
    }
#endif
    return "unknown";
}

}  // namespace device
}  // namespace licenseseat
