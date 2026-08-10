#include "licenseseat/device.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <map>
#include <sstream>
#include <vector>

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

// Internal namespace for sha256_hex - implementation in crypto.cpp using PicoSHA2
namespace internal {

// Forward declaration - implementation in crypto.cpp
std::string sha256_hex(const std::string& input);

} // namespace internal

namespace {

constexpr std::size_t MAX_FINGERPRINT_COMPONENT_BYTES = 255;

bool safe_component(const std::string& value) {
    return !value.empty() && value.size() <= MAX_FINGERPRINT_COMPONENT_BYTES &&
           std::all_of(value.begin(), value.end(), [](unsigned char character) {
               return character >= 0x20 && character <= 0x7e;
           });
}

#if defined(LICENSESEAT_PLATFORM_LINUX)
std::string trim_identifier(const std::string& value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return "";
    }

    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

std::string read_trimmed_file(const char* path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return "";
    }

    std::array<char, MAX_FINGERPRINT_COMPONENT_BYTES + 1> buffer{};
    file.read(buffer.data(), static_cast<std::streamsize>(MAX_FINGERPRINT_COMPONENT_BYTES));
    const auto count = file.gcount();
    char extra = '\0';
    if (count <= 0 || file.get(extra))
        return "";
    const auto value = trim_identifier(std::string(buffer.data(), static_cast<std::size_t>(count)));
    return safe_component(value) ? value : "";
}
#endif

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
        const CFIndex length = CFStringGetLength(uuid_string);
        const CFIndex max_size =
            length > 0 && length <= static_cast<CFIndex>(MAX_FINGERPRINT_COMPONENT_BYTES)
                ? CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1
                : 0;

        if (max_size > 1 &&
            max_size <= 4 * static_cast<CFIndex>(MAX_FINGERPRINT_COMPONENT_BYTES) + 1) {
            std::vector<char> buffer(static_cast<std::size_t>(max_size));
            if (CFStringGetCString(uuid_string, buffer.data(), max_size, kCFStringEncodingUTF8)) {
                result = buffer.data();
            }
        }
    }

    CFRelease(uuid_ref);
    return safe_component(result) ? result : "";
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

    result = RegQueryValueExA(hKey, "MachineGuid", nullptr, &type, reinterpret_cast<LPBYTE>(guid),
                              &size);

    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS || type != REG_SZ || size == 0 || size > sizeof(guid)) {
        return "";
    }

    std::size_t length = size;
    while (length > 0 && guid[length - 1] == '\0')
        --length;
    const std::string value(guid, length);
    return safe_component(value) ? value : "";
}

#endif

} // namespace

std::string generate_device_id() {
    auto components = collect_fingerprint_components();
    std::string raw_id;

    const auto use_component = [&](const char* key) {
        auto it = components.find(key);
        if (it != components.end() && !it->second.empty()) {
            raw_id = it->second;
            return true;
        }
        return false;
    };

    use_component("platform_uuid") || use_component("machine_id") ||
        use_component("dbus_machine_id") || use_component("dmi_product_uuid") ||
        use_component("machine_guid") || use_component("hostname");

    if (raw_id.empty()) {
        return "";
    }

    // Hash the raw ID for privacy and consistent format
    std::string hash = internal::sha256_hex(raw_id);

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
    if (GetComputerNameA(hostname, &size) && size > 0 && size < sizeof(hostname)) {
        const std::string value(hostname, size);
        return safe_component(value) ? value : "unknown";
    }
#else
    char hostname[256] = {0};
    if (gethostname(hostname, sizeof(hostname) - 1) == 0) {
        hostname[sizeof(hostname) - 1] = '\0';
        const std::string value(hostname);
        return safe_component(value) ? value : "unknown";
    }
#endif
    return "unknown";
}

std::map<std::string, std::string> collect_fingerprint_components() {
    std::map<std::string, std::string> components;
    components["schema_version"] = "1";
    components["strategy"] = "stable_exact";
    components["platform"] = get_platform_name();

    const auto hostname = get_hostname();
    if (!hostname.empty() && hostname != "unknown") {
        components["hostname"] = hostname;
    }

#if defined(LICENSESEAT_PLATFORM_MACOS)
    auto platform_uuid = get_macos_platform_uuid();
    if (!platform_uuid.empty()) {
        components["platform_uuid"] = platform_uuid;
        components["primary_signal"] = "platform_uuid";
    }
#elif defined(LICENSESEAT_PLATFORM_LINUX)
    auto machine_id = read_trimmed_file("/etc/machine-id");
    if (!machine_id.empty()) {
        components["machine_id"] = machine_id;
        components["primary_signal"] = "machine_id";
    }

    auto dbus_machine_id = read_trimmed_file("/var/lib/dbus/machine-id");
    if (!dbus_machine_id.empty() && dbus_machine_id != machine_id) {
        components["dbus_machine_id"] = dbus_machine_id;
        if (components.find("primary_signal") == components.end()) {
            components["primary_signal"] = "dbus_machine_id";
        }
    }

    auto dmi_uuid = read_trimmed_file("/sys/class/dmi/id/product_uuid");
    if (!dmi_uuid.empty()) {
        components["dmi_product_uuid"] = dmi_uuid;
        if (components.find("primary_signal") == components.end()) {
            components["primary_signal"] = "dmi_product_uuid";
        }
    }
#elif defined(LICENSESEAT_PLATFORM_WINDOWS)
    auto machine_guid = get_windows_machine_guid();
    if (!machine_guid.empty()) {
        components["machine_guid"] = machine_guid;
        components["primary_signal"] = "machine_guid";
    }
#endif

    if (components.find("primary_signal") == components.end() && components.count("hostname") > 0) {
        components["primary_signal"] = "hostname";
    }

    return components;
}

} // namespace device
} // namespace licenseseat
