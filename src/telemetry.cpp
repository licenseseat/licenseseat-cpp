#include "licenseseat/telemetry.hpp"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>

// Platform detection
#if defined(__APPLE__)
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <unistd.h>
#define LICENSESEAT_PLATFORM_MACOS 1
#elif defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#define LICENSESEAT_PLATFORM_WINDOWS 1
#elif defined(__linux__)
#include <sys/utsname.h>
#include <unistd.h>
#define LICENSESEAT_PLATFORM_LINUX 1
#endif

namespace licenseseat {
namespace telemetry {

namespace {

#if defined(LICENSESEAT_PLATFORM_MACOS)

std::string get_os_name() { return "macOS"; }

std::string get_os_version() {
    // Use sysctl kern.osproductversion (available on macOS 10.13.4+)
    char version[64] = {0};
    size_t len = sizeof(version);
    if (sysctlbyname("kern.osproductversion", version, &len, nullptr, 0) == 0) {
        return std::string(version);
    }
    // Fallback to uname
    struct utsname info {};
    if (uname(&info) == 0) {
        return std::string(info.release);
    }
    return "";
}

std::string get_platform() { return "macOS"; }

std::string get_device_model() {
    char model[128] = {0};
    size_t len = sizeof(model);
    if (sysctlbyname("hw.model", model, &len, nullptr, 0) == 0) {
        return std::string(model);
    }
    return "";
}

std::string get_timezone() {
    // Try readlink /etc/localtime
    std::array<char, 512> buf{};
    auto count = readlink("/etc/localtime", buf.data(), buf.size() - 1);
    if (count > 0) {
        buf[static_cast<size_t>(count)] = '\0';
        std::string path(buf.data());
        auto pos = path.find("zoneinfo/");
        if (pos != std::string::npos) {
            return path.substr(pos + 9);
        }
    }
    // Fallback to TZ env
    const char* tz = std::getenv("TZ");
    if (tz != nullptr && std::strlen(tz) > 0) {
        return std::string(tz);
    }
    return "";
}

#elif defined(LICENSESEAT_PLATFORM_LINUX)

std::string get_os_name() { return "Linux"; }

std::string get_os_version() {
    struct utsname info {};
    if (uname(&info) == 0) {
        return std::string(info.release);
    }
    return "";
}

std::string get_platform() { return "Linux"; }

std::string get_device_model() {
    std::ifstream file("/sys/class/dmi/id/product_name");
    if (file.is_open()) {
        std::string model;
        std::getline(file, model);
        if (!model.empty()) {
            return model;
        }
    }
    return "";
}

std::string get_timezone() {
    // Try readlink /etc/localtime
    std::array<char, 512> buf{};
    auto count = readlink("/etc/localtime", buf.data(), buf.size() - 1);
    if (count > 0) {
        buf[static_cast<size_t>(count)] = '\0';
        std::string path(buf.data());
        auto pos = path.find("zoneinfo/");
        if (pos != std::string::npos) {
            return path.substr(pos + 9);
        }
    }
    // Fallback to TZ env
    const char* tz = std::getenv("TZ");
    if (tz != nullptr && std::strlen(tz) > 0) {
        return std::string(tz);
    }
    return "";
}

#elif defined(LICENSESEAT_PLATFORM_WINDOWS)

std::string get_os_name() { return "Windows"; }

std::string get_os_version() {
    // Use RtlGetVersion via ntdll for accurate version
    using RtlGetVersionFunc = NTSTATUS(WINAPI*)(PRTL_OSVERSIONINFOW);
    auto* ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll != nullptr) {
        auto rtl_get_version =
            reinterpret_cast<RtlGetVersionFunc>(GetProcAddress(ntdll, "RtlGetVersion"));
        if (rtl_get_version != nullptr) {
            RTL_OSVERSIONINFOW info{};
            info.dwOSVersionInfoSize = sizeof(info);
            if (rtl_get_version(&info) == 0) {
                return std::to_string(info.dwMajorVersion) + "." +
                       std::to_string(info.dwMinorVersion) + "." +
                       std::to_string(info.dwBuildNumber);
            }
        }
    }
    return "";
}

std::string get_platform() { return "Windows"; }

std::string get_device_model() {
    // Read from registry
    HKEY hKey;
    LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                                "HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &hKey);
    if (result != ERROR_SUCCESS) {
        return "";
    }
    char model[256] = {0};
    DWORD size = sizeof(model);
    DWORD type = REG_SZ;
    result = RegQueryValueExA(hKey, "SystemProductName", nullptr, &type,
                              reinterpret_cast<LPBYTE>(model), &size);
    RegCloseKey(hKey);
    if (result == ERROR_SUCCESS) {
        return std::string(model);
    }
    return "";
}

std::string get_timezone() {
    TIME_ZONE_INFORMATION tz_info{};
    auto result = GetTimeZoneInformation(&tz_info);
    if (result != TIME_ZONE_ID_INVALID) {
        // Convert wide string to narrow
        char name[128] = {0};
        WideCharToMultiByte(CP_UTF8, 0, tz_info.StandardName, -1, name, sizeof(name), nullptr,
                            nullptr);
        if (std::strlen(name) > 0) {
            return std::string(name);
        }
    }
    return "";
}

#else

std::string get_os_name() { return ""; }
std::string get_os_version() { return ""; }
std::string get_platform() { return ""; }
std::string get_device_model() { return ""; }
std::string get_timezone() { return ""; }

#endif

std::string get_locale() {
    // Try environment variables
    const char* lang = std::getenv("LANG");
    if (lang != nullptr && std::strlen(lang) > 0) {
        return std::string(lang);
    }
    const char* lc_all = std::getenv("LC_ALL");
    if (lc_all != nullptr && std::strlen(lc_all) > 0) {
        return std::string(lc_all);
    }
    return "";
}

}  // namespace

nlohmann::json collect(const std::string& sdk_version) {
    nlohmann::json telemetry = nlohmann::json::object();

    // Always include sdk_version
    telemetry["sdk_version"] = sdk_version;

    // Only include non-empty values
    auto os_name = get_os_name();
    if (!os_name.empty()) {
        telemetry["os_name"] = os_name;
    }

    auto os_version = get_os_version();
    if (!os_version.empty()) {
        telemetry["os_version"] = os_version;
    }

    auto platform = get_platform();
    if (!platform.empty()) {
        telemetry["platform"] = platform;
    }

    auto device_model = get_device_model();
    if (!device_model.empty()) {
        telemetry["device_model"] = device_model;
    }

    auto locale = get_locale();
    if (!locale.empty()) {
        telemetry["locale"] = locale;
    }

    auto timezone = get_timezone();
    if (!timezone.empty()) {
        telemetry["timezone"] = timezone;
    }

    return telemetry;
}

}  // namespace telemetry
}  // namespace licenseseat
