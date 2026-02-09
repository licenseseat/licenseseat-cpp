#include "licenseseat/telemetry.hpp"

#include <array>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <thread>

// Platform detection
#if defined(__APPLE__)
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <CoreGraphics/CGDirectDisplay.h>
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

std::string get_platform() { return "native"; }

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

std::string get_device_type() { return "desktop"; }

int get_memory_gb() {
    int64_t memsize = 0;
    size_t len = sizeof(memsize);
    if (sysctlbyname("hw.memsize", &memsize, &len, nullptr, 0) == 0) {
        // Round to nearest GB
        return static_cast<int>((memsize + 536870912LL) / 1073741824LL);
    }
    return 0;
}

std::string get_screen_resolution() {
    auto width = CGDisplayPixelsWide(kCGDirectMainDisplay);
    auto height = CGDisplayPixelsHigh(kCGDirectMainDisplay);
    if (width > 0 && height > 0) {
        return std::to_string(width) + "x" + std::to_string(height);
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

std::string get_platform() { return "native"; }

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

std::string get_device_type() {
    const char* display = std::getenv("DISPLAY");
    if (display == nullptr || std::strlen(display) == 0) {
        return "server";
    }
    return "desktop";
}

int get_memory_gb() {
    std::ifstream file("/proc/meminfo");
    if (file.is_open()) {
        std::string line;
        if (std::getline(file, line)) {
            // "MemTotal:       16384000 kB"
            auto colon = line.find(':');
            if (colon != std::string::npos) {
                auto val_str = line.substr(colon + 1);
                // Trim leading whitespace
                auto start = val_str.find_first_not_of(" \t");
                if (start != std::string::npos) {
                    val_str = val_str.substr(start);
                }
                try {
                    long long kb = std::stoll(val_str);
                    // Round to nearest GB (1 GB = 1048576 kB)
                    return static_cast<int>((kb + 524288LL) / 1048576LL);
                } catch (...) {
                    return 0;
                }
            }
        }
    }
    return 0;
}

std::string get_screen_resolution() {
    // Try reading from DRM subsystem
    std::ifstream file("/sys/class/drm/card0-eDP-1/modes");
    if (!file.is_open()) {
        file.open("/sys/class/drm/card0-HDMI-A-1/modes");
    }
    if (file.is_open()) {
        std::string mode;
        if (std::getline(file, mode) && !mode.empty()) {
            return mode;
        }
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

std::string get_platform() { return "native"; }

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

std::string get_device_type() { return "desktop"; }

int get_memory_gb() {
    MEMORYSTATUSEX statex{};
    statex.dwLength = sizeof(statex);
    if (GlobalMemoryStatusEx(&statex)) {
        // Round to nearest GB
        return static_cast<int>((statex.ullTotalPhys + 536870912ULL) / 1073741824ULL);
    }
    return 0;
}

std::string get_screen_resolution() {
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    if (width > 0 && height > 0) {
        return std::to_string(width) + "x" + std::to_string(height);
    }
    return "";
}

#else

std::string get_os_name() { return ""; }
std::string get_os_version() { return ""; }
std::string get_platform() { return "native"; }
std::string get_device_model() { return ""; }
std::string get_timezone() { return ""; }
std::string get_device_type() { return "unknown"; }
int get_memory_gb() { return 0; }
std::string get_screen_resolution() { return ""; }

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

std::string get_architecture() {
#if defined(__aarch64__) || defined(_M_ARM64)
    return "arm64";
#elif defined(__x86_64__) || defined(_M_X64) || defined(_M_AMD64)
    return "x64";
#elif defined(__i386__) || defined(_M_IX86)
    return "x86";
#elif defined(__arm__) || defined(_M_ARM)
    return "arm";
#else
    return "";
#endif
}

int get_cpu_cores() {
    auto cores = std::thread::hardware_concurrency();
    return cores > 0 ? static_cast<int>(cores) : 0;
}

std::string get_language() {
    const char* lang = std::getenv("LANG");
    if (lang != nullptr && std::strlen(lang) >= 2) {
        std::string full(lang);
        // Extract first 2 chars (the language code)
        auto code = full.substr(0, 2);
        // Validate it's alphabetic
        if (std::isalpha(static_cast<unsigned char>(code[0])) &&
            std::isalpha(static_cast<unsigned char>(code[1]))) {
            return code;
        }
    }
    return "";
}

}  // namespace

nlohmann::json collect(const std::string& sdk_version,
                       const std::string& app_version,
                       const std::string& app_build) {
    nlohmann::json telemetry = nlohmann::json::object();

    try {
        // Always include sdk identifiers
        telemetry["sdk_name"] = "cpp";
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

        // User-provided fields
        if (!app_version.empty()) {
            telemetry["app_version"] = app_version;
        }

        if (!app_build.empty()) {
            telemetry["app_build"] = app_build;
        }

        auto device_type = get_device_type();
        if (!device_type.empty()) {
            telemetry["device_type"] = device_type;
        }

        auto architecture = get_architecture();
        if (!architecture.empty()) {
            telemetry["architecture"] = architecture;
        }

        auto cpu_cores = get_cpu_cores();
        if (cpu_cores > 0) {
            telemetry["cpu_cores"] = cpu_cores;
        }

        auto memory_gb = get_memory_gb();
        if (memory_gb > 0) {
            telemetry["memory_gb"] = memory_gb;
        }

        auto language = get_language();
        if (!language.empty()) {
            telemetry["language"] = language;
        }

        auto screen_resolution = get_screen_resolution();
        if (!screen_resolution.empty()) {
            telemetry["screen_resolution"] = screen_resolution;
        }
    } catch (...) {
        // Never let telemetry crash the application
    }

    return telemetry;
}

}  // namespace telemetry
}  // namespace licenseseat
