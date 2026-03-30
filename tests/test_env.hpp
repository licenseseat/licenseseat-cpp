#pragma once

#include <cstdlib>
#include <string>

namespace test_env {

inline std::string get(const char* name) {
#if defined(_WIN32) || defined(_WIN64)
    char* value = nullptr;
    size_t len = 0;
    if (_dupenv_s(&value, &len, name) != 0 || value == nullptr) {
        return {};
    }

    std::string result(value);
    free(value);
    return result;
#else
    const char* value = std::getenv(name);
    return value ? std::string(value) : std::string();
#endif
}

inline std::string get(const char* name, const char* fallback) {
    std::string value = get(name);
    return value.empty() ? std::string(fallback) : value;
}

}  // namespace test_env
