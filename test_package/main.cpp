#include <licenseseat/json.hpp>
#include <licenseseat/telemetry.hpp>

#include <cassert>
#include <string>

int main() {
    const auto parsed = licenseseat::json::parse_strict(R"({"package":"conan"})");
    assert(parsed.at("package") == "conan");
    assert(std::string(licenseseat::VERSION).find('.') != std::string::npos);
    return 0;
}
