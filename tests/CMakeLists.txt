# Tests CMakeLists.txt

find_package(GTest REQUIRED)

# Unit tests
add_executable(licenseseat_tests
    test_result.cpp
    test_license.cpp
    test_client.cpp
    test_json.cpp
    test_http.cpp
    test_crypto.cpp
    test_device.cpp
    test_events.cpp
    test_storage.cpp
    test_special_packaging.cpp
)

target_compile_definitions(licenseseat_tests
    PRIVATE
        CPPHTTPLIB_OPENSSL_SUPPORT
)

target_link_libraries(licenseseat_tests
    PRIVATE
        licenseseat::licenseseat
        GTest::gtest
        GTest::gtest_main
        nlohmann_json::nlohmann_json
        httplib::httplib
)

# Register tests with CTest
include(GoogleTest)
gtest_discover_tests(licenseseat_tests)

# Integration tests (live API - run manually)
add_executable(integration_test
    integration_test.cpp
)

target_compile_definitions(integration_test
    PRIVATE
        CPPHTTPLIB_OPENSSL_SUPPORT
        $<$<CXX_COMPILER_ID:MSVC>:_CRT_SECURE_NO_WARNINGS>
)

target_link_libraries(integration_test
    PRIVATE
        licenseseat::licenseseat
        nlohmann_json::nlohmann_json
        httplib::httplib
)

# Crypto stress test (offline tokens & Ed25519)
add_executable(crypto_stress_test
    crypto_stress_test.cpp
)

target_compile_definitions(crypto_stress_test
    PRIVATE
        CPPHTTPLIB_OPENSSL_SUPPORT
        $<$<CXX_COMPILER_ID:MSVC>:_CRT_SECURE_NO_WARNINGS>
)

target_link_libraries(crypto_stress_test
    PRIVATE
        licenseseat::licenseseat
        nlohmann_json::nlohmann_json
        httplib::httplib
)

# Scenario tests (real-world use cases)
add_executable(scenario_test
    scenario_test.cpp
)

target_compile_definitions(scenario_test
    PRIVATE
        CPPHTTPLIB_OPENSSL_SUPPORT
        $<$<CXX_COMPILER_ID:MSVC>:_CRT_SECURE_NO_WARNINGS>
)

target_link_libraries(scenario_test
    PRIVATE
        licenseseat::licenseseat
        nlohmann_json::nlohmann_json
        httplib::httplib
)
