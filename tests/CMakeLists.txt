# Tests CMakeLists.txt

find_package(GTest REQUIRED)

# Bundled deps are in deps/ (nlohmann/json.hpp, httplib.h)
set(BUNDLED_DEPS_INCLUDE ${CMAKE_SOURCE_DIR}/deps)

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
    test_telemetry.cpp
)

target_include_directories(licenseseat_tests PRIVATE ${BUNDLED_DEPS_INCLUDE})
target_compile_definitions(licenseseat_tests PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
target_link_libraries(licenseseat_tests PRIVATE licenseseat::licenseseat GTest::gtest GTest::gtest_main)

# Register tests with CTest
include(GoogleTest)
gtest_discover_tests(licenseseat_tests)

# Integration tests (live API - run manually)
add_executable(integration_test integration_test.cpp)
target_include_directories(integration_test PRIVATE ${BUNDLED_DEPS_INCLUDE})
target_compile_definitions(integration_test PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
target_link_libraries(integration_test PRIVATE licenseseat::licenseseat)

# Crypto stress test (offline tokens & Ed25519)
add_executable(crypto_stress_test crypto_stress_test.cpp)
target_include_directories(crypto_stress_test PRIVATE ${BUNDLED_DEPS_INCLUDE})
target_compile_definitions(crypto_stress_test PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
target_link_libraries(crypto_stress_test PRIVATE licenseseat::licenseseat)

# Telemetry & heartbeat stress test
add_executable(telemetry_stress_test telemetry_stress_test.cpp)
target_include_directories(telemetry_stress_test PRIVATE ${BUNDLED_DEPS_INCLUDE})
target_compile_definitions(telemetry_stress_test PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
target_link_libraries(telemetry_stress_test PRIVATE licenseseat::licenseseat)

# Scenario tests (real-world use cases)
add_executable(scenario_test scenario_test.cpp)
target_include_directories(scenario_test PRIVATE ${BUNDLED_DEPS_INCLUDE})
target_compile_definitions(scenario_test PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
target_link_libraries(scenario_test PRIVATE licenseseat::licenseseat)

# Offline workflow test
add_executable(offline_workflow_test offline_workflow_test.cpp)
target_include_directories(offline_workflow_test PRIVATE ${BUNDLED_DEPS_INCLUDE})
target_compile_definitions(offline_workflow_test PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
target_link_libraries(offline_workflow_test PRIVATE licenseseat::licenseseat)
