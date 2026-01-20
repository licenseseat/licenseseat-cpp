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
