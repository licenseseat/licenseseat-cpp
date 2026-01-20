cmake_minimum_required(VERSION 3.14)

project(licenseseat
    VERSION 0.1.0
    DESCRIPTION "C++ SDK for LicenseSeat licensing API"
    HOMEPAGE_URL "https://github.com/licenseseat/licenseseat-cpp"
    LANGUAGES CXX C
)

# Require C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Export compile commands for clang-tidy
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Options
option(LICENSESEAT_BUILD_TESTS "Build tests" ON)
option(LICENSESEAT_BUILD_EXAMPLES "Build examples" ON)
option(LICENSESEAT_ENABLE_CLANG_TIDY "Enable clang-tidy" OFF)

# Compiler warnings
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
        -Werror
        -Wno-unused-parameter
    )
elseif(MSVC)
    add_compile_options(/W4 /WX)
endif()

# clang-tidy integration
if(LICENSESEAT_ENABLE_CLANG_TIDY)
    find_program(CLANG_TIDY_EXE
        NAMES clang-tidy clang-tidy-21 clang-tidy-20 clang-tidy-19
        HINTS /opt/homebrew/opt/llvm/bin
    )
    if(CLANG_TIDY_EXE)
        message(STATUS "clang-tidy found: ${CLANG_TIDY_EXE}")
        set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY_EXE}")
    else()
        message(WARNING "clang-tidy not found, linting disabled")
    endif()
endif()

# Find dependencies (JSON and HTTP only - crypto is vendored)
find_package(nlohmann_json REQUIRED)
find_package(httplib REQUIRED)
find_package(OpenSSL REQUIRED)

# Vendored ed25519 sources
set(ED25519_SOURCES
    deps/ed25519/add_scalar.c
    deps/ed25519/fe.c
    deps/ed25519/ge.c
    deps/ed25519/key_exchange.c
    deps/ed25519/keypair.c
    deps/ed25519/sc.c
    deps/ed25519/seed.c
    deps/ed25519/sha512.c
    deps/ed25519/sign.c
    deps/ed25519/verify.c
)

# Main library sources
set(LICENSESEAT_SOURCES
    src/client.cpp
    src/http.cpp
    src/device.cpp
    src/storage.cpp
    src/crypto.cpp
    ${ED25519_SOURCES}
)

add_library(licenseseat ${LICENSESEAT_SOURCES})

add_library(licenseseat::licenseseat ALIAS licenseseat)

target_include_directories(licenseseat
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/deps
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ed25519
)

# Compile definitions for HTTPS support via cpp-httplib
target_compile_definitions(licenseseat
    PRIVATE
        CPPHTTPLIB_OPENSSL_SUPPORT
)

# Link libraries
target_link_libraries(licenseseat
    PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
    PRIVATE
        nlohmann_json::nlohmann_json
        httplib::httplib
)

# Platform-specific libraries for device identification
if(APPLE)
    target_link_libraries(licenseseat PRIVATE
        "-framework CoreFoundation"
        "-framework IOKit"
    )
endif()

# Set library properties
set_target_properties(licenseseat PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    PUBLIC_HEADER "include/licenseseat/licenseseat.hpp"
)

# Tests
if(LICENSESEAT_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Examples
if(LICENSESEAT_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Installation
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS licenseseat
    EXPORT licenseseatTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/licenseseat
)

install(DIRECTORY include/licenseseat
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT licenseseatTargets
    FILE licenseseatTargets.cmake
    NAMESPACE licenseseat::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/licenseseat
)

# Generate config file
configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/licenseseatConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/licenseseatConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/licenseseat
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/licenseseatConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/licenseseatConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/licenseseatConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/licenseseat
)

# CPack configuration
set(CPACK_PACKAGE_NAME "licenseseat")
set(CPACK_PACKAGE_VENDOR "LicenseSeat")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "C++ SDK for LicenseSeat licensing API")
set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
    set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
endif()
set(CPACK_GENERATOR "TGZ;ZIP")

include(CPack)

# Summary
message(STATUS "")
message(STATUS "LicenseSeat C++ SDK ${PROJECT_VERSION}")
message(STATUS "  Build tests:    ${LICENSESEAT_BUILD_TESTS}")
message(STATUS "  Build examples: ${LICENSESEAT_BUILD_EXAMPLES}")
message(STATUS "  clang-tidy:     ${LICENSESEAT_ENABLE_CLANG_TIDY}")
message(STATUS "  Crypto:         Vendored (ed25519 + PicoSHA2)")
message(STATUS "")
