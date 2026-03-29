cmake_minimum_required(VERSION 3.16)
project(SynthDemo VERSION 1.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# Detect WASM/Emscripten build
if(EMSCRIPTEN)
    message(STATUS "Building for WebAssembly (WASM Demo Mode)")
    set(WASM_BUILD ON)
else()
    set(WASM_BUILD OFF)
    # Add parent LicenseSeat SDK (native builds only)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/.. ${CMAKE_CURRENT_BINARY_DIR}/licenseseat)
endif()

# Fetch raylib
FetchContent_Declare(
    raylib
    GIT_REPOSITORY https://github.com/raysan5/raylib.git
    GIT_TAG master
    GIT_SHALLOW TRUE
)
set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(raylib)

# Fetch raygui (single header)
FetchContent_Declare(
    raygui
    GIT_REPOSITORY https://github.com/raysan5/raygui.git
    GIT_TAG master
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(raygui)

# === Platform-specific configuration ===
if(WASM_BUILD)
    # WASM executable (no bundle, no SDK)
    add_executable(synthdemo main_gui.cpp)

    target_link_libraries(synthdemo PRIVATE raylib)

    target_include_directories(synthdemo PRIVATE
        ${raygui_SOURCE_DIR}/src
    )

    # Emscripten compiler flags (required for raylib since Emscripten 3.1.51)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -sUSE_GLFW=3 -sASSERTIONS=1 -sWASM=1 -sASYNCIFY -sGL_ENABLE_GET_PROC_ADDRESS=1")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -sUSE_GLFW=3 -sASSERTIONS=1 -sWASM=1 -sASYNCIFY -sGL_ENABLE_GET_PROC_ADDRESS=1")

    # Emscripten linker flags
    # - INITIAL_MEMORY: Starting heap size (64MB)
    # - ALLOW_MEMORY_GROWTH: Can grow beyond initial
    # - ASYNCIFY: Required for raylib's blocking calls
    # - AUDIO_WORKLET + WASM_WORKERS: Modern audio API (replaces deprecated ScriptProcessorNode)
    set(WASM_LINKER_FLAGS
        "-sUSE_GLFW=3"
        "-sASYNCIFY"
        "-sINITIAL_MEMORY=67108864"
        "-sALLOW_MEMORY_GROWTH=1"
        "-sGL_ENABLE_GET_PROC_ADDRESS=1"
        "--shell-file ${CMAKE_CURRENT_SOURCE_DIR}/shell.html"
    )
    string(REPLACE ";" " " WASM_LINKER_FLAGS_STR "${WASM_LINKER_FLAGS}")

    set_target_properties(synthdemo PROPERTIES
        SUFFIX ".html"
        LINK_FLAGS "${WASM_LINKER_FLAGS_STR}"
    )
else()
    # === macOS Bundle Configuration ===
    set(MACOSX_BUNDLE_BUNDLE_NAME "SynthDemo")
    set(MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION})
    set(MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION})
    set(MACOSX_BUNDLE_LONG_VERSION_STRING ${PROJECT_VERSION})
    set(MACOSX_BUNDLE_GUI_IDENTIFIER "com.licenseseat.synthdemo")
    set(MACOSX_BUNDLE_ICON_FILE "AppIcon.icns")
    set(MACOSX_BUNDLE_COPYRIGHT "Copyright 2026 LicenseSeat")

    # Icon file for macOS bundle
    set(APP_ICON_MACOS "${CMAKE_CURRENT_SOURCE_DIR}/resources/AppIcon.icns")
    set_source_files_properties(${APP_ICON_MACOS} PROPERTIES MACOSX_PACKAGE_LOCATION "Resources")

    # Demo executable
    add_executable(synthdemo MACOSX_BUNDLE
        main_gui.cpp
        ${APP_ICON_MACOS}
    )

    target_link_libraries(synthdemo PRIVATE raylib licenseseat::licenseseat)

    # Include raygui header and SDK
    target_include_directories(synthdemo PRIVATE
        ${raygui_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/../include  # LicenseSeat SDK headers
        ${CMAKE_CURRENT_SOURCE_DIR}/../deps     # SDK dependencies (nlohmann/json, etc.)
    )

    # Platform-specific
    if(APPLE)
        target_link_libraries(synthdemo PRIVATE "-framework IOKit" "-framework Cocoa" "-framework OpenGL")

        set_target_properties(synthdemo PROPERTIES
            MACOSX_BUNDLE TRUE
            MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/Info.plist.in"
        )
    elseif(UNIX)
        target_link_libraries(synthdemo PRIVATE m pthread dl)
    endif()
endif()
