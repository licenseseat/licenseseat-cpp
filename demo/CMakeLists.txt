cmake_minimum_required(VERSION 3.16)
project(SynthDemo VERSION 1.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

function(replace_or_fail variable search replace)
    string(FIND "${${variable}}" "${search}" match_index)
    if(match_index EQUAL -1)
        # Reconfiguring over an already-patched FetchContent source dir is normal
        # (it happens on every incremental rebuild). Only fail when the replacement
        # is missing too, which means upstream really did move.
        string(FIND "${${variable}}" "${replace}" applied_index)
        if(applied_index EQUAL -1)
            message(FATAL_ERROR "Failed to patch raylib web backend. Expected snippet was not found.")
        endif()

        return()
    endif()

    string(REPLACE "${search}" "${replace}" updated_value "${${variable}}")
    set(${variable} "${updated_value}" PARENT_SCOPE)
endfunction()

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
# Pinned: the web backend below is patched by exact source snippets, and the
# shipped WASM bundle has to be rebuildable byte-for-byte. Tracking master made
# every rebuild a different demo.
set(RAYLIB_PINNED_COMMIT "c7df641aa25d40b1998d28cd38876e09f738b656")  # 6.0 dev, 2026-03-30
FetchContent_Declare(
    raylib
    GIT_REPOSITORY https://github.com/raysan5/raylib.git
    GIT_TAG ${RAYLIB_PINNED_COMMIT}
    GIT_SHALLOW FALSE  # a shallow clone cannot check out an arbitrary commit
)
set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(raylib)

# Fetch raygui (single header)
set(RAYGUI_PINNED_COMMIT "3b2855842ab578a034f827c38cf8f62c042fc983")  # 4.5 dev, 2026-03-30
FetchContent_Declare(
    raygui
    GIT_REPOSITORY https://github.com/raysan5/raygui.git
    GIT_TAG ${RAYGUI_PINNED_COMMIT}
    GIT_SHALLOW FALSE
)
FetchContent_MakeAvailable(raygui)

if(WASM_BUILD)
    # Emscripten's GLFW runtime already supports GLFW_SCALE_TO_MONITOR/devicePixelRatio.
    # raylib's web backend leaves that hint commented out and still sizes the viewport
    # from the logical window instead of the framebuffer. That leaves the web build
    # blurry on HiDPI displays, and enabling only the HiDPI hint renders into the
    # lower-left of an oversized canvas because SetupViewport() still sees logical
    # window pixels. Patch it in-place so the embedded demo uses framebuffer pixels.
    # Upstream trail: raylib issue #3372 and PR #3520.
    set(RAYLIB_RCORE_WEB "${raylib_SOURCE_DIR}/src/platforms/rcore_web.c")
    file(READ "${RAYLIB_RCORE_WEB}" RAYLIB_RCORE_WEB_CONTENTS)

    replace_or_fail(RAYLIB_RCORE_WEB_CONTENTS
        "    //if (FLAG_IS_SET(CORE.Window.flags, FLAG_WINDOW_HIGHDPI)) glfwWindowHint(GLFW_SCALE_TO_MONITOR, GLFW_TRUE);\n    //else glfwWindowHint(GLFW_SCALE_TO_MONITOR, GLFW_FALSE);"
        "    if (FLAG_IS_SET(CORE.Window.flags, FLAG_WINDOW_HIGHDPI)) glfwWindowHint(GLFW_SCALE_TO_MONITOR, GLFW_TRUE);\n    else glfwWindowHint(GLFW_SCALE_TO_MONITOR, GLFW_FALSE);"
    )

    replace_or_fail(RAYLIB_RCORE_WEB_CONTENTS
        "        int fbWidth = CORE.Window.screen.width;\n        int fbHeight = CORE.Window.screen.height;\n\n        CORE.Window.render.width = fbWidth;\n        CORE.Window.render.height = fbHeight;\n        CORE.Window.currentFbo.width = fbWidth;\n        CORE.Window.currentFbo.height = fbHeight;"
        "        int fbWidth;\n        int fbHeight;\n\n        glfwGetFramebufferSize(platform.handle, &fbWidth, &fbHeight);\n\n        // Screen scaling matrix is required in case desired screen area is different from display area\n        CORE.Window.screenScale = MatrixScale((float)fbWidth/CORE.Window.screen.width, (float)fbHeight/CORE.Window.screen.height, 1.0f);\n\n        // no need to scale mouse as glfw is doing it already\n\n        CORE.Window.render.width = fbWidth;\n        CORE.Window.render.height = fbHeight;\n        CORE.Window.currentFbo.width = fbWidth;\n        CORE.Window.currentFbo.height = fbHeight;"
    )

    replace_or_fail(RAYLIB_RCORE_WEB_CONTENTS
        "static void WindowSizeCallback(GLFWwindow *window, int width, int height)\n{\n    // Reset viewport and projection matrix for new size\n    SetupViewport(width, height);\n\n    CORE.Window.currentFbo.width = width;\n    CORE.Window.currentFbo.height = height;\n    CORE.Window.resizedLastFrame = true;\n\n    if (IsWindowFullscreen()) return;\n\n    // Set current screen size\n    if (FLAG_IS_SET(CORE.Window.flags, FLAG_WINDOW_HIGHDPI))\n    {\n        Vector2 windowScaleDPI = GetWindowScaleDPI();\n\n        CORE.Window.screen.width = (unsigned int)(width/windowScaleDPI.x);\n        CORE.Window.screen.height = (unsigned int)(height/windowScaleDPI.y);\n    }\n    else\n    {\n        CORE.Window.screen.width = width;\n        CORE.Window.screen.height = height;\n    }\n\n    // NOTE: Postprocessing texture is not scaled to new size\n}\n\n// GLFW3: Called on window content (framebuffer) scaled\nstatic void WindowContentScaleCallback(GLFWwindow *window, float scalex, float scaley)\n{\n    CORE.Window.screenScale = MatrixScale(scalex, scaley, 1.0f);\n}"
        "static void WindowSizeCallback(GLFWwindow *window, int width, int height)\n{\n    CORE.Window.screen.width = width;\n    CORE.Window.screen.height = height;\n\n    int fbWidth;\n    int fbHeight;\n\n    glfwGetFramebufferSize(platform.handle, &fbWidth, &fbHeight);\n\n    // Screen scaling matrix is required in case desired screen area is different from display area\n    CORE.Window.screenScale = MatrixScale((float)fbWidth/(float)CORE.Window.screen.width, (float)fbHeight/(float)CORE.Window.screen.height, 1.0f);\n\n    CORE.Window.render.width = fbWidth;\n    CORE.Window.render.height = fbHeight;\n    CORE.Window.currentFbo.width = fbWidth;\n    CORE.Window.currentFbo.height = fbHeight;\n    CORE.Window.resizedLastFrame = true;\n\n    SetupViewport(fbWidth, fbHeight);\n\n    // NOTE: Postprocessing texture is not scaled to new size\n}\n\n// GLFW3: Called on window content (framebuffer) scaled\nstatic void WindowContentScaleCallback(GLFWwindow *window, float scalex, float scaley)\n{\n    CORE.Window.screenScale = MatrixScale(scalex, scaley, 1.0f);\n}"
    )

    replace_or_fail(RAYLIB_RCORE_WEB_CONTENTS
        "    emscripten_set_canvas_element_size(platform.canvasId, width, height);\n\n    SetupViewport(width, height); // Reset viewport and projection matrix for new size\n\n    CORE.Window.currentFbo.width = width;\n    CORE.Window.currentFbo.height = height;\n    CORE.Window.resizedLastFrame = true;\n\n    if (IsWindowFullscreen()) return 1;\n\n    // Set current screen size\n    CORE.Window.screen.width = width;\n    CORE.Window.screen.height = height;\n\n    glfwSetWindowSize(platform.handle, CORE.Window.screen.width, CORE.Window.screen.height);\n\n    // NOTE: Postprocessing texture is not scaled to new size\n\n    return 0;"
        "    if (IsWindowFullscreen()) return 1;\n\n    SetWindowSize(width, height); // will trigger callback\n\n    return 1; // The event was consumed by the callback handler"
    )

    file(WRITE "${RAYLIB_RCORE_WEB}" "${RAYLIB_RCORE_WEB_CONTENTS}")
endif()

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
