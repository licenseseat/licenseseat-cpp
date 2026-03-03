cmake_minimum_required(VERSION 3.16)
project(ImageToolDemo VERSION 1.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# Add parent LicenseSeat SDK
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/.. ${CMAKE_CURRENT_BINARY_DIR}/licenseseat)

# Fetch raylib
FetchContent_Declare(
    raylib
    GIT_REPOSITORY https://github.com/raysan5/raylib.git
    GIT_TAG master
    GIT_SHALLOW TRUE
)
set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(raylib)

# Fetch raygui (single header, we just need the file)
FetchContent_Declare(
    raygui
    GIT_REPOSITORY https://github.com/raysan5/raygui.git
    GIT_TAG master
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(raygui)

# === macOS Bundle Configuration ===
set(MACOSX_BUNDLE_BUNDLE_NAME "ImageTool Pro")
set(MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION})
set(MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION})
set(MACOSX_BUNDLE_LONG_VERSION_STRING ${PROJECT_VERSION})
set(MACOSX_BUNDLE_GUI_IDENTIFIER "com.licenseseat.imagetool-demo")
set(MACOSX_BUNDLE_ICON_FILE "AppIcon.icns")
set(MACOSX_BUNDLE_COPYRIGHT "Copyright © 2026 LicenseSeat")

# Icon file for macOS bundle
set(APP_ICON_MACOS "${CMAKE_CURRENT_SOURCE_DIR}/resources/AppIcon.icns")
set_source_files_properties(${APP_ICON_MACOS} PROPERTIES MACOSX_PACKAGE_LOCATION "Resources")

# Font file (copy to app bundle)
set(APP_FONT "${CMAKE_CURRENT_SOURCE_DIR}/resources/Inter-Medium.ttf")
set_source_files_properties(${APP_FONT} PROPERTIES MACOSX_PACKAGE_LOCATION "Resources")

# Demo executable
add_executable(imagetool_demo MACOSX_BUNDLE
    main_gui.cpp
    ${APP_ICON_MACOS}
    ${APP_FONT}
)

target_link_libraries(imagetool_demo PRIVATE raylib licenseseat::licenseseat)

# Include raygui header and SDK
target_include_directories(imagetool_demo PRIVATE
    ${raygui_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}  # For style_dark.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../include  # LicenseSeat SDK headers
)

# Platform-specific
if(APPLE)
    target_link_libraries(imagetool_demo PRIVATE "-framework IOKit" "-framework Cocoa" "-framework OpenGL")

    # Set bundle properties
    set_target_properties(imagetool_demo PROPERTIES
        MACOSX_BUNDLE TRUE
        MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/Info.plist.in"
    )

    # Copy resources to bundle
    add_custom_command(TARGET imagetool_demo POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_BUNDLE_CONTENT_DIR:imagetool_demo>/Resources"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "${APP_FONT}" "$<TARGET_BUNDLE_CONTENT_DIR:imagetool_demo>/Resources/"
    )
elseif(UNIX)
    target_link_libraries(imagetool_demo PRIVATE m pthread dl)
endif()
