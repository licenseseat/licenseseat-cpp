cmake_minimum_required(VERSION 3.14)

project(licenseseat_package_consumer LANGUAGES CXX)

find_package(licenseseat CONFIG REQUIRED)

add_executable(licenseseat_package_consumer main.cpp)
target_compile_features(licenseseat_package_consumer PRIVATE cxx_std_17)
target_link_libraries(licenseseat_package_consumer PRIVATE licenseseat::licenseseat)
