cmake_minimum_required(VERSION 3.20)
project(SwiftFS VERSION 0.1.0 LANGUAGES CXX)

# Require C++20 standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Platform-specific compiler options and optimization flags
if(MSVC)
    add_compile_options(
        /W4
        /O2
        /permissive-
        /Zc:__cplusplus
        /utf-8
    )
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
        -O3
        -march=native
    )
endif()

# ---------------------------------------------------------------------------
# 1. SwiftFS Core C++ Library
# ---------------------------------------------------------------------------
set(SWIFTFS_CORE_HEADERS
    include/scanner.hpp
    include/hasher.hpp
    include/processor.hpp
    include/analyzer.hpp
    include/swiftfs.hpp
)

set(SWIFTFS_CORE_SOURCES
    cpp/scanner.cpp
    cpp/hasher.cpp
    cpp/processor.cpp
    cpp/analyzer.cpp
)

add_library(swiftfs_core STATIC
    ${SWIFTFS_CORE_SOURCES}
    ${SWIFTFS_CORE_HEADERS}
)

target_include_directories(swiftfs_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Multi-threading support (std::jthread / worker threads)
find_package(Threads REQUIRED)
target_link_libraries(swiftfs_core PUBLIC Threads::Threads)

# ---------------------------------------------------------------------------
# 2. Pybind11 Python Native Extension Module
# ---------------------------------------------------------------------------
# Try to find pybind11 via system/virtualenv first, fallback to FetchContent
find_package(pybind11 CONFIG QUIET)

if(NOT pybind11_FOUND)
    include(FetchContent)
    FetchContent_Declare(
        pybind11
        GIT_REPOSITORY https://github.com/pybind/pybind11.git
        GIT_TAG        v2.13.6
    )
    FetchContent_MakeAvailable(pybind11)
endif()

# Define the native Python C-extension module
pybind11_add_module(_swiftfs_core bindings/bindings.cpp)
target_link_libraries(_swiftfs_core PRIVATE swiftfs_core)

# Output compiled binary to python/ package directory for easy local import
set_target_properties(_swiftfs_core PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/python"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_SOURCE_DIR}/python"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_SOURCE_DIR}/python"
    OUTPUT_NAME "_swiftfs_core"
)

# ---------------------------------------------------------------------------
# 3. Optional Testing
# ---------------------------------------------------------------------------
enable_testing()
file(GLOB TEST_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp")
if(TEST_SOURCES)
    add_executable(swiftfs_tests ${TEST_SOURCES})
    target_link_libraries(swiftfs_tests PRIVATE swiftfs_core)
    add_test(NAME swiftfs_tests COMMAND swiftfs_tests)
endif()
