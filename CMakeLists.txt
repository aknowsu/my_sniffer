cmake_minimum_required(VERSION 3.16)

project(my_sniffer
    VERSION 0.1.0
    DESCRIPTION "Cross-platform network packet sniffer (from-scratch capture)"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

file(GLOB_RECURSE COMMON_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")
list(FILTER COMMON_SOURCES EXCLUDE REGEX "/src/platform/")

add_executable(my_sniffer ${COMMON_SOURCES})

target_include_directories(my_sniffer PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_compile_definitions(my_sniffer PRIVATE
    SNIFFER_NAME="${PROJECT_NAME}"
    SNIFFER_VERSION="${PROJECT_VERSION}")

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_sources(my_sniffer PRIVATE src/platform/capture_linux.cpp)
    target_compile_definitions(my_sniffer PRIVATE SNIFFER_PLATFORM_LINUX=1)
elseif(WIN32)
    target_sources(my_sniffer PRIVATE src/platform/capture_windows.cpp)
    target_compile_definitions(my_sniffer PRIVATE SNIFFER_PLATFORM_WINDOWS=1)

    if(NOT NPCAP_SDK_DIR)
        set(NPCAP_SDK_DIR "$ENV{NPCAP_SDK_DIR}" CACHE PATH "Path to the Npcap SDK")
    endif()
    find_path(NPCAP_INCLUDE_DIR Packet32.h HINTS "${NPCAP_SDK_DIR}/Include")
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        find_library(NPCAP_PACKET_LIB Packet HINTS "${NPCAP_SDK_DIR}/Lib/x64")
    else()
        find_library(NPCAP_PACKET_LIB Packet HINTS "${NPCAP_SDK_DIR}/Lib")
    endif()
    if(NOT NPCAP_INCLUDE_DIR OR NOT NPCAP_PACKET_LIB)
        message(FATAL_ERROR "Npcap SDK not found. Install it from https://npcap.com/#download "
                             "and pass its path with -DNPCAP_SDK_DIR=<path> "
                             "or the NPCAP_SDK_DIR environment variable.")
    endif()
    target_include_directories(my_sniffer PRIVATE "${NPCAP_INCLUDE_DIR}")
    target_link_libraries(my_sniffer PRIVATE "${NPCAP_PACKET_LIB}")
else()
    message(FATAL_ERROR "No capture backend for ${CMAKE_SYSTEM_NAME}")
endif()

if(MSVC)
    target_compile_options(my_sniffer PRIVATE /W4 /WX /permissive-)
else()
    target_compile_options(my_sniffer PRIVATE
        -Wall -Wextra -Wpedantic -Werror
        $<$<CONFIG:Debug>:-g -O0 -fsanitize=address,undefined>)
    target_link_options(my_sniffer PRIVATE
        $<$<CONFIG:Debug>:-fsanitize=address,undefined>)
endif()

install(TARGETS my_sniffer RUNTIME DESTINATION bin)
