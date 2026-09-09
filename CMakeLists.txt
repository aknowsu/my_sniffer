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

# Common, platform-agnostic code.
file(GLOB_RECURSE COMMON_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")
list(FILTER COMMON_SOURCES EXCLUDE REGEX "/src/platform/")

add_executable(my_sniffer ${COMMON_SOURCES})

target_compile_definitions(my_sniffer PRIVATE
    SNIFFER_NAME="${PROJECT_NAME}"
    SNIFFER_VERSION="${PROJECT_VERSION}")

# Platform-specific capture backend: raw capture implemented by hand,
# NO networking library allowed by the subject.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_sources(my_sniffer PRIVATE src/platform/capture_linux.cpp)   # AF_PACKET / SOCK_RAW
    target_compile_definitions(my_sniffer PRIVATE SNIFFER_PLATFORM_LINUX=1)
elseif(WIN32)
    target_sources(my_sniffer PRIVATE src/platform/capture_windows.cpp) # raw socket + SIO_RCVALL
    target_compile_definitions(my_sniffer PRIVATE SNIFFER_PLATFORM_WINDOWS=1)
    target_link_libraries(my_sniffer PRIVATE ws2_32 iphlpapi)
else()
    message(FATAL_ERROR "No capture backend for ${CMAKE_SYSTEM_NAME}")
endif()

target_include_directories(my_sniffer PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/my_func")

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
