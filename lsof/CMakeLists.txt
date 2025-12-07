cmake_minimum_required(VERSION 3.15)

set(CMAKE_C_COMPILER /usr/bin/gcc)
set(CMAKE_CXX_COMPILER /usr/bin/g++-12)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(lsof_project VERSION 0.1 LANGUAGES C)

option(BUILD_TESTS "Build unit tests" OFF)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(lsof STATIC
    src/lsof.c
    src/utils.c
    src/main.c
)

target_include_directories(lsof
    PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

add_executable(lsof_demo
    src/main.c
)

target_link_libraries(lsof_demo PRIVATE lsof)
