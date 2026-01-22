cmake_minimum_required(VERSION 3.15)

set(CMAKE_C_COMPILER /usr/bin/gcc)
set(CMAKE_CXX_COMPILER /usr/bin/g++-12)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(bind_mount C)

add_library(bind_mount_lib STATIC
    src/bind_mount.c
)

target_include_directories(bind_mount_lib
    PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

add_executable(bind_mount
    src/main.c
)

target_link_libraries(bind_mount PRIVATE bind_mount_lib)
