cmake_minimum_required(VERSION 3.5)
project(ext2_parsing C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(SRC_FILES
    main.c
    parse.c
)

add_executable(ext2_parser ${SRC_FILES})

target_include_directories(ext2_parser PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
