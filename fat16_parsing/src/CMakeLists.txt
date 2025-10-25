cmake_minimum_required(VERSION 3.5)
project(fat16_parsing C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Sources
set(SRC_FILES
    main.c
    parse.c
)

add_executable(fat16_parser ${SRC_FILES})

# Ensure the current directory is used for headers
target_include_directories(fat16_parser PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Optional: show compile warnings
if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
    target_compile_options(fat16_parser PRIVATE -Wall -Wextra -Wpedantic)
endif()
