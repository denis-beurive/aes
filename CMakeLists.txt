cmake_minimum_required(VERSION 3.28)
project(aes C)
set(CMAKE_C_STANDARD 23)
enable_testing()
include(CMakePrintHelpers)
add_definitions(-DTRACE)


set(SRC_DIRECTORY "${CMAKE_SOURCE_DIR}/src")
set(BIN_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")
set(LIB_DIRECTORY "${CMAKE_SOURCE_DIR}/lib")
set(TEST_DIRECTORY "${CMAKE_SOURCE_DIR}/test")

cmake_print_variables(CMAKE_SOURCE_DIR)
cmake_print_variables(CMAKE_BINARY_DIR)

include_directories(${SRC_DIRECTORY})

add_library(aes_util STATIC src/aes_utils.c src/aes_utils.h)
set_target_properties(
        aes_util
        PROPERTIES
        COMPILE_FLAGS -Wall
        POSITION_INDEPENDENT_CODE ON
        ARCHIVE_OUTPUT_DIRECTORY ${LIB_DIRECTORY}
        EXCLUDE_FROM_ALL off)

add_library(aes STATIC ${SRC_DIRECTORY}/aes.c ${SRC_DIRECTORY}/aes.h)
set_target_properties(
        aes
        PROPERTIES
        COMPILE_FLAGS -Wall
        POSITION_INDEPENDENT_CODE ON
        ARCHIVE_OUTPUT_DIRECTORY ${LIB_DIRECTORY}
        EXCLUDE_FROM_ALL off)

# Unit tests

add_executable(test-aes ${TEST_DIRECTORY}/test_aes.c)
add_dependencies(test-aes aes)
target_link_libraries(test-aes aes)
set_target_properties(
        test-aes
        PROPERTIES
        COMPILE_FLAGS -Wall
        RUNTIME_OUTPUT_DIRECTORY ${BIN_DIRECTORY}
        EXCLUDE_FROM_ALL false)
add_test(test-aes ${BIN_DIRECTORY}/test-aes)

add_executable(test-aes-utils ${TEST_DIRECTORY}/test_aes_utils.c)
add_dependencies(test-aes-utils aes_util)
target_link_libraries(test-aes-utils aes_util)
set_target_properties(
        test-aes-utils
        PROPERTIES
        COMPILE_FLAGS -Wall
        RUNTIME_OUTPUT_DIRECTORY ${BIN_DIRECTORY}
        EXCLUDE_FROM_ALL false)
add_test(test-aes-utils ${BIN_DIRECTORY}/test-aes-utils)

