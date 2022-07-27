# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.13.1)

# find_package(Zephyr) in order to load application boilerplate:
# http://docs.zephyrproject.org/application/application.html
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

# Path to "os" subdirectory of repository root.
get_filename_component(OS_DIR ${APPLICATION_SOURCE_DIR} DIRECTORY)
# Path to repository root.
get_filename_component(ROOT_DIR ${OS_DIR} DIRECTORY)

file(READ "${ROOT_DIR}/VERSION" KVS_VERSION)
project(kvstst_${KVS_VERSION})

# Path to kvs library
set(KVS_DIR "${ROOT_DIR}/lib")
assert_exists(KVS_DIR)

if(CONFIG_KVS)

zephyr_include_directories(
    ${ROOT_DIR}/lib/include
)

zephyr_library_sources(
    ${ROOT_DIR}/lib/src/kvs.c
)

zephyr_library_sources(
    ./src/main.c
)
endif()