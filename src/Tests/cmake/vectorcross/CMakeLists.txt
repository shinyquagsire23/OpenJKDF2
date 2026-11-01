cmake_minimum_required(VERSION 3.20)
project(OpenJKDF2VectorCrossTest LANGUAGES C CXX)
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "This focused source target requires a Linux host")
endif()
enable_testing()
find_package(Python3 REQUIRED COMPONENTS Interpreter)
get_filename_component(ENGINE_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)
set(TEST_ROOT "${ENGINE_ROOT}/src/Tests")
# Only the normal globals header generator is needed; do not configure or build
# the game and its graphical/audio/network dependencies for this host test.
file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/generated")
set(GLOBALS "${CMAKE_CURRENT_BINARY_DIR}/generated/globals.h")
add_custom_command(OUTPUT "${GLOBALS}"
    COMMAND "${Python3_EXECUTABLE}" -m cogapp -d
        -D "symbols_fpath=${ENGINE_ROOT}/symbols.syms"
        -D "project_root=${ENGINE_ROOT}" -D "embedded_resources="
        -o "${GLOBALS}" "${ENGINE_ROOT}/src/globals.h.cog"
    DEPENDS "${ENGINE_ROOT}/symbols.syms" "${ENGINE_ROOT}/src/globals.h.cog"
    VERBATIM)
add_executable(vectorcross_test "${TEST_ROOT}/vectorcross_test.c" "${GLOBALS}"
    "${ENGINE_ROOT}/src/Cog/sithCogFunction.c" "${ENGINE_ROOT}/src/Cog/sithCogExec.c" "${ENGINE_ROOT}/src/Cog/sithCogParse.c"
    "${ENGINE_ROOT}/src/Primitives/rdVector.c" "${ENGINE_ROOT}/src/stdPlatform.c" "${ENGINE_ROOT}/src/jk.c")
target_include_directories(vectorcross_test PRIVATE "${ENGINE_ROOT}/src" "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_compile_definitions(vectorcross_test PRIVATE LINUX PLATFORM_POSIX NO_JK_MMAP STDSOUND_NULL QOL_IMPROVEMENTS OPENJKDF2_FOCUSED_TEST)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_compile_definitions(vectorcross_test PRIVATE ARCH_64BIT)
endif()
target_compile_options(vectorcross_test PRIVATE -ffunction-sections -fdata-sections -fshort-wchar)
if(APPLE)
    target_link_options(vectorcross_test PRIVATE -Wl,-dead_strip)
else()
    target_link_options(vectorcross_test PRIVATE -Wl,--gc-sections)
endif()
target_link_libraries(vectorcross_test PRIVATE m)
option(ENABLE_UBSAN "Enable undefined behavior sanitizer" OFF)
if(ENABLE_UBSAN)
    target_compile_options(vectorcross_test PRIVATE -fsanitize=undefined -fno-sanitize-recover=undefined)
    target_link_options(vectorcross_test PRIVATE -fsanitize=undefined)
endif()
add_test(NAME vectorcross COMMAND vectorcross_test)
set_tests_properties(vectorcross PROPERTIES TIMEOUT 30)
