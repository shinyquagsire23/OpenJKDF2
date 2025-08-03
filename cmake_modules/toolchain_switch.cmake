# CMake toolchain file for Nintendo Switch (devkitPro)
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_VERSION "0.0.0")
set(CMAKE_SYSTEM_PROCESSOR aarch64)

# Define a few important devkitPro system paths.
if(DEFINED ENV{DEVKITPRO})
    file(TO_CMAKE_PATH "$ENV{DEVKITPRO}" DEVKITPRO)
else()
    message(FATAL_ERROR "DEVKITPRO environment variable not set. Please install devkitPro.")
endif()

if(NOT IS_DIRECTORY ${DEVKITPRO})
    message(FATAL_ERROR "Please install devkitA64 or set DEVKITPRO in your environment.")
endif()

set(DEVKITA64 "${DEVKITPRO}/devkitA64")
set(LIBNX "${DEVKITPRO}/libnx")
set(PORTLIBS "${DEVKITPRO}/portlibs/switch")

if(NOT EXISTS ${DEVKITA64})
    message(FATAL_ERROR "devkitA64 not found at ${DEVKITA64}. Please install switch-dev package.")
endif()

if(NOT EXISTS ${LIBNX})
    message(FATAL_ERROR "libnx not found at ${LIBNX}. Please install libnx package.")
endif()

# Add devkitA64 GCC tools to CMake.
if(WIN32)
    set(CMAKE_C_COMPILER "${DEVKITA64}/bin/aarch64-none-elf-gcc.exe")
    set(CMAKE_CXX_COMPILER "${DEVKITA64}/bin/aarch64-none-elf-g++.exe")
    set(CMAKE_LINKER "${DEVKITA64}/bin/aarch64-none-elf-ld.exe")
    set(CMAKE_AR "${DEVKITA64}/bin/aarch64-none-elf-gcc-ar.exe" CACHE STRING "")
    set(CMAKE_RANLIB "${DEVKITA64}/bin/aarch64-none-elf-gcc-ranlib.exe" CACHE STRING "")
else()
    set(CMAKE_C_COMPILER "${DEVKITA64}/bin/aarch64-none-elf-gcc")
    set(CMAKE_CXX_COMPILER "${DEVKITA64}/bin/aarch64-none-elf-g++")
    set(CMAKE_LINKER "${DEVKITA64}/bin/aarch64-none-elf-ld")
    set(CMAKE_AR "${DEVKITA64}/bin/aarch64-none-elf-gcc-ar" CACHE STRING "")
    set(CMAKE_RANLIB "${DEVKITA64}/bin/aarch64-none-elf-gcc-ranlib" CACHE STRING "")
endif()

# Prevent CMake from testing the compilers (they need special flags to work)
set(CMAKE_C_COMPILER_WORKS 1)
set(CMAKE_CXX_COMPILER_WORKS 1)

# Set compiler features for C++
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Manually set compiler features since CMake can't detect them for cross-compilers
set(CMAKE_CXX_COMPILE_FEATURES 
    cxx_std_98
    cxx_std_11
    cxx_std_14
    cxx_std_17
    cxx_std_20
    cxx_alias_templates
    cxx_alignas
    cxx_alignof
    cxx_attributes
    cxx_auto_type
    cxx_constexpr
    cxx_decltype
    cxx_decltype_auto
    cxx_default_function_template_args
    cxx_defaulted_functions
    cxx_delegating_constructors
    cxx_deleted_functions
    cxx_final
    cxx_generalized_initializers
    cxx_generic_lambdas
    cxx_inheriting_constructors
    cxx_lambda_init_captures
    cxx_lambdas
    cxx_noexcept
    cxx_nonstatic_member_init
    cxx_nullptr
    cxx_override
    cxx_range_for
    cxx_raw_string_literals
    cxx_right_angle_brackets
    cxx_rvalue_references
    cxx_static_assert
    cxx_strong_enums
    cxx_trailing_return_types
    cxx_unicode_literals
    cxx_uniform_initialization
    cxx_unrestricted_unions
    cxx_user_literals
    cxx_variadic_templates
)

# Set C standard and features
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Manually set C compiler features
set(CMAKE_C_COMPILE_FEATURES
    c_std_90
    c_std_99
    c_std_11
    c_function_prototypes
    c_restrict
    c_static_assert
    c_variadic_macros
)

# Compiler flags
set(ARCH_FLAGS "-march=armv8-a+crc+crypto -mtune=cortex-a57 -mtp=soft -fPIE")
set(CMAKE_C_FLAGS_INIT "${ARCH_FLAGS}")
set(CMAKE_CXX_FLAGS_INIT "${ARCH_FLAGS}")

# Find root path settings
set(CMAKE_FIND_ROOT_PATH ${DEVKITPRO} ${DEVKITA64} ${LIBNX} ${PORTLIBS})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Add tools to program path
list(APPEND CMAKE_PROGRAM_PATH "${DEVKITPRO}/tools/bin")
list(APPEND CMAKE_PROGRAM_PATH "${DEVKITA64}/bin")

# Set install and prefix paths
set(CMAKE_INSTALL_PREFIX ${PORTLIBS} CACHE PATH "Install libraries to the portlibs directory")
set(CMAKE_PREFIX_PATH ${PORTLIBS} CACHE PATH "Find libraries in the portlibs directory")

# Platform identification
set(PLAT_SWITCH TRUE)
set(NINTENDO_SWITCH TRUE)
set(SWITCH TRUE)
add_compile_options(-Wno-implicit-function-declaration)
# Additional include paths for Switch portlibs
if(EXISTS "${PORTLIBS}/include")
    message(STATUS "Found portlibs include directory")
    include_directories("${PORTLIBS}/include")
endif()

# OpenAL specific paths
if(EXISTS "${PORTLIBS}/include/AL")
    include_directories("${PORTLIBS}/include")
endif()

message(STATUS "Nintendo Switch ARM64 toolchain invoked")
message(STATUS "DevkitPro: ${DEVKITPRO}")
message(STATUS "DevkitA64: ${DEVKITA64}")
message(STATUS "libnx: ${LIBNX}")
message(STATUS "Portlibs: ${PORTLIBS}")
