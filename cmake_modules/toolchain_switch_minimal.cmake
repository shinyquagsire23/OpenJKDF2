# Minimal CMake toolchain file for Nintendo Switch (devkitPro)
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_VERSION "0.0.0")
set(CMAKE_SYSTEM_PROCESSOR aarch64)

# Define devkitPro system paths
if(DEFINED ENV{DEVKITPRO})
    file(TO_CMAKE_PATH "$ENV{DEVKITPRO}" DEVKITPRO)
else()
    message(FATAL_ERROR "DEVKITPRO environment variable not set. Please install devkitPro.")
endif()

set(DEVKITA64 "${DEVKITPRO}/devkitA64")
set(LIBNX "${DEVKITPRO}/libnx")
set(PORTLIBS "${DEVKITPRO}/portlibs/switch")

if(NOT EXISTS ${DEVKITA64})
    message(FATAL_ERROR "devkitA64 not found at ${DEVKITA64}")
endif()

if(NOT EXISTS ${LIBNX})
    message(FATAL_ERROR "libnx not found at ${LIBNX}")
endif()

# Set compilers
set(CMAKE_C_COMPILER "${DEVKITA64}/bin/aarch64-none-elf-gcc")
set(CMAKE_CXX_COMPILER "${DEVKITA64}/bin/aarch64-none-elf-g++")
set(CMAKE_ASM_COMPILER "${DEVKITA64}/bin/aarch64-none-elf-gcc")
set(CMAKE_AR "${DEVKITA64}/bin/aarch64-none-elf-gcc-ar")
set(CMAKE_RANLIB "${DEVKITA64}/bin/aarch64-none-elf-gcc-ranlib")
set(CMAKE_STRIP "${DEVKITA64}/bin/aarch64-none-elf-strip")

# Skip compiler tests
set(CMAKE_C_COMPILER_WORKS 1)
set(CMAKE_CXX_COMPILER_WORKS 1)
set(CMAKE_ASM_COMPILER_WORKS 1)

# Compiler and linker flags
set(ARCH_FLAGS "-march=armv8-a+crc+crypto -mtune=cortex-a57 -mtp=soft -fPIC -ftls-model=local-exec")

set(CMAKE_C_FLAGS_INIT "${ARCH_FLAGS} -ffunction-sections -fdata-sections")
set(CMAKE_CXX_FLAGS_INIT "${ARCH_FLAGS} -ffunction-sections -fdata-sections -fno-rtti -fno-exceptions")
set(CMAKE_ASM_FLAGS_INIT "${ARCH_FLAGS}")

# Essential linker flags for Switch
set(CMAKE_EXE_LINKER_FLAGS_INIT "-specs=${LIBNX}/switch.specs ${ARCH_FLAGS}")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "-specs=${LIBNX}/switch.specs ${ARCH_FLAGS}")

# Set find root path
set(CMAKE_FIND_ROOT_PATH ${DEVKITPRO} ${DEVKITA64} ${LIBNX} ${PORTLIBS})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Add library and include paths
include_directories(SYSTEM ${LIBNX}/include)
include_directories(SYSTEM ${PORTLIBS}/include)
include_directories(SYSTEM ${PORTLIBS}/include/SDL2)
link_directories(${LIBNX}/lib)
link_directories(${PORTLIBS}/lib)

# Set pkg-config paths for finding SDL2 and other libraries
set(ENV{PKG_CONFIG_PATH} "${PORTLIBS}/lib/pkgconfig:${LIBNX}/lib/pkgconfig")
set(PKG_CONFIG_EXECUTABLE "${DEVKITPRO}/portlibs/switch/bin/aarch64-none-elf-pkg-config")

# Platform identification
set(SWITCH TRUE)
set(NINTENDO_SWITCH TRUE)
add_definitions(-D__SWITCH__ -DSWITCH -DNINTENDO_SWITCH)

message(STATUS "Nintendo Switch toolchain configured")
message(STATUS "DevkitPro: ${DEVKITPRO}")
message(STATUS "DevkitA64: ${DEVKITA64}")
message(STATUS "libnx: ${LIBNX}")
message(STATUS "Portlibs: ${PORTLIBS}")
