# CMake toolchain file for the Sega Dreamcast (KallistiOS).
#
# The KallistiOS environment must be sourced before configuring, e.g.:
#     source /opt/toolchains/dc/kos/environ.sh
# which exports KOS_BASE, KOS_CC_BASE, KOS_ARCH, etc.
#
# We delegate the heavy lifting (kos-cc/kos-c++ wrappers, SH4 flags, sysroot,
# kos-ports) to KOS's own maintained CMake toolchain, then flag PLAT_DREAMCAST
# so CMakeLists.txt selects plat_dreamcast.cmake.

if(NOT DEFINED ENV{KOS_BASE})
    message(FATAL_ERROR
        "KallistiOS environment not found. Source it first, e.g.:\n"
        "    source /opt/toolchains/dc/kos/environ.sh")
endif()

include($ENV{KOS_BASE}/utils/cmake/kallistios.toolchain.cmake)

# Force the cache entry so the `set(PLAT_DREAMCAST FALSE CACHE BOOL ...)` default in
# CMakeLists.txt doesn't clobber it (the included KOS toolchain shifts policy scope,
# which otherwise drops a plain normal variable set here).
set(PLAT_DREAMCAST TRUE CACHE BOOL "Sega Dreamcast (KallistiOS)" FORCE)

message(STATUS "Sega Dreamcast (KallistiOS) toolchain invoked")
