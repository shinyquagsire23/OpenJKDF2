set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_VERSION 6.0)
set(CMAKE_SYSTEM_PROCESSOR x86_64)
set(TOOLCHAIN_PREFIX x86_64-w64-mingw32)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)

set(CMAKE_C_COMPILER   "${TOOLCHAIN_PREFIX}-gcc" CACHE STRING "C compiler" FORCE)
set(CMAKE_CXX_COMPILER "${TOOLCHAIN_PREFIX}-g++" CACHE STRING "C++ compiler" FORCE)
set(CMAKE_RC_COMPILER  "${TOOLCHAIN_PREFIX}-windres" CACHE STRING "RC compiler" FORCE)
# windres chokes on the OPENJKDF2_RELEASE_VERSION_STRING_W macro when pre-processor output is piped
set(CMAKE_RC_FLAGS "--use-temp-file")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

string(REGEX MATCH "^[0-9]+" CMAKE_SYSTEM_MAJOR_VERSION ${CMAKE_SYSTEM_VERSION})
string(REGEX REPLACE "^[0-9]+\\.([0-9]+).*" "\\1" CMAKE_SYSTEM_MINOR_VERSION ${CMAKE_SYSTEM_VERSION})

add_compile_options(-fstack-check=no -fno-stack-limit)
add_link_options(
    -Wl,-t
#   -flto=auto -ffat-lto-objects -flto-compression-level=9 -flto-partition=one
)

string(JOIN " " CMAKE_C_FLAGS_INIT
# We do not want to link to the deprecated MSVCRT.DLL (Microsoft Visual C++ 6.0) C runtime library
# and unfortunately, -nolibc does not get rid of MSVCRT.DLL completely
    -nodefaultlibs
# __imp_ prefixed symbols are long time obsolete and not used in static libs anyway
    -mnop-fun-dllimport)
set(CMAKE_CXX_FLAGS_INIT ${CMAKE_C_FLAGS_INIT})
# Unfortunately, CMAKE_SIZEOF_VOID_P is not yet available for determining machine word size
if(CMAKE_SYSTEM_PROCESSOR STREQUAL x86 OR
   CMAKE_SYSTEM_PROCESSOR STREQUAL arm)
set(MINGW_STACK_SIZE  0x10000,0x1000)
set(MINGW_HEAP_SIZE 0x100000,0x10000)
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL x86_64 OR
       CMAKE_SYSTEM_PROCESSOR STREQUAL AMD64 OR
       CMAKE_SYSTEM_PROCESSOR STREQUAL arm64 OR
       CMAKE_SYSTEM_PROCESSOR STREQUAL aarch64)
set(MINGW_STACK_SIZE  0x20000,0x2000)
set(MINGW_HEAP_SIZE 0x200000,0x20000)
else()
set(MINGW_STACK_SIZE  0x10000,0x1000)
set(MINGW_HEAP_SIZE 0x100000,0x10000)
endif()
set(CMAKE_EXE_LINKER_FLAGS_INIT
    "-Wl,--major-os-version,${CMAKE_SYSTEM_MAJOR_VERSION},--minor-os-version,${CMAKE_SYSTEM_MINOR_VERSION}\
     -Wl,--major-subsystem-version,${CMAKE_SYSTEM_MAJOR_VERSION},--minor-subsystem-version,${CMAKE_SYSTEM_MINOR_VERSION}\
     -Wl,--major-image-version,${CMAKE_SYSTEM_MAJOR_VERSION},--minor-image-version,${CMAKE_SYSTEM_MINOR_VERSION}\
     -Wl,--dynamicbase,--nxcompat,--no-bind,--no-seh,--gc-sections,--no-insert-timestamp\
     -Wl,-Map,%\
     -Xlinker --stack -Xlinker ${MINGW_STACK_SIZE}\
     -Xlinker --heap  -Xlinker ${MINGW_HEAP_SIZE}" # -Wl does not support commas , in options
)
set(CMAKE_SHARED_LINKER_FLAGS_INIT "-mwindows ${CMAKE_EXE_LINKER_FLAGS_INIT}")
# Original MinGW default libs
# -lmingw32 -lgcc -lgcc_eh -lmoldname -lmingwex -lmsvcrt -ladvapi32 -lshell32 -luser32 -lkernel32 -lmingw32 -lgcc -lgcc_eh -lmoldname -lmingwex -lmsvcrt
# By design, MinGW should not link to advapi32 shell32 user32 by default anyway
set(CMAKE_C_STANDARD_LIBRARIES
# FIXME: static linking with MinGW is a challange because key static and dynamic libs are not symbol twins
    "-Wl,-Bstatic,-lpthread,-lmingwex,-lmingw32,-lgcc,-Bdynamic,-lmsvcr120,-lkernel32"
#   "-lpthread -lmingw32 -lgcc -lmingwex -lmsvcr120 -lkernel32" # link to msvcr120 aka Microsoft Visual C++ 2013 Redistributable
    CACHE INTERNAL CMAKE_C_STANDARD_LIBRARIES # there are nasty interdependencies between libpthread and libgcc/libgcc_eh
)
set(CMAKE_CXX_STANDARD_LIBRARIES
# FIXME: static linking with MinGW is a challange because key static and dynamic libs are not symbol twins
    "-Wl,-Bstatic,-lstdc++,-lpthread,-lmingwex,-lmingw32,-lgcc,-lgcc_eh,-Bdynamic,-lmsvcr120,-lkernel32"
#   "-lstdc++ -lpthread -lmingw32 -lgcc -lgcc_eh -lpthread -lmingwex -lmsvcr120 -lkernel32" # link to msvcr120 aka Microsoft Visual C++ 2013 Redistributable
    CACHE INTERNAL CMAKE_CXX_STANDARD_LIBRARIES # there are nasty interdependencies between libpthread and libgcc/libgcc_eh
)

set(WIN32 TRUE)
set(MINGW TRUE)
set(PLAT_MINGW_X86_64 TRUE CACHE BOOL "MinGW Win64 target")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake_modules")

message(STATUS "MinGW cross-compile toolchain invoked")
