include(ExternalProject)

# Makes cross-compiling easier in the build_whatever.cmake files
if(NOT CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE ${PROJECT_SOURCE_DIR}/cmake_modules/toolchain_native.cmake)
endif()

# Automatic updates
if(TARGET_USE_CURL)
    add_compile_definitions(
        HAVE_STRUCT_TIMEVAL
        HAVE_CONFIG_H
        BUILDING_LIBCURL
        USE_MBEDTLS
        __USE_MINGW_ANSI_STDIO
        CURL_STATICLIB
    )

    if(TARGET_LINUX)
        # Linux can just use the package manager version of libcurl, yay
        add_definitions(-DPLATFORM_CURL)
    else()
        # curl
        file(GLOB CURL_SRCS ${PROJECT_SOURCE_DIR}/src/external/curl/*.c ${PROJECT_SOURCE_DIR}/src/external/curl/vtls/*.c ${PROJECT_SOURCE_DIR}/src/external/curl/vauth/*.c  ${PROJECT_SOURCE_DIR}/src/external/curl/vquic/*.c)
        list(APPEND SOURCE_FILES ${CURL_SRCS})
        include_directories(${PROJECT_SOURCE_DIR}/src/external/curl)

        # mbedtls
        file(GLOB MBEDTLS_SRCS ${PROJECT_SOURCE_DIR}/src/external/mbedtls/*.c)
        list(APPEND SOURCE_FILES ${MBEDTLS_SRCS})
        include_directories(${PROJECT_SOURCE_DIR}/src/external/mbedtls)

        add_definitions(-DPLATFORM_CURL)
    endif()
endif()

if(TARGET_NO_BLOBS)
    add_definitions(-DLINUX_TMP)
    add_definitions(-DNO_JK_MMAP)
endif()

# Enables all force powers by default, useful for debugging.
if(DEBUG_QOL_CHEATS)
    add_definitions(-DDEBUG_QOL_CHEATS)
endif()

find_package(GLUT)
if(NOT FreeGLUT_FOUND OR CMAKE_CROSSCOMPILING)
    message(STATUS "Going to build “FreeGLUT 3.4.0” from Git module")
    include(build_freeglut)
endif()

set(GLEW_USE_STATIC_LIBS TRUE)
find_package(GLEW 2.2.0)
if((NOT GLEW_FOUND OR CMAKE_CROSSCOMPILING) AND NOT PLAT_WASM)
    message(STATUS "Going to build “GLEW 2.2.0” from Git module")
    include(build_glew)
endif()

if (NOT TARGET_USE_BASICSOCKETS AND NOT TARGET_USE_GAMENETWORKINGSOCKETS)
    set(TARGET_USE_NOSOCKETS TRUE)
endif()


message(STATUS "Going to build “zlib 1.2.13” from Git module")
include(build_zlib)

if(TARGET_USE_PHYSFS)
    message(STATUS "Going to build “PhysFS 3.2.0” from Git module")
    include(build_physfs)
    add_compile_definitions(PLATFORM_PHYSFS)
endif()

if(TARGET_USE_GAMENETWORKINGSOCKETS)
    set(PROTOBUF_DEPENDS ZLIB_${CMAKE_SYSTEM_NAME}_${CMAKE_SYSTEM_PROCESSOR})
    set(PROTOBUF_BUILD_PROTOC_BINARIES TRUE)
    if(CMAKE_CROSSCOMPILING)
        # Build zlib for cross‑compiling target
        
        include(build_host_zlib)
        set(PROTOC_DEPENDS ZLIB_HOST_${CMAKE_HOST_SYSTEM_NAME}_${CMAKE_HOST_SYSTEM_PROCESSOR})
        
        # When cross‑compiling, build protoc for the host system
        message(STATUS "Going to build “protoc” for ${CMAKE_HOST_SYSTEM_NAME} on ${CMAKE_HOST_SYSTEM_PROCESSOR}")
        include(build_protoc)
        # When cross‑compiling, only build libprotobuf because the host system
        # cannot execute a cross-compiled libprotoc nor protoc
        set(PROTOBUF_BUILD_PROTOC_BINARIES FALSE)
        # Use native protoc when building GameNetworkingSockets
        set(GAMENETWORKINGSOCKETS_PROTOC_EXECUTABLE -DProtobuf_PROTOC_EXECUTABLE:FILEPATH=${Protoc_PROTOC_EXECUTABLE})
        set(GAMENETWORKINGSOCKETS_DEPENDS PROTOC)
    endif()

    find_package(GameNetworkingSockets 1.4.1)
    if(NOT GameNetworkingSockets_FOUND)
        message(STATUS "Going to build “protobuf 3.21.12” from Git module")
        include(build_protobuf)

        message(STATUS "Going to build “GameNetworkingSockets 1.4.1” from Git module")
        include(build_gns)
    endif()

    file(GLOB TARGET_GNS_SRCS ${PROJECT_SOURCE_DIR}/src/Platform/Networking/GNS/*.cpp)
    list(APPEND SOURCE_FILES ${TARGET_GNS_SRCS})

    add_compile_definitions(PLATFORM_GNS)
endif()

if(TARGET_USE_BASICSOCKETS)
    file(GLOB TARGET_BASIC_SRCS ${PROJECT_SOURCE_DIR}/src/Platform/Networking/Basic/*.c)
    list(APPEND SOURCE_FILES ${TARGET_BASIC_SRCS})

    add_definitions(-DPLATFORM_BASICSOCKETS)
endif()

if(TARGET_USE_NOSOCKETS AND NOT TARGET_HOOKS)
    file(GLOB TARGET_NOSOCK_SRCS ${PROJECT_SOURCE_DIR}/src/Platform/Networking/None/*.c)
    list(APPEND SOURCE_FILES ${TARGET_NOSOCK_SRCS})

    add_definitions(-DPLATFORM_NOSOCKETS)
endif()

message(STATUS "Going to build “libpng 1.6.39” from Git module")
include(build_libpng)

if(TARGET_USE_LIBSMACKER)
    list(APPEND SOURCE_FILES ${PROJECT_SOURCE_DIR}/src/external/libsmacker/smacker.c ${PROJECT_SOURCE_DIR}/src/external/libsmacker/smk_bitstream.c ${PROJECT_SOURCE_DIR}/src/external/libsmacker/smk_hufftree.c)
endif()

if(TARGET_USE_LIBSMUSHER)
    list(APPEND SOURCE_FILES ${PROJECT_SOURCE_DIR}/src/external/libsmusher/src/smush.c ${PROJECT_SOURCE_DIR}/src/external/libsmusher/src/codec48.c)
endif()

# Build SDL2 from sources (n/a for WASM)
if(TARGET_USE_SDL2 AND NOT PLAT_WASM)
    message(STATUS "Going to build “SDL 2.26.5” from Git module")
    include(build_sdl)

    if(TARGET_USE_OPENAL)
        message(STATUS "Going to build “SDL_mixer 2.6.3” from Git module")
        include(build_sdl_mixer)
    endif()
endif()

# SDL2 Platform/
if(TARGET_USE_SDL2)
    file(GLOB TARGET_SDL2_SRCS ${PROJECT_SOURCE_DIR}/src/Platform/SDL2/*.c)
    list(APPEND SOURCE_FILES ${TARGET_SDL2_SRCS})
    add_compile_definitions(SDL2_RENDER)
endif()

if(TARGET_USE_OPENGL)
    file(GLOB TARGET_GL_SRCS ${PROJECT_SOURCE_DIR}/src/Platform/GL/*.c)
    list(APPEND SOURCE_FILES ${TARGET_GL_SRCS})

    file(GLOB TARGET_GL_CPP_SRCS ${PROJECT_SOURCE_DIR}/src/Platform/GL/*.cpp)
    list(APPEND SOURCE_FILES ${TARGET_GL_CPP_SRCS})
endif()

if(TARGET_USE_OPENAL AND NOT PLAT_WASM)
    #find_package(OpenAL 1.23.1)
    if(NOT OPENAL_FOUND)
        message(STATUS "Going to build “libopenal 1.23.1” from Git module")
        include(build_openal)
    endif()
    add_compile_definitions(STDSOUND_OPENAL)
else()
    add_compile_definitions(STDSOUND_NULL)
endif()

if(TARGET_USE_D3D)
    file(GLOB TARGET_D3D_SRCS ${PROJECT_SOURCE_DIR}/src/Platform/D3D/*.c)
    list(APPEND SOURCE_FILES ${TARGET_D3D_SRCS})
endif()

if(TARGET_POSIX)
    file(GLOB TARGET_POSIX_SRCS ${PROJECT_SOURCE_DIR}/src/Platform/Posix/*.c)
    list(APPEND SOURCE_FILES ${TARGET_POSIX_SRCS})

    add_definitions(-DPLATFORM_POSIX)
endif()

if(TARGET_LINUX)
    list(APPEND SOURCE_FILES ${PROJECT_SOURCE_DIR}/src/external/nativefiledialog-extended/nfd_gtk.cpp)

    add_definitions(-DLINUX)
    add_definitions(-DPLATFORM_LINUX)
    add_definitions(-DPLATFORM_NO_CACERT_BLOB)
endif()

if(TARGET_MACOS)
    list(APPEND SOURCE_FILES ${PROJECT_SOURCE_DIR}/src/external/nativefiledialog-extended/nfd_cocoa.m)
    file(GLOB TARGET_MACOS_SRCS ${PROJECT_SOURCE_DIR}/src/Platform/macOS/*.c)
    list(APPEND SOURCE_FILES ${TARGET_MACOS_SRCS})
    file(GLOB TARGET_MACOS_M_SRCS ${PROJECT_SOURCE_DIR}/src/Platform/macOS/*.m)
    list(APPEND SOURCE_FILES ${TARGET_MACOS_M_SRCS})

    add_definitions(-DMACOS)
    add_definitions(-DLINUX)
endif()

if(TARGET_WASM)
    add_definitions(-DLINUX)
endif()

if(TARGET_CAN_JKGM)
    add_definitions(-DTARGET_CAN_JKGM)
endif()

if(TARGET_WIN32)
    include_directories(
        ${PROJECT_SOURCE_DIR}/3rdparty/drmingw-0.9.3-win64/include
        ${PROJECT_SOURCE_DIR}/3rdparty/SDL2_mixer/x86_64-w64-mingw32/include/SDL2
    )
    file(GLOB TARGET_WIN32_SRCS ${PROJECT_SOURCE_DIR}/src/Platform/Win32/*.c)
    list(APPEND SOURCE_FILES ${TARGET_WIN32_SRCS})

    add_subdirectory(${PROJECT_SOURCE_DIR}/packaging/win32)
    list(APPEND SOURCE_FILES ${PROJECT_SOURCE_DIR}/packaging/win32/openjkdf2.rc)

    # Prefer the POSIX wuRegistry (JSON) over native
    if (TARGET_POSIX OR PLAT_MSVC)
        list(REMOVE_ITEM SOURCE_FILES ${PROJECT_SOURCE_DIR}/src/Platform/Win32/wuRegistry.c)
    endif()

    if(PLAT_MSVC)
        list(APPEND SOURCE_FILES ${PROJECT_SOURCE_DIR}/src/Platform/Posix/wuRegistry.c)
    endif()

    if(TARGET_USE_SDL2)
        list(APPEND SOURCE_FILES ${PROJECT_SOURCE_DIR}/src/external/nativefiledialog-extended/nfd_win.cpp)
        if(PLAT_MSVC)
            set(LINK_LIBS ${LINK_LIBS} ole32.lib uuid.lib)
        endif()
    endif()
endif()
