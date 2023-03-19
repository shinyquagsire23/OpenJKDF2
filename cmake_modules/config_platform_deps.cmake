# Automatic updates
if(TARGET_USE_CURL)
    add_definitions(-DHAVE_STRUCT_TIMEVAL)
    add_definitions(-DHAVE_CONFIG_H)
    add_definitions(-DBUILDING_LIBCURL)
    add_definitions(-DUSE_MBEDTLS)
    add_definitions(-D__USE_MINGW_ANSI_STDIO)

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

if(TARGET_USE_PHYSFS)
    include_directories(${PROJECT_SOURCE_DIR}/3rdparty/physfs/src)
    add_definitions(-DPLATFORM_PHYSFS)
endif()

if (NOT TARGET_USE_BASICSOCKETS AND NOT TARGET_USE_GAMENETWORKINGSOCKETS)
    set(TARGET_USE_NOSOCKETS TRUE)
endif()

if(TARGET_USE_GAMENETWORKINGSOCKETS)
    file(GLOB TARGET_GNS_SRCS ${PROJECT_SOURCE_DIR}/src/Platform/Networking/GNS/*.cpp)
    list(APPEND SOURCE_FILES ${TARGET_GNS_SRCS})

    add_definitions(-DPLATFORM_GNS)
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

if(TARGET_USE_LIBSMACKER)
    list(APPEND SOURCE_FILES ${PROJECT_SOURCE_DIR}/src/external/libsmacker/smacker.c ${PROJECT_SOURCE_DIR}/src/external/libsmacker/smk_bitstream.c ${PROJECT_SOURCE_DIR}/src/external/libsmacker/smk_hufftree.c)
endif()

if(TARGET_USE_LIBSMUSHER)
    list(APPEND SOURCE_FILES ${PROJECT_SOURCE_DIR}/src/external/libsmusher/src/smush.c ${PROJECT_SOURCE_DIR}/src/external/libsmusher/src/codec48.c)
endif()

if(TARGET_USE_SDL2)
    file(GLOB TARGET_SDL2_SRCS ${PROJECT_SOURCE_DIR}/src/Platform/SDL2/*.c)
    list(APPEND SOURCE_FILES ${TARGET_SDL2_SRCS})
    add_definitions(-DSDL2_RENDER)
    
endif()

if(TARGET_USE_OPENGL)
    file(GLOB TARGET_GL_SRCS ${PROJECT_SOURCE_DIR}/src/Platform/GL/*.c)
    list(APPEND SOURCE_FILES ${TARGET_GL_SRCS})

    file(GLOB TARGET_GL_CPP_SRCS ${PROJECT_SOURCE_DIR}/src/Platform/GL/*.cpp)
    list(APPEND SOURCE_FILES ${TARGET_GL_CPP_SRCS})
endif()

if(TARGET_USE_OPENAL)
    add_definitions(-DSTDSOUND_OPENAL)
else()
    add_definitions(-DSTDSOUND_NULL)
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
    file(GLOB TARGET_WIN32_SRCS ${PROJECT_SOURCE_DIR}/src/Platform/Win32/*.c)
    list(APPEND SOURCE_FILES ${TARGET_WIN32_SRCS})

    list(APPEND SOURCE_FILES ${PROJECT_SOURCE_DIR}/packaging/win32/openjkdf2.rc)

    # Prefer the POSIX wuRegistry (JSON) over native
    if (TARGET_POSIX OR PLAT_MSVC)
        list(REMOVE_ITEM SOURCE_FILES ${PROJECT_SOURCE_DIR}/src/Platform/Win32/wuRegistry.c)
    endif()

    if (PLAT_MSVC)
        list(APPEND SOURCE_FILES ${PROJECT_SOURCE_DIR}/src/Platform/Posix/wuRegistry.c)
    endif()

    if(TARGET_USE_SDL2)
        list(APPEND SOURCE_FILES ${PROJECT_SOURCE_DIR}/src/external/nativefiledialog-extended/nfd_win.cpp)
        if(PLAT_MSVC)
            set(LINK_LIBS ${LINK_LIBS} ole32.lib uuid.lib)
        else()
            add_link_options(-lm -ldinput8 -ldxguid -ldxerr8 -luser32 -lgdi32 -lwinmm -limm32 -lole32 -loleaut32 -lshell32 -lsetupapi -lversion -luuid -lws2_32)
        endif()
    endif()
endif()