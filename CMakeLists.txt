cmake_minimum_required(VERSION 3.20)

if(PLAT_MACOS_X86_64)
set(CMAKE_OSX_ARCHITECTURES "x86_64")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

set(SDL2_DIR "/usr/local/opt/sdl2")
set(SDL2_MIXER_PATH "/usr/local/opt/sdl2_mixer")
set(GLEW_PATH "/usr/local/opt/glew")
set(CMAKE_IGNORE_PATH "/opt/homebrew")
set(CMAKE_IGNORE_PATH "/opt/homebrew/include")
set(CMAKE_IGNORE_PATH "/opt/homebrew/lib")

list(APPEND CMAKE_PREFIX_PATH /usr/local)
endif()

project(OpenJKDF2)

# All of our supported platforms
set(PLAT_LINUX_32 FALSE CACHE BOOL "Linux 32-bit target")
set(PLAT_LINUX_64 FALSE CACHE BOOL "Linux 64-bit target")
set(PLAT_MACOS FALSE CACHE BOOL "MacOS target")
set(PLAT_MACOS_X86_64 FALSE CACHE BOOL "MacOS x86_64")
set(PLAT_MINGW_X86_64 FALSE CACHE BOOL "MinGW Win64 target")
set(PLAT_WASM FALSE CACHE BOOL "Emscripten WASM target")
set(PLAT_HOOKS FALSE CACHE BOOL "Hook DLL target")
set(PLAT_MSVC FALSE CACHE BOOL "Windows 64-bit MSVC")
set(PLAT_AUTO FALSE CACHE BOOL "Target the host OS")

# Set PLAT_AUTO if a platform isn't specifically selected
if(NOT PLAT_LINUX_32 AND NOT PLAT_LINUX_64 AND NOT PLAT_MACOS AND NOT PLAT_MACOS_X86_64 AND NOT PLAT_MINGW_X86_64 AND NOT PLAT_WASM AND NOT PLAT_HOOKS)
    set(PLAT_AUTO TRUE)
endif()

# Internal targets: Stuff like OpenGL vs D3D, OpenAL vs null sound, etc
set(TARGET_USE_LIBSMACKER FALSE)
set(TARGET_USE_SDL2 FALSE)
set(TARGET_USE_OPENGL FALSE)
set(TARGET_USE_D3D FALSE)
set(TARGET_POSIX FALSE)
set(TARGET_LINUX FALSE)
set(TARGET_MACOS FALSE)
set(TARGET_WIN32 FALSE)
set(TARGET_WASM FALSE)
set(TARGET_NO_BLOBS FALSE)
set(OPENJKDF2_USE_BLOBS FALSE CACHE BOOL "Use blobs")

set(DEBUG_QOL_CHEATS $ENV{DEBUG_QOL_CHEATS})

# Options for compiling
set(OPENJKDF2_NO_ASAN TRUE)

message( STATUS "${PLAT_MINGW_X86_64}")

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux" AND PLAT_AUTO)
    set(PLAT_LINUX_64 TRUE)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Darwin" AND PLAT_AUTO)
    set(PLAT_MACOS TRUE)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Windows" AND PLAT_AUTO)
    set(PLAT_MSVC TRUE)
endif()

add_definitions(-DQOL_IMPROVEMENTS)
set(CMAKE_CXX_STANDARD 17)

if(PLAT_LINUX_32)
    message( STATUS "Targeting Linux 32-bit" )
    set(BIN_NAME "openjkdf2")
    
    add_definitions(-D_XOPEN_SOURCE=500)
    add_definitions(-D_DEFAULT_SOURCE)

    set(TARGET_USE_LIBSMACKER TRUE)
    set(TARGET_USE_SDL2 TRUE)
    set(TARGET_USE_OPENGL TRUE)
    set(TARGET_POSIX TRUE)
    set(TARGET_LINUX TRUE)
    set(TARGET_NO_BLOBS TRUE)
    set(OPENJKDF2_NO_ASAN TRUE)

    if(OPENJKDF2_USE_BLOBS)
        set(TARGET_NO_BLOBS FALSE)
    endif()
    
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -std=c11 -fshort-wchar")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
    add_link_options(-fshort-wchar)

elseif(PLAT_LINUX_64)
    message( STATUS "Targeting Linux 64-bit" )
    set(BIN_NAME "openjkdf2-64")

    add_definitions(-DARCH_64BIT)
    add_definitions(-D_XOPEN_SOURCE=500)
    add_definitions(-D_DEFAULT_SOURCE)

    set(TARGET_USE_LIBSMACKER TRUE)
    set(TARGET_USE_SDL2 TRUE)
    set(TARGET_USE_OPENGL TRUE)
    set(TARGET_POSIX TRUE)
    set(TARGET_LINUX TRUE)
    set(TARGET_NO_BLOBS TRUE)
    set(OPENJKDF2_NO_ASAN TRUE)
    
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -std=c11 -fshort-wchar")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
    add_link_options(-fshort-wchar)

elseif(PLAT_MACOS)
    message( STATUS "Targeting MacOS" )
    set(BIN_NAME "openjkdf2-64")

    add_definitions(-DARCH_64BIT)

    set(TARGET_USE_LIBSMACKER TRUE)
    set(TARGET_USE_SDL2 TRUE)
    set(TARGET_USE_OPENGL TRUE)
    set(TARGET_POSIX TRUE)
    set(TARGET_MACOS TRUE)
    set(TARGET_NO_BLOBS TRUE)

    set(BUNDLE "${PROJECT_SOURCE_DIR}/OpenJKDF2.app")
    set(HOMEBREW_PREFIX $ENV{HOMEBREW_PREFIX})

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -std=c11 -O2 -Wuninitialized -fshort-wchar -Wall -Wno-unused-variable -Wno-parentheses -Wno-missing-braces")
    
    add_link_options(-fshort-wchar)

elseif(PLAT_MACOS_X86_64)
    message( STATUS "Targeting MacOS x86_64 ${CMAKE_OSX_ARCHITECTURES}" )
    set(BIN_NAME "openjkdf2-64")

    add_definitions(-DARCH_64BIT)

    set(TARGET_USE_LIBSMACKER TRUE)
    set(TARGET_USE_SDL2 TRUE)
    set(TARGET_USE_OPENGL TRUE)
    set(TARGET_POSIX TRUE)
    set(TARGET_MACOS TRUE)
    set(TARGET_NO_BLOBS TRUE)

    set(BUNDLE "${PROJECT_SOURCE_DIR}/OpenJKDF2_x86_64.app")
    set(HOMEBREW_PREFIX "/usr/local")

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -std=c11 -O2 -Wuninitialized -fshort-wchar -Wall -Wno-unused-variable -Wno-parentheses -Wno-missing-braces")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
    add_link_options(-fshort-wchar)

elseif(PLAT_MINGW_X86_64)
    message( STATUS "Targeting Win64 MinGW" )

    set(BIN_NAME "openjkdf2-64")

    add_definitions(-DWIN64)
    add_definitions(-DWIN64_STANDALONE)
    add_definitions(-DARCH_64BIT)
    add_definitions(-DWIN32)
    add_definitions(-DWIN64_MINGW)

    set(OPENJKDF2_NO_ASAN TRUE)
    set(TARGET_USE_LIBSMACKER TRUE)
    set(TARGET_USE_SDL2 TRUE)
    set(TARGET_USE_OPENGL TRUE)
    set(TARGET_POSIX TRUE)
    set(TARGET_WIN32 TRUE)
    set(TARGET_NO_BLOBS TRUE)

    # TODO: Bump to O2 eventually. MinGW likes to replace memset with calls to itself...
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -ggdb -fno-omit-frame-pointer")
    
    add_link_options(-Wl,-Map=output-win64.map -fno-trapping-math -fshort-wchar -D_MBCS)
    add_compile_options(-Wuninitialized -fno-trapping-math -fshort-wchar -Dmain=SDL_main -D_MBCS)

    include_directories(${PROJECT_SOURCE_DIR}/3rdparty/drmingw-0.9.3-win64/include)
    include_directories(${PROJECT_SOURCE_DIR}/3rdparty/freeglut/include)
    include_directories(${PROJECT_SOURCE_DIR}/3rdparty/glew/include)
    include_directories(${PROJECT_SOURCE_DIR}/3rdparty/SDL2_mixer/x86_64-w64-mingw32/include/SDL2)
    include_directories(${PROJECT_SOURCE_DIR}/3rdparty/SDL2/x86_64-w64-mingw32/include/SDL2)
    include_directories(${PROJECT_SOURCE_DIR}/3rdparty/libpng-1.2.37-lib/include)
    include_directories(${PROJECT_SOURCE_DIR}/3rdparty/zlib-1.2.3-lib/include)

elseif(PLAT_WASM)
    message( STATUS "Targeting Emscripten WASM" )

    set(BIN_NAME "openjkdf2")

    add_definitions(-DARCH_WASM)

    set(OPENJKDF2_NO_ASAN TRUE)
    set(TARGET_USE_LIBSMACKER TRUE)
    set(TARGET_USE_SDL2 TRUE)
    set(TARGET_USE_OPENGL TRUE)
    set(TARGET_POSIX TRUE)
    set(TARGET_NO_BLOBS TRUE)
    set(TARGET_WASM TRUE)

    add_link_options(-fno-exceptions)
    add_compile_options(-fno-exceptions)
    set(USE_FLAGS "-s USE_SDL=2 -s USE_SDL_MIXER=2 -s WASM=1 -s ALLOW_MEMORY_GROWTH=1 -s FULL_ES3=1 -s ASYNCIFY")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${USE_FLAGS}")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${USE_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${USE_FLAGS} --profiling --preload-file ${PROJECT_SOURCE_DIR}/wasm_out@/ ")
    set(CMAKE_EXECUTABLE_SUFFIX .js)

    #LDFLAGS += -g -O2  -fshort-wchar

    add_compile_options(-O2 -Wuninitialized -fshort-wchar -Wall -Wno-unused-variable -Wno-parentheses -Wno-missing-braces)

elseif(PLAT_HOOKS)
    message( STATUS "Targeting MinGW Hooks DLL" )

    set(BIN_NAME "df2_reimpl")

    add_definitions(-DWIN32)
    add_definitions(-DWIN32_BLOBS)
    add_definitions(-DARCH_X86)
    add_definitions(-DTARGET_HAS_DPLAY)

    add_compile_options(-g -Wuninitialized -fno-trapping-math)
    add_link_options(-g -Wl,--subsystem,windows -Wl,-Map=output.map -fno-trapping-math)

    set(OPENJKDF2_NO_ASAN TRUE)
    set(TARGET_WIN32 TRUE)
    set(TARGET_USE_D3D TRUE)
elseif(PLAT_MSVC)
    message( STATUS "Targeting Win64 MSVC" )

    set(BIN_NAME "openjkdf2-64")

    add_definitions(-DWIN64)
    add_definitions(-DWIN64_STANDALONE)
    add_definitions(-DARCH_64BIT)
    add_definitions(-DWIN32)

    set(OPENJKDF2_NO_ASAN TRUE)
    set(TARGET_USE_LIBSMACKER TRUE)
    set(TARGET_USE_SDL2 TRUE)
    set(TARGET_USE_OPENGL TRUE)
    set(TARGET_POSIX TRUE)
    set(TARGET_WIN32 TRUE)
    set(TARGET_NO_BLOBS TRUE)
	
	set(SDL2_PATH ${CMAKE_SOURCE_DIR}/3rdparty/SDL2-2.0.18)
	set(SDL2_MIXER_PATH ${CMAKE_SOURCE_DIR}/3rdparty/SDL2_mixer-2.0.4)
	#set(GLEW_DIR ${CMAKE_SOURCE_DIR}/3rdparty/glew)
	list(APPEND CMAKE_PREFIX_PATH "${CMAKE_SOURCE_DIR}/3rdparty/glew")
	
	

    # TODO: Bump to O2 eventually. MinGW likes to replace memset with calls to itself...
    #set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -ggdb -fno-omit-frame-pointer")
    
    #add_link_options(-Wl,-Map=output-win64.map -fno-trapping-math -fshort-wchar -D_MBCS)
    #add_compile_options(-Wuninitialized -fno-trapping-math -fshort-wchar -Dmain=SDL_main -D_MBCS)

	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /std:c11")
	include_directories(${PROJECT_SOURCE_DIR}/3rdparty/drmingw-0.9.3-win64/include)
	
	add_link_options("${PROJECT_SOURCE_DIR}/3rdparty/drmingw-0.9.3-win64/lib/libexchndl.a")
	add_link_options("${PROJECT_SOURCE_DIR}/3rdparty/freeglut/lib/x64/libfreeglut.a")
	add_link_options(OpenGL32.lib)
endif()

set(CMAKE_BUILD_TYPE Debug)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake_modules")

if(TARGET_LINUX)
    list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake_modules_linux")
endif()

if(TARGET_MACOS)
    list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake_modules_linux")
endif()

if(PLAT_MSVC)
	list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake_modules_linux")
endif()

if(NOT PLAT_MINGW_X86_64 AND NOT PLAT_HOOKS AND NOT PLAT_WASM)
    find_package(SDL2 REQUIRED)
    find_package(SDL2_mixer REQUIRED)
    find_package(OpenAL REQUIRED)
    find_package(GLEW 2.0 REQUIRED)

    set(JSON_Install OFF CACHE INTERNAL "")
    add_subdirectory(${CMAKE_SOURCE_DIR}/3rdparty/json)
else()
    # idk
    set(JSON_Install OFF CACHE INTERNAL "")
    add_subdirectory(${CMAKE_SOURCE_DIR}/3rdparty/json)
endif()

# All of the includes
include_directories(${PROJECT_SOURCE_DIR}/src  ${PROJECT_SOURCE_DIR}/src/external/libsmacker ${PROJECT_SOURCE_DIR}/src/external/nativefiledialog-extended ${OPENAL_INCLUDE_DIR} ${SDL2_INCLUDE_DIR} ${SDL2_MIXER_INCLUDE_DIR} ${GLEW_INCLUDE_DIRS})

# All of the base sources
file(GLOB SOURCE_FILES ${PROJECT_SOURCE_DIR}/src/*.c ${PROJECT_SOURCE_DIR}/src/*/*.c ${PROJECT_SOURCE_DIR}/src/Platform/Common/*.c)

# Fcaseopen
file(GLOB FCASEOPEN_SRCS ${PROJECT_SOURCE_DIR}/src/external/fcaseopen/*.c)
list(APPEND SOURCE_FILES ${FCASEOPEN_SRCS})
include_directories(${PROJECT_SOURCE_DIR}/src/external/fcaseopen)

if(TARGET_NO_BLOBS)
    add_definitions(-DLINUX_TMP)
    add_definitions(-DNO_JK_MMAP)
endif()

if(DEBUG_QOL_CHEATS)
    add_definitions(-DDEBUG_QOL_CHEATS)
endif()

if(TARGET_USE_LIBSMACKER)
    list(APPEND SOURCE_FILES ${PROJECT_SOURCE_DIR}/src/external/libsmacker/smacker.c ${PROJECT_SOURCE_DIR}/src/external/libsmacker/smk_bitstream.c ${PROJECT_SOURCE_DIR}/src/external/libsmacker/smk_hufftree.c)
endif()

if(TARGET_USE_SDL2)
    file(GLOB TARGET_SDL2_SRCS ${PROJECT_SOURCE_DIR}/src/Platform/SDL2/*.c)
    list(APPEND SOURCE_FILES ${TARGET_SDL2_SRCS})
    add_definitions(-DSDL2_RENDER)
    add_definitions(-DOPENAL_SOUND)
endif()

if(TARGET_USE_OPENGL)
    file(GLOB TARGET_GL_SRCS ${PROJECT_SOURCE_DIR}/src/Platform/GL/*.c)
    list(APPEND SOURCE_FILES ${TARGET_GL_SRCS})

    file(GLOB TARGET_GL_CPP_SRCS ${PROJECT_SOURCE_DIR}/src/Platform/GL/*.cpp)
    list(APPEND SOURCE_FILES ${TARGET_GL_CPP_SRCS})
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

if(TARGET_WIN32)
    file(GLOB TARGET_WIN32_SRCS ${PROJECT_SOURCE_DIR}/src/Platform/Win32/*.c)
    list(APPEND SOURCE_FILES ${TARGET_WIN32_SRCS})

    list(APPEND SOURCE_FILES ${PROJECT_SOURCE_DIR}/packaging/win32/openjkdf2.rc)

    # Win64 can use the registry fine, even if stdlib is POSIX
    list(REMOVE_ITEM SOURCE_FILES ${PROJECT_SOURCE_DIR}/src/Platform/Posix/wuRegistry.c)

    if(TARGET_USE_SDL2)
        list(APPEND SOURCE_FILES ${PROJECT_SOURCE_DIR}/src/external/nativefiledialog-extended/nfd_win.cpp)
        if(PLAT_MSVC)
			set(LINK_LIBS ${LINK_LIBS} ole32.lib uuid.lib)
		else()
			add_link_options(-lm -ldinput8 -ldxguid -ldxerr8 -luser32 -lgdi32 -lwinmm -limm32 -lole32 -loleaut32 -lshell32 -lsetupapi -lversion -luuid)
		endif()
    endif()
endif()

set(SYMBOLS_FILE ${PROJECT_SOURCE_DIR}/symbols.syms)
set(GLOBALS_H ${PROJECT_SOURCE_DIR}/src/globals.h)
set(GLOBALS_C ${PROJECT_SOURCE_DIR}/src/globals.c)
set(GLOBALS_H_COG ${PROJECT_SOURCE_DIR}/src/globals.h.cog)
set(GLOBALS_C_COG ${PROJECT_SOURCE_DIR}/src/globals.c.cog)
list(APPEND SOURCE_FILES ${GLOBALS_C})

# All of our pre-build steps
add_custom_command(
    OUTPUT ${GLOBALS_C}
    COMMAND cog -d -D symbols_fpath="${SYMBOLS_FILE}" -o ${GLOBALS_C} ${GLOBALS_C_COG}
    DEPENDS ${SYMBOLS_FILE} ${GLOBALS_C_COG} ${GLOBALS_H} ${PROJECT_SOURCE_DIR}/resource/shaders/default_f.glsl ${PROJECT_SOURCE_DIR}/resource/shaders/default_v.glsl ${PROJECT_SOURCE_DIR}/resource/shaders/menu_f.glsl ${PROJECT_SOURCE_DIR}/resource/shaders/menu_v.glsl ${PROJECT_SOURCE_DIR}/resource/shaders/texfbo_f.glsl ${PROJECT_SOURCE_DIR}/resource/shaders/texfbo_v.glsl ${PROJECT_SOURCE_DIR}/resource/shaders/blur_f.glsl ${PROJECT_SOURCE_DIR}/resource/shaders/blur_v.glsl ${PROJECT_SOURCE_DIR}/resource/shaders/ssao_f.glsl ${PROJECT_SOURCE_DIR}/resource/shaders/ssao_v.glsl ${PROJECT_SOURCE_DIR}/resource/shaders/ssao_mix_f.glsl ${PROJECT_SOURCE_DIR}/resource/shaders/ssao_mix_v.glsl
)

add_custom_command(
    OUTPUT ${GLOBALS_H}
    COMMAND cog -d -D symbols_fpath="${SYMBOLS_FILE}" -o ${GLOBALS_H} ${GLOBALS_H_COG}
    DEPENDS ${SYMBOLS_FILE} ${GLOBALS_H_COG}
)

add_custom_command(
    PRE_BUILD
    OUTPUT ${BIN_NAME}
    DEPENDS ${GLOBALS_C} ${GLOBALS_H}
)

#set( CMAKE_VERBOSE_MAKEFILE on )

if(NOT PLAT_HOOKS)
    add_executable(${BIN_NAME} ${SOURCE_FILES})
else()
    add_library(${BIN_NAME} SHARED ${SOURCE_FILES})
    add_library("${BIN_NAME}_kvm" SHARED ${SOURCE_FILES})

    SET_TARGET_PROPERTIES(${BIN_NAME} PROPERTIES PREFIX "")
    SET_TARGET_PROPERTIES("${BIN_NAME}_kvm" PROPERTIES PREFIX "")
endif()

# TODO byacc and flex

if(TARGET_MACOS)
    set_target_properties(${BIN_NAME} PROPERTIES
      LINK_SEARCH_START_STATIC ON
      LINK_SEARCH_END_STATIC ON
    )
    target_link_libraries(${BIN_NAME} PRIVATE "-framework AppKit")

    find_package(PkgConfig REQUIRED)
    
    pkg_check_modules(LIBPNG REQUIRED libpng)
    include_directories(${LIBPNG_STATIC_INCLUDE_DIRS})
    link_directories(${LIBPNG_STATIC_LIBRARY_DIRS})
    add_definitions(${LIBPNG_STATIC_CFLAGS_OTHER})

    pkg_check_modules(ZLIB REQUIRED zlib)
    include_directories(${LIBPNG_STATIC_INCLUDE_DIRS})
    link_directories(${LIBPNG_STATIC_LIBRARY_DIRS})
    add_definitions(${LIBPNG_STATIC_CFLAGS_OTHER})
endif()

if(TARGET_LINUX)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(GTK3 REQUIRED gtk+-3.0)
    include_directories(${GTK3_INCLUDE_DIRS})
    link_directories(${GTK3_LIBRARY_DIRS})
    add_definitions(${GTK3_CFLAGS_OTHER})
    
    pkg_check_modules(LIBPNG REQUIRED libpng)
    include_directories(${LIBPNG_STATIC_INCLUDE_DIRS})
    link_directories(${LIBPNG_STATIC_LIBRARY_DIRS})
    add_definitions(${LIBPNG_STATIC_CFLAGS_OTHER})
endif()

if(NOT OPENJKDF2_NO_ASAN)
    add_compile_options(-fsanitize=address -fsanitize=float-divide-by-zero)
    add_link_options(-fsanitize=address -fsanitize=float-divide-by-zero)
    target_link_libraries(${BIN_NAME} PRIVATE "-static-libsan")

    add_compile_options(-fsanitize=leak)
    add_link_options(-fsanitize=leak)
endif()

if(PLAT_MINGW_X86_64)
    set_target_properties(${BIN_NAME} PROPERTIES
      LINK_SEARCH_START_STATIC ON
      LINK_SEARCH_END_STATIC ON
    )
    set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
    set(THREADS_PREFER_PTHREAD_FLAG TRUE)
    find_package(Threads REQUIRED)
    target_link_libraries(${BIN_NAME} PRIVATE -static)
    set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++")
    target_link_libraries(${BIN_NAME} PRIVATE Threads::Threads)

    
    target_link_libraries(${BIN_NAME} PRIVATE "-L${PROJECT_SOURCE_DIR}/3rdparty/freeglut/lib/x64/" freeglut)
    target_link_libraries(${BIN_NAME} PRIVATE "-L${PROJECT_SOURCE_DIR}/3rdparty/glew/lib/Release/x64" opengl32 glew32)
    target_link_libraries(${BIN_NAME} PRIVATE "-L${PROJECT_SOURCE_DIR}/3rdparty/SDL2/x86_64-w64-mingw32/lib" mingw32 SDL2main SDL2)
    target_link_libraries(${BIN_NAME} PRIVATE "-L${PROJECT_SOURCE_DIR}/3rdparty/SDL2_mixer/x86_64-w64-mingw32/lib" SDL2_mixer)
    target_link_libraries(${BIN_NAME} PRIVATE "-L${PROJECT_SOURCE_DIR}/3rdparty/drmingw-0.9.3-win64/lib/" exchndl)
    target_link_libraries(${BIN_NAME} PRIVATE "-L${PROJECT_SOURCE_DIR}/3rdparty/libpng-1.2.37-lib/lib/" png)
    target_link_libraries(${BIN_NAME} PRIVATE "-L${PROJECT_SOURCE_DIR}/3rdparty/zlib-1.2.3-lib/lib/" z)
    target_link_libraries(${BIN_NAME} PRIVATE m dinput8 dxguid dxerr8 user32 gdi32 winmm imm32 ole32 oleaut32 shell32 setupapi -lversion uuid)

    target_link_libraries(${BIN_NAME} PRIVATE -mwindows -Wl,--subsystem,windows ${PROJECT_SOURCE_DIR}/3rdparty/openal-soft/libs/Win64/OpenAL32.lib)
    target_link_libraries(${BIN_NAME} PRIVATE nlohmann_json::nlohmann_json)

    add_custom_command(TARGET ${BIN_NAME} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/3rdparty/glew/bin/Release/x64/glew32.dll ${CMAKE_CURRENT_BINARY_DIR})
    add_custom_command(TARGET ${BIN_NAME} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/3rdparty/SDL2_mixer/x86_64-w64-mingw32/bin/libogg-0.dll ${CMAKE_CURRENT_BINARY_DIR})
    add_custom_command(TARGET ${BIN_NAME} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/3rdparty/SDL2_mixer/x86_64-w64-mingw32/bin/libvorbis-0.dll ${CMAKE_CURRENT_BINARY_DIR})
    add_custom_command(TARGET ${BIN_NAME} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/3rdparty/SDL2_mixer/x86_64-w64-mingw32/bin/libvorbisfile-3.dll ${CMAKE_CURRENT_BINARY_DIR})
    add_custom_command(TARGET ${BIN_NAME} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/3rdparty/openal-soft/bin/Win64/soft_oal.dll ${CMAKE_CURRENT_BINARY_DIR}/OpenAL32.dll)
    add_custom_command(TARGET ${BIN_NAME} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/3rdparty/drmingw-0.9.3-win64/bin/*.dll ${CMAKE_CURRENT_BINARY_DIR})
    add_custom_command(TARGET ${BIN_NAME} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/3rdparty/drmingw-0.9.3-win64/bin/symsrv.yes ${CMAKE_CURRENT_BINARY_DIR})
elseif(PLAT_HOOKS)
    target_link_libraries(${BIN_NAME} PRIVATE -static-libgcc)
    target_link_libraries("${BIN_NAME}_kvm" PRIVATE -Wl,-e_hook_init -nostartfiles -static -static-libgcc -static-libstdc++)
elseif(PLAT_WASM)
    target_link_libraries(${BIN_NAME} PRIVATE -lm -lSDL2 -lSDL2_mixer -lGL -lGLEW -lopenal -lpng)
    target_link_libraries(${BIN_NAME} PRIVATE nlohmann_json::nlohmann_json)
elseif(TARGET_LINUX)
    target_link_libraries(${BIN_NAME} PRIVATE ${SDL2_LIBRARY} ${SDL2_MIXER_LIBRARY} GL ${OPENAL_LIBRARY} GLEW::GLEW ${GTK3_LIBRARIES} ${LIBPNG_STATIC_LDFLAGS})
    target_link_libraries(${BIN_NAME} PRIVATE nlohmann_json::nlohmann_json)
elseif(PLAT_MSVC)
    set_target_properties(${BIN_NAME} PROPERTIES
      LINK_SEARCH_START_STATIC ON
      LINK_SEARCH_END_STATIC ON
    )
    set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
    set(THREADS_PREFER_PTHREAD_FLAG TRUE)
    find_package(Threads REQUIRED)
    target_link_libraries(${BIN_NAME} PRIVATE -static)
    set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++")
    target_link_libraries(${BIN_NAME} PRIVATE Threads::Threads)

	target_link_libraries(${BIN_NAME} PRIVATE ${SDL2_LIBRARY} ${SDL2_MIXER_LIBRARY} ${OPENGL_LIBRARIES} ${OPENAL_LIBRARY} ${GLEW_LIBRARIES} ${LIBPNG_STATIC_LDFLAGS})
    target_link_libraries(${BIN_NAME} PRIVATE nlohmann_json::nlohmann_json)

    target_link_libraries(${BIN_NAME} PRIVATE m dinput8 dxguid dxerr8 user32 gdi32 winmm imm32 ole32 oleaut32 shell32 setupapi -lversion uuid)
	
	add_custom_command(TARGET ${BIN_NAME} 
	POST_BUILD 
    COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/3rdparty/glew/bin/Release/x64/glew32.dll ${CMAKE_CURRENT_BINARY_DIR}/\$\(Configuration\)/
    COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/3rdparty/SDL2_mixer/x86_64-w64-mingw32/bin/libogg-0.dll ${CMAKE_CURRENT_BINARY_DIR}/\$\(Configuration\)/
    COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/3rdparty/SDL2_mixer/x86_64-w64-mingw32/bin/libvorbis-0.dll ${CMAKE_CURRENT_BINARY_DIR}/\$\(Configuration\)/
    COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/3rdparty/SDL2_mixer/x86_64-w64-mingw32/bin/libvorbisfile-3.dll ${CMAKE_CURRENT_BINARY_DIR}/\$\(Configuration\)/
    COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/3rdparty/openal-soft/bin/Win64/soft_oal.dll ${CMAKE_CURRENT_BINARY_DIR}/\$\(Configuration\)/OpenAL32.dll
    COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/3rdparty/drmingw-0.9.3-win64/bin/dbgcore.dll ${CMAKE_CURRENT_BINARY_DIR}/\$\(Configuration\)/
	COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/3rdparty/drmingw-0.9.3-win64/bin/dbghelp.dll ${CMAKE_CURRENT_BINARY_DIR}/\$\(Configuration\)/
	COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/3rdparty/drmingw-0.9.3-win64/bin/exchndl.dll ${CMAKE_CURRENT_BINARY_DIR}/\$\(Configuration\)/
	COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/3rdparty/drmingw-0.9.3-win64/bin/mgwhelp.dll ${CMAKE_CURRENT_BINARY_DIR}/\$\(Configuration\)/
	COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/3rdparty/drmingw-0.9.3-win64/bin/symsrv.dll ${CMAKE_CURRENT_BINARY_DIR}/\$\(Configuration\)/
    COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/3rdparty/drmingw-0.9.3-win64/bin/symsrv.yes ${CMAKE_CURRENT_BINARY_DIR}/\$\(Configuration\)/
	)
else()
    set(LIBPNG_LIST ${LIBPNG_LIBRARY_DIRS})
    separate_arguments(LIBPNG_LIST)
    message(STATUS "list = ${ZLIB_STATIC_LDFLAGS}")
    list(FILTER LIBPNG_LIST INCLUDE REGEX ${HOMEBREW_PREFIX}.*)
    message(STATUS "list = ${LIBPNG_LIST}")

    target_link_libraries(${BIN_NAME} PRIVATE ${SDL2_LIBRARY} ${SDL2_MIXER_LIBRARY} ${OPENGL_LIBRARY} ${OPENAL_LIBRARY} GLEW::GLEW ${LIBPNG_LIST}/libpng.a ${ZLIB_STATIC_LDFLAGS})
    target_link_libraries(${BIN_NAME} PRIVATE nlohmann_json::nlohmann_json)
endif()

if(TARGET_MACOS)
    add_custom_command(TARGET ${BIN_NAME}
    POST_BUILD
    COMMAND dsymutil ${CMAKE_CURRENT_BINARY_DIR}/${BIN_NAME} -o ${CMAKE_CURRENT_BINARY_DIR}/${BIN_NAME}.dsym
    COMMAND rm -rf ${BUNDLE}
    COMMAND rm -rf ${PROJECT_SOURCE_DIR}/packaging/icon.iconset
    COMMAND rm -rf ${PROJECT_SOURCE_DIR}/packaging/icon.icns
    COMMAND mkdir -p ${BUNDLE}
    COMMAND cp -r ${PROJECT_SOURCE_DIR}/packaging/macos/* ${BUNDLE}/
    COMMAND mkdir -p ${BUNDLE}/Contents/MacOS/
    COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/${BIN_NAME} ${BUNDLE}/Contents/MacOS
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/sdl2_mixer/lib/libSDL2_mixer-2.0.0.dylib @executable_path/libSDL2_mixer-2.0.0.dylib ${BUNDLE}/Contents/MacOS/${BIN_NAME}
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/sdl2/lib/libSDL2-2.0.0.dylib @executable_path/libSDL2-2.0.0.dylib ${BUNDLE}/Contents/MacOS/${BIN_NAME}
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/glew/lib/libGLEW.2.2.dylib @executable_path/libGLEW.2.2.dylib ${BUNDLE}/Contents/MacOS/${BIN_NAME}
    COMMAND cp ${HOMEBREW_PREFIX}/opt/sdl2/lib/libSDL2-2.0.0.dylib ${BUNDLE}/Contents/MacOS
    COMMAND cp ${HOMEBREW_PREFIX}/opt/sdl2_mixer/lib/libSDL2_mixer-2.0.0.dylib ${BUNDLE}/Contents/MacOS
    COMMAND cp ${HOMEBREW_PREFIX}/opt/glew/lib/libGLEW.2.2.dylib ${BUNDLE}/Contents/MacOS

    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/sdl2/lib/libSDL2-2.0.0.dylib @executable_path/libSDL2-2.0.0.dylib ${BUNDLE}/Contents/MacOS/libSDL2_mixer-2.0.0.dylib
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/sdl2_mixer/lib/libSDL2_mixer-2.0.0.dylib @executable_path/libSDL2_mixer-2.0.0.dylib ${BUNDLE}/Contents/MacOS/libSDL2_mixer-2.0.0.dylib

    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/libmodplug/lib/libmodplug.1.dylib @executable_path/libmodplug.1.dylib ${BUNDLE}/Contents/MacOS/libSDL2_mixer-2.0.0.dylib
    COMMAND cp ${HOMEBREW_PREFIX}/opt/libmodplug/lib/libmodplug.1.dylib ${BUNDLE}/Contents/MacOS

    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/mpg123/lib/libmpg123.0.dylib @executable_path/libmpg123.0.dylib ${BUNDLE}/Contents/MacOS/libSDL2_mixer-2.0.0.dylib
    COMMAND cp ${HOMEBREW_PREFIX}/opt/mpg123/lib/libmpg123.0.dylib ${BUNDLE}/Contents/MacOS

    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/libvorbis/lib/libvorbis.0.dylib @executable_path/libvorbis.0.dylib ${BUNDLE}/Contents/MacOS/libSDL2_mixer-2.0.0.dylib
    COMMAND cp ${HOMEBREW_PREFIX}/opt/libvorbis/lib/libvorbis.0.dylib ${BUNDLE}/Contents/MacOS
    
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/libvorbis/lib/libvorbisfile.3.dylib @executable_path/libvorbisfile.3.dylib ${BUNDLE}/Contents/MacOS/libSDL2_mixer-2.0.0.dylib
    COMMAND cp ${HOMEBREW_PREFIX}/opt/libvorbis/lib/libvorbisfile.3.dylib ${BUNDLE}/Contents/MacOS
    
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/flac/lib/libFLAC.8.dylib @executable_path/libFLAC.8.dylib ${BUNDLE}/Contents/MacOS/libSDL2_mixer-2.0.0.dylib
    COMMAND cp ${HOMEBREW_PREFIX}/opt/flac/lib/libFLAC.8.dylib ${BUNDLE}/Contents/MacOS
    
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/libogg/lib/libogg.0.dylib @executable_path/libogg.0.dylib ${BUNDLE}/Contents/MacOS/libvorbis.0.dylib
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/Cellar/libvorbis/1.3.7/lib/libvorbis.0.dylib @executable_path/libvorbis.0.dylib ${BUNDLE}/Contents/MacOS/libvorbisfile.3.dylib
    COMMAND install_name_tool -change ${HOMEBREW_PREFIX}/opt/libogg/lib/libogg.0.dylib @executable_path/libogg.0.dylib ${BUNDLE}/Contents/MacOS/libvorbisfile.3.dylib

    COMMAND cp ${HOMEBREW_PREFIX}/opt/libogg/lib/libogg.0.dylib ${BUNDLE}/Contents/MacOS
    COMMAND chmod 774 ${BUNDLE}/Contents/MacOS/*.dylib
    COMMAND cp -r ${CMAKE_CURRENT_BINARY_DIR}/openjkdf2-64.dsym ${BUNDLE}/Contents/MacOS/openjkdf2-64.dsym
    COMMAND chmod 774 ${BUNDLE}/Contents/MacOS/${BIN_NAME}
    COMMAND generate-iconset ${PROJECT_SOURCE_DIR}/packaging/icon.png
    COMMAND mkdir -p ${BUNDLE}/Contents/Resources/
    COMMAND cp ${PROJECT_SOURCE_DIR}/packaging/icon.icns ${BUNDLE}/Contents/Resources/OpenJKDF2.icns
    COMMAND cp -r ${PROJECT_SOURCE_DIR}/resource/ ${BUNDLE}/Contents/Resources/resource/
    COMMAND rm -rf ${PROJECT_SOURCE_DIR}/packaging/icon.iconset
    COMMAND rm -rf ${PROJECT_SOURCE_DIR}/packaging/icon.icns
    )
endif()
