macro(plat_initialize)
    message(STATUS "Targeting Nintendo Switch")
set(DEVKITA64 "${DEVKITPRO}/devkitA64")
set(LIBNX "${DEVKITPRO}/libnx")
set(PORTLIBS "${DEVKITPRO}/portlibs/switch")
    set(BIN_NAME "openjkdf2")
    set(NRO_NAME "openjkdf2.nro")

    # Ensure we're targeting AArch64
    set(CMAKE_SYSTEM_NAME "Generic")
    set(CMAKE_SYSTEM_PROCESSOR "aarch64")
    
    # Application metadata
    set(APP_TITLE "OpenJKDF2")
    set(APP_AUTHOR "OpenJKDF2 Team")
    set(APP_VERSION "1.0.0")

    # Platform defines
    add_definitions(-DPLAT_MISSING_WIN32)
    add_definitions(-DTARGET_SWITCH)
    add_definitions(-D_XOPEN_SOURCE=500)
    add_definitions(-D_DEFAULT_SOURCE)
    add_definitions(-D__SWITCH__)
    add_definitions(-DARM64)
    add_definitions(-DSMK_FAST)

    # Feature configuration for Switch
    set(TARGET_USE_PHYSFS TRUE)
    set(TARGET_USE_GAMENETWORKINGSOCKETS FALSE)  # Networking likely disabled for now
    set(TARGET_USE_LIBSMACKER TRUE)
    set(TARGET_USE_LIBSMUSHER TRUE)
    set(TARGET_USE_SDL2 TRUE)
    set(TARGET_USE_OPENGL TRUE)  # Switch supports OpenGL ES
    set(TARGET_USE_OPENAL TRUE)  # Should work via portlibs
    set(TARGET_POSIX TRUE)
    set(TARGET_NO_BLOBS TRUE)
    set(TARGET_CAN_JKGM FALSE)  # Game mode disabled for now
    set(OPENJKDF2_NO_ASAN TRUE)
    set(TARGET_USE_CURL FALSE)  # Curl might not be available
    set(TARGET_FIND_OPENAL FALSE)  # We'll link it manually
    set(TARGET_NO_MULTIPLAYER_MENUS TRUE)  # Disable multiplayer UI

    set(TARGET_BUILD_TESTS FALSE)
    set(SDL2_COMMON_LIBS "")
    set(TARGET_SWITCH_EXECUTABLE TRUE)  # Force executable instead of shared library

    set(TARGET_SWITCH TRUE)
    set(TARGET_COMPILE_FREEGLUT FALSE)  # Switch doesn't need freeglut

    # Mock OpenGL targets to prevent CMake from searching
    set(OPENGL_FOUND TRUE)
    set(OpenGL_FOUND TRUE)
    set(OPENGL_GL_FOUND TRUE)
    set(OpenGL_OpenGL_FOUND TRUE)
    set(OpenGL_EGL_FOUND TRUE)
    set(OPENGL_opengl_LIBRARY "")
    set(OPENGL_glx_LIBRARY "")
    

    # Compiler and linker flags  
    add_compile_options(-g -Wall -O2 -ffunction-sections)
   add_compile_options(${ARCH_FLAGS})
    add_compile_options(-D__SWITCH__ -I${LIBNX}/include -I${PORTLIBS}/include)
    
    
    # C specific flags
    add_compile_options($<$<COMPILE_LANGUAGE:C>:-Wno-implicit-function-declaration>)
       set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--verbose")
    # Linker flags
    #add_link_options(-specs=${LIBNX}/switch.specs -march=armv8-a+crc+crypto -mtune=cortex-a57 -mtp=soft -fPIE -g ${ARCH_FLAGS} -Wl,-Map,${CMAKE_CURRENT_BINARY_DIR}/openjkdf2.map)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti -fno-exceptions -fno-strict-aliasing")
    # Include paths
    include_directories(${LIBNX}/include)
    include_directories(${PORTLIBS}/include)
    
    # Library paths
    link_directories(${LIBNX}/lib)
    link_directories(${PORTLIBS}/lib)
    
    # Add Switch-specific OpenGL module path
    list(APPEND CMAKE_MODULE_PATH "${PORTLIBS}/lib/cmake/OpenGL")
endmacro()

macro(plat_specific_deps)
    # Switch-specific dependencies - SDL2 via portlibs
    set(SDL2_COMMON_LIBS "-lSDL2main -lSDL2 -lSDL2_mixer")
endmacro()

macro(plat_link_and_package)
    # Link Switch libraries
    target_link_libraries(${BIN_NAME} PRIVATE 
        -lnx
        -lm 
        -lstdc++ 
        -lc
    )

    # Link portlibs libraries
    if(TARGET_USE_SDL2)
        target_link_libraries(${BIN_NAME} PRIVATE -lSDL2main -lSDL2 -lSDL2_mixer)
            target_link_libraries(${BIN_NAME} PRIVATE 
            -lopusfile 
            -lopus 
            -logg 
            -lvorbisfile 
            -lvorbis 
            -lFLAC
            -lmpg123
            -lmodplug
        )
    endif()
    
    if(TARGET_USE_OPENAL)
        target_link_libraries(${BIN_NAME} PRIVATE -lopenal)
    endif()
    
    if(TARGET_USE_PHYSFS)
        target_link_libraries(${BIN_NAME} PRIVATE -lphysfs)
    endif()
    
    # PNG support for textures
    target_link_libraries(${BIN_NAME} PRIVATE -lpng -lz)
    
    # OpenGL ES via mesa
        target_link_libraries(${BIN_NAME} PRIVATE -lEGL -lGLESv2 -lglapi -lglad -ldrm_nouveau)

    
    target_link_libraries(sith_engine PRIVATE nlohmann_json::nlohmann_json)

    # Find tools for manual conversion (optional)
    find_program(ELF2NRO elf2nro ${DEVKITPRO}/tools/bin)
    find_program(NACPTOOL nacptool ${DEVKITPRO}/tools/bin)
    
    # Show exact file locations
    message(STATUS "ELF file will be located at: ${CMAKE_CURRENT_BINARY_DIR}/${BIN_NAME}")
    
    if(ELF2NRO AND NACPTOOL)
        message(STATUS "elf2nro found at: ${ELF2NRO}")
        message(STATUS "nacptool found at: ${NACPTOOL}")
        message(STATUS "To manually create NRO file, run from build directory:")
        message(STATUS "  ${NACPTOOL} --create \"${APP_TITLE}\" \"${APP_AUTHOR}\" \"${APP_VERSION}\" openjkdf2.nacp")
        message(STATUS "  ${ELF2NRO} ${BIN_NAME} ${NRO_NAME} --nacp=openjkdf2.nacp")
    else()
        if(NOT ELF2NRO)
            message(WARNING "elf2nro not found. Install switch-tools package to convert ELF to NRO.")
        endif()
        if(NOT NACPTOOL)
            message(WARNING "nacptool not found. Install switch-tools package to create NACP file.")
        endif()
    endif()
endmacro()

macro(plat_extra_deps)
    # Any additional Switch-specific dependencies
endmacro()
