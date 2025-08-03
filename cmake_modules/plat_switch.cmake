macro(plat_initialize)
    message(STATUS "Targeting Nintendo Switch")

    set(BIN_NAME "openjkdf2.elf")
    set(NRO_NAME "openjkdf2.nro")

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

    set(TARGET_SWITCH TRUE)

    # Compiler and linker flags  
    set(SWITCH_COMMON_FLAGS "-g -Wall -O2 -ffunction-sections")
    set(SWITCH_COMMON_FLAGS "${SWITCH_COMMON_FLAGS} -march=armv8-a+crc+crypto -mtune=cortex-a57 -mtp=soft -fPIE")
    
    add_compile_options(${SWITCH_COMMON_FLAGS})
    add_compile_options(-D__SWITCH__ -I${LIBNX}/include -I${PORTLIBS}/include)
    
    # C++ specific flags

    # Linker flags
    add_link_options(-specs=${LIBNX}/switch.specs -g ${ARCH_FLAGS} -Wl,-Map,${CMAKE_CURRENT_BINARY_DIR}/openjkdf2.map)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti -fno-exceptions -fno-strict-aliasing")
    # Include paths
    include_directories(${LIBNX}/include)
    include_directories(${PORTLIBS}/include)
    
    # Library paths
    link_directories(${LIBNX}/lib)
    link_directories(${PORTLIBS}/lib)
endmacro()

macro(plat_specific_deps)
    # Switch-specific dependencies - SDL2 via portlibs
    set(SDL2_COMMON_LIBS "SDL2main SDL2 SDL2_mixer")
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
        target_link_libraries(${BIN_NAME} PRIVATE SDL2main SDL2 SDL2_mixer)
    endif()
    
    if(TARGET_USE_OPENAL)
        target_link_libraries(${BIN_NAME} PRIVATE openal)
    endif()
    
    if(TARGET_USE_PHYSFS)
        target_link_libraries(${BIN_NAME} PRIVATE physfs)
    endif()
    
    # PNG support for textures
    target_link_libraries(${BIN_NAME} PRIVATE png z)
    
    # OpenGL ES via mesa
    target_link_libraries(${BIN_NAME} PRIVATE EGL GLESv2)
    
    target_link_libraries(sith_engine PRIVATE nlohmann_json::nlohmann_json)

    # Create .nro file using elf2nro
    find_program(ELF2NRO elf2nro ${DEVKITPRO}/tools/bin)
    if(NOT ELF2NRO)
        message(FATAL_ERROR "elf2nro not found. Please install switch-tools package.")
    endif()

    add_custom_target(${NRO_NAME} ALL
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${BIN_NAME}
        COMMAND ${ELF2NRO} ${CMAKE_CURRENT_BINARY_DIR}/${BIN_NAME} ${CMAKE_CURRENT_BINARY_DIR}/${NRO_NAME} --nacp=${CMAKE_CURRENT_BINARY_DIR}/openjkdf2.nacp
        COMMENT "Converting ELF to NRO"
    )

    # Create NACP (Nintendo Application Control Property) file
    find_program(NACPTOOL nacptool ${DEVKITPRO}/tools/bin)
    if(NOT NACPTOOL)
        message(FATAL_ERROR "nacptool not found. Please install switch-tools package.")
    endif()

    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/openjkdf2.nacp
        COMMAND ${NACPTOOL} --create "${APP_TITLE}" "${APP_AUTHOR}" "${APP_VERSION}" ${CMAKE_CURRENT_BINARY_DIR}/openjkdf2.nacp
        COMMENT "Creating NACP file"
    )

    add_custom_target(nacp ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/openjkdf2.nacp)
    add_dependencies(${NRO_NAME} nacp)
endmacro()

macro(plat_extra_deps)
    # Any additional Switch-specific dependencies
endmacro()
