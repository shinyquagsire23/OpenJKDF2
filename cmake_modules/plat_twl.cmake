macro(plat_initialize)
    message( STATUS "Targeting Nintendo DSi" )

    set(BIN_NAME "openjkdf2.elf")
    set(NDS_NAME "openjkdf2.nds")

    set(GAME_ICON ${DEVKITPRO}/libnds/icon.bmp)
    set(GAME_TITLE OpenJKDF2)
    set(GAME_SUBTITLE1 subtitle1)
    set(GAME_SUBTITLE2 subtitle2)

    add_definitions(-DPLAT_MISSING_WIN32)
    add_definitions(-DTARGET_TWL)
    add_definitions(-D_XOPEN_SOURCE=500)
    add_definitions(-D_DEFAULT_SOURCE)
    add_definitions(-DARM9)

    # These are the standard features for full game support
    set(TARGET_USE_PHYSFS FALSE)
    #set(TARGET_USE_BASICSOCKETS TRUE)
    set(TARGET_USE_GAMENETWORKINGSOCKETS FALSE)
    set(TARGET_USE_LIBSMACKER TRUE)
    set(TARGET_USE_LIBSMUSHER TRUE)
    set(TARGET_USE_SDL2 FALSE)
    set(TARGET_USE_OPENGL FALSE)
    set(TARGET_USE_OPENAL FALSE)
    set(TARGET_POSIX TRUE)
    set(TARGET_NO_BLOBS TRUE)
    set(TARGET_CAN_JKGM FALSE)
    set(OPENJKDF2_NO_ASAN TRUE)
    set(TARGET_USE_CURL FALSE)
    set(TARGET_FIND_OPENAL FALSE)

    set(TARGET_BUILD_TESTS FALSE)
    set(SDL2_COMMON_LIBS "")

    set(TARGET_TWL TRUE)

    add_link_options(-mthumb -mthumb-interwork -fno-exceptions -fshort-wchar -L${LIBNDS}/lib -L${DEVKITARM}/arm-none-eabi/lib/ -Wl,--gc-sections)
    add_compile_options(-mthumb -mthumb-interwork -fno-exceptions -march=armv5te -mtune=arm946e-s -fomit-frame-pointer -ffast-math -Wl,--gc-sections)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
    add_compile_options(-O2 -Wuninitialized -fshort-wchar -Wall -Wno-unused-variable -Wno-parentheses -Wno-missing-braces)
    include_directories(${LIBNDS}/include)
endmacro()

macro(plat_specific_deps)
    set(SDL2_COMMON_LIBS "")
endmacro()

macro(plat_link_and_package)
    target_link_libraries(${BIN_NAME} PRIVATE -lm -lfat -lnds9)
    target_link_libraries(sith_engine PRIVATE nlohmann_json::nlohmann_json)

    target_link_options(${BIN_NAME} PRIVATE -T${PROJECT_SOURCE_DIR}/cmake_modules/openjkdf2_dsi_arm9.mem -T${PROJECT_SOURCE_DIR}/cmake_modules/openjkdf2_ds_arm9.ld -Wl,--no-warn-rwx-segments -Wl,-Map,openjkdf2.map ${DEVKITARM}/arm-none-eabi/lib/ds_arm9_crt0.o)

    add_custom_target(${NDS_NAME} ALL
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${BIN_NAME}
        COMMAND ${NDSTOOL} -c ${CMAKE_CURRENT_BINARY_DIR}/${NDS_NAME} -9 ${CMAKE_CURRENT_BINARY_DIR}/${BIN_NAME} -b ${GAME_ICON} \"${GAME_TITLE}\;${GAME_SUBTITLE1}\;${GAME_SUBTITLE2}\"
        )
endmacro()

macro(plat_extra_deps)
    
endmacro()