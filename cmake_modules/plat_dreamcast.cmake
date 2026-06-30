macro(plat_initialize)
    message( STATUS "Targeting Sega Dreamcast" )

    set(BIN_NAME "openjkdf2")
    set(CDI_NAME "openjkdf2.cdi")

    # mkdcdisc turns the ELF into a bootable DiscJuggler .cdi (handles elf->bin,
    # scramble, IP.BIN and the license/boot image). Flycast/redream load the .cdi
    # directly. Searched on PATH and in the common ~/.local/bin install location.
    find_program(MKDCDISC mkdcdisc
        HINTS $ENV{HOME}/.local/bin /usr/local/bin /opt/homebrew/bin)
    if(MKDCDISC)
        message(STATUS "Found mkdcdisc: ${MKDCDISC}")
    else()
        message(WARNING "mkdcdisc not found; the .cdi disc image won't be built "
                        "(the ELF will still build). Install it and re-run CMake.")
    endif()

    add_definitions(-DPLAT_MISSING_WIN32)
    add_definitions(-DTARGET_DREAMCAST)
    add_definitions(-DTARGET_RETRO_HOMEBREW)
    add_definitions(-D_XOPEN_SOURCE=500)
    add_definitions(-D_DEFAULT_SOURCE)

    # These mirror the DSi/TWL feature set: no SDL2, no desktop GL, no sockets,
    # software video codecs on, POSIX filesystem (KOS newlib), no blobs.
    set(TARGET_USE_PHYSFS FALSE)
    set(TARGET_USE_GAMENETWORKINGSOCKETS FALSE)
    set(TARGET_USE_LIBSMACKER TRUE)
    set(TARGET_USE_LIBSMUSHER TRUE)
    set(TARGET_USE_SDL2 FALSE)
    set(TARGET_USE_OPENGL FALSE)
    # NOTE: Dreamcast will likely borrow the GL 1.1 renderer (KOS ships GLdc) later;
    # for now it uses its own stub std3D in src/Platform/Dreamcast.
    set(TARGET_USE_OPENGL11 FALSE)
    set(TARGET_USE_OPENAL FALSE)
    set(TARGET_POSIX TRUE)
    set(TARGET_NO_BLOBS TRUE)
    set(TARGET_CAN_JKGM FALSE)
    set(OPENJKDF2_NO_ASAN TRUE)
    set(TARGET_USE_CURL FALSE)
    set(TARGET_FIND_OPENAL FALSE)
    set(TARGET_NO_MULTIPLAYER_MENUS TRUE)

    set(TARGET_BUILD_TESTS FALSE)
    set(SDL2_COMMON_LIBS "")

    set(TARGET_DREAMCAST TRUE)

    # kos-cc (the compiler wrapper) already injects the SH4/KOS flags, includes
    # and the kernel/libc link line, so we only add project-level options here.
    add_compile_options(-Wall -Wno-unused-variable -Wno-parentheses -Wno-missing-braces)
    add_compile_options(-ffast-math -fomit-frame-pointer -ffunction-sections -fdata-sections -fshort-wchar)
    add_compile_options(-O2)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti -fno-exceptions")
    add_link_options(-ffunction-sections -fdata-sections -Wl,--gc-sections)
endmacro()

macro(plat_specific_deps)
    set(SDL2_COMMON_LIBS "")
endmacro()

macro(plat_link_and_package)
    # kos-cc/kos-c++ supply the KOS kernel + newlib automatically. Add the math
    # lib and the header-only JSON dependency. (GLdc -lGL will be added when the
    # GL 1.1 renderer is wired up.)
    target_link_libraries(${BIN_NAME} PRIVATE -lm)
    target_link_libraries(sith_engine PRIVATE nlohmann_json::nlohmann_json)

    target_link_options(${BIN_NAME} PRIVATE -Wl,-Map,openjkdf2.map)

    # Final packaging: build the bootable .cdi from the linked ELF.
    if(MKDCDISC)
        add_custom_target(${CDI_NAME} ALL
            DEPENDS ${BIN_NAME}
            BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/${CDI_NAME}
            # --no-padding keeps the .cdi small (~MBs, not ~700MB). Emulators
            # (Flycast/redream) load non-padded images fine; drop -N if you need a
            # disc that boots padded GD-ROM hardware.
            COMMAND ${MKDCDISC}
                    -e $<TARGET_FILE:${BIN_NAME}>
                    -o ${CMAKE_CURRENT_BINARY_DIR}/${CDI_NAME}
                    -n "OpenJKDF2"
                    --no-padding
                    -v 1
            COMMENT "Creating Dreamcast disc image ${CDI_NAME}"
            VERBATIM)
    endif()
endmacro()

macro(plat_extra_deps)

endmacro()
