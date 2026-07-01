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
    add_definitions(-DSMK_FAST)

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
    add_compile_options(-fomit-frame-pointer -ffunction-sections -fdata-sections -fshort-wchar)
    # NOTE: -ffast-math removed (and unsafe-math/contraction explicitly disabled).
    # KOS injects -mfsrra/-mfsca, which GCC only emits under -funsafe-math-optimizations
    # (part of -ffast-math). Those approximate reciprocals/normals break the FP-heavy
    # collision math (floor raycasts / move-and-slide), causing things to fall through
    # the world. Disabling them trades a little speed for correct physics.
    add_compile_options(-fno-fast-math -fno-unsafe-math-optimizations -ffp-contract=off -Wl,--wrap,malloc -Wl,--wrap,free -Wl,--wrap,realloc -Wl,--wrap,calloc)
    add_compile_options(-O2)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti -fno-exceptions -Wl,--wrap,malloc -Wl,--wrap,free -Wl,--wrap,realloc -Wl,--wrap,calloc -ffp-contract=off")
    add_link_options(-ffunction-sections -fdata-sections -Wl,--gc-sections -Wl,--wrap,malloc -Wl,--wrap,free -Wl,--wrap,realloc -Wl,--wrap,calloc)
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
        # Assets dropped into packaging/dreamcast/disc are placed at the root of the
        # disc data track (so they appear under /cd at runtime, where the Dreamcast
        # main() chdir's). Only pass -D if the directory has real content, since an
        # empty/placeholder-only directory upsets mkdcdisc.
        set(DC_DISC_DIR ${PROJECT_SOURCE_DIR}/packaging/dreamcast/disc)
        file(GLOB_RECURSE DC_DISC_ASSETS LIST_DIRECTORIES false
             ${DC_DISC_DIR}/* )
        list(FILTER DC_DISC_ASSETS EXCLUDE REGEX "/\\.dummy$|/\\.DS_Store$|/\\.gitignore$")

        set(DC_DISC_ARGS "")
        if(DC_DISC_ASSETS)
            set(DC_DISC_ARGS -D ${DC_DISC_DIR})
        endif()

        # --- CDDA soundtrack --------------------------------------------------
        # Drop the DF2 soundtrack Oggs into packaging/dreamcast/music/ (named so they
        # sort in track order, e.g. Track2.ogg .. Track12.ogg). Each is transcoded to
        # 44.1kHz/16-bit stereo WAV and authored as a Red Book CDDA audio track, which
        # the GD-ROM plays in hardware (see the Dreamcast stdMci). The data track is 1,
        # so the first Ogg becomes CD track 2 -- matching the engine's track numbers.
        # Needs ffmpeg on the host; missing ffmpeg or no Oggs => disc builds without
        # music (not an error). Oggs are user-supplied game assets and not committed.
        set(DC_MUSIC_DIR ${PROJECT_SOURCE_DIR}/packaging/dreamcast/music)
        set(DC_CDDA_ARGS "")
        set(DC_CDDA_WAVS "")
        find_program(FFMPEG_BIN ffmpeg)
        # CONFIGURE_DEPENDS: re-glob (and thus pick up newly added Oggs) on a plain
        # `make`, without needing a manual cmake re-run.
        file(GLOB DC_MUSIC_OGGS CONFIGURE_DEPENDS
             ${DC_MUSIC_DIR}/*.ogg ${DC_MUSIC_DIR}/*.OGG)
        list(SORT DC_MUSIC_OGGS COMPARE NATURAL)   # so Track2 precedes Track10
        if(DC_MUSIC_OGGS AND FFMPEG_BIN)
            set(DC_CDDA_DIR ${CMAKE_CURRENT_BINARY_DIR}/cdda)
            file(MAKE_DIRECTORY ${DC_CDDA_DIR})
            set(_cdda_track 2)
            foreach(ogg ${DC_MUSIC_OGGS})
                get_filename_component(_base ${ogg} NAME_WE)
                set(_wav ${DC_CDDA_DIR}/${_base}.wav)
                add_custom_command(
                    OUTPUT ${_wav}
                    COMMAND ${FFMPEG_BIN} -y -loglevel error -i ${ogg}
                            -ar 44100 -ac 2 -c:a pcm_s16le ${_wav}
                    DEPENDS ${ogg}
                    COMMENT "CDDA: ${_base}.ogg -> audio track ${_cdda_track}"
                    VERBATIM)
                list(APPEND DC_CDDA_WAVS ${_wav})
                list(APPEND DC_CDDA_ARGS --cdda ${_wav})
                math(EXPR _cdda_track "${_cdda_track}+1")
            endforeach()
        elseif(DC_MUSIC_OGGS AND NOT FFMPEG_BIN)
            message(WARNING "packaging/dreamcast/music has Oggs but ffmpeg was not found; "
                            "the disc will be built without a CDDA soundtrack.")
        endif()

        add_custom_target(${CDI_NAME} ALL
            DEPENDS ${BIN_NAME} ${DC_DISC_ASSETS} ${DC_CDDA_WAVS}
            BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/${CDI_NAME}
            # --no-padding keeps the .cdi small (~MBs, not ~700MB). Emulators
            # (Flycast/redream) load non-padded images fine; drop -N if you need a
            # disc that boots padded GD-ROM hardware.
            COMMAND ${MKDCDISC}
                    -e $<TARGET_FILE:${BIN_NAME}>
                    -o ${CMAKE_CURRENT_BINARY_DIR}/${CDI_NAME}
                    -n "OpenJKDF2"
                    ${DC_DISC_ARGS}
                    ${DC_CDDA_ARGS}
                    --no-padding
                    -v 1
            COMMENT "Creating Dreamcast disc image ${CDI_NAME}"
            VERBATIM)
    endif()
endmacro()

macro(plat_extra_deps)

endmacro()
