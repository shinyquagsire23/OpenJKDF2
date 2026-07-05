macro(plat_initialize)
    message( STATUS "Targeting Win64 MinGW" )

    set(BIN_NAME "${PROJECT_NAME}-64")
    string(TOLOWER ${BIN_NAME} BIN_NAME)

    add_compile_definitions(
        WINVER=0x0600 _WIN32_WINNT=0x0600
        WIN64_STANDALONE #TODO: Rename to `WINDOWS_STANDALONE`
        ARCH_64BIT       #TODO: Test `sizeof(void*)` or `_WIN64` instead
        WIN32            #TODO: Test `_WIN32` instead
        WIN64_MINGW      #TODO: Test `_WIN64 && __MINGW32__` or `__MINGW64__` or `_WIN64 && __GNUC__` instead
    )

    if (NOT DEFINED GITHUB_RUNNER_COMPILE)
        set(TARGET_USE_PHYSFS TRUE)
        set(TARGET_USE_GAMENETWORKINGSOCKETS TRUE)
    endif()
    set(OPENJKDF2_NO_ASAN TRUE)
    set(TARGET_USE_LIBSMACKER TRUE)
    set(TARGET_USE_LIBSMUSHER TRUE)
    set(TARGET_USE_SDL2 TRUE)
    set(TARGET_USE_OPENGL TRUE)
    if (NOT DEFINED GITHUB_RUNNER_COMPILE)
        set(TARGET_USE_OPENAL TRUE)
    endif()
    set(TARGET_POSIX TRUE)
    set(TARGET_WIN32 TRUE)
    set(TARGET_NO_BLOBS TRUE)
    set(TARGET_CAN_JKGM TRUE)
    set(TARGET_USE_CURL TRUE)
    set(TARGET_COMPILE_FREEGLUT TRUE)
    set(TARGET_FIND_OPENAL FALSE)
    

    add_compile_definitions(main=SDL_main _MBCS)
    # TODO: Bump to O2 eventually. MinGW likes to replace memset with calls to itself...
    add_compile_options(-pthread -Wall -Wno-unused-variable -Wno-parentheses -Wno-missing-braces)
    if(CMAKE_BUILD_TYPE STREQUAL Debug)
        add_compile_options(-Og)
    else()
        add_compile_options(-O2)
    endif()
endmacro()

macro(plat_specific_deps)
    set(SDL2_COMMON_LIBS SDL2main SDL::SDL)
endmacro()

macro(plat_link_and_package)
    set_target_properties(${BIN_NAME} PROPERTIES
        ENABLE_EXPORTS FALSE
        WINDOWS_EXPORT_ALL_SYMBOLS FALSE
        # CMake missbehaives here because the PE image version field actually
        # specifies the version of the PE specification the PE image has been
        # built to and has NOTHING to do with the application version.
        # Traditionally, the PE image version has followed the internal release
        # version of Windows. Consequently, becuase the linker is the last tool
        # to build a PE image it is supposed to be the linker who should set
        # the PE image version field.
        VERSION ${CMAKE_SYSTEM_VERSION}
    )
    if(CMAKE_BUILD_TYPE STREQUAL Release OR
       CMAKE_BUILD_TYPE STREQUAL MinSizeRel OR
       CMAKE_BUILD_TYPE STREQUAL RelWithDebInfo)
        # TODO: Implement WinMain() for this to work nicely
        set_target_properties(${BIN_NAME} PROPERTIES WIN32_EXECUTABLE TRUE)
    elseif(CMAKE_BUILD_TYPE STREQUAL Debug)
        set_target_properties(${BIN_NAME} PROPERTIES WIN32_EXECUTABLE FALSE)
    endif()

    target_link_libraries(sith_engine PRIVATE GLUT::GLUT)
    target_link_libraries(sith_engine PRIVATE GLEW::glew_s)
    target_link_libraries(${BIN_NAME} PRIVATE GLEW::glew_s)
    # Note: libssp is statically linked in the toolchain's standard libraries, so
    # it is intentionally not listed here -- adding -lssp re-adds libssp-0.dll.
    target_link_libraries(sith_engine PRIVATE mingw32 ${SDL2_COMMON_LIBS} version imm32 setupapi gdi32 winmm imm32 ole32 oleaut32 shell32 winmm user32 crypt32 advapi32) # SDL2’s peculiarity that you have to link mingw32 before SDL2main
    
    if(TARGET_CAN_JKGM)
        target_link_libraries(sith_engine PRIVATE PNG::PNG ZLIB::ZLIB)
    endif()

    if (TARGET_USE_OPENAL)
        # SDL::Mixer must precede its Vorbis/Ogg deps: with fully static libs the
        # linker only pulls objects that resolve an already-seen undefined symbol,
        # so the mixer archive (which references ov_*) has to come before
        # vorbisfile/vorbis/ogg in SDL_MIXER_DEPS.
        target_link_libraries(sith_engine PRIVATE SDL::Mixer ${SDL_MIXER_DEPS})
        target_link_libraries(sith_engine PRIVATE OpenAL::OpenAL)
    endif()
    target_link_libraries(sith_engine PRIVATE nlohmann_json::nlohmann_json)
    if(TARGET_USE_GAMENETWORKINGSOCKETS)
        # Loaded at runtime via LoadLibrary("libGameNetworkingSockets.dll") in
        # stdComm_GNS.cpp -- shipped as a DLL, not statically linked.
        target_link_libraries(sith_engine PRIVATE GameNetworkingSockets::GameNetworkingSockets)
    endif()
    if(TARGET_USE_PHYSFS)
        target_link_libraries(sith_engine PRIVATE PhysFS::PhysFS_s)
        target_link_libraries(${BIN_NAME} PRIVATE PhysFS::PhysFS_s)
    endif()
    # Windows system import libs, listed last so they satisfy undefined symbols
    # pulled in by any of the static archives above (link order matters for the
    # import-stub archives too, e.g. SDL's SHGetSpecialFolderPathW in shell32).
    target_link_libraries(sith_engine PRIVATE opengl32 ws2_32 uuid ole32 shell32 shlwapi advapi32 user32 gdi32 winmm imm32 version setupapi oleaut32 crypt32)

    # OpenAL ships as a DLL so it can be swapped for another OpenAL implementation.
    if (TARGET_USE_OPENAL)
        add_custom_command(
            TARGET ${BIN_NAME}
            POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_BINARY_DIR}/openal/bin/OpenAL32.dll ${PROJECT_BINARY_DIR}
        )
    endif()

    # GameNetworkingSockets ships as a DLL (loaded on demand via LoadLibrary).
    if(TARGET_USE_GAMENETWORKINGSOCKETS)
        add_custom_command(
            TARGET ${BIN_NAME}
            POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_BINARY_DIR}/GameNetworkingSockets/bin/libGameNetworkingSockets.dll ${PROJECT_BINARY_DIR}
        )
    endif()
endmacro()