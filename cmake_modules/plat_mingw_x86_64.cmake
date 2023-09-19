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