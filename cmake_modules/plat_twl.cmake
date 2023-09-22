macro(plat_initialize)
    message( STATUS "Targeting Nintendo DSi" )

    set(BIN_NAME "openjkdf2")

    #add_definitions(-DARCH_WASM)

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

    if(OPENJKDF2_USE_BLOBS)
        set(TARGET_NO_BLOBS FALSE)
    endif()

    set(TARGET_BUILD_TESTS FALSE)
    set(SDL2_COMMON_LIBS "")

    set(TARGET_TWL TRUE)

    add_link_options(-fno-exceptions)
    add_compile_options(-fno-exceptions)
    add_compile_options(-O2 -Wuninitialized -fshort-wchar -Wall -Wno-unused-variable -Wno-parentheses -Wno-missing-braces)
endmacro()

macro(plat_specific_deps)
    set(SDL2_COMMON_LIBS "")
endmacro()

macro(plat_link_and_package)
    target_link_libraries(${BIN_NAME} PRIVATE -lm -lSDL2 -lSDL2_mixer -lGL -lGLEW -lopenal)
    target_link_libraries(sith_engine PRIVATE nlohmann_json::nlohmann_json)
endmacro()