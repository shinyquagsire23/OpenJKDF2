macro(plat_initialize)
    message( STATUS "Targeting Win64 MSVC" )

    set(BIN_NAME "openjkdf2-64")

    add_compile_definitions(WINVER=0x0600 _WIN32_WINNT=0x0600)
    add_compile_definitions(WIN64)
    add_compile_definitions(WIN64_STANDALONE)
    add_compile_definitions(ARCH_64BIT)
    add_compile_definitions(WIN32)

    include(cmake_modules/plat_feat_full_sdl2.cmake)
    set(TARGET_USE_PHYSFS FALSE)
    set(TARGET_USE_CURL FALSE)
    set(TARGET_COMPILE_FREEGLUT TRUE)
    set(TARGET_FIND_OPENAL FALSE)
    set(SDL2_COMMON_LIBS SDL2main SDL::SDL)
    
    set(TARGET_WIN32 TRUE)

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /std:c11")
endmacro()

macro(plat_specific_deps)
    set(SDL2_COMMON_LIBS SDL2main SDL::SDL)
endmacro()