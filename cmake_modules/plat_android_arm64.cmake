include(cmake_modules/target_android_all.cmake)

macro(plat_initialize)
    message( STATUS "Targeting Android ARM64" )

    set(BIN_NAME "openjkdf2-armv8a")

    add_definitions(-DARCH_64BIT)
    add_definitions(-DTARGET_ANDROID)
    add_definitions(-DLINUX)
    #add_definitions(-DSTDSOUND_NULL)

    include(cmake_modules/plat_feat_full_sdl2.cmake)
    set(TARGET_USE_PHYSFS FALSE)
    set(TARGET_USE_CURL FALSE)
    set(TARGET_BUILD_TESTS FALSE)
    set(TARGET_FIND_OPENAL FALSE)
    set(TARGET_USE_GAMENETWORKINGSOCKETS FALSE)
    
    set(TARGET_ANDROID TRUE)
    set(TARGET_ANDROID_ARM64 TRUE)

    list(APPEND CMAKE_PREFIX_PATH "${CMAKE_SOURCE_DIR}/lib/glew")
    include_directories(${PROJECT_SOURCE_DIR}/lib/freeglut/include)
    include_directories(${PROJECT_SOURCE_DIR}/lib/glew/include)

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -std=c11 -fshort-wchar -Werror=implicit-function-declaration -Wno-unused-variable -Wno-parentheses")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fshort-wchar")
    add_link_options(-fshort-wchar)
endmacro()

macro(plat_specific_deps)
    #set(SDL2_COMMON_LIBS SDL2main SDL::SDL)
    set(SDL2_COMMON_LIBS SDL2main SDL::SDL ${SDL_MIXER_DEPS} SDL::Mixer OpenAL::OpenAL)
endmacro()

