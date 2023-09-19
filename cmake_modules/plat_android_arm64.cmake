function(plat_initialize)
    message( STATUS "Targeting Android ARM64" )

    set(BIN_NAME "openjkdf2-armv8a")

    add_definitions(-DTARGET_ANDROID)
    add_definitions(-DLINUX)
    add_definitions(-DSTDSOUND_NULL)

    include(cmake_modules/plat_feat_full_sdl2.cmake)
    set(TARGET_USE_PHYSFS FALSE)
    set(TARGET_USE_OPENAL FALSE)
    set(TARGET_CAN_JKGM FALSE)
    set(TARGET_USE_CURL FALSE)
    set(TARGET_BUILD_TESTS FALSE)
    set(TARGET_FIND_OPENAL FALSE)
    
    set(TARGET_ANDROID TRUE)
    set(TARGET_ANDROID_ARM64 TRUE)

    list(APPEND CMAKE_PREFIX_PATH "${CMAKE_SOURCE_DIR}/lib/glew")
    include_directories(${PROJECT_SOURCE_DIR}/lib/freeglut/include)
    include_directories(${PROJECT_SOURCE_DIR}/lib/glew/include)

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -std=c11 -fshort-wchar -Werror=implicit-function-declaration -Wno-unused-variable -Wno-parentheses")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fshort-wchar")
    add_link_options(-fshort-wchar)
endfunction()

macro(plat_specific_deps)
    plat_sdl2_deps()
endmacro()

macro(plat_link_and_package)
    
endmacro()