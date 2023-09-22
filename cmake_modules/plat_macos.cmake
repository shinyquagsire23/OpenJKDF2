include(cmake_modules/target_macos_all.cmake)

macro(plat_initialize)
    message( STATUS "Targeting MacOS" )
    set(BIN_NAME "openjkdf2-64")

    add_definitions(-DARCH_64BIT)

    # macOS specific options
    set(MACOSX_DEPLOYMENT_TARGET "10.15" CACHE STRING "Minimum OS X deployment version" FORCE)

    include(cmake_modules/plat_feat_full_sdl2.cmake)

    set(TARGET_MACOS TRUE)

    set(BUNDLE "${PROJECT_SOURCE_DIR}/OpenJKDF2.app")
    set(HOMEBREW_PREFIX $ENV{HOMEBREW_PREFIX})

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -std=c11 -O2 -Wuninitialized -fshort-wchar -Wall -Wno-unused-variable -Wno-parentheses -Wno-missing-braces -Werror=implicit-function-declaration")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fshort-wchar")

    add_link_options(-fshort-wchar -Wl,-map,openjkdf2.map)
endmacro()

macro(plat_specific_deps)
    plat_sdl2_deps()
endmacro()