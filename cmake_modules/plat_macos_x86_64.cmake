include(cmake_modules/target_macos_all.cmake)

macro(plat_initialize)
    message( STATUS "Targeting MacOS x86_64 ${CMAKE_OSX_ARCHITECTURES}" )
    set(BIN_NAME "openjkdf2-64")

    add_definitions(-DARCH_64BIT)

    # macOS specific options
    set(MACOSX_DEPLOYMENT_TARGET "10.15" CACHE STRING "Minimum OS X deployment version" FORCE)

    include(cmake_modules/plat_feat_full_sdl2.cmake)

    set(TARGET_MACOS TRUE)

    set(BUNDLE "${PROJECT_SOURCE_DIR}/OpenJKDF2_x86_64.app")
    set(HOMEBREW_PREFIX "/usr/local")

    # Added: -fno-builtin-wcslen, same trap as WASM/iOS (see plat_wasm.cmake): Apple clang 21
    # turns jk.c's char16_t _wcslen loop into libc wcslen(), which counts 4-byte wchar_t
    # on macOS -> every menu label cut in half.
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -std=c11 -O2 -Wuninitialized -fshort-wchar -fno-builtin-wcslen -Wall -Wno-unused-variable -Wno-parentheses -Wno-missing-braces -Werror=implicit-function-declaration")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fshort-wchar -fno-builtin-wcslen")
    add_link_options(-fshort-wchar)
endmacro()

macro(plat_specific_deps)
    plat_sdl2_deps()
endmacro()