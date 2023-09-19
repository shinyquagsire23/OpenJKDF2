macro(plat_initialize)
    message( STATUS "Targeting Linux 64-bit" )
    set(BIN_NAME "openjkdf2")

    add_definitions(-DARCH_64BIT)
    add_definitions(-D_XOPEN_SOURCE=500)
    add_definitions(-D_DEFAULT_SOURCE)

    include(cmake_modules/plat_feat_full_sdl2.cmake)

    set(TARGET_LINUX TRUE)

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -std=c11 -fshort-wchar -Werror=implicit-function-declaration -Wno-unused-variable -Wno-parentheses ")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fshort-wchar -Werror=implicit-function-declaration -Wno-unused-variable -Wno-parentheses ")
    add_link_options(-fshort-wchar)
endmacro()

macro(plat_specific_deps)
    plat_sdl2_deps()
endmacro()