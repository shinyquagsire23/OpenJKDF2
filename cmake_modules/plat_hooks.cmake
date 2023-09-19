macro(plat_initialize)
    message( STATUS "Targeting MinGW Hooks DLL" )

    set(BIN_NAME "df2_reimpl")

    add_definitions(-DWIN32)
    add_definitions(-DWIN32_BLOBS)
    add_definitions(-DARCH_X86)
    add_definitions(-DTARGET_HAS_DPLAY)

    set(TARGET_HOOKS TRUE)
    set(OPENJKDF2_NO_ASAN TRUE)
    set(TARGET_USE_D3D TRUE)
    set(TARGET_BUILD_TESTS FALSE)
    set(TARGET_FIND_OPENAL FALSE)

    set(TARGET_WIN32 TRUE)

    add_compile_options(-g -Wuninitialized -fno-trapping-math)
    add_link_options(-g -Wl,--subsystem,windows -Wl,-Map=% -fno-trapping-math)
endmacro()

macro(plat_specific_deps)
    plat_sdl2_deps()
endmacro()

macro(plat_link_and_package)
    target_link_libraries(${BIN_NAME} PRIVATE -static-libgcc)
    target_link_libraries("${BIN_NAME}_kvm" PRIVATE -Wl,-e_hook_init -nostartfiles -static -static-libgcc -static-libstdc++)
endmacro()