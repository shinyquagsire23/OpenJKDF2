set(SYMBOLS_FILE ${PROJECT_SOURCE_DIR}/symbols.syms)
set(GLOBALS_H ${CMAKE_CURRENT_BINARY_DIR}/generated/globals.h)
set(GLOBALS_C ${CMAKE_CURRENT_BINARY_DIR}/generated/globals.c)
set(GLOBALS_H_COG ${PROJECT_SOURCE_DIR}/src/globals.h.cog)
set(GLOBALS_C_COG ${PROJECT_SOURCE_DIR}/src/globals.c.cog)

make_directory(${CMAKE_CURRENT_BINARY_DIR}/generated)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/generated)

if(NOT PLAT_MSVC)
    set(PYTHON_EXE "${CMAKE_CURRENT_BINARY_DIR}/cogapp_venv/bin/python3")
    # We invoke cog via `python3 -m cogapp`, never the `cog` console-script (which
    # newer cogapp/Python combos don't reliably install). Use an explicit stamp file
    # as the install command's output so it always exists after a successful install;
    # pointing at bin/cog made the command perpetually dirty (missing output), which
    # cascaded into regenerating globals.h/globals.c and recompiling the engine every build.
    set(COGAPP_DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/cogapp_venv/.cogapp_installed.stamp")
else()
    find_package(Python3 COMPONENTS Interpreter REQUIRED)

    # Print the Python executable path
    message(STATUS "Python executable: ${Python3_EXECUTABLE}")
    set(PYTHON_EXE "${Python3_EXECUTABLE}")
    set(COGAPP_DEPENDS "${Python3_EXECUTABLE}")
endif()

list(JOIN EMBEDDED_RESOURCES "+" EMBEDDED_RESOURCES_SEPARATED)

# All of our pre-build steps
add_custom_command(
    OUTPUT ${GLOBALS_C}
    COMMAND ${PYTHON_EXE} -m cogapp -d -D symbols_fpath="${SYMBOLS_FILE}" -D project_root="${PROJECT_SOURCE_DIR}" -D embedded_resources="${EMBEDDED_RESOURCES_SEPARATED}" -o ${GLOBALS_C} ${GLOBALS_C_COG}
    DEPENDS ${SYMBOLS_FILE} ${GLOBALS_C_COG} ${GLOBALS_H} ${EMBEDDED_RESOURCES} ${PYTHON_EXE} ${COGAPP_DEPENDS}
)

if(NOT PLAT_MSVC)
    add_custom_command(
        OUTPUT ${PYTHON_EXE}
        COMMAND python3 -m venv ${CMAKE_CURRENT_BINARY_DIR}/cogapp_venv
    )
    add_custom_command(
        OUTPUT ${COGAPP_DEPENDS}
        COMMAND ${PYTHON_EXE} -m pip install cogapp
        COMMAND ${CMAKE_COMMAND} -E touch ${COGAPP_DEPENDS}
        DEPENDS ${PYTHON_EXE}
    )
endif()

add_custom_command(
    OUTPUT ${GLOBALS_H}
    COMMAND ${PYTHON_EXE} -m cogapp -d -D symbols_fpath="${SYMBOLS_FILE}" -D project_root="${PROJECT_SOURCE_DIR}" -D embedded_resources="${EMBEDDED_RESOURCES_SEPARATED}" -o ${GLOBALS_H} ${GLOBALS_H_COG}
    DEPENDS ${SYMBOLS_FILE} ${GLOBALS_H_COG} ${PYTHON_EXE} ${COGAPP_DEPENDS} ${EMBEDDED_RESOURCES}
)

# Gather the cog generation into one target. Many sith_engine translation units
# include generated/globals.h transitively (via rdMaterial.h etc.), but CMake has
# no way to know that on a clean build, so a high -j build would compile them while
# cog is still writing globals.h and read a truncated header ("unterminated
# #ifndef"). add_dependencies(sith_engine generate_globals) (in CMakeLists.txt)
# makes every sith_engine object wait for this target to finish first.
set_source_files_properties(${GLOBALS_H} ${GLOBALS_C} PROPERTIES GENERATED TRUE)
add_custom_target(generate_globals DEPENDS ${GLOBALS_H} ${GLOBALS_C})

# HACK
list(REMOVE_ITEM ENGINE_SOURCE_FILES ${GLOBALS_C})
list(APPEND ENGINE_SOURCE_FILES ${GLOBALS_C})