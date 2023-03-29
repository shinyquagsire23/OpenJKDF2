set(SYMBOLS_FILE ${PROJECT_SOURCE_DIR}/symbols.syms)
set(GLOBALS_H ${PROJECT_SOURCE_DIR}/src/globals.h)
set(GLOBALS_C ${PROJECT_SOURCE_DIR}/src/globals.c)
set(GLOBALS_H_COG ${PROJECT_SOURCE_DIR}/src/globals.h.cog)
set(GLOBALS_C_COG ${PROJECT_SOURCE_DIR}/src/globals.c.cog)
list(APPEND SOURCE_FILES ${GLOBALS_C})

# All of our pre-build steps
add_custom_command(
    OUTPUT ${GLOBALS_C}
    COMMAND cog -d -D symbols_fpath="${SYMBOLS_FILE}" -D project_root="${PROJECT_SOURCE_DIR}" -o ${GLOBALS_C} ${GLOBALS_C_COG}
    DEPENDS ${SYMBOLS_FILE} ${GLOBALS_C_COG} ${GLOBALS_H} ${PROJECT_SOURCE_DIR}/resource/shaders/default_f.glsl ${PROJECT_SOURCE_DIR}/resource/shaders/default_v.glsl ${PROJECT_SOURCE_DIR}/resource/shaders/menu_f.glsl ${PROJECT_SOURCE_DIR}/resource/shaders/menu_v.glsl ${PROJECT_SOURCE_DIR}/resource/shaders/texfbo_f.glsl ${PROJECT_SOURCE_DIR}/resource/shaders/texfbo_v.glsl ${PROJECT_SOURCE_DIR}/resource/shaders/blur_f.glsl ${PROJECT_SOURCE_DIR}/resource/shaders/blur_v.glsl ${PROJECT_SOURCE_DIR}/resource/shaders/ssao_f.glsl ${PROJECT_SOURCE_DIR}/resource/shaders/ssao_v.glsl ${PROJECT_SOURCE_DIR}/resource/shaders/ssao_mix_f.glsl ${PROJECT_SOURCE_DIR}/resource/shaders/ssao_mix_v.glsl ${PROJECT_SOURCE_DIR}/resource/shaders/ui_f.glsl ${PROJECT_SOURCE_DIR}/resource/shaders/ui_v.glsl ${PROJECT_SOURCE_DIR}/resource/ssl/cacert.pem ${PROJECT_SOURCE_DIR}/resource/ui/openjkdf2.uni  ${PROJECT_SOURCE_DIR}/resource/ui/openjkdf2_i8n.uni
)

add_custom_command(
    OUTPUT ${GLOBALS_H}
    COMMAND cog -d -D symbols_fpath="${SYMBOLS_FILE}" -D project_root="${PROJECT_SOURCE_DIR}" -o ${GLOBALS_H} ${GLOBALS_H_COG}
    DEPENDS ${SYMBOLS_FILE} ${GLOBALS_H_COG}
)

add_custom_command(
    PRE_BUILD
    OUTPUT ${BIN_NAME}
    DEPENDS ${GLOBALS_C} ${GLOBALS_H}
)