#include "jkl.h"

#include "jk.h"

int (*jkl_parse_adjoins_surfaces)(sith_jkl* jkl, int b) = (void*)0x004E5C00;
//int (*jkl_init_parsers)(sith_jkl* jkl, int b) = (void*)0x004CF6F0;
//int (*jkl_set_section_parser)(sith_jkl* jkl, int b) = (void*)0x004D0820;
//int (*jkl_find_section_parser)(sith_jkl* jkl, int b) = (void*)0x004D0E20;

int (*jkl_things_parse)(sith_jkl* jkl, int b) = (void*)0x004CE710;
int (*jkl_templates_parse)(sith_jkl* jkl, int b) = (void*)0x004DD9B0;
int (*jkl_sprites_parse)(sith_jkl* jkl, int b) = (void*)0x004F2190;
int (*jkl_sounds_parse)(sith_jkl* jkl, int b) = (void*)0x004EEF00;
int (*jkl_soundclass_parse)(sith_jkl* jkl, int b) = (void*)0x004E64C0;
int (*jkl_sound_sprite_line_parse)(sith_jkl* jkl, int b) = (void*)0x004315C0;
int (*jkl_sectors_parse)(sith_jkl* jkl, int b) = (void*)0x004F8720;
int (*jkl_models_parse)(sith_jkl* jkl, int b) = (void*)0x004E96A0;
int (*jkl_materials_parse_)(sith_jkl* jkl, int b) = (void*)0x004F0D94;
int (*jkl_materials_parse)(sith_jkl* jkl, int b) = (void*)0x004F0D90;
int (*jkl_keyframes_parse)(sith_jkl* jkl, int b) = (void*)0x004E55B0;
int (*jkl_header_parse)(sith_jkl* jkl, int b) = (void*)0x004D02D0;
int (*jkl_georesource_parse)(sith_jkl* jkl, int b) = (void*)0x004D0E70;
int (*jkl_copyright_parse)(sith_jkl* jkl, int b) = (void*)0x004D04D0;
int (*jkl_cogsripts_parse)(sith_jkl* jkl, int b) = (void*)0x004E0040;
int (*jkl_cogscript_parse)(sith_jkl* jkl, int b) = (void*)0x004FC9D0;
int (*jkl_cogs_parse)(sith_jkl* jkl, int b) = (void*)0x004DF110;
int (*jkl_animclass_parse)(sith_jkl* jkl, int b) = (void*)0x004E4ED0;
int (*jkl_aiclass_parse)(sith_jkl* jkl, int b) = (void*)0x004F1230;

int jkl_find_section_parser(char *a1)
{
    if ( jkl_num_parsers <= 0 )
        return -1;

    int i = 0;
    sith_map_section_and_func *iter = jkl_section_parsers;
    while ( __strcmpi(iter->section_name, a1) )
    {
        ++i;
        ++iter;
        if ( i >= jkl_num_parsers )
            return -1;
    }
    return i;
}

int jkl_set_section_parser(char *section_name, int (*funcptr)(sith_jkl *, int))
{
    int idx = jkl_find_section_parser(section_name);
    if (idx == -1)
    {
        if ( jkl_num_parsers >= 32 )
            return 0;
        idx = jkl_num_parsers++;
    }
    _strncpy(jkl_section_parsers[idx].section_name, section_name, 0x1Fu);
    jkl_section_parsers[idx].section_name[31] = 0;
    jkl_section_parsers[idx].funcptr = funcptr;
    return 1;
}

int jkl_init_parsers()
{
    jkl_num_parsers = 0;
    jkl_set_section_parser("georesource", jkl_georesource_parse);
    jkl_set_section_parser("copyright", jkl_copyright_parse);
    jkl_set_section_parser("header", jkl_header_parse);
    jkl_set_section_parser("sectors", jkl_sectors_parse);
    jkl_set_section_parser("models", jkl_models_parse);
    jkl_set_section_parser("sprites", jkl_sprites_parse);
    jkl_set_section_parser("things", jkl_things_parse);
    jkl_set_section_parser("templates", jkl_templates_parse);
    jkl_set_section_parser("materials", jkl_materials_parse);
    jkl_set_section_parser("sounds", jkl_sounds_parse);
    jkl_set_section_parser("cogs", jkl_cogs_parse);
    jkl_set_section_parser("cogscripts", jkl_cogsripts_parse);
    jkl_set_section_parser("keyframes", jkl_keyframes_parse);
    jkl_set_section_parser("animclass", jkl_animclass_parse);
    jkl_set_section_parser("aiclass", jkl_aiclass_parse);
    jkl_set_section_parser("soundclass", jkl_soundclass_parse);
    some_integer_2 = 1;
    return 1;
}
