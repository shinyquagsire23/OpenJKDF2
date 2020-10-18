#include "jkl.h"

#include "jk.h"

int (*jkl_parse_adjoins_surfaces)(sith_jkl* jkl, int b) = (void*)0x004E5C00;
//int (*jkl_init_parsers)(sith_jkl* jkl, int b) = (void*)0x004CF6F0;
//int (*jkl_set_section_parser)(sith_jkl* jkl, int b) = (void*)0x004D0820;
//int (*jkl_find_section_parser)(sith_jkl* jkl, int b) = (void*)0x004D0E20;
int (*jkl_parse_next_line)(void) = (void*)0x004315C0;
int (*jkl_read_line)(void) = (void*)0x431650;

int (*jkl_things_parse)(sith_jkl* jkl, int b) = (void*)0x004CE710;
int (*jkl_templates_parse)(sith_jkl* jkl, int b) = (void*)0x004DD9B0;
int (*jkl_sprites_parse)(sith_jkl* jkl, int b) = (void*)0x004F2190;
int (*jkl_sounds_parse)(sith_jkl* jkl, int b) = (void*)0x004EEF00;
int (*jkl_soundclass_parse)(sith_jkl* jkl, int b) = (void*)0x004E64C0;
int (*jkl_sectors_parse)(sith_jkl* jkl, int b) = (void*)0x004F8720;
int (*jkl_models_parse)(sith_jkl* jkl, int b) = (void*)0x004E96A0;
int (*jkl_materials_parse_)(sith_jkl* jkl, int b) = (void*)0x004F0D94;
int (*jkl_materials_parse)(sith_jkl* jkl, int b) = (void*)0x004F0D90;
int (*jkl_keyframes_parse)(sith_jkl* jkl, int b) = (void*)0x004E55B0;
//int (*jkl_header_parse)(sith_jkl* jkl, int b) = (void*)0x004D02D0;
int (*jkl_georesource_parse)(sith_jkl* jkl, int b) = (void*)0x004D0E70;
//int (*jkl_copyright_parse)(sith_jkl* jkl, int b) = (void*)0x004D04D0;
int (*jkl_cogsripts_parse)(sith_jkl* jkl, int b) = (void*)0x004E0040;
int (*jkl_cogscript_parse)(sith_jkl* jkl, int b) = (void*)0x004FC9D0;
int (*jkl_cogs_parse)(sith_jkl* jkl, int b) = (void*)0x004DF110;
int (*jkl_animclass_parse)(sith_jkl* jkl, int b) = (void*)0x004E4ED0;
int (*jkl_aiclass_parse)(sith_jkl* jkl, int b) = (void*)0x004F1230;

#define jkl_line_that_was_read (*(char**)0x860D40)
#define jkl_read_copyright ((char*)0x833108)
#define some_integer_4 (*(uint32_t*)0x8339E0)

const char* g_level_header =
    "................................"
    "................@...@...@...@..."
    ".............@...@..@..@...@...."
    "................@.@.@.@.@.@....."
    "@@@@@@@@......@...........@....."
    "@@@@@@@@....@@......@@@....@...."
    "@@.....@.....@......@@@.....@@.."
    "@@.@@@@@......@.....@@@......@@."
    "@@@@@@@@.......@....@@.....@@..."
    "@@@@@@@@.........@@@@@@@@@@....."
    "@@@@@@@@..........@@@@@@........"
    "@@.....@..........@@@@@........."
    "@@.@@@@@.........@@@@@@........."
    "@@.....@.........@@@@@@........."
    "@@@@@@@@.........@@@@@@........."
    "@@@@@@@@.........@@@@@@@........"
    "@@@...@@.........@@@@@@@........"
    "@@.@@@.@.........@.....@........"
    "@@..@..@........@.......@......."
    "@@@@@@@@........@.......@......."
    "@@@@@@@@.......@........@......."
    "@@..@@@@.......@........@......."
    "@@@@..@@......@.........@......."
    "@@@@.@.@......@.........@......."
    "@@....@@........................"
    "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
    "@@@@@@@@@@@@@.@@@@@@@@@@@@@@@@@@"
    "@@.@@..@@@@@..@@@@@@@@@@.@@@@@@@"
    "@@.@.@.@@@@.@.@@@.@..@@...@@@..@"
    "@@..@@@@@@....@@@..@@@@@.@@@@.@@"
    "@@@@@@@@...@@.@@@.@@@@@..@@...@@"
    "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
    "@.copyright.(c).1997.lucasarts.@"
    "@@@@@@..entertainment.co..@@@@@@";

int jkl_copyright_parse(sith_jkl *lvl, int junk)
{
    char *iter;

    if (junk)
        return 0;

    iter = jkl_read_copyright;
    do
    {
        if (!jkl_read_line())
            return 0;
        _memcpy(iter, jkl_line_that_was_read, 0x20);
        iter += 0x20;
    }
    while (iter < &jkl_read_copyright[0x440]);

    
    if (_memcmp(jkl_read_copyright, g_level_header, 0x440))
    {
        some_integer_4 = 0;
        return 0;
    }

    some_integer_4 = 1;
    return 1;
}

int jkl_header_parse(sith_jkl *lvl, int junk)
{
    if ( junk )
        return 0;

    if ( !jkl_read_line() )
        return 0;
    _sscanf(jkl_line_that_was_read, "version %d", &junk);

    if ( !jkl_read_line() )
        return 0;
    _sscanf(jkl_line_that_was_read, "world gravity %f", &lvl->world_gravity);

    if ( !jkl_read_line() )
        return 0;
    _sscanf(jkl_line_that_was_read, "ceiling sky z %f", &lvl->ceiling_sky);

    if ( !jkl_read_line() )
        return 0;
    _sscanf(jkl_line_that_was_read, "horizon distance %f", &lvl->horizontal_distance);

    if ( !jkl_read_line() )
        return 0;
    _sscanf(jkl_line_that_was_read, "horizon pixels per rev %f", &lvl->horizontal_pixels_per_rev);

    if ( !jkl_read_line() )
        return 0;
    _sscanf(jkl_line_that_was_read, "horizon sky offset %f %f", &lvl->horizontal_sky_offs.x, &lvl->horizontal_sky_offs.y);
    
    if ( !jkl_read_line() )
        return 0;
    _sscanf(jkl_line_that_was_read, "ceiling sky offset %f %f", &lvl->ceiling_sky_offs.x, &lvl->ceiling_sky_offs.y);
    
    if ( !jkl_read_line() )
        return 0;
    _sscanf(jkl_line_that_was_read, "mipmap distances %f %f %f %f",
           &lvl->mipmap_distance.x,
           &lvl->mipmap_distance.y,
           &lvl->mipmap_distance.z,
           &lvl->mipmap_distance.w);

    if ( !jkl_read_line() )
        return 0;
    _sscanf(jkl_line_that_was_read, "lod distances %f %f %f %f",
           &lvl->load_distance.x,
           &lvl->load_distance.y,
           &lvl->load_distance.z,
           &lvl->load_distance.w);

    if ( !jkl_read_line() )
        return 0;
    _sscanf(jkl_line_that_was_read, "perspective distance %f", &lvl->perspective_distance);
    
    if ( !jkl_read_line() )
        return 0;
    _sscanf(jkl_line_that_was_read, "gouraud distance %f", &lvl->gourad_distance);

    return 1;
}

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
