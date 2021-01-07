#include "sithWorld.h"

#include "General/stdConffile.h"
#include "jk.h"

#define jkl_section_parsers ((sith_map_section_and_func*)0x833548)

int (*jkl_parse_adjoins_surfaces)(sithWorld* jkl, int b) = (void*)0x004E5C00;
//int (*jkl_init_parsers)(sithWorld* jkl, int b) = (void*)0x004CF6F0;
//int (*sithWorld_SetSectionParser)(sithWorld* jkl, int b) = (void*)0x004D0820;
//int (*sithWorld_FindSectionParser)(sithWorld* jkl, int b) = (void*)0x004D0E20;
int (*jkl_parse_next_line)(void) = (void*)0x004315C0;
int (*jkl_read_line)(void) = (void*)0x431650;

int (*jkl_things_parse)(sithWorld* jkl, int b) = (void*)0x004CE710;
int (*jkl_templates_parse)(sithWorld* jkl, int b) = (void*)0x004DD9B0;
int (*jkl_sprites_parse)(sithWorld* jkl, int b) = (void*)0x004F2190;
int (*jkl_sounds_parse)(sithWorld* jkl, int b) = (void*)0x004EEF00;
int (*jkl_soundclass_parse)(sithWorld* jkl, int b) = (void*)0x004E64C0;
int (*jkl_sectors_parse)(sithWorld* jkl, int b) = (void*)0x004F8720;
int (*jkl_models_parse)(sithWorld* jkl, int b) = (void*)0x004E96A0;
int (*jkl_materials_parse_)(sithWorld* jkl, int b) = (void*)0x004F0D94;
int (*jkl_materials_parse)(sithWorld* jkl, int b) = (void*)0x004F0D90;
int (*jkl_keyframes_parse)(sithWorld* jkl, int b) = (void*)0x004E55B0;
//int (*jkl_header_parse)(sithWorld* jkl, int b) = (void*)0x004D02D0;
int (*jkl_georesource_parse)(sithWorld* jkl, int b) = (void*)0x004D0E70;
//int (*jkl_copyright_parse)(sithWorld* jkl, int b) = (void*)0x004D04D0;
int (*jkl_cogsripts_parse)(sithWorld* jkl, int b) = (void*)0x004E0040;
int (*jkl_cogscript_parse)(sithWorld* jkl, int b) = (void*)0x004FC9D0;
int (*jkl_cogs_parse)(sithWorld* jkl, int b) = (void*)0x004DF110;
int (*jkl_animclass_parse)(sithWorld* jkl, int b) = (void*)0x004E4ED0;
int (*jkl_aiclass_parse)(sithWorld* jkl, int b) = (void*)0x004F1230;

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

static sithWorldProgressCallback_t sithWorld_LoadPercentCallback;

int sithWorld_Startup()
{
    sithWorld_numParsers = 0;
    sithWorld_SetSectionParser("georesource", jkl_georesource_parse);
    sithWorld_SetSectionParser("copyright", sithCopyright_Load);
    sithWorld_SetSectionParser("header", sithHeader_Load);
    sithWorld_SetSectionParser("sectors", jkl_sectors_parse);
    sithWorld_SetSectionParser("models", jkl_models_parse);
    sithWorld_SetSectionParser("sprites", jkl_sprites_parse);
    sithWorld_SetSectionParser("things", jkl_things_parse);
    sithWorld_SetSectionParser("templates", jkl_templates_parse);
    sithWorld_SetSectionParser("materials", jkl_materials_parse);
    sithWorld_SetSectionParser("sounds", jkl_sounds_parse);
    sithWorld_SetSectionParser("cogs", jkl_cogs_parse);
    sithWorld_SetSectionParser("cogscripts", jkl_cogsripts_parse);
    sithWorld_SetSectionParser("keyframes", jkl_keyframes_parse);
    sithWorld_SetSectionParser("animclass", jkl_animclass_parse);
    sithWorld_SetSectionParser("aiclass", jkl_aiclass_parse);
    sithWorld_SetSectionParser("soundclass", jkl_soundclass_parse);
    sithWorld_bInitted = 1;
    return 1;
}

void sithWorld_Shutdown()
{
    if ( sithWorld_pCurWorld )
        pSithHS->free(sithWorld_pCurWorld);
    if ( sithWorld_pStatic )
        pSithHS->free(sithWorld_pStatic);
    sithWorld_pCurWorld = 0;
    sithWorld_pStatic = 0;
    sithWorld_pLoading = 0;
    sithWorld_bInitted = 0;
}

void sithWorld_SetLoadPercentCallback(sithWorldProgressCallback_t func)
{
    sithWorld_LoadPercentCallback = func;
}

void sithWorld_UpdateLoadPercent(float percent)
{
    if ( sithWorld_LoadPercentCallback )
        sithWorld_LoadPercentCallback(percent);
}

int sithHeader_Load(sithWorld *world, int junk)
{
    if ( junk )
        return 0;
    if ( !stdConffile_ReadLine() )
        return 0;
    _sscanf(stdConffile_aLine, "version %d", &junk);
    if ( !stdConffile_ReadLine() )
        return 0;
    _sscanf(stdConffile_aLine, "world gravity %f", &world->worldGravity);
    if ( !stdConffile_ReadLine() )
        return 0;
    _sscanf(stdConffile_aLine, "ceiling sky z %f", &world->ceilingSky);
    if ( !stdConffile_ReadLine() )
        return 0;
    _sscanf(stdConffile_aLine, "horizon distance %f", &world->horizontalDistance);
    if ( !stdConffile_ReadLine() )
        return 0;
    _sscanf(stdConffile_aLine, "horizon pixels per rev %f", &world->horizontalPixelsPerRev);
    if ( !stdConffile_ReadLine() )
        return 0;
    _sscanf(stdConffile_aLine, "horizon sky offset %f %f", &world->horizontalSkyOffs, &world->horizontalSkyOffs.y);
    if ( !stdConffile_ReadLine() )
        return 0;
    _sscanf(stdConffile_aLine, "ceiling sky offset %f %f", &world->ceilingSkyOffs, &world->ceilingSkyOffs.y);
    if ( !stdConffile_ReadLine() )
        return 0;
    _sscanf(
        stdConffile_aLine,
        "mipmap distances %f %f %f %f",
        &world->mipmapDistance.x,
        &world->mipmapDistance.y,
        &world->mipmapDistance.z,
        &world->mipmapDistance.w);
    if ( !stdConffile_ReadLine() )
        return 0;
    _sscanf(stdConffile_aLine, "lod distances %f %f %f %f", &world->loadDistance.x, &world->loadDistance.y, &world->loadDistance.z, &world->loadDistance.w);
    if ( !stdConffile_ReadLine() )
        return 0;
    _sscanf(stdConffile_aLine, "perspective distance %f", &world->perspectiveDistance);
    if ( !stdConffile_ReadLine() )
        return 0;
    _sscanf(stdConffile_aLine, "gouraud distance %f", &world->gouradDistance);

#ifdef QOL_IMPROVEMENTS
    world->mipmapDistance.x = 200.0;
    world->mipmapDistance.y = 200.0;
    world->mipmapDistance.z = 200.0;
    world->mipmapDistance.w = 200.0;
    world->loadDistance.x = 200.0;
    world->loadDistance.y = 200.0;
    world->loadDistance.z = 200.0;
    world->loadDistance.w = 200.0;
#endif

    return 1;
}

int sithCopyright_Load(sithWorld *lvl, int junk)
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

int sithWorld_SetSectionParser(char *section_name, sithWorldSectionParser_t funcptr)
{
    int idx = sithWorld_FindSectionParser(section_name);
    if (idx == -1)
    {
        if ( sithWorld_numParsers >= 32 )
            return 0;
        idx = sithWorld_numParsers++;
    }
    _strncpy(jkl_section_parsers[idx].section_name, section_name, 0x1Fu);
    jkl_section_parsers[idx].section_name[31] = 0;
    jkl_section_parsers[idx].funcptr = funcptr;
    return 1;
}

int sithWorld_FindSectionParser(char *a1)
{
    if ( sithWorld_numParsers <= 0 )
        return -1;

    int i = 0;
    sith_map_section_and_func *iter = jkl_section_parsers;
    while ( __strcmpi(iter->section_name, a1) )
    {
        ++i;
        ++iter;
        if ( i >= sithWorld_numParsers )
            return -1;
    }
    return i;
}
