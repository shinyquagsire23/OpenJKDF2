#include "sithWorld.h"

#include "General/stdConffile.h"
#include "Engine/sithModel.h"
#include "Engine/sithSprite.h"
#include "Engine/sithTemplate.h"
#include "Engine/sithMaterial.h"
#include "Engine/sithSound.h"
#include "Cog/sithCog.h"
#include "Cog/sithCogScript.h"
#include "Engine/sithKeyFrame.h"
#include "Engine/sithAnimclass.h"
#include "AI/sithAIClass.h"
#include "Engine/sithSoundClass.h"
#include "jk.h"

#define jkl_section_parsers ((sith_map_section_and_func*)0x833548)

int (*sithThing_Load)(sithWorld* jkl, int b) = (void*)0x004CE710;
int (*sithSector_Load)(sithWorld* jkl, int b) = (void*)0x004F8720;
int (*sithWorld_LoadGeoresource)(sithWorld* jkl, int b) = (void*)0x004D0E70;
int (*sithAnimClass_Load)(sithWorld* jkl, int b) = (void*)0x004E4ED0;

//#define jkl_read_copyright ((char*)0x833108)
#define some_integer_4 (*(uint32_t*)0x8339E0)

static char jkl_read_copyright[1088];

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
    sithWorld_SetSectionParser("georesource", sithWorld_LoadGeoresource);
    sithWorld_SetSectionParser("copyright", sithCopyright_Load);
    sithWorld_SetSectionParser("header", sithHeader_Load);
    sithWorld_SetSectionParser("sectors", sithSector_Load);
    sithWorld_SetSectionParser("models", sithModel_Load);
    sithWorld_SetSectionParser("sprites", sithSprite_Load);
    sithWorld_SetSectionParser("things", sithThing_Load);
    sithWorld_SetSectionParser("templates", sithTemplate_Load);
    sithWorld_SetSectionParser("materials", sithMaterial_Load);
    sithWorld_SetSectionParser("sounds", sithSound_Load);
    sithWorld_SetSectionParser("cogs", sithCog_Load);
    sithWorld_SetSectionParser("cogscripts", sithCogScript_Load);
    sithWorld_SetSectionParser("keyframes", sithKeyFrame_Load);
    sithWorld_SetSectionParser("animclass", sithAnimClass_Load);
    sithWorld_SetSectionParser("aiclass", sithAIClass_ParseSection);
    sithWorld_SetSectionParser("soundclass", sithSoundClass_Load);
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
        if (!stdConffile_ReadLine())
            return 0;
        _memcpy(iter, stdConffile_aLine, 0x20);
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
