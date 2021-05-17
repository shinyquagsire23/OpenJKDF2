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
#include "stdPlatform.h"
#include "Win95/DebugConsole.h"
#include "General/stdFnames.h"
#include "Engine/rdColormap.h"
#include "World/sithThing.h"
#include "World/sithSector.h"
#include "Engine/sithParticle.h"
#include "Engine/sithSurface.h"
#include "Cog/sithCog.h"
#include "jk.h"

#define jkl_section_parsers ((sith_map_section_and_func*)0x833548)

int (*sithThing_Load)(sithWorld* jkl, int b) = (void*)0x004CE710;
int (*sithSector_Load)(sithWorld* jkl, int b) = (void*)0x004F8720;
int (*sithWorld_LoadGeoresource)(sithWorld* jkl, int b) = (void*)0x004D0E70;
int (*sithAnimClass_Load)(sithWorld* jkl, int b) = (void*)sithAnimClass_Load_ADDR;

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

int sithWorld_Load(sithWorld *world, char *map_jkl_fname)
{
    int result; // eax
    int v3; // esi
    sith_map_section_and_func *parser; // edi
    int startMsecs; // edi
    __int64 v6; // [esp+1Ch] [ebp-120h]
    char section[32]; // [esp+24h] [ebp-118h] BYREF
    char v8[128]; // [esp+44h] [ebp-F8h] BYREF
    char tmp[120]; // [esp+C4h] [ebp-78h] BYREF

    if ( !world )
        return 0;
    if ( map_jkl_fname )
    {
        _strncpy(world->map_jkl_fname, map_jkl_fname, 0x7Fu);
        world->map_jkl_fname[0] = 0; // aaaaaa these sizes are wrong
        _strtolower(world->map_jkl_fname);
        _strncpy(world->some_text_jk1, sithWorld_some_text_jk1, 0x1Fu);
        world->some_text_jk1[0x1F] = 0;
        sithWorld_pLoading = world;
        stdFnames_MakePath(v8, 128, "jkl", map_jkl_fname);
        some_integer_4 = 0;
        if ( !stdConffile_OpenRead(v8) )
        {
LABEL_20:
            stdPrintf(pSithHS->errorPrint, ".\\World\\sithWorld.c", 276, "Parse problem in file '%s'.\n", v8);
            sithWorld_FreeEntry(world);
            return 0;
        }
        while ( stdConffile_ReadLine() )
        {
            if ( _sscanf(stdConffile_aLine, " section: %s", section) == 1 )
            {
                v3 = 0;
                if ( sithWorld_numParsers <= 0 )
                {
LABEL_11:
                    v3 = -1;
                }
                else
                {
                    parser = jkl_section_parsers;
                    while ( __strcmpi(parser->section_name, section) )
                    {
                        ++v3;
                        ++parser;
                        if ( v3 >= sithWorld_numParsers )
                            goto LABEL_11;
                    }
                }
                if ( v3 != -1 )
                {
                    startMsecs = stdPlatform_GetTimeMsec();
                    if ( !jkl_section_parsers[v3].funcptr(world, 0) )
                        goto LABEL_19;
                    v6 = (unsigned int)(stdPlatform_GetTimeMsec() - startMsecs);
                    _sprintf(tmp, "%f seconds to parse section %s.\n", (double)v6 * 0.001, section);
                    DebugConsole_Print(tmp);
                }
            }
        }
        if ( sithWorld_LoadPercentCallback )
            sithWorld_LoadPercentCallback(100.0);
        if ( !some_integer_4 )
        {
LABEL_19:
            stdConffile_Close();
            goto LABEL_20;
        }
        stdConffile_Close();
    }
    if ( sithWorld_NewEntry(world) )
    {
        result = 1;
        sithWorld_bLoaded = 1;
    }
    else
    {
        sithWorld_FreeEntry(world);
        result = 0;
    }
    return result;
}

sithWorld* sithWorld_New()
{
    sithWorld *result; // eax

    result = (sithWorld *)pSithHS->alloc(sizeof(sithWorld));
    if ( result )
        memset(result, 0, sizeof(sithWorld));
    return result;
}

void sithWorld_FreeEntry(sithWorld *world)
{
    unsigned int v1; // edi
    int v2; // ebx

    if ( world->colormaps )
    {
        v1 = 0;
        if ( world->numColormaps )
        {
            v2 = 0;
            do
            {
                rdColormap_FreeEntry(&world->colormaps[v2]);
                ++v1;
                ++v2;
            }
            while ( v1 < world->numColormaps );
        }
        pSithHS->free(world->colormaps);
        world->colormaps = 0;
        world->numColormaps = 0;
    }
    if ( world->things )
        sithThing_Free(world);
    if ( world->sectors )
        sithSector_Free(world);
    if ( world->models )
        sithModel_Free(world);
    if ( world->sprites )
        sithSprite_FreeEntry(world);
    if ( world->particles )
        sithParticle_Free(world);
    if ( world->keyframes )
        sithKeyFrame_Free(world);
    if ( world->templates )
        sithTemplate_FreeWorld(world);
    if ( world->vertices )
    {
        pSithHS->free(world->vertices);
        world->vertices = 0;
    }
    if ( world->verticesTransformed )
    {
        pSithHS->free(world->verticesTransformed);
        world->verticesTransformed = 0;
    }
    if ( world->alloc_unk94 )
    {
        pSithHS->free(world->alloc_unk94);
        world->alloc_unk94 = 0;
    }
    if ( world->alloc_unk9c )
    {
        pSithHS->free(world->alloc_unk9c);
        world->alloc_unk9c = 0;
    }
    if ( world->vertexUVs )
    {
        pSithHS->free(world->vertexUVs);
        world->vertexUVs = 0;
    }
    if ( world->surfaces )
        sithSurface_Free((int)world);
    if ( world->alloc_unk98 )
    {
        pSithHS->free(world->alloc_unk98);
        world->alloc_unk98 = 0;
    }
    if ( world->materials )
        sithMaterial_Free(world);
    if ( world->sounds )
        sithSound_Free(world);
    if ( world->cogs || world->cogScripts )
        sithCog_Free(world);
    if ( world->animclasses )
        sithAnimClass_Free(world);
    if ( world->aiclasses )
        sithAIClass_Free(world);
    if ( world->soundclasses )
        sithSoundClass_Free2(world);
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
