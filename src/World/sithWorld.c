#include "sithWorld.h"

#include "General/stdConffile.h"
#include "General/stdString.h"
#include "World/sithModel.h"
#include "World/sithSprite.h"
#include "World/sithTemplate.h"
#include "World/sithMaterial.h"
#include "Devices/sithSound.h"
#include "Raster/rdCache.h" // rdTri
#include "Cog/sithCog.h"
#include "Engine/sithKeyFrame.h"
#include "Engine/sithAnimClass.h"
#include "AI/sithAIClass.h"
#include "World/sithSoundClass.h"
#include "stdPlatform.h"
#include "Devices/sithConsole.h"
#include "General/stdFnames.h"
#include "Engine/rdColormap.h"
#include "World/sithThing.h"
#include "World/sithSector.h"
#include "World/jkPlayer.h"
#include "Engine/sithParticle.h"
#include "World/sithSurface.h"
#include "World/sithArchLighting.h"
#include "Engine/sithPhysics.h"
#include "Cog/sithCog.h"
#include "General/util.h"
#include "Gameplay/sithPlayer.h"
#include "Platform/std3D.h"
#include "Dw/dwLaser.h" // Added: DroidWorks laser pool free (no-ops off-desktop)
#include "jk.h"

#ifdef TARGET_TWL
#include <nds.h>
#endif

// MOTS added
static sithWorld_ChecksumHandler_t sithWorld_checksumExtraFunc;

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
    sithWorld_RegisterTextSectionParser("georesource", sithWorld_ReadGeoresourceText);
    sithWorld_RegisterTextSectionParser("copyright", sithWorld_ReadCopyrightText);
    sithWorld_RegisterTextSectionParser("header", sithWorld_ReadHeaderText);
    sithWorld_RegisterTextSectionParser("sectors", sithSector_ReadSectorsListText);
    sithWorld_RegisterTextSectionParser("models", sithModel_ReadStaticModelsListText);
    sithWorld_RegisterTextSectionParser("sprites", sithSprite_ReadStaticSpritesListText);
    sithWorld_RegisterTextSectionParser("things", sithThing_ReadStaticThingsListText);
    sithWorld_RegisterTextSectionParser("templates", sithTemplate_ReadThingTemplatesListText);
    sithWorld_RegisterTextSectionParser("materials", sithMaterial_ReadMaterialsListText);
    sithWorld_RegisterTextSectionParser("sounds", sithSound_ReadSoundsListText);
    sithWorld_RegisterTextSectionParser("cogs", sithCog_ReadCogsListText);
    sithWorld_RegisterTextSectionParser("cogscripts", sithCog_ReadCogScriptsListText);
    sithWorld_RegisterTextSectionParser("keyframes", sithKeyFrame_Load);
    sithWorld_RegisterTextSectionParser("animclass", sithAnimClass_Load);
    sithWorld_RegisterTextSectionParser("aiclass", sithAIClass_ReadStaticAIClassesListText);
    sithWorld_RegisterTextSectionParser("soundclass", sithSoundClass_ReadSoundClassesListText);
#ifdef JKM_LIGHTING
    sithWorld_RegisterTextSectionParser("archlighting", sithArchLighting_ParseSection); // MOTS added
#endif
    sithWorld_bInitted = 1;
    return 1;
}

void sithWorld_Shutdown()
{
    if ( sithWorld_g_pCurrentWorld )
        SITH_FREE(sithWorld_g_pCurrentWorld);
    if ( sithWorld_g_pStaticWorld ) {
        //SITH_FREE(sithWorld_g_pStaticWorld); // Added: Actually free everything
        sithWorld_FreeEntry(sithWorld_g_pStaticWorld); // Added: Actually free everything
    }
    sithWorld_g_pCurrentWorld = 0;
    sithWorld_g_pStaticWorld = 0;
    sithWorld_g_pLastLoadedWorld = 0;
    sithWorld_bInitted = 0;
}

void sithWorld_SetLoadProgressCallback(sithWorldProgressCallback_t pfProgressCallback)
{
    sithWorld_LoadPercentCallback = pfProgressCallback;
}

void sithWorld_UpdateLoadProgress(flex_t progress)
{
    if ( sithWorld_LoadPercentCallback )
        sithWorld_LoadPercentCallback(progress);
}

int sithWorld_Load(SithWorld *pWorld, char *pFilename)
{
    int result; // eax
    int v3; // esi
    SithWorldTextSectionParseHandler *parser; // edi
    int startMsecs; // edi
    __int64 v6; // [esp+1Ch] [ebp-120h]
    char section[32]; // [esp+24h] [ebp-118h] BYREF
    char v8[128]; // [esp+44h] [ebp-F8h] BYREF
    char tmp[120]; // [esp+C4h] [ebp-78h] BYREF

    if ( !pWorld )
        return 0;

    stdPlatform_Printf("OpenJKDF2: %s -> %s\n", __func__, pFilename); // Added

#if defined(SDL2_RENDER) || defined(TARGET_RETRO_HOMEBREW)
    std3D_PurgeEntireTextureCache();
#endif

    if ( pFilename )
    {
        // aaaaaa these sizes are wrong
        // Added: actually use correct lengths
        _strncpy(pWorld->map_jkl_fname, pFilename, 0x1F);
        pWorld->map_jkl_fname[31] = 0; 
        _strtolower(pWorld->map_jkl_fname);
        _strncpy(pWorld->episodeName, sithWorld_episodeName, 0x1Fu);
        pWorld->episodeName[0x1F] = 0;
        sithWorld_g_pLastLoadedWorld = pWorld;
        // Added: Droidworks has different paths
        if (!Main_bDroidWorks) {
            stdFnames_MakePath(v8, 128, "jkl", pFilename);
        }
        else {
            stdFnames_MakePath(v8, 128, "mission", pFilename);
        }
        sithWorld_some_integer_4 = 0;
        if ( !stdConffile_Open(v8) )
        {
            goto failed_open;
        }

        while ( stdConffile_ReadLine() )
        {
            if ( _sscanf(stdConffile_g_aLine, " section: %s", section) == 1 )
            {
                v3 = 0;
                if ( sithWorld_numParsers <= 0 )
                {
LABEL_11:
                    v3 = -1;
                }
                else
                {
                    parser = sithWorld_aSectionParsers;
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
                    if ( !sithWorld_aSectionParsers[v3].funcptr(pWorld, 0) ) {
                        // Added
                        _sprintf(tmp, "%f seconds to parse section %s -- FAILED!\n", (flex32_t)v6 * 0.001, section);
                        sithConsole_PrintString(tmp);
#ifdef TARGET_RETRO_HOMEBREW
                        stdPlatform_PrintHeapStats();
#endif
                        goto LABEL_19;
                    }
                    v6 = (unsigned int)(stdPlatform_GetTimeMsec() - startMsecs);
                    _sprintf(tmp, "%f seconds to parse section %s.\n", (flex32_t)v6 * 0.001, section);
                    sithConsole_PrintString(tmp);
#ifdef TARGET_RETRO_HOMEBREW
                    stdPlatform_PrintHeapStats();
#endif
                }
            }
        }
        if ( sithWorld_LoadPercentCallback )
            sithWorld_LoadPercentCallback(100.0);
        if ( !sithWorld_some_integer_4 )
        {
LABEL_19:
            stdConffile_Close();
            goto parse_problem;
        }
        stdConffile_Close();
    }

    if ( sithWorld_LoadPostProcess(pWorld) )
    {
#ifdef SDL2_RENDER
        std3D_UpdateSettings();
#endif
        sithWorld_bLoaded = 1;
#ifdef STDPLATFORM_ALLOC_TRACKING
        // Added: dump the per-file allocation catalog once the world is in.
        stdPlatform_PrintAllocStats();
#endif
        return 1;
    }
    goto cleanup;

failed_open:
    stdPrintf(pSithHS->errorPrint, ".\\World\\sithWorld.c", 276, "Failed to open file '%s'.\n", v8);
    goto cleanup;
parse_problem:
    stdPrintf(pSithHS->errorPrint, ".\\World\\sithWorld.c", 276, "Parse problem in file '%s'.\n", v8);
    goto cleanup;
cleanup:
    sithWorld_FreeEntry(pWorld);
    return 0;
}

SithWorld* sithWorld_NewEntry()
{
    SithWorld *result; // eax

    result = (SithWorld *)SITH_ALLOC(sizeof(SithWorld));
    if ( result )
        _memset(result, 0, sizeof(SithWorld));

    return result;
}

int sithWorld_LoadPostProcess(SithWorld *pWorld)
{
    SithSurfaceAdjoin *v1; // ebp
    SithSector *v2; // ebx
    int v3; // eax
    rdVector3 *v4; // eax
    flex_t *v5; // edi
    int32_t *v6; // edi
    int32_t *v7; // edi
    SithSector **v8; // edx
    int v9; // edi
    SithSurfaceAdjoin *adjoinIter; // eax
    SithSurfaceAdjoin *adjoinIterMirror; // ecx
    SithSector *v12; // ecx
    SithThing *v15; // edx
    SithThing *v16; // eax

    v1 = 0;
    v2 = 0;
    if ( (pWorld->level_type_maybe & 2) == 0 )
    {
        v3 = pWorld->numVertices;
        if ( v3 )
        {
            { TWL_EXTRAM_SUGGEST(pSithHS); // Added: per-frame arrays; word writes only
            v4 = (rdVector3 *)SITH_ALLOC(sizeof(rdVector3) * v3);
            TWL_EXTRAM_RESTORE(pSithHS); }
            pWorld->aTransformedVertices = v4;
            if ( !v4 )
                return 0;

            { TWL_EXTRAM_SUGGEST(pSithHS); // Added
            v5 = (flex_t *)SITH_ALLOC(sizeof(flex_t) * pWorld->numVertices);
            TWL_EXTRAM_RESTORE(pSithHS); }
            pWorld->aVertDynamicLights = v5;
            if ( !v5 )
                return 0;
            stdPlatform_Memzero32(v5, sizeof(flex_t) * pWorld->numVertices); // Added: word-safe

            { TWL_EXTRAM_SUGGEST(pSithHS); // Added
            v6 = (int32_t *)SITH_ALLOC(sizeof(int32_t) * pWorld->numVertices);
            TWL_EXTRAM_RESTORE(pSithHS); }
            pWorld->alloc_unk98 = v6;
            if ( !v6 )
                return 0;
            stdPlatform_Memzero32(v6, sizeof(int) * pWorld->numVertices); // Added: word-safe

            { TWL_EXTRAM_SUGGEST(pSithHS); // Added
            v7 = (int32_t *)SITH_ALLOC(sizeof(int32_t) * pWorld->numVertices);
            TWL_EXTRAM_RESTORE(pSithHS); }
            pWorld->alloc_unk9c = v7;
            if ( !v7 )
                return 0;
            _memset(v7, 0, sizeof(int) * pWorld->numVertices);
            for (int i = 0; i < pWorld->numSurfaces; i++)
            {
                adjoinIter = pWorld->surfaces[i].pAdjoin;
                if ( adjoinIter )
                {
                    adjoinIterMirror = adjoinIter->mirror;
                    if ( adjoinIterMirror )
                        adjoinIter->sector = adjoinIterMirror->surface->pSector;
                    if ( v1 && (v12 = pWorld->surfaces[i].pSector, v2 == pWorld->surfaces[i].pSector) )
                    {
                        v1->next = adjoinIter;
                    }
                    else
                    {
                        v12 = pWorld->surfaces[i].pSector;
                        pWorld->surfaces[i].pSector->adjoins = adjoinIter;
                    }
                    v1 = adjoinIter;
                    v2 = v12;
                }
            }
            sithPlayer_PlacePlayers(pWorld);
            for (int i = 0; i < pWorld->numThingsLoaded; i++)
            {
                v16 = &pWorld->aThings[i];
                if ( v16->type
                  && v16->moveType == SITH_MT_PHYSICS
                  && (v16->physicsParams.flags & (SITH_PF_WALLSTICK|SITH_PF_FLOORSTICK)))
                {
                    sithPhysics_FindFloor(v16, 1);
                }
            }
            if ( !sithWorld_ValidateWorld(pWorld) )
                return 0;
        }
        pWorld->level_type_maybe |= 2;
    }
    return 1;
}

// MOTS altered
void sithWorld_FreeEntry(SithWorld *pWorld)
{
    unsigned int v1; // edi
    int v2; // ebx

    SITH_ASSERTREL(pWorld); // Added: J3D assert

#ifdef DW_LASERS
    dwLaser_Free(pWorld); // Added: DroidWorks laser pool (binary @0x44d3d5; no-op off-desktop)
#endif

    if ( pWorld->colormaps )
    {
        v1 = 0;
        if ( pWorld->numColormaps )
        {
            v2 = 0;
            do
            {
                rdColormap_FreeEntry(&pWorld->colormaps[v2]);
                ++v1;
                ++v2;
            }
            while ( v1 < pWorld->numColormaps );
        }
        SITH_FREE(pWorld->colormaps);
        pWorld->colormaps = 0;
        pWorld->numColormaps = 0;
    }
    if ( pWorld->aThings )
        sithThing_FreeWorldThings(pWorld);
    if ( pWorld->aSectors )
        sithSector_FreeWorldSectors(pWorld);
    if ( pWorld->aModels )
        sithModel_FreeWorldModels(pWorld);
    if ( pWorld->aSprites )
        sithSprite_FreeWorldSprites(pWorld);
    if ( pWorld->aParticles )
        sithParticle_FreeWorldParticles(pWorld);
    if ( pWorld->aKeyframes )
        sithKeyFrame_Free(pWorld);
    if ( pWorld->aThingTemplates )
        sithTemplate_FreeWorldTemplates(pWorld);
    if ( pWorld->aVertices )
    {
        SITH_FREE(pWorld->aVertices);
        pWorld->aVertices = 0;
    }
    if ( pWorld->aTransformedVertices )
    {
        SITH_FREE(pWorld->aTransformedVertices);
        pWorld->aTransformedVertices = 0;
    }
    if ( pWorld->aVertDynamicLights )
    {
        SITH_FREE(pWorld->aVertDynamicLights);
        pWorld->aVertDynamicLights = 0;
    }
    if ( pWorld->alloc_unk9c )
    {
        SITH_FREE(pWorld->alloc_unk9c);
        pWorld->alloc_unk9c = 0;
    }
    if ( pWorld->aTexVerticies )
    {
        SITH_FREE(pWorld->aTexVerticies);
        pWorld->aTexVerticies = 0;
    }
    if ( pWorld->surfaces )
        sithSurface_FreeWorldSurfaces(pWorld);
    if ( pWorld->alloc_unk98 )
    {
        SITH_FREE(pWorld->alloc_unk98);
        pWorld->alloc_unk98 = 0;
    }
    if ( pWorld->aMaterials )
        sithMaterial_FreeWorldMaterials(pWorld);
    if ( pWorld->sounds )
        sithSound_FreeWorldSounds(pWorld);
    if ( pWorld->aCogs || pWorld->aCogScripts )
        sithCog_FreeWorldCogs(pWorld);
    if ( pWorld->aPuppetClasses )
        sithAnimClass_Free(pWorld);
    if ( pWorld->aAIClasses )
        sithAIClass_FreeWorldAIClasses(pWorld);
    if ( pWorld->aSoundClasses )
        sithSoundClass_FreeWorldSoundClasses(pWorld);

#ifdef JKM_LIGHTING
    // MOTS added
    if (pWorld->aArchlights) {
        sithArchLighting_Free(pWorld);
    }
#endif

    // Added: Fix UAF from previous world's viewmodel anims
    for (int i = 0; i < jkPlayer_maxPlayers; i++)
    {
        jkPlayerInfo* playerInfoJk = &playerThings[i];
        jkPlayer_SetPovModel(playerInfoJk, NULL);
    }

    // Added: Fix MoTS UAF
    for (int i = 0; i < 64; i++) {
        memset(&jkPlayer_aBubbleInfo[i], 0, sizeof(jkPlayer_aBubbleInfo[i]));
    }

    // Added: Kinda hacky, but static never gets unloaded.
    memset(pWorld, 0, sizeof(*pWorld));
    sithWorld_g_pCurrentWorld = 0;

    // Added (Droidworks): JK and MoTS memleaked the world alloc
    SITH_FREE(pWorld);
}

int sithWorld_ReadHeaderText(SithWorld *pWorld, int bSkip)
{
    flex32_t tmp;
    flex32_t tmp2;
    flex32_t tmp3;
    flex32_t tmp4;

    if ( bSkip )
        return 0;
    if ( !stdConffile_ReadLine() )
        return 0;
    if (_sscanf(stdConffile_g_aLine, "version %d", &bSkip) != 1) // MOTS added: check 1
        return 0;
    // MOTS added
    if (bSkip != 1) {
        //return 0;
    }
    if ( !stdConffile_ReadLine() )
        return 0;
    _sscanf(stdConffile_g_aLine, "world gravity %f", &tmp);
    pWorld->gravity = tmp; // FLEXTODO
    if ( !stdConffile_ReadLine() )
        return 0;
    _sscanf(stdConffile_g_aLine, "ceiling sky z %f", &tmp);
    pWorld->ceilingSkyHeight = tmp; // FLEXTODO
    if ( !stdConffile_ReadLine() )
        return 0;
    _sscanf(stdConffile_g_aLine, "horizon distance %f", &tmp);
    pWorld->horizonDistance = tmp; // FLEXTODO
    if ( !stdConffile_ReadLine() )
        return 0;
    _sscanf(stdConffile_g_aLine, "horizon pixels per rev %f", &tmp);
    pWorld->horizontalPixelsPerRev = tmp; // FLEXTODO
    if ( !stdConffile_ReadLine() )
        return 0;
    _sscanf(stdConffile_g_aLine, "horizon sky offset %f %f", &tmp, &tmp2);
    pWorld->horizonSkyOffset.x = tmp; // FLEXTODO
    pWorld->horizonSkyOffset.y = tmp2; // FLEXTODO
    if ( !stdConffile_ReadLine() )
        return 0;
    _sscanf(stdConffile_g_aLine, "ceiling sky offset %f %f", &tmp, &tmp2);
    pWorld->ceilingSkyOffset.x = tmp; // FLEXTODO
    pWorld->ceilingSkyOffset.y = tmp2; // FLEXTODO
    if ( !stdConffile_ReadLine() )
        return 0;
    _sscanf(
        stdConffile_g_aLine,
        "mipmap distances %f %f %f %f",
        &tmp,
        &tmp2,
        &tmp3,
        &tmp4);
    pWorld->mipmapDistance.x = tmp; // FLEXTODO
    pWorld->mipmapDistance.y = tmp2; // FLEXTODO
    pWorld->mipmapDistance.z = tmp3; // FLEXTODO
    pWorld->mipmapDistance.w = tmp4; // FLEXTODO
    if ( !stdConffile_ReadLine() )
        return 0;
    _sscanf(stdConffile_g_aLine, "lod distances %f %f %f %f", &tmp, &tmp2, &tmp3, &tmp4);
    pWorld->distancesLOD.x = tmp; // FLEXTODO
    pWorld->distancesLOD.y = tmp2; // FLEXTODO
    pWorld->distancesLOD.z = tmp3; // FLEXTODO
    pWorld->distancesLOD.w = tmp4; // FLEXTODO
    if ( !stdConffile_ReadLine() )
        return 0;
    _sscanf(stdConffile_g_aLine, "perspective distance %f", &tmp);
    pWorld->perspectiveDistance = tmp; // FLEXTODO
    if ( !stdConffile_ReadLine() )
        return 0;
    _sscanf(stdConffile_g_aLine, "gouraud distance %f", &tmp);
    pWorld->gouradDistance = tmp; // FLEXTODO

// Old-style mipmap/LOD removal
//#ifdef QOL_IMPROVEMENTS
#if 0
    pWorld->mipmapDistance.x = 200.0;
    pWorld->mipmapDistance.y = 200.0;
    pWorld->mipmapDistance.z = 200.0;
    pWorld->mipmapDistance.w = 200.0;
    pWorld->loadDistance.x = 200.0;
    pWorld->loadDistance.y = 200.0;
    pWorld->loadDistance.z = 200.0;
    pWorld->loadDistance.w = 200.0;
#endif

    return 1;
}

int sithWorld_ReadCopyrightText(SithWorld *pWorld, int bSkip)
{
    char *iter;

    if (bSkip)
        return 0;

    iter = jkl_read_copyright;
    do
    {
        if (!stdConffile_ReadLine())
            return 0;
        _memcpy(iter, stdConffile_g_aLine, 0x20);
        iter += 0x20;
    }
    while (iter < &jkl_read_copyright[0x440]);

    // QOL improvement: don't check copyright header.
#ifndef QOL_IMPROVEMENTS
    if (_memcmp(jkl_read_copyright, g_level_header, 0x440))
    {
        sithWorld_some_integer_4 = 0;
        return 0;
    }
#endif

    sithWorld_some_integer_4 = 1;
    return 1;
}

int sithWorld_RegisterTextSectionParser(char *aSectionName, sithWorldSectionParser_t pfParseFunction)
{
    int idx = sithWorld_GetTextSectionParserIndex(aSectionName);
    if (idx == -1)
    {
        if ( sithWorld_numParsers >= 32 )
            return 0;
        idx = sithWorld_numParsers++;
    }
    _strncpy(sithWorld_aSectionParsers[idx].section_name, aSectionName, 0x1Fu);
    sithWorld_aSectionParsers[idx].section_name[31] = 0;
    sithWorld_aSectionParsers[idx].funcptr = pfParseFunction;
    return 1;
}

int sithWorld_GetTextSectionParserIndex(char *aSectionName)
{
    if ( sithWorld_numParsers <= 0 )
        return -1;

    int i = 0;
    SithWorldTextSectionParseHandler *iter = sithWorld_aSectionParsers;
    while ( __strcmpi(iter->section_name, aSectionName) )
    {
        ++i;
        ++iter;
        if ( i >= sithWorld_numParsers )
            return -1;
    }
    return i;
}

int sithWorld_ValidateWorld(SithWorld *pWorld)
{
    if ( !pWorld->aThings && pWorld->numThingsLoaded )
    {
        stdPrintf(pSithHS->errorPrint, ".\\World\\sithWorld.c", 1245, "Problem with things array, should not be NULL.\n", 0, 0, 0, 0);
        return 0;
    }
    if ( !pWorld->aSprites && pWorld->numSprites )
    {
        stdPrintf(pSithHS->errorPrint, ".\\World\\sithWorld.c", 1251, "Problem with spriates array, should not be NULL.\n", 0, 0, 0, 0);
        return 0;
    }
    if ( !pWorld->aModels && pWorld->numModels )
    {
        stdPrintf(pSithHS->errorPrint, ".\\World\\sithWorld.c", 1257, "Problem with models array, should not be NULL.\n", 0, 0, 0, 0);
        return 0;
    }
    if ( !pWorld->aSectors || !pWorld->surfaces || !pWorld->aVertices )
    {
        stdPrintf(pSithHS->errorPrint, ".\\World\\sithWorld.c", 1263, "A required geometry section is missing from the level file.\n", 0, 0, 0, 0);
        return 0;
    }
    if ( sithSurface_ValidateWorldSurfaces(pWorld) )
        return 1;
    stdPrintf(pSithHS->errorPrint, ".\\World\\sithWorld.c", 1271, "Surface resources did not pass validation.\n", 0, 0, 0, 0);
    return 0;
}

// MOTS altered
uint32_t sithWorld_CalcWorldChecksum(SithWorld *pWorld, uint32_t seed)
{
    // Starting hash seed
    uint32_t hash = seed;

    // Hash all world pScript __VM bytecode__ (*not* text)
    for (int i = 0; i < pWorld->numCogScripts; i++)
    {
        hash = util_Weirdchecksum((uint8_t *)pWorld->aCogScripts[i].pCode, pWorld->aCogScripts[i].codeSize, hash);
    }

    // Hash all world aVertices
    hash = util_Weirdchecksum((uint8_t *)pWorld->aVertices, 12 * pWorld->numVertices, hash);

    // Hash all thing aThingTemplates
    for (int i = 0; i < pWorld->numThingTemplates; i++)
    {
        hash = sithThing_CalcThingChecksum(&pWorld->aThingTemplates[i], hash);
    }
    
    // Hash static COG __VM bytecode__ (*not* text)
    if (sithWorld_g_pStaticWorld )
    {
        for (int i = 0; i < sithWorld_g_pStaticWorld->numCogScripts; i++)
        {
            hash = util_Weirdchecksum((uint8_t *)sithWorld_g_pStaticWorld->aCogScripts[i].pCode, sithWorld_g_pStaticWorld->aCogScripts[i].codeSize, hash);
        }
    }

    if (Main_bMotsCompat && sithWorld_checksumExtraFunc) {
        hash = sithWorld_checksumExtraFunc(hash);
    }

    return hash;
}

int sithWorld_InitPlayers()
{
    for (int i = 1; i < jkPlayer_maxPlayers; i++)
    {
        sithPlayer_Startup(i);
    }
    sithPlayer_SetLocalPlayer(0);
    sithPlayer_ResetPalEffects();
    return 1;
}

int sithWorld_ReadGeoresourceText(SithWorld *pWorld, int bSkip)
{
    uint32_t numVertices;
    uint32_t textureVertices;
    uint32_t numColormaps; // [esp+14h] [ebp-9Ch] BYREF
    int v_idx;
    flex32_t v_x, v_y, v_z, v_u, v_v;
    char colormap_fname[128];

    if ( bSkip )
        return 0;

    if ( sithWorld_LoadPercentCallback )
        sithWorld_LoadPercentCallback(50.0);

    if (!stdConffile_ReadLine() )
    {
        return 0;
    }

    if ( _sscanf(stdConffile_g_aLine, " world colormaps %d", &numColormaps) != 1 )
    {
        return 0;
    }

    pWorld->numColormaps = numColormaps;
    pWorld->colormaps = (rdColormap *)SITH_ALLOC(sizeof(rdColormap) * numColormaps);
    memset(pWorld->colormaps, 0, sizeof(rdColormap) * numColormaps); // Added: prevent freeing issues on load failures
    
    if (!pWorld->colormaps)
    {
        return 0;
    }

    for (int i = 0; i < numColormaps; i++)
    {
        if (!stdConffile_ReadLine() )
        {
            return 0;
        }

        if ( _sscanf(stdConffile_g_aLine, " %d: %s", &v_idx, std_g_genBuffer) != 2 )
        {
            return 0;
        }
        
        stdString_snprintf(colormap_fname, sizeof(colormap_fname), "%s%c%s", "misc\\cmp", '\\', std_g_genBuffer); // Added: sprintf -> snprintf
        if ( !rdColormap_LoadEntry(colormap_fname, &pWorld->colormaps[i]) )
        {
            return 0;
        }
    }

    if (!stdConffile_ReadLine())
    {
        return 0;
    }

    if (_sscanf(stdConffile_g_aLine, " world vertices %d", &numVertices) != 1 )
    {
        return 0;
    }

#ifdef TARGET_TWL
    // Added: static world aVertices are parsed once (word stores) then read-only;
    // extram-safe on TWL. Per-frame arrays (transformed/dynamic light) stay in
    // sysram -- they are written every frame.
    int prevSuggest = pSithHS->suggestHeap(HEAP_WORD_ADDRESSABLE);
#endif
    pWorld->aVertices = (rdVector3 *)SITH_ALLOC(sizeof(rdVector3) * numVertices);
#ifdef TARGET_TWL
    pSithHS->suggestHeap(prevSuggest);
#endif
    if (!pWorld->aVertices)
    {
        return 0;
    }

    for (int i = 0; i < numVertices; i++)
    {
        if (!stdConffile_ReadLine())
        {
            return 0;
        }

        if (_sscanf(stdConffile_g_aLine, " %d: %f %f %f", &v_idx, &v_x, &v_y, &v_z) != 4 )
        {
            return 0;
        }

        pWorld->aVertices[i].x = v_x;
        pWorld->aVertices[i].y = v_y;
        pWorld->aVertices[i].z = v_z;
    }

    pWorld->numVertices = numVertices;
    if (!stdConffile_ReadLine())
    {
        return 0;
    }

    if (_sscanf(stdConffile_g_aLine, " world texture vertices %d", &textureVertices) != 1)
    {
        return 0;
    }

#ifdef TARGET_TWL
    int prevSuggestUV = pSithHS->suggestHeap(HEAP_WORD_ADDRESSABLE); // Added: see aVertices
#endif
    pWorld->aTexVerticies = (rdVector2 *)SITH_ALLOC(sizeof(rdVector2) * textureVertices);
#ifdef TARGET_TWL
    pSithHS->suggestHeap(prevSuggestUV);
#endif
    if (!pWorld->aTexVerticies)
    {
        return 0;
    }

    for (int i = 0; i < textureVertices; i++) {
        if (!stdConffile_ReadLine()) {
            return 0;
        }
        if (_sscanf(stdConffile_g_aLine, " %d: %f %f", &v_idx, &v_u, &v_v) != 3) {
            return 0;
        }

        pWorld->aTexVerticies[i].x = v_u;
        pWorld->aTexVerticies[i].y = v_v;
    }

    return sithSurface_ReadSurfacesListText(pWorld) != 0;
}

void sithWorld_ResetRenderState(SithWorld *pWorld)
{
    SITH_ASSERTREL((pWorld != NULL)); // Added: J3D assert
    SITH_ASSERTREL((pWorld->aSectors != NULL)); // Added: J3D assert

    _memset(pWorld->alloc_unk98, 0, sizeof(int) * pWorld->numVertices);
    _memset(pWorld->alloc_unk9c, 0, sizeof(int) * pWorld->numVertices);

    for (int i = 0; i < pWorld->numSectors; i++)
    {
        SithSector* sector = &pWorld->aSectors[i];
        
        for (int j = 0; j < pWorld->aSectors[i].numSurfaces; j++)
        {
            SithSurface* surface = &pWorld->aSectors[i].surfaces[j];
            surface->field_4 = 0;
        }
        sector->renderTick = 0;
    }
}

void sithWorld_Free()
{
    if ( sithWorld_bLoaded )
    {
        sithWorld_FreeEntry(sithWorld_g_pCurrentWorld);
        sithWorld_g_pCurrentWorld = 0;
        sithWorld_bLoaded = 0;
    }
}

void sithWorld_ResetGeoresource(SithWorld *pWorld)
{
    SITH_ASSERTREL(pWorld); // Added: J3D assert

    for (int i = 0; i < pWorld->numMaterials; i++)
    {
        pWorld->aMaterials[i].curCelNum = 0;;
    }

    for (int i = 0; i < pWorld->numSectors; i++)
    {
        rdVector_Zero3(&pWorld->aSectors[i].thrust);
        rdVector_Zero3(&pWorld->aSectors[i].tint);
    }
    sithPlayer_ResetPalEffects();
}

// MOTS altered
void sithWorld_GetMemoryUsage(SithWorld *pWorld, int *aMemUsed, int *aCount)
{
    SITH_ASSERTREL(aMemUsed && aCount); // Added: J3D assert
    SITH_ASSERTREL(pWorld); // Added: J3D assert

    _memset(aMemUsed, 0, sizeof(int) * 0x11);
    _memset(aCount, 0, sizeof(int) * 0x11);
    aCount[0] = pWorld->numMaterials;
    for (int i = 0; i < pWorld->numMaterials; i++)
    {
        aMemUsed[0] += sithMaterial_GetMemorySize(&pWorld->aMaterials[i]);
    }
    aCount[1] = pWorld->numVertices;
    aMemUsed[1] = 0x34 * pWorld->numVertices;               // TODO: what is this size?
    aCount[2] = pWorld->numTexVertices;
    aMemUsed[2] = sizeof(rdVector2) * pWorld->numTexVertices;
    aCount[3] = pWorld->numSurfaces;
    for (int i = 0; i < pWorld->numSurfaces; i++)
    {
        aMemUsed[3] += sizeof(rdVector3) * pWorld->surfaces[i].surfaceInfo.face.numVertices + sizeof(SithSurface);
    }
    aCount[4] = pWorld->numAdjoinsLoaded;
    aMemUsed[4] = sizeof(SithSurfaceAdjoin) * pWorld->numAdjoinsLoaded;
    aCount[5] = pWorld->numSectors;
    for (int i = 0; i < pWorld->numSectors; i++)
    {
        aMemUsed[5] += sizeof(flex_t) * pWorld->aSectors[i].numVertices + sizeof(SithSector); // TODO bug?
    }
    aCount[6] = pWorld->numSoundsLoaded;
    for (int i = 0; i < pWorld->numSoundsLoaded; i++)
    {
        aMemUsed[6] += pWorld->sounds[i].bufferBytes + sizeof(sithSound);
    }
    aCount[8] = pWorld->numCogScripts;
    for (int i = 0; i < pWorld->numCogScripts; i++)
    {
        aMemUsed[8] += 4 * (7 * pWorld->aCogScripts[i].pSymbolTable->numUsedSymbols + pWorld->aCogScripts[i].numSymbolRefs) + 0x1DD0; // TODO verify struct sizes here...
    }
    aCount[7] = pWorld->numCogs;
    for (int i = 0; i < pWorld->numCogs; i++)
    {
        aMemUsed[7] += 28 * pWorld->aCogs[i].pSymbolTable->numUsedSymbols + 0x14DC; // TODO verify struct sizes
    }
    aCount[10] = pWorld->numModels;
    for (int i = 0; i < pWorld->numModels; i++)
    {
        aMemUsed[10] += sithModel_GetModelMemUsage(&pWorld->aModels[i]);
    }
    aCount[11] = pWorld->numKeyframes;
    for (int i = 0; i < pWorld->numKeyframes; i++)
    {
        aMemUsed[11] += sizeof(rdJoint) * (pWorld->aKeyframes[i].numJoints2 + 3);
        for (int j = 0; j < pWorld->aKeyframes[i].numJoints2; j++)
        {
            aMemUsed[11] += sizeof(rdAnimEntry) * pWorld->aKeyframes[i].aNodes[j].numEntries;
        }
    }
    aCount[12] = pWorld->numPuppetClasses;
    aMemUsed[12] = sizeof(SithPuppetClass) * pWorld->numPuppetClasses;
    aCount[13] = pWorld->numSprites;
    aMemUsed[13] = sizeof(rdSprite) * pWorld->numSprites;
    for (int i = 0; i < pWorld->numSprites; i++)
    {
        aMemUsed[13] += sizeof(rdTri) * pWorld->aSprites[i].face.numVertices;
    }
    aCount[14] = pWorld->numThingTemplates;
    aCount[15] = pWorld->numThingsLoaded;
    aMemUsed[14] = sizeof(SithThing) * pWorld->numThingTemplates;
    aMemUsed[15] = sizeof(SithThing) * pWorld->numThingsLoaded;
}


void sithWorld_SetChecksumExtraFunc(sithWorld_ChecksumHandler_t handler)
{
    sithWorld_checksumExtraFunc = handler;
}