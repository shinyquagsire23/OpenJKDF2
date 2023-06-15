#include "sithWorld.h"

#include "General/stdConffile.h"
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
#include "jk.h"

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
#ifdef JKM_LIGHTING
    sithWorld_SetSectionParser("archlighting", sithArchLighting_ParseSection); // MOTS added
#endif
    sithWorld_bInitted = 1;
    return 1;
}

void sithWorld_Shutdown()
{
    if ( sithWorld_pCurrentWorld )
        pSithHS->free(sithWorld_pCurrentWorld);
    if ( sithWorld_pStatic ) {
        //pSithHS->free(sithWorld_pStatic); // Added: Actually free everything
        sithWorld_FreeEntry(sithWorld_pStatic); // Added: Actually free everything
    }
    sithWorld_pCurrentWorld = 0;
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

int sithWorld_Load(sithWorld *pWorld, char *map_jkl_fname)
{
    int result; // eax
    int v3; // esi
    sithWorldParser *parser; // edi
    int startMsecs; // edi
    __int64 v6; // [esp+1Ch] [ebp-120h]
    char section[32]; // [esp+24h] [ebp-118h] BYREF
    char v8[128]; // [esp+44h] [ebp-F8h] BYREF
    char tmp[120]; // [esp+C4h] [ebp-78h] BYREF

    if ( !pWorld )
        return 0;
#ifdef SDL2_RENDER
    std3D_PurgeTextureCache();
#endif

    if ( map_jkl_fname )
    {
        // aaaaaa these sizes are wrong
        // Added: actually use correct lengths
        _strncpy(pWorld->map_jkl_fname, map_jkl_fname, 0x1F);
        pWorld->map_jkl_fname[31] = 0; 
        _strtolower(pWorld->map_jkl_fname);
        _strncpy(pWorld->episodeName, sithWorld_episodeName, 0x1Fu);
        pWorld->episodeName[0x1F] = 0;
        sithWorld_pLoading = pWorld;
        stdFnames_MakePath(v8, 128, "jkl", map_jkl_fname);
        sithWorld_some_integer_4 = 0;
        if ( !stdConffile_OpenRead(v8) )
        {
            goto parse_problem;
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
                        _sprintf(tmp, "%f seconds to parse section %s -- FAILED!\n", (double)v6 * 0.001, section);
                        sithConsole_Print(tmp);
                        goto LABEL_19;
                    }
                    v6 = (unsigned int)(stdPlatform_GetTimeMsec() - startMsecs);
                    _sprintf(tmp, "%f seconds to parse section %s.\n", (double)v6 * 0.001, section);
                    sithConsole_Print(tmp);
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

    if ( sithWorld_NewEntry(pWorld) )
    {
#ifdef SDL2_RENDER
        std3D_UpdateSettings();
#endif
        sithWorld_bLoaded = 1;
        return 1;
    }
    goto cleanup;

parse_problem:
    stdPrintf(pSithHS->errorPrint, ".\\World\\sithWorld.c", 276, "Parse problem in file '%s'.\n", v8);
cleanup:
    sithWorld_FreeEntry(pWorld);
    return 0;
}

sithWorld* sithWorld_New()
{
    sithWorld *result; // eax

    result = (sithWorld *)pSithHS->alloc(sizeof(sithWorld));
    if ( result )
        _memset(result, 0, sizeof(sithWorld));
    return result;
}

int sithWorld_NewEntry(sithWorld *pWorld)
{
    sithAdjoin *v1; // ebp
    sithSector *v2; // ebx
    int v3; // eax
    rdVector3 *v4; // eax
    float *v5; // edi
    int *v6; // edi
    int *v7; // edi
    sithSector **v8; // edx
    int v9; // edi
    sithAdjoin *adjoinIter; // eax
    sithAdjoin *adjoinIterMirror; // ecx
    sithSector *v12; // ecx
    sithThing *v15; // edx
    sithThing *v16; // eax

    v1 = 0;
    v2 = 0;
    if ( (pWorld->level_type_maybe & 2) == 0 )
    {
        v3 = pWorld->numVertices;
        if ( v3 )
        {
            v4 = (rdVector3 *)pSithHS->alloc(sizeof(rdVector3) * v3);
            pWorld->verticesTransformed = v4;
            if ( !v4 )
                return 0;

            v5 = (float *)pSithHS->alloc(sizeof(float) * pWorld->numVertices);
            pWorld->verticesDynamicLight = v5;
            if ( !v5 )
                return 0;
            _memset(v5, 0, sizeof(float) * pWorld->numVertices);

            v6 = (int *)pSithHS->alloc(sizeof(int) * pWorld->numVertices);
            pWorld->alloc_unk98 = v6;
            if ( !v6 )
                return 0;
            _memset(v6, 0, sizeof(int) * pWorld->numVertices);

            v7 = (int *)pSithHS->alloc(sizeof(int) * pWorld->numVertices);
            pWorld->alloc_unk9c = v7;
            if ( !v7 )
                return 0;
            _memset(v7, 0, sizeof(int) * pWorld->numVertices);
            for (int i = 0; i < pWorld->numSurfaces; i++)
            {
                adjoinIter = pWorld->surfaces[i].adjoin;
                if ( adjoinIter )
                {
                    adjoinIterMirror = adjoinIter->mirror;
                    if ( adjoinIterMirror )
                        adjoinIter->sector = adjoinIterMirror->surface->parent_sector;
                    if ( v1 && (v12 = pWorld->surfaces[i].parent_sector, v2 == pWorld->surfaces[i].parent_sector) )
                    {
                        v1->next = adjoinIter;
                    }
                    else
                    {
                        v12 = pWorld->surfaces[i].parent_sector;
                        pWorld->surfaces[i].parent_sector->adjoins = adjoinIter;
                    }
                    v1 = adjoinIter;
                    v2 = v12;
                }
            }
            sithPlayer_NewEntry(pWorld);
            for (int i = 0; i < pWorld->numThingsLoaded; i++)
            {
                v16 = &pWorld->things[i];
                if ( v16->type
                  && v16->moveType == SITH_MT_PHYSICS
                  && (v16->physicsParams.physflags & (SITH_PF_WALLSTICK|SITH_PF_FLOORSTICK)))
                {
                    sithPhysics_FindFloor(v16, 1);
                }
            }
            if ( !sithWorld_Verify(pWorld) )
                return 0;
        }
        pWorld->level_type_maybe |= 2;
    }
    return 1;
}

// MOTS altered
void sithWorld_FreeEntry(sithWorld *pWorld)
{
    unsigned int v1; // edi
    int v2; // ebx

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
        pSithHS->free(pWorld->colormaps);
        pWorld->colormaps = 0;
        pWorld->numColormaps = 0;
    }
    if ( pWorld->things )
        sithThing_Free(pWorld);
    if ( pWorld->sectors )
        sithSector_Free(pWorld);
    if ( pWorld->models )
        sithModel_Free(pWorld);
    if ( pWorld->sprites )
        sithSprite_FreeEntry(pWorld);
    if ( pWorld->particles )
        sithParticle_Free(pWorld);
    if ( pWorld->keyframes )
        sithKeyFrame_Free(pWorld);
    if ( pWorld->templates )
        sithTemplate_FreeWorld(pWorld);
    if ( pWorld->vertices )
    {
        pSithHS->free(pWorld->vertices);
        pWorld->vertices = 0;
    }
    if ( pWorld->verticesTransformed )
    {
        pSithHS->free(pWorld->verticesTransformed);
        pWorld->verticesTransformed = 0;
    }
    if ( pWorld->verticesDynamicLight )
    {
        pSithHS->free(pWorld->verticesDynamicLight);
        pWorld->verticesDynamicLight = 0;
    }
    if ( pWorld->alloc_unk9c )
    {
        pSithHS->free(pWorld->alloc_unk9c);
        pWorld->alloc_unk9c = 0;
    }
    if ( pWorld->vertexUVs )
    {
        pSithHS->free(pWorld->vertexUVs);
        pWorld->vertexUVs = 0;
    }
    if ( pWorld->surfaces )
        sithSurface_Free(pWorld);
    if ( pWorld->alloc_unk98 )
    {
        pSithHS->free(pWorld->alloc_unk98);
        pWorld->alloc_unk98 = 0;
    }
    if ( pWorld->materials )
        sithMaterial_Free(pWorld);
    if ( pWorld->sounds )
        sithSound_Free(pWorld);
    if ( pWorld->cogs || pWorld->cogScripts )
        sithCog_Free(pWorld);
    if ( pWorld->animclasses )
        sithAnimClass_Free(pWorld);
    if ( pWorld->aiclasses )
        sithAIClass_Free(pWorld);
    if ( pWorld->soundclasses )
        sithSoundClass_Free2(pWorld);

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
    sithWorld_pCurrentWorld = 0;

    // Added (Droidworks): JK and MoTS memleaked the world alloc
    pSithHS->free(pWorld);
}

int sithHeader_Load(sithWorld *pWorld, int junk)
{
    if ( junk )
        return 0;
    if ( !stdConffile_ReadLine() )
        return 0;
    if (_sscanf(stdConffile_aLine, "version %d", &junk) != 1) // MOTS added: check 1
        return 0;
    // MOTS added
    if (junk != 1) {
        //return 0;
    }
    if ( !stdConffile_ReadLine() )
        return 0;
    _sscanf(stdConffile_aLine, "world gravity %f", &pWorld->worldGravity);
    if ( !stdConffile_ReadLine() )
        return 0;
    _sscanf(stdConffile_aLine, "ceiling sky z %f", &pWorld->ceilingSky);
    if ( !stdConffile_ReadLine() )
        return 0;
    _sscanf(stdConffile_aLine, "horizon distance %f", &pWorld->horizontalDistance);
    if ( !stdConffile_ReadLine() )
        return 0;
    _sscanf(stdConffile_aLine, "horizon pixels per rev %f", &pWorld->horizontalPixelsPerRev);
    if ( !stdConffile_ReadLine() )
        return 0;
    _sscanf(stdConffile_aLine, "horizon sky offset %f %f", &pWorld->horizontalSkyOffs, &pWorld->horizontalSkyOffs.y);
    if ( !stdConffile_ReadLine() )
        return 0;
    _sscanf(stdConffile_aLine, "ceiling sky offset %f %f", &pWorld->ceilingSkyOffs, &pWorld->ceilingSkyOffs.y);
    if ( !stdConffile_ReadLine() )
        return 0;
    _sscanf(
        stdConffile_aLine,
        "mipmap distances %f %f %f %f",
        &pWorld->mipmapDistance.x,
        &pWorld->mipmapDistance.y,
        &pWorld->mipmapDistance.z,
        &pWorld->mipmapDistance.w);
    if ( !stdConffile_ReadLine() )
        return 0;
    _sscanf(stdConffile_aLine, "lod distances %f %f %f %f", &pWorld->lodDistance.x, &pWorld->lodDistance.y, &pWorld->lodDistance.z, &pWorld->lodDistance.w);
    if ( !stdConffile_ReadLine() )
        return 0;
    _sscanf(stdConffile_aLine, "perspective distance %f", &pWorld->perspectiveDistance);
    if ( !stdConffile_ReadLine() )
        return 0;
    _sscanf(stdConffile_aLine, "gouraud distance %f", &pWorld->gouradDistance);

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

int sithWorld_SetSectionParser(char *section_name, sithWorldSectionParser_t funcptr)
{
    int idx = sithWorld_FindSectionParser(section_name);
    if (idx == -1)
    {
        if ( sithWorld_numParsers >= 32 )
            return 0;
        idx = sithWorld_numParsers++;
    }
    _strncpy(sithWorld_aSectionParsers[idx].section_name, section_name, 0x1Fu);
    sithWorld_aSectionParsers[idx].section_name[31] = 0;
    sithWorld_aSectionParsers[idx].funcptr = funcptr;
    return 1;
}

int sithWorld_FindSectionParser(char *a1)
{
    if ( sithWorld_numParsers <= 0 )
        return -1;

    int i = 0;
    sithWorldParser *iter = sithWorld_aSectionParsers;
    while ( __strcmpi(iter->section_name, a1) )
    {
        ++i;
        ++iter;
        if ( i >= sithWorld_numParsers )
            return -1;
    }
    return i;
}

int sithWorld_Verify(sithWorld *pWorld)
{
    if ( !pWorld->things && pWorld->numThingsLoaded )
    {
        stdPrintf(pSithHS->errorPrint, ".\\World\\sithWorld.c", 1245, "Problem with things array, should not be NULL.\n", 0, 0, 0, 0);
        return 0;
    }
    if ( !pWorld->sprites && pWorld->numSpritesLoaded )
    {
        stdPrintf(pSithHS->errorPrint, ".\\World\\sithWorld.c", 1251, "Problem with spriates array, should not be NULL.\n", 0, 0, 0, 0);
        return 0;
    }
    if ( !pWorld->models && pWorld->numModelsLoaded )
    {
        stdPrintf(pSithHS->errorPrint, ".\\World\\sithWorld.c", 1257, "Problem with models array, should not be NULL.\n", 0, 0, 0, 0);
        return 0;
    }
    if ( !pWorld->sectors || !pWorld->surfaces || !pWorld->vertices )
    {
        stdPrintf(pSithHS->errorPrint, ".\\World\\sithWorld.c", 1263, "A required geometry section is missing from the level file.\n", 0, 0, 0, 0);
        return 0;
    }
    if ( sithSurface_Verify(pWorld) )
        return 1;
    stdPrintf(pSithHS->errorPrint, ".\\World\\sithWorld.c", 1271, "Surface resources did not pass validation.\n", 0, 0, 0, 0);
    return 0;
}

// MOTS altered
uint32_t sithWorld_CalcChecksum(sithWorld *pWorld, uint32_t seed)
{
    // Starting hash seed
    uint32_t hash = seed;

    // Hash all world cogscript __VM bytecode__ (*not* text)
    for (int i = 0; i < pWorld->numCogScriptsLoaded; i++)
    {
        hash = util_Weirdchecksum((uint8_t *)pWorld->cogScripts[i].script_program, pWorld->cogScripts[i].codeSize, hash);
    }

    // Hash all world vertices
    hash = util_Weirdchecksum((uint8_t *)pWorld->vertices, 12 * pWorld->numVertices, hash);

    // Hash all thing templates
    for (int i = 0; i < pWorld->numTemplatesLoaded; i++)
    {
        hash = sithThing_Checksum(&pWorld->templates[i], hash);
    }
    
    // Hash static COG __VM bytecode__ (*not* text)
    if (sithWorld_pStatic )
    {
        for (int i = 0; i < sithWorld_pStatic->numCogScriptsLoaded; i++)
        {
            hash = util_Weirdchecksum((uint8_t *)sithWorld_pStatic->cogScripts[i].script_program, sithWorld_pStatic->cogScripts[i].codeSize, hash);
        }
    }

    if (Main_bMotsCompat && sithWorld_checksumExtraFunc) {
        hash = sithWorld_checksumExtraFunc(hash);
    }

    return hash;
}

int sithWorld_Initialize()
{
    for (int i = 1; i < jkPlayer_maxPlayers; i++)
    {
        sithPlayer_Startup(i);
    }
    sithPlayer_idk(0);
    sithPlayer_ResetPalEffects();
    return 1;
}

int sithWorld_LoadGeoresource(sithWorld *pWorld, int a2)
{
    rdVector3 *vertices; // eax
    rdVector3 *vertex; // esi
    rdVector2 *vertices_uvs; // eax
    rdVector2 *vertex_uvs; // esi
    int v14; // eax
    int v15; // edi
    unsigned int num_vertices; // [esp+Ch] [ebp-A4h] BYREF
    unsigned int num_vertices_uvs; // [esp+10h] [ebp-A0h] BYREF
    unsigned int numColormaps; // [esp+14h] [ebp-9Ch] BYREF
    int v_idx; // [esp+18h] [ebp-98h] BYREF
    float v_x; // [esp+1Ch] [ebp-94h] BYREF
    float v21; // [esp+20h] [ebp-90h] BYREF
    float v_y; // [esp+24h] [ebp-8Ch] BYREF
    float v23; // [esp+28h] [ebp-88h] BYREF
    float v_z; // [esp+2Ch] [ebp-84h] BYREF
    char colormap_fname[128]; // [esp+30h] [ebp-80h] BYREF

    if ( a2 )
        return 0;

    if ( sithWorld_LoadPercentCallback )
        sithWorld_LoadPercentCallback(50.0);

    if (!stdConffile_ReadLine() )
    {
        return 0;
    }

    if ( _sscanf(stdConffile_aLine, " world colormaps %d", &numColormaps) != 1 )
    {
        return 0;
    }

    pWorld->numColormaps = numColormaps;
    pWorld->colormaps = (rdColormap *)pSithHS->alloc(sizeof(rdColormap) * numColormaps);
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

        if ( _sscanf(stdConffile_aLine, " %d: %s", &v_idx, std_genBuffer) != 2 )
        {
            return 0;
        }
        _sprintf(colormap_fname, "%s%c%s", "misc\\cmp", '\\', std_genBuffer);
        if ( !rdColormap_LoadEntry(colormap_fname, &pWorld->colormaps[i]) )
        {
            return 0;
        }
    }

    if (!stdConffile_ReadLine())
    {
        return 0;
    }

    if (_sscanf(stdConffile_aLine, " world vertices %d", &num_vertices) != 1 )
    {
        return 0;
    }

    vertices = (rdVector3 *)pSithHS->alloc(sizeof(rdVector3) * num_vertices);
    pWorld->vertices = vertices;
    if (!vertices)
    {
        return 0;
    }

    vertex = vertices;
    for (int i = 0; i < num_vertices; i++)
    {
        if (!stdConffile_ReadLine())
        {
            return 0;
        }

        if (_sscanf(stdConffile_aLine, " %d: %f %f %f", &v_idx, &v_x, &v_y, &v_z) != 4 )
        {
            return 0;
        }

        vertex->x = v_x;
        vertex->y = v_y;
        vertex->z = v_z;
        ++vertex;
    }

    pWorld->numVertices = num_vertices;
    if (!stdConffile_ReadLine())
    {
        return 0;
    }

    if (_sscanf(stdConffile_aLine, " world texture vertices %d", &num_vertices_uvs) != 1)
    {
        return 0;
    }

    pWorld->vertexUVs = (rdVector2 *)pSithHS->alloc(sizeof(rdVector2) * num_vertices_uvs);
    if (!pWorld->vertexUVs)
    {
        return 0;
    }

    vertex_uvs = pWorld->vertexUVs;
    v14 = num_vertices_uvs;
    v15 = 0;
    if ( !num_vertices_uvs )
    {
LABEL_28:
        pWorld->numVertexUVs = v14;
        return sithSurface_Load(pWorld) != 0;
    }
    while ( stdConffile_ReadLine() && _sscanf(stdConffile_aLine, " %d: %f %f", &v_idx, &v21, &v23) == 3 )
    {
        vertex_uvs->x = v21;
        vertex_uvs->y = v23;
        v14 = num_vertices_uvs;
        ++vertex_uvs;
        if ( ++v15 >= num_vertices_uvs )
            goto LABEL_28;
    }

    return 0;
}

void sithWorld_sub_4D0A20(sithWorld *pWorld)
{
    _memset(pWorld->alloc_unk98, 0, 4 * pWorld->numVertices);
    _memset(pWorld->alloc_unk9c, 0, 4 * pWorld->numVertices);

    for (int i = 0; i < pWorld->numSectors; i++)
    {
        sithSector* sector = &pWorld->sectors[i];
        
        for (int j = 0; j < pWorld->sectors[i].numSurfaces; j++)
        {
            sithSurface* surface = &pWorld->sectors[i].surfaces[j];
            surface->field_4 = 0;
        }
        sector->renderTick = 0;
    }
}

void sithWorld_Free()
{
    if ( sithWorld_bLoaded )
    {
        sithWorld_FreeEntry(sithWorld_pCurrentWorld);
        sithWorld_pCurrentWorld = 0;
        sithWorld_bLoaded = 0;
    }
}

void sithWorld_ResetSectorRuntimeAlteredVars(sithWorld *pWorld)
{
    for (int i = 0; i < pWorld->numMaterialsLoaded; i++)
    {
        pWorld->materials[i].celIdx = 0;;
    }

    for (int i = 0; i < pWorld->numSectors; i++)
    {
        rdVector_Zero3(&pWorld->sectors[i].thrust);
        rdVector_Zero3(&pWorld->sectors[i].tint);
    }
    sithPlayer_ResetPalEffects();
}

// MOTS altered
void sithWorld_GetMemorySize(sithWorld *pWorld, int *outAllocated, int *outQuantity)
{
    _memset(outAllocated, 0, sizeof(int) * 0x11);
    _memset(outQuantity, 0, sizeof(int) * 0x11);
    outQuantity[0] = pWorld->numMaterialsLoaded;
    for (int i = 0; i < pWorld->numMaterialsLoaded; i++)
    {
        outAllocated[0] += sithMaterial_GetMemorySize(&pWorld->materials[i]);
    }
    outQuantity[1] = pWorld->numVertices;
    outAllocated[1] = 0x34 * pWorld->numVertices;               // TODO: what is this size?
    outQuantity[2] = pWorld->numVertexUVs;
    outAllocated[2] = sizeof(rdVector2) * pWorld->numVertexUVs;
    outQuantity[3] = pWorld->numSurfaces;
    for (int i = 0; i < pWorld->numSurfaces; i++)
    {
        outAllocated[3] += sizeof(rdVector3) * pWorld->surfaces[i].surfaceInfo.face.numVertices + sizeof(sithSurface);
    }
    outQuantity[4] = pWorld->numAdjoinsLoaded;
    outAllocated[4] = sizeof(sithAdjoin) * pWorld->numAdjoinsLoaded;
    outQuantity[5] = pWorld->numSectors;
    for (int i = 0; i < pWorld->numSectors; i++)
    {
        outAllocated[5] += 4 * pWorld->sectors[i].numVertices + sizeof(sithSector); // TODO bug?
    }
    outQuantity[6] = pWorld->numSoundsLoaded;
    for (int i = 0; i < pWorld->numSoundsLoaded; i++)
    {
        outAllocated[6] += pWorld->sounds[i].bufferBytes + sizeof(sithSound);
    }
    outQuantity[8] = pWorld->numCogScriptsLoaded;
    for (int i = 0; i < pWorld->numCogScriptsLoaded; i++)
    {
        outAllocated[8] += 4 * (7 * pWorld->cogScripts[i].pSymbolTable->entry_cnt + pWorld->cogScripts[i].numIdk) + 0x1DD0; // TODO verify struct sizes here...
    }
    outQuantity[7] = pWorld->numCogsLoaded;
    for (int i = 0; i < pWorld->numCogsLoaded; i++)
    {
        outAllocated[7] += 28 * pWorld->cogs[i].pSymbolTable->entry_cnt + 0x14DC; // TODO verify struct sizes
    }
    outQuantity[10] = pWorld->numModelsLoaded;
    for (int i = 0; i < pWorld->numModelsLoaded; i++)
    {
        outAllocated[10] += sithModel_GetMemorySize(&pWorld->models[i]);
    }
    outQuantity[11] = pWorld->numKeyframesLoaded;
    for (int i = 0; i < pWorld->numKeyframesLoaded; i++)
    {
        outAllocated[11] += sizeof(rdJoint) * (pWorld->keyframes[i].numJoints2 + 3);
        for (int j = 0; j < pWorld->keyframes[i].numJoints2; j++)
        {
            outAllocated[11] += sizeof(rdAnimEntry) * pWorld->keyframes[i].paJoints[j].numAnimEntries;
        }
    }
    outQuantity[12] = pWorld->numAnimClassesLoaded;
    outAllocated[12] = sizeof(sithAnimclass) * pWorld->numAnimClassesLoaded;
    outQuantity[13] = pWorld->numSpritesLoaded;
    outAllocated[13] = sizeof(rdSprite) * pWorld->numSpritesLoaded;
    for (int i = 0; i < pWorld->numSpritesLoaded; i++)
    {
        outAllocated[13] += sizeof(rdTri) * pWorld->sprites[i].face.numVertices;
    }
    outQuantity[14] = pWorld->numTemplatesLoaded;
    outQuantity[15] = pWorld->numThingsLoaded;
    outAllocated[14] = sizeof(sithThing) * pWorld->numTemplatesLoaded;
    outAllocated[15] = sizeof(sithThing) * pWorld->numThingsLoaded;
}


void sithWorld_SetChecksumExtraFunc(sithWorld_ChecksumHandler_t handler)
{
    sithWorld_checksumExtraFunc = handler;
}