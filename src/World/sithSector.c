#include "sithSector.h"

#include "stdPlatform.h" // Added: *_ALLOC/*_FREE macros

#include "General/stdMath.h"
#include "Primitives/rdMath.h"
#include "Raster/rdFace.h"
#include "World/sithThing.h"
#include "World/jkPlayer.h"
#include "World/sithWorld.h"
#include "Engine/sithCollision.h"
#include "Engine/sithIntersect.h"
#include "jk.h"
#include "Gameplay/sithEvent.h"
#include "Engine/rdColormap.h"
#include "Engine/sithCamera.h"
#include "Devices/sithSound.h"
#include "Devices/sithSoundMixer.h"
#include "Engine/sithRender.h"
#include "Raster/rdCache.h"
#include "Engine/sithPuppet.h"
#include "Engine/sithKeyFrame.h"
#include "World/sithMaterial.h"
#include "World/sithSurface.h"
#include "AI/sithAI.h"
#include "AI/sithAIClass.h"
#include "Dss/sithDSS.h"

// MOTS altered
int sithSector_ReadSectorsListText(SithWorld *pWorld, int bSkip)
{
    unsigned int alloc_size; // ebx
    SithSector *v6; // eax
    unsigned int v7; // ecx
    SithSector *aSectors; // esi
    int v13; // edi
    unsigned int v15; // eax
    void *v16; // ecx
    int junk; // [esp+10h] [ebp-3Ch] BYREF
    unsigned int num_vertices; // [esp+14h] [ebp-38h] BYREF
    unsigned int amount_2; // [esp+18h] [ebp-34h] BYREF
    unsigned int sectors_amt; // [esp+1Ch] [ebp-30h] BYREF
    int v21; // [esp+20h] [ebp-2Ch]
    int vtx_idx; // [esp+24h] [ebp-28h] BYREF
    int amount_1; // [esp+28h] [ebp-24h] BYREF
    char sound_fname[32]; // [esp+2Ch] [ebp-20h] BYREF
    flex32_t tmpf1;
    flex32_t tmpf2;
    flex32_t tmpf3;
    flex32_t tmpf4;
    flex32_t tmpf5;
    flex32_t tmpf6;

    if ( bSkip )
        return 0;
    if ( !stdConffile_ReadLine() || _sscanf(stdConffile_g_aLine, " world sectors %d", &sectors_amt) != 1 )
        return 0;

#ifdef STDPLATFORM_HEAP_SUGGESTIONS
    int prevSuggest = pSithHS->suggestHeap(HEAP_FAST);
#endif
    alloc_size = sizeof(SithSector) * sectors_amt;
    { TWL_EXTRAM_SUGGEST(pSithHS); // Added: word-width fields/writes (audited)
    pWorld->aSectors = (SithSector *)SITH_ALLOC(sizeof(SithSector) * sectors_amt);
    TWL_EXTRAM_RESTORE(pSithHS); }
#ifdef STDPLATFORM_HEAP_SUGGESTIONS
    pSithHS->suggestHeap(prevSuggest);
#endif
    if ( pWorld->aSectors )
    {
        stdPlatform_Memzero32(pWorld->aSectors, alloc_size); // Added: word-safe
        v6 = pWorld->aSectors;
        v7 = 0;
        for ( pWorld->numSectors = sectors_amt; v7 < sectors_amt; ++v7 )
        {
            v6->id = v7;
            v6->numVertices = 0;
            v6->aVertIdxs = 0;
            v6->numSurfaces = 0;
            v6->surfaces = 0;
            v6->pFirstThingInSector = 0;
            ++v6;
        }
    }
    aSectors = pWorld->aSectors;
    if ( !aSectors )
        return 0;
    v21 = 0;
    if ( sectors_amt )
    {
        while ( stdConffile_ReadLine() )
        {
            if ( _sscanf(stdConffile_g_aLine, " sector %d", &junk) != 1 )
                break;
            if ( !stdConffile_ReadLine() )
                break;
            if ( _sscanf(stdConffile_g_aLine, " flags %x", &aSectors->flags) != 1 )
                break;
            if ( !stdConffile_ReadLine() )
                break;
            if ( _sscanf(stdConffile_g_aLine, " ambient light %f", &tmpf1) != 1 )
                break;
            aSectors->ambientLight = tmpf1; // FLEXTODO
            if ( !stdConffile_ReadLine() )
                break;
            if ( _sscanf(stdConffile_g_aLine, " extra light %f", &tmpf1) != 1 )
                break;
            aSectors->extraLight = tmpf1; // FLEXTODO
            if ( !stdConffile_ReadLine() )
                break;
            if ( _sscanf(stdConffile_g_aLine, " colormap %d", &bSkip) != 1 )
                break;
            aSectors->colormap = &pWorld->colormaps[bSkip];
            if ( !stdConffile_ReadLine()
              || _sscanf(stdConffile_g_aLine, " tint %f %f %f", &tmpf1, &tmpf2, &tmpf3) == 3 && !stdConffile_ReadLine() )
            {
                break;
            }
            aSectors->tint.x = tmpf1; // FLEXTODO
            aSectors->tint.y = tmpf2; // FLEXTODO
            aSectors->tint.z = tmpf3; // FLEXTODO
            if ( _sscanf(
                     stdConffile_g_aLine,
                     " boundbox %f %f %f %f %f %f ",
                     &tmpf1,
                     &tmpf2,
                     &tmpf3,
                     &tmpf4,
                     &tmpf5,
                     &tmpf6) != 6 )
                break;
            aSectors->boundingbox_onecorner.x = tmpf1; // FLEXTODO
            aSectors->boundingbox_onecorner.y = tmpf2; // FLEXTODO
            aSectors->boundingbox_onecorner.z = tmpf3; // FLEXTODO
            aSectors->boundingbox_othercorner.x = tmpf4; // FLEXTODO
            aSectors->boundingbox_othercorner.y = tmpf5; // FLEXTODO
            aSectors->boundingbox_othercorner.z = tmpf6; // FLEXTODO
            if ( !stdConffile_ReadLine() )
                break;
            if ( _sscanf(
                     stdConffile_g_aLine,
                     " collidebox %f %f %f %f %f %f ",
                     &tmpf1,
                     &tmpf2,
                     &tmpf3,
                     &tmpf4,
                     &tmpf5,
                     &tmpf6) == 6 )
            {
                aSectors->collidebox_onecorner.x = tmpf1; // FLEXTODO
                aSectors->collidebox_onecorner.y = tmpf2; // FLEXTODO
                aSectors->collidebox_onecorner.z = tmpf3; // FLEXTODO
                aSectors->collidebox_othercorner.x = tmpf4; // FLEXTODO
                aSectors->collidebox_othercorner.y = tmpf5; // FLEXTODO
                aSectors->collidebox_othercorner.z = tmpf6; // FLEXTODO
                aSectors->flags |= SITH_SECTOR_HASCOLLIDEBOX;
                if ( !stdConffile_ReadLine() )
                    break;
            }
            if ( _sscanf(stdConffile_g_aLine, "sound %s %f", sound_fname, &tmpf1) == 2 )
            {
                aSectors->ambientSoundVolume = tmpf1; // FLEXTODO
                aSectors->hAmbientSound = sithSound_Load(sound_fname, 0);
                if ( !stdConffile_ReadLine() )
                    break;
            }
            if ( _sscanf(stdConffile_g_aLine, " center %f %f %f", &tmpf1, &tmpf2, &tmpf3) != 3 )
                break;
            aSectors->center.x = tmpf1; // FLEXTODO
            aSectors->center.y = tmpf2; // FLEXTODO
            aSectors->center.z = tmpf3; // FLEXTODO
            if ( !stdConffile_ReadLine() )
                break;
            if ( _sscanf(stdConffile_g_aLine, " radius %f", &tmpf1) != 1 )
                break;
            aSectors->radius = tmpf1; // FLEXTODO
            if ( !stdConffile_ReadLine() )
                break;
            if ( _sscanf(stdConffile_g_aLine, " vertices %d", &num_vertices) != 1 )
                break;
            { TWL_EXTRAM_SUGGEST(pSithHS); // Added: word-width fields/writes (audited)
            aSectors->aVertIdxs = (int32_t *)SITH_ALLOC(sizeof(int32_t) * num_vertices);
            TWL_EXTRAM_RESTORE(pSithHS); }
            if ( !aSectors->aVertIdxs )
                break;

            for (v13 = 0; v13 < num_vertices; v13++)
            {
                if (!stdConffile_ReadLine())
                    return 0;
                if (_sscanf(stdConffile_g_aLine, " %d: %d", &junk, &vtx_idx) != 2)
                    return 0;
                aSectors->aVertIdxs[v13] = vtx_idx;
            }

            aSectors->numVertices = num_vertices;
            if ( !stdConffile_ReadLine() || _sscanf(stdConffile_g_aLine, " surfaces %d %d", &amount_1, &amount_2) != 2 )
                return 0;
            aSectors->numSurfaces = amount_2;

            aSectors->surfaces = &pWorld->surfaces[amount_1];
            for (v15 = 0; v15 < amount_2; v15++)
            {
                aSectors->surfaces[v15].pSector = aSectors;
            }
            ++aSectors;
            if ( ++v21 >= sectors_amt )
                return 1;
        }
        return 0;
    }
    return 1;
}

int sithSector_GetIdxFromPtr(SithSector *pSector)
{
    return pSector && pSector->id == pSector - sithWorld_g_pCurrentWorld->aSectors && pSector->id < (unsigned int)sithWorld_g_pCurrentWorld->numSectors;
}

void sithSector_ShowSectorAdjoins(SithSector *pSector)
{
    SithSurfaceAdjoin *i; // esi

    for ( i = pSector->adjoins; i; i = i->next )
        sithSurface_ShowSectorAdjoin(i);
    pSector->flags &= ~SITH_SECTOR_ADJOINSOFF;
}

void sithSector_HideSectorAdjoins(SithSector *pSector)
{
    SithSurfaceAdjoin *i; // esi

    SITH_ASSERTREL(pSector); // Added: J3D assert
    for ( i = pSector->adjoins; i; i = i->next )
        sithSurface_HideSectorAdjoin(i);
    pSector->flags |= SITH_SECTOR_ADJOINSOFF;
}

int sithSector_GetSectorThingCount(SithSector *pSector)
{
    int result; // eax
    SithThing *i; // ecx

    SITH_ASSERTREL(pSector != NULL); // Added: J3D assert
    result = 0;
    for ( i = pSector->pFirstThingInSector; i; ++result )
        i = i->pNextThingInSector;
    return result;
}

int sithSector_AllocWorldSectors(SithWorld *pWorld, int numSectors)
{
    SithSector *aSectors;
    SITH_ASSERTREL(pWorld != NULL); // Added: J3D assert
    { TWL_EXTRAM_SUGGEST(pSithHS); // Added: word-width fields/writes (audited)
    aSectors = (SithSector *)SITH_ALLOC(numSectors * sizeof(SithSector));
    TWL_EXTRAM_RESTORE(pSithHS); }
    pWorld->aSectors = aSectors;
    if ( !aSectors )
        return 0;
    stdPlatform_Memzero32(aSectors, numSectors * sizeof(SithSector)); // Added: word-safe
    pWorld->numSectors = numSectors;
    return 1;
}

void sithSector_NewEntry(SithSector *sector, int idx)
{
    sector->id = idx;
    sector->ambientLight = 0.0f;
    sector->extraLight = 0.0f;
    sector->colormap = NULL;
    sector->tint.x = 0.0f;
    sector->tint.y = 0.0f;
    sector->tint.z = 0.0f;
    sector->numVertices = 0;
    sector->numSurfaces = 0;
    sector->adjoins = NULL;
    sector->pFirstThingInSector = NULL;
}

void sithSector_FreeWorldSectors(SithWorld *pWorld)
{
    SITH_ASSERTREL(pWorld->aSectors); // Added: J3D assert
    for (uint32_t i = 0; i < pWorld->numSectors; i++)
    {
        if ( pWorld->aSectors[i].aVertIdxs )
            SITH_FREE(pWorld->aSectors[i].aVertIdxs);
    }
    SITH_FREE(pWorld->aSectors);
    pWorld->aSectors = 0;
    pWorld->numSectors = 0;
}

int sithSector_GetSectorPlayerCount(SithSector *pSector)
{
    int result; // eax
    SithThing *i; // ecx

    SITH_ASSERTREL(pSector != NULL); // Added: J3D assert
    result = 0;
    for ( i = pSector->pFirstThingInSector; i; i = i->pNextThingInSector )
    {
        if ( i->type == SITH_THING_PLAYER )
            ++result;
    }
    return result;
}

SithSector* sithSector_GetPtrFromIdx(int idx)
{
    SithSector *result; // eax

    if ( sithWorld_g_pCurrentWorld && idx >= 0 && idx < sithWorld_g_pCurrentWorld->numSectors )
        result = &sithWorld_g_pCurrentWorld->aSectors[idx];
    else
        result = 0;
    return result;
}

void sithSector_SyncSector(SithSector *pSector, int flags)
{
    uint32_t v3; // edx
    uint32_t v4; // eax
    SithSector **v5; // ecx

    SITH_ASSERTREL(pSector); // Added: J3D assert
    if ( flags )
    {
        pSector->flags |= SITH_SECTOR_SYNC;
    }

    if (!sithMessage_g_outputstream || sithSector_numModifiedSectors >= 0x10)
        return;

    for (v4 = 0; v4 < sithSector_numModifiedSectors; v4++ )
    {
        if ( sithSector_aModifiedSectors[v4] == pSector )
        {
            sithSector_aSyncFlags[v4] |= flags;
            break;
        }
    }

    if (v4 == sithSector_numModifiedSectors)
    {
        sithSector_aModifiedSectors[sithSector_numModifiedSectors] = pSector;
        sithSector_aSyncFlags[sithSector_numModifiedSectors++] = flags;
    }
}

void sithSector_SyncSectors()
{
    uint32_t i; // esi

    for ( i = 0; i < sithSector_numModifiedSectors; ++i )
    {
        if ( (sithSector_aSyncFlags[i] & 1) != 0 )
            sithDSS_SectorStatus(sithSector_aModifiedSectors[i], -1, 255);
        else
            sithDSS_SectorFlags(sithSector_aModifiedSectors[i], -1, 255);
    }
    sithSector_numModifiedSectors = 0;
}

SithSector* sithSector_FindSectorAtPos(SithWorld *pWorld, rdVector3 *pos)
{
    int v2; // ebx
    unsigned int v3; // ebp
    SithSector *v4; // esi
    int v7; // eax

    SITH_ASSERTREL(pos != NULL); // Added: J3D assert
    SITH_ASSERTREL(pWorld != NULL); // Added: J3D assert
    v2 = 0;
    v3 = pWorld->numSectors;
    v4 = pWorld->aSectors;
    if ( !v3 )
        return 0;
    while ( 1 )
    {
        if ( pos->x >= (flex_d_t)v4->boundingbox_onecorner.x
          && pos->x <= (flex_d_t)v4->boundingbox_othercorner.x
          && v4->boundingbox_onecorner.y <= (flex_d_t)pos->y
          && v4->boundingbox_othercorner.y >= (flex_d_t)pos->y )
        {
            v7 = v4->boundingbox_onecorner.z <= (flex_d_t)pos->z && v4->boundingbox_othercorner.z >= (flex_d_t)pos->z;
            if ( v7 && sithIntersect_IsSphereInSector(pos, 0.0, v4) )
                break;
        }
        ++v4;
        if ( ++v2 >= v3 )
            return 0;
    }
    return v4;
}