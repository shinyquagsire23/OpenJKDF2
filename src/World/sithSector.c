#include "sithSector.h"

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
int sithSector_Load(sithWorld *world, int tmp)
{
    unsigned int alloc_size; // ebx
    sithSector *v6; // eax
    unsigned int v7; // ecx
    sithSector *sectors; // esi
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

    if ( tmp )
        return 0;
    if ( !stdConffile_ReadLine() || _sscanf(stdConffile_aLine, " world sectors %d", &sectors_amt) != 1 )
        return 0;

#ifdef STDPLATFORM_HEAP_SUGGESTIONS
    int prevSuggest = pSithHS->suggestHeap(HEAP_FAST);
#endif
    alloc_size = sizeof(sithSector) * sectors_amt;
    world->sectors = (sithSector *)pSithHS->alloc(sizeof(sithSector) * sectors_amt);
#ifdef STDPLATFORM_HEAP_SUGGESTIONS
    pSithHS->suggestHeap(prevSuggest);
#endif
    if ( world->sectors )
    {
        _memset(world->sectors, 0, alloc_size);
        v6 = world->sectors;
        v7 = 0;
        for ( world->numSectors = sectors_amt; v7 < sectors_amt; ++v7 )
        {
            v6->id = v7;
            v6->numVertices = 0;
            v6->verticeIdxs = 0;
            v6->numSurfaces = 0;
            v6->surfaces = 0;
            v6->thingsList = 0;
            ++v6;
        }
    }
    sectors = world->sectors;
    if ( !sectors )
        return 0;
    v21 = 0;
    if ( sectors_amt )
    {
        while ( stdConffile_ReadLine() )
        {
            if ( _sscanf(stdConffile_aLine, " sector %d", &junk) != 1 )
                break;
            if ( !stdConffile_ReadLine() )
                break;
            if ( _sscanf(stdConffile_aLine, " flags %x", &sectors->flags) != 1 )
                break;
            if ( !stdConffile_ReadLine() )
                break;
            if ( _sscanf(stdConffile_aLine, " ambient light %f", &tmpf1) != 1 )
                break;
            sectors->ambientLight = tmpf1; // FLEXTODO
            if ( !stdConffile_ReadLine() )
                break;
            if ( _sscanf(stdConffile_aLine, " extra light %f", &tmpf1) != 1 )
                break;
            sectors->extraLight = tmpf1; // FLEXTODO
            if ( !stdConffile_ReadLine() )
                break;
            if ( _sscanf(stdConffile_aLine, " colormap %d", &tmp) != 1 )
                break;
            sectors->colormap = &world->colormaps[tmp];
            if ( !stdConffile_ReadLine()
              || _sscanf(stdConffile_aLine, " tint %f %f %f", &tmpf1, &tmpf2, &tmpf3) == 3 && !stdConffile_ReadLine() )
            {
                break;
            }
            sectors->tint.x = tmpf1; // FLEXTODO
            sectors->tint.y = tmpf2; // FLEXTODO
            sectors->tint.z = tmpf3; // FLEXTODO
            if ( _sscanf(
                     stdConffile_aLine,
                     " boundbox %f %f %f %f %f %f ",
                     &tmpf1,
                     &tmpf2,
                     &tmpf3,
                     &tmpf4,
                     &tmpf5,
                     &tmpf6) != 6 )
                break;
            sectors->boundingbox_onecorner.x = tmpf1; // FLEXTODO
            sectors->boundingbox_onecorner.y = tmpf2; // FLEXTODO
            sectors->boundingbox_onecorner.z = tmpf3; // FLEXTODO
            sectors->boundingbox_othercorner.x = tmpf4; // FLEXTODO
            sectors->boundingbox_othercorner.y = tmpf5; // FLEXTODO
            sectors->boundingbox_othercorner.z = tmpf6; // FLEXTODO
            if ( !stdConffile_ReadLine() )
                break;
            if ( _sscanf(
                     stdConffile_aLine,
                     " collidebox %f %f %f %f %f %f ",
                     &tmpf1,
                     &tmpf2,
                     &tmpf3,
                     &tmpf4,
                     &tmpf5,
                     &tmpf6) == 6 )
            {
                sectors->collidebox_onecorner.x = tmpf1; // FLEXTODO
                sectors->collidebox_onecorner.y = tmpf2; // FLEXTODO
                sectors->collidebox_onecorner.z = tmpf3; // FLEXTODO
                sectors->collidebox_othercorner.x = tmpf4; // FLEXTODO
                sectors->collidebox_othercorner.y = tmpf5; // FLEXTODO
                sectors->collidebox_othercorner.z = tmpf6; // FLEXTODO
                sectors->flags |= SITH_SECTOR_HAS_COLLIDE_BOX;
                if ( !stdConffile_ReadLine() )
                    break;
            }
            if ( _sscanf(stdConffile_aLine, "sound %s %f", sound_fname, &tmpf1) == 2 )
            {
                sectors->sectorSoundVol = tmpf1; // FLEXTODO
                sectors->sectorSound = sithSound_LoadEntry(sound_fname, 0);
                if ( !stdConffile_ReadLine() )
                    break;
            }
            if ( _sscanf(stdConffile_aLine, " center %f %f %f", &tmpf1, &tmpf2, &tmpf3) != 3 )
                break;
            sectors->center.x = tmpf1; // FLEXTODO
            sectors->center.y = tmpf2; // FLEXTODO
            sectors->center.z = tmpf3; // FLEXTODO
            if ( !stdConffile_ReadLine() )
                break;
            if ( _sscanf(stdConffile_aLine, " radius %f", &tmpf1) != 1 )
                break;
            sectors->radius = tmpf1; // FLEXTODO
            if ( !stdConffile_ReadLine() )
                break;
            if ( _sscanf(stdConffile_aLine, " vertices %d", &num_vertices) != 1 )
                break;
            sectors->verticeIdxs = (int32_t *)pSithHS->alloc(sizeof(int32_t) * num_vertices);
            if ( !sectors->verticeIdxs )
                break;

            for (v13 = 0; v13 < num_vertices; v13++)
            {
                if (!stdConffile_ReadLine())
                    return 0;
                if (_sscanf(stdConffile_aLine, " %d: %d", &junk, &vtx_idx) != 2)
                    return 0;
                sectors->verticeIdxs[v13] = vtx_idx;
            }

            sectors->numVertices = num_vertices;
            if ( !stdConffile_ReadLine() || _sscanf(stdConffile_aLine, " surfaces %d %d", &amount_1, &amount_2) != 2 )
                return 0;
            sectors->numSurfaces = amount_2;

            sectors->surfaces = &world->surfaces[amount_1];
            for (v15 = 0; v15 < amount_2; v15++)
            {
                sectors->surfaces[v15].parent_sector = sectors;
            }
            ++sectors;
            if ( ++v21 >= sectors_amt )
                return 1;
        }
        return 0;
    }
    return 1;
}

int sithSector_GetIdxFromPtr(sithSector *sector)
{
    return sector && sector->id == sector - sithWorld_pCurrentWorld->sectors && sector->id < (unsigned int)sithWorld_pCurrentWorld->numSectors;
}

void sithSector_SetAdjoins(sithSector *sector)
{
    sithAdjoin *i; // esi

    for ( i = sector->adjoins; i; i = i->next )
        sithSurface_SetAdjoins(i);
    sector->flags &= ~SITH_SECTOR_ADJOINS_SET;
}

void sithSector_UnsetAdjoins(sithSector *sector)
{
    sithAdjoin *i; // esi

    for ( i = sector->adjoins; i; i = i->next )
        sithSurface_UnsetAdjoins(i);
    sector->flags |= SITH_SECTOR_ADJOINS_SET;
}

int sithSector_GetThingsCount(sithSector *sector)
{
    int result; // eax
    sithThing *i; // ecx

    result = 0;
    for ( i = sector->thingsList; i; ++result )
        i = i->nextThing;
    return result;
}

void sithSector_Free(sithWorld *world)
{
    for (uint32_t i = 0; i < world->numSectors; i++)
    {
        if ( world->sectors[i].verticeIdxs )
            pSithHS->free(world->sectors[i].verticeIdxs);
    }
    pSithHS->free(world->sectors);
    world->sectors = 0;
    world->numSectors = 0;
}

int sithSector_GetNumPlayers(sithSector *sector)
{
    int result; // eax
    sithThing *i; // ecx

    result = 0;
    for ( i = sector->thingsList; i; i = i->nextThing )
    {
        if ( i->type == SITH_THING_PLAYER )
            ++result;
    }
    return result;
}

sithSector* sithSector_GetPtrFromIdx(int idx)
{
    sithSector *result; // eax

    if ( sithWorld_pCurrentWorld && idx >= 0 && idx < sithWorld_pCurrentWorld->numSectors )
        result = &sithWorld_pCurrentWorld->sectors[idx];
    else
        result = 0;
    return result;
}

void sithSector_SyncSector(sithSector *pSector, int a2)
{
    uint32_t v3; // edx
    uint32_t v4; // eax
    sithSector **v5; // ecx

    if ( a2 )
    {
        pSector->flags |= SITH_SECTOR_SYNC;
    }

    if (!sithComm_multiplayerFlags || sithSector_numSync >= 0x10)
        return;

    for (v4 = 0; v4 < sithSector_numSync; v4++ )
    {
        if ( sithSector_aSyncIdk[v4] == pSector )
        {
            sithSector_aSyncIdk2[v4] |= a2;
            break;
        }
    }

    if (v4 == sithSector_numSync)
    {
        sithSector_aSyncIdk[sithSector_numSync] = pSector;
        sithSector_aSyncIdk2[sithSector_numSync++] = a2;
    }
}

void sithSector_Sync()
{
    uint32_t i; // esi

    for ( i = 0; i < sithSector_numSync; ++i )
    {
        if ( (sithSector_aSyncIdk2[i] & 1) != 0 )
            sithDSS_SendSectorStatus(sithSector_aSyncIdk[i], -1, 255);
        else
            sithDSS_SendSectorFlags(sithSector_aSyncIdk[i], -1, 255);
    }
    sithSector_numSync = 0;
}

sithSector* sithSector_sub_4F8D00(sithWorld *pWorld, rdVector3 *pos)
{
    int v2; // ebx
    unsigned int v3; // ebp
    sithSector *v4; // esi
    int v7; // eax

    v2 = 0;
    v3 = pWorld->numSectors;
    v4 = pWorld->sectors;
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