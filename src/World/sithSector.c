#include "sithSector.h"

#include "General/stdMath.h"
#include "Primitives/rdMath.h"
#include "Primitives/rdFace.h"
#include "World/sithThing.h"
#include "World/jkPlayer.h"
#include "World/sithWorld.h"
#include "Engine/sithCollision.h"
#include "Engine/sithIntersect.h"
#include "jk.h"
#include "Engine/sithAdjoin.h"
#include "Engine/sithNet.h"
#include "Gameplay/sithEvent.h"
#include "Engine/rdColormap.h"
#include "Engine/sithCamera.h"
#include "Engine/sithSound.h"
#include "Engine/sithSoundMixer.h"
#include "Engine/sithRender.h"
#include "Engine/rdCache.h"
#include "Engine/sithPuppet.h"
#include "Engine/sithKeyFrame.h"
#include "Engine/sithMaterial.h"
#include "Engine/sithSurface.h"
#include "AI/sithAI.h"
#include "AI/sithAIClass.h"
#include "Dss/sithDSS.h"

int sithSector_Load(sithWorld *world, int tmp)
{
    unsigned int alloc_size; // ebx
    sithSector *v5; // eax
    sithSector *v6; // eax
    unsigned int v7; // ecx
    sithSector *sectors; // esi
    int *sector_vertices; // eax
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

    if ( tmp )
        return 0;
    if ( !stdConffile_ReadLine() || _sscanf(stdConffile_aLine, " world sectors %d", &sectors_amt) != 1 )
        return 0;
    alloc_size = sizeof(sithSector) * sectors_amt;
    v5 = (sithSector *)pSithHS->alloc(sizeof(sithSector) * sectors_amt);
    world->sectors = v5;
    if ( v5 )
    {
        _memset(v5, 0, alloc_size);
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
            if ( _sscanf(stdConffile_aLine, " ambient light %f", &sectors->ambientLight) != 1 )
                break;
            if ( !stdConffile_ReadLine() )
                break;
            if ( _sscanf(stdConffile_aLine, " extra light %f", &sectors->extraLight) != 1 )
                break;
            if ( !stdConffile_ReadLine() )
                break;
            if ( _sscanf(stdConffile_aLine, " colormap %d", &tmp) != 1 )
                break;
            sectors->colormap = &world->colormaps[tmp];
            if ( !stdConffile_ReadLine()
              || _sscanf(stdConffile_aLine, " tint %f %f %f", &sectors->tint, &sectors->tint.y, &sectors->tint.z) == 3 && !stdConffile_ReadLine() )
            {
                break;
            }
            if ( _sscanf(
                     stdConffile_aLine,
                     " boundbox %f %f %f %f %f %f ",
                     &sectors->boundingbox_onecorner,
                     &sectors->boundingbox_onecorner.y,
                     &sectors->boundingbox_onecorner.z,
                     &sectors->boundingbox_othercorner,
                     &sectors->boundingbox_othercorner.y,
                     &sectors->boundingbox_othercorner.z) != 6 )
                break;
            if ( !stdConffile_ReadLine() )
                break;
            if ( _sscanf(
                     stdConffile_aLine,
                     " collidebox %f %f %f %f %f %f ",
                     &sectors->collidebox_onecorner,
                     &sectors->collidebox_onecorner.y,
                     &sectors->collidebox_onecorner.z,
                     &sectors->collidebox_othercorner,
                     &sectors->collidebox_othercorner.y,
                     &sectors->collidebox_othercorner.z) == 6 )
            {
                sectors->flags |= SITH_SECTOR_HAS_COLLIDE_BOX;
                if ( !stdConffile_ReadLine() )
                    break;
            }
            if ( _sscanf(stdConffile_aLine, "sound %s %f", sound_fname, &sectors->sectorSoundVol) == 2 )
            {
                sectors->sectorSound = sithSound_LoadEntry(sound_fname, 0);
                if ( !stdConffile_ReadLine() )
                    break;
            }
            if ( _sscanf(stdConffile_aLine, " center %f %f %f", &sectors->center, &sectors->center.y, &sectors->center.z) != 3 )
                break;
            if ( !stdConffile_ReadLine() )
                break;
            if ( _sscanf(stdConffile_aLine, " radius %f", &sectors->radius) != 1 )
                break;
            if ( !stdConffile_ReadLine() )
                break;
            if ( _sscanf(stdConffile_aLine, " vertices %d", &num_vertices) != 1 )
                break;
            sector_vertices = (int *)pSithHS->alloc(4 * num_vertices);
            sectors->verticeIdxs = sector_vertices;
            if ( !sector_vertices )
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

void sithSector_Sync(sithSector *pSector, int a2)
{
    uint32_t v3; // edx
    uint32_t v4; // eax
    sithSector **v5; // ecx

    if ( a2 )
    {
        pSector->flags |= SITH_SECTOR_SYNC;
    }

    if (!sithCogVm_multiplayerFlags || sithSector_numSync >= 0x10)
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

void sithSector_sub_4F8EF0()
{
    uint32_t i; // esi

    for ( i = 0; i < sithSector_numSync; ++i )
    {
        if ( (sithSector_aSyncIdk2[i] & 1) != 0 )
            sithDSS_SendSyncSector(sithSector_aSyncIdk[i], -1, 255);
        else
            sithDSS_SendSyncSectorAlt(sithSector_aSyncIdk[i], -1, 255);
    }
    sithSector_numSync = 0;
}