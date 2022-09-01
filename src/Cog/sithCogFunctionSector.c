#include "sithCogFunctionSector.h"

#include "Cog/sithCogVm.h"
#include "World/sithSector.h"
#include "World/sithWorld.h"
#include "Engine/rdColormap.h"

void sithCogFunctionSector_GetTint(sithCog *ctx);
void sithCogFunctionSector_SetTint(sithCog *ctx);
void sithCogFunctionSector_SetSectorAdjoins(sithCog *ctx);
void sithCogFunctionSector_GetSectorLight(sithCog *ctx);
void sithCogFunctionSector_SetSectorLight(sithCog *ctx);
void sithCogFunctionSector_GetColormap(sithCog *ctx);
void sithCogFunctionSector_SetColormap(sithCog *ctx);
void sithCogFunctionSector_GetSectorThrust(sithCog *ctx);
void sithCogFunctionSector_SetSectorThrust(sithCog *ctx);
void sithCogFunctionSector_SetSectorFlags(sithCog *ctx);
void sithCogFunctionSector_ClearSectorFlags(sithCog *ctx);
void sithCogFunctionSector_GetSectorFlags(sithCog *ctx);
void sithCogFunctionSector_GetThingCount(sithCog *ctx);
void sithCogFunctionSector_GetPlayerCount(sithCog *ctx);
void sithCogFunctionSector_GetSectorCount(sithCog *ctx);
void sithCogFunctionSector_GetSectorCenter(sithCog *ctx);
void sithCogFunctionSector_GetNumSectorVertices(sithCog *ctx);
void sithCogFunctionSector_GetNumSectorSurfaces(sithCog *ctx);
void sithCogFunctionSector_GetSectorVertexPos(sithCog *ctx);
void sithCogFunctionSector_GetSectorSurfaceRef(sithCog *ctx);
void sithCogFunctionSector_SyncSector(sithCog *ctx);

void sithCogFunctionSector_Initialize(void* ctx)
{
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_GetTint, "getsectortint");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_SetTint, "setsectortint");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_SetSectorAdjoins, "setsectoradjoins");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_SetSectorAdjoins, "sectoradjoins");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_GetSectorLight, "getsectorlight");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_SetSectorLight, "setsectorlight");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_SetSectorLight, "sectorlight");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_GetColormap, "getcolormap");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_GetColormap, "getsectorcolormap");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_SetColormap, "setcolormap");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_SetColormap, "setsectorcolormap");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_GetSectorThrust, "getsectorthrust");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_SetSectorThrust, "setsectorthrust");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_SetSectorThrust, "sectorthrust");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_GetSectorFlags, "getsectorflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_SetSectorFlags, "setsectorflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_ClearSectorFlags, "clearsectorflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_GetThingCount, "getsectorthingcount");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_GetThingCount, "sectorthingcount");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_GetPlayerCount, "getsectorplayercount");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_GetPlayerCount, "sectorplayercount");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_GetSectorCount, "getsectorcount");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_GetSectorCenter, "getsectorcenter");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_GetNumSectorVertices, "getnumsectorvertices");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_GetSectorVertexPos, "getsectorvertexpos");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_GetNumSectorSurfaces, "getnumsectorsurfaces");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_GetSectorSurfaceRef, "getsectorsurfaceref");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_SyncSector, "syncsector");
}

void sithCogFunctionSector_GetTint(sithCog *ctx)
{
    rdVector3 vecCopy;

    sithSector* sector = sithCogVm_PopSector(ctx);
    if ( sector )
    {
        vecCopy = sector->tint;
        sithCogVm_PushVector3(ctx, &vecCopy);
    }
    else
    {
        sithCogVm_PushVector3(ctx, &rdroid_zeroVector3);
    }
}

void sithCogFunctionSector_SetTint(sithCog *ctx)
{
    sithSector *sector; // ecx
    double v2; // st7
    double v3; // st7
    double v4; // st7
    rdVector3 poppedVector; // [esp+4h] [ebp-Ch] BYREF

    sithCogVm_PopVector3(ctx, &poppedVector);
    sector = sithCogVm_PopSector(ctx);
    if ( sector )
    {
        if ( poppedVector.x < 0.0 )
        {
            v2 = 0.0;
        }
        else if ( poppedVector.x > 1.0 )
        {
            v2 = 1.0;
        }
        else
        {
            v2 = poppedVector.x;
        }
        sector->tint.x = v2;
        if ( poppedVector.y < 0.0 )
        {
            v3 = 0.0;
        }
        else if ( poppedVector.y > 1.0 )
        {
            v3 = 1.0;
        }
        else
        {
            v3 = poppedVector.y;
        }
        sector->tint.y = v3;
        if ( poppedVector.z < 0.0 )
        {
            v4 = 0.0;
        }
        else if ( poppedVector.z > 1.0 )
        {
            v4 = 1.0;
        }
        else
        {
            v4 = poppedVector.z;
        }
        sector->tint.z = v4;
        if ( COG_SHOULD_SYNC(ctx) )
        {
            sithSector_Sync(sector, 1);
        }
    }
}

void sithCogFunctionSector_SetSectorAdjoins(sithCog *ctx)
{
    signed int v1; // edi
    sithSector *sector; // esi
    int v3; // eax

    v1 = sithCogVm_PopInt(ctx);
    sector = sithCogVm_PopSector(ctx);
    if ( sector )
    {
        if ( v1 )
        {
            if ( (sector->flags & 0x80) == 0 )
                return;
            sithSector_SetAdjoins(sector);
        }
        else
        {
            if ( (sector->flags & 0x80) != 0 )
                return;
            sithSector_UnsetAdjoins(sector);
        }
        if ( COG_SHOULD_SYNC(ctx) )
        {
            sithSector_Sync(sector, 0);
        }
    }
}

void sithCogFunctionSector_GetSectorLight(sithCog *ctx)
{
    sithSector *sector; // eax

    sector = sithCogVm_PopSector(ctx);
    if ( sector )
        sithCogVm_PushFlex(ctx, sector->extraLight);
    else
        sithCogVm_PushFlex(ctx, 0.0);
}

void sithCogFunctionSector_SetSectorLight(sithCog *ctx)
{
    sithSector *sector; // ecx
    float v4; // [esp+4h] [ebp-4h]
    float extraLight; // [esp+Ch] [ebp+4h]

    v4 = sithCogVm_PopFlex(ctx);
    extraLight = sithCogVm_PopFlex(ctx);
    sector = sithCogVm_PopSector(ctx);
    if ( sector && extraLight >= 0.0 )
    {
        if ( v4 == 0.0 )
        {
            sector->extraLight = extraLight;
            if ( COG_SHOULD_SYNC(ctx) )
            {
                sithSector_Sync(sector, 1);
            }
        }
        else
        {
            sithSurface_SetSectorLight(sector, extraLight, v4, 0);
        }
    }
}

void sithCogFunctionSector_GetColormap(sithCog *ctx)
{
    sithSector *sector; // eax
    uintptr_t v2; // ecx

    sector = sithCogVm_PopSector(ctx);
    if ( sector
      && (v2 = (char *)sector->colormap - (char *)sithWorld_pCurrentWorld->colormaps,
          (unsigned int)((int)v2 / (int)sizeof(rdColormap)) < sithWorld_pCurrentWorld->numColormaps) )
    {
        sithCogVm_PushInt(ctx, (int)v2 / (int)sizeof(rdColormap));
    }
    else
    {
        sithCogVm_PushInt(ctx, -1);
    }
}

void sithCogFunctionSector_SetColormap(sithCog *ctx)
{
    sithWorld* world = sithWorld_pCurrentWorld;
    uint32_t colormap_idx = sithCogVm_PopInt(ctx);
    sithSector* sector = sithCogVm_PopSector(ctx);

    if ( world )
    {
        if ( sector )
        {
            if ( colormap_idx < world->numColormaps )
            {
                sector->colormap = &world->colormaps[colormap_idx];
                if ( COG_SHOULD_SYNC(ctx) )
                {
                    sithSector_Sync(sector, 1);
                }
            }
        }
    }
}

void sithCogFunctionSector_GetSectorThrust(sithCog *ctx)
{
    sithSector* sector = sithCogVm_PopSector(ctx);

    if ( sector )
        sithCogVm_PushVector3(ctx, &sector->thrust);
    else
        sithCogVm_PushVector3(ctx, &rdroid_zeroVector3);
}

void sithCogFunctionSector_SetSectorThrust(sithCog *ctx)
{
    rdVector3 thrust;

    float mult = sithCogVm_PopFlex(ctx);
    int thrust_valid = sithCogVm_PopVector3(ctx, &thrust);
    sithSector* sector = sithCogVm_PopSector(ctx);

    if ( sector && thrust_valid )
    {
        if ( thrust.x == 0.0 && thrust.y == 0.0 && thrust.z == 0.0 )
        {
            sector->flags &= ~SITH_SECTOR_HASTHRUST;
            sector->thrust.x = 0.0;
            sector->thrust.y = 0.0;
            sector->thrust.z = 0.0;
        }
        else
        {
            sector->flags |= SITH_SECTOR_HASTHRUST;
            sector->thrust.x = mult * thrust.x;
            sector->thrust.y = mult * thrust.y;
            sector->thrust.z = mult * thrust.z;
        }
        if ( COG_SHOULD_SYNC(ctx) )
        {
            sithSector_Sync(sector, 1);
        }
    }
}

void sithCogFunctionSector_SetSectorFlags(sithCog *ctx)
{
    uint32_t flags = sithCogVm_PopInt(ctx);
    sithSector* sector = sithCogVm_PopSector(ctx);

    if (sector && flags)
    {
        sector->flags |= flags;
        if (COG_SHOULD_SYNC(ctx))
        {
            sithSector_Sync(sector, 0);
        }
    }
}

void sithCogFunctionSector_ClearSectorFlags(sithCog *ctx)
{
    uint32_t flags = sithCogVm_PopInt(ctx);
    sithSector* sector = sithCogVm_PopSector(ctx);

    if (sector && flags)
    {
        sector->flags &= ~flags;
        if (COG_SHOULD_SYNC(ctx))
        {
            sithSector_Sync(sector, 0);
        }
    }
}

void sithCogFunctionSector_GetSectorFlags(sithCog *ctx)
{
    sithSector* sector = sithCogVm_PopSector(ctx);
    if ( sector )
        sithCogVm_PushInt(ctx, sector->flags);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionSector_GetThingCount(sithCog *ctx)
{
    sithSector* sector = sithCogVm_PopSector(ctx);
    if ( sector )
    {
        sithCogVm_PushInt(ctx, sithSector_GetThingsCount(sector));
    }
    else
    {
        sithCogVm_PushInt(ctx, -1);
    }
}

void sithCogFunctionSector_GetPlayerCount(sithCog *ctx)
{
    sithSector *v1; // eax
    int v2; // eax

    v1 = sithCogVm_PopSector(ctx);
    if ( v1 )
    {
        v2 = sithSector_GetNumPlayers(v1);
        sithCogVm_PushInt(ctx, v2);
    }
    else
    {
        sithCogVm_PushInt(ctx, -1);
    }
}

void sithCogFunctionSector_GetSectorCount(sithCog *ctx)
{
    sithCogVm_PushInt(ctx, sithWorld_pCurrentWorld->numSectors);
}

void sithCogFunctionSector_GetSectorCenter(sithCog *ctx)
{
    sithSector *v1; // eax

    v1 = sithCogVm_PopSector(ctx);
    if ( v1 )
        sithCogVm_PushVector3(ctx, &v1->center);
    else
        sithCogVm_PushVector3(ctx, &rdroid_zeroVector3);
}

void sithCogFunctionSector_GetNumSectorVertices(sithCog *ctx)
{
    sithSector *v1; // eax

    v1 = sithCogVm_PopSector(ctx);
    if ( v1 )
        sithCogVm_PushInt(ctx, v1->numVertices);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionSector_GetNumSectorSurfaces(sithCog *ctx)
{
    sithSector *v1; // eax

    v1 = sithCogVm_PopSector(ctx);
    if ( v1 )
        sithCogVm_PushInt(ctx, v1->numSurfaces);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionSector_GetSectorVertexPos(sithCog *ctx)
{
    sithWorld *active_jkl; // ebx
    int vertex_idx; // edi
    sithSector *sector; // eax

    active_jkl = sithWorld_pCurrentWorld;
    vertex_idx = sithCogVm_PopInt(ctx);
    sector = sithCogVm_PopSector(ctx);
    if ( sector && (unsigned int)vertex_idx < sector->numVertices && vertex_idx >= 0 )
        sithCogVm_PushVector3(ctx, &active_jkl->vertices[sector->verticeIdxs[vertex_idx]]);
    else
        sithCogVm_PushVector3(ctx, &rdroid_zeroVector3);
}

void sithCogFunctionSector_GetSectorSurfaceRef(sithCog *ctx)
{
    int v1; // esi
    sithSector *v2; // eax

    v1 = sithCogVm_PopInt(ctx);
    v2 = sithCogVm_PopSector(ctx);
    if ( v2 && (unsigned int)v1 < v2->numSurfaces && v1 >= 0 )
        sithCogVm_PushInt(ctx, v2->surfaces[v1].field_0);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionSector_SyncSector(sithCog *ctx)
{
    sithSector *v1; // eax

    v1 = sithCogVm_PopSector(ctx);
    if ( v1 )
        sithSector_Sync(v1, 1);
}
