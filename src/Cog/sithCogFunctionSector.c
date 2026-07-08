#include "sithCogFunctionSector.h"

#include "General/stdMath.h"
#include "Cog/sithCogExec.h"
#include "World/sithSector.h"
#include "World/sithWorld.h"
#include "Engine/rdColormap.h"
#include "Engine/sithIntersect.h"
#include "Main/Main.h"

void sithCogFunctionSector_GetSectorTint(sithCog *ctx)
{
    rdVector3 vecCopy;

    sithSector* sector = sithCogExec_PopSector(ctx);
    if ( sector )
    {
        vecCopy = sector->tint;
        sithCogExec_PushVector(ctx, &vecCopy);
    }
    else
    {
        sithCogExec_PushVector(ctx, &rdroid_zeroVector3);
    }
}

void sithCogFunctionSector_SetSectorTint(sithCog *ctx)
{
    sithSector *sector; // ecx
    rdVector3 poppedVector; // [esp+4h] [ebp-Ch] BYREF

    sithCogExec_PopVector(ctx, &poppedVector);
    sector = sithCogExec_PopSector(ctx);
    if ( sector )
    {
        sector->tint.x = stdMath_Clamp(poppedVector.x, 0.0, 1.0);
        sector->tint.y = stdMath_Clamp(poppedVector.y, 0.0, 1.0);
        sector->tint.z = stdMath_Clamp(poppedVector.z, 0.0, 1.0);
        if ( COG_SHOULD_SYNC(ctx) )
        {
            sithSector_SyncSector(sector, 1);
        }
    }
}

void sithCogFunctionSector_SetSectorAdjoins(sithCog *ctx)
{
    signed int v1; // edi
    sithSector *sector; // esi
    int v3; // eax

    v1 = sithCogExec_PopInt(ctx);
    sector = sithCogExec_PopSector(ctx);
    if ( sector )
    {
        if ( v1 )
        {
            if ( (sector->flags & 0x80) == 0 )
                return;
            sithSector_ShowSectorAdjoins(sector);
        }
        else
        {
            if ( (sector->flags & 0x80) != 0 )
                return;
            sithSector_HideSectorAdjoins(sector);
        }
        if ( COG_SHOULD_SYNC(ctx) )
        {
            sithSector_SyncSector(sector, 0);
        }
    }
}

void sithCogFunctionSector_GetSectorLight(sithCog *ctx)
{
    sithSector *sector; // eax

    sector = sithCogExec_PopSector(ctx);
    if ( sector )
        sithCogExec_PushFlex(ctx, sector->extraLight);
    else
        sithCogExec_PushFlex(ctx, 0.0);
}

void sithCogFunctionSector_SetSectorLight(sithCog *ctx)
{
    sithSector *sector; // ecx

    cog_flex_t v4 = sithCogExec_PopFlex(ctx);
    cog_flex_t extraLight = sithCogExec_PopFlex(ctx);
    sector = sithCogExec_PopSector(ctx);
    if ( sector && extraLight >= 0.0 )
    {
        if ( v4 == 0.0 )
        {
            sector->extraLight = extraLight;
            if ( COG_SHOULD_SYNC(ctx) )
            {
                sithSector_SyncSector(sector, 1);
            }
        }
        else
        {
            sithSurface_SetSectorLight(sector, extraLight, v4, 0);
        }
    }
}

void sithCogFunctionSector_GetSectorColormap(sithCog *ctx)
{
    sithSector *sector; // eax
    uintptr_t v2; // ecx

    sector = sithCogExec_PopSector(ctx);
    if ( sector
      && (v2 = (char *)sector->colormap - (char *)sithWorld_pCurrentWorld->colormaps,
          (unsigned int)((int)v2 / (int)sizeof(rdColormap)) < sithWorld_pCurrentWorld->numColormaps) )
    {
        sithCogExec_PushInt(ctx, (int)v2 / (int)sizeof(rdColormap));
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunctionSector_SetSectorColormap(sithCog *ctx)
{
    sithWorld* world = sithWorld_pCurrentWorld;
    uint32_t colormap_idx = sithCogExec_PopInt(ctx);
    sithSector* sector = sithCogExec_PopSector(ctx);

    if ( world )
    {
        if ( sector )
        {
            if ( colormap_idx < world->numColormaps )
            {
                sector->colormap = &world->colormaps[colormap_idx];
                if ( COG_SHOULD_SYNC(ctx) )
                {
                    sithSector_SyncSector(sector, 1);
                }
            }
        }
    }
}

void sithCogFunctionSector_GetSectorThrust(sithCog *ctx)
{
    sithSector* sector = sithCogExec_PopSector(ctx);

    if ( sector )
        sithCogExec_PushVector(ctx, &sector->thrust);
    else
        sithCogExec_PushVector(ctx, &rdroid_zeroVector3);
}

void sithCogFunctionSector_SetSectorThrust(sithCog *ctx)
{
    rdVector3 thrust;

    cog_flex_t mult = sithCogExec_PopFlex(ctx);
    int thrust_valid = sithCogExec_PopVector(ctx, &thrust);
    sithSector* sector = sithCogExec_PopSector(ctx);

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
            sithSector_SyncSector(sector, 1);
        }
    }
}

void sithCogFunctionSector_SetSectorFlags(sithCog *ctx)
{
    uint32_t flags = sithCogExec_PopInt(ctx);
    sithSector* sector = sithCogExec_PopSector(ctx);

    if (sector && flags)
    {
        sector->flags |= flags;
        if (COG_SHOULD_SYNC(ctx))
        {
            sithSector_SyncSector(sector, 0);
        }
    }
}

void sithCogFunctionSector_ClearSectorFlags(sithCog *ctx)
{
    uint32_t flags = sithCogExec_PopInt(ctx);
    sithSector* sector = sithCogExec_PopSector(ctx);

    if (sector && flags)
    {
        sector->flags &= ~flags;
        if (COG_SHOULD_SYNC(ctx))
        {
            sithSector_SyncSector(sector, 0);
        }
    }
}

void sithCogFunctionSector_GetSectorFlags(sithCog *ctx)
{
    sithSector* sector = sithCogExec_PopSector(ctx);
    if ( sector )
        sithCogExec_PushInt(ctx, sector->flags);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionSector_GetSectorThingCount(sithCog *ctx)
{
    sithSector* sector = sithCogExec_PopSector(ctx);
    if ( sector )
    {
        sithCogExec_PushInt(ctx, sithSector_GetSectorThingCount(sector));
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunctionSector_GetSectorPlayerCount(sithCog *ctx)
{
    sithSector *v1; // eax
    int v2; // eax

    v1 = sithCogExec_PopSector(ctx);
    if ( v1 )
    {
        v2 = sithSector_GetSectorPlayerCount(v1);
        sithCogExec_PushInt(ctx, v2);
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunctionSector_GetSectorCount(sithCog *ctx)
{
    sithCogExec_PushInt(ctx, sithWorld_pCurrentWorld->numSectors);
}

void sithCogFunctionSector_GetSectorCenter(sithCog *ctx)
{
    sithSector *v1; // eax

    v1 = sithCogExec_PopSector(ctx);
    if ( v1 )
        sithCogExec_PushVector(ctx, &v1->center);
    else
        sithCogExec_PushVector(ctx, &rdroid_zeroVector3);
}

void sithCogFunctionSector_GetNumSectorVertices(sithCog *ctx)
{
    sithSector *v1; // eax

    v1 = sithCogExec_PopSector(ctx);
    if ( v1 )
        sithCogExec_PushInt(ctx, v1->numVertices);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionSector_GetNumSectorSurfaces(sithCog *ctx)
{
    sithSector *v1; // eax

    v1 = sithCogExec_PopSector(ctx);
    if ( v1 )
        sithCogExec_PushInt(ctx, v1->numSurfaces);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionSector_GetSectorVertexPos(sithCog *ctx)
{
    sithWorld *active_jkl; // ebx
    int vertex_idx; // edi
    sithSector *sector; // eax

    active_jkl = sithWorld_pCurrentWorld;
    vertex_idx = sithCogExec_PopInt(ctx);
    sector = sithCogExec_PopSector(ctx);
    if ( sector && (unsigned int)vertex_idx < sector->numVertices && vertex_idx >= 0 )
        sithCogExec_PushVector(ctx, &active_jkl->vertices[sector->verticeIdxs[vertex_idx]]);
    else
        sithCogExec_PushVector(ctx, &rdroid_zeroVector3);
}

void sithCogFunctionSector_GetSectorSurfaceRef(sithCog *ctx)
{
    int v1; // esi
    sithSector *v2; // eax

    v1 = sithCogExec_PopInt(ctx);
    v2 = sithCogExec_PopSector(ctx);
    if ( v2 && (unsigned int)v1 < v2->numSurfaces && v1 >= 0 )
        sithCogExec_PushInt(ctx, v2->surfaces[v1].index);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionSector_SyncSector(sithCog *ctx)
{
    sithSector *v1; // eax

    v1 = sithCogExec_PopSector(ctx);
    if ( v1 )
        sithSector_SyncSector(v1, 1);
}

// MOTS added
void sithCogFunctionSector_ChangeAllSectorsLight(sithCog *ctx)
{
    sithSector *v1; // eax

    cog_flex_t val = sithCogExec_PopFlex(ctx);
    for (int i = 0; i < sithWorld_pCurrentWorld->numSectors; i++) {
        sithSector* pSector = &sithWorld_pCurrentWorld->sectors[i];
        pSector->extraLight = val;
    }
}

// MOTS added
void sithCogFunctionSector_FindSectorAtPos(sithCog *ctx)
{
    rdVector3 tmp;
    
    sithCogExec_PopVector(ctx,&tmp);
    sithSector* pSector = sithSector_FindSectorAtPos(sithWorld_pCurrentWorld,&tmp);
    if (pSector) {
        sithCogExec_PushInt(ctx, pSector->id);
        return;
    }
    sithCogExec_PushInt(ctx, -1);
}

// MOTS added
void sithCogFunctionSector_IsSphereInSector(sithCog *ctx)
{
    rdVector3 tmp;
    
    sithSector* pSector = sithCogExec_PopSector(ctx);
    cog_flex_t radius = sithCogExec_PopFlex(ctx);
    sithCogExec_PopVector(ctx,&tmp);
    if (pSector && (0.0 <= radius)) {
        if (sithIntersect_IsSphereInSector(&tmp,radius,pSector)) {
            sithCogExec_PushInt(ctx,1);
            return;
        }
    }
    sithCogExec_PushInt(ctx,0);
}

// MOTS added
void sithCogFunctionSector_GetSectorAmbientLight(sithCog *ctx)
{
    sithSector *pSector;
    
    pSector = sithCogExec_PopSector(ctx);
    if (pSector) {
        sithCogExec_PushFlex(ctx,0.0);
        return;
    }
    sithCogExec_PushFlex(ctx,pSector->ambientLight);
}

// MOTS added
void sithCogFunctionSector_SetSectorAmbientLight(sithCog *ctx)
{
    cog_flex_t val = sithCogExec_PopFlex(ctx);
    sithSector* pSector = sithCogExec_PopSector(ctx);

    if (pSector && (0.0 <= val)) {
        pSector->ambientLight = val;
    }
}

// DW added
void sithCogFunctionSector_GetAmbient(sithCog *ctx)
{
    sithSector* pSector = sithCogExec_PopSector(ctx);
    if (!pSector) {
        sithCogExec_PushFlex(ctx, 0.0);
        return;
    }

    cog_flex_t val = pSector->extraLight + pSector->ambientLight;
    if (0.0 <= val) {
        if (val <= 1.0) {
            sithCogExec_PushFlex(ctx, val);
        }
        else {
            sithCogExec_PushFlex(ctx, 1.0);
        }
        return;
    }
    sithCogExec_PushFlex(ctx,0.0);
}

void sithCogFunctionSector_Startup(sithCogSymboltable* ctx)
{
    sithCog_RegisterFunction(ctx, sithCogFunctionSector_GetSectorTint, "getsectortint");
    sithCog_RegisterFunction(ctx, sithCogFunctionSector_SetSectorTint, "setsectortint");
    sithCog_RegisterFunction(ctx, sithCogFunctionSector_SetSectorAdjoins, "setsectoradjoins");
    sithCog_RegisterFunction(ctx, sithCogFunctionSector_SetSectorAdjoins, "sectoradjoins");
    if (Main_bDwCompat) {
        sithCog_RegisterFunction(ctx, sithCogFunctionSector_GetAmbient, "getsectorambient");
    }
    sithCog_RegisterFunction(ctx, sithCogFunctionSector_GetSectorLight, "getsectorlight");
    sithCog_RegisterFunction(ctx, sithCogFunctionSector_SetSectorLight, "setsectorlight");
    sithCog_RegisterFunction(ctx, sithCogFunctionSector_SetSectorLight, "sectorlight");
    sithCog_RegisterFunction(ctx, sithCogFunctionSector_GetSectorColormap, "getcolormap");
    sithCog_RegisterFunction(ctx, sithCogFunctionSector_GetSectorColormap, "getsectorcolormap");
    sithCog_RegisterFunction(ctx, sithCogFunctionSector_SetSectorColormap, "setcolormap");
    sithCog_RegisterFunction(ctx, sithCogFunctionSector_SetSectorColormap, "setsectorcolormap");
    sithCog_RegisterFunction(ctx, sithCogFunctionSector_GetSectorThrust, "getsectorthrust");
    sithCog_RegisterFunction(ctx, sithCogFunctionSector_SetSectorThrust, "setsectorthrust");
    sithCog_RegisterFunction(ctx, sithCogFunctionSector_SetSectorThrust, "sectorthrust");
    sithCog_RegisterFunction(ctx, sithCogFunctionSector_GetSectorFlags, "getsectorflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionSector_SetSectorFlags, "setsectorflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionSector_ClearSectorFlags, "clearsectorflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionSector_GetSectorThingCount, "getsectorthingcount");
    sithCog_RegisterFunction(ctx, sithCogFunctionSector_GetSectorThingCount, "sectorthingcount");
    sithCog_RegisterFunction(ctx, sithCogFunctionSector_GetSectorPlayerCount, "getsectorplayercount");
    sithCog_RegisterFunction(ctx, sithCogFunctionSector_GetSectorPlayerCount, "sectorplayercount");
    sithCog_RegisterFunction(ctx, sithCogFunctionSector_GetSectorCount, "getsectorcount");
    sithCog_RegisterFunction(ctx, sithCogFunctionSector_GetSectorCenter, "getsectorcenter");
    sithCog_RegisterFunction(ctx, sithCogFunctionSector_GetNumSectorVertices, "getnumsectorvertices");
    sithCog_RegisterFunction(ctx, sithCogFunctionSector_GetSectorVertexPos, "getsectorvertexpos");
    sithCog_RegisterFunction(ctx, sithCogFunctionSector_GetNumSectorSurfaces, "getnumsectorsurfaces");
    sithCog_RegisterFunction(ctx, sithCogFunctionSector_GetSectorSurfaceRef, "getsectorsurfaceref");
    sithCog_RegisterFunction(ctx, sithCogFunctionSector_SyncSector, "syncsector");

    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(ctx,sithCogFunctionSector_ChangeAllSectorsLight,"changeallsectorslight");
        sithCog_RegisterFunction(ctx,sithCogFunctionSector_FindSectorAtPos,"findsectoratpos");
        sithCog_RegisterFunction(ctx,sithCogFunctionSector_IsSphereInSector,"issphereinsector");
        sithCog_RegisterFunction(ctx,sithCogFunctionSector_GetSectorAmbientLight,"getsectorambientlight");
        sithCog_RegisterFunction(ctx,sithCogFunctionSector_SetSectorAmbientLight,"setsectorambientlight");
    }
}
