#include "sithCogFunctionSector.h"

#include "Cog/sithCogExec.h"
#include "World/sithSector.h"
#include "World/sithWorld.h"
#include "Engine/rdColormap.h"
#include "Engine/sithIntersect.h"
#include "Main/Main.h"

void sithCogFunctionSector_GetTint(sithCog *ctx)
{
    rdVector3 vecCopy;

    sithSector* sector = sithCogExec_PopSector(ctx);
    if ( sector )
    {
        vecCopy = sector->tint;
        sithCogExec_PushVector3(ctx, &vecCopy);
    }
    else
    {
        sithCogExec_PushVector3(ctx, &rdroid_zeroVector3);
    }
}

void sithCogFunctionSector_SetTint(sithCog *ctx)
{
    sithSector *sector; // ecx
    double v2; // st7
    double v3; // st7
    double v4; // st7
    rdVector3 poppedVector; // [esp+4h] [ebp-Ch] BYREF

    sithCogExec_PopVector3(ctx, &poppedVector);
    sector = sithCogExec_PopSector(ctx);
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
    float v4; // [esp+4h] [ebp-4h]
    float extraLight; // [esp+Ch] [ebp+4h]

    v4 = sithCogExec_PopFlex(ctx);
    extraLight = sithCogExec_PopFlex(ctx);
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

void sithCogFunctionSector_GetColormap(sithCog *ctx)
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

void sithCogFunctionSector_SetColormap(sithCog *ctx)
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
        sithCogExec_PushVector3(ctx, &sector->thrust);
    else
        sithCogExec_PushVector3(ctx, &rdroid_zeroVector3);
}

void sithCogFunctionSector_SetSectorThrust(sithCog *ctx)
{
    rdVector3 thrust;

    float mult = sithCogExec_PopFlex(ctx);
    int thrust_valid = sithCogExec_PopVector3(ctx, &thrust);
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

void sithCogFunctionSector_GetThingCount(sithCog *ctx)
{
    sithSector* sector = sithCogExec_PopSector(ctx);
    if ( sector )
    {
        sithCogExec_PushInt(ctx, sithSector_GetThingsCount(sector));
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunctionSector_GetPlayerCount(sithCog *ctx)
{
    sithSector *v1; // eax
    int v2; // eax

    v1 = sithCogExec_PopSector(ctx);
    if ( v1 )
    {
        v2 = sithSector_GetNumPlayers(v1);
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
        sithCogExec_PushVector3(ctx, &v1->center);
    else
        sithCogExec_PushVector3(ctx, &rdroid_zeroVector3);
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
        sithCogExec_PushVector3(ctx, &active_jkl->vertices[sector->verticeIdxs[vertex_idx]]);
    else
        sithCogExec_PushVector3(ctx, &rdroid_zeroVector3);
}

void sithCogFunctionSector_GetSectorSurfaceRef(sithCog *ctx)
{
    int v1; // esi
    sithSector *v2; // eax

    v1 = sithCogExec_PopInt(ctx);
    v2 = sithCogExec_PopSector(ctx);
    if ( v2 && (unsigned int)v1 < v2->numSurfaces && v1 >= 0 )
        sithCogExec_PushInt(ctx, v2->surfaces[v1].field_0);
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

    float val = sithCogExec_PopFlex(ctx);
    for (int i = 0; i < sithWorld_pCurrentWorld->numSectors; i++) {
        sithSector* pSector = &sithWorld_pCurrentWorld->sectors[i];
        pSector->extraLight = val;
    }
}

// MOTS added
void sithCogFunctionSector_FindSectorAtPos(sithCog *ctx)
{
    rdVector3 tmp;
    
    sithCogExec_PopVector3(ctx,&tmp);
    sithSector* pSector = sithSector_sub_4F8D00(sithWorld_pCurrentWorld,&tmp);
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
    float radius = sithCogExec_PopFlex(ctx);
    sithCogExec_PopVector3(ctx,&tmp);
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
    float val = sithCogExec_PopFlex(ctx);
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

    float val = pSector->extraLight + pSector->ambientLight;
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

void sithCogFunctionSector_Startup(void* ctx)
{
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_GetTint, "getsectortint");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_SetTint, "setsectortint");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_SetSectorAdjoins, "setsectoradjoins");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_SetSectorAdjoins, "sectoradjoins");
    if (Main_bDwCompat) {
        sithCogScript_RegisterVerb(ctx, sithCogFunctionSector_GetAmbient, "getsectorambient");
    }
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

    if (Main_bMotsCompat) {
        sithCogScript_RegisterVerb(ctx,sithCogFunctionSector_ChangeAllSectorsLight,"changeallsectorslight");
        sithCogScript_RegisterVerb(ctx,sithCogFunctionSector_FindSectorAtPos,"findsectoratpos");
        sithCogScript_RegisterVerb(ctx,sithCogFunctionSector_IsSphereInSector,"issphereinsector");
        sithCogScript_RegisterVerb(ctx,sithCogFunctionSector_GetSectorAmbientLight,"getsectorambientlight");
        sithCogScript_RegisterVerb(ctx,sithCogFunctionSector_SetSectorAmbientLight,"setsectorambientlight");
    }
}
