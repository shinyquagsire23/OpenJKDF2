#include "sithCogFunctionSector.h"

#include "General/stdMath.h"
#include "Cog/sithCogExec.h"
#include "World/sithSector.h"
#include "World/sithWorld.h"
#include "Engine/rdColormap.h"
#include "Engine/sithIntersect.h"
#include "Main/Main.h"

void sithCogFunctionSector_GetSectorTint(sithCog *pCog)
{
    rdVector3 vecCopy;

    SithSector* sector = sithCogExec_PopSector(pCog);
    if ( sector )
    {
        vecCopy = sector->tint;
        sithCogExec_PushVector(pCog, &vecCopy);
    }
    else
    {
        sithCogExec_PushVector(pCog, &rdroid_zeroVector3);
    }
}

void sithCogFunctionSector_SetSectorTint(sithCog *pCog)
{
    SithSector *sector; // ecx
    rdVector3 poppedVector; // [esp+4h] [ebp-Ch] BYREF

    sithCogExec_PopVector(pCog, &poppedVector);
    sector = sithCogExec_PopSector(pCog);
    if ( sector )
    {
        sector->tint.x = stdMath_Clamp(poppedVector.x, 0.0, 1.0);
        sector->tint.y = stdMath_Clamp(poppedVector.y, 0.0, 1.0);
        sector->tint.z = stdMath_Clamp(poppedVector.z, 0.0, 1.0);
        if ( COG_SHOULD_SYNC(pCog) )
        {
            sithSector_SyncSector(sector, 1);
        }
    }
}

void sithCogFunctionSector_SetSectorAdjoins(sithCog *pCog)
{
    signed int v1; // edi
    SithSector *sector; // esi
    int v3; // eax

    v1 = sithCogExec_PopInt(pCog);
    sector = sithCogExec_PopSector(pCog);
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
        if ( COG_SHOULD_SYNC(pCog) )
        {
            sithSector_SyncSector(sector, 0);
        }
    }
}

void sithCogFunctionSector_GetSectorLight(sithCog *pCog)
{
    SithSector *sector; // eax

    sector = sithCogExec_PopSector(pCog);
    if ( sector )
        sithCogExec_PushFlex(pCog, sector->extraLight);
    else
        sithCogExec_PushFlex(pCog, 0.0);
}

void sithCogFunctionSector_SetSectorLight(sithCog *pCog)
{
    SithSector *sector; // ecx

    cog_flex_t v4 = sithCogExec_PopFlex(pCog);
    cog_flex_t extraLight = sithCogExec_PopFlex(pCog);
    sector = sithCogExec_PopSector(pCog);
    if ( sector && extraLight >= 0.0 )
    {
        if ( v4 == 0.0 )
        {
            sector->extraLight = extraLight;
            if ( COG_SHOULD_SYNC(pCog) )
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

void sithCogFunctionSector_GetSectorColormap(sithCog *pCog)
{
    SithSector *sector; // eax
    uintptr_t v2; // ecx

    sector = sithCogExec_PopSector(pCog);
    if ( sector
      && (v2 = (char *)sector->colormap - (char *)sithWorld_g_pCurrentWorld->colormaps,
          (unsigned int)((int)v2 / (int)sizeof(rdColormap)) < sithWorld_g_pCurrentWorld->numColormaps) )
    {
        sithCogExec_PushInt(pCog, (int)v2 / (int)sizeof(rdColormap));
    }
    else
    {
        sithCogExec_PushInt(pCog, -1);
    }
}

void sithCogFunctionSector_SetSectorColormap(sithCog *pCog)
{
    SithWorld* world = sithWorld_g_pCurrentWorld;
    uint32_t colormap_idx = sithCogExec_PopInt(pCog);
    SithSector* sector = sithCogExec_PopSector(pCog);

    if ( world )
    {
        if ( sector )
        {
            if ( colormap_idx < world->numColormaps )
            {
                sector->colormap = &world->colormaps[colormap_idx];
                if ( COG_SHOULD_SYNC(pCog) )
                {
                    sithSector_SyncSector(sector, 1);
                }
            }
        }
    }
}

void sithCogFunctionSector_GetSectorThrust(sithCog *pCog)
{
    SithSector* sector = sithCogExec_PopSector(pCog);

    if ( sector )
        sithCogExec_PushVector(pCog, &sector->thrust);
    else
        sithCogExec_PushVector(pCog, &rdroid_zeroVector3);
}

void sithCogFunctionSector_SetSectorThrust(sithCog *pCog)
{
    rdVector3 thrust;

    cog_flex_t mult = sithCogExec_PopFlex(pCog);
    int thrust_valid = sithCogExec_PopVector(pCog, &thrust);
    SithSector* sector = sithCogExec_PopSector(pCog);

    if ( sector && thrust_valid )
    {
        if ( thrust.x == 0.0 && thrust.y == 0.0 && thrust.z == 0.0 )
        {
            sector->flags &= ~SITH_SECTOR_USETHRUST;
            sector->thrust.x = 0.0;
            sector->thrust.y = 0.0;
            sector->thrust.z = 0.0;
        }
        else
        {
            sector->flags |= SITH_SECTOR_USETHRUST;
            sector->thrust.x = mult * thrust.x;
            sector->thrust.y = mult * thrust.y;
            sector->thrust.z = mult * thrust.z;
        }
        if ( COG_SHOULD_SYNC(pCog) )
        {
            sithSector_SyncSector(sector, 1);
        }
    }
}

void sithCogFunctionSector_SetSectorFlags(sithCog *pCog)
{
    uint32_t flags = sithCogExec_PopInt(pCog);
    SithSector* sector = sithCogExec_PopSector(pCog);

    if (sector && flags)
    {
        sector->flags |= flags;
        if (COG_SHOULD_SYNC(pCog))
        {
            sithSector_SyncSector(sector, 0);
        }
    }
}

void sithCogFunctionSector_ClearSectorFlags(sithCog *pCog)
{
    uint32_t flags = sithCogExec_PopInt(pCog);
    SithSector* sector = sithCogExec_PopSector(pCog);

    if (sector && flags)
    {
        sector->flags &= ~flags;
        if (COG_SHOULD_SYNC(pCog))
        {
            sithSector_SyncSector(sector, 0);
        }
    }
}

void sithCogFunctionSector_GetSectorFlags(sithCog *pCog)
{
    SithSector* sector = sithCogExec_PopSector(pCog);
    if ( sector )
        sithCogExec_PushInt(pCog, sector->flags);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionSector_GetSectorThingCount(sithCog *pCog)
{
    SithSector* sector = sithCogExec_PopSector(pCog);
    if ( sector )
    {
        sithCogExec_PushInt(pCog, sithSector_GetSectorThingCount(sector));
    }
    else
    {
        sithCogExec_PushInt(pCog, -1);
    }
}

void sithCogFunctionSector_GetSectorPlayerCount(sithCog *pCog)
{
    SithSector *v1; // eax
    int v2; // eax

    v1 = sithCogExec_PopSector(pCog);
    if ( v1 )
    {
        v2 = sithSector_GetSectorPlayerCount(v1);
        sithCogExec_PushInt(pCog, v2);
    }
    else
    {
        sithCogExec_PushInt(pCog, -1);
    }
}

void sithCogFunctionSector_GetSectorCount(sithCog *pCog)
{
    sithCogExec_PushInt(pCog, sithWorld_g_pCurrentWorld->numSectors);
}

void sithCogFunctionSector_GetSectorCenter(sithCog *pCog)
{
    SithSector *v1; // eax

    v1 = sithCogExec_PopSector(pCog);
    if ( v1 )
        sithCogExec_PushVector(pCog, &v1->center);
    else
        sithCogExec_PushVector(pCog, &rdroid_zeroVector3);
}

void sithCogFunctionSector_GetNumSectorVertices(sithCog *pCog)
{
    SithSector *v1; // eax

    v1 = sithCogExec_PopSector(pCog);
    if ( v1 )
        sithCogExec_PushInt(pCog, v1->numVertices);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionSector_GetNumSectorSurfaces(sithCog *pCog)
{
    SithSector *v1; // eax

    v1 = sithCogExec_PopSector(pCog);
    if ( v1 )
        sithCogExec_PushInt(pCog, v1->numSurfaces);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionSector_GetSectorVertexPos(sithCog *pCog)
{
    SithWorld *active_jkl; // ebx
    int vertex_idx; // edi
    SithSector *sector; // eax

    active_jkl = sithWorld_g_pCurrentWorld;
    vertex_idx = sithCogExec_PopInt(pCog);
    sector = sithCogExec_PopSector(pCog);
    if ( sector && (unsigned int)vertex_idx < sector->numVertices && vertex_idx >= 0 )
        sithCogExec_PushVector(pCog, &active_jkl->aVertices[sector->aVertIdxs[vertex_idx]]);
    else
        sithCogExec_PushVector(pCog, &rdroid_zeroVector3);
}

void sithCogFunctionSector_GetSectorSurfaceRef(sithCog *pCog)
{
    int v1; // esi
    SithSector *v2; // eax

    v1 = sithCogExec_PopInt(pCog);
    v2 = sithCogExec_PopSector(pCog);
    if ( v2 && (unsigned int)v1 < v2->numSurfaces && v1 >= 0 )
        sithCogExec_PushInt(pCog, v2->surfaces[v1].index);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionSector_SyncSector(sithCog *pCog)
{
    SithSector *v1; // eax

    v1 = sithCogExec_PopSector(pCog);
    if ( v1 )
        sithSector_SyncSector(v1, 1);
}

// MOTS added
void sithCogFunctionSector_ChangeAllSectorsLight(sithCog *pCog)
{
    SithSector *v1; // eax

    cog_flex_t val = sithCogExec_PopFlex(pCog);
    for (int i = 0; i < sithWorld_g_pCurrentWorld->numSectors; i++) {
        SithSector* pSector = &sithWorld_g_pCurrentWorld->aSectors[i];
        pSector->extraLight = val;
    }
}

// MOTS added
void sithCogFunctionSector_FindSectorAtPos(sithCog *pCog)
{
    rdVector3 tmp;
    
    sithCogExec_PopVector(pCog,&tmp);
    SithSector* pSector = sithSector_FindSectorAtPos(sithWorld_g_pCurrentWorld,&tmp);
    if (pSector) {
        sithCogExec_PushInt(pCog, pSector->id);
        return;
    }
    sithCogExec_PushInt(pCog, -1);
}

// MOTS added
void sithCogFunctionSector_IsSphereInSector(sithCog *pCog)
{
    rdVector3 tmp;
    
    SithSector* pSector = sithCogExec_PopSector(pCog);
    cog_flex_t radius = sithCogExec_PopFlex(pCog);
    sithCogExec_PopVector(pCog,&tmp);
    if (pSector && (0.0 <= radius)) {
        if (sithIntersect_IsSphereInSector(&tmp,radius,pSector)) {
            sithCogExec_PushInt(pCog,1);
            return;
        }
    }
    sithCogExec_PushInt(pCog,0);
}

// MOTS added
void sithCogFunctionSector_GetSectorAmbientLight(sithCog *pCog)
{
    SithSector *pSector;
    
    pSector = sithCogExec_PopSector(pCog);
    if (pSector) {
        sithCogExec_PushFlex(pCog,0.0);
        return;
    }
    sithCogExec_PushFlex(pCog,pSector->ambientLight);
}

// MOTS added
void sithCogFunctionSector_SetSectorAmbientLight(sithCog *pCog)
{
    cog_flex_t val = sithCogExec_PopFlex(pCog);
    SithSector* pSector = sithCogExec_PopSector(pCog);

    if (pSector && (0.0 <= val)) {
        pSector->ambientLight = val;
    }
}

// DW added
void sithCogFunctionSector_GetAmbient(sithCog *pCog)
{
    SithSector* pSector = sithCogExec_PopSector(pCog);
    if (!pSector) {
        sithCogExec_PushFlex(pCog, 0.0);
        return;
    }

    cog_flex_t val = pSector->extraLight + pSector->ambientLight;
    if (0.0 <= val) {
        if (val <= 1.0) {
            sithCogExec_PushFlex(pCog, val);
        }
        else {
            sithCogExec_PushFlex(pCog, 1.0);
        }
        return;
    }
    sithCogExec_PushFlex(pCog,0.0);
}

void sithCogFunctionSector_Startup(SithCogSymbolTable* pCog)
{
    sithCog_RegisterFunction(pCog, sithCogFunctionSector_GetSectorTint, "getsectortint");
    sithCog_RegisterFunction(pCog, sithCogFunctionSector_SetSectorTint, "setsectortint");
    sithCog_RegisterFunction(pCog, sithCogFunctionSector_SetSectorAdjoins, "setsectoradjoins");
    sithCog_RegisterFunction(pCog, sithCogFunctionSector_SetSectorAdjoins, "sectoradjoins");
    if (Main_bDwCompat) {
        sithCog_RegisterFunction(pCog, sithCogFunctionSector_GetAmbient, "getsectorambient");
    }
    sithCog_RegisterFunction(pCog, sithCogFunctionSector_GetSectorLight, "getsectorlight");
    sithCog_RegisterFunction(pCog, sithCogFunctionSector_SetSectorLight, "setsectorlight");
    sithCog_RegisterFunction(pCog, sithCogFunctionSector_SetSectorLight, "sectorlight");
    sithCog_RegisterFunction(pCog, sithCogFunctionSector_GetSectorColormap, "getcolormap");
    sithCog_RegisterFunction(pCog, sithCogFunctionSector_GetSectorColormap, "getsectorcolormap");
    sithCog_RegisterFunction(pCog, sithCogFunctionSector_SetSectorColormap, "setcolormap");
    sithCog_RegisterFunction(pCog, sithCogFunctionSector_SetSectorColormap, "setsectorcolormap");
    sithCog_RegisterFunction(pCog, sithCogFunctionSector_GetSectorThrust, "getsectorthrust");
    sithCog_RegisterFunction(pCog, sithCogFunctionSector_SetSectorThrust, "setsectorthrust");
    sithCog_RegisterFunction(pCog, sithCogFunctionSector_SetSectorThrust, "sectorthrust");
    sithCog_RegisterFunction(pCog, sithCogFunctionSector_GetSectorFlags, "getsectorflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionSector_SetSectorFlags, "setsectorflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionSector_ClearSectorFlags, "clearsectorflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionSector_GetSectorThingCount, "getsectorthingcount");
    sithCog_RegisterFunction(pCog, sithCogFunctionSector_GetSectorThingCount, "sectorthingcount");
    sithCog_RegisterFunction(pCog, sithCogFunctionSector_GetSectorPlayerCount, "getsectorplayercount");
    sithCog_RegisterFunction(pCog, sithCogFunctionSector_GetSectorPlayerCount, "sectorplayercount");
    sithCog_RegisterFunction(pCog, sithCogFunctionSector_GetSectorCount, "getsectorcount");
    sithCog_RegisterFunction(pCog, sithCogFunctionSector_GetSectorCenter, "getsectorcenter");
    sithCog_RegisterFunction(pCog, sithCogFunctionSector_GetNumSectorVertices, "getnumsectorvertices");
    sithCog_RegisterFunction(pCog, sithCogFunctionSector_GetSectorVertexPos, "getsectorvertexpos");
    sithCog_RegisterFunction(pCog, sithCogFunctionSector_GetNumSectorSurfaces, "getnumsectorsurfaces");
    sithCog_RegisterFunction(pCog, sithCogFunctionSector_GetSectorSurfaceRef, "getsectorsurfaceref");
    sithCog_RegisterFunction(pCog, sithCogFunctionSector_SyncSector, "syncsector");

    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(pCog,sithCogFunctionSector_ChangeAllSectorsLight,"changeallsectorslight");
        sithCog_RegisterFunction(pCog,sithCogFunctionSector_FindSectorAtPos,"findsectoratpos");
        sithCog_RegisterFunction(pCog,sithCogFunctionSector_IsSphereInSector,"issphereinsector");
        sithCog_RegisterFunction(pCog,sithCogFunctionSector_GetSectorAmbientLight,"getsectorambientlight");
        sithCog_RegisterFunction(pCog,sithCogFunctionSector_SetSectorAmbientLight,"setsectorambientlight");
    }
}
