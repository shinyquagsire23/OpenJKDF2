#include "sithCogSector.h"

#include "Cog/sithCogVm.h"
#include "World/sithSector.h"
#include "World/sithWorld.h"
#include "Engine/rdColormap.h"

void sithCogSector_GetTint(sithCog *ctx);
void sithCogSector_SetTint(sithCog *ctx);
void sithCogSector_SetSectorAdjoins(sithCog *ctx);
void sithCogSector_GetSectorLight(sithCog *ctx);
void sithCogSector_SetSectorLight(sithCog *ctx);
void sithCogSector_GetColormap(sithCog *ctx);
void sithCogSector_SetColormap(sithCog *ctx);
void sithCogSector_GetSectorThrust(sithCog *ctx);
void sithCogSector_SetSectorThrust(sithCog *ctx);
void sithCogSector_SetSectorFlags(sithCog *ctx);
void sithCogSector_ClearSectorFlags(sithCog *ctx);
void sithCogSector_GetSectorFlags(sithCog *ctx);
void sithCogSector_GetThingCount(sithCog *ctx);

static void (*sithCogSector_GetPlayerCount)(sithCog* ctx) = (void*)0x004FEE90;
static void (*sithCogSector_GetSectorCount)(sithCog* ctx) = (void*)0x004FEED0;
static void (*sithCogSector_GetSectorCenter)(sithCog* ctx) = (void*)0x004FEEF0;
static void (*sithCogSector_GetNumSectorVertices)(sithCog* ctx) = (void*)0x004FEF30;
static void (*sithCogSector_GetNumSectorSurfaces)(sithCog* ctx) = (void*)0x004FEF60;
static void (*sithCogSector_GetSectorVertexPos)(sithCog* ctx) = (void*)0x004FEF90;
static void (*sithCogSector_GetSectorSurfaceRef)(sithCog* ctx) = (void*)0x004FEFF0;
static void (*sithCogSector_SyncSector)(sithCog* ctx) = (void*)0x004FF040;

void sithCogSector_Initialize(void* ctx)
{
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSector_GetTint, "getsectortint");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSector_SetTint, "setsectortint");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSector_SetSectorAdjoins, "setsectoradjoins");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSector_SetSectorAdjoins, "sectoradjoins");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSector_GetSectorLight, "getsectorlight");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSector_SetSectorLight, "setsectorlight");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSector_SetSectorLight, "sectorlight");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSector_GetColormap, "getcolormap");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSector_GetColormap, "getsectorcolormap");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSector_SetColormap, "setcolormap");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSector_SetColormap, "setsectorcolormap");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSector_GetSectorThrust, "getsectorthrust");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSector_SetSectorThrust, "setsectorthrust");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSector_SetSectorThrust, "sectorthrust");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSector_GetSectorFlags, "getsectorflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSector_SetSectorFlags, "setsectorflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSector_ClearSectorFlags, "clearsectorflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSector_GetThingCount, "getsectorthingcount");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSector_GetThingCount, "sectorthingcount");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSector_GetPlayerCount, "getsectorplayercount");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSector_GetPlayerCount, "sectorplayercount");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSector_GetSectorCount, "getsectorcount");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSector_GetSectorCenter, "getsectorcenter");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSector_GetNumSectorVertices, "getnumsectorvertices");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSector_GetSectorVertexPos, "getsectorvertexpos");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSector_GetNumSectorSurfaces, "getnumsectorsurfaces");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSector_GetSectorSurfaceRef, "getsectorsurfaceref");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSector_SyncSector, "syncsector");
}

void sithCogSector_GetTint(sithCog *ctx)
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

void sithCogSector_SetTint(sithCog *ctx)
{
    sithSector *sector; // ecx
    double v2; // st7
    double v3; // st7
    double v4; // st7
    int v5; // eax
    int v6; // esi
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
        v5 = sithCogVm_multiplayerFlags;
        sector->tint.z = v4;
        if ( v5 )
        {
            if ( (ctx->flags & 0x200) == 0 )
            {
                v6 = ctx->trigId;
                if ( v6 != SITH_MESSAGE_STARTUP && v6 != SITH_MESSAGE_SHUTDOWN )
                    sithSector_Sync(sector, 1);
            }
        }
    }
}

void sithCogSector_SetSectorAdjoins(sithCog *ctx)
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
        if ( sithCogVm_multiplayerFlags )
        {
            if ( (ctx->flags & 0x200) == 0 )
            {
                v3 = ctx->trigId;
                if ( v3 != SITH_MESSAGE_STARTUP && v3 != SITH_MESSAGE_SHUTDOWN )
                    sithSector_Sync(sector, 0);
            }
        }
    }
}

void sithCogSector_GetSectorLight(sithCog *ctx)
{
    sithSector *sector; // eax

    sector = sithCogVm_PopSector(ctx);
    if ( sector )
        sithCogVm_PushFlex(ctx, sector->extraLight);
    else
        sithCogVm_PushFlex(ctx, 0.0);
}

void sithCogSector_SetSectorLight(sithCog *ctx)
{
    sithSector *sector; // ecx
    int v3; // esi
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
            if ( sithCogVm_multiplayerFlags )
            {
                if ( (ctx->flags & 0x200) == 0 )
                {
                    v3 = ctx->trigId;
                    if ( v3 != SITH_MESSAGE_STARTUP && v3 != SITH_MESSAGE_SHUTDOWN )
                        sithSector_Sync(sector, 1);
                }
            }
        }
        else
        {
            sithSurface_SetSectorLight(sector, extraLight, v4, 0);
        }
    }
}

void sithCogSector_GetColormap(sithCog *ctx)
{
    sithSector *sector; // eax
    uintptr_t v2; // ecx

    sector = sithCogVm_PopSector(ctx);
    if ( sector
      && (v2 = (char *)sector->colormap - (char *)sithWorld_pCurWorld->colormaps,
          (unsigned int)((int)v2 / (int)sizeof(rdColormap)) < sithWorld_pCurWorld->numColormaps) )
    {
        sithCogVm_PushInt(ctx, (int)v2 / (int)sizeof(rdColormap));
    }
    else
    {
        sithCogVm_PushInt(ctx, -1);
    }
}

void sithCogSector_SetColormap(sithCog *ctx)
{
    sithWorld* world = sithWorld_pCurWorld;
    uint32_t colormap_idx = sithCogVm_PopInt(ctx);
    sithSector* sector = sithCogVm_PopSector(ctx);

    if ( world )
    {
        if ( sector )
        {
            if ( colormap_idx < world->numColormaps )
            {
                sector->colormap = &world->colormaps[colormap_idx];
                if ( (sithCogVm_multiplayerFlags != 0) && (ctx->flags & 0x200) == 0 )
                {
                    if ( ctx->trigId != SITH_MESSAGE_STARTUP && ctx->trigId != SITH_MESSAGE_SHUTDOWN )
                        sithSector_Sync(sector, 1);
                }
            }
        }
    }
}

void sithCogSector_GetSectorThrust(sithCog *ctx)
{
    sithSector* sector = sithCogVm_PopSector(ctx);

    if ( sector )
        sithCogVm_PushVector3(ctx, &sector->thrust);
    else
        sithCogVm_PushVector3(ctx, &rdroid_zeroVector3);
}

void sithCogSector_SetSectorThrust(sithCog *ctx)
{
    rdVector3 thrust;

    float mult = sithCogVm_PopFlex(ctx);
    int thrust_valid = sithCogVm_PopVector3(ctx, &thrust);
    sithSector* sector = sithCogVm_PopSector(ctx);

    if ( sector && thrust_valid )
    {
        if ( thrust.x == 0.0 && thrust.y == 0.0 && thrust.z == 0.0 )
        {
            sector->flags &= ~SITH_SF_HASTHRUST;
            sector->thrust.x = 0.0;
            sector->thrust.y = 0.0;
            sector->thrust.z = 0.0;
        }
        else
        {
            sector->flags |= SITH_SF_HASTHRUST;
            sector->thrust.x = mult * thrust.x;
            sector->thrust.y = mult * thrust.y;
            sector->thrust.z = mult * thrust.z;
        }
        if ( sithCogVm_multiplayerFlags )
        {
            if ( (ctx->flags & 0x200) == 0 )
            {
                if ( ctx->trigId != SITH_MESSAGE_STARTUP && ctx->trigId != SITH_MESSAGE_SHUTDOWN )
                    sithSector_Sync(sector, 1);
            }
        }
    }
}

void sithCogSector_SetSectorFlags(sithCog *ctx)
{
    uint32_t flags = sithCogVm_PopInt(ctx);
    sithSector* sector = sithCogVm_PopSector(ctx);

    if (sector && flags)
    {
        sector->flags |= flags;
        if (sithCogVm_multiplayerFlags && !(ctx->flags & 0x200))
        {
            if ( ctx->trigId != SITH_MESSAGE_STARTUP && ctx->trigId != SITH_MESSAGE_SHUTDOWN )
                sithSector_Sync(sector, 0);
        }
    }
}

void sithCogSector_ClearSectorFlags(sithCog *ctx)
{
    uint32_t flags = sithCogVm_PopInt(ctx);
    sithSector* sector = sithCogVm_PopSector(ctx);

    if (sector && flags)
    {
        sector->flags &= ~flags;
        if (sithCogVm_multiplayerFlags && !(ctx->flags & 0x200))
        {
            if ( ctx->trigId != SITH_MESSAGE_STARTUP && ctx->trigId != SITH_MESSAGE_SHUTDOWN )
                sithSector_Sync(sector, 0);
        }
    }
}

void sithCogSector_GetSectorFlags(sithCog *ctx)
{
    sithSector* sector = sithCogVm_PopSector(ctx);
    if ( sector )
        sithCogVm_PushInt(ctx, sector->flags);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogSector_GetThingCount(sithCog *ctx)
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
