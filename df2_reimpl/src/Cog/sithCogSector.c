#include "sithCogSector.h"

static void (*sithCogSector_GetTint)(sithCog* ctx) = (void*)0x004FE8A0;
static void (*sithCogSector_SetTint)(sithCog* ctx) = (void*)0x004FE8F0;
static void (*sithCogSector_GetSectorLight)(sithCog* ctx) = (void*)0x004FEA00;
static void (*sithCogSector_SetSectorLight)(sithCog* ctx) = (void*)0x004FEA30;
static void (*sithCogSector_SetSectorAdjoins)(sithCog* ctx) = (void*)0x004FEAD0;
static void (*sithCogSector_GetColormap)(sithCog* ctx) = (void*)0x004FEB50;
static void (*sithCogSector_SetColormap)(sithCog* ctx) = (void*)0x004FEBB0;
static void (*sithCogSector_GetSectorThrust)(sithCog* ctx) = (void*)0x004FEC30;
static void (*sithCogSector_SetSectorThrust)(sithCog* ctx) = (void*)0x004FEC70;
static void (*sithCogSector_SetSectorFlags)(sithCog* ctx) = (void*)0x004FED60;
static void (*sithCogSector_ClearSectorFlags)(sithCog* ctx) = (void*)0x004FEDC0;
static void (*sithCogSector_GetSectorFlags)(sithCog* ctx) = (void*)0x004FEE20;
static void (*sithCogSector_GetThingCount)(sithCog* ctx) = (void*)0x004FEE50;
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
