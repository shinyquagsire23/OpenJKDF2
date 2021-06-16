#ifndef _SITHUNK3_H
#define _SITHUNK3_H

#include "types.h"

#define sithUnk3_Startup_ADDR (0x004E6D90)
#define sithUnk3_Shutdown_ADDR (0x004E6F20)
#define sithUnk3_RegisterCollisionHandler_ADDR (0x004E6F40)
#define sithUnk3_RegisterHitHandler_ADDR (0x004E6FA0)
#define sithUnk3_sub_4E6FB0_ADDR (0x004E6FB0)
#define sithUnk3_NextSearchResult_ADDR (0x004E7120)
#define sithUnk3_GetSectorLookAt_ADDR (0x004E71B0)
#define sithUnk3_sub_4E7310_ADDR (0x004E7310)
#define sithUnk3_sub_4E73F0_ADDR (0x004E73F0)
#define sithUnk3_HasLos_ADDR (0x004E7500)
#define sithUnk3_sub_4E7670_ADDR (0x004E7670)
#define sithUnk3_sub_4E77A0_ADDR (0x004E77A0)
#define sithUnk3_UpdateThingCollision_ADDR (0x004E7950)
#define sithUnk3_SearchRadiusForThings_ADDR (0x004E8160)
#define sithUnk3_SearchClose_ADDR (0x004E8420)
#define sithUnk3_UpdateSectorThingCollision_ADDR (0x004E8430)
#define sithUnk3_sub_4E86D0_ADDR (0x004E86D0)
#define sithUnk3_DefaultHitHandler_ADDR (0x004E8B40)
#define sithUnk3_DebrisDebrisCollide_ADDR (0x004E8C50)
#define sithUnk3_sub_4E9090_ADDR (0x004E9090)
#define sithUnk3_FallHurt_ADDR (0x004E9550)
#define sithUnk3_DebrisPlayerCollide_ADDR (0x004E95A0)

#define sithUnk3_stackIdk ((int*)0x847F28)
#define sithUnk3_collisionHandlers ((sithUnk3Entry*)0x00847F38)
#define sithUnk3_funcList ((void**)0x8485F8)
#define sithUnk3_searchStack ((sithUnk3SearchResult*)0x00848628)
#define sithUnk3_searchNumResults ((int*)0x84DA28)
#define sithUnk3_searchStackIdx (*(int*)0x54BA90)
#define sithUnk3_stackSectors ((sithUnk3SectorEntry*)0x0084D628) // 4

typedef int (*sithUnk3_collisionHandler_t)(sithThing*, sithThing*);

typedef struct sithUnk3Entry
{
    sithUnk3_collisionHandler_t handler;
    sithUnk3_collisionHandler_t search_handler;
    uint32_t inverse;
} sithUnk3Entry;

typedef struct sithUnk3SearchEntry
{
    uint32_t collideType;
    sithThing* receiver;
    sithSurface* surface;
    rdFace* face;
    rdMesh* sender;
    rdVector3 field_14;
    float distance;
    uint32_t hasBeenEnumerated;
} sithUnk3SearchEntry;

typedef struct sithUnk3SectorEntry
{
    sithSector* sectors[64];
} sithUnk3SectorEntry;

typedef struct sithUnk3SearchResult
{
    sithUnk3SearchEntry collisions[128];
} sithUnk3SearchResult;

int sithUnk3_Startup();
static void (*sithUnk3_Shutdown)() = (void*)sithUnk3_Shutdown_ADDR;
void sithUnk3_RegisterCollisionHandler(int idxA, int idxB, void* func, void* a4);
void sithUnk3_RegisterHitHandler(int thingType, void* a2);
#if 1
sithUnk3SearchEntry* sithUnk3_NextSearchResult();
float sithUnk3_SearchRadiusForThings(sithSector *sector, sithThing *a2, const rdVector3 *position, const rdVector3 *direction, float a5, float range, int flags);
float sithUnk3_UpdateSectorThingCollision(sithSector *a1, sithThing *sender, const rdVector3 *a2, const rdVector3 *a3, float a4, float range, int flags);
void sithUnk3_sub_4E86D0(sithSector *a1, const rdVector3 *a2, const rdVector3 *a3, float a4, float a5, int unk3Flags);
sithSector* sithUnk3_GetSectorLookAt(sithSector *sector, const rdVector3 *a3, rdVector3 *a4, float a5);
#endif

#if 0
static int (*_sithUnk3_Startup)() = (void*)sithUnk3_Startup_ADDR;
static sithUnk3SearchEntry* (*sithUnk3_NextSearchResult)(void) = (void*)sithUnk3_NextSearchResult_ADDR;
static float (*sithUnk3_SearchRadiusForThings)(sithSector *sector, sithThing *a2, rdVector3 *position, const rdVector3 *direction, float a5, float range, int flags) = (void*)sithUnk3_SearchRadiusForThings_ADDR;
static float (*sithUnk3_UpdateSectorThingCollision)(sithSector *a1, sithThing *sender, rdVector3 *a2, rdVector3 *a3, float a4, float range, int flags) = (void*)sithUnk3_UpdateSectorThingCollision_ADDR;
static void (*sithUnk3_sub_4E86D0)(sithSector *a1, rdVector3 *a2, rdVector3 *a3, float a4, float a5, int a6) = (void*)sithUnk3_sub_4E86D0_ADDR;
static sithSector* (*sithUnk3_GetSectorLookAt)(sithSector *sector, rdVector3 *a3, rdVector3 *a4, float a5) = (void*)sithUnk3_GetSectorLookAt_ADDR;
#endif

static void (*sithUnk3_sub_4E7670)(sithThing *a1, rdMatrix34 *a2) = (void*)sithUnk3_sub_4E7670_ADDR;
static void (*sithUnk3_SearchClose)(void) = (void*)sithUnk3_SearchClose_ADDR;
static int (*sithUnk3_DebrisDebrisCollide)(sithThing *arg0, sithThing *a1, rdMatrix34 *a3, int a4) = (void*)sithUnk3_DebrisDebrisCollide_ADDR;
static int (*sithUnk3_DebrisPlayerCollide)(sithThing *thing, sithThing *a1, rdMatrix34 *a3, int a4) = (void*)sithUnk3_DebrisPlayerCollide_ADDR;
static int (*sithUnk3_HasLos)(sithThing *a1, sithThing *a2, int flag) = (void*)sithUnk3_HasLos_ADDR;
static float (*sithUnk3_UpdateThingCollision)(sithThing *a3, rdVector3 *a2, float a6, int a8) = (void*)sithUnk3_UpdateThingCollision_ADDR;
static int (*sithUnk3_DefaultHitHandler)(sithThing *thing, sithSurface *surface, sithUnk3SearchEntry *a3) = (void*)sithUnk3_DefaultHitHandler_ADDR;


#endif // _SITHUNK3_H
