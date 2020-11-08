#ifndef _SITHUNK3_H
#define _SITHUNK3_H

typedef struct sithThing sithThing;
typedef struct sithSurface sithSurface;
typedef struct sithSector sithSector;

#define sithUnk3_Startup_ADDR (0x004E6D90)
#define sithUnk3_Shutdown_ADDR (0x004E6F20)
#define sithUnk3_registerCollisionHandler_ADDR (0x004E6F40)
#define sithUnk3_sub_4E6FA0_ADDR (0x004E6FA0)
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
#define sithUnk3_sub_4E8B40_ADDR (0x004E8B40)
#define sithUnk3_DebrisDebrisCollide_ADDR (0x004E8C50)
#define sithUnk3_sub_4E9090_ADDR (0x004E9090)
#define sithUnk3_FallHurt_ADDR (0x004E9550)
#define sithUnk3_DebrisPlayerCollide_ADDR (0x004E95A0)

typedef struct sithUnk3Entry
{
    uint32_t field_0;
    uint32_t field_4;
    uint32_t field_8;
} sithUnk3Entry;

typedef struct sithUnk3SearchEntry
{
    uint32_t collideType;
    sithThing* receiver;
    sithSurface* surface;
    uint32_t field_C;
    sithThing* sender;
    rdVector3 field_14;
    float distance;
    uint32_t field_24;
} sithUnk3SearchEntry;

typedef struct sithUnk3SearchResult
{
    sithUnk3SearchEntry collisions[128];
} sithUnk3SearchResult;

static sithSector* (*sithUnk3_GetSectorLookAt)(sithSector *sector, rdVector3 *a3, rdVector3 *a4, float a5) = (void*)sithUnk3_GetSectorLookAt_ADDR;
static void (*sithUnk3_SearchClose)(void) = (void*)sithUnk3_SearchClose_ADDR;
static void (*sithUnk3_SearchRadiusForThings)(sithSector *sector, sithThing *a2, rdVector3 *position, rdVector3 *direction, float a5, float range, int flags) = (void*)sithUnk3_SearchRadiusForThings_ADDR;
static sithUnk3SearchEntry* (*sithUnk3_NextSearchResult)(void) = (void*)sithUnk3_NextSearchResult_ADDR;

#endif // _SITHUNK3_H
