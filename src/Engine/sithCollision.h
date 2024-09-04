#ifndef _SITHUNK3_H
#define _SITHUNK3_H

#include "types.h"
#include "globals.h"

#define sithCollision_Startup_ADDR (0x004E6D90)
#define sithCollision_Shutdown_ADDR (0x004E6F20)
#define sithCollision_RegisterCollisionHandler_ADDR (0x004E6F40)
#define sithCollision_RegisterHitHandler_ADDR (0x004E6FA0)
#define sithCollision_sub_4E6FB0_ADDR (0x004E6FB0)
#define sithCollision_NextSearchResult_ADDR (0x004E7120)
#define sithCollision_GetSectorLookAt_ADDR (0x004E71B0)
#define sithCollision_sub_4E7310_ADDR (0x004E7310)
#define sithCollision_sub_4E73F0_ADDR (0x004E73F0)
#define sithCollision_HasLos_ADDR (0x004E7500)
#define sithCollision_sub_4E7670_ADDR (0x004E7670)
#define sithCollision_sub_4E77A0_ADDR (0x004E77A0)
#define sithCollision_UpdateThingCollision_ADDR (0x004E7950)
#define sithCollision_SearchRadiusForThings_ADDR (0x004E8160)
#define sithCollision_SearchClose_ADDR (0x004E8420)
#define sithCollision_UpdateSectorThingCollision_ADDR (0x004E8430)
#define sithCollision_BuildCollisionList_ADDR (0x004E86D0)
#define sithCollision_DefaultHitHandler_ADDR (0x004E8B40)
#define sithCollision_DebrisDebrisCollide_ADDR (0x004E8C50)
#define sithCollision_CollideHurt_ADDR (0x004E9090)
#define sithCollision_FallHurt_ADDR (0x004E9550)
#define sithCollision_DebrisPlayerCollide_ADDR (0x004E95A0)

int sithCollision_Startup();
int sithCollision_Shutdown();
void sithCollision_RegisterCollisionHandler(int idxA, int idxB, void* func, void* a4);
void sithCollision_RegisterHitHandler(int type, void* a2);
#if 1
sithCollisionSearchEntry* sithCollision_NextSearchResult();
float sithCollision_SearchRadiusForThings(sithSector* pStartSector, sithThing* pThing, const rdVector3* pStartPos, const rdVector3* pMoveNorm, float moveDist, float radius, int flags);
void sithCollision_SearchClose();
float sithCollision_UpdateSectorThingCollision(sithSector *a1, sithThing *sender, const rdVector3 *a2, const rdVector3 *a3, float a4, float range, int flags);
void sithCollision_BuildCollisionList(sithSector *a1, const rdVector3 *a2, const rdVector3 *a3, float a4, float a5, int unk3Flags);
sithSector* sithCollision_GetSectorLookAt(sithSector *sector, const rdVector3 *a3, rdVector3 *a4, float a5);
#endif
void sithCollision_FallHurt(sithThing *thing, float vel);
void sithCollision_sub_4E7670(sithThing *thing, rdMatrix34 *orient);
float sithCollision_UpdateThingCollision(sithThing* pThing, rdVector3* a2, float a6, int flags);
int sithCollision_DefaultHitHandler(sithThing *thing, sithSurface *surface, sithCollisionSearchEntry *a3);
int sithCollision_DebrisDebrisCollide(sithThing *thing1, sithThing *thing2, sithCollisionSearchEntry *a3, int isInverse);
int sithCollision_CollideHurt(sithThing *a1, rdVector3 *a2, float a3, int a4);
int sithCollision_HasLos(sithThing *thing1, sithThing *thing2, int flag);
void sithCollision_sub_4E77A0(sithThing *thing, rdMatrix34 *a2);
int sithCollision_DebrisPlayerCollide(sithThing *thing, sithThing *thing2, sithCollisionSearchEntry *searchEnt, int isSolid);

#if 0
static int (*_sithCollision_Startup)() = (void*)sithCollision_Startup_ADDR;
static sithCollisionSearchEntry* (*sithCollision_NextSearchResult)(void) = (void*)sithCollision_NextSearchResult_ADDR;
static float (*sithCollision_SearchRadiusForThings)(sithSector *sector, sithThing *a2, rdVector3 *position, const rdVector3 *direction, float a5, float range, int flags) = (void*)sithCollision_SearchRadiusForThings_ADDR;
static float (*sithCollision_UpdateSectorThingCollision)(sithSector *a1, sithThing *sender, rdVector3 *a2, rdVector3 *a3, float a4, float range, int flags) = (void*)sithCollision_UpdateSectorThingCollision_ADDR;
static void (*sithCollision_BuildCollisionList)(sithSector *a1, rdVector3 *a2, rdVector3 *a3, float a4, float a5, int a6) = (void*)sithCollision_BuildCollisionList_ADDR;
static sithSector* (*sithCollision_GetSectorLookAt)(sithSector *sector, rdVector3 *a3, rdVector3 *a4, float a5) = (void*)sithCollision_GetSectorLookAt_ADDR;
#endif

//static void (*sithCollision_sub_4E7670)(sithThing *a1, rdMatrix34 *a2) = (void*)sithCollision_sub_4E7670_ADDR;
//static void (*sithCollision_SearchClose)(void) = (void*)sithCollision_SearchClose_ADDR;
//static int (*sithCollision_DebrisDebrisCollide)(sithThing *arg0, sithThing *a1, rdMatrix34 *a3, int a4) = (void*)sithCollision_DebrisDebrisCollide_ADDR;
//static int (*sithCollision_DebrisPlayerCollide)(sithThing *thing, sithThing *a1, rdMatrix34 *a3, int a4) = (void*)sithCollision_DebrisPlayerCollide_ADDR;
//static int (*sithCollision_HasLos)(sithThing *a1, sithThing *a2, int flag) = (void*)sithCollision_HasLos_ADDR;
//static float (*sithCollision_UpdateThingCollision)(sithThing *a3, rdVector3 *a2, float a6, int a8) = (void*)sithCollision_UpdateThingCollision_ADDR;
//static int (*sithCollision_DefaultHitHandler)(sithThing *thing, sithSurface *surface, sithCollisionSearchEntry *a3) = (void*)sithCollision_DefaultHitHandler_ADDR;
//static int (*sithCollision_CollideHurt)(sithThing *a1, rdVector3 *a2, float a3, int a4) = (void*)sithCollision_CollideHurt_ADDR;


#endif // _SITHUNK3_H
