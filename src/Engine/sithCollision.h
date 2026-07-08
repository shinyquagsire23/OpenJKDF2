#ifndef _SITHUNK3_H
#define _SITHUNK3_H

#include "types.h"
#include "globals.h"

#define sithCollision_Startup_ADDR (0x004E6D90)
#define sithCollision_Shutdown_ADDR (0x004E6F20)
#define sithCollision_AddCollisionHandler_ADDR (0x004E6F40)
#define sithCollision_AddSurfaceCollisionHandler_ADDR (0x004E6FA0)
#define sithCollision_sub_4E6FB0_ADDR (0x004E6FB0)
#define sithCollision_PopStack_ADDR (0x004E7120)
#define sithCollision_FindSectorInRadius_ADDR (0x004E71B0)
#define sithCollision_sub_4E7310_ADDR (0x004E7310)
#define sithCollision_sub_4E73F0_ADDR (0x004E73F0)
#define sithCollision_HasLOS_ADDR (0x004E7500)
#define sithCollision_RotateThing_ADDR (0x004E7670)
#define sithCollision_sub_4E77A0_ADDR (0x004E77A0)
#define sithCollision_MoveThing_ADDR (0x004E7950)
#define sithCollision_SearchForCollisions_ADDR (0x004E8160)
#define sithCollision_DecreaseStackLevel_ADDR (0x004E8420)
#define sithCollision_SearchForThingCollisions_ADDR (0x004E8430)
#define sithCollision_SearchForSurfaceCollisions_ADDR (0x004E86D0)
#define sithCollision_HandleThingHitSurface_ADDR (0x004E8B40)
#define sithCollision_ThingCollisionHandler_ADDR (0x004E8C50)
#define sithCollision_CollideHurt_ADDR (0x004E9090)
#define sithCollision_FallHurt_ADDR (0x004E9550)
#define sithCollision_ParticleAndActorCollisionHandler_ADDR (0x004E95A0)

int sithCollision_Startup();
int sithCollision_Shutdown();
void sithCollision_AddCollisionHandler(int idxA, int idxB, sithCollision_collisionHandler_t func, sithCollision_searchHandler_t a4);
void sithCollision_AddSurfaceCollisionHandler(int type, sithCollisionHitHandler_t a2);
#if 1
MATH_FUNC sithCollisionSearchEntry* sithCollision_PopStack();
MATH_FUNC flex_t sithCollision_SearchForCollisions(sithSector* pStartSector, sithThing* pThing, const rdVector3* pStartPos, const rdVector3* pMoveNorm, flex_t moveDist, flex_t radius, int flags);
MATH_FUNC void sithCollision_DecreaseStackLevel();
MATH_FUNC flex_t sithCollision_SearchForThingCollisions(sithSector *a1, sithThing *sender, const rdVector3 *a2, const rdVector3 *a3, flex_t a4, flex_t range, int flags);
MATH_FUNC void sithCollision_SearchForSurfaceCollisions(sithSector *a1, const rdVector3 *a2, const rdVector3 *a3, flex_t a4, flex_t a5, int raycastFlags);
MATH_FUNC sithSector* sithCollision_FindSectorInRadius(sithSector *sector, const rdVector3 *a3, rdVector3 *a4, flex_t a5);
#endif
MATH_FUNC void sithCollision_FallHurt(sithThing *thing, flex_t vel);
MATH_FUNC void sithCollision_RotateThing(sithThing *thing, rdMatrix34 *orient);
MATH_FUNC flex_t sithCollision_MoveThing(sithThing* pThing, rdVector3* a2, flex_t a6, int flags);
MATH_FUNC int sithCollision_HandleThingHitSurface(sithThing *thing, sithSurface *surface, sithCollisionSearchEntry *a3);
MATH_FUNC int sithCollision_ThingCollisionHandler(sithThing *thing1, sithThing *thing2, sithCollisionSearchEntry *a3, int isInverse);
MATH_FUNC int sithCollision_CollideHurt(sithThing *a1, rdVector3 *a2, flex_t a3, int a4);
MATH_FUNC int sithCollision_HasLOS(sithThing *thing1, sithThing *thing2, int flag);
MATH_FUNC void sithCollision_sub_4E77A0(sithThing *thing, rdMatrix34 *a2);
MATH_FUNC int sithCollision_ParticleAndActorCollisionHandler(sithThing *thing, sithThing *thing2, sithCollisionSearchEntry *searchEnt, int isSolid);
sithThing* sithCollision_RaycastFromCamera(rdVector3 *pos);
sithThing* sithCollision_RaycastSector(sithSector *sector, rdVector3 *startPos, rdVector3 *dir, flex_t dist, flex_t radius, uint32_t *pHitType);
int sithCollision_CheckPathClear(sithSector *sector, rdVector3 *startPos, rdVector3 *endPos, flex_t radius);

#if 0
static int (*_sithCollision_Startup)() = (void*)sithCollision_Startup_ADDR;
static sithCollisionSearchEntry* (*sithCollision_PopStack)(void) = (void*)sithCollision_PopStack_ADDR;
static flex_t (*sithCollision_SearchForCollisions)(sithSector *sector, sithThing *a2, rdVector3 *position, const rdVector3 *direction, flex_t a5, flex_t range, int flags) = (void*)sithCollision_SearchForCollisions_ADDR;
static flex_t (*sithCollision_SearchForThingCollisions)(sithSector *a1, sithThing *sender, rdVector3 *a2, rdVector3 *a3, flex_t a4, flex_t range, int flags) = (void*)sithCollision_SearchForThingCollisions_ADDR;
static void (*sithCollision_SearchForSurfaceCollisions)(sithSector *a1, rdVector3 *a2, rdVector3 *a3, flex_t a4, flex_t a5, int raycastFlags) = (void*)sithCollision_SearchForSurfaceCollisions_ADDR;
static sithSector* (*sithCollision_FindSectorInRadius)(sithSector *sector, rdVector3 *a3, rdVector3 *a4, flex_t a5) = (void*)sithCollision_FindSectorInRadius_ADDR;
#endif

//static void (*sithCollision_RotateThing)(sithThing *a1, rdMatrix34 *a2) = (void*)sithCollision_RotateThing_ADDR;
//static void (*sithCollision_DecreaseStackLevel)(void) = (void*)sithCollision_DecreaseStackLevel_ADDR;
//static int (*sithCollision_ThingCollisionHandler)(sithThing *arg0, sithThing *a1, rdMatrix34 *a3, int a4) = (void*)sithCollision_ThingCollisionHandler_ADDR;
//static int (*sithCollision_ParticleAndActorCollisionHandler)(sithThing *thing, sithThing *a1, rdMatrix34 *a3, int a4) = (void*)sithCollision_ParticleAndActorCollisionHandler_ADDR;
//static int (*sithCollision_HasLOS)(sithThing *a1, sithThing *a2, int flag) = (void*)sithCollision_HasLOS_ADDR;
//static flex_t (*sithCollision_MoveThing)(sithThing *a3, rdVector3 *a2, flex_t a6, int a8) = (void*)sithCollision_MoveThing_ADDR;
//static int (*sithCollision_HandleThingHitSurface)(sithThing *thing, sithSurface *surface, sithCollisionSearchEntry *a3) = (void*)sithCollision_HandleThingHitSurface_ADDR;
//static int (*sithCollision_CollideHurt)(sithThing *a1, rdVector3 *a2, flex_t a3, int a4) = (void*)sithCollision_CollideHurt_ADDR;


#endif // _SITHUNK3_H
