#ifndef _SITHAI_H
#define _SITHAI_H

#include <stdint.h>
#include "types.h"
#include "globals.h"

#include "World/sithThing.h" // sithActor struct def

#define sithAI_Startup_ADDR (0x004E9AA0)
#define sithAI_Shutdown_ADDR (0x004E9B90)
#define sithAI_Open_ADDR (0x004E9BD0)
#define sithAI_Close_ADDR (0x004E9C00)
#define sithAI_NewEntry_ADDR (0x004E9CB0)
#define sithAI_FreeEntry_ADDR (0x004E9D80)
#define sithAI_TickAll_ADDR (0x004E9E20)
#define sithAI_TickActor_ADDR (0x004E9E90)
#define sithAI_SetActorFireTarget_ADDR (0x004E9F80)
#define sithAI_RegisterCommand_ADDR (0x004EA0A0)
#define sithAI_FindCommand_ADDR (0x004EA110)
#define sithAI_PrintThings_ADDR (0x004EA190)
#define sithAI_PrintThingStatus_ADDR (0x004EA230)
#define sithAI_LoadThingActorParams_ADDR (0x004EA3F0)
#define sithAI_idkframesalloc_ADDR (0x004EA520)
#define sithAI_Tick_ADDR (0x004EA5E0)
#define sithAI_sub_4EA630_ADDR (0x004EA630)
#define sithAI_idk_msgarrived_target_ADDR (0x004EA890)
#define sithAI_SetLookFrame_ADDR (0x004EAB80)
#define sithAI_SetMoveThing_ADDR (0x004EAC90)
#define sithAI_Jump_ADDR (0x004EACF0)
#define sithAI_sub_4EAD60_ADDR (0x004EAD60)
#define sithAI_sub_4EAF40_ADDR (0x004EAF40)
#define sithAI_CheckSightThing_ADDR (0x004EB090)
#define sithAI_sub_4EB300_ADDR (0x004EB300)
#define sithAI_CanWalk_ADDR (0x004EB4B0)
#define sithAI_CanWalk_ExplicitSector_ADDR (0x004EB640)
#define sithAI_FirstThingInView_ADDR (0x004EB790)
#define sithAI_sub_4EB860_ADDR (0x004EB860)
#define sithAI_SetRandomThingLook_ADDR (0x004EB880)
#define sithAI_RandomFireVector_ADDR (0x004EB920)
#define sithAI_RandomRotationVector_ADDR (0x004EB9A0)
#define sithAI_FireWeapon_ADDR (0x004EBA10)
#define sithAI_GetThingsInView_ADDR (0x004EBE80)
#define sithAI_CanDetectSightThing_ADDR (0x004EC140)

extern int sithAI_bOpened;
extern sithActor sithAI_actors[256];
extern int sithAI_inittedActors;
extern sithAIAlign sithAI_aAlignments[10];
extern flex_t sithAI_FLOAT_005a79d8;
extern sithThing* sithAI_pDistractor;

int sithAI_Startup();
void sithAI_Shutdown();
int sithAI_Open();
void sithAI_Close();
void sithAI_NewEntry(sithThing *thing);
void sithAI_FreeEntry(sithThing *thing);
void sithAI_TickAll();
void sithAI_TickActor(sithActor *actor);
void sithAI_SetActorFireTarget(sithActor *actor, int a2, intptr_t a3);
void sithAI_RegisterCommand(const char *cmdName, sithAICommandFunc_t func, int param1, int param2, int param3);
sithAICommand* sithAI_FindCommand(const char *cmdName);
int sithAI_PrintThings(stdDebugConsoleCmd* a, const char* b);
int sithAI_PrintThingStatus(stdDebugConsoleCmd* a1, const char *idxStr);
int sithAI_LoadThingActorParams(stdConffileArg *arg, sithThing *thing, int param);
void sithAI_idkframesalloc(sithThing *a2, sithThing *a3, rdVector3 *a4);
void sithAI_Tick(sithThing *thing, flex_t deltaSeconds);
MATH_FUNC void sithAI_sub_4EA630(sithActor *actor, flex_t deltaSeconds);
MATH_FUNC void sithAI_idk_msgarrived_target(sithActor *actor, flex_t deltaSeconds);
void sithAI_SetLookFrame(sithActor *actor, rdVector3 *lookPos);
void sithAI_SetMoveThing(sithActor *actor, rdVector3 *movePos, flex_t moveSpeed);
void sithAI_Jump(sithActor *actor, rdVector3 *pos, flex_t vel);
void sithAI_sub_4EAD60(sithActor *actor);
void sithAI_sub_4EAF40(sithActor *actor);
int sithAI_CheckSightThing(sithThing* thing, rdVector3* targetPosition, sithThing* targetThing, flex_t fov, flex_t maxDistance, flex_t unused, rdVector3* targetErrorDir, flex_t* targetDistance);
int sithAI_sub_4EB300(sithThing *a3, rdVector3 *a4, rdVector3 *arg8, flex_t argC, flex_t arg10, flex_t a7, rdVector3 *a5, flex_t *a8);
int sithAI_CanWalk(sithActor* actor, rdVector3* targetPosition, int* out);
int sithAI_CanWalk_ExplicitSector(sithActor* actor, rdVector3* targetPosition, sithSector* targetSector, int* out);
int sithAI_FirstThingInView(sithSector *sector, rdMatrix34 *out, flex_t autoaimFov, flex_t autoaimMaxDist, int a5, sithThing **thingList, int a7, flex_t a8);
int sithAI_sub_4EB860(int a1, flex_t a2);
void sithAI_SetRandomThingLook(rdMatrix34 *a1, sithThing *a2, rdVector3 *a3, flex_t a4);
MATH_FUNC void sithAI_RandomFireVector(rdVector3 *out, flex_t magnitude);
MATH_FUNC void sithAI_RandomRotationVector(rdVector3 *out);
MATH_FUNC int sithAI_FireWeapon(sithActor *actor, flex_t a2, flex_t a3, flex_t a4, flex_t a5, int bAltFire, int a7);
void sithAI_GetThingsInView(sithSector *a1, rdMatrix34 *a2, flex_t a3);
MATH_FUNC int sithAI_CanDetectSightThing(sithActor* actor, sithThing* targetThing, flex_t distance);

void sithAI_SetDistractor(sithThing *pDistractor);
void sithAI_AddAlignmentPriority(flex_t param_1);
int sithAI_FirstThingInCone(sithSector *sector, rdMatrix34 *out, flex_t autoaimFov, flex_t autoaimMaxDist, int a5, sithThing **thingList, int a7, flex_t a8);
MATH_FUNC int sithAI_FUN_0053a520(sithActor *pActor,flex_t param_2,flex_t param_3,flex_t param_4,int param_5,
                       flex_t param_6,uint32_t param_7);
MATH_FUNC int sithAI_Leap(sithActor *pActor,flex_t minDist,flex_t maxDist,flex_t minDot,int param_5,
                       flex_t param_6,uint32_t param_7);
MATH_FUNC sithThing* sithAI_FUN_00539a60(sithActor *pThing);

//static int (*sithAI_Startup)() = (void*)sithAI_Startup_ADDR;
//static int (*sithAI_LoadThingActorParams)(stdConffileArg *arg, sithThing *thing, int param) = (void*)sithAI_LoadThingActorParams_ADDR;
//static void (*sithAI_FreeEntry)(sithThing *thing) = (void*)sithAI_FreeEntry_ADDR;
//static void (*sithAI_Tick)(sithThing *thing, flex_t deltaSeconds) = (void*)sithAI_Tick_ADDR;
//static void (*sithAI_TickActor)(sithActor *actor) = (void*)sithAI_TickActor_ADDR;
//static void (*sithAI_TickAll)() = (void*)sithAI_TickAll_ADDR;
//static void (*sithAI_SetActorFireTarget)(sithActor *a1, int a2, int a3) = (void*)sithAI_SetActorFireTarget_ADDR;
//static int (*sithAI_FirstThingInView)(sithSector *a1, rdMatrix34 *a2, flex_t a3, flex_t a4, int a5, sithThing **a6, int a7, flex_t a8) = (void*)sithAI_FirstThingInView_ADDR;

//static int (*sithAI_FireWeapon)(sithActor *a1, flex_t a2, flex_t a3, flex_t a4, flex_t a5, int a6, int a7) = (void*)sithAI_FireWeapon_ADDR;
//static int (*sithAI_SetMoveThing)(sithActor *actor, rdVector3 *movePos, flex_t moveSpeed) = (void*)sithAI_SetMoveThing_ADDR;
//static void (*sithAI_Jump)(sithActor *actor, rdVector3 *a2, flex_t a3) = (void*)sithAI_Jump_ADDR;
//static void (*sithAI_SetLookFrame)(sithActor *actor, rdVector3 *lookPos) = (void*)sithAI_SetLookFrame_ADDR;

//static void (*sithAI_sub_4EA630)(sithActor *actor, flex_t deltaSeconds) = (void*)sithAI_sub_4EA630_ADDR;
//static void (*sithAI_sub_4EAF40)(sithActor *a1) = (void*)sithAI_sub_4EAF40_ADDR;
//static int (*sithAI_sub_4EB300)(sithThing *a3, rdVector3 *a4, rdVector3 *arg8, flex_t argC, flex_t arg10, flex_t a7, rdVector3 *a5, flex_t *a8) = (void*)sithAI_sub_4EB300_ADDR;
//static void (*sithAI_idk_msgarrived_target)(sithActor *actor, flex_t deltaSeconds) = (void*)sithAI_idk_msgarrived_target_ADDR;
//static void (*sithAI_sub_4EAD60)(sithActor *actor) = (void*)sithAI_sub_4EAD60_ADDR;
//static int (*sithAI_CanWalk)(sithActor *a7, rdVector3 *a4, int *arg8) = (void*)sithAI_CanWalk_ADDR;
//static int (*sithAI_CanWalk_ExplicitSector)(sithActor *arg0, rdVector3 *a4, sithSector *a2, int *argC) = (void*)sithAI_CanWalk_ExplicitSector_ADDR;
//static int (*sithAI_CheckSightThing)(sithThing* thing, rdVector3* targetPosition, sithThing* targetThing, flex_t fov, flex_t maxDistance, flex_t unused, rdVector3* targetErrorDir, flex_t* targetDistance) = (void*)sithAI_CheckSightThing_ADDR;

#endif // _SITHAI_H
