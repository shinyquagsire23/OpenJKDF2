#ifndef _SITHAI_H
#define _SITHAI_H

#include <stdint.h>
#include "types.h"
#include "globals.h"

#include "World/sithThing.h" // SithAIControlBlock struct def

#define sithAI_Startup_ADDR (0x004E9AA0)
#define sithAI_Shutdown_ADDR (0x004E9B90)
#define sithAI_Open_ADDR (0x004E9BD0)
#define sithAI_Close_ADDR (0x004E9C00)
#define sithAI_Create_ADDR (0x004E9CB0)
#define sithAI_Free_ADDR (0x004E9D80)
#define sithAI_Process_ADDR (0x004E9E20)
#define sithAI_InstinctUpdate_ADDR (0x004E9E90)
#define sithAI_EmitEvent_ADDR (0x004E9F80)
#define sithAI_RegisterInstinct_ADDR (0x004EA0A0)
#define sithAI_FindInstinct_ADDR (0x004EA110)
#define sithAI_AIList_ADDR (0x004EA190)
#define sithAI_AIStatus_ADDR (0x004EA230)
#define sithAI_ParseArg_ADDR (0x004EA3F0)
#define sithAI_CreateAIFramesFomMarker_ADDR (0x004EA520)
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
#ifdef TARGET_TWL
extern SithAIControlBlock* sithAI_actors; // Added: heap'd (extram); see sithAI.c
#else
extern SithAIControlBlock sithAI_actors[SITHAI_MAX_ACTORS];
#endif
extern int sithAI_inittedActors;
extern sithAIAlign sithAI_aAlignments[10];
extern flex_t sithAI_FLOAT_005a79d8;
extern SithThing* sithAI_pDistractor;

int sithAI_Startup();
void sithAI_Shutdown();
int sithAI_Open();
void sithAI_Close();
void sithAI_Create(SithThing *thing);
void sithAI_Free(SithThing *thing);
void sithAI_Process();
void sithAI_InstinctUpdate(SithAIControlBlock *actor);
void sithAI_EmitEvent(SithAIControlBlock *actor, int a2, intptr_t a3);
void sithAI_RegisterInstinct(const char *cmdName, sithAICommandFunc_t func, int param1, int param2, int param3);
SithAIRegisteredInstinct* sithAI_FindInstinct(const char *cmdName);
int sithAI_AIList(stdDebugConsoleCmd* a, const char* b);
int sithAI_AIStatus(stdDebugConsoleCmd* a1, const char *idxStr);
int sithAI_ParseArg(stdConffileArg *arg, SithThing *thing, int param);
void sithAI_CreateAIFramesFomMarker(SithThing *a2, SithThing *a3, rdVector3 *a4);
void sithAI_Tick(SithThing *thing, flex_t deltaSeconds);
MATH_FUNC void sithAI_sub_4EA630(SithAIControlBlock *actor, flex_t deltaSeconds);
MATH_FUNC void sithAI_idk_msgarrived_target(SithAIControlBlock *actor, flex_t deltaSeconds);
void sithAI_SetLookFrame(SithAIControlBlock *actor, rdVector3 *lookPos);
void sithAI_SetMoveThing(SithAIControlBlock *actor, rdVector3 *movePos, flex_t moveSpeed);
void sithAI_Jump(SithAIControlBlock *actor, rdVector3 *pos, flex_t vel);
void sithAI_sub_4EAD60(SithAIControlBlock *actor);
void sithAI_sub_4EAF40(SithAIControlBlock *actor);
int sithAI_CheckSightThing(SithThing* thing, rdVector3* targetPosition, SithThing* targetThing, flex_t fov, flex_t maxDistance, flex_t unused, rdVector3* targetErrorDir, flex_t* targetDistance);
int sithAI_sub_4EB300(SithThing *a3, rdVector3 *a4, rdVector3 *arg8, flex_t argC, flex_t arg10, flex_t a7, rdVector3 *a5, flex_t *a8);
int sithAI_CanWalk(SithAIControlBlock* actor, rdVector3* targetPosition, int* out);
int sithAI_CanWalk_ExplicitSector(SithAIControlBlock* actor, rdVector3* targetPosition, SithSector* targetSector, int* out);
int sithAI_FirstThingInView(SithSector *sector, rdMatrix34 *out, flex_t autoaimFov, flex_t autoaimMaxDist, int a5, SithThing **thingList, int a7, flex_t a8);
int sithAI_sub_4EB860(int a1, flex_t a2);
void sithAI_SetRandomThingLook(rdMatrix34 *a1, SithThing *a2, rdVector3 *a3, flex_t a4);
MATH_FUNC void sithAI_RandomFireVector(rdVector3 *out, flex_t magnitude);
MATH_FUNC void sithAI_RandomRotationVector(rdVector3 *out);
MATH_FUNC int sithAI_FireWeapon(SithAIControlBlock *actor, flex_t a2, flex_t a3, flex_t a4, flex_t a5, int bAltFire, int a7);
void sithAI_GetThingsInView(SithSector *a1, rdMatrix34 *a2, flex_t a3);
MATH_FUNC int sithAI_CanDetectSightThing(SithAIControlBlock* actor, SithThing* targetThing, flex_t distance);

void sithAI_SetDistractor(SithThing *pDistractor);
void sithAI_AddAlignmentPriority(flex_t param_1);
int sithAI_FirstThingInCone(SithSector *sector, rdMatrix34 *out, flex_t autoaimFov, flex_t autoaimMaxDist, int a5, SithThing **thingList, int a7, flex_t a8);
MATH_FUNC int sithAI_Charge(SithAIControlBlock *pActor,flex_t param_2,flex_t param_3,flex_t param_4,int param_5,
                       flex_t param_6,uint32_t param_7);
MATH_FUNC int sithAI_Leap(SithAIControlBlock *pActor,flex_t minDist,flex_t maxDist,flex_t minDot,int param_5,
                       flex_t leapSpeed,uint32_t param_7);
MATH_FUNC SithThing* sithAI_FUN_00539a60(SithAIControlBlock *pThing);

//static int (*sithAI_Startup)() = (void*)sithAI_Startup_ADDR;
//static int (*sithAI_ParseArg)(stdConffileArg *arg, SithThing *thing, int param) = (void*)sithAI_ParseArg_ADDR;
//static void (*sithAI_Free)(SithThing *thing) = (void*)sithAI_Free_ADDR;
//static void (*sithAI_Tick)(SithThing *thing, flex_t deltaSeconds) = (void*)sithAI_Tick_ADDR;
//static void (*sithAI_InstinctUpdate)(SithAIControlBlock *actor) = (void*)sithAI_InstinctUpdate_ADDR;
//static void (*sithAI_Process)() = (void*)sithAI_Process_ADDR;
//static void (*sithAI_EmitEvent)(SithAIControlBlock *a1, int a2, int a3) = (void*)sithAI_EmitEvent_ADDR;
//static int (*sithAI_FirstThingInView)(SithSector *a1, rdMatrix34 *a2, flex_t a3, flex_t a4, int a5, SithThing **a6, int a7, flex_t a8) = (void*)sithAI_FirstThingInView_ADDR;

//static int (*sithAI_FireWeapon)(SithAIControlBlock *a1, flex_t a2, flex_t a3, flex_t a4, flex_t a5, int a6, int a7) = (void*)sithAI_FireWeapon_ADDR;
//static int (*sithAI_SetMoveThing)(SithAIControlBlock *actor, rdVector3 *movePos, flex_t moveSpeed) = (void*)sithAI_SetMoveThing_ADDR;
//static void (*sithAI_Jump)(SithAIControlBlock *actor, rdVector3 *a2, flex_t a3) = (void*)sithAI_Jump_ADDR;
//static void (*sithAI_SetLookFrame)(SithAIControlBlock *actor, rdVector3 *lookPos) = (void*)sithAI_SetLookFrame_ADDR;

//static void (*sithAI_sub_4EA630)(SithAIControlBlock *actor, flex_t deltaSeconds) = (void*)sithAI_sub_4EA630_ADDR;
//static void (*sithAI_sub_4EAF40)(SithAIControlBlock *a1) = (void*)sithAI_sub_4EAF40_ADDR;
//static int (*sithAI_sub_4EB300)(SithThing *a3, rdVector3 *a4, rdVector3 *arg8, flex_t argC, flex_t arg10, flex_t a7, rdVector3 *a5, flex_t *a8) = (void*)sithAI_sub_4EB300_ADDR;
//static void (*sithAI_idk_msgarrived_target)(SithAIControlBlock *actor, flex_t deltaSeconds) = (void*)sithAI_idk_msgarrived_target_ADDR;
//static void (*sithAI_sub_4EAD60)(SithAIControlBlock *actor) = (void*)sithAI_sub_4EAD60_ADDR;
//static int (*sithAI_CanWalk)(SithAIControlBlock *a7, rdVector3 *a4, int *arg8) = (void*)sithAI_CanWalk_ADDR;
//static int (*sithAI_CanWalk_ExplicitSector)(SithAIControlBlock *arg0, rdVector3 *a4, SithSector *a2, int *argC) = (void*)sithAI_CanWalk_ExplicitSector_ADDR;
//static int (*sithAI_CheckSightThing)(SithThing* thing, rdVector3* targetPosition, SithThing* targetThing, flex_t fov, flex_t maxDistance, flex_t unused, rdVector3* targetErrorDir, flex_t* targetDistance) = (void*)sithAI_CheckSightThing_ADDR;

#endif // _SITHAI_H
