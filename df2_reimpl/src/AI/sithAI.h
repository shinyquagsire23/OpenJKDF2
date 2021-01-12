#ifndef _SITHAI_H
#define _SITHAI_H

#include <stdint.h>

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
#define sithAI_sub_4EB090_ADDR (0x004EB090)
#define sithAI_sub_4EB300_ADDR (0x004EB300)
#define sithAI_physidk_ADDR (0x004EB4B0)
#define sithAI_sub_4EB640_ADDR (0x004EB640)
#define sithAI_sub_4EB790_ADDR (0x004EB790)
#define sithAI_sub_4EB860_ADDR (0x004EB860)
#define sithAI_sub_4EB880_ADDR (0x004EB880)
#define sithAI_RandomFireVector_ADDR (0x004EB920)
#define sithAI_RandomRotationVector_ADDR (0x004EB9A0)
#define sithAI_weapon_fire_ADDR (0x004EBA10)
#define sithAI_sub_4EBE80_ADDR (0x004EBE80)
#define sithAI_sub_4EC140_ADDR (0x004EC140)

typedef struct sithThing sithThing;

typedef int (*sithAICommandFunc_t)(void *actor, void *a8, void *a3, int a4);

typedef struct sithAICommand
{
    char name[32];
    sithAICommandFunc_t func;
    int param1;
    int param2;
    int param3;
} sithAICommand;

#define sithAI_bInit       (*(int*)0x84DE4C)
#define sithAI_commandList (*(sithAICommand**)0x0084DE50)
#define sithAI_numCommands (*(uint32_t*)0x84DE54)

void sithAI_RegisterCommand(char *cmdName, void *func, int param1, int param2, int param3);
sithAICommand* sithAI_FindCommand(const char *cmdName);

static void (*sithAI_FreeEntry)(sithThing *thing) = (void*)sithAI_FreeEntry_ADDR;
static void (*sithAI_Tick)(sithThing *thing, float deltaSeconds) = (void*)sithAI_Tick_ADDR;

#endif // _SITHAI_H
