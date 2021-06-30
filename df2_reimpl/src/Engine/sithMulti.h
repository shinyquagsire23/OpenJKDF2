#ifndef _SITHMULTI_H
#define _SITHMULTI_H

#include "types.h"

#define sithMulti_Startup_ADDR (0x004C9AE0)
#define sithMulti_Shutdown_ADDR (0x004C9CB0)
#define sithMulti_ServerLeft_ADDR (0x004C9D00)
#define sithMulti_CreatePlayer_ADDR (0x004C9FC0)
#define sithMulti_InitTick_ADDR (0x004CA140)
#define sithMulti_LobbyMessage_ADDR (0x004CA1B0)
#define sithMulti_map_init_related_ADDR (0x004CA310)
#define sithMulti_sub_4CA3B0_ADDR (0x004CA3B0)
#define sithMulti_sub_4CA410_ADDR (0x004CA410)
#define sithMulti_sub_4CA470_ADDR (0x004CA470)
#define sithMulti_sendmsgidk4_ADDR (0x004CA610)
#define sithMulti_sendmsgidk3_ADDR (0x004CA710)
#define sithMulti_HandleJoinLeave_ADDR (0x004CA780)
#define sithMulti_HandleJoin_unused_ADDR (0x004CA910)
#define sithMulti_SendLeaveJoin_ADDR (0x004CA9C0)
#define sithMulti_HandleLeaveJoin_ADDR (0x004CAAF0)
#define sithMulti_SendRequestConnect_ADDR (0x004CADB0)
#define sithMulti_HandleRequestConnect_ADDR (0x004CAE50)
#define sithMulti_Send36_ADDR (0x004CB200)
#define sithMulti_SendChat_ADDR (0x004CB250)
#define sithMulti_HandleChat_ADDR (0x004CB2E0)
#define sithMulti_SendPing_ADDR (0x004CB390)
#define sithMulti_HandlePing_ADDR (0x004CB3E0)
#define sithMulti_HandlePingResponse_ADDR (0x004CB410)
#define sithMulti_SendKickPlayer_ADDR (0x004CB4A0)
#define sithMulti_HandleKickPlayer_ADDR (0x004CB4F0)
#define sithMulti_HandleTimeLimit_ADDR (0x004CB690)
#define sithMulti_SyncScores_ADDR (0x004CBC00)
#define sithMulti_IterPlayersnothingidk_ADDR (0x004CBC10)
#define sithMulti_SetHandleridk_ADDR (0x004CBC40)
#define sithMulti_HandleDeath_ADDR (0x004CBC50)
#define sithMulti_HandleScore_ADDR (0x004CBDE0)
#define sithMulti_EndLevel_ADDR (0x004CBF90)
#define sithMulti_sub_4CBFC0_ADDR (0x004CBFC0)
#define sithMulti_FreeThing_ADDR (0x004CC110)

typedef int (*sithMultiHandler_t)();

#define sithMulti_name ((wchar_t*)0x008C4BE0)
#define sithMulti_handlerIdk (*(sithMultiHandler_t*)0x0083264C)

void sithMulti_SetHandleridk(sithMultiHandler_t a1);

#ifdef WIN32
static int (*sithMulti_SendChat)(char *a1, int a2, int a3) = (void*)sithMulti_SendChat_ADDR;
#else
int sithMulti_SendChat(char *a1, int a2, int a3);
#endif

static void (*sithMulti_Startup)() = (void*)sithMulti_Startup_ADDR;
static void (*sithMulti_FreeThing)(int a1) = (void*)sithMulti_FreeThing_ADDR;
static int (*sithMulti_SendKickPlayer)(int a1) = (void*)sithMulti_SendKickPlayer_ADDR;
static void (*sithMulti_SyncScores)(void) = (void*)sithMulti_SyncScores_ADDR;
static void (*sithMulti_Shutdown)() = (void*)sithMulti_Shutdown_ADDR;
static int (*sithMulti_LobbyMessage)() = (void*)sithMulti_LobbyMessage_ADDR;
static void (*sithMulti_HandleTimeLimit)(int) = (void*)sithMulti_HandleTimeLimit_ADDR;
static int (*sithMulti_sendmsgidk3)(int,int,int) = (void*)sithMulti_sendmsgidk3_ADDR;
static void (*sithMulti_HandleDeath)(sithPlayerInfo *a1, sithThing *killed, sithThing *killed_by) = (void*)sithMulti_HandleDeath_ADDR;

#endif // _SITHMULTI_H
