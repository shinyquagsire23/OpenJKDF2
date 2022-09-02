#ifndef _SITHMULTI_H
#define _SITHMULTI_H

#ifdef __cplusplus
extern "C" {
#endif

#include "types.h"
#include "globals.h"

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

enum sithMultiModeFlags
{
    MULTIMODEFLAG_TEAMS = 0x1,
    MULTIMODEFLAG_2 = 0x2,
    MULTIMODEFLAG_4 = 0x4,
    MULTIMODEFLAG_TIMELIMIT = 0x8,
    MULTIMODEFLAG_SCORELIMIT = 0x10,
    MULTIMODEFLAG_20 = 0x20,
    MULTIMODEFLAG_40 = 0x40,
    MULTIMODEFLAG_SINGLE_LEVEL = 0x80,
    MULTIMODEFLAG_100 = 0x100,
};

enum sithMultiSessionFlags
{
    SESSIONFLAG_1 = 0x1,
    SESSIONFLAG_2 = 0x2,
    SESSIONFLAG_4 = 0x4,
    SESSIONFLAG_8 = 0x8,
    SESSIONFLAG_10 = 0x10,
    SESSIONFLAG_20 = 0x20,
    SESSIONFLAG_40 = 0x40,
    SESSIONFLAG_80 = 0x80,
    SESSIONFLAG_100 = 0x100,
    SESSIONFLAG_200 = 0x200,
    SESSIONFLAG_PASSWORD = 0x400,
    SESSIONFLAG_800 = 0x800,
    SESSIONFLAG_1000 = 0x1000,
    SESSIONFLAG_2000 = 0x2000,
    SESSIONFLAG_4000 = 0x4000,
    SESSIONFLAG_ISDEDICATED = 0x8000,
};

extern int jkGuiNetHost_bIsDedicated;

void sithMulti_SetHandleridk(sithMultiHandler_t a1);
void sithMulti_SendChat(char *pStr, int arg0, int arg1);
void sithMulti_HandleScore();
int sithMulti_HandleChat(sithCogMsg *msg);

HRESULT sithMulti_CreatePlayer(const wchar_t *a1, const wchar_t *a2, const char *a3, const char *a4, int a5, int a6, int multiModeFlags, int rate, int a9);
int sithMulti_Startup();
void sithMulti_FreeThing(int a1);
void sithMulti_Shutdown();
int sithMulti_SendRequestConnect(int sendto_id);
int sithMulti_sub_4CBFC0(sithThing *pPlayerThing);
void sithMulti_SyncScores();
void sithMulti_HandleDeath(sithPlayerInfo *pPlayerInfo, sithThing *pKilledThing, sithThing *pKilledByThing);
void sithMulti_EndLevel(unsigned int a1, int a2);
void sithMulti_sendmsgidk3(int a1, int playerIdx, int sendtoId);
void sithMulti_SendKickPlayer(int idx);
int sithMulti_LobbyMessage();
int sithMulti_HandleJoinLeave(sithCogMsg *msg);
int sithMulti_HandlePing(sithCogMsg *msg);
int sithMulti_HandlePingResponse(sithCogMsg *msg);
int sithMulti_HandleKickPlayer(sithCogMsg *msg);
int sithMulti_ServerLeft();
void sithMulti_SendLeaveJoin(int sendtoId, int bSync);
int sithMulti_HandleLeaveJoin(sithCogMsg *msg);
void sithMulti_sub_4CA470(int a1);
void sithMulti_InitTick(unsigned int tickrate);
int sithMulti_HandleRequestConnect(sithCogMsg *msg);
void sithMulti_HandleTimeLimit(int deltaMs);

//static void (*sithMulti_Startup)() = (void*)sithMulti_Startup_ADDR;
//static void (*sithMulti_FreeThing)(int a1) = (void*)sithMulti_FreeThing_ADDR;
//static int (*sithMulti_SendKickPlayer)(int a1) = (void*)sithMulti_SendKickPlayer_ADDR;
//static void (*sithMulti_SyncScores)(void) = (void*)sithMulti_SyncScores_ADDR;
//static void (*sithMulti_Shutdown)() = (void*)sithMulti_Shutdown_ADDR;
//static int (*sithMulti_LobbyMessage)() = (void*)sithMulti_LobbyMessage_ADDR;
//static void (*sithMulti_HandleTimeLimit)(int) = (void*)sithMulti_HandleTimeLimit_ADDR;
//static int (*sithMulti_sendmsgidk3)(int,int,int) = (void*)sithMulti_sendmsgidk3_ADDR;
//static void (*sithMulti_HandleDeath)(sithPlayerInfo *a1, sithThing *killed, sithThing *killed_by) = (void*)sithMulti_HandleDeath_ADDR;
//static int (*sithMulti_CreatePlayer)(wchar_t *a1, wchar_t *a2, char *a3, char *a4, int a5, int a6, int a7, int a8, int a9) = (void*)sithMulti_CreatePlayer_ADDR;
//static uint32_t (*sithMulti_InitTick)(uint32_t) = (void*)sithMulti_InitTick_ADDR;
//static int (*sithMulti_ServerLeft)() = (void*)sithMulti_ServerLeft_ADDR;
//static int (*sithMulti_SendRequestConnect)(int a1) = (void*)sithMulti_SendRequestConnect_ADDR;

#ifdef __cplusplus
}
#endif


#endif // _SITHMULTI_H
