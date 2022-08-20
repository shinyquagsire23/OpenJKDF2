#ifndef _SITHDPLAY_H
#define _SITHDPLAY_H

#include "types.h"
#include "globals.h"

#define sithDplay_Startup_ADDR (0x004C9530)
#define sithDplay_Shutdown_ADDR (0x004C9550)
#define sithDplay_OpenConnection_ADDR (0x004C9570)
#define sithDplay_CloseConnection_ADDR (0x004C95B0)
#define sithDplay_EnumSessions_ADDR (0x004C9600)
#define sithDplay_EnumSessions2_ADDR (0x004C9620)
#define sithDplay_EnumPlayers_ADDR (0x004C9630)
#define sithDplay_SendToPlayer_ADDR (0x004C9640)
#define sithDplay_Recv_ADDR (0x004C9710)
#define sithDplay_Open_ADDR (0x004C97A0)
#define sithDplay_Close_ADDR (0x004C9820)
#define sithDplay_CreatePlayer_ADDR (0x004C9850)
#define sithDplay_seed_idk_ADDR (0x004C98D0)
#define sithDplay_EarlyInit_ADDR (0x004C9930)
#define sithDplay_DoReceive_ADDR (0x004C99B0)
#define sithDplay_cogMsg_SendEnumPlayers_ADDR (0x004C99E0)
#define sithDplay_cogMsg_HandleEnumPlayers_ADDR (0x004C9A40)

#define DirectPlay_EarlyInit_ADDR (0x0042F840)
#define DirectPlay_Initialize_ADDR (0x0042FA40)
#define DirectPlay_Destroy_ADDR (0x0042FAB0)
#define DirectPlay_InitConnection_ADDR (0x0042FB10)
#define DirectPlay_CloseConnection_ADDR (0x0042FB80)
#define DirectPlay_Send_ADDR (0x0042FBB0)
#define DirectPlay_Receive_ADDR (0x0042FBE0)
#define DirectPlay_OpenIdk_ADDR (0x0042FC90)
#define DirectPlay_GetSession_passwordidk_ADDR (0x0042FDC0)
#define DirectPlay_IdkSessionDesc_ADDR (0x0042FEE0)
#define DirectPlay_SetSessionFlagidk_ADDR (0x0042FF50)
#define DirectPlay_SetSessionDesc_ADDR (0x0042FFF0)
#define DirectPlay_Open_ADDR (0x004300D0)
#define DirectPlay_Close_ADDR (0x00430180)
#define DirectPlay_StartSession_ADDR (0x004301A0)
#define DirectPlay_GetCaps_ADDR (0x004302E0)
#define DirectPlay_EnumPlayers_ADDR (0x00430330)
#define DirectPlay_EnumSessions_ADDR (0x004303C0)
#define DirectPlay_EnumSessions2_ADDR (0x00430470)
#define DirectPlay_CreatePlayer_ADDR (0x004304E0)
#define DirectPlay_DestroyPlayer_ADDR (0x00430530)
#define DirectPlay_CreateGroup_ADDR (0x00430550)
#define DirectPlay_AddPlayerToGroup_ADDR (0x00430570)
#define DirectPlay_DeletePlayerFromGroup_ADDR (0x00430590)
#define DirectPlay_EnumGroupPlayers_ADDR (0x004305B0)
#define DirectPlay_SendLobbyMessage_ADDR (0x004305E0)
#define DirectPlay_EnumConnectionsCallback_ADDR (0x004306E0)
#define DirectPlay_EnumSessionsCallback_ADDR (0x004307C0)
#define DirectPlay_EnumPlayersCallback_ADDR (0x00430810)
#define DirectPlay_sub_4308C0_ADDR (0x004308C0)
#define DirectPlay_parseSessionDescidk_ADDR (0x004308F0)

int sithDplay_Startup();
static void (*sithDplay_Shutdown)() = (void*)sithDplay_Shutdown_ADDR;

//static int (*sithDplay_Startup)() = (void*)sithDplay_Startup_ADDR;


static int (*DirectPlay_Initialize)() = (void*)DirectPlay_Initialize_ADDR;
static int (*DirectPlay_SetSessionFlagidk)(int) = (void*)DirectPlay_SetSessionFlagidk_ADDR;
static wchar_t* (*DirectPlay_SetSessionDesc)(int a1, DWORD a2) = (void*)DirectPlay_SetSessionDesc_ADDR;
static void (*sithDplay_EnumSessions2)() = (void*)sithDplay_EnumSessions2_ADDR;

#ifdef WIN32_BLOBS
static int (*sithDplay_EarlyInit)() = (void*)sithDplay_EarlyInit_ADDR;
static int (*sithDplay_Open)(int a, void* b) = (void*)sithDplay_Open_ADDR;
static int (*sithDplay_OpenConnection)(void* a) = (void*)sithDplay_OpenConnection_ADDR;
static void (*sithDplay_CloseConnection)() = (void*)sithDplay_CloseConnection_ADDR;
static int (*sithDplay_seed_idk)(void*) = (void*)sithDplay_seed_idk_ADDR;
static int (*sithDplay_CreatePlayer)(void*) = (void*)sithDplay_CreatePlayer_ADDR;
static void (*sithDplay_DoReceive)() = (void*)sithDplay_DoReceive_ADDR;
static void (*sithDplay_Close)() = (void*)sithDplay_Close_ADDR;
static BOOL (*sithDplay_SendToPlayer)(void *a1, int sendto_id) = (void*)sithDplay_SendToPlayer_ADDR;
static int (*sithDplay_Recv)(void *a1) = (void*)sithDplay_Recv_ADDR;
#else
int sithDplay_EarlyInit();
int sithDplay_OpenConnection(void* a);
void sithDplay_CloseConnection();
int sithDplay_Open(int a, void* b);
int sithDplay_seed_idk(void* a);
int sithDplay_CreatePlayer(void* a);
void sithDplay_DoReceive();
void sithDplay_Close();
BOOL sithDplay_SendToPlayer(void *a1, int sendto_id);
int sithDplay_Recv(void *a1);
#endif

#endif // _SITHDPLAY_H
