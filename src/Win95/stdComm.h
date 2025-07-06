#ifndef _WIN95_STDCOMM_H
#define _WIN95_STDCOMM_H

#include "types.h"
#include "globals.h"

#include "Platform/Networking/Basic/stdComm_basic.h"
#include "Platform/Networking/GNS/stdComm_GNS.h"
#include "Platform/Networking/None/stdComm_none.h"

#ifdef __cplusplus
extern "C" {
#endif

#define stdComm_Startup_ADDR (0x004C9530)
#define stdComm_Shutdown_ADDR (0x004C9550)
#define stdComm_OpenConnection_ADDR (0x004C9570)
#define stdComm_CloseConnection_ADDR (0x004C95B0)
#define stdComm_EnumSessions_ADDR (0x004C9600)
#define stdComm_EnumSessions2_ADDR (0x004C9620)
#define stdComm_EnumPlayers_ADDR (0x004C9630)
#define stdComm_SendToPlayer_ADDR (0x004C9640)
#define stdComm_Recv_ADDR (0x004C9710)
#define stdComm_Open_ADDR (0x004C97A0)
#define stdComm_Close_ADDR (0x004C9820)
#define stdComm_CreatePlayer_ADDR (0x004C9850)
#define stdComm_seed_idk_ADDR (0x004C98D0)
#define stdComm_EarlyInit_ADDR (0x004C9930)
#define stdComm_DoReceive_ADDR (0x004C99B0)
#define stdComm_cogMsg_SendEnumPlayers_ADDR (0x004C99E0)
#define stdComm_cogMsg_HandleEnumPlayers_ADDR (0x004C9A40)

#define DirectPlay_EarlyInit_ADDR (0x0042F840)
#define DirectPlay_Startup_ADDR (0x0042FA40)
#define DirectPlay_Destroy_ADDR (0x0042FAB0)
#define DirectPlay_InitConnection_ADDR (0x0042FB10)
#define DirectPlay_CloseConnection_ADDR (0x0042FB80)
#define DirectPlay_Send_ADDR (0x0042FBB0)
#define DirectPlay_Receive_ADDR (0x0042FBE0)
#define DirectPlay_OpenHost_ADDR (0x0042FC90)
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


int stdComm_Startup();
void stdComm_Shutdown();
HRESULT stdComm_EnumSessions2(void);
int stdComm_seed_idk(jkMultiEntry *pEntry);
int stdComm_CreatePlayer(jkMultiEntry *pEntry);
int stdComm_Recv(sithCogMsg *msg);
int stdComm_DoReceive();
int stdComm_SendToPlayer(sithCogMsg *msg, int sendto_id);
int DirectPlay_EnumPlayersCallback(DPID dpId, DWORD dwPlayerType, LPCDPNAME lpName, DWORD dwFlags, LPVOID lpContext);

void stdComm_cogMsg_SendEnumPlayers(int sendtoId);
int stdComm_cogMsg_HandleEnumPlayers(sithCogMsg *msg);
int stdComm_EarlyInit();

//static void (*stdComm_Shutdown)() = (void*)stdComm_Shutdown_ADDR;

//static int (*stdComm_Startup)() = (void*)stdComm_Startup_ADDR;



//static void (*stdComm_EnumSessions2)() = (void*)stdComm_EnumSessions2_ADDR;

#ifdef WIN32_BLOBS
static int (*DirectPlay_Startup)() = (void*)DirectPlay_Startup_ADDR;
static int (*DirectPlay_EarlyInit)(wchar_t*, wchar_t*) = (void*)DirectPlay_EarlyInit_ADDR;
//static int (*stdComm_EarlyInit)() = (void*)stdComm_EarlyInit_ADDR;
static int (*stdComm_Open)(int idx, wchar_t* pwPassword) = (void*)stdComm_Open_ADDR;
static int (*stdComm_OpenConnection)(void* a) = (void*)stdComm_OpenConnection_ADDR;
static void (*stdComm_CloseConnection)() = (void*)stdComm_CloseConnection_ADDR;
//static int (*stdComm_seed_idk)(void*) = (void*)stdComm_seed_idk_ADDR;
//static int (*stdComm_CreatePlayer)(void*) = (void*)stdComm_CreatePlayer_ADDR;
//static int (*stdComm_DoReceive)() = (void*)stdComm_DoReceive_ADDR;
static void (*stdComm_Close)() = (void*)stdComm_Close_ADDR;
//static BOOL (*stdComm_SendToPlayer)(void *a1, int sendto_id) = (void*)stdComm_SendToPlayer_ADDR;
static int (*DirectPlay_SendLobbyMessage)(void*, uint32_t) = (void*)DirectPlay_SendLobbyMessage_ADDR;
static int (*DirectPlay_EnumSessions2)() = (void*)DirectPlay_EnumSessions2_ADDR;
static int (*DirectPlay_Receive)(int *pIdOut, int *pMsgIdOut, int *pLenOut) = (void*)DirectPlay_Receive_ADDR;
static BOOL (*DirectPlay_Send)(DPID idFrom, DPID idTo, void *lpData, DWORD dwDataSize) = (void*)DirectPlay_Send_ADDR;
static int (*DirectPlay_SetSessionFlagidk)(int) = (void*)DirectPlay_SetSessionFlagidk_ADDR;
static wchar_t* (*DirectPlay_SetSessionDesc)(int a1, DWORD a2) = (void*)DirectPlay_SetSessionDesc_ADDR;
static DPID (*DirectPlay_CreatePlayer)(wchar_t*, int) = (void*)DirectPlay_CreatePlayer_ADDR;
static void (*DirectPlay_Close)() = (void*)DirectPlay_Close_ADDR;
static int (*DirectPlay_OpenHost)(void*) = (void*)DirectPlay_OpenHost_ADDR;
static int (*DirectPlay_GetSession_passwordidk)(void*) = (void*)DirectPlay_GetSession_passwordidk_ADDR;
static int (*stdComm_EnumSessions)(int, void*) = (void*)stdComm_EnumSessions_ADDR;
static void (*DirectPlay_EnumPlayers)(int a) = (void*)DirectPlay_EnumPlayers_ADDR;
static int (*DirectPlay_StartSession)(void*, void*) = (void*)DirectPlay_StartSession_ADDR;
static void (*DirectPlay_Destroy)() = (void*)DirectPlay_Destroy_ADDR;
static int (*DirectPlay_IdkSessionDesc)(jkMultiEntry* pEntry) = (void*)DirectPlay_IdkSessionDesc_ADDR;
#else

int stdComm_OpenConnection(void* a);
void stdComm_CloseConnection();
int stdComm_Open(int idx, wchar_t* pwPassword);
//int stdComm_seed_idk(void* a);
//int stdComm_CreatePlayer(void* a);
//int stdComm_DoReceive();
void stdComm_Close();
//BOOL stdComm_SendToPlayer(void *a1, int sendto_id);
int DirectPlay_SendLobbyMessage(void* pPkt, uint32_t pktLen);
int DirectPlay_EnumSessions2();
int DirectPlay_Receive(int *pIdOut, int *pMsgIdOut, int *pLenOut);
BOOL DirectPlay_Send(DPID idFrom, DPID idTo, void *lpData, DWORD dwDataSize);
void DirectPlay_SetSessionDesc(const char* a1, DWORD maxPlayers);
BOOL DirectPlay_SetSessionFlagidk(int a1);
BOOL DirectPlay_Startup();
int DirectPlay_EarlyInit(wchar_t* pwIdk, wchar_t* pwPlayerName);
DPID DirectPlay_CreatePlayer(wchar_t* pwIdk, int idk2);
void DirectPlay_Close();
int DirectPlay_OpenHost(jkMultiEntry* a);
int DirectPlay_GetSession_passwordidk(jkMultiEntry* a);
int stdComm_EnumSessions(int a, void* b);
void DirectPlay_EnumPlayers(int a);
int DirectPlay_StartSession(void* a, void* b);
void DirectPlay_Destroy();
int DirectPlay_IdkSessionDesc(jkMultiEntry* pEntry);
#endif

#ifdef __cplusplus
}
#endif

#endif // _WIN95_STDCOMM_H
