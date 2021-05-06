#ifndef _SITHDPLAY_H
#define _SITHDPLAY_H

#include "types.h"

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

static int (*sithDplay_EarlyInit)() = (void*)sithDplay_EarlyInit_ADDR;
static int (*sithDplay_SendToPlayer)(sithCogMsg *msg, int a2) = (void*)sithDplay_SendToPlayer_ADDR;
static int (*sithDplay_Recv)(void *a1) = (void*)sithDplay_Recv_ADDR;

#define sithDplay_idk (*(int*)0x008321F8)

#endif // _SITHDPLAY_H
