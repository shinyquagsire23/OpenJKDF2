#ifndef _DEVICES_SITHCOMM_H
#define _DEVICES_SITHCOMM_H

#define sithComm_Startup_ADDR (0x004E1700)
#define sithComm_Shutdown_ADDR (0x004E18E0)
#define sithComm_SetMsgFunc_ADDR (0x004E1900)
#define sithComm_SendMsgToPlayer_ADDR (0x004E1910)
#define sithComm_FileWrite_ADDR (0x004E1B30)
#define sithComm_Sync_ADDR (0x004E1B70)
#define sithComm_SetNeedsSync_ADDR (0x004E1DC0)
#define sithComm_InvokeMsgByIdx_ADDR (0x004E1DD0)
#define sithComm_SyncWithPlayers_ADDR (0x004E1E00)
#define sithComm_ClearMsgTmpBuf_ADDR (0x004E1EC0)
#define sithComm_cogMsg_Reset_ADDR (0x004E1EE0)

#include "types.h"

extern int sithComm_version;

int sithComm_Startup();
void sithComm_Shutdown();
void sithComm_SetMsgFunc(int msgid, void *func);
int sithComm_SendMsgToPlayer(sithCogMsg *msg, int a2, int mpFlags, int a4);
void sithComm_FileWrite(sithCogMsg *ctx);
int sithComm_Sync();
void sithComm_SetNeedsSync();
int sithComm_InvokeMsgByIdx(sithCogMsg *a1);
void sithComm_SyncWithPlayers();
void sithComm_ClearMsgTmpBuf();
int sithComm_cogMsg_Reset();

#endif // _DEVICES_SITHCOMM_H