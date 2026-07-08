#ifndef _DEVICES_SITHCOMM_H
#define _DEVICES_SITHCOMM_H

#define sithComm_Startup_ADDR (0x004E1700)
#define sithMessage_Shutdown_ADDR (0x004E18E0)
#define sithMessage_RegisterFunction_ADDR (0x004E1900)
#define sithComm_SendMsgToPlayer_ADDR (0x004E1910)
#define sithMessage_FileWrite_ADDR (0x004E1B30)
#define sithMessage_ProcessMessages_ADDR (0x004E1B70)
#define sithMessage_StopProcessMessages_ADDR (0x004E1DC0)
#define sithMessage_Process_ADDR (0x004E1DD0)
#define sithComm_SyncWithPlayers_ADDR (0x004E1E00)
#define sithComm_ClearMsgTmpBuf_ADDR (0x004E1EC0)
#define sithComm_cogMsg_Reset_ADDR (0x004E1EE0)

#include "types.h"

extern int sithComm_version;

int sithComm_Startup();
void sithMessage_Shutdown();
void sithMessage_RegisterFunction(int type, cogMsg_Handler pFunc);
int sithComm_SendMsgToPlayer(SithMessage *pMessage, int idTo, int outstream, int dwDPFlags);
void sithMessage_FileWrite(SithMessage *pMessage);
int sithMessage_ProcessMessages();
void sithMessage_StopProcessMessages();
int sithMessage_Process(SithMessage *pMessage);
void sithComm_SyncWithPlayers();
void sithComm_ClearMsgTmpBuf();
int sithComm_cogMsg_Reset(SithMessage *msg);

#endif // _DEVICES_SITHCOMM_H