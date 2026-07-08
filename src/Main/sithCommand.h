#ifndef _SITHDEBUGCONSOLE_H
#define _SITHDEBUGCONSOLE_H

#include "types.h"
#include "globals.h"

#define sithCommand_Startup_ADDR (0x004EDC10)
#define sithCommand_Tick_ADDR (0x004EDE70)
#define sithCommand_Session_ADDR (0x004EDF10)
#define sithCommand_DebugMode_ADDR (0x004EDFC0)
#define sithCommand_CogTrace_ADDR (0x004EE170)
#define sithCommand_CogPause_ADDR (0x004EE230)
#define sithCommand_CogList_ADDR (0x004EE2F0)
#define sithCommand_Fly_ADDR (0x004EE420)
#define sithCommand_Memory_ADDR (0x004EE4A0)
#define sithCommand_DynamicMemory_ADDR (0x004EE710)
#define sithCommand_MemoryDump_ADDR (0x004EE750)
#define sithCommand_MatList_ADDR (0x004EE7F0)
#define sithCommand_Coords_ADDR (0x004EE960)
#define sithCommand_Warp_ADDR (0x004EEA40)
#define sithCommand_Activate_ADDR (0x004EEB90)
#define sithCommand_Jump_ADDR (0x004EEC30)
#define sithCommand_Players_ADDR (0x004EEC70)
#define sithCommand_PingPlayer_ADDR (0x004EED10)
#define sithCommand_Kick_ADDR (0x004EEDB0)
#define sithCommand_CompareMatInfos_ADDR (0x004EEE70)

void sithCommand_Startup();
int sithCommand_DebugMode(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_Tick(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_Session(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_CogTrace(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_CogPause(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_CogList(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_Memory(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_DynamicMemory(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_MemoryDump(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_MatList(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_CompareMatInfos(const void *a, const void *b);
int sithCommand_Coords(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_Fly(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_Warp(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_Activate(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_Jump(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_Players(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_PingPlayer(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_Kick(stdDebugConsoleCmd *pCmd, const char *pArgStr);

// Added
int sithCommand_CmdThingNpc(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_CmdBind(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_CmdUnbind(stdDebugConsoleCmd *pCmd, const char *pArgStr);

// Added
void sithCommand_StartupBinds();
void sithCommand_ShutdownBinds();
void sithCommand_SaveBinds();
void sithCommand_LoadBinds();
void sithCommand_HandleBinds(uint16_t key);
void sithCommand_AddBind(uint16_t key, const char* pCmd);
void sithCommand_RemoveBind(uint16_t key);

#endif // _SITHDEBUGCONSOLE_H
