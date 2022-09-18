#ifndef _SITHDEBUGCONSOLE_H
#define _SITHDEBUGCONSOLE_H

#include "types.h"
#include "globals.h"

#define sithCommand_Startup_ADDR (0x004EDC10)
#define sithCommand_CmdTick_ADDR (0x004EDE70)
#define sithCommand_CmdSession_ADDR (0x004EDF10)
#define sithCommand_CheatSetDebugFlags_ADDR (0x004EDFC0)
#define sithCommand_CmdCogTrace_ADDR (0x004EE170)
#define sithCommand_CmdCogPause_ADDR (0x004EE230)
#define sithCommand_CmdCogList_ADDR (0x004EE2F0)
#define sithCommand_CmdFly_ADDR (0x004EE420)
#define sithCommand_CmdMem_ADDR (0x004EE4A0)
#define sithCommand_CmdDynamicMem_ADDR (0x004EE710)
#define sithCommand_CmdMemDump_ADDR (0x004EE750)
#define sithCommand_CmdMatList_ADDR (0x004EE7F0)
#define sithCommand_CmdCoords_ADDR (0x004EE960)
#define sithCommand_CmdWarp_ADDR (0x004EEA40)
#define sithCommand_CmdActivate_ADDR (0x004EEB90)
#define sithCommand_CmdJump_ADDR (0x004EEC30)
#define sithCommand_CmdPlayers_ADDR (0x004EEC70)
#define sithCommand_CmdPing_ADDR (0x004EED10)
#define sithCommand_CmdKick_ADDR (0x004EEDB0)
#define sithCommand_matlist_sort_ADDR (0x004EEE70)

void sithCommand_Startup();
int sithCommand_CheatSetDebugFlags(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_CmdTick(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_CmdSession(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_CmdCogTrace(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_CmdCogPause(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_CmdCogList(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_CmdMem(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_CmdDynamicMem(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_CmdMemDump(stdDebugConsoleCmd *pCmd, const char *pArgStr);
// Matlist
int sithCommand_CmdCoords(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_CmdFly(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_CmdWarp(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_CmdActivate(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_CmdJump(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_CmdPlayers(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_CmdPing(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int sithCommand_CmdKick(stdDebugConsoleCmd *pCmd, const char *pArgStr);

#endif // _SITHDEBUGCONSOLE_H
