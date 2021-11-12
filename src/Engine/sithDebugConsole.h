#ifndef _SITHDEBUGCONSOLE_H
#define _SITHDEBUGCONSOLE_H

#include "types.h"

#define sithDebugConsole_Initialize_ADDR (0x004EDC10)
#define sithDebugConsole_CmdTick_ADDR (0x004EDE70)
#define sithDebugConsole_CmdSession_ADDR (0x004EDF10)
#define sithDebugConsole_CheatSetDebugFlags_ADDR (0x004EDFC0)
#define sithDebugConsole_CmdCogTrace_ADDR (0x004EE170)
#define sithDebugConsole_CmdCogPause_ADDR (0x004EE230)
#define sithDebugConsole_CmdCogList_ADDR (0x004EE2F0)
#define sithDebugConsole_CmdFly_ADDR (0x004EE420)
#define sithDebugConsole_CmdMem_ADDR (0x004EE4A0)
#define sithDebugConsole_CmdDynamicMem_ADDR (0x004EE710)
#define sithDebugConsole_CmdMemDump_ADDR (0x004EE750)
#define sithDebugConsole_CmdMatList_ADDR (0x004EE7F0)
#define sithDebugConsole_CmdCoords_ADDR (0x004EE960)
#define sithDebugConsole_CmdWarp_ADDR (0x004EEA40)
#define sithDebugConsole_CmdActivate_ADDR (0x004EEB90)
#define sithDebugConsole_CmdJump_ADDR (0x004EEC30)
#define sithDebugConsole_CmdPlayers_ADDR (0x004EEC70)
#define sithDebugConsole_CmdPing_ADDR (0x004EED10)
#define sithDebugConsole_CmdKick_ADDR (0x004EEDB0)
#define sithDebugConsole_matlist_sort_ADDR (0x004EEE70)

void sithDebugConsole_Initialize();

#endif // _SITHDEBUGCONSOLE_H
