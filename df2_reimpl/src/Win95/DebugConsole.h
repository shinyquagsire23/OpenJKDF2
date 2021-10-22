#ifndef _DEBUGCONSOLE_H
#define _DEBUGCONSOLE_H

#include "types.h"
#include "globals.h"

#define DebugConsole_Initialize_ADDR (0x004D9DB0)
#define DebugConsole_Shutdown_ADDR (0x004D9E90)
#define DebugConsole_Open_ADDR (0x004D9EF0)
#define DebugConsole_Close_ADDR (0x004D9F40)
#define DebugConsole_Print_ADDR (0x004D9F50)
#define DebugConsole_PrintUniStr_ADDR (0x004D9FE0)
#define DebugConsole_TryCommand_ADDR (0x004DA000)
#define DebugConsole_sub_4DA100_ADDR (0x004DA100)
#define DebugConsole_AdvanceLogBuf_ADDR (0x004DA110)
#define DebugConsole_RegisterDevCmd_ADDR (0x004DA140)
#define DebugConsole_SetPrintFuncs_ADDR (0x004DA1B0)
#define DebugConsole_PrintHelp_ADDR (0x004DA1D0)
#define DebugConsole_AlertSound_ADDR (0x004DA3D0)

int DebugConsole_Initialize(int maxCmds);
void DebugConsole_Shutdown();
int DebugConsole_Open(int maxLines);
void DebugConsole_Close();
void DebugConsole_Print(char *str);
void DebugConsole_PrintUniStr(wchar_t *a1);
int DebugConsole_TryCommand(char *cmd);
int DebugConsole_sub_4DA100();
void DebugConsole_AdvanceLogBuf();
int DebugConsole_RegisterDevCmd(void *fn, char *cmd, int extra);
int DebugConsole_SetPrintFuncs(void *a1, void *a2);
int DebugConsole_PrintHelp();
void DebugConsole_AlertSound();

#endif // _DEBUGCONSOLE_H
