#ifndef _DEVICES_SITHCONSOLE_H
#define _DEVICES_SITHCONSOLE_H

#include "types.h"
#include "globals.h"

#define sithConsole_Startup_ADDR (0x004D9DB0)
#define sithConsole_Shutdown_ADDR (0x004D9E90)
#define sithConsole_Open_ADDR (0x004D9EF0)
#define sithConsole_Close_ADDR (0x004D9F40)
#define sithConsole_Print_ADDR (0x004D9F50)
#define sithConsole_PrintUniStr_ADDR (0x004D9FE0)
#define sithConsole_TryCommand_ADDR (0x004DA000)
#define sithConsole_sub_4DA100_ADDR (0x004DA100)
#define sithConsole_AdvanceLogBuf_ADDR (0x004DA110)
#define sithConsole_RegisterDevCmd_ADDR (0x004DA140)
#define sithConsole_SetPrintFuncs_ADDR (0x004DA1B0)
#define sithConsole_PrintHelp_ADDR (0x004DA1D0)
#define sithConsole_AlertSound_ADDR (0x004DA3D0)

int sithConsole_Startup(int maxCmds);
void sithConsole_Shutdown();
int sithConsole_Open(int maxLines);
void sithConsole_Close();
void sithConsole_Print(const char *str);
void sithConsole_PrintUniStr(const wchar_t *a1);
int sithConsole_TryCommand(const char *cmd);
int sithConsole_sub_4DA100();
void sithConsole_AdvanceLogBuf();
int sithConsole_RegisterDevCmd(DebugConsoleCmd_t fn, const char *cmd, int extra);
int sithConsole_SetPrintFuncs(DebugConsolePrintFunc_t a1, DebugConsolePrintUniStrFunc_t a2);
int sithConsole_PrintHelp(stdDebugConsoleCmd* a, const char* b);
void sithConsole_AlertSound();

#endif // _DEVICES_SITHCONSOLE_H
