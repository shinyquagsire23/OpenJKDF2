#ifndef _DEVICES_SITHCONSOLE_H
#define _DEVICES_SITHCONSOLE_H

#include "types.h"
#include "globals.h"

#define sithConsole_Startup_ADDR (0x004D9DB0)
#define sithConsole_Shutdown_ADDR (0x004D9E90)
#define sithConsole_Open_ADDR (0x004D9EF0)
#define sithConsole_Close_ADDR (0x004D9F40)
#define sithConsole_PrintString_ADDR (0x004D9F50)
#define sithConsole_PrintWString_ADDR (0x004D9FE0)
#define sithConsole_ExeCommand_ADDR (0x004DA000)
#define sithConsole_sub_4DA100_ADDR (0x004DA100)
#define sithConsole_Flush_ADDR (0x004DA110)
#define sithConsole_RegisterCommand_ADDR (0x004DA140)
#define sithConsole_RegisterPrintFunctions_ADDR (0x004DA1B0)
#define sithConsole_Help_ADDR (0x004DA1D0)
#define sithConsole_AlertSound_ADDR (0x004DA3D0)

int sithConsole_Startup(int maxCmds);
void sithConsole_Shutdown();
int sithConsole_Open(int maxLines);
void sithConsole_Close();
void sithConsole_PrintString(const char *pString);
void sithConsole_PrintWString(const wchar_t *pwString);
int sithConsole_ExeCommand(const char *pLine);
int sithConsole_sub_4DA100();
void sithConsole_Flush();
int sithConsole_RegisterCommand(DebugConsoleCmd_t pfFunc, const char *pName, int flags);
int sithConsole_RegisterPrintFunctions(DebugConsolePrintFunc_t a1, DebugConsolePrintUniStrFunc_t a2);
int sithConsole_Help(stdDebugConsoleCmd* pFunc, const char* pArg);
void sithConsole_AlertSound();

#endif // _DEVICES_SITHCONSOLE_H
