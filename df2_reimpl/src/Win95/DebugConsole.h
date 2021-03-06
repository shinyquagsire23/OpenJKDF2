#ifndef _DEBUGCONSOLE_H
#define _DEBUGCONSOLE_H

#include "types.h"

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

#ifdef LINUX
void DebugConsole_Print(char* s);
void DebugConsole_PrintUniStr(wchar_t* s);
void DebugConsole_AdvanceLogBuf();
void DebugConsole_AlertSound();
#else
static void (*DebugConsole_PrintUniStr)(wchar_t *a1) = (void*)DebugConsole_PrintUniStr_ADDR;
static void (__cdecl *DebugConsole_Print)(char *str) = (void*)DebugConsole_Print_ADDR;
static void (*DebugConsole_AdvanceLogBuf)() = (void*)DebugConsole_AdvanceLogBuf_ADDR;
static void (*DebugConsole_AlertSound)() = (void*)DebugConsole_AlertSound_ADDR;
#endif

#endif // _DEBUGCONSOLE_H
