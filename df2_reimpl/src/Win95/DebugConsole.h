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

#define DebugGui_aIdk ((int*)0x008BBF80) // int[32]
#define DebugGui_idk (*(int*)0x008BC000)
#define DebugGui_some_line_amt (*(int*)0x008BC004)
#define DebugGui_some_num_lines (*(int*)0x008BC008)
#define DebugLog_buffer ((char*)0x008BC020)

#define DebugConsole_aCmds (*(stdDebugConsoleCmd**)0x008358D0)
#define DebugConsole_pCmdHashtable (*(stdHashTable**)0x008358D4)
#define DebugConsole_bOpened (*(int*)0x008358D8)
#define DebugConsole_bInitted (*(int*)0x008358DC)

#define DebugConsole_maxCmds (*(int*)0x008358E4)
#define DebugConsole_numRegisteredCmds (*(int*)0x008358E8)
#define DebugGui_maxLines (*(uint32_t*)0x008358EC)
#define DebugGui_fnPrint (*(DebugConsolePrintFunc_t*)0x008358F0)
#define DebugGui_fnPrintUniStr (*(DebugConsolePrintUniStrFunc_t*)0x008358F4)
#define DebugConsole_alertSound (*(stdSound_buffer_t**)0x008358F8)
#define DebugConsole_idk2 (*(int16_t*)0x008358FC)

typedef int (*DebugConsolePrintFunc_t)(const char*);
typedef int (*DebugConsolePrintUniStrFunc_t)(const wchar_t*);
typedef int (*DebugConsoleCmd_t)(stdDebugConsoleCmd* cmd, uint32_t extra);

typedef struct stdDebugConsoleCmd
{
    char cmdStr[32];
    DebugConsoleCmd_t cmdFunc;
    uint32_t extra;
} stdDebugConsoleCmd;

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
