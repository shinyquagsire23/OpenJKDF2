#ifndef _JKDEV_H
#define _JKDEV_H

#include "types.h"
#include "globals.h"

#define jkDev_Startup_ADDR (0x0041F100)
#define jkDev_Shutdown_ADDR (0x0041F6A0)
#define jkDev_Open_ADDR (0x0041F6E0)
#define jkDev_Close_ADDR (0x0041F7A0)
#define jkDev_DrawLog_ADDR (0x0041F7D0)
#define jkDev_BlitLogToScreen_ADDR (0x0041F950)
#define jkDev_PrintUniString_ADDR (0x0041FA50)
#define jkDev_DebugLog_ADDR (0x0041FB10)
#define jkDev_sub_41FB80_ADDR (0x0041FB80)
#define jkDev_sub_41FC40_ADDR (0x0041FC40)
#define jkDev_sub_41FC90_ADDR (0x0041FC90)
#define jkDev_RegisterCmd_ADDR (0x0041FCE0)
#define jkDev_TryCommand_ADDR (0x0041FD60)
#define jkDev_Decrypt_ADDR (0x0041FE20)
#define jkDev_CmdVersion_ADDR (0x0041FE40)
#define jkDev_CmdFramerate_ADDR (0x0041FE90)
#define jkDev_CmdDispStats_ADDR (0x0041FEB0)
#define jkDev_CmdKill_ADDR (0x0041FED0)
#define jkDev_CmdEndLevel_ADDR (0x0041FEF0)
#define jkDev_CmdSkipToLevel_ADDR (0x0041FF20)
#define jkDev_CmdDebugFlags_ADDR (0x0041FF70)
#define jkDev_CmdFly_ADDR (0x0041FFA0)
#define jkDev_CmdDebugFlags2_ADDR (0x0041FFD0)
#define jkDev_CmdWarp_ADDR (0x00420000)
#define jkDev_CmdActivate_ADDR (0x00420050)
#define jkDev_CmdDebugFlags3_ADDR (0x00420080)
#define jkDev_CmdJump_ADDR (0x004200B0)
#define jkDev_CmdEndLevel2_ADDR (0x004200E0)
#define jkDev_CmdAllWeapons_ADDR (0x00420100)
#define jkDev_CmdAllItems_ADDR (0x00420260)
#define jkDev_CmdLightMaster_ADDR (0x00420490)
#define jkDev_CmdDarkMaster_ADDR (0x004206F0)
#define jkDev_CmdUberJedi_ADDR (0x00420950)
#define jkDev_CmdLevelUp_ADDR (0x00420C10)
#define jkDev_CmdHeal_ADDR (0x00420EB0)
#define jkDev_CmdAllMap_ADDR (0x00420F00)
#define jkDev_CmdMana_ADDR (0x00420F40)
#define jkDev_CmdTeam_ADDR (0x00420F80)
#define jkDev_DialogFunc_ADDR (0x00420FD0)
#define jkDev_UpdateEntries_ADDR (0x004210D0)
#define jkDev_DrawEntries_ADDR (0x00421190)

void jkDev_Startup();
void jkDev_Shutdown();
int jkDev_Open();
void jkDev_Close();
void jkDev_DrawLog();
void jkDev_BlitLogToScreen();
int jkDev_PrintUniString(const wchar_t *str);
int jkDev_DebugLog(const char *lParam);
int jkDev_sub_41FB80(int a1, const wchar_t *a2);
int jkDev_sub_41FC40(int a1, const char *a2);
void jkDev_sub_41FC90(int a1);
void jkDev_DrawEntries();

int jkDev_RegisterCmd(void *pfCheatFunc, const char *pCryptCheatStr, const char *pCheatFlavortext, int extra);
int jkDev_TryCommand(const char *cmd);
char* jkDev_Decrypt(char *cheatStr);
int jkDev_CmdVersion(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int jkDev_CmdFramerate(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int jkDev_CmdDispStats(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int jkDev_CmdKill(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int jkDev_CmdEndLevel(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int jkDev_CmdSkipToLevel(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int jkDev_Custom_CmdJumpNextCheckpoint(stdDebugConsoleCmd* pCmd, const char* pArgStr);// strike added
int jkDev_CmdDebugFlags(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int jkDev_CmdFly(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int jkDev_CmdDebugFlags2(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int jkDev_CmdWarp(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int jkDev_CmdActivate(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int jkDev_CmdDebugFlags3(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int jkDev_CmdJump(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int jkDev_CmdEndLevel2(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int jkDev_CmdAllWeapons(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int jkDev_CmdAllItems(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int jkDev_CmdLightMaster(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int jkDev_CmdDarkMaster(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int jkDev_CmdUberJedi(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int jkDev_CmdLevelUp(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int jkDev_CmdHeal(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int jkDev_CmdAllMap(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int jkDev_CmdMana(stdDebugConsoleCmd *pCmd, const char *pArgStr);
int jkDev_CmdTeam(stdDebugConsoleCmd *pCmd, const char *pArgStr);

int jkDev_UpdateEntries();

#ifdef QOL_IMPROVEMENTS
int jkDev_CmdNoclip(stdDebugConsoleCmd *pCmd, const char *pArgStr);
#endif

static int (*jkDev_DialogFunc)(HWND, UINT, WPARAM, LPARAM) = (void*)jkDev_DialogFunc_ADDR;

#endif // _JKDEV_H
