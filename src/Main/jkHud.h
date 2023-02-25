#ifndef _JKHUD_H
#define _JKHUD_H

#include "types.h"
#include "globals.h"

#define jkHud_Startup_ADDR (0x00407500)
#define jkHud_Shutdown_ADDR (0x00407540)
#define jkHud_Open_ADDR (0x00407560)
#define jkHud_Close_ADDR (0x00407980)
#define jkHud_ClearRects_ADDR (0x00407A20)
#define jkHud_Draw_ADDR (0x00407C10)
#define jkHud_GetWeaponAmmo_ADDR (0x00408CC0)
#define jkHud_Chat_ADDR (0x00408D80)
#define jkHud_SendChat_ADDR (0x00408E50)
#define jkHud_chat2_ADDR (0x00409000)
#define jkHud_idk_time_ADDR (0x004090A0)
#define jkHud_SetTargetColors_ADDR (0x004090D0)
#define jkHud_SetTarget_ADDR (0x00409150)
#define jkHud_EndTarget_ADDR (0x00409170)
#define jkHud_SortPlayerScore_ADDR (0x00409180)
#define jkHud_SortTeamScore_ADDR (0x004091A0)
#define jkHud_Tally_ADDR (0x004091C0)

#ifdef QOL_IMPROVEMENTS
BOOL jkHud_shouldCrosshairBeShownForWeapon(sithThing *player);
#endif // DEBUG

int jkHud_Startup();
void jkHud_Shutdown();
int jkHud_Open();
void jkHud_Close();
int jkHud_ClearRects(int unk);
void jkHud_Draw();
int jkHud_GetWeaponAmmo(sithThing *player);
int jkHud_Chat();
void jkHud_SendChat(char a1);
void jkHud_SetTargetColors(int *color_idxs);
void jkHud_SetTarget(sithThing *target);
void jkHud_EndTarget();
int jkHud_SortPlayerScore(const void* a, const void* b);
int jkHud_SortTeamScore(const void* a, const void* b);
void jkHud_Tally();
void jkHud_idk_time();
int jkHud_chat2();

//static int (*jkHud_Startup)() = (void*)jkHud_Startup_ADDR;
//static void (*jkHud_Shutdown)() = (void*)jkHud_Shutdown_ADDR;
//static void (*jkHud_Chat)() = (void*)jkHud_Chat_ADDR;
//static void (*jkHud_Tally)() = (void*)jkHud_Tally_ADDR;

//static int (*jkHud_ClearRects)() = (void*)jkHud_ClearRects_ADDR;
//static void (*jkHud_idk_time)() = (void*)jkHud_idk_time_ADDR;
//static void (*jkHud_SendChat)(char a1) = (void*)jkHud_SendChat_ADDR;
//static void (*jkHud_Draw)() = (void*)jkHud_Draw_ADDR;
//static void (*jkHud_Close)() = (void*)jkHud_Close_ADDR;
//static void (*jkHud_Open)() = (void*)jkHud_Open_ADDR;

#endif // _JKHUD_H
