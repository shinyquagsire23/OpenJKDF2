#ifndef _JKGAME_H
#define _JKGAME_H

#include "types.h"
#include "globals.h"

#include "jk.h"
#include "Main/Main.h"

#define jkGame_SetDefaultSettings_ADDR (0x00401480)
#define jkGame_ForceRefresh_ADDR (0x00401EC0)
#define jkGame_Update_ADDR (0x00401EE0)
#define jkGame_cam_idk_maybe_ADDR (0x00402230)
#define jkGame_ScreensizeIncrease_ADDR (0x00402540)
#define jkGame_ScreensizeDecrease_ADDR (0x00402570)
#define jkGame_Gamma_ADDR (0x004025A0)
#define jkGame_Screenshot_ADDR (0x004025E0)
#define jkGame_ddraw_idk_palettes_ADDR (0x004027C0)
#define jkGame_nullsub_36_ADDR (0x00402810)
#define jkGame_Initialize_ADDR (0x00402820)
#define jkGame_Shutdown_ADDR (0x00402840)
#define jkGame_ParseSection_ADDR (0x00402850)

int jkGame_Initialize();
int jkGame_ParseSection(sithWorld* a1, int a2);
void jkGame_ForceRefresh();
void jkGame_Shutdown();
int jkGame_Update();
void jkGame_SetDefaultSettings();

void jkGame_ScreensizeIncrease();
void jkGame_ScreensizeDecrease();

//static int (*jkGame_Initialize)(void) = (void*)jkGame_Initialize_ADDR;
//static int (*jkGame_ScreensizeIncrease)() = (void*)jkGame_ScreensizeIncrease_ADDR;
//static int (*jkGame_ScreensizeDecrease)() = (void*)jkGame_ScreensizeDecrease_ADDR;
//static void (*jkGame_SetDefaultSettings)() = (void*)jkGame_SetDefaultSettings_ADDR;
//static void (*jkGame_Update)() = (void*)jkGame_Update_ADDR;
static int (*jkGame_ddraw_idk_palettes)() = (void*)jkGame_ddraw_idk_palettes_ADDR;
//static void (*jkGame_Gamma)() = (void*)jkGame_Gamma_ADDR;

void jkGame_Gamma();

#ifdef SDL2_RENDER
void jkGame_Screenshot();
#else
static void (*jkGame_Screenshot)() = (void*)jkGame_Screenshot_ADDR;
#endif

#endif // _JKGAME_H
