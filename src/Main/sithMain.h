#ifndef _MAIN_SITHMAIN_H
#define _MAIN_SITHMAIN_H

#include "types.h"
#include "globals.h"

#define sithMain_Startup_ADDR (0x004C4630)
#define sithShutdown_ADDR (0x004C4700)
#define sithOpenStatic_ADDR (0x004C4780)
#define sithCloseStatic_ADDR (0x004C47B0)
#define sithMain_Mode1Init_ADDR (0x004C47D0)
#define sithOpenPostProcess_ADDR (0x004C4880)
#define sithOpenNormal_ADDR (0x004C49D0)
#define sithOpenMulti_ADDR (0x004C4A70)
#define sithOpen_ADDR (0x004C4B10)
#define sithClose_ADDR (0x004C4B80)
#define sithMain_SetEndLevel_ADDR (0x004C4BF0)
#define sithUpdate_ADDR (0x004C4C00)
#define sithDrawScene_ADDR (0x004C4D30)
#define sithAdvanceRenderTick_ADDR (0x004C4D80)
#define sithMain_set_sithmode_5_ADDR (0x004C4DB0)
#define sithMain_SetEpisodeName_ADDR (0x004C4DC0)

extern flex_t sithMain_lastAspect;

int sithMain_Startup(HostServices *commonFuncs);
void sithShutdown();
int sithOpenStatic(char *pFilename);
void sithCloseStatic();
int sithMain_Mode1Init(char *a1);
int sithOpenNormal(char *path);
int sithOpenMulti(char *fpath);
int sithOpen();
void sithClose();
void sithMain_SetEndLevel();
MATH_FUNC int sithUpdate();
void sithDrawScene();
void sithAdvanceRenderTick();
void sithMain_set_sithmode_5();
void sithMain_SetEpisodeName(char *text);
void sithOpenPostProcess();
void sithAdvanceRenderTick();

extern int sithMain_tickStartMs;
extern int sithMain_tickEndMs;

//static int (*sithMain_Startup)() = (void*)sithMain_Startup_ADDR;
//static int (*sithUpdate)() = (void*)sithUpdate_ADDR;
//static void (*sithOpenPostProcess)() = (void*)sithOpenPostProcess_ADDR;
//static int (*sithMain_Mode1Init)(char*) = (void*)sithMain_Mode1Init_ADDR;
//static int (*sithOpenMulti)(char*) = (void*)sithOpenMulti_ADDR;
//static void (*sithClose)() = (void*)sithClose_ADDR;

//static void (*sithMain_SetEpisodeName)(char *text) = (void*)sithMain_SetEpisodeName_ADDR;

#endif // _MAIN_SITHMAIN_H
