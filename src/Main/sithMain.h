#ifndef _MAIN_SITHMAIN_H
#define _MAIN_SITHMAIN_H

#include "types.h"
#include "globals.h"

#define sithMain_Startup_ADDR (0x004C4630)
#define sithMain_Shutdown_ADDR (0x004C4700)
#define sithMain_Load_ADDR (0x004C4780)
#define sithMain_Free_ADDR (0x004C47B0)
#define sithMain_Mode1Init_ADDR (0x004C47D0)
#define sithMain_AutoSave_ADDR (0x004C4880)
#define sithMain_OpenNormal_ADDR (0x004C49D0)
#define sithMain_Mode1Init_3_ADDR (0x004C4A70)
#define sithMain_Open_ADDR (0x004C4B10)
#define sithMain_Close_ADDR (0x004C4B80)
#define sithMain_SetEndLevel_ADDR (0x004C4BF0)
#define sithMain_Tick_ADDR (0x004C4C00)
#define sithMain_UpdateCamera_ADDR (0x004C4D30)
#define sithMain_sub_4C4D80_ADDR (0x004C4D80)
#define sithMain_set_sithmode_5_ADDR (0x004C4DB0)
#define sithMain_SetEpisodeName_ADDR (0x004C4DC0)

extern flex_t sithMain_lastAspect;

int sithMain_Startup(HostServices *commonFuncs);
void sithMain_Shutdown();
int sithMain_Load(char *path);
void sithMain_Free();
int sithMain_Mode1Init(char *a1);
int sithMain_OpenNormal(char *path);
int sithMain_Mode1Init_3(char *fpath);
int sithMain_Open();
void sithMain_Close();
void sithMain_SetEndLevel();
int sithMain_Tick();
void sithMain_UpdateCamera();
void sithMain_sub_4C4D80();
void sithMain_set_sithmode_5();
void sithMain_SetEpisodeName(char *text);
void sithMain_AutoSave();
void sithMain_sub_4C4D80();

//static int (*sithMain_Startup)() = (void*)sithMain_Startup_ADDR;
//static int (*sithMain_Tick)() = (void*)sithMain_Tick_ADDR;
//static void (*sithMain_AutoSave)() = (void*)sithMain_AutoSave_ADDR;
//static int (*sithMain_Mode1Init)(char*) = (void*)sithMain_Mode1Init_ADDR;
//static int (*sithMain_Mode1Init_3)(char*) = (void*)sithMain_Mode1Init_3_ADDR;
//static void (*sithMain_Close)() = (void*)sithMain_Close_ADDR;

//static void (*sithMain_SetEpisodeName)(char *text) = (void*)sithMain_SetEpisodeName_ADDR;

#endif // _MAIN_SITHMAIN_H
