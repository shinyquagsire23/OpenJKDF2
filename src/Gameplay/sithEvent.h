#ifndef _SITHEVENT_H
#define _SITHEVENT_H

#include "types.h"
#include "globals.h"

#define sithEvent_Startup_ADDR (0x004F2650)
#define sithEvent_Shutdown_ADDR (0x004F26B0)
#define sithEvent_Open_ADDR (0x004F26D0)
#define sithEvent_Close_ADDR (0x004F26F0)
#define sithEvent_Reset_ADDR (0x004F2740)
#define sithEvent_Set_ADDR (0x004F2780)
#define sithEvent_Kill_ADDR (0x004F2820)
#define sithEvent_RegisterFunc_ADDR (0x004F2860)
#define sithEvent_Advance_ADDR (0x004F28B0)

int sithEvent_Startup();
void sithEvent_Shutdown();
void sithEvent_Open();
void sithEvent_Close();
void sithEvent_Reset();
int sithEvent_Set(int a1, sithTimerInfo *timerInfo, int timerMs);
void sithEvent_Kill(sithTimer *timer);
int sithEvent_RegisterFunc(int idx, sithTimerHandler_t handler, int rate, int a4);
void sithEvent_Advance();

//static void (*sithEvent_Kill)(sithTimer *timer) = (void*)sithEvent_Kill_ADDR;
//static int (*sithEvent_Set)(int a1, sithTimerInfo *timerInfo, int timerMs) = (void*)sithEvent_Set_ADDR;

#endif // _SITHEVENT_H
