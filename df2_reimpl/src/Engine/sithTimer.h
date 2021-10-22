#ifndef _SITHTIMER_H
#define _SITHTIMER_H

#include "types.h"
#include "globals.h"

#define sithTimer_Startup_ADDR (0x004F2650)
#define sithTimer_Shutdown_ADDR (0x004F26B0)
#define sithTimer_Open_ADDR (0x004F26D0)
#define sithTimer_Close_ADDR (0x004F26F0)
#define sithTimer_Reset_ADDR (0x004F2740)
#define sithTimer_Set_ADDR (0x004F2780)
#define sithTimer_Kill_ADDR (0x004F2820)
#define sithTimer_RegisterFunc_ADDR (0x004F2860)
#define sithTimer_Advance_ADDR (0x004F28B0)

int sithTimer_Startup();
void sithTimer_Shutdown();
void sithTimer_Open();
void sithTimer_Close();
void sithTimer_Reset();
int sithTimer_Set(int a1, sithTimerInfo *timerInfo, int timerMs);
void sithTimer_Kill(sithTimer *timer);
int sithTimer_RegisterFunc(int idx, sithTimerHandler_t handler, int rate, int a4);
void sithTimer_Advance();

//static void (*sithTimer_Kill)(sithTimer *timer) = (void*)sithTimer_Kill_ADDR;
//static int (*sithTimer_Set)(int a1, sithTimerInfo *timerInfo, int timerMs) = (void*)sithTimer_Set_ADDR;

#endif // _SITHTIMER_H
