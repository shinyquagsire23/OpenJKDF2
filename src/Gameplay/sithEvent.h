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

#define SITHEVENT_TASKDISABLED (0)
#define SITHEVENT_TASKPERIODIC (1)
#define SITHEVENT_TASKONDEMAND (2)

int sithEvent_Startup();
void sithEvent_Shutdown();
void sithEvent_Open();
void sithEvent_Close();
void sithEvent_Reset();
int sithEvent_Set(int taskId, sithEventInfo *timerInfo, uint32_t when);
void sithEvent_Kill(sithEvent *pEvent);
int sithEvent_RegisterFunc(int idx, sithEventHandler_t handler, int rate, int startMode);
void sithEvent_Advance();

//static void (*sithEvent_Kill)(sithEvent *timer) = (void*)sithEvent_Kill_ADDR;
//static int (*sithEvent_Set)(int a1, sithEventInfo *timerInfo, int timerMs) = (void*)sithEvent_Set_ADDR;

#endif // _SITHEVENT_H
