#ifndef _SITHEVENT_H
#define _SITHEVENT_H

#include "types.h"
#include "globals.h"

#define sithEvent_Startup_ADDR (0x004F2650)
#define sithEvent_Shutdown_ADDR (0x004F26B0)
#define sithEvent_Open_ADDR (0x004F26D0)
#define sithEvent_Close_ADDR (0x004F26F0)
#define sithEvent_Reset_ADDR (0x004F2740)
#define sithEvent_CreateEvent_ADDR (0x004F2780)
#define sithEvent_FreeEvent_ADDR (0x004F2820)
#define sithEvent_RegisterTask_ADDR (0x004F2860)
#define sithEvent_Process_ADDR (0x004F28B0)

#define SITHEVENT_TASKDISABLED (0)
#define SITHEVENT_TASKPERIODIC (1)
#define SITHEVENT_TASKONDEMAND (2)

int sithEvent_Startup();
void sithEvent_Shutdown();
void sithEvent_Open();
void sithEvent_Close();
void sithEvent_Reset();
int sithEvent_CreateEvent(int taskId, SithEventParams *params, uint32_t when);
void sithEvent_FreeEvent(SithEvent *pEvent);
int sithEvent_RegisterTask(int idx, sithEventHandler_t handler, int rate, int startMode);
void sithEvent_Process();

//static void (*sithEvent_FreeEvent)(SithEvent *timer) = (void*)sithEvent_FreeEvent_ADDR;
//static int (*sithEvent_CreateEvent)(int a1, SithEventParams *params, int timerMs) = (void*)sithEvent_CreateEvent_ADDR;

#endif // _SITHEVENT_H
