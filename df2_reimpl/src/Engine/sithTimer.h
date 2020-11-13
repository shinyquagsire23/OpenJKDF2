#ifndef _SITHTIMER_H
#define _SITHTIMER_H

#include <stdint.h>

#define sithTimer_Startup_ADDR (0x004F2650)
#define sithTimer_Shutdown_ADDR (0x004F26B0)
#define sithTimer_Open_ADDR (0x004F26D0)
#define sithTimer_Close_ADDR (0x004F26F0)
#define sithTimer_Reset_ADDR (0x004F2740)
#define sithTimer_Set_ADDR (0x004F2780)
#define sithTimer_Kill_ADDR (0x004F2820)
#define sithTimer_RegisterFunc_ADDR (0x004F2860)
#define sithTimer_Advance_ADDR (0x004F28B0)

typedef struct sithTimerInfo sithTimerInfo; 
typedef struct sithTimer sithTimer;

typedef int (*sithTimerHandler_t)(int, sithTimerInfo*);

typedef struct sithTimerInfo
{
    int cogIdx;
    int timerIdx;
    float field_10;
    float field_14;
} sithTimerInfo;

typedef struct sithTimer
{
    uint32_t endMs;
    int field_4;
    sithTimerInfo timerInfo;
    sithTimer* nextTimer;
} sithTimer;

typedef struct sithTimerFunc
{
    sithTimerHandler_t handler;
    uint32_t field_4;
    uint32_t rate;
    uint32_t creationMs;
    uint32_t field_10;
} sithTimerFunc;

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

#define sithTimer_timers ((sithTimer*)0x852F98)
#define sithTimer_list (*(sithTimer**)0x855000)
#define sithTimer_arrLut ((int*)0x854B98)
#define sithTimer_timerFuncs ((sithTimerFunc*)0x854F98)
#define sithTimer_numFree (*(int*)0x854FFC)
#define sithTimer_bInit (*(int*)0x855004)
#define sithTimer_bOpen (*(int*)0x855008)

#endif // _SITHTIMER_H
