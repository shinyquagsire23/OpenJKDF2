#ifndef _SITHTIMER_H
#define _SITHTIMER_H

#define sithTimer_Startup_ADDR (0x004F2650)
#define sithTimer_Shutdown_ADDR (0x004F26B0)
#define sithTimer_Open_ADDR (0x004F26D0)
#define sithTimer_Close_ADDR (0x004F26F0)
#define sithTimer_Serialize_ADDR (0x004F2740)
#define sithTimer_Set_ADDR (0x004F2780)
#define sithTimer_Kill_ADDR (0x004F2820)
#define sithTimer_RegisterFunc_ADDR (0x004F2860)
#define sithTimer_Advance_ADDR (0x004F28B0)

typedef struct sithTimer sithTimer;

typedef struct sithTimerInfo
{
    int cogIdx;
    int timerIdx;
    float field_10;
    float field_14;
} sithTimerInfo;

typedef struct sithTimer
{
    int endMs;
    int field_4;
    sithTimerInfo timerInfo;
    sithTimer* nextTimer;
} sithTimer;

void (*sithTimer_Kill)(sithTimer *timer) = (void*)sithTimer_Kill_ADDR;
int (*sithTimer_Set)(int a1, sithTimerInfo *timerInfo, int timerMs) = (void*)sithTimer_Set_ADDR;

#define sithTimer_arr (*(sithTimer**)0x855000)

#endif // _SITHTIMER_H
