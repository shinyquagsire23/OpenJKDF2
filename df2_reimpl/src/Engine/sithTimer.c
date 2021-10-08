#include "sithTimer.h"

#include "jk.h"
#include "Engine/sithTime.h"

int sithTimer_Startup()
{
    if ( sithTimer_bInit )
        return 0;

    _memset(sithTimer_timerFuncs, 0, sizeof(sithTimer_timerFuncs));

    sithTimer_Reset();
    sithTimer_bInit = 1;

    return 1;
}

void sithTimer_Shutdown()
{
    if (sithTimer_bInit)
        sithTimer_bInit = 0;
}

void sithTimer_Open()
{
    if ( !sithTimer_bOpen )
        sithTimer_bOpen = 1;
}

void sithTimer_Close()
{
    if ( sithTimer_bOpen )
    {
        sithTimer_Reset();
        sithTimer_bOpen = 0;
    }
}

void sithTimer_Reset()
{
    _memset(sithTimer_timers, 0, sizeof(sithTimer_timers));
    int id = 256;
    for (int i = 0; i < 256; i++)
    {
        sithTimer_arrLut[i] = --id;
    }

    sithTimer_numFree = 256;
    sithTimer_list = 0;
}

int sithTimer_Set(int a1, sithTimerInfo *timerInfo, int timerMs)
{
    sithTimer *timer;
    sithTimer *v5;
    sithTimer *i;

    if ( sithTimer_numFree )
        timer = &sithTimer_timers[sithTimer_arrLut[--sithTimer_numFree]];
    else
        timer = 0;

    if ( !timer )
        return 0;

    timer->endMs = sithTime_curMs + timerMs;
    timer->field_4 = a1;
    timer->timerInfo = *timerInfo;

    v5 = sithTimer_list;
    for ( i = 0; v5; v5 = v5->nextTimer )
    {
        if ( v5->endMs > timer->endMs )
            break;
        i = v5;
    }

    if ( i )
    {
        i->nextTimer = timer;
        timer->nextTimer = v5;
    }
    else
    {
        timer->nextTimer = v5;
        sithTimer_list = timer;
    }

    return 1;
}

void sithTimer_Kill(sithTimer *timer)
{
    _memset(timer, 0, sizeof(sithTimer));
    
    uint32_t timerOffs = (uint32_t)((char *)timer - (char *)sithTimer_timers);
    
    // ????
    uint32_t v1 = (signed int)(timerOffs + ((uint64_t)(0xFFFFFFFF92492493ull * timerOffs) >> 32)) >> 4;
    sithTimer_arrLut[sithTimer_numFree] = (v1 >> 31) + v1;

    sithTimer_numFree++;
}

int sithTimer_RegisterFunc(int idx, sithTimerHandler_t handler, int rate, int a4)
{
    sithTimer_timerFuncs[idx].handler = handler;
    sithTimer_timerFuncs[idx].creationMs = sithTime_curMs;
    sithTimer_timerFuncs[idx].field_10 = 0;
    sithTimer_timerFuncs[idx].rate = rate;
    sithTimer_timerFuncs[idx].field_4 = a4;
    return 1;
}

void sithTimer_Advance()
{
    sithTimer *i;

    for (int idx = 1; idx < 5; idx++)
    {
        sithTimerFunc* timerFunc = &sithTimer_timerFuncs[idx];
        if ( timerFunc->field_4 == 1 )
        {
            uint32_t delta = (sithTime_curMs - timerFunc->creationMs);
            if ( delta > timerFunc->rate )
            {
                if ( timerFunc->handler(delta, 0) )
                    timerFunc->creationMs = sithTime_curMs;
            }
        }
    }

    for ( i = sithTimer_list; i; sithTimer_numFree )
    {
        if ( i->endMs >= sithTime_curMs )
            break;

        sithTimer_list = i->nextTimer;
        sithTimer_timerFuncs[i->field_4].handler(0, &i->timerInfo);
        
        sithTimer_Kill(i);
        i = sithTimer_list;
    }
}
