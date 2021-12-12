#include "sithEvent.h"

#include "jk.h"
#include "Engine/sithTime.h"

int sithEvent_Startup()
{
    if ( sithEvent_bInit )
        return 0;

    _memset(sithEvent_timerFuncs, 0, sizeof(sithTimerFunc) * 5);

    sithEvent_Reset();
    sithEvent_bInit = 1;

    return 1;
}

void sithEvent_Shutdown()
{
    if (sithEvent_bInit)
        sithEvent_bInit = 0;
}

void sithEvent_Open()
{
    if ( !sithEvent_bOpen )
        sithEvent_bOpen = 1;
}

void sithEvent_Close()
{
    if ( sithEvent_bOpen )
    {
        sithEvent_Reset();
        sithEvent_bOpen = 0;
    }
}

void sithEvent_Reset()
{
    _memset(sithEvent_timers, 0, sizeof(sithTimer) * 256);
    int id = 256;
    for (int i = 0; i < 256; i++)
    {
        sithEvent_arrLut[i] = --id;
    }

    sithEvent_numFree = 256;
    sithEvent_list = 0;
}

int sithEvent_Set(int a1, sithTimerInfo *timerInfo, int timerMs)
{
    sithTimer *timer;
    sithTimer *v5;
    sithTimer *i;

    if ( sithEvent_numFree )
        timer = &sithEvent_timers[sithEvent_arrLut[--sithEvent_numFree]];
    else
        timer = 0;

    if ( !timer )
        return 0;

    timer->endMs = sithTime_curMs + timerMs;
    timer->field_4 = a1;
    timer->timerInfo = *timerInfo;

    v5 = sithEvent_list;
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
        sithEvent_list = timer;
    }

    return 1;
}

void sithEvent_Kill(sithTimer *timer)
{
    _memset(timer, 0, sizeof(sithTimer));
    
    intptr_t timerOffs = ((intptr_t)timer - (intptr_t)sithEvent_timers);
    
    sithEvent_arrLut[sithEvent_numFree] = timerOffs / sizeof(sithTimer);

    sithEvent_numFree++;
}

int sithEvent_RegisterFunc(int idx, sithTimerHandler_t handler, int rate, int a4)
{
    sithEvent_timerFuncs[idx].handler = handler;
    sithEvent_timerFuncs[idx].creationMs = sithTime_curMs;
    sithEvent_timerFuncs[idx].field_10 = 0;
    sithEvent_timerFuncs[idx].rate = rate;
    sithEvent_timerFuncs[idx].field_4 = a4;
    return 1;
}

void sithEvent_Advance()
{
    sithTimer *i;

    for (int idx = 1; idx < 5; idx++)
    {
        sithTimerFunc* timerFunc = &sithEvent_timerFuncs[idx];
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

    i = sithEvent_list;
    while (i)
    {
        if ( i->endMs >= sithTime_curMs )
            break;

        sithEvent_list = i->nextTimer;

        // Added: nullptr check
        if (sithEvent_timerFuncs[i->field_4].handler)
            sithEvent_timerFuncs[i->field_4].handler(0, &i->timerInfo);
        
        sithEvent_Kill(i);
        i = sithEvent_list;
    }
}
