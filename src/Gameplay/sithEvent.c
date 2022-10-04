#include "sithEvent.h"

#include "jk.h"
#include "Gameplay/sithTime.h"

int sithEvent_Startup()
{
    if ( sithEvent_bInit )
        return 0;

    _memset(sithEvent_aTasks, 0, sizeof(sithEventTask) * SITH_NUM_EVENTS);

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
    _memset(sithEvent_aEvents, 0, sizeof(sithEvent) * 256);
    int id = 256;
    for (int i = 0; i < 256; i++)
    {
        sithEvent_arrLut[i] = --id;
    }

    sithEvent_numFreeEventBuffers = 256;
    sithEvent_list = 0;
}

int sithEvent_Set(int taskId, sithEventInfo *timerInfo, uint32_t when)
{
    sithEvent *timer;
    sithEvent *v5;
    sithEvent *i;

    if ( sithEvent_numFreeEventBuffers )
        timer = &sithEvent_aEvents[sithEvent_arrLut[--sithEvent_numFreeEventBuffers]];
    else
        timer = 0;

    if ( !timer )
        return 0;

    timer->endMs = sithTime_curMs + when;
    timer->taskNum = taskId;
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

void sithEvent_Kill(sithEvent *pEvent)
{
    _memset(pEvent, 0, sizeof(sithEvent));
    
    intptr_t timerOffs = ((intptr_t)pEvent - (intptr_t)sithEvent_aEvents);
    
    sithEvent_arrLut[sithEvent_numFreeEventBuffers] = timerOffs / sizeof(sithEvent);

    sithEvent_numFreeEventBuffers++;
}

int sithEvent_RegisterFunc(int idx, sithEventHandler_t handler, int rate, int startMode)
{
    sithEvent_aTasks[idx].pfProcess = handler;
    sithEvent_aTasks[idx].creationMs = sithTime_curMs;
    sithEvent_aTasks[idx].field_10 = 0;
    sithEvent_aTasks[idx].rate = rate;
    sithEvent_aTasks[idx].startMode = startMode;
    return 1;
}

void sithEvent_Advance()
{
    sithEvent *i;

    for (int idx = 1; idx < 5; idx++)
    {
        sithEventTask* timerFunc = &sithEvent_aTasks[idx];
        if ( timerFunc->startMode == SITHEVENT_TASKPERIODIC )
        {
            uint32_t delta = (sithTime_curMs - timerFunc->creationMs);
            if ( delta > timerFunc->rate )
            {
                if ( timerFunc->pfProcess(delta, 0) )
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
        if (sithEvent_aTasks[i->taskNum].pfProcess)
            sithEvent_aTasks[i->taskNum].pfProcess(0, &i->timerInfo);
        
        sithEvent_Kill(i);
        i = sithEvent_list;
    }
}
