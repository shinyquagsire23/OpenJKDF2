#include "sithEvent.h"

#include "jk.h"
#include "Gameplay/sithTime.h"

int sithEvent_Startup()
{
    if ( sithEvent_bInit )
        return 0;

    _memset(sithEvent_aTasks, 0, sizeof(SithEventTask) * SITH_NUM_EVENTS);

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
    _memset(sithEvent_aEvents, 0, sizeof(SithEvent) * 256);
    int id = 256;
    for (int i = 0; i < 256; i++)
    {
        sithEvent_arrLut[i] = --id;
    }

    sithEvent_numFreeEventBuffers = 256;
    sithEvent_g_pFirstQueuedEvent = 0;
}

int sithEvent_CreateEvent(int taskId, SithEventParams *params, uint32_t when)
{
    SithEvent *timer;
    SithEvent *v5;
    SithEvent *i;

    if ( sithEvent_numFreeEventBuffers )
        timer = &sithEvent_aEvents[sithEvent_arrLut[--sithEvent_numFreeEventBuffers]];
    else
        timer = 0;

    if ( !timer )
        return 0;

    timer->msecEventTime = sithTime_g_msecGameTime + when;
    timer->taskNum = taskId;
    timer->params = *params;

    v5 = sithEvent_g_pFirstQueuedEvent;
    for ( i = 0; v5; v5 = v5->pNextEvent )
    {
        if ( v5->msecEventTime > timer->msecEventTime )
            break;
        i = v5;
    }

    if ( i )
    {
        i->pNextEvent = timer;
        timer->pNextEvent = v5;
    }
    else
    {
        timer->pNextEvent = v5;
        sithEvent_g_pFirstQueuedEvent = timer;
    }

    return 1;
}

void sithEvent_FreeEvent(SithEvent *pEvent)
{
    _memset(pEvent, 0, sizeof(SithEvent));
    
    intptr_t timerOffs = ((intptr_t)pEvent - (intptr_t)sithEvent_aEvents);
    
    sithEvent_arrLut[sithEvent_numFreeEventBuffers] = timerOffs / sizeof(SithEvent);

    sithEvent_numFreeEventBuffers++;
}

int sithEvent_RegisterTask(int taskId, sithEventHandler_t pfProcess, int frequency, int startMode)
{
    sithEvent_aTasks[taskId].pfProcess = pfProcess;
    sithEvent_aTasks[taskId].msecLastIntervalTime = sithTime_g_msecGameTime;
    sithEvent_aTasks[taskId].field_10 = 0;
    sithEvent_aTasks[taskId].rate = frequency;
    sithEvent_aTasks[taskId].startMode = startMode;
    return 1;
}

void sithEvent_Process()
{
    SithEvent *i;

    for (int idx = 1; idx < 5; idx++)
    {
        SithEventTask* timerFunc = &sithEvent_aTasks[idx];
        if ( timerFunc->startMode == SITHEVENT_TASKPERIODIC )
        {
            uint32_t delta = (sithTime_g_msecGameTime - timerFunc->msecLastIntervalTime);
            if ( delta > timerFunc->rate )
            {
                if ( timerFunc->pfProcess(delta, 0) )
                    timerFunc->msecLastIntervalTime = sithTime_g_msecGameTime;
            }
        }
    }

    i = sithEvent_g_pFirstQueuedEvent;
    while (i)
    {
        if ( i->msecEventTime >= sithTime_g_msecGameTime )
            break;

        sithEvent_g_pFirstQueuedEvent = i->pNextEvent;

        // Added: nullptr check
        if (sithEvent_aTasks[i->taskNum].pfProcess)
            sithEvent_aTasks[i->taskNum].pfProcess(0, &i->params);
        
        sithEvent_FreeEvent(i);
        i = sithEvent_g_pFirstQueuedEvent;
    }
}
