#include "sithTime.h"

#include "stdPlatform.h"

// original game will speed up if framerate is over 100?
#ifndef QOL_IMPROVEMENTS
#define SITHTIME_MINDELTA (10)
#define SITHTIME_MAXDELTA (500)
#else
#define SITHTIME_MINDELTA (1)
#define SITHTIME_MAXDELTA (500)
#endif

void sithTime_Tick()
{
    sithTime_SetDelta(stdPlatform_GetTimeMsec() - sithTime_curMsAbsolute);
}

void sithTime_Pause()
{
    if ( !sithTime_bRunning )
    {
        sithTime_pauseTimeMs = stdPlatform_GetTimeMsec();
        sithTime_bRunning = 1;
    }
}

void sithTime_Resume()
{
    if ( sithTime_bRunning )
    {
        sithTime_bRunning = 0;
        sithTime_curMsAbsolute += stdPlatform_GetTimeMsec() - sithTime_pauseTimeMs;
    }
}

void sithTime_SetDelta(int deltaMs)
{
    sithTime_deltaMs = deltaMs;
    sithTime_curMsAbsolute = stdPlatform_GetTimeMsec();
    if ( sithTime_deltaMs < SITHTIME_MINDELTA )
    {
        sithTime_deltaMs = SITHTIME_MINDELTA;
    }
    if ( sithTime_deltaMs > SITHTIME_MAXDELTA )
    {
        sithTime_deltaMs = SITHTIME_MAXDELTA;
    }
    sithTime_curMs += sithTime_deltaMs;
    sithTime_deltaSeconds = (double)sithTime_deltaMs * 0.001;
    sithTime_TickHz = 1.0 / sithTime_deltaSeconds;
    sithTime_curSeconds = (double)sithTime_curMs * 0.001;
}

void sithTime_Startup()
{
    sithTime_curMs = 0;
    sithTime_curSeconds = 0.0;
    sithTime_deltaMs = 0;
    sithTime_deltaSeconds = 0.0;
    sithTime_TickHz = 0.0;
    sithTime_curMsAbsolute = stdPlatform_GetTimeMsec();
}

void sithTime_SetMs(uint32_t curMs)
{
    sithTime_deltaSeconds = 0.0;
    sithTime_TickHz = 0.0;
    sithTime_curMs = curMs;
    sithTime_deltaMs = 0;
    sithTime_curSeconds = (double)curMs * 0.001;
    sithTime_curMsAbsolute = stdPlatform_GetTimeMsec();
}
