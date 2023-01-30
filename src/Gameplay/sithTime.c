#include "sithTime.h"

#include "stdPlatform.h"

#ifdef MICROSECOND_TIME
static int64_t sithTime_deltaUs;
static uint64_t sithTime_curUsAbsolute;
static int64_t sithTime_pauseTimeUs;
#endif

// Added
double sithTime_physicsRolloverFrames = 0.0;

// MOTS altered
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
#ifdef MICROSECOND_TIME
        sithTime_pauseTimeUs = Linux_TimeUs();
#endif

        sithTime_physicsRolloverFrames = 0.0; // Added
    }
}

void sithTime_Resume()
{
    if ( sithTime_bRunning )
    {
        sithTime_bRunning = 0;
        sithTime_curMsAbsolute += stdPlatform_GetTimeMsec() - sithTime_pauseTimeMs;
#ifdef MICROSECOND_TIME
        sithTime_curUsAbsolute += Linux_TimeUs() - sithTime_pauseTimeUs;
#endif

        sithTime_physicsRolloverFrames = 0.0; // Added
    }
}

// MOTS altered: min/max are variables
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
    if (g_debugmodeFlags & DEBUGFLAG_SLOWMO) {
        sithTime_deltaMs = (uint32_t)((double)sithTime_deltaMs * 0.2);
    }
    sithTime_curMs += sithTime_deltaMs;
#ifdef MICROSECOND_TIME
    sithTime_deltaUs = Linux_TimeUs() - sithTime_curUsAbsolute;
    if ( sithTime_deltaMs < SITHTIME_MINDELTA_US )
    {
        sithTime_deltaMs = SITHTIME_MINDELTA_US;
    }
    if ( sithTime_deltaUs > SITHTIME_MAXDELTA_US)
    {
        sithTime_deltaUs = SITHTIME_MAXDELTA_US;
    }
    if (g_debugmodeFlags & DEBUGFLAG_SLOWMO) {
        sithTime_deltaUs = (uint64_t)((double)sithTime_deltaUs * 0.2);
    }
    sithTime_curUsAbsolute = Linux_TimeUs();
    sithTime_deltaSeconds = (double)sithTime_deltaUs * 0.001 * 0.001;
    //printf("%u %u %f\n", sithTime_deltaMs, sithTime_deltaUs, sithTime_deltaSeconds);
#else
    sithTime_deltaSeconds = (double)sithTime_deltaMs * 0.001;
#endif
    sithTime_TickHz = 1.0 / sithTime_deltaSeconds;
    sithTime_curSeconds = (double)sithTime_curMs * 0.001;
}

void sithTime_Startup()
{
#ifdef MICROSECOND_TIME
    sithTime_curUsAbsolute = Linux_TimeUs();
    sithTime_pauseTimeUs = 0;
    sithTime_deltaUs = 0;
#endif
    sithTime_curMs = 0;
    sithTime_curSeconds = 0.0;
    sithTime_deltaMs = 0;
    sithTime_deltaSeconds = 0.0;
    sithTime_TickHz = 0.0;
    sithTime_curMsAbsolute = stdPlatform_GetTimeMsec();

    sithTime_physicsRolloverFrames = 0.0; // Added
}

void sithTime_SetMs(uint32_t curMs)
{
#ifdef MICROSECOND_TIME
    sithTime_curUsAbsolute = Linux_TimeUs();
    sithTime_pauseTimeUs = 0;
    sithTime_deltaUs = 0;
#endif
    sithTime_deltaSeconds = 0.0;
    sithTime_TickHz = 0.0;
    sithTime_curMs = curMs;
    sithTime_deltaMs = 0;
    sithTime_curSeconds = (double)curMs * 0.001;
    sithTime_curMsAbsolute = stdPlatform_GetTimeMsec();
}
