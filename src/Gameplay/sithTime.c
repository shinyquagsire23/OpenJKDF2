#include "sithTime.h"

#include "stdPlatform.h"

#ifdef MICROSECOND_TIME
static int64_t sithTime_deltaUs;
static uint64_t sithTime_curUsAbsolute;
static int64_t sithTime_pauseTimeUs;
#endif

//#define TIME_PROFILING
#ifdef TIME_PROFILING
static uint64_t sithTime_deltaUs_history[1000];
static size_t sithTime_deltaUs_history_idx = 0;
static size_t sithTime_deltaUs_history_collected_entries = 0;
#endif

// Added
flex_d_t sithTime_physicsRolloverFrames = 0.0;

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
        sithTime_deltaMs = (uint32_t)((flex_d_t)sithTime_deltaMs * 0.2);
    }
    sithTime_curMs += sithTime_deltaMs;
#ifdef MICROSECOND_TIME
    sithTime_deltaUs = Linux_TimeUs() - sithTime_curUsAbsolute;
    if ( sithTime_deltaUs < SITHTIME_MINDELTA_US )
    {
        sithTime_deltaUs = SITHTIME_MINDELTA_US;
    }
    if ( sithTime_deltaUs > SITHTIME_MAXDELTA_US)
    {
        sithTime_deltaUs = SITHTIME_MAXDELTA_US;
    }
    if (g_debugmodeFlags & DEBUGFLAG_SLOWMO) {
        sithTime_deltaUs = (uint64_t)((flex_d_t)sithTime_deltaUs * 0.2);
    }
    sithTime_curUsAbsolute = Linux_TimeUs();
    sithTime_deltaSeconds = (flex_d_t)sithTime_deltaUs * 0.001 * 0.001;

#ifdef TIME_PROFILING
    sithTime_deltaUs_history[sithTime_deltaUs_history_idx++] = sithTime_deltaUs;
    if (sithTime_deltaUs_history_idx >= 1000) {
        sithTime_deltaUs_history_idx = 0;
    }
    sithTime_deltaUs_history_collected_entries++;
    if (sithTime_deltaUs_history_collected_entries >= 1000) {
        sithTime_deltaUs_history_collected_entries = 1000;
    } 
    uint64_t avg_us = 0;
    uint64_t largest_us = 0;
    uint64_t smallest_us = 0xFFFFFFFF;
    for (int i = 0; i < sithTime_deltaUs_history_collected_entries; i++) {
        uint64_t val = sithTime_deltaUs_history[i];
        if (val > largest_us) 
            largest_us = val;
        if (val < smallest_us)
            smallest_us = val;
        avg_us += val;
    }
    avg_us /= sithTime_deltaUs_history_collected_entries;

    printf("%u %u %f %llu %llu %llu\n", sithTime_deltaMs, sithTime_deltaUs, sithTime_deltaSeconds, avg_us, largest_us, smallest_us);
#endif // TIME_PROFILING
#else
    sithTime_deltaSeconds = (flex_d_t)sithTime_deltaMs * 0.001;
#endif
    sithTime_TickHz = 1.0 / sithTime_deltaSeconds;
    sithTime_curSeconds = (flex_d_t)sithTime_curMs * 0.001;
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
    sithTime_curSeconds = (flex_d_t)curMs * 0.001;
    sithTime_curMsAbsolute = stdPlatform_GetTimeMsec();
}
