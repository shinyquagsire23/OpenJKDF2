#include "sithTimer.h"

int sithTimer_Startup()
{
    if ( sithTimer_bInit )
        return 0;

    _memset(sithTimer_timerFuncs, 0, sizeof(sithTimer_timerFuncs));
    _memset(sithTimer_timers, 0, sizeof(sithTimer_timers));

    int id = 256;
    for (int i = 0; i < 256; i++)
    {
        sithTimer_arrLut[i] = --id;
    }

    sithTimer_numFree = 256;
    sithTimer_arr = 0;
    sithTimer_bInit = 1;

    return 1;
}
