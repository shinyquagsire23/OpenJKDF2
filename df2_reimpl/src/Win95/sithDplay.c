#include "sithDplay.h"

int sithDplay_Startup()
{
    if ( sithDplay_bInitted )
        return 0;

#ifdef WIN32
    DirectPlay_Initialize();
#endif
    sithDplay_bInitted = 1;

    return 1;
}

#ifdef LINUX
int sithDplay_EarlyInit()
{
    return 1;
}
#endif
