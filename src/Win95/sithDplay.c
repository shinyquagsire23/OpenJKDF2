#include "sithDplay.h"

int sithDplay_Startup()
{
    if ( sithDplay_bInitted )
        return 0;

#ifdef TARGET_HAS_DPLAY
    DirectPlay_Initialize();
#endif
    sithDplay_bInitted = 1;

    return 1;
}

#ifndef WIN32_BLOBS
int sithDplay_EarlyInit()
{
    return 0;
}

int sithDplay_OpenConnection(void* a)
{
    return 0;
}

void sithDplay_CloseConnection()
{
}

int sithDplay_Open(int a, void* b)
{
    return 0;
}
#endif
