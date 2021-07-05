#include "jkDev.h"

#include "Win95/stdDisplay.h"

void jkDev_Close()
{
    if ( jkDev_bOpened )
    {
        if ( jkDev_vbuf )
        {
            stdDisplay_VBufferFree(jkDev_vbuf);
            jkDev_vbuf = 0;
        }
        jkDev_bOpened = 0;
    }
}

#ifdef LINUX
void jkDev_PrintUniString(wchar_t* str)
{
}
#endif
