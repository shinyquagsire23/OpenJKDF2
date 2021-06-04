#include "sithControl.h"

#include "Win95/stdControl.h"

int sithControl_IsOpen()
{
    return sithControl_bOpened;
}

int sithControl_Open()
{
    if (stdControl_Open())
    {
        sithControl_dword_835830 = 0;
        sithControl_bOpened = 1;
        return 1;
    }
    return 0;
}

#ifdef LINUX
int sithControl_Initialize()
{
    return 1;
}

void sithControl_InputInit()
{
}

void sithControl_AddInputHandler(void *a1)
{
}
#endif
