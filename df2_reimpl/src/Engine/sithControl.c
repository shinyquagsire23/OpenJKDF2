#include "sithControl.h"

int sithControl_IsOpen()
{
    return sithControl_bOpened;
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
