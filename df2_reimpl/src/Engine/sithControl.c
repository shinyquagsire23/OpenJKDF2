#include "sithControl.h"

int sithControl_IsOpen()
{
    return sithControl_bOpened;
}

#ifdef LINUX
void sithControl_InputInit()
{
}
#endif
