#include "stdControl.h"

#ifdef LINUX
void stdControl_Flush()
{
}

void stdControl_ToggleCursor(int a)
{
    
}

static int _cursorState = 0;

int stdControl_ShowCursor(int a)
{
    if (a)
    {
        _cursorState++;
    }
    else
    {
        _cursorState--;
    }
    return _cursorState;
}
#endif
