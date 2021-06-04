#include "stdControl.h"

int stdControl_MessageHandler(int a1, int a2, int a3)
{
    if ( a2 != 0x112 )
        return 0;
    return a3 == 0xF100 || a3 == 0xF140;
}

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

int stdControl_Open()
{
    return 1;
}
#endif
