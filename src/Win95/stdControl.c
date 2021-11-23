#include "stdControl.h"

#include "Engine/sithControl.h"
#include "Win95/Window.h"

int stdControl_MessageHandler(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam, void* unused)
{
    if ( Msg != 0x112 )
        return 0;
    return wParam == 0xF100 || wParam == 0xF140;
}

#ifdef SDL2_RENDER
#include <SDL2/SDL.h>
void stdControl_Flush()
{
}

void stdControl_ToggleCursor(int a)
{
    SDL_SetRelativeMouseMode(!!a);
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

int stdControl_Close()
{
    return 1;
}

int stdControl_ReadControls()
{
    return 1;
}

int stdControl_FinishRead()
{
    return 1;
}

float stdControl_ReadAxis(int a)
{
    return sithControl_GetAxis2(a);
}
#endif
