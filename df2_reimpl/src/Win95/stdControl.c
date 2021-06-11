#include "stdControl.h"

int stdControl_MessageHandler(int a1, int a2, int a3)
{
    if ( a2 != 0x112 )
        return 0;
    return a3 == 0xF100 || a3 == 0xF140;
}

#ifdef LINUX
#include <SDL2/SDL.h>
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

float stdControl_GetAxis2(int a)
{
    const Uint8 *state = SDL_GetKeyboardState(NULL);
    if (state[SDL_SCANCODE_W] && a == 0) {
        return 1.0;
    }
    else if (state[SDL_SCANCODE_S] && a == 0) {
        return -1.0;
    }
    else if (state[SDL_SCANCODE_LEFT] && a == 1) {
        return 1.0;
    }
    else if (state[SDL_SCANCODE_RIGHT] && a == 1) {
        return -1.0;
    }
    else if (state[SDL_SCANCODE_A] && a == 2) {
        return -1.0;
    }
    else if (state[SDL_SCANCODE_D] && a == 2) {
        return 1.0;
    }

    return 0.0;
}
#endif
