#include "stdControl.h"

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
    return stdControl_GetAxis2(a);
}

float stdControl_GetAxis2(int a)
{
    const Uint8 *state = SDL_GetKeyboardState(NULL);
    
    if (a == 0)
    {
        float axisAmt = 0.0;
        
        if (state[SDL_SCANCODE_W] && a == 0) {
            axisAmt += 1.0;
        }
        else if (state[SDL_SCANCODE_S] && a == 0) {
            axisAmt += -1.0;
        }

        return axisAmt;
    }
    else if (a == 1)
    {
        float axisAmt = 0.0;
        
        if (state[SDL_SCANCODE_LEFT]) {
            axisAmt += 1.0;
        }
        else if (state[SDL_SCANCODE_RIGHT]) {
            axisAmt += -1.0;
        }
        
        Window_lastSampleMs = 6;
        axisAmt += (float)Window_lastXRel * -((double)Window_lastSampleMs / 44.0);
        
        Window_lastXRel = 0;
        
        return axisAmt;
    }
    else if (a == 2)
    {
        float axisAmt = 0.0;
        if (state[SDL_SCANCODE_A]) {
            axisAmt += -1.0;
        }
        if (state[SDL_SCANCODE_D]) {
            axisAmt += 1.0;
        }
        
        
        return axisAmt;
    }
    else if (a == 8)
    {
        float axisAmt = 0.0;
        
        if (state[SDL_SCANCODE_UP]) {
            axisAmt += 1.0;
        }
        else if (state[SDL_SCANCODE_DOWN]) {
            axisAmt += -1.0;
        }
        
        Window_lastSampleMs = 6;
        axisAmt += (float)Window_lastYRel * -((double)Window_lastSampleMs / 44.0);
        
        Window_lastYRel = 0;
        
        return axisAmt;
    }
    

    return 0.0;
}
#endif
