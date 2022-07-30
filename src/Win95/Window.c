#include "Window.h"

#include "Win95/stdGdi.h"
#include "Platform/std3D.h"
#include "Main/Main.h"
#include "Main/jkMain.h"
#include "Main/jkGame.h"
#include "Gui/jkGUI.h"
#include "Win95/stdDisplay.h"
#include "World/jkPlayer.h"
#include "Platform/stdControl.h"
#include "stdPlatform.h"

#include "jk.h"

#ifdef ARCH_WASM
#include <emscripten.h>
#endif

int Window_xSize = 640;
int Window_ySize = 480;
int Window_screenXSize = 640;
int Window_screenYSize = 480;
int Window_isHiDpi = 0;
int Window_isFullscreen = 0;
int Window_needsRecreate = 0;

void Window_SetHiDpi(int val)
{
    if (Window_isHiDpi != val)
    {
        Window_isHiDpi = val;

        Window_needsRecreate = 1;
    }
}

void Window_SetFullscreen(int val)
{
    if (Window_isFullscreen != val)
    {
        Window_isFullscreen = val;
        Window_needsRecreate = 1;
    }
}

//static wm_handler Window_ext_handlers[16] = {0};

int Window_AddMsgHandler(WindowHandler_t a1)
{
    int i = 0;

    // Added: no duplicates
    for (i = 0; i < 16; i++)
    {
        if (Window_ext_handlers[i].exists && Window_ext_handlers[i].handler == a1)
            return 1;
    }

    for (i = 0; i < 16; i++)
    {
        if ( !Window_ext_handlers[i].exists )
            break;
    }
    
    // Added: no OOB
    if (i >= 16) return 1;

    Window_ext_handlers[i].handler = a1;
    Window_ext_handlers[i].exists = 1;
    ++g_handler_count;
    return 1;
}

int Window_RemoveMsgHandler(WindowHandler_t a1)
{
    int i = 0;

    // Added: the original would still decrement on missing handlers
    for (i = 0; i < 16; i++)
    {
        if ( Window_ext_handlers[i].handler == a1 )
        {
            Window_ext_handlers[i].handler = 0;
            Window_ext_handlers[i].exists = 0;
            g_handler_count -= 1; // doing g_handler_count-- changes behavior???
            return 1;
        }
    }

    return 1;
}

int Window_AddDialogHwnd(HWND a1)
{
    int v1; // eax

    v1 = g_thing_two_some_dialog_count;
    if ( (unsigned int)g_thing_two_some_dialog_count >= 0x10 )
        return 0;
    Window_aDialogHwnds[g_thing_two_some_dialog_count] = a1;
    g_thing_two_some_dialog_count = v1 + 1;
    return 1;
}

#ifdef SDL2_RENDER
static int dword_855E98 = 0;
static int dword_855DE4 = 0;
#else
#define dword_855E98 (*(int*)0x855E98)
#define dword_855DE4 (*(int*)0x855DE4)
#endif

int Window_msg_main_handler(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    int handler_count; // ebx
    struct wm_handler *ext_handler; // esi
    DWORD dwProcessId; // [esp+10h] [ebp-8h] BYREF
    LRESULT v10; // [esp+14h] [ebp-4h] BYREF

    switch ( Msg )
    {
        case WM_CREATE:
            g_app_active = 0;
            g_window_active = 0;
            break;
        case WM_DESTROY:
            g_window_not_destroyed = 0;
            Main_Shutdown();
            break;
        case WM_ACTIVATE:
            if ( (uint16_t)wParam == 2 || (uint16_t)wParam == 1 )// WA_ACTIVE or WA_CLICKACTIVE
            {
                g_window_active = 1;
                if ( dword_855E98 )
                {
                    dword_855E98 = 0;
                    if ( Window_setCooperativeLevel )
                        Window_setCooperativeLevel(0);
                }
#ifdef WIN32_BLOBS
                jk_SetFocus(g_hWnd);
#endif
            }
            else
            {
                if ( dword_855DE4 == 1 && g_window_not_destroyed && g_app_active && !dword_855E98 )
                {
                    dwProcessId = 0;
                    lParam = 1;
                    if ( lParam )
                    {
#ifdef WIN32_BLOBS
                        jk_GetWindowThreadProcessId((HWND)lParam, (LPDWORD)&lParam);
                        jk_GetWindowThreadProcessId(hWnd, &dwProcessId);
#endif
                    }
                    if ( dwProcessId == lParam )
                    {
                        dword_855E98 = 1;
                        if ( Window_drawAndFlip )
                            Window_drawAndFlip(0);
                    }
                }
                g_window_active = 0;
            }
            break;
        case WM_ACTIVATEAPP:
            g_app_active = wParam != 0;
            break;
        default:
            break;
    }

    if ( !g_app_active || (g_app_suspended = 1, !g_window_active) )
        g_app_suspended = 0;
    handler_count = 0;

    if ( g_handler_count <= 0 )
        return Window_DefaultHandler(hWnd, Msg, wParam, lParam, NULL);

    for ( ext_handler = Window_ext_handlers; !ext_handler->exists || !ext_handler->handler(hWnd, Msg, wParam, lParam, &v10); ++ext_handler )
    {
        if ( ++handler_count >= g_handler_count )
            return Window_DefaultHandler(hWnd, Msg, wParam, lParam, NULL);
    }
    return v10;
}

#ifndef SDL2_RENDER

int Window_Main(HINSTANCE hInstance, int a2, char *lpCmdLine, int nShowCmd, LPCSTR lpWindowName)
{
    int result;
    WNDCLASSEXA wndClass;
    MSG msg;

    g_handler_count = 0;
    g_thing_two_some_dialog_count = 0;
    g_should_exit = 0;
    g_window_not_destroyed = 0;
    g_hInstance = hInstance;
    g_nShowCmd = nShowCmd;

    wndClass.cbSize = 48;
    wndClass.hInstance = hInstance;
    wndClass.lpszClassName = "wKernel";
    wndClass.lpszMenuName = 0;
    wndClass.lpfnWndProc = Window_msg_main_handler;
    wndClass.style = 3;
    wndClass.hIcon = jk_LoadIconA(hInstance, "APPICON");
    if ( !wndClass.hIcon )
        wndClass.hIcon = jk_LoadIconA(0, (void*)32512);
    wndClass.hIconSm = jk_LoadIconA(hInstance, "APPICON");
    if ( !wndClass.hIconSm )
        wndClass.hIconSm = jk_LoadIconA(0, (void*)32512);
    wndClass.hCursor = jk_LoadCursorA(0, (void*)0x7F00);
    wndClass.cbClsExtra = 0;
    wndClass.cbWndExtra = 0;
    wndClass.hbrBackground = jk_GetStockObject(4);

    if (jk_RegisterClassExA(&wndClass))
    {
        if ( jk_FindWindowA("wKernel", lpWindowName) )
            jk_exit(-1);

        uint32_t hres = jk_GetSystemMetrics(1);
        uint32_t vres = jk_GetSystemMetrics(0);
        g_hWnd = jk_CreateWindowExA(0x40000u, "wKernel", lpWindowName, 0x90000000, 0, 0, vres, hres, 0, 0, hInstance, 0);

        if (g_hWnd)
        {
            g_hInstance = hInstance;
            jk_ShowWindow(g_hWnd, 1);
            jk_UpdateWindow(g_hWnd);
        }
    }

    stdGdi_SetHwnd(g_hWnd);
    stdGdi_SetHInstance(g_hInstance);
    jk_InitCommonControls();

    g_855E8C = 2 * jk_GetSystemMetrics(32);
    uint32_t metrics_32 = jk_GetSystemMetrics(32);
    g_855E90 = jk_GetSystemMetrics(15) + 2 * metrics_32;
    result = Main_Startup(lpCmdLine);

    if (!result) return result;

    
    g_window_not_destroyed = 1;

    while (1)
    {
        if (jk_PeekMessageA(&msg, 0, 0, 0, 0))
        {
            if (!jk_GetMessageA(&msg, 0, 0, 0))
            {
                result = msg.wParam;
                g_should_exit = 1;
                break;
            }

            uint32_t some_cnt = 0;
            if (g_thing_two_some_dialog_count > 0)
            {
#if 0
                v16 = &thing_three;
                do
                {
                    //TODO if ( jk_IsDialogMessageA(*v16, &msg) )
                    //  break;
                    ++some_cnt;
                    ++v16;
                }
                while ( some_cnt < g_thing_two_some_dialog_count );
#endif
            }

            if (some_cnt == g_thing_two_some_dialog_count)
            {
                jk_TranslateMessage(&msg);
                jk_DispatchMessageA(&msg);
            }

            if (!jk_PeekMessageA(&msg, 0, 0, 0, 0))
            {
                result = 0;
                if ( g_should_exit )
                    return result;
            }
        }

        //if (user32->stopping) break;

        jkMain_GuiAdvance();
    }

    return result;
}

int Window_DefaultHandler(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam, void* unused)
{
    return DefWindowProcA(hWnd, Msg, wParam, lParam);
}

#endif

#ifdef SDL2_RENDER

#ifdef ARCH_WASM
#include <SDL2/SDL.h>
#else
#include <SDL.h>
#endif

#include <string.h>

#include <GL/glew.h>
#ifdef MACOS
#include "Platform/macOS/SDL_fix.h"
#else
#include <GL/gl.h>
#endif
#include "Win95/Video.h"

SDL_Window* displayWindow = NULL;
SDL_Event event;
SDL_GLContext glWindowContext;

int Window_lastXRel = 0;
int Window_lastYRel = 0;
int Window_lastSampleTime = 0;
int Window_lastSampleMs = 0;
int Window_bMouseLeft = 0;
int Window_bMouseRight = 0;
int Window_resized = 0;
int Window_mouseX = 0;
int Window_mouseY = 0;
int Window_lastMouseX = 0;
int Window_lastMouseY = 0;
int Window_xPos = SDL_WINDOWPOS_CENTERED;
int Window_yPos = SDL_WINDOWPOS_CENTERED;
int last_jkGame_isDDraw = 0;
int Window_menu_mouseX = 0;
int Window_menu_mouseY = 0;

void Window_HandleMouseMove(SDL_MouseMotionEvent *event)
{
    int x = event->x;
    int y = event->y;

    Window_lastMouseX = Window_mouseX;
    Window_lastMouseY = Window_mouseY;

    if (!jkGame_isDDraw)
    {
        float fX = (float)x;
        float fY = (float)y;

        // Keep 4:3 aspect
        float menu_x = ((float)Window_screenXSize - ((float)Window_screenYSize * (640.0 / 480.0))) / 2.0;
        float menu_w = ((float)Window_screenYSize * (640.0 / 480.0));

        Window_mouseX = (int)(((fX - menu_x) / (float)menu_w) * 640.0);
        Window_mouseY = (int)((fY / (float)Window_screenYSize) * 480.0);
        //printf("%d %d\n", Window_mouseX, Window_mouseY);
    }
    else
    {
        Window_mouseX = x;
        Window_mouseY = y;// - (Window_ySize - 480);
    }

    if (Window_mouseX < 0)
        Window_mouseX = 0;

    uint32_t pos = ((Window_mouseX) & 0xFFFF) | (((Window_mouseY) << 16) & 0xFFFF0000);
    
    Window_lastSampleMs = event->timestamp - Window_lastSampleTime;
    //Window_lastSampleTime = event->timestamp;
    Window_lastXRel += event->xrel;
    Window_lastYRel += event->yrel;

    Window_msg_main_handler(g_hWnd, WM_MOUSEMOVE, 0, pos);
}

void Window_HandleWindowEvent(SDL_Event* event)
{
    switch (event->window.event) 
    {
        case SDL_WINDOWEVENT_SHOWN:
            //printf("Window %d shown", event->window.windowID);
            break;
        case SDL_WINDOWEVENT_HIDDEN:
            //printf("Window %d hidden", event->window.windowID);
            break;
        case SDL_WINDOWEVENT_EXPOSED:
            //printf("Window %d exposed", event->window.windowID);
            break;
        case SDL_WINDOWEVENT_MOVED:
            /*printf("Window %d moved to %d,%d",
                    event->window.windowID, event->window.data1,
                    event->window.data2);*/
            Window_xPos = event->window.data1;
            Window_yPos = event->window.data2;
            break;
        case SDL_WINDOWEVENT_RESIZED:
        case SDL_WINDOWEVENT_SIZE_CHANGED:
            if (Window_xSize != event->window.data1 || Window_ySize != event->window.data2)
                Window_resized = 1;

            //Window_xSize = event->window.data1;
            //Window_ySize = event->window.data2;
            SDL_GL_GetDrawableSize(displayWindow, &Window_xSize, &Window_ySize);
            SDL_GetWindowSize(displayWindow, &Window_screenXSize, &Window_screenYSize);

            if (Window_xSize < 640) Window_xSize = 640;
            if (Window_ySize < 480) Window_ySize = 480;
            //printf("%u %u\n", Window_xSize, Window_ySize);
            break;
        case SDL_WINDOWEVENT_MINIMIZED:
            //printf("Window %d minimized", event->window.windowID);
            break;
        case SDL_WINDOWEVENT_MAXIMIZED:
            //printf("Window %d maximized", event->window.windowID);
            break;
        case SDL_WINDOWEVENT_RESTORED:
            //printf("Window %d restored", event->window.windowID);
            break;
        case SDL_WINDOWEVENT_ENTER:
            //printf("Mouse entered window %d\n", event->window.windowID);
            break;
        case SDL_WINDOWEVENT_LEAVE:
            //printf("Mouse left window %d\n", event->window.windowID);
            break;
        case SDL_WINDOWEVENT_FOCUS_GAINED:
            //printf("Window %d gained keyboard focus", event->window.windowID);
            break;
        case SDL_WINDOWEVENT_FOCUS_LOST:
            //printf("Window %d lost keyboard focus", event->window.windowID);
            break;
        case SDL_WINDOWEVENT_CLOSE:
            //printf("Window %d closed", event->window.windowID);
            break;
        case SDL_WINDOWEVENT_TAKE_FOCUS:
            //printf("Window %d is offered a focus", event->window.windowID);
            break;
        case SDL_WINDOWEVENT_HIT_TEST:
            //printf("Window %d has a special hit test", event->window.windowID);
            break;
    }
}

void Window_SdlUpdate()
{
    uint16_t left, right;
    uint32_t pos, msgl, msgr;
    int hasLeft, hasRight;
    SDL_Event event;
    SDL_MouseButtonEvent* mevent;

    while (SDL_PollEvent(&event))
    {
        switch (event.type)
        {
            case SDL_TEXTINPUT:
                for (int i = 0; i < _strlen(event.text.text); i++)
                {
                    Window_msg_main_handler(g_hWnd, WM_CHAR, event.text.text[i], 0);
                }
                break;
            case SDL_WINDOWEVENT:
                Window_HandleWindowEvent(&event);
                break;
            case SDL_KEYDOWN:
                //handleKey(&event.key.keysym, WM_KEYDOWN, 0x1);
                if (event.key.keysym.sym == SDLK_ESCAPE)
                {
                    if (!event.key.repeat)
                        Window_msg_main_handler(g_hWnd, WM_KEYFIRST, 0x1B, 0);
                    Window_msg_main_handler(g_hWnd, WM_CHAR, 0x1B, 0);
                }
                else if (event.key.keysym.sym == SDLK_LEFT)
                {
                    if (!event.key.repeat)
                        Window_msg_main_handler(g_hWnd, WM_KEYFIRST, 0x25, 0);
                    //Window_msg_main_handler(g_hWnd, WM_CHAR, 0x25, 0);
                }
                else if (event.key.keysym.sym == SDLK_RIGHT)
                {
                    if (!event.key.repeat)
                        Window_msg_main_handler(g_hWnd, WM_KEYFIRST, 0x27, 0);
                    //Window_msg_main_handler(g_hWnd, WM_CHAR, 0x27, 0);
                }
                else if (event.key.keysym.sym == SDLK_UP)
                {
                    if (!event.key.repeat)
                        Window_msg_main_handler(g_hWnd, WM_KEYFIRST, 0x26, 0);
                    //Window_msg_main_handler(g_hWnd, WM_CHAR, 0x26, 0);
                }
                else if (event.key.keysym.sym == SDLK_DOWN)
                {
                    if (!event.key.repeat)
                        Window_msg_main_handler(g_hWnd, WM_KEYFIRST, 0x28, 0);
                    //Window_msg_main_handler(g_hWnd, WM_CHAR, 0x28, 0);
                }
                else if (event.key.keysym.sym == SDLK_BACKSPACE)
                {
                    if (!event.key.repeat)
                        Window_msg_main_handler(g_hWnd, WM_KEYFIRST, 0x8, 0);
                    Window_msg_main_handler(g_hWnd, WM_CHAR, 0x8, 0);
                }
                else if (event.key.keysym.sym == SDLK_DELETE)
                {
                    if (!event.key.repeat)
                        Window_msg_main_handler(g_hWnd, WM_KEYFIRST, 0x2E, 0);
                    //Window_msg_main_handler(g_hWnd, WM_CHAR, 0x8, 0);
                }
                else if (event.key.keysym.sym == SDLK_RETURN)
                {
                    // HACK apparently Windows buffers these events in some way, but to replicate the behavior in jkGUI we just spam KEYFIRST
                    //if (!event.key.repeat)
                        Window_msg_main_handler(g_hWnd, WM_KEYFIRST, 0xD, 0);
                    Window_msg_main_handler(g_hWnd, WM_CHAR, 0xD, 0);
                }
                else if (event.key.keysym.sym == SDLK_LSHIFT)
                {
                    if (!event.key.repeat)
                        Window_msg_main_handler(g_hWnd, WM_KEYFIRST, 0xA0, 0);
                    Window_msg_main_handler(g_hWnd, WM_KEYDOWN, 0xA0, 0);
                }
                else if (event.key.keysym.sym == SDLK_RSHIFT)
                {
                    if (!event.key.repeat)
                        Window_msg_main_handler(g_hWnd, WM_KEYFIRST, 0xA1, 0);
                    Window_msg_main_handler(g_hWnd, WM_KEYDOWN, 0xA1, 0);
                }
                else if (event.key.keysym.sym == SDLK_TAB)
                {
                    if (!event.key.repeat)
                        Window_msg_main_handler(g_hWnd, WM_KEYFIRST, 0x9, 0);
                    Window_msg_main_handler(g_hWnd, WM_CHAR, 0x9, 0);
                }
                else if (event.key.keysym.sym == SDLK_END)
                {
                    if (!event.key.repeat)
                        Window_msg_main_handler(g_hWnd, WM_KEYFIRST, 0x23, 0);
                    //Window_msg_main_handler(g_hWnd, WM_CHAR, 0x23, 0);
                }
                else if (event.key.keysym.sym == SDLK_HOME)
                {
                    if (!event.key.repeat)
                        Window_msg_main_handler(g_hWnd, WM_KEYFIRST, 0x24, 0);
                    //Window_msg_main_handler(g_hWnd, WM_CHAR, 0x24, 0);
                }

                //if (!event.key.repeat)
                //    stdControl_SetSDLKeydown(event.key.keysym.scancode, 1, event.key.timestamp);
                break;
            case SDL_KEYUP:
                if (event.key.keysym.sym == SDLK_ESCAPE)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYUP, 0x1B, 0);
                }
                else if (event.key.keysym.sym == SDLK_LEFT)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYUP, 0x25, 0);
                }
                else if (event.key.keysym.sym == SDLK_RIGHT)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYUP, 0x27, 0);
                }
                else if (event.key.keysym.sym == SDLK_UP)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYUP, 0x26, 0);
                }
                else if (event.key.keysym.sym == SDLK_DOWN)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYUP, 0x28, 0);
                }
                else if (event.key.keysym.sym == SDLK_BACKSPACE)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYUP, 0x8, 0);
                }
                else if (event.key.keysym.sym == SDLK_DELETE)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYUP, 0x2E, 0);
                }
                else if (event.key.keysym.sym == SDLK_RETURN)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYUP, 0xB, 0);
                }
                else if (event.key.keysym.sym == SDLK_LSHIFT)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYUP, 0xA0, 0);
                }
                else if (event.key.keysym.sym == SDLK_RSHIFT)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYUP, 0xA1, 0);
                }
                else if (event.key.keysym.sym == SDLK_TAB)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYUP, 0x9, 0);
                }
                else if (event.key.keysym.sym == SDLK_END)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYUP, 0x23, 0);
                }
                else if (event.key.keysym.sym == SDLK_HOME)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYUP, 0x24, 0);
                }
                //handleKey(&event.key.keysym, WM_KEYUP, 0xc0000001);

                stdControl_SetSDLKeydown(event.key.keysym.scancode, 0, event.key.timestamp);
                break;
            case SDL_MOUSEMOTION:
                Window_HandleMouseMove(&event.motion);
                break;
            case SDL_MOUSEBUTTONDOWN:
            case SDL_MOUSEBUTTONUP:

                mevent = (SDL_MouseButtonEvent*)&event;
                left = 0;
                right = 0;
                hasLeft = 0;
                hasRight = 0;
                if (event.type == SDL_MOUSEBUTTONDOWN)
                {
                    left = (mevent->button == SDL_BUTTON_LEFT ? 1 : 0);
                    right = (mevent->button == SDL_BUTTON_RIGHT ? 2 : 0);
                    
                    if (left)
                        hasLeft = 1;
                    if (right)
                        hasRight = 1;
                }
                else if (event.type == SDL_MOUSEBUTTONUP)
                {
                    left = (mevent->button == SDL_BUTTON_LEFT ? 0 : 1);
                    right = (mevent->button == SDL_BUTTON_RIGHT ? 0 : 2);
                    
                    if (!left)
                        hasLeft = 1;
                    if (!right)
                        hasRight = 1;
                }
                
                if (hasLeft)
                    Window_bMouseLeft = left;
                if (hasRight)
                    Window_bMouseRight = right;

                Window_mouseX = mevent->x;
                Window_mouseY = mevent->y;// - (Window_ySize - 480);

                pos = ((Window_mouseX) & 0xFFFF) | (((Window_mouseY) << 16) & 0xFFFF0000);
                msgl = (event.type == SDL_MOUSEBUTTONDOWN ? WM_LBUTTONDOWN : WM_LBUTTONUP);
                msgr = (event.type == SDL_MOUSEBUTTONDOWN ? WM_RBUTTONDOWN : WM_RBUTTONUP);
                
                if (hasLeft)
                    Window_msg_main_handler(g_hWnd, msgl, left | right, pos);
                if (hasRight)
                    Window_msg_main_handler(g_hWnd, msgr, left | right, pos);

                //stdControl_SetKeydown(KEY_MOUSE_B1, Window_bMouseLeft, mevent->timestamp);
                //stdControl_SetKeydown(KEY_MOUSE_B2, Window_bMouseRight, mevent->timestamp);

                break;
            case SDL_QUIT:
                printf("Quit!\n");
                exit(-1);
                break;
            default:
                break;
        }
    }
    
    if (Window_resized)
    {
        jkMain_FixRes();
        if (!jkGui_SetModeMenu(0))
        {
            stdDisplay_SetMode(0, 0, 0);
            //jkMain_FixRes();
        }
        
        Window_resized = 0;
    }
    
    //printf("%u\n", SDL_GetTicks() - Window_lastSampleTime);
    Window_lastSampleTime = SDL_GetTicks();

    static int jkPlayer_enableVsync_last = 0;

    if (jkPlayer_enableVsync_last != jkPlayer_enableVsync)
    {
        SDL_GL_SetSwapInterval(jkPlayer_enableVsync);
    }

    if (!jkGame_isDDraw)
    {
        // Restore menu mouse position
        if (jkGame_isDDraw != last_jkGame_isDDraw) {
            SDL_WarpMouseInWindow(displayWindow, Window_menu_mouseX, Window_menu_mouseY);
        }

        SDL_SetRelativeMouseMode(SDL_FALSE);

        std3D_StartScene();
        std3D_DrawMenu();
        std3D_EndScene();
        SDL_GL_SwapWindow(displayWindow);

        if (Window_needsRecreate)
            Window_RecreateSDL2Window();
        //SDL_RenderClear(displayRenderer);
        //SDL_RenderCopy(displayRenderer, menuTexture, NULL, NULL);
        //SDL_RenderPresent(displayRenderer);
    }
    else
    {
        // Save mouse position for menu
        if (jkGame_isDDraw != last_jkGame_isDDraw) {
            Window_menu_mouseX = Window_mouseX;
            Window_menu_mouseY = Window_mouseY;
            Window_lastXRel = 0;
            Window_lastYRel = 0;
        }

        if (SDL_GetWindowFlags(displayWindow) & SDL_WINDOW_MOUSE_FOCUS) {
            SDL_SetRelativeMouseMode(SDL_TRUE);
            //SDL_WarpMouseInWindow(displayWindow, 100, 100);
        }
        else
        {
            SDL_SetRelativeMouseMode(SDL_FALSE);
        }
    }

    jkPlayer_enableVsync_last = jkPlayer_enableVsync;

    last_jkGame_isDDraw = jkGame_isDDraw;
}

void Window_SdlVblank()
{
    //static uint32_t roundtrip = 0;
    //uint32_t before = stdPlatform_GetTimeMsec();
    SDL_GL_SwapWindow(displayWindow);
    //uint32_t after = stdPlatform_GetTimeMsec();
    //printf("%u %u\n", after-before, before-roundtrip);

    //roundtrip = before;

    if (Window_needsRecreate)
        Window_RecreateSDL2Window();

#ifdef ARCH_WASM
    //emscripten_sleep(1);
#endif
}

#ifdef ARCH_WASM
EM_JS(int, canvas_get_width, (), {
  return canvas.width;
});

EM_JS(int, canvas_get_height, (), {
  return canvas.height;
});
#endif

void Window_RecreateSDL2Window()
{
    printf("Recreating SDL2 Window!\n");
    Window_needsRecreate = 0;

    if (displayWindow) {
        std3D_FreeResources();
        SDL_GL_DeleteContext(glWindowContext);
        SDL_DestroyWindow(displayWindow);
    }

    int flags = SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE;

    if (displayWindow) {
        flags = SDL_GetWindowFlags(displayWindow);
        //std3D_FreeResources();
        //SDL_GL_DeleteContext(glWindowContext);
        //SDL_DestroyWindow(displayWindow);

        flags |= SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE;
    }

    if (Window_isHiDpi)
        flags |= SDL_WINDOW_ALLOW_HIGHDPI;
    else
        flags &= ~SDL_WINDOW_ALLOW_HIGHDPI;

    if (Window_isFullscreen)
        flags |= SDL_WINDOW_FULLSCREEN_DESKTOP;
    else
        flags &= ~SDL_WINDOW_FULLSCREEN_DESKTOP;

#if defined(ARCH_WASM)
    //flags &= ~SDL_WINDOW_RESIZABLE;
#endif

#ifdef ARCH_WASM
    displayWindow = SDL_CreateWindow(Window_isHiDpi ? "OpenJKDF2 HiDPI" : "OpenJKDF2", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, canvas_get_width(), canvas_get_height(), flags);
#else
    displayWindow = SDL_CreateWindow(Window_isHiDpi ? "OpenJKDF2 HiDPI" : "OpenJKDF2", Window_xPos, Window_yPos, Window_screenXSize, Window_screenYSize, flags);
#endif
    if (!displayWindow) {
        char errtmp[256];
        snprintf(errtmp, 256, "!! Failed to create SDL2 window !!\n%s", SDL_GetError());
        SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "Error", errtmp, NULL);
        exit (-1);
    }
    //SDL_SetRenderDrawBlendMode(displayRenderer, SDL_BLENDMODE_BLEND);

#if defined(MACOS) && defined(__aarch64__)
    SDL_FixWindowMacOS(displayWindow);
#endif

    if (flags & (SDL_WINDOW_FULLSCREEN | SDL_WINDOW_FULLSCREEN_DESKTOP)) {
        SDL_SetWindowFullscreen(displayWindow, flags & (SDL_WINDOW_FULLSCREEN | SDL_WINDOW_FULLSCREEN_DESKTOP));
    }

    glWindowContext = SDL_GL_CreateContext(displayWindow);
    
    // Retry with 3.30 instead
    if (glWindowContext == NULL)
    {
        SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
        SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 3);
        SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
        SDL_GL_SetAttribute(SDL_GL_SHARE_WITH_CURRENT_CONTEXT, 1);
        SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, SDL_GL_CONTEXT_FORWARD_COMPATIBLE_FLAG);
        glWindowContext = SDL_GL_CreateContext(displayWindow);
    }
    
    if (glWindowContext == NULL)
    {
        char errtmp[256];
        snprintf(errtmp, 256, "!! Failed to initialize SDL OpenGL context !!\n%s", SDL_GetError());
        SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "Error", errtmp, NULL);
        exit(-1);
    }

    SDL_GL_MakeCurrent(displayWindow, glWindowContext);
    SDL_GL_SetSwapInterval(jkPlayer_enableVsync); // Disable vsync
    SDL_StartTextInput();

    SDL_GL_GetDrawableSize(displayWindow, &Window_xSize, &Window_ySize);
    SDL_GetWindowSize(displayWindow, &Window_screenXSize, &Window_screenYSize);

    Window_resized = 1;
}

void Window_Main_Loop()
{
    jkMain_GuiAdvance();
    Window_msg_main_handler(g_hWnd, WM_PAINT, 0, 0);
    
    //Window_SdlUpdate();
}

int Window_Main_Linux(int argc, char** argv)
{
    char cmdLine[1024];
    int result;
    
    // Init SDL
    SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO | SDL_INIT_NOPARACHUTE);

#if defined(MACOS)
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
    SDL_GL_SetAttribute(SDL_GL_SHARE_WITH_CURRENT_CONTEXT, 1);
#else

#if defined(WIN64_STANDALONE)
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 2);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
    SDL_GL_SetAttribute(SDL_GL_SHARE_WITH_CURRENT_CONTEXT, 1);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, SDL_GL_CONTEXT_FORWARD_COMPATIBLE_FLAG);

    // apitrace
#if 0
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_COMPATIBILITY);
    SDL_GL_SetAttribute(SDL_GL_SHARE_WITH_CURRENT_CONTEXT, 1);
#endif
#elif defined(ARCH_WASM)
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_ES);
    SDL_GL_SetAttribute(SDL_GL_SHARE_WITH_CURRENT_CONTEXT, 1);
#else
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 2);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
    SDL_GL_SetAttribute(SDL_GL_SHARE_WITH_CURRENT_CONTEXT, 1);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, SDL_GL_CONTEXT_FORWARD_COMPATIBLE_FLAG);
#endif

#endif

    Window_RecreateSDL2Window();
    
    glewInit();
    
    //SDL_RenderClear(displayRenderer);
    //SDL_RenderPresent(displayRenderer);
    
    
    strcpy(cmdLine, "");
    
    g_handler_count = 0;
    g_thing_two_some_dialog_count = 0;
    g_should_exit = 0;
    g_window_not_destroyed = 0;
    g_hInstance = 0;//hInstance;
    g_nShowCmd = 0;//nShowCmd;
    
    for (int i = 1; i < argc; i++)
    {
        strcat(cmdLine, argv[i]);
        strcat(cmdLine, " ");
    }
    
    result = Main_Startup(cmdLine);

    if (!result) return result;

    g_window_not_destroyed = 1;
    
    Window_msg_main_handler(g_hWnd, 0x1, 0, 0); // WM_CREATE
    Window_msg_main_handler(g_hWnd, 0x6, 2, 0); // WM_ACTIVATE
    Window_msg_main_handler(g_hWnd, 0x1C, 1, 0); // WM_ACTIVATEAPP
    Window_msg_main_handler(g_hWnd, 0x18, 0, 0); // WM_SHOWWINDOW
    Window_msg_main_handler(g_hWnd, WM_PAINT, 0, 0);


#ifdef ARCH_WASM
    //int fps = 0; // Use browser's requestAnimationFrame
    //emscripten_set_main_loop_arg(Window_Main_Loop, NULL, fps, 1);
    while (1)
    {
        Window_Main_Loop();
    }
#else
    while (1)
    {
        Window_Main_Loop();
    }
#endif
}

int Window_Main(HINSTANCE hInstance, int a2, char *lpCmdLine, int nShowCmd, LPCSTR lpWindowName)
{
    int result;

    g_handler_count = 0;
    g_thing_two_some_dialog_count = 0;
    g_should_exit = 0;
    g_window_not_destroyed = 0;
    g_hInstance = hInstance;
    g_nShowCmd = nShowCmd;
#if 0
    if (jk_RegisterClassExA(&wndClass))
    {
        if ( jk_FindWindowA("wKernel", lpWindowName) )
            jk_exit(-1);

        uint32_t hres = jk_GetSystemMetrics(1);
        uint32_t vres = jk_GetSystemMetrics(0);
        g_hWnd = jk_CreateWindowExA(0x40000u, "wKernel", lpWindowName, 0x90000000, 0, 0, vres, hres, 0, 0, hInstance, 0);

        if (g_hWnd)
        {
            g_hInstance = hInstance;
            jk_ShowWindow(g_hWnd, 1);
            jk_UpdateWindow(g_hWnd);
        }
    }

    stdGdi_SetHwnd(g_hWnd);
    stdGdi_SetHInstance(g_hInstance);
    jk_InitCommonControls();

    g_855E8C = 2 * jk_GetSystemMetrics(32);
    uint32_t metrics_32 = jk_GetSystemMetrics(32);
    g_855E90 = jk_GetSystemMetrics(15) + 2 * metrics_32;
    result = Main_Startup(lpCmdLine);

    if (!result) return result;

    
    g_window_not_destroyed = 1;

    while (1)
    {
        if (jk_PeekMessageA(&msg, 0, 0, 0, 0))
        {
            if (!jk_GetMessageA(&msg, 0, 0, 0))
            {
                result = msg.wParam;
                g_should_exit = 1;
                break;
            }

            uint32_t some_cnt = 0;
            if (g_thing_two_some_dialog_count > 0)
            {
#if 0
                v16 = &thing_three;
                do
                {
                    //TODO if ( jk_IsDialogMessageA(*v16, &msg) )
                    //  break;
                    ++some_cnt;
                    ++v16;
                }
                while ( some_cnt < g_thing_two_some_dialog_count );
#endif
            }

            if (some_cnt == g_thing_two_some_dialog_count)
            {
                jk_TranslateMessage(&msg);
                jk_DispatchMessageA(&msg);
            }

            if (!jk_PeekMessageA(&msg, 0, 0, 0, 0))
            {
                result = 0;
                if ( g_should_exit )
                    return result;
            }
        }

        //if (user32->stopping) break;

        jkMain_GuiAdvance();
    }
#endif
    result = 1;
    return result;
}

int Window_ShowCursorUnwindowed(int a1)
{
    return stdControl_ShowCursor(a1);
}

int Window_DefaultHandler(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam, void* unused)
{
    return 0;
}

int Window_MessageLoop()
{
    jkMain_GuiAdvance();
    Window_msg_main_handler(g_hWnd, WM_PAINT, 0, 0);
    
    //Window_SdlUpdate();
    return 0;
}

#endif

void Window_SetDrawHandlers(WindowDrawHandler_t a1, WindowDrawHandler_t a2)
{
    Window_drawAndFlip = a1;
    Window_setCooperativeLevel = a2;
}

void Window_GetDrawHandlers(WindowDrawHandler_t *a1, WindowDrawHandler_t *a2)
{
    *a1 = Window_drawAndFlip;
    *a2 = Window_setCooperativeLevel;
}
