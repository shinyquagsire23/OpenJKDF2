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
#include "Devices/sithConsole.h"
#include "Platform/wuRegistry.h"
#include "Main/jkQuakeConsole.h"

#include "jk.h"

#ifdef ARCH_WASM
#include <emscripten.h>
#endif

#ifdef SDL2_RENDER

#include <fcntl.h> 
#include <stdio.h>
#ifndef _WIN32
#include <unistd.h>
#endif

#if !defined(WIN64_MINGW) && !defined(_WIN32)
#include <sys/ioctl.h>
#include <sys/select.h>
#include <termios.h>
#else
#include <conio.h>
#endif
//#include <stropts.h>

#include "SDL2_helper.h"

#include <string.h>

//#include <GL/glew.h>
#ifdef MACOS
#include "Platform/macOS/SDL_fix.h"
#else
//#include <GL/gl.h>
#endif
#include "Win95/Video.h"

#if defined(MACOS)
#include <stdbool.h>
#import <Carbon/Carbon.h>
#endif

extern int Window_xPos, Window_yPos;
#endif

int Window_xSize = WINDOW_DEFAULT_WIDTH;
int Window_ySize = WINDOW_DEFAULT_HEIGHT;
int Window_screenXSize = WINDOW_DEFAULT_WIDTH;
int Window_screenYSize = WINDOW_DEFAULT_HEIGHT;
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

    wuRegistry_SaveBool("Window_isHiDpi", Window_isHiDpi);
}

void Window_SetFullscreen(int val)
{
    if (Window_isFullscreen != val)
    {
        // Reset window when exiting fullscreen
        // TODO: Add settings for these sizes maybe?
        if (Window_isFullscreen && !val) {
            Window_xSize = WINDOW_DEFAULT_WIDTH;
            Window_ySize = WINDOW_DEFAULT_HEIGHT;
            Window_screenXSize = WINDOW_DEFAULT_WIDTH;
            Window_screenYSize = WINDOW_DEFAULT_HEIGHT;
#ifdef SDL2_RENDER
            Window_xPos = SDL_WINDOWPOS_CENTERED;
            Window_yPos = SDL_WINDOWPOS_CENTERED;
#endif
        }

        Window_isFullscreen = val;
        Window_needsRecreate = 1;
    }

    wuRegistry_SaveBool("Window_isFullscreen", Window_isFullscreen);
    
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
int Window_mouseWheelX = 0;
int Window_mouseWheelY = 0;
int Window_lastMouseX = 0;
int Window_lastMouseY = 0;
int Window_xPos = SDL_WINDOWPOS_CENTERED;
int Window_yPos = SDL_WINDOWPOS_CENTERED;
int last_jkGame_isDDraw = 0;
int last_jkQuakeConsole_bOpen = 0;
int Window_menu_mouseX = 0;
int Window_menu_mouseY = 0;

extern int jkGuiBuildMulti_bRendering;

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

    if (jkQuakeConsole_bOpen) return; // Hijack all input to console

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
#ifdef MACOS
            {
                static int bMacosOnlyOncePerProcessLifetimeTriggerTheStupidDylibLoad = 0;
                if (!bMacosOnlyOncePerProcessLifetimeTriggerTheStupidDylibLoad)
                {
                    CGEventRef ref = CGEventCreateKeyboardEvent(NULL, 0x72 /* help */, 1);
                    CGEventSetFlags( ref, kCGEventFlagMaskNumericPad );
                    CGEventSetFlags( ref, kCGEventFlagMaskSecondaryFn );
                    CGEventPost(kCGHIDEventTap, ref);
                    CFRelease(ref);
                    bMacosOnlyOncePerProcessLifetimeTriggerTheStupidDylibLoad = 1;
                }
            }
#endif
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

#if defined(WIN64_MINGW) || defined(_WIN32)
CHAR my_getch() {
    DWORD mode, cc;
    DWORD num;
    INPUT_RECORD irInBuf[1];
    HANDLE h = GetStdHandle( STD_INPUT_HANDLE );

    if (h == NULL) {
        return 0; // console not found
    }

    GetConsoleMode( h, &mode );
    SetConsoleMode( h, mode & ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT) );
    TCHAR c = 0;
    GetNumberOfConsoleInputEvents(h, &num);
    if (num)
    {
        if (!ReadConsoleInput(
            h,      // input buffer handle 
            irInBuf,     // buffer to read into 
            1,         // size of read buffer 
            &num))
        {

        }
        else
        {
            if (irInBuf[0].EventType == KEY_EVENT && irInBuf[0].Event.KeyEvent.bKeyDown) {
                c = irInBuf[0].Event.KeyEvent.uChar.AsciiChar;
            }
        }
    }
    SetConsoleMode( h, mode );
    return c;
}

int my_kbhit() {
    DWORD num;
    DWORD mode, cc;
    HANDLE h = GetStdHandle( STD_INPUT_HANDLE );
    if (h == NULL) {
        return 0; // console not found
    }

    GetConsoleMode( h, &mode );
    SetConsoleMode( h, mode & ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT) );
    
    GetNumberOfConsoleInputEvents(h, &num);
    SetConsoleMode( h, mode );

    return num;
}
#else
int my_kbhit() {
    static const int STDIN = 0;
    static int initialized = 0;

    if (! initialized) {
        // Use termios to turn off line buffering
        struct termios term;
        tcgetattr(STDIN, &term);
        term.c_lflag &= ~ICANON;
        term.c_lflag &= ~ECHO;
        tcsetattr(STDIN, TCSANOW, &term);
        setbuf(stdin, NULL);
        initialized = 1;
    }

    int bytesWaiting;
    ioctl(STDIN, FIONREAD, &bytesWaiting);
    return bytesWaiting;
}
#endif

static char Window_headlessBuffer[256];

void Window_UpdateHeadless()
{
    char buffer[32];
    size_t bytes_read = 0;

    if (my_kbhit() > 0) {
#if defined(WIN64_MINGW) || (_WIN32)
        buffer[0] = my_getch();
        buffer[1] = 0;
        bytes_read = 1;
#else
        int fd = STDIN_FILENO;
        bytes_read = read(fd, buffer, sizeof(buffer)-1);
        buffer[bytes_read] = 0;
#endif

        for (int i = 0; i < bytes_read; i++)
        {
            if (buffer[i] == '\n' || buffer[i] == '\r') {
                printf("\r> %s\n", Window_headlessBuffer);
                sithConsole_TryCommand(Window_headlessBuffer);
                memset(Window_headlessBuffer, 0, sizeof(Window_headlessBuffer));
                continue;
            }
            else if (buffer[i] == 0x7F && strlen(Window_headlessBuffer)) {
                Window_headlessBuffer[strlen(Window_headlessBuffer)-1] = 0;
                printf("\r> %s ", Window_headlessBuffer);
                continue;
            }
            else if (buffer[i] < ' ' || buffer[i] > '~')
            {
                continue;
            }

            char tmp[2] = {buffer[i], 0};
            strncat(Window_headlessBuffer, tmp, 255);
        }
    }
    
    printf("\r> %s", Window_headlessBuffer);
    //printf("> %x %x %s\n", buffer[0], my_kbhit(), Window_headlessBuffer);
    fflush(stdout);

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
    
    int sampleTime_roundtrip = SDL_GetTicks() - Window_lastSampleTime;
    //printf("%u\n", sampleTime_roundtrip);
    Window_lastSampleTime = SDL_GetTicks();

    static int sampleTime_delay = 0;
    int menu_framelimit_amt_ms = 6;

    if (!jkGame_isDDraw)
    {

        if (!jkGuiBuildMulti_bRendering) {
            std3D_StartScene();
            jkQuakeConsole_Render();
            std3D_DrawMenu();
            std3D_EndScene();
            //SDL_GL_SwapWindow(displayWindow);
        }
        else {
            jkQuakeConsole_Render();
            std3D_DrawMenu();
            //SDL_GL_SwapWindow(displayWindow);
            //menu_framelimit_amt_ms = 64;
        }
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
    }

    // Keep entire loop at 6ms (150FPS)
    if (sampleTime_roundtrip < menu_framelimit_amt_ms) {
        sampleTime_delay++;
    }
    else {
        sampleTime_delay--;
    }
    if (sampleTime_delay <= 0) {
        sampleTime_delay = 1;
    }
    if (sampleTime_delay >= menu_framelimit_amt_ms) {
        sampleTime_delay = menu_framelimit_amt_ms;
    }
    SDL_Delay(sampleTime_delay);

    last_jkGame_isDDraw = jkGame_isDDraw;
    last_jkQuakeConsole_bOpen = jkQuakeConsole_bOpen;
}

void Window_SdlUpdate()
{
    if (Main_bHeadless)
    {
        Window_UpdateHeadless();
        return;
    }

    uint16_t left, right;
    uint32_t pos, msgl, msgr;
    int hasLeft, hasRight;
    SDL_Event event;
    SDL_MouseButtonEvent* mevent;

    while (SDL_PollEvent(&event))
    {
        switch (event.type)
        {
            case SDL_JOYDEVICEADDED: {
                stdControl_InitSdlJoysticks();
                break;
            }
            case SDL_JOYDEVICEREMOVED: {
                stdControl_InitSdlJoysticks();
                break;
            }

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
                    Window_msg_main_handler(g_hWnd, WM_KEYFIRST, VK_ESCAPE, event.key.repeat & 0xFFFF);
                    Window_msg_main_handler(g_hWnd, WM_CHAR, VK_ESCAPE, event.key.repeat & 0xFFFF);
                }
                else if (event.key.keysym.sym == SDLK_PAGEUP)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYFIRST, VK_PRIOR, event.key.repeat & 0xFFFF);
                }
                else if (event.key.keysym.sym == SDLK_PAGEDOWN)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYFIRST, VK_NEXT, event.key.repeat & 0xFFFF);
                }
                else if (event.key.keysym.sym == SDLK_LEFT)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYFIRST, VK_LEFT, event.key.repeat & 0xFFFF);
                }
                else if (event.key.keysym.sym == SDLK_RIGHT)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYFIRST, VK_RIGHT, event.key.repeat & 0xFFFF);
                }
                else if (event.key.keysym.sym == SDLK_UP)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYFIRST, VK_UP, event.key.repeat & 0xFFFF);
                }
                else if (event.key.keysym.sym == SDLK_DOWN)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYFIRST, VK_DOWN, event.key.repeat & 0xFFFF);
                }
                else if (event.key.keysym.sym == SDLK_BACKSPACE)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYFIRST, VK_BACK, event.key.repeat & 0xFFFF);
                    Window_msg_main_handler(g_hWnd, WM_CHAR, VK_BACK, event.key.repeat & 0xFFFF);
                }
                else if (event.key.keysym.sym == SDLK_DELETE)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYFIRST, VK_DELETE, event.key.repeat & 0xFFFF);
                    //Window_msg_main_handler(g_hWnd, WM_CHAR, VK_DELETE, 0);
                }
                else if (event.key.keysym.sym == SDLK_INSERT)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYFIRST, VK_INSERT, event.key.repeat & 0xFFFF);
                    Window_msg_main_handler(g_hWnd, WM_CHAR, VK_INSERT, 0);
                }
                else if (event.key.keysym.sym == SDLK_RETURN)
                {
                    // HACK apparently Windows buffers these events in some way, but to replicate the behavior in jkGUI we just spam KEYFIRST
                    Window_msg_main_handler(g_hWnd, WM_KEYFIRST, VK_RETURN, event.key.repeat & 0xFFFF);
                    Window_msg_main_handler(g_hWnd, WM_CHAR, VK_RETURN, event.key.repeat & 0xFFFF);
                }
                else if (event.key.keysym.sym == SDLK_LSHIFT)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYFIRST, VK_LSHIFT, event.key.repeat & 0xFFFF);
                }
                else if (event.key.keysym.sym == SDLK_RSHIFT)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYFIRST, VK_RSHIFT, event.key.repeat & 0xFFFF);
                }
                else if (event.key.keysym.sym == SDLK_TAB)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYFIRST, VK_TAB, event.key.repeat & 0xFFFF);
                    Window_msg_main_handler(g_hWnd, WM_CHAR, VK_TAB, event.key.repeat & 0xFFFF);
                }
                else if (event.key.keysym.sym == SDLK_END)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYFIRST, VK_END, event.key.repeat & 0xFFFF);
                    //Window_msg_main_handler(g_hWnd, WM_CHAR, 0x23, 0);
                }
                else if (event.key.keysym.sym == SDLK_HOME)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYFIRST, VK_HOME, event.key.repeat & 0xFFFF);
                    //Window_msg_main_handler(g_hWnd, WM_CHAR, 0x24, 0);
                }
                else if (event.key.keysym.sym == SDLK_BACKQUOTE)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYFIRST, VK_OEM_3, event.key.repeat & 0xFFFF);
                }

                //if (!event.key.repeat)
                //    stdControl_SetSDLKeydown(event.key.keysym.scancode, 1, event.key.timestamp);
                break;
            case SDL_KEYUP:
                if (event.key.keysym.sym == SDLK_ESCAPE)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYUP, VK_ESCAPE, 0);
                }
                else if (event.key.keysym.sym == SDLK_PAGEUP)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYUP, VK_PRIOR, 0);
                }
                else if (event.key.keysym.sym == SDLK_PAGEDOWN)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYUP, VK_NEXT, 0);
                }
                else if (event.key.keysym.sym == SDLK_LEFT)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYUP, VK_LEFT, 0);
                }
                else if (event.key.keysym.sym == SDLK_RIGHT)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYUP, VK_RIGHT, 0);
                }
                else if (event.key.keysym.sym == SDLK_UP)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYUP, VK_UP, 0);
                }
                else if (event.key.keysym.sym == SDLK_DOWN)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYUP, VK_DOWN, 0);
                }
                else if (event.key.keysym.sym == SDLK_BACKSPACE)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYUP, VK_BACK, 0);
                }
                else if (event.key.keysym.sym == SDLK_DELETE)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYUP, VK_DELETE, 0);
                }
                else if (event.key.keysym.sym == SDLK_INSERT)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYUP, VK_INSERT, 0);
                }
                else if (event.key.keysym.sym == SDLK_RETURN)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYUP, VK_RETURN, 0); // 0xB?
                }
                else if (event.key.keysym.sym == SDLK_LSHIFT)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYUP, VK_LSHIFT, 0);
                }
                else if (event.key.keysym.sym == SDLK_RSHIFT)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYUP, VK_RSHIFT, 0);
                }
                else if (event.key.keysym.sym == SDLK_TAB)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYUP, VK_TAB, 0);
                }
                else if (event.key.keysym.sym == SDLK_END)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYUP, VK_END, 0);
                }
                else if (event.key.keysym.sym == SDLK_HOME)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYUP, VK_HOME, 0);
                }
                else if (event.key.keysym.sym == SDLK_BACKQUOTE)
                {
                    Window_msg_main_handler(g_hWnd, WM_KEYUP, VK_OEM_3, 0);
                }
                //handleKey(&event.key.keysym, WM_KEYUP, 0xc0000001);

                if (jkQuakeConsole_bOpen) break; // Hijack all input to console

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

                if (jkQuakeConsole_bOpen) break; // Hijack all input to console
                
                if (hasLeft)
                    Window_msg_main_handler(g_hWnd, msgl, left | right, pos);
                if (hasRight)
                    Window_msg_main_handler(g_hWnd, msgr, left | right, pos);

                //stdControl_SetKeydown(KEY_MOUSE_B1, Window_bMouseLeft, mevent->timestamp);
                //stdControl_SetKeydown(KEY_MOUSE_B2, Window_bMouseRight, mevent->timestamp);

                break;
            case SDL_MOUSEWHEEL:
                Window_mouseWheelY = event.wheel.y;
                Window_mouseWheelX = event.wheel.x;

                if (jkQuakeConsole_bOpen) break; // Hijack all input to console
                break;
            case SDL_QUIT:
                stdPlatform_Printf("Quit!\n");

                // Added
                if (jkPlayer_bHasLoadedSettingsOnce) {
                    jkPlayer_WriteConf(jkPlayer_playerShortName);
                }
                
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
    
    static int sampleTime_delay = 0;
    int sampleTime_roundtrip = SDL_GetTicks() - Window_lastSampleTime;
    //printf("%u\n", sampleTime_roundtrip);
    Window_lastSampleTime = SDL_GetTicks();

    static int jkPlayer_enableVsync_last = 0;
    int menu_framelimit_amt_ms = 16;

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

        if (!jkGuiBuildMulti_bRendering) {
            std3D_StartScene();
            jkQuakeConsole_Render();
            std3D_DrawMenu();
            std3D_EndScene();
            SDL_GL_SwapWindow(displayWindow);
        }
        else {
            jkQuakeConsole_Render();
            std3D_DrawMenu();
            SDL_GL_SwapWindow(displayWindow);
            //menu_framelimit_amt_ms = 64;
        }

        if (Window_needsRecreate) {
            std3D_PurgeTextureCache();
            Window_RecreateSDL2Window();
        }
        
        // Keep menu FPS at 60FPS, to avoid cranking the GPU unnecessarily.
        if (sampleTime_roundtrip < menu_framelimit_amt_ms) {
            sampleTime_delay++;
        }
        else {
            sampleTime_delay--;
        }
        if (sampleTime_delay <= 0) {
            sampleTime_delay = 1;
        }
        if (sampleTime_delay >= menu_framelimit_amt_ms) {
            sampleTime_delay = menu_framelimit_amt_ms;
        }
        SDL_Delay(sampleTime_delay);
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

        if (jkQuakeConsole_bOpen && jkQuakeConsole_bOpen != last_jkQuakeConsole_bOpen) {
            SDL_WarpMouseInWindow(displayWindow, Window_menu_mouseX, Window_menu_mouseY);
        }
        else if (!jkQuakeConsole_bOpen && jkQuakeConsole_bOpen != last_jkQuakeConsole_bOpen) {
            Window_menu_mouseX = Window_mouseX;
            Window_menu_mouseY = Window_mouseY;
            Window_lastXRel = 0;
            Window_lastYRel = 0;
        }

        if (jkQuakeConsole_bOpen)
        {
            SDL_SetRelativeMouseMode(SDL_FALSE);
        }

        if (!jkQuakeConsole_bOpen && SDL_GetWindowFlags(displayWindow) & SDL_WINDOW_MOUSE_FOCUS) {
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
    last_jkQuakeConsole_bOpen = jkQuakeConsole_bOpen;
}

void Window_SdlVblank()
{
    if (Main_bHeadless) return;

    //static uint32_t roundtrip = 0;
    //uint32_t before = stdPlatform_GetTimeMsec();
#ifdef ARCH_WASM
    if (!jkGuiBuildMulti_bRendering)
#endif
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
#ifdef ARCH_WASM
    static int onlyOnce = 0;
    if (onlyOnce) {
        return;
    }
    onlyOnce = 1;
#endif

    if (Main_bHeadless) return;

    stdPlatform_Printf("Recreating SDL2 Window!\n");
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

#ifdef WIN64_STANDALONE
    SDL_SetHint(SDL_HINT_WINDOWS_DPI_AWARENESS, "permonitorv2");
#endif

    if (Window_isHiDpi)
        flags |= SDL_WINDOW_ALLOW_HIGHDPI;
    else
        flags &= ~SDL_WINDOW_ALLOW_HIGHDPI;

    if (Window_isFullscreen) {
        //flags |= SDL_WINDOW_FULLSCREEN_DESKTOP;
    }
    else {
        //flags &= ~SDL_WINDOW_FULLSCREEN_DESKTOP;
    }

#if defined(ARCH_WASM)
    //flags &= ~SDL_WINDOW_RESIZABLE;
#endif

#ifdef TARGET_ANDROID
    flags = SDL_WINDOW_SHOWN;
#endif

#ifdef ARCH_WASM
    displayWindow = SDL_CreateWindow(Window_isHiDpi ? "OpenJKDF2 HiDPI" : "OpenJKDF2", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, canvas_get_width(), canvas_get_height(), flags);
#elif defined(TARGET_ANDROID)
    displayWindow = SDL_CreateWindow(Window_isHiDpi ? "OpenJKDF2 HiDPI" : "OpenJKDF2", 0, 0, Window_screenXSize, Window_screenYSize, flags);
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
    //SDL_FixWindowMacOS(displayWindow);
#endif

    if (Window_isFullscreen) {
        SDL_SetWindowFullscreen(displayWindow, SDL_WINDOW_FULLSCREEN_DESKTOP);
    }
    else {
        SDL_SetWindowFullscreen(displayWindow, 0);
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
    SDL_SetHint(SDL_HINT_NO_SIGNAL_HANDLERS, "1");
    SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO | SDL_INIT_JOYSTICK | SDL_INIT_NOPARACHUTE);

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
#elif defined(TARGET_ANDROID)
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_ES);
    SDL_GL_SetAttribute(SDL_GL_SHARE_WITH_CURRENT_CONTEXT, 1);
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
#if !defined(TARGET_ANDROID) && !defined(ARCH_WASM)
    glewInit();
#endif
    
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

    int fullscreen = wuRegistry_GetBool("Window_isFullscreen", 0);
    int hidpi = wuRegistry_GetBool("Window_isHiDpi", 0);
    Window_SetFullscreen(fullscreen);
    Window_SetHiDpi(hidpi);
    Window_RecreateSDL2Window();

    if (!result) return result;

    if (Main_bHeadless)
    {
        if (displayWindow) {
            std3D_FreeResources();
            SDL_GL_DeleteContext(glWindowContext);
            SDL_DestroyWindow(displayWindow);
        }
    }

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
        if (g_should_exit) break;
    }
#else
    while (1)
    {
        Window_Main_Loop();
        if (g_should_exit) break;
    }
#endif

    // Added
    if (jkPlayer_bHasLoadedSettingsOnce) {
        jkPlayer_WriteConf(jkPlayer_playerShortName);
    }

    Main_Shutdown();
    return 1;
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
