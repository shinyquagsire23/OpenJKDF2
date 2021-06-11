#include "Window.h"

#include "Win95/stdGdi.h"
#include "Main/Main.h"
#include "Main/jkMain.h"
#include "Main/jkGame.h"

#include "jk.h"

//static wm_handler Window_ext_handlers[16] = {0};

int Window_AddMsgHandler(WindowHandler_t a1)
{
    int i; // ecx

    for (i = 0; i < 16; i++)
    {
        if ( !Window_ext_handlers[i].exists )
            break;
    }
    Window_ext_handlers[i].handler = a1;
    Window_ext_handlers[i].exists = 1;
    ++g_handler_count;
    return 1;
}

int Window_RemoveMsgHandler(WindowHandler_t a1)
{
    int i;

    for (i = 0; i < 16; i++)
    {
        if ( Window_ext_handlers[i].handler == a1 )
            break;
    }

    Window_ext_handlers[i].handler = 0;
    Window_ext_handlers[i].exists = 0;
    g_handler_count -= 1; // doing g_handler_count-- changes behavior???
    return 1;
}

//static int dword_855E98 = 0;
//static int dword_855DE4 = 0;
#define dword_855E98 (*(int*)0x855E98)
#define dword_855DE4 (*(int*)0x855DE4)

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
#ifdef WIN32
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
#ifdef WIN32
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
        return Window_DefaultHandler(hWnd, Msg, wParam, lParam);

    for ( ext_handler = Window_ext_handlers; !ext_handler->exists || !ext_handler->handler(hWnd, Msg, wParam, lParam, &v10); ++ext_handler )
    {
        if ( ++handler_count >= g_handler_count )
            return Window_DefaultHandler(hWnd, Msg, wParam, lParam);
    }
    return v10;
}

#ifdef WIN32

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

int Window_DefaultHandler(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProcA(hWnd, Msg, wParam, lParam);
}

#endif

#ifdef LINUX

#include <string.h>
#include <SDL2/SDL.h>
#include <GL/gl.h>
#include "Win95/Video.h"

SDL_Window* displayWindow;
SDL_Renderer* displayRenderer;
SDL_Event event;
SDL_GLContext glWindowContext;
SDL_Surface* displaySurface;
SDL_Texture *menuTexture;
SDL_Surface *menuSurface;

void Window_HandleMouseMove(SDL_MouseMotionEvent *event)
{
    uint32_t pos = ((event->x) & 0xFFFF) | (((event->y) << 16) & 0xFFFF0000);

    Window_msg_main_handler(g_hWnd, WM_MOUSEMOVE, 0, pos);
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
            case SDL_KEYDOWN:
                //handleKey(&event.key.keysym, WM_KEYDOWN, 0x1);
                break;
            case SDL_KEYUP:
                //handleKey(&event.key.keysym, WM_KEYUP, 0xc0000001);
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

                pos = ((mevent->x) & 0xFFFF) | (((mevent->y) << 16) & 0xFFFF0000);
                msgl = (event.type == SDL_MOUSEBUTTONDOWN ? WM_LBUTTONDOWN : WM_LBUTTONUP);
                msgr = (event.type == SDL_MOUSEBUTTONDOWN ? WM_RBUTTONDOWN : WM_RBUTTONUP);
                
                if (hasLeft)
                    Window_msg_main_handler(g_hWnd, msgl, left | right, pos);
                if (hasRight)
                    Window_msg_main_handler(g_hWnd, msgr, left | right, pos);

                break;
            case SDL_QUIT:
                printf("Quit!\n");
                while(1);
                break;
            default:
                break;
        }
    }

    if (Video_bInitted)
    {
        SDL_Rect srcRect = {0, 0, 640, 480};
        SDL_Rect dstRect = {0, 0, 640, 480};
        
        SDL_BlitSurface(Video_menuBuffer.sdlSurface, 0, menuSurface, 0); //TODO error check
        
        SDL_UpdateTexture(menuTexture, NULL, menuSurface->pixels, menuSurface->pitch);
    }
    else
    {
        SDL_UpdateTexture(menuTexture, NULL, menuSurface->pixels, menuSurface->pitch);
    }

    if (!jkGame_isDDraw)
    {
        std3D_StartScene();
        std3D_DrawMenu();
        std3D_EndScene();
        SDL_GL_SwapWindow(displayWindow);
        //SDL_RenderClear(displayRenderer);
        //SDL_RenderCopy(displayRenderer, menuTexture, NULL, NULL);
        //SDL_RenderPresent(displayRenderer);
    }
    else
    {
        
    }
}

void Window_SdlVblank()
{
    SDL_GL_SwapWindow(displayWindow);
}

int Window_Main_Linux(int argc, char** argv)
{
    char cmdLine[1024];
    int result;
    
    // Init SDL
    SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO | SDL_INIT_NOPARACHUTE);

    SDL_CreateWindowAndRenderer(640, 480, SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE, &displayWindow, &displayRenderer);
    SDL_SetRenderDrawBlendMode(displayRenderer, SDL_BLENDMODE_BLEND);
    
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
	SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 2);
	//SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
	
	SDL_GL_SetAttribute(SDL_GL_SHARE_WITH_CURRENT_CONTEXT, 1);
	glWindowContext = SDL_GL_CreateContext(displayWindow);
	if (glWindowContext == NULL)
	{
	    jk_printf("!! Failed to initialize SDL OpenGL context !!\n");
	    while (1);
	}
	
	displaySurface = SDL_GetWindowSurface(displayWindow);
		
    SDL_GL_MakeCurrent(displayWindow, glWindowContext);
    SDL_GL_SetSwapInterval(1); // Enable vsync
    
    menuSurface = SDL_CreateRGBSurface(0, 640, 480, 32,
                                        0x00FF0000,
                                        0x0000FF00,
                                        0x000000FF,
                                        0xFF000000);
    
	SDL_FillRect(menuSurface, NULL, 0xFFFFFFFF);
    
    menuTexture = SDL_CreateTexture(displayRenderer,
                                            SDL_PIXELFORMAT_ARGB8888,
                                            SDL_TEXTUREACCESS_STREAMING,
                                            640, 480);
    
    glewInit();
    
    SDL_RenderClear(displayRenderer);
    SDL_RenderPresent(displayRenderer);
    
    
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
    
    while (1)
    {
        jkMain_GuiAdvance();
        Window_msg_main_handler(g_hWnd, WM_PAINT, 0, 0);
        
        Window_SdlUpdate();
    }
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
    return 1;
}

int Window_DefaultHandler(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    return 0;
}

int Window_MessageLoop()
{
    jkMain_GuiAdvance();
    Window_msg_main_handler(g_hWnd, WM_PAINT, 0, 0);
    
    Window_SdlUpdate();
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
