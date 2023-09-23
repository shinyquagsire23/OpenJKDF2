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


#ifdef TARGET_TWL

#include <nds.h>

static int dword_855E98 = 0;
static int dword_855DE4 = 0;

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
int Window_xPos = 0;
int Window_yPos = 0;
int last_jkGame_isDDraw = 0;
int last_jkQuakeConsole_bOpen = 0;
int Window_menu_mouseX = 0;
int Window_menu_mouseY = 0;

void test_display()
{
    swiWaitForVBlank();
    scanKeys();
    int keys = keysDown();
    //if (keys & KEY_START) break;


    // print at using ansi escape sequence \x1b[line;columnH 
    iprintf("\x1b[0;0HMain Window");
}

void Window_Main_Loop()
{
    test_display();

    jkMain_GuiAdvance();
    Window_msg_main_handler(g_hWnd, WM_PAINT, 0, 0);
    
    //Window_SdlUpdate();
}

int Window_Main_Linux(int argc, char** argv)
{
    char cmdLine[1024];
    int result;
    
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

    while(1){test_display();}

    int fullscreen = wuRegistry_GetBool("Window_isFullscreen", 0);
    int hidpi = wuRegistry_GetBool("Window_isHiDpi", 0);
    Window_SetFullscreen(fullscreen);
    Window_SetHiDpi(hidpi);
    //Window_RecreateSDL2Window();

    if (!result) return result;

#if 0
    if (Main_bHeadless)
    {
        if (displayWindow) {
            std3D_FreeResources();
            SDL_GL_DeleteContext(glWindowContext);
            SDL_DestroyWindow(displayWindow);
        }
    }
#endif

    g_window_not_destroyed = 1;
    
    Window_msg_main_handler(g_hWnd, 0x1, 0, 0); // WM_CREATE
    Window_msg_main_handler(g_hWnd, 0x6, 2, 0); // WM_ACTIVATE
    Window_msg_main_handler(g_hWnd, 0x1C, 1, 0); // WM_ACTIVATEAPP
    Window_msg_main_handler(g_hWnd, 0x18, 0, 0); // WM_SHOWWINDOW
    Window_msg_main_handler(g_hWnd, WM_PAINT, 0, 0);

    while (1)
    {
        Window_Main_Loop();
        if (g_should_exit) break;
    }

    // Added
    if (jkPlayer_bHasLoadedSettingsOnce) {
        jkPlayer_WriteConf(jkPlayer_playerShortName);
    }

    Main_Shutdown();
    return 1;
}

int Window_DefaultHandler(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam, void* unused)
{
    return 0;
}

#endif