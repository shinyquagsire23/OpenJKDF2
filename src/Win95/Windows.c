#include "Windows.h"

#include "Win95/WinIdk.h"
#include "Platform/wuRegistry.h"
#include "Win95/Window.h"
#include "Win95/stdGdi.h"
#include "Platform/stdControl.h"
#include "Win95/stdDisplay.h"
#include "Main/jkRes.h"
#include "Main/jkHud.h"
#include "Main/jkMain.h"
#include "Main/jkStrings.h"
#include "jk.h"
#include "General/stdString.h"
#include "Cog/sithCog.h"

#include "Main/Main.h"
#include "Main/InstallHelper.h"
#include "Main/jkQuakeConsole.h" // Added

#ifdef SDL2_RENDER
#include <SDL.h>
#endif

static int Windows_bInitted;
static uint32_t Windows_DplayGuid[4] = {0x0BF0613C0, 0x11D0DE79, 0x0A000C999, 0x4BAD7624};
static char Windows_cpu_info[0x4c] = { 0 };
static char Windows_cdpath_default[4] = {0}; // ???

static int Windows_bInittedGdi;
static int Windows_bWindowed;
static int Windows_bUnk;

void Windows_Startup()
{
    char cdPath[128]; // [esp+0h] [ebp-80h] BYREF

    Windows_bInitted = 1;
    WinIdk_SetDplayGuid(Windows_DplayGuid);
    WinIdk_detect_cpu(Windows_cpu_info);

#ifndef SDL2_RENDER
    wuRegistry_GetString("CD Path", cdPath, 128, Windows_cdpath_default); // ????
#else
    memset(cdPath, 0, sizeof(cdPath));
#endif
    jkRes_LoadCd(cdPath);
    Windows_installType = wuRegistry_GetInt("InstallType", 9);
    Window_AddMsgHandler(Windows_DefaultHandler);
}

void Windows_Shutdown()
{
    Window_RemoveMsgHandler(Windows_DefaultHandler);
    wuRegistry_Shutdown();

    // Added: Clean reset
#ifdef QOL_IMPROVEMENTS
    Windows_bInitted = 0;
    memset(Windows_cpu_info, 0, sizeof(Windows_cpu_info));
    memset(Windows_cdpath_default, 0, sizeof(Windows_cdpath_default));

    Windows_bInittedGdi = 0;
    Windows_bWindowed = 0;
    Windows_bUnk = 0;
#endif

    Windows_bInitted = 0;
}

int Windows_InitWindow()
{
#ifdef SDL2_RENDER
    return 1;
#endif
    HDC v2; // esi
    unsigned int v3; // ebx
    HWND v4; // eax

    v2 = jk_GetDC(jk_GetDesktopWindow());
    v3 = jk_GetDeviceCaps(v2, 12);
    jk_ReleaseDC(jk_GetDesktopWindow(), v2);

    if ( v3 < 8 )
        Windows_GameErrorMsgbox("ERR_NEED_256_COLOR");

    return 1;
}

void Windows_InitGdi(int windowed)
{
    Windows_bInittedGdi = 1;

#ifndef SDL2_RENDER
    jk_SetFocus(stdGdi_GetHwnd());
    jk_SetActiveWindow(stdGdi_GetHwnd());
#endif

    Windows_bWindowed = windowed;
#ifndef SDL2_RENDER
    if ( windowed )
        stdControl_ShowCursor(0);
    else
        Window_ShowCursorUnwindowed(0);

    jk_ValidateRect(stdGdi_GetHwnd(), 0);
#endif
    Window_AddMsgHandler(Windows_GdiHandler);
    Windows_bUnk = 0;
}

void Windows_ShutdownGdi()
{
#ifndef SDL2_RENDER
    if ( Windows_bInittedGdi )
#endif
    {
        Windows_bInittedGdi = 0;
        Window_RemoveMsgHandler(Windows_GdiHandler);
#ifndef SDL2_RENDER
        if ( Windows_bWindowed )
            stdControl_ShowCursor(1);
#endif
        Windows_bUnk = 0;
    }
}

UINT Windows_CalibrateJoystick()
{
#ifndef SDL2_RENDER
    return jk_WinExec("CONTROL JOY.CPL", 5u);
#else
    return 0;
#endif
}

int Windows_DefaultHandler(HWND a1, UINT a2, WPARAM a3, HWND a4, LRESULT *a5)
{
    signed int result; // eax

    result = 0;
    if ( a2 == WM_ERASEBKGND )
    {
        result = 1;
        *a5 = 1;
    }
    
    return result;
}

int Windows_GdiHandler(HWND a1, UINT msg, WPARAM wParam, HWND a4, LRESULT *a5)
{
    signed int v5; // esi
    int v6; // eax
    int v8; // eax

    v5 = 0;
    switch ( msg )
    {
        case WM_CLOSE:
            v5 = 1;
            *a5 = 1;
            break;
        case WM_SETCURSOR:
            if ( Windows_bWindowed )
            {
                jk_SetCursor(0);
                v5 = 1;
                *a5 = 1;
            }
            break;
        case WM_KEYFIRST:
            if ( wParam == VK_ESCAPE )               // ESC
            {
                if (Main_bMotsCompat)
                {
                    if (!jkGuiMultiplayer_mpcInfo.pCutsceneCog) {
                        if ( jkHud_bChatOpen )
                            jkHud_idk_time();
                        else
                            jkMain_do_guistate6();
                    }
                    else {
                        sithCog_SendMessage(jkGuiMultiplayer_mpcInfo.pCutsceneCog,SITH_MESSAGE_ESCAPED,0,0,0,0,0);
                    }
                }
                else
                {
                    if ( jkHud_bChatOpen )
                        jkHud_idk_time();
                    else
                        jkMain_do_guistate6();
                }
            }
            else if ( wParam >= VK_LWIN && wParam <= VK_RWIN )// WIN
            {
                v5 = 1;
                *a5 = 1;
            }
            break;
        case WM_CHAR:
            if ( jkHud_bChatOpen )
            {
                jkHud_SendChat(wParam);
                v5 = 1;
                *a5 = 1;
            }
            else if ( jkQuakeConsole_bOpen ) // Added: Quake console
            {
                jkQuakeConsole_SendInput(wParam, 1);
                v5 = 1;
                *a5 = 1;
            }
            break;
        default:
            break;
    }
    v6 = stdControl_ShowCursor(0);

    int v7 = v6 < -1;
    if ( v6 > -1 )
    {
        do
        {
            v8 = stdControl_ShowCursor(0);
            v7 = v8 < -1;
        }
        while ( v8 > -1 );
    }
    if ( v7 )
    {
        while ( stdControl_ShowCursor(1) < -1 )
            ;
    }
    return v5;
}

int Windows_ErrorMsgboxWide(const char *a1, ...)
{
    wchar_t *v1; // eax
    HWND v2; // eax
    wchar_t *v4; // [esp-8h] [ebp-808h]
    wchar_t Text[1024]; // [esp+0h] [ebp-800h] BYREF
    char tmp[1024+1];
    va_list va; // [esp+808h] [ebp+8h] BYREF

    va_start(va, a1);
#ifndef SDL2_RENDER
    v1 = jkStrings_GetUniStringWithFallback(a1);
    jk_vsnwprintf(Text, 0x400u, v1, va);
    v4 = jkStrings_GetUniStringWithFallback("ERROR");
    v2 = stdGdi_GetHwnd();
    return jk_MessageBoxW(v2, Text, v4, 0x10u);
#else
    v1 = jkStrings_GetUniStringWithFallback(a1);
    jk_vsnwprintf(Text, 0x400u, v1, va);
    //v4 = jkStrings_GetUniStringWithFallback("ERROR");
    stdString_WcharToChar(tmp, Text, 1024);

    jk_printf("ERROR: %s\n", tmp);
    SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "Error", tmp, NULL);
    return 0;
#endif
}

int Windows_ErrorMsgbox(const char *a1, ...)
{
    wchar_t *v1; // eax
    HWND v2; // eax
    wchar_t *v4; // [esp-8h] [ebp-408h]
    wchar_t Text[512]; // [esp+0h] [ebp-400h] BYREF
    va_list va; // [esp+408h] [ebp+8h] BYREF
    char tmp[512+1];

    va_start(va, a1);

#ifndef SDL2_RENDER
    v1 = jkStrings_GetUniStringWithFallback(a1);
    jk_vsnwprintf(Text, 0x200u, v1, va);
    v4 = jkStrings_GetUniStringWithFallback("ERROR");
    v2 = stdGdi_GetHwnd();
    return jk_MessageBoxW(v2, Text, v4, 0x10u);
#else
    v1 = jkStrings_GetUniStringWithFallback(a1);
    jk_vsnwprintf(Text, 0x200u, v1, va);
    //v4 = jkStrings_GetUniStringWithFallback("ERROR");

    stdString_WcharToChar(tmp, Text, 512);

    jk_printf("ERROR: %s\n", tmp);
    SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "Error", tmp, NULL);
    return 0;
#endif
}

void Windows_GameErrorMsgbox(const char *a1, ...)
{
    wchar_t *v1; // eax
    HWND v2; // eax
    wchar_t *v3; // [esp-8h] [ebp-408h]
    wchar_t Text[512+1]; // [esp+0h] [ebp-400h] BYREF
    char tmp[512+1];
    va_list va; // [esp+408h] [ebp+8h] BYREF

    va_start(va, a1);

#ifndef SDL2_RENDER
    v1 = jkStrings_GetUniStringWithFallback(a1);
    jk_vsnwprintf(Text, 0x200u, v1, va);
    v3 = jkStrings_GetUniStringWithFallback("ERROR");
    stdDisplay_ClearMode();
    v2 = stdGdi_GetHwnd();
    jk_MessageBoxW(v2, Text, v3, 0x10u);
#else
    vsnprintf(tmp, 0x200u, a1, va);
    jk_printf("FATAL ERROR: %s\n", tmp);
    SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, "Error", tmp, NULL);

#if !defined(ARCH_WASM) && !defined(TARGET_ANDROID)
    InstallHelper_CheckRequiredAssets(1);
#endif
#endif
    jk_exit(1);
}
