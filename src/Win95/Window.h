#ifndef _WINDOW_H
#define _WINDOW_H

#include "types.h"
#include "globals.h"

#define Window_Main_ADDR (0x0050E750)
#define Window_MessageLoop_ADDR (0x0050E9C0)
#define Window_ShowCursorUnwindowed_ADDR (0x0050EAA0)
#define Window_Fullscreen_ADDR (0x0050EAFD)
#define Window_Show_ADDR (0x0050EB20)
#define Window_sub_50EB30_ADDR (0x0050EB30)
#define Window_AddMsgHandler_ADDR (0x0050EB40)
#define Window_RemoveMsgHandler_ADDR (0x0050EB80)
#define Window_AddDialogHwnd_ADDR (0x0050EBD0)
#define Window_sub_50EC00_ADDR (0x0050EC00)
#define Window_SetDrawHandlers_ADDR (0x0050EC70)
#define Window_GetDrawHandlers_ADDR (0x0050EC90)
#define Window_msg_main_handler_ADDR (0x0050ECB0)

extern int Window_xSize;
extern int Window_ySize;

int Window_AddMsgHandler(WindowHandler_t a1);
int Window_RemoveMsgHandler(WindowHandler_t a1);
int Window_AddDialogHwnd(HWND a1);
int Window_msg_main_handler(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
int Window_Main(HINSTANCE hInstance, int a2, char *lpCmdLine, int nShowCmd, LPCSTR lpWindowName);
void Window_SetDrawHandlers(WindowDrawHandler_t a1, WindowDrawHandler_t a2);
void Window_GetDrawHandlers(WindowDrawHandler_t *a1, WindowDrawHandler_t *a2);

//static void (*Window_GetDrawHandlers)(int *a1, int *a2) = (void*)Window_GetDrawHandlers_ADDR;
//static void (*Window_SetDrawHandlers)(int a1, int a2) = (void*)Window_SetDrawHandlers_ADDR;

//static int (*_Window_msg_main_handler)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) = (void*)Window_msg_main_handler_ADDR;

// Added
int Window_DefaultHandler(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam, void* unused);

extern int Window_isHiDpi;
extern int Window_isFullscreen;
void Window_SetHiDpi(int val);
void Window_SetFullscreen(int val);


extern int Window_lastXRel;
extern int Window_lastYRel;
extern int Window_lastSampleMs;
extern int Window_bMouseLeft;
extern int Window_bMouseRight;
extern int Window_mouseWheelY;
extern int Window_mouseWheelX;

#if !defined(SDL2_RENDER) && defined(WIN32)
//static int (*Window_ShowCursorUnwindowed)(int a1) = (void*)Window_ShowCursorUnwindowed_ADDR;
//static int (*Window_MessageLoop)() = (void*)Window_MessageLoop_ADDR;
//static int (*Window_AddMsgHandler)(WindowHandler_t handler) = (void*)Window_AddMsgHandler_ADDR;
//static int (*Window_RemoveMsgHandler)(WindowHandler_t handler) = (void*)Window_RemoveMsgHandler_ADDR;
#else
int Window_Main_Linux(int argc, char** argv);
//int Window_AddMsgHandler(WindowHandler_t a1);
//int Window_RemoveMsgHandler(WindowHandler_t a1);
int Window_ShowCursorUnwindowed(int a1);
int Window_MessageLoop();
void Window_SdlUpdate();
void Window_SdlVblank();
void Window_RecreateSDL2Window();
#endif

#endif // _WINDOW_H
