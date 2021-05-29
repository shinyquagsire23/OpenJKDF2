#ifndef _WINDOW_H
#define _WINDOW_H

#include "types.h"

#define Window_Main_ADDR (0x0050E750)
#define Window_MessageLoop_ADDR (0x0050E9C0)
#define Window_ShowCursorUnwindowed_ADDR (0x0050EAA0)
#define Window_Fullscreen_ADDR (0x0050EAFD)
#define Window_Show_ADDR (0x0050EB20)
#define Window_sub_50EB30_ADDR (0x0050EB30)
#define Window_AddMsgHandler_ADDR (0x0050EB40)
#define Window_RemoveMsgHandler_ADDR (0x0050EB80)
#define Window_gui_dialogidk_ADDR (0x0050EBD0)
#define Window_sub_50EC00_ADDR (0x0050EC00)
#define Window_SetDrawHandlers_ADDR (0x0050EC70)
#define Window_GetDrawHandlers_ADDR (0x0050EC90)
#define Window_msg_main_handler_ADDR (0x0050ECB0)

typedef int (*WindowDrawHandler_t)(uint32_t);

#define Window_drawAndFlip (*(WindowDrawHandler_t*)0x00855E9C)
#define Window_setCooperativeLevel (*(WindowDrawHandler_t*)0x00855EA0)
#define Window_ext_handlers ((wm_handler*)0x00855DF0) // 16

typedef int (*WindowHandler_t)(HWND, UINT, WPARAM, HWND, LRESULT *);

typedef struct wm_handler
{
  WindowHandler_t handler;
  int32_t exists;
} wm_handler;

int Window_AddMsgHandler(WindowHandler_t a1);
int Window_RemoveMsgHandler(WindowHandler_t a1);
int Window_msg_main_handler(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
int Window_Main(HINSTANCE hInstance, int a2, char *lpCmdLine, int nShowCmd, LPCSTR lpWindowName);
void Window_SetDrawHandlers(WindowDrawHandler_t a1, WindowDrawHandler_t a2);
void Window_GetDrawHandlers(WindowDrawHandler_t *a1, WindowDrawHandler_t *a2);

//static void (*Window_GetDrawHandlers)(int *a1, int *a2) = (void*)Window_GetDrawHandlers_ADDR;
//static void (*Window_SetDrawHandlers)(int a1, int a2) = (void*)Window_SetDrawHandlers_ADDR;

static int (*_Window_msg_main_handler)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) = (void*)Window_msg_main_handler_ADDR;

// Added
int Window_DefaultHandler(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);

#ifdef LINUX
//int Window_AddMsgHandler(WindowHandler_t a1);
//int Window_RemoveMsgHandler(WindowHandler_t a1);
int Window_ShowCursorUnwindowed(int a1);
int Window_MessageLoop();
void Window_SdlUpdate();
#else
static int (*Window_ShowCursorUnwindowed)(int a1) = (void*)Window_ShowCursorUnwindowed_ADDR;
static int (*Window_MessageLoop)() = (void*)Window_MessageLoop_ADDR;
//static int (*Window_AddMsgHandler)(WindowHandler_t handler) = (void*)Window_AddMsgHandler_ADDR;
//static int (*Window_RemoveMsgHandler)(WindowHandler_t handler) = (void*)Window_RemoveMsgHandler_ADDR;
#endif

#endif // _WINDOW_H
