#ifndef _WIN95WINDOWS_H
#define _WIN95WINDOWS_H

#include "types.h"

#define Windows_Startup_ADDR (0x041EC00)
#define Windows_Shutdown_ADDR (0x041EC80)
#define Windows_InitWindow_ADDR (0x041ECA0)
#define Windows_InitGdi_ADDR (0x041ECF0)
#define Windows_ShutdownGdi_ADDR (0x041ED70)
#define Windows_CalibrateJoystick_ADDR (0x0041EDB0)
#define Windows_DefaultHandler_ADDR (0x041EDC0)
#define Windows_GdiHandler_ADDR (0x041EDE0)
#define Windows_ErrorMsgboxWide_ADDR (0x041EFD0)
#define Windows_ErrorMsgbox_ADDR (0x041F030)
#define Windows_GameErrorMsgbox_ADDR (0x041F090)

void Windows_Startup();
void Windows_Shutdown();
int Windows_InitWindow();
void Windows_InitGdi(int windowed);
void Windows_ShutdownGdi();
UINT Windows_CalibrateJoystick();
int Windows_DefaultHandler(HWND a1, UINT a2, WPARAM a3, HWND a4, LRESULT *a5);
int Windows_GdiHandler(HWND a1, UINT msg, WPARAM wParam, HWND a4, LRESULT *a5);

int Windows_ErrorMsgboxWide(const char *a1, ...);
int Windows_ErrorMsgbox(const char *a1, ...);
void Windows_GameErrorMsgbox(const char *a1, ...);
//static void (*Windows_GameErrorMsgbox)(const char *a1, ...) = (void*)Windows_GameErrorMsgbox_ADDR;
//static int (*Windows_ErrorMsgboxWide)(const char *a1, ...) = (void*)Windows_ErrorMsgboxWide_ADDR;

#define Windows_installType (*(int*)0x008606E0)

#endif // _WIN95WINDOWS_H
