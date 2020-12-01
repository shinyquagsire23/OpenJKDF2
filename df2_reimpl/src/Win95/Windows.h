#ifndef _WIN95WINDOWS_H
#define _WIN95WINDOWS_H

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

static void (*Windows_GameErrorMsgbox)(const char *a1, ...) = (void*)Windows_GameErrorMsgbox_ADDR;
static int (*Windows_ErrorMsgboxWide)(const char *a1, ...) = (void*)Windows_ErrorMsgboxWide_ADDR;

#endif // _WIN95WINDOWS_H
