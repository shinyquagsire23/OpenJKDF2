#ifndef _STDCONTROL_H
#define _STDCONTROL_H

#include "types.h"
#include "globals.h"

#define stdControl_Startup_ADDR (0x0042DE60)
#define stdControl_Shutdown_ADDR (0x0042E240)
#define stdControl_Open_ADDR (0x0042E280)
#define stdControl_Close_ADDR (0x0042E2D0)
#define stdControl_Flush_ADDR (0x0042E320)
#define stdControl_Reset_ADDR (0x0042E440)
#define stdControl_EnableAxis_ADDR (0x0042E490)
#define stdControl_ReadControls_ADDR (0x0042E560) // MOTS altered
#define stdControl_ReadAxis_ADDR (0x0042E9B0)
#define stdControl_ReadAxisRaw_ADDR (0x0042EA80)
#define stdControl_ReadKeyAsAxis_ADDR (0x0042EAD0)
#define stdControl_ReadAxisAsKey_ADDR (0x0042EB60)
#define stdControl_ReadKey_ADDR (0x0042EBA0)
#define stdControl_FinishRead_ADDR (0x0042EC10)
#define stdControl_MessageHandler_ADDR (0x0042EC20)
#define stdControl_SetMouseSensitivity_ADDR (0x0042EC50)
#define stdControl_ToggleCursor_ADDR (0x0042ED40)
#define stdControl_ShowCursor_ADDR (0x0042EDC0)
#define stdControl_ToggleMouse_ADDR (0x0042EDD0)
#define stdControl_keyidk_ADDR (0x0042EE20)
#define stdControl_mouse_getdevicestate_ADDR (0x0042EEC0)
#define stdControl_InitAxis_ADDR (0x0042F090)

#ifdef SDL2_RENDER
void stdControl_FreeSdlJoysticks();
void stdControl_InitSdlJoysticks();
#endif

void stdControl_Reset();
int stdControl_EnableAxis(unsigned int idx);
flex_t stdControl_ReadAxis(int axisNum);
int stdControl_ReadAxisRaw(int axisNum);
flex_t stdControl_ReadKeyAsAxis(int keyNum);
int stdControl_ReadAxisAsKey(int axisNum);
int stdControl_ReadKey(int keyNum, int *pOut);
void stdControl_FinishRead();
int stdControl_MessageHandler(HWND hWnd, UINT Msg, WPARAM wParam, HWND lParam, LRESULT* unused);
void stdControl_SetMouseSensitivity(flex_t xSensitivity, flex_t ySensitivity);
void stdControl_SetKeydown(int keyNum, int bDown, uint32_t readTime);
void stdControl_SetSDLKeydown(int keyNum, int bDown, uint32_t readTime);

void stdControl_InitAxis(int index, int stickMin, int stickMax, flex_t multiplier);

#if !defined(SDL2_RENDER) && defined(WIN32)
static int (*stdControl_Startup)() = (void*)stdControl_Startup_ADDR;
static void (*stdControl_Shutdown)() = (void*)stdControl_Shutdown_ADDR;
static int (*stdControl_Open)() = (void*)stdControl_Open_ADDR;
static int (*stdControl_Close)() = (void*)stdControl_Close_ADDR;
static void (*stdControl_Flush)() = (void*)stdControl_Flush_ADDR;
static void (*stdControl_ToggleCursor)(int a1) = (void*)stdControl_ToggleCursor_ADDR;
static int (*stdControl_ShowCursor)(BOOL bShow) = (void*)stdControl_ShowCursor_ADDR;
static void (*stdControl_ReadControls)() = (void*)stdControl_ReadControls_ADDR;
#else
int stdControl_Startup();
void stdControl_Shutdown();
int stdControl_Open();
int stdControl_Close();
void stdControl_Flush();
void stdControl_ToggleCursor(int a);
int stdControl_ShowCursor(int a);
void stdControl_ToggleMouse();
void stdControl_ReadControls();
void stdControl_ReadMouse();
#endif

extern const stdControlDikStrToNum stdControl_aDikNumToStr[JK_TOTAL_NUM_KEYS];
extern const char *stdControl_aAxisNames[JK_NUM_AXES+1];

//static int (*stdControl_MessageHandler)(HWND a1, UINT a2, WPARAM a3, HWND a4, LRESULT *a5) = (void*)stdControl_MessageHandler_ADDR;;

#endif // _STDCONTROL_H
