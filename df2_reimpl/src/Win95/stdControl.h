#ifndef _STDCONTROL_H
#define _STDCONTROL_H

#include "types.h"

#define stdControl_Startup_ADDR (0x0042DE60)
#define stdControl_Shutdown_ADDR (0x0042E240)
#define stdControl_Open_ADDR (0x0042E280)
#define stdControl_Close_ADDR (0x0042E2D0)
#define stdControl_Flush_ADDR (0x0042E320)
#define stdControl_input_keymap_idk2_ADDR (0x0042E440)
#define stdControl_EnableAxis_ADDR (0x0042E490)
#define stdControl_ReadControls_ADDR (0x0042E560)
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
#define stdControl_axis_state_ADDR (0x0042F090)
#define stdConffile_OpenRead_ADDR (0x00430F50)
#define stdConffile_OpenWrite_ADDR (0x00431100)
#define stdConffile_OpenMode_ADDR (0x00431160)
#define stdConffile_Close_ADDR (0x00431310)
#define stdConffile_CloseWrite_ADDR (0x004313E0)
#define stdConffile_WriteLine_ADDR (0x00431420)
#define stdConffile_Write_ADDR (0x00431470)
#define stdConffile_Printf_ADDR (0x004314B0)
#define stdConffile_Read_ADDR (0x00431510)
#define stdConffile_ReadArgsFromStr_ADDR (0x00431550)
#define stdConffile_ReadArgs_ADDR (0x004315C0)
#define stdConffile_ReadLine_ADDR (0x00431650)
#define stdConffile_GetFileHandle_ADDR (0x00431730)
#define stdControl_GetAxis2_ADDR (0x004D6D70)

#define stdControl_bControlsIdle (*(int*)0x0055D5D4)

int stdControl_MessageHandler(int a1, int a2, int a3);

#ifdef WIN32
static int (*stdControl_Open)() = (void*)stdControl_Open_ADDR;
static int (*stdControl_Close)() = (void*)stdControl_Close_ADDR;
static void (*stdControl_Flush)() = (void*)stdControl_Flush_ADDR;
static void (*stdControl_ToggleCursor)(int a1) = (void*)stdControl_ToggleCursor_ADDR;
static int (*stdControl_ShowCursor)(BOOL bShow) = (void*)stdControl_ShowCursor_ADDR;
static int (*stdControl_ReadControls)() = (void*)stdControl_ReadControls_ADDR;
static int (*stdControl_FinishRead)() = (void*)stdControl_FinishRead_ADDR;
static float (*stdControl_ReadAxis)(int a) = (void*)stdControl_ReadAxis_ADDR;
static float (*stdControl_GetAxis2)(int a1) = (void*)stdControl_GetAxis2_ADDR;
#else
int stdControl_Open();
int stdControl_Close();
void stdControl_Flush();
void stdControl_ToggleCursor(int a);
int stdControl_ShowCursor(int a);
int stdControl_ReadControls();
int stdControl_FinishRead();
float stdControl_ReadAxis(int a);
float stdControl_GetAxis2(int a);
#endif

//static int (*stdControl_MessageHandler)(HWND a1, UINT a2, WPARAM a3, HWND a4, LRESULT *a5) = (void*)stdControl_MessageHandler_ADDR;;

#endif // _STDCONTROL_H
