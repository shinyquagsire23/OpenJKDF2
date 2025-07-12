#ifndef _JKGUI_JOYSTICK_H
#define _JKGUI_JOYSTICK_H

#include "types.h"

#define jkGuiJoystick_nullsub_51_ADDR (0x0041AD50)
#define jkGuiJoystick_ClickList1_ADDR (0x0041AD60)
#define jkGuiJoystick_Draw_ADDR (0x0041ADD0)
#define jkGuiJoystick_ClickList2_ADDR (0x0041B220)
#define jkGuiJoystick_BindControl_ADDR (0x0041B2A0)
#define jkGuiJoystick_sub_41B390_ADDR (0x0041B390)
#define jkGuiJoystick_EnumFunc_ADDR (0x0041B570)
#define jkGuiJoystick_ClickList3_ADDR (0x0041B740)
#define jkGuiJoystick_AddEditClick_ADDR (0x0041B870)
#define jkGuiJoystick_RemoveClick_ADDR (0x0041B8B0)
#define jkGuiJoystick_OkCancelClick_ADDR (0x0041B920)
#define jkGuiJoystick_RestoreDefaultsClick_ADDR (0x0041BA70)
#define jkGuiJoystick_CaptureClick_ADDR (0x0041BAF0)
#define jkGuiJoystick_CalibrateClick_ADDR (0x0041BB30)
#define jkGuiJoystick_MenuTick_ADDR (0x0041BB60)
#define jkGuiJoystick_Show_ADDR (0x0041BF00)
#define jkGuiJoystick_DisableJoystickClick_ADDR (0x0041C170)
#define jkGuiJoystick_Startup_ADDR (0x0041C1C0)
#define jkGuiJoystick_Shutdown_ADDR (0x0041C1E0)

void jkGuiJoystick_nullsub_51();
int jkGuiJoystick_ClickList1(jkGuiElement *pElement, jkGuiMenu *pMenu, int32_t mouseX, int32_t mouseY, BOOL bRedraw);
MATH_FUNC void jkGuiJoystick_Draw(jkGuiMenu *pMenu, BOOL bRedraw);
int jkGuiJoystick_ClickList2(jkGuiElement *pElement, jkGuiMenu *pMenu, int32_t mouseX, int32_t mouseY, BOOL bRedraw);
void jkGuiJoystick_BindControl(int a1, int a2);
void jkGuiJoystick_sub_41B390();
int jkGuiJoystick_EnumFunc(int32_t inputFuncIdx, const char *pInputFuncStr, uint32_t flags, int32_t dxKeyNum, uint32_t dikNum, int32_t flags2, stdControlKeyInfoEntry *pControlEntry, Darray *pDarr);
int jkGuiJoystick_ClickList3(jkGuiElement *pElement, jkGuiMenu *pMenu, int32_t mouseX, int32_t mouseY, BOOL bRedraw);
int jkGuiJoystick_AddEditClick(jkGuiElement *pElement, jkGuiMenu *pMenu, int32_t mouseX, int32_t mouseY, BOOL bRedraw);
int jkGuiJoystick_RemoveClick(jkGuiElement *pElement, jkGuiMenu *pMenu, int32_t mouseX, int32_t mouseY, BOOL bRedraw);
int jkGuiJoystick_OkCancelClick(jkGuiElement *pElement, jkGuiMenu *pMenu, int32_t mouseX, int32_t mouseY, BOOL bRedraw);
int jkGuiJoystick_RestoreDefaultsClick(jkGuiElement *pElement, jkGuiMenu *pMenu, int32_t mouseX, int32_t mouseY, BOOL bRedraw);
int jkGuiJoystick_CaptureClick(jkGuiElement *pElement, jkGuiMenu *pMenu, int32_t mouseX, int32_t mouseY, BOOL bRedraw);
int jkGuiJoystick_CalibrateClick(jkGuiElement *pElement, jkGuiMenu *pMenu, int32_t mouseX, int32_t mouseY, BOOL bRedraw);
void jkGuiJoystick_MenuTick(jkGuiMenu *pMenu);
MATH_FUNC int32_t jkGuiJoystick_Show();
int jkGuiJoystick_DisableJoystickClick(jkGuiElement *pElement, jkGuiMenu *pMenu, int32_t mouseX, int32_t mouseY, BOOL bRedraw);
void jkGuiJoystick_Startup();
void jkGuiJoystick_Shutdown();

//static int (*jkGuiJoystick_Startup)() = (void*)jkGuiJoystick_Startup_ADDR;
//static int (*jkGuiJoystick_Show)() = (void*)jkGuiJoystick_Show_ADDR;
//static void (*jkGuiJoystick_Shutdown)() = (void*)jkGuiJoystick_Shutdown_ADDR;

#endif // _JKGUI_JOYSTICK_H
