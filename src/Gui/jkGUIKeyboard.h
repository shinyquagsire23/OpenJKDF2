#ifndef _JKGUI_KEYBOARD_H
#define _JKGUI_KEYBOARD_H

#include "globals.h"
#include "types.h"

#define jkGuiKeyboard_DIKStrToNum_ADDR (0x00411DE0)
#define jkGuiKeyboard_sub_411E40_ADDR (0x00411E40)
#define jkGuiKeyboard_sub_411E90_ADDR (0x00411E90)
#define jkGuiKeyboard_sub_411F40_ADDR (0x00411F40)
#define jkGuiKeyboard_sub_412110_ADDR (0x00412110)
#define jkGuiKeyboard_sub_4122C0_ADDR (0x004122C0)
#define jkGuiKeyboard_sub_4123C0_ADDR (0x004123C0)
#define jkGuiKeyboard_sub_4126C0_ADDR (0x004126C0)
#define jkGuiKeyboard_sub_4126F0_ADDR (0x004126F0)
#define jkGuiKeyboard_sub_412740_ADDR (0x00412740)
#define jkGuiKeyboard_sub_4127C0_ADDR (0x004127C0)
#define jkGuiKeyboard_Show_ADDR (0x00412830)
#define jkGuiKeyboard_Startup_ADDR (0x00412970)
#define jkGuiKeyboard_Shutdown_ADDR (0x00412990)

const char* jkGuiKeyboard_DIKNumToStr(unsigned int idx, char bIsIdxAxis);
int jkGuiKeyboard_sub_411E40(Darray *pDarr);
int jkGuiKeyboard_RemoveControlClicked(jkGuiElement *pClickedElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw);
void jkGuiKeyboard_sub_411F40(jkGuiElement *pElement, Darray *pDarr);
int jkGuiKeyboard_EnumBindings(int inputFuncIdx, const char *pInputFuncStr, uint32_t a3, int dxKeyNum, uint32_t a5, int flags, stdControlKeyInfoEntry *pControlEntry, Darray *pDarr);
int jkGuiKeyboard_AddControlClicked(jkGuiElement *pElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw);
void jkGuiKeyboard_sub_4123C0(jkGuiMenu *pMenu);
int jkGuiKeyboard_OkClicked(jkGuiElement *pElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw);
int jkGuiKeyboard_CancelClicked(jkGuiElement *pElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw);
int jkGuiKeyboard_ControlListClicked(jkGuiElement *pElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw);
int jkGuiKeyboard_RestoreDefaultsClicked(jkGuiElement *pElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw);
int jkGuiKeyboard_Show();
void jkGuiKeyboard_Startup();
void jkGuiKeyboard_Shutdown();

//static int (*jkGuiKeyboard_Startup)() = (void*)jkGuiKeyboard_Startup_ADDR;
//static int (*jkGuiKeyboard_Show)() = (void*)jkGuiKeyboard_Show_ADDR;
//static void (*jkGuiKeyboard_Shutdown)() = (void*)jkGuiKeyboard_Shutdown_ADDR;

#endif // _JKGUI_KEYBOARD_H
