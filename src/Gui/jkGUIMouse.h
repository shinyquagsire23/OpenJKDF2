#ifndef _JKGUI_MOUSE_H
#define _JKGUI_MOUSE_H

#include "globals.h"
#include "types.h"

#define jkGuiMouse_ListClicked1_ADDR (0x00416CE0)
#define jkGuiMouse_sub_416D40_ADDR (0x00416D40)
#define jkGuiMouse_ListClicked2_ADDR (0x00417080)
#define jkGuiMouse_sub_417100_ADDR (0x00417100)
#define jkGuiMouse_sub_417210_ADDR (0x00417210)
#define jkGuiMouse_EnumBindings_ADDR (0x00417390)
#define jkGuiMouse_ListClicked3_ADDR (0x00417560)
#define jkGuiMouse_AddEditControlsClicked_ADDR (0x00417680)
#define jkGuiMouse_RemoveClicked_ADDR (0x004176B0)
#define jkGuiMouse_CancelOkClicked_ADDR (0x00417720)
#define jkGuiMouse_RestoreDefaultsClicked_ADDR (0x00417860)
#define jkGuiMouse_Show_ADDR (0x004178D0)
#define jkGuiMouse_Startup_ADDR (0x00417AD0)
#define jkGuiMouse_Shutdown_ADDR (0x00417AF0)

//static int (*jkGuiMouse_ListClicked1)(jkGuiElement *pClickedElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw) = (void*)jkGuiMouse_ListClicked1_ADDR;
//static int (*jkGuiMouse_ListClicked2)(jkGuiElement *pClickedElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw) = (void*)jkGuiMouse_ListClicked2_ADDR;
//static int (*jkGuiMouse_ListClicked3)(jkGuiElement *pElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw) = (void*)jkGuiMouse_ListClicked3_ADDR;
//static int (*jkGuiMouse_AddEditControlsClicked)(jkGuiElement *pClickedElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw) = (void*)jkGuiMouse_AddEditControlsClicked_ADDR;
//static int (*jkGuiMouse_RemoveClicked)(jkGuiElement *pClickedElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw) = (void*)jkGuiMouse_RemoveClicked_ADDR;
//static int (*jkGuiMouse_CancelOkClicked)(jkGuiElement *pClickedElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw) = (void*)jkGuiMouse_CancelOkClicked_ADDR;
//static int (*jkGuiMouse_RestoreDefaultsClicked)(jkGuiElement *pClickedElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw) = (void*)jkGuiMouse_RestoreDefaultsClicked_ADDR;

//static int (*jkGuiMouse_Show)() = (void*)jkGuiMouse_Show_ADDR;

int jkGuiMouse_ListClicked1(jkGuiElement *pElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw);
void jkGuiMouse_sub_416D40(jkGuiMenu *pMenu, int a2);
int jkGuiMouse_ListClicked2(jkGuiElement *pClickedElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw);
void jkGuiMouse_sub_417100(int a1, int a2);
void jkGuiMouse_sub_417210();
int jkGuiMouse_EnumBindings(int a1, const char *a2, uint32_t a3, int a4, uint32_t a5, int a6, stdControlKeyInfoEntry* a7, Darray* a8);
int jkGuiMouse_ListClicked3(jkGuiElement *pElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw);
int jkGuiMouse_AddEditControlsClicked(jkGuiElement *pClickedElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw);
int jkGuiMouse_RemoveClicked(jkGuiElement *pClickedElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw);
int jkGuiMouse_CancelOkClicked(jkGuiElement *pClickedElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw);
int jkGuiMouse_RestoreDefaultsClicked(jkGuiElement *pClickedElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw);
int jkGuiMouse_Show();
void jkGuiMouse_Startup();
void jkGuiMouse_Shutdown();

#endif // _JKGUI_MOUSE_H
