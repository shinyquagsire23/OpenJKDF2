#ifndef _JKGUI_MOUSE_H
#define _JKGUI_MOUSE_H

#define jkGuiMouse_sub_416CE0_ADDR (0x00416CE0)
#define jkGuiMouse_sub_416D40_ADDR (0x00416D40)
#define jkGuiMouse_sub_417080_ADDR (0x00417080)
#define jkGuiMouse_sub_417100_ADDR (0x00417100)
#define jkGuiMouse_sub_417210_ADDR (0x00417210)
#define jkGuiMouse_sub_417390_ADDR (0x00417390)
#define jkGuiMouse_sub_417560_ADDR (0x00417560)
#define jkGuiMouse_sub_417680_ADDR (0x00417680)
#define jkGuiMouse_sub_4176B0_ADDR (0x004176B0)
#define jkGuiMouse_sub_417720_ADDR (0x00417720)
#define jkGuiMouse_sub_417860_ADDR (0x00417860)
#define jkGuiMouse_Show_ADDR (0x004178D0)
#define jkGuiMouse_Initialize_ADDR (0x00417AD0)
#define jkGuiMouse_Shutdown_ADDR (0x00417AF0)

static int (*jkGuiMouse_Initialize)() = (void*)jkGuiMouse_Initialize_ADDR;
static int (*jkGuiMouse_Show)() = (void*)jkGuiMouse_Show_ADDR;

#endif // _JKGUI_MOUSE_H
