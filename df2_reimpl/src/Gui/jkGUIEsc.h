#ifndef _JKGUIESC_H
#define _JKGUIESC_H

#include "types.h"

#define jkGuiEsc_Startup_ADDR (0x00411C00)
#define jkGuiEsc_Shutdown_ADDR (0x00411C20)
#define jkGuiEsc_Show_ADDR (0x00411C30)

//#define jkGuiEsc_menu (*(jkGuiMenu*)0x0529948)
//#define jkGuiEsc_aElements ((jkGuiElement*)0x0529560)

void jkGuiEsc_Startup();
void jkGuiEsc_Shutdown();
void jkGuiEsc_Show();

#endif // _JKGUIESC_H
