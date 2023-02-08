#ifndef _JKGUISETUP_H
#define _JKGUISETUP_H

#include "types.h"

#define jkGuiSetup_sub_412EF0_ADDR (0x00412EF0)
#define jkGuiSetup_Show_ADDR (0x00412F40)
#define jkGuiSetup_Startup_ADDR (0x00413140)
#define jkGuiSetup_Shutdown_ADDR (0x00413170)

void jkGuiSetup_sub_412EF0(jkGuiMenu *menu, int a2);
void jkGuiSetup_Show();
void jkGuiSetup_Startup();
void jkGuiSetup_Shutdown();

#endif // _JKGUISETUP_H
