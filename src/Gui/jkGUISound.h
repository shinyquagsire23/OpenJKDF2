#ifndef _JKGUI_SOUND_H
#define _JKGUI_SOUND_H

#include "types.h"
#include "globals.h"

#define jkGuiSound_Startup_ADDR (0x00410D70)
#define jkGuiSound_Shutdown_ADDR (0x00410E30)
#define jkGuiSound_Show_ADDR (0x00410E70)

void jkGuiSound_Startup();
void jkGuiSound_Shutdown();
int jkGuiSound_Show();

#endif // _JKGUI_SOUND_H
