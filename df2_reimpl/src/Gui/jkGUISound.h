#ifndef _JKGUI_SOUND_H
#define _JKGUI_SOUND_H

#define jkGuiSound_Initialize_ADDR (0x00410D70)
#define jkGuiSound_Shutdown_ADDR (0x00410E30)
#define jkGuiSound_Show_ADDR (0x00410E70)

static int (*jkGuiSound_Show)() = (void*)jkGuiSound_Show_ADDR;

#endif // _JKGUI_SOUND_H
