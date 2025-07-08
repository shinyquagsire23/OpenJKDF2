#ifndef _JKGUIPLAYER_H
#define _JKGUIPLAYER_H

#include "types.h"

#define jkGuiPlayer_Startup_ADDR (0x004105F0)
#define jkGuiPlayer_Shutdown_ADDR (0x00410630)
#define jkGuiPlayer_sub_410640_ADDR (0x00410640)
#define jkGuiPlayer_ShowNewPlayer_ADDR (0x00410870)
#define jkGuiPlayer_DifficultyDraw_ADDR (0x00410D10)

int jkGuiPlayer_Startup();
void jkGuiPlayer_Shutdown();
void jkGuiPlayer_ShowNewPlayer(int a1);
int jkGuiPlayer_DifficultyDraw(jkGuiElement *element, jkGuiMenu *menu, int32_t mouseX, int32_t mouseY, int bRedraw);

#endif // _JKGUIPLAYER_H
