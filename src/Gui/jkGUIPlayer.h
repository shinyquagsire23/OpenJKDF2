#ifndef _JKGUIPLAYER_H
#define _JKGUIPLAYER_H

#include "types.h"

#define jkGuiPlayer_Initialize_ADDR (0x004105F0)
#define jkGuiPlayer_Shutdown_ADDR (0x00410630)
#define jkGuiPlayer_sub_410640_ADDR (0x00410640)
#define jkGuiPlayer_ShowNewPlayer_ADDR (0x00410870)
#define jkGuiPlayer_DifficultyDraw_ADDR (0x00410D10)

//#define jkGuiPlayer_menuNew (*(jkGuiMenu*)0x005275B8)
//#define jkGuiPlayer_menuSelect (*(jkGuiMenu*)0x005270B8)
//#define jkGuiPlayer_menuNewElements ((jkGuiElement*)0x00527108)
//#define jkGuiPlayer_menuSelectElements ((jkGuiElement*)0x00526D98)
//#define jkGuiPlayer_bInitted (*(int*)0x00555D20)

int jkGuiPlayer_Initialize();
void jkGuiPlayer_Shutdown();
void jkGuiPlayer_ShowNewPlayer(int a1);
int jkGuiPlayer_DifficultyDraw(jkGuiElement *element, jkGuiMenu *menu, int mouseX, int mouseY, int bRedraw);

//static int (*jkGuiPlayer_Initialize)() = (void*)jkGuiPlayer_Initialize_ADDR;
//static void (*jkGuiPlayer_ShowNewPlayer)(int) = (void*)jkGuiPlayer_ShowNewPlayer_ADDR;

#endif // _JKGUIPLAYER_H
