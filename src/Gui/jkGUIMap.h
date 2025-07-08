#ifndef _JKGUIMAP_H
#define _JKGUIMAP_H

#include "types.h"
#include "globals.h"

#define jkGuiMap_Startup_ADDR (0x00415670)
#define jkGuiMap_Shutdown_ADDR (0x00415690)
#define jkGuiMap_dim_ADDR (0x004156A0)
#define jkGuiMap_sub_415720_ADDR (0x00415720)
#define jkGuiMap_sub_415B40_ADDR (0x00415B40)
#define jkGuiMap_sub_415B60_ADDR (0x00415B60)
#define jkGuiMap_sub_415B70_ADDR (0x00415B70)
#define jkGuiMap_Show_ADDR (0x00415C50)

void jkGuiMap_Startup();
void jkGuiMap_Shutdown();
void jkGuiMap_DrawMapScreen(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw);
void jkGuiMap_sub_415720(jkGuiMenu *menu);
int jkGuiMap_sub_415B40(jkGuiElement* pElement, jkGuiMenu *menu, int32_t mouseX, int32_t mouseY, int bRedraw);
int jkGuiMap_sub_415B60(jkGuiElement* pElement, jkGuiMenu *menu, int32_t mouseX, int32_t mouseY, int bRedraw);
int jkGuiMap_sub_415B70(jkGuiElement* pElement, jkGuiMenu *menu, int32_t mouseX, int32_t mouseY, int bRedraw);
int jkGuiMap_Show();

//static int (*jkGuiMap_Show)() = (void*)jkGuiMap_Show_ADDR;

#endif // _JKGUIMAP_H
