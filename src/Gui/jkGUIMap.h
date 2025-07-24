#ifndef _JKGUIMAP_H
#define _JKGUIMAP_H

#include "types.h"
#include "globals.h"

#define jkGuiMap_Startup_ADDR (0x00415670)
#define jkGuiMap_Shutdown_ADDR (0x00415690)
#define jkGuiMap_dim_ADDR (0x004156A0)
#define jkGuiMap_Update_ADDR (0x00415720)
#define jkGuiMap_OrbitButtonClicked_ADDR (0x00415B40)
#define jkGuiMap_TransformButtonClicked_ADDR (0x00415B60)
#define jkGuiMap_ResetButtonClicked_ADDR (0x00415B70)
#define jkGuiMap_Show_ADDR (0x00415C50)

void jkGuiMap_Startup();
void jkGuiMap_Shutdown();
void jkGuiMap_DrawMapScreen(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw);
void jkGuiMap_Update(jkGuiMenu *menu);
int jkGuiMap_OrbitButtonClicked(jkGuiElement* pElement, jkGuiMenu *menu, int32_t mouseX, int32_t mouseY, int bRedraw);
int jkGuiMap_TransformButtonClicked(jkGuiElement* pElement, jkGuiMenu *menu, int32_t mouseX, int32_t mouseY, int bRedraw);
int jkGuiMap_ResetButtonClicked(jkGuiElement* pElement, jkGuiMenu *menu, int32_t mouseX, int32_t mouseY, int bRedraw);
int jkGuiMap_Show();

//static int (*jkGuiMap_Show)() = (void*)jkGuiMap_Show_ADDR;

#endif // _JKGUIMAP_H
