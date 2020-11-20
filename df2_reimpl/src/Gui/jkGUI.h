#ifndef _JKGUI_H
#define _JKGUI_H

#include "Primitives/rdRect.h"

#define jkGui_InitMenu_ADDR (0x004129A0)
#define jkGui_MessageBeep_ADDR (0x00412A10)
#define jkGui_Initialize_ADDR (0x00412A20)
#define jkGui_Shutdown_ADDR (0x00412B70)
#define jkGui_SetModeMenu_ADDR (0x00412C00)
#define jkGui_SetModeGame_ADDR (0x00412DF0)
#define jkGui_sub_412E20_ADDR (0x00412E20)
#define jkGui_copies_string_ADDR (0x00412EA0)
#define jkGui_sub_412EC0_ADDR (0x00412EC0)
#define jkGui_sub_412ED0_ADDR (0x00412ED0)

typedef struct jkGuiMenu jkGuiMenu;
typedef struct stdBitmap stdBitmap;

void jkGui_InitMenu(jkGuiMenu *menu, stdBitmap *bgBitmap);

#endif // _JKGUI_H
