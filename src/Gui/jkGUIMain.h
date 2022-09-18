#ifndef _JKGUIMAIN_H
#define _JKGUIMAIN_H

#include "types.h"

#define jkGuiMain_Show_ADDR (0x004100F0)
#define jkGuiMain_ShowCutscenes_ADDR (0x00410210)
#define jkGuiMain_Startup_ADDR (0x004104A0)
#define jkGuiMain_Shutdown_ADDR (0x004104C0)
#define jkGuiMain_PopulateCutscenes_ADDR (0x004104D0)
#define jkGuiMain_FreeCutscenes_ADDR (0x004105B0)

void jkGuiMain_Show();
void jkGuiMain_ShowCutscenes();
void jkGuiMain_Startup();
void jkGuiMain_Shutdown();
void jkGuiMain_PopulateCutscenes(Darray *list, jkGuiElement *element);
void jkGuiMain_FreeCutscenes(Darray *a1);

#endif // _JKGUIMAIN_H
