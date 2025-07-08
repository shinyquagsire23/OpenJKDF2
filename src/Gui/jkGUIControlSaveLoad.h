#ifndef _JKGUI_CONTROLSAVELOAD_H
#define _JKGUI_CONTROLSAVELOAD_H

#include "types.h"

#define jkGuiControlSaveLoad_sub_41E470_ADDR (0x0041E470)
#define jkGuiControlSaveLoad_ConfirmDelete_ADDR (0x0041E4F0)
#define jkGuiControlSaveLoad_FindFile_ADDR (0x0041E640)
#define jkGuiControlSaveLoad_Write_ADDR (0x0041E7E0)
#define jkGuiControlSaveLoad_Startup_ADDR (0x0041EBA0)
#define jkGuiControlSaveLoad_Shutdown_ADDR (0x0041EBC0)

int jkGuiControlSaveLoad_sub_41E470(jkGuiElement *pElement, jkGuiMenu *pMenu, int32_t mouseX, int32_t mouseY, int bRedraw);
int jkGuiControlSaveLoad_ConfirmDelete(jkGuiElement *pElement, jkGuiMenu *pMenu, int32_t mouseX, int32_t mouseY, int bRedraw);
void jkGuiControlSaveLoad_FindFile();
int jkGuiControlSaveLoad_Write(int bIdk);
void jkGuiControlSaveLoad_Startup();
void jkGuiControlSaveLoad_Shutdown();

//static int (*jkGuiControlSaveLoad_Startup)() = (void*)jkGuiControlSaveLoad_Startup_ADDR;
//static void (*jkGuiControlSaveLoad_Shutdown)() = (void*)jkGuiControlSaveLoad_Shutdown_ADDR;
//static int (*jkGuiControlSaveLoad_Write)(int a1) = (void*)jkGuiControlSaveLoad_Write_ADDR;

#endif // _JKGUI_CONTROLSAVELOAD_H
