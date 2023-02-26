#ifndef _JKGUISAVELOAD_H
#define _JKGUISAVELOAD_H

#include "types.h"
#include "globals.h"

#define jkGuiSaveLoad_ListClick_ADDR (0x0041D900)
#define jkGuiSaveLoad_PopulateInfo_ADDR (0x0041D940)
#define jkGuiSaveLoad_DeleteOnClick_ADDR (0x0041DC60)
#define jkGuiSaveLoad_PopulateList_ADDR (0x0041DDD0)
#define jkGuiSaveLoad_SaveSort_ADDR (0x0041DFE0)
#define jkGuiSaveLoad_Show_ADDR (0x0041E010)
#define jkGuiSaveLoad_PopulateInfoInit_ADDR (0x0041E430)
#define jkGuiSaveLoad_Startup_ADDR (0x0041E440)
#define jkGuiSaveLoad_Shutdown_ADDR (0x0041E460)

int jkGuiSaveLoad_ListClick(jkGuiElement *element, jkGuiMenu *menu, int mouseX, int mouseY, BOOL redraw);
void jkGuiSaveLoad_PopulateInfo(int bRedraw);
int jkGuiSaveLoad_DeleteOnClick(jkGuiElement *element, jkGuiMenu *menu, int mouseX, int mouseY, int bRedraw);
void jkGuiSaveLoad_PopulateList();
int jkGuiSaveLoad_SaveSort(const void* a_, const void* b_);
int jkGuiSaveLoad_Show(int bIsSave);
int jkGuiSaveLoad_PopulateInfoInit(jkGuiElement *a1, jkGuiMenu *a2, int a3, int a4, BOOL redraw);
void jkGuiSaveLoad_Startup();
void jkGuiSaveLoad_Shutdown();

//static int (*jkGuiSaveLoad_Startup)() = (void*)jkGuiSaveLoad_Startup_ADDR;
//static int (*jkGuiSaveLoad_Show)(int a1) = (void*)jkGuiSaveLoad_Show_ADDR;

#endif // _JKGUISAVELOAD_H
