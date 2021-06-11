#ifndef _JKGUISAVELOAD_H
#define _JKGUISAVELOAD_H

#include "types.h"
#include "Engine/sithSave.h"

#define jkGuiSaveLoad_ListClick_ADDR (0x0041D900)
#define jkGuiSaveLoad_PopulateInfo_ADDR (0x0041D940)
#define jkGuiSaveLoad_DeleteOnClick_ADDR (0x0041DC60)
#define jkGuiSaveLoad_PopulateList_ADDR (0x0041DDD0)
#define jkGuiSaveLoad_SaveSort_ADDR (0x0041DFE0)
#define jkGuiSaveLoad_Show_ADDR (0x0041E010)
#define jkGuiSaveLoad_PopulateInfoInit_ADDR (0x0041E430)
#define jkGuiSaveLoad_Initialize_ADDR (0x0041E440)
#define jkGuiSaveLoad_Shutdown_ADDR (0x0041E460)

//#define jkGuiSaveLoad_aElements ((jkGuiElement*)0x0053B948)
//#define jkGuiSaveLoad_menu (*(jkGuiMenu*)0x0053BF28)
#define jkGuiSaveLoad_wtextEpisode ((wchar_t*)0x00559528) //[256]
#define jkGuiSaveLoad_wtextHealth ((wchar_t*)0x00559728) // 64
#define jkGuiSaveLoad_numEntries (*(int*)0x005597A8)
#define jkGuiSaveLoad_wtextShields ((wchar_t*)0x005597B0) // 64
#define jkGuiSaveLoad_word_559830 ((wchar_t*)0x00559830) // 256
#define jkGuiSaveLoad_bIsSaveMenu (*(int*)0x00559A30)
#define jkGuiSaveLoad_wtextSaveName ((wchar_t*)0x00559A38) // 256
#define jkGuiSaveLoad_DarrayEntries (*(Darray*)0x00559C38)
#define jkGuiSaveLoad_word_559C54 ((wchar_t*)0x00559C54) // 10
#define jkGuiSaveLoad_byte_559C50 ((char*)0x00559C50) // 4

typedef struct jkGuiSaveLoad_Entry
{
  sithSave_Header saveHeader;
  char fpath[128];
} jkGuiSaveLoad_Entry;

int jkGuiSaveLoad_ListClick(jkGuiElement *element, jkGuiMenu *menu, int mouseX, int mouseY, int a5);
void jkGuiSaveLoad_PopulateInfo(int bRedraw);
int jkGuiSaveLoad_DeleteOnClick(jkGuiElement *element, jkGuiMenu *menu);
void jkGuiSaveLoad_PopulateList();
int jkGuiSaveLoad_SaveSort(jkGuiStringEntry *a, jkGuiStringEntry *b);
int jkGuiSaveLoad_Show(int bIsSave);
int jkGuiSaveLoad_PopulateInfoInit(jkGuiElement *a1, jkGuiMenu *a2, int a3, int a4, int a5);
void jkGuiSaveLoad_Initialize();
void jkGuiSaveLoad_Shutdown();

//static int (*jkGuiSaveLoad_Initialize)() = (void*)jkGuiSaveLoad_Initialize_ADDR;
//static int (*jkGuiSaveLoad_Show)(int a1) = (void*)jkGuiSaveLoad_Show_ADDR;

#endif // _JKGUISAVELOAD_H
