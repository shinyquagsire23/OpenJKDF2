#ifndef _JKGUISAVELOAD_H
#define _JKGUISAVELOAD_H

#define jkGuiSaveLoad_ListClick_ADDR (0x0041D900)
#define jkGuiSaveLoad_PopulateInfo_ADDR (0x0041D940)
#define jkGuiSaveLoad_DeleteOnClick_ADDR (0x0041DC60)
#define jkGuiSaveLoad_PopulateList_ADDR (0x0041DDD0)
#define jkGuiSaveLoad_SaveSort_ADDR (0x0041DFE0)
#define jkGuiSaveLoad_Show_ADDR (0x0041E010)
#define jkGuiSaveLoad_PopulateInfoInit_ADDR (0x0041E430)
#define jkGuiSaveLoad_Initialize_ADDR (0x0041E440)
#define jkGuiSaveLoad_Shutdown_ADDR (0x0041E460)

static int (*jkGuiSaveLoad_Initialize)() = (void*)jkGuiSaveLoad_Initialize_ADDR;
static int (*jkGuiSaveLoad_Show)(int a1) = (void*)jkGuiSaveLoad_Show_ADDR;

#endif // _JKGUISAVELOAD_H
