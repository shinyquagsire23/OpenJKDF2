#ifndef _JKGUI_CONTROLSAVELOAD_H
#define _JKGUI_CONTROLSAVELOAD_H

#define jkGuiControlSaveLoad_sub_41E470_ADDR (0x0041E470)
#define jkGuiControlSaveLoad_ConfirmDelete_ADDR (0x0041E4F0)
#define jkGuiControlSaveLoad_FindFile_ADDR (0x0041E640)
#define jkGuiControlSaveLoad_Write_ADDR (0x0041E7E0)
#define jkGuiControlSaveLoad_Initialize_ADDR (0x0041EBA0)
#define jkGuiControlSaveLoad_Shutdown_ADDR (0x0041EBC0)

static int (*jkGuiControlSaveLoad_Initialize)() = (void*)jkGuiControlSaveLoad_Initialize_ADDR;
static void (*jkGuiControlSaveLoad_Shutdown)() = (void*)jkGuiControlSaveLoad_Shutdown_ADDR;
static int (*jkGuiControlSaveLoad_Write)(int a1) = (void*)jkGuiControlSaveLoad_Write_ADDR;

#endif // _JKGUI_CONTROLSAVELOAD_H
