#ifndef _JKHUDINV_H
#define _JKHUDINV_H

#include "types.h"
#include "globals.h"

#define jkHudInv_ItemDatLoad_ADDR (0x00409230)
#define jkHudInv_ClearRects_ADDR (0x004093A0)
#define jkHudInv_Draw_ADDR (0x004094A0)
#define jkHudInv_InputInit_ADDR (0x00409B90)
#define jkHudInv_InitItems_ADDR (0x00409C10)
#define jkHudInv_LoadItemRes_ADDR (0x00409CB0)
#define jkHudInv_Close_ADDR (0x00409FD0)
#define jkHudInv_Startup_ADDR (0x00409FF0)
#define jkHudInv_Shutdown_ADDR (0x0040A010)

int jkHudInv_ItemDatLoad(char *fpath);
void jkHudInv_ClearRects();
MATH_FUNC void jkHudInv_Draw();
MATH_FUNC void jkHudInv_DrawGPU();
void jkHudInv_InputInit();
int jkHudInv_InitItems();
MATH_FUNC void jkHudInv_LoadItemRes();
void jkHudInv_Close();
int jkHudInv_Startup();
int jkHudInv_Shutdown();

void jkHudInv_FixAmmoMaximums(); // MOTS added

//static void (*jkHudInv_InputInit)() = (void*)jkHudInv_InputInit_ADDR;
//static int (*jkHudInv_Draw)() = (void*)jkHudInv_Draw_ADDR;
//static int (*jkHudInv_ClearRects)() = (void*)jkHudInv_ClearRects_ADDR;
//static void (*jkHudInv_Close)() = (void*)jkHudInv_Close_ADDR;
//static int (*jkHudInv_InitItems)() = (void*)jkHudInv_InitItems_ADDR;
//static int (*jkHudInv_ItemDatLoad)(char*) = (void*)jkHudInv_ItemDatLoad_ADDR;
//static void (*jkHudInv_LoadItemRes)() = (void*)jkHudInv_LoadItemRes_ADDR;
//static void (*jkHudInv_Shutdown)() = (void*)jkHudInv_Shutdown_ADDR;

#endif // _JKHUDINV_H
