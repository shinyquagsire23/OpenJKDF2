#ifndef _JKHUDINV_H
#define _JKHUDINV_H

#include "types.h"
#include "globals.h"

#define jkHudInv_ItemDatLoad_ADDR (0x00409230)
#define jkHudInv_render_textmaybe_ADDR (0x004093A0)
#define jkHudInv_render_itemsmaybe_ADDR (0x004094A0)
#define jkHudInv_InputInit_ADDR (0x00409B90)
#define jkHudInv_items_init_ADDR (0x00409C10)
#define jkHudInv_LoadItemRes_ADDR (0x00409CB0)
#define jkHudInv_deinit_menu_graphics_maybe_ADDR (0x00409FD0)
#define jkHudInv_Initialize_ADDR (0x00409FF0)
#define jkHudInv_Shutdown_ADDR (0x0040A010)

int jkHudInv_Initialize();
int jkHudInv_items_init();
int jkHudInv_ItemDatLoad(char *fpath);

static int (*jkHudInv_render_itemsmaybe)() = (void*)jkHudInv_render_itemsmaybe_ADDR;
static int (*jkHudInv_render_textmaybe)() = (void*)jkHudInv_render_textmaybe_ADDR;
static void (*jkHudInv_deinit_menu_graphics_maybe)() = (void*)jkHudInv_deinit_menu_graphics_maybe_ADDR;
//static int (*jkHudInv_items_init)() = (void*)jkHudInv_items_init_ADDR;
//static int (*jkHudInv_ItemDatLoad)(char*) = (void*)jkHudInv_ItemDatLoad_ADDR;
static void (*jkHudInv_LoadItemRes)() = (void*)jkHudInv_LoadItemRes_ADDR;
static void (*jkHudInv_Shutdown)() = (void*)jkHudInv_Shutdown_ADDR;

#endif // _JKHUDINV_H
