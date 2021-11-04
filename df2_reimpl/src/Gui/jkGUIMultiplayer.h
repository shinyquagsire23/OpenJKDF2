#ifndef _JKGUIMULTIPLAYER_H
#define _JKGUIMULTIPLAYER_H

#include "types.h"
#include "globals.h"

#define jkGuiMultiplayer_Initialize_ADDR (0x00413180)
#define jkGuiMultiplayer_Shutdown_ADDR (0x004131E0)
#define jkGuiMultiplayer_Show_ADDR (0x004131F0)

//#define jkGuiMultiplayer_bInitted (*(int*)0x005564E0)
/*#define jkGuiMultiplayer_menu (*(jkGuiMenu*)0x0052C360)
#define jkGuiMultiplayer_menu2 (*(jkGuiMenu*)0x0052C670)
#define jkGuiMultiplayer_menu3 (*(jkGuiMenu*)0x0052CB70)
#define jkGuiMultiplayer_menu4 (*(jkGuiMenu*)0x0052CD50)*/

//#define jkGuiMultiplayer_aElements ((jkGuiElement*)0x0052C108)
//#define jkGuiMultiplayer_aElements2 ((jkGuiElement*)0x0052C3B0)
//#define jkGuiMultiplayer_aElements3 ((jkGuiElement*)0x0052C6C0)
//#define jkGuiMultiplayer_aElements4 ((jkGuiElement*)0x0052CBC0)

void jkGuiMultiplayer_Initialize();
void jkGuiMultiplayer_Shutdown();
int jkGuiMultiplayer_Show();

//static int (*jkGuiMultiplayer_Initialize)() = (void*)jkGuiMultiplayer_Initialize_ADDR;
//static void (*jkGuiMultiplayer_Shutdown)() = (void*)jkGuiMultiplayer_Shutdown_ADDR;
//static int (__cdecl *jkGuiMultiplayer_Show)() = (void*)jkGuiMultiplayer_Show_ADDR;

#endif // _JKGUIMULTIPLAYER_H
