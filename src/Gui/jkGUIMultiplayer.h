#ifndef _JKGUIMULTIPLAYER_H
#define _JKGUIMULTIPLAYER_H

#include "types.h"
#include "globals.h"

#define jkGuiMultiplayer_Startup_ADDR (0x00413180)
#define jkGuiMultiplayer_Shutdown_ADDR (0x004131E0)
#define jkGuiMultiplayer_Show_ADDR (0x004131F0)
#define jkGuiMultiplayer_Show2_ADDR (0x00413960)
#define jkGuiMultiplayer_ShowSynchronizing_ADDR (0x00413BA0)
#define jkGuiMultiplayer_ShowWaitHostSettings_ADDR (0x00413C10)
#define jkGuiMultiplayer_sub_413C80_ADDR (0x00413C80)
#define jkGuiMultiplayer_CogMsgHandleJoining_ADDR (0x00413CF0)
#define jkGuiMultiplayer_sub_413E00_ADDR (0x00413E00)
#define jkGuiMultiplayer_sub_413E50_ADDR (0x00413E50)
#define jkGuiMultiplayer_sub_4140B0_ADDR (0x004140B0)
#define jkGuiMultiplayer_idk_ADDR (0x00414230)
#define jkGuiMultiplayer_sub_4142C0_ADDR (0x004142C0)



//#define jkGuiMultiplayer_bInitted (*(int*)0x005564E0)
/*#define jkGuiMultiplayer_menu (*(jkGuiMenu*)0x0052C360)
#define jkGuiMultiplayer_menu2 (*(jkGuiMenu*)0x0052C670)
#define jkGuiMultiplayer_menu3 (*(jkGuiMenu*)0x0052CB70)
#define jkGuiMultiplayer_menu4 (*(jkGuiMenu*)0x0052CD50)*/

//#define jkGuiMultiplayer_aElements ((jkGuiElement*)0x0052C108)
//#define jkGuiMultiplayer_aElements2 ((jkGuiElement*)0x0052C3B0)
//#define jkGuiMultiplayer_aElements3 ((jkGuiElement*)0x0052C6C0)
//#define jkGuiMultiplayer_aElements4 ((jkGuiElement*)0x0052CBC0)

void jkGuiMultiplayer_Startup();
void jkGuiMultiplayer_Shutdown();
int jkGuiMultiplayer_Show();

int jkGuiMultiplayer_ShowSynchronizing();

void jkGuiMultiplayer_idk(jkGuiMenu *pMenu);
int jkGuiMultiplayer_CogMsgHandleJoining(sithCogMsg *msg);
void jkGuiMultiplayer_sub_4140B0(jkGuiMenu *pMenu);
void jkGuiMultiplayer_sub_413E50(int idx);
int jkGuiMultiplayer_sub_413E00(jkGuiElement *pElement, jkGuiMenu *pMenu, int32_t mouseX, int32_t mouseY, int bRedraw);

int jkGuiMultiplayer_Show2();
void jkGuiMultiplayer_sub_4142C0(jkGuiMenu *pMenu);
int jkGuiMultiplayer_sub_413C80(Darray *pDarray, jkGuiElement *pElement, int a3);
int jkGuiMultiplayer_ShowWaitHostSettings();

//static void (*jkGuiMultiplayer_sub_413E00)() = (void*)jkGuiMultiplayer_sub_413E00_ADDR;
//static int (*jkGuiMultiplayer_CogMsgHandleJoining)(int a1) = (void*)jkGuiMultiplayer_CogMsgHandleJoining_ADDR;
//static int (*jkGuiMultiplayer_ShowSynchronizing)() = (void*)jkGuiMultiplayer_ShowSynchronizing_ADDR;
//static int (*jkGuiMultiplayer_Show2)() = (void*)jkGuiMultiplayer_Show2_ADDR;
//static void (*jkGuiMultiplayer_idk)(jkGuiElement *a1) = (void*)jkGuiMultiplayer_idk_ADDR;


//static int (*jkGuiMultiplayer_Startup)() = (void*)jkGuiMultiplayer_Startup_ADDR;
//static void (*jkGuiMultiplayer_Shutdown)() = (void*)jkGuiMultiplayer_Shutdown_ADDR;
//static int (__cdecl *jkGuiMultiplayer_Show)() = (void*)jkGuiMultiplayer_Show_ADDR;

#endif // _JKGUIMULTIPLAYER_H
