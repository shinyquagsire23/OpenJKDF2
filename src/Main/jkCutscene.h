#ifndef _JK_CUTSCENE_H
#define _JK_CUTSCENE_H

#include "types.h"
#include "globals.h"

#define jkCutscene_Startup_ADDR (0x00421250)
#define jkCutscene_Shutdown_ADDR (0x004212D0)
#define jkCutscene_sub_421310_ADDR (0x00421310)
#define jkCutscene_sub_421410_ADDR (0x00421410)
#define jkCutscene_smack_related_loops_ADDR (0x00421450)
#define jkCutscene_PauseShow_ADDR (0x00421560)
#define jkCutscene_Handler_ADDR (0x004215C0)

void jkCutscene_Startup(char *fpath);
void jkCutscene_Shutdown();
int jkCutscene_sub_421310(char* a1);
int jkCutscene_sub_421410();
int jkCutscene_smack_related_loops();
int jkCutscene_PauseShow(int unk);
int jkCutscene_Handler(HWND a1, UINT a2, WPARAM a3, LPARAM a4, LRESULT *a5);

//#ifdef SDL2_RENDER
int jkCutscene_smacker_process();
int jkCutscene_smusher_process();
//#endif

//static void (*jkCutscene_Shutdown)() = (void*)jkCutscene_Shutdown_ADDR;
//static void (*jkCutscene_Startup)() = (void*)jkCutscene_Startup_ADDR;
//static void (*jkCutscene_PauseShow)() = (void*)jkCutscene_PauseShow_ADDR;
//static void (*jkCutscene_sub_421410)() = (void*)jkCutscene_sub_421410_ADDR;
//static int (*_jkCutscene_sub_421310)(char* a1) = (void*)jkCutscene_sub_421310_ADDR;

#endif // _JK_CUTSCENE_H
