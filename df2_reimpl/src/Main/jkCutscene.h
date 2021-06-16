#ifndef _JK_CUTSCENE_H
#define _JK_CUTSCENE_H

#include "types.h"

#define jkCutscene_Initialize_ADDR (0x00421250)
#define jkCutscene_Shutdown_ADDR (0x004212D0)
#define jkCutscene_sub_421310_ADDR (0x00421310)
#define jkCutscene_sub_421410_ADDR (0x00421410)
#define jkCutscene_smack_related_loops_ADDR (0x00421450)
#define jkCutscene_PauseShow_ADDR (0x00421560)
#define jkCutscene_Handler_ADDR (0x004215C0)

#define jkCutscene_rect1 (*(rdRect*)0x0055AA18)
#define jkCutscene_rect2 (*(rdRect*)0x0055AA38)
#define jkCutscene_strings (*(stdStrTable*)0x0055AA28)
#define jkCutscene_subtitlefont (*(stdFont**)0x0055AA4C)
#define jkCutscene_bInitted (*(int*)0x0055AA58)
#define jkCutscene_smack_loaded (*(int*)0x0055AA48)

void jkCutscene_Initialize(char *fpath);

static void (*jkCutscene_Shutdown)() = (void*)jkCutscene_Shutdown_ADDR;
//static void (*jkCutscene_Initialize)() = (void*)jkCutscene_Initialize_ADDR;
static void (*jkCutscene_PauseShow)() = (void*)jkCutscene_PauseShow_ADDR;
static void (*jkCutscene_sub_421410)() = (void*)jkCutscene_sub_421410_ADDR;

#endif // _JK_CUTSCENE_H
