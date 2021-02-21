#ifndef _JK_CUTSCENE_H
#define _JK_CUTSCENE_H

#define jkCutscene_Initialize_ADDR (0x00421250)
#define jkCutscene_Shutdown_ADDR (0x004212D0)
#define jkCutscene_sub_421310_ADDR (0x00421310)
#define jkCutscene_sub_421410_ADDR (0x00421410)
#define jkCutscene_smack_related_loops_ADDR (0x00421450)
#define jkCutscene_PauseShow_ADDR (0x00421560)
#define jkCutscene_Handler_ADDR (0x004215C0)

static void (*jkCutscene_Initialize)() = (void*)jkCutscene_Initialize_ADDR;
static void (*jkCutscene_PauseShow)() = (void*)jkCutscene_PauseShow_ADDR;

#endif // _JK_CUTSCENE_H
