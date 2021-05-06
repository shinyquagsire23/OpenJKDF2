#ifndef _SITH__H
#define _SITH__H

#define sith_Startup_ADDR (0x004C4630)
#define sith_Shutdown_ADDR (0x004C4700)
#define sith_Load_ADDR (0x004C4780)
#define sith_Free_ADDR (0x004C47B0)
#define sith_Mode1Init_ADDR (0x004C47D0)
#define sith_AutoSave_ADDR (0x004C4880)
#define sith_Mode1Init_2_ADDR (0x004C49D0)
#define sith_Mode1Init_3_ADDR (0x004C4A70)
#define sith_Open_ADDR (0x004C4B10)
#define sith_Close_ADDR (0x004C4B80)
#define sith_SetEndLevel_ADDR (0x004C4BF0)
#define sith_Tick_ADDR (0x004C4C00)
#define sith_UpdateCamera_ADDR (0x004C4D30)
#define sith_sub_4C4D80_ADDR (0x004C4D80)
#define sith_set_sithmode_5_ADDR (0x004C4DB0)
#define sith_set_some_text_jk1_ADDR (0x004C4DC0)

#define dword_8EE678 (*(int*)0x008EE678)

void sith_UpdateCamera();
static int (*sith_Startup)() = (void*)sith_Startup_ADDR;
static int (*sith_Tick)() = (void*)sith_Tick_ADDR;

static void (*sith_set_some_text_jk1)(char *text) = (void*)sith_set_some_text_jk1_ADDR;

#endif // _SITH__H
