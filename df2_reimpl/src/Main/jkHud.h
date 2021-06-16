#ifndef _JKHUD_H
#define _JKHUD_H

#define jkHud_Startup_ADDR (0x00407500)
#define jkHud_Shutdown_ADDR (0x00407540)
#define jkHud_InitRes_ADDR (0x00407560)
#define jkHud_Deinit_ADDR (0x00407980)
#define jkHud_render_idktexs_ADDR (0x00407A20)
#define jkHud_gui_render_ADDR (0x00407C10)
#define jkHud_sub_408CC0_ADDR (0x00408CC0)
#define jkHud_Chat_ADDR (0x00408D80)
#define jkHud_send_message_ADDR (0x00408E50)
#define jkHud_chat2_ADDR (0x00409000)
#define jkHud_idk_time_ADDR (0x004090A0)
#define jkHud_SetTargetColors_ADDR (0x004090D0)
#define jkHud_SetTarget_ADDR (0x00409150)
#define jkHud_EndTarget_ADDR (0x00409170)
#define jkHud_sortcallback1_ADDR (0x00409180)
#define jkHud_sortcallback2_ADDR (0x004091A0)
#define jkHud_Tally_ADDR (0x004091C0)

#define jkHud_dword_553E94 (*(int*)0x00553E94)

static int (*jkHud_Startup)() = (void*)jkHud_Startup_ADDR;
static void (*jkHud_Shutdown)() = (void*)jkHud_Shutdown_ADDR;
static void (*jkHud_Chat)() = (void*)jkHud_Chat_ADDR;
static void (*jkHud_Tally)() = (void*)jkHud_Tally_ADDR;

static int (*jkHud_render_idktexs)() = (void*)jkHud_render_idktexs_ADDR;
static void (*jkHud_idk_time)() = (void*)jkHud_idk_time_ADDR;
static void (*jkHud_send_message)(char a1) = (void*)jkHud_send_message_ADDR;
static void (*jkHud_gui_render)() = (void*)jkHud_gui_render_ADDR;
static void (*jkHud_Deinit)() = (void*)jkHud_Deinit_ADDR;
static void (*jkHud_InitRes)() = (void*)jkHud_InitRes_ADDR;

#endif // _JKHUD_H
