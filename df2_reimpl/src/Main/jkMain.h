#ifndef _JKMAIN_H
#define _JKMAIN_H

#define jkMain_Startup_ADDR (0x00402CC0)
#define jkMain_Shutdown_ADDR (0x00402CE0)
#define jkMain_SetVideoMode_ADDR (0x00402D00)
#define jkMain_SetVideoModeGdi_ADDR (0x00402E40)
#define jkMain_InitPlayerThings_ADDR (0x00402E70)
#define jkMain_do_guistate6_ADDR (0x00402E80)
#define jkMain_EndLevel_ADDR (0x00402EB0)
#define jkMain_CdSwitch_ADDR (0x00402F90)
#define jkMain_cd_swap_reverify_ADDR (0x00403120)
#define jkMain_SetMap_ADDR (0x004033E0)
#define jkMain_MenuReturn_ADDR (0x00403410)
#define jkMain_MissionReload_ADDR (0x00403440)
#define jkMain_sub_403470_ADDR (0x00403470)
#define jkMain_sub_4034D0_ADDR (0x004034D0)
#define jkMain_loadFile_ADDR (0x00403570)
#define jkMain_loadFile2_ADDR (0x004035F0)
#define jkMain_SwitchTo5_2_ADDR (0x004036B0)
#define jkMain_SwitchTo5_ADDR (0x004036F0)
#define jkMain_SwitchTo12_ADDR (0x00403740)
#define jkMain_SwitchTo4_ADDR (0x00403770)
#define jkMain_SwitchTo13_ADDR (0x004037B0)
#define jkMain_gui_loop_ADDR (0x004037E0)
#define jkMain_TitleShow_ADDR (0x00403A20)
#define jkMain_TitleTick_ADDR (0x00403A40)
#define jkMain_TitleLeave_ADDR (0x00403A70)
#define jkMain_MainShow_ADDR (0x00403A80)
#define jkMain_MainTick_ADDR (0x00403A90)
#define jkMain_MainLeave_ADDR (0x00403AA0)
#define jkMain_GameplayShow_ADDR (0x00403AB0)
#define jkMain_GameplayTick_ADDR (0x00403D40)
#define jkMain_GameplayLeave_ADDR (0x00403E60)
#define jkMain_EscapeMenuShow_ADDR (0x00403F40)
#define jkMain_EscapeMenuTick_ADDR (0x00403F70)
#define jkMain_EscapeMenuLeave_ADDR (0x004040A0)
#define jkMain_EndLevelScreenShow_ADDR (0x004041A0)
#define jkMain_EndLevelScreenTick_ADDR (0x00404240)
#define jkMain_EndLevelScreenLeave_ADDR (0x00404250)
#define jkMain_CdSwitchShow_ADDR (0x00404260)
#define jkMain_VideoShow_ADDR (0x00404270)
#define jkMain_VideoTick_ADDR (0x00404350)
#define jkMain_VideoLeave_ADDR (0x00404430)
#define jkMain_CutsceneShow_ADDR (0x00404450)
#define jkMain_CutsceneTick_ADDR (0x00404460)
#define jkMain_CutsceneLeave_ADDR (0x00404470)
#define jkMain_CreditsShow_ADDR (0x00404480)
#define jkMain_CreditsTick_ADDR (0x004044B0)
#define jkMain_CreditsLeave_ADDR (0x004044E0)
#define jkMain_ChoiceShow_ADDR (0x004044F0)
#define jkMain_ChoiceTick_ADDR (0x00404550)
#define jkMain_ChoiceLeave_ADDR (0x00404560)
#define jkMain_UnkShow_ADDR (0x00404570)
#define jkMain_UnkTick_ADDR (0x00404580)
#define jkMain_UnkLeave_ADDR (0x004045F0)

#define gamemode_0_2_str ((char*)0x005528D0)
#define thing_nine (*(int*)0x0052552C)
#define thing_six (*(int*)0x00552B90)
#define thing_eight (*(int*)0x00552B94)
#define jkMain_lastTickMs (*(int*)0x552B9C)
#define dword_552B5C (*(int*)0x552B5C)
#define sith_bEndLevel (*(int*)0x0082F0A8)
#define game_updateMsecsTotal (*(int*)0x00552B58)
#define guiStateFuncs ((jkGuiStateFuncs*)0x00525478)

typedef struct jkGuiStateFuncs
{
  void (__cdecl *showFunc)(int, int);
  int (__cdecl *tickFunc)(int);
  void (__cdecl *leaveFunc)(int, int);
} jkGuiStateFuncs;

void jkMain_gui_loop();
void jkMain_EscapeMenuTick(int a2);
void jkMain_GameplayTick(int a2);
static int (*jkMain_EndLevel)(int a1) = (void*)jkMain_EndLevel_ADDR;
static void (*jkMain_do_guistate6)() = (void*)jkMain_do_guistate6_ADDR;

#endif // _JKMAIN_H
