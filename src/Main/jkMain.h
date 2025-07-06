#ifndef _JKMAIN_H
#define _JKMAIN_H

#include "types.h"
#include "globals.h"

#define jkMain_Startup_ADDR (0x00402CC0)
#define jkMain_Shutdown_ADDR (0x00402CE0)
#define jkMain_SetVideoMode_ADDR (0x00402D00)
#define jkMain_SetVideoModeGdi_ADDR (0x00402E40)
#define jkMain_InitPlayerThings_ADDR (0x00402E70)
#define jkMain_do_guistate6_ADDR (0x00402E80)
#define jkMain_EndLevel_ADDR (0x00402EB0)
#define jkMain_StartNextLevelInEpisode_ADDR (0x00402F90)
#define jkMain_cd_swap_reverify_ADDR (0x00403120)
#define jkMain_SetMap_ADDR (0x004033E0)
#define jkMain_MenuReturn_ADDR (0x00403410)
#define jkMain_MissionReload_ADDR (0x00403440)
#define jkMain_sub_403470_ADDR (0x00403470)
#define jkMain_sub_4034D0_ADDR (0x004034D0)
#define jkMain_LoadFile_ADDR (0x00403570)
#define jkMain_loadFile2_ADDR (0x004035F0)
#define jkMain_SwitchTo5_2_ADDR (0x004036B0)
#define jkMain_SwitchTo5_ADDR (0x004036F0)
#define jkMain_SwitchTo12_ADDR (0x00403740)
#define jkMain_SwitchTo4_ADDR (0x00403770)
#define jkMain_SwitchTo13_ADDR (0x004037B0)
#define jkMain_GuiAdvance_ADDR (0x004037E0)
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

enum JK_GAMEMODE
{
    JK_GAMEMODE_NONE = 0,
    JK_GAMEMODE_VIDEO = 1,
    JK_GAMEMODE_TITLE = 2,
    JK_GAMEMODE_MAIN = 3,
    JK_GAMEMODE_VIDEO2 = 4,
    JK_GAMEMODE_GAMEPLAY = 5,
    JK_GAMEMODE_ESCAPE = 6,
    JK_GAMEMODE_CD_SWITCH = 7,
    JK_GAMEMODE_VIDEO3 = 8,
    JK_GAMEMODE_ENDLEVEL = 9,
    JK_GAMEMODE_VIDEO4 = 10,
    JK_GAMEMODE_CHOICE = 11,
    JK_GAMEMODE_CUTSCENE = 12,
    JK_GAMEMODE_CREDITS = 13,
    JK_GAMEMODE_UNK = 14,
    JK_GAMEMODE_MOTS_CUTSCENE = 15,
};

typedef struct jkGuiStateFuncs
{
  void (*showFunc)(int, int);
  void (*tickFunc)(int);
  void (*leaveFunc)(int, int);
} jkGuiStateFuncs;

extern jkEpisodeEntry* jkMain_pEpisodeEnt;
extern jkEpisodeEntry* jkMain_pEpisodeEnt2;

void jkMain_Startup();
void jkMain_Shutdown();
int jkMain_SetVideoMode();
void jkMain_SetVideoModeGdi();
void jkMain_InitPlayerThings();
int jkMain_SwitchTo5_2();
int jkMain_SwitchTo5(char *pJklFname);
void jkMain_GuiAdvance();
void jkMain_EscapeMenuShow(int a1, int a2);
void jkMain_EscapeMenuTick(int a2);
void jkMain_EscapeMenuLeave(int a2, int a3);
void jkMain_EndLevelScreenShow(int a1, int a2);
void jkMain_EndLevelScreenTick(int a1);
void jkMain_EndLevelScreenLeave(int a1, int a2);
void jkMain_GameplayShow(int a1, int a2);
void jkMain_GameplayTick(int a2);
void jkMain_GameplayLeave(int a2, int a3);
void jkMain_TitleShow(int a1, int a2);
void jkMain_TitleTick(int a1);
void jkMain_TitleLeave(int a1, int a2);
void jkMain_MainShow(int a1, int a2);
void jkMain_MainTick(int a1);
void jkMain_MainLeave(int a1, int a2);
void jkMain_ChoiceShow(int a1, int a2);
void jkMain_ChoiceTick(int a1);
void jkMain_ChoiceLeave(int a1, int a2);
void jkMain_UnkShow(int a1, int a2);
void jkMain_UnkTick(int a1);
void jkMain_UnkLeave(int a1, int a2);
int jkMain_LoadFile(char *a1);
int jkMain_loadFile2(char *pGobPath, char *pEpisodeName);
int jkMain_LoadLevelSingleplayer(char *pGobPath, char *pEpisodeName);

int jkMain_sub_403470(char *a1);
int jkMain_StartNextLevelInEpisode(int a1, int bIsAPath);
int jkMain_cd_swap_reverify(jkEpisodeEntry *ent);
int jkMain_SetMap(int levelNum);
void jkMain_do_guistate6();
int jkMain_sub_4034D0(char *a1, char *a2, char *a3, wchar_t *a4);
int jkMain_MissionReload();
int jkMain_MenuReturn();

int jkMain_EndLevel(int bIsAPath);
void jkMain_CdSwitchShow(int a1, int a2);
void jkMain_VideoShow(int a1, int a2);
void jkMain_VideoTick(int a2);
void jkMain_VideoLeave(int a1, int a2);

void jkMain_CreditsShow(int a1, int a2);
void jkMain_CreditsTick(int a1);
void jkMain_CreditsLeave(int a1, int a2);

void jkMain_CutsceneShow(int a1, int a2);
void jkMain_CutsceneTick(int a1);
void jkMain_CutsceneLeave(int a1, int a2);

int jkMain_SwitchTo13();
int jkMain_SwitchTo12();
int jkMain_SwitchTo4(const char *pFpath);

void jkMain_StartupCutscene(char *pCutsceneStr); // MOTS added

//static int (*jkMain_loadFile)(char *a1) = (void*)jk_loadFile_ADDR;;

//static int (*jkMain_EndLevel)(int a1) = (void*)jkMain_EndLevel_ADDR;
//static void (*jkMain_do_guistate6)() = (void*)jkMain_do_guistate6_ADDR;
//static void (*jkMain_SwitchTo12)() = (void*)jkMain_SwitchTo12_ADDR;
//static void (*jkMain_SwitchTo13)() = (void*)jkMain_SwitchTo13_ADDR;
//static void (*jkMain_MenuReturn)() = (void*)jkMain_MenuReturn_ADDR;
//static void (*jkMain_SwitchTo4)(void*) = (void*)jkMain_SwitchTo4_ADDR;
//static int (*jkMain_sub_403470)(char *a1) = (void*)jkMain_sub_403470_ADDR;
//static int (*jkMain_loadFile2)(char*, char*) = (void*)jkMain_loadFile2_ADDR;

#if defined(SDL2_RENDER) || defined(TARGET_TWL)
//int jkMain_SetVideoMode();
void jkMain_FixRes();
#else
//static int (*jkMain_SetVideoMode)() = (void*)jkMain_SetVideoMode_ADDR;
#endif

#endif // _JKMAIN_H
