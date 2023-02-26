#ifndef _JKGUIBUILDMULTI_H
#define _JKGUIBUILDMULTI_H

#include "types.h"

#define jkGuiBuildMulti_StartupEditCharacter_ADDR (0x00418ED0)
#define jkGuiBuildMulti_ShutdownEditCharacter_ADDR (0x00418EF0)
#define jkGuiBuildMulti_ModelLoader_ADDR (0x00418F00)
#define jkGuiBuildMulti_MatLoader_ADDR (0x00418F60)
#define jkGuiBuildMulti_KeyframeLoader_ADDR (0x00418FE0)
#define jkGuiBuildMulti_CloseRender_ADDR (0x00419030)
#define jkGuiBuildMulti_ThingInit_ADDR (0x004190F0)
#define jkGuiBuildMulti_ThingCleanup_ADDR (0x004191E0)
#define jkGuiBuildMulti_ShowEditCharacter_ADDR (0x00419230)
#define jkGuiBuildMulti_DisplayModel_ADDR (0x00419AE0)
#define jkGuiBuildMulti_ModelDrawer_ADDR (0x00419DB0)
#define jkGuiBuildMulti_SaberDrawer_ADDR (0x0041A0A0)
#define jkGuiBuildMulti_sub_41A120_ADDR (0x0041A120)
#define jkGuiBuildMulti_SaberButtonClicked_ADDR (0x0041A140)

#define jkGuiBuildMulti_Startup_ADDR (0x0041C5E0)
#define jkGuiBuildMulti_Shutdown_ADDR (0x0041C630)
#define jkGuiBuildMulti_Load_ADDR (0x0041C640)
#define jkGuiBuildMulti_Show_ADDR (0x0041C700)
#define jkGuiBuildMulti_Show2_ADDR (0x0041CAA0)
#define jkGuiBuildMulti_ShowNewCharacter_ADDR (0x0041CCB0)
#define jkGuiBuildMulti_sub_41D000_ADDR (0x0041D000)
#define jkGuiBuildMulti_ShowLoad_ADDR (0x0041D0E0)
#define jkGuiBuildMulti_sub_41D680_ADDR (0x0041D680)
#define jkGuiBuildMulti_sub_41D830_ADDR (0x0041D830)

void jkGuiBuildMulti_StartupEditCharacter();
void jkGuiBuildMulti_ShutdownEditCharacter();
rdModel3* jkGuiBuildMulti_ModelLoader(const char *pCharFpath, int unused);
rdMaterial* jkGuiBuildMulti_MatLoader(const char *pMatFname, int a, int b);
rdKeyframe* jkGuiBuildMulti_KeyframeLoader(const char *pKeyframeFname);
void jkGuiBuildMulti_CloseRender();
void jkGuiBuildMulti_ThingInit(char *pModelFpath);
void jkGuiBuildMulti_ThingCleanup();
int jkGuiBuildMulti_ShowEditCharacter(int bIdk);
int jkGuiBuildMulti_DisplayModel();
void jkGuiBuildMulti_ModelDrawer(jkGuiElement *pElement, jkGuiMenu *pMenu, stdVBuffer *pVbuf, int redraw);
void jkGuiBuildMulti_SaberDrawer(jkGuiElement *pElement, jkGuiMenu *pMenu, stdVBuffer *pVbuf, int redraw);
void jkGuiBuildMulti_sub_41A120(jkGuiMenu *pMenu);
int jkGuiBuildMulti_SaberButtonClicked(jkGuiElement *pElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw);
//static int (*jkGuiBuildMulti_StartupEditCharacter)() = (void*)jkGuiBuildMulti_StartupEditCharacter_ADDR;

int jkGuiBuildMulti_Startup();
void jkGuiBuildMulti_Shutdown();
void jkGuiBuildMulti_Load(char *pPathOut, int pathOutLen, wchar_t *pPlayerName, wchar_t *pCharName, int bCharPath);
int jkGuiBuildMulti_Show();
int jkGuiBuildMulti_Show2(Darray *pDarray, jkGuiElement *pElement, int minIdk, int maxIdk, int idx);
int jkGuiBuildMulti_ShowNewCharacter(int rank, int bGameFormatIsJK, int bHasNoValidChars);
int jkGuiBuildMulti_menuNewCharacter_rankArrowButtonClickHandler(jkGuiElement *pElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw);
int jkGuiBuildMulti_ShowLoad(jkPlayerMpcInfo *pPlayerMpcInfo, char *pStrEpisode, char *pJklFname, int minIdk, int rank, int bGameFormatIsJK);
void jkGuiBuildMulti_sub_41D680(jkGuiMenu *pMenu, int idx);
int jkGuiBuildMulti_sub_41D830(jkGuiElement *pElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw);


int jkGuiBuildMulti_FUN_00420930(jkGuiElement *pElement,jkGuiMenu *pMenu,int mouseX,int mouseY,int a5);
int jkGuiBuildMulti_FUN_004209b0(jkGuiElement *pElement,jkGuiMenu *pMenu,int mouseX,int mouseY,int a5);

//static int (*jkGuiBuildMulti_ShowLoad)(jkPlayerMpcInfo *a1, char *a2, char *a3, int a4, int a5) = (void*)jkGuiBuildMulti_ShowLoad_ADDR;

//static int (*jkGuiBuildMulti_sub_41D000)() = (void*)jkGuiBuildMulti_sub_41D000_ADDR;
//static int (*jkGuiBuildMulti_sub_41D830)() = (void*)jkGuiBuildMulti_sub_41D830_ADDR;
//static int (*jkGuiBuildMulti_sub_41D680)() = (void*)jkGuiBuildMulti_sub_41D680_ADDR;
//static int (*jkGuiBuildMulti_Show2)(Darray *pDarray, jkGuiElement *pElement, int a3, int a4, int a5) = (void*)jkGuiBuildMulti_Show2_ADDR;
//static int (*jkGuiBuildMulti_ShowEditCharacter)(int bIdk) = (void*)jkGuiBuildMulti_ShowEditCharacter_ADDR;
//static int (*jkGuiBuildMulti_ShowNewCharacter)(int rank, int bHasValidChars) = (void*)jkGuiBuildMulti_ShowNewCharacter_ADDR;

//static int (*jkGuiBuildMulti_SaberDrawer)() = (void*)jkGuiBuildMulti_SaberDrawer_ADDR;
//static int (*jkGuiBuildMulti_ModelDrawer)() = (void*)jkGuiBuildMulti_ModelDrawer_ADDR;
//static int (*jkGuiBuildMulti_SaberButtonClicked)() = (void*)jkGuiBuildMulti_SaberButtonClicked_ADDR;
//static int (*jkGuiBuildMulti_sub_41A120)() = (void*)jkGuiBuildMulti_sub_41A120_ADDR;
//static int (*jkGuiBuildMulti_DisplayModel)() = (void*)jkGuiBuildMulti_DisplayModel_ADDR;

#endif // _JKGUIBUILDMULTI_H
