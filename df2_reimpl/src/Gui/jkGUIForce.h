#ifndef _JKGUIFORCE_H
#define _JKGUIFORCE_H

#define jkGuiForce_ChoiceRemoveStar_ADDR (0x00415E90)
#define jkGuiForce_ChoiceRemoveStars_ADDR (0x00415F70)
#define jkGuiForce_ForceStarsDraw_ADDR (0x004160F0)
#define jkGuiForce_ExtraClick_ADDR (0x00416240)
#define jkGuiForce_ButtonClick_ADDR (0x00416250)
#define jkGuiForce_ResetClick_ADDR (0x004163B0)
#define jkGuiForce_Show_ADDR (0x00416480)
#define jkGuiForce_Initialize_ADDR (0x004167B0)
#define jkGuiForce_Shutdown_ADDR (0x00416830)
#define jkGuiForce_UpdateViewForRank_ADDR (0x00416860)
#define jkGuiForce_DarkLightHoverDraw_ADDR (0x004168C0)

typedef struct jkGuiElement jkGuiElement;
typedef struct jkGuiMenu jkGuiMenu;
typedef struct stdVBuffer stdVBuffer;

void jkGuiForce_ChoiceRemoveStar(jkGuiMenu *menu, int fpIdx, int amount);
void jkGuiForce_ChoiceRemoveStars(jkGuiMenu *menu);
void jkGuiForce_ForceStarsDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw);
int jkGuiForce_ExtraClick(jkGuiElement *element, jkGuiMenu *menu, int a, int b, int c);
int jkGuiForce_ButtonClick(jkGuiElement *element, jkGuiMenu *menu, int a, int b, int c);
int jkGuiForce_ResetClick(jkGuiElement *element, jkGuiMenu *menu, int a, int b, int c);
int jkGuiForce_Show(int bCanSpendStars, int isMulti, float a4, int a5, int *pbIsLight, int bEnableIdk);
void jkGuiForce_Initialize();
void jkGuiForce_Shutdown();
void jkGuiForce_UpdateViewForRank();
void jkGuiForce_DarkLightHoverDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw);

//#define jkGuiForce_bCanSpendStars (*(int*)0x556688)
//#define jkGuiForce_aBitmaps ((stdBitmap**)0x00856780)
//#define jkGuiForce_buttons ((jkGuiElement*)0x0052F168)
//#define jkGuiForce_alignment (*(int*)0x556670)
//#define jkGuiForce_flt_556674 (*(float*)0x556674)
//#define jkGuiForce_darkLightBalance (*(float*)0x55668C)
//#define jkGuiForce_numSpendStars (*(int*)0x556680)
//#define jkGuiForce_menu (*(jkGuiMenu*)0x52FB30)

#endif // _JKGUIFORCE_H
