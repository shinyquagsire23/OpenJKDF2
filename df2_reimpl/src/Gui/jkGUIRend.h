#ifndef _JKGUIREND_H
#define _JKGUIREND_H

#include <stdint.h>
#include "types.h"

#include "Primitives/rdRect.h"

#define jkGuiRend_CopyVBuffer_ADDR (0x0050F4B0)
#define jkGuiRend_SetPalette_ADDR (0x0050F4F0)
#define jkGuiRend_DrawRect_ADDR (0x0050F510)
#define jkGuiRend_UpdateDrawMenu_ADDR (0x0050F700)
#define jkGuiRend_Paint_ADDR (0x0050F780)
#define jkGuiRend_SetElementIdk_ADDR (0x0050F870)
#define jkGuiRend_MenuSetLastElement_ADDR (0x0050F880)
#define jkGuiRend_SetDisplayingStruct_ADDR (0x0050F890)
#define jkGuiRend_DisplayAndReturnClicked_ADDR (0x0050F8A0)
#define jkGuiRend_sub_50FAD0_ADDR (0x0050FAD0)
#define jkGuiRend_gui_sets_handler_framebufs_ADDR (0x0050FC00)
#define jkGuiRend_Menuidk_ADDR (0x0050FD50)
#define jkGuiRend_sub_50FDB0_ADDR (0x0050FDB0)
#define jkGuiRend_Initialize_ADDR (0x0050FDF0)
#define jkGuiRend_Shutdown_ADDR (0x0050FE00)
#define jkGuiRend_Open_ADDR (0x0050FE10)
#define jkGuiRend_Close_ADDR (0x0050FE40)
#define jkGuiRend_MenuGetClickableById_ADDR (0x0050FE60)
#define jkGuiRend_PlayWav_ADDR (0x0050FE90)
#define jkGuiRend_SetCursorVisible_ADDR (0x005100A0)
#define jkGuiRend_UpdateCursor_ADDR (0x00510110)
#define jkGuiRend_UpdateSurface_ADDR (0x00510180)
#define jkGuiRend_DrawAndFlip_ADDR (0x005101C0)
#define jkGuiRend_Invalidate_ADDR (0x005101D0)
#define jkGuiRend_DarrayNewStr_ADDR (0x005101F0)
#define jkGuiRend_DarrayReallocStr_ADDR (0x00510210)
#define jkGuiRend_AddStringEntry_ADDR (0x00510270)
#define jkGuiRend_SetClickableString_ADDR (0x005102C0)
#define jkGuiRend_GetString_ADDR (0x005102E0)
#define jkGuiRend_GetId_ADDR (0x00510300)
#define jkGuiRend_GetStringEntry_ADDR (0x00510320)
#define jkGuiRend_DarrayFree_ADDR (0x00510340)
#define jkGuiRend_DarrayFreeEntry_ADDR (0x00510390)
#define jkGuiRend_sub_5103E0_ADDR (0x005103E0)
#define jkGuiRend_ElementHasHoverSound_ADDR (0x00510410)
#define jkGuiRend_UpdateAndDrawClickable_ADDR (0x00510460)
#define jkGuiRend_InvokeButtonDown_ADDR (0x00510650)
#define jkGuiRend_InvokeButtonUp_ADDR (0x005106A0)
#define jkGuiRend_PlayClickSound_ADDR (0x005106F0)
#define jkGuiRend_RenderFocused_ADDR (0x00510710)
#define jkGuiRend_RenderIdk2_ADDR (0x00510770)
#define jkGuiRend_RenderAll_ADDR (0x00510840)
#define jkGuiRend_ClickableMouseover_ADDR (0x00510910)
#define jkGuiRend_MouseMovedCallback_ADDR (0x005109B0)
#define jkGuiRend_SetVisibleAndDraw_ADDR (0x00510B50)
#define jkGuiRend_ClickableHover_ADDR (0x00510B80)
#define jkGuiRend_sub_510C60_ADDR (0x00510C60)
#define jkGuiRend_ClickSound_ADDR (0x00510CF0)
#define jkGuiRend_HoverOn_ADDR (0x00510D20)
#define jkGuiRend_ListBoxButtonDown_ADDR (0x00510D50)
#define jkGuiRend_ListBoxDraw_ADDR (0x00511000)
#define jkGuiRend_CheckBoxDraw_ADDR (0x00511260)
#define jkGuiRend_DrawClickableAndUpdatebool_ADDR (0x00511350)
#define jkGuiRend_WindowHandler_ADDR (0x00511380)
#define jkGuiRend_UpdateMouse_ADDR (0x005117B0)
#define jkGuiRend_FlipAndDraw_ADDR (0x00511800)
#define jkGuiRend_GetMousePos_ADDR (0x00511870)
#define jkGuiRend_ResetMouseLatestMs_ADDR (0x005118C0)
#define jkGuiRend_InvalidateGdi_ADDR (0x005118D0)
#define jkGuiRend_SliderButtonDown_ADDR (0x005118F0)
#define jkGuiRend_SliderDraw_ADDR (0x00511B60)
#define jkGuiRend_TextBoxButtonDown_ADDR (0x00511E10)
#define jkGuiRend_TextBoxDraw_ADDR (0x00512080)
#define jkGuiRend_TextDraw_ADDR (0x00512200)
#define jkGuiRend_PicButtonButtonDown_ADDR (0x00512250)
#define jkGuiRend_PicButtonDraw_ADDR (0x005122C0)
#define jkGuiRend_TextButtonButtonDown_ADDR (0x00512370)
#define jkGuiRend_TextButtonDraw_ADDR (0x005123C0)

typedef struct stdFont stdFont;
typedef struct jkGuiStringEntry jkGuiStringEntry;
typedef struct jkGuiElement jkGuiElement;
typedef struct jkGuiMenu jkGuiMenu;
typedef struct jkGuiTexInfo jkGuiTexInfo;
typedef struct stdBitmap stdBitmap;
typedef struct stdVBuffer stdVBuffer;
typedef struct Darray Darray;

typedef void (*jkGuiDrawFunc_t)(jkGuiElement*, jkGuiMenu*, stdVBuffer*, int);
typedef int (*jkGuiButtonDownFunc_t)(jkGuiElement*, jkGuiMenu*, int, int);
typedef int (*jkGuiButtonUpFunc_t)(jkGuiElement*, jkGuiMenu*, int, int, int);

enum jkGuiElementType_t
{
    ELEMENT_TEXTBUTTON = 0,
    ELEMENT_PICBUTTON = 1,
    ELEMENT_TEXT = 2,
    ELEMENT_CHECKBOX = 3,
    ELEMENT_LISTBOX = 4,
    ELEMENT_TEXTBOX = 5,
    ELEMENT_SLIDER = 6,
    ELEMENT_CUSTOM = 7,
    ELEMENT_8 = 8,
    ELEMENT_END = 9,
};

typedef struct jkGuiElementHandlers
{
  jkGuiButtonDownFunc_t buttonDown;
  jkGuiDrawFunc_t draw;
  jkGuiButtonUpFunc_t buttonUp;
} jkGuiElementHandlers;

struct jkGuiTexInfo
{
  int textHeight;
  int numTextEntries;
  int maxTextEntries;
  int textScrollY;
  int anonymous_18;
  rdRect rect;
};

struct jkGuiElement
{
    int type;
    int hoverId;
    int field_8;
    union
    {
      const char* str;
      jkGuiStringEntry *unistr;
      wchar_t* wstr;
      int extraInt;
    };
    union
    {
        int selectedTextEntry;
        int boxChecked;
    };
    rdRect rect;
    int bIsVisible;
    int anonymous_9;
    union
    {
        const char* hintText;
        wchar_t* wHintText;
    };
    jkGuiDrawFunc_t drawFuncOverride;
    jkGuiButtonUpFunc_t func;
    void *anonymous_13;
    jkGuiTexInfo texInfo;
    int elementIdk;
};

struct jkGuiStringEntry
{
  wchar_t *str;
  int id;
};

struct jkGuiMenu
{
  jkGuiElement *clickables;
  int clickableIdxIdk;
  int anonymous_1;
  int fillColor;
  int anonymous_3;
  stdVBuffer *texture;
  uint8_t* palette;
  stdBitmap **ui_structs;
  stdFont** fonts;
  int anonymous_7;
  void (__cdecl *idkFunc)(jkGuiMenu *);
  char *soundHover;
  char *soundClick;
  jkGuiElement *focusedElement;
  jkGuiElement *lastMouseDownClickable;
  jkGuiElement *lastMouseOverClickable;
  int lastButtonUp;
  jkGuiElement* clickables_end;
  jkGuiElement* field_48;
};

//#define jkGuiRend_palette ((uint8_t*)0x855EC8)
//#define jkGuiRend_idk2 (*(int*)0x8561C8)
//#define jkGuiRend_idk (*(int*)0x8561CC)
//#define jkGuiRend_activeMenu (*(jkGuiMenu**)0x8561E0)
//#define jkGuiRend_menuBuffer (*(stdVBuffer**)0x8561E4)
//#define jkGuiRend_texture_dword_8561E8 (*(stdVBuffer**)0x8561E8)

//#define jkGuiRend_thing_five (*(int*)0x8561EC)
//#define jkGuiRend_thing_four (*(int*)0x8561F0)
//#define jkGuiRend_bIsSurfaceValid (*(int*)0x8561F4)
//#define jkGuiRend_bInitted (*(int*)0x008561F8)
//#define jkGuiRend_bOpen (*(int*)0x008561FC)
//#define jkGuiRend_HandlerIsSet (*(int*)0x00856200)
//#define jkGuiRend_fillColor (*(int*)0x00856204)
//#define jkGuiRend_paletteChecksum (*(int*)0x00856208)
//#define jkGuiRend_dword_85620C (*(int*)0x0085620C)
//#define jkGuiRend_lastKeyScancode (*(int*)0x00856210)
//#define jkGuiRend_mouseX (*(int*)0x00856214)
//#define jkGuiRend_mouseY (*(int*)0x00856218)
//#define jkGuiRend_bShiftDown (*(int*)0x0085621C)
//#define jkGuiRend_mouseXLatest (*(int*)0x00856220)
//#define jkGuiRend_mouseYLatest (*(int*)0x00856224)
//#define jkGuiRend_mouseLatestMs (*(int*)0x00856228)
//#define jkGuiRend_hCursor (*(HCURSOR*)0x0085622C)

//#define jkGuiRend_CursorVisible (*(int*)0x54F6BC)
//#define jkGuiRend_elementHandlers ((jkGuiElementHandlers*)0x54F6D0)

extern int jkGuiRend_thing_five;
extern int jkGuiRend_thing_four;

void jkGuiRend_CopyVBuffer(jkGuiMenu *menu, rdRect *rect);
void jkGuiRend_SetPalette(uint8_t* pal);
void jkGuiRend_DrawRect(stdVBuffer *vbuf, rdRect *rect, __int16 color);
void jkGuiRend_UpdateDrawMenu(jkGuiMenu *menu);
void jkGuiRend_Paint(jkGuiMenu *menu);
void jkGuiRend_SetElementIdk(jkGuiElement *element, int idk);
void jkGuiRend_MenuSetLastElement(jkGuiMenu *menu, jkGuiElement *element);
void jkGuiRend_SetDisplayingStruct(jkGuiMenu *menu, jkGuiElement *element);
int jkGuiRend_DisplayAndReturnClicked(jkGuiMenu *menu);
void jkGuiRend_sub_50FAD0(jkGuiMenu *menu);
void jkGuiRend_gui_sets_handler_framebufs(jkGuiMenu *menu);
int jkGuiRend_Menuidk();
void jkGuiRend_sub_50FDB0();
void jkGuiRend_Initialize();
void jkGuiRend_Shutdown();
void jkGuiRend_Open(stdVBuffer *menuBuffer, stdVBuffer *otherBuf, int fillColor);
void jkGuiRend_Close();
jkGuiElement* jkGuiRend_MenuGetClickableById(jkGuiMenu *menu, int id);
void jkGuiRend_PlayWav(char *fpath);
void jkGuiRend_SetCursorVisible(int visible);
void jkGuiRend_UpdateCursor();
void jkGuiRend_UpdateSurface();
void jkGuiRend_DrawAndFlip();
void jkGuiRend_Invalidate();
int jkGuiRend_DarrayNewStr(Darray *array, int num, int initVal);
int jkGuiRend_DarrayReallocStr(Darray *array, wchar_t *wStr, int id);
int jkGuiRend_AddStringEntry(Darray *a1, const char *str, int id);
void jkGuiRend_SetClickableString(jkGuiElement *element, Darray *array);
wchar_t* jkGuiRend_GetString(Darray *array, int idx);
int jkGuiRend_GetId(Darray *array, int idx);
jkGuiStringEntry* jkGuiRend_GetStringEntry(Darray *array, int idx);
void jkGuiRend_DarrayFree(Darray *array);
void jkGuiRend_DarrayFreeEntry(Darray *array);
int jkGuiRend_sub_5103E0(jkGuiElement *element);
int jkGuiRend_ElementHasHoverSound(jkGuiElement *element);
void jkGuiRend_UpdateAndDrawClickable(jkGuiElement *clickable, jkGuiMenu *menu, int forceRedraw);
int jkGuiRend_InvokeButtonDown(jkGuiElement *element, jkGuiMenu *menu, int a3, int a4);
int jkGuiRend_InvokeButtonUp(jkGuiElement *clickable, jkGuiMenu *menu, int mouseX, int mouseY, int a5);
int jkGuiRend_PlayClickSound(jkGuiElement *element, jkGuiMenu *menu, int a, int b, int c);
void jkGuiRend_RenderFocused(jkGuiMenu *menu, jkGuiElement *element);
void jkGuiRend_RenderIdk2(jkGuiMenu *menu);
void jkGuiRend_RenderAll(jkGuiMenu *menu);
void jkGuiRend_ClickableMouseover(jkGuiMenu *menu, jkGuiElement *element);
void jkGuiRend_MouseMovedCallback(jkGuiMenu *menu, int x, int y);
void jkGuiRend_SetVisibleAndDraw(jkGuiElement *clickable, jkGuiMenu *menu, int bVisible);
void jkGuiRend_ClickableHover(jkGuiMenu *menu, jkGuiElement *element, int a3);
void jkGuiRend_sub_510C60(jkGuiElement *element);
int jkGuiRend_ClickSound(jkGuiElement *element, jkGuiMenu *menu, int mouseX, int mouseY, int a5);
void jkGuiRend_HoverOn(jkGuiElement *element, jkGuiMenu *menu, int a3);
int jkGuiRend_ListBoxButtonDown(jkGuiElement *element, jkGuiMenu *menu, int mouseY, int mouseX);
void jkGuiRend_ListBoxDraw(jkGuiElement *element_, jkGuiMenu *menu, stdVBuffer *vbuf, int a4);
void jkGuiRend_CheckBoxDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw);
int jkGuiRend_DrawClickableAndUpdatebool(jkGuiElement *element, jkGuiMenu *menu, int a, int b, int c);
int jkGuiRend_WindowHandler(HWND hWnd, unsigned int a2, int wParam, unsigned int lParam);
void jkGuiRend_UpdateMouse();
void jkGuiRend_FlipAndDraw(jkGuiMenu *menu, rdRect *drawRect);
void jkGuiRend_GetMousePos(int *pX, int *pY);
void jkGuiRend_ResetMouseLatestMs();
void jkGuiRend_InvalidateGdi();
int jkGuiRend_SliderButtonDown(jkGuiElement *element, jkGuiMenu *menu, int a3, signed int a4);
void jkGuiRend_SliderDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw);
int jkGuiRend_TextBoxButtonDown(jkGuiElement *element, jkGuiMenu *menu, int a3, int a4);
void jkGuiRend_TextBoxDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw);
void jkGuiRend_TextDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *outBuf, int redraw);
int jkGuiRend_PicButtonButtonDown(jkGuiElement *element, jkGuiMenu *menu, int a, int b);
void jkGuiRend_PicButtonDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw);
int jkGuiRend_TextButtonButtonDown(jkGuiElement *element, jkGuiMenu *menu, int a3, int b);
void jkGuiRend_TextButtonDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw);

#endif // _JKGUIREND_H
