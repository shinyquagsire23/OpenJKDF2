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
#define jkGuiRend_ElementSetClickShortcutScancode_ADDR (0x0050F870)
#define jkGuiRend_MenuSetReturnKeyShortcutElement_ADDR (0x0050F880)
#define jkGuiRend_MenuSetEscapeKeyShortcutElement_ADDR (0x0050F890)
#define jkGuiRend_DisplayAndReturnClicked_ADDR (0x0050F8A0)
#define jkGuiRend_sub_50FAD0_ADDR (0x0050FAD0)
#define jkGuiRend_gui_sets_handler_framebufs_ADDR (0x0050FC00)
#define jkGuiRend_Menuidk_ADDR (0x0050FD50)
#define jkGuiRend_sub_50FDB0_ADDR (0x0050FDB0)
#define jkGuiRend_Startup_ADDR (0x0050FDF0)
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
#define jkGuiRend_InvokeEvent_ADDR (0x00510650)
#define jkGuiRend_InvokeClicked_ADDR (0x005106A0)
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
#define jkGuiRend_ListBoxEventHandler_ADDR (0x00510D50)
#define jkGuiRend_ListBoxDraw_ADDR (0x00511000)
#define jkGuiRend_CheckBoxDraw_ADDR (0x00511260)
#define jkGuiRend_DrawClickableAndUpdatebool_ADDR (0x00511350)
#define jkGuiRend_WindowHandler_ADDR (0x00511380)
#define jkGuiRend_UpdateMouse_ADDR (0x005117B0)
#define jkGuiRend_FlipAndDraw_ADDR (0x00511800)
#define jkGuiRend_GetMousePos_ADDR (0x00511870)
#define jkGuiRend_ResetMouseLatestMs_ADDR (0x005118C0)
#define jkGuiRend_InvalidateGdi_ADDR (0x005118D0)
#define jkGuiRend_SliderEventHandler_ADDR (0x005118F0)
#define jkGuiRend_SliderDraw_ADDR (0x00511B60)
#define jkGuiRend_TextBoxEventHandler_ADDR (0x00511E10)
#define jkGuiRend_TextBoxDraw_ADDR (0x00512080)
#define jkGuiRend_TextDraw_ADDR (0x00512200)
#define jkGuiRend_PicButtonEventHandler_ADDR (0x00512250)
#define jkGuiRend_PicButtonDraw_ADDR (0x005122C0)
#define jkGuiRend_TextButtonEventHandler_ADDR (0x00512370)
#define jkGuiRend_TextButtonDraw_ADDR (0x005123C0)

extern int jkGuiRend_thing_five;
extern int jkGuiRend_thing_four;

void jkGuiRend_CopyVBuffer(jkGuiMenu *menu, rdRect *rect);
void jkGuiRend_SetPalette(uint8_t* pal);
void jkGuiRend_DrawRect(stdVBuffer *vbuf, rdRect *rect, __int16 color);
void jkGuiRend_UpdateDrawMenu(jkGuiMenu *menu);
void jkGuiRend_Paint(jkGuiMenu *menu);
void jkGuiRend_ElementSetClickShortcutScancode(jkGuiElement *element, int idk);
void jkGuiRend_MenuSetReturnKeyShortcutElement(jkGuiMenu *menu, jkGuiElement *element);
void jkGuiRend_MenuSetEscapeKeyShortcutElement(jkGuiMenu *menu, jkGuiElement *element);
int jkGuiRend_DisplayAndReturnClicked(jkGuiMenu *menu);
void jkGuiRend_sub_50FAD0(jkGuiMenu *menu);
void jkGuiRend_gui_sets_handler_framebufs(jkGuiMenu *menu);
int jkGuiRend_Menuidk();
void jkGuiRend_sub_50FDB0();
void jkGuiRend_Startup();
void jkGuiRend_Shutdown();
void jkGuiRend_Open(stdVBuffer *menuBuffer, stdVBuffer *otherBuf, int fillColor);
void jkGuiRend_Close();
jkGuiElement* jkGuiRend_MenuGetClickableById(jkGuiMenu *menu, int id);
void jkGuiRend_PlayWav(char *fpath);
void jkGuiRend_SetCursorVisible(int visible);
void jkGuiRend_UpdateCursor();
void jkGuiRend_UpdateSurface();
int jkGuiRend_DrawAndFlip(uint32_t a);
int jkGuiRend_Invalidate(uint32_t a);
int jkGuiRend_DarrayNewStr(Darray *array, int num, int initVal);
int jkGuiRend_DarrayReallocStr(Darray *array, wchar_t *wStr, intptr_t id);
int jkGuiRend_AddStringEntry(Darray *a1, const char *str, intptr_t id);
void jkGuiRend_SetClickableString(jkGuiElement *element, Darray *array);
wchar_t* jkGuiRend_GetString(Darray *array, int idx);
intptr_t jkGuiRend_GetId(Darray *array, int idx);
jkGuiStringEntry* jkGuiRend_GetStringEntry(Darray *array, int idx);
void jkGuiRend_DarrayFree(Darray *array);
void jkGuiRend_DarrayFreeEntry(Darray *array);
int jkGuiRend_sub_5103E0(jkGuiElement *element);
int jkGuiRend_ElementHasHoverSound(jkGuiElement *element);
void jkGuiRend_UpdateAndDrawClickable(jkGuiElement *clickable, jkGuiMenu *menu, int forceRedraw);
int jkGuiRend_InvokeEvent(jkGuiElement *element, jkGuiMenu *menu, int eventType, int eventParam);
int jkGuiRend_InvokeClicked(jkGuiElement *clickable, jkGuiMenu *menu, int mouseX, int mouseY, BOOL redraw);
int jkGuiRend_PlayClickSound(jkGuiElement *element, jkGuiMenu *menu, int a, int b, int c);
void jkGuiRend_RenderFocused(jkGuiMenu *menu, jkGuiElement *element);
void jkGuiRend_RenderIdk2(jkGuiMenu *menu);
void jkGuiRend_RenderIdk2_alt(jkGuiMenu *menu);
void jkGuiRend_RenderAll(jkGuiMenu *menu);
void jkGuiRend_ClickableMouseover(jkGuiMenu *menu, jkGuiElement *element);
void jkGuiRend_MouseMovedCallback(jkGuiMenu *menu, int x, int y);
void jkGuiRend_SetVisibleAndDraw(jkGuiElement *clickable, jkGuiMenu *menu, int bVisible);
void jkGuiRend_ClickableHover(jkGuiMenu *menu, jkGuiElement *element, int a3);
void jkGuiRend_sub_510C60(jkGuiElement *element);
int jkGuiRend_ClickSound(jkGuiElement *element, jkGuiMenu *menu, int mouseX, int mouseY, BOOL redraw);
void jkGuiRend_HoverOn(jkGuiElement *element, jkGuiMenu *menu, int a3);
int jkGuiRend_ListBoxEventHandler(jkGuiElement *element, jkGuiMenu *menu, int mouseY, int mouseX);
void jkGuiRend_ListBoxDraw(jkGuiElement *element_, jkGuiMenu *menu, stdVBuffer *vbuf, int a4);
void jkGuiRend_CheckBoxDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw);
int jkGuiRend_DrawClickableAndUpdatebool(jkGuiElement *element, jkGuiMenu *menu, int a, int b, int c);
int jkGuiRend_WindowHandler(HWND hWnd, UINT a2, WPARAM wParam, LPARAM lParam, LRESULT * unused);
void jkGuiRend_UpdateMouse();
void jkGuiRend_FlipAndDraw(jkGuiMenu *menu, rdRect *drawRect);
void jkGuiRend_GetMousePos(int *pX, int *pY);
void jkGuiRend_ResetMouseLatestMs();
void jkGuiRend_InvalidateGdi();
int jkGuiRend_SliderEventHandler(jkGuiElement *element, jkGuiMenu *menu, int a3, signed int a4);
void jkGuiRend_SliderDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw);
int jkGuiRend_TextBoxEventHandler(jkGuiElement *element, jkGuiMenu *menu, int a3, int a4);
void jkGuiRend_TextBoxDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw);
void jkGuiRend_TextDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *outBuf, int redraw);
int jkGuiRend_PicButtonEventHandler(jkGuiElement *element, jkGuiMenu *menu, int a, int b);
void jkGuiRend_PicButtonDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw);
int jkGuiRend_TextButtonEventHandler(jkGuiElement *element, jkGuiMenu *menu, int a3, int b);
void jkGuiRend_TextButtonDraw(jkGuiElement *element, jkGuiMenu *menu, stdVBuffer *vbuf, int redraw);

#endif // _JKGUIREND_H
