#ifndef _DWGUIWIDGETBAR_H
#define _DWGUIWIDGETBAR_H

// dwGuiWidgetBar — the WIDGETBAR control: a vertically stacked, sliding
// toolbar of icon+label items (the workshop tool strip / HUD widget bar).
// TWO classes:
//
//   dwGuiWidgetBar (0x18, dwGuiWidgetBar_vtbl) — dwWidget subclass owning a dwList
//                  of items and a selection. Every input virtual forwards to
//                  the item whose LABEL BAND is under the point (or to the
//                  selected item); Draw clips each item to its band (from
//                  its top to the next item's top).
//   dwGuiBarItem   (0x40, dwGuiBarItem_vtbl) — one bar entry: a
//                  dwWcChildDecorator wrapping the item's inner control
//                  (pChild) and adding an icon image, a label and the
//                  slide animation (Update eases the item — and, through the
//                  decorator Move, its child — toward the scroll target at
//                  1000 px/s).
//
// Selection model: ScrollToItem stacks the items ABOVE the target from the
// bar top downward (each advancing by its padTop label band) and the items
// BELOW from the bar bottom upward, so the selected item's full content is
// the only one exposed; clicking a label band selects that item (clicking
// the selected item's own band selects the PREVIOUS one — collapse).
//
// Decompiled from DroidWorks.exe. The next
// functions (dwWidgetGroup_FreeChildImages / dwList_InsertAfter
// dwList_InsertAfter) are shared COMDATs already translated with their own
// units. Verifiably C++ (vtables, ctor/dtor pairs, MSVC EH frames) -> C++.
//
// No module statics — no dwGuiWidgetBar_Startup needed (soft-reset rule).

#include "Dw/dwTypes.h"
#include "Dw/dwRect.h"

#ifdef __cplusplus
struct dwGuiWidgetBar;
struct dwGuiBarItem;
extern "C" {
#else
// C++ classes; opaque in the C view.
typedef struct dwGuiWidgetBar dwGuiWidgetBar;
typedef struct dwGuiBarItem dwGuiBarItem;
#endif

// (no C-callable entry points — section kept for symmetry)

#ifdef __cplusplus
} // extern "C"

#include "Dw/dwWidget.h"
#include "Dw/dwWorkshopCtrl.h" // dwWcChildDecorator (dwGuiBarItem base)
#include "Dw/dwString.h"
#include "Dw/dwList.h"
#include "Dw/dwImage.h"
#include "Dw/dwFont.h"

// ---- dwGuiBarItem -----------------------------------------------------------
//
// Binary layout: dwWcChildDecorator @0x00 (dwWidget 0xe + pChild @0x10) +
// own fields from 0x14 — sizeof 0x40. dwGuiBarItem_vtbl:
// overrides ONLY the dtor, +0x14 Update and +0x44 Draw — all other slots are
// the decorator's child-forwarders.
//
// Geometry: the item rect starts as the child's rect, then becomes
// {0, 0, icon width, icon height} when an icon image was given; the CHILD is
// then inset to {left + padSide, top + padTop, right - padSide,
// bottom - padSide} (label band on top, side/bottom margins). The label is
// drawn inside the padTop band; the icon fills the whole item rect.

struct dwGuiBarItem : dwWcChildDecorator
{
    dwFont* pFont;      // 0x14: owned heap handle (dwFont_Load)
    uint8_t color;      // 0x18: label color index
    dwString label;     // 0x1c
    dwImage* pImage;    // 0x28: OWNED icon (passed in already loaded; deleted by the dtor)
    int32_t padTop;     // 0x2c (Ghidra: padX — misleading): label band height;
                        //      also the per-item stacking advance in the bar
    int32_t padSide;    // 0x30 (Ghidra: padY): child left/right/bottom inset
    float scrollPos;    // 0x34: slide-anim time accumulator (sec)
    int16_t animCurX;   // 0x38: slide start position (SetScrollTarget)
    int16_t animCurY;   // 0x3a
    int16_t animTgtX;   // 0x3c: slide target position
    int16_t animTgtY;   // 0x3e

    // dwGuiWidgetBar_ItemCtor — decorator(pChildWidget) [widget
    // rect = the child's]; loads the font when pFontName is non-empty; icon
    // resizes the item; insets the child (see the geometry note).
    dwGuiBarItem(dwWidget* pChildWidget, dwImage* pImage, char* pText,
                 char* pFontName, uint8_t color, int padTop, int padSide);

    // dwGuiWidgetBar_ItemDtor (scalar-deleting wrapper dwGuiWidgetBar_ItemDtorDelete) —
    // font handle + icon (virtual delete) + label; the decorator base then
    // FreeImages()es and deletes the child.
    virtual ~dwGuiBarItem();

    // vtbl +0x14 dwGuiWidgetBar_ItemUpdate — when not at the
    // target: step = (int16)(scrollPos * 1000) px (scrollPos accumulates
    // dt), clamp the remaining delta to it, Invalidate + Move (virtual — the
    // decorator moves the child too) + Invalidate. Always forwards
    // pChild->Update(dt) afterwards. (Constant 1000.0f.)
    virtual void Update(float dt);

    // vtbl +0x44 dwGuiWidgetBar_ItemDraw — EnsureImages (virtual:
    // the decorator forwards to the child), icon at (left, top), the label
    // at (left + 3, top + font y-inset + (padTop - line height) / 2 - 1),
    // then pChild->DrawChild.
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);

    // dwGuiWidgetBar_ItemSetScrollTarget — arm the slide: reset
    // scrollPos, animCur = current (left, top), animTgt = *pPos.
    void SetScrollTarget(dwPoint* pPos);
};

// ---- dwGuiWidgetBar -----------------------------------------------------------
//
// Binary layout: dwWidget base @0x00 (0xe) + fields from 0x10 — sizeof 0x18.
// dwGuiWidgetBar_vtbl. The +0x3c/+0x40 slots reuse the
// dwWidgetGroup broadcast COMDATs over the +0x10 list — implemented here as
// equivalent overrides.

struct dwGuiWidgetBar : dwWidget
{
    dwList items;                // 0x10 (Ghidra: pItems): dwGuiBarItem* payloads
    dwGuiBarItem* pSelectedItem; // 0x14

    // dwGuiWidgetBar_Ctor — dwWidget(pRect); empty list.
    dwGuiWidgetBar(dwRect* pRect);

    // dwGuiWidgetBar_Dtor (scalar-deleting wrapper dwGuiWidgetBar_DtorDelete) —
    // FreeImages broadcast, delete every item + node, free the list.
    virtual ~dwGuiWidgetBar();

    // vtbl +0x04 dwGuiWidgetBar_OnMouseMove — forward to the SELECTED item when it is enabled
    // and contains the point. Returns the item's result, else 0.
    // ⚠ pSelectedItem is dereferenced UNGUARDED (binary behavior) — the bar
    // always has a selection once populated (AddItem selects).
    virtual int OnMouseMove(int16_t x, int16_t y);
    // vtbl +0x08 dwGuiWidgetBar_OnMouseDown — label-band hit: select that item (previous item
    // when it IS the selected one) + WInfoCard.wav; otherwise forward to the
    // selected item when it contains the point.
    virtual int OnMouseDown(int16_t x, int16_t y);
    // vtbl +0x0c dwGuiWidgetBar_OnMouseUp — like OnMouseMove, forwarding OnMouseUp.
    virtual int OnMouseUp(int16_t x, int16_t y);
    // vtbl +0x10 dwGuiWidgetBar_OnKey — forward to the selected item when enabled.
    virtual int OnKey(int key, int repeat);
    // vtbl +0x14 dwGuiWidgetBar_Update — tick every ENABLED item.
    virtual void Update(float dt);
    // vtbl +0x18 dwGuiWidgetBar_OnHover — label-band hit item's OnHover, else the selected
    // item's.
    virtual int OnHover(int16_t x, int16_t y);
    // vtbl +0x1c dwGuiWidgetBar_OnMessage — broadcast to enabled items until one handles it.
    virtual int OnMessage(dwWidgetMsg* pMsg);
    // vtbl +0x3c (shared dwWidgetGroup_EnsureImages body) — broadcast.
    virtual void EnsureImages();
    // vtbl +0x40 (shared dwWidgetGroup_FreeChildImages body) — broadcast.
    virtual void FreeImages();
    // vtbl +0x44 dwGuiWidgetBar_Draw — per item: band = {left, item band top, right,
    // next item's top (bar bottom for the last)} clipped to pClipRect, then
    // the item's DrawChild with that band as the clip.
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);

    // -- non-virtual methods --------------------------------------------------

    // dwGuiWidgetBar_AddItem — load the icon (when a name is
    // given), build the item around pInner, push-back, re-stack every item
    // at the bar left (each Move()d to y advancing by its padTop), then
    // ScrollToItem(new item). Returns the new item.
    dwGuiBarItem* AddItem(dwWidget* pInner, char* pImageFile, char* pText,
                          char* pFontName, uint8_t color, int padTop, int padSide);

    // dwGuiWidgetBar_SelectIndex — ScrollToItem(items[index]).
    void SelectIndex(int index);

    // dwGuiWidgetBar_ScrollToItem — select pItem and arm every
    // item's slide target (see the selection-model note above). No-op when
    // already selected; selection unchanged when pItem is not in the list
    // (though the above-items still get retargeted — binary quirk).
    void ScrollToItem(dwGuiBarItem* pItem);
};

#endif // __cplusplus

#endif // _DWGUIWIDGETBAR_H
