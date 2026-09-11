#ifndef _DWGUIINVBAR_H
#define _DWGUIINVBAR_H

// dwGuiInvBar — the in-game INVENTORY item-bar popup widget (derives
// dwWidget). Built by dwGuiInGame_CreateControl (keyword "INVENTORY"): a modal
// full-screen grid overlay. When shown it lays out the player's usable
// inventory items (sithInventory_aDescriptors[0x32]; descriptor flag & 2 =
// selectable, GetInventory != 0 = owned) into a centered icon grid,
// hover-highlights the cell under the cursor, and on click uses that item via
// dwCog_UseItem, then hides.
//
// Decompiled from DroidWorks.exe unit range 0x41a9f0-0x41b240 (this class was
// originally mis-binned into the dw-core unit; it is its own dwGui compile-unit
// contribution — the four undetected vtbl fns OnMouseMove/OnMessage/
// ContainsPoint/Draw were recovered in Ghidra). vtable dwGuiInvBar_vtbl
// @0x51ee58 (18 slots): +00 DtorDelete / +04 OnMouseMove / +08 OnMouseDown /
// +1c OnMessage / +2c ContainsPoint (returns 1: modal, grabs every click) /
// +44 Draw; the rest are dwWidget defaults.
//
// Compiled as C++ (vtable + ctor/dtor pair + MSVC EH frames). The class is
// C++-only; C consumers see the opaque typedef plus dwGuiInvBar_Startup.

#include "Dw/dwTypes.h"
#include "Dw/dwRect.h"

#ifdef __cplusplus
struct dwGuiInvBar; // C++ class below
extern "C" {
#else
typedef struct dwGuiInvBar dwGuiInvBar; // C++ class; opaque in the C view
#endif

// Note: no binary counterpart — the unit owns no module statics; kept for the
// project-wide soft-reset convention.
void dwGuiInvBar_Startup(void);

#ifdef __cplusplus
} // extern "C"

#include "Dw/dwWidget.h"
#include "Dw/dwFont.h" // dwFont handle (plain-C struct)

// Binary /DW struct dwGuiInvBar (sizeof 0x34): dwWidget base @0x00, own fields
// @0x10+. Member ORDER is the contract (offsets differ on 64-bit).
struct dwGuiInvBar : dwWidget
{
    int16_t cellSpacing;   // 0x10: horizontal margin/gap (ctor arg)
    int16_t gridLeft;      // 0x12: laid-out grid bbox (Layout)
    int16_t gridTop;       // 0x14
    int16_t gridRight;     // 0x16
    int16_t gridBottom;    // 0x18
    uint8_t bShown;        // 0x1a: overlay currently visible
    uint8_t bgColorIdx;    // 0x1b: FillTriBlend background-triangle color (=0x46)
    int32_t selectedBin;   // 0x1c: inventory descriptor idx under cursor (0 = none)
    int16_t selRectL;      // 0x20: highlighted cell rect (for AddDirtyRect)
    int16_t selRectT;      // 0x22
    int16_t selRectR;      // 0x24
    int16_t selRectB;      // 0x26
    dwFont* pFont;         // 0x28: count/name text font (owned heap handle)
    uint8_t textColorIdx;  // 0x2c: count + name text color
    int16_t cellWidth;     // 0x2e: max icon width across usable items
    int16_t cellHeight;    // 0x30: max icon height
    int16_t columns;       // 0x32: computed grid column count

    // @41a9f0 (dwGuiInvBar_Ctor) — dwWidget(pRect); cellSpacing/textColorIdx
    // from the args; bgColorIdx = 0x46; loads pFontName when non-empty.
    dwGuiInvBar(dwRect* pRect, int16_t cellSpacing, const char* pFontName, uint8_t textColorIdx);

    // @41aad0 (dwGuiInvBar_Dtor; scalar-deleting wrapper @41aab0) — Hide if
    // shown, free the font, base dtor.
    virtual ~dwGuiInvBar();

    // vtbl +0x04 @41ace0 — hover: find the cell under (x,y), update selectedBin
    // and dirty the old/new highlight rects.
    virtual int OnMouseMove(int16_t x, int16_t y);
    // vtbl +0x08 @41aeb0 — click: Hide, then if a cell was under the cursor
    // select it (sithInventory) and dwCog_UseItem it.
    virtual int OnMouseDown(int16_t x, int16_t y);
    // vtbl +0x1c @41af40 — 0x1f41 toggle / 0x1f49 hide-if-shown /
    // 0x1f4a show-if-hidden / 0x1f4b relayout-if-shown.
    virtual int OnMessage(dwWidgetMsg* pMsg);
    // vtbl +0x2c @41b240 — always returns 1 (modal: grabs every click).
    virtual int ContainsPoint(dwPoint* pPt);
    // vtbl +0x44 @41afd0 — FillTriBlend background, then each usable item's
    // icon + owned-count digits + item name.
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);

    // @41ab40 — measure the usable inventory items, compute the centered grid,
    // and show the bar (or, if nothing is usable, play GHCA037.wav + Hide).
    void Layout();
    // @41acd0 — bShown = 0, Invalidate.
    void Hide();
};

#endif // __cplusplus

#endif // _DWGUIINVBAR_H
