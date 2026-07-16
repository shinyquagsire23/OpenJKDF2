#ifndef _DWGUIWIDGETS_H
#define _DWGUIWIDGETS_H

// dwGuiWidgets — the scroll-control cluster + the .drd droid-file
// serialization free functions:
//
//   dwGuiScrollBar    (0x5c, vtbl 0x51f7f0) — draggable scrollbar/slider
//                     (SCROLLBAR/NAMESCROLLBAR keywords): drives a
//                     dwGuiScrollBox or a volume/size value through its
//                     msgSetValue notification; auto-repeats a line-up/down
//                     scroll every 0.1s while a paired dwGuiScrollButton is
//                     held.
//   dwGuiScrollBox    (0x38, vtbl 0x51f840) — scrollable text list
//                     (SCROLLBOX keyword: DROIDBOX saved-droid list /
//                     FINDBOX search results / RANKING). Items are
//                     {filename, display name} dwString pairs kept sorted
//                     case-insensitively by display name.
//   dwGuiScrollButton (0x50, vtbl 0x51f888) — SCROLLUPBUTTON/
//                     SCROLLDOWNBUTTON: a dwWorkshopCtrl push button that
//                     sends its cmdId on press (arming the scrollbar's
//                     repeat) and again on release (stopping it).
//   dwGuiTextRollover (0xcc, vtbls 0x51f928 primary / 0x51f8d8 hyptext) —
//                     CTextRollover: clickable hyperlinked text (the
//                     dwGuiTextBlock <link> child + the reference SEEALSO
//                     link). REAL MSVC multiple inheritance:
//                     dwGuiTextButton @0x00 + dwGuiHypText @0x78 +
//                     linkTarget dwString @0xc0.
//
// plus the .drd (saved droid) file format:
//   dwGuiWidgets_WriteDroidFile / ReadDroidFile / SaveDroidToFile /
//   LoadDroidFromFile / NodeIndexOf / NodeAtIndex — VERSION/NAME/PARTS/
//   COLORS/PARENTS sections over the workspace dwPartNode list (see the
//   notes in dwGuiWidgets.cpp; the part-tree walkers are P5-blocked stubs).
//
// Decompiled from DroidWorks.exe, unit range 0x432150-0x433d8f (+ the four
// MI this-adjustor thunks @0x433db0-0x433de0, which the C++ compiler now
// emits itself). 0x432150/0x432170 at the range start are
// dwGuiScreen_EnsureImages/FreeImages (translated in dwGuiScreen.cpp);
// dw_CoreStubCtor @0x432280 is a dwSegment-vptr COMDAT owned by the dw core
// unit's EH cleanup — neither is re-implemented here. Verifiably C++
// (vtables, ctor/dtor pairs, MSVC EH frames) -> C++ classes.
//
// No module statics — no dwGuiWidgets_Startup needed (soft-reset rule).

#include "Dw/dwTypes.h"
#include "Dw/dwRect.h"
#include "Dw/dwConfFile.h"

#ifdef __cplusplus
struct dwGuiScrollBar;
struct dwGuiScrollBox;
struct dwGuiScrollBoxItem;
struct dwGuiScrollButton;
struct dwGuiTextRollover;
struct dwList;   // Dw/dwList.h (C++-only header)
struct dwString; // Dw/dwString.h
extern "C" {
#else
// C++ classes; opaque in the C view.
typedef struct dwGuiScrollBar dwGuiScrollBar;
typedef struct dwGuiScrollBox dwGuiScrollBox;
typedef struct dwGuiScrollBoxItem dwGuiScrollBoxItem;
typedef struct dwGuiScrollButton dwGuiScrollButton;
typedef struct dwGuiTextRollover dwGuiTextRollover;
typedef struct dwList dwList;
typedef struct dwString dwString;
#endif

// ---- .drd droid-file serialization (__cdecl free functions in the binary) --
//
// pNodeList is the workspace dwPartNode list (dwList of dwPartNode*, e.g.
// the global dwCore_pWorkspaceNodes); pName is the droid's display name.

// Write the droid to an already-open file. Sections: "VERSION 1" / "NAME %s"
// ("NAME Untitled" when pName is empty) / "PARTS %lu" (one "%s %lu %f %f %f"
// line per node: blueprint name, slot index, position) / "COLORS" (9
// "  %lu %lu" material-color pairs per node) / "PARENTS" (one "%lu %lu" line
// per node: 1-based parent node index + 1-based attach-slot index, 0 0 for
// the root). Returns 1.
// TODO(dw-decomp): currently a LOUD STUB — the per-node payload readers need
// the dwPart/dwPartNode unit (P5); the full binary recipe is documented at
// the implementation. @4322a0
int dwGuiWidgets_WriteDroidFile(stdFile_t file, dwString* pName, dwList* pNodeList);

// Parse a .drd out of an open dwConfFile into pNameOut (may be NULL) +
// pNodeList (dwPart_FindBlueprint/CreateNode + Translate/AttachToSlot per
// node; stops at an "END" line). Returns 1 on success, 0 when a blueprint
// was missing/unavailable.
// TODO(dw-decomp): currently a LOUD STUB (P5) — recipe at the implementation.
// @4325d0
int dwGuiWidgets_ReadDroidFile(dwConfFile* pConf, dwString* pNameOut, dwList* pNodeList);

// fileOpen(pPath, "wt") + WriteDroidFile + fileClose. Returns 0 when the
// open failed, else WriteDroidFile's result. @432580
int dwGuiWidgets_SaveDroidToFile(const char* pPath, dwString* pName, dwList* pNodeList);

// dwConfFile_Open(pPath) + ReadDroidFile + Close. Returns ReadDroidFile's
// result (the binary did NOT check whether the open succeeded — a missing
// file just parses as empty/EOF). @4328f0
int dwGuiWidgets_LoadDroidFromFile(const char* pPath, dwString* pNameOut, dwList* pNodeList);

// Index of the node whose pData == pPayload. QUIRK (faithful): returns the
// list SIZE when not found (the walk counter simply runs out). @432540
int dwGuiWidgets_NodeIndexOf(dwList* pList, void* pPayload);

// pData of the index-th node, or NULL when index > size. QUIRK (faithful):
// index == size returns the SENTINEL's pData slot (uninitialized memory in
// the binary and here — malloc'd, links-only sentinel). @4328a0
void* dwGuiWidgets_NodeAtIndex(dwList* pList, int index);

#ifdef __cplusplus
} // extern "C"

#include "Dw/dwWidget.h"
#include "Dw/dwWorkshopCtrl.h" // dwGuiScrollButton base
#include "Dw/dwGuiButton.h"    // dwGuiTextButton (dwGuiTextRollover base)
#include "Dw/dwGuiHypText.h"   // dwGuiTextRollover second base
#include "Dw/dwString.h"
#include "Dw/dwList.h"
#include "Dw/dwImage.h"
#include "Dw/dwFont.h"

// ---- dwGuiScrollBar -----------------------------------------------------------
//
// Binary layout: dwWidget base @0x00 (0xe) + fields from 0x10 — sizeof 0x5c
// (0x28..0x2f is 8 bytes of never-touched padding, not carried here).
// vtable @0x51f7f0 (dwGuiScrollBar_vtbl).
//
// Orientation is auto-detected from the ctor rect (taller than wide ->
// vertical). value moves in [minValue, maxValue]; an INVERTED range
// (minValue > maxValue) is supported throughout (clamping and the repeat
// direction flip). Every value change dispatches { msgSetValue,
// (void*)value, 0, NULL } to dwWidget_pDefault. Receiving msgLineUp/
// msgLineDown arms/stops the auto-repeat (one value step per 0.1s in
// Update) — the paired dwGuiScrollButton sends the same code on press AND
// release, so the first message arms and the second stops.

struct dwGuiScrollBar : dwWidget
{
    int32_t msgSetValue;     // 0x10: value-changed notification code (also OnHover payload)
    int32_t msgLineUp;       // 0x14: arms repeat mode 2 (toward minValue)
    int32_t msgLineDown;     // 0x18: arms repeat mode 1 (toward maxValue)
    int32_t minValue;        // 0x1c
    int32_t maxValue;        // 0x20
    int32_t value;           // 0x24: current value (ctor: = minValue)
    // (0x28..0x2f: unused padding in the binary)
    dwImage* pTrackImage;    // 0x30: lazily loaded from trackImageName
    dwImage* pThumbImage;    // 0x34: lazily loaded from thumbImageName
    dwString trackImageName; // 0x38
    dwString thumbImageName; // 0x44
    uint8_t bDragging;       // 0x50: thumb drag latched (mouse captured)
    uint8_t bVertical;       // 0x51 (Ghidra: bHorizontal — MISNAMED; set when
                             //       rect height > width, selects the y axis)
    int32_t dragMode;        // 0x54: 0 idle / 1 = msgLineDown repeat / 2 = msgLineUp repeat
    float repeatAccum;       // 0x58: repeat timer (NOT initialized by the
                             //       binary ctor; zeroed when a mode is armed.
                             //       Note: zero-initialized here.)

    // @432980 (dwGuiScrollBar_Ctor) — dwWidget(pRect); value = minValue;
    // assigns both image names and EnsureImages()es immediately.
    dwGuiScrollBar(dwRect* pRect, int msgSetValue, int msgLineUp, int msgLineDown,
                   int minValue, int maxValue, char* pTrackImgName, char* pThumbImgName);

    // @432a80 (dwGuiScrollBar_Dtor; scalar-deleting wrapper @432a60) —
    // FreeImages + the two string frees (member dtors here).
    virtual ~dwGuiScrollBar();

    // vtbl +0x04 @432b20 — while dragging: SetValue(PointToValue(x, y)).
    // Returns bDragging.
    virtual int OnMouseMove(int16_t x, int16_t y);
    // vtbl +0x08 @432b50 — latch bDragging, capture dwWidget_pMouseTarget,
    // then tail-call OnMouseMove (virtual) with the same point.
    virtual int OnMouseDown(int16_t x, int16_t y);
    // vtbl +0x0c @432b70 — clear the drag + release the capture; returns 1.
    virtual int OnMouseUp(int16_t x, int16_t y);
    // vtbl +0x14 @432c00 — auto-repeat: while a mode is armed, accumulate dt
    // and step value by (int)(accum * 10) every 0.1s (direction from the
    // mode, flipped for inverted ranges).
    virtual void Update(float dt);
    // vtbl +0x18 @419780 — the shared dwWidget_OnHoverNotify body reading
    // the +0x10 field: dispatch { 0x7531, (void*)msgSetValue }; return 1.
    virtual int OnHover(int16_t x, int16_t y);
    // vtbl +0x1c @432b90 — msgSetValue: SetValue((int)pMsg->pSender);
    // msgLineUp/Down: arm the repeat (or stop it when one is already
    // armed). Returns 0.
    virtual int OnMessage(dwWidgetMsg* pMsg);
    // vtbl +0x20 @432af0 (Ghidra: dwGuiScrollBar_EnableInput) — Enable
    // OVERRIDE: bEnabled = 1 + re-dispatch { msgSetValue, (void*)value }.
    virtual void Enable();
    // vtbl +0x3c @433000 — lazy loads (thumb first, then track).
    virtual void EnsureImages();
    // vtbl +0x40 @433050 — delete both images (thumb first).
    virtual void FreeImages();
    // vtbl +0x44 @432f60 — track image at (left, top), thumb image at its
    // GetThumbRect position (or a transparent-index FillRect when the thumb
    // image is missing). NOTE: GetThumbRect runs BEFORE the bEnabled gate
    // (binary quirk).
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);

    // -- non-virtual methods --------------------------------------------------

    // @432cc0 — clamp into the (possibly inverted) range; on change:
    // Invalidate (virtual) + dispatch { msgSetValue, (void*)value }.
    void SetValue(int newValue);
    // @432d30 — map a point on the track axis to a value (thumb size, or 5px
    // when no thumb image, insets the track ends). Off-track-start returns
    // minValue, off-track-end maxValue.
    int PointToValue(int16_t x, int16_t y);
    // @432e20 — compute the thumb rect: *pRectOut starts as the widget rect,
    // then the axis span is replaced by the thumb extent centered on the
    // value's track position (exact right/bottom edge stop at maxValue).
    void GetThumbRect(dwRect* pRectOut);
};

// ---- dwGuiScrollBox -----------------------------------------------------------
//
// Binary layout: dwWidget base @0x00 (0xe) + fields from 0x10 — sizeof 0x38.
// vtable @0x51f840 (dwGuiScrollBox_vtbl).
//
// The item list is sorted case-insensitively by display name on insert.
// pFirstVisible is the top row's NODE (scrolled by scrollMsgCode messages
// from the paired dwGuiScrollBar, whose value is the absolute row index);
// selection changes dispatch { msgSelChanged, item->filename.pBuffer } (or
// NULL pSender when the selection empties).

// One list entry: {filename, display name}. 0x18 in the binary (no vptr).
// Ghidra: the payload freed by dwGuiScrollBox_ItemFree @433700 /
// _ItemDtorDelete @4336e0 (the dtor here; delete = the DtorDelete pair).
struct dwGuiScrollBoxItem
{
    dwString filename;    // 0x00
    dwString displayName; // 0x0c: sort key + drawn text

    dwGuiScrollBoxItem(const char* pFilename, const char* pDisplayName)
        : filename(pFilename, 0), displayName(pDisplayName, 0) {}
    // @433700 (dwGuiScrollBox_ItemFree) — displayName then filename
    // (member dtors, reverse declaration order).
    ~dwGuiScrollBoxItem() {}
};

struct dwGuiScrollBox : dwWidget
{
    uint8_t textColorIdx;              // 0x10
    uint8_t bHasSelection;             // 0x11: ctor-initialized to 1 (quirk)
    uint8_t highlightColorIdx;         // 0x12
    uint8_t bNeedsScroll;              // 0x13: itemCount exceeds the visible rows
    int32_t scrollMsgCode;             // 0x14: scroll-position message (from the scrollbar)
    int32_t itemCount;                 // 0x18
    int32_t scrollPos;                 // 0x1c: absolute row index of pFirstVisible
    dwListNode* pFirstVisible;         // 0x20: top visible row's node
    dwList items;                      // 0x24 (Ghidra: pItems): dwGuiScrollBoxItem* payloads
    dwGuiScrollBoxItem* pSelectedItem; // 0x28
    dwFont* pFont;                     // 0x2c: owned heap handle (dwFont_Load)
    int32_t msgSelChanged;             // 0x30 (Ghidra: field_0x30): selection-changed
                                       //      message code (also the OnHover payload)
    uint8_t bDrawBorder;               // 0x34: focus border (set by an inside click)

    // @433080 (dwGuiScrollBox_Ctor) — dwWidget(pRect); loads the font when
    // pFontName is non-NULL; pFirstVisible = first node (the empty sentinel).
    dwGuiScrollBox(dwRect* pRect, int scrollMsgCode, char* pFontName,
                   uint8_t textColorIdx, uint8_t highlightColorIdx, int msgSelChanged);

    // @433180 (dwGuiScrollBox_Dtor; scalar-deleting wrapper @433160) — free
    // the font handle, delete every item + node, free the list.
    virtual ~dwGuiScrollBox();

    // vtbl +0x08 @433310 — inside: select the clicked row (dispatch
    // { msgSelChanged, filename } + Invalidate), turn the border on;
    // outside: border off. Returns 0 either way.
    virtual int OnMouseDown(int16_t x, int16_t y);
    // vtbl +0x18 @4337f0 — dispatch { 0x7531, (void*)msgSelChanged };
    // return 1 (the OnHoverNotify pattern).
    virtual int OnHover(int16_t x, int16_t y);
    // vtbl +0x1c @433750 — scrollMsgCode: pMsg->pSender is the new absolute
    // row index; walk pFirstVisible by the delta (backward stops at the
    // FIRST node, forward at the sentinel; both only while bNeedsScroll)
    // and Invalidate on success. Returns 0.
    virtual int OnMessage(dwWidgetMsg* pMsg);
    // vtbl +0x44 @433820 — rows from pFirstVisible while the row top is
    // above pClipRect->bottom: selected row gets a highlightColorIdx
    // FillRect (clipped), text at (left, rowTop + font y-inset); then the
    // color-7 focus FrameRect when bDrawBorder.
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);

    // -- non-virtual methods --------------------------------------------------

    // @433410 — 1 when any item's filename BASENAME equals pFilename's
    // buffer (dwString_FindFilename + dwString_Equals).
    int ContainsFile(dwString* pFilename);
    // @433490 — insert { pFilename, pDisplayName } sorted by display name
    // (case-insensitive; NULL display buffers sort first); resets the
    // scroll to the top and selects the FIRST item; UpdateScrollFlag +
    // Invalidate.
    void AddItem(char* pFilename, char* pDisplayName);
    // @4335c0 — remove pSelectedItem's node + item; the selection moves to
    // the previous node (next when it was the first); dispatches
    // { msgSelChanged, new filename or NULL }; UpdateScrollFlag + Invalidate.
    void RemoveSelected();
    // @433960 (dwGuiScrollBox_UpdateScrollFlag) — bNeedsScroll =
    // (visible rows < itemCount); when scrolling is NOT needed the view
    // snaps back to the first node.
    void UpdateScrollFlag();
};

// ---- dwGuiScrollButton -----------------------------------------------------------
//
// Binary layout: dwWorkshopCtrl base only (sizeof 0x50, no added fields).
// vtable @0x51f888 (dwGuiScrollButton_vtbl); overrides ONLY OnMouseDown/
// OnMouseUp — everything else (incl. the { 0x7531, cmdId } OnHover and the
// two-image Draw) is the dwWorkshopCtrl base.

struct dwGuiScrollButton : dwWorkshopCtrl
{
    // @433aa0 (dwGuiScrollButton_Ctor) — base(pRect, pImgUp, NULL, pImgDown,
    // NULL, cmdId, /*bToggle*/0); the base defaults the click sound to
    // CGenButton.wav.
    dwGuiScrollButton(dwRect* pRect, char* pImgUpName, char* pImgDownName, int cmdId);

    // @433af0 (dwGuiScrollButton_Dtor; scalar-deleting wrapper @433ad0) —
    // base only.
    virtual ~dwGuiScrollButton();

    // vtbl +0x08 @433b00 — base OnMouseDown (momentary press), then when it
    // went hot: dispatch { cmdId, 0, 0, NULL } (ARMS the scrollbar repeat).
    // Returns the base result.
    virtual int OnMouseDown(int16_t x, int16_t y);
    // vtbl +0x0c @433b50 — release the capture; when the press was latched:
    // clear bPressed/bHot, Invalidate, dispatch { cmdId, 0, 0, NULL }
    // (STOPS the repeat). Returns 0.
    virtual int OnMouseUp(int16_t x, int16_t y);
};

// ---- dwGuiTextRollover -----------------------------------------------------------
//
// Binary layout: dwGuiTextButton @0x00 (0x78) + dwGuiHypText @0x78 (0x48) +
// linkTarget @0xc0 — sizeof 0xcc. REAL MSVC MI: primary vtable
// dwGuiTextRollover_vtbl @0x51f928 (dwGuiTextButton shape + the base
// dwWorkshopCtrl +0x48 HitTest slot), secondary dwGuiTextRollover_HypText_vtbl
// @0x51f8d8 whose dtor/OnMouseUp/OnHover/Draw slots are this-adjustor thunks
// (-0x78) into the overrides below (@433db0/433dc0/433dd0/433de0 — the C++
// compiler emits these itself now) while +0x14 Update and +0x48 SetText stay
// dwGuiHypText's. So: ticking the hyptext side animates the runs, and the
// rollover draws BOTH bases' text (hyptext runs + the button label).
//
// Both dwWidget bases carry the same ctor rect. Reading widget fields in the
// overrides is ambiguous in C++ — the binary reads the PRIMARY
// (dwGuiTextButton) subobject; qualify accordingly.

struct dwGuiTextRollover : dwGuiTextButton, dwGuiHypText
{
    dwString linkTarget; // 0xc0: pSender payload of the click dispatch

    // @433bb0 (dwGuiTextRollover_Ctor) —
    //   dwGuiTextButton(pRect, pText, pFontName, color, pSndOff, colorHot,
    //                   pSndClick, pHoverSnd, cmdId, /*bAltDraw*/0)
    //   dwGuiHypText(pRect, NULL, pFontName, color, "BCO")   (wrap words /
    //                h-center / shadowed glyphs; binary string @5294a4)
    // then: hyptext text.Free() + virtual SetText(pText) (SetText APPENDS —
    // the Free-first is the documented replace idiom) and labelText =
    // hyptext text (same buffer content).
    dwGuiTextRollover(dwRect* pRect, char* pText, char* pFontName, char* pLinkTarget,
                      uint8_t color, char* pSndOff, uint8_t colorHot,
                      char* pSndClick, char* pHoverSnd, int cmdId);

    // @433cb0 (dwGuiTextRollover_Dtor; scalar-deleting wrapper @433c90) —
    // linkTarget free + both base dtors (all implicit here).
    virtual ~dwGuiTextRollover();

    // vtbl +0x0c @433d50 (secondary thunk @433dc0, Ghidra:
    // dwGuiTextRollover_OnHover2_Thunk — MISNAMED, it is the OnMouseUp
    // thunk) — dispatch { cmdId, linkTarget.pBuffer, 0, NULL }; return 1.
    virtual int OnMouseUp(int16_t x, int16_t y);
    // vtbl +0x18 @433d30 (secondary thunk @433dd0) — forwards to the shared
    // dwWorkshopCtrl body @439ad0: dispatch { 0x7531, (void*)cmdId };
    // return 1.
    virtual int OnHover(int16_t x, int16_t y);
    // vtbl +0x44 @433d80 (secondary thunk @433de0) — when the PRIMARY
    // subobject is enabled: dwGuiHypText::Draw then dwGuiTextButton::Draw
    // (both direct calls in the binary).
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);
};

#endif // __cplusplus

#endif // _DWGUIWIDGETS_H
