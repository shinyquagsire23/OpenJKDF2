#ifndef _DWGUIFIND_H
#define _DWGUIFIND_H

// dwGuiFind — the reference-room TOPIC SEARCH screen ("Find"), a slide-in panel
// spawned by dwGuiReference_OnMessage@42cc80 to search the in-game encyclopedia.
// Its factory populates a scroll list with every TPC/SUB topic file whose
// TOPIC_CATEGORY == 0, an editable query box that type-ahead-matches the list,
// a scrollbar and scroll buttons.
//
//   dwGuiFind          (0xf0, primary vtbl 0x51eb90 / segment vtbl 0x51eb78,
//                      ctor @412380) — dwGuiScreen subclass. Slides the whole
//                      controls group on/off; on slide-in completion focuses
//                      the query box, on slide-out completion advances the
//                      segment. Composites the parent-supplied snapshot into
//                      its background on activation.
//   dwGuiFindScrollBar (0x60, vtbl 0x51ebe0, ctor @4136b0) — dwGuiScrollBar +
//                      msgCode@0x5c. OnMessage intercepts msgCode to scroll by
//                      a signed delta via a clamp-no-notify SetValue.
//   dwGuiFindScrollBox (0x44, vtbl 0x51ec28, ctor @4137e0) — dwGuiScrollBox +
//                      msgNotify@0x38 / searchStep@0x3c. OnMessage is the
//                      TYPE-AHEAD incremental search matcher (prefix-matches
//                      the typed query, scrolls+selects the nearest topic,
//                      sends 0x1b7b, plays RFindError.WAV on no match).
//
// Decompiled from DroidWorks.exe, unit range 0x412380-0x413c1f. (dwGuiFindEntry
// @413c20 is the query box; it lives in Dw/dwGuiTextEntry.h with dwGuiTextEntry.)
// Verifiably C++ (vtables, ctor/dtor pairs, MSVC EH frames) -> C++ classes.
//
// No module statics — no dwGuiFind_Startup needed (soft-reset rule).

#include "Dw/dwTypes.h"

#ifdef __cplusplus
struct dwGuiFind;
struct dwGuiFindScrollBar;
struct dwGuiFindScrollBox;
struct dwImage;   // Dw/dwImage.h
struct dwSegment; // Dw/dwSegment.h
extern "C" {
#else
typedef struct dwGuiFind dwGuiFind;
typedef struct dwGuiFindScrollBar dwGuiFindScrollBar;
typedef struct dwGuiFindScrollBox dwGuiFindScrollBox;
typedef struct dwImage dwImage;
typedef struct dwSegment dwSegment;
#endif

// C-callable factory (dwGuiReference_OnMessage spawns the Find panel): builds a
// dwGuiFind over the caller's background snapshot and returns its dwSegment
// subobject to push. @412380 (bundles new(0xf0) + Ctor).
dwSegment* dwGuiFind_New(dwImage* pBgSnapshot);

#ifdef __cplusplus
} // extern "C"

#include "Dw/dwGuiScreen.h"
#include "Dw/dwGuiWidgets.h"   // dwGuiScrollBar / dwGuiScrollBox / dwGuiScrollButton
#include "Dw/dwGuiTextEntry.h" // dwGuiFindEntry (query box)
#include "Dw/dwImage.h"

// ---- dwGuiFindScrollBar -----------------------------------------------------
//
// Binary layout: dwGuiScrollBar base @0x00 (0x5c) + msgCode@0x5c — sizeof 0x60.
// vtable @0x51ebe0 (dwGuiFindScrollBar_vtbl): overrides only +0x00 dtor and
// +0x1c OnMessage.

struct dwGuiFindScrollBar : dwGuiScrollBar
{
    int32_t msgCode; // 0x5c: the scroll-by-delta message this bar listens for

    // @4136b0 — base dwGuiScrollBar ctor (8 args) then msgCode = msgCode.
    dwGuiFindScrollBar(dwRect* pRect, int msgSetValue, int msgLineUp, int msgLineDown,
                       int minValue, int maxValue, char* pTrackImgName, char* pThumbImgName,
                       int msgCode);

    // @413720 (dwGuiFindScrollBar_Dtor; scalar-deleting wrapper @413700) —
    // vptr re-point + base dtor (implicit here).
    virtual ~dwGuiFindScrollBar();

    // vtbl +0x1c @413730 — when pMsg->code == msgCode: scroll by the signed
    // delta in pMsg->pSender (added to the current value when >1, else set
    // outright) via the clamp-no-notify SetValueClamp; then chain to the base
    // OnMessage. Returns the base result.
    virtual int OnMessage(dwWidgetMsg* pMsg);

    // @4137a0 (dwGuiFindScrollBar_SetValue) — clamp newValue into the (possibly
    // inverted) [minValue, maxValue] range; on change store it + Invalidate,
    // WITHOUT the base SetValue's msgSetValue notification.
    void SetValueClamp(int newValue);
};

// ---- dwGuiFindScrollBox -----------------------------------------------------
//
// Binary layout: dwGuiScrollBox base @0x00 (0x38) + msgNotify@0x38 +
// searchStep@0x3c + reserved@0x40 — sizeof 0x44. vtable @0x51ec28
// (dwGuiFindScrollBox_vtbl): overrides +0x00 dtor, +0x08 OnMouseDown,
// +0x10 OnKey, +0x1c OnMessage.

struct dwGuiFindScrollBox : dwGuiScrollBox
{
    int32_t msgNotify; // 0x38: the type-ahead trigger message code
    uint8_t searchStep;// 0x3c: match-walk guard counter (0..0x5f)
    int32_t reserved;  // 0x40: ctor-zeroed, unused in this unit

    // @4137e0 — base dwGuiScrollBox ctor (6 args) then msgNotify = msgNotify;
    // searchStep = 0; reserved = 0.
    dwGuiFindScrollBox(dwRect* pRect, int scrollMsgCode, char* pFontName,
                       uint8_t textColorIdx, uint8_t highlightColorIdx,
                       int msgSelChanged, int msgNotify);

    // @413850 (dwGuiFindScrollBox_Dtor; scalar-deleting wrapper @413830) —
    // vptr re-point + base dtor (implicit here).
    virtual ~dwGuiFindScrollBox();

    // vtbl +0x08 @413860 — select the clicked row (like the base) and dispatch
    // the selection-changed notification; returns 0.
    virtual int OnMouseDown(int16_t x, int16_t y);

    // vtbl +0x10 @413910 — swallow keys (returns 0).
    virtual int OnKey(int key, int repeat);

    // vtbl +0x1c @413920 — when pMsg->code == msgNotify: prefix-match the typed
    // query (pMsg->pSender) against the sorted topic list, walking forward/back
    // from pFirstVisible to the nearest match; select+scroll to it (dispatch
    // { 0x1b7b, delta }), or play RFindError.WAV when no match. Always
    // repaints + chains to the base OnMessage. Returns 1 when it handled
    // msgNotify, else the base result.
    virtual int OnMessage(dwWidgetMsg* pMsg);
};

// ---- dwGuiFind --------------------------------------------------------------
//
// Binary layout: dwGuiScreen base @0x00 (0xc8) + own fields from 0xc8 —
// sizeof 0xf0. vtables: primary dwGuiFind_vtbl @0x51eb90 (dwWidget shape +
// screen factory slots), segment dwGuiFind_scn_vtbl @0x51eb78 (dwSegment
// lifecycle; its +0x04 Deactivate reuses the shared dwGuiLoadSave_OnDeactivate
// body — see dwGuiFind.cpp).

struct dwGuiFind : dwGuiScreen
{
    dwImage* pParent;             // 0xc8: parent snapshot image (also the ctor's
                                  //       dwGuiScreen bg source; blitted into
                                  //       pBgImage on activation)
    uint8_t bAutoEditQuery;       // 0xcc: focus the query box when the slide-in
                                  //       completes
    dwWidget* pBgImageControl;    // 0xd0: FINDBOX -> the base IMAGE control
    dwGuiFindEntry* pQueryEntry;  // 0xd4: QUERY -> the editable query box
    dwGuiFindScrollBar* pScrollBar;// 0xd8: FILESCROLLBAR
    dwGuiFindScrollBox* pResultBox;// 0xdc: SCROLLBOX -> the searchable topic list
    dwGuiScrollButton* pScrollUp; // 0xe0: SCROLLUPBUTTON
    dwGuiScrollButton* pScrollDown;// 0xe4: SCROLLDOWNBUTTON
    float slidePos;               // 0xe8: current slide offset
    float slideDir;               // 0xec: slide direction/speed (0 = settled)

    // @412380 — dwGuiScreen("Find", pBgSnapshot); pParent = pBgSnapshot;
    // everything else zero.
    dwGuiFind(dwImage* pBgSnapshot);

    // @412410 (dwGuiFind_Dtor; scalar-deleting wrapper @4123f0; segment dtor
    // thunk @4136a0) — the tracked controls are children of the base screen's
    // `controls` group and die in its dtor (see dwGuiFind.cpp note).
    virtual ~dwGuiFind();

    // ---- dwWidget-side overrides (primary vtbl @0x51eb90) ----
    // vtbl +0x10 @412be0 — Esc starts the close slide; then base OnKey.
    virtual int OnKey(int key, int repeat);
    // vtbl +0x14 @412730 — drive the slide (advance/complete), then tick the
    // controls group.
    virtual void Update(float dt);
    // vtbl +0x1c @412c30 — Find command codes 0x1b76/0x1b78/0x1b79/0x1b7a
    // (refresh / reopen / confirm-selection); then base OnMessage.
    virtual int OnMessage(dwWidgetMsg* pMsg);
    // vtbl +0x48 @412d10 — the keyword factory (FINDBOX/QUERY/SCROLLBOX/
    // FILESCROLLBAR/SCROLLUPBUTTON/SCROLLDOWNBUTTON; else base).
    virtual dwWidget* CreateControl(char* pKeyword, dwConfFile* pConf);

    // ---- dwSegment-side overrides (segment vtbl @0x51eb78) ----
    // vtbl(scn) +0x00 @4128e0 — (re)open: composite the parent snapshot into
    // the background, seed the slide-in, set the ambient volume.
    virtual int Activate();
    // vtbl(scn) +0x04 @40bea0 — the binary reuses the shared
    // dwGuiLoadSave_OnDeactivate body: free the cached sound samples.
    virtual void Deactivate();

    // -- non-virtual methods --------------------------------------------------

    // @412b00 — show/hide the scrollbar + scroll buttons per the result box's
    // bNeedsScroll, and refresh the box selection state.
    void RefreshScrollWidgets();
};

#endif // __cplusplus

#endif // _DWGUIFIND_H
