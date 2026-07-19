#ifndef _DWGUIQUICKVIEW_H
#define _DWGUIQUICKVIEW_H

// dwGuiQuickView — the DroidWorks 3D droid-model PREVIEW widget: an orbiting
// dwGuiViewBox that shows a droid assembled from its OWN dwPartNode list
// (falling back to the live global workspace droid, dwCore_pWorkspaceNodes,
// when its own list is empty), auto-rotating each tick. Built by the
// dwGuiScreen factory for the QUICKVIEW control keyword.
//
// dwGuiQuickView is the shared BASE that dwGuiDroidDance (a sibling unit in
// dwGuiList — NOT implemented here) and dwGuiDroidPreview (below) derive from;
// its Update/OnHover/OnMessage/Draw/LayoutNodes are the shared implementations
// those subclasses inherit.
//
// dwGuiDroidPreview — a dwGuiQuickView subclass built by dwGuiMissionMap
// (JAWA_ANIM) and dwGuiStatus; on message 0xbbc it rebuilds its list to show
// one blueprint variant of the selected part.
//
// Decompiled from DroidWorks.exe, unit range 0x429a80-0x42a5xx.
//   dwGuiQuickView   ctor@429c90  vtable @0x51f5c0  struct sizeof 0x574
//   dwGuiDroidPreview ctor@429a80 vtable @0x51f548  struct sizeof 0x574 (0 new fields)
//
// dwGuiQuickView binary layout (sizeof 0x574):
//   +0x000 dwGuiViewBox base (0x560; ctor forces bLightsFollowView = 1)
//   +0x560 dwString name    (loaded .drd droid name; empty -> live workspace)
//   +0x56c float rotTimer   (auto-rotate accumulator, seconds)
//   +0x570 dwListNode* pNodes  (heap sentinel of a dwPartNode* list; own droid)
//
// Slot overrides (against the dwGuiViewBox / dwGui3DView / dwWidget maps):
//   +0x14 Update    (auto-rotate: broadcast a 0x3e8 set-pitch message)
//   +0x18 OnHover   (0x7531 hover notification; QuickView id 0x7922 /
//                    DroidPreview id 0x7920)
//   +0x1c OnMessage (0xfa3 load-from-.drd / 0x7d5-0x7d6 relayout /
//                    0xfa9 commit-to-workspace; DroidPreview adds 0xbbc)
//   +0x44 Draw      (camera bring-up, then draw the droid's root/detached nodes)
// Move / RebuildLights / Refresh / SetAngles are inherited from the bases.

#include "types.h"
#include "Dw/dwGuiViewBox.h"
#include "Dw/dwString.h"
#include "Dw/dwRect.h"
#include "Dw/dwPart.h" // dwPart (blueprint) — dwGuiDroidPreview ctor/msg use it

#ifndef __cplusplus

typedef struct dwGuiQuickView dwGuiQuickView;    // C++ classes; opaque in C
typedef struct dwGuiDroidPreview dwGuiDroidPreview;

#else // __cplusplus

#include "Dw/dwList.h" // dwListNode

struct dwGuiQuickView : dwGuiViewBox
{
    dwString name;       // 0x560
    float rotTimer;      // 0x56c
    dwListNode* pNodes;  // 0x570: own droid's part-node list (heap sentinel)

    // Orbit preview covering *pRect (lights follow the view). @429c90
    dwGuiQuickView(dwRect* pRect);

    // Free every node + delete its dwPartNode payload, free the sentinel,
    // release the name, then the base dtor. @429d50 (DtorDelete @429d30)
    virtual ~dwGuiQuickView();

    // @429e80 — vtbl +0x14: rotTimer += dt, then broadcast a set-pitch message
    // (angle = round(rotTimer*45) + 180, mod 360) to pDefault.
    virtual void Update(float dt);

    // @42a510 — vtbl +0x18: dispatch a { 0x7531, 0x7922 } hover notification.
    virtual int OnHover(int16_t x, int16_t y);

    // @429ee0 — vtbl +0x1c (see the code map above).
    virtual int OnMessage(dwWidgetMsg* pMsg);

    // @42a260 — vtbl +0x44: camera bring-up, then draw every root/detached
    // node of the active droid list (own list, or the workspace when empty).
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);

    // @42a320 — fit the orbit camera to the bounding box of the active droid
    // list (own list, or the workspace when empty): sets orbitDistance + pivot
    // then Refresh. Non-virtual helper.
    void LayoutNodes();
};

// dwGuiDroidPreview — dwGuiQuickView subclass (adds NO fields). @429a80
struct dwGuiDroidPreview : dwGuiQuickView
{
    // Preview covering *pRect. When pBlueprint != NULL, seeds the list with
    // one node of that blueprint. @429a80
    dwGuiDroidPreview(dwRect* pRect, dwPart* pBlueprint);

    // Base dtor only. @429b30 (DtorDelete @429b10)
    virtual ~dwGuiDroidPreview();

    // @429c60 — vtbl +0x18: dispatch a { 0x7531, 0x7920 } hover notification.
    virtual int OnHover(int16_t x, int16_t y);

    // @429b40 — vtbl +0x1c: on { 0xbbc, pPart } rebuild the list to show one
    // blueprint variant of the selected part, then chain the base OnMessage.
    virtual int OnMessage(dwWidgetMsg* pMsg);
};

#endif // __cplusplus

// ---- C FFI factories --------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif

// Added: C shims over `new dwGuiQuickView(pRect)` / `new dwGuiDroidPreview(
// pRect, pBlueprint)`. The current factories are C++ and can `new` directly;
// these exist for any C-side factory. Return the object as a dwWidget*.
dwWidget* dwGuiQuickView_New(dwRect* pRect);
dwWidget* dwGuiDroidPreview_New(dwRect* pRect, dwPart* pBlueprint);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // _DWGUIQUICKVIEW_H
