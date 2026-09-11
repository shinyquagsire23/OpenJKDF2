#ifndef _DWDROIDVIEW_H
#define _DWDROIDVIEW_H

// dwDroidView — the DroidWorks 3D droid-VIEWER widget: an orbiting
// dwGuiViewBox that renders the global workspace droid (the dwPartNode tree
// hanging off dwCore_pWorkspaceNodes) and supports mouse-capture ray-pick of
// the part under the cursor (recentering the orbit pivot on the picked point).
// Built by the dwWorkshop screen for the PANCONTROL control keyword.
//
// Decompiled from DroidWorks.exe, unit range 0x426080-0x426d6f.
// vtable @0x51f418 (dwDroidView_vtbl). struct dwDroidView sizeof 0x57c.
//
// NOTE: the dwDroidView compile unit ALSO physically contains dwPartNode
// (@0x4267a0+), but that class landed in dwPart.cpp/.h (P5) — it is NOT
// re-translated here; this file is only the dwDroidView class.
//
// Binary layout (sizeof 0x57c):
//   +0x000 dwGuiViewBox base (0x560)
//   +0x560 u8    bMouseCaptured
//   +0x562 i16   lastPickX  (contiguous with lastPickY as a dwPoint)
//   +0x564 i16   lastPickY
//   +0x568 rdVector3 pickResult  (Ghidra pickResult0/1/2 as int — actually the
//                                 last picked WORLD point; fed back through
//                                 dwGui3DView::ProjectPoint on a FOV change)
//   +0x574 float tanFovX  (FOV% * 0.01 — pick-rectangle half-angle factor, X)
//   +0x578 float tanFovY  (FOV% * 0.01 — pick-rectangle half-angle factor, Y)
//
// Slot overrides (against the dwGuiViewBox / dwGui3DView / dwWidget maps):
//   +0x04 OnMouseMove (pick under cursor while captured)
//   +0x08 OnMouseDown (capture mouse + set pMouseTarget, then OnMouseMove)
//   +0x0c OnMouseUp   (release capture)
//   +0x18 OnHover     (dispatch a 0x7531 hover notification, id 0x3eb)
//   +0x1c OnMessage   (0x3ea re-pick on FOV change / 0x3eb swallowed /
//                      0x7d6,0x7dc,0x7dd Invalidate / else base)
//   +0x44 Draw        (dwGui3DView camera bring-up, draw the workspace nodes
//                      highlighted, then the green selection FrameRect)
// Move / RebuildLights / Refresh / SetAngles are inherited from the bases.

#include "types.h"
#include "Dw/dwGuiViewBox.h"
#include "Dw/dwRect.h"

#ifndef __cplusplus

typedef struct dwDroidView dwDroidView; // C++ class; opaque in the C view

#else // __cplusplus

struct dwDroidView : dwGuiViewBox
{
    uint8_t bMouseCaptured; // 0x560
    int16_t lastPickX;      // 0x562
    int16_t lastPickY;      // 0x564
    rdVector3 pickResult;   // 0x568: last picked world point
    float tanFovX;          // 0x574
    float tanFovY;          // 0x578

    // Orbit droid viewer covering *pRect. The binary ctor has a dead middle
    // argument (kept so the PANCONTROL factory call stays literal); fovPct is
    // the FOV percent (also seeds tanFovX/tanFovY and the camera FOV). @426080
    dwDroidView(dwRect* pRect, int dwUnused, int fovPct);

    // Base dtor only (vtable reset handled by the compiler). @426190
    // (DtorDelete @426170)
    virtual ~dwDroidView();

    // While mouse-captured, ray-pick the part under (x, y) (forced). Returns
    // bMouseCaptured (the "handled" flag). @4261d0 — vtbl +0x04
    virtual int OnMouseMove(int16_t x, int16_t y);

    // Start capture when free: set bMouseCaptured + dwWidget_pMouseTarget, then
    // OnMouseMove(x, y). Returns 1 iff it just captured. @426210 — vtbl +0x08
    virtual int OnMouseDown(int16_t x, int16_t y);

    // Release capture (clears bMouseCaptured; clears pMouseTarget when it is
    // us). @426240 — vtbl +0x0c
    virtual int OnMouseUp(int16_t x, int16_t y);

    // Dispatch a { 0x7531, 0x3eb } hover notification to pDefault, return 1.
    // @4261a0 — vtbl +0x18
    virtual int OnHover(int16_t x, int16_t y);

    // @426270 — vtbl +0x1c (see the code map above).
    virtual int OnMessage(dwWidgetMsg* pMsg);

    // @426690 — vtbl +0x44: camera bring-up, draw every root/detached
    // workspace node highlighted, then the green pick-selection FrameRect.
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);

    // -- non-virtual helpers -------------------------------------------------

    // @426370 — slide *pRect so it stays inside the widget rect (keeping its
    // size); returns nonzero when it had to be moved (i.e. was out of bounds).
    bool ClampRectToView(dwRect* pRect);

    // @4263f0 — build a pick rect around *pPoint, clamp it to the view, and if
    // its center moved (or bForce) cast a ray through that center against the
    // camera-facing plane, store the world hit as pickResult, broadcast a
    // 0x3eb pivot-recenter, and Invalidate.
    void PickPart(dwPoint* pPoint, uint8_t bForce);

    // @426590 — compute a screen-space rect centered on *pPoint whose size is
    // the widget rect scaled by tan(tanFovY*0.5)/tan(tanFovX*0.5).
    void ComputeViewExtents(dwPoint* pPoint, dwRect* pOut);
};

#endif // __cplusplus

// ---- C FFI factory ----------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif

// Added: C shim over `new dwDroidView(pRect, dwUnused, fovPct)`. Both current
// factories (dwWorkshop PANCONTROL) are C++ and can `new` directly; this shim
// exists for any C-side factory. Returns the object as a dwWidget*.
dwWidget* dwDroidView_New(dwRect* pRect, int dwUnused, int fovPct);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // _DWDROIDVIEW_H
