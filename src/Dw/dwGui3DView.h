#ifndef _DWGUI3DVIEW_H
#define _DWGUI3DVIEW_H

// dwGui3DView — the DroidWorks base 3D-view widget: a dwWidget that embeds a
// REAL engine rdCanvas + rdCamera (+ two rdLights) to render a small 3D
// viewport inside a GUI rect. dwGuiViewBox (orbit/turntable view, see
// dwGuiViewBox.h) and the P5 droid viewers derive from it.
//
// Decompiled from DroidWorks.exe, unit range 0x43ae40-0x43b4bf.
// vtable @0x51fef0 (dwGui3DView_vtbl).
//
// Binary layout (sizeof 0x544; pinned by the dwGuiViewBox ctor):
//   +0x00  dwWidget base (0xe)
//   +0x10  rdMatrix34 viewMat      — camera PLACEMENT matrix (camera->world);
//                                    rdCamera_Update inverts it into
//                                    camera.orient (world->camera)
//   +0x40  rdCanvas   canvas       — embedded, wired to the DW back buffer
//   +0x68  rdCamera   camera       — embedded (0x464 bytes in the binary).
//          The Ghidra /DW struct's "landmark fields" all live INSIDE it:
//            currentFOV@0xa0    = camera.fov
//            groundPlaneY@0xa4  = camera.focalLength (projection distance,
//                                 built by rdCamera_BuildFOV)
//            pClipFrustum@0xb0  = camera.pClipFrustum
//            pProjCallback@0xb4 = camera.pfProject
//   +0x4cc rdVector3 light0Pos    (Ghidra: light0Dir — it is passed to
//   +0x4d8 rdVector3 light1Pos     rdCamera_AddLight as the light POSITION)
//   +0x4e4 rdLight   light0       (light0.intensity = Ghidra light0Intensity@0x4fc)
//   +0x514 rdLight   light1       (light1.intensity = Ghidra light1Intensity@0x52c)
//
// The 64-bit translation keeps the field ORDER and embeds the repo's real
// rdCanvas/rdCamera/rdLight structs (their sizes/offsets differ from the
// 32-bit binary; all accesses below go through field names).
//
// vtable overrides/additions (against the dwWidget slot map in dwWidget.h):
//   +0x00 dtor, +0x1c OnMessage (0x3ea = set FOV percent), +0x28 Move,
//   +0x44 Draw (camera bring-up only — derived classes render content after),
//   +0x48 RebuildLights (NEW), +0x4c Refresh (NEW; forwards to Invalidate —
//   dwGuiViewBox overrides this slot with its RebuildView body).

#include "types.h"
#include "Dw/dwWidget.h"

#ifndef __cplusplus

typedef struct dwGui3DView dwGui3DView; // C++ class; opaque in the C view

#else // __cplusplus

struct dwGui3DView : dwWidget
{
    rdMatrix34 viewMat;  // 0x10: camera placement (camera->world)
    rdCanvas canvas;     // 0x40: embedded render canvas (DW back buffer)
    rdCamera camera;     // 0x68: embedded camera (see landmark-field map above)
    rdVector3 light0Pos; // 0x4cc (Ghidra: light0Dir)
    rdVector3 light1Pos; // 0x4d8 (Ghidra: light1Dir)
    rdLight light0;      // 0x4e4
    rdLight light1;      // 0x514

    // View covering *pRect: canvas over the DW back buffer, camera
    // fov=20 near=0.008 far=50 aspect=1 ambient=0.3 attenuation=1e-5,
    // light0=(0,-1,-0.4) i=1.0, light1=(0,-0.2,1) i=0.75 (both type 2).
    // @43ae40
    dwGui3DView(dwRect* pRect);

    // rdCanvas_FreeEntry + rdCamera_FreeEntry, then the dwWidget base dtor.
    // @43afd0 (DtorDelete @43afb0)
    virtual ~dwGui3DView();

    // Msg 0x3ea = set FOV/zoom: fov = (uint)payload * 0.01; re-syncs the
    // frustum to the WIDGET rect when the canvas cache is stale, then
    // BuildFOV + virtual Refresh. Always returns 0. @43b000
    virtual int OnMessage(dwWidgetMsg* pMsg); // vtbl +0x1c

    // Translate the widget rect and recenter the canvas
    // half_screen_width/height on it. @43b0f0 (recovered fn)
    virtual void Move(int16_t dx, int16_t dy); // vtbl +0x28

    // Camera bring-up for a repaint: SetCurrent + Update(viewMat), re-syncs
    // the frustum to (clip.left+1, clip.top+1, clip.right, clip.bottom) when
    // the canvas cache is stale, then rdSetLightingMode(3). Draws NO pixels —
    // derived classes call this first, then render their content. @43b2b0
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect); // vtbl +0x44

    // NEW virtuals — appended after dwWidget's +0x44 Draw.

    // ClearLights, then re-add each light whose |intensity| > 1e-5 at its
    // static lightNPos. @43b370
    virtual void RebuildLights(); // vtbl +0x48

    // Forwards to virtual Invalidate (+0x34); called after camera changes.
    // dwGuiViewBox overrides this slot with its view-matrix rebuild
    // (Ghidra: dwGuiViewBox_RebuildView). @43b150
    virtual void Refresh(); // vtbl +0x4c

    // -- non-virtual methods --------------------------------------------------

    // 2D canvas point -> 3D world point at depth camera.focalLength (the
    // distance where 1 world unit == 1 pixel, i.e. the inverse projection),
    // transformed by viewMat. @43b160
    void ScreenToWorld(dwPoint* pPt, rdVector3* pOut);

    // World point -> screen via camera.orient + camera.pfProject (makes this
    // camera current first when it is not). @43b1b0
    void ProjectPoint(rdVector3* pOut, rdVector3* pWorldPos);

    // Project pWorldPos and fill a (2*halfSize)^2 square marker centered on
    // it (clipped to pClipRect when non-NULL). @43b220
    void DrawMarker(dwImageBits* pDestBits, rdVector3* pWorldPos, int16_t halfSize, int color, dwRect* pClipRect);

    // Set light 0/1 position + intensity + rdLight type, then virtual
    // RebuildLights (+0x48). @43b440 / @43b480
    void SetLight0(float x, float y, float z, float intensity, int type);
    void SetLight1(float x, float y, float z, float intensity, int type);
};

// ---- Added: shared software-render bracket for the DW 3D views ---------------
// (factored out of dwWorkshopDroidEditor::Draw). DW has no HW path — the 3D
// views render through the CPU rasterizer into the 8bpp back buffer. Call AFTER
// the Draw's dwGui3DView::Draw camera bring-up (which makes the view's camera
// current); Begin locks the current camera canvas VBuffer, advances the frame
// and arms the software rasterizer (rdroid_curAcceleration=0 AFTER
// rdAdvanceFrame, since rdCache_AdvanceFrame force-sets it =1 on SDL2_RENDER —
// without that, rdCache_Flush takes the GL path and nothing reaches the DW
// VBuffer), and clears the SW z-buffer. End runs rdFinishFrame, unlocks and
// restores the accel flag saved into *pSavedAccel.
rdCanvas* dwGui3DView_BeginSwRender(int* pSavedAccel);
void dwGui3DView_EndSwRender(rdCanvas* pSwCanvas, int savedAccel);

#endif // __cplusplus

#endif // _DWGUI3DVIEW_H
