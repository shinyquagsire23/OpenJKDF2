#ifndef _DWGUIVIEWBOX_H
#define _DWGUIVIEWBOX_H

// dwGuiViewBox — the DroidWorks ORBIT/TURNTABLE 3D-view widget: a
// dwGui3DView whose camera orbits a pivot point at a fixed distance, driven
// by two angles. dwDroidView / dwGuiQuickView (P5) derive from it.
// This binary compile unit ALSO contains dwGuiImage, a separate small
// static-image widget (adjacent vtable) — declared below.
//
// Decompiled from DroidWorks.exe, unit range 0x434840-0x434cff.
// vtables: dwGuiViewBox_vtbl @0x51f988, dwGuiImage_vtbl @0x51f9e0.
//
// dwGuiViewBox binary layout (sizeof 0x560):
//   +0x000 dwGui3DView base (0x544)
//   +0x544 u8    bLightsFollowView (ctor arg)
//   +0x548 float orbitDistance = 0.08 / tan(fov * 0.5)  (fits the subject)
//   +0x54c float yaw            } fed to rdMatrix_BuildRotate34 as rot.x/rot.y
//   +0x550 float pitch (init 180)} respectively (Ghidra names kept — note
//                                  rot.x is the engine's pitch slot and rot.y
//                                  its yaw slot, i.e. the names are the
//                                  binary struct's, not JK's PYR convention)
//   +0x554 float pivotX, +0x558 pivotY, +0x55c pivotZ (orbit center)
//
// Slot overrides (vs the dwGui3DView map in dwGui3DView.h):
//   +0x00 dtor, +0x1c OnMessage (0x3e8 set pitch / 0x3e9 set yaw /
//   0x3eb set pivot, else base), +0x48 RebuildLights (routes through
//   SetAngles when lights follow the view), +0x4c Refresh — OVERRIDDEN with
//   the view-matrix rebuild (Ghidra: dwGuiViewBox_RebuildView), and
//   +0x50 SetAngles(yaw, pitch) — NEW virtual.

#include "types.h"
#include "Dw/dwGui3DView.h"
#include "Dw/dwString.h"
#include "Dw/dwImage.h" // dwImage base class (dwGuiImage::pImage)

#ifndef __cplusplus

typedef struct dwGuiViewBox dwGuiViewBox; // C++ classes; opaque in the C view
typedef struct dwGuiImage dwGuiImage;

#else // __cplusplus

struct dwGuiViewBox : dwGui3DView
{
    uint8_t bLightsFollowView; // 0x544: rotate the two base lights WITH the camera
    float orbitDistance;       // 0x548: camera back-off from the pivot
    float yaw;                 // 0x54c: -> BuildRotate34 rot.x
    float pitch;               // 0x550: -> BuildRotate34 rot.y (init 180)
    float pivotX;              // 0x554: orbit center
    float pivotY;              // 0x558
    float pivotZ;              // 0x55c

    // Orbit view covering *pRect: pivot origin, yaw 0 / pitch 180,
    // orbitDistance = 0.08 / tan(fov * 0.5), then RebuildLights +
    // the view-matrix rebuild. @434840
    dwGuiViewBox(dwRect* pRect, uint8_t bLightsFollowView);

    // @434910 (DtorDelete @4348f0)
    virtual ~dwGuiViewBox();

    // 0x3e8 = set pitch, 0x3e9 = set yaw (integer degrees in the pSender
    // slot, via virtual SetAngles), 0x3eb = set pivot from a float[3]
    // payload (then virtual Refresh); everything else -> dwGui3DView.
    // Handled codes return 0. @434920
    virtual int OnMessage(dwWidgetMsg* pMsg); // vtbl +0x1c

    // When bLightsFollowView: re-drive SetAngles(yaw, pitch) (which rebuilds
    // the view AND the following lights); else the static base rebuild.
    // @434b20
    virtual void RebuildLights(); // vtbl +0x48

    // THE ORBIT REBUILD (Ghidra: dwGuiViewBox_RebuildView — this class's
    // override of the +0x4c Refresh slot): viewMat = Build34(rot,
    // pivot + rot * (0, -orbitDistance, 0)); when bLightsFollowView, re-adds
    // the two base lights with their positions rotated by the new view
    // matrix (plain != 0 intensity test here, unlike the base's epsilon);
    // ends with virtual Invalidate. @4349c0
    virtual void Refresh(); // vtbl +0x4c

    // NEW virtual — appended after dwGui3DView's +0x4c Refresh.
    // Stores the angles (pitch first) and virtual-Refreshes. @4349a0
    // (recovered fn)
    virtual void SetAngles(float yaw, float pitch); // vtbl +0x50
};

// dwGuiImage — simple static-image widget: lazily loads a named image and
// blits it at the widget's top-left. Built by the dwGuiScreen factory for
// the IMAGE control keyword.
//
// Binary layout (sizeof 0x20): dwWidget base @0x00 + dwString filename@0x10
// + dwImage* pImage@0x1c. vtable @0x51f9e0.
struct dwGuiImage : dwWidget
{
    dwString filename; // 0x10: image file name (.BMP/.RLE)
    dwImage* pImage;   // 0x1c: lazily-loaded image object (NULL until
                       //       EnsureImages; dwImage_LoadFile is the P8 stub
                       //       for now, so this stays NULL — all uses guard)

    // Image widget covering *pRect showing pFilename (loaded immediately).
    // @434b50
    dwGuiImage(dwRect* pRect, char* pFilename);

    // FreeImages + filename release + base dtor. @434bf0 (DtorDelete @434bd0)
    virtual ~dwGuiImage();

    // Lazy-load the image when missing and the filename is non-empty.
    // @434c80 (Ghidra: dwGuiImage_EnsureLoaded)
    virtual void EnsureImages(); // vtbl +0x3c

    // Delete the image object (virtual dtor) and NULL it. @434cb0
    // (Ghidra: dwGuiImage_FreeImage)
    virtual void FreeImages(); // vtbl +0x40

    // Virtual EnsureImages, then blit the image at (left, top) clipped to
    // pClipRect. @434c50
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect); // vtbl +0x44
};

#endif // __cplusplus

#endif // _DWGUIVIEWBOX_H
