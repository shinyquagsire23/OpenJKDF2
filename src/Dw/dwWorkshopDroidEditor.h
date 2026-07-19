#ifndef _DWWORKSHOPDROIDEDITOR_H
#define _DWWORKSHOPDROIDEDITOR_H

// dwWorkshopDroidEditor — the workshop's DROID_EDITOR control: the main 3D
// droid-ASSEMBLY view where the player drags/attaches/detaches/paints parts
// onto the droid being built. Derives dwGuiViewBox (orbit 3D view) ->
// dwGui3DView -> dwWidget. Built only by dwWorkshop::CreateControl (keyword
// DROID_EDITOR, binary alloc 0x5b4). Operates on the shared assembled-droid
// workspace = the global dwPartNode list dwCore_pWorkspaceNodes (@0x53d984).
//
// Decompiled from DroidWorks.exe, unit range 0x40cea0-0x40eb5f.
// vtable @0x51e9b8 (dwWorkshopDroidEditor_vtbl).
// ⚠ EnsureImages@40eab0 / FreeImages@40eaf0 / ContainsPoint@40eb10 belong to
// THIS class (their old dwDroidStats Ghidra labels were wrong — the real
// dwDroidStats record class starts @40eb60).
//
// Binary layout (sizeof 0x5b4): dwGuiViewBox base @0x00 (0x560) + own fields
// from 0x560 (declared below in binary ORDER; 64-bit offsets differ).
//
// Key mechanics:
//  - Drag/attach: OnMouseDown picks a part via a CPU raycast
//    (RaycastPickNode) and detaches it from its slot (BeginDragOrDetach);
//    OnMouseMove drags it on the camera-facing plane through the grab point
//    (rdRaycast_RayPlane); OnMouseUp / a second click drops it
//    (DropDraggedPart): nearest COMPATIBLE free slot within 10 screen px
//    attaches (part-type compat = equal or the mirror pairs 1<->3 / 7<->8 /
//    2<->4), outside the view or over the trash rect destroys the subtree.
//  - Batteries (part type 9) are consumed on drop: FindBatteryTarget walks
//    the hit assembly for a node with battery capacity and adds the charge.
//  - Paint tool: PaintPickedPart re-renders the picked part unlit into the
//    PICK BUFFER (the canvas' second tVBuffer; cleared manually when the
//    global render option 0x100 didn't make rdAdvanceFrame do it — the DW
//    engine's rdAdvanceFrame also clears it, see rdRaycast.h notes), samples
//    the pixel under the cursor and recolors the contacted materials
//    (dwPartNode::CollectContacts).
//  - Draw renders all root/detached parts plus the attach-slot MARKERS
//    (dwGui3DView::DrawMarker squares, colors from dw_aPartSlotColors);
//    slots/mounts compatible with the dragged part BLINK at 500ms.
//
// Compiled as C++ (vtable, ctor/dtor pair, MSVC EH frames). C consumers see
// only the opaque typedef + the Startup shim.

#include "Dw/dwTypes.h"

#ifdef __cplusplus
struct dwWorkshopDroidEditor;
extern "C" {
#else
typedef struct dwWorkshopDroidEditor dwWorkshopDroidEditor; // C++ class; opaque in the C view
#endif

// Note: no binary counterpart — the unit owns no module statics; kept for the
// project-wide soft-reset convention (documented no-op).
void dwWorkshopDroidEditor_Startup(void);

#ifdef __cplusplus
} // extern "C"

#include "Dw/dwGuiViewBox.h"
#include "Dw/dwString.h"
#include "Dw/dwRect.h"

struct dwPartNode; // Dw/dwPart.h
struct dwImage;    // Dw/dwImage.h

struct dwWorkshopDroidEditor : dwGuiViewBox
{
    uint8_t bIdleAnims;      // 0x560: part idle anims running (msg 0x7d4 toggles)
    uint8_t bActiveAnims;    // 0x561: "dance"/active anim variant (msg 0x7e3)
    float yawSpinDelta;      // 0x564: camera yaw spin deg/sec (+/-90; 0 = idle)
    float yawSpinAccum;      // 0x568: seconds since the spin started
    float yawSpinStart;      // 0x56c: yaw when the spin started
    float pitchSpinDelta;    // 0x570: camera pitch spin deg/sec (+/-90; 0 = idle)
    float pitchSpinAccum;    // 0x574
    float pitchSpinStart;    // 0x578
    uint8_t bCursorActive;   // 0x57c: paint cursor armed (msg 0x7d3 sets / 0x7ea clears)
    uint8_t paintColorIdx;   // 0x57d: PALETTE color (msg 0x7d3 payload mapped
                             //        through the slot->palette table; 0 = none)
    rdVector3 dragGrab;      // 0x580: world-space grab point of the dragged part
    dwPartNode* pDraggedNode;// 0x58c: part being dragged (NULL = none)
    uint8_t bDragStarted;    // 0x590: 1 = fresh blueprint spawn (msg 0x7d1) —
                             //        follows the cursor until the NEXT click;
                             //        0 = press-drag-release pickup
    uint32_t dragTimerTick;  // 0x594: last blink flip (host ms tick)
    uint8_t bBlinkPhase;     // 0x598: compatible-marker blink phase (1 = shown)
    uint8_t bInTrashZone;    // 0x599: cursor over the trash rect while dragging
    dwRect trashRect;        // 0x59a: trash drop zone (ctor arg)
    dwString trashImageName; // 0x5a4: trash overlay image (ctor arg)
    dwImage* pTrashImage;    // 0x5b0: lazily loaded (P8 dwImage_LoadFile stub -> NULL for now)

    // @40cea0 (dwWorkshopDroidEditor_Ctor) — dwGuiViewBox(pRect, 1); copies
    // *pTrashRect, assigns the trash image name and EnsureImages()es.
    dwWorkshopDroidEditor(dwRect* pRect, dwRect* pTrashRect, char* pTrashImageName);

    // @40cf90 (dwWorkshopDroidEditor_Dtor; scalar-deleting wrapper @40cf70) —
    // FreeImages + trashImageName release (member dtor here), then base dtor.
    virtual ~dwWorkshopDroidEditor();

    // vtbl +0x04 @40e370 — while dragging: trash-zone tracking (plays
    // WOpenTrash.wav on enter/exit), then drag the part along the
    // camera-facing plane through dragGrab (rdRaycast_RayPlane). Returns
    // nonzero while dragging.
    virtual int OnMouseMove(int16_t x, int16_t y);
    // vtbl +0x08 @40e260 — dragging: drop (and release the capture); else
    // in-rect: paint (bCursorActive + color) or BeginDragOrDetach (captures
    // the mouse on success). Returns the in-rect/paint result.
    virtual int OnMouseDown(int16_t x, int16_t y);
    // vtbl +0x0c @40e310 — press-drag-release drop (only when NOT a fresh
    // blueprint spawn, bDragStarted == 0).
    virtual int OnMouseUp(int16_t x, int16_t y);
    // vtbl +0x14 @40cff0 — advance the yaw/pitch camera spins (re-dispatching
    // {0x3e9/0x3e8, angle} to the screen), FadeAnim every workspace part while
    // bIdleAnims (then broadcast {0x7d6} repaint), and flip the dragged-slot
    // blink phase every 500ms.
    virtual void Update(float dt);
    // vtbl +0x18 @40e510 — hover feedback: dispatches { 0x7531, code } with
    // code = 0x7d5 (trash rect) / 0x791d (near a free slot or mount) /
    // 0x7920 (over a part) / 0x791c (empty space). Returns 1.
    virtual int OnHover(int16_t x, int16_t y);
    // vtbl +0x1c @40d1e0 — the command sink (codes in dwWorkshopDroidEditor.cpp);
    // default falls through to dwGuiViewBox::OnMessage.
    virtual int OnMessage(dwWidgetMsg* pMsg);
    // vtbl +0x2c @40eb10 — while dragging, contains EVERYTHING (keeps the
    // mouse capture); else the plain rect test.
    virtual int ContainsPoint(dwPoint* pPt);
    // vtbl +0x3c @40eab0 — lazy pTrashImage load (NULL-guarded, P8 stub).
    virtual void EnsureImages();
    // vtbl +0x40 @40eaf0 — delete pTrashImage.
    virtual void FreeImages();
    // vtbl +0x44 @40e770 — base camera bring-up, manual pick-buffer clear,
    // trash overlay, all root/detached parts, then the slot/mount markers
    // (compat markers blink while dragging).
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);

    // -- non-virtual methods --------------------------------------------------

    // @40d180 — bIdleAnims = 1 and restart every workspace part's anim
    // (idle or active per bActiveAnims).
    void RefreshPartAnims();

    // @40d740 — cast a ray from the camera through the screen point at every
    // workspace part; returns the hit part (the hit record keeps improving,
    // so the LAST hit is the nearest) or NULL. pHit must be initialized
    // (pMesh/pFace NULL, distance FLT_MAX-ish).
    dwPartNode* RaycastPickNode(dwPoint* pPt, rdRaycastHit* pHit);

    // @40d7f0 — pick the part under pPt and start dragging it: TORSO parts
    // drag their parent assembly instead; LOCOMOTION parts detach their
    // TORSO children; anything else detaches itself (WPartDetach.wav).
    // Returns nonzero when a drag started.
    int BeginDragOrDetach(dwPoint* pPt);

    // @40d950 — drop the dragged part at pPt (see the class comment).
    void DropDraggedPart(dwPoint* pPt);

    // @40dfc0 — paint tool: render the picked part into the pick buffer,
    // sample the pixel under pPt, CollectContacts(color, paintColorIdx).
    // Returns nonzero when a part was under the cursor and a color is armed.
    int PaintPickedPart(dwPoint* pPt);
};

#endif // __cplusplus

#endif // _DWWORKSHOPDROIDEDITOR_H
