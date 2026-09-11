#ifndef _DWANIM_H
#define _DWANIM_H

// dwAnim — the DroidWorks animation WIDGET family (the widget half of the
// dwAnim compile unit, 0x401000-0x404010):
//
//   dwAnimBase    (0x1c, vtbl 0x51e1d0, ctor @4038f0) — message-triggered
//                 animation base: dwWidget + bPlaying/msgCode/bLoop and TWO
//                 NEW virtuals appended after dwWidget's +0x44 Draw:
//                 +0x48 Play() / +0x4c Stop(). OnMessage toggles them when
//                 pMsg->code == msgCode; Stop() broadcasts a 0x2328
//                 "anim finished" widget message. Also derived by
//                 dwWcMaterials + dwGuiBriefText (other units).
//   dwAnim        (0x40, vtbl 0x51e000, ctor @401000) — the FLC widget
//                 player: loads every frame of a .FLC up front into an array
//                 of engine RLE bitmap images (EnsureImages/EnsureLoaded),
//                 advances curFrame at fps in Update, blits the current
//                 frame in Draw. dwHelp (P5) derives it.
//   dwGuiAnimView (0x54, MI vtbls 0x51e180 primary / 0x51e138 group, ctor
//                 @402cf0) — the reference-room animation VIEWER: REAL
//                 MSVC multiple inheritance dwAnimBase + dwWidgetGroup,
//                 hosting an optional still image, a dwAnim player and a
//                 list of {animFile, code, imageFile} items swapped in by
//                 GUI messages (0x1b62 play / 0x1b63 stop). Built by
//                 dwGuiReference_BuildAnimViewer.
//
// The segment half of the unit (dwAnimSeg/dwFlicSeg/dwSmushSeg/dwMovie +
// SMUSH glue) lives in Dw/dwMovie.h. The mis-binned rdKeyframe helpers live
// in Dw/dwKeyframe.h. The dwWidget/dwWidgetGroup/dwSegment base-default
// bodies also physically located in this unit's range were translated with
// their owning P3 units — not here.
//
// No module statics in the widget half — no dwAnim_Startup needed (the
// segment half's statics are reset by dwMovie_Startup, see dwMovie.h).

#include "Dw/dwTypes.h"
#include "Dw/dwRect.h"

#ifdef __cplusplus
struct dwAnimBase;
struct dwAnim;
struct dwGuiAnimView;
extern "C" {
#else
// C++ classes; opaque in the C view.
typedef struct dwAnimBase dwAnimBase;
typedef struct dwAnim dwAnim;
typedef struct dwGuiAnimView dwGuiAnimView;
#endif

// (no C-callable entry points in the widget half — section kept for symmetry)

#ifdef __cplusplus
} // extern "C"

#include "Dw/dwWidget.h"
#include "Dw/dwWidgetGroup.h"
#include "Dw/dwList.h"
#include "Dw/dwString.h"
#include "Dw/dwImage.h"

// ---- dwAnimBase -------------------------------------------------------------
//
// Binary layout: dwWidget base @0x00 (0xe) + bPlaying@0x10 + msgCode@0x14 +
// bLoop@0x18 — sizeof 0x1c. vtable @0x51e1d0 (dwAnimBase_vtbl): overrides
// only OnMessage and appends the two new slots.

struct dwAnimBase : dwWidget
{
    uint8_t bPlaying; // 0x10: currently playing (gates Update/Draw in subclasses)
    int32_t msgCode;  // 0x14: widget-message code that toggles this anim
    uint8_t bLoop;    // 0x18: 0 -> play once (dwAnim::Update calls virtual Stop at the end)

    // @4038f0 (dwAnimBase_Ctor) — dwWidget(pRect); bPlaying = 0.
    dwAnimBase(dwRect* pRect, int msgCode, uint8_t bLoop);

    // @403940 (dwAnimBase_Dtor; scalar-deleting wrapper @403920) — body is
    // just the vptr re-point + dwWidget base dtor (implicit here).
    virtual ~dwAnimBase();

    // vtbl +0x1c @403950 — when pMsg->code == msgCode: toggle (bPlaying ->
    // virtual Stop, else virtual Play). Always returns 0 (unhandled — the
    // message keeps broadcasting to other widgets).
    virtual int OnMessage(dwWidgetMsg* pMsg);

    // NEW virtuals — appended after dwWidget's +0x44 Draw, in slot order.
    // vtbl +0x48 @403980 (dwAnimBase_Play) — bPlaying = 1; Invalidate().
    virtual void Play();
    // vtbl +0x4c @403990 (dwAnimBase_Stop) — if playing: bPlaying = 0;
    // Invalidate(); dispatch { 0x2328, (void*)msgCode, 0, NULL } to
    // dwWidget_pDefault ("anim finished" notification).
    virtual void Stop();
};

// ---- dwAnim -------------------------------------------------------------------
//
// Binary layout: dwAnimBase @0x00 + fps@0x1c + accumTimeSec@0x20 +
// frameCount@0x24 + curFrame@0x28 + pFrames@0x2c + filename dwString@0x30 +
// bUpdatedThisFrame@0x3c — sizeof 0x40. vtable @0x51e000 (dwAnim_vtbl):
// overrides Update / EnsureImages / FreeImages / Draw; Play/Stop stay the
// dwAnimBase bases.

struct dwAnim : dwAnimBase
{
    float fps;                 // 0x1c: playback rate (15.0 from dwAnim_Open)
    float accumTimeSec;        // 0x20: accumulated play time (sec)
    uint32_t frameCount;       // 0x24: frames decoded from the FLC
    uint32_t curFrame;         // 0x28
    dwImage** paFrames;        // 0x2c (Ghidra: pFrames): frameCount images, each frame
                               //      fully decoded (delta frames baked onto the previous)
    dwString filename;         // 0x30: .FLC name (resolved through the DW VFS on open)
    uint8_t bUpdatedThisFrame; // 0x3c: set by Play(arg) to skip the next Update tick
                               //      (Update clears it unconditionally)

    // @401000 (dwAnim_Ctor) — stores fps, zeroes frameCount/paFrames, and if
    // pFilename is non-NULL assigns it and calls EnsureImages() immediately
    // (frames are loaded in the ctor).
    // Note: the binary leaves accumTimeSec/curFrame/bUpdatedThisFrame
    // uninitialized until Play()/EnsureImages(); zero-initialized here.
    dwAnim(dwRect* pRect, const char* pFilename, int msgCode, uint8_t bLoop, float fps);

    // @4010c0 (dwAnim_Dtor; scalar-deleting wrapper @4010a0) — FreeFrames +
    // filename free (the latter implicit here).
    virtual ~dwAnim();

    // vtbl +0x14 @401120 (dwAnim_Update) — if playing and not flagged
    // bUpdatedThisFrame: accumTimeSec += dt; frame = (int)(fps * accumTimeSec);
    // past the end -> loop (mod) or virtual Stop() (play-once); on a frame
    // change: curFrame = frame, Invalidate(). Always clears bUpdatedThisFrame.
    virtual void Update(float dt);

    // vtbl +0x3c @401200 (Ghidra: dwAnim_EnsureLoaded — the EnsureImages
    // slot). Decodes EVERY frame of the FLC up front: frame 0 into a fresh
    // stdBitmapRle2 image, each later frame into a COPY of the previous
    // frame's image (so FLC deltas accumulate). No-op when already loaded or
    // no filename.
    virtual void EnsureImages();

    // vtbl +0x40 @4013c0 (Ghidra: dwAnim_FreeFrames — the FreeImages slot).
    // Deletes every frame image + the frame array.
    virtual void FreeImages();

    // vtbl +0x44 @4011c0 (dwAnim_Draw) — if playing: EnsureImages(), then
    // blit paFrames[curFrame] at (left, top) clipped to pClipRect.
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);

    // Non-virtual Play OVERLOAD (@401190, Ghidra: dwAnim_Play — distinct from
    // the +0x48 virtual dwAnimBase_Play, which stays un-overridden in the
    // dwAnim vtable): EnsureImages(); bUpdatedThisFrame = bSkipUpdate; and if
    // frames are loaded: curFrame = 0, accumTimeSec = 0, dwAnimBase::Play().
    using dwAnimBase::Play; // keep the virtual Play() visible next to the overload
    void Play(uint8_t bSkipUpdate);
};

// @4037f0 (dwAnim_Open) — factory used by the GUI layer: dispatch on the
// filename extension (case-insensitive). "FLC"/"FLI" -> new dwAnim(pRect,
// pFilename, msgCode, bLoop, 15.0f). "SAN" is compared but its result is
// DISCARDED (binary quirk — .san widget anims fall through to failure). On
// any failure logs "Error opening animation: %s" and returns NULL.
dwAnim* dwAnim_Open(dwRect* pRect, char* pFilename, int msgCode, uint8_t bLoop);

// ---- dwGuiAnimView ---------------------------------------------------------------
//
// Binary layout: dwAnimBase @0x00 (primary) + dwWidgetGroup @0x1c (secondary
// MI base) + own fields from 0x30 — sizeof 0x54. vtables: primary
// dwGuiAnimView_vtbl @0x51e180 (dwAnimBase shape), secondary
// dwGuiAnimView_scn_vtbl @0x51e138 (dwWidgetGroup shape; Dtor/Update/OnHover/
// OnMessage/EnsureImages/FreeImages/Draw slots are this-adjustor thunks
// @403780-4037e0 into the primary overrides, everything else keeps the
// dwWidgetGroup implementations). Real C++ MI reproduces both vtables +
// thunks exactly.

// One selectable animation entry (0x2c in the binary; built by AddItem,
// destroyed by @4036b0 dwGuiAnimView_ItemDtor / @403690 _ItemDtorDelete).
struct dwGuiAnimViewItem
{
    dwString animFile;  // 0x00: .FLC to play when selected
    int32_t code;       // 0x0c: widget-message code that selects this item
    uint8_t flag;       // 0x10: stored by AddItem, never read in this unit
    dwString imageFile; // 0x14: optional still image swapped in when selected
    dwString extraFile; // 0x20: stored by AddItem, never read in this unit
                        //       (kept for the dwGuiReference caller)

    dwGuiAnimViewItem(const char* pAnimFile, int code, uint8_t flag,
                      const char* pImageFile, const char* pExtraFile);
};

struct dwGuiAnimView : dwAnimBase, dwWidgetGroup
{
    dwList items;         // 0x30 (Ghidra: pItems): dwGuiAnimViewItem* payloads
    dwImage* pImage;      // 0x34: current still image (or NULL)
    int32_t itemCode;     // 0x38: hover-notification payload (see OnHover)
    dwString filename;    // 0x3c: current still-image filename
    uint32_t itemCount;   // 0x48 (Ghidra: field_0x48)
    uint8_t bAnimStarted; // 0x4c: an item has been explicitly selected
    dwAnim* pAnimPlayer;  // 0x50: current player (or NULL)

    // @402cf0 (dwGuiAnimView_Ctor) — dwAnimBase(pRect, 0, 1) +
    // dwWidgetGroup(pRect); assigns the still-image filename and calls
    // EnsureImages() immediately.
    dwGuiAnimView(dwRect* pRect, const char* pImageFilename, int itemCode);

    // @402dd0 (dwGuiAnimView_Dtor; primary DtorDelete @402db0, group-vtbl
    // thunk @403780) — FreeImages, delete player + image, free every item +
    // list node; group children/filename/base teardown implicit.
    virtual ~dwGuiAnimView();

    // vtbl +0x14 @403450 (group thunk @403790) — tick the player (when
    // enabled), then the group children.
    virtual void Update(float dt);

    // vtbl +0x18 @4032c0 (group thunk @4037a0) — dispatch { 0x7531,
    // (void*)itemCode } to dwWidget_pDefault; return 1.
    virtual int OnHover(int16_t x, int16_t y);

    // vtbl +0x1c @403050 (group thunk @4037b0) — select the item whose code
    // == pMsg->code (stop+delete the old player, swap the still image, open
    // the item's anim); 0x1b62 = play (auto-selecting the first item when
    // nothing was selected and itemCount > 1), 0x1b63 = stop. Chains to
    // dwAnimBase::OnMessage.
    virtual int OnMessage(dwWidgetMsg* pMsg);

    // vtbl +0x3c @403500 (group thunk @4037c0) — lazy-load the still image,
    // forward to the player and the group children.
    virtual void EnsureImages();

    // vtbl +0x40 @403540 (group thunk @4037d0) — drop the still image,
    // forward to the player and the group children.
    virtual void FreeImages();

    // vtbl +0x44 @403480 (group thunk @4037e0) — when enabled: EnsureImages,
    // blit the still image at the GROUP rect origin, draw the player as a
    // child (clip rect additionally clipped to the player rect); always
    // draws the group children on top.
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);

    // @4031f0 (dwGuiAnimView_AddItem) — append a dwGuiAnimViewItem; itemCount++.
    void AddItem(const char* pAnimFile, int code, uint8_t flag,
                 const char* pImageFile, const char* pExtraFile);

    // @4032f0 (dwGuiAnimView_AddHypTextChild) — build a dwGuiHypText child at
    // (pos, size) relative to the group rect and push-front it onto the group
    // children (un-stubbed once the dwGuiHypText unit landed, P4).
    void AddHypTextChild(char* pText, dwPoint pos, dwPoint size, int param_4, int param_5);

    // @4033d0 (dwGuiAnimView_InitFirstFrame) — preload the FIRST item's still
    // image, and when it is the ONLY item also open its anim player (so
    // single-anim views show frame 0 before any message arrives).
    void InitFirstFrame();
};

#endif // __cplusplus

#endif // _DWANIM_H
