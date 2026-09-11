#ifndef _DWHELP_H
#define _DWHELP_H

// dwHelp — the animated HELP-droid speech/hint control (keyword "HELP"), plus
// the blinking dwGuiIndicator status widget (keyword "INDICATOR"):
//
//   dwHelp        (0x5c, vtbl 0x51ed50, ctor @418af0) — dwAnim subclass: an
//                 FLC "help droid" whose mouth flaps while it plays a voice
//                 line. PlaySpeech maps (speakerCode, msgCode) to a wav via a
//                 giant per-speaker table and plays it (through dwSound, or
//                 through the in-game HUD when speakerCode == 0x6b/player).
//                 speechDelay auto-advances to the idle line; StopSpeech
//                 stops the sound and resumes the idle anim frame. Built by
//                 every screen factory's CreateControl.
//   dwGuiIndicator(0x48, vtbl 0x51edc8, ctor @4197b0) — dwWidget subclass:
//                 a two-image status light. pImage1 is always drawn, clipped
//                 to a progress-reveal rect (wipe along the widget's long
//                 axis); pImage2 overlays it while active AND on the visible
//                 blink phase (0.5s toggle). Built ONLY by
//                 dwGuiScreen_CreateControl@0x43045f.
//
// Decompiled from DroidWorks.exe, unit range 0x418af0-0x419ba0. Verifiably C++
// (vtables, ctor/dtor pairs, MSVC EH frames) -> C++ classes.
//
// This unit OWNS the dwGuiIndicator_*/dwHelp_Ctor cross-unit shims that were
// placeholder-stubbed in dwMain.c (dwGuiInGame HUD + screen factories call
// them). The real bodies live in dwHelp.cpp.
//
// No module statics — no dwHelp_Startup needed (soft-reset rule).

#include "Dw/dwTypes.h"
#include "Dw/dwRect.h"

#ifdef __cplusplus
struct dwHelp;
struct dwGuiIndicator;
extern "C" {
#else
// C++ classes; opaque in the C view.
typedef struct dwHelp dwHelp;
typedef struct dwGuiIndicator dwGuiIndicator;
typedef struct dwRect dwRect;
#endif

// ---- C-linkage shims (own the ex-dwMain.c placeholders) ---------------------
// dwGuiInGame's HUD drives the indicator by name through these; dwGuiScreen /
// dwWorkshop / dwGuiMission factories build a dwHelp via dwHelp_Ctor.

// @4197b0 (dwGuiIndicator_Ctor) — placement-ctor a dwGuiIndicator (the caller
// idk_alloc(0x48)'d it). pImage1Name/pImage2Name are the two status images,
// code is an external tag, progress0 seeds the reveal wipe.
dwGuiIndicator* dwGuiIndicator_Ctor(dwGuiIndicator* pThis, dwRect* pRect,
                                    char* pImage1Name, char* pImage2Name,
                                    int code, float progress0);
// @419910 — set the reveal fraction [0,1] and repaint on change.
void dwGuiIndicator_SetProgress(dwGuiIndicator* pInd, float progress);
// @419a30 — begin the blink (active). @419a50 — stop it (idle).
void dwGuiIndicator_Show(dwGuiIndicator* pInd);
void dwGuiIndicator_Hide(dwGuiIndicator* pInd);

// @418af0 (dwHelp_Ctor) — placement-ctor a dwHelp (the caller idk_alloc(0x5c)'d
// it). pAnimName is the mouth-flap FLC; speakerCode selects the wav prefix
// family in PlaySpeech.
dwHelp* dwHelp_Ctor(dwHelp* pThis, dwRect* pRect, char* pAnimName, int speakerCode);

#ifdef __cplusplus
} // extern "C"

#include "Dw/dwAnim.h"    // dwAnim base (dwHelp)
#include "Dw/dwWidget.h"  // dwWidget base (dwGuiIndicator)
#include "Dw/dwString.h"
#include "Dw/dwImage.h"

// ---- dwHelp -----------------------------------------------------------------
//
// Binary layout: dwAnim base @0x00 (0x40) + bAutoAdvance@0x40 +
// speechDelay@0x44 + currentWav dwString@0x48 + speakerCode@0x54 +
// savedAnimFrame@0x58 — sizeof 0x5c. vtable @0x51ed50 (dwHelp_vtbl): overrides
// dtor/OnKey/Update/OnHover/OnMessage; PlaySpeech/StopSpeech are non-virtual.

struct dwHelp : dwAnim
{
    uint8_t bAutoAdvance;  // 0x40: PlaySpeech armed the auto-advance-to-idle line
    float speechDelay;     // 0x44: Update counts this down (>0) then auto-plays
                           //       code 0; -1 = disarmed
    dwString currentWav;   // 0x48: currently-playing wav name (empty = idle)
    int32_t speakerCode;   // 0x54: wav-prefix selector (100 HPCP / 0x66 MMCP /
                           //       0x68 LSCP / 0x6a RHCP / 0x6c SSCA / 0x6b player)
    int32_t savedAnimFrame;// 0x58: idle-anim resume frame saved by StopSpeech

    // @418af0 — dwAnim(pRect, pAnimName, /*msgCode*/0, /*bLoop*/1, /*fps*/15.0);
    // speechDelay = -1; speakerCode = a2.
    dwHelp(dwRect* pRect, char* pAnimName, int speakerCode);

    // @418b90 (dwHelp_Dtor; scalar-deleting wrapper @418b70) — StopSpeech +
    // currentWav free (implicit) + dwAnim base dtor.
    virtual ~dwHelp();

    // vtbl +0x10 @418bf0 — Esc stops the current speech. Returns 0.
    virtual int OnKey(int key, int repeat);

    // vtbl +0x14 @418c10 — when idle and speechDelay > 0: count it down and,
    // on reaching 0, PlaySpeech(0, 1); then tick the dwAnim mouth flap.
    virtual void Update(float dt);

    // vtbl +0x18 @4196d0 — consume the hover (returns 1).
    virtual int OnHover(int16_t x, int16_t y);

    // vtbl +0x1c @419700 — 0x7531 play(msgCode, var); 0x7530 idle line (code 0
    // when idle); 0x7532/0x2329 stop; else dwAnimBase::OnMessage. Returns
    // 1 when handled.
    virtual int OnMessage(dwWidgetMsg* pMsg);

    // -- non-virtual methods --------------------------------------------------

    // @418c70 — look msgCode up in speakerCode's wav table, then StopSpeech +
    // play the resulting "%s.wav" (via dwSound, or the HUD for the player
    // speaker) and resume the idle anim frame. Some codes trigger side effects
    // (cursor precache, dwPlayer_statsFlags bits) instead of a wav. Returns 1
    // when a wav actually started.
    char PlaySpeech(unsigned int msgCode, int var);

    // @419610 — stop the playing wav (or notify the HUD), restore + freeze the
    // idle anim frame, clear currentWav.
    void StopSpeech();
};

// ---- dwGuiIndicator ---------------------------------------------------------
//
// Binary layout: dwWidget base @0x00 (0xe) + pImage1@0x10 + imageName1 dwString
// @0x14 + pImage2@0x20 + imageName2 dwString@0x24 + clipLeft/Top/Right/Bottom
// (int16)@0x30..0x36 + progress@0x38 + code@0x3c + bActive@0x40 +
// bBlinkPhase@0x41 + blinkTimer@0x44 — sizeof 0x48. vtable @0x51edc8
// (dwGuiIndicator_vtbl): overrides Update/OnHover/Draw + EnsureImages/
// FreeImages; OnMessage is the shared dwWidget default.

struct dwGuiIndicator : dwWidget
{
    dwImage* pImage1;     // 0x10: base image (always drawn, reveal-clipped)
    dwString imageName1;  // 0x14
    dwImage* pImage2;     // 0x20: overlay image (drawn on the visible blink)
    dwString imageName2;  // 0x24
    int16_t clipLeft;     // 0x30: reveal rect (recomputed by SetProgress)
    int16_t clipTop;      // 0x32
    int16_t clipRight;    // 0x34
    int16_t clipBottom;   // 0x36
    float progress;       // 0x38: reveal fraction [0,1]
    int32_t code;         // 0x3c: external id/tag (set only, not read here)
    uint8_t bActive;      // 0x40: blink running
    uint8_t bBlinkPhase;  // 0x41: current blink phase (overlay visible)
    float blinkTimer;     // 0x44: seconds into the current 0.5s blink phase

    // @4197b0 — dwWidget(pRect); progress = 1.0; code = a3; not active; the
    // reveal rect = the full widget rect (SetProgress(progress0) then refines
    // it), assigns both image names + EnsureImages().
    dwGuiIndicator(dwRect* pRect, char* pImage1Name, char* pImage2Name,
                   int code, float progress0);

    // @4198a0 (dwGuiIndicator_Dtor; scalar-deleting wrapper @419880) —
    // FreeImages + both string frees (member dtors) + dwWidget base dtor.
    virtual ~dwGuiIndicator();

    // vtbl +0x14 @419a70 — while active: toggle bBlinkPhase every 0.5s and
    // repaint on a phase change.
    virtual void Update(float dt);

    // vtbl +0x18 @419a00 — consume the hover (returns 1).
    virtual int OnHover(int16_t x, int16_t y);

    // vtbl +0x3c @419b50 — lazy-load pImage1/pImage2 from their names.
    virtual void EnsureImages();

    // vtbl +0x40 @419ba0 — delete both images.
    virtual void FreeImages();

    // vtbl +0x44 @419ad0 — EnsureImages, overlay pImage2 (blink), then blit
    // pImage1 clipped to the reveal rect.
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);

    // -- non-virtual methods --------------------------------------------------

    // @419910 — clamp progress to [0,1]; on change, recompute the reveal rect
    // (wipe up from the bottom when taller than wide, else right from the left)
    // and repaint.
    void SetProgress(float progress);
    // @419a30 — begin blinking (active + overlay visible + 0.5s timer).
    void Show();
    // @419a50 — stop blinking (idle).
    void Hide();
};

#endif // __cplusplus

#endif // _DWHELP_H
