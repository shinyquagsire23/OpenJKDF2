#ifndef _DWMOVIE_H
#define _DWMOVIE_H

// dwMovie — the DroidWorks full-screen movie SEGMENT family (the segment
// half of the dwAnim compile unit, 0x401000-0x404010):
//
//   dwAnimSeg  (0x28, vtbl 0x51e108, ctor @402b50) — abstract media-segment
//              base: dwSegment + bPlaying + a per-subclass context pointer +
//              the movie filename; installs a window-message handler on
//              Activate so ESC skips the movie (dwSegment_RequestAdvance),
//              and its Update requests the advance once bPlaying drops.
//   dwFlicSeg  (0x3cc, vtbl 0x51e050, ctor @401410) — full-screen FLC movie:
//              embeds a dwFlic decode context BY VALUE and decodes frames
//              straight into dwDisplay_pScreenImage at 15 fps, optionally
//              compositing over an overlay dwImage (color-0 pixels show the
//              overlay). FULLY FUNCTIONAL (dwFlic is translated).
//   dwSmushSeg (0x28, vtbl 0x51e070, ctor @401900) — SMUSH .san movie base:
//              resolves the filename through the DW VFS and drives the
//              SmushPlay/LECSmush player with the dwSmushVid_*/dwSmushAud_*
//              callbacks. PLAYBACK IS STUBBED (SMUSH policy, see
//              DW/DECOMP_PROGRESS.md "Architecture decisions"): Activate
//              takes the binary's open-failure path, so the segment
//              finishes immediately on its next Update.
//   dwMovie    (0x40, vtbl 0x51e0a0, ctor @4023c0) — concrete .san player:
//              dwSmushSeg + a full-screen dwWidgetGroup OVERLAY drawn over
//              every presented frame (subtitles/skip prompts) via the NEW
//              +0x18 virtual Draw called from the dwMovie_VidPresent
//              callback. dwEnding, dwGuiOpening and dwMissionTransIn/Out
//              (later units) derive it. Active instance: dwMovie_pActive.
//
// The widget half of the unit lives in Dw/dwAnim.h.

#include "Dw/dwTypes.h"
#include "Dw/dwRect.h"
#include "Dw/dwImage.h" // dwImageBits (plain-C struct)

#ifdef __cplusplus
struct dwAnimSeg;
struct dwFlicSeg;
struct dwSmushSeg;
struct dwMovie;
extern "C" {
#else
// C++ classes; opaque in the C view.
typedef struct dwAnimSeg dwAnimSeg;
typedef struct dwFlicSeg dwFlicSeg;
typedef struct dwSmushSeg dwSmushSeg;
typedef struct dwMovie dwMovie;
#endif

// ---- module globals ---------------------------------------------------------

// The dwMovie currently activated (NULL outside playback); read by the
// dwMovie_VidPresent SMUSH callback. Binary: 0x53d6b0.
extern dwMovie* dwMovie_pActive;

// Set by dwAnim_SmushStartup, cleared by dwAnim_SmushShutdown. Binary global
// dwAnim_bSmushInitted (in the stub it just tracks the Startup/Shutdown pair).
extern int dwAnim_bSmushInitted;

// ---- C-callable API ----------------------------------------------------------

// Note: no binary counterpart — resets this module's statics
// (dwMovie_pActive, dwAnim_bSmushInitted, the lecSmush present-disable flag)
// for OpenJKDF2's soft-reset loop. Call from dwMain_Startup.
void dwMovie_Startup(void);

// @402af0 (dwAnim_SmushStartup) — original: LECSmush_Initialize(pHS, 0) +
// SmushPlay_Initialize(pHS, 0) + LECSmush_SysStartup() +
// SmushPlay_SysStartup(), returning 1 only if all four succeed. STUBBED
// (SMUSH policy): logs once, sets dwAnim_bSmushInitted and returns 1 so the
// boot flow (StartOpeningCutscenes @41b5de) proceeds.
int dwAnim_SmushStartup(void* pHS);

// @402b30 (dwAnim_SmushShutdown) — original: smushPlay/lecSmush system
// shutdown x4. STUBBED: clears dwAnim_bSmushInitted.
void dwAnim_SmushShutdown(void);

// ---- SMUSH player callbacks (ALL STUBBED — SMUSH policy) ----------------------
//
// These are the video/audio callback tables the binary handed to SmushPlay
// (smushPlay_sub_43D080 video / smushPlay_sub_43D060 audio); jkSmack drives
// the same audio set. Signatures preserved for the future P8 wiring; each
// stub is a LOUD no-op. The per-callback original behavior is documented at
// the definitions in dwMovie.cpp.

int dwSmushVid_Open(uint32_t* pCtx, uint32_t* pOut);                    // @401b90
int dwSmushVid_Close(void);                                            // @401bf0
int dwSmushVid_Clear(void);                                            // @401c10
int dwSmushVid_SetPalette(uint8_t* pEntriesRGBX, int start, int count); // @401c60
int dwSmushAud_Open(int samplesPerFrame, int numChannels, int bitsPerSample, uint32_t* pCtx); // @401cd0
int dwSmushAud_Close(uint32_t* pCtx);                                   // @401fa0
uint32_t dwSmushAud_GetTime(void* pCtx);                                // @401fe0
int dwSmushAud_Stop(void* pCtx);                                        // @402160
int dwSmushAud_Play(void* pCtx);                                        // @402190
void dwSmushAud_Service(void* pCtx);                                    // @4021e0

// The dwMovie frame-present callback (replaces dwSmushVid_Close's slot in
// the video table while a dwMovie is active): unlocks the SMUSH target
// (back) buffer, draws dwMovie_pActive's overlay onto the screen image over
// the just-decoded frame rect, and flips. pFrameRect is the decoded frame's
// {x, y, width, height}. Kept functional (it only touches translated
// pieces), though nothing calls it until SMUSH lands (P8). @4026b0
int dwMovie_VidPresent(rdRect* pFrameRect);

#ifdef __cplusplus
} // extern "C"

#include "Dw/dwSegment.h"
#include "Dw/dwString.h"
#include "Dw/dwWidgetGroup.h"
#include "Dw/dwFlic.h"

// ---- dwAnimSeg -------------------------------------------------------------
//
// Binary layout: dwSegment @0x00 (0x14) + pCallbacks@0x14 + bPlaying@0x18 +
// bKeyHandlerInstalled@0x19 + filename dwString@0x1c — sizeof 0x28. vtable
// @0x51e108 (dwAnimSeg_vtbl, 6 slots — pins the dwSegment slot count).

struct dwAnimSeg : dwSegment
{
    void* pCallbacks;             // 0x14 (Ghidra name): per-subclass context —
                                  //   dwFlicSeg stores the overlay dwImage* here;
                                  //   dwSmushSeg/dwMovie pass NULL
    uint8_t bPlaying;             // 0x18: 0 -> Update requests the segment advance
    uint8_t bKeyHandlerInstalled; // 0x19 (Ghidra: field_0x19): ESC handler is live
    dwString filename;            // 0x1c: movie filename

    // @402b50 (dwAnimSeg_Ctor)
    dwAnimSeg(const char* pFilename, void* pCallbacks);

    // vtbl +0x00 @402c20 (dwAnimSeg_OnActivate) — install the ESC key
    // handler, bPlaying = 1, unpause the segment clock, hide the cursor
    // (dwCursor_SetCursor(0)); returns 1.
    virtual int Activate();
    // vtbl +0x04 @402c50 (dwAnimSeg_OnDeactivate) — remove the ESC handler
    // if installed.
    virtual void Deactivate();
    // (vtbl +0x08/+0x0c keep the dwSegment Suspend/Resume bases.)
    // vtbl +0x10 @402c70 (dwAnimSeg_Update) — when bPlaying == 0:
    // dwSegment_RequestAdvance().
    virtual void Update();
    // vtbl +0x14 @402bd0 (dwAnimSeg_Dtor; scalar-deleting wrapper @402bb0).
    virtual ~dwAnimSeg();
};

// The ESC-skip window-message handler (WindowHandler_t; installed by
// dwAnimSeg::Activate): WM_KEYDOWN + VK_ESCAPE -> dwSegment_RequestAdvance.
// Always returns 0 with *pResult = 0 (message not consumed). @402c80
extern "C" int dwAnimSeg_KeyMsgHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, LRESULT* pResult);

// ---- dwFlicSeg -------------------------------------------------------------
//
// Binary layout: dwAnimSeg @0x00 + dwFlic movie@0x28 BY VALUE + curFrame@
// 0x3c8 — sizeof 0x3cc. vtable @0x51e050: overrides Activate/Deactivate/
// Update.

struct dwFlicSeg : dwAnimSeg
{
    dwFlic movie;      // 0x28: FLC decode context (embedded)
    uint32_t curFrame; // 0x3c8: frames shown (lags movie.curFrame by one)

    // @401410 (dwFlicSeg_Ctor) — pOverlayImage (may be NULL) lands in
    // pCallbacks: pixels that decode to color 0 show this image instead.
    dwFlicSeg(const char* pFilename, dwImage* pOverlayImage);

    // vtbl +0x14 @401460 (dwFlicSeg_Dtor; scalar-deleting wrapper @401440).
    virtual ~dwFlicSeg();

    // vtbl +0x00 @401470 (dwFlicSeg_OnActivate) — open the FLC, base
    // Activate, decode + present the first frame.
    virtual int Activate();
    // vtbl +0x04 @401620 (dwFlicSeg_OnDeactivate) — close the FLC when it
    // was playing, then the base Deactivate.
    virtual void Deactivate();
    // vtbl +0x10 @401640 (dwFlicSeg_Update) — while playing and unpaused:
    // when GetElapsed()*15 has passed curFrame, decode the next frame into
    // the screen image (with overlay compositing) and present; bPlaying
    // drops when the decoder reaches numFrames. Calls the base Update both
    // BEFORE and AFTER (faithful binary quirk).
    virtual void Update();
};

// ---- dwSmushSeg -------------------------------------------------------------
//
// Binary layout: dwAnimSeg alias (no own fields) — sizeof 0x28. vtable
// @0x51e070: overrides all six slots.

struct dwSmushSeg : dwAnimSeg
{
    // @401900 (dwSmushSeg_Ctor) — base ctor, then re-resolves pFilename
    // through the DW VFS (inits_ResolveAndOpen) into this->filename so the
    // external SMUSH library can open it with plain OS I/O; the probe handle
    // is closed immediately. On resolve failure filename becomes "" (which
    // is what makes Activate bail).
    dwSmushSeg(const char* pFilename, void* pCallbacks);

    // vtbl +0x14 @4019a0 (dwSmushSeg_Dtor; scalar-deleting wrapper @401980).
    virtual ~dwSmushSeg();

    // vtbl +0x00 @4019b0 (dwSmushSeg_OnActivate) — STUBBED: the original
    // installed the dwSmushVid_*/dwSmushAud_* callback tables, set the
    // SMUSH volume from dw_settingSoundVol and opened the .san via
    // SmushPlay (smushPlay_sub_43D0A0(path, 0, 1000000, 640, 480)), calling
    // the base Activate only on success. The stub takes the open-failure
    // path: bPlaying stays 0 (next Update requests the advance), returns 0.
    virtual int Activate();
    // vtbl +0x04 @401ad0 (dwSmushSeg_OnDeactivate) — original closed the
    // SmushPlay session when bPlaying; then base Deactivate (kept).
    virtual void Deactivate();
    // vtbl +0x08 @401af0 (Ghidra: dwSmushSeg_Pause — the Suspend slot) —
    // original paused LECSmush first and only then suspended the clock.
    virtual void Suspend();
    // vtbl +0x0c @401b20 (Ghidra: dwSmushSeg_Resume) — mirror of Suspend.
    virtual void Resume();
    // vtbl +0x10 @401b50 (dwSmushSeg_Update) — base Update; original then
    // serviced SmushPlay and dropped bPlaying when the movie reported done.
    virtual void Update();
};

// ---- dwMovie -------------------------------------------------------------------
//
// Binary layout: dwSmushSeg @0x00 + lastOverlayTimeSec@0x28 + dwWidgetGroup
// overlay@0x2c BY VALUE — sizeof 0x40. vtable @0x51e0a0 (7 slots): overrides
// Activate/Deactivate/Update and APPENDS the +0x18 Draw virtual.

struct dwMovie : dwSmushSeg
{
    float lastOverlayTimeSec; // 0x28 (Ghidra: field_0x28): clock time of the
                              //      last overlay Update tick
    dwWidgetGroup overlay;    // 0x2c: full-screen overlay widgets, drawn over
                              //      each presented frame

    // @4023c0 (dwMovie_Ctor) — dwSmushSeg(pFilename, NULL) + default
    // (full-screen) overlay group.
    // Note: lastOverlayTimeSec is uninitialized in the binary until
    // Activate; zero-initialized here.
    dwMovie(const char* pFilename);

    // vtbl +0x14 @402440 (dwMovie_Dtor; scalar-deleting wrapper @402420) —
    // overlay teardown + base dtors, all implicit.
    virtual ~dwMovie();

    // vtbl +0x00 @402580 (dwMovie_OnActivate) — base Activate; the original
    // then swapped the video callback table's present slot for
    // dwMovie_VidPresent (stubbed with the rest of SMUSH); sets
    // dwMovie_pActive = this and latches lastOverlayTimeSec = GetElapsed().
    virtual int Activate();
    // vtbl +0x04 @4025f0 (dwMovie_OnDeactivate) — base Deactivate; clears
    // dwMovie_pActive when it is this movie.
    virtual void Deactivate();
    // vtbl +0x10 @402610 (dwMovie_Update) — throttled overlay tick: when
    // more than 0.022 s of clock advanced since the last tick (deltas
    // <= 1e-5 s snap to 0), Update the overlay group with the delta; always
    // chains to the base Update.
    virtual void Update();

    // NEW virtual — appended after the dwSegment dtor slot.
    // vtbl +0x18 @402690 (dwMovie_Draw) — overlay.DrawChild(pDestBits,
    // pClipRect); called by dwMovie_VidPresent over each presented frame.
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);
};

#endif // __cplusplus

#endif // _DWMOVIE_H
