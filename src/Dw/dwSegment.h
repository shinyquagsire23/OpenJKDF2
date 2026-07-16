#ifndef _DWSEGMENT_H
#define _DWSEGMENT_H

// dwSegment — the app-flow "segment" base class + the GLOBAL segment-stack
// manager + recorded-input cue playback.
//
// DroidWorks.exe unit range: 0x433e40-0x43483f, plus the base default virtual
// bodies that physically live in the dwAnim range (dwSegment_DefaultReturnTrue
// @0x402cb0, the ICF'd no-op @0x402cc0, dwSegment_DtorDelete @0x402cd0).
//
// A dwSegment is one node in the app flow (a screen, cutscene, dialog,
// transition). The dwAnim segment tree (dwAnimSeg/dwFlicSeg/dwSmushSeg/
// dwMovie) derives it directly; dwGuiScreen and the other screens embed it as
// a SECONDARY MI base @obj+0x10 (their "scn" vtables in Ghidra). The base
// carries a pausable CLOCK — GetElapsed() is the animation time every
// anim/screen reads.
//
// The MANAGER (module globals @0x53e858-0x53e8ac) runs the whole app: a
// pending-segment STACK plus the ACTIVE segment and an optional modal OVERLAY
// (dwGuiDialog_RunModal), ticked once per frame by dwSegment_Tick from the
// main loop (dwMain_MainLoopTick @41b6d0). It also owns a timed CUE playlist
// that replays recorded 'D'/'U'/'K' input events (widget.rec lines written by
// dwWidget_RecordEvent) back into the widget layer, with cursor interpolation
// between move cues (tutorial/attract playback).
//
// Compiled as C++ (vtable dwSegment_vtbl @0x51e120, ctor + scalar-deleting
// dtor pair); the manager API keeps C linkage so the C main loop (dwMain.c)
// can drive it.

#include "Dw/dwTypes.h"

#ifdef __cplusplus

// C++ class (binary: vptr@0x00, sizeof 0x14). Vtable @0x51e120 has exactly 6
// slots — the derived dwAnimSeg vtable @0x51e108 (6 dwords wide) pins the
// count. Slot names derive from how the manager drives them (verified against
// dwSegment_Tick / Push / Pop / Begin- and EndOverlay / Shutdown):
// Activate when becoming the current segment, Deactivate when being retired,
// Suspend/Resume around stacking and overlays, Update per unpaused frame.
struct dwSegment
{
    // (vptr @0x00 in the binary)
    uint8_t bPaused;     // 0x04: clock is paused
    float startTimeSec;  // 0x08: absolute time (sec) latched by ResetClock
    float pausedAtSec;   // 0x0c: absolute time (sec) latched by Suspend
    float pauseAccumSec; // 0x10: accumulated paused span (sec)

    // Zeroes the pause state and starts the clock. @4341e0 (dwSegment_Ctor)
    dwSegment();

    // Declaration order below == binary vtable slot order.
    virtual int Activate();    // vtbl +0x00 @402cb0 (dwSegment_DefaultReturnTrue) —
                               //   called when this segment becomes current
                               //   (Tick advance, BeginOverlay); default returns 1
    virtual void Deactivate(); // vtbl +0x04 @402cc0 (no-op default; ICF-folded with
                               //   the empty jk_logtofile stub) — called when
                               //   retired (Tick advance, EndOverlay, Shutdown)
    virtual void Suspend();    // vtbl +0x08 @434280 (dwSegment_Suspend) — pause the
                               //   clock (latches pausedAtSec); called by Push,
                               //   BeginOverlay and SuspendActive
    virtual void Resume();     // vtbl +0x0c @4342c0 (dwSegment_Resume) — unpause;
                               //   adds the paused span (when > 1e-5 s) to
                               //   pauseAccumSec; called by Pop, EndOverlay and
                               //   ResumeActive
    virtual void Update();     // vtbl +0x10 @402cc0 (no-op default) — per-frame
                               //   tick from dwSegment_Tick while not paused
    virtual ~dwSegment();      // vtbl +0x14 @402cd0 (dwSegment_DtorDelete; invoked
                               //   with flag 1 by dwSegment_Release == delete)

    // Restart the clock at now (pauseAccumSec = 0, start = pausedAt = now).
    // @434200 (dwSegment_ResetClock)
    void ResetClock();

    // Pause-aware elapsed seconds since ResetClock: now - start - accum.
    // Quirk (preserved from the binary): while paused this returns
    // pausedAtSec — the ABSOLUTE pause timestamp, not an elapsed span.
    // @434240 (dwSegment_GetElapsed — THE anim-time source)
    float GetElapsed();
};

extern "C" {
#else
typedef struct dwSegment dwSegment; // C++ class; opaque in the C view
#endif

// ---- manager globals (the rest live as statics in dwSegment.cpp) -----------

// The current segment (NULL until the first advance pops one). @0x53e888
extern dwSegment* dwSegment_pActive;

// Modal overlay segment (set by dwSegment_BeginOverlay, used by
// dwGuiDialog_RunModal). While set it gets exclusive Update and the advance
// machinery is held off. @0x53e894
extern dwSegment* dwSegment_pOverlay;

// ---- manager API ------------------------------------------------------------

// Allocates the cue-playlist sentinel. The binary ran this as a CRT static
// ctor (thunk @433e30, which also atexit-registered dwSegment_FreePlaylist);
// here it additionally resets every module global for the soft-reset loop.
// On a soft reset call dwSegment_FreePlaylist first (the old sentinel is not
// freed here, mirroring the binary). @433e40
void dwSegment_Startup(void);

// Frees every cue node AND the sentinel, once (guarded by an internal flag;
// the sentinel pointer is left dangling like the binary — atexit there). @433e80
void dwSegment_FreePlaylist(void);

// Sets the quit flag returned by dwSegment_Tick. @433f00
void dwSegment_SignalQuit(void);

// Ends the overlay (if any), deactivates + releases the active segment, then
// pops/deactivates/releases everything still on the pending stack. @433f10
void dwSegment_Shutdown(void);

// Suspend the overlay if present, else the active segment. @433f80
void dwSegment_SuspendActive(void);

// Flush buffered input, then resume the overlay if present, else the active
// segment. @433fa0
void dwSegment_ResumeActive(void);

// Start recorded-input playback: clears the playlist, parses pFilename
// ("%f time, %c cmd, %lu, %lu" lines — see dwWidget_RecordEvent), snapshots
// the cursor, disables live widget mouse input and latches the playback start
// time. @433fd0
void dwSegment_Play(const char* pFilename);

// Clears the playlist and re-enables live widget input (also reached from
// dwSegment_Tick when the playlist drains). @434180
void dwSegment_EndPlayback(void);

// Suspend the active segment and make pSeg the modal overlay (Activate it,
// full-screen dirty rect). Binary caller: dwGuiDialog_RunModal. @434340
void dwSegment_BeginOverlay(dwSegment* pSeg);

// Deactivate the overlay, clear it, resume the active segment (full-screen
// dirty rect). The overlay object is NOT freed here. @434390
void dwSegment_EndOverlay(void);

// The per-frame manager tick (called from the main loop): replays due input
// cues into the widget layer (with cursor interpolation between move cues),
// performs the pending advance (retire active, pop next, Activate), then
// Updates the overlay or the active segment. Returns the quit flag (see
// dwSegment_SignalQuit); returns 0 immediately (clearing the flag) once the
// OS window is shutting down. @4343f0
int dwSegment_Tick(void);

// Push pSeg onto the pending stack (10 slots, unguarded like the binary) and
// Suspend it. The top of the stack is what the next advance activates. @434740
void dwSegment_Push(dwSegment* pSeg);

// Pop the top pending segment and Resume it. Underflow logs a warning and
// returns NULL (the binary then dereferenced NULL — guarded here). @434760
dwSegment* dwSegment_Pop(void);

// Ask dwSegment_Tick to retire the active segment and activate the top of the
// pending stack on its next run. @4347b0
void dwSegment_RequestAdvance(void);

// Push(pSeg) + RequestAdvance(). @4347c0
void dwSegment_PushAndAdvance(dwSegment* pSeg);

// Interrupt the flow with pInterrupt, returning to pReturnTo afterwards:
// Push(pReturnTo), Push(pInterrupt), RequestAdvance() — the next advance runs
// pInterrupt; the one after that comes back to pReturnTo. @4347e0
void dwSegment_InterruptWith(dwSegment* pReturnTo, dwSegment* pInterrupt);

// Destroy pSeg (virtual delete) UNLESS it is still on the pending stack. @434800
void dwSegment_Release(dwSegment* pSeg);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // _DWSEGMENT_H
