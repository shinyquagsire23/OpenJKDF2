// dwSegment — app-flow "segment" base class + global segment-stack manager +
// recorded-input cue playback. See dwSegment.h for the design overview.
//
// DroidWorks.exe unit range: 0x433e40-0x43483f (+ base default virtual bodies
// @0x402cb0/0x402cc0/0x402cd0, physically in the dwAnim range).
//
// Win32/engine -> OpenJKDF2 mappings used in this file:
//   dwHS->getTimerTick() / dwHS->some_float (binary global @0x6b6258)
//       -> dwMain_pHS->getTimerTick() / ->some_float (ms tick -> seconds;
//          same HostServices fields the binary read)
//   stdControl_FUN_00503e00 (drain buffered DirectInput device data)
//       -> stdControl_Flush() (JK.EXE twin @0x42e320)
//   DAT_0065be0c (DW Window unit's message-loop quit flag, set on WM_QUIT)
//       -> g_should_exit (generated globals.h)
//   video-mode global @0x6478f8 (+0x08 width / +0x0c height)
//       -> stdDisplay_pCurVideoMode->format.width/.height (same mapping as
//          dwColormap.c / dwDisplay.cpp)
//   jk_logtofile -> stdPlatform_Printf (the binary's jk_logtofile @0x402cc0 is
//       an empty stub — the prints were compiled out; kept visible here)
//   operator new/delete (idk_alloc/stdPlatform_FreeHandle) -> new/delete
//
// Compiled as C++ (vtable @0x51e120, ctor + scalar-deleting dtor pair, MSVC
// EH frame around the dwConfFile local in dwSegment_Play).

#include "Dw/dwSegment.h"

#include "Dw/dwConfFile.h"
#include "Dw/dwCursor.h"  // dwCursor_pos, dwCursor_Redraw
#include "Dw/dwDisplay.h" // dwDisplay_AddDirtyRect
#include "Dw/dwRect.h"
#include "Dw/dwWidget.h"  // dwWidget_pMouseTarget/pDefault, Disable/EnableInput, OnMouse*/OnKey

#include "stdPlatform.h"

// Generated globals.h + Platform/stdControl.h have no extern "C" guards of
// their own — wrap at include site. globals.h provides
// stdDisplay_pCurVideoMode and g_should_exit.
extern "C" {
#include "globals.h"
#include "Platform/stdControl.h"
}

extern "C" HostServices* dwMain_pHS; // the DW host-services pointer (dwMain.c)

// ---------------------------------------------------------------------------
// Cue playlist node
// ---------------------------------------------------------------------------

// One recorded-input cue (binary: 0x18-byte template-list node; the payload
// {time, cmd, arg0, arg1} sits inline where a dwListNode carries pData).
// cmd: 'D' mouse-down / 'U' mouse-up / 'K' key (see dwWidget_RecordEvent).
// For 'D'/'U', arg0/arg1 = cursor x/y; for 'K', arg0 = key, arg1 = repeat.
typedef struct dwSegmentCue dwSegmentCue;
struct dwSegmentCue
{
    dwSegmentCue* pNext; // 0x00
    dwSegmentCue* pPrev; // 0x04
    float timeSec;       // 0x08: cue time, seconds from playback start
    char cmd;            // 0x0c
    int32_t arg0;        // 0x10
    int32_t arg1;        // 0x14
};

// ---------------------------------------------------------------------------
// Manager globals (binary @0x53e858-0x53e8ac; all reset in dwSegment_Startup)
// ---------------------------------------------------------------------------

#define DWSEGMENT_STACK_SLOTS 10 // binary: 10 pointers @0x53e860..0x53e884

static dwSegmentCue* dwSegment_pCueList = NULL; // @0x53e858: playlist sentinel (circular)
static dwPoint dwSegment_cursorPos = {0, 0};    // @0x53e85c: synthesized cursor pos at the last fired move cue
static dwSegment* dwSegment_aStack[DWSEGMENT_STACK_SLOTS] = {NULL}; // @0x53e860: pending-segment stack
dwSegment* dwSegment_pActive = NULL;            // @0x53e888: current segment
static int dwSegment_stackDepth = 0;            // @0x53e88c
static float dwSegment_lastMoveCueTime = 0.0f;  // @0x53e890: time of the last fired 'D'/'U' cue
dwSegment* dwSegment_pOverlay = NULL;           // @0x53e894: modal overlay segment
static float dwSegment_nextMoveCueTime = 0.0f;  // @0x53e898: time of the next pending 'D'/'U' cue
static uint8_t dwSegment_bPlaylistFreed = 0;    // @0x53e89c: FreePlaylist once-guard
static float dwSegment_playbackStartTime = 0.0f;// @0x53e8a0: absolute time (sec) when Play latched
static int16_t dwSegment_nextCursorX = 0;       // @0x53e8a4: cursor target of the next move cue
static int16_t dwSegment_nextCursorY = 0;       // @0x53e8a6
static uint8_t dwSegment_bAdvancePending = 0;   // @0x53e8a8: RequestAdvance flag
static uint8_t dwSegment_bQuit = 0;             // @0x53e8ac: Tick return value (SignalQuit)

// Current absolute time in seconds (the binary inlines this expression at
// every site: dwHS->getTimerTick() / dwHS->some_float; ms -> sec).
static float dwSegment_GetNowSec()
{
    return (float)dwMain_pHS->getTimerTick() / (float)dwMain_pHS->some_float;
}

// Unlink + delete every cue node, leaving the sentinel self-linked (the
// binary inlines this template-list loop in FreePlaylist/Play/EndPlayback;
// factored here for the translation).
static void dwSegment_ClearCues()
{
    dwSegmentCue* pCue = dwSegment_pCueList->pNext;
    while (pCue != dwSegment_pCueList)
    {
        dwSegmentCue* pNextCue = pCue->pNext;
        pCue->pPrev->pNext = pCue->pNext;
        pCue->pNext->pPrev = pCue->pPrev;
        pCue->pNext = NULL;
        pCue->pPrev = NULL;
        delete pCue;
        pCue = pNextCue;
    }
}

// ---------------------------------------------------------------------------
// dwSegment class (base slots + clock)
// ---------------------------------------------------------------------------

// @4341e0 (dwSegment_Ctor)
dwSegment::dwSegment()
{
    this->bPaused = 0;
    this->pausedAtSec = 0.0f;
    this->pauseAccumSec = 0.0f;
    ResetClock();
}

// vtbl +0x00 @402cb0 (dwSegment_DefaultReturnTrue)
int dwSegment::Activate()
{
    return 1;
}

// vtbl +0x04 @402cc0 (no-op default; ICF-folded with the empty jk_logtofile stub)
void dwSegment::Deactivate()
{
}

// vtbl +0x08 @434280 (dwSegment_Suspend)
void dwSegment::Suspend()
{
    float nowSec = dwSegment_GetNowSec();
    this->bPaused = 1;
    this->pausedAtSec = nowSec;
}

// vtbl +0x0c @4342c0 (dwSegment_Resume)
void dwSegment::Resume()
{
    float pausedSpan = dwSegment_GetNowSec() - this->pausedAtSec;
    float absSpan = (pausedSpan < 0.0f) ? -pausedSpan : pausedSpan;
    if (absSpan <= 1e-05f)
        pausedSpan = 0.0f;
    this->bPaused = 0;
    if (pausedSpan > 0.0f)
        this->pauseAccumSec += pausedSpan;
}

// vtbl +0x10 @402cc0 (no-op default)
void dwSegment::Update()
{
}

// vtbl +0x14 @402cd0 (dwSegment_DtorDelete: reset vtbl + conditional free —
// the compiler emits the equivalent for `delete`)
dwSegment::~dwSegment()
{
}

// @434200 (dwSegment_ResetClock)
void dwSegment::ResetClock()
{
    float nowSec = dwSegment_GetNowSec();
    this->pauseAccumSec = 0.0f;
    this->startTimeSec = nowSec;
    this->pausedAtSec = nowSec;
}

// @434240 (dwSegment_GetElapsed)
float dwSegment::GetElapsed()
{
    float elapsedSec = dwSegment_GetNowSec() - this->startTimeSec - this->pauseAccumSec;
    if (this->bPaused)
        elapsedSec = this->pausedAtSec; // quirk preserved: ABSOLUTE pause timestamp (see header)
    return elapsedSec;
}

// ---------------------------------------------------------------------------
// Manager: lifecycle
// ---------------------------------------------------------------------------

// @433e40 — binary: CRT static ctor body (thunk @433e30 also atexit-registers
// dwSegment_FreePlaylist).
void dwSegment_Startup(void)
{
    // Note: resets added for OpenJKDF2's soft-reset loop; the binary ran this
    // once before WinMain and relied on static zero-init for the rest. On a
    // soft reset call dwSegment_FreePlaylist first — the old sentinel is not
    // freed here (mirrors the binary's unconditional alloc).
    dwSegment_pActive = NULL;
    dwSegment_pOverlay = NULL;
    for (int i = 0; i < DWSEGMENT_STACK_SLOTS; i++)
        dwSegment_aStack[i] = NULL;
    dwSegment_stackDepth = 0;
    dwSegment_cursorPos.x = 0;
    dwSegment_cursorPos.y = 0;
    dwSegment_lastMoveCueTime = 0.0f;
    dwSegment_nextMoveCueTime = 0.0f;
    dwSegment_playbackStartTime = 0.0f;
    dwSegment_nextCursorX = 0;
    dwSegment_nextCursorY = 0;
    dwSegment_bPlaylistFreed = 0;
    dwSegment_bAdvancePending = 0;
    dwSegment_bQuit = 0;

    dwSegment_pCueList = new dwSegmentCue;
    dwSegment_pCueList->pNext = dwSegment_pCueList;
    dwSegment_pCueList->pPrev = dwSegment_pCueList;
    dwSegment_pCueList->timeSec = 0.0f; // sentinel payload unread (uninitialized in the binary)
    dwSegment_pCueList->cmd = 0;
    dwSegment_pCueList->arg0 = 0;
    dwSegment_pCueList->arg1 = 0;
}

// @433e80 — atexit-registered in the binary.
void dwSegment_FreePlaylist(void)
{
    if ((dwSegment_bPlaylistFreed & 1) == 0)
    {
        dwSegment_bPlaylistFreed |= 1;
        dwSegment_ClearCues();
        delete dwSegment_pCueList; // sentinel left dangling, as in the binary (Startup reallocates)
    }
}

// @433f00
void dwSegment_SignalQuit(void)
{
    dwSegment_bQuit = 1;
}

// @433f10
void dwSegment_Shutdown(void)
{
    dwSegment_bQuit = 0;
    if (dwSegment_pOverlay != NULL)
        dwSegment_EndOverlay();
    if (dwSegment_pActive != NULL)
    {
        dwSegment_pActive->Deactivate();
        dwSegment_Release(dwSegment_pActive);
    }
    dwSegment_pActive = NULL; // binary clears it (again) on every loop entry below
    while (dwSegment_stackDepth != 0)
    {
        dwSegment* pSeg = dwSegment_Pop(); // Pop Resumes the popped segment first
        pSeg->Deactivate();
        dwSegment_Release(pSeg);
    }
}

// ---------------------------------------------------------------------------
// Manager: suspend/resume + overlay
// ---------------------------------------------------------------------------

// @433f80
void dwSegment_SuspendActive(void)
{
    if (dwSegment_pOverlay != NULL)
    {
        dwSegment_pOverlay->Suspend();
        return;
    }
    if (dwSegment_pActive != NULL)
        dwSegment_pActive->Suspend();
}

// @433fa0
void dwSegment_ResumeActive(void)
{
    stdControl_Flush(); // binary: stdControl_FUN_00503e00 (drain buffered device input)
    if (dwSegment_pOverlay != NULL)
    {
        dwSegment_pOverlay->Resume();
        return;
    }
    if (dwSegment_pActive != NULL)
        dwSegment_pActive->Resume();
}

// Full-screen dirty rect from the current video mode (binary: the video-mode
// global @0x6478f8, +0x08 width / +0x0c height — same mapping as dwColormap.c).
static void dwSegment_AddFullScreenDirtyRect()
{
    if (stdDisplay_pCurVideoMode) // Note: guard added; always non-NULL here in the binary
    {
        dwRect rect;
        rect.left = 0;
        rect.top = 0;
        rect.right = (int16_t)stdDisplay_pCurVideoMode->format.width;
        rect.bottom = (int16_t)stdDisplay_pCurVideoMode->format.height;
        dwDisplay_AddDirtyRect(&rect);
    }
}

// @434340 — binary caller: dwGuiDialog_RunModal.
void dwSegment_BeginOverlay(dwSegment* pSeg)
{
    dwSegment_pActive->Suspend(); // binary: unguarded — an overlay requires an active segment
    dwSegment_pOverlay = pSeg;
    pSeg->Activate();
    dwSegment_AddFullScreenDirtyRect();
}

// @434390
void dwSegment_EndOverlay(void)
{
    dwSegment_pOverlay->Deactivate();
    dwSegment_pOverlay = NULL;
    dwSegment_pActive->Resume(); // binary: unguarded
    dwSegment_AddFullScreenDirtyRect();
}

// ---------------------------------------------------------------------------
// Manager: recorded-input playback
// ---------------------------------------------------------------------------

// @433fd0
void dwSegment_Play(const char* pFilename)
{
    stdPlatform_Printf("Attempting playback of %s\n", pFilename); // binary: jk_logtofile (compiled-out stub)

    dwSegment_ClearCues();

    dwConfFile conf;
    dwConfFile_Open(&conf, pFilename);
    dwConfFile_ReadLine(&conf);
    while (!conf.bEof)
    {
        float timeSec = 0.0f;
        uint32_t arg0 = 0;
        uint32_t arg1 = 0;
        dwConfFile_ParseFloat(&conf, &timeSec);
        char cmd = *dwConfFile_NextToken(&conf); // binary: unguarded deref
        dwConfFile_ParseULong(&conf, &arg0);
        dwConfFile_ParseULong(&conf, &arg1);
        dwConfFile_ReadLine(&conf); // the node is appended AFTER advancing (binary order kept)

        dwSegmentCue* pCue = new dwSegmentCue;
        pCue->timeSec = timeSec;
        pCue->cmd = cmd;
        pCue->arg0 = (int32_t)arg0;
        pCue->arg1 = (int32_t)arg1;

        // append at the tail (insert after sentinel->pPrev)
        dwSegmentCue* pTail = dwSegment_pCueList->pPrev;
        pCue->pPrev = pTail;
        pCue->pNext = pTail->pNext;
        pTail->pNext = pCue;
        pCue->pNext->pPrev = pCue;
    }

    dwSegment_lastMoveCueTime = 0.0f;
    dwSegment_nextMoveCueTime = 0.0f;
    dwSegment_cursorPos = dwCursor_pos;
    dwWidget_DisableInput();
    dwSegment_playbackStartTime = dwSegment_GetNowSec();
    dwConfFile_Close(&conf);
}

// @434180
void dwSegment_EndPlayback(void)
{
    dwSegment_ClearCues();
    dwWidget_EnableInput();
}

// ---------------------------------------------------------------------------
// Manager: the per-frame tick
// ---------------------------------------------------------------------------

// @4343f0 — called once per frame by the main loop (dwMain_MainLoopTick @41b6d0).
int dwSegment_Tick(void)
{
    if (g_should_exit) // binary: the DW Window unit's msg-loop quit flag DAT_0065be0c
    {
        dwSegment_bQuit = 0;
        return 0;
    }

    // ---- recorded-input cue playback ----
    if (dwSegment_pCueList->pNext != dwSegment_pCueList)
    {
        dwPoint prevPos = dwCursor_pos;
        float elapsed = dwSegment_GetNowSec() - dwSegment_playbackStartTime;

        // Fire every cue that is due (<= elapsed), injecting it into the
        // capture target (fallback: the default/screen widget).
        dwSegmentCue* pCue = dwSegment_pCueList->pNext;
        while (pCue != dwSegment_pCueList)
        {
            if (elapsed < pCue->timeSec)
                break;
            dwWidget* pTarget = dwWidget_pMouseTarget ? dwWidget_pMouseTarget : dwWidget_pDefault;
            if (pCue->cmd == 'D')
            {
                dwSegment_lastMoveCueTime = pCue->timeSec;
                dwSegment_cursorPos.x = (int16_t)pCue->arg0;
                dwSegment_cursorPos.y = (int16_t)pCue->arg1;
                dwCursor_pos = dwSegment_cursorPos;
                pTarget->OnMouseMove(dwSegment_cursorPos.x, dwSegment_cursorPos.y);
                pTarget->OnMouseDown(dwSegment_cursorPos.x, dwSegment_cursorPos.y);
            }
            else if (pCue->cmd == 'K')
            {
                pTarget->OnKey((uint8_t)pCue->arg0, pCue->arg1); // binary passes the low byte of arg0
            }
            else if (pCue->cmd == 'U')
            {
                dwSegment_lastMoveCueTime = pCue->timeSec;
                dwSegment_cursorPos.x = (int16_t)pCue->arg0;
                dwSegment_cursorPos.y = (int16_t)pCue->arg1;
                dwCursor_pos = dwSegment_cursorPos;
                pTarget->OnMouseMove(dwSegment_cursorPos.x, dwSegment_cursorPos.y);
                pTarget->OnMouseUp(dwSegment_cursorPos.x, dwSegment_cursorPos.y);
            }
            // unlink + free the fired cue, refetch the head (binary order)
            pCue->pPrev->pNext = pCue->pNext;
            pCue->pNext->pPrev = pCue->pPrev;
            pCue->pNext = NULL;
            pCue->pPrev = NULL;
            delete pCue;
            pCue = dwSegment_pCueList->pNext;
        }
        // (pCue now = first unfired node, or the sentinel when drained)

        // Latch the NEXT pending move cue once the previous one was consumed.
        if (dwSegment_nextMoveCueTime <= dwSegment_lastMoveCueTime)
        {
            for (dwSegmentCue* pScan = pCue; pScan != dwSegment_pCueList; pScan = pScan->pNext)
            {
                if (pScan->cmd == 'D' || pScan->cmd == 'U')
                {
                    dwSegment_nextMoveCueTime = pScan->timeSec;
                    dwSegment_nextCursorX = (int16_t)pScan->arg0;
                    dwSegment_nextCursorY = (int16_t)pScan->arg1;
                    break;
                }
            }
        }

        // Interpolate the synthesized cursor toward the next move cue.
        // (Quirk preserved: when nextMoveCueTime == lastMoveCueTime the t
        // division is by zero, exactly as in the binary.)
        if (elapsed <= dwSegment_nextMoveCueTime)
        {
            float t = (elapsed - dwSegment_lastMoveCueTime)
                    / (dwSegment_nextMoveCueTime - dwSegment_lastMoveCueTime);
            int16_t x = (int16_t)(dwSegment_cursorPos.x + (int)((dwSegment_nextCursorX - dwSegment_cursorPos.x) * t));
            int16_t y = (int16_t)(dwSegment_cursorPos.y + (int)((dwSegment_nextCursorY - dwSegment_cursorPos.y) * t));
            dwCursor_pos.x = x;
            dwCursor_pos.y = y;
            dwWidget* pTarget = dwWidget_pMouseTarget ? dwWidget_pMouseTarget : dwWidget_pDefault;
            pTarget->OnMouseMove(x, y);
        }

        if (dwSegment_pCueList->pNext == dwSegment_pCueList)
            dwSegment_EndPlayback();

        if (prevPos.x != dwCursor_pos.x || prevPos.y != dwCursor_pos.y)
            dwCursor_Redraw();
    }

    // ---- overlay / advance / active update ----
    if (dwSegment_pOverlay != NULL)
    {
        if (dwSegment_pOverlay->bPaused == 0)
            dwSegment_pOverlay->Update();
        return dwSegment_bQuit;
    }

    if (dwSegment_bAdvancePending)
    {
        dwSegment_bAdvancePending = 0;
        dwSegment* pOld = dwSegment_pActive;
        if (pOld != NULL)
        {
            dwSegment_pActive = NULL;
            pOld->Deactivate();
            dwSegment_Release(pOld);
        }
        dwSegment_pActive = dwSegment_Pop();
        if (dwSegment_pActive == NULL)
            return dwSegment_bQuit;
        dwSegment_pActive->Activate();
    }

    if (dwSegment_pActive != NULL && dwSegment_pActive->bPaused == 0)
        dwSegment_pActive->Update();
    return dwSegment_bQuit;
}

// ---------------------------------------------------------------------------
// Manager: pending-segment stack
// ---------------------------------------------------------------------------

// @434740
void dwSegment_Push(dwSegment* pSeg)
{
    dwSegment_aStack[dwSegment_stackDepth] = pSeg; // binary: unguarded (10 slots)
    dwSegment_stackDepth++;
    pSeg->Suspend();
}

// @434760
dwSegment* dwSegment_Pop(void)
{
    if (dwSegment_stackDepth != 0)
    {
        dwSegment* pSeg = dwSegment_aStack[dwSegment_stackDepth - 1];
        dwSegment_stackDepth--;
        dwSegment_aStack[dwSegment_stackDepth] = NULL;
        pSeg->Resume();
        return pSeg;
    }
    stdPlatform_Printf("*** Warning! Popped off the segment stack!\n"); // binary: jk_logtofile (compiled-out stub)
    // Note: the binary then calls Resume() through a NULL segment (guaranteed
    // crash); guarded here — underflow returns NULL like the code below expects.
    return NULL;
}

// @4347b0
void dwSegment_RequestAdvance(void)
{
    dwSegment_bAdvancePending = 1;
}

// @4347c0
void dwSegment_PushAndAdvance(dwSegment* pSeg)
{
    dwSegment_Push(pSeg);
    dwSegment_RequestAdvance();
}

// @4347e0
void dwSegment_InterruptWith(dwSegment* pReturnTo, dwSegment* pInterrupt)
{
    dwSegment_Push(pReturnTo);
    dwSegment_Push(pInterrupt);
    dwSegment_RequestAdvance();
}

// @434800
void dwSegment_Release(dwSegment* pSeg)
{
    int i = 0;
    if (dwSegment_stackDepth != 0)
    {
        for (i = 0; i < dwSegment_stackDepth; i++)
        {
            if (dwSegment_aStack[i] == pSeg)
                break;
        }
    }
    if (i == dwSegment_stackDepth && pSeg != NULL)
        delete pSeg; // binary: vtbl +0x14 scalar-deleting dtor, flag 1
}
