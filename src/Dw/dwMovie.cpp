// dwMovie — the DroidWorks full-screen movie SEGMENT family: dwAnimSeg
// (media-segment base + ESC skip), dwFlicSeg (FLC player, fully functional),
// dwSmushSeg (.san base, plays via libsmusher) and dwMovie (.san + widget
// overlay), plus the SMUSH playback glue.
//
// Decompiled from DroidWorks.exe, unit range 0x401000-0x404010 (segment
// half; the widget half is dwAnim.cpp). vtables: dwAnimSeg 0x51e108 ·
// dwFlicSeg 0x51e050 · dwSmushSeg 0x51e070 · dwMovie 0x51e0a0 (7 slots —
// dwMovie appends the +0x18 Draw virtual to the 6-slot dwSegment shape).
//
// SMUSH (P8, wired 2026-07-18): the binary's SmushPlay/LECSmush decode
// cluster (0x43cf50-0x442390) stays bounds-only in Ghidra BY REQUEST — it is
// replaced wholesale by the repo's vendored libsmusher
// (src/external/libsmusher), the same library jkCutscene.c drives for JK's
// .san cutscenes; the glue below mirrors that usage. Role map for the
// binary's pieces (per-callback originals documented where absorbed):
//   smushPlay_sub_43D0A0 (open)    -> dwMovie_SmushOpen (smush_from_fpath)
//   smushPlay_sub_43D2E0 (volume)  -> dwMovie_SmushOpen's BufferSetVolume
//   smushPlay_sub_43D1B0 (service) -> dwSmushSeg::Update's pacing loop
//   smushPlay_sub_43D190 (close)   -> dwMovie_SmushClose
//   dwSmushVid_Open @401b90        -> dwMovie_SmushBlitFrame (binary locked
//      the back VBuffer @0x6b5a40 as the SMUSH decode target; libsmusher
//      decodes into its own framebuffer, row-copied there per frame)
//   dwSmushVid_Close @401bf0       -> dwMovie_VidPresent (the present slot;
//      dwMovie swaps it for the overlay-drawing variant via dwMovie_pActive)
//   dwSmushVid_Clear @401c10       -> unused (SmushPlay-era clear; no caller)
//   dwSmushVid_SetPalette @401c60  -> dwMovie_SmushSetPalette
//   dwSmushAud_* @401cd0-4021e0    -> the stdSound queue mirror below: the
//      binary's 5-second DirectSound streaming ring becomes 32 x 0x8000
//      stdSound buffers chained with stdSound_BufferQueueAfterAnother
//      (jkCutscene's exact pattern); the binary's audio-clock master pacing
//      becomes the dwSegment clock, same as dwFlicSeg.
//
// Adaptations (marked // Note: below):
//  - DW-stdDisplay calls in dwMovie_VidPresent map per dwDisplay.cpp's
//    table: GDI flip @0x4fdc60 -> dwDisplay_Present (the binary's flip showed
//    the DDraw back buffer directly; our two-buffer model needs the
//    back->front copy — dwFlicSeg parity), back buffer @0x6b5a40 ->
//    dwDisplay_pBackVBuf.

#include "Dw/dwMovie.h"

#include "Dw/dwAnim.h" // family header (not strictly needed; keeps the pair discoverable)
#include "Dw/dwFlic.h"
#include "Dw/dwImage.h"
#include "Dw/dwImageVBuf.h"
#include "Dw/dwDisplay.h"
#include "Dw/dwCursor.h"
#include "Dw/dwInits.h"
#include "Dw/dwColormap.h" // dwColormap_pDisplayPalette (palette gamma re-apply)
#include "Dw/dwPlayer.h"   // dw_settingSoundVol (SMUSH volume)

#include "jk.h"
#include "stdPlatform.h"

#include <stdio.h> // before the extern "C" block (smush.h pulls it in)

// These engine headers have no extern "C" guards of their own — wrap at include site.
extern "C" {
#include "Win95/Window.h"     // Window_AddMsgHandler/Window_RemoveMsgHandler
#include "Win95/stdDisplay.h" // stdDisplay_VBufferLock/Unlock, stdDisplay_SetMasterPalette
#include "Win95/stdSound.h"   // the stdSound streaming-buffer API
#include "smush.h"            // vendored libsmusher (src/external/libsmusher)
}

extern "C" HostServices* dwMain_pHS; // the DW host-services pointer (dwMain.c); binary global dwHS @0x6b6258

// ---- module globals/statics ---------------------------------------------------

dwMovie* dwMovie_pActive = NULL; // binary: 0x53d6b0
int dwAnim_bSmushInitted = 0;    // binary: dwAnim_bSmushInitted

// binary: DAT_00540620 — in the binary this was written by the lecSmush
// cluster (nonzero disables the dwMovie_VidPresent overlay draw, codec error
// path). No libsmusher counterpart; kept 0.
static int dwMovie_bPresentDisabled = 0;

// @0x68b1c4 (lecSmush_frameNum; adopted from the dwEnding.cpp placeholder for
// P8) — index of the SMUSH frame currently on screen, written per presented
// frame by dwSmushSeg::Update. Read by dwEnding + dwGuiOpening.
extern "C" uint32_t lecSmush_frameNum = 0;

// ---- SMUSH session state (the libsmusher replacement for the SmushPlay session)
static smush_ctx* dwMovie_pSmush = NULL;      // active session; non-NULL only while a .san plays
static uint32_t dwMovie_framesDecoded = 0;    // smush_frame calls since open (buffer holds frame framesDecoded-1)
static uint32_t dwMovie_nextPresentIdx = 0;   // index of the frame due on screen next
static int dwMovie_smushFps = 0;              // smush_video_fps of the open session
static uint32_t dwMovie_smushW = 0;           // smush_video_width/height (arrive with frame 0)
static uint32_t dwMovie_smushH = 0;

// ---- SMUSH audio ring (mirrors jkCutscene.c's smusher audio machinery) --------
#define DWMOVIE_AUDIO_NUM_STDBUFS (32)   // jkCutscene AUDIO_NUM_STDBUFS
#define DWMOVIE_AUDIO_BUFS_DEPTH (0x8000)
#define DWMOVIE_AUDIO_QUEUE_DEPTH (128)

static stdSound_buffer_t* dwMovie_audio[DWMOVIE_AUDIO_NUM_STDBUFS];
static stdSound_buffer_t* dwMovie_lastAudio = NULL;
static stdSound_buffer_t* dwMovie_currentAudio = NULL;
static uint8_t* dwMovie_currentAudioBuf = NULL;
static int32_t dwMovie_currentAudioBufSize = 0;
static int32_t dwMovie_currentAudioWritten = 0;
static int dwMovie_audioFlip = 0;

static const uint8_t* dwMovie_audio_buf = NULL;
static const uint8_t* dwMovie_audio_pos = NULL;
static uint32_t dwMovie_audio_len = 0;

static const uint8_t* dwMovie_audio_queue[DWMOVIE_AUDIO_QUEUE_DEPTH];
static size_t dwMovie_audio_queue_lens[DWMOVIE_AUDIO_QUEUE_DEPTH];
static int32_t dwMovie_audio_queue_read_idx = 0;
static int32_t dwMovie_audio_queue_write_idx = 0;

// Defined in the SMUSH glue section below.
static int dwMovie_SmushOpen(const char* pPath);
static void dwMovie_SmushClose(void);
static void dwMovie_SmushAudioPump(void);
static void dwMovie_SmushSetPalette(void);
static void dwMovie_SmushBlitFrame(void);

// Note: no binary counterpart — statics reset for the soft-reset loop.
void dwMovie_Startup(void)
{
    dwMovie_pActive = NULL;
    dwAnim_bSmushInitted = 0;
    dwMovie_bPresentDisabled = 0;
    dwMovie_SmushClose(); // NULL-guarded; no-op when no .san is playing
}

// ---- dwAnimSeg -------------------------------------------------------------

// @402c80 (dwAnimSeg_KeyMsgHandler) — ESC skips the movie.
extern "C" int dwAnimSeg_KeyMsgHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, LRESULT* pResult)
{
    (void)hWnd;
    (void)lParam;
    *pResult = 0;
    if (msg == WM_KEYDOWN && wParam == VK_ESCAPE)
        dwSegment_RequestAdvance();
    return 0;
}

// @402b50 (dwAnimSeg_Ctor)
dwAnimSeg::dwAnimSeg(const char* pFilename, void* pCallbacks)
    : dwSegment()
    , pCallbacks(pCallbacks)
    , bPlaying(0)
    , bKeyHandlerInstalled(0)
    , filename(pFilename, 0)
{
}

// @402bd0 (dwAnimSeg_Dtor; scalar-deleting wrapper @402bb0) — filename free
// + vptr walk-back, both implicit here.
dwAnimSeg::~dwAnimSeg()
{
}

// vtbl +0x00 @402c20 (dwAnimSeg_OnActivate)
int dwAnimSeg::Activate()
{
    Window_AddMsgHandler(dwAnimSeg_KeyMsgHandler);
    this->bPlaying = 1;
    this->bPaused = 0; // dwSegment clock unpaused (binary writes the field directly)
    this->bKeyHandlerInstalled = 1;
    dwCursor_SetCursor(0); // hide the cursor during movies
    return 1;
}

// vtbl +0x04 @402c50 (dwAnimSeg_OnDeactivate)
void dwAnimSeg::Deactivate()
{
    if (this->bKeyHandlerInstalled != 0)
        Window_RemoveMsgHandler(dwAnimSeg_KeyMsgHandler);
}

// vtbl +0x10 @402c70 (dwAnimSeg_Update)
void dwAnimSeg::Update()
{
    if (this->bPlaying == 0)
        dwSegment_RequestAdvance();
}

// ---- dwFlicSeg -------------------------------------------------------------

// Decode ONE FLC frame into the screen image, compositing over the overlay
// image (pCallbacks) when present. Inlined four times in the binary
// (@401470/@401640, overlay and non-overlay flavors); factored here,
// behavior-identical: lock screen -> [lock overlay ->] decode -> [unlock
// overlay ->] unlock screen. The dwFlicBits geometry comes from each image
// object's desc, the pixels/stride from its Lock.
static void dwFlicSeg_DecodeFrameToScreen(dwFlicSeg* pThis)
{
    dwImage* pScreen;
    dwImage* pOverlay;
    dwFlicBits destBits;
    dwFlicBits overlayBits;
    void* pPixels;
    int stride;

    pScreen = (dwImage*)dwDisplay_pScreenImage; // binary global @0x541c3c
    pPixels = NULL;
    stride = 0;
    pScreen->Lock(&pPixels, &stride); // vtbl +0x0c
    destBits.pPixels = (uint8_t*)pPixels;
    destBits.width = (int16_t)pScreen->desc.width;
    destBits.height = (int16_t)pScreen->desc.height;
    destBits.rowStride = stride;

    pOverlay = (dwImage*)pThis->pCallbacks;
    if (pOverlay != NULL)
    {
        pPixels = NULL;
        stride = 0;
        pOverlay->Lock(&pPixels, &stride);
        overlayBits.pPixels = (uint8_t*)pPixels;
        overlayBits.width = (int16_t)pOverlay->desc.width;
        overlayBits.height = (int16_t)pOverlay->desc.height;
        overlayBits.rowStride = stride;
        dwFlic_DecodeFrame(&pThis->movie, &destBits, &overlayBits);
        pOverlay->Unlock(); // vtbl +0x10
    }
    else
    {
        dwFlic_DecodeFrame(&pThis->movie, &destBits, NULL);
    }
    pScreen->Unlock();
}

// @401410 (dwFlicSeg_Ctor)
dwFlicSeg::dwFlicSeg(const char* pFilename, dwImage* pOverlayImage)
    : dwAnimSeg(pFilename, pOverlayImage)
    , curFrame(0)
{
    // Note: the embedded dwFlic context is left unconstructed like the
    // binary (dwFlic_Open fills it in Activate).
}

// @401460 (dwFlicSeg_Dtor; scalar-deleting wrapper @401440) — base only.
dwFlicSeg::~dwFlicSeg()
{
}

// vtbl +0x00 @401470 (dwFlicSeg_OnActivate)
int dwFlicSeg::Activate()
{
    int result;

    if (dwFlic_Open(&this->movie, this->filename.pBuffer) != 0)
        return 0; // Note: dwFlic_Open always returns 0 (see dwFlic.h) — the
                  // binary's failure return here is an uninitialized byte
    result = dwAnimSeg::Activate(); // direct base call @402c20
    this->curFrame = 0;
    dwFlicSeg_DecodeFrameToScreen(this); // first frame up immediately
    dwDisplay_Present();                 // @444050
    return result;
}

// vtbl +0x04 @401620 (dwFlicSeg_OnDeactivate)
void dwFlicSeg::Deactivate()
{
    if (this->bPlaying != 0)
        dwFlic_Close(&this->movie);
    dwAnimSeg::Deactivate(); // direct base call @402c50
}

// vtbl +0x10 @401640 (dwFlicSeg_Update) — 15 fps schedule off the segment
// clock. Faithful quirks kept: the base Update runs both BEFORE and AFTER
// the decode work, and the decode "loop" is a do/while whose condition
// compares curFrame against the movie frame counter captured at the loop
// top — the two are equal after one pass, so at most ONE frame is decoded
// per tick (catch-up happens across ticks).
void dwFlicSeg::Update()
{
    uint32_t target;
    uint32_t frameBefore;
    int numFrames;
    int bPresent;

    dwAnimSeg::Update(); // faithful: base tick #1 (requests advance once bPlaying == 0)

    if (this->bPlaying != 0 && this->bPaused == 0)
    {
        target = (uint32_t)(int32_t)(this->GetElapsed() * 15.0f); // binary: FMUL [0x51e068] + __ftol
        numFrames = (int16_t)this->movie.numFrames;
        if (target >= (uint32_t)numFrames)
            target = (uint32_t)(numFrames - 1);

        bPresent = 0;
        if (this->curFrame < target)
        {
            bPresent = 1;
            do
            {
                frameBefore = (uint32_t)this->movie.curFrame;
                this->curFrame = (uint32_t)this->movie.curFrame;
                dwFlicSeg_DecodeFrameToScreen(this);
                if (this->movie.curFrame == numFrames)
                    this->bPlaying = 0; // decoder consumed the last frame
            } while (this->curFrame < frameBefore); // faithful: never repeats
        }
        if (bPresent != 0)
            dwDisplay_Present(); // @444050
    }

    dwAnimSeg::Update(); // faithful: base tick #2
}

// ---- dwSmushSeg -------------------------------------------------------------

// @401900 (dwSmushSeg_Ctor)
dwSmushSeg::dwSmushSeg(const char* pFilename, void* pCallbacks)
    : dwAnimSeg(pFilename, pCallbacks)
{
    stdFile_t fh;

    // Re-resolve the name through the DW VFS into this->filename (the
    // external SMUSH library opens with plain OS I/O, so it needs the full
    // path). inits_ResolveAndOpen empties the output first, so a failed
    // resolve leaves filename == "" -> Activate bails.
    fh = inits_ResolveAndOpen(pFilename, "rb", &this->filename);
    if (fh != 0)
        dwMain_pHS->fileClose(fh);
}

// @4019a0 (dwSmushSeg_Dtor; scalar-deleting wrapper @401980) — base only.
dwSmushSeg::~dwSmushSeg()
{
}

// vtbl +0x00 @4019b0 (dwSmushSeg_OnActivate) — original sequence:
//   1. video callback table { CRT stub x2, dwSmushVid_Open, dwSmushVid_Close,
//      dwSmushVid_Clear, dwSmushVid_SetPalette } -> smushPlay_sub_43D080
//   2. smushPlay_sub_43D2E0(dw_settingSoundVol * 127 / 100)   [volume]
//   3. audio callback table { dwSmushAud_Open, _Close, _Stop, _Play,
//      _Service, _GetTime } -> smushPlay_sub_43D060
//   4. if (filename.length != 0):
//        smushPlay_sub_43D0A0(filename.pBuffer, 0, 1000000, 640, 480) == 0
//          -> return dwAnimSeg::Activate()   [movie opened; plays]
//   5. otherwise/failure: return 0 with bPlaying still 0 (the segment's
//      next Update requests the advance).
// The callback tables have no libsmusher counterpart (the glue section below
// absorbs their roles); step 4 becomes dwMovie_SmushOpen.
int dwSmushSeg::Activate()
{
    if (this->filename.length == 0) // binary: filename.length != 0 gate
        return 0;
    if (!dwMovie_SmushOpen(this->filename.pBuffer))
        return 0; // bPlaying stays 0 -> next Update requests the advance
    return dwAnimSeg::Activate();
}

// vtbl +0x04 @401ad0 (dwSmushSeg_OnDeactivate) — original: if (bPlaying)
// smushPlay_sub_43D190() [close the SmushPlay session]; then base.
void dwSmushSeg::Deactivate()
{
    if (dwMovie_pSmush != NULL) // Note: guarded on the session, not bPlaying —
        dwMovie_SmushClose();   // the done path already closed with bPlaying = 0
    dwAnimSeg::Deactivate();
}

// vtbl +0x08 @401af0 (Ghidra: dwSmushSeg_Pause — the Suspend slot) —
// original: if (bPlaying && !bPaused) { if (lecSmush_sub_43DC00() == 0)
// dwSegment::Suspend(); }  (clock suspends only when the codec pause
// succeeded). libsmusher has no codec pause (treated as success); the
// already-queued stdSound audio tail keeps playing through a suspend.
void dwSmushSeg::Suspend()
{
    if (this->bPlaying != 0 && this->bPaused == 0)
        dwSegment::Suspend();
}

// vtbl +0x0c @401b20 (Ghidra: dwSmushSeg_Resume) — mirror of Suspend
// (original gated on lecSmush_sub_43DC30() == 0).
void dwSmushSeg::Resume()
{
    if (this->bPlaying != 0 && this->bPaused != 0)
        dwSegment::Resume();
}

// vtbl +0x10 @401b50 (dwSmushSeg_Update) — original: base Update; then if
// (bPlaying && !bPaused) { int bDone = 0; smushPlay_sub_43D1B0(&bDone)
// [service the player]; if (bDone) { smushPlay_sub_43D190() [close];
// bPlaying = 0; } }. The service call is the pacing loop below: frames are
// paced off the segment clock (dwFlicSeg parity — the binary paced off the
// DirectSound audio clock), decoded frames are row-copied into the back
// buffer and presented via dwMovie_VidPresent (which draws the dwMovie
// overlay when one is active).
void dwSmushSeg::Update()
{
    dwAnimSeg::Update(); // base tick (requests the advance once bPlaying == 0)

    if (this->bPlaying == 0 || this->bPaused != 0 || dwMovie_pSmush == NULL)
        return;

    // Drain the decoded-PCM queue into the stdSound ring (every tick, decode
    // or not).
    dwMovie_SmushAudioPump();

    // The frame the segment clock wants on screen now (clamped to the last
    // frame; dwFlicSeg's pacing shape).
    uint32_t numFrames = (uint32_t)smush_num_frames(dwMovie_pSmush);
    uint32_t target = (uint32_t)(int32_t)(this->GetElapsed() * (float)dwMovie_smushFps);
    if (target >= numFrames)
        target = numFrames - 1;

    if (dwMovie_nextPresentIdx <= target)
    {
        // Decode until the buffered frame IS the target. Catch-up decodes
        // without presenting (codec48 is delta-based — frames can't be
        // skipped, only decoded past); smush_done guards the library's
        // internal loop-restart so it never fires here.
        while (dwMovie_framesDecoded - 1 < target && !smush_done(dwMovie_pSmush))
        {
            smush_frame(dwMovie_pSmush);
            smush_audio_flush(dwMovie_pSmush);
            dwMovie_framesDecoded++;
        }

        // Present the buffered frame (index dwMovie_framesDecoded-1). Note:
        // w/h are re-pulled here (not just at open) — the first FRME can be
        // FOBJ-less, so the open-time snapshot may still be 0x0.
        lecSmush_frameNum = dwMovie_framesDecoded - 1;
        dwMovie_smushW = smush_video_width(dwMovie_pSmush);
        dwMovie_smushH = smush_video_height(dwMovie_pSmush);
        dwMovie_SmushSetPalette();
        dwMovie_SmushBlitFrame();
        rdRect frameRect;
        frameRect.x = 0;
        frameRect.y = 0;
        frameRect.width = (int)dwMovie_smushW;
        frameRect.height = (int)dwMovie_smushH;
        dwMovie_VidPresent(&frameRect);
        dwMovie_nextPresentIdx = dwMovie_framesDecoded; // next frame index due
    }

    // Finished once the LAST frame has been shown (the binary's service-set
    // bDone): close the session and drop bPlaying; the next base Update
    // requests the segment advance.
    if (smush_done(dwMovie_pSmush) && dwMovie_framesDecoded - 1 >= numFrames - 1)
    {
        dwMovie_SmushClose();
        this->bPlaying = 0;
    }
}

// ---- dwMovie -------------------------------------------------------------------

// @4023c0 (dwMovie_Ctor)
dwMovie::dwMovie(const char* pFilename)
    : dwSmushSeg(pFilename, NULL)
    , lastOverlayTimeSec(0.0f) // Note: uninitialized in the binary until Activate
    , overlay()                // full-screen dwWidgetGroup
{
}

// @402440 (dwMovie_Dtor; scalar-deleting wrapper @402420) — the binary body
// is the inlined overlay-group teardown (FreeChildImages + delete children +
// node/sentinel frees) followed by the base dtors; all implicit here.
dwMovie::~dwMovie()
{
}

// vtbl +0x00 @402580 (dwMovie_OnActivate)
int dwMovie::Activate()
{
    int result;

    result = dwSmushSeg::Activate(); // direct base call @4019b0

    // The original re-registered the video callback table with
    // dwMovie_VidPresent in the present slot (smushPlay_sub_43D080 with
    // { CRT stub x2, dwSmushVid_Open, dwMovie_VidPresent, dwSmushVid_Clear,
    // dwSmushVid_SetPalette }) so every decoded frame gets the overlay drawn
    // on top. Here that swap is dwMovie_pActive: dwMovie_VidPresent draws the
    // overlay whenever it is set (see below).

    dwMovie_pActive = this;
    this->lastOverlayTimeSec = this->GetElapsed(); // @434240
    return result;
}

// vtbl +0x04 @4025f0 (dwMovie_OnDeactivate)
void dwMovie::Deactivate()
{
    dwSmushSeg::Deactivate(); // direct base call @401ad0
    if (dwMovie_pActive == this)
        dwMovie_pActive = NULL;
}

// vtbl +0x10 @402610 (dwMovie_Update) — overlay tick throttled to ~45 Hz.
void dwMovie::Update()
{
    float elapsed;
    float delta;
    float absDelta;
    float snapped;

    elapsed = this->GetElapsed();
    delta = elapsed - this->lastOverlayTimeSec;
    absDelta = delta;
    if (delta < 0.0f)
        absDelta = -delta;
    snapped = delta;
    if (absDelta <= 1e-05f)
        snapped = 0.0f;
    if (snapped < 0.022f)
    {
        dwSmushSeg::Update(); // direct base call @401b50
        return;
    }
    this->lastOverlayTimeSec = elapsed;
    this->overlay.Update(delta); // virtual +0x14 on the overlay group (binary:
                                 // dispatched through the overlay's vptr)
    dwSmushSeg::Update();
}

// vtbl +0x18 @402690 (dwMovie_Draw) — NEW virtual; draw the overlay group as
// a child (clip = dest bounds ∩ pClipRect ∩ overlay rect).
void dwMovie::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    this->overlay.DrawChild(pDestBits, pClipRect); // @4424b0
}

// @4026b0 (dwMovie_VidPresent) — SMUSH frame-present callback (the video
// table's present slot; dwSmushVid_Close's role with the dwMovie overlay on
// top). Called from dwSmushSeg::Update once per due frame, after the frame
// has been row-copied into the back buffer (dwMovie_SmushBlitFrame): draws
// the active dwMovie's overlay onto the screen image over the frame rect,
// then presents. pFrameRect is the decoded frame's {x, y, width, height}.
extern "C" int dwMovie_VidPresent(rdRect* pFrameRect)
{
    dwImage* pScreen;
    dwImageBits bits;
    dwRect rect;
    void* pPixels;
    int stride;

    // Note: the binary unlocked the DW back VBuffer @0x6b5a40 here (locked at
    // dwSmushVid_Open as the SMUSH decode target). Our blit locks/unlocks per
    // frame, so there is nothing to unlock.

    if (dwMovie_bPresentDisabled == 0 && dwMovie_pActive != NULL)
    {
        pScreen = (dwImage*)dwDisplay_pScreenImage;
        pPixels = NULL;
        stride = 0;
        pScreen->Lock(&pPixels, &stride); // vtbl +0x0c
        bits.pDesc = &pScreen->desc;
        bits.pPixels = pPixels;
        bits.stride = stride;
        rect.left = (int16_t)pFrameRect->x;
        rect.top = (int16_t)pFrameRect->y;
        rect.right = (int16_t)(pFrameRect->x + pFrameRect->width);
        rect.bottom = (int16_t)(pFrameRect->y + pFrameRect->height);
        dwMovie_pActive->Draw(&bits, &rect); // virtual +0x18
        pScreen->Unlock();
    }

    // Note: binary was the bare DW-stdDisplay GDI flip @0x4fdc60 (the DDraw
    // back buffer became visible directly). Our two-buffer model needs
    // dwDisplay_Present's back->front copy — dwFlicSeg parity.
    dwDisplay_Present();
    return 0;
}

// ---- SMUSH glue (libsmusher — see the banner role map) ------------------------

// @402af0 (dwAnim_SmushStartup) — original: LECSmush_Initialize(pHS, 0),
// SmushPlay_Initialize(pHS, 0), LECSmush_SysStartup(), SmushPlay_SysStartup();
// 1 only if all four returned 0. Caller: StartOpeningCutscenes @41b5de.
// libsmusher needs no global init, so only the binary's flag bookkeeping
// remains.
extern "C" int dwAnim_SmushStartup(void* pHS)
{
    (void)pHS;
    dwAnim_bSmushInitted = 1;
    return 1;
}

// @402b30 (dwAnim_SmushShutdown) — original: smushPlay_sub_43D010(),
// lecSmush_sub_43DBF0(), smushPlay_sub_43CFC0(), tail lecSmush_sub_43DBA0();
// clears dwAnim_bSmushInitted.
extern "C" void dwAnim_SmushShutdown(void)
{
    dwAnim_bSmushInitted = 0;
}

// libsmusher audio callback (smush_audio_callback_t): the library HANDS
// OWNERSHIP of each decoded PCM chunk (smush_audio_flush NULLs its
// audio_buffer_tmp afterwards) — queue it; freed on drain/close. Mirrors
// jkCutscene.c's smush_audio_callback.
extern "C" void dwMovie_SmushAudioCallback(const uint8_t* data, size_t len)
{
    if (dwMovie_audio_queue[dwMovie_audio_queue_write_idx])
    {
        free((void*)dwMovie_audio_queue[dwMovie_audio_queue_write_idx]);
        dwMovie_audio_queue[dwMovie_audio_queue_write_idx] = NULL;
    }

    dwMovie_audio_queue[dwMovie_audio_queue_write_idx] = data;
    dwMovie_audio_queue_lens[dwMovie_audio_queue_write_idx++] = len;
    dwMovie_audio_queue_write_idx = dwMovie_audio_queue_write_idx % DWMOVIE_AUDIO_QUEUE_DEPTH;
}

// Drain the decoded-PCM queue into the stdSound ring (one buffer per call),
// chaining each filled buffer onto buffer 0. Mirrors
// jkCutscene_smacker_smusher_audio_queue (the dwSmushAud_Service role).
static void dwMovie_SmushAudioPump(void)
{
    if (dwMovie_audio_queue_read_idx == dwMovie_audio_queue_write_idx && !dwMovie_audio_len
        && dwMovie_currentAudioWritten >= dwMovie_currentAudioBufSize)
        return; // nothing queued and nothing mid-fill

    // If we ran through the queued samples, fetch new samples
    if (dwMovie_audio_len <= 0)
    {
        if (dwMovie_audio_buf)
        {
            free((void*)dwMovie_audio_buf);
            dwMovie_audio_buf = NULL;
        }
        dwMovie_audio_buf = dwMovie_audio_queue[dwMovie_audio_queue_read_idx];
        dwMovie_audio_len = dwMovie_audio_queue_lens[dwMovie_audio_queue_read_idx];
        dwMovie_audio_pos = dwMovie_audio_buf;

        if (!dwMovie_audio_buf)
            return;

        dwMovie_audio_queue[dwMovie_audio_queue_read_idx] = NULL;
        dwMovie_audio_queue_lens[dwMovie_audio_queue_read_idx++] = 0;
        dwMovie_audio_queue_read_idx = dwMovie_audio_queue_read_idx % DWMOVIE_AUDIO_QUEUE_DEPTH;
    }

    if (!dwMovie_audio_pos || !dwMovie_audio_len)
        return;

    if (!dwMovie_currentAudio)
    {
        dwMovie_audioFlip++;
        if (!dwMovie_audioFlip)
            dwMovie_audioFlip++;
        dwMovie_audioFlip %= DWMOVIE_AUDIO_NUM_STDBUFS;
        dwMovie_currentAudio = dwMovie_audio[dwMovie_audioFlip];

        if (!dwMovie_lastAudio)
            dwMovie_lastAudio = dwMovie_currentAudio;
        dwMovie_currentAudioWritten = 0;

        dwMovie_currentAudioBuf = (uint8_t*)stdSound_BufferSetData(dwMovie_currentAudio, DWMOVIE_AUDIO_BUFS_DEPTH, &dwMovie_currentAudioBufSize);
        memset(dwMovie_currentAudioBuf, 0, dwMovie_currentAudioBufSize);
    }

    uint8_t* stream = dwMovie_currentAudioBuf;
    uint8_t* stream_iter = stream + dwMovie_currentAudioWritten;
    uint32_t stream_left = dwMovie_currentAudioBufSize - dwMovie_currentAudioWritten;

    int32_t written_len = 0;
    while (written_len < (int32_t)stream_left)
    {
        int32_t to_write = ((int32_t)stream_left > (int32_t)dwMovie_audio_len ? (int32_t)dwMovie_audio_len : (int32_t)stream_left);
        if (to_write > 0 && dwMovie_audio_pos)
        {
            memcpy(stream_iter, dwMovie_audio_pos, to_write);
            stream_iter += to_write;
            stream_left -= to_write;
        }

        written_len += to_write;
        dwMovie_audio_pos += to_write;
        dwMovie_audio_len -= to_write;
        dwMovie_currentAudioWritten += to_write;

        if (to_write <= 0)
            break;
    }

    if (dwMovie_currentAudioWritten >= dwMovie_currentAudioBufSize)
    {
        stdSound_BufferUnlock(dwMovie_currentAudio, stream, 0);
        stdSound_BufferQueueAfterAnother(dwMovie_audio[0], dwMovie_currentAudio);

        dwMovie_lastAudio = dwMovie_currentAudio;
        dwMovie_currentAudio = NULL;
        dwMovie_currentAudioWritten = 0;
        dwMovie_currentAudioBufSize = 0;
    }
}

// @401c60 (dwSmushVid_SetPalette) role — original: repack the RGBX entries
// into the RGB dwSmushVid_palette[768], force entry 0 black, and when a
// palettized mode is up push it to the display [SetMasterPalette-style
// @0x4fe430] followed by a gamma re-apply of dwColormap_pDisplayPalette
// [@0x4fe490]. libsmusher tracks delta-palette chunks internally, so the
// current RGB palette is pulled per presented frame (DW's SW display is
// always the palettized mode).
static void dwMovie_SmushSetPalette(void)
{
    uint8_t pal[256 * 3];
    memcpy(pal, smush_get_palette(dwMovie_pSmush), sizeof(pal));
    pal[0] = 0;
    pal[1] = 0;
    pal[2] = 0; // binary quirk: entry 0 forced black
    stdDisplay_SetMasterPalette(pal);
    stdDisplay_GammaCorrect3((int)(intptr_t)dwColormap_pDisplayPalette);
}

// @401b90 (dwSmushVid_Open) role, per frame — the binary locked the back
// VBuffer @0x6b5a40 once and SMUSH decoded straight into it; libsmusher
// decodes into its own 8bpp framebuffer, so row-copy it into the back buffer
// (the dwDisplay_pScreenImage target) at (0,0).
static void dwMovie_SmushBlitFrame(void)
{
    if (dwDisplay_pBackVBuf == NULL || dwMovie_pSmush == NULL)
        return;

    stdDisplay_VBufferLock(dwDisplay_pBackVBuf);
    uint8_t* pDst = (uint8_t*)dwDisplay_pBackVBuf->surface_lock_alloc;
    const uint8_t* pSrc = smush_get_video(dwMovie_pSmush);
    uint32_t dstStride = dwDisplay_pBackVBuf->format.rowWidth; // 8bpp: bytes/row

    // Note: clamps added (retail DW .san are full-frame 640x480).
    uint32_t copyW = dwMovie_smushW;
    if (copyW > (uint32_t)dwDisplay_pBackVBuf->format.width)
        copyW = (uint32_t)dwDisplay_pBackVBuf->format.width;
    uint32_t copyH = dwMovie_smushH;
    if (copyH > (uint32_t)dwDisplay_pBackVBuf->format.height)
        copyH = (uint32_t)dwDisplay_pBackVBuf->format.height;

    for (uint32_t row = 0; row < copyH; row++)
        memcpy(pDst + row * dstStride, pSrc + row * dwMovie_smushW, copyW);

    stdDisplay_VBufferUnlock(dwDisplay_pBackVBuf);
}

// smushPlay_sub_43D0A0 role: open the .san through libsmusher, decode the
// first frame (video dims/fps arrive with it — jkCutscene's open pattern),
// and create the audio ring. Returns nonzero on success.
static int dwMovie_SmushOpen(const char* pPath)
{
    // Note: the DW VFS resolves with Win32 '\' separators; the engine's own
    // opens translate them (Linux_stdFileOpen) but libsmusher's plain fopen
    // does not — convert here ('/' is accepted by Win32 too, so this is
    // safe on every host).
    char aPath[512];
    _strncpy(aPath, pPath, sizeof(aPath) - 1);
    aPath[sizeof(aPath) - 1] = 0;
    for (char* p = aPath; *p != '\0'; p++)
    {
        if (*p == '\\')
            *p = '/';
    }

    dwMovie_pSmush = smush_from_fpath(aPath);
    if (dwMovie_pSmush == NULL)
    {
        // Note: the binary's open-failure path was silent; this print is an
        // added diagnostic (jkCutscene's "Failed to load file" parity).
        stdPlatform_Printf("OpenJKDF2: dwMovie_SmushOpen — failed to open %s as Smush\n", aPath);
        return 0;
    }

    smush_set_debug(dwMovie_pSmush, 0);
    smush_set_audio_buffer_size(dwMovie_pSmush, 0x1000);
    smush_set_audio_callback(dwMovie_pSmush, dwMovie_SmushAudioCallback);
    smush_frame(dwMovie_pSmush); // first frame up (also primes the audio lookahead)

    dwMovie_framesDecoded = 1; // buffer holds frame 0
    dwMovie_nextPresentIdx = 0;
    lecSmush_frameNum = 0;
    dwMovie_smushW = smush_video_width(dwMovie_pSmush);
    dwMovie_smushH = smush_video_height(dwMovie_pSmush);
    dwMovie_smushFps = smush_video_fps(dwMovie_pSmush);
    if (dwMovie_smushFps <= 0) // Note: guard added (unset ahdr_ext)
        dwMovie_smushFps = 15;

    stdPlatform_Printf("OpenJKDF2: Opened %s as Smush (w %u h %u frames %d fps %d)\n",
                       aPath, dwMovie_smushW, dwMovie_smushH,
                       smush_num_frames(dwMovie_pSmush), dwMovie_smushFps);

    // Audio: 32 x 0x8000-byte stdSound buffers — stereo 22050 Hz 16-bit
    // (libsmusher's IACT decode format, jkCutscene's choice) — primed with
    // silence. Volume: binary set the SmushPlay volume to
    // dw_settingSoundVol*127/100 (0..127); the stdSound float is 0..1.
    flex_t volume = (flex_t)dw_settingSoundVol * (flex_t)0.01;
    for (int i = 0; i < DWMOVIE_AUDIO_NUM_STDBUFS; i++)
    {
        int32_t len = 0;
        uint8_t* stream;
        dwMovie_audio[i] = stdSound_BufferCreate(1, 22050, 16, DWMOVIE_AUDIO_BUFS_DEPTH);
        stdSound_BufferSetVolume(dwMovie_audio[i], volume);
        stream = (uint8_t*)stdSound_BufferSetData(dwMovie_audio[i], DWMOVIE_AUDIO_BUFS_DEPTH, &len);
        memset(stream, 0, len);
        stdSound_BufferUnlock(dwMovie_audio[i], stream, len);
        stdSound_BufferReset(dwMovie_audio[i]);
    }
    return 1;
}

// smushPlay_sub_43D190 role: tear the session down — release the stdSound
// ring, free any undrained PCM, destroy the decoder. Fully NULL-guarded so
// dwMovie_Startup can call it defensively.
static void dwMovie_SmushClose(void)
{
    for (int32_t i = 0; i < DWMOVIE_AUDIO_QUEUE_DEPTH; i++)
    {
        if (dwMovie_audio_queue[i])
        {
            free((void*)dwMovie_audio_queue[i]);
            dwMovie_audio_queue[i] = NULL;
        }
        dwMovie_audio_queue_lens[i] = 0;
    }
    dwMovie_audio_queue_read_idx = 0;
    dwMovie_audio_queue_write_idx = 0;

    if (dwMovie_audio_buf)
    {
        free((void*)dwMovie_audio_buf);
        dwMovie_audio_buf = NULL;
    }
    dwMovie_audio_pos = NULL;
    dwMovie_audio_len = 0;

    for (int i = 0; i < DWMOVIE_AUDIO_NUM_STDBUFS; i++)
    {
        if (dwMovie_audio[i])
        {
            stdSound_BufferRelease(dwMovie_audio[i]);
            dwMovie_audio[i] = NULL;
        }
    }
    dwMovie_lastAudio = NULL;
    dwMovie_currentAudio = NULL;
    dwMovie_currentAudioBuf = NULL;
    dwMovie_currentAudioWritten = 0;
    dwMovie_currentAudioBufSize = 0;
    dwMovie_audioFlip = 0;

    if (dwMovie_pSmush)
    {
        smush_destroy(dwMovie_pSmush);
        dwMovie_pSmush = NULL;
    }
    dwMovie_framesDecoded = 0;
    dwMovie_nextPresentIdx = 0;
    dwMovie_smushFps = 0;
    dwMovie_smushW = 0;
    dwMovie_smushH = 0;
    lecSmush_frameNum = 0;
}
