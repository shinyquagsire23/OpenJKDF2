// dwMovie — the DroidWorks full-screen movie SEGMENT family: dwAnimSeg
// (media-segment base + ESC skip), dwFlicSeg (FLC player, fully functional),
// dwSmushSeg (.san base, playback STUBBED) and dwMovie (.san + widget
// overlay), plus the SMUSH callback glue.
//
// Decompiled from DroidWorks.exe, unit range 0x401000-0x404010 (segment
// half; the widget half is dwAnim.cpp). vtables: dwAnimSeg 0x51e108 ·
// dwFlicSeg 0x51e050 · dwSmushSeg 0x51e070 · dwMovie 0x51e0a0 (7 slots —
// dwMovie appends the +0x18 Draw virtual to the 6-slot dwSegment shape).
//
// SMUSH POLICY (DW/DECOMP_PROGRESS.md "Architecture decisions"): the SMUSH
// decode cluster (0x43cf50-0x442390, bounds-only in Ghidra) is NOT
// translated. dwSmushSeg::Activate takes the binary's open-failure path so
// .san segments finish immediately (Update -> dwSegment_RequestAdvance),
// and every dwSmushVid_*/dwSmushAud_* callback is a LOUD no-op stub with
// its original behavior documented in place for the P8 wiring (the repo
// vendors libsmusher). dwFlicSeg is NOT affected — FLC movies play.
//
// Adaptations (marked // Note: below):
//  - DW-stdDisplay calls in dwMovie_VidPresent map per dwDisplay.cpp's
//    table: VBuffer unlock @0x4fdfc0 -> stdDisplay_VBufferUnlock, GDI flip
//    @0x4fdc60 -> stdDisplay_DDrawGdiSurfaceFlip, back buffer @0x6b5a40 ->
//    dwDisplay_pBackVBuf.

#include "Dw/dwMovie.h"

#include "Dw/dwAnim.h" // family header (not strictly needed; keeps the pair discoverable)
#include "Dw/dwFlic.h"
#include "Dw/dwImage.h"
#include "Dw/dwImageVBuf.h"
#include "Dw/dwDisplay.h"
#include "Dw/dwCursor.h"
#include "Dw/dwInits.h"

#include "jk.h"
#include "stdPlatform.h"

// These engine headers have no extern "C" guards of their own — wrap at include site.
extern "C" {
#include "Win95/Window.h"     // Window_AddMsgHandler/Window_RemoveMsgHandler
#include "Win95/stdDisplay.h" // stdDisplay_VBufferUnlock, stdDisplay_DDrawGdiSurfaceFlip
}

extern "C" HostServices* dwMain_pHS; // the DW host-services pointer (dwMain.c); binary global dwHS @0x6b6258

// ---- module globals/statics ---------------------------------------------------

dwMovie* dwMovie_pActive = NULL; // binary: 0x53d6b0
int dwAnim_bSmushInitted = 0;    // binary: dwAnim_bSmushInitted

// binary: DAT_00540620 — written by the lecSmush cluster (untranslated);
// nonzero disables the dwMovie_VidPresent overlay draw (codec error path).
static int dwMovie_bPresentDisabled = 0;

// One-shot warning latch for the SMUSH stubs.
static int dwMovie_bSmushWarned = 0;

static void dwMovie_WarnSmushStubbed(const char* pWhere)
{
    if (!dwMovie_bSmushWarned)
    {
        stdPlatform_Printf("TODO(dw-decomp): SMUSH (.san) playback stubbed (%s) — segment will finish immediately\n", pWhere);
        dwMovie_bSmushWarned = 1;
    }
}

// Note: no binary counterpart — statics reset for the soft-reset loop.
void dwMovie_Startup(void)
{
    dwMovie_pActive = NULL;
    dwAnim_bSmushInitted = 0;
    dwMovie_bPresentDisabled = 0;
    dwMovie_bSmushWarned = 0;
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

// vtbl +0x00 @4019b0 (dwSmushSeg_OnActivate) — STUBBED (SMUSH policy).
// Original sequence:
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
// The stub takes path 5 unconditionally.
int dwSmushSeg::Activate()
{
    dwMovie_WarnSmushStubbed("dwSmushSeg::Activate");
    this->bPlaying = 0; // ctor already left it 0; restated for the policy's sake
    return 0;
}

// vtbl +0x04 @401ad0 (dwSmushSeg_OnDeactivate) — original: if (bPlaying)
// smushPlay_sub_43D190() [close the SmushPlay session]; then base.
void dwSmushSeg::Deactivate()
{
    // TODO(dw-decomp): SMUSH close call elided (bPlaying can never be set
    // while playback is stubbed).
    dwAnimSeg::Deactivate();
}

// vtbl +0x08 @401af0 (Ghidra: dwSmushSeg_Pause — the Suspend slot) —
// original: if (bPlaying && !bPaused) { if (lecSmush_sub_43DC00() == 0)
// dwSegment::Suspend(); }  (clock suspends only when the codec pause
// succeeded). Stub: treat the codec pause as success.
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
// bPlaying = 0; } }. With playback stubbed the branch is unreachable;
// bPlaying = 0 is kept as the "movie finished" outcome.
void dwSmushSeg::Update()
{
    dwAnimSeg::Update();
    if (this->bPlaying != 0 && this->bPaused == 0)
    {
        // TODO(dw-decomp): SMUSH service call elided (see comment above).
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

    result = dwSmushSeg::Activate(); // direct base call @4019b0 (stubbed)

    // TODO(dw-decomp): the original re-registered the video callback table
    // with dwMovie_VidPresent in the present slot (smushPlay_sub_43D080 with
    // { CRT stub x2, dwSmushVid_Open, dwMovie_VidPresent, dwSmushVid_Clear,
    // dwSmushVid_SetPalette }) so every decoded frame gets the overlay drawn
    // on top. Elided while SMUSH is stubbed.

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

// @4026b0 (dwMovie_VidPresent) — SMUSH frame-present callback. Functional
// translation (only touches translated pieces), but nothing installs it
// until SMUSH playback lands (P8).
extern "C" int dwMovie_VidPresent(rdRect* pFrameRect)
{
    dwImage* pScreen;
    dwImageBits bits;
    dwRect rect;
    void* pPixels;
    int stride;

    // Note: binary unlocks the DW back VBuffer @0x6b5a40 (the SMUSH decode
    // target locked by dwSmushVid_Open) -> stdDisplay_VBufferUnlock on
    // dwDisplay_pBackVBuf, guarded here since the stubs never lock it.
    if (dwDisplay_pBackVBuf != NULL)
        stdDisplay_VBufferUnlock(dwDisplay_pBackVBuf); // binary: DW-stdDisplay @0x4fdfc0

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

    stdDisplay_DDrawGdiSurfaceFlip(); // binary: DW-stdDisplay flip @0x4fdc60
    return 0;
}

// ---- SMUSH glue (ALL STUBBED — SMUSH policy) -----------------------------------

// @402af0 (dwAnim_SmushStartup) — original: LECSmush_Initialize(pHS, 0),
// SmushPlay_Initialize(pHS, 0), LECSmush_SysStartup(), SmushPlay_SysStartup();
// 1 only if all four returned 0. Caller: StartOpeningCutscenes @41b5de.
extern "C" int dwAnim_SmushStartup(void* pHS)
{
    (void)pHS;
    dwMovie_WarnSmushStubbed("dwAnim_SmushStartup");
    dwAnim_bSmushInitted = 1; // Note: stub bookkeeping (the binary flag is
                              // managed inside the SMUSH cluster)
    return 1; // pretend success so the boot flow proceeds
}

// @402b30 (dwAnim_SmushShutdown) — original: smushPlay_sub_43D010(),
// lecSmush_sub_43DBF0(), smushPlay_sub_43CFC0(), tail lecSmush_sub_43DBA0();
// clears dwAnim_bSmushInitted.
extern "C" void dwAnim_SmushShutdown(void)
{
    dwAnim_bSmushInitted = 0;
}

// The video callbacks SmushPlay drove while a .san played. Original
// behavior, per callback (for the P8 wiring; DW-stdDisplay addresses in
// [brackets] map per dwDisplay.cpp's table):
//   dwSmushVid_Open(pCtx, pOut) @401b90 — lock the back VBuffer @0x6b5a40
//     [VBufferLock @0x4fdf70]; pCtx = { stride (vbuf lock), pixel base,
//     mode height (stdDisplay_pCurVideoMode->height), 1 }; pOut = { 0, 0,
//     pixel base, mode height }. SMUSH then decodes straight into the back
//     buffer. Returns 0.
//   dwSmushVid_Close() @401bf0 — unlock the back VBuffer [@0x4fdfc0] + GDI
//     flip [@0x4fdc60]. Returns 0. (dwMovie swaps this slot for
//     dwMovie_VidPresent, which also draws the overlay.)
//   dwSmushVid_Clear() @401c10 — fill {0, 0, mode w, mode h} of the back
//     VBuffer with color 0 [VBufferFill @0x4fe010] + flip. Returns 0.
//   dwSmushVid_SetPalette(pRGBX, start, count) @401c60 — repack the RGBX
//     entries into the RGB dwSmushVid_palette[768], force entry 0 black,
//     and when a palettized mode is up push it to the display
//     [SetMasterPalette-style @0x4fe430] followed by a gamma re-apply of
//     dwColormap_pDisplayPalette [@0x4fe490]. Returns 0.

extern "C" int dwSmushVid_Open(uint32_t* pCtx, uint32_t* pOut)
{
    (void)pCtx;
    (void)pOut;
    dwMovie_WarnSmushStubbed("dwSmushVid_Open");
    return 1; // refuse: no decode target
}

extern "C" int dwSmushVid_Close(void)
{
    return 0;
}

extern "C" int dwSmushVid_Clear(void)
{
    return 0;
}

extern "C" int dwSmushVid_SetPalette(uint8_t* pEntriesRGBX, int start, int count)
{
    (void)pEntriesRGBX;
    (void)start;
    (void)count;
    return 0;
}

// The audio callbacks (a DirectSound streaming ring in the original; also
// driven by jkSmack). Original behavior, per callback:
//   dwSmushAud_Open(samplesPerFrame, channels, bits, pCtx) @401cd0 — under
//     the dwGob critical section: allocate + zero a staging buffer
//     (pCtx[3] bytes), create a 5-second looping DirectSound secondary
//     buffer (fmt from the args), set its volume from a 0..127 table, fill
//     it with silence (0x00 for 16-bit, 0x80 for 8-bit), and prime the
//     stream counters (bytesWritten/wrapCount/playCursor/refTimestamp/
//     playbackMs/timeWatermark/bStarted/bPaused/msPerFrame/endPos).
//   dwSmushAud_Close(pCtx) @401fa0 — Stop + Release the DS buffer, free the
//     staging buffer.
//   dwSmushAud_GetTime(pCtx) @401fe0 — the playback clock: ms derived from
//     the DS play cursor + wrap count; wall-clock extrapolation while the
//     buffer is stopped; monotonic watermark; also auto-starts the DS
//     buffer once >= 0.5 s is buffered.
//   dwSmushAud_Stop(pCtx) @402160 — DSBuffer->Stop(); bPaused = 1.
//   dwSmushAud_Play(pCtx) @402190 — bPaused = 0; refTimestamp = now;
//     DSBuffer->Play(looping) + SetCurrentPosition(playCursor).
//   dwSmushAud_Service(pCtx) @4021e0 — the ring writer: compute the
//     writable span from the play cursor/wrap count (keeping ~0x1000 bytes
//     of headroom), Lock/copy-from-staging/Unlock, bytesWritten += n;
//     restart-after-underrun handling (re-Play + reposition when
//     bytesWritten passes endPos).

extern "C" int dwSmushAud_Open(int samplesPerFrame, int numChannels, int bitsPerSample, uint32_t* pCtx)
{
    (void)samplesPerFrame;
    (void)numChannels;
    (void)bitsPerSample;
    (void)pCtx;
    dwMovie_WarnSmushStubbed("dwSmushAud_Open");
    return 0; // original returns the success flag; 0 = failed
}

extern "C" int dwSmushAud_Close(uint32_t* pCtx)
{
    (void)pCtx;
    return 0;
}

extern "C" uint32_t dwSmushAud_GetTime(void* pCtx)
{
    (void)pCtx;
    return 0;
}

extern "C" int dwSmushAud_Stop(void* pCtx)
{
    (void)pCtx;
    return 0;
}

extern "C" int dwSmushAud_Play(void* pCtx)
{
    (void)pCtx;
    return 0;
}

extern "C" void dwSmushAud_Service(void* pCtx)
{
    (void)pCtx;
}
