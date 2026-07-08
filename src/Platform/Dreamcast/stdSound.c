// stdSound backend for the Sega Dreamcast (KallistiOS), AICA hardware path.
//
// Selected by STDSOUND_DREAMCAST. The engine hands us raw PCM buffers (via
// stdSound_BufferSetData); we upload them to SPU sound RAM on first play and let
// KOS's snd_sfx layer mix them on the AICA (so no software mixer is needed).
//
// Scope / known limits (first pass):
//  - snd_sfx caps a single effect at 65534 samples; longer sounds (the cantina
//    music loop, long voice lines) are routed to memory-fed snd_stream slots.
//  - Volume/pan/frequency are applied at play time. Continuously-updated 3D
//    sources won't retrack mid-playback yet (needs per-channel AICA control).
//  - IsPlaying is a time estimate (KOS doesn't expose a per-channel status here),
//    which is enough for the mixer to reclaim finished one-shots.

#include "Win95/stdSound.h"

#include "Gui/jkGUISound.h"
#include "Main/Main.h"
#include "stdPlatform.h"
#include "General/stdMath.h"

#include <stdio.h>

#include "jk.h"

#ifdef STDSOUND_DREAMCAST

#include <dc/sound/sound.h>
#include <dc/sound/sfxmgr.h>
#include <dc/sound/stream.h>
#include <kos/thread.h>
#include <kos/mutex.h>  // Added: cutscene ring lifecycle lock
#include <malloc.h>    // Added: memalign for the lazy stream scratch

static int stdSound_dcReady = 0;

// --- Refcounted samples --------------------------------------------------------
// The engine is written against DirectSound, where DuplicateSoundBuffer shares
// the sample memory between buffers and lifetime is implicit COM refcounting.
// dcSample carries that: the PCM and its (single, shared) SPU upload live here;
// every buffer -- original or duplicate -- holds a reference. The last release
// unloads the SPU copy and frees the PCM. Duplicates play the SAME SPU sample on
// their own AICA channel (no per-duplicate upload).
typedef struct dcSample {
    int      refs;         // buffers referencing this sample
    void*    data;         // sysram PCM; freed after SPU upload unless bLong
    int      bufferBytes;
    uint32_t sfxHandle;    // shared SPU upload; 0 until first play
    uint16_t bits, chans;
    uint32_t rate;
    int      bLong;        // over the 65534-sample snd_sfx cap -> streamed from data
} dcSample;

static dcSample* stdSound_dcSampleOf(stdSound_buffer_t* buf)
{
    return (dcSample*)buf->pSample;
}

static void stdSound_dcSampleUnref(stdSound_buffer_t* buf)
{
    dcSample* smp = stdSound_dcSampleOf(buf);
    buf->pSample = NULL;
    buf->data = NULL;
    if (!smp) return;
    if (--smp->refs > 0) return;
    if (smp->sfxHandle) snd_sfx_unload(smp->sfxHandle);
    if (smp->data) STD_FREE(smp->data);
    STD_FREE(smp);
}

// --- Gapless streaming (cutscene audio) --------------------------------------
// Cutscenes decode ahead of real time and chain fixed PCM chunks via
// stdSound_BufferQueueAfterAnother, expecting seamless back-to-back playback.
// snd_sfx one-shots would overlap into a garbled mess, so those chunks are fed
// into a ring buffer that a single snd_stream channel consumes at real time. A
// tiny KOS thread polls the stream; when it drains and stays idle we stop it so
// snd_sfx gets its channels back until the next cutscene.
#define DC_STREAM_RING (64 * 1024)
// Added: the SPU-side AICA loop for the cutscene stream. Deliberately small
// (~0.37s of stereo @22kHz) -- snd_stream_start prefills the WHOLE loop, so an
// oversized loop (the stock SND_STREAM_BUFFER_MAX is 64KB/channel = ~1.5s) lays
// down ~1s of silence ahead of the first real sample and permanently shifts the
// audio track behind the video. See stdSound_dcStreamQueue's deferred start.
#define DC_STREAM_SPU_BUF (16 * 1024)
// Added: the ring and its stream scratch (128KB combined) are heap-allocated on
// the first cutscene audio chunk and freed when the stream drains and self-stops
// (cutscenes and gameplay are mutually exclusive, so the memory is returned for
// the level that follows). stdSound_dcRingMtx guards queue-vs-free.
static mutex_t  stdSound_dcRingMtx = MUTEX_INITIALIZER;
static uint8_t* stdSound_dcRing = NULL;
static volatile uint32_t stdSound_dcRingW = 0;  // absolute write count (producer: engine)
static volatile uint32_t stdSound_dcRingR = 0;  // absolute read count (consumer: stream cb)
static uint8_t* stdSound_dcScratch = NULL;      // DC_STREAM_SPU_BUF, 32-byte aligned
static snd_stream_hnd_t stdSound_dcStream = SND_STREAM_INVALID;
static int      stdSound_dcStreamOn = 0;
static int      stdSound_dcStreamRate = 22050;
static int      stdSound_dcStreamStereo = 1;
static volatile uint32_t stdSound_dcStreamLastMs = 0; // last time a chunk was queued
static kthread_t* stdSound_dcStreamThd = NULL;
static volatile int stdSound_dcStreamThdRun = 0;

// snd_stream callback: hand back `req` bytes from the ring, padding with silence
// on underrun. Runs on the poll thread; single-consumer of dcRingR.
static void* stdSound_dcStreamCb(snd_stream_hnd_t hnd, int req, int* recv)
{
    (void)hnd;
    if (!stdSound_dcRing || !stdSound_dcScratch) { *recv = 0; return NULL; } // Added: lazy buffers
    uint32_t avail = stdSound_dcRingW - stdSound_dcRingR;
    uint32_t give  = (avail < (uint32_t)req) ? avail : (uint32_t)req;
    uint32_t r     = stdSound_dcRingR % DC_STREAM_RING;
    uint32_t first = (give < DC_STREAM_RING - r) ? give : (DC_STREAM_RING - r);
    if (first) memcpy(stdSound_dcScratch, stdSound_dcRing + r, first);
    if (give > first) memcpy(stdSound_dcScratch + first, stdSound_dcRing, give - first);
    if (give < (uint32_t)req) memset(stdSound_dcScratch + give, 0, req - give);
    stdSound_dcRingR += give;
    *recv = req;
    return stdSound_dcScratch;
}

static void stdSound_dcLongPollAll(void); // long-sound streaming, defined below

static void* stdSound_dcStreamThread(void* arg)
{
    (void)arg;
    while (stdSound_dcStreamThdRun) {
        if (stdSound_dcStreamOn && stdSound_dcStream != SND_STREAM_INVALID) {
            mutex_lock(&stdSound_dcRingMtx); // Added: the callback reads the ring inside poll
            snd_stream_poll(stdSound_dcStream);
            // Self-stop once fully drained and idle, so snd_sfx reclaims channels.
            if (stdSound_dcRingR == stdSound_dcRingW &&
                (stdPlatform_GetTimeMsec() - stdSound_dcStreamLastMs) > 750) {
                snd_stream_stop(stdSound_dcStream);
                stdSound_dcStreamOn = 0;
                // Added: cutscene over -- return the ring + scratch to the heap.
                if (stdSound_dcRing) {
                    std_g_pHS->free(stdSound_dcRing);
                    stdSound_dcRing = NULL;
                }
                if (stdSound_dcScratch) {
                    free(stdSound_dcScratch);
                    stdSound_dcScratch = NULL;
                }
            }
            mutex_unlock(&stdSound_dcRingMtx);
        }
        stdSound_dcLongPollAll();
        thd_sleep(10);
    }
    return NULL;
}

// Push a chunk's PCM into the ring, (re)starting the stream if needed.
static void stdSound_dcStreamQueue(stdSound_buffer_t* buf)
{
    int rate   = buf->nSamplesPerSec ? (int)buf->nSamplesPerSec : 22050;
    int stereo = buf->bStereo ? 1 : 0;

    mutex_lock(&stdSound_dcRingMtx); // Added: vs. the pump's drain-free
    // Added: first cutscene chunk allocates the ring + scratch (see above);
    // memalign because snd_stream fills the scratch via 32-byte SQ bursts. A
    // fresh ring is a fresh stream, so rewind the cursors when we (re)allocate it.
    if (!stdSound_dcRing) {
        stdSound_dcRing = (uint8_t*)std_g_pHS->alloc(DC_STREAM_RING);
        if (!stdSound_dcRing) { mutex_unlock(&stdSound_dcRingMtx); return; }
        stdSound_dcRingR = stdSound_dcRingW = 0;
    }
    if (!stdSound_dcScratch) {
        stdSound_dcScratch = (uint8_t*)memalign(32, DC_STREAM_SPU_BUF);
        if (!stdSound_dcScratch) { mutex_unlock(&stdSound_dcRingMtx); return; }
    }
    if (stdSound_dcStream == SND_STREAM_INVALID) {
        snd_stream_init();
        // Small SPU loop on purpose (see DC_STREAM_SPU_BUF) -- an oversized loop
        // desyncs the cutscene audio by ~1s.
        stdSound_dcStream = snd_stream_alloc(stdSound_dcStreamCb, DC_STREAM_SPU_BUF);
        if (stdSound_dcStream == SND_STREAM_INVALID) { mutex_unlock(&stdSound_dcRingMtx); return; } // Added
    }
    if (!stdSound_dcStreamThd) {
        stdSound_dcStreamThdRun = 1;
        stdSound_dcStreamThd = thd_create(0, stdSound_dcStreamThread, NULL);
    }
    stdSound_dcStreamRate = rate;
    stdSound_dcStreamStereo = stereo;

    // Copy this chunk into the ring FIRST, so the deferred start below prefills the
    // SPU loop from real audio rather than silence.
    uint32_t len   = (uint32_t)buf->bufferBytes;
    uint32_t space = DC_STREAM_RING - (stdSound_dcRingW - stdSound_dcRingR);
    if (len == 0 || len > space) { // ring full -> drop (better than corrupting)
        mutex_unlock(&stdSound_dcRingMtx);
        return;
    }

    uint32_t w     = stdSound_dcRingW % DC_STREAM_RING;
    uint32_t first = (len < DC_STREAM_RING - w) ? len : (DC_STREAM_RING - w);
    memcpy(stdSound_dcRing + w, buf->data, first);
    if (len > first) memcpy(stdSound_dcRing, (uint8_t*)buf->data + first, len - first);
    __asm__ __volatile__("" ::: "memory"); // publish data before advancing the write index
    stdSound_dcRingW += len;
    stdSound_dcStreamLastMs = stdPlatform_GetTimeMsec();

    // Added: deferred start. snd_stream_start prefills the entire SPU loop
    // (buffer_size * channels bytes) from our callback in one shot; if the ring
    // is short it pads the shortfall with silence and that silence sits *ahead*
    // of the first real sample forever, which is the ~1s cutscene audio lag. So
    // hold off starting until the ring actually holds a full prefill's worth of
    // real audio (one 32KB chunk covers it), then start clean with zero silence.
    if (!stdSound_dcStreamOn) {
        uint32_t prefill  = (uint32_t)DC_STREAM_SPU_BUF * (stereo ? 2u : 1u);
        uint32_t buffered = stdSound_dcRingW - stdSound_dcRingR;
        if (buffered >= prefill) {
            snd_stream_start(stdSound_dcStream, rate, stereo);
            stdSound_dcStreamOn = 1;
        }
    }
    // Carry the cutscene's per-buffer volume (cutsceneVolume * menuVolume) onto the
    // stream (0..255) once it's actually playing.
    if (stdSound_dcStreamOn) {
        int v = (int)(buf->vol * 255.0);
        snd_stream_volume(stdSound_dcStream, v < 0 ? 0 : (v > 255 ? 255 : v));
    }
    mutex_unlock(&stdSound_dcRingMtx);
}

// --- Long-sound streaming (sfx over the 65534-sample snd_sfx cap) -------------
// The AICA's per-channel loop registers hold 16-bit sample positions, so snd_sfx
// can't play anything longer than 65534 samples (the level 1 cantina music loop,
// long voice lines, ...). Those buffers get routed to a snd_stream slot instead,
// fed straight from the buffer's in-memory PCM: the callback walks buf->data and
// wraps for loops, so playback is seamless and touches no disk. Slots are polled
// by the same thread as the cutscene ring.
#define DC_NUM_LONG    2               // stream handles left: 4 - music - cutscene
#define DC_LONG_BUFSZ  (16 << 10)      // per-channel ring in SPU RAM (~0.37s @22kHz)
typedef struct dcLongSlot {
    snd_stream_hnd_t   hnd;
    stdSound_buffer_t* buf;            // whose PCM we stream (data/bufferBytes)
    uint32_t           pos;            // byte position in buf->data
    int                loop;
    volatile int       on;
    volatile uint32_t  doneMs;         // one-shot fully fed at this tick (0 = playing)
} dcLongSlot;
static dcLongSlot stdSound_dcLong[DC_NUM_LONG];
// One shared scratch: all long-slot callbacks run on the single poll thread.
static uint8_t stdSound_dcLongScratch[DC_LONG_BUFSZ * 2] __attribute__((aligned(32)));

static void* stdSound_dcLongCb(snd_stream_hnd_t hnd, int req, int* recv)
{
    dcLongSlot* s = (dcLongSlot*)snd_stream_get_userdata(hnd);
    if (!s || !s->on || !s->buf || !s->buf->data) { *recv = 0; return NULL; }
    if (req > (int)sizeof(stdSound_dcLongScratch)) req = (int)sizeof(stdSound_dcLongScratch);

    uint8_t* src = (uint8_t*)s->buf->data;
    uint32_t total = (uint32_t)s->buf->bufferBytes;
    int got = 0;
    while (got < req) {
        if (s->pos >= total) {
            if (s->loop) s->pos = 0;
            else { if (!s->doneMs) s->doneMs = stdPlatform_GetTimeMsec() | 1; break; }
        }
        uint32_t chunk = total - s->pos;
        if (chunk > (uint32_t)(req - got)) chunk = (uint32_t)(req - got);
        memcpy(stdSound_dcLongScratch + got, src + s->pos, chunk);
        s->pos += chunk;
        got += chunk;
    }
    if (got < req) memset(stdSound_dcLongScratch + got, 0, req - got); // one-shot tail
    *recv = req;
    return stdSound_dcLongScratch;
}

static dcLongSlot* stdSound_dcLongFind(stdSound_buffer_t* buf)
{
    for (int i = 0; i < DC_NUM_LONG; i++)
        if (stdSound_dcLong[i].on && stdSound_dcLong[i].buf == buf)
            return &stdSound_dcLong[i];
    return NULL;
}

static void stdSound_dcLongStop(stdSound_buffer_t* buf)
{
    dcLongSlot* s = stdSound_dcLongFind(buf);
    if (!s) return;
    s->on = 0;
    snd_stream_stop(s->hnd);
    s->buf = NULL;
}

// Poll every bEnabled long slot; retire finished one-shots so the slot frees up.
static void stdSound_dcLongPollAll(void)
{
    for (int i = 0; i < DC_NUM_LONG; i++) {
        dcLongSlot* s = &stdSound_dcLong[i];
        if (!s->on) continue;
        snd_stream_poll(s->hnd);
        // One-shot fully fed: give the SPU ring ~1s to drain, then free the slot.
        if (s->doneMs && (stdPlatform_GetTimeMsec() - s->doneMs) > 1000) {
            s->on = 0;
            snd_stream_stop(s->hnd);
            s->buf = NULL;
        }
    }
}

static int stdSound_dcLongPlay(stdSound_buffer_t* buf, int loop)
{
    // Reuse the buffer's own slot if it's already streaming (restart).
    dcLongSlot* s = stdSound_dcLongFind(buf);
    if (!s) {
        for (int i = 0; i < DC_NUM_LONG; i++) {
            if (!stdSound_dcLong[i].on) { s = &stdSound_dcLong[i]; break; }
        }
    }
    if (!s) return 0; // all slots busy -> silently skip (as before)

    if (s->hnd == SND_STREAM_INVALID || s->hnd == 0) {
        snd_stream_init();
        s->hnd = snd_stream_alloc(stdSound_dcLongCb, DC_LONG_BUFSZ);
        if (s->hnd == SND_STREAM_INVALID) return 0;
    }
    if (!stdSound_dcStreamThd) {
        stdSound_dcStreamThdRun = 1;
        stdSound_dcStreamThd = thd_create(0, stdSound_dcStreamThread, NULL);
    }

    if (s->on) snd_stream_stop(s->hnd);
    s->buf   = buf;
    s->pos   = 0;
    s->loop  = loop;
    s->doneMs = 0;
    snd_stream_set_userdata(s->hnd, s);

    uint32_t rate = buf->freqHz ? (uint32_t)buf->freqHz
                                : (buf->nSamplesPerSec ? buf->nSamplesPerSec : 22050);
    snd_stream_start(s->hnd, rate, buf->bStereo ? 1 : 0);
    {
        int v = (int)(buf->vol * 255.0);
        snd_stream_volume(s->hnd, stdMath_ClampInt(v, 0, 255));
        snd_stream_pan(s->hnd, buf->panVal, buf->panVal);
    }
    s->on = 1;
    return 1;
}

int stdSound_Startup()
{
    jkGuiSound_b3DSound = 0;
    // snd_init uploads the AICA driver; only do it once for the session (the engine
    // calls Startup again across GUI transitions).
    if (!stdSound_dcReady && !Main_bHeadless && snd_init() >= 0)
        stdSound_dcReady = 1;
    return 1;
}

void stdSound_Shutdown()
{
    // Stop bEnabled channels only. We deliberately do NOT snd_sfx_unload_all(): the
    // engine's stdSound buffers still hold their sfxHandles and free them one-by-one
    // in stdSound_BufferRelease, so unloading here would leave dangling handles if
    // Shutdown fires on a transition rather than at exit.
    if (stdSound_dcReady) {
        snd_sfx_stop_all();
        if (stdSound_dcStreamOn) { snd_stream_stop(stdSound_dcStream); stdSound_dcStreamOn = 0; }
    }
}

void stdSound_SetMenuVolume(flex_t a1)
{
    stdSound_fMenuVolume = a1;
}

stdSound_buffer_t* stdSound_BufferCreate(int bStereo, uint32_t nSamplesPerSec, uint16_t bitsPerSample, int bufferLen)
{
    stdSound_buffer_t* out = (stdSound_buffer_t*)STD_ALLOC(sizeof(stdSound_buffer_t));
    if (!out)
        return NULL;

    _memset(out, 0, sizeof(*out));

    out->data = NULL;
    out->bStereo = bStereo;
    out->bufferLen = bufferLen;
    out->nSamplesPerSec = nSamplesPerSec;
    out->bitsPerSample = bitsPerSample;
    out->refcnt = 1;
    out->vol = 1.0 * stdSound_fMenuVolume;
    out->format = 0;
    out->channel = -1;
    out->panVal = 128; // center
    return out;
}

void* stdSound_BufferSetData(stdSound_buffer_t* sound, int bufferBytes, int32_t* bufferMaxSize)
{
    sound->bufferBytes = bufferBytes;

    if (bufferMaxSize)
        *bufferMaxSize = bufferBytes;

    stdSound_dcLongStop(sound); // must not stream from a freed/refilled buffer

    // DirectSound semantics: refilling this buffer makes a NEW sample; duplicates
    // keep the old one alive through their own references.
    stdSound_dcSampleUnref(sound);

    dcSample* smp = (dcSample*)STD_ALLOC(sizeof(dcSample));
    if (!smp)
        return NULL;
    _memset(smp, 0, sizeof(*smp));

    // Long sounds (over the 65534-sample snd_sfx cap) stay resident and are
    // streamed from this buffer, only ever filled word-safely -- so let them
    // land in the VRAM overflow arena and keep megabytes of PCM (cantina loop,
    // long voice lines) out of system RAM. They're cold: read back 16KB per
    // ~0.4s by the stream slot. Short sounds stay in sysram (freed after SPU
    // upload anyway).
    {
        uint16_t bits  = sound->bitsPerSample ? (uint16_t)sound->bitsPerSample : 16;
        uint16_t chans = sound->bStereo ? 2 : 1;
        uint32_t bps   = (bits / 8) * chans;
        int bLong = bps && (uint32_t)bufferBytes / bps > 65534;
        int prevSuggest = bLong ? std_g_pHS->suggestHeap(HEAP_WORD_ADDRESSABLE) : 0;
        smp->data = STD_ALLOC(bufferBytes);
        if (bLong) {
            std_g_pHS->suggestHeap(prevSuggest);
            stdPlatform_Printf("stdSound: long sample %u KB -> %08x\n",
                               (unsigned)(bufferBytes / 1024), (unsigned)(uintptr_t)smp->data);
        }
    }
    if (!smp->data) {
        STD_FREE(smp);
        return NULL;
    }
    smp->refs = 1;
    smp->bufferBytes = bufferBytes;
    // (no memset: DC_alloc already zeroes allocations word-safely)

    sound->pSample = smp;
    sound->data = smp->data;        // engine writes PCM through this pointer
    sound->bufferBytes = bufferBytes;
    return sound->data;
}

int stdSound_BufferUnlock(stdSound_buffer_t* sound, void* buffer, int bufferRead)
{
    return 1;
}

// Upload this buffer's sample into SPU RAM (once, shared with duplicates).
// Returns 1 if the shared handle is ready. On success for short sounds the sysram
// PCM is freed -- the SPU copy is the sample from then on (a refill goes through
// BufferSetData, which makes a new sample).
static int stdSound_dcEnsureLoaded(stdSound_buffer_t* buf)
{
    dcSample* smp = stdSound_dcSampleOf(buf);
    if (!smp) return 0;
    if (smp->sfxHandle) return 1;
    if (!stdSound_dcReady || !smp->data || smp->bufferBytes <= 0) return 0;

    smp->bits  = buf->bitsPerSample ? (uint16_t)buf->bitsPerSample : 16;
    smp->chans = buf->bStereo ? 2 : 1;
    smp->rate  = buf->nSamplesPerSec ? buf->nSamplesPerSec : 22050;

    // snd_sfx caps at 65534 samples; longer sounds stream from sysram instead.
    uint32_t bytesPerSample = (smp->bits / 8) * smp->chans;
    if (bytesPerSample && (uint32_t)smp->bufferBytes / bytesPerSample > 65534) {
        smp->bLong = 1;
        return 0;
    }

    smp->sfxHandle = snd_sfx_load_raw_buf((char*)smp->data, smp->bufferBytes, smp->rate, smp->bits, smp->chans);
    if (!smp->sfxHandle) return 0;

    // SPU copy is authoritative now: reclaim the sysram PCM.
    STD_FREE(smp->data);
    smp->data = NULL;
    buf->data = NULL;
    return 1;
}

int stdSound_BufferPlay(stdSound_buffer_t* buf, int loop)
{
    if (!buf) return 0;

    dcSample* smp = stdSound_dcSampleOf(buf);
    if (!stdSound_dcEnsureLoaded(buf)) {
        // Over the snd_sfx 65534-sample cap (cantina loop, long voice lines): play
        // through a memory-fed snd_stream slot instead of skipping it.
        if (smp && smp->bLong && smp->data) {
            if (stdSound_dcLongPlay(buf, loop)) {
                uint16_t bits_  = smp->bits ? smp->bits : 16;
                uint16_t chans_ = smp->chans ? smp->chans : 1;
                uint32_t bps    = (bits_ / 8) * chans_;
                uint32_t rate_  = buf->freqHz ? (uint32_t)buf->freqHz
                                              : (smp->rate ? smp->rate : 22050);
                buf->isPlaying   = 1;
                buf->isLooping   = loop;
                buf->playStartMs = stdPlatform_GetTimeMsec();
                buf->playDurMs   = (rate_ && bps) ? (uint32_t)(((uint64_t)((uint32_t)smp->bufferBytes / bps) * 1000) / rate_) : 0;
            }
        }
        return 1; // no SPU handle -> silently no-op (as before)
    }

    uint16_t chans = buf->bStereo ? 2 : 1;
    uint16_t bits  = buf->bitsPerSample ? (uint16_t)buf->bitsPerSample : 16;
    uint32_t rate  = buf->freqHz ? (uint32_t)buf->freqHz
                                 : (buf->nSamplesPerSec ? buf->nSamplesPerSec : 22050);

    int vol = (int)(buf->vol * 255.0);
    vol = stdMath_ClampInt(vol, 0, 255);

    sfx_play_data_t d;
    _memset(&d, 0, sizeof(d));
    d.chn  = -1;             // auto-allocate a free channel
    d.idx  = smp->sfxHandle; // shared upload (duplicates play the same SPU sample)
    d.vol  = vol;
    d.pan  = buf->panVal;
    d.loop = loop;
    d.freq = (int)rate;

    buf->channel   = snd_sfx_play_ex(&d);
    buf->isPlaying = 1;
    buf->isLooping = loop;

    // Time-based finish estimate (KOS has no per-channel status query here).
    uint32_t bytesPerSample = (bits / 8) * chans;
    uint32_t samples = bytesPerSample ? ((uint32_t)buf->bufferBytes / bytesPerSample) : 0;
    buf->playStartMs = stdPlatform_GetTimeMsec();
    buf->playDurMs   = rate ? (uint32_t)(((uint64_t)samples * 1000) / rate) : 0;
    return 1;
}

int stdSound_BufferQueueAfterAnother(stdSound_buffer_t* bufPrev, stdSound_buffer_t* bufNext)
{
    // Gapless chunk chaining (cutscenes): feed the PCM into the streaming ring
    // instead of firing overlapping one-shots.
    (void)bufPrev;
    if (!bufNext || !bufNext->data) return 1;
    if (stdSound_dcReady) stdSound_dcStreamQueue(bufNext);
    return 1;
}

void stdSound_BufferRelease(stdSound_buffer_t* sound)
{
    if (!sound) return;
    stdSound_dcLongStop(sound); // must stop before data is freed
    if (sound->channel >= 0) { snd_sfx_stop(sound->channel); sound->channel = -1; }
    // The sample (PCM + the single shared SPU upload) is refcounted: the last
    // buffer out -- original or duplicate, in any order -- tears it down.
    stdSound_dcSampleUnref(sound);

    memset(sound, 0, sizeof(*sound));
    STD_FREE(sound);
}

int stdSound_BufferReset(stdSound_buffer_t* sound)
{
    if (!sound) return 0;
    // Stop playback and rewind so the buffer can be refilled and replayed. The SPU
    // handle is kept (the PCM is re-uploaded by BufferSetData when the data changes).
    stdSound_dcLongStop(sound);
    if (sound->channel >= 0) { snd_sfx_stop(sound->channel); sound->channel = -1; }
    sound->isPlaying = 0;
    sound->isLooping = 0;
    sound->currentSample = 0;
    return 1;
}

void stdSound_BufferSetPan(stdSound_buffer_t* a1, flex_t a2)
{
    if (!a1) return;
    // DirectSound-style pan is roughly -10000 (left) .. +10000 (right).
    int pan = 128 + (int)((a2 / 10000.0) * 127.0);
    a1->panVal = stdMath_ClampInt(pan, 0, 255);
    // Long-sound slots play live off a stream: retrack the pan immediately.
    dcLongSlot* s = stdSound_dcLongFind(a1);
    if (s) snd_stream_pan(s->hnd, a1->panVal, a1->panVal);
}

void stdSound_BufferSetFrequency(stdSound_buffer_t* sound, int freq)
{
    if (sound) sound->freqHz = freq;
}

stdSound_buffer_t* stdSound_BufferDuplicate(stdSound_buffer_t* sound)
{
    stdSound_buffer_t* out = (stdSound_buffer_t*)STD_ALLOC(sizeof(stdSound_buffer_t));
    if (!out)
        return NULL;

    _memset(out, 0, sizeof(*out));

    out->data = sound->data;
    out->bStereo = sound->bStereo;
    out->bufferLen = sound->bufferLen;
    out->nSamplesPerSec = sound->nSamplesPerSec;
    out->bitsPerSample = sound->bitsPerSample;
    out->refcnt = 1;
    out->vol = sound->vol;
    out->format = sound->format;
    out->bufferBytes = sound->bufferBytes;
    out->bIsCopy = 1;
    out->channel = -1;
    out->panVal = sound->panVal;
    out->freqHz = sound->freqHz;
    // DirectSound semantics: the duplicate SHARES the sample (memory + the one
    // SPU upload); it just plays on its own channel.
    out->pSample = sound->pSample;
    out->sfxHandle = 0;
    {
        dcSample* smp = stdSound_dcSampleOf(out);
        if (smp) smp->refs++;
    }
    return out;
}

void stdSound_IA3D_idk(flex_t a)
{
}

int stdSound_BufferStop(stdSound_buffer_t* buf)
{
    if (!buf) return 1;
    stdSound_dcLongStop(buf); // no-op unless this buffer holds a long-sound slot
    if (buf->channel >= 0) { snd_sfx_stop(buf->channel); buf->channel = -1; }
    buf->isPlaying = 0;
    return 1;
}

void stdSound_BufferSetVolume(stdSound_buffer_t* sound, flex_t vol)
{
    if (!sound) return;
    sound->vol = vol * stdSound_fMenuVolume;
    // Long-sound slots play live off a stream: retrack the volume immediately.
    dcLongSlot* s = stdSound_dcLongFind(sound);
    if (s) {
        int v = (int)(sound->vol * 255.0);
        snd_stream_volume(s->hnd, stdMath_ClampInt(v, 0, 255));
    }
}

int stdSound_3DSetMode(stdSound_buffer_t* a1, int a2)
{
    return 1;
}

stdSound_3dBuffer_t* stdSound_BufferQueryInterface(stdSound_buffer_t* pSoundBuffer)
{
    return pSoundBuffer;
}

void stdSound_CommitDeferredSettings()
{
}

void stdSound_SetPositionOrientation(rdVector3 *pos, rdVector3 *lvec, rdVector3 *uvec)
{
}

void stdSound_SetPosition(stdSound_buffer_t* sound, rdVector3 *pos)
{
}

void stdSound_SetVelocity(stdSound_buffer_t* sound, rdVector3 *vel)
{
}

int stdSound_IsPlaying(stdSound_buffer_t* sound, rdVector3 *pos)
{
    if (!sound || !sound->isPlaying) return 0;
    if (sound->isLooping) return 1;             // loops play until explicitly stopped
    if (stdPlatform_GetTimeMsec() - sound->playStartMs < sound->playDurMs)
        return 1;
    sound->isPlaying = 0;
    return 0;
}

void stdSound_3DBufferRelease(stdSound_3dBuffer_t* p3DBuffer)
{
}

#endif // STDSOUND_DREAMCAST
