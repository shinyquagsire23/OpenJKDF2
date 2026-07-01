// stdSound backend for the Sega Dreamcast (KallistiOS), AICA hardware path.
//
// Selected by STDSOUND_DREAMCAST. The engine hands us raw PCM buffers (via
// stdSound_BufferSetData); we upload them to SPU sound RAM on first play and let
// KOS's snd_sfx layer mix them on the AICA (so no software mixer is needed).
//
// Scope / known limits (first pass):
//  - snd_sfx caps a single effect at 65534 samples; longer sounds (some voice
//    lines) won't upload and are silently skipped -- streaming (snd_stream) TBD.
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

static int stdSound_dcReady = 0;

// --- Gapless streaming (cutscene audio) --------------------------------------
// Cutscenes decode ahead of real time and chain fixed PCM chunks via
// stdSound_BufferQueueAfterAnother, expecting seamless back-to-back playback.
// snd_sfx one-shots would overlap into a garbled mess, so those chunks are fed
// into a ring buffer that a single snd_stream channel consumes at real time. A
// tiny KOS thread polls the stream; when it drains and stays idle we stop it so
// snd_sfx gets its channels back until the next cutscene.
#define DC_STREAM_RING (256 * 1024)
static uint8_t  stdSound_dcRing[DC_STREAM_RING];
static volatile uint32_t stdSound_dcRingW = 0;  // absolute write count (producer: engine)
static volatile uint32_t stdSound_dcRingR = 0;  // absolute read count (consumer: stream cb)
static uint8_t  stdSound_dcScratch[SND_STREAM_BUFFER_MAX] __attribute__((aligned(32)));
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

static void* stdSound_dcStreamThread(void* arg)
{
    (void)arg;
    while (stdSound_dcStreamThdRun) {
        if (stdSound_dcStreamOn && stdSound_dcStream != SND_STREAM_INVALID) {
            snd_stream_poll(stdSound_dcStream);
            // Self-stop once fully drained and idle, so snd_sfx reclaims channels.
            if (stdSound_dcRingR == stdSound_dcRingW &&
                (stdPlatform_GetTimeMsec() - stdSound_dcStreamLastMs) > 750) {
                snd_stream_stop(stdSound_dcStream);
                stdSound_dcStreamOn = 0;
            }
        }
        thd_sleep(10);
    }
    return NULL;
}

// Push a chunk's PCM into the ring, (re)starting the stream if needed.
static void stdSound_dcStreamQueue(stdSound_buffer_t* buf)
{
    int rate   = buf->nSamplesPerSec ? (int)buf->nSamplesPerSec : 22050;
    int stereo = buf->bStereo ? 1 : 0;

    if (stdSound_dcStream == SND_STREAM_INVALID) {
        snd_stream_init();
        stdSound_dcStream = snd_stream_alloc(stdSound_dcStreamCb, SND_STREAM_BUFFER_MAX);
        if (stdSound_dcStream == SND_STREAM_INVALID) return;
    }
    if (!stdSound_dcStreamThd) {
        stdSound_dcStreamThdRun = 1;
        stdSound_dcStreamThd = thd_create(0, stdSound_dcStreamThread, NULL);
    }
    if (!stdSound_dcStreamOn) {
        stdSound_dcRingR = stdSound_dcRingW = 0; // fresh stream
        stdSound_dcStreamRate = rate;
        stdSound_dcStreamStereo = stereo;
        snd_stream_start(stdSound_dcStream, rate, stereo);
        stdSound_dcStreamOn = 1;
    }
    // Carry the cutscene's per-buffer volume (cutsceneVolume * menuVolume) onto the
    // stream (0..255).
    {
        int v = (int)(buf->vol * 255.0);
        snd_stream_volume(stdSound_dcStream, v < 0 ? 0 : (v > 255 ? 255 : v));
    }

    uint32_t len   = (uint32_t)buf->bufferBytes;
    uint32_t space = DC_STREAM_RING - (stdSound_dcRingW - stdSound_dcRingR);
    if (len == 0 || len > space) return; // ring full -> drop (better than corrupting)

    uint32_t w     = stdSound_dcRingW % DC_STREAM_RING;
    uint32_t first = (len < DC_STREAM_RING - w) ? len : (DC_STREAM_RING - w);
    memcpy(stdSound_dcRing + w, buf->data, first);
    if (len > first) memcpy(stdSound_dcRing, (uint8_t*)buf->data + first, len - first);
    __asm__ __volatile__("" ::: "memory"); // publish data before advancing the write index
    stdSound_dcRingW += len;
    stdSound_dcStreamLastMs = stdPlatform_GetTimeMsec();
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
    // Stop active channels only. We deliberately do NOT snd_sfx_unload_all(): the
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
    stdSound_buffer_t* out = (stdSound_buffer_t*)std_pHS->alloc(sizeof(stdSound_buffer_t));
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

    if (sound->data && !sound->bIsCopy)
        std_pHS->free(sound->data);

    // The PCM must survive in SPU RAM independently of this buffer; re-uploading
    // means the old handle is stale.
    if (sound->sfxHandle) { snd_sfx_unload(sound->sfxHandle); sound->sfxHandle = 0; }

    sound->data = std_pHS->alloc(bufferBytes);
    if (!sound->data)
        return NULL;
    sound->bufferBytes = bufferBytes;

    _memset(sound->data, 0, sound->bufferBytes);

    return sound->data;
}

int stdSound_BufferUnlock(stdSound_buffer_t* sound, void* buffer, int bufferRead)
{
    return 1;
}

// Upload this buffer's PCM into SPU RAM (once). Returns 1 if a handle is ready.
static int stdSound_dcEnsureLoaded(stdSound_buffer_t* buf)
{
    if (buf->sfxHandle) return 1;
    if (!stdSound_dcReady || !buf->data || buf->bufferBytes <= 0) return 0;

    uint16_t bits  = buf->bitsPerSample ? (uint16_t)buf->bitsPerSample : 16;
    uint16_t chans = buf->bStereo ? 2 : 1;
    uint32_t rate  = buf->nSamplesPerSec ? buf->nSamplesPerSec : 22050;

    // snd_sfx caps at 65534 samples; skip anything longer (would corrupt/fail).
    uint32_t bytesPerSample = (bits / 8) * chans;
    if (bytesPerSample && (uint32_t)buf->bufferBytes / bytesPerSample > 65534)
        return 0;

    buf->sfxHandle = snd_sfx_load_raw_buf((char*)buf->data, buf->bufferBytes, rate, bits, chans);
    return buf->sfxHandle != 0;
}

int stdSound_BufferPlay(stdSound_buffer_t* buf, int loop)
{
    if (!buf) return 0;
    if (!stdSound_dcEnsureLoaded(buf)) return 1; // couldn't upload -> silently no-op

    uint16_t chans = buf->bStereo ? 2 : 1;
    uint16_t bits  = buf->bitsPerSample ? (uint16_t)buf->bitsPerSample : 16;
    uint32_t rate  = buf->freqHz ? (uint32_t)buf->freqHz
                                 : (buf->nSamplesPerSec ? buf->nSamplesPerSec : 22050);

    int vol = (int)(buf->vol * 255.0);
    vol = stdMath_ClampInt(vol, 0, 255);

    sfx_play_data_t d;
    _memset(&d, 0, sizeof(d));
    d.chn  = -1;             // auto-allocate a free channel
    d.idx  = buf->sfxHandle;
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
    if (sound->channel >= 0) { snd_sfx_stop(sound->channel); sound->channel = -1; }
    // Only the owner of the PCM owns its SPU handle; duplicates share `data`.
    if (!sound->bIsCopy) {
        if (sound->sfxHandle) snd_sfx_unload(sound->sfxHandle);
        if (sound->data) std_pHS->free(sound->data);
    }

    memset(sound, 0, sizeof(*sound));
    std_pHS->free(sound);
}

int stdSound_BufferReset(stdSound_buffer_t* sound)
{
    if (!sound) return 0;
    // Stop playback and rewind so the buffer can be refilled and replayed. The SPU
    // handle is kept (the PCM is re-uploaded by BufferSetData when the data changes).
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
}

void stdSound_BufferSetFrequency(stdSound_buffer_t* sound, int freq)
{
    if (sound) sound->freqHz = freq;
}

stdSound_buffer_t* stdSound_BufferDuplicate(stdSound_buffer_t* sound)
{
    stdSound_buffer_t* out = (stdSound_buffer_t*)std_pHS->alloc(sizeof(stdSound_buffer_t));
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
    // A duplicate uploads its own SPU copy lazily on first play.
    out->sfxHandle = 0;
    return out;
}

void stdSound_IA3D_idk(flex_t a)
{
}

int stdSound_BufferStop(stdSound_buffer_t* buf)
{
    if (!buf) return 1;
    if (buf->channel >= 0) { snd_sfx_stop(buf->channel); buf->channel = -1; }
    buf->isPlaying = 0;
    return 1;
}

void stdSound_BufferSetVolume(stdSound_buffer_t* sound, flex_t vol)
{
    if (!sound) return;
    sound->vol = vol * stdSound_fMenuVolume;
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
