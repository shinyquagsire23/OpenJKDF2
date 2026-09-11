#ifndef _DWSOUND_H
#define _DWSOUND_H

// dwSound — DroidWorks sound manager + three sample classes.
// DroidWorks.exe unit range: 0x444d40-0x44612x.
//
// MANAGER (struct dwSound 0x24, global dwSound_pManager = dwSound_pManagerCached
// @0x541d2c / @0x53d960): owns a name->sample stdHashtbl cache, a circular
// active-voice list, a crossfading music slot and a clockSec driven by a worker
// thread (dwSound_ThreadProc: 25ms tick -> dwSound::Update = advance clock,
// lazy-start pending music, service voices via the sample Update virtual, reap
// finished voices).
//
// SAMPLE CLASSES (verifiably C++ in the binary: vtables @0x520168/0x520188/
// 0x520190, ctor/dtor pairs, MSVC EH frames — hence a .cpp translation):
//   dwSoundSample       base (0x30): stdSound buffer + volume-envelope lerp.
//   dwSoundSampleStatic (0x30): fully-loaded WAV SFX (the GetOrLoadSample kind).
//   dwSoundSampleStream (0x44): streamed/looped from an open file (music).
//
// Dual-language header: classes are C++-only; C consumers (COG glue, future C
// units) get opaque typedefs + the name-keyed C-linkage API below.
//
// Win32/DirectSound adaptations (see the mapping table at the top of
// dwSound.cpp): worker thread -> SDL_CreateThread; the shared dwGob_critSec ->
// a module-local recursive SDL_Mutex; the 0x4000-byte DSound ring of the
// stream class -> two 0x2000 chunk buffers queued via
// stdSound_BufferQueueAfterAnother (jkCutscene streaming pattern).

#include "Dw/dwTypes.h"

#ifdef __cplusplus

#include "Dw/dwString.h"
#include "Dw/dwList.h"

// Engine headers without extern "C" guards — wrap at the include site.
extern "C" {
#include "Win95/stdSound.h"
#include "General/stdHashtbl.h"
}

// Streamed samples: 0x4000-byte ring in the binary, refilled 0x2000 at a time.
#define DWSOUND_STREAM_RING_LEN  0x4000
#define DWSOUND_STREAM_CHUNK_LEN 0x2000

// Base sample: a named stdSound buffer with a volume envelope
// (curVolume lerps startVolume -> targetVolume over fadeStartSec..fadeEndSec).
// vtbl @0x520168 {+0 scalar-deleting dtor, +4 Update}.
struct dwSoundSample
{
    // (vtable @0x00)
    dwString name;             // 0x04: the load name (also the cache hash key)
    stdSound_buffer_t* pBuffer;// 0x10: NULL when the WAV failed to load
    void* pFinishMsg;          // 0x14: finish message CODE (int stored in the
                               //       pointer slot); dwSound::Update dispatches
                               //       { code, pSample, 0, NULL } when the voice ends
    uint8_t bPlaying;          // 0x18
    uint8_t bLooping;          // 0x19
    float curVolume;           // 0x1c
    float startVolume;         // 0x20: envelope start value
    float targetVolume;        // 0x24: envelope end value
    float fadeStartSec;        // 0x28: manager clockSec at envelope start
    float fadeEndSec;          // 0x2c: manager clockSec at envelope end

    // Opens pName via dwMain_pHS, parses the WAV header and creates the
    // stdSound buffer (len = data length, or bufferLen when nonzero).
    // flags was the DSBCAPS static/streaming split; unused here. @444d40
    dwSoundSample(const char* pName, int flags, uint32_t bufferLen);
    virtual ~dwSoundSample();  // @444e50 (dwSoundSample_Dtor; scalar-deleting
                               //  thunk @444e30 = the compiler's delete path)
    virtual void Update();     // @444f60: clear bPlaying when the buffer went
                               //  silent, then ProcessFade
    void ProcessFade();        // @444e80: envelope lerp; 0-crossing ends voice
    void ApplyVolume(float volume);              // @444fa0
    void SetVolume(float volume, float fadeSec); // @444fe0: fadeSec<=0 -> immediate
    uint32_t GetLengthMs();    // @445040: bufferBytes*1000/nAvgBytesPerSec
};

// Fully-loaded SFX sample (the common cache entry). vtbl @0x520188.
struct dwSoundSampleStatic : dwSoundSample
{
    dwSoundSampleStatic(const char* pName); // @4450d0: load whole data chunk
    virtual ~dwSoundSampleStatic();         // @445230 (DtorDelete @445210)
};

// Streamed/looped sample (music/long speech). vtbl @0x520190.
struct dwSoundSampleStream : dwSoundSample
{
    stdFile_t hFile;           // 0x30: file kept open for streaming (dwMain_pHS)
    int dataStartOffset;       // 0x34: WAV data chunk offset (loop seek target)
    uint32_t ringWritePos;     // 0x38: write position within the virtual ring
    int loopDataLen;           // 0x3c: WAV data chunk length
    int bytesRemaining;        // 0x40: unread bytes until the loop wrap

    // Note: adaptation fields (OpenAL queue streaming; see dwSound.cpp):
    stdSound_buffer_t* apChunks[4]; // ring halves as own buffers (2 -> 4 for refill margin, BUG 13)
    int chunkFlip;                  // next chunk index to fill
    float fChunkSec;                // seconds of audio per chunk
    float fQueueEndSec;             // manager clockSec when queued audio runs out

    dwSoundSampleStream(const char* pName); // @445240
    virtual ~dwSoundSampleStream();         // @445320 (DtorDelete @445300)
    virtual void Update();                  // @4454c0: refill to stay >= two chunks ahead
    void FillRing();                        // @445380: stage+queue the next 0x2000
};

// The manager (0x24). One instance, created by dwSound_Startup().
struct dwSound
{
    tHashTable* pSampleCache;         // 0x00: name -> dwSoundSample* (0x65 buckets)
    dwList activeVoices;              // 0x04: circular list of playing samples
    uint8_t bMusicLoop;               // 0x08: loop flag for the pending music
    dwString pendingMusicName;        // 0x0c: music to lazy-start on the worker
    dwSoundSampleStream* pMusicVoice; // 0x18: current music stream (not in list)
    float masterVolume;               // 0x1c: mirror of stdSound menu volume
    float clockSec;                   // 0x20: worker-thread clock (absolute sec)

    dwSound();                        // @4455c0 (dwSound_Startup: the manager
                                      //  ctor; also spawns the worker thread)
    void Shutdown();                  // @445670: stop+free all, join thread
    void SetMenuVolume(float volume); // @445760
    dwSoundSample* FindSample(const char* pName);      // @445780
    dwSoundSample* GetOrLoadSample(const char* pName); // @4457c0
    void FreeSample(dwSoundSample* pSample);           // @445860
    void FreeAllSamples();                             // @445910 (skips playing)
    void SetMusic(const char* pName, uint8_t bLoop);   // @445990 (crossfade)
    void FadeMusic(float volume, float fadeSec);       // @445a30
    dwSoundSampleStream* StartMusicStream(const char* pName, float volume); // @445a70
    int IsPlaying(const char* pName);                  // @445b50
    dwSoundSample* Play(const char* pName);            // @445bb0
    dwSoundSample* PlayLooping(const char* pName);     // @445bf0
    dwSoundSample* StartSample(dwSoundSample* pSample);// @445c50
    void Stop(const char* pName);                      // @445ce0
    static void StopSample(dwSoundSample* pSample);    // @445d20 (no this in binary)
    void RestartSample(dwSoundSample* pSample);        // @445d60
    dwSoundSample* PlayRestart(const char* pName);     // @445de0
    void StopAll();                                    // @445e20 (music too)
    void PauseAll();                                   // @445ed0 (voices only)
    void ResumeAll();                                  // @445f30 (voices only)
    void SetSampleVolume(const char* pName, float volume, float fadeSec); // @445fa0
    void Update(float clockSec);                       // @445fe0 (worker only)
};

#else // !__cplusplus

// Opaque to C: only pointers cross the language boundary.
typedef struct dwSound dwSound;
typedef struct dwSoundSample dwSoundSample;
typedef struct dwSoundSampleStream dwSoundSampleStream;

#endif // __cplusplus

// ---------------------------------------------------------------------------
// C-linkage public API (name-keyed; forwards to dwSound_pManager). Future C
// callers and COG glue use these; C++ units may call the methods directly.
// ---------------------------------------------------------------------------
#ifdef __cplusplus
extern "C" {
#endif

// The manager singleton. dwSound_pManager is the dw-core slot (@0x53d960),
// dwSound_pManagerCached the module's own mirror (@0x541d2c, set by the ctor
// and read by the sample envelope code).
extern dwSound* dwSound_pManager;
extern dwSound* dwSound_pManagerCached;

// Note: added — the binary's dw_Startup news the manager itself; this pair is
// the OpenJKDF2 module entry (full static reset per the soft-reset rule).
int  dwSound_Startup(void);
void dwSound_Shutdown(void);

void dwSound_SetMenuVolume(float volume);
dwSoundSample* dwSound_Play(const char* pName);
dwSoundSample* dwSound_PlayLooping(const char* pName);
dwSoundSample* dwSound_PlayRestart(const char* pName);
void dwSound_Stop(const char* pName);
int  dwSound_IsPlaying(const char* pName);
void dwSound_SetSampleVolume(const char* pName, float volume, float fadeSec);
void dwSound_SetMusic(const char* pName, int bLoop);
void dwSound_FadeMusic(float volume, float fadeSec);
void dwSound_StopAll(void);
void dwSound_PauseAll(void);
void dwSound_ResumeAll(void);

#ifdef __cplusplus
}
#endif

#endif // _DWSOUND_H
