// dwSound — DroidWorks sound manager + three sample classes.
// DroidWorks.exe unit range: 0x444d40-0x44612x (see dwSound.h for the class map).
//
// DirectSound / Win32 -> OpenJKDF2 mapping used throughout this file:
//   DW stdSound_BufferCreate/ParseWav/BufferSetData/
//     BufferUnlock/BufferPlay/BufferSetVolume/BufferRelease  -> same repo stdSound calls
//   stdSound_FUN_00500c30 (IDSB::Stop + SetCurrentPosition 0) -> stdSound_BufferReset
//   stdSound_FUN_00500c70 (IDSB::Stop only, i.e. pause)       -> stdSound_BufferStop
//   stdSound_FUN_00500d50 (IDSB::Lock at a ring offset)       -> no positional lock in
//       the OpenAL stdSound: each 0x2000 ring half is staged in its own chunk
//       buffer and queued with stdSound_BufferQueueAfterAnother (the
//       jkCutscene streaming pattern); see dwSoundSampleStream::FillRing.
//   IDSB::GetFormat + GetCaps (sample length)                 -> stdSound_buffer_t fields
//   stdSound_IsPlaying(buf, &playCursor)                      -> stdSound_IsPlaying(buf, NULL);
//       the repo variant has no play cursor, so the stream refill decision is
//       re-derived from the manager clock (see dwSoundSampleStream::Update).
//   CreateThread(stack 0x800)/ExitThread/Sleep                -> SDL_CreateThread/return/SDL_Delay
//       (SDL threads get a default stack; the 0x800-byte request is dropped)
//   EnterCriticalSection(dwGob_critSec)                       -> dwSound_Lock() below.
//       The binary shares dwGob's CRITICAL_SECTION; here dwSound gets its OWN
//       recursive SDL_Mutex. Mutual exclusion between dwSound call sites (the
//       part the unit relies on) is preserved; dwGob's file layer keeps its own
//       internal lock. Lock order is always dwSound -> dwGob (dwGob never calls
//       back into dwSound), so the split cannot deadlock. Every Enter/Leave
//       site below sits exactly where the binary's critsec calls sat.
//
// File I/O goes through dwMain_pHS (the DW VFS: dwInits hook + dwGob shim).
// stdSound_ParseWav internally uses std_g_pHS, which points at the SAME
// patched HostServices instance, so GOB-backed handles parse fine.

#include "Dw/dwSound.h"

#include "Dw/dwString.h"
#include "Dw/dwList.h"

extern "C" {
#include "General/stdLinkList.h" // tLinkListNode layout (FreeAllSamples bucket walk)
}

#include <SDL3/SDL.h> // Note: SDL thread/mutex/delay replace the Win32 worker thread bits (desktop-only unit)

extern "C" HostServices* dwMain_pHS; // the DW host-services pointer (dwMain.c)

// dwWidget (P3, landed): dwWidgetMsg + the shared OnMessage dispatcher
// (binary @0x444d00). dwSound::Update builds a { code, pSample, 0, NULL }
// stack msg when a voice with a finish message CODE is reaped.
#include "Dw/dwWidget.h"

// ---------------------------------------------------------------------------
// Module state
// ---------------------------------------------------------------------------
dwSound* dwSound_pManager = NULL;       // @0x53d960 (the dw-core slot)
dwSound* dwSound_pManagerCached = NULL; // @0x541d2c (set by the manager ctor)

static uint8_t dwSound_bShutdownReq = 0; // worker-thread stop request (Ghidra: dwSound_bShutdownReq)
static uint8_t dwSound_bThreadDone = 0;  // worker acknowledges exit (Ghidra: dwSound_bThreadDone)
static SDL_Thread* dwSound_pThread = NULL; // Note: added — SDL thread handle for the clean join
static SDL_Mutex* dwSound_mtx = NULL;      // Note: replaces the shared dwGob_critSec (see file top); lazily created, kept across soft resets

// Note: SDL mutexes are recursive, matching Win32 CRITICAL_SECTION — the unit
// nests its lock several levels deep (e.g. Play -> GetOrLoadSample ->
// FindSample, ThreadProc -> Update -> FillRing).
static void dwSound_Lock(void)
{
    if (dwSound_mtx)
        SDL_LockMutex(dwSound_mtx);
}

static void dwSound_Unlock(void)
{
    if (dwSound_mtx)
        SDL_UnlockMutex(dwSound_mtx);
}

// ---------------------------------------------------------------------------
// dwSoundSample (base)
// ---------------------------------------------------------------------------

// @444d40
dwSoundSample::dwSoundSample(const char* pName, int flags, uint32_t bufferLen)
    : name(pName, 0)
{
    stdFile_t soundFile;
    uint32_t dataLen;
    uint32_t nSamplesPerSec;
    int32_t bitsPerSample;
    int32_t bStereo;
    int32_t seekOffset;

    (void)flags; // Note: was the DSBCAPS static/streaming split; the repo BufferCreate has no flags

    this->pBuffer = NULL;
    this->pFinishMsg = NULL;
    this->bPlaying = 0;
    this->bLooping = 0;
    // Note: the binary left the five envelope floats uninitialized (first
    // StartSample/SetVolume writes them all before ProcessFade can look);
    // zeroed here for determinism.
    this->curVolume = 0.0f;
    this->startVolume = 0.0f;
    this->targetVolume = 0.0f;
    this->fadeStartSec = 0.0f;
    this->fadeEndSec = 0.0f;

    dwSound_Lock();
    soundFile = dwMain_pHS->fileOpen(pName, "rb");
    if (soundFile != 0)
    {
        nSamplesPerSec = 0;
        bitsPerSample = 0;
        bStereo = 0;
        seekOffset = 0;
        dataLen = stdSound_ParseWav(soundFile, &nSamplesPerSec, &bitsPerSample, &bStereo, &seekOffset);
        if (bufferLen != 0)
            dataLen = bufferLen;
        this->pBuffer = stdSound_BufferCreate(bStereo, nSamplesPerSec, (uint16_t)bitsPerSample, dataLen);
        dwMain_pHS->fileClose(soundFile);
    }
    dwSound_Unlock();
}

// @444e50 (dwSoundSample_Dtor; the scalar-deleting thunk @444e30 is the
// compiler-generated delete path)
dwSoundSample::~dwSoundSample()
{
    if (this->pBuffer != NULL)
        stdSound_BufferRelease(this->pBuffer);
    // name is freed by the dwString member dtor (the binary called
    // dwString_Free here explicitly).
}

// @444e80
void dwSoundSample::ProcessFade()
{
    float fVol;

    if (this->bPlaying == 0 || this->pBuffer == NULL)
        return;
    // Quirk kept: the fade also runs when curVolume == targetVolume == 0 (that
    // path ends the voice below).
    if (this->curVolume == this->targetVolume && this->targetVolume != 0.0f)
        return;

    if (dwSound_pManagerCached->clockSec < this->fadeEndSec)
    {
        this->curVolume =
            (this->targetVolume - this->startVolume) *
                ((dwSound_pManagerCached->clockSec - this->fadeStartSec) /
                 (this->fadeEndSec - this->fadeStartSec)) +
            this->startVolume;
    }
    else
    {
        this->curVolume = this->targetVolume;
    }

    fVol = this->curVolume;
    if (fVol < 0.0f)
        fVol = -fVol;
    if (fVol <= 1e-05f)
        fVol = 0.0f;
    else
        fVol = this->curVolume;
    this->curVolume = fVol;

    if (fVol == 0.0f && this->targetVolume == 0.0f)
    {
        this->bPlaying = 0;
        return;
    }
    this->ApplyVolume(fVol);
}

// @444f60 (vtbl +4)
void dwSoundSample::Update()
{
    if (this->bPlaying != 0 && this->pBuffer != NULL)
    {
        // Note: the binary passed an out-param that received the DSound play
        // cursor (unused here); the repo variant writes a position vector, so
        // just pass NULL.
        if (stdSound_IsPlaying(this->pBuffer, NULL) == 0)
            this->bPlaying = 0;
    }
    this->ProcessFade();
}

// @444fa0
void dwSoundSample::ApplyVolume(float volume)
{
    dwSound_Lock();
    this->curVolume = volume;
    if (this->pBuffer != NULL)
    {
        // Note: the repo's OpenAL stdSound_BufferSetVolume STOPS the source at
        // gain 0 (and stdSound_IsPlaying then reports "not playing"), while
        // DirectSound kept a zero-volume buffer playing silently. dwSound
        // depends on the DirectSound behavior (music fades in from volume 0),
        // so the applied gain is floored just above zero; true silence still
        // ends a voice via ProcessFade's epsilon -> bPlaying = 0 -> reap.
        float gain = volume;
        if (gain < 0.001f)
            gain = 0.001f;
        stdSound_BufferSetVolume(this->pBuffer, gain);
    }
    dwSound_Unlock();
}

// @444fe0
void dwSoundSample::SetVolume(float volume, float fadeSec)
{
    float fNow;

    dwSound_Lock();
    if (fadeSec <= 0.0f)
        this->ApplyVolume(volume);
    fNow = dwSound_pManagerCached->clockSec;
    this->targetVolume = volume;
    this->fadeStartSec = fNow;
    this->startVolume = this->curVolume;
    this->fadeEndSec = fNow + fadeSec;
    dwSound_Unlock();
}

// @445040
uint32_t dwSoundSample::GetLengthMs()
{
    uint32_t result = 0;

    dwSound_Lock();
    // Note: the binary asked DirectSound for the format (GetFormat) and caps
    // (GetCaps) and computed dwBufferBytes * 1000 / nAvgBytesPerSec; the
    // stdSound buffer struct carries the same fields directly.
    if (this->pBuffer != NULL) // Note: added guard (the binary dereferenced unconditionally)
    {
        uint32_t bytesPerSec = this->pBuffer->nSamplesPerSec
                             * (this->pBuffer->bStereo ? 2u : 1u)
                             * ((uint32_t)this->pBuffer->bitsPerSample / 8u);
        if (bytesPerSec != 0) // Note: added guard around the binary's raw division
            result = (uint32_t)this->pBuffer->bufferBytes * 1000u / bytesPerSec;
    }
    dwSound_Unlock();
    return result;
}

// ---------------------------------------------------------------------------
// dwSoundSampleStatic — fully-loaded SFX
// ---------------------------------------------------------------------------

// @4450d0
dwSoundSampleStatic::dwSoundSampleStatic(const char* pName)
    : dwSoundSample(pName, 1, 0)
{
    stdFile_t soundFile;
    uint32_t bufferBytes;
    uint32_t nSamplesPerSec;
    int32_t bitsPerSample;
    int32_t bStereo;
    int32_t seekOffset;
    void* pData;
    int32_t maxSize;
    size_t bytesRead;

    dwSound_Lock();
    if (this->pBuffer != NULL)
    {
        soundFile = dwMain_pHS->fileOpen(pName, "rb");
        if (soundFile != 0)
        {
            nSamplesPerSec = 0;
            bitsPerSample = 0;
            bStereo = 0;
            seekOffset = 0;
            bufferBytes = stdSound_ParseWav(soundFile, &nSamplesPerSec, &bitsPerSample, &bStereo, &seekOffset);

            bytesRead = 0;
            maxSize = 0;
            pData = stdSound_BufferSetData(this->pBuffer, bufferBytes, &maxSize);
            if (pData != NULL)
            {
                dwMain_pHS->fseek(soundFile, seekOffset, 0);
                bytesRead = dwMain_pHS->fileRead(soundFile, pData, maxSize);
                stdSound_BufferUnlock(this->pBuffer, pData, maxSize);
            }
            if (bytesRead == 0)
            {
                stdSound_BufferRelease(this->pBuffer);
                this->pBuffer = NULL;
            }
            dwMain_pHS->fileClose(soundFile);
        }
    }
    dwSound_Unlock();
}

// @445230 (DtorDelete @445210)
dwSoundSampleStatic::~dwSoundSampleStatic()
{
    // Nothing beyond the base dtor (the binary only reset the vtable).
}

// ---------------------------------------------------------------------------
// dwSoundSampleStream — streamed/looped from an open file (music)
// ---------------------------------------------------------------------------

// @445240
dwSoundSampleStream::dwSoundSampleStream(const char* pName)
    : dwSoundSample(pName, 0, DWSOUND_STREAM_RING_LEN)
{
    uint32_t dataLen;
    uint32_t nSamplesPerSec;
    int32_t bitsPerSample;
    int32_t bStereo;

    this->hFile = 0;
    this->dataStartOffset = 0;
    this->ringWritePos = 0;
    this->loopDataLen = 0;
    this->bytesRemaining = 0;
    this->apChunks[0] = NULL;
    this->apChunks[1] = NULL;
    this->chunkFlip = 0;
    this->fChunkSec = 0.0f;
    this->fQueueEndSec = 0.0f;

    dwSound_Lock();
    if (this->pBuffer != NULL)
    {
        this->hFile = dwMain_pHS->fileOpen(pName, "rb");
        if (this->hFile != 0)
        {
            nSamplesPerSec = 0;
            bitsPerSample = 0;
            bStereo = 0;
            dataLen = stdSound_ParseWav(this->hFile, &nSamplesPerSec, &bitsPerSample, &bStereo, &this->dataStartOffset);
            this->loopDataLen = (int)dataLen;
            this->bytesRemaining = (int)dataLen;

            // Note: adaptation — the binary streamed into one 0x4000 DSound
            // ring via positional Lock; here the two 0x2000 ring halves are
            // separate chunk buffers queued onto pBuffer's source, and
            // consumption is tracked by wall-clock (no play cursor in the
            // OpenAL stdSound).
            this->apChunks[0] = stdSound_BufferCreate(bStereo, nSamplesPerSec, (uint16_t)bitsPerSample, DWSOUND_STREAM_CHUNK_LEN);
            this->apChunks[1] = stdSound_BufferCreate(bStereo, nSamplesPerSec, (uint16_t)bitsPerSample, DWSOUND_STREAM_CHUNK_LEN);
            uint32_t bytesPerSec = nSamplesPerSec * (bStereo ? 2u : 1u) * ((uint32_t)bitsPerSample / 8u);
            if (bytesPerSec != 0)
                this->fChunkSec = (float)DWSOUND_STREAM_CHUNK_LEN / (float)bytesPerSec;
        }
    }
    dwSound_Unlock();
}

// @445320 (DtorDelete @445300)
dwSoundSampleStream::~dwSoundSampleStream()
{
    if (this->hFile != 0)
        dwMain_pHS->fileClose(this->hFile);
    // Note: adaptation — release the chunk buffers (the binary had no
    // per-chunk objects; the ring died with pBuffer in the base dtor).
    if (this->apChunks[0] != NULL)
        stdSound_BufferRelease(this->apChunks[0]);
    if (this->apChunks[1] != NULL)
        stdSound_BufferRelease(this->apChunks[1]);
}

// @445380 — stage the next 0x2000 bytes from the file (wrapping to
// dataStartOffset at the end of the data chunk, endlessly) and queue them.
// The binary locked the DSound ring at ringWritePos (twice on ring wrap,
// stdSound_FUN_00500d50) and wrote in place; here the bytes go into the next
// chunk buffer, which is queued after pBuffer's source (starting playback if
// it wasn't running — jkCutscene pattern).
void dwSoundSampleStream::FillRing()
{
    uint8_t* pDst;
    int32_t maxSize;
    uint32_t want;
    uint32_t off;
    uint32_t readLen;
    size_t got;
    stdSound_buffer_t* pChunk;

    dwSound_Lock();
    pChunk = this->apChunks[this->chunkFlip];
    if (this->hFile != 0 && pChunk != NULL)
    {
        this->chunkFlip ^= 1;
        maxSize = 0;
        pDst = (uint8_t*)stdSound_BufferSetData(pChunk, DWSOUND_STREAM_CHUNK_LEN, &maxSize);
        if (pDst != NULL)
        {
            want = (uint32_t)maxSize;
            off = 0;
            while (want != 0)
            {
                readLen = want;
                if ((uint32_t)this->bytesRemaining < readLen)
                    readLen = (uint32_t)this->bytesRemaining;
                got = dwMain_pHS->fileRead(this->hFile, pDst + off, readLen);
                this->bytesRemaining -= (int)got;
                if (dwMain_pHS->fileEof(this->hFile) == 0 && this->bytesRemaining != 0)
                {
                    // Short read without EOF: bail (as the binary; the rest of
                    // the chunk stays zero-filled from BufferSetData).
                    if (got != want)
                        break;
                }
                else
                {
                    // End of the data chunk: loop back (streams loop endlessly
                    // at the ring level; bLooping only steers BufferPlay).
                    this->bytesRemaining = this->loopDataLen;
                    dwMain_pHS->fseek(this->hFile, this->dataStartOffset, 0);
                }
                off += (uint32_t)got;
                this->ringWritePos = (this->ringWritePos + (uint32_t)got) & (DWSOUND_STREAM_RING_LEN - 1);
                want -= (uint32_t)got;
            }
            stdSound_BufferUnlock(pChunk, pDst, maxSize);
            stdSound_BufferQueueAfterAnother(this->pBuffer, pChunk);

            // Note: adaptation — wall-clock bookkeeping standing in for the
            // DSound play cursor (see Update).
            if (dwSound_pManagerCached != NULL)
            {
                if (this->fQueueEndSec < dwSound_pManagerCached->clockSec)
                    this->fQueueEndSec = dwSound_pManagerCached->clockSec;
                this->fQueueEndSec += this->fChunkSec;
            }
        }
    }
    dwSound_Unlock();
}

// @4454c0 (vtbl +4)
void dwSoundSampleStream::Update()
{
    // The binary read the play cursor out of stdSound_IsPlaying and refilled
    // when fewer than 0x2000 valid bytes remained ahead of it. The repo
    // stdSound has no play cursor, so the same "less than one chunk left"
    // test is done against the manager clock.
    if (stdSound_IsPlaying(this->pBuffer, NULL) == 0)
    {
        this->bPlaying = 0;
    }
    else if (this->fChunkSec > 0.0f && dwSound_pManagerCached != NULL &&
             (this->fQueueEndSec - dwSound_pManagerCached->clockSec) < this->fChunkSec)
    {
        this->FillRing();
    }
    this->ProcessFade();
}

// ---------------------------------------------------------------------------
// Worker thread
// ---------------------------------------------------------------------------

// @445520 — every 25ms, under the lock, advance the manager clock and service
// everything. Note: SDL_ThreadFunction shape (returns instead of ExitThread).
extern "C" int dwSound_ThreadProc(void* pParam)
{
    dwSound* pMgr = (dwSound*)pParam;
    uint32_t startTick;
    uint32_t nowTick;
    float ticksPerSec;

    startTick = dwMain_pHS->getTimerTick();
    do
    {
        nowTick = dwMain_pHS->getTimerTick();
        ticksPerSec = (float)dwMain_pHS->some_float; // 1000 (ms ticks)
        dwSound_Lock();
        pMgr->Update((float)(nowTick - startTick) / ticksPerSec);
        dwSound_Unlock();
        SDL_Delay(25);
    } while (dwSound_bShutdownReq == 0);
    dwSound_bThreadDone = 1;
    return 0; // Note: replaces ExitThread(0)
}

// ---------------------------------------------------------------------------
// dwSound manager
// ---------------------------------------------------------------------------

// @4455c0 (dwSound_Startup — the manager ctor; the binary's dw_Startup news
// the object and calls this). activeVoices/pendingMusicName are constructed
// by their member ctors, exactly as the binary's inline ctors did.
dwSound::dwSound()
{
    this->pSampleCache = NULL;
    this->pMusicVoice = NULL;
    this->bMusicLoop = 0; // Note: the binary left this byte uninitialized
    this->masterVolume = 1.0f;
    this->clockSec = 0.0f;
    dwSound_pManagerCached = this;
    this->pSampleCache = stdHashtbl_New(0x65);
    dwSound_bShutdownReq = 0;
    dwSound_bThreadDone = 0;
    if (dwSound_mtx == NULL)
        dwSound_mtx = SDL_CreateMutex();
    // Note: CreateThread(stack 0x800) -> SDL_CreateThread (default stack)
    dwSound_pThread = SDL_CreateThread(dwSound_ThreadProc, "dwSound", this);
}

// @445670
void dwSound::Shutdown()
{
    this->StopAll();
    this->FreeAllSamples();
    dwSound_bShutdownReq = 1;
    // Note: the binary polled dwSound_bThreadDone with Sleep(75) forever; a
    // clean SDL_WaitThread join replaces the poll (same end state).
    if (dwSound_pThread != NULL)
    {
        SDL_WaitThread(dwSound_pThread, NULL);
        dwSound_pThread = NULL;
    }
    stdHashtbl_Free(this->pSampleCache);
    this->pSampleCache = NULL;
    dwSound_pManagerCached = NULL;
    this->pendingMusicName.Free();
    // Free every voice node + the sentinel (the binary inlines dwList::Free).
    this->activeVoices.Free();
}

// @445760
void dwSound::SetMenuVolume(float volume)
{
    this->masterVolume = volume;
    stdSound_SetMenuVolume(volume);
}

// @445780
dwSoundSample* dwSound::FindSample(const char* pName)
{
    dwSoundSample* pSample;

    dwSound_Lock();
    pSample = (dwSoundSample*)stdHashtbl_Find(this->pSampleCache, pName);
    dwSound_Unlock();
    return pSample;
}

// @4457c0 — no top-level lock in the binary (FindSample/the ctor lock
// internally; callers that need atomicity hold the lock already).
dwSoundSample* dwSound::GetOrLoadSample(const char* pName)
{
    dwSoundSample* pSample;

    pSample = this->FindSample(pName);
    if (pSample == NULL)
    {
        pSample = new dwSoundSampleStatic(pName);
        if (pSample != NULL)
        {
            if (pSample->pBuffer == NULL)
            {
                delete pSample;
                pSample = NULL;
            }
            else
            {
                stdHashtbl_Add(this->pSampleCache, pSample->name.pBuffer, pSample);
            }
        }
    }
    return pSample;
}

// @445860
void dwSound::FreeSample(dwSoundSample* pSample)
{
    dwListNode* pSent;
    dwListNode* pNode;

    dwSound_Lock();
    dwSound::StopSample(pSample);
    stdHashtbl_Remove(this->pSampleCache, pSample->name.pBuffer);
    pSent = this->activeVoices.pSentinel;
    for (pNode = pSent->pNext; pNode != pSent && (dwSoundSample*)pNode->pData != pSample; pNode = pNode->pNext)
    {
    }
    if (pNode != pSent)
        this->activeVoices.UnlinkFreeNode(pNode);
    if (pSample != NULL)
        delete pSample;
    dwSound_Unlock();
}

// @445910 — free every cached sample that is not currently playing.
void dwSound::FreeAllSamples()
{
    tHashTable* pTable;
    tHashLink* pBucket;
    tHashLink* pTail;
    tHashLink* pIter;
    tHashLink* pPrev;
    dwSoundSample* pSample;
    int idx;

    SDL_Delay(50); // Sleep(0x32): let in-flight stops settle first
    dwSound_Lock();
    pTable = this->pSampleCache;
    if (pTable != NULL)
    {
        for (idx = 0; idx < pTable->numNodes; idx++)
        {
            // Walk to the bucket chain's tail, then free backwards so
            // stdHashtbl_Remove (inside FreeSample) never frees a node we
            // still have to visit — same trick as the binary.
            pBucket = &pTable->aSymbols[idx];
            pTail = pBucket;
            for (pIter = pBucket->next; pIter != NULL; pIter = pIter->next)
                pTail = pIter;
            pIter = pTail;
            while (pIter != NULL)
            {
                pPrev = pIter->prev;
                pSample = (dwSoundSample*)pIter->value;
                if (pSample != NULL && pSample->bPlaying == 0)
                    this->FreeSample(pSample);
                pIter = pPrev;
            }
            pTable = this->pSampleCache; // the binary reloads per iteration
        }
    }
    dwSound_Unlock();
}

// @445990 — queue new music; the worker crossfades: the old stream fades to 0
// (0.25s loop music / 0.01s one-shot / 0.75s when stopping), gets reaped, and
// Update lazy-starts pendingMusicName.
void dwSound::SetMusic(const char* pName, uint8_t bLoop)
{
    float fadeSec;

    dwSound_Lock();
    this->bMusicLoop = bLoop;
    if (this->pMusicVoice == NULL)
    {
        this->pendingMusicName.AssignCStr(pName);
        dwSound_Unlock();
        return;
    }
    fadeSec = (bLoop != 0) ? 0.25f : 0.01f;
    if (pName == NULL)
    {
        fadeSec = 0.75f;
    }
    else if (dwString_Equals(this->pMusicVoice->name.pBuffer, pName))
    {
        dwSound_Unlock();
        return;
    }
    this->pendingMusicName.AssignCStr(pName);
    this->pMusicVoice->SetVolume(0.0f, fadeSec);
    dwSound_Unlock();
}

// @445a30
void dwSound::FadeMusic(float volume, float fadeSec)
{
    dwSound_Lock();
    if (this->pMusicVoice != NULL)
        this->pMusicVoice->SetVolume(volume, fadeSec);
    dwSound_Unlock();
}

// @445a70 — open + prime + start the music stream. Quirk kept: if a CACHED
// sample already owns the name, nothing starts and the current pMusicVoice
// (usually NULL) is returned.
dwSoundSampleStream* dwSound::StartMusicStream(const char* pName, float volume)
{
    dwSoundSampleStream* pStream;

    dwSound_Lock();
    if (this->FindSample(pName) == NULL)
    {
        pStream = new dwSoundSampleStream(pName);
        this->pMusicVoice = pStream;
        if (pStream != NULL)
        {
            if (pStream->pBuffer != NULL)
            {
                pStream->FillRing();
                this->pMusicVoice->ApplyVolume(volume);
                // Note: with the queue adaptation the source is already
                // playing after FillRing; BufferPlay(loop=1) is kept for the
                // binary's success check (it just re-plays the queue head).
                if (stdSound_BufferPlay(this->pMusicVoice->pBuffer, 1) != 0)
                    this->pMusicVoice->bPlaying = 1;
                dwSound_Unlock();
                return this->pMusicVoice;
            }
            delete pStream;
        }
        this->pMusicVoice = NULL;
    }
    dwSound_Unlock();
    return this->pMusicVoice;
}

// @445b50
int dwSound::IsPlaying(const char* pName)
{
    dwSoundSample* pSample;

    dwSound_Lock();
    pSample = this->FindSample(pName);
    if (pSample != NULL && pSample->bPlaying != 0 && pSample->curVolume > 0.0f)
    {
        dwSound_Unlock();
        return 1;
    }
    dwSound_Unlock();
    return 0;
}

// @445bb0
dwSoundSample* dwSound::Play(const char* pName)
{
    dwSoundSample* pSample;

    dwSound_Lock();
    pSample = this->GetOrLoadSample(pName);
    this->StartSample(pSample);
    dwSound_Unlock();
    return pSample;
}

// @445bf0 — quirk kept: an already-cached one-shot sample is stopped, flagged
// looping, and re-fetched (the second GetOrLoadSample returns the same object).
dwSoundSample* dwSound::PlayLooping(const char* pName)
{
    dwSoundSample* pSample;

    dwSound_Lock();
    pSample = this->GetOrLoadSample(pName);
    if (pSample != NULL && pSample->bLooping == 0)
    {
        dwSound::StopSample(pSample);
        pSample->bLooping = 1;
        pSample = this->GetOrLoadSample(pName);
    }
    this->StartSample(pSample);
    dwSound_Unlock();
    return pSample;
}

// @445c50 — start (if stopped) + snap volume to 1, adding a voice-list node.
dwSoundSample* dwSound::StartSample(dwSoundSample* pSample)
{
    dwSound_Lock();
    if (pSample != NULL && pSample->pBuffer != NULL)
    {
        if (pSample->bPlaying == 0)
        {
            if (stdSound_BufferPlay(pSample->pBuffer, pSample->bLooping != 0) != 0)
            {
                pSample->bPlaying = 1;
                // push-back: insert after the sentinel's prev (the tail)
                this->activeVoices.InsertAfter(this->activeVoices.pSentinel->pPrev, pSample);
            }
        }
        pSample->SetVolume(1.0f, 0.0f);
    }
    dwSound_Unlock();
    return pSample;
}

// @445ce0
void dwSound::Stop(const char* pName)
{
    dwSoundSample* pSample;

    dwSound_Lock();
    pSample = this->FindSample(pName);
    if (pSample != NULL)
        dwSound::StopSample(pSample);
    dwSound_Unlock();
}

// @445d20 — static in effect (no this in the binary): flag the sample stopped
// and give the worker a tick to reap it. (When the caller holds the lock the
// delay just waits; the reap then happens on the next worker tick — same as
// the original recursive critsec.)
void dwSound::StopSample(dwSoundSample* pSample)
{
    dwSound_Lock();
    if (pSample != NULL && pSample->bPlaying != 0)
        pSample->bPlaying = 0;
    dwSound_Unlock();
    SDL_Delay(25); // Sleep(0x19)
}

// @445d60 — rewind + replay a playing sample (or just start it).
void dwSound::RestartSample(dwSoundSample* pSample)
{
    if (pSample == NULL)
        return;
    if (pSample->bPlaying == 0)
    {
        this->StartSample(pSample);
        return;
    }
    dwSound_Lock();
    stdSound_BufferReset(pSample->pBuffer); // Stop + SetCurrentPosition(0)
    if (stdSound_BufferPlay(pSample->pBuffer, pSample->bLooping != 0) != 0)
    {
        pSample->SetVolume(1.0f, 0.0f);
        dwSound_Unlock();
        return;
    }
    pSample->bPlaying = 0;
    dwSound_Unlock();
}

// @445de0
dwSoundSample* dwSound::PlayRestart(const char* pName)
{
    dwSoundSample* pSample;

    dwSound_Lock();
    pSample = this->GetOrLoadSample(pName);
    this->RestartSample(pSample);
    dwSound_Unlock();
    return pSample;
}

// @445e20 — stop + drop every voice node, and kill the music stream.
void dwSound::StopAll()
{
    dwListNode* pSent;
    dwListNode* pNode;
    dwListNode* pNext;
    dwSoundSample* pSample;

    dwSound_Lock();
    pSent = this->activeVoices.pSentinel;
    for (pNode = pSent->pNext; pNode != pSent; pNode = pNext)
    {
        pNext = pNode->pNext;
        pSample = (dwSoundSample*)pNode->pData;
        pSample->bPlaying = 0;
        stdSound_BufferReset(pSample->pBuffer);
        this->activeVoices.UnlinkFreeNode(pNode);
    }
    if (this->pMusicVoice != NULL)
    {
        stdSound_BufferReset(this->pMusicVoice->pBuffer);
        delete this->pMusicVoice;
        this->pMusicVoice = NULL;
    }
    dwSound_Unlock();
}

// @445ed0 — pause the active voices (NOT the music stream, as in the binary).
// Quirk kept: the worker's next Update sees the paused buffers as not playing
// and reaps them, so this is effectively a stop for anything not re-Played.
void dwSound::PauseAll()
{
    dwListNode* pSent;
    dwListNode* pNode;
    dwSoundSample* pSample;

    dwSound_Lock();
    pSent = this->activeVoices.pSentinel;
    for (pNode = pSent->pNext; pNode != pSent; pNode = pNode->pNext)
    {
        pSample = (dwSoundSample*)pNode->pData;
        if (pSample != NULL && pSample->pBuffer != NULL)
            stdSound_BufferStop(pSample->pBuffer); // Stop-only (pause)
    }
    dwSound_Unlock();
}

// @445f30
void dwSound::ResumeAll()
{
    dwListNode* pSent;
    dwListNode* pNode;
    dwSoundSample* pSample;

    dwSound_Lock();
    pSent = this->activeVoices.pSentinel;
    for (pNode = pSent->pNext; pNode != pSent; pNode = pNode->pNext)
    {
        pSample = (dwSoundSample*)pNode->pData;
        if (pSample != NULL && pSample->pBuffer != NULL)
            stdSound_BufferPlay(pSample->pBuffer, pSample->bLooping != 0);
    }
    dwSound_Unlock();
}

// @445fa0
void dwSound::SetSampleVolume(const char* pName, float volume, float fadeSec)
{
    dwSoundSample* pSample;

    dwSound_Lock();
    pSample = this->FindSample(pName);
    if (pSample != NULL)
        pSample->SetVolume(volume, fadeSec);
    dwSound_Unlock();
}

// @445fe0 — the worker tick (runs under the lock, from dwSound_ThreadProc):
// advance the clock, lazy-start pending music, service each voice via the
// Update virtual, reap finished voices (dispatching their finish message).
void dwSound::Update(float clockSec_)
{
    dwListNode* pSent;
    dwListNode* pNode;
    dwListNode* pNext;
    dwSoundSample* pSample;
    float fadeSec;

    this->clockSec = clockSec_;

    if (this->pMusicVoice == NULL && this->pendingMusicName.length != 0)
    {
        this->pMusicVoice = this->StartMusicStream(this->pendingMusicName.pBuffer, 0.0f);
        this->pendingMusicName.Free();
        if (this->pMusicVoice != NULL)
        {
            fadeSec = (this->bMusicLoop != 0) ? 0.25f : 0.0f;
            this->pMusicVoice->SetVolume(0.0f, 0.0f);
            this->pMusicVoice->SetVolume(1.0f, fadeSec);
        }
    }

    pSent = this->activeVoices.pSentinel;
    for (pNode = pSent->pNext; pNode != pSent; pNode = pNext)
    {
        pNext = pNode->pNext;
        pSample = (dwSoundSample*)pNode->pData;
        if (pSample->bPlaying != 0)
            pSample->Update(); // vtbl +4
        if (pSample->bPlaying == 0)
        {
            stdSound_BufferReset(pSample->pBuffer);
            if (pSample->pFinishMsg != NULL)
            {
                // binary @446093: the field is the finish message CODE (int in
                // the pointer slot); the reap builds a stack msg with the
                // sample as sender and dispatches THAT (not the field itself).
                dwWidgetMsg finishMsg;
                finishMsg.code = (int32_t)(intptr_t)pSample->pFinishMsg;
                finishMsg.pSender = pSample;
                finishMsg.param = 0;
                finishMsg.pTarget = NULL;
                dwWidget_DispatchMsg(&finishMsg, NULL); // binary @444d00
            }
            this->activeVoices.UnlinkFreeNode(pNode);
        }
    }

    if (this->pMusicVoice != NULL)
    {
        if (this->pMusicVoice->bPlaying != 0)
            this->pMusicVoice->Update();
        if (this->pMusicVoice->bPlaying == 0)
        {
            stdSound_BufferReset(this->pMusicVoice->pBuffer);
            delete this->pMusicVoice;
            this->pMusicVoice = NULL;
        }
    }
}

// ---------------------------------------------------------------------------
// C-linkage public API (singleton wrappers). Note: added — the binary's
// callers hold dwSound_pManager and call the methods; these wrappers give
// C/COG code the same name-keyed surface.
// ---------------------------------------------------------------------------

extern "C" int dwSound_Startup(void)
{
    // Note: added guard — a re-Startup without Shutdown (soft-reset loop)
    // must not leak the manager or double-start the worker thread.
    if (dwSound_pManager != NULL)
        dwSound_Shutdown();

    // Statics reset (soft-reset rule); dwSound_mtx is intentionally kept.
    dwSound_pManagerCached = NULL;
    dwSound_bShutdownReq = 0;
    dwSound_bThreadDone = 0;
    dwSound_pThread = NULL;

    dwSound_pManager = new dwSound();
    return dwSound_pManager != NULL;
}

extern "C" void dwSound_Shutdown(void)
{
    if (dwSound_pManager == NULL)
        return;
    dwSound_pManager->Shutdown();
    delete dwSound_pManager;
    dwSound_pManager = NULL;
}

extern "C" void dwSound_SetMenuVolume(float volume)
{
    if (dwSound_pManager != NULL)
        dwSound_pManager->SetMenuVolume(volume);
}

extern "C" dwSoundSample* dwSound_Play(const char* pName)
{
    if (dwSound_pManager == NULL)
        return NULL;
    return dwSound_pManager->Play(pName);
}

extern "C" dwSoundSample* dwSound_PlayLooping(const char* pName)
{
    if (dwSound_pManager == NULL)
        return NULL;
    return dwSound_pManager->PlayLooping(pName);
}

extern "C" dwSoundSample* dwSound_PlayRestart(const char* pName)
{
    if (dwSound_pManager == NULL)
        return NULL;
    return dwSound_pManager->PlayRestart(pName);
}

extern "C" void dwSound_Stop(const char* pName)
{
    if (dwSound_pManager != NULL)
        dwSound_pManager->Stop(pName);
}

extern "C" int dwSound_IsPlaying(const char* pName)
{
    if (dwSound_pManager == NULL)
        return 0;
    return dwSound_pManager->IsPlaying(pName);
}

extern "C" void dwSound_SetSampleVolume(const char* pName, float volume, float fadeSec)
{
    if (dwSound_pManager != NULL)
        dwSound_pManager->SetSampleVolume(pName, volume, fadeSec);
}

extern "C" void dwSound_SetMusic(const char* pName, int bLoop)
{
    if (dwSound_pManager != NULL)
        dwSound_pManager->SetMusic(pName, (uint8_t)(bLoop != 0));
}

extern "C" void dwSound_FadeMusic(float volume, float fadeSec)
{
    if (dwSound_pManager != NULL)
        dwSound_pManager->FadeMusic(volume, fadeSec);
}

extern "C" void dwSound_StopAll(void)
{
    if (dwSound_pManager != NULL)
        dwSound_pManager->StopAll();
}

extern "C" void dwSound_PauseAll(void)
{
    if (dwSound_pManager != NULL)
        dwSound_pManager->PauseAll();
}

extern "C" void dwSound_ResumeAll(void)
{
    if (dwSound_pManager != NULL)
        dwSound_pManager->ResumeAll();
}
