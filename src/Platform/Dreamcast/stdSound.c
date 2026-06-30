// Stub stdSound backend for the Sega Dreamcast (KallistiOS).
//
// Selected by STDSOUND_DREAMCAST (see config_platform_deps.cmake). Mirrors the
// generic STDSOUND_NULL implementation: buffers are allocated/tracked but nothing
// is mixed or output yet. The shared src/Win95/stdSound.c still provides
// stdSound_fMenuVolume and stdSound_ParseWav (the latter under !TARGET_TWL), so
// they are intentionally not redefined here.
//
// A real backend can later be built on KOS's AICA sound stream API.

#include "Win95/stdSound.h"

#include "Gui/jkGUISound.h"
#include "Main/Main.h"
#include "stdPlatform.h"
#include "General/stdMath.h"

#include <stdio.h>

#include "jk.h"

#ifdef STDSOUND_DREAMCAST

int stdSound_Startup()
{
    jkGuiSound_b3DSound = 0;
    printf("Using STDSOUND_DREAMCAST (stub) as audio backend\n");
    return 1;
}

void stdSound_Shutdown()
{
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

    return out;
}

void* stdSound_BufferSetData(stdSound_buffer_t* sound, int bufferBytes, int32_t* bufferMaxSize)
{
    sound->bufferBytes = bufferBytes;

    if (bufferMaxSize)
        *bufferMaxSize = bufferBytes;

    if (sound->data && !sound->bIsCopy)
        std_pHS->free(sound->data);

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

int stdSound_BufferPlay(stdSound_buffer_t* buf, int loop)
{
    return 1;
}

int stdSound_BufferQueueAfterAnother(stdSound_buffer_t* bufPrev, stdSound_buffer_t* bufNext)
{
    return 1;
}

void stdSound_BufferRelease(stdSound_buffer_t* sound)
{
    if (sound->data && !sound->bIsCopy)
        std_pHS->free(sound->data);

    memset(sound, 0, sizeof(*sound));
    std_pHS->free(sound);
}

int stdSound_BufferReset(stdSound_buffer_t* sound)
{
    return 1;
}

void stdSound_BufferSetPan(stdSound_buffer_t* a1, flex_t a2)
{
}

void stdSound_BufferSetFrequency(stdSound_buffer_t* sound, int freq)
{
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

    return out;
}

void stdSound_IA3D_idk(flex_t a)
{
}

int stdSound_BufferStop(stdSound_buffer_t* buf)
{
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
    return 0;
}

void stdSound_3DBufferRelease(stdSound_3dBuffer_t* p3DBuffer)
{
}

#endif // STDSOUND_DREAMCAST
