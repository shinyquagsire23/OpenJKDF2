#ifndef _STDSOUND_H
#define _STDSOUND_H

#include "types.h"

#define stdSound_Startup_ADDR (0x0436E80)
#define stdSound_Shutdown_ADDR (0x04370E0)
#define stdSound_SetMenuVolume_ADDR (0x0437150)
#define stdSound_BufferCreate_ADDR (0x0437190)
#define stdSound_BufferQueryInterface_ADDR (0x04372D0)
#define stdSound_BufferDuplicate_ADDR (0x0437300)
#define stdSound_BufferPlay_ADDR (0x0437330)
#define stdSound_BufferSetPan_ADDR (0x0437360)
#define stdSound_BufferSetVolume_ADDR (0x0437390)
#define stdSound_BufferSetFrequency_ADDR (0x0437410)
#define stdSound_BufferSetFrequency2_ADDR (0x0437430)
#define stdSound_SetPosition_ADDR (0x0437450)
#define stdSound_SetVelocity_ADDR (0x0437480)
#define stdSound_SetPositionOrientation_ADDR (0x04374B0)
#define stdSound_CommitDeferredSettings_ADDR (0x0437510)
#define stdSound_3DSetMode_ADDR (0x0437520)
#define stdSound_IA3D_idk_ADDR (0x0437540)
#define stdSound_BufferReset_ADDR (0x0437560)
#define stdSound_BufferStop_ADDR (0x0437590)
#define stdSound_BufferRelease_ADDR (0x04375B0)
#define stdSound_3DBufferRelease_ADDR (0x04375D0)
#define stdSound_IsPlaying_ADDR (0x04375F0)
#define stdSound_BufferSetData_ADDR (0x0437640)
#define stdSound_BufferUnlock_ADDR (0x04376A0)
#define stdSound_BufferCopyData_ADDR (0x04376D0)
#define stdSound_ParseWav_ADDR (0x0437770)
#define stdSound_SetMenuSoundFormat_ADDR (0x0437890)

#ifdef STDSOUND_OPENAL
//#include <AL/al.h>
#ifdef ARCH_WASM
#include <AL/al.h>
#include <AL/alc.h>
#else
#include "al.h"
#include "alc.h"
#endif
typedef struct stdALBuffer
{
    ALuint buffer;
    ALuint source;
    void* data;
    int format;
    int bStereo;
    int bitsPerSample;
    uint32_t nSamplesPerSec;
    int bufferBytes;
    int bufferLen;
    int refcnt;
    float vol;
    int bIsCopy;
    rdVector3 pos;
    rdVector3 vel;
} stdALBuffer;
#else
typedef struct IDirectSoundBuffer
{
    void* p;
} IDirectSoundBuffer;
typedef struct IDirectSound3DBuffer
{
    void* p;
} IDirectSound3DBuffer;
#endif

typedef struct stdNullSoundBuffer
{
    void* data;
    int format;
    int bStereo;
    int bitsPerSample;
    uint32_t nSamplesPerSec;
    int bufferBytes;
    int bufferLen;
    int refcnt;
    float vol;
    int bIsCopy;
    rdVector3 pos;
    rdVector3 vel;
} stdNullSoundBuffer;

typedef struct stdWaveFormat
{
  int16_t wFormatTag;
  uint16_t nChannels;
  uint32_t nSamplesPerSec;
  int32_t nAvgBytesPerSec;
  uint16_t nBlockAlign;
  int16_t wBitsPerSample;
} stdWaveFormat;

uint32_t stdSound_ParseWav(stdFile_t sound_file, uint32_t *nSamplesPerSec, int *bitsPerSample, int *bStereo, int *seekOffset);

extern float stdSound_fMenuVolume;

#ifndef SDL2_RENDER
static int (*stdSound_Startup)() = (void*)stdSound_Startup_ADDR;
static void (*stdSound_Shutdown)() = (void*)stdSound_Shutdown_ADDR;
static void (*stdSound_SetMenuVolume)(float a1) = (void*)stdSound_SetMenuVolume_ADDR;
static stdSound_buffer_t* (*stdSound_BufferCreate)(int bStereo, uint32_t nSamplesPerSec, uint16_t bitsPerSample, int bufferLen) = (void*)stdSound_BufferCreate_ADDR;
static void* (*stdSound_BufferSetData)(stdSound_buffer_t* a1, int bufferBytes, int *bufferMaxSize) = (void*)stdSound_BufferSetData_ADDR;
static int (*stdSound_BufferUnlock)(stdSound_buffer_t* a1, void* buffer, int bufferReadLen) = (void*)stdSound_BufferUnlock_ADDR;
static void (*stdSound_BufferRelease)(stdSound_buffer_t* a1) = (void*)stdSound_BufferRelease_ADDR;
static int (*stdSound_BufferReset)(stdSound_buffer_t* a1) = (void*)stdSound_BufferReset_ADDR;
//static uint32_t (*stdSound_ParseWav)(int sound_file, int *nSamplesPerSec, int *bitsPerSample, int *bStereo, int *seekOffset) = (void*)stdSound_ParseWav_ADDR;
static int (*stdSound_BufferPlay)(stdSound_buffer_t* a1, int a2) = (void*)stdSound_BufferPlay_ADDR;
static void (*stdSound_BufferSetPan)(stdSound_buffer_t* a1, float a2) = (void*)stdSound_BufferSetPan_ADDR;
static void (*stdSound_BufferSetFrequency)(stdSound_buffer_t* a1, int a2) = (void*)stdSound_BufferSetFrequency_ADDR;
static stdSound_buffer_t* (*stdSound_BufferDuplicate)(stdSound_buffer_t* buf) = (void*)stdSound_BufferDuplicate_ADDR;
static void (*stdSound_IA3D_idk)(float a) = (void*)stdSound_IA3D_idk_ADDR;
static int (*stdSound_BufferStop)(stdSound_buffer_t* a1) = (void*)stdSound_BufferStop_ADDR;
static void (*stdSound_BufferSetVolume)(stdSound_buffer_t* a1, float a2) = (void*)stdSound_BufferSetVolume_ADDR;
static int (*stdSound_3DSetMode)(stdSound_buffer_t* a1, int a2) = (void*)stdSound_3DSetMode_ADDR;
static stdSound_3dBuffer_t* (*stdSound_BufferQueryInterface)(stdSound_buffer_t* a1) = (void*)stdSound_BufferQueryInterface_ADDR;
static void (*stdSound_CommitDeferredSettings)() = (void*)stdSound_CommitDeferredSettings_ADDR;
static void (*stdSound_SetPositionOrientation)(rdVector3 *pos, rdVector3 *lvec, rdVector3 *uvec) = (void*)stdSound_SetPositionOrientation_ADDR;
static void (*stdSound_SetPosition)(stdSound_buffer_t* sound, rdVector3 *pos) = (void*)stdSound_SetPosition_ADDR;
static void (*stdSound_SetVelocity)(stdSound_buffer_t* sound, rdVector3 *vel) = (void*)stdSound_SetVelocity_ADDR;
static int (*stdSound_IsPlaying)(stdSound_buffer_t* a1, rdVector3 *pos) = (void*)stdSound_IsPlaying_ADDR;
static void (*stdSound_3DBufferRelease)(stdSound_3dBuffer_t* a1) = (void*)stdSound_3DBufferRelease_ADDR;
#else
int stdSound_Startup();
void stdSound_Shutdown();
void stdSound_SetMenuVolume(float a1);
stdSound_buffer_t* stdSound_BufferCreate(int bStereo, uint32_t nSamplesPerSec, uint16_t bitsPerSample, int bufferLen);
void* stdSound_BufferSetData(stdSound_buffer_t* sound, int bufferBytes, int* bufferMaxSize);
int stdSound_BufferUnlock(stdSound_buffer_t* sound, void* buffer, int bufferRead);
void stdSound_BufferRelease(stdSound_buffer_t* sound);
int stdSound_BufferReset(stdSound_buffer_t* sound);
//uint32_t stdSound_ParseWav(int sound_file, int *nSamplesPerSec, int *bitsPerSample, int *bStereo, int *seekOffset);
int stdSound_BufferPlay(stdSound_buffer_t* buf, int loop);
void stdSound_BufferSetPan(stdSound_buffer_t* a1, float a2);
void stdSound_BufferSetFrequency(stdSound_buffer_t* a1, int a2);
stdSound_buffer_t* stdSound_BufferDuplicate(stdSound_buffer_t* sound);
void stdSound_IA3D_idk(float a);
int stdSound_BufferStop(stdSound_buffer_t* a1);
void stdSound_BufferSetVolume(stdSound_buffer_t* a1, float a2);
int stdSound_3DSetMode(stdSound_3dBuffer_t* a1, int a2);
stdSound_3dBuffer_t* stdSound_BufferQueryInterface(stdSound_buffer_t* a1);
void stdSound_CommitDeferredSettings();
void stdSound_SetPositionOrientation(rdVector3 *pos, rdVector3 *lvec, rdVector3 *uvec);
void stdSound_SetPosition(stdSound_buffer_t* sound, rdVector3 *pos);
void stdSound_SetVelocity(stdSound_buffer_t* sound, rdVector3 *vel);
int stdSound_IsPlaying(stdSound_buffer_t* a1, rdVector3 *pos);
void stdSound_3DBufferRelease(stdSound_3dBuffer_t* p3DBuffer);
#endif

#endif // _STDSOUND_H
