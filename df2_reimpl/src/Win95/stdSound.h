#ifndef _STDSOUND_H
#define _STDSOUND_H

#include "types.h"

#define stdSound_Initialize_ADDR (0x0436E80)
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
#define stdSound_BufferUnlock_0_ADDR (0x0437450)
#define stdSound_BufferRestore_ADDR (0x0437480)
#define stdSound_SetPositionOrientation_ADDR (0x04374B0)
#define stdSound_CommitDeferredSettings_ADDR (0x0437510)
#define stdSound_sub_437520_ADDR (0x0437520)
#define stdSound_IA3D_idk_ADDR (0x0437540)
#define stdSound_BufferReset_ADDR (0x0437560)
#define stdSound_BufferStop_ADDR (0x0437590)
#define stdSound_BufferRelease_ADDR (0x04375B0)
#define stdSound_BufferRelease_0_ADDR (0x04375D0)
#define stdSound_IsPlaying_ADDR (0x04375F0)
#define stdSound_BufferSetData_ADDR (0x0437640)
#define stdSound_BufferUnlock_ADDR (0x04376A0)
#define stdSound_BufferCopyData_ADDR (0x04376D0)
#define stdSound_ParseWav_ADDR (0x0437770)
#define stdSound_SetMenuSoundFormat_ADDR (0x0437890)


typedef struct IDirectSoundBuffer
{
} IDirectSoundBuffer;

static void (*stdSound_Shutdown)() = (void*)stdSound_Shutdown_ADDR;
static void (*stdSound_SetMenuVolume)(float a1) = (void*)stdSound_SetMenuVolume_ADDR;
static int (*stdSound_BufferReset)(LPDIRECTSOUNDBUFFER a1) = (void*)stdSound_BufferReset_ADDR;
static int (*stdSound_BufferPlay)(LPDIRECTSOUNDBUFFER a1, int a2) = (void*)stdSound_BufferPlay_ADDR;
static IDirectSoundBuffer* (*stdSound_BufferCreate)(int bStereo, int a2, uint16_t bitsPerSample, int bufferLen) = (void*)stdSound_BufferCreate_ADDR;
static void* (*stdSound_BufferSetData)(LPDIRECTSOUNDBUFFER a1, int bufferBytes, int *bufferMaxSize) = (void*)stdSound_BufferSetData_ADDR;
static int (*stdSound_BufferUnlock)(LPDIRECTSOUNDBUFFER a1, void* buffer, int bufferReadLen) = (void*)stdSound_BufferUnlock_ADDR;
static void (*stdSound_BufferRelease)(LPDIRECTSOUNDBUFFER a1) = (void*)stdSound_BufferRelease_ADDR;
static LPDIRECTSOUNDBUFFER (*stdSound_BufferDuplicate)(LPDIRECTSOUNDBUFFER buf) = (void*)stdSound_BufferDuplicate_ADDR;
static int (*stdSound_IsPlaying)(LPDIRECTSOUNDBUFFER a1, int *pos) = (void*)stdSound_IsPlaying_ADDR;
static void (*stdSound_BufferRelease_0)(LPDIRECTSOUNDBUFFER a1) = (void*)stdSound_BufferRelease_0_ADDR;

#ifdef WIN32
static int (*stdSound_Initialize)() = (void*)stdSound_Initialize_ADDR;
static uint32_t (*stdSound_ParseWav)(int sound_file, int *nSamplesPerSec, int *bitsPerSample, int *bStereo, int *seekOffset) = (void*)stdSound_ParseWav_ADDR;
#else
int stdSound_Initialize();
uint32_t stdSound_ParseWav(int sound_file, int *nSamplesPerSec, int *bitsPerSample, int *bStereo, int *seekOffset);
#endif

#endif // _STDSOUND_H
