#ifndef _ENGINE_SITHSOUNDMIXER_H
#define _ENGINE_SITHSOUNDMIXER_H

#include "types.h"
#include "globals.h"

#define sithSoundMixer_Startup_ADDR (0x004DAE00)
#define sithSoundMixer_Shutdown_ADDR (0x004DAE40)
#define sithSoundMixer_PlaySong_ADDR (0x004DAE60)
#define sithSoundMixer_StopSong_ADDR (0x004DAF20)
#define sithSoundMixer_UpdateMusicVolume_ADDR (0x004DAF40)
#define sithSoundMixer_SetMusicVol_ADDR (0x004DB080)
#define sithSoundMixer_ResumeMusic_ADDR (0x004DB0F0)
#define sithSoundMixer_Open_ADDR (0x004DB180)
#define sithSoundMixer_Close_ADDR (0x004DB230)
#define sithSoundMixer_ClearAll_ADDR (0x004DB340)
#define sithSoundMixer_StopAll_ADDR (0x004DB3C0)
#define sithSoundMixer_ResumeAll_ADDR (0x004DB410)
#define sithSoundMixer_PlayingSoundFromSound_ADDR (0x004DB460)
#define sithSoundMixer_PlaySound_ADDR (0x004DB4F0)
#define sithSoundMixer_PlaySoundPos_ADDR (0x004DB880)
#define sithSoundMixer_PlaySoundThing_ADDR (0x004DBA60)
#define sithSoundMixer_PlayingSoundReset_ADDR (0x004DBF40)
#define sithSoundMixer_Reset_ADDR (0x004DBF90)
#define sithSoundMixer_SetPitch_ADDR (0x004DC070)
#define sithSoundMixer_SetFrequency_ADDR (0x004DC110)
#define sithSoundMixer_FadeVolume_ADDR (0x004DC170)
#define sithSoundMixer_SetVolume_ADDR (0x004DC280)
#define sithSoundMixer_Update_ADDR (0x004DC2F0)
#define sithSoundMixer_GetThingSoundIdx_ADDR (0x004DC750)
#define sithSoundMixer_TickPlayingSound_ADDR (0x004DC790)
#define sithSoundMixer_UpdateSoundPos_ADDR (0x004DCC00)
#define sithSoundMixer_SetVelocity_ADDR (0x004DCE10)
#define sithSoundMixer_StopSound_ADDR (0x004DCE80)
#define sithSoundMixer_FreeThing_ADDR (0x004DCF20)
#define sithSoundMixer_GetChannelHandle_ADDR (0x004DD040)
#define sithSoundMixer_UpdatePlayingSoundPosition_ADDR (0x004DD190)
#define sithSoundMixer_GetSoundFromIdx_ADDR (0x004DD310)
#define sithSoundMixer_SetSectorAmbientSound_ADDR (0x004DD330)
#define sithSoundMixer_SyncSounds_ADDR (0x004DD360)
#define sithSoundMixer_FreePlayingSound_ADDR (0x004DD3C0)
#define sithSoundMixer_sub_4DD3F0_ADDR (0x004DD3F0)
#define sithSoundMixer_sub_4DD5D0_ADDR (0x004DD5D0)

int sithSoundMixer_Startup();
void sithSoundMixer_Shutdown();
int sithSoundMixer_PlaySong(unsigned int trackFrom, unsigned int trackTo, unsigned int trackNum, int a4);
void sithSoundMixer_StopSong();
MATH_FUNC void sithSoundMixer_UpdateMusicVolume(flex_t musicVolume);
MATH_FUNC void sithSoundMixer_SetMusicVol(flex_t volume);
void sithSoundMixer_ResumeMusic(int a1);
int sithSoundMixer_Open();
void sithSoundMixer_Close();
void sithSoundMixer_ClearAll();
void sithSoundMixer_StopAll();
void sithSoundMixer_ResumeAll();
sithPlayingSound* sithSoundMixer_PlayingSoundFromSound(sithSound *sound, int flags);
sithPlayingSound* sithSoundMixer_PlaySound(sithSound *hSnd, flex_t volume, flex_t pan, int playflags);
sithPlayingSound* sithSoundMixer_PlaySoundPos(sithSound *hSnd, rdVector3 *pos, SithSector *pSector, flex_t volume, flex_t minRadius, flex_t maxRadius, int playflags);
sithPlayingSound* sithSoundMixer_PlaySoundThing(sithSound *hSnd, SithThing *a2, flex_t volume, flex_t minRadius, flex_t maxRadius, int playflags);
void sithSoundMixer_PlayingSoundReset(sithPlayingSound *sound);
void sithSoundMixer_Reset();
MATH_FUNC void sithSoundMixer_SetPitch(sithPlayingSound *sound, flex_t pitch, flex_t changetime);
int sithSoundMixer_SetFrequency(sithPlayingSound *sound, flex_t pitch);
void sithSoundMixer_FadeVolume(sithPlayingSound *hChannel, flex_t volume, flex_t secFadeTime);
void sithSoundMixer_SetVolume(sithPlayingSound *hChannel, flex_t volume);

MATH_FUNC void sithSoundMixer_Update(flex_t deltaSecs);
MATH_FUNC void sithSoundMixer_TickPlayingSound(sithPlayingSound *sound, flex_t deltaSecs);
MATH_FUNC void sithSoundMixer_UpdateSoundPos(sithPlayingSound *sound);
void sithSoundMixer_SetVelocity(sithPlayingSound *sound);

void sithSoundMixer_SyncSounds();
void sithSoundMixer_FreePlayingSound(sithPlayingSound *sound);

void sithSoundMixer_FreeThing(SithThing *thing);
sithPlayingSound* sithSoundMixer_GetChannelHandle(int guid);
MATH_FUNC void sithSoundMixer_UpdatePlayingSoundPosition(sithPlayingSound *sound);
void sithSoundMixer_SetSectorAmbientSound(SithSector *pSector, sithSound *hSnd, flex_t volume);
int sithSoundMixer_sub_4DD3F0(sithPlayingSound *sound);
int sithSoundMixer_sub_4DD5D0(sithPlayingSound *sound);
int32_t sithSoundMixer_GetThingSoundIdx(SithThing *thing, sithSound *sound);
void sithSoundMixer_StopSound(sithPlayingSound *sound);
sithPlayingSound* sithSoundMixer_GetSoundFromIdx(int idx);

//static int (*sithSoundMixer_Startup)() = (void*)sithSoundMixer_Startup_ADDR;
//static void (*sithSoundMixer_Shutdown)() = (void*)sithSoundMixer_Shutdown_ADDR;

//static void (*sithSoundMixer_FreeThing)(SithThing *thing) = (void*)sithSoundMixer_FreeThing_ADDR;
//static sithPlayingSound* (*sithSoundMixer_PlaySoundThing)(sithSound *a1, SithThing *a2, flex_t a3, flex_t a4, flex_t a5, int a6) = (void*)sithSoundMixer_PlaySoundThing_ADDR;
//static sithPlayingSound* (*sithSoundMixer_PlaySoundPos)(sithSound *a1, rdVector3 *a2, SithSector *a3, flex_t a4, flex_t a5, flex_t a6, int a7) = (void*)sithSoundMixer_PlaySoundPos_ADDR;
//static int (*sithSoundMixer_StopSound)(sithPlayingSound *a1) = (void*)sithSoundMixer_StopSound_ADDR;
//static sithPlayingSound* (*sithSoundMixer_GetChannelHandle)(int a1) = (void*)sithSoundMixer_GetChannelHandle_ADDR;
//static void (*_sithSoundMixer_FadeSound)(sithPlayingSound *sound, flex_t vol_, flex_t fadeintime_) = (void*)sithSoundMixer_FadeVolume_ADDR;
//static void (*sithSoundMixer_SetPitch)(sithPlayingSound *a1, flex_t pitch, flex_t changetime) = (void*)sithSoundMixer_SetPitch_ADDR;
//static void (*sithSoundMixer_SetSectorAmbientSound)(SithSector *a1, sithSound *a2, flex_t a3) = (void*)sithSoundMixer_SetSectorAmbientSound_ADDR;

#endif // _ENGINE_SITHSOUNDMIXER_H
