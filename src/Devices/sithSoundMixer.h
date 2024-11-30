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
#define sithSoundMixer_cog_playsound_internal_ADDR (0x004DB4F0)
#define sithSoundMixer_PlaySoundPosAbsolute_ADDR (0x004DB880)
#define sithSoundMixer_PlaySoundPosThing_ADDR (0x004DBA60)
#define sithSoundMixer_PlayingSoundReset_ADDR (0x004DBF40)
#define sithSoundMixer_Reset_ADDR (0x004DBF90)
#define sithSoundMixer_SetPitch_ADDR (0x004DC070)
#define sithSoundMixer_SetFrequency_ADDR (0x004DC110)
#define sithSoundMixer_FadeSound_ADDR (0x004DC170)
#define sithSoundMixer_SetVolume_ADDR (0x004DC280)
#define sithSoundMixer_Tick_ADDR (0x004DC2F0)
#define sithSoundMixer_GetThingSoundIdx_ADDR (0x004DC750)
#define sithSoundMixer_TickPlayingSound_ADDR (0x004DC790)
#define sithSoundMixer_UpdateSoundPos_ADDR (0x004DCC00)
#define sithSoundMixer_SetVelocity_ADDR (0x004DCE10)
#define sithSoundMixer_StopSound_ADDR (0x004DCE80)
#define sithSoundMixer_FreeThing_ADDR (0x004DCF20)
#define sithSoundMixer_GetSoundFromRef_ADDR (0x004DD040)
#define sithSoundMixer_UpdatePlayingSoundPosition_ADDR (0x004DD190)
#define sithSoundMixer_GetSoundFromIdx_ADDR (0x004DD310)
#define sithSoundMixer_SectorSound_ADDR (0x004DD330)
#define sithSoundMixer_SyncSounds_ADDR (0x004DD360)
#define sithSoundMixer_FreePlayingSound_ADDR (0x004DD3C0)
#define sithSoundMixer_sub_4DD3F0_ADDR (0x004DD3F0)
#define sithSoundMixer_sub_4DD5D0_ADDR (0x004DD5D0)

int sithSoundMixer_Startup();
void sithSoundMixer_Shutdown();
int sithSoundMixer_PlaySong(unsigned int trackFrom, unsigned int trackTo, unsigned int trackNum, int a4);
void sithSoundMixer_StopSong();
void sithSoundMixer_UpdateMusicVolume(float musicVolume);
void sithSoundMixer_SetMusicVol(float volume);
void sithSoundMixer_ResumeMusic(int a1);
int sithSoundMixer_Open();
void sithSoundMixer_Close();
void sithSoundMixer_ClearAll();
void sithSoundMixer_StopAll();
void sithSoundMixer_ResumeAll();
sithPlayingSound* sithSoundMixer_PlayingSoundFromSound(sithSound *sound, int flags);
sithPlayingSound* sithSoundMixer_cog_playsound_internal(sithSound *sound, float volume, float pan, int flags);
sithPlayingSound* sithSoundMixer_PlaySoundPosAbsolute(sithSound *a1, rdVector3 *a2, sithSector *a3, float a4, float a5, float a6, int a7);
sithPlayingSound* sithSoundMixer_PlaySoundPosThing(sithSound *sound, sithThing *a2, float a3, float a4, float a5, int flags);
void sithSoundMixer_PlayingSoundReset(sithPlayingSound *sound);
void sithSoundMixer_Reset();
void sithSoundMixer_SetPitch(sithPlayingSound *sound, float pitch, float changetime);
int sithSoundMixer_SetFrequency(sithPlayingSound *sound, float pitch);
void sithSoundMixer_FadeSound(sithPlayingSound *sound, float vol_, float fadeintime_);
void sithSoundMixer_SetVolume(sithPlayingSound *sound, float volume);

void sithSoundMixer_Tick(float deltaSecs);
void sithSoundMixer_TickPlayingSound(sithPlayingSound *sound, float deltaSecs);
void sithSoundMixer_UpdateSoundPos(sithPlayingSound *sound);
void sithSoundMixer_SetVelocity(sithPlayingSound *sound);

void sithSoundMixer_SyncSounds();
void sithSoundMixer_FreePlayingSound(sithPlayingSound *sound);

void sithSoundMixer_FreeThing(sithThing *thing);
sithPlayingSound* sithSoundMixer_GetSoundFromRef(int refid);
void sithSoundMixer_UpdatePlayingSoundPosition(sithPlayingSound *sound);
void sithSoundMixer_SectorSound(sithSector *sector, sithSound *sound, float vol);
int sithSoundMixer_sub_4DD3F0(sithPlayingSound *sound);
int sithSoundMixer_sub_4DD5D0(sithPlayingSound *sound);
int32_t sithSoundMixer_GetThingSoundIdx(sithThing *thing, sithSound *sound);
void sithSoundMixer_StopSound(sithPlayingSound *sound);
sithPlayingSound* sithSoundMixer_GetSoundFromIdx(int idx);

//static int (*sithSoundMixer_Startup)() = (void*)sithSoundMixer_Startup_ADDR;
//static void (*sithSoundMixer_Shutdown)() = (void*)sithSoundMixer_Shutdown_ADDR;

//static void (*sithSoundMixer_FreeThing)(sithThing *thing) = (void*)sithSoundMixer_FreeThing_ADDR;
//static sithPlayingSound* (*sithSoundMixer_PlaySoundPosThing)(sithSound *a1, sithThing *a2, float a3, float a4, float a5, int a6) = (void*)sithSoundMixer_PlaySoundPosThing_ADDR;
//static sithPlayingSound* (*sithSoundMixer_PlaySoundPosAbsolute)(sithSound *a1, rdVector3 *a2, sithSector *a3, float a4, float a5, float a6, int a7) = (void*)sithSoundMixer_PlaySoundPosAbsolute_ADDR;
//static int (*sithSoundMixer_StopSound)(sithPlayingSound *a1) = (void*)sithSoundMixer_StopSound_ADDR;
//static sithPlayingSound* (*sithSoundMixer_GetSoundFromRef)(int a1) = (void*)sithSoundMixer_GetSoundFromRef_ADDR;
static void (*_sithSoundMixer_FadeSound)(sithPlayingSound *sound, float vol_, float fadeintime_) = (void*)sithSoundMixer_FadeSound_ADDR;
//static void (*sithSoundMixer_SetPitch)(sithPlayingSound *a1, float pitch, float changetime) = (void*)sithSoundMixer_SetPitch_ADDR;
//static void (*sithSoundMixer_SectorSound)(sithSector *a1, sithSound *a2, float a3) = (void*)sithSoundMixer_SectorSound_ADDR;

#endif // _ENGINE_SITHSOUNDMIXER_H
