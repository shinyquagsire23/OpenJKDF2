#ifndef _SITHSOUNDSYS_H
#define _SITHSOUNDSYS_H

#include "types.h"
#include "globals.h"

#define sithSoundSys_Startup_ADDR (0x004DAE00)
#define sithSoundSys_Shutdown_ADDR (0x004DAE40)
#define sithSoundSys_PlaySong_ADDR (0x004DAE60)
#define sithSoundSys_StopSong_ADDR (0x004DAF20)
#define sithSoundSys_UpdateMusicVolume_ADDR (0x004DAF40)
#define sithSoundSys_SetMusicVol_ADDR (0x004DB080)
#define sithSoundSys_ResumeMusic_ADDR (0x004DB0F0)
#define sithSoundSys_Open_ADDR (0x004DB180)
#define sithSoundSys_Close_ADDR (0x004DB230)
#define sithSoundSys_ClearAll_ADDR (0x004DB340)
#define sithSoundSys_StopAll_ADDR (0x004DB3C0)
#define sithSoundSys_ResumeAll_ADDR (0x004DB410)
#define sithSoundSys_PlayingSoundFromSound_ADDR (0x004DB460)
#define sithSoundSys_cog_playsound_internal_ADDR (0x004DB4F0)
#define sithSoundSys_PlaySoundPosAbsolute_ADDR (0x004DB880)
#define sithSoundSys_PlaySoundPosThing_ADDR (0x004DBA60)
#define sithSoundSys_PlayingSoundReset_ADDR (0x004DBF40)
#define sithSoundSys_Reset_ADDR (0x004DBF90)
#define sithSoundSys_SetPitch_ADDR (0x004DC070)
#define sithSoundSys_SetFrequency_ADDR (0x004DC110)
#define sithSoundSys_FadeSound_ADDR (0x004DC170)
#define sithSoundSys_SetVolume_ADDR (0x004DC280)
#define sithSoundSys_Tick_ADDR (0x004DC2F0)
#define sithSoundSys_GetThingSoundIdx_ADDR (0x004DC750)
#define sithSoundSys_TickPlayingSound_ADDR (0x004DC790)
#define sithSoundSys_UpdateSoundPos_ADDR (0x004DCC00)
#define sithSoundSys_SetVelocity_ADDR (0x004DCE10)
#define sithSoundSys_StopSound_ADDR (0x004DCE80)
#define sithSoundSys_FreeThing_ADDR (0x004DCF20)
#define sithSoundSys_GetSoundFromRef_ADDR (0x004DD040)
#define sithSoundSys_UpdatePlayingSoundPosition_ADDR (0x004DD190)
#define sithSoundSys_GetSoundFromIdx_ADDR (0x004DD310)
#define sithSoundSys_SectorSound_ADDR (0x004DD330)
#define sithSoundSys_SyncSounds_ADDR (0x004DD360)
#define sithSoundSys_FreePlayingSound_ADDR (0x004DD3C0)
#define sithSoundSys_sub_4DD3F0_ADDR (0x004DD3F0)
#define sithSoundSys_sub_4DD5D0_ADDR (0x004DD5D0)

#define SITHSOUNDSYS_NUMPLAYINGSOUNDS (32)

enum SITHSOUNDFLAG
{
    SITHSOUNDFLAG_LOOP = 0x1,
    SITHSOUNDFLAG_FADING = 0x2,
    SITHSOUNDFLAG_AMBIENT_NOPAN = 0x4,
    SITHSOUNDFLAG_8 = 0x8,
    SITHSOUNDFLAG_10 = 0x10,
    SITHSOUNDFLAG_20 = 0x20,
    SITHSOUNDFLAG_ABSOLUTE = 0x40,
    SITHSOUNDFLAG_FOLLOWSTHING = 0x80,
    SITHSOUNDFLAG_HIGHPRIO = 0x100,
    SITHSOUNDFLAG_200 = 0x200,
    SITHSOUNDFLAG_400 = 0x400,
    SITHSOUNDFLAG_800 = 0x800,
    SITHSOUNDFLAG_1000 = 0x1000,
    SITHSOUNDFLAG_UNDERWATER = 0x2000,
    SITHSOUNDFLAG_4000 = 0x4000,
    SITHSOUNDFLAG_8000 = 0x8000,
    SITHSOUNDFLAG_NOOVERRIDE = 0x10000,
    SITHSOUNDFLAG_PLAYING = 0x20000,
    SITHSOUNDFLAG_40000 = 0x40000,
    SITHSOUNDFLAG_80000 = 0x80000,
};

int sithSoundSys_Startup();
void sithSoundSys_Shutdown();
int sithSoundSys_PlaySong(unsigned int trackFrom, unsigned int trackTo, unsigned int trackNum, int a4);
void sithSoundSys_StopSong();
void sithSoundSys_UpdateMusicVolume(float musicVolume);
void sithSoundSys_SetMusicVol(float volume);
void sithSoundSys_ResumeMusic(int a1);
int sithSoundSys_Open();
void sithSoundSys_Close();
void sithSoundSys_ClearAll();
void sithSoundSys_StopAll();
void sithSoundSys_ResumeAll();
sithPlayingSound* sithSoundSys_PlayingSoundFromSound(sithSound *sound, int flags);
sithPlayingSound* sithSoundSys_cog_playsound_internal(sithSound *sound, float volume, float pan, int flags);
sithPlayingSound* sithSoundSys_PlaySoundPosAbsolute(sithSound *a1, rdVector3 *a2, sithSector *a3, float a4, float a5, float a6, int a7);
sithPlayingSound* sithSoundSys_PlaySoundPosThing(sithSound *sound, sithThing *a2, float a3, float a4, float a5, int flags);
void sithSoundSys_PlayingSoundReset(sithPlayingSound *sound);
void sithSoundSys_Reset();
void sithSoundSys_SetPitch(sithPlayingSound *sound, float pitch, float changetime);
int sithSoundSys_SetFrequency(sithPlayingSound *sound, float pitch);
void sithSoundSys_FadeSound(sithPlayingSound *sound, float vol_, float fadeintime_);
void sithSoundSys_SetVolume(sithPlayingSound *sound, float volume);

void sithSoundSys_Tick(float deltaSecs);
void sithSoundSys_TickPlayingSound(sithPlayingSound *sound, float deltaSecs);
void sithSoundSys_UpdateSoundPos(sithPlayingSound *sound);
void sithSoundSys_SetVelocity(sithPlayingSound *sound);

void sithSoundSys_SyncSounds();
void sithSoundSys_FreePlayingSound(sithPlayingSound *sound);

void sithSoundSys_FreeThing(sithThing *thing);
sithPlayingSound* sithSoundSys_GetSoundFromRef(int refid);
void sithSoundSys_UpdatePlayingSoundPosition(sithPlayingSound *sound);
void sithSoundSys_SectorSound(sithSector *sector, sithSound *sound, float vol);
int sithSoundSys_sub_4DD3F0(sithPlayingSound *sound);
int sithSoundSys_sub_4DD5D0(sithPlayingSound *sound);
uint32_t sithSoundSys_GetThingSoundIdx(sithThing *thing, sithSound *sound);
void sithSoundSys_StopSound(sithPlayingSound *sound);
sithPlayingSound* sithSoundSys_GetSoundFromIdx(signed int idx);

//static int (*sithSoundSys_Startup)() = (void*)sithSoundSys_Startup_ADDR;
//static void (*sithSoundSys_Shutdown)() = (void*)sithSoundSys_Shutdown_ADDR;

//static void (*sithSoundSys_FreeThing)(sithThing *thing) = (void*)sithSoundSys_FreeThing_ADDR;
//static sithPlayingSound* (*sithSoundSys_PlaySoundPosThing)(sithSound *a1, sithThing *a2, float a3, float a4, float a5, int a6) = (void*)sithSoundSys_PlaySoundPosThing_ADDR;
//static sithPlayingSound* (*sithSoundSys_PlaySoundPosAbsolute)(sithSound *a1, rdVector3 *a2, sithSector *a3, float a4, float a5, float a6, int a7) = (void*)sithSoundSys_PlaySoundPosAbsolute_ADDR;
//static int (*sithSoundSys_StopSound)(sithPlayingSound *a1) = (void*)sithSoundSys_StopSound_ADDR;
//static sithPlayingSound* (*sithSoundSys_GetSoundFromRef)(int a1) = (void*)sithSoundSys_GetSoundFromRef_ADDR;
static void (*_sithSoundSys_FadeSound)(sithPlayingSound *sound, float vol_, float fadeintime_) = (void*)sithSoundSys_FadeSound_ADDR;
//static void (*sithSoundSys_SetPitch)(sithPlayingSound *a1, float pitch, float changetime) = (void*)sithSoundSys_SetPitch_ADDR;
//static void (*sithSoundSys_SectorSound)(sithSector *a1, sithSound *a2, float a3) = (void*)sithSoundSys_SectorSound_ADDR;

#endif // _SITHSOUNDSYS_H
