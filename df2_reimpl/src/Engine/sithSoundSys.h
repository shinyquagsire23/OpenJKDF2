#ifndef _SITHSOUNDSYS_H
#define _SITHSOUNDSYS_H

#include "types.h"

#define sithSoundSys_FreeThing_ADDR (0x004DCF20)
#define sithSoundSys_UpdateMusicVolume_ADDR (0x004DAF40)
#define sithSoundSys_cog_playsoundpos_2_ADDR (0x004DBA60)

static void (*sithSoundSys_UpdateMusicVolume)(float musicVolume) = (void*)sithSoundSys_UpdateMusicVolume_ADDR;
static void (*sithSoundSys_FreeThing)(sithThing *thing) = (void*)sithSoundSys_FreeThing_ADDR;
static void (*sithSoundSys_cog_playsoundpos_2)(sithSound *a1, sithThing *a2, float a3, float a4, float a5, int a6) = (void*)sithSoundSys_cog_playsoundpos_2_ADDR;

#endif // _SITHSOUNDSYS_H
