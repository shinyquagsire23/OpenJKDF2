#ifndef _SITHSOUNDSYS_H
#define _SITHSOUNDSYS_H

#include "types.h"

#define sithSoundSys_FreeThing_ADDR (0x004DCF20)
#define sithSoundSys_UpdateMusicVolume_ADDR (0x004DAF40)

static void (*sithSoundSys_UpdateMusicVolume)(float musicVolume) = (void*)sithSoundSys_UpdateMusicVolume_ADDR;
static void (*sithSoundSys_FreeThing)(sithThing *thing) = (void*)sithSoundSys_FreeThing_ADDR;

#endif // _SITHSOUNDSYS_H
