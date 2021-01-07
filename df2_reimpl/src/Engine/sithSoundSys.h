#ifndef _SITHSOUNDSYS_H
#define _SITHSOUNDSYS_H

#define sithSoundSys_FreeThing_ADDR (0x004DCF20)

static void (*sithSoundSys_FreeThing)(sithThing *thing) = (void*)sithSoundSys_FreeThing_ADDR;

#endif // _SITHSOUNDSYS_H
