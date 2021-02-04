#ifndef _SITHEXPLOSION_H
#define _SITHEXPLOSION_H

#include "types.h"

#define sithExplosion_CreateThing_ADDR (0x004FB790)
#define sithExplosion_Tick_ADDR (0x004FB860)
#define sithExplosion_UpdateForce_ADDR (0x004FB920)
#define sithExplosion_LoadThingParams_ADDR (0x004FBBD0)

void sithExplosion_CreateThing(sithThing *explosion);
void sithExplosion_Tick(sithThing *explosion);
void sithExplosion_UpdateForce(sithThing *explosion);

//static void (*sithExplosion_UpdateForce)(sithThing *explosion) = (void*)sithExplosion_UpdateForce_ADDR;

#endif // _SITHEXPLOSION_H
