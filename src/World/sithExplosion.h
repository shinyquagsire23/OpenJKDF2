#ifndef _SITHEXPLOSION_H
#define _SITHEXPLOSION_H

#include "types.h"

#define sithExplosion_CreateThing_ADDR (0x004FB790)
#define sithExplosion_Tick_ADDR (0x004FB860)
#define sithExplosion_UpdateForce_ADDR (0x004FB920)
#define sithExplosion_LoadThingParams_ADDR (0x004FBBD0)

enum SithExplosionFlag
{
    SITHEXPLOSION_FLAG_ANIMATED_SPRITE = 0x1,
    SITHEXPLOSION_FLAG_HAS_BLAST_PHASE = 0x2,
    SITHEXPLOSION_FLAG_DAMAGE_IN_BLAST_RADIUS = 0x4,
    SITHEXPLOSION_FLAG_HAS_CHILD_EXPLOSION = 0x8,
    SITHEXPLOSION_FLAG_VARIABLE_LIGHT = 0x10,
    SITHEXPLOSION_FLAG_NO_DAMAGE_TO_SHOOTER = 0x40,
    SITHEXPLOSION_FLAG_RANDOM_DEBRIS = 0x80,
    SITHEXPLOSION_FLAG_FLASH_BLINDS_THINGS = 0x100,
    SITHEXPLOSION_FLAG_ANIMATE_DEBRIS_MATERIAL = 0x200, // maybe jones specific, makes the explosion debries mat to animate
    SITHEXPLOSION_FLAG_UPDATE_DEBRIS_MATERIAL = 0x400, // maybe jones specific, makes the explosion debries mat the same to the mat of the hit surface
    SITHEXPLOSION_USE_EXPAND_TIME = 0x800,
    SITHEXPLOSION_FLAG_USE_FADE_TIME = 0x1000,
};

void sithExplosion_CreateThing(sithThing *explosion);
MATH_FUNC void sithExplosion_Tick(sithThing *explosion);
MATH_FUNC void sithExplosion_UpdateForce(sithThing *explosion);
int sithExplosion_LoadThingParams(stdConffileArg *arg, sithThing *thing, int param);

//static void (*sithExplosion_UpdateForce)(sithThing *explosion) = (void*)sithExplosion_UpdateForce_ADDR;

#endif // _SITHEXPLOSION_H
