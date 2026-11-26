#ifndef _WORLD_SITHARCHLIGHTING_H
#define _WORLD_SITHARCHLIGHTING_H

#include "types.h"

#ifdef JKM_LIGHTING

void sithArchLighting_Free(SithWorld* pWorld);
int sithArchLighting_ParseSection(SithWorld *pWorld, int unk);
flex_t sithArchLighting_ThingAmbient(SithThing* pThing, flex_t ambient); // Added

#endif // JKM_LIGHTING

#endif // _WORLD_SITHARCHLIGHTING_H