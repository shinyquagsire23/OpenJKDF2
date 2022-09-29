#ifndef _WORLD_SITHARCHLIGHTING_H
#define _WORLD_SITHARCHLIGHTING_H

#include "types.h"

#ifdef JKM_LIGHTING

void sithArchLighting_Free(sithWorld* pWorld);
int sithArchLighting_ParseSection(sithWorld *pWorld, int unk);

#endif // JKM_LIGHTING

#endif // _WORLD_SITHARCHLIGHTING_H