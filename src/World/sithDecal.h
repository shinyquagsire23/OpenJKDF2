#ifndef _SITHDECAL_H
#define _SITHDECAL_H

#ifdef DEFERRED_DECALS

#include "types.h"
#include "globals.h"

#include "Primitives/rdDecal.h"

int sithDecal_Startup();
void sithDecal_Shutdown();
int sithDecal_Load(sithWorld *world, int a2);
void sithDecal_FreeEntry(sithWorld *world);
rdDecal* sithDecal_LoadEntry(char *fpath);
int sithDecal_New(sithWorld *world, int num);

#endif

#endif // _SITHDECAL_H