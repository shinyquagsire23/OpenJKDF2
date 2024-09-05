#ifndef _SITHDECAL_H
#define _SITHDECAL_H

#include "types.h"
#include "globals.h"

#ifdef DEFERRED_DECALS

#include "Primitives/rdDecal.h"

int sithDecal_Startup();
void sithDecal_Shutdown();
int sithDecal_Load(sithWorld *world, int a2);
void sithDecal_FreeEntry(sithWorld *world);
rdDecal* sithDecal_LoadEntry(char *fpath);
int sithDecal_New(sithWorld *world, int num);

#endif

#endif // _SITHDECAL_H
