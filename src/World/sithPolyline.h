#ifndef _SITHPOLYLINE_H
#define _SITHPOLYLINE_H

#include "types.h"
#include "globals.h"

#ifdef POLYLINE_EXT

int sithPolyline_Startup();
void sithPolyline_Shutdown();
int sithPolyline_Load(sithWorld *world, int a2);
void sithPolyline_Free(sithWorld *world);
rdPolyLine* sithPolyline_LoadEntry(char *fpath);

#endif

#endif // _SITHPOLYLINE_H
