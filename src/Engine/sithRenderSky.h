#ifndef _SITHRENDERSKY_H
#define _SITHRENDERSKY_H

#include "types.h"
#include "globals.h"

#define sithRenderSky_Open_ADDR (0x004F2D30)
#define sithRenderSky_Close_ADDR (0x004F2DC0)
#define sithRenderSky_Update_ADDR (0x004F2DD0)
#define sithRenderSky_TransformHorizontal_ADDR (0x004F2E30)
#define sithRenderSky_TransformVertical_ADDR (0x004F2F60)

int sithRenderSky_Open(float horizontalPixelsPerRev, float horizontalDist, float ceilingSky);
void sithRenderSky_Close();
void sithRenderSky_Update();
void sithRenderSky_TransformHorizontal(rdProcEntry *a1, sithSurfaceInfo *a2, int num_vertices);
void sithRenderSky_TransformVertical(rdProcEntry *a1, sithSurfaceInfo *a2, rdVector3 *a3, unsigned int a4);

#endif // _SITHRENDERSKY_H