#ifndef _RDDECAL_H
#define _RDDECAL_H

#include "Primitives/rdVector.h"
#include "Primitives/rdMatrix.h"
#include "Raster/rdFace.h"

#if defined(DECAL_RENDERING) || defined(RENDER_DROID2)

typedef struct rdMaterial rdMaterial;

rdDecal* rdDecal_New(char *fpath, char *materialFpath, uint32_t flags, rdVector3* color, rdVector3* size, float fadeTime, float angleFade);
int rdDecal_NewEntry(rdDecal* decal, char* decalPath, char* material, uint32_t flags, rdVector3* color, rdVector3* size, float fadeTime, float angleFade);
void rdDecal_Free(rdDecal* decal);
void rdDecal_FreeEntry(rdDecal* decal);

//void rdDecal_Draw(rdDecal* decal, rdMatrix34* matrix, float scale, int32_t fadeMs);
void rdDecal_Draw(rdThing* thing, rdMatrix34* matrix);

#endif

#endif // _RDDECAL_H
