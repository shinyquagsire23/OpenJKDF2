#ifndef _RDPOLYLINE_H
#define _RDPOLYLINE_H

#include "types.h"

#include "Raster/rdFace.h"

#define rdPolyline_New_ADDR (0x00448710)
#define rdPolyline_NewEntry_ADDR (0x00448770)
#define rdPolyline_Free_ADDR (0x00448A40)
#define rdPolyline_FreeEntry_ADDR (0x00448A60)
#define rdPolyline_Draw_ADDR (0x00448B10)
#define rdPolyline_DrawFace_ADDR (0x00448FA0)

rdPolyline* rdPolyline_New(char *polyline_fname, char *material_fname, char *material_fname2, flex_t length, flex_t base_rad, flex_t tip_rad, int lightmode, int texmode, int sortingmethod, flex_t extraLight);
int rdPolyline_NewEntry(rdPolyline *polyline, char *polyline_fname, char *material_side_fname, char *material_tip_fname, flex_t length, flex_t base_rad, flex_t tip_rad, rdGeoMode_t edgeGeometryMode, rdLightMode_t edgeLightingMode, rdTexMode_t edgeTextureMode, flex_t extraLight);
void rdPolyline_Free(rdPolyline *polyline);
void rdPolyline_FreeEntry(rdPolyline *polyline);
MATH_FUNC int rdPolyline_Draw(rdThing *thing, rdMatrix34 *matrix);

MATH_FUNC void rdPolyline_DrawFace(rdThing *thing, rdFace *face, rdVector3 *unused, rdMeshinfo *idxInfo);
//static void (*rdPolyline_DrawFace)(rdThing *thing, rdFace *face, rdVector3 *unused, rdMeshinfo *idxInfo) = (void*)rdPolyline_DrawFace_ADDR;

#endif // _RDPOLYLINE_H
