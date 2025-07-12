#ifndef _RDPOLYLINE_H
#define _RDPOLYLINE_H

#include "types.h"

#include "Raster/rdFace.h"

#define rdPolyLine_New_ADDR (0x00448710)
#define rdPolyLine_NewEntry_ADDR (0x00448770)
#define rdPolyLine_Free_ADDR (0x00448A40)
#define rdPolyLine_FreeEntry_ADDR (0x00448A60)
#define rdPolyLine_Draw_ADDR (0x00448B10)
#define rdPolyLine_DrawFace_ADDR (0x00448FA0)

rdPolyLine* rdPolyLine_New(char *polyline_fname, char *material_fname, char *material_fname2, flex_t length, flex_t base_rad, flex_t tip_rad, int lightmode, int texmode, int sortingmethod, flex_t extraLight);
int rdPolyLine_NewEntry(rdPolyLine *polyline, char *polyline_fname, char *material_side_fname, char *material_tip_fname, flex_t length, flex_t base_rad, flex_t tip_rad, rdGeoMode_t edgeGeometryMode, rdLightMode_t edgeLightingMode, rdTexMode_t edgeTextureMode, flex_t extraLight);
void rdPolyLine_Free(rdPolyLine *polyline);
void rdPolyLine_FreeEntry(rdPolyLine *polyline);
MATH_FUNC int rdPolyLine_Draw(rdThing *thing, rdMatrix34 *matrix);

MATH_FUNC void rdPolyLine_DrawFace(rdThing *thing, rdFace *face, rdVector3 *unused, rdVertexIdxInfo *idxInfo);
//static void (*rdPolyLine_DrawFace)(rdThing *thing, rdFace *face, rdVector3 *unused, rdVertexIdxInfo *idxInfo) = (void*)rdPolyLine_DrawFace_ADDR;

#endif // _RDPOLYLINE_H
