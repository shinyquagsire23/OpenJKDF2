#ifndef _RDAFRASTER_H
#define _RDAFRASTER_H

#include "types.h"
#include "globals.h"

#ifdef RDRASTER_SOFTWARE_RENDERER

// Wireframe (LW) family — geometryMode 2 (RD_GEOMETRYMODE_WIREFRAME). This is the only
// genuinely untextured mode: each scanline span draws just its two endpoint pixels, so a
// filled polygon renders as its outline. It exercises the whole software pipeline
// (face setup -> edge setup/advance -> span build -> pixel plot) with the least code.
// The interpolated edge "i" value is the per-vertex reciprocal depth (1/z).

void rdAFRaster_SetupNGonLW_0(rdActiveFace* pFace, rdTexinfo* pTexinfo);
int  rdAFRaster_SetupEdgeNGonLW(rdEdge* pEdge, rdActiveFace* pFace, int vA, int vB);
void rdAFRaster_AdvanceLeftEdgeNGonLW(rdEdge* pEdge);
void rdAFRaster_AdvanceRightEdgeNGonLW(rdEdge* pEdge);
void rdAFRaster_DrawNGonLW(rdActiveFace* pFace);
void rdAFRaster_DrawSpanNGonLW_8(rdActiveSpan* pSpan);

// Affine textured families — geometryMode 4 / textureMode 0. Spans step (u,v) linearly in
// screen space and copy texels; the shading suffix picks the light modulation:
//   FAT flat (no light) · LAT lit (one per-face light row) · GAT gouraud (per-pixel light).
void rdAFRaster_SetupNGonFAT(rdActiveFace* pFace, rdTexinfo* pTexinfo);
void rdAFRaster_SetupNGonLAT(rdActiveFace* pFace, rdTexinfo* pTexinfo, int lightLevel);
void rdAFRaster_SetupNGonGAT(rdActiveFace* pFace, rdTexinfo* pTexinfo);
int  rdAFRaster_SetupEdgeNGonFAT(rdEdge* pEdge, rdActiveFace* pFace, int vA, int vB);
int  rdAFRaster_SetupEdgeNGonGAT(rdEdge* pEdge, rdActiveFace* pFace, int vA, int vB);
void rdAFRaster_AdvanceLeftEdgeNGonFAT(rdEdge* pEdge);
void rdAFRaster_AdvanceRightEdgeNGonFAT(rdEdge* pEdge);
void rdAFRaster_AdvanceLeftEdgeNGonGAT(rdEdge* pEdge);
void rdAFRaster_AdvanceRightEdgeNGonGAT(rdEdge* pEdge);
void rdAFRaster_DrawNGonFAT(rdActiveFace* pFace);
void rdAFRaster_DrawNGonLAT(rdActiveFace* pFace);
void rdAFRaster_DrawNGonGAT(rdActiveFace* pFace);
void rdAFRaster_DrawSpanNGonFAT_8(rdActiveSpan* pSpan);
void rdAFRaster_DrawSpanNGonLAT_8(rdActiveSpan* pSpan);
void rdAFRaster_DrawSpanNGonGAT_8(rdActiveSpan* pSpan);

#endif // RDRASTER_SOFTWARE_RENDERER

#endif // _RDAFRASTER_H
