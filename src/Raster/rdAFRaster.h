#ifndef _RDAFRASTER_H
#define _RDAFRASTER_H

#include "types.h"
#include "globals.h"

#ifdef RDRASTER_SOFTWARE_RENDERER

// Affine active-edge software rasterizer family (JK.EXE rdAFRaster). rdActive builds a per-face
// span list; each face's installed pfnDrawSpan flush walks that list and draws it. The GrimFandango
// DrawNGon matrix: LW (wireframe) · {F,G,L}S (solid) · {,M}{F,G,L}AT (affine textured) ·
// {,M}{F,G,L}IT (perspective textured) — F/G/L flat/gouraud/lit, M masked, AT affine, IT
// perspective(per-pixel 1/z divide). The 12 textured span samplers are emitted from one template
// (rdAFRaster_span.h); the wireframe/solid families fill inline. Not wired into OpenJKDF2's live
// render path (only rdZRaster is) — this exists for function-by-function parity with the Grim
// symbol list (a net-new module, no per-function // Added notes needed).
//
// Only the family SetupNGon entry points (called by rdActive_AddActiveFace) and the edge callbacks
// (forward-referenced within the module) are declared here; the DrawNGon/DrawSpan variant functions
// are file-static (installed as per-face callbacks).

// --- Face setups (one per Grim SetupNGon<V>): pick mip/texels + light + install callbacks. ---
void rdAFRaster_SetupNGonLW_0(rdActiveFace* pFace, rdTexinfo* pTexinfo);
void rdAFRaster_SetupNGonFS(rdActiveFace* pFace, rdTexinfo* pTexinfo);
void rdAFRaster_SetupNGonLS(rdActiveFace* pFace, rdTexinfo* pTexinfo, int lightLevel);
void rdAFRaster_SetupNGonGS(rdActiveFace* pFace, rdTexinfo* pTexinfo);
void rdAFRaster_SetupNGonFAT(rdActiveFace* pFace, rdTexinfo* pTexinfo);
void rdAFRaster_SetupNGonLAT(rdActiveFace* pFace, rdTexinfo* pTexinfo, int lightLevel);
void rdAFRaster_SetupNGonGAT(rdActiveFace* pFace, rdTexinfo* pTexinfo);
void rdAFRaster_SetupNGonMFAT(rdActiveFace* pFace, rdTexinfo* pTexinfo);
void rdAFRaster_SetupNGonMLAT(rdActiveFace* pFace, rdTexinfo* pTexinfo, int lightLevel);
void rdAFRaster_SetupNGonMGAT(rdActiveFace* pFace, rdTexinfo* pTexinfo);
void rdAFRaster_SetupNGonFIT(rdActiveFace* pFace, rdTexinfo* pTexinfo);
void rdAFRaster_SetupNGonLIT(rdActiveFace* pFace, rdTexinfo* pTexinfo, int lightLevel);
void rdAFRaster_SetupNGonGIT(rdActiveFace* pFace, rdTexinfo* pTexinfo);
void rdAFRaster_SetupNGonMFIT(rdActiveFace* pFace, rdTexinfo* pTexinfo);
void rdAFRaster_SetupNGonMLIT(rdActiveFace* pFace, rdTexinfo* pTexinfo, int lightLevel);
void rdAFRaster_SetupNGonMGIT(rdActiveFace* pFace, rdTexinfo* pTexinfo);

// --- Edge setup + per-scanline advance (forward-referenced within rdAFRaster.c). One per
// distinct edge interpolation; shade/mask variants share (masking/lit don't change the edge). ---
int  rdAFRaster_SetupEdgeNGonLW(rdEdge* pEdge, rdActiveFace* pFace, int vA, int vB);
int  rdAFRaster_SetupEdgeNGonFAT(rdEdge* pEdge, rdActiveFace* pFace, int vA, int vB);
int  rdAFRaster_SetupEdgeNGonGAT(rdEdge* pEdge, rdActiveFace* pFace, int vA, int vB);
int  rdAFRaster_SetupEdgeNGonFIT(rdEdge* pEdge, rdActiveFace* pFace, int vA, int vB);
int  rdAFRaster_SetupEdgeNGonGIT(rdEdge* pEdge, rdActiveFace* pFace, int vA, int vB);
int  rdAFRaster_SetupEdgeNGonGS(rdEdge* pEdge, rdActiveFace* pFace, int vA, int vB);
void rdAFRaster_AdvanceLeftEdgeNGonLW(rdEdge* pEdge);
void rdAFRaster_AdvanceRightEdgeNGonLW(rdEdge* pEdge);
void rdAFRaster_AdvanceLeftEdgeNGonFAT(rdEdge* pEdge);
void rdAFRaster_AdvanceRightEdgeNGonFAT(rdEdge* pEdge);
void rdAFRaster_AdvanceLeftEdgeNGonGAT(rdEdge* pEdge);
void rdAFRaster_AdvanceRightEdgeNGonGAT(rdEdge* pEdge);
void rdAFRaster_AdvanceLeftEdgeNGonFIT(rdEdge* pEdge);
void rdAFRaster_AdvanceRightEdgeNGonFIT(rdEdge* pEdge);
void rdAFRaster_AdvanceLeftEdgeNGonGIT(rdEdge* pEdge);
void rdAFRaster_AdvanceRightEdgeNGonGIT(rdEdge* pEdge);
void rdAFRaster_AdvanceLeftEdgeNGonGS(rdEdge* pEdge);
void rdAFRaster_AdvanceRightEdgeNGonGS(rdEdge* pEdge);

// Wireframe flush + single-span drawer (installed by SetupNGonLW_0; not static so the setup can
// take its address before the definition).
void rdAFRaster_DrawNGonLW(rdActiveFace* pFace);
void rdAFRaster_DrawSpanNGonLW_8(rdActiveSpan* pSpan);

#endif // RDRASTER_SOFTWARE_RENDERER

#endif // _RDAFRASTER_H
