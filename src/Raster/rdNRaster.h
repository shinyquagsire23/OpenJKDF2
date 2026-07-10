#ifndef _RDNRASTER_H
#define _RDNRASTER_H

#include "types.h"
#include "globals.h"

#ifdef RDRASTER_SOFTWARE_RENDERER

// Perspective-correct, NON-z-buffered per-face software rasterizer — the functional equivalent of
// JK.EXE's rdNRaster family (the rdCache_DrawFaceN path). It is the non-depth sibling of rdZRaster:
// same per-face convex scanline sweep with perspective (IT) / affine (AT) texturing, flat/lit/
// gouraud shading, masking and translucency — but no depth buffer, so faces composite in painter's
// order with no per-pixel z-test or z-write.
//
// Not wired into OpenJKDF2's live render path (only rdZRaster is); this exists for function-by-
// function parity with the GrimFandango rdNRaster symbol list (a net-new module, like the DSi
// std3D — no per-function // Added notes needed). JK spun this family's ~30 DrawNGon variants from
// one scanline body via #define/#ifdef/#undef; rdNRaster_ngon.h reproduces that.

// Rasterize one proc face (textured, perspective-correct, no z-test). Mirrors the mode clamping /
// material-cel / lighting selection of JK's rdCache_DrawFaceN. No-ops faces it cannot draw
// (untextured with no solid color, non-8bpp target, missing texels).
void rdNRaster_DrawFace(rdProcEntry* pProcEntry);

#endif // RDRASTER_SOFTWARE_RENDERER

#endif // _RDNRASTER_H
