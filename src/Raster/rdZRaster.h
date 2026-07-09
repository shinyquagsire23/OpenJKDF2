#ifndef _RDZRASTER_H
#define _RDZRASTER_H

#include "types.h"
#include "globals.h"

#ifdef RDRASTER_SOFTWARE_RENDERER

// Perspective-correct, z-buffered per-face software rasterizer. This is the functional
// equivalent of JK.EXE's rdZRaster family (the curZBufferMethod path): unlike the affine
// active-edge path (rdActive/rdAFRaster, painter's algorithm), it draws each cached proc
// face independently, interpolating 1/w, u/w, v/w linearly in screen space and dividing per
// pixel (true perspective), while a per-pixel depth buffer (max 1/w wins) resolves occlusion.
//
// JK's rdZRaster transcribes as ~30 file globals + MMX 16-pixel-block scanlines across dozens
// of shading/bpp variants; this is a single idiomatic implementation that produces the same
// result (a net-new module, like the DSi std3D — no per-function // Added notes needed).

void rdZRaster_Startup(void);

// Scene-start depth clear (alloc/resize + clear) for an explicit target vbuffer. Called once per
// frame from the software render bracket, before the world is drawn — the reliable per-frame clear.
void rdZRaster_BeginFrame(tVBuffer* pVBuffer);

// Depth clear against the current camera's canvas. Hooked into std3D_ClearZBuffer() so JK's own
// mid-frame clear (the POV weapon's, in jkPlayer_DrawPov) also clears the software depth buffer.
void rdZRaster_ClearZBuffer(void);

// Rasterize one cached proc face (textured, perspective-correct, z-tested). Mirrors the mode
// clamping / material-cel / lighting selection of JK's rdCache_DrawFaceZ. No-ops faces it
// cannot draw (untextured, non-8bpp target, missing texels).
void rdZRaster_DrawFace(rdProcEntry* pProcEntry);

#endif // RDRASTER_SOFTWARE_RENDERER

#endif // _RDZRASTER_H
