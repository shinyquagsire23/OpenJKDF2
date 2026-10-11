#ifndef _DWIMAGEDRAW_H
#define _DWIMAGEDRAW_H

// dwImageDraw — DroidWorks 2D drawing primitives onto a locked image surface
// (dwImageBits). 8bpp is fully implemented; every 16bpp path in the binary is
// routed to a shared no-op stub (the fill tables' [2] entries and the
// DrawGlyph16-style dispatch), so 16bpp draws nothing.
//
// Blends use the ENGINE's current colormap (rdColormap_pCurMap, the global
// set by rdColormap_SetCurrent — binary DAT_005542b8):
//   colormap->transparency (+0x338) = 256x256 color-mix table,
//   colormap->lightlevel   (+0x330) = 64x256 brightness ramp.
//
// Ghidra (DroidWorks.exe), 13 functions:
//   dwImageDraw_FillRunH8 (internal) dwImageDraw_FillRunV8 (internal)
//   dwImageDraw_Circle    dwImageDraw_FillRect
//   dwImageDraw_BlendRect dwImageDraw_FrameRect
//   dwImageDraw_ShadeRect dwImageDraw_Line
//   dwImageDraw_LineRunVert (internal) dwImageDraw_LineRunHoriz (internal)
//   dwImageDraw_ClipLine  dwImageDraw_FillTriBlend
//   dwImageDraw_BlendColumn
// Per-bpp fill tables: dwImageDraw_aFillRunH / aFillRunV
// (file-static here; indexed [bpp], bpp 1=8bpp real, 2=16bpp no-op stub).

#include "Dw/dwTypes.h"
#include "Dw/dwRect.h"

// Genuinely-C unit (procedural, no C++ features in the binary); guarded for
// inclusion from the C++ DW units.
#ifdef __cplusplus
extern "C" {
#endif

// Owned by the dwImage unit (src/Dw/dwImage.h); repeating the typedef here is
// valid C11/C++ and keeps this header self-contained.
typedef struct dwImageBits dwImageBits;

// Bresenham circle outline (8bpp only), 4-way symmetric plot with per-pixel
// clipping to {0,0,w,h} intersected with pClip (NULL = whole surface).
void dwImageDraw_Circle(dwImageBits* pBits, dwPoint* pCenter, int16_t radius, int color, dwRect* pClip);

// Solid fill of pRect (clipped to pClip when non-NULL) via the per-bpp
// horizontal fill-run table.
void dwImageDraw_FillRect(dwImageBits* pBits, dwRect* pRect, int color, dwRect* pClip);

// Translucent color overlay: dest = transparency[dest*256 + color]. 8bpp only.
void dwImageDraw_BlendRect(dwImageBits* pBits, dwRect* pRect, int color, dwRect* pClip);

// Rectangle outline; each of the four edges is drawn only when it survives
// the clip (per-edge visibility flags).
void dwImageDraw_FrameRect(dwImageBits* pBits, dwRect* pRect, int color, dwRect* pClip);

// Darken pRect by pct (0..100 -> brightness-ramp level 0..63). 8bpp only.
// NOTE: no clip parameter — the caller pre-clips.
void dwImageDraw_ShadeRect(dwImageBits* pBits, dwRect* pRect, int pct);

// Run-length-slice Bresenham line from *pP0 to *pP1, clipped (Cohen-
// Sutherland) to {0,0,w,h} ∩ pClip. 8bpp draws; 16bpp routes to the stub.
void dwImageDraw_Line(dwImageBits* pBits, dwPoint* pP0, dwPoint* pP1, int color, dwRect* pClip);

// Cohen-Sutherland segment clip of *pP0-*pP1 against pBounds (left/top
// inclusive, right/bottom exclusive). Clamps the endpoints in place; returns
// 1 when a visible segment remains, 0 when fully rejected.
int dwImageDraw_ClipLine(dwRect* pBounds, dwPoint* pP0, dwPoint* pP1);

// Translucent filled triangle: apex at *pApex, opposite edge vertical at
// paEnds[0].x from paEnds[0].y to paEnds[1].y (both end points share x).
// Walks columns left->right calling dwImageDraw_BlendColumn. pClip REQUIRED.
void dwImageDraw_FillTriBlend(dwImageBits* pBits, int color, dwPoint* pApex, dwPoint* paEnds, dwRect* pClip);

// Vertical translucent span at column x from yTop (inclusive) to yBottom
// (exclusive), clipped to pClip (REQUIRED, not NULL-checked). 8bpp only.
void dwImageDraw_BlendColumn(dwImageBits* pBits, int16_t x, int16_t yTop, int16_t yBottom, int color, dwRect* pClip);

#ifdef __cplusplus
}
#endif

#endif // _DWIMAGEDRAW_H
