#ifndef _DWRECT_H
#define _DWRECT_H

// dwRect — DroidWorks short-LTRB rectangle helpers, shared across the whole
// DW GUI (widget rects, font glyph clipping, image blits, dwDisplay dirty
// rects).
//
// Ghidra (DroidWorks.exe): dwRect_ContainsPoint@0x406570 (COMDAT),
// dwRect_Set@0x418850 (COMDAT), dwRect_Overlaps@0x444180,
// dwRect_Clip@0x4441f0, dwRect_Union@0x444270 (the latter three live in the
// dwDisplay unit's range and feed its dirty-rect list).

#include "Dw/dwTypes.h"

// Genuinely-C unit (no C++ features in the binary); guarded for inclusion
// from the C++ DW units.
#ifdef __cplusplus
extern "C" {
#endif

// The DW widget rect: 4 inline int16s, LTRB order. There is no named struct
// in the binary — every widget embeds these as its first fields (offsets
// 0x00/0x02/0x04/0x06), and dwDirtyRect nodes start with the same four
// shorts. left/top are inclusive, right/bottom are exclusive.
typedef struct dwRect { int16_t left, top, right, bottom; } dwRect;
typedef struct dwPoint { int16_t x, y; } dwPoint;

// Returns 1 when (x, y) is inside pRect: left/top inclusive, right/bottom
// exclusive.
int dwRect_ContainsPoint(dwRect* pRect, int16_t x, int16_t y);

// Writes the four LTRB fields.
void dwRect_Set(dwRect* pRect, int16_t left, int16_t top, int16_t right, int16_t bottom);

// Returns 1 when the two rects intersect. NOTE: uses <= on the intersection
// edges, so rects that merely touch (zero-area intersection) still count as
// overlapping — the dwDisplay dirty-rect coalescer relies on this.
int dwRect_Overlaps(dwRect* pRect, dwRect* pOther);

// Clips pRect to the intersection with pClip; if the result is empty
// (width or height < 1) pRect is zeroed. Used by the font glyph draw and the
// dwImage blit layer.
void dwRect_Clip(dwRect* pRect, dwRect* pClip);

// Grows pRect to the union of pRect and pOther. An empty rect
// (left == right or top == bottom) on either side is special-cased: an empty
// pRect is replaced by pOther outright, an empty pOther is ignored.
void dwRect_Union(dwRect* pRect, dwRect* pOther);

#ifdef __cplusplus
}
#endif

#endif // _DWRECT_H
