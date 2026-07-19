#ifndef _DWCONSOLEASSETS_H
#define _DWCONSOLEASSETS_H

// dwConsoleAssets — OpenJKDF2-side helpers (no binary counterpart): build the
// JK-engine asset objects the Quake console needs (stdFont font-strip +
// stdBitmap background) out of DroidWorks resources, since DW has no .sft
// fonts or .bm bitmaps.
//
//   Font:       dwFont_Load parses `Arial12.laf` (the same font the DW HUD
//               console uses); the glyphs are baked into a one-row 8bpp
//               "FONTSTRIP" stdBitmap exactly like an .sft (glyph cell width =
//               the .laf advance width, glyph pixels at their baseline
//               x/yOffset), then wrapped in a stdFont whose charset entries
//               point at the cells. .laf pixels are a monochrome mask (0 =
//               transparent, 0xff = solid), so the strip palette is a gray
//               ramp — index 0 is forced transparent by the GL UI texture
//               upload, everything else tints toward white.
//   Background: an .rle screen background (workshop.ifc's WBACKGROUND.RLE) is
//               decoded by stdBitmapRle2_LoadFile16 and copied into an 8bpp
//               stdBitmap with the palette taken from its .cmp colormap
//               (workshop2.cmp), so it renders with its intended colors
//               regardless of the currently-applied screen palette.
//
// Both conversions run through the DW VFS (dwMain_pHS), so they must be
// called only after dwMain_Startup; the font additionally needs dwFont_Startup
// (part of dw_Startup, first frame) — dwConsoleAssets_Ready() gates that.

#include "types.h"

#ifdef PLATFORM_DROIDWORKS

// These engine headers have no extern "C" guards of their own — wrap at
// include site (same pattern as dwCursor.cpp).
#ifdef __cplusplus
extern "C" {
#endif
#include "General/stdBitmap.h"
#include "General/stdFont.h"
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Nonzero once the DW app layer is far enough up that asset loads work
// (dwFont cache exists, i.e. dw_Startup ran; implies the DW VFS is mounted).
int dwConsoleAssets_Ready();

// Build a stdFont from a DroidWorks .laf font (e.g. "Arial12"). Returns NULL
// on failure. The result is owned by the caller and freed with stdFont_Free.
stdFont* dwConsoleAssets_LoadFont(const char* pName);

// Build a stdBitmap from a DroidWorks .rle/.bmp image (e.g. "WBACKGROUND.RLE"),
// with the stdBitmap palette taken from pCmpName (e.g. "workshop2.cmp"; falls
// back to a gray ramp if the colormap can't be loaded). Returns NULL on
// failure. The result is owned by the caller and freed with stdBitmap_Free.
stdBitmap* dwConsoleAssets_LoadBitmap(const char* pPath, const char* pCmpName);

#ifdef __cplusplus
}
#endif

#else // !PLATFORM_DROIDWORKS

// Retro targets exclude src/Dw from the build; Main_bDroidWorks is never set
// there, so the call sites compile to dead no-ops (same pattern as dwMain.h).
#define dwConsoleAssets_Ready() (0)
#define dwConsoleAssets_LoadFont(pName) (NULL)
#define dwConsoleAssets_LoadBitmap(pPath, pCmpName) (NULL)

#endif // PLATFORM_DROIDWORKS

#endif // _DWCONSOLEASSETS_H
