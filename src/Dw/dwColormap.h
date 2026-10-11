#ifndef _DWCOLORMAP_H
#define _DWCOLORMAP_H

// dwColormap — DroidWorks global current-colormap manager (single active
// rdColormap for the whole DW GUI).
//
// Ghidra (DroidWorks.exe), 3 functions:
//   dwColormap_SetDisplayPalette
//   dwColormap_Load
//   dwColormap_Apply

#include "Dw/dwTypes.h"

// Genuinely-C unit (no C++ features in the binary); guarded for inclusion
// from the C++ DW units.
#ifdef __cplusplus
extern "C" {
#endif

// The single active colormap (binary: dwColormap_pCurrent).
extern rdColormap* dwColormap_pCurrent;

// Cached display-gamma parameter (binary: dwColormap_pDisplayPalette). Despite the pointer
// type (kept from the Ghidra decompilation), this is an opaque gamma value:
// the binary forwards it verbatim to stdDisplay's gamma-correct-and-push
// palette routine and only uses it for change-dedup.
extern void* dwColormap_pDisplayPalette;

// Palette indices closest to black/white/green in the current colormap,
// biased +1 (entry 0 is reserved/forced black). transparentIdx (binary:
// dwColormap_transparentIdx) is read widely by the GUI text/options code.
extern int dwColormap_transparentIdx;
extern int dwColormap_whiteIdx;
extern int dwColormap_greenIdx;

// 8bpp -> 16bpp palette lookup table, rebuilt whenever the colormap changes
// while the display runs 16bpp. Note: in the binary this table lives in
// stdDisplay's .bss (unnamed, dwColormap_aPalette16) and is read by the dwImage 16bpp
// blit path; it is owned here so it links before dwImage/dwDisplay land.
extern uint16_t dwColormap_aPalette16[256];

// Note: the binary has no dwColormap startup function; this exists only to
// reset the module globals for OpenJKDF2's soft-reset loop.
void dwColormap_Startup();

void dwColormap_SetDisplayPalette(void* pPalette);
int dwColormap_Load(char* pName);
void dwColormap_Apply();

#ifdef __cplusplus
}
#endif

#endif // _DWCOLORMAP_H
