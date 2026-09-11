#ifndef _STDBITMAPRLE2_H
#define _STDBITMAPRLE2_H

// stdBitmapRle2 — the DroidWorks engine-side BMP/RLE image LOADER unit.
//
// Decompiled from DroidWorks.exe, address ranges:
//   0x442df0-0x443090  stdBitmapRle2 (uncompressed image class, vtbl 0x520140)
//   0x444820-0x444d50  the loader chain (dwImage_LoadFile dispatch + loads_bmp
//                       + LoadEntry + LoadFormat0/1 + the 16bpp LoadFile16)
//   0x449750-0x449f40  stdBitmapRle (lazy-decode RLE image class, vtbl 0x5201b8)
//
// This is the module dwImage_LoadFile (@0x444820, in dwImage.cpp) dispatches
// into. On the DW 640x480x8 SOFTWARE display it takes the 8bpp loads_bmp path;
// a 16bpp display would take stdBitmapRle2_LoadFile16.
//
// The two image classes (stdBitmapRle2 / stdBitmapRle) are file-local to
// stdBitmapRle2.cpp — every external caller uses only the C free functions
// declared below (all __cdecl / C-visible in the binary).

#include "Dw/dwImage.h"

#ifdef __cplusplus
extern "C" {
#endif

// 8bpp BMP/RLE file loader. Validates the .BMP/.RLE extension then reads the
// file through dwMain_pHS. bForceDecompress != 0 forces a BI_RLE8 file to be
// fully decoded into an uncompressed stdBitmapRle2 (used by the mask loader).
// Returns a heap dwImage (stdBitmapRle2 or stdBitmapRle), or NULL. @444850
dwImage* loads_bmp(char* pFilePath, int bForceDecompress);

// Allocate an empty width x height stdBitmapRle2 at the given bpp (BITS: 8/16).
// (Binary: operator new(0x18) + stdBitmapRle2_Ctor @442df0.)
dwImage* stdBitmapRle2_Instantiate(int16_t width, int16_t height, int bpp);

// Allocate a width x height stdBitmapRle2 and blit the {0,0,width,height}
// region of pSrc into it (a flat copy of pSrc at pSrc's bpp).
// (Binary: operator new(0x18) + stdBitmapRle2_ToVBuffer @442ec0.)
dwImage* stdBitmapRle2_InstantiateCopy(dwImage* pSrc, int16_t width, int16_t height);

// Image loader picked for a >8bpp display: on an 8bpp display it forwards to
// loads_bmp(path, 1); on a deeper display it loads 8bpp then converts to a
// display-format dwImageVBuf. @444c50 (Ghidra: stdBitmapRle_FUN_00444c50)
dwImage* stdBitmapRle2_LoadFile16(char* pFilePath);

#ifdef __cplusplus
}
#endif

#endif // _STDBITMAPRLE2_H
