#ifndef _DWIMAGEVBUF_H
#define _DWIMAGEVBUF_H

// dwImageVBuf — dwImage subclass backed by a stdDisplay tVBuffer.
//
// Decompiled from DroidWorks.exe, unit range 0x449540-0x449740 (6 functions,
// vtbl dwImageVBuf_vtbl @0x5201a0). Binary /DW struct dwImageVBuf, size 0x18:
//   0x00 vptr (aliases dwImageDesc.format — see dwImage.h layout quirk)
//   0x04 width / 0x06 height / 0x08 bpp (bytes)   [= the dwImage base fields]
//   0x0c lockState
//   0x10 bOwnsVBuffer
//   0x14 pVBuffer
//
// Two construction modes:
//  - dwImageVBuf(tVBuffer*): WRAPS an existing buffer (bOwnsVBuffer = 0);
//    pulls width/height/bpp from the buffer's format. Used by dwCursor
//    (cursor sprites) and dwDisplay_SetMode (the screen image wrapping the
//    primary surface / back buffer).
//  - dwImageVBuf(dwImage*, bppBits): allocates an OWNED tVBuffer sized to the
//    source image (display-format template, width/height/bpp overridden),
//    then locks itself and virtual-Blits the source image in. Used by the
//    stdBitmapRle2 loader and dwGuiScreen_Ctor.
//
// Only Lock/Unlock/dtor are overridden — Blit/BlitColorMap are the shared
// dwImage base implementations (vtbl slots +0x04/+0x08 @0x448d60/@0x448e40).

#include "Dw/dwImage.h"

#ifdef __cplusplus

struct dwImageVBuf : dwImage
{
    int32_t lockState;    // 0x0c: tVBuffer lock state snapshot (see Lock)
    uint8_t bOwnsVBuffer; // 0x10: nonzero -> dtor frees pVBuffer
    tVBuffer* pVBuffer;   // 0x14

    dwImageVBuf(tVBuffer* pVBuffer);                  // @449540 (dwImageVBuf_Ctor) — wraps, non-owning
    dwImageVBuf(dwImage* pSrcImage, uint8_t bppBits); // @4495a0 (dwImageVBuf_CtorFromImage) — owned copy
    virtual ~dwImageVBuf();                           // @4496a0 (dwImageVBuf_Dtor; the scalar-deleting
                                                      //  dwImageVBuf_DtorDelete @449580 is the compiler's)
    virtual int Lock(void** ppPixels, int* pStride);  // vtbl +0x0c @4496d0
    virtual int Unlock();                             // vtbl +0x10 @449730
}; // binary sizeof 0x18

#else // !__cplusplus

typedef struct dwImageVBuf dwImageVBuf; // opaque in the C view

#endif // __cplusplus

#ifdef __cplusplus
extern "C" {
#endif

// Added: C FFI factories (not in the binary — its callers inlined
// `operator new(0x18)` + the ctor). Return the object as the dwImage base so
// C callers can hand it straight to the dwImage_Call* shims / dwImage_Delete.
dwImage* dwImageVBuf_New(tVBuffer* pVBuffer);                     // new + @449540
dwImage* dwImageVBuf_NewFromImage(dwImage* pSrcImage, uint8_t bppBits); // new + @4495a0

#ifdef __cplusplus
}
#endif

#endif // _DWIMAGEVBUF_H
