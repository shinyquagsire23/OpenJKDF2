// dwImageVBuf — dwImage subclass backed by a stdDisplay tVBuffer.
//
// Decompiled from DroidWorks.exe, unit range 0x449540-0x449740 (vtbl
// @0x5201a0). See dwImageVBuf.h for the class layout and construction modes.
//
// Engine-API mapping (binary -> repo):
//   stdDisplay_FUN_004fdcc0 -> stdDisplay_VBufferNew(fmt, 1, 1, NULL)
//   stdDisplay_FUN_004fdf70 -> stdDisplay_VBufferLock
//   stdDisplay_FUN_004fdfc0 -> stdDisplay_VBufferUnlock
//   stdDisplay_VBufferFree  -> stdDisplay_VBufferFree (already named)
//   tVBuffer field reads: +0x04 lock state -> lockSurfRefCount (adapted, see
//   Lock), +0x0c/+0x10 width/height -> format.width/height, +0x18 stride ->
//   format.rowSize, +0x24 bpp bits -> format.format.bpp, +0x5c pixels ->
//   surface_lock_alloc.
//   Display-format template DAT_006b17cc (global tRasterInfo written by the
//   DW engine's stdDisplay SetMode; its bpp dword is the DAT_006b17e4 depth
//   checked all over the GUI) -> stdDisplay_pCurVideoMode->format.
//
// Compiled as C++ (vtable class; the binary ctor carries MSVC EH frames).

#include "Dw/dwImageVBuf.h"

#include "stdPlatform.h"

// Win95/stdDisplay.h + generated globals.h have no extern "C" guards of their
// own — wrap at include site. globals.h provides stdDisplay_pCurVideoMode.
extern "C" {
#include "Win95/stdDisplay.h"
#include "globals.h"
}

// Wrap an existing tVBuffer (non-owning). @449540
dwImageVBuf::dwImageVBuf(tVBuffer* pVBuffer)
{
    this->desc.width = (uint16_t)pVBuffer->format.width;
    this->desc.height = (uint16_t)pVBuffer->format.height;
    this->desc.bpp = (uint8_t)((uint8_t)pVBuffer->format.format.bpp >> 3); // bits -> bytes
    this->lockState = 0;
    this->bOwnsVBuffer = 0;
    this->pVBuffer = pVBuffer;
}

// Allocate an owned tVBuffer sized to pSrcImage (bppBits BITS per pixel) and
// copy the source in through its virtual Blit. @4495a0
dwImageVBuf::dwImageVBuf(dwImage* pSrcImage, uint8_t bppBits)
{
    this->desc.width = pSrcImage->desc.width;
    this->desc.height = pSrcImage->desc.height;
    this->desc.bpp = (uint8_t)(bppBits >> 3); // bits -> bytes
    this->lockState = 0;
    this->bOwnsVBuffer = 1;
    this->pVBuffer = NULL;

    // Binary: copies the 0x4c-byte display-format global (tRasterInfo
    // @0x6b17cc, kept current by the engine's stdDisplay SetMode) as the
    // template, then overrides width/height/bpp.
    // Note: mapped to stdDisplay_pCurVideoMode->format; NULL-guarded with a
    // zeroed template (the binary trusted the global unconditionally —
    // stdDisplay_VBufferNew recomputes stride/size/masks from
    // width/height/bpp anyway).
    tRasterInfo fmt = {};
    if (stdDisplay_pCurVideoMode)
        fmt = stdDisplay_pCurVideoMode->format;
    fmt.width = pSrcImage->desc.width;
    fmt.height = pSrcImage->desc.height;
    fmt.format.bpp = bppBits;

    this->pVBuffer = stdDisplay_VBufferNew(&fmt, 1, 1, NULL);
    if (this->pVBuffer)
    {
        // Binary quirk: unlocks the freshly created buffer (a no-op on a
        // never-locked buffer; harmless under the SDL stdDisplay too).
        stdDisplay_VBufferUnlock(this->pVBuffer);

        dwImageBits destBits;
        destBits.pDesc = &this->desc; // binary: (dwImageDesc*)this
        destBits.pPixels = NULL;
        destBits.stride = 0;
        this->Lock(&destBits.pPixels, &destBits.stride);
        pSrcImage->Blit(&destBits, 0, 0, NULL);
        this->Unlock();
    }
}

// Frees the buffer only when owned. (The binary body also re-points the vptr
// at the dwImage base vtbl @0x520158 while unwinding — the compiler does
// that here; the scalar-deleting dwImageVBuf_DtorDelete @449580 is likewise
// compiler-generated via `delete`.) @4496a0
dwImageVBuf::~dwImageVBuf()
{
    if (this->bOwnsVBuffer)
        stdDisplay_VBufferFree(this->pVBuffer);
}

// Lock the underlying buffer and expose its pixels/stride. Returns nonzero
// when stdDisplay_VBufferLock succeeded. @4496d0
int dwImageVBuf::Lock(void** ppPixels, int* pStride)
{
    int bRes = stdDisplay_VBufferLock(this->pVBuffer);
    // Binary: lockState = pVBuffer->lockSurfRefCount (+0x04), and the pixel
    // pointer is only handed out while that is nonzero. Note: the repo's SDL
    // stdDisplay does not maintain lockSurfRefCount — surface_lock_alloc
    // presence is the equivalent locked-state signal, so it drives lockState
    // here.
    this->lockState = (this->pVBuffer->surface_lock_alloc != NULL);
    if (this->lockState != 0)
    {
        *ppPixels = this->pVBuffer->surface_lock_alloc;
        *pStride = (int)this->pVBuffer->format.rowSize;
    }
    else
    {
        *ppPixels = NULL;
        *pStride = 0;
    }
    return bRes != 0;
}

// Unlock the underlying buffer and re-snapshot the lock state. @449730
int dwImageVBuf::Unlock()
{
    stdDisplay_VBufferUnlock(this->pVBuffer);
    // Binary: returns (stdDisplay unlock result != 0) and re-reads +0x04.
    // Note: the repo's stdDisplay_VBufferUnlock returns void; report success
    // and mirror the cleared lock state (surface_lock_alloc is now NULL).
    this->lockState = (this->pVBuffer->surface_lock_alloc != NULL);
    return 1;
}

// ---------------------------------------------------------------------------
// Added: C FFI factories (not in the binary — callers inlined operator new)
// ---------------------------------------------------------------------------

extern "C" dwImage* dwImageVBuf_New(tVBuffer* pVBuffer)
{
    return new dwImageVBuf(pVBuffer);
}

extern "C" dwImage* dwImageVBuf_NewFromImage(dwImage* pSrcImage, uint8_t bppBits)
{
    return new dwImageVBuf(pSrcImage, bppBits);
}
