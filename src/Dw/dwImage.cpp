// dwImage — the shared DroidWorks image/blit BASE class implementation.
//
// Decompiled from DroidWorks.exe, unit range 0x448d60-0x449530 (+ the
// dwImage_LoadFile dispatcher @0x444820). See dwImage.h for the vtable
// contract, the Blit semantics (this = SOURCE image) and the object-as-desc
// layout quirk.
//
// Row-copy dispatch (from the 0x448f20/0x4491c0/0x449370 disassembly), keyed
// on BYTES-per-pixel of source (outer) then destination (inner):
//   src 1 -> dest 1 : CopyRow8 / CopyRow8ColorMap / CopyRow8Transparent
//   src 1 -> dest 2 : RLE_decompress_type2 (an EMPTY stub in the binary —
//                     the RLE/cross-depth row path was never implemented)
//   src 2 -> dest 2 : CopyRow16 (the ColorMap/Transparent 16bpp variants just
//                     forward to the plain copy — no translate/color-key,
//                     binary quirk preserved)
// The ColorMap 8bpp path blends src over dest through the current engine
// colormap's 256x256 transparency table (binary: *(DAT_005542b8 + 0x338) =
// rdColormap_pCurMap->transparency).
//
// Compiled as C++ (the binary unit carries vtable dispatch + MSVC EH frames
// in dwImage_Blit/dwImage_BlitColorMap).

#include "Dw/dwImage.h"

#include "stdPlatform.h"

// Win95/stdDisplay.h + generated globals.h have no extern "C" guards of their
// own — wrap at include site. globals.h provides rdColormap_pCurMap.
extern "C" {
#include "Win95/stdDisplay.h"
#include "globals.h"
}

typedef void (*dwImageCopyRowFn)(uint8_t* pDestRow, uint8_t* pSrcRow, unsigned int count);

// ---------------------------------------------------------------------------
// Row copiers (file-local in the binary; addresses within 0x449160-0x44950x)
// ---------------------------------------------------------------------------

// Empty stub in the binary (a lone RET) — the src-8bpp -> dest-16bpp row path
// is unimplemented. Kept so the dispatch tables stay faithful. @449180
static void RLE_decompress_type2(uint8_t* pDestRow, uint8_t* pSrcRow, unsigned int count)
{
    (void)pDestRow; (void)pSrcRow; (void)count;
}

// Opaque 8bpp row copy: dword-at-a-time then the 0-3 byte tail. count is in
// pixels (== bytes at 8bpp). @449160
static void dwImage_CopyRow8(uint8_t* pDestRow, uint8_t* pSrcRow, unsigned int count)
{
    uint32_t* pDest32 = (uint32_t*)pDestRow;
    uint32_t* pSrc32 = (uint32_t*)pSrcRow;
    for (unsigned int n = count >> 2; n != 0; n--)
    {
        *pDest32++ = *pSrc32++;
    }
    uint8_t* pDest8 = (uint8_t*)pDest32;
    uint8_t* pSrc8 = (uint8_t*)pSrc32;
    for (unsigned int n = count & 3; n != 0; n--)
    {
        *pDest8++ = *pSrc8++;
    }
}

// Opaque 16bpp row copy: count is in PIXELS (2 bytes each) — dwords then the
// odd-pixel tail. @449190
static void dwImage_CopyRow16(uint8_t* pDestRow, uint8_t* pSrcRow, unsigned int count)
{
    uint32_t* pDest32 = (uint32_t*)pDestRow;
    uint32_t* pSrc32 = (uint32_t*)pSrcRow;
    for (unsigned int n = (count & 0x7fffffff) >> 1; n != 0; n--)
    {
        *pDest32++ = *pSrc32++;
    }
    uint8_t* pDest8 = (uint8_t*)pDest32;
    uint8_t* pSrc8 = (uint8_t*)pSrc32;
    for (unsigned int n = (count * 2) & 3; n != 0; n--)
    {
        *pDest8++ = *pSrc8++;
    }
}

// 8bpp blend copy: dest = transparencyTable[dest * 256 + src], where the
// table is the current engine colormap's 256x256 transparency/mix table
// (binary: *(DAT_005542b8 + 0x338); DAT_005542b8 = rdColormap_pCurMap, set by
// rdColormap_SetCurrent via dwColormap_Apply). @4492e0
static void dwImage_CopyRow8ColorMap(uint8_t* pDestRow, uint8_t* pSrcRow, unsigned int count)
{
    uint8_t* pTable = (uint8_t*)rdColormap_pCurMap->transparency;
    for (unsigned int n = count; n != 0; n--)
    {
        unsigned int srcPixel = *pSrcRow++;
        *pDestRow = pTable[(unsigned int)*pDestRow * 0x100 + srcPixel];
        pDestRow++;
    }
}

// Forwards to the empty RLE stub (binary quirk preserved). @449330
static void dwImage_CopyRow8ColorMapRle(uint8_t* pDestRow, uint8_t* pSrcRow, unsigned int count)
{
    RLE_decompress_type2(pDestRow, pSrcRow, count);
}

// 16bpp "colormap" copy is a plain copy — no palette translate (binary
// quirk). @449350
static void dwImage_CopyRow16ColorMap(uint8_t* pDestRow, uint8_t* pSrcRow, unsigned int count)
{
    dwImage_CopyRow16(pDestRow, pSrcRow, count);
}

// 8bpp color-key copy: source bytes of 0 are transparent. @449490
static void dwImage_CopyRow8Transparent(uint8_t* pDestRow, uint8_t* pSrcRow, unsigned int count)
{
    for (unsigned int n = count; n != 0; n--)
    {
        if (*pSrcRow != 0)
            *pDestRow = *pSrcRow;
        pSrcRow++;
        pDestRow++;
    }
}

// Forwards to the empty RLE stub (binary quirk preserved). @4494c0
static void dwImage_CopyRow8TransparentRle(uint8_t* pDestRow, uint8_t* pSrcRow, unsigned int count)
{
    RLE_decompress_type2(pDestRow, pSrcRow, count);
}

// 16bpp "transparent" copy is a plain copy — no color key (binary quirk).
// @4494e0
static void dwImage_CopyRow16Transparent(uint8_t* pDestRow, uint8_t* pSrcRow, unsigned int count)
{
    dwImage_CopyRow16(pDestRow, pSrcRow, count);
}

// ---------------------------------------------------------------------------
// Blit rect clipping + row loops
// ---------------------------------------------------------------------------

// Clips the (x, y, x + srcW, y + srcH) destination footprint of pSrcBits
// against pRect. Outputs the clipped destination rect [*pDestX0, *pDestX1) x
// [*pDestY0, *pDestY1) and how much was clipped off the left/top
// (*pSrcXofs/*pSrcYofs = source start offsets; only written when the
// footprint overlaps pRect at all). Returns nonzero when anything is left to
// draw. pDestBits is unused (kept for fidelity — the binary passes it too).
// Quirk preserved: the pre-test uses <=, so a footprint that merely touches
// pRect's left/top edge from outside still takes the clip path (the final
// x0 < x1 && y0 < y1 test rejects it anyway). @449040
static int dwImage_ClipBlitRect(dwImageBits* pSrcBits, dwImageBits* pDestBits, int x, int y, dwRect* pRect,
                                int* pDestX0, int* pDestY0, int* pDestX1, int* pDestY1,
                                int* pSrcXofs, int* pSrcYofs)
{
    (void)pDestBits;

    *pDestX0 = x;
    *pDestX1 = x;
    *pDestY0 = y;
    *pDestY1 = y;
    if ((pRect->left - (int)pSrcBits->pDesc->width <= x) &&
        (pRect->top - (int)pSrcBits->pDesc->height <= y) &&
        (x < (int)pRect->right) && (y < (int)pRect->bottom))
    {
        *pSrcXofs = 0;
        *pSrcYofs = 0;
        *pDestX1 = x + (int)pSrcBits->pDesc->width;
        *pDestY1 = y + (int)pSrcBits->pDesc->height;
        if (x < (int)pRect->left)
        {
            *pSrcXofs = pRect->left - x;
            *pDestX0 = pRect->left;
        }
        if (y < (int)pRect->top)
        {
            *pSrcYofs = pRect->top - y;
            *pDestY0 = pRect->top;
        }
        if ((int)pRect->right < *pDestX1)
            *pDestX1 = pRect->right;
        if ((int)pRect->bottom < *pDestY1)
            *pDestY1 = pRect->bottom;
    }
    return (*pDestX0 < *pDestX1) && (*pDestY0 < *pDestY1);
}

// Shared row-loop skeleton for the three blit modes. The binary emits three
// near-identical functions (@448f20/@4491c0/@449370) differing only in the
// dispatch table; the skeleton is factored here and each named function keeps
// its own faithful dispatch.
static void dwImage_BlitRowsCommon(dwImageBits* pSrcBits, dwImageBits* pDestBits, int x, int y,
                                   dwRect* pClipRect, dwImageCopyRowFn pfnCopy8, dwImageCopyRowFn pfnCopy8Rle,
                                   dwImageCopyRowFn pfnCopy16)
{
    int destX0 = 0, destY0 = 0, destX1 = 0, destY1 = 0;
    int srcXofs = 0, srcYofs = 0;

    if (!dwImage_ClipBlitRect(pSrcBits, pDestBits, x, y, pClipRect,
                              &destX0, &destY0, &destX1, &destY1, &srcXofs, &srcYofs))
        return;

    dwImageCopyRowFn pfnCopy = NULL;
    uint8_t srcBpp = pSrcBits->pDesc->bpp;
    uint8_t destBpp = pDestBits->pDesc->bpp;
    if (srcBpp == 1)
    {
        if (destBpp == 1)
            pfnCopy = pfnCopy8;
        else if (destBpp == 2)
            pfnCopy = pfnCopy8Rle;
    }
    else if (srcBpp == 2 && destBpp == 2)
    {
        pfnCopy = pfnCopy16;
    }
    if (!pfnCopy)
        return;

    uint8_t* pSrcRow = (uint8_t*)pSrcBits->pPixels + srcYofs * pSrcBits->stride + srcXofs * (int)srcBpp;
    uint8_t* pDestRow = (uint8_t*)pDestBits->pPixels + destY0 * pDestBits->stride + destX0 * (int)destBpp;
    for (int rows = destY1 - destY0; rows != 0; rows--)
    {
        pfnCopy(pDestRow, pSrcRow, (unsigned int)(destX1 - destX0));
        pDestRow += pDestBits->stride;
        pSrcRow += pSrcBits->stride;
    }
}

// Opaque row blit. @448f20
static void dwImage_BlitRows(dwImageBits* pSrcBits, dwImageBits* pDestBits, int x, int y, dwRect* pClipRect)
{
    dwImage_BlitRowsCommon(pSrcBits, pDestBits, x, y, pClipRect,
                           dwImage_CopyRow8, RLE_decompress_type2, dwImage_CopyRow16);
}

// Colormap-blend row blit. @4491c0
static void dwImage_BlitRowsColorMap(dwImageBits* pSrcBits, dwImageBits* pDestBits, int x, int y, dwRect* pClipRect)
{
    dwImage_BlitRowsCommon(pSrcBits, pDestBits, x, y, pClipRect,
                           dwImage_CopyRow8ColorMap, dwImage_CopyRow8ColorMapRle, dwImage_CopyRow16ColorMap);
}

// Color-key-0 row blit; extern — called directly by the dwCompleteMovie frame
// draw (binary @0x41112a). @449370
extern "C" void dwImage_BlitRowsTransparent(dwImageBits* pSrcBits, dwImageBits* pDestBits, int x, int y, dwRect* pClipRect)
{
    dwImage_BlitRowsCommon(pSrcBits, pDestBits, x, y, pClipRect,
                           dwImage_CopyRow8Transparent, dwImage_CopyRow8TransparentRle, dwImage_CopyRow16Transparent);
}

// ---------------------------------------------------------------------------
// dwImage base class
// ---------------------------------------------------------------------------

// Note: the binary has no standalone base ctor (subclass ctors write the
// width/height/bpp fields directly and desc.format is the vptr alias slot);
// zero-init here is translation-added so a default-constructed base is inert.
dwImage::dwImage()
{
    this->desc.format = 0;
    this->desc.width = 0;
    this->desc.height = 0;
    this->desc.bpp = 0;
}

// Base dtor (binary: @0x4430a0, emitted in the stdBitmapRle2 unit; base vtbl
// @0x520158). Trivial.
dwImage::~dwImage()
{
}

// Draw this image into the locked destination bits at (x, y), clipped to the
// destination bounds intersected with pClipRect. Locks `this` (vtbl +0x0c)
// around the row loop; the Lock return value is ignored (binary behavior).
// vtbl +0x04, shared by stdBitmapRle2 @0x520144 and dwImageVBuf @0x5201a4.
// @448d60
void dwImage::Blit(dwImageBits* pDestBits, int x, int y, dwRect* pClipRect)
{
    dwRect clipRect;
    clipRect.left = 0;
    clipRect.top = 0;
    clipRect.right = (int16_t)pDestBits->pDesc->width;
    clipRect.bottom = (int16_t)pDestBits->pDesc->height;
    if (pClipRect)
        dwRect_Clip(&clipRect, pClipRect);

    if ((int16_t)(clipRect.right - clipRect.left) == 0 || (int16_t)(clipRect.bottom - clipRect.top) == 0)
        return;

    dwImageBits srcBits;
    srcBits.pDesc = &this->desc; // binary: (dwImageDesc*)this — object doubles as its own desc
    srcBits.pPixels = NULL;
    srcBits.stride = 0;
    this->Lock(&srcBits.pPixels, &srcBits.stride);
    dwImage_BlitRows(&srcBits, pDestBits, x, y, &clipRect);
    this->Unlock();
}

// Same as Blit but blends through the current colormap's transparency table
// (8bpp path). vtbl +0x08, shared by both concrete vtables. @448e40
void dwImage::BlitColorMap(dwImageBits* pDestBits, int x, int y, dwRect* pClipRect)
{
    dwRect clipRect;
    clipRect.left = 0;
    clipRect.top = 0;
    clipRect.right = (int16_t)pDestBits->pDesc->width;
    clipRect.bottom = (int16_t)pDestBits->pDesc->height;
    if (pClipRect)
        dwRect_Clip(&clipRect, pClipRect);

    if ((int16_t)(clipRect.right - clipRect.left) == 0 || (int16_t)(clipRect.bottom - clipRect.top) == 0)
        return;

    dwImageBits srcBits;
    srcBits.pDesc = &this->desc; // binary: (dwImageDesc*)this
    srcBits.pPixels = NULL;
    srcBits.stride = 0;
    this->Lock(&srcBits.pPixels, &srcBits.stride);
    dwImage_BlitRowsColorMap(&srcBits, pDestBits, x, y, &clipRect);
    this->Unlock();
}

// ---------------------------------------------------------------------------
// dwImage_LoadFile
// ---------------------------------------------------------------------------

// Loads an image file, picking the loader by the current display depth.
// Binary:
//   if (<display tRasterInfo @0x6b17cc>.format.bpp > 8)   // = DAT_006b17e4
//       return stdBitmapRle_FUN_00444c50(pFilePath);       // 16bpp RLE loader
//   return loads_bmp(pFilePath, 0);                        // 8bpp BMP/RLE loader
// Both loaders (@0x444850/@0x444c50) belong to the NOT-YET-TRANSLATED
// stdBitmapRle2 engine-side unit, which also provides the RLE dwImage
// subclass they return.
// TODO(dw-decomp): LOUD STUB — always returns NULL until the stdBitmapRle2
// unit lands (referencing the loaders as externs would break the desktop
// link today). The display-depth global maps to
// stdDisplay_pCurVideoMode->format.format.bpp when the real dispatch is
// restored. @444820
extern "C" dwImage* dwImage_LoadFile(char* pFilePath)
{
    stdPlatform_Printf("TODO(dw-decomp): dwImage_LoadFile(\"%s\") — stdBitmapRle2 loaders not translated yet, returning NULL\n",
                       pFilePath ? pFilePath : "(null)");
    return NULL;
}

// ---------------------------------------------------------------------------
// HostServices print-handler install (names inherited from the Ghidra pass)
// ---------------------------------------------------------------------------

// Logs the raw format string and returns 0. The binary forwards ONLY pFmt to
// jk_logtofile@0x402cc0 and drops the varargs (quirk preserved — arguments
// are never expanded). Note: mapped to stdPlatform_Printf; printing via
// "%s" rather than vfprintf-with-missing-args keeps the dropped-varargs
// behavior without the UB. @449530
extern "C" int dwImage_NullMethodLog(const char* pFmt, ...)
{
    stdPlatform_Printf("%s", pFmt);
    return 0;
}

// Despite the (inherited Ghidra) name, this installs dwImage_NullMethodLog as
// the five HostServices print handlers (offsets +0x04..+0x14 = messagePrint,
// statusPrint, warningPrint, errorPrint, debugPrint). Called once by the DW
// boot (StartOpeningCutscenes) right after std_Startup(&dw_hostServices).
// @449500
extern "C" void dwImage_InitNullVtable(HostServices* pHS)
{
    pHS->messagePrint = dwImage_NullMethodLog;
    pHS->statusPrint = dwImage_NullMethodLog;
    pHS->warningPrint = dwImage_NullMethodLog;
    pHS->errorPrint = dwImage_NullMethodLog;
    pHS->debugPrint = dwImage_NullMethodLog;
}

// ---------------------------------------------------------------------------
// Added: C FFI shims (not in the binary — C callers used the vtable directly)
// ---------------------------------------------------------------------------

extern "C" void dwImage_CallBlit(dwImage* pImage, dwImageBits* pDestBits, int x, int y, dwRect* pClipRect)
{
    pImage->Blit(pDestBits, x, y, pClipRect);
}

extern "C" void dwImage_CallBlitColorMap(dwImage* pImage, dwImageBits* pDestBits, int x, int y, dwRect* pClipRect)
{
    pImage->BlitColorMap(pDestBits, x, y, pClipRect);
}

extern "C" int dwImage_CallLock(dwImage* pImage, void** ppPixels, int* pStride)
{
    return pImage->Lock(ppPixels, pStride);
}

extern "C" int dwImage_CallUnlock(dwImage* pImage)
{
    return pImage->Unlock();
}

// The binary's scalar-deleting-dtor call: vtbl +0x00 with flags = 1.
extern "C" void dwImage_Delete(dwImage* pImage)
{
    delete pImage;
}
