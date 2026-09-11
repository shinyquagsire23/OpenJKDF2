// stdBitmapRle2 — DroidWorks engine-side BMP/RLE image loader + image classes.
//
// Decompiled from DroidWorks.exe. See stdBitmapRle2.h for the address map and
// the exported C loader API. This unit provides the two concrete dwImage
// subclasses the loaders return:
//
//   stdBitmapRle2 (vtbl 0x520140, struct 0x18) — an UNCOMPRESSED image: a flat
//     4-byte-aligned pixel buffer. Overrides Lock/Unlock (+ dtor); inherits the
//     shared dwImage base Blit/BlitColorMap (@0x448d60/@0x448e40).
//
//   stdBitmapRle (vtbl 0x5201b8, struct 0x10) — a LAZY-DECODE RLE8 image: it
//     keeps the raw BI_RLE8 byte stream and decodes it straight into the
//     destination on every Blit/BlitColorMap. Its binary vtable has only THREE
//     slots (dtor/Blit/BlitColorMap) — it is never Lock'd, so Lock/Unlock are
//     inert stubs added here to satisfy the abstract dwImage base (see note).
//
// Compiled as C++ (both classes carry vtable dispatch + MSVC EH frames in the
// binary; the loaders inline `operator new` + the ctors).

#include "Dw/stdBitmapRle2.h"
#include "Dw/dwImage.h"
#include "Dw/dwImageVBuf.h"
#include "Dw/dwString.h"
#include "Dw/dwRect.h"

#include "stdPlatform.h"

// Win95/stdDisplay.h + generated globals.h have no extern "C" guards of their
// own — wrap at include site. globals.h provides rdColormap_pCurMap and
// stdDisplay_pCurVideoMode.
extern "C" {
#include "Win95/stdDisplay.h"
#include "globals.h"
}

// The DW host-services pointer (file I/O + alloc/free), set in dwMain_Startup.
extern "C" HostServices* dwMain_pHS;

// ===========================================================================
// stdBitmapRle2 — uncompressed image (vtbl 0x520140, struct 0x18)
// ===========================================================================

// binary /DW struct stdBitmapRle2, size 0x18:
//   0x00 vptr (aliases dwImageDesc.format — see dwImage.h layout quirk)
//   0x04 width / 0x06 height / 0x08 bpp (bytes)   [= the dwImage base fields]
//   0x0c lockCount
//   0x10 pPixels
//   0x14 stride
struct stdBitmapRle2 : dwImage
{
    int32_t lockCount; // 0x0c: incremented by Lock, decremented by Unlock
    void* pPixels;     // 0x10: owned pixel buffer
    int32_t stride;    // 0x14: bytes per row (4-byte aligned)

    stdBitmapRle2(uint16_t width, uint16_t height, uint8_t bppBits); // @442df0 (Ctor)
    stdBitmapRle2(dwImage* pSrc, dwRect* pRect);                     // @442ec0 (ToVBuffer)
    virtual ~stdBitmapRle2();                                        // @442ea0/@442fd0
    virtual int Lock(void** ppPixels, int* pStride);                 // vtbl +0x0c @443030
    virtual int Unlock();                                            // vtbl +0x10 @443070
};

// Construct an empty width x height image at bppBits (8 or 16). @442df0
stdBitmapRle2::stdBitmapRle2(uint16_t width, uint16_t height, uint8_t bppBits)
{
    uint8_t bppBytes = (uint8_t)(bppBits >> 3);
    this->desc.width = width;
    this->desc.height = height;
    this->desc.bpp = bppBytes;
    this->lockCount = 0;
    this->pPixels = NULL;
    unsigned int stride = ((unsigned int)width * bppBytes + 3) & 0xfffffffc;
    this->stride = (int32_t)stride;
    unsigned int size = (unsigned int)height * stride;
    this->pPixels = dwMain_pHS->alloc(size);
    // Zero the buffer (binary: dword loop + byte tail; the tail count is always
    // 0 here since size is 4-aligned).
    if (this->pPixels)
    {
        uint32_t* p = (uint32_t*)this->pPixels;
        for (unsigned int n = size >> 2; n != 0; n--)
            *p++ = 0;
    }
}

// Construct a width x height copy of pRect's region of pSrc (a flat blit of the
// source image at the source's bpp). pRect = {left,top,right,bottom}. @442ec0
stdBitmapRle2::stdBitmapRle2(dwImage* pSrc, dwRect* pRect)
{
    uint8_t bppBytes = (uint8_t)(pSrc->desc.bpp & 0x1f);
    uint16_t width = (uint16_t)(pRect->right - pRect->left);
    uint16_t height = (uint16_t)(pRect->bottom - pRect->top);
    this->desc.width = width;
    this->desc.height = height;
    this->desc.bpp = bppBytes;
    this->lockCount = 0;
    this->pPixels = NULL;
    unsigned int stride = ((unsigned int)bppBytes * width + 3) & 0xfffffffc;
    this->stride = (int32_t)stride;
    unsigned int size = (unsigned int)height * stride;
    this->pPixels = dwMain_pHS->alloc(size);
    if (this->pPixels)
    {
        uint32_t* p = (uint32_t*)this->pPixels;
        for (unsigned int n = size >> 2; n != 0; n--)
            *p++ = 0;

        // Lock self and have the source draw itself in at (-left, -top).
        dwImageBits destBits;
        destBits.pDesc = &this->desc; // binary: (dwImageDesc*)this
        destBits.pPixels = NULL;
        destBits.stride = 0;
        this->Lock(&destBits.pPixels, &destBits.stride);
        pSrc->Blit(&destBits, -(int)pRect->left, -(int)pRect->top, NULL);
        this->Unlock();
    }
}

// Free the pixel buffer (binary: stdBitmapRle2_Dtor2 @442fd0; the base dtor
// then re-points the vptr — the compiler does that here). @442ea0
stdBitmapRle2::~stdBitmapRle2()
{
    if (this->pPixels)
        dwMain_pHS->free(this->pPixels);
}

// Hand out the pixel pointer + stride and bump the lock count. If the stride is
// negative (bottom-up storage) the pixel pointer is repositioned to the last
// row — never happens here (stride is always positive), preserved for fidelity.
// @443030
int stdBitmapRle2::Lock(void** ppPixels, int* pStride)
{
    this->lockCount++;
    *ppPixels = this->pPixels;
    *pStride = this->stride;
    if (this->stride < 0)
        *ppPixels = (uint8_t*)this->pPixels - (int)(this->desc.height - 1) * this->stride;
    return 1;
}

// Release a lock (decrement the count). @443070
int stdBitmapRle2::Unlock()
{
    this->lockCount--;
    return 1;
}

// ===========================================================================
// stdBitmapRle — lazy-decode RLE8 image (vtbl 0x5201b8, struct 0x10)
// ===========================================================================

// The RLE8 decoders write straight into the destination's locked pixel buffer.
// pDest = dwImageBits {pDesc, pPixels, stride}; pDstExtent supplies the draw
// origin (left) + starting scanline (bottom-1, BMP rows are bottom-up);
// pSrcExtent is the clip region {left,top,right,bottom}.
//
// BI_RLE8 encoding: a (count,value) pair fills `count` bytes with `value`; a
// (0,code) escape means 0=EOL, 1=EOB, 2=delta (dx,dy), 3+=absolute run of
// `code` literal bytes (word-aligned). Both decoders treat pixel value 0 as
// transparent.

// Real 8bpp decode WITHOUT colormap blend (plain copy; 0 = transparent).
// @4498f0 (Ghidra: RLE_decompress_type1)
static void RLE_decompress_type1(dwImageBits* pDest, uint8_t* pData,
                                 dwRect* pDstExtent, dwRect* pSrcExtent)
{
    short dstLeft = pDstExtent->left;
    short clipRight = pSrcExtent->right;
    short clipTop = pSrcExtent->top;
    short clipLeft = pSrcExtent->left;
    short clipBottom = pSrcExtent->bottom;
    short row = (short)(pDstExtent->bottom - 1);
    short curX = dstLeft;

    while (clipTop <= row)
    {
        uint16_t count = (uint16_t)*pData;
        if (count == 0)
        {
            uint16_t code = (uint16_t)pData[1];
            int codeI = (int)(short)code;
            uint8_t* pOp = pData + 2;
            if (codeI == 0) // EOL
            {
                row = (short)(row - 1);
                curX = pDstExtent->left;
                pData = pOp;
            }
            else if (codeI == 1) // EOB
            {
                row = (short)(clipTop - 1); // forces loop exit
                pData = pOp;
            }
            else if (codeI == 2) // delta (dx, dy)
            {
                curX = (short)(curX + (uint16_t)pData[2]);
                row = (short)(row - (uint16_t)pData[3]);
                pData = pData + 4;
            }
            else // absolute run of `code` literal bytes
            {
                count = code;
                if (row < clipBottom)
                {
                    short sVar2 = curX;
                    if (curX < clipLeft)
                    {
                        sVar2 = (short)(clipLeft - curX);
                        if (sVar2 < (short)count)
                        {
                            pOp += sVar2;
                            count = (uint16_t)(count - sVar2);
                            sVar2 = clipLeft;
                        }
                        else
                        {
                            sVar2 = (short)(curX + count);
                            pOp += codeI;
                            count = 0;
                        }
                    }
                    if (clipRight <= sVar2)
                    {
                        sVar2 = (short)(sVar2 + count);
                        pOp += (short)count;
                        count = 0;
                    }
                    curX = sVar2;
                    if ((short)count > 0)
                    {
                        curX = (short)(count + sVar2);
                        short trailing = 0;
                        uint16_t run = count;
                        if (clipRight <= curX)
                        {
                            run = (uint16_t)(clipRight - sVar2);
                            trailing = (short)(count - run);
                        }
                        uint8_t* pDst = (uint8_t*)pDest->pPixels + pDest->stride * (int)row + (int)sVar2;
                        if (run != 0)
                        {
                            int n = (short)(run - 1) + 1;
                            do
                            {
                                if (*pOp != 0)
                                    *pDst = *pOp;
                                pDst++;
                                pOp++;
                                n--;
                            } while (n != 0);
                        }
                        pOp += trailing;
                    }
                }
                else
                {
                    pOp += codeI;
                    curX = (short)(curX + count);
                }
                if (((uintptr_t)pOp & 1) != 0) // word-align
                    pOp++;
                pData = pOp;
            }
        }
        else // encoded run (count, value)
        {
            uint8_t value = pData[1];
            uint8_t* pOp = pData + 2;
            if (row < clipBottom && value != 0)
            {
                short sVar2 = curX;
                if (curX < clipLeft)
                {
                    if ((short)(clipLeft - curX) < (short)count)
                    {
                        count = (uint16_t)(count - (clipLeft - curX));
                        sVar2 = clipLeft;
                    }
                    else
                    {
                        sVar2 = (short)(curX + count);
                        count = 0;
                    }
                }
                if (clipRight <= sVar2)
                {
                    sVar2 = (short)(sVar2 + count);
                    count = 0;
                }
                curX = sVar2;
                if ((short)count > 0)
                {
                    curX = (short)(count + sVar2);
                    if (clipRight <= curX)
                        count = (uint16_t)(clipRight - sVar2);
                    if (count != 0)
                    {
                        unsigned int n = (unsigned int)(int)(short)(count - 1) + 1;
                        uint8_t* pDst = (uint8_t*)pDest->pPixels + pDest->stride * (int)row + (int)sVar2;
                        uint32_t fill = (uint32_t)value * 0x01010101u;
                        for (unsigned int w = n >> 2; w != 0; w--)
                        {
                            *(uint32_t*)pDst = fill;
                            pDst += 4;
                        }
                        for (unsigned int t = n & 3; t != 0; t--)
                            *pDst++ = value;
                    }
                }
            }
            else
            {
                curX = (short)(curX + count);
            }
            pData = pOp;
        }
    }
}

// 8bpp decode WITH colormap blend: dest = transparencyTable[dest*256 + src]
// for src != 0. The table is the current engine colormap's 256x256 transparency
// table (binary: *(DAT_005542b8 + 0x338) = rdColormap_pCurMap->transparency).
// @449bf0 (Ghidra: stdBitmapRle_sub_449BF0)
static void RLE_decompress_type1_colormap(dwImageBits* pDest, uint8_t* pData,
                                          dwRect* pDstExtent, dwRect* pSrcExtent)
{
    uint8_t* pTable = (uint8_t*)rdColormap_pCurMap->transparency;
    short clipRight = pSrcExtent->right;
    short clipTop = pSrcExtent->top;
    short clipLeft = pSrcExtent->left;
    short clipBottom = pSrcExtent->bottom;
    short row = (short)(pDstExtent->bottom - 1);
    short curX = pDstExtent->left;

    while (clipTop <= row)
    {
        uint16_t count = (uint16_t)*pData;
        if (count == 0)
        {
            uint16_t code = (uint16_t)pData[1];
            int codeI = (int)(short)code;
            uint8_t* pOp = pData + 2;
            if (codeI == 0) // EOL
            {
                row = (short)(row - 1);
                curX = pDstExtent->left;
                pData = pOp;
            }
            else if (codeI == 1) // EOB
            {
                row = (short)(clipTop - 1);
                pData = pOp;
            }
            else if (codeI == 2) // delta
            {
                curX = (short)(curX + (uint16_t)pData[2]);
                row = (short)(row - (uint16_t)pData[3]);
                pData = pData + 4;
            }
            else // absolute run
            {
                count = code;
                if (row < clipBottom)
                {
                    short sVar6 = curX;
                    if (curX < clipLeft)
                    {
                        sVar6 = (short)(clipLeft - curX);
                        if (sVar6 < (short)count)
                        {
                            pOp += sVar6;
                            count = (uint16_t)(count - sVar6);
                            sVar6 = clipLeft;
                        }
                        else
                        {
                            sVar6 = (short)(curX + count);
                            pOp += codeI;
                            count = 0;
                        }
                    }
                    if (clipRight <= sVar6)
                    {
                        sVar6 = (short)(sVar6 + count);
                        pOp += (short)count;
                        count = 0;
                    }
                    curX = sVar6;
                    if ((short)count > 0)
                    {
                        curX = (short)(count + sVar6);
                        short trailing = 0;
                        uint16_t run = count;
                        if (clipRight <= curX)
                        {
                            run = (uint16_t)(clipRight - sVar6);
                            trailing = (short)(count - run);
                        }
                        uint8_t* pDst = (uint8_t*)pDest->pPixels + pDest->stride * (int)row + (int)sVar6;
                        if (run != 0)
                        {
                            int n = (short)(run - 1) + 1;
                            do
                            {
                                uint8_t src = *pOp++;
                                if (src != 0)
                                    *pDst = pTable[(unsigned int)*pDst * 0x100 + src];
                                pDst++;
                                n--;
                            } while (n != 0);
                        }
                        pOp += trailing;
                    }
                }
                else
                {
                    pOp += codeI;
                    curX = (short)(curX + count);
                }
                if (((uintptr_t)pOp & 1) != 0)
                    pOp++;
                pData = pOp;
            }
        }
        else // encoded run (count, value)
        {
            uint8_t value = pData[1];
            uint8_t* pOp = pData + 2;
            if (row < clipBottom && value != 0)
            {
                short sVar6 = curX;
                if (curX < clipLeft)
                {
                    if ((short)(clipLeft - curX) < (short)count)
                    {
                        count = (uint16_t)(count - (clipLeft - curX));
                        sVar6 = clipLeft;
                    }
                    else
                    {
                        sVar6 = (short)(curX + count);
                        count = 0;
                    }
                }
                if (clipRight <= sVar6)
                {
                    sVar6 = (short)(sVar6 + count);
                    count = 0;
                }
                curX = sVar6;
                if ((short)count > 0)
                {
                    curX = (short)(count + sVar6);
                    if (clipRight <= curX)
                        count = (uint16_t)(clipRight - sVar6);
                    if (count != 0)
                    {
                        int n = (short)(count - 1) + 1;
                        uint8_t* pDst = (uint8_t*)pDest->pPixels + pDest->stride * (int)row + (int)sVar6;
                        do
                        {
                            *pDst = pTable[(unsigned int)*pDst * 0x100 + value];
                            pDst++;
                            n--;
                        } while (n != 0);
                    }
                }
            }
            else
            {
                curX = (short)(curX + count);
            }
            pData = pOp;
        }
    }
}

// The src-16bpp RLE decode path — an EMPTY stub in the binary (a lone RET; the
// 16bpp RLE decode was never implemented). @449180 (Ghidra: RLE_decompress_type2)
static void RLE_decompress_type2(dwImageBits* pDest, uint8_t* pData,
                                 dwRect* pDstExtent, dwRect* pSrcExtent)
{
    (void)pDest; (void)pData; (void)pDstExtent; (void)pSrcExtent;
}

// binary /DW struct stdBitmapRle, size 0x10:
//   0x00 vptr / 0x04 width / 0x06 height / 0x08 bpp (=1) / 0x0c pRleData
struct stdBitmapRle : dwImage
{
    void* pRleData; // 0x0c: owned raw BI_RLE8 byte stream

    stdBitmapRle(int16_t width, int16_t height, void* pRleData);       // @449750 (InstFormat1)
    virtual ~stdBitmapRle();                                           // @449780/@4497a0
    virtual void Blit(dwImageBits* pDestBits, int x, int y, dwRect* pClipRect);         // vtbl +0x04 @449800
    virtual void BlitColorMap(dwImageBits* pDestBits, int x, int y, dwRect* pClipRect); // vtbl +0x08 @449b00
    // Note: the binary's stdBitmapRle vtable has ONLY 3 slots (dtor/Blit/
    // BlitColorMap) — this class is never Lock'd (it decodes on Blit). These
    // inert overrides exist only to make the class concrete against the
    // abstract dwImage base; they are never invoked.
    virtual int Lock(void** ppPixels, int* pStride);                   // (not in binary vtable)
    virtual int Unlock();                                              // (not in binary vtable)
};

// Construct from a raw RLE stream (bpp fixed at 1 = 8bpp). @449750
stdBitmapRle::stdBitmapRle(int16_t width, int16_t height, void* pRleData)
{
    this->desc.width = (uint16_t)width;
    this->desc.height = (uint16_t)height;
    this->desc.bpp = 1;
    this->pRleData = pRleData;
}

// Free the RLE stream (binary frees via rdroid_pHS->free — the same underlying
// HostServices as dwMain_pHS in DW). @4497a0
stdBitmapRle::~stdBitmapRle()
{
    if (this->pRleData)
        dwMain_pHS->free(this->pRleData);
}

// Decode the RLE stream into pDestBits at (x, y), clipped to the destination
// bounds intersected with pClipRect. @449800
void stdBitmapRle::Blit(dwImageBits* pDestBits, int x, int y, dwRect* pClipRect)
{
    dwRect dstExtent;
    dstExtent.left = (int16_t)x;
    dstExtent.top = (int16_t)y;
    dstExtent.right = (int16_t)(this->desc.width + x);
    dstExtent.bottom = (int16_t)(this->desc.height + y);

    dwRect clip;
    clip.left = 0;
    clip.top = 0;
    clip.right = (int16_t)pDestBits->pDesc->width;
    clip.bottom = (int16_t)pDestBits->pDesc->height;
    dwRect_Clip(&clip, &dstExtent);
    if (pClipRect)
        dwRect_Clip(&clip, pClipRect);

    if (clip.right == clip.left || clip.bottom == clip.top)
        return;

    uint8_t destBpp = pDestBits->pDesc->bpp;
    if (destBpp == 1)
        RLE_decompress_type1(pDestBits, (uint8_t*)this->pRleData, &dstExtent, &clip);
    else if (destBpp == 2)
        RLE_decompress_type2(pDestBits, (uint8_t*)this->pRleData, &dstExtent, &clip);
}

// Same as Blit but blends through the current colormap's transparency table
// (8bpp path). @449b00
void stdBitmapRle::BlitColorMap(dwImageBits* pDestBits, int x, int y, dwRect* pClipRect)
{
    dwRect dstExtent;
    dstExtent.left = (int16_t)x;
    dstExtent.top = (int16_t)y;
    dstExtent.right = (int16_t)(this->desc.width + x);
    dstExtent.bottom = (int16_t)(this->desc.height + y);

    dwRect clip;
    clip.left = 0;
    clip.top = 0;
    clip.right = (int16_t)pDestBits->pDesc->width;
    clip.bottom = (int16_t)pDestBits->pDesc->height;
    dwRect_Clip(&clip, &dstExtent);
    if (pClipRect)
        dwRect_Clip(&clip, pClipRect);

    if (clip.right == clip.left || clip.bottom == clip.top)
        return;

    // Binary: (pDest->pDesc->bpp << 3) == 8 -> colormap decode; == 0x10 -> the
    // (empty) 16bpp path.
    uint8_t destBits = (uint8_t)(pDestBits->pDesc->bpp << 3);
    if (destBits == 8)
        RLE_decompress_type1_colormap(pDestBits, (uint8_t*)this->pRleData, &dstExtent, &clip);
    else if (destBits == 0x10)
        RLE_decompress_type2(pDestBits, (uint8_t*)this->pRleData, &dstExtent, &clip);
}

// Inert (see class note): a compressed image cannot be Lock'd.
int stdBitmapRle::Lock(void** ppPixels, int* pStride)
{
    if (ppPixels) *ppPixels = NULL;
    if (pStride) *pStride = 0;
    return 0;
}

int stdBitmapRle::Unlock()
{
    return 0;
}

// ===========================================================================
// BMP / RLE file loaders
// ===========================================================================

// The 40-byte BITMAPINFOHEADER, read raw from the file. Field offsets are the
// BMP-spec offsets the binary indexes (biWidth@4, biHeight@8, biPlanes@0xc,
// biBitCount@0xe, biCompression@0x10, biSizeImage@0x14). Desktop is
// little-endian, matching the file byte order (src/Dw is desktop-only).
#pragma pack(push, 1)
typedef struct BmpInfoHeader
{
    uint32_t biSize;        // 0x00
    int32_t  biWidth;       // 0x04
    int32_t  biHeight;      // 0x08
    uint16_t biPlanes;      // 0x0c
    uint16_t biBitCount;    // 0x0e
    uint32_t biCompression; // 0x10
    uint32_t biSizeImage;   // 0x14
    int32_t  biXPelsPerM;   // 0x18
    int32_t  biYPelsPerM;   // 0x1c
    uint32_t biClrUsed;     // 0x20
    uint32_t biClrImportant;// 0x24
} BmpInfoHeader;
#pragma pack(pop)

// Read `sizeImage` raw RLE bytes and wrap them in a lazy-decode stdBitmapRle.
// @444ba0 (Ghidra: stdBitmapRle_LoadFormat1)
static dwImage* stdBitmapRle_LoadFormat1(stdFile_t fp, BmpInfoHeader* pInfo)
{
    dwImage* pResult = NULL;
    void* pData = dwMain_pHS->alloc(pInfo->biSizeImage);
    if (pData)
    {
        size_t nRead = dwMain_pHS->fileRead(fp, pData, pInfo->biSizeImage);
        if (nRead == pInfo->biSizeImage)
        {
            pResult = new stdBitmapRle((int16_t)pInfo->biWidth, (int16_t)pInfo->biHeight, pData);
        }
        if (pResult == NULL)
            dwMain_pHS->free(pData);
    }
    return pResult;
}

// Load an uncompressed (BI_RGB) BMP body into a flat stdBitmapRle2. When the
// file is really BI_RLE8 but the caller forced decompression, it loads the RLE
// image then flattens it via stdBitmapRle2(pSrc, {0,0,w,h}). @444a30
static dwImage* stdBitmapRle_LoadFormat0(stdFile_t fp, BmpInfoHeader* pInfo)
{
    dwImage* pResult = NULL;
    if (pInfo->biCompression == 0)
    {
        stdBitmapRle2* pBmp = new stdBitmapRle2((uint16_t)pInfo->biWidth, (uint16_t)pInfo->biHeight, 8);
        pResult = pBmp;
        if (pResult)
        {
            void* pPixels = NULL;
            int stride = 0;
            pBmp->Lock(&pPixels, &stride);
            int height = (int)pBmp->desc.height;
            // BMP rows are stored bottom-up and each is padded to 4 bytes.
            unsigned int rowBytes = ((unsigned int)pInfo->biWidth + 3) & 0xfffffffc;
            uint8_t* pRow = (uint8_t*)pPixels + (height - 1) * stride;
            while (height != 0)
            {
                size_t nRead = dwMain_pHS->fileRead(fp, pRow, rowBytes);
                pRow -= stride;
                height--;
                if (height == 0 || nRead != rowBytes)
                    break;
            }
            pBmp->Unlock();
        }
    }
    else if (pInfo->biCompression == 1)
    {
        dwImage* pRle = stdBitmapRle_LoadFormat1(fp, pInfo);
        if (pRle)
        {
            dwRect rect;
            rect.left = 0;
            rect.top = 0;
            rect.right = (int16_t)pRle->desc.width;
            rect.bottom = (int16_t)pRle->desc.height;
            pResult = new stdBitmapRle2(pRle, &rect);
            dwImage_Delete(pRle); // free the temporary RLE source
        }
    }
    return pResult;
}

// Open pFilePath, validate the BITMAPFILEHEADER + BITMAPINFOHEADER (8bpp only),
// seek to the pixel data and dispatch by compression. bForceDecompress forces a
// BI_RLE8 file down the flat LoadFormat0 path. @4448f0 (stdBitmapRle_LoadEntry)
static dwImage* stdBitmapRle_LoadEntry(char* pFilePath, int bForceDecompress)
{
    dwImage* pResult = NULL;
    stdFile_t fp = dwMain_pHS->fileOpen(pFilePath, "rb");
    if (fp == 0)
    {
        stdPlatform_Printf("File not found: %s\n", pFilePath); // binary: jk_logtofile
        return NULL;
    }

    // 14-byte BITMAPFILEHEADER.
    uint16_t bfType = 0;
    uint32_t bfSize = 0;
    uint16_t bfReserved[2] = { 0, 0 };
    uint32_t bfOffBits = 0;
    size_t nHdr = 0;
    nHdr += dwMain_pHS->fileRead(fp, &bfType, 2);
    nHdr += dwMain_pHS->fileRead(fp, &bfSize, 4);
    nHdr += dwMain_pHS->fileRead(fp, bfReserved, 4);
    nHdr += dwMain_pHS->fileRead(fp, &bfOffBits, 4);

    BmpInfoHeader info;
    size_t nInfo = dwMain_pHS->fileRead(fp, &info, 0x28);

    const char* pErr = NULL;
    if (nHdr + nInfo == 0x36 && bfType == 0x4d42 && info.biSize == 0x28)
    {
        if (info.biPlanes == 1 && info.biBitCount == 8)
        {
            if (dwMain_pHS->fseek(fp, (int)bfOffBits, 0) == 0)
            {
                if (info.biSizeImage == 0)
                    info.biSizeImage = bfSize - bfOffBits;
                if (info.biCompression == 0 || bForceDecompress != 0)
                    pResult = stdBitmapRle_LoadFormat0(fp, &info);
                else if (info.biCompression == 1)
                    pResult = stdBitmapRle_LoadFormat1(fp, &info);
                else
                    pErr = "Compressed BMP files of this format not supported: %s\n";
            }
            else
            {
                pErr = "Seek error reading file %s\n";
            }
        }
        else
        {
            pErr = "Non-8bpp images not supported: %s\n";
        }
    }
    else
    {
        pErr = "File corrupt or incorrect type: %s\n";
    }
    if (pErr)
        stdPlatform_Printf(pErr, pFilePath); // binary: jk_logtofile

    dwMain_pHS->fileClose(fp);
    return pResult;
}

// 8bpp image file loader. @444850
extern "C" dwImage* loads_bmp(char* pFilePath, int bForceDecompress)
{
    if (pFilePath == NULL)
        return NULL;
    if (*pFilePath == '\0')
        return NULL;

    dwImage* pResult = NULL;
    char* pExt = pFilePath;
    dwString_FindExtension(&pExt);
    if (*pExt == '\0')
    {
        stdPlatform_Printf("Image file has no extension: %s\n", pFilePath); // binary: jk_logtofile
    }
    else
    {
        pExt++; // skip the '.'
        if (dwString_Equals(pExt, "BMP") || dwString_Equals(pExt, "RLE"))
            pResult = stdBitmapRle_LoadEntry(pFilePath, bForceDecompress);
        else
            stdPlatform_Printf("Unknown image file type: %s\n", pFilePath); // binary: jk_logtofile
    }

    if (pResult == NULL)
        stdPlatform_Printf("Error opening image: %s\n", pFilePath); // binary: jk_logtofile
    return pResult;
}

// >8bpp-display image loader. @444c50 (Ghidra: stdBitmapRle_FUN_00444c50)
extern "C" dwImage* stdBitmapRle2_LoadFile16(char* pFilePath)
{
    // Binary reads the display depth from DAT_006b17e4 (tRasterInfo @0x6b17cc);
    // in the repo that is stdDisplay_pCurVideoMode->format.format.bpp. A NULL
    // video mode is treated as the 8bpp path (DW's default software display).
    int displayBpp = stdDisplay_pCurVideoMode ? (int)stdDisplay_pCurVideoMode->format.format.bpp : 8;
    if (displayBpp < 9)
        return loads_bmp(pFilePath, 1);

    dwImage* pSrc = loads_bmp(pFilePath, 0);
    if (pSrc)
    {
        dwImage* pResult = dwImageVBuf_NewFromImage(pSrc, (uint8_t)displayBpp);
        dwImage_Delete(pSrc); // free the temporary 8bpp image
        return pResult;
    }
    return NULL;
}

// ===========================================================================
// stdBitmapRle2 C factories (binary: callers inlined operator new + the ctor)
// ===========================================================================

extern "C" dwImage* stdBitmapRle2_Instantiate(int16_t width, int16_t height, int bpp)
{
    return new stdBitmapRle2((uint16_t)width, (uint16_t)height, (uint8_t)bpp);
}

extern "C" dwImage* stdBitmapRle2_InstantiateCopy(dwImage* pSrc, int16_t width, int16_t height)
{
    dwRect rect;
    rect.left = 0;
    rect.top = 0;
    rect.right = width;
    rect.bottom = height;
    return new stdBitmapRle2(pSrc, &rect);
}
