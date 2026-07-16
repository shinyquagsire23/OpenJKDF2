#ifndef _DWIMAGE_H
#define _DWIMAGE_H

// dwImage — the shared DroidWorks image/blit BASE class.
//
// Decompiled from DroidWorks.exe, unit range 0x448d60-0x449530 (the blit
// cluster, mis-binned into the dwFont row in the original compile-unit map)
// plus the dwImage_LoadFile dispatcher @0x444820.
//
// The binary's image hierarchy is a 6-slot vtable contract shared by TWO
// concrete classes: stdBitmapRle2 (engine-side RLE bitmap, vtbl 0x520140 —
// NOT translated here) and dwImageVBuf (tVBuffer-backed, vtbl 0x5201a0, see
// dwImageVBuf.h). Both vtables point at the SAME code for the two blit slots:
//   +0x00 scalar-deleting dtor    (per-class)
//   +0x04 Blit         @0x448d60  (SHARED base implementation)
//   +0x08 BlitColorMap @0x448e40  (SHARED base implementation)
//   +0x0c Lock                    (per-class)
//   +0x10 Unlock                  (per-class)
//   +0x14 NULL in both vtables    (never called; no method translated)
// The naked base-class vtable also exists in the binary @0x520158 (its dtor
// @0x4430a0 was emitted in the stdBitmapRle2 unit; the dwImageVBuf dtor
// re-points the vptr at it while unwinding).
//
// Blit semantics (proven from the 0x448d60 disassembly + the
// dwImageVBuf_CtorFromImage caller): `this` is the SOURCE image;
// pImage->Blit(pDestBits, x, y, pClipRect) draws the whole image into the
// already-locked destination bits at (x, y), clipped to the destination
// bounds intersected with pClipRect. The source pixels are obtained by
// locking `this` (vtbl +0x0c) around the row loop.
//
// LAYOUT QUIRK: in the 32-bit binary the image OBJECT doubles as its own
// dwImageDesc — the vptr @0x00 aliases desc.format, and width/height/bpp sit
// at +0x04/+0x06/+0x08, exactly the dwImageDesc field offsets. The blit code
// exploits this by using `(dwImageDesc*)this` as dwImageBits::pDesc. A 64-bit
// vptr breaks that alias, so this translation carries an explicit `desc`
// member instead and uses `&this->desc` where the binary cast `this`.

#include "Dw/dwTypes.h"
#include "Dw/dwRect.h"

// ---- Plain-C structs (shared with the C units) ----------------------------

// Image pixel-format descriptor (binary /DW struct dwImageDesc, size 0xa).
typedef struct dwImageDesc
{
    int32_t format;  // 0x00: in the binary this dword is the object's vptr
                     //       when the desc is an aliased image object; unused
                     //       (0) in the translation.
    uint16_t width;  // 0x04
    uint16_t height; // 0x06
    uint8_t bpp;     // 0x08: BYTES per pixel (1 = 8bpp, 2 = 16bpp)
} dwImageDesc;

// A locked pixel view of an image (binary /DW struct dwImageBits, size 0xc).
typedef struct dwImageBits
{
    dwImageDesc* pDesc; // 0x00
    void* pPixels;      // 0x04: top-left pixel of the locked surface
    int32_t stride;     // 0x08: bytes per row
} dwImageBits;

#ifdef __cplusplus

// ---- C++ class (verifiably C++ in the binary: vtables + MSVC EH frames) ----

struct dwImage
{
    dwImageDesc desc; // width/height/bpp of this image (see layout quirk above)

    dwImage();
    virtual ~dwImage();                                                          // vtbl +0x00 (base vtbl @0x520158, base dtor @0x4430a0)
    virtual void Blit(dwImageBits* pDestBits, int x, int y, dwRect* pClipRect);         // vtbl +0x04 @448d60 (shared impl)
    virtual void BlitColorMap(dwImageBits* pDestBits, int x, int y, dwRect* pClipRect); // vtbl +0x08 @448e40 (shared impl)
    // Lock fills *ppPixels/*pStride for this image's surface (NULL/0 on
    // failure) and returns nonzero on success. Unlock releases it.
    virtual int Lock(void** ppPixels, int* pStride) = 0;                         // vtbl +0x0c
    virtual int Unlock() = 0;                                                    // vtbl +0x10
    // vtbl +0x14 is NULL in both concrete vtables — intentionally untranslated.
}; // binary sizeof 0x0c (vptr + width/height/bpp)

#else // !__cplusplus

typedef struct dwImage dwImage; // opaque in the C view

#endif // __cplusplus

#ifdef __cplusplus
extern "C" {
#endif

// Loads an image file (.BMP/.RLE) and returns a heap image object, or NULL.
// Binary dispatch: display bpp > 8 -> stdBitmapRle_FUN_00444c50 (16bpp RLE
// loader), else loads_bmp(pFilePath, 0). Both loaders live in the
// NOT-YET-TRANSLATED stdBitmapRle2 engine-side unit, so this is currently a
// LOUD STUB returning NULL — see dwImage.cpp. TODO(dw-decomp).
dwImage* dwImage_LoadFile(char* pFilePath); // @444820

// Color-key-0 row blit between two locked pixel views (skips source bytes of
// 0 in the 8bpp path; the 16bpp path is a plain copy — binary quirk). The
// only in-binary external caller is the dwCompleteMovie frame draw @0x41112a.
void dwImage_BlitRowsTransparent(dwImageBits* pSrcBits, dwImageBits* pDestBits, int x, int y, dwRect* pClipRect); // @449370

// Despite the (inherited Ghidra) name, this installs dwImage_NullMethodLog as
// the five HostServices print handlers (+0x04..+0x14: messagePrint,
// statusPrint, warningPrint, errorPrint, debugPrint). Called once by the DW
// WinMain boot (StartOpeningCutscenes) right after std_Startup.
void dwImage_InitNullVtable(HostServices* pHS); // @449500

// The installed print handler: logs the raw format string (the binary
// forwards only pFmt to jk_logtofile and DROPS the varargs) and returns 0.
int dwImage_NullMethodLog(const char* pFmt, ...); // @449530

// Added: C FFI shims for the virtual methods — the C units (dwCursor/
// dwDisplay/dwMain) called these through the vtable in the binary. Each shim
// just virtual-dispatches on pImage. dwImage_Delete is the binary's
// scalar-deleting dtor call (vtbl +0x00 with flags=1).
void dwImage_CallBlit(dwImage* pImage, dwImageBits* pDestBits, int x, int y, dwRect* pClipRect);
void dwImage_CallBlitColorMap(dwImage* pImage, dwImageBits* pDestBits, int x, int y, dwRect* pClipRect);
int dwImage_CallLock(dwImage* pImage, void** ppPixels, int* pStride);
int dwImage_CallUnlock(dwImage* pImage);
void dwImage_Delete(dwImage* pImage);

#ifdef __cplusplus
}
#endif

#endif // _DWIMAGE_H
