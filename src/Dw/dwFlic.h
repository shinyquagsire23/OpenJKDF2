#ifndef _DWFLIC_H
#define _DWFLIC_H

// dwFlic — DroidWorks Autodesk FLC/FLI animation decoder (used by the dwAnim
// widget player and the dwFlicSeg full-screen segments).
//
// Ghidra (DroidWorks.exe) unit 0x413c20-0x414e5f; the flic code proper is:
//   dwFlic_Open@0x413cd0          dwFlic_Close@0x413d70
//   dwFlic_DecodeFrame@0x413d90
// plus the file-local chunk handlers (static in dwFlic.c):
//   dwFlic_ChunkColor256@0x413f80  dwFlic_ChunkColor64@0x414060
//   dwFlic_ChunkDeltaSS2@0x414160  dwFlic_ChunkDeltaLC@0x414640
//   dwFlic_ChunkBlack@0x414900     dwFlic_ChunkBrun@0x414930
//   dwFlic_ChunkCopy@0x414b80
// (0x413c20-0x413c9x is dwGuiFindEntry — re-attributed to dwGuiFind — and
// 0x414c20-0x414e50 is dw-core static ctor/dtor glue; neither lives here.)
//
// The decoder is standalone: all state lives in a caller-owned dwFlic
// context (embedded in dwFlicSeg / stack-local in dwAnim_EnsureLoaded), so
// this module has no statics and needs no _Startup reset hook. File I/O
// goes through dwMain_pHS (the DW VFS resolves bare .FLC names).

#include "Dw/dwTypes.h"

// Genuinely-C unit (cdecl context-pointer procedures in the binary; no
// vtable/ctor/EH); guarded for inclusion from the C++ DW units.
#ifdef __cplusplus
extern "C" {
#endif

// Destination (or overlay-source) pixel descriptor for dwFlic_DecodeFrame.
// In the binary this is an untyped 0xc-byte blob the callers assemble on the
// stack from a locked dwImage: {locked 8bpp pixel base, width, height,
// bytes-per-row}. Layout must match the chunk decoders' field offsets
// (pPixels@0x00, width@0x04, height@0x06, rowStride@0x08 in the original).
typedef struct dwFlicBits
{
    uint8_t* pPixels;   // 0x00 top-left of the locked 8bpp surface
    int16_t width;      // 0x04 in pixels
    int16_t height;     // 0x06 in rows
    int32_t rowStride;  // 0x08 bytes per row
} dwFlicBits;

// FLC/FLI decode context, 0x39e bytes in the binary. The first 0x80 bytes
// are the raw little-endian FLIC main header (read in one fileRead), the
// frame header (0x10 bytes) and sub-chunk header (6 bytes) are also read
// straight into their fields, so the byte layout of those three regions is
// load-bearing (all fields sit on natural boundaries; no packing needed).
// Note: on 64-bit builds pFile widens, shifting curFrame/palette past their
// original 0x9a/0x9e offsets — harmless, nothing reads them from disk.
typedef struct dwFlic
{
    // FLIC main header (0x80 bytes, raw from the file)
    uint32_t fileSize;         // 0x00
    uint16_t type;             // 0x04 0xAF12=FLC, 0xAF11=FLI (forces 320x200)
    uint16_t numFrames;        // 0x06
    uint16_t width;            // 0x08
    uint16_t height;           // 0x0a
    uint16_t depth;            // 0x0c bits per pixel (always 8)
    uint16_t flags;            // 0x0e
    uint32_t speed;            // 0x10 frame delay: ms (FLC) / jiffies (FLI)
    uint8_t aReserved1[0x3c];  // 0x14 created/creator/updated/aspect/...
    uint32_t oframe1;          // 0x50 file offset of frame 1 (FLC only)
    uint8_t aReserved2[0x2c];  // 0x54
    // current FRAME header (0x10 bytes, read per frame)
    uint32_t frameSize;        // 0x80
    uint16_t frameType;        // 0x84 0xF1FA
    uint16_t numSubChunks;     // 0x86
    uint8_t aFramePad[8];      // 0x88 reserved part of the frame header
    // current sub-chunk header (6 bytes, read per chunk)
    uint32_t chunkSize;        // 0x90
    uint16_t chunkType;        // 0x94
    // decoder state
    void* pFile;               // 0x96 dwMain_pHS file handle
    int32_t curFrame;          // 0x9a frames decoded so far
    uint8_t palette[768];      // 0x9e RGB888, updated in place by COLOR chunks
} dwFlic;

// @0x413cd0 — open pFilename ("rb" via dwMain_pHS, so the DW VFS/GOB shim
// applies), read the 0x80-byte main header, seek to the first frame (FLC) or
// force 320x200 (FLI). Quirks kept from the binary: ALWAYS returns 0, even
// on open failure or unknown type (callers cannot detect failure); on an
// unknown type the file is closed but pFile is left dangling (non-NULL).
int dwFlic_Open(dwFlic* pThis, const char* pFilename);

// @0x413d70 — close the file if open. pFile is not cleared (as original).
void dwFlic_Close(dwFlic* pThis);

// @0x413d90 — decode the next frame into pTarget (8bpp). Returns 0xFFFF when
// all frames have been decoded, 1 on a non-0xF1FA frame header (file position
// is NOT restored in that case — original behavior), 0 on success. Palette
// chunks update pThis->palette even when pTarget is NULL (the caller pushes
// it to the display palette itself); pixel chunks are skipped when pTarget
// is NULL. pOverlay (optional) enables transparent compositing: pixels that
// decode to 0 take the byte at the same position in pOverlay instead.
int dwFlic_DecodeFrame(dwFlic* pThis, dwFlicBits* pTarget, dwFlicBits* pOverlay);

#ifdef __cplusplus
}
#endif

#endif // _DWFLIC_H
