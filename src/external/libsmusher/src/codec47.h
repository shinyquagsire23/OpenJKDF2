#ifndef _LIBSMUSHER_CODEC47_H
#define _LIBSMUSHER_CODEC47_H

#include "smush.h"

// codec47 (INSANE-era SMUSH video) — derived 2026-07-18 from DroidWorks.exe's
// SMUSH cluster via Ghidra so DroidWorks' .san movies (all codec 47, 640x480)
// decode. MIT like the rest of libsmusher. Sources:
//   smushFrame_sub_43F5A0  — FOBJ frame driver (header parse, dispatch,
//                            xlat rebuild, buffer rotation)
//   smushCodec_sub_4416C0  — 8x8 block decoder (opcode engine)
//   smushCodec_sub_441C60  — 4x4 block decoder
//   smushCodec_sub_442250  — 2x2 block decoder
//   smushFrame_sub_43F040  — glyph-table builder (corner-table driven)
//   smushFrame_sub_43EEC0  — per-width table materializer (motion + glyphs)
//   smushCodec_sub_441560  — PackBits RLE (type 5)
//   smushCodec_sub_441600  — type-1 xlat predictor (UNUSED by DW content — LOUD todo)
// Data tables lifted from the binary: 255 motion pairs @0x529980, the 4 corner
// tables @0x529d80/0x529da0 (4x4) and 0x529dc0/0x529de0 (8x8).
//
// Codec47 frame layout (data passed here = FOBJ payload at +0x0E):
//   +0x00 le16 sequence number
//   +0x02 u8 frame type: 0 raw, 1 xlat predictor, 2 block codec, 3 copy bufB,
//        4 copy bufC, 5 PackBits RLE
//   +0x03 u8 buffer-rotate mode (0 none, 1 swap A<->B, 2 cycle A->B->C)
//   +0x04 u8 flags (bit0: rebuild the 256x256 interpolation table from a
//        0x8080-byte triangular stream before the payload)
//   +0x08 4 palette colors for opcodes 0xF8-0xFB
//   +0x0C fill color for bufC, +0x0D fill color for bufB (applied at seq 0)
//   +0x0E le32 decompressed size (type 5)
//   +0x1A stream: [0x8080 xlat bytes when flags&1] + payload

typedef struct codec47_glyph
{
    uint8_t count[2];     // run lengths: run 0 = covered pixels, run 1 = rest
    uint8_t idx[2][64];   // pixel indices within the block (row * size + col)
    int32_t offs[2][64];  // width-materialized: (idx / size) * pitch + (idx % size)
} codec47_glyph;

typedef struct codec47_ctx
{
    uint32_t width;
    uint32_t height;
    size_t pitch;    // == width (blocks overhang into the guard rows at edges)
    size_t buf_size; // per-buffer allocation ((height + 2 * C47_GUARD_ROWS) * pitch)
    uint8_t* bufs;   // one allocation holding the three frame buffers
    uint8_t* bufA;   // current frame (decode target)
    uint8_t* bufB;   // previous frame (motion-copy source)
    uint8_t* bufC;   // older frame (0xFC copy source)

    int glyphs_built;
    codec47_glyph big[256];   // 8x8 glyphs
    codec47_glyph small[256]; // 4x4 glyphs

    int32_t motion[255];       // width-materialized motion offsets
    int32_t materialized_width; // rebuild latch (binary DAT_00529d7c)

    uint8_t xlat[256 * 256];  // interpolation table (flags&1 frames; type 1)

    int32_t last_seq;         // binary DAT_00529e00
} codec47_ctx;

#define C47_GUARD_ROWS (44)   // covers the +/-43-row motion-table reach

void codec47_destroy(smush_ctx* parent_ctx);
void codec47_proc(smush_ctx* parent_ctx, const uint8_t* data, size_t data_len);

#endif // _LIBSMUSHER_CODEC47_H
