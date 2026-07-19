// codec47 (INSANE-era SMUSH video) — derived 2026-07-18 from DroidWorks.exe's
// SMUSH cluster via Ghidra (see codec47.h for the source-function map and the
// frame layout). All offsets/semantics verified against the binary's
// disassembly; the tables are lifted from the binary's .rdata.

#include "codec47.h"

#include <stddef.h> // ptrdiff_t
#include <stdlib.h>
#include <string.h>

// ---------------------------------------------------------------------------
// Tables lifted from DroidWorks.exe
// ---------------------------------------------------------------------------

// @0x529980: 255 (x, y) motion-vector pairs; materialized per frame width as
// motion[i] = y * pitch + x (smushFrame_sub_43EEC0). Identical to the first
// 255 pairs of codec48.c's table — same LucasArts codec family.
static const int16_t codec47_motion_pairs[255][2] = {
    0,    0,   -1,  -43,    6,  -43,   -9,  -42,   13,  -41,
  -16,  -40,   19,  -39,  -23,  -36,   26,  -34,   -2,  -33,
    4,  -33,  -29,  -32,   -9,  -32,   11,  -31,  -16,  -29,
   32,  -29,   18,  -28,  -34,  -26,  -22,  -25,   -1,  -25,
    3,  -25,   -7,  -24,    8,  -24,   24,  -23,   36,  -23,
  -12,  -22,   13,  -21,  -38,  -20,    0,  -20,  -27,  -19,
   -4,  -19,    4,  -19,  -17,  -18,   -8,  -17,    8,  -17,
   18,  -17,   28,  -17,   39,  -17,  -12,  -15,   12,  -15,
  -21,  -14,   -1,  -14,    1,  -14,  -41,  -13,   -5,  -13,
    5,  -13,   21,  -13,  -31,  -12,  -15,  -11,   -8,  -11,
    8,  -11,   15,  -11,   -2,  -10,    1,  -10,   31,  -10,
  -23,   -9,  -11,   -9,   -5,   -9,    4,   -9,   11,   -9,
   42,   -9,    6,   -8,   24,   -8,  -18,   -7,   -7,   -7,
   -3,   -7,   -1,   -7,    2,   -7,   18,   -7,  -43,   -6,
  -13,   -6,   -4,   -6,    4,   -6,    8,   -6,  -33,   -5,
   -9,   -5,   -2,   -5,    0,   -5,    2,   -5,    5,   -5,
   13,   -5,  -25,   -4,   -6,   -4,   -3,   -4,    3,   -4,
    9,   -4,  -19,   -3,   -7,   -3,   -4,   -3,   -2,   -3,
   -1,   -3,    0,   -3,    1,   -3,    2,   -3,    4,   -3,
    6,   -3,   33,   -3,  -14,   -2,  -10,   -2,   -5,   -2,
   -3,   -2,   -2,   -2,   -1,   -2,    0,   -2,    1,   -2,
    2,   -2,    3,   -2,    5,   -2,    7,   -2,   14,   -2,
   19,   -2,   25,   -2,   43,   -2,   -7,   -1,   -3,   -1,
   -2,   -1,   -1,   -1,    0,   -1,    1,   -1,    2,   -1,
    3,   -1,   10,   -1,   -5,    0,   -3,    0,   -2,    0,
   -1,    0,    1,    0,    2,    0,    3,    0,    5,    0,
    7,    0,  -10,    1,   -7,    1,   -3,    1,   -2,    1,
   -1,    1,    0,    1,    1,    1,    2,    1,    3,    1,
  -43,    2,  -25,    2,  -19,    2,  -14,    2,   -5,    2,
   -3,    2,   -2,    2,   -1,    2,    0,    2,    1,    2,
    2,    2,    3,    2,    5,    2,    7,    2,   10,    2,
   14,    2,  -33,    3,   -6,    3,   -4,    3,   -2,    3,
   -1,    3,    0,    3,    1,    3,    2,    3,    4,    3,
   19,    3,   -9,    4,   -3,    4,    3,    4,    7,    4,
   25,    4,  -13,    5,   -5,    5,   -2,    5,    0,    5,
    2,    5,    5,    5,    9,    5,   33,    5,   -8,    6,
   -4,    6,    4,    6,   13,    6,   43,    6,  -18,    7,
   -2,    7,    0,    7,    2,    7,    7,    7,   18,    7,
  -24,    8,   -6,    8,  -42,    9,  -11,    9,   -4,    9,
    5,    9,   11,    9,   23,    9,  -31,   10,   -1,   10,
    2,   10,  -15,   11,   -8,   11,    8,   11,   15,   11,
   31,   12,  -21,   13,   -5,   13,    5,   13,   41,   13,
   -1,   14,    1,   14,   21,   14,  -12,   15,   12,   15,
  -39,   17,  -28,   17,  -18,   17,   -8,   17,    8,   17,
   17,   18,   -4,   19,    0,   19,    4,   19,   27,   19,
   38,   20,  -13,   21,   12,   22,  -36,   23,  -24,   23,
   -8,   24,    7,   24,   -3,   25,    1,   25,   22,   25,
   34,   26,  -18,   28,  -32,   29,   16,   29,  -11,   31,
    9,   32,   29,   32,   -4,   33,    2,   33,  -26,   34,
   23,   36,  -19,   39,   16,   40,  -13,   41,    9,   42,
   -6,   43,    1,   43,    0,    0,    0,    0,    0,    0
};

// Corner tables driving the glyph builder (smushFrame_sub_43F040): per size,
// two 16-entry int16 tables. The (i, j) glyph sweeps a line across the block
// between the i- and j-side endpoints; which side of the line is "covered"
// is decided by the endpoint classifications (see codec47_build_glyphs).
static const int16_t codec47_corners4_a[16] = // @0x529d80 (cols)
    { 0, 1, 2, 3, 3, 3, 3, 2, 1, 0, 0, 0, 1, 2, 2, 1 };
static const int16_t codec47_corners4_b[16] = // @0x529da0 (rows)
    { 0, 0, 0, 0, 1, 2, 3, 3, 3, 3, 2, 1, 1, 1, 2, 2 };
static const int16_t codec47_corners8_a[16] = // @0x529dc0 (cols)
    { 0, 2, 5, 7, 7, 7, 7, 7, 7, 5, 2, 0, 0, 0, 0, 0 };
static const int16_t codec47_corners8_b[16] = // @0x529de0 (rows)
    { 0, 0, 0, 0, 1, 3, 4, 6, 7, 7, 7, 7, 6, 4, 3, 1 };

// Fill directions, from the binary's decision tree (ci = classification of
// the i endpoint, cj of the j endpoint — 0: B==0, 1: B==size-1, 2: A==0,
// 3: A==size-1, 4: A mid). UP/DOWN fill the covered column to the top/bottom
// block edge, LEFT/RIGHT the covered row to the left/right edge; NEXT = line
// only, no fill.
enum
{
    C47_FILL_NEXT = 0,
    C47_FILL_UP,
    C47_FILL_DOWN,
    C47_FILL_LEFT,
    C47_FILL_RIGHT
};

static const uint8_t codec47_fill_dir[5][5] = {
    // cj:   0(B)           1(T)            2(L)             3(R)             4(N)
    /* 0 B */ { C47_FILL_UP,    C47_FILL_RIGHT, C47_FILL_UP,    C47_FILL_UP,    C47_FILL_UP    },
    /* 1 T */ { C47_FILL_RIGHT, C47_FILL_DOWN,  C47_FILL_DOWN,  C47_FILL_DOWN,  C47_FILL_DOWN  },
    /* 2 L */ { C47_FILL_UP,    C47_FILL_DOWN,  C47_FILL_LEFT,  C47_FILL_UP,    C47_FILL_LEFT  },
    /* 3 R */ { C47_FILL_UP,    C47_FILL_DOWN,  C47_FILL_UP,    C47_FILL_RIGHT, C47_FILL_RIGHT },
    /* 4 N */ { C47_FILL_UP,    C47_FILL_DOWN,  C47_FILL_LEFT,  C47_FILL_RIGHT, C47_FILL_NEXT  }
};

// ---------------------------------------------------------------------------
// Glyph-table builder (smushFrame_sub_43F040)
// ---------------------------------------------------------------------------

// Classify one endpoint: 0 if b == 0, 1 if b == size-1, 2 if a == 0,
// 3 if a == size-1, else 4.
static int codec47_classify(int16_t a, int16_t b, int size)
{
    if (b == 0)
        return 0;
    if (b == size - 1)
        return 1;
    if (a == 0)
        return 2;
    return (a != size - 1) ? 4 : 3;
}

static void codec47_build_glyphs(codec47_glyph* out, const int16_t* cornersA,
                                 const int16_t* cornersB, int size)
{
    // For each (i, j): sweep a line from (B[i], A[i]) to (B[j], A[j]) across
    // the block (B = row endpoints, A = col endpoints); mark the line pixels,
    // then fill each marked pixel toward the block edge chosen by the
    // endpoint classifications. Pixels under the swept region end up in run 0,
    // the rest in run 1 (both recorded bottom-right to top-left).
    uint32_t grid[64];
    int gi = 0;

    memset(out, 0, sizeof(codec47_glyph) * 256);

    for (int i = 0; i < 16; i++)
    {
        for (int j = 0; j < 16; j++, gi++)
        {
            int ci = codec47_classify(cornersA[i], cornersB[i], size);
            int cj = codec47_classify(cornersA[j], cornersB[j], size);
            int dir = codec47_fill_dir[ci][cj];

            int di = cornersA[i] - cornersA[j];
            if (di < 0)
                di = -di;
            int dj = cornersB[i] - cornersB[j];
            if (dj < 0)
                dj = -dj;
            int steps = (dj < di ? di : dj) + 1;

            memset(grid, 0, sizeof(grid));

            int accR = 0; // k * B[i]
            int accC = 0; // k * A[i]
            for (int k = 0; k < steps; k++)
            {
                int row = cornersB[i];
                int col = cornersA[i];
                if (steps > 1)
                {
                    int m = steps - 1;
                    int rem = m - k;
                    row = (cornersB[j] * rem + accR + (m >> 1)) / m;
                    col = (cornersA[j] * rem + accC + (m >> 1)) / m;
                }

                if (row >= 0 && row < size && col >= 0 && col < size)
                    grid[row * size + col] = 1;

                // The binary fills unconditionally (negative edge coords just
                // skip the fill); the line pixel itself is only set when
                // in-bounds (the interpolation can overshoot by one).
                switch (dir)
                {
                case C47_FILL_UP:
                    for (int r = row; r >= 0; r--)
                        if (col >= 0 && col < size)
                            grid[r * size + col] = 1;
                    break;
                case C47_FILL_DOWN:
                    for (int r = row; r < size; r++)
                        if (col >= 0 && col < size)
                            grid[r * size + col] = 1;
                    break;
                case C47_FILL_LEFT:
                    for (int c = col; c >= 0; c--)
                        if (row >= 0 && row < size)
                            grid[row * size + c] = 1;
                    break;
                case C47_FILL_RIGHT:
                    for (int c = col; c < size; c++)
                        if (row >= 0 && row < size)
                            grid[row * size + c] = 1;
                    break;
                default:
                    break;
                }

                accR += cornersB[i];
                accC += cornersA[i];
            }

            // Record runs, bottom-right (size*size-1) to top-left (0).
            codec47_glyph* g = &out[gi];
            for (int p = size * size - 1; p >= 0; p--)
            {
                int run = grid[p] ? 0 : 1;
                g->idx[run][g->count[run]++] = (uint8_t)p;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Per-width materializer (smushFrame_sub_43EEC0): scale the motion offsets and
// convert the glyph pixel indices to frame-pitch offsets.
// ---------------------------------------------------------------------------

static void codec47_materialize(codec47_ctx* ctx, int width)
{
    if (ctx->materialized_width == width)
        return;
    ctx->materialized_width = width;

    for (int i = 0; i < 255; i++)
        ctx->motion[i] = codec47_motion_pairs[i][1] * width + codec47_motion_pairs[i][0];

    for (int gi = 0; gi < 256; gi++)
    {
        codec47_glyph* g8 = &ctx->big[gi];
        for (int run = 0; run < 2; run++)
            for (int k = 0; k < g8->count[run]; k++)
                g8->offs[run][k] = (g8->idx[run][k] >> 3) * width + (g8->idx[run][k] & 7);

        codec47_glyph* g4 = &ctx->small[gi];
        for (int run = 0; run < 2; run++)
            for (int k = 0; k < g4->count[run]; k++)
                g4->offs[run][k] = (g4->idx[run][k] >> 2) * width + (g4->idx[run][k] & 3);
    }
}

// ---------------------------------------------------------------------------
// Block decoders (smushCodec_sub_4416C0 / 441C60 / 442250)
//
// All take the decode context + a dst pointer into bufA and advance the shared
// opcode stream. Opcodes (per block size):
//   0x00-0xF7: copy the block from bufB at (dst + motion[op])
//   0xF8-0xFB: fill with the frame's 4 palette colors (colors[op - 0xF8])
//   0xFC:      copy the block from bufC at the same position
//   0xFD:      glyph splat (8x8/4x4 only): [glyph, color0, color1]
//   0xFE:      fill with a literal color byte
//   0xFF:      subdivide (4x4->2x2 with per-quadrant opcodes; 2x2 = 4 raw pixels)
// ---------------------------------------------------------------------------

typedef struct codec47_dec
{
    codec47_ctx* ctx;
    const uint8_t* stream;
    const uint8_t* colors; // the frame's 4 palette colors (opcodes 0xF8-0xFB)
    ptrdiff_t bufB_off;    // bufB - bufA (motion copies read dst + bufB_off)
    ptrdiff_t bufC_off;    // bufC - bufA (0xFC copies read dst + bufC_off)
} codec47_dec;

static void codec47_block2(codec47_dec* dec, uint8_t* dst)
{
    codec47_ctx* ctx = dec->ctx;
    int pitch = (int)ctx->pitch;
    uint8_t op = *dec->stream++;

    switch (op)
    {
    case 0xF8:
    case 0xF9:
    case 0xFA:
    case 0xFB:
    {
        uint8_t c = dec->colors[op - 0xF8];
        dst[0] = c;
        dst[1] = c;
        dst[pitch] = c;
        dst[pitch + 1] = c;
        break;
    }
    case 0xFC:
        memcpy(dst, dst + dec->bufC_off, 2);
        memcpy(dst + pitch, dst + dec->bufC_off + pitch, 2);
        break;
    case 0xFE:
    {
        uint8_t c = *dec->stream++;
        dst[0] = c;
        dst[1] = c;
        dst[pitch] = c;
        dst[pitch + 1] = c;
        break;
    }
    case 0xFF: // four literal pixels
        dst[0] = dec->stream[0];
        dst[1] = dec->stream[1];
        dst[pitch] = dec->stream[2];
        dst[pitch + 1] = dec->stream[3];
        dec->stream += 4;
        break;
    default: // motion copy from bufB
    {
        const uint8_t* src = dst + dec->bufB_off + ctx->motion[op];
        memcpy(dst, src, 2);
        memcpy(dst + pitch, src + pitch, 2);
        break;
    }
    }
}

static void codec47_block4(codec47_dec* dec, uint8_t* dst)
{
    codec47_ctx* ctx = dec->ctx;
    int pitch = (int)ctx->pitch;
    uint8_t op = *dec->stream++;

    switch (op)
    {
    case 0xF8:
    case 0xF9:
    case 0xFA:
    case 0xFB:
    {
        uint8_t c = dec->colors[op - 0xF8];
        for (int r = 0; r < 4; r++)
            memset(dst + r * pitch, c, 4);
        break;
    }
    case 0xFC:
        for (int r = 0; r < 4; r++)
            memcpy(dst + r * pitch, dst + dec->bufC_off + r * pitch, 4);
        break;
    case 0xFD: // glyph splat
    {
        uint8_t gi = dec->stream[0];
        uint8_t color0 = dec->stream[1];
        uint8_t color1 = dec->stream[2];
        dec->stream += 3;
        const codec47_glyph* g = &ctx->small[gi];
        for (int k = 0; k < g->count[0]; k++)
            dst[g->offs[0][k]] = color0;
        for (int k = 0; k < g->count[1]; k++)
            dst[g->offs[1][k]] = color1;
        break;
    }
    case 0xFE:
    {
        uint8_t c = *dec->stream++;
        for (int r = 0; r < 4; r++)
            memset(dst + r * pitch, c, 4);
        break;
    }
    case 0xFF: // four 2x2 quadrants, one opcode each
        codec47_block2(dec, dst);
        codec47_block2(dec, dst + 2);
        codec47_block2(dec, dst + 2 * pitch);
        codec47_block2(dec, dst + 2 * pitch + 2);
        break;
    default: // motion copy from bufB
    {
        const uint8_t* src = dst + dec->bufB_off + ctx->motion[op];
        for (int r = 0; r < 4; r++)
            memcpy(dst + r * pitch, src + r * pitch, 4);
        break;
    }
    }
}

static void codec47_decode_blocks(codec47_dec* dec)
{
    codec47_ctx* ctx = dec->ctx;
    int pitch = (int)ctx->pitch;
    uint8_t* dst = ctx->bufA;

    // Walk the frame in 8x8 blocks. Band advance matches the binary
    // (8 * pitch - (width & ~7)); right/bottom edges overhang into the guard
    // rows when the size isn't a multiple of 8.
    for (uint32_t y = 0; y < ctx->height; y += 8)
    {
        for (uint32_t x = 0; x < ctx->width; x += 8)
        {
            uint8_t op = *dec->stream++;

            switch (op)
            {
            case 0xF8:
            case 0xF9:
            case 0xFA:
            case 0xFB:
            {
                uint8_t c = dec->colors[op - 0xF8];
                for (int r = 0; r < 8; r++)
                    memset(dst + r * pitch, c, 8);
                break;
            }
            case 0xFC:
                for (int r = 0; r < 8; r++)
                    memcpy(dst + r * pitch, dst + dec->bufC_off + r * pitch, 8);
                break;
            case 0xFD: // glyph splat
            {
                uint8_t gi = dec->stream[0];
                uint8_t color0 = dec->stream[1];
                uint8_t color1 = dec->stream[2];
                dec->stream += 3;
                const codec47_glyph* g = &ctx->big[gi];
                for (int k = 0; k < g->count[0]; k++)
                    dst[g->offs[0][k]] = color0;
                for (int k = 0; k < g->count[1]; k++)
                    dst[g->offs[1][k]] = color1;
                break;
            }
            case 0xFE:
            {
                uint8_t c = *dec->stream++;
                for (int r = 0; r < 8; r++)
                    memset(dst + r * pitch, c, 8);
                break;
            }
            case 0xFF: // four 4x4 quadrants, one opcode each
                codec47_block4(dec, dst);
                codec47_block4(dec, dst + 4);
                codec47_block4(dec, dst + 4 * pitch);
                codec47_block4(dec, dst + 4 * pitch + 4);
                break;
            default: // motion copy from bufB
            {
                const uint8_t* src = dst + dec->bufB_off + ctx->motion[op];
                for (int r = 0; r < 8; r++)
                    memcpy(dst + r * pitch, src + r * pitch, 8);
                break;
            }
            }

            dst += 8;
        }
        dst += 8 * pitch - (ctx->width & ~7U);
    }
}

// ---------------------------------------------------------------------------
// PackBits RLE (smushCodec_sub_441560): opcode byte b -> run of (b>>1)+1;
// b&1 = repeat next byte, else copy that many literal bytes. Stops after
// `size` output bytes.
// ---------------------------------------------------------------------------

static void codec47_rle_decode(uint8_t* dst, const uint8_t* src, int32_t size)
{
    while (size > 0)
    {
        uint8_t op = *src++;
        int32_t count = (op >> 1) + 1;
        if (count > size)
            count = size;
        if (op & 1)
        {
            memset(dst, *src++, count);
        }
        else
        {
            memcpy(dst, src, count);
            src += count;
        }
        dst += count;
        size -= count;
    }
}

// ---------------------------------------------------------------------------
// Frame driver (smushFrame_sub_43F5A0)
// ---------------------------------------------------------------------------

void codec47_destroy(smush_ctx* parent_ctx)
{
    if (!parent_ctx)
        return;
    codec47_ctx* ctx = parent_ctx->c47_ctx;
    if (!ctx)
        return;

    free(ctx->bufs);
    free(ctx);
    parent_ctx->c47_ctx = NULL;
}

void codec47_proc(smush_ctx* parent_ctx, const uint8_t* data, size_t data_len)
{
    codec47_ctx* ctx = parent_ctx->c47_ctx;
    uint32_t w = parent_ctx->codec_w;
    uint32_t h = parent_ctx->codec_h;
    (void)data_len;

    if (!ctx)
    {
        ctx = (codec47_ctx*)malloc(sizeof(codec47_ctx));
        if (!ctx)
            return;
        memset(ctx, 0, sizeof(*ctx));
        parent_ctx->c47_ctx = ctx;

        ctx->width = w;
        ctx->height = h;
        ctx->pitch = w;
        ctx->buf_size = (h + 2 * C47_GUARD_ROWS) * ctx->pitch;
        ctx->bufs = (uint8_t*)malloc(ctx->buf_size * 3);
        if (!ctx->bufs)
        {
            free(ctx);
            parent_ctx->c47_ctx = NULL;
            return;
        }
        memset(ctx->bufs, 0, ctx->buf_size * 3);
        // Three slots of buf_size each; every frame region sits behind its
        // own top guard rows (motion copies can reach +/-43 rows).
        ctx->bufA = ctx->bufs + 0 * ctx->buf_size + C47_GUARD_ROWS * ctx->pitch;
        ctx->bufB = ctx->bufs + 1 * ctx->buf_size + C47_GUARD_ROWS * ctx->pitch;
        ctx->bufC = ctx->bufs + 2 * ctx->buf_size + C47_GUARD_ROWS * ctx->pitch;
        ctx->last_seq = -1;

        codec47_build_glyphs(ctx->big, codec47_corners8_a, codec47_corners8_b, 8);
        codec47_build_glyphs(ctx->small, codec47_corners4_a, codec47_corners4_b, 4);
        ctx->glyphs_built = 1;
    }

    if (ctx->width != w || ctx->height != h)
    {
        // Note: DW content is uniformly 640x480; resize defensively.
        ctx->width = w;
        ctx->height = h;
        ctx->pitch = w;
        ctx->buf_size = (h + 2 * C47_GUARD_ROWS) * ctx->pitch;
        uint8_t* nbuf = (uint8_t*)realloc(ctx->bufs, ctx->buf_size * 3);
        if (!nbuf)
            return;
        ctx->bufs = nbuf;
        memset(ctx->bufs, 0, ctx->buf_size * 3);
        ctx->bufA = ctx->bufs + 0 * ctx->buf_size + C47_GUARD_ROWS * ctx->pitch;
        ctx->bufB = ctx->bufs + 1 * ctx->buf_size + C47_GUARD_ROWS * ctx->pitch;
        ctx->bufC = ctx->bufs + 2 * ctx->buf_size + C47_GUARD_ROWS * ctx->pitch;
        ctx->last_seq = -1;
    }

    uint16_t seq = getle16(data + 0x00);
    uint8_t type = data[0x02];
    uint8_t rotate = data[0x03];
    uint8_t flags = data[0x04];
    const uint8_t* colors = data + 0x08;
    uint8_t fill_c = data[0x0C];
    uint8_t fill_b = data[0x0D];
    uint32_t rle_size = getle32(data + 0x0E);
    const uint8_t* stream = data + 0x1A;

    smush_debug("  Codec 47: seq %u type %u rotate %u flags 0x%x (%ux%u)\n",
                seq, type, rotate, flags, w, h);

    if (seq == 0)
    {
        // First frame: (re)materialize the width-scaled tables and prefill
        // both history buffers (binary: smushFrame_sub_43EEC0 + the fills).
        // Fill from each buffer's slot start (frame base minus the guard rows).
        codec47_materialize(ctx, (int)w);
        memset(ctx->bufC - C47_GUARD_ROWS * ctx->pitch, fill_c, ctx->buf_size);
        memset(ctx->bufB - C47_GUARD_ROWS * ctx->pitch, fill_b, ctx->buf_size);
        ctx->last_seq = -1;
    }

    if ((flags & 1) != 0)
    {
        // Interpolation-table rebuild: 0x8080 triangular-stream bytes filling
        // the symmetric 256x256 table (types 0/5 carry this; feeds type 1).
        for (int i = 0; i < 256; i++)
        {
            for (int k = 0; k < 256 - i; k++)
            {
                uint8_t v = *stream++;
                ctx->xlat[i * 256 + (i + k)] = v;
                ctx->xlat[(i + k) * 256 + i] = v;
            }
        }
    }

    switch (type)
    {
    case 0: // raw frame
        memcpy(ctx->bufA, stream, (size_t)w * h);
        break;
    case 1: // xlat predictor — UNUSED by DroidWorks content (verified across
            // the whole Movie/ set); loud like codec48.c's block-5 todo.
        smush_warn("codec47: type-1 (xlat predictor) frame not implemented (seq %u)\n", seq);
        break;
    case 2: // block codec; the binary decodes only in-sequence frames
        if ((int32_t)seq == ctx->last_seq + 1)
        {
            codec47_dec dec;
            dec.ctx = ctx;
            dec.stream = stream;
            dec.colors = colors;
            dec.bufB_off = ctx->bufB - ctx->bufA;
            dec.bufC_off = ctx->bufC - ctx->bufA;
            codec47_decode_blocks(&dec);
        }
        break;
    case 3: // copy the previous frame
        memcpy(ctx->bufA, ctx->bufB, (size_t)w * h);
        break;
    case 4: // copy the older frame
        memcpy(ctx->bufA, ctx->bufC, (size_t)w * h);
        break;
    case 5: // PackBits RLE
        codec47_rle_decode(ctx->bufA, stream, (int32_t)rle_size);
        break;
    default:
        smush_warn("codec47: unknown frame type %u (seq %u)\n", type, seq);
        break;
    }

    // Present BEFORE the rotation (binary order): the current buffer as it
    // stands after the decode is what hits the screen; the rotation then
    // sets up the history buffers for the NEXT frame. (Getting this order
    // wrong plays every rotated frame one position late.)
    memcpy(parent_ctx->framebuffer, ctx->bufA, (size_t)w * h);

    // Buffer rotation (smushFrame_sub_43F5A0 tail), in-sequence frames only.
    if ((int32_t)seq == ctx->last_seq + 1)
    {
        if (rotate == 1) // swap A <-> B
        {
            uint8_t* tmp = ctx->bufA;
            ctx->bufA = ctx->bufB;
            ctx->bufB = tmp;
        }
        else if (rotate == 2) // cycle A->B->C->A
        {
            uint8_t* tmp = ctx->bufC;
            ctx->bufC = ctx->bufB;
            ctx->bufB = ctx->bufA;
            ctx->bufA = tmp;
        }
    }
    ctx->last_seq = (int32_t)seq;
}
