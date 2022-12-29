#include "codec48.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>

void codec48_destroy(smush_ctx* parent_ctx)
{
    if (!parent_ctx) return;
    codec48_ctx* ctx = parent_ctx->c48_ctx;

    free(ctx->delta_bufs);
    free(ctx);

    parent_ctx->c48_ctx = NULL;
}

void codec48_proc(smush_ctx* parent_ctx, const uint8_t* data, size_t data_len)
{
    codec48_hdr* hdr = (codec48_hdr*)data;
    codec48_ctx* ctx = parent_ctx->c48_ctx;

    if (!ctx) {
        ctx = (codec48_ctx*)malloc(sizeof(codec48_ctx));
        memset(ctx, 0, sizeof(*ctx));
        parent_ctx->c48_ctx = ctx;

        ctx->width = parent_ctx->codec_w;
        ctx->height = parent_ctx->codec_h;
        ctx->block_x = (parent_ctx->codec_w + 7) / 8;
        ctx->block_y = (parent_ctx->codec_h + 7) / 8;
        ctx->pitch = ctx->block_x * 8;

        ctx->frame_size = 640*480;
        uint8_t* buf = (uint8_t*)malloc((ctx->frame_size*2) + ctx->pitch);
        memset(buf, 0, (ctx->frame_size*2) + ctx->pitch);
        ctx->delta_bufs = buf;
        ctx->delta_buf[0] = buf + 640;
        ctx->delta_buf[1] = ctx->delta_buf[0] + ctx->frame_size;
    }

    uint16_t seq_num = getle16(hdr->seq_num);
    uint32_t flags = getle32(hdr->flags);
    
    smush_debug("  Codec 48:\n");
    smush_debug("    Type: 0x%02x\n", hdr->type);
    smush_debug("    Table Idx: 0x%02x\n", hdr->table_index);
    smush_debug("    Seq num: 0x%04x\n", seq_num);
    smush_debug("    Unk2: 0x%04x\n", getle32(hdr->unk2));
    smush_debug("    Unk3: 0x%04x\n", getle32(hdr->unk3));
    smush_debug("    Flags: 0x%04x\n", flags);


    codec48_make_table(ctx, hdr->table_index);

    data += sizeof(codec48_hdr);
    data_len -= sizeof(codec48_hdr);

    if (flags & C48_INTERPOLATION_FLAG) {

        uint8_t* pT = ctx->interpolation_table;
        for (int i = 0; i < 256; i++)
        {
            uint8_t* pA = pT + i;
            uint8_t* pB = pT + i;

            for (int j = 256 - i; j > 0; j--) {
                uint8_t val = *data++;
                *pB = val;
                *pA++ = val;
                pB += 256;
            }
            pT += 256;
        }
    }

    if (hdr->type == 0) {
        memcpy(ctx->delta_buf[ctx->cur_buf], data, getle32(hdr->unk2));
    }
    else if (hdr->type == 2) {
        codec48_proc_block2(ctx, data, ctx->width * ctx->height, ctx->delta_buf[ctx->cur_buf]);
    }
    else if (hdr->type == 3) {
        // 8x8 block encoding
        if (!(seq_num && seq_num != ctx->last_seq_num + 1))
        {
            if (seq_num & 1 || !(flags & C48_FLAG_1) || (flags & C48_FLAG_10)) {
                ctx->cur_buf ^= 1;
            }

            codec48_proc_block3(ctx, data, ctx->delta_buf[ctx->cur_buf], ctx->delta_buf[ctx->cur_buf ^ 1] - ctx->delta_buf[ctx->cur_buf]);
        }
    }
    else if (hdr->type == 5) {
        smush_warn("TODO block 5\n");
    }
    else {
        smush_warn("Unknown block type %x\n", hdr->type);
    }

    memcpy(parent_ctx->framebuffer, ctx->delta_buf[ctx->cur_buf], ctx->pitch * ctx->height);

    ctx->last_seq_num = seq_num;
}

void codec48_make_table(codec48_ctx* ctx, int8_t idx)
{
    int32_t strided_idx = idx * 255;
    static const int16_t table[] = {
          0,    0,   -1, -43,   6, -43,  -9, -42,  13, -41,
        -16,  -40,   19, -39, -23, -36,  26, -34,  -2, -33,
          4,  -33,  -29, -32,  -9, -32,  11, -31, -16, -29,
         32,  -29,   18, -28, -34, -26, -22, -25,  -1, -25,
          3,  -25,   -7, -24,   8, -24,  24, -23,  36, -23,
        -12,  -22,   13, -21, -38, -20,   0, -20, -27, -19,
         -4,  -19,    4, -19, -17, -18,  -8, -17,   8, -17,
         18,  -17,   28, -17,  39, -17, -12, -15,  12, -15,
        -21,  -14,   -1, -14,   1, -14, -41, -13,  -5, -13,
          5,  -13,   21, -13, -31, -12, -15, -11,  -8, -11,
          8,  -11,   15, -11,  -2, -10,   1, -10,  31, -10,
        -23,   -9,  -11,  -9,  -5,  -9,   4,  -9,  11,  -9,
         42,   -9,    6,  -8,  24,  -8, -18,  -7,  -7,  -7,
         -3,   -7,   -1,  -7,   2,  -7,  18,  -7, -43,  -6,
        -13,   -6,   -4,  -6,   4,  -6,   8,  -6, -33,  -5,
         -9,   -5,   -2,  -5,   0,  -5,   2,  -5,   5,  -5,
         13,   -5,  -25,  -4,  -6,  -4,  -3,  -4,   3,  -4,
          9,   -4,  -19,  -3,  -7,  -3,  -4,  -3,  -2,  -3,
         -1,   -3,    0,  -3,   1,  -3,   2,  -3,   4,  -3,
          6,   -3,   33,  -3, -14,  -2, -10,  -2,  -5,  -2,
         -3,   -2,   -2,  -2,  -1,  -2,   0,  -2,   1,  -2,
          2,   -2,    3,  -2,   5,  -2,   7,  -2,  14,  -2,
         19,   -2,   25,  -2,  43,  -2,  -7,  -1,  -3,  -1,
         -2,   -1,   -1,  -1,   0,  -1,   1,  -1,   2,  -1,
          3,   -1,   10,  -1,  -5,   0,  -3,   0,  -2,   0,
         -1,    0,    1,   0,   2,   0,   3,   0,   5,   0,
          7,    0,  -10,   1,  -7,   1,  -3,   1,  -2,   1,
         -1,    1,    0,   1,   1,   1,   2,   1,   3,   1,
        -43,    2,  -25,   2, -19,   2, -14,   2,  -5,   2,
         -3,    2,   -2,   2,  -1,   2,   0,   2,   1,   2,
          2,    2,    3,   2,   5,   2,   7,   2,  10,   2,
         14,    2,  -33,   3,  -6,   3,  -4,   3,  -2,   3,
         -1,    3,    0,   3,   1,   3,   2,   3,   4,   3,
         19,    3,   -9,   4,  -3,   4,   3,   4,   7,   4,
         25,    4,  -13,   5,  -5,   5,  -2,   5,   0,   5,
          2,    5,    5,   5,   9,   5,  33,   5,  -8,   6,
         -4,    6,    4,   6,  13,   6,  43,   6, -18,   7,
         -2,    7,    0,   7,   2,   7,   7,   7,  18,   7,
        -24,    8,   -6,   8, -42,   9, -11,   9,  -4,   9,
          5,    9,   11,   9,  23,   9, -31,  10,  -1,  10,
          2,   10,  -15,  11,  -8,  11,   8,  11,  15,  11,
         31,   12,  -21,  13,  -5,  13,   5,  13,  41,  13,
         -1,   14,    1,  14,  21,  14, -12,  15,  12,  15,
        -39,   17,  -28,  17, -18,  17,  -8,  17,   8,  17,
         17,   18,   -4,  19,   0,  19,   4,  19,  27,  19,
         38,   20,  -13,  21,  12,  22, -36,  23, -24,  23,
         -8,   24,    7,  24,  -3,  25,   1,  25,  22,  25,
         34,   26,  -18,  28, -32,  29,  16,  29, -11,  31,
          9,   32,   29,  32,  -4,  33,   2,  33, -26,  34,
         23,   36,  -19,  39,  16,  40, -13,  41,   9,  42,
         -6,   43,    1,  43,   0,   0,   0,   0,   0,   0,
          0,    0,    1,   0,   2,   0,   3,   0,   5,   0,
          8,    0,   13,   0,  21,   0,  -1,   0,  -2,   0,
         -3,    0,   -5,   0,  -8,   0, -13,   0, -17,   0,
        -21,    0,    0,   1,   1,   1,   2,   1,   3,   1,
          5,    1,    8,   1,  13,   1,  21,   1,  -1,   1,
         -2,    1,   -3,   1,  -5,   1,  -8,   1, -13,   1,
        -17,    1,  -21,   1,   0,   2,   1,   2,   2,   2,
          3,    2,    5,   2,   8,   2,  13,   2,  21,   2,
         -1,    2,   -2,   2,  -3,   2,  -5,   2,  -8,   2,
        -13,    2,  -17,   2, -21,   2,   0,   3,   1,   3,
          2,    3,    3,   3,   5,   3,   8,   3,  13,   3,
         21,    3,   -1,   3,  -2,   3,  -3,   3,  -5,   3,
         -8,    3,  -13,   3, -17,   3, -21,   3,   0,   5,
          1,    5,    2,   5,   3,   5,   5,   5,   8,   5,
         13,    5,   21,   5,  -1,   5,  -2,   5,  -3,   5,
         -5,    5,   -8,   5, -13,   5, -17,   5, -21,   5,
          0,    8,    1,   8,   2,   8,   3,   8,   5,   8,
          8,    8,   13,   8,  21,   8,  -1,   8,  -2,   8,
         -3,    8,   -5,   8,  -8,   8, -13,   8, -17,   8,
        -21,    8,    0,  13,   1,  13,   2,  13,   3,  13,
          5,   13,    8,  13,  13,  13,  21,  13,  -1,  13,
         -2,   13,   -3,  13,  -5,  13,  -8,  13, -13,  13,
        -17,   13,  -21,  13,   0,  21,   1,  21,   2,  21,
          3,   21,    5,  21,   8,  21,  13,  21,  21,  21,
         -1,   21,   -2,  21,  -3,  21,  -5,  21,  -8,  21,
        -13,   21,  -17,  21, -21,  21,   0,  -1,   1,  -1,
          2,   -1,    3,  -1,   5,  -1,   8,  -1,  13,  -1,
         21,   -1,   -1,  -1,  -2,  -1,  -3,  -1,  -5,  -1,
         -8,   -1,  -13,  -1, -17,  -1, -21,  -1,   0,  -2,
          1,   -2,    2,  -2,   3,  -2,   5,  -2,   8,  -2,
         13,   -2,   21,  -2,  -1,  -2,  -2,  -2,  -3,  -2,
         -5,   -2,   -8,  -2, -13,  -2, -17,  -2, -21,  -2,
          0,   -3,    1,  -3,   2,  -3,   3,  -3,   5,  -3,
          8,   -3,   13,  -3,  21,  -3,  -1,  -3,  -2,  -3,
         -3,   -3,   -5,  -3,  -8,  -3, -13,  -3, -17,  -3,
        -21,   -3,    0,  -5,   1,  -5,   2,  -5,   3,  -5,
          5,   -5,    8,  -5,  13,  -5,  21,  -5,  -1,  -5,
         -2,   -5,   -3,  -5,  -5,  -5,  -8,  -5, -13,  -5,
        -17,   -5,  -21,  -5,   0,  -8,   1,  -8,   2,  -8,
          3,   -8,    5,  -8,   8,  -8,  13,  -8,  21,  -8,
         -1,   -8,   -2,  -8,  -3,  -8,  -5,  -8,  -8,  -8,
        -13,   -8,  -17,  -8, -21,  -8,   0, -13,   1, -13,
          2,  -13,    3, -13,   5, -13,   8, -13,  13, -13,
         21,  -13,   -1, -13,  -2, -13,  -3, -13,  -5, -13,
         -8,  -13,  -13, -13, -17, -13, -21, -13,   0, -17,
          1,  -17,    2, -17,   3, -17,   5, -17,   8, -17,
         13,  -17,   21, -17,  -1, -17,  -2, -17,  -3, -17,
         -5,  -17,   -8, -17, -13, -17, -17, -17, -21, -17,
          0,  -21,    1, -21,   2, -21,   3, -21,   5, -21,
          8,  -21,   13, -21,  21, -21,  -1, -21,  -2, -21,
         -3,  -21,   -5, -21,  -8, -21, -13, -21, -17, -21
    };

    // Don't recalculate this table if we can avoid it.
    if (ctx->offset_table_pitch == ctx->pitch && ctx->offset_table_index == idx) {
        return;
    }
    ctx->offset_table_pitch = ctx->pitch;
    ctx->offset_table_index = idx;

    assert(strided_idx + 254 < (sizeof(table) / 2));

    for (int32_t i = 0; i < 255; i++) 
    {
        int32_t j = (i + strided_idx) * 2;
        ctx->offset_table[i] = table[j + 1] * ctx->pitch + table[j];
    }
}

void codec48_proc_block2(codec48_ctx* ctx, const uint8_t* data, uint32_t len, uint8_t* out)
{
    while (len > 0)
    {
        uint8_t packed = *data++;
        uint8_t num = (packed >> 1) + 1;

        if (num > len) {
            num = len;
        }

        if (packed & 1) {
            memset(out, *data++, num);
        }
        else {
            memcpy(out, data, num);
            data += num;
        }

        out += num;
        len -= num;
    }
}

void codec48_proc_block3(codec48_ctx* ctx, const uint8_t* data, uint8_t* out, size_t inter_buf_offs)
{
    for (int i = 0; i < ctx->block_y; i++) 
    {
        for (int j = 0; j < ctx->block_x; j++) 
        {
            uint8_t op = *data++;
            
            //printf("%p %p %p %p %p\n", ctx, data, out, &out[7 - (size_t)ctx->pitch], ctx->delta_buf[0]); // (out[7 - ctx->pitch] << 8) | *data
            switch (op) {
                // Interpolate a 4x4 block based on 1 pixel, then scale to 8x8
                case 0xFF: 
                {
                    uint8_t tmp_scale[16] = {0};
                    tmp_scale[15] = *data++;
                    tmp_scale[7] = ctx->interpolation_table[(out[7 - ctx->pitch] << 8) | tmp_scale[15]];
                    tmp_scale[3] = ctx->interpolation_table[(out[7 - ctx->pitch] << 8) | tmp_scale[7]];
                    tmp_scale[11] = ctx->interpolation_table[(tmp_scale[15] << 8) | tmp_scale[7]];

                    tmp_scale[1] = ctx->interpolation_table[(out[-1] << 8) | tmp_scale[3]];
                    tmp_scale[0] = ctx->interpolation_table[(out[-1] << 8) | tmp_scale[1]];
                    tmp_scale[2] = ctx->interpolation_table[(tmp_scale[3] << 8) | tmp_scale[1]];

                    tmp_scale[5] = ctx->interpolation_table[(out[ctx->pitch * 2 - 1] << 8) | tmp_scale[7]];
                    tmp_scale[4] = ctx->interpolation_table[(out[ctx->pitch * 2 - 1] << 8) | tmp_scale[5]];
                    tmp_scale[6] = ctx->interpolation_table[(tmp_scale[7] << 8) | tmp_scale[5]];

                    tmp_scale[9] = ctx->interpolation_table[(out[ctx->pitch * 3 - 1] << 8) | tmp_scale[11]];
                    tmp_scale[8] = ctx->interpolation_table[(out[ctx->pitch * 3 - 1] << 8) | tmp_scale[9]];
                    tmp_scale[10] = ctx->interpolation_table[(tmp_scale[11] << 8) | tmp_scale[9]];

                    tmp_scale[13] = ctx->interpolation_table[(out[ctx->pitch * 4 - 1] << 8) | tmp_scale[15]];
                    tmp_scale[12] = ctx->interpolation_table[(out[ctx->pitch * 4 - 1] << 8) | tmp_scale[13]];
                    tmp_scale[14] = ctx->interpolation_table[(tmp_scale[15] << 8) | tmp_scale[13]];

                    codec48_block_scale(ctx, out, tmp_scale);
                    break;
                }

                // Copy a block using an absolute offset
                case 0xFE:
                {
                    codec48_block_copy(ctx, out, inter_buf_offs, (int16_t)getle16(data));
                    data += 2;
                    break;
                }

                // Interpolate a 4x4 block based on 4 pixels, then scale to 8x8
                case 0xFD: 
                {
                    uint8_t tmp_scale[16] = {0};
                    tmp_scale[5] = data[0];
                    tmp_scale[7] = data[1];
                    tmp_scale[13] = data[2];
                    tmp_scale[15] = data[3];

                    tmp_scale[1] = ctx->interpolation_table[(out[3 - ctx->pitch] << 8) | tmp_scale[5]];
                    tmp_scale[3] = ctx->interpolation_table[(out[7 - ctx->pitch] << 8) | tmp_scale[7]];
                    tmp_scale[11] = ctx->interpolation_table[(tmp_scale[15] << 8) | tmp_scale[7]];
                    tmp_scale[9] = ctx->interpolation_table[(tmp_scale[13] << 8) | tmp_scale[5]];

                    tmp_scale[0] = ctx->interpolation_table[(out[-1] << 8) | tmp_scale[1]];
                    tmp_scale[2] = ctx->interpolation_table[(tmp_scale[3] << 8) | tmp_scale[1]];
                    tmp_scale[4] = ctx->interpolation_table[(out[ctx->pitch * 2 - 1] << 8) | tmp_scale[5]];
                    tmp_scale[6] = ctx->interpolation_table[(tmp_scale[7] << 8) | tmp_scale[5]];

                    tmp_scale[8] = ctx->interpolation_table[(out[ctx->pitch * 3 - 1] << 8) | tmp_scale[9]];
                    tmp_scale[10] = ctx->interpolation_table[(tmp_scale[11] << 8) | tmp_scale[9]];
                    tmp_scale[12] = ctx->interpolation_table[(out[ctx->pitch * 4 - 1] << 8) | tmp_scale[13]];
                    tmp_scale[14] = ctx->interpolation_table[(tmp_scale[15] << 8) | tmp_scale[13]];
                    
                    codec48_block_scale(ctx, out, tmp_scale);

                    data += 4;
                    break;
                }

                // Copy 4 4x4 blocks using the offset table
                case 0xFC:
                {
                    *((uint32_t *)(out + (ctx->pitch * 0))) = *((uint32_t *)(out + inter_buf_offs + ctx->offset_table[data[0]]));
                    *((uint32_t *)(out + (ctx->pitch * 1))) = *((uint32_t *)(out + inter_buf_offs + ctx->offset_table[data[0]] + ctx->pitch));
                    *((uint32_t *)(out + (ctx->pitch * 2))) = *((uint32_t *)(out + inter_buf_offs + ctx->offset_table[data[0]] + ctx->pitch * 2));
                    *((uint32_t *)(out + (ctx->pitch * 3))) = *((uint32_t *)(out + inter_buf_offs + ctx->offset_table[data[0]] + ctx->pitch * 3));

                    *((uint32_t *)(out + (ctx->pitch * 0) + 4)) = *((uint32_t *)(out + inter_buf_offs + ctx->offset_table[data[1]] + 4));
                    *((uint32_t *)(out + (ctx->pitch * 1) + 4)) = *((uint32_t *)(out + inter_buf_offs + ctx->offset_table[data[1]] + ctx->pitch + 4));
                    *((uint32_t *)(out + (ctx->pitch * 2) + 4)) = *((uint32_t *)(out + inter_buf_offs + ctx->offset_table[data[1]] + ctx->pitch * 2 + 4));
                    *((uint32_t *)(out + (ctx->pitch * 3) + 4)) = *((uint32_t *)(out + inter_buf_offs + ctx->offset_table[data[1]] + ctx->pitch * 3 + 4));

                    *((uint32_t *)(out + (ctx->pitch * 4))) = *((uint32_t *)(out + inter_buf_offs + ctx->offset_table[data[2]] + ctx->pitch * 4));
                    *((uint32_t *)(out + (ctx->pitch * 5))) = *((uint32_t *)(out + inter_buf_offs + ctx->offset_table[data[2]] + ctx->pitch * 5));
                    *((uint32_t *)(out + (ctx->pitch * 6))) = *((uint32_t *)(out + inter_buf_offs + ctx->offset_table[data[2]] + ctx->pitch * 6));
                    *((uint32_t *)(out + (ctx->pitch * 7))) = *((uint32_t *)(out + inter_buf_offs + ctx->offset_table[data[2]] + ctx->pitch * 7));

                    *((uint32_t *)(out + (ctx->pitch * 4) + 4)) = *((uint32_t *)(out + inter_buf_offs + ctx->offset_table[data[3]] + ctx->pitch * 4 + 4));
                    *((uint32_t *)(out + (ctx->pitch * 5) + 4)) = *((uint32_t *)(out + inter_buf_offs + ctx->offset_table[data[3]] + ctx->pitch * 5 + 4));
                    *((uint32_t *)(out + (ctx->pitch * 6) + 4)) = *((uint32_t *)(out + inter_buf_offs + ctx->offset_table[data[3]] + ctx->pitch * 6 + 4));
                    *((uint32_t *)(out + (ctx->pitch * 7) + 4)) = *((uint32_t *)(out + inter_buf_offs + ctx->offset_table[data[3]] + ctx->pitch * 7 + 4));

                    data += 4;
                    break;
                }

                // Copy 4 4x4 blocks using absolute offsets
                case 0xFB:
                {
                    *((uint32_t *)out) = *((uint32_t *)(out + inter_buf_offs + (int16_t)getle16(data)));
                    *((uint32_t *)(out + ctx->pitch)) = *((uint32_t *)(out + inter_buf_offs + (int16_t)getle16(data) + ctx->pitch));
                    *((uint32_t *)(out + ctx->pitch * 2)) = *((uint32_t *)(out + inter_buf_offs + (int16_t)getle16(data) + ctx->pitch * 2));
                    *((uint32_t *)(out + ctx->pitch * 3)) = *((uint32_t *)(out + inter_buf_offs + (int16_t)getle16(data) + ctx->pitch * 3));

                    *((uint32_t *)(out + 4)) = *((uint32_t *)(out + inter_buf_offs + (int16_t)getle16(data + 2) + 4));
                    *((uint32_t *)(out + ctx->pitch + 4)) = *((uint32_t *)(out + inter_buf_offs + (int16_t)getle16(data + 2) + ctx->pitch + 4));
                    *((uint32_t *)(out + ctx->pitch * 2 + 4)) = *((uint32_t *)(out + inter_buf_offs + (int16_t)getle16(data + 2) + ctx->pitch * 2 + 4));
                    *((uint32_t *)(out + ctx->pitch * 3 + 4)) = *((uint32_t *)(out + inter_buf_offs + (int16_t)getle16(data + 2) + ctx->pitch * 3 + 4));

                    *((uint32_t *)(out + ctx->pitch * 4)) = *((uint32_t *)(out + inter_buf_offs + (int16_t)getle16(data + 4) + ctx->pitch * 4));
                    *((uint32_t *)(out + ctx->pitch * 5)) = *((uint32_t *)(out + inter_buf_offs + (int16_t)getle16(data + 4) + ctx->pitch * 5));
                    *((uint32_t *)(out + ctx->pitch * 6)) = *((uint32_t *)(out + inter_buf_offs + (int16_t)getle16(data + 4) + ctx->pitch * 6));
                    *((uint32_t *)(out + ctx->pitch * 7)) = *((uint32_t *)(out + inter_buf_offs + (int16_t)getle16(data + 4) + ctx->pitch * 7));

                    *((uint32_t *)(out + ctx->pitch * 4 + 4)) = *((uint32_t *)(out + inter_buf_offs + (int16_t)getle16(data + 6) + ctx->pitch * 4 + 4));
                    *((uint32_t *)(out + ctx->pitch * 5 + 4)) = *((uint32_t *)(out + inter_buf_offs + (int16_t)getle16(data + 6) + ctx->pitch * 5 + 4));
                    *((uint32_t *)(out + ctx->pitch * 6 + 4)) = *((uint32_t *)(out + inter_buf_offs + (int16_t)getle16(data + 6) + ctx->pitch * 6 + 4));
                    *((uint32_t *)(out + ctx->pitch * 7 + 4)) = *((uint32_t *)(out + inter_buf_offs + (int16_t)getle16(data + 6) + ctx->pitch * 7 + 4));
                    data += 8;
                    break;
                }

                // Scale a 4x4 block to an 8x8 block
                case 0xFA:
                {
                    codec48_block_scale(ctx, out, data);
                    data += 16;
                    break;
                }

                // Copy 16 2x2 blocks using the offset table
                case 0xF9:
                {
                    *((uint16_t *)out) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[0]]));
                    *((uint16_t *)(out + ctx->pitch)) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[0]] + ctx->pitch));

                    *((uint16_t *)(out + 2)) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[1]] + 2));
                    *((uint16_t *)(out + ctx->pitch + 2)) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[1]] + ctx->pitch + 2));

                    *((uint16_t *)(out + 4)) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[2]] + 4));
                    *((uint16_t *)(out + ctx->pitch + 4)) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[2]] + ctx->pitch + 4));

                    *((uint16_t *)(out + 6)) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[3]] + 6));
                    *((uint16_t *)(out + ctx->pitch + 6)) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[3]] + ctx->pitch + 6));

                    *((uint16_t *)(out + ctx->pitch * 2)) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[4]] + ctx->pitch * 2));
                    *((uint16_t *)(out + ctx->pitch * 3)) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[4]] + ctx->pitch * 3));

                    *((uint16_t *)(out + ctx->pitch * 2 + 2)) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[5]] + ctx->pitch * 2 + 2));
                    *((uint16_t *)(out + ctx->pitch * 3 + 2)) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[5]] + ctx->pitch * 3 + 2));

                    *((uint16_t *)(out + ctx->pitch * 2 + 4)) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[6]] + ctx->pitch * 2 + 4));
                    *((uint16_t *)(out + ctx->pitch * 3 + 4)) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[6]] + ctx->pitch * 3 + 4));

                    *((uint16_t *)(out + ctx->pitch * 2 + 6)) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[7]] + ctx->pitch * 2 + 6));
                    *((uint16_t *)(out + ctx->pitch * 3 + 6)) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[7]] + ctx->pitch * 3 + 6));

                    *((uint16_t *)(out + ctx->pitch * 4)) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[8]] + ctx->pitch * 4));
                    *((uint16_t *)(out + ctx->pitch * 5)) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[8]] + ctx->pitch * 5));

                    *((uint16_t *)(out + ctx->pitch * 4 + 2)) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[9]] + ctx->pitch * 4 + 2));
                    *((uint16_t *)(out + ctx->pitch * 5 + 2)) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[9]] + ctx->pitch * 5 + 2));

                    *((uint16_t *)(out + ctx->pitch * 4 + 4)) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[10]] + ctx->pitch * 4 + 4));
                    *((uint16_t *)(out + ctx->pitch * 5 + 4)) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[10]] + ctx->pitch * 5 + 4));

                    *((uint16_t *)(out + ctx->pitch * 4 + 6)) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[11]] + ctx->pitch * 4 + 6));
                    *((uint16_t *)(out + ctx->pitch * 5 + 6)) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[11]] + ctx->pitch * 5 + 6));

                    *((uint16_t *)(out + ctx->pitch * 6)) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[12]] + ctx->pitch * 6));
                    *((uint16_t *)(out + ctx->pitch * 7)) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[12]] + ctx->pitch * 7));

                    *((uint16_t *)(out + ctx->pitch * 6 + 2)) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[13]] + ctx->pitch * 6 + 2));
                    *((uint16_t *)(out + ctx->pitch * 7 + 2)) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[13]] + ctx->pitch * 7 + 2));

                    *((uint16_t *)(out + ctx->pitch * 6 + 4)) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[14]] + ctx->pitch * 6 + 4));
                    *((uint16_t *)(out + ctx->pitch * 7 + 4)) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[14]] + ctx->pitch * 7 + 4));

                    *((uint16_t *)(out + ctx->pitch * 6 + 6)) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[15]] + ctx->pitch * 6 + 6));
                    *((uint16_t *)(out + ctx->pitch * 7 + 6)) = *((uint16_t *)(out + inter_buf_offs + ctx->offset_table[data[15]] + ctx->pitch * 7 + 6));
                    data += 16;
                    break;
                }

                // Copy 16 2x2 blocks using absolute offsets
                case 0xF8:
                {
                    *((uint16_t *)out) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data)));
                    *((uint16_t *)(out + ctx->pitch)) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data) + ctx->pitch));
            
                    *((uint16_t *)(out + 2)) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data + 2) + 2));
                    *((uint16_t *)(out + ctx->pitch + 2)) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data + 2) + ctx->pitch + 2));

                    *((uint16_t *)(out + 4)) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data + 4) + 4));
                    *((uint16_t *)(out + ctx->pitch + 4)) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data + 4) + ctx->pitch + 4));

                    *((uint16_t *)(out + 6)) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data + 6) + 6));
                    *((uint16_t *)(out + ctx->pitch + 6)) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data + 6) + ctx->pitch + 6));

                    *((uint16_t *)(out + ctx->pitch * 2)) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data + 8) + ctx->pitch * 2));
                    *((uint16_t *)(out + ctx->pitch * 3)) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data + 8) + ctx->pitch * 3));

                    *((uint16_t *)(out + ctx->pitch * 2 + 2)) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data + 10) + ctx->pitch * 2 + 2));
                    *((uint16_t *)(out + ctx->pitch * 3 + 2)) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data + 10) + ctx->pitch * 3 + 2));

                    *((uint16_t *)(out + ctx->pitch * 2 + 4)) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data + 12) + ctx->pitch * 2 + 4));
                    *((uint16_t *)(out + ctx->pitch * 3 + 4)) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data + 12) + ctx->pitch * 3 + 4));

                    *((uint16_t *)(out + ctx->pitch * 2 + 6)) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data + 14) + ctx->pitch * 2 + 6));
                    *((uint16_t *)(out + ctx->pitch * 3 + 6)) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data + 14) + ctx->pitch * 3 + 6));

                    *((uint16_t *)(out + ctx->pitch * 4)) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data + 16) + ctx->pitch * 4));
                    *((uint16_t *)(out + ctx->pitch * 5)) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data + 16) + ctx->pitch * 5));

                    *((uint16_t *)(out + ctx->pitch * 4 + 2)) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data + 18) + ctx->pitch * 4 + 2));
                    *((uint16_t *)(out + ctx->pitch * 5 + 2)) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data + 18) + ctx->pitch * 5 + 2));

                    *((uint16_t *)(out + ctx->pitch * 4 + 4)) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data + 20) + ctx->pitch * 4 + 4));
                    *((uint16_t *)(out + ctx->pitch * 5 + 4)) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data + 20) + ctx->pitch * 5 + 4));

                    *((uint16_t *)(out + ctx->pitch * 4 + 6)) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data + 22) + ctx->pitch * 4 + 6));
                    *((uint16_t *)(out + ctx->pitch * 5 + 6)) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data + 22) + ctx->pitch * 5 + 6));

                    *((uint16_t *)(out + ctx->pitch * 6)) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data + 24) + ctx->pitch * 6));
                    *((uint16_t *)(out + ctx->pitch * 7)) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data + 24) + ctx->pitch * 7));

                    *((uint16_t *)(out + ctx->pitch * 6 + 2)) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data + 26) + ctx->pitch * 6 + 2));
                    *((uint16_t *)(out + ctx->pitch * 7 + 2)) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data + 26) + ctx->pitch * 7 + 2));

                    *((uint16_t *)(out + ctx->pitch * 6 + 4)) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data + 28) + ctx->pitch * 6 + 4));
                    *((uint16_t *)(out + ctx->pitch * 7 + 4)) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data + 28) + ctx->pitch * 7 + 4));

                    *((uint16_t *)(out + ctx->pitch * 6 + 6)) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data + 30) + ctx->pitch * 6 + 6));
                    *((uint16_t *)(out + ctx->pitch * 7 + 6)) = *((uint16_t *)(out + inter_buf_offs + (int16_t)getle16(data + 30) + ctx->pitch * 7 + 6));

                    data += 32;
                    break;
                }

                // Raw 8x8 block
                case 0xF7:
                {
                    *((uint32_t *)out) = getle32(data);
                    *((uint32_t *)(out + 4)) = getle32((data + 4));
                    *((uint32_t *)(out + ctx->pitch)) = getle32((data + 8));
                    *((uint32_t *)(out + ctx->pitch + 4)) = getle32((data + 12));
                    *((uint32_t *)(out + ctx->pitch * 2)) = getle32((data + 16));
                    *((uint32_t *)(out + ctx->pitch * 2 + 4)) = getle32((data + 20));
                    *((uint32_t *)(out + ctx->pitch * 3)) = getle32((data + 24));
                    *((uint32_t *)(out + ctx->pitch * 3 + 4)) = getle32((data + 28));
                    *((uint32_t *)(out + ctx->pitch * 4)) = getle32((data + 32));
                    *((uint32_t *)(out + ctx->pitch * 4 + 4)) = getle32((data + 36));
                    *((uint32_t *)(out + ctx->pitch * 5)) = getle32((data + 40));
                    *((uint32_t *)(out + ctx->pitch * 5 + 4)) = getle32((data + 44));
                    *((uint32_t *)(out + ctx->pitch * 6)) = getle32((data + 48));
                    *((uint32_t *)(out + ctx->pitch * 6 + 4)) = getle32((data + 52));
                    *((uint32_t *)(out + ctx->pitch * 7)) = getle32((data + 56));
                    *((uint32_t *)(out + ctx->pitch * 7 + 4)) = getle32((data + 60));

                    data += 64;
                    break;
                }

                // Copy a block using the offset table
                default:
                {
                    codec48_block_copy(ctx, out, inter_buf_offs, ctx->offset_table[op]);
                    break;
                }
            }

            out += 8;
        }

        out += ctx->pitch * 7;
    }
}

void codec48_block_copy(codec48_ctx* ctx, uint8_t *dst, size_t inter_buf_offs, int32_t offset)
{
    const uint8_t *src = dst + inter_buf_offs + offset;

    for (int i = 0; i < 8; i++) 
    {
        *((uint32_t *)(dst + ctx->pitch * i)) = getle32((src + ctx->pitch * i));
        *((uint32_t *)(dst + ctx->pitch * i + 4)) = getle32((src + ctx->pitch * i + 4));
    }
}

void codec48_block_scale(codec48_ctx* ctx, uint8_t *dst, const uint8_t *src)
{
    // Scale the data by 2x
    for (int i = 0; i < 4; i++) 
    {
        uint16_t pixels = src[0];
        pixels = (pixels << 8) | pixels;

        *((uint16_t *)dst) = pixels;
        *((uint16_t *)(dst + ctx->pitch)) = pixels;

        pixels = src[1];
        pixels = (pixels << 8) | pixels;

        *((uint16_t *)(dst + 2)) = pixels;
        *((uint16_t *)(dst + ctx->pitch + 2)) = pixels;

        pixels = src[2];
        pixels = (pixels << 8) | pixels;

        *((uint16_t *)(dst + 4)) = pixels;
        *((uint16_t *)(dst + ctx->pitch + 4)) = pixels;

        pixels = src[3];
        pixels = (pixels << 8) | pixels;

        *((uint16_t *)(dst + 6)) = pixels;
        *((uint16_t *)(dst + ctx->pitch + 6)) = pixels;

        src += 4;
        dst += ctx->pitch * 2;
    }
}