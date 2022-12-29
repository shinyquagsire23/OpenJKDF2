#ifndef _LIBSMUSHER_CODEC48_H
#define _LIBSMUSHER_CODEC48_H

#include "smush.h"

typedef struct codec48_hdr
{
    uint8_t type;
    uint8_t table_index;
    uint8_t seq_num[2];
    uint8_t unk2[4];

    uint8_t unk3[4];
    uint8_t flags[4];

} codec48_hdr;

typedef struct codec48_ctx
{
    uint32_t width;
    uint32_t height;

    size_t pitch;
    uint32_t block_x;
    uint32_t block_y;
    size_t frame_size;

    uint8_t cur_buf;

    uint8_t* delta_bufs;
    uint8_t* delta_buf[2];

    uint16_t last_seq_num;
    int32_t offset_table_pitch;
    int32_t offset_table_index;
    int16_t offset_table[256];
    uint8_t interpolation_table[65536];
} codec48_ctx;

#define C48_FLAG_1  (0x0001)
#define C48_FLAG_10 (0x0010)
#define C48_INTERPOLATION_FLAG (0x0008)

void codec48_destroy(smush_ctx* parent_ctx);
void codec48_proc(smush_ctx* ctx, const uint8_t* data, size_t data_len);
void codec48_make_table(codec48_ctx* ctx, int8_t idx);
void codec48_proc_block2(codec48_ctx* ctx, const uint8_t* data, uint32_t len, uint8_t* out);
void codec48_proc_block3(codec48_ctx* ctx, const uint8_t* data, uint8_t* out, size_t inter_buf_offs);

void codec48_block_copy(codec48_ctx* ctx, uint8_t *dst, size_t inter_buf_offs, int32_t offset);
void codec48_block_scale(codec48_ctx* ctx, uint8_t *dst, const uint8_t *src);

#endif // _LIBSMUSHER_CODEC48_H