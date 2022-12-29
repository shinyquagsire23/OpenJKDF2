#ifndef _LIBSMUSHER_SMUSH_H
#define _LIBSMUSHER_SMUSH_H

#include "endian.h"

#include <stdio.h>

extern int _smush_debug_prints;

typedef FILE* filehandle_t;
typedef void (*smush_audio_callback_t)(const uint8_t*, size_t);

typedef struct smush_header
{
    uint8_t magic[4];
    uint8_t size[4];
} smush_header;

typedef struct smush_ahdr
{
    uint8_t magic[4];
    uint8_t size[4];
    uint8_t version[2];
    uint8_t num_frames[2];
    uint8_t unk1[2];
    uint8_t palette[256 * 3];
} smush_ahdr;

typedef struct smush_ahdr_ext
{
    uint8_t frame_rate[4];
    uint8_t unk2[4];
    uint8_t audio_rate[4];
} smush_ahdr_ext;

typedef struct smush_fobj
{
    uint8_t magic[4];
    uint8_t size[4];
    uint8_t codec;
    uint8_t codec_param;
    uint8_t x[2];
    uint8_t y[2];
    uint8_t width[2];
    uint8_t height[2];
    uint8_t unk3[2];
    uint8_t unk4[2];
} smush_fobj;

typedef struct smush_iact
{
    uint8_t code[2];
    uint8_t flags[2];
    uint8_t unk[2];
    uint8_t track_flags[2];
} smush_iact;

typedef struct smush_imuse_iact
{
    uint8_t track_id[2];
    uint8_t index[2];
    uint8_t frame_count[2];
    uint8_t bytes_left[4];
} smush_imuse_iact;


typedef struct codec48_ctx codec48_ctx; 
typedef struct smush_ctx
{
    char fpath[512];
    filehandle_t f;
    smush_header header;
    smush_ahdr ahdr;
    smush_ahdr_ext ahdr_ext;

    uint8_t palette[256*3];

    uint32_t start_fpos;
    uint32_t max_fpos;
    uint32_t frame_fpos;
    uint8_t num_channels;
    uint32_t cur_frame;

    codec48_ctx* c48_ctx;
    uint8_t* framebuffer;

    int16_t codec_x;
    int16_t codec_y;
    uint16_t codec_w;
    uint16_t codec_h;

    uint16_t delta_palette[256 * 3];

    int iact_idx;
    uint8_t iact_tmp[0x10008];

    smush_audio_callback_t audio_callback;
} smush_ctx;

// BE32
#define SMUSH_MAGIC_ANIM (0x414e494d)
#define SMUSH_MAGIC_AHDR (0x41484452)
#define SMUSH_MAGIC_FRME (0x46524D45)
#define SMUSH_MAGIC_FOBJ (0x464F424A)
#define SMUSH_MAGIC_XPAL (0x5850414C)
#define SMUSH_MAGIC_NPAL (0x4E50414C)
#define SMUSH_MAGIC_IACT (0x49414354)
#define SMUSH_MAGIC_FTCH (0x46544348)
#define SMUSH_MAGIC_STOR (0x53544F52)

#define smush_error(...) { printf(__VA_ARGS__); }
#define smush_warn(...) { printf(__VA_ARGS__); }
#define smush_debug(...) { if (_smush_debug_prints) printf(__VA_ARGS__); }

smush_ctx* smush_from_fpath(const char* fpath);
void smush_set_debug(smush_ctx* ctx, int val);
void smush_set_audio_callback(smush_ctx* ctx, smush_audio_callback_t callback);

void smush_destroy(smush_ctx* ctx);
int smush_done(smush_ctx* ctx);
int smush_cur_frame(smush_ctx* ctx);
int smush_num_frames(smush_ctx* ctx);

void smush_frame(smush_ctx* ctx);
void smush_proc_frme(smush_ctx* ctx, uint32_t seek_pos, uint32_t total_size);

void smush_print(smush_ctx* ctx);
void smush_print_frme(smush_ctx* ctx, uint32_t seek_pos, uint32_t total_size);

#endif // _LIBSMUSHER_SMUSH_H