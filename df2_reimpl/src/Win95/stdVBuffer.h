#ifndef _WIN95_STDVBUFFER_H
#define _WIN95_STDVBUFFER_H

#include "types.h"

#ifdef LINUX
typedef struct SDL_Surface SDL_Surface;
#endif

typedef struct rdDDrawSurface
{
    void* lpVtbl; // IDirectDrawSurfaceVtbl *lpVtbl
    uint32_t direct3d_tex;
    uint8_t surface_desc[0x6c];
    uint32_t texture_id;
    uint32_t texture_loaded;
    uint32_t is_16bit;
    uint32_t width;
    uint32_t height;
    uint32_t texture_area;
    uint32_t gpu_accel_maybe;
    rdDDrawSurface* tex_prev;
    rdDDrawSurface* tex_next;
} rdDDrawSurface;

typedef struct rdTexformat
{
    uint32_t is16bit;
    uint32_t bpp;
    uint32_t r_bits;
    uint32_t g_bits;
    uint32_t b_bits;
    uint32_t r_shift;
    uint32_t g_shift;
    uint32_t b_shift;
    uint32_t r_bitdiff;
    uint32_t g_bitdiff;
    uint32_t b_bitdiff;
    uint32_t unk_40;
    uint32_t unk_44;
    uint32_t unk_48;
} rdTexformat;

typedef struct stdVBufferTexFmt
{
    int32_t width;
    int32_t height;
    uint32_t texture_size_in_bytes;
    uint32_t width_in_bytes;
    uint32_t width_in_pixels;
    rdTexformat format;
} stdVBufferTexFmt;

typedef struct stdVBuffer
{
    uint32_t bSurfaceLocked;
    uint32_t lock_cnt;
    uint32_t gap8;
    stdVBufferTexFmt format;
    void* palette;
    char* surface_lock_alloc;
    uint32_t transparent_color;
    union
    {
    rdDDrawSurface *ddraw_surface;
#ifdef LINUX
    SDL_Surface* sdlSurface;
#endif
    };
    void* ddraw_palette; // LPDIRECTDRAWPALETTE
    uint8_t desc[0x6c];
} stdVBuffer;

#endif // _WIN95_STDVBUFFER_H
