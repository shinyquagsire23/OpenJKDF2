#ifndef _RDMATERIAL_H
#define _RDMATERIAL_H

#include "types.h"

#define rdMaterial_RegisterLoader_ADDR (0x0044A110)
#define rdMaterial_RegisterUnloader_ADDR (0x0044A120)
#define rdMaterial_Load_ADDR (0x0044A130)
#define rdMaterial_LoadEntry_ADDR (0x0044A260)
#define rdMaterial_Free_ADDR (0x0044A690)
#define rdMaterial_FreeEntry_ADDR (0x0044A770)
#define rdMaterial_Write_ADDR (0x0044A830)
#define rdMaterial_AddToTextureCache_ADDR (0x0044AA70)
#define rdMaterial_ResetCacheInfo_ADDR (0x0044AB20)

typedef struct sith_tex_2 sith_tex_2;

typedef struct sith_tex_2
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
    sith_tex_2* tex_prev;
    sith_tex_2* tex_next;
} sith_tex_2;

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

typedef struct texture_format
{
    uint32_t width;
    uint32_t height;
    uint32_t texture_size_in_bytes;
    uint32_t width_in_bytes;
    uint32_t width_in_pixels;
    rdTexformat format;
} texture_format;

typedef struct stdVBuffer
{
    uint32_t surface_locked;
    uint32_t lock_cnt;
    uint32_t gap8;
    texture_format format;
    void* palette;
    char* surface_lock_alloc;
    uint32_t transparent_color;
    sith_tex_2 *ddraw_surface;
    void* ddraw_palette; // LPDIRECTDRAWPALETTE
    uint8_t desc[0x6c];
} stdVBuffer;

typedef struct rdTexture
{
    uint32_t alpha_en;
    uint32_t unk_0c;
    uint32_t color_transparent;
    uint32_t width_bitcnt;
    uint32_t width_minus_1;
    uint32_t height_minus_1;
    uint32_t num_mipmaps;
    stdVBuffer *texture_struct[4];
    sith_tex_2 alphaMats[4];
    sith_tex_2 opaqueMats[4];
} rdTexture;

typedef struct rdColor24
{
    uint8_t r;
    uint8_t g;
    uint8_t b;
} rdColor24;

typedef struct rdTextureHeader
{
    uint32_t width;
    uint32_t height;
    uint32_t alpha_en;
    uint32_t unk_0c;
    uint32_t unk_10;
    uint32_t num_mipmaps;
} rdTextureHeader;

typedef struct rdTexinfoExtHeader
{
    uint32_t unk_00;
    uint32_t height;
    uint32_t alpha_en;
    uint32_t unk_0c;
} rdTexinfoExtHeader;

typedef struct rdTexinfoHeader
{
    uint32_t texture_type;
    uint32_t field_4;
    uint32_t field_8;
    uint32_t field_C;
    uint32_t field_10;
    uint32_t field_14;
} rdTexinfoHeader;

typedef struct rdTexinfo
{
    rdTexinfoHeader header;
    uint32_t texext_unk00;
    rdTexture *texture_ptr;
} rdTexinfo;

typedef struct rdMaterialHeader
{
    uint8_t magic[4];
    uint32_t revision;
    uint32_t type;
    uint32_t num_texinfo;
    uint32_t num_textures;
    rdTexformat tex_format;
} rdMaterialHeader;

typedef struct rdMaterial
{
    uint32_t tex_type;
    char mat_fpath[32];
    uint32_t id;
    rdTexformat tex_format;
    rdColor24 *palette_alloc;
    uint32_t num_texinfo;
    uint32_t celIdx;
    rdTexinfo *texinfos[8];
    uint32_t field_8C;
    uint32_t field_90;
    uint32_t field_94;
    uint32_t field_98;
    uint32_t field_9C;
    uint32_t field_A0;
    uint32_t field_A4;
    uint32_t field_A8;
    uint32_t num_textures;
    rdTexture* textures;
} rdMaterial;

typedef int (__cdecl *rdMaterialUnloader_t)(rdMaterial*);
typedef int (__cdecl *rdMaterialLoader_t)(char*, int, int);

#define pMaterialsLoader (*(rdMaterialLoader_t*)0x73D600)
#define pMaterialsUnloader (*(rdMaterialUnloader_t*)0x73D604)

void rdMaterial_RegisterLoader(rdMaterialLoader_t load);
void rdMaterial_RegisterUnloader(rdMaterialUnloader_t unload);
rdMaterial* rdMaterial_Load(char *material_fname, int create_ddraw_surface, int gpu_memory);
int rdMaterial_LoadEntry(char *mat_fpath, rdMaterial *material, int create_ddraw_surface, int gpu_mem);
void rdMaterial_Free(rdMaterial *material);
void rdMaterial_FreeEntry(rdMaterial* material);

static int (*rdMaterial_AddToTextureCache)(rdMaterial *material, rdTexture *a2, int mipmap_level, int no_alpha) = (void*)rdMaterial_AddToTextureCache_ADDR;
static void (*rdMaterial_ResetCacheInfo)(rdMaterial *material) = (void*)rdMaterial_ResetCacheInfo_ADDR;

//int rdMaterial_AddToTextureCache(rdMaterial *material, sith_tex *a2, int mipmap_level, int no_alpha);


#endif // _RDMATERIAL_H
