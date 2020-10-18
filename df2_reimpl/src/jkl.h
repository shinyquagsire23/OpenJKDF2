#ifndef JKL_H
#define JKL_H

#include "types.h"

#define jkl_find_section_parser_ADDR (0x004D0E20)
#define jkl_set_section_parser_ADDR (0x004D0820)
#define jkl_init_parsers_ADDR (0x004CF6F0)

#define jkl_num_parsers (*(uint32_t*)0x8339D4)
#define some_integer_2 (*(uint32_t*)0x8339D8)
#define jkl_section_parsers ((sith_map_section_and_func*)0x833548)

typedef struct sith_vector2
{
    float x;
    float y;
} sith_vector2;

typedef struct sith_vector3
{
    float x;
    float y;
    float z;
} sith_vector3;

typedef struct sith_vector4
{
    float x;
    float y;
    float z;
    float w;
} sith_vector4;

typedef struct sith_jkl
{
    uint32_t level_type_maybe;
    char map_jkl_fname[32];
    char some_text_jk1[32];
    uint32_t num_colormaps;
    uint32_t colormaps_alloc;
    uint32_t sectors_amt;
    void* sectors_alloc;
    uint32_t field_54;
    uint32_t materials_amt;
    uint32_t materials_alloc;
    uint32_t materials_alloc_2;
    uint32_t models_loaded;
    uint32_t models_amt;
    void* models_alloc;
    uint32_t sprites_loaded;
    uint32_t sprites_amt;
    uint32_t sprites_alloc;
    uint32_t field_7C;
    uint8_t field_80;
    uint8_t field_81;
    uint8_t field_82;
    uint8_t field_83;
    uint32_t field_84;
    uint32_t num_vertices;
    void* vertices_alloc;
    void* vertices_transformed;
    uint32_t alloc_unk98;
    uint32_t alloc_unk94;
    uint32_t alloc_unk9c;
    uint32_t num_vertices_uvs;
    uint32_t vertices_uvs_alloc;
    uint32_t num_surfaces;
    void* surfaces_alloc;
    uint32_t num_adjoins;
    uint32_t field_B4;
    uint32_t adjoins_alloc;
    uint32_t thing_count;
    uint32_t max_thing_idx;
    void* things;
    uint32_t templates_loaded;
    uint32_t templates_amt;
    void* templates_alloc;
    float world_gravity;
    uint32_t field_D8;
    float ceiling_sky;
    uint32_t horizontal_distance;
    uint32_t horizontal_pixels_per_rev;
    sith_vector2 horizontal_sky_offs;
    sith_vector2 ceiling_sky_offs;
    sith_vector4 mipmap_distance;
    sith_vector4 load_distance;
    float perspective_distance;
    float gourad_distance;
    uint32_t unk_struct;
    uint32_t field_124;
    uint32_t field_128;
    uint32_t sounds_alloc_amt_unk;
    uint32_t sounds_alloc_amt;
    void* sounds_alloc;
    uint32_t soundclasses_loaded;
    uint32_t num_soundclasses;
    void* soundclass_ptr;
    uint32_t cogscripts_loaded;
    uint32_t cogscripts_amt;
    void* cogscripts_alloc;
    uint32_t cogs_loaded;
    uint32_t cogs_amt;
    void* cogs_alloc;
    uint32_t aiclass_loaded;
    uint32_t aiclass_amt;
    void* aiclass_alloc;
    uint32_t num_keyframes_loaded;
    uint32_t num_keyframes;
    void* keyframes_alloc;
    uint32_t animclass_loaded;
    uint32_t num_animclasses;
    void* animclass_alloc;
} __attribute__((packed)) sith_jkl;

typedef struct sith_colormap
{
    char colormap_fname[32];
    uint32_t dword20;
    uint32_t dword24;
    uint32_t dword28;
    uint32_t dword2C;
    char char30[768];
    uint32_t dword330;
    uint32_t dword334;
    uint32_t dword338;
    uint32_t dword33C;
    uint32_t dword340;
    uint32_t dword344;
    uint32_t dword348;
    uint32_t dword34C;
} sith_colormap;

typedef struct sith_map_section_and_func
{
    char section_name[32];
    int (*funcptr)(sith_jkl* ctx, int b);
} sith_map_section_and_func;

int jkl_find_section_parser(char *a1);
int jkl_set_section_parser(char *section_name, int (*funcptr)(sith_jkl *, int));
int jkl_init_parsers();

#endif // JKL_H
