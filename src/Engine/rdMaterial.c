#include "rdMaterial.h"

#include "Engine/rdroid.h"
#include "Win95/stdDisplay.h"
#include "Win95/std.h"
#include "Platform/std3D.h"
#include "stdPlatform.h"
#include "jk.h"

#ifdef SDL2_RENDER
#include "Platform/GL/jkgm.h"
#endif

void rdMaterial_RegisterLoader(rdMaterialLoader_t load)
{
    pMaterialsLoader = load;
}

void rdMaterial_RegisterUnloader(rdMaterialUnloader_t unload)
{
    pMaterialsUnloader = unload;
}

rdMaterial* rdMaterial_Load(char *material_fname, int create_ddraw_surface, int gpu_memory)
{
    rdMaterial *material;
    unsigned int v5;
    void **v6;
    int *v7;
    unsigned int v8;
    stdVBuffer **v9;
    unsigned int gpu_mem;

    if (pMaterialsLoader)
        return (rdMaterial*)pMaterialsLoader(material_fname, create_ddraw_surface, gpu_memory);

    material = (rdMaterial*)rdroid_pHS->alloc(sizeof(rdMaterial));
    if (material && rdMaterial_LoadEntry(material_fname, material, create_ddraw_surface, gpu_memory))
        return material;

    rdMaterial_Free(material);

    return NULL;
}

int rdMaterial_LoadEntry(char *mat_fpath, rdMaterial *material, int create_ddraw_surface, int gpu_mem)
{
    int mat_file; // eax
    int mat_file_; // ebx
    int num_texinfo; // eax
    int tex_type; // edx
    int *texture_idk; // edi
    rdTexinfo *texinfo_alloc; // eax
    int num_textures; // ecx
    rdTexture *textures; // eax
    rdTexture *texture; // esi
    unsigned int mipmap_num; // ebx
    int bpp; // eax
    stdVBuffer **texture_struct; // edi
    int v21; // cf
    unsigned int v22; // edi
    int *v23; // esi
    rdTexinfo **v24; // ebx
    rdColor24 *colors; // eax
    char *v26; // eax
    int mat_file__; // [esp+10h] [ebp-128h]
    int tex_num; // [esp+14h] [ebp-124h]
    int tex_numa; // [esp+14h] [ebp-124h]
    rdTextureHeader tex_header_1; // [esp+20h] [ebp-118h]
    rdTexinfoHeader texinfo_header; // [esp+38h] [ebp-100h]
    rdTexinfoExtHeader tex_ext; // [esp+50h] [ebp-E8h]
    stdVBufferTexFmt format; // [esp+60h] [ebp-D8h]
    rdMaterialHeader mat_header; // [esp+ACh] [ebp-8Ch]
    int textures_idk[16]; // [esp+F8h] [ebp-40h]
    stdVBuffer *created_tex; // eax

    memset(&format, 0, sizeof(format));

    _memset(material, 0, sizeof(rdMaterial));
    mat_file = rdroid_pHS->fileOpen(mat_fpath, "rb");
    mat_file_ = mat_file;
    mat_file__ = mat_file;
    if (!mat_file) {
        return 0;
    }

    rdroid_pHS->fileRead(mat_file, &mat_header, sizeof(rdMaterialHeader));
    if ( _memcmp(mat_header.magic, "MAT ", 4u) || mat_header.revision != '2' )
    {
        rdroid_pHS->fileClose(mat_file_);
        return 0;
    }
    num_texinfo = mat_header.num_texinfo;
    tex_type = mat_header.type;
    material->num_textures = mat_header.num_textures;
    material->tex_type = tex_type;
    material->num_texinfo = num_texinfo;
    material->celIdx = 0;
    tex_num = 0;
    _memcpy(&material->tex_format, &mat_header.tex_format, sizeof(material->tex_format));
    texture_idk = textures_idk;
    for (tex_num = 0; tex_num < material->num_texinfo; tex_num++)
    {
        texinfo_alloc = (rdTexinfo *)rdroid_pHS->alloc(sizeof(rdTexinfo));
        material->texinfos[tex_num] = texinfo_alloc;
        if ( !texinfo_alloc )
        {
            rdroid_pHS->fileClose(mat_file_);
            return 0;
        }
        rdroid_pHS->fileRead(mat_file_, &texinfo_header, sizeof(rdTexinfoHeader));
        texinfo_alloc->header = texinfo_header;
        if ( texinfo_header.texture_type & 8 )  // bitflag for texture, not color
        {
              rdroid_pHS->fileRead(mat_file_, &tex_ext, sizeof(rdTexinfoExtHeader));
              texinfo_alloc->texext_unk00 = tex_ext.unk_00;
              *texture_idk = tex_ext.unk_0c;
        }
        ++texture_idk;
    }
    num_textures = material->num_textures;
    material->textures = 0;
    if ( num_textures )
    {
      textures = (rdTexture *)rdroid_pHS->alloc(sizeof(rdTexture) * num_textures);
      material->textures = textures;
      if ( !textures )
      {
        rdroid_pHS->fileClose(mat_file_);
        return 0;
      }
    }
    tex_numa = 0;
    if ( material->num_textures )
    {
      while ( 1 )
      {
        //printf("asdf %x %x\n", tex_numa, material->num_textures);
        rdroid_pHS->fileRead(mat_file_, &tex_header_1, sizeof(rdTextureHeader));
        texture = &material->textures[tex_numa];
        texture->alpha_en = tex_header_1.alpha_en;
        texture->unk_0c = tex_header_1.unk_0c;
        texture->width_bitcnt = stdCalcBitPos(tex_header_1.width);
        texture->width_minus_1 = tex_header_1.width - 1;
        mipmap_num = 0;
        texture->height_minus_1 = tex_header_1.height - 1;
        texture->num_mipmaps = tex_header_1.num_mipmaps;
        texture->color_transparent = tex_header_1.unk_10;
        format.width = tex_header_1.width;
        format.height = tex_header_1.height;
        bpp = material->tex_format.bpp;
        format.format.is16bit = material->tex_format.is16bit;
        format.format.bpp = bpp;
        if ( texture->num_mipmaps )
          break;
LABEL_21:
        mat_file_ = mat_file__;
        v21 = (unsigned int)(tex_numa++ + 1) < material->num_textures;
        if ( !v21 )
          goto LABEL_22;
      }
      texture_struct = (stdVBuffer **)texture->texture_struct;
      while ( 1 )
      {
        texture->alphaMats[mipmap_num].texture_loaded = 0;
        texture->alphaMats[mipmap_num].gpu_accel_maybe = 0;
        texture->opaqueMats[mipmap_num].texture_loaded = 0;
        texture->opaqueMats[mipmap_num].gpu_accel_maybe = 0;
#ifdef SDL2_RENDER
        texture->alphaMats[mipmap_num].skip_jkgm = 0;
        texture->opaqueMats[mipmap_num].skip_jkgm = 0;
#endif
        created_tex = stdDisplay_VBufferNew(&format, create_ddraw_surface, gpu_mem, 0);
        *texture_struct = created_tex;
        if ( !created_tex )
          break;
        if ( texture->alpha_en & 1 )
          stdDisplay_VBufferSetColorKey(created_tex, texture->color_transparent);
        stdDisplay_VBufferLock(*texture_struct);
        rdroid_pHS->fileRead(
          mat_file__,
          (void *)(*texture_struct)->surface_lock_alloc,
          (*texture_struct)->format.texture_size_in_bytes);
        stdDisplay_VBufferUnlock(*texture_struct);
        format.width = (unsigned int)format.width >> 1;
        format.height = (unsigned int)format.height >> 1;
        ++mipmap_num;
        ++texture_struct;
        if ( mipmap_num >= texture->num_mipmaps )
        {
          goto LABEL_21;
        }
      }
      mat_file_ = mat_file__;
      rdroid_pHS->fileClose(mat_file_);
      return 0;
    }
LABEL_22:
    v22 = 0;
    if ( material->num_texinfo )
    {
      v23 = textures_idk;
      v24 = material->texinfos;
      do
      {
        if ( (*v24)->header.texture_type & 8 )
          (*v24)->texture_ptr = &material->textures[*v23];
        ++v22;
        ++v23;
        ++v24;
      }
      while ( v22 < material->num_texinfo );
      mat_file_ = mat_file__;
    }
    if ( material->tex_type & 1 )
    {
      colors = (rdColor24 *)rdroid_pHS->alloc(0x300u);
      material->palette_alloc = colors;
      if ( !colors )
      {
        rdroid_pHS->fileClose(mat_file_);
        return 0;
      }
      rdroid_pHS->fileRead(mat_file_, colors, 0x300);
    }
    v26 = stdFileFromPath(mat_fpath);
    _strncpy(material->mat_fpath, v26, 0x1Fu);
    material->mat_fpath[31] = 0;
    rdroid_pHS->fileClose(mat_file_);
    mat_file = 1;
#ifdef SDL2_RENDER
    _strncpy(material->mat_full_fpath, mat_fpath, 0xFF);
    for (int i = 0; i < 256; i++)
    {
        if (material->mat_full_fpath[i] == '\\') {
            material->mat_full_fpath[i] = '/';
        }
    }
    material->mat_full_fpath[255] = 0;

    for (int i = 0; i < material->num_textures; i++)
    {
        rdTexture *texture = &material->textures[i];
        for (int j = 0; j < texture->num_mipmaps; j++) {
            stdVBuffer* mipmap = texture->texture_struct[j];
            rdDDrawSurface* surface = &texture->alphaMats[j];

            surface->albedo_data = NULL;
            surface->displacement_data = NULL;
            surface->emissive_data = NULL;
            surface->emissive_texture_id = 0;
            surface->displacement_texture_id = 0;
            surface->emissive_factor[0] = 0.0;
            surface->emissive_factor[1] = 0.0;
            surface->emissive_factor[2] = 0.0;
            surface->displacement_factor = 0.0;

            jkgm_populate_shortcuts(mipmap, surface, material, texture->alpha_en & 1, i);
        }
    }
#endif

    return mat_file;
}

void rdMaterial_Free(rdMaterial *material)
{
    if (!material)
        return;

    if (pMaterialsUnloader)
    {
        pMaterialsUnloader(material);
        return;
    }

    rdMaterial_FreeEntry(material);

    rdroid_pHS->free(material);
}

void rdMaterial_FreeEntry(rdMaterial* material)
{
    unsigned int v5;
    void **v6;
    rdTexture *v7;
    unsigned int v8;
    stdVBuffer **v9;
    unsigned int gpu_mem;

    v5 = 0;
    if (material->num_texinfo)
    {
      v6 = (void **)material->texinfos;
      do
      {
        rdroid_pHS->free(*v6);
        ++v5;
        ++v6;
      }
      while ( v5 < material->num_texinfo );
    }
    gpu_mem = 0;
    if ( material->num_textures )
    {
      v7 = &material->textures[0];
      do
      {
        v8 = 0;
        if ( v7->num_mipmaps )
        {
          v9 = v7->texture_struct;
          do
          {
            stdDisplay_VBufferFree(*v9);
            ++v8;
            ++v9;
          }
          while ( v8 < v7->num_mipmaps );
        }
        v7++;
        ++gpu_mem;
      }
      while ( gpu_mem < material->num_textures );
    }

    if (material->textures)
      rdroid_pHS->free(material->textures);

    if (material->tex_type & 1)
      rdroid_pHS->free(material->palette_alloc);
}

// rdMaterial_Write

int rdMaterial_AddToTextureCache(rdMaterial *material, rdTexture *texture, int mipmap_level, int no_alpha)
{
    stdVBuffer* mipmap = texture->texture_struct[mipmap_level];

    int celIdx = 0;
    for (int i = 0; i < material->num_textures; i++)
    {
        if (texture == &material->textures[i])
        {
            celIdx = i;
            break;
        }
    }

#ifdef SDL2_RENDER
    mipmap->palette = material->palette_alloc;
#endif

    if ( no_alpha )
    {
        rdDDrawSurface* surface = &texture->opaqueMats[mipmap_level];
        if (surface->texture_loaded)
        {
            std3D_UpdateFrameCount(surface);
            return 1;
        }
#ifdef SDL2_RENDER
        else if (jkgm_std3D_AddToTextureCache(mipmap, surface, texture->alpha_en & 1, no_alpha, material, celIdx))
        {
            //printf("%s\n", material->mat_fpath);
            return 1;
        }
#endif
        else if (std3D_AddToTextureCache(mipmap, surface, texture->alpha_en & 1, no_alpha))
        {
            return 1;
        }
        return 0;
    }
    else
    {
        rdDDrawSurface* surface = &texture->alphaMats[mipmap_level];
        if ( surface->texture_loaded )
        {
            std3D_UpdateFrameCount(surface);
            return 1;
        }
#ifdef SDL2_RENDER
        else if (jkgm_std3D_AddToTextureCache(mipmap, surface, texture->alpha_en & 1, no_alpha, material, celIdx))
        {
            //printf("%s\n", material->mat_fpath);
            return 1;
        }
#endif
        else if (std3D_AddToTextureCache(mipmap, surface, texture->alpha_en & 1, 0))
        {
            return 1;
        }
        return 0;
    }
}

void rdMaterial_ResetCacheInfo(rdMaterial *material)
{
    for (int i = 0; i < material->num_textures; i++)
    {
        rdTexture* texIter = &material->textures[i];
        for (int j = 0; j < texIter->num_mipmaps; j++)
        {
            rdDDrawSurface* matIter = &texIter->alphaMats[j];
            matIter->texture_loaded = 0;
            matIter->gpu_accel_maybe = 0;
            matIter[4].texture_loaded = 0;
            matIter[4].gpu_accel_maybe = 0;
        }
    }
}
