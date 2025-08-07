#include "rdMaterial.h"

#include "General/stdString.h"
#include "Engine/rdroid.h"
#include "Win95/stdDisplay.h"
#include "Win95/std.h"
#include "Platform/std3D.h"
#include "stdPlatform.h"
#include "Main/jkRes.h"
#include "jk.h"

#ifdef SDL2_RENDER
#include "Platform/GL/jkgm.h"
#endif

#ifdef TARGET_TWL
#include <nds.h>
#endif


#if defined(RDMATERIAL_LRU_LOAD_UNLOAD)

rdMaterial* rdMaterial_pFirstMatCache = NULL;
rdMaterial* rdMaterial_pLastMatCache = NULL;
int rdMaterial_numCachedMaterials = 0;

#endif

rdMaterialLoader_t rdMaterial_RegisterLoader(rdMaterialLoader_t load)
{
    rdMaterialLoader_t result = pMaterialsLoader;
    pMaterialsLoader = load;
    return result;
}

rdMaterialUnloader_t rdMaterial_RegisterUnloader(rdMaterialUnloader_t unload)
{
    rdMaterialUnloader_t result = pMaterialsUnloader;
    pMaterialsUnloader = unload;
    return result;
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

#if 0 // sithMaterial already does this more or less, via rdMaterial_RegisterLoader
    rdMaterial* pIter = rdMaterial_pFirstMatCache;
    while (pIter) {
        if (!strcmp(material_fname, pIter->mat_full_fpath)) {
            pIter->refcnt++;
            return pIter;
        }
        pIter = pIter->pNextCachedMaterial;
    }
#endif

    if (pMaterialsLoader)
        return (rdMaterial*)pMaterialsLoader(material_fname, create_ddraw_surface, gpu_memory);

    material = (rdMaterial*)rdroid_pHS->alloc(sizeof(rdMaterial));
    if (material && rdMaterial_LoadEntry(material_fname, material, create_ddraw_surface, gpu_memory))
        return material;

    rdMaterial_Free(material);

    return NULL;
}

int rdMaterial_LoadEntry_Common(char *mat_fpath, rdMaterial *material, int create_ddraw_surface, int gpu_mem, int bDoLoad)
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
    int textures_idk[RDMATERIAL_MAX_TEXINFOS]; // [esp+F8h] [ebp-40h]
    stdVBuffer *created_tex; // eax

    stdPlatform_Printf("OpenJKDF2: %s mat_fpath: %s create_ddraw_surface: %d gpu_mem: %d bDoLoad: %d\n", __func__, mat_fpath, create_ddraw_surface, gpu_mem, bDoLoad);
    // Added: No nullptr derefs
    if (!material) {
        return 0;
    }

#if defined(RDMATERIAL_LRU_LOAD_UNLOAD)
    if (bDoLoad) {
        if (material->bDataLoaded) {
            return 1;
        }
    }
#endif

    memset(&format, 0, sizeof(format));

#if defined(RDMATERIAL_LRU_LOAD_UNLOAD)
    //if (!bDoLoad) {
#endif
        _memset(material, 0, sizeof(rdMaterial));
#if defined(RDMATERIAL_LRU_LOAD_UNLOAD)
    //}
#endif

#if 0
    if (!bDoLoad) {
        material->refcnt = 1;
    }
#endif

    mat_file = rdroid_pHS->fileOpen(mat_fpath, "rb");
    mat_file_ = mat_file;
    mat_file__ = mat_file;
    if (!mat_file) {
        stdPlatform_Printf("OpenJKDF2: Material `%s` could not be opened!\n", mat_fpath); // Added
        return 0;
    }

    rdroid_pHS->fileRead(mat_file, &mat_header, sizeof(rdMaterialHeader));
    if ( _memcmp(mat_header.magic, "MAT ", 4u) || mat_header.revision != '2' )
    {
        stdPlatform_Printf("OpenJKDF2: Material `%s` has improper magic or bad revision!\n", mat_fpath); // Added
        rdroid_pHS->fileClose(mat_file_);

        return 0;
    }

#if defined(RDMATERIAL_LRU_LOAD_UNLOAD)
    // We have to short-circuit here so that we get the right fullpath
    if (!bDoLoad) {
        // We need this to ensure sithMaterial loader doesn't break
#ifdef SITH_DEBUG_STRUCT_NAMES
        stdString_SafeStrCopy(material->mat_fpath, stdFileFromPath(mat_fpath), sizeof(material->mat_fpath));
#endif
        stdString_SafeStrCopy(material->mat_full_fpath, mat_fpath, sizeof(material->mat_full_fpath));
        rdroid_pHS->fileClose(mat_file_);
        return 1;
    }
#endif

    num_texinfo = mat_header.num_texinfo;

    // Added: prevent mem corruption
    if (num_texinfo > RDMATERIAL_MAX_TEXINFOS) {
        num_texinfo = RDMATERIAL_MAX_TEXINFOS;
    }
    else if (num_texinfo < 0) {
        num_texinfo = 0;
    }

    tex_type = mat_header.type;
    material->num_textures = mat_header.num_textures;
    material->tex_type = tex_type;
    material->num_texinfo = num_texinfo;
    material->celIdx = 0;
    tex_num = 0;
    _memcpy(&material->tex_format, &mat_header.tex_format, sizeof(material->tex_format));
    texture_idk = textures_idk;
    memset(material->texinfos, 0, sizeof(material->texinfos)); // Added: just in case?
    for (tex_num = 0; tex_num < material->num_texinfo; tex_num++)
    {
        texinfo_alloc = (rdTexinfo *)rdroid_pHS->alloc(sizeof(rdTexinfo));
        material->texinfos[tex_num] = texinfo_alloc;
        if ( !texinfo_alloc )
        {
            stdPlatform_Printf("OpenJKDF2: Material `%s` texinfo could not be allocated!\n", mat_fpath); // Added
            rdroid_pHS->fileClose(mat_file_);

            return 0;
        }
        memset(texinfo_alloc, 0, sizeof(rdTexinfo)); // Moved
        rdroid_pHS->fileRead(mat_file_, &texinfo_header, sizeof(rdTexinfoHeader));
        texinfo_alloc->header = texinfo_header;
        if ( texinfo_header.texture_type & 8 )  // bitflag for texture, not color
        {
              rdroid_pHS->fileRead(mat_file_, &tex_ext, sizeof(rdTexinfoExtHeader));
              texinfo_alloc->texext_unk00 = tex_ext.unk_00;
              *texture_idk = tex_ext.unk_0c;
        }
        else {
            // Added: uninitialized memory getting used as an index later, yikes
            *texture_idk = 0;
        }
        ++texture_idk;
    }
#if defined(RDMATERIAL_LRU_LOAD_UNLOAD)
    material->bMetadataLoaded = 1;
    // Short circuit only after metadata
    if (bDoLoad == 2) {
        stdString_SafeStrCopy(material->mat_full_fpath, mat_fpath, sizeof(material->mat_full_fpath));
        rdroid_pHS->fileClose(mat_file_);
        return 1;
    }
#endif
    num_textures = material->num_textures;
    material->textures = 0;
    if ( num_textures )
    {
      textures = (rdTexture *)rdroid_pHS->alloc(sizeof(rdTexture) * num_textures);
      if ( !textures )
      {
        stdPlatform_Printf("OpenJKDF2: Material `%s` textures array could not be allocated!\n", mat_fpath); // Added
        rdroid_pHS->fileClose(mat_file_);

        return 0;
      }
      // Moved?
      memset(textures, 0, sizeof(rdTexture) * num_textures);
      material->textures = textures;
    }
    else {
        // Some materials are solid colors
#if defined(RDMATERIAL_LRU_LOAD_UNLOAD)
        material->bDataLoaded = bDoLoad;
#endif
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
        texture->alphaMats[mipmap_num].frameNum = 0;
        texture->opaqueMats[mipmap_num].texture_loaded = 0;
        texture->opaqueMats[mipmap_num].frameNum = 0;
#ifdef SDL2_RENDER
#if defined(TARGET_CAN_JKGM)
        texture->alphaMats[mipmap_num].skip_jkgm = 0;
        texture->opaqueMats[mipmap_num].skip_jkgm = 0;
#endif
#endif

#if defined(TARGET_TWL)
        texture->alphaMats[mipmap_num].width = format.width;
        texture->alphaMats[mipmap_num].height = format.height;
        texture->opaqueMats[mipmap_num].width = format.width;
        texture->opaqueMats[mipmap_num].height = format.height;
#endif

#if defined(RDMATERIAL_LRU_LOAD_UNLOAD)
        if (!bDoLoad) {
            std_pHS->fseek(mat_file__, format.width*format.height*(format.format.is16bit?2:1), SEEK_CUR);
            goto no_loading;
        }
#endif

#if !defined(TARGET_TWL)
        printf("Load %s tex %d/%d mip %d/%d\n", mat_fpath, tex_numa, material->num_textures, mipmap_num, texture->num_mipmaps);
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

#if defined(RDMATERIAL_LRU_LOAD_UNLOAD)
        material->bDataLoaded = bDoLoad;
#endif

#else
        // Limit textures that are loaded on TWL
        if ((format.width <= 16 || mipmap_num >= texture->num_mipmaps-1)) {
            printf("Load %s tex %d/%d mip %d/%d\n", mat_fpath, tex_numa, material->num_textures, mipmap_num, texture->num_mipmaps);
            created_tex = stdDisplay_VBufferNew(&format, create_ddraw_surface, gpu_mem, 0);
            *texture_struct = created_tex;
            material->bDataLoaded = bDoLoad;
            if ( !created_tex ) {
                /*mat_file_ = mat_file__;
                rdroid_pHS->fileClose(mat_file_);
                return 1;*/
                std_pHS->fseek(mat_file__, format.width*format.height*(format.format.is16bit?2:1), SEEK_CUR);
                goto no_loading;
            }
            (*texture_struct)->format.texture_size_in_bytes = format.width*format.height*(format.format.is16bit?2:1);
            if ( texture->alpha_en & 1 )
              stdDisplay_VBufferSetColorKey(created_tex, texture->color_transparent);
            stdDisplay_VBufferLock(*texture_struct);
            rdroid_pHS->fileRead(
              mat_file__,
              (void *)(*texture_struct)->surface_lock_alloc,
              (*texture_struct)->format.texture_size_in_bytes);
            stdDisplay_VBufferUnlock(*texture_struct);
#if defined(RDMATERIAL_LRU_LOAD_UNLOAD)
            material->bDataLoaded = bDoLoad;
#endif
        }
        else {
            std_pHS->fseek(mat_file__, format.width*format.height*(format.format.is16bit?2:1), SEEK_CUR);
        }
#endif
no_loading:
        format.width = (unsigned int)format.width >> 1;
        format.height = (unsigned int)format.height >> 1;
        ++mipmap_num;
        ++texture_struct;
        if ( mipmap_num >= texture->num_mipmaps )
        {
          goto LABEL_21;
        }
      }
      stdPlatform_Printf("OpenJKDF2: Material `%s` vbuffer could not be allocated!\n", mat_fpath); // Added
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
        else
          (*v24)->texture_ptr = NULL; // Added
        ++v22;
        ++v23;
        ++v24;
      }
      while ( v22 < material->num_texinfo );
      mat_file_ = mat_file__;
    }
#ifndef TARGET_TWL
    if ( material->tex_type & 1 )
    {
      colors = (rdColor24 *)rdroid_pHS->alloc(0x300u);
      material->palette_alloc = colors;
      if ( !colors )
      {
        jk_printf("OpenJKDF2: Material `%s` color palette could not be allocated!\n", mat_fpath); // Added
        rdroid_pHS->fileClose(mat_file_);

        return 0;
      }
      rdroid_pHS->fileRead(mat_file_, colors, 0x300);
    }
#endif

    // Added: Move this up to start
    /*v26 = stdFileFromPath(mat_fpath);
#ifdef SITH_DEBUG_STRUCT_NAMES
    stdString_SafeStrCopy(material->mat_fpath, v26, sizeof(material->mat_fpath));
#endif*/
    rdroid_pHS->fileClose(mat_file_);
    mat_file = 1;

#if defined(SDL2_RENDER) || defined(RDMATERIAL_LRU_LOAD_UNLOAD)
    stdString_SafeStrCopy(material->mat_full_fpath, mat_fpath, sizeof(material->mat_full_fpath));
#endif
#ifdef SDL2_RENDER
    for (int i = 0; i < 128; i++)
    {
        if (material->mat_full_fpath[i] == '\\') {
            material->mat_full_fpath[i] = '/';
        }
    }
    material->mat_full_fpath[127] = 0;

    for (int i = 0; i < material->num_textures; i++)
    {
        rdTexture *texture = &material->textures[i];
        texture->has_jkgm_override = 0;
        for (int j = 0; j < texture->num_mipmaps; j++) {
            stdVBuffer* mipmap = texture->texture_struct[j];
            rdDDrawSurface* surface = &texture->alphaMats[j];
            
            surface->emissive_texture_id = 0;
            surface->displacement_texture_id = 0;
            surface->emissive_factor[0] = 0.0;
            surface->emissive_factor[1] = 0.0;
            surface->emissive_factor[2] = 0.0;
            surface->displacement_factor = 0.0;
            surface->albedo_factor[0] = 1.0;
            surface->albedo_factor[1] = 1.0;
            surface->albedo_factor[2] = 1.0;
            surface->albedo_factor[3] = 1.0;
            surface->albedo_data = NULL;
            surface->displacement_data = NULL;
            surface->emissive_data = NULL;
            surface->skip_jkgm = 0;
            surface->cache_entry = NULL;

            surface->is_16bit = 0;
            surface->texture_loaded = 0;

#if defined(TARGET_CAN_JKGM)
            jkgm_populate_shortcuts(mipmap, surface, material, texture->alpha_en & 1, j, i);
#endif
        }
    }
#endif

    return mat_file;
}

int rdMaterial_LoadEntry(char *mat_fpath, rdMaterial *material, int create_ddraw_surface, int gpu_mem)
{
    // Added: No nullptr derefs
    if (!material) {
        return 0;
    }

    // TODO: refcounting
    // Added: juuuust in case
    int prevId = material->id;
    _memset(material, 0, sizeof(rdMaterial));
    material->id = prevId;
#if defined(RDMATERIAL_LRU_LOAD_UNLOAD)
    return rdMaterial_LoadEntry_Common(mat_fpath, material, create_ddraw_surface, gpu_mem, /*!openjkdf2_bIsExtraLowMemoryPlatform*/0);
#else
    return rdMaterial_LoadEntry_Common(mat_fpath, material, create_ddraw_surface, gpu_mem, 1);
#endif
}

int rdMaterial_LoadEntry_Deferred(rdMaterial *material, int create_ddraw_surface, int gpu_mem, int partial)
{
    // Added: No nullptr derefs
    if (!material) {
        return 0;
    }

    int res = 1;
#if defined(RDMATERIAL_LRU_LOAD_UNLOAD)
    char tmp[256+1];
    if (material->bDataLoaded) {
        return 1;
    }

#ifdef STDPLATFORM_HEAP_SUGGESTIONS
    int prevSuggest = pSithHS->suggestHeap(HEAP_SLOW);
#endif
    int prevId = material->id;
    int prevCelIdx = material->celIdx;
#if 0
    int prevRefCnt = material->refcnt;
#endif

    stdString_SafeStrCopy(tmp, material->mat_full_fpath, sizeof(tmp));
    rdMaterial_FreeEntry(material);
    //stdPlatform_Printf("rdMaterial_LoadEntry_Deferred %s\n", tmp);
    //_memset(material, 0, sizeof(rdMaterial));
    res = rdMaterial_LoadEntry_Common(tmp, material, create_ddraw_surface, gpu_mem, partial ? 2 : 1);
    if (!material->bDataLoaded || (!res && partial)) {
        rdMaterial_FreeEntry(material);
        if (rdMaterial_PurgeMaterialCache()) {
            res = rdMaterial_LoadEntry_Common(tmp, material, create_ddraw_surface, gpu_mem, partial ? 2 : 1);
            if (!res && !partial) {
                rdMaterial_FreeEntry(material);
                rdMaterial_LoadEntry_Common(tmp, material, create_ddraw_surface, gpu_mem, 0);
            }
        }
    }
    material->id = prevId;
    material->celIdx = prevCelIdx;
#if 0
    material->refcnt = prevRefCnt;
#endif

#ifdef STDPLATFORM_HEAP_SUGGESTIONS
    pSithHS->suggestHeap(prevSuggest);
#endif

    //if (material->bDataLoaded) {
        rdMaterial_UpdateFrameCount(material);
    //}

#ifdef TARGET_TWL
    //stdPlatform_PrintHeapStats();
#endif
#endif
    return res;
}

void rdMaterial_Free(rdMaterial *material)
{
    if (!material)
        return;

#if 0
    material->refcnt--;
    if (material->refcnt) {
        return;
    }
#endif

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
    if (!material) {
        return;
    }
    //stdPlatform_Printf("OpenJKDF2: rdMaterial_FreeEntry %s\n", material->mat_fpath);

    // Added
    rdMaterial_ResetCacheInfo(material);

    for (size_t i = 0; i < material->num_texinfo; i++)
    {
        rdTexinfo* texinfo = material->texinfos[i];

        // Added: nullptr check
        if (texinfo) {

            // Added: be extra sure this stuff is freed
            rdTexture* pTex = texinfo->texture_ptr;

            if (pTex) {
                for (size_t j = 0; j < pTex->num_mipmaps; j++)
                {
                    rdDDrawSurface* surface = &pTex->alphaMats[j];

#if defined(SDL2_RENDER) || defined(TARGET_TWL)
                    if (surface->texture_loaded) {
                        stdPlatform_Printf("OpenJKDF2: rdMaterial_FreeEntry %s %x\n", material->mat_fpath, surface->texture_id);
                        std3D_PurgeSurfaceRefs(&pTex->alphaMats[j]);
                        std3D_PurgeSurfaceRefs(&pTex->opaqueMats[j]);
                        pTex->alphaMats[j].texture_id = 0;
                        pTex->alphaMats[j].texture_loaded = 0;
                        pTex->alphaMats[j].frameNum = 0;
                        pTex->opaqueMats[j].texture_id = 0;
                        pTex->opaqueMats[j].texture_loaded = 0;
                        pTex->opaqueMats[j].frameNum = 0;
                    }
#if defined(TARGET_CAN_JKGM)
                    jkgm_free_cache_entry(surface->cache_entry);
#endif
#endif
                    if (pTex->texture_struct[j]) { // Added
                        stdDisplay_VBufferFree(pTex->texture_struct[j]);
                        pTex->texture_struct[j] = NULL; // Added
                    }
                }
            }
            
            texinfo->texture_ptr = NULL; // Added

            rdroid_pHS->free(texinfo);
        }

        // Added:
        material->texinfos[i] = NULL;
    }

    for (size_t i = 0; i < material->num_textures; i++)
    {
        if (!material->textures) break;

        rdTexture* pTex = &material->textures[i];

        for (size_t j = 0; j < pTex->num_mipmaps; j++)
        {
            rdDDrawSurface* surface = &pTex->alphaMats[j];

#if defined(SDL2_RENDER) || defined(TARGET_TWL)
            if (surface->texture_loaded) {
                stdPlatform_Printf("OpenJKDF2: rdMaterial_FreeEntry %s %x\n", material->mat_fpath, surface->texture_id);
                std3D_PurgeSurfaceRefs(&pTex->alphaMats[j]);
                std3D_PurgeSurfaceRefs(&pTex->opaqueMats[j]);
                pTex->alphaMats[j].texture_id = 0;
                pTex->alphaMats[j].texture_loaded = 0;
                pTex->alphaMats[j].frameNum = 0;
                pTex->opaqueMats[j].texture_id = 0;
                pTex->opaqueMats[j].texture_loaded = 0;
                pTex->opaqueMats[j].frameNum = 0;
            }
#if defined(TARGET_CAN_JKGM)
            jkgm_free_cache_entry(surface->cache_entry);
#endif
#endif
            if (pTex->texture_struct[j]) { // Added
                stdDisplay_VBufferFree(pTex->texture_struct[j]);
                pTex->texture_struct[j] = NULL; // Added
            }
            
        }
    }

    if (material->textures) {
        rdroid_pHS->free(material->textures);

        // Added
        material->textures = NULL;
    }

    // Added: nullptr check, removed type check
    if (/*(material->tex_type & 1) &&*/ material->palette_alloc) {
        rdroid_pHS->free(material->palette_alloc);

        // Added
        material->palette_alloc = NULL;
    }

#if defined(RDMATERIAL_LRU_LOAD_UNLOAD)
    rdMaterial_RemoveMaterialFromCacheList(material);
    material->bDataLoaded = 0;
    material->bMetadataLoaded = 0;
#endif
}

#if defined(RDMATERIAL_LRU_LOAD_UNLOAD)
static uint32_t rdMaterial_budgetFrameCount = 0;
static uint32_t rdMaterial_budgetMs = 0;
#endif

// Added
int rdMaterial_EnsureData(rdMaterial* pMaterial) {
    if (!pMaterial) {
        return 0;
    }
#if defined(RDMATERIAL_LRU_LOAD_UNLOAD)
    if (pMaterial->bDataLoaded) {
        return 1;
    }

    // Ensure that we don't stall for a ridiculous amount of time
    // if we need to load textures
    if (rdMaterial_budgetFrameCount != std3D_frameCount) {
        rdMaterial_budgetMs = 0;
        rdMaterial_budgetFrameCount = std3D_frameCount;
    }
    if (rdMaterial_budgetMs > 20) {
        return 0;
    }
    if (rdMaterial_budgetMs > 5) {
        uint32_t timeBefore = stdPlatform_GetTimeMsec();
        int res = rdMaterial_EnsureMetadata(pMaterial);
        uint32_t timeAfter = stdPlatform_GetTimeMsec();
        rdMaterial_budgetMs += timeAfter - timeBefore;
        return res;
    }

    uint32_t timeBefore = stdPlatform_GetTimeMsec();
    // Only allow trying to load data once per frame
    if (!pMaterial->bDataLoaded && (pMaterial->frameNum != std3D_frameCount && std3D_frameCount != 1)) {
        rdMaterial_LoadEntry_Deferred(pMaterial, 1, 1, 0);
    }
    uint32_t timeAfter = stdPlatform_GetTimeMsec();
    rdMaterial_budgetMs += timeAfter - timeBefore;
#endif
    return 1;
}

int rdMaterial_EnsureDataForced(rdMaterial* pMaterial) {
    if (!pMaterial) {
        return 0;
    }
#if defined(RDMATERIAL_LRU_LOAD_UNLOAD)
    // Only allow trying to load data once per frame
    if (!pMaterial->bDataLoaded) {
        if (!rdMaterial_LoadEntry_Deferred(pMaterial, 1, 1, 0)) {
            rdMaterial_PurgeEntireMaterialCache();
            rdMaterial_LoadEntry_Deferred(pMaterial, 1, 1, 0);
        }
    }
#endif
    return 1;
}

// Added
int rdMaterial_EnsureMetadata(rdMaterial* pMaterial) {
    if (!pMaterial) {
        return 0;
    }
#if defined(RDMATERIAL_LRU_LOAD_UNLOAD)
    if (pMaterial->bDataLoaded) {
        return 1;
    }
    // Only allow trying to load data once per frame
    if (!pMaterial->bMetadataLoaded) {
        //int prev_std3D_frameCount = std3D_frameCount;
        //std3D_frameCount = 1;
        rdMaterial_LoadEntry_Deferred(pMaterial, 1, 1, 1);
        //std3D_frameCount = prev_std3D_frameCount;
    }
#endif
    return 1;
}

// Added
void rdMaterial_OptionalFree(rdMaterial* pMaterial) {
    if (!pMaterial) return;
#ifdef TARGET_TWL
    //if (openjkdf2_bIsExtraLowMemoryPlatform) {
        rdMaterial_FreeEntry(pMaterial);
    //}
#endif
}

// rdMaterial_Write
extern int std3D_loadedTexturesAmt;
// Added: cel_idx
int rdMaterial_AddToTextureCache(rdMaterial *pMaterial, rdTexture *texture, int mipmap_level, int no_alpha, int cel_idx)
{
#if defined(RDMATERIAL_LRU_LOAD_UNLOAD)
    //if (pMaterial->bDataLoaded) {
        rdMaterial_UpdateFrameCount(pMaterial);
    //}
#endif
    stdVBuffer* mipmap = texture->texture_struct[mipmap_level];

#ifdef SDL2_RENDER
    if (mipmap) {
        mipmap->palette = pMaterial->palette_alloc;
    }
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
#if defined(TARGET_CAN_JKGM)
        else if (jkgm_std3D_AddToTextureCache(mipmap, surface, texture->alpha_en & 1, no_alpha, pMaterial, cel_idx))
        {
            //printf("rdmat Init %s %x %x\n", pMaterial->mat_fpath, surface->texture_id, std3D_loadedTexturesAmt);
            return 1;
        }
#endif
#endif
        else if (std3D_AddToTextureCache(mipmap, surface, texture->alpha_en & 1, no_alpha))
        {
            //printf("rdmat Init %s %x %x\n", pMaterial->mat_fpath, surface->texture_id, std3D_loadedTexturesAmt);
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
#if defined(TARGET_CAN_JKGM)
        else if (jkgm_std3D_AddToTextureCache(mipmap, surface, texture->alpha_en & 1, no_alpha, pMaterial, cel_idx))
        {
            //printf("rdmat Init %s %x %x\n", pMaterial->mat_fpath, surface->texture_id, std3D_loadedTexturesAmt);
            return 1;
        }
#endif
#endif
        else if (std3D_AddToTextureCache(mipmap, surface, texture->alpha_en & 1, 0))
        {
            //printf("rdmat Init %s %x %x\n", pMaterial->mat_fpath, surface->texture_id, std3D_loadedTexturesAmt);
            return 1;
        }
        return 0;
    }
}

// TODO verify behavior in here
void rdMaterial_ResetCacheInfo(rdMaterial *pMaterial)
{
    // Added
    if (!pMaterial) {
        return;
    }
    
    //printf("Evicting material %s\n", pMaterial->mat_full_fpath);
#ifndef SDL2_RENDER
    for (int i = 0; i < pMaterial->num_textures; i++)
    {
        if (!pMaterial->textures) {
            break;
        }
        rdTexture* texIter = &pMaterial->textures[i];
        for (int j = 0; j < texIter->num_mipmaps; j++)
        {
#if defined(SDL2_RENDER) || defined(TARGET_TWL)
            std3D_PurgeSurfaceRefs(&texIter->alphaMats[j]);
            std3D_PurgeSurfaceRefs(&texIter->opaqueMats[j]);
#endif
            texIter->alphaMats[j].texture_id = 0;
            texIter->alphaMats[j].texture_loaded = 0;
            texIter->alphaMats[j].frameNum = 0;
            texIter->opaqueMats[j].texture_id = 0;
            texIter->opaqueMats[j].texture_loaded = 0;
            texIter->opaqueMats[j].frameNum = 0;
        }
    }
#endif

#if defined(RDMATERIAL_LRU_LOAD_UNLOAD)
    rdMaterial_EvictData(pMaterial);
    rdMaterial_RemoveMaterialFromCacheList(pMaterial);
#endif
}

#if defined(RDMATERIAL_LRU_LOAD_UNLOAD)

void rdMaterial_EvictData(rdMaterial *pMaterial)
{
    if (!pMaterial) {
        return;
    }
    if (!pMaterial->bDataLoaded) {
        return;
    }

    for (size_t i = 0; i < pMaterial->num_textures; i++)
    {
        if (!pMaterial->textures) break;

        rdTexture* pTex = &pMaterial->textures[i];

        for (size_t j = 0; j < pTex->num_mipmaps; j++)
        {
            rdDDrawSurface* matIter = &pTex->alphaMats[j];
            std3D_PurgeSurfaceRefs(matIter);
            std3D_PurgeSurfaceRefs(&matIter[4]);
            matIter->texture_loaded = 0;
            matIter->frameNum = 0;
            matIter[4].texture_loaded = 0;
            matIter[4].frameNum = 0;

            if (pTex->texture_struct[j]) {
                printf("Evicting material %s fr %d\n", pMaterial->mat_full_fpath, rdMaterial_numCachedMaterials);
                stdDisplay_VBufferFree(pTex->texture_struct[j]);
                pTex->texture_struct[j] = NULL;
            }
        }
    }

    //
    // Make sure there's no dangling references to any textures
    //
    if (pMaterial->textures) {
        rdroid_pHS->free(pMaterial->textures);

        // Added
        pMaterial->textures = NULL;
    }

    if (/*(material->tex_type & 1) &&*/ pMaterial->palette_alloc) {
        rdroid_pHS->free(pMaterial->palette_alloc);

        // Added
        pMaterial->palette_alloc = NULL;
    }

    for (size_t i = 0; i < pMaterial->num_texinfo; i++)
    {
        if (pMaterial->texinfos[i]) {
            rdTexinfo* texinfo = pMaterial->texinfos[i];
            
            texinfo->texture_ptr = NULL;
        }
    }

    pMaterial->bDataLoaded = 0;
    //pMaterial->bMetadataLoaded = 0;
}

// Derived from https://github.com/smlu/OpenJones3D/blob/main/Libs/std/Win95/std3D.c
void rdMaterial_UpdateFrameCount(rdMaterial *pMaterial) {
    if (!pMaterial) {
        return;
    }

    rdMaterial_RemoveMaterialFromCacheList(pMaterial);
    rdMaterial_AddMaterialToCacheList(pMaterial);
}

void rdMaterial_RemoveMaterialFromCacheList(rdMaterial *pCacheMaterial) {
    if (!pCacheMaterial) {
        return;
    }

    if (!pCacheMaterial->frameNum) {
        return;
    }

    if ( pCacheMaterial == rdMaterial_pFirstMatCache )
    {
        rdMaterial_pFirstMatCache = pCacheMaterial->pNextCachedMaterial;
        if ( rdMaterial_pFirstMatCache )
        {
            rdMaterial_pFirstMatCache->pPrevCachedMaterial = NULL;
            if ( !rdMaterial_pFirstMatCache->pNextCachedMaterial ) {
                rdMaterial_pLastMatCache = rdMaterial_pFirstMatCache;
            }
        }
        else {
            rdMaterial_pLastMatCache = NULL;
        }
    }
    else if ( pCacheMaterial == rdMaterial_pLastMatCache )
    {
        rdMaterial_pLastMatCache = pCacheMaterial->pPrevCachedMaterial;
        if (pCacheMaterial->pPrevCachedMaterial)
            pCacheMaterial->pPrevCachedMaterial->pNextCachedMaterial = NULL;
        else
            rdMaterial_pLastMatCache = rdMaterial_pFirstMatCache;
    }
    else
    {
        if (pCacheMaterial->pPrevCachedMaterial)
            pCacheMaterial->pPrevCachedMaterial->pNextCachedMaterial = pCacheMaterial->pNextCachedMaterial;
        if (pCacheMaterial->pNextCachedMaterial)
            pCacheMaterial->pNextCachedMaterial->pPrevCachedMaterial = pCacheMaterial->pPrevCachedMaterial;
    }

    pCacheMaterial->pNextCachedMaterial = NULL;
    pCacheMaterial->pPrevCachedMaterial = NULL;
    pCacheMaterial->frameNum = 0;

    --rdMaterial_numCachedMaterials;
}

void rdMaterial_AddMaterialToCacheList(rdMaterial *pMaterial) {
    if (!pMaterial) {
        return;
    }

    if (pMaterial->frameNum) {
        return;
    }

    if ( rdMaterial_pFirstMatCache )
    {
        rdMaterial_pLastMatCache->pNextCachedMaterial = pMaterial;
        pMaterial->pPrevCachedMaterial            = rdMaterial_pLastMatCache;
        pMaterial->pNextCachedMaterial            = NULL;
        rdMaterial_pLastMatCache                = pMaterial;
    }
    else
    {
        rdMaterial_pLastMatCache          = pMaterial;
        rdMaterial_pFirstMatCache         = pMaterial;
        pMaterial->pPrevCachedMaterial = NULL;
        pMaterial->pNextCachedMaterial = NULL;
    }

    if (!std3D_frameCount) {
        std3D_frameCount = 1;
    }

    ++rdMaterial_numCachedMaterials;
    pMaterial->frameNum = std3D_frameCount;
}

int rdMaterial_PurgeMaterialCache()
{
    //printf("Purge mat... %d\n", rdMaterial_numCachedMaterials);

    // TODO: maybe be gentler here and have like, a 60 frame buffer

    int purgedAnything = 0;
    rdMaterial* pNextCachedMaterial = NULL;
    for ( rdMaterial* pCacheMaterial = rdMaterial_pFirstMatCache; pCacheMaterial; pCacheMaterial = pNextCachedMaterial )
    {
        pNextCachedMaterial = pCacheMaterial->pNextCachedMaterial;

        // On DSi, we can't purge the current frame nor the previous, because the previous is being rastered constantly by the hardware
        if (!(pCacheMaterial->frameNum == std3D_frameCount || pCacheMaterial->frameNum == std3D_frameCount-1))
        {
            purgedAnything = 1;
            
            rdMaterial_ResetCacheInfo(pCacheMaterial);
            //std3D_PurgeSurfaceRefs(pCacheMaterial);
        }
    }

#ifdef TARGET_TWL
    if (purgedAnything) {
        stdPlatform_PrintHeapStats();
    }
#endif

    return purgedAnything;
}

int rdMaterial_PurgeEntireMaterialCache()
{
    int res = 0;

    // HACK but whatever lol
    int prev_std3D_frameCount = std3D_frameCount;
    std3D_frameCount = 0;
    res = rdMaterial_PurgeMaterialCache();
    std3D_frameCount = prev_std3D_frameCount;

    rdMaterial_numCachedMaterials = 0;
    rdMaterial_pLastMatCache          = NULL;
    rdMaterial_pFirstMatCache         = NULL;
        

    return res;
}

#endif // defined(RDMATERIAL_LRU_LOAD_UNLOAD)
