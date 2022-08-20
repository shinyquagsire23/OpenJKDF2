#ifndef _RDMATERIAL_H
#define _RDMATERIAL_H

#include "types.h"
#include "globals.h"
#include "Win95/stdVBuffer.h"

#define rdMaterial_RegisterLoader_ADDR (0x0044A110)
#define rdMaterial_RegisterUnloader_ADDR (0x0044A120)
#define rdMaterial_Load_ADDR (0x0044A130)
#define rdMaterial_LoadEntry_ADDR (0x0044A260)
#define rdMaterial_Free_ADDR (0x0044A690)
#define rdMaterial_FreeEntry_ADDR (0x0044A770)
#define rdMaterial_Write_ADDR (0x0044A830)
#define rdMaterial_AddToTextureCache_ADDR (0x0044AA70)
#define rdMaterial_ResetCacheInfo_ADDR (0x0044AB20)

rdMaterialLoader_t rdMaterial_RegisterLoader(rdMaterialLoader_t load);
rdMaterialUnloader_t rdMaterial_RegisterUnloader(rdMaterialUnloader_t unload);
rdMaterial* rdMaterial_Load(char *material_fname, int create_ddraw_surface, int gpu_memory);
int rdMaterial_LoadEntry(char *mat_fpath, rdMaterial *material, int create_ddraw_surface, int gpu_mem);
void rdMaterial_Free(rdMaterial *material);
void rdMaterial_FreeEntry(rdMaterial* material);
int rdMaterial_AddToTextureCache(rdMaterial *material, rdTexture *texture, int mipmap_level, int no_alpha);
void rdMaterial_ResetCacheInfo(rdMaterial *material);
//static int (*rdMaterial_AddToTextureCache)(rdMaterial *material, rdTexture *a2, int mipmap_level, int no_alpha) = (void*)rdMaterial_AddToTextureCache_ADDR;
//static void (*rdMaterial_ResetCacheInfo)(rdMaterial *material) = (void*)rdMaterial_ResetCacheInfo_ADDR;

//int rdMaterial_AddToTextureCache(rdMaterial *material, sith_tex *a2, int mipmap_level, int no_alpha);


#endif // _RDMATERIAL_H
