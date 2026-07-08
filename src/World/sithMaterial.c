#include "sithMaterial.h"

#include "stdPlatform.h" // Added: *_ALLOC/*_FREE macros

#include "General/stdHashtbl.h"
#include "General/stdString.h"
#include "General/stdFnames.h"
#include "World/sithWorld.h"
#include "Main/sithMain.h"
#include "Engine/rdMaterial.h"
#include "Platform/std3D.h"
#include "jk.h"

int sithMaterial_Startup()
{
    sithMaterial_pHashtable = stdHashtbl_New(1024);
    return sithMaterial_pHashtable != 0;
}

void sithMaterial_Shutdown()
{
    if ( sithMaterial_pHashtable )
    {
        stdHashtbl_Free(sithMaterial_pHashtable);
        sithMaterial_pHashtable = 0;
    }

    // Added
    if (sithMaterial_aMaterials) {
        SITH_FREE(sithMaterial_aMaterials);
        sithMaterial_aMaterials = NULL;
    }
}

void sithMaterial_FreeWorldMaterials(SithWorld *world)
{
    unsigned int v1; // ebx
    int v2; // edi
    void *v3; // eax

    if (!world->sizeMaterials)
        return;

    v1 = 0;
    if ( world->numMaterials )
    {
        v2 = 0;
        do
        {
            stdHashtbl_Remove(sithMaterial_pHashtable, world->aMaterials[v2].mat_fpath);
            rdMaterial_FreeEntry(&world->aMaterials[v2]);
            ++v1;
            ++v2;
        }
        while ( v1 < world->numMaterials );
    }
    SITH_FREE(world->aMaterials);
    v3 = world->materials2;
    world->aMaterials = 0;
    world->numMaterials = 0;
    SITH_FREE(v3);
    world->materials2 = 0;
}

int sithMaterial_ReadMaterialsListText(SithWorld *world, int a2)
{
    int v2; // ebx
    int result; // eax

    rdMaterial *v7; // eax
    flex_d_t v8; // st7
    char *v9; // ecx
    char *a1; // [esp+0h] [ebp-24h]
    flex_t a1a; // [esp+0h] [ebp-24h]
    flex_t v12; // [esp+14h] [ebp-10h]

    v2 = 0;
    if ( a2 && a2 != 3 )
        return 0;
    result = stdConffile_ReadLine();
    if ( result )
    {
        sithWorld_UpdateLoadProgress(5.0);
        if ( _sscanf(stdConffile_g_aLine, " world aMaterials %d", &a2) == 1 )
        {
            // Added: needed for JKE?
            a2 *= 2;

            sithMaterial_AllocWorldMaterials(world, a2);

            v12 = 45.0 / (flex_d_t)(unsigned int)a2;

            // Added: memleak. TODO: static.jkl??
            if (sithMaterial_aMaterials) {
#ifdef RDMATERIAL_LRU_LOAD_UNLOAD
                for (uint32_t i = 0; i < sithMaterial_numMaterials; i++) {
                    rdMaterial_FreeEntry(sithMaterial_aMaterials[i]);
                }
#endif
                SITH_FREE(sithMaterial_aMaterials);
                sithMaterial_aMaterials = NULL;
                sithMaterial_numMaterials = 0;
            }

            sithMaterial_aMaterials = (rdMaterial **)SITH_ALLOC(sizeof(rdMaterial*) * a2);
            if ( stdConffile_ReadArgs() )
            {
                while ( _strcmp(stdConffile_g_entry.args[0].value, "end") )
                {
                    v7 = sithMaterial_Load(stdConffile_g_entry.args[1].value, 0, 0);
                    if ( !v7 )
                        return 0;
                    a1 = stdConffile_g_entry.args[2].value;
                    sithMaterial_aMaterials[v2] = v7;
                    v8 = _atof(a1);
                    v9 = stdConffile_g_entry.args[3].value;
                    world->materials2[v2].x = v8;
                    world->materials2[v2++].y = _atof(v9);
                    a1a = (flex_d_t)(unsigned int)v2 * v12 - -5.0;
                    sithWorld_UpdateLoadProgress(a1a);
                    if ( !stdConffile_ReadArgs() )
                        break;
                }
            }
            sithMaterial_numMaterials = v2;
            sithWorld_UpdateLoadProgress(50.0);
            result = 1;
        }
        else
        {
            result = 0;
        }
    }
    return result;
}

rdMaterial* sithMaterial_Load(const char *a1, int create_ddraw_surface, int gpu_mem)
{
    SithWorld *v4; // ebp
    rdMaterial *result; // eax
    unsigned int v6; // eax
    char *v7; // edi
    rdMaterial *v8; // ebx
    int v9; // eax
    char v10; // cl
    int v11; // eax
    int v12; // ecx
    char mat_fpath[128]; // [esp+14h] [ebp-80h] BYREF
    char mat_fpath2[128];

    while ( 1 )
    {
        v4 = sithWorld_g_pLastLoadedWorld;
        result = (rdMaterial *)stdHashtbl_Find(sithMaterial_pHashtable, a1);
        if ( result )
            return result;
        v6 = v4->numMaterials;
        if ( v6 >= v4->sizeMaterials )
            return 0;
        v7 = "mat;3do\\mat";
        v8 = &v4->aMaterials[v6];
        do
        {
            v7 = stdString_CopyBetweenDelimiter(v7, mat_fpath, 128, ";");
            if ( mat_fpath[0] )
            {
                stdString_snprintf(mat_fpath2, 128, "%s%c%s", mat_fpath, 92, a1); // Added: WASM doesn't like the dst being the same as src, also sprintf -> snprintf
                if ( rdMaterial_LoadEntry(mat_fpath2, v8, create_ddraw_surface, gpu_mem) )
                {
                    v9 = 1;
                    goto LABEL_10;
                }
            }
        }
        while ( v7 );
        v9 = 0;
LABEL_10:
        if ( v9 )
        {
            stdHashtbl_Add(sithMaterial_pHashtable, v8->mat_fpath, v8);
            v10 = v4->level_type_maybe;
            v11 = v4->numMaterials;
            v8->id = v11;
            if ( (v10 & 1) != 0 )
            {
                v12 = v11 | 0x8000;
                v8->id = v12;
            }
            v4->numMaterials = v11 + 1;
            return v8;
        }
        if ( !_strcmp(a1, "dflt.mat") )
            return 0;
        a1 = "dflt.mat";
    }
}

rdMaterial* sithMaterial_GetMaterialByIndex(int idx)
{
    SithWorld *world; // ecx
    rdMaterial *result; // eax

    world = sithWorld_g_pCurrentWorld;
    if ( (idx & 0x8000) != 0 )
    {
        world = sithWorld_g_pStaticWorld;
        idx &= 0x7FFF;
    }

    if ( world && idx >= 0 && idx < world->numMaterials )
        result = &world->aMaterials[idx];
    else
        result = NULL;

    return result;
}

int sithMaterial_GetMemorySize(rdMaterial *mat)
{
    int result; // eax

    result = 32 * mat->num_texinfo + sizeof(rdTexture) * mat->num_textures + 180;
    for (int i = 0; i < mat->num_textures; i++)
    {
        for (int j = 0; j < mat->textures[i].num_mipmaps; j++)
        {
            result += mat->textures[i].texture_struct[j]->format.texture_size_in_bytes;
        }
    }
    return result;
}

rdVector2* sithMaterial_AllocWorldMaterials(SithWorld *world, int num)
{
    rdMaterial *v2; // eax
    rdVector2 *result; // eax

    // Added: needed for JKE?
    num *= 2;

    { TWL_EXTRAM_SUGGEST(pSithHS); // Added: all writers into this array are word-safe (see rdMaterial.c)
    v2 = (rdMaterial *)SITH_ALLOC(sizeof(rdMaterial) * num);
    TWL_EXTRAM_RESTORE(pSithHS); }
    world->aMaterials = v2;
    if ( !v2 )
        return 0;

    world->sizeMaterials = num;
    if ( !sithMaterial_pHashtable )
    {
        sithMaterial_pHashtable = stdHashtbl_New(1024);
        if ( !sithMaterial_pHashtable )
        {
            SITH_FREE(world->aMaterials);
            return 0;
        }
    }
    result = (rdVector2 *)SITH_ALLOC(sizeof(rdVector2) * num);
    world->materials2 = result;
    if ( !result )
        return 0;
    return result;
}

void sithMaterial_UnloadAll()
{
    unsigned int v0; // edi
    rdMaterial *i; // esi

    v0 = 0;
    for ( i = sithWorld_g_pCurrentWorld->aMaterials; v0 < sithWorld_g_pCurrentWorld->numMaterials; ++v0 )
    {
        rdMaterial_ResetCacheInfo(i++);
    }
}
