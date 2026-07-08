#include "sithModel.h"

#include "Primitives/rdModel3.h"
#include "Engine/rdroid.h"
#include "World/sithWorld.h"
#include "General/stdConffile.h"
#include "stdPlatform.h"
#include "jk.h"

static tHashTable* sithModel_hashtable;

int sithModel_Startup()
{
    sithModel_hashtable = stdHashtbl_New(256);
    return sithModel_hashtable != 0;
}

void sithModel_Shutdown()
{
    if ( sithModel_hashtable )
    {
        stdHashtbl_Free(sithModel_hashtable);
        sithModel_hashtable = 0;
    }
}

int sithModel_ReadStaticModelsListText(SithWorld *world, int a2)
{
    int sizeModels;
    flex_t loadStep;
    flex_t loadProgress;

    if ( a2 )
        return 0;
    stdConffile_ReadArgs();
    if ( _memcmp(stdConffile_g_entry.args[0].value, "world", 6u) || _memcmp(stdConffile_g_entry.args[1].value, "aModels", 7u) )
        return 0;
    world->sizeModels = _atoi(stdConffile_g_entry.args[2].value);
    if ( !world->sizeModels )
        return 1;

    world->aModels = (rdModel3 *)SITH_ALLOC(sizeof(rdModel3) * world->sizeModels);
    if ( !world->aModels )
    {
        stdPrintf(pSithHS->errorPrint, ".\\World\\sithModel.c", 164, "Memory error while reading aModels, line %d.\n", stdConffile_linenum, 0, 0, 0);
        return 0;
    }
    world->numModels = 0;
    _memset(world->aModels, 0, sizeof(rdModel3) * world->sizeModels);

    sithWorld_UpdateLoadProgress(60.0);
    loadStep = 10.0 / (flex_d_t)world->sizeModels;
    loadProgress = 60.0;
    while ( stdConffile_ReadArgs() )
    {
        if ( !_memcmp(stdConffile_g_entry.args[0].value, "end", 4u) )
            break;
        sithModel_Load(stdConffile_g_entry.args[1].value, 0);
        loadProgress = loadProgress + loadStep;
        sithWorld_UpdateLoadProgress(loadProgress);
    }
    sithWorld_UpdateLoadProgress(70.0);

    return 1;
}

void sithModel_FreeWorldModels(SithWorld *world)
{
    if (!world->sizeModels )
        return;

    for (int i = 0; i < world->numModels; i++)
    {
        stdHashtbl_Remove(sithModel_hashtable, world->aModels[i].filename);
        rdModel3_FreeEntryGeometryOnly(&world->aModels[i]);
    }
    SITH_FREE(world->aModels);
    world->aModels = 0;
    world->numModels = 0;
    world->sizeModels = 0;
}

rdModel3* sithModel_Load(const char *model_3do_fname, int unk)
{
    rdModel3 *model;
    char model_fpath[128];

    model = (rdModel3 *)stdHashtbl_Find(sithModel_hashtable, model_3do_fname);
    if ( model ) {
        //stdPlatform_Printf("OpenJKDF2: %s: Load %s from static jkl.\n", __func__, model_3do_fname); // Added
        return model;
    }

    if ( sithWorld_g_pLastLoadedWorld->numModels >= sithWorld_g_pLastLoadedWorld->sizeModels ) {
        stdPlatform_Printf("OpenJKDF2: %s: Too many aModels already loaded!\n", __func__); // Added
        return 0;
    }
    model = &sithWorld_g_pLastLoadedWorld->aModels[sithWorld_g_pLastLoadedWorld->numModels];

    _sprintf(model_fpath, "%s%c%s", "3do", '\\', model_3do_fname);
    if ( !rdModel3_LoadEntry(model_fpath, model) )
    {
        if ( !unk ) {
            stdPlatform_Printf("OpenJKDF2: %s: rdModel3_LoadEntry failed for `%s`, loading dflt.3do!\n", __func__, model_3do_fname); // Added
            return sithModel_Load("dflt.3do", 1);
        }
        return 0;
    }
    
    model->id = sithWorld_g_pLastLoadedWorld->numModels;
    if (sithWorld_g_pLastLoadedWorld->level_type_maybe & 1)
        model->id |= 0x8000;
    
    stdHashtbl_Add(sithModel_hashtable, model->filename, model);
    sithWorld_g_pLastLoadedWorld->numModels += 1;

    return model;
}

uint32_t sithModel_GetModelMemUsage(rdModel3 *model)
{
    unsigned int result; // eax
    rdGeoset *v2; // ebx
    int v3; // edi
    rdMesh* v4; // edx
    int v5; // esi
    rdFace* v6; // ecx
    int modela; // [esp+8h] [ebp+4h]

    result = (sizeof(void*) * model->sizeMaterials) + (sizeof(rdHierarchyNode) * model->numHNodes) + sizeof(rdModel3);
    if ( model->numGeos )
    {
        v2 = model->aGeos;
        modela = model->numGeos;
        do
        {
            result += 8;
            if ( v2->numMeshes )
            {
                v3 = v2->numMeshes;
                v4 = v2->aMeshes;
                do
                {
                    v5 = v4->numFaces;
                    result += (sizeof(rdVector2) * v4->numUVs) + ((sizeof(rdVector3) + sizeof(rdVector3) + sizeof(rdVector2)) * v4->numVertices) + (sizeof(rdFace) * v4->numFaces) + sizeof(rdMesh);
                    if ( v4->numFaces )
                    {
                        v6 = v4->faces;
                        do
                        {
                            result += (sizeof(int) * 2) * v6->numVertices;
                            v6++;
                            --v5;
                        }
                        while ( v5 );
                    }
                    ++v4;
                    --v3;
                }
                while ( v3 );
            }
            ++v2;
            --modela;
        }
        while ( modela );
    }
    return result;
}

int sithModel_AllocWorldModels(SithWorld *world, int num)
{
    world->aModels = (rdModel3 *)SITH_ALLOC(sizeof(rdModel3) * num);
    if ( !world->aModels )
        return 0;

    world->sizeModels = num;
    world->numModels = 0;
    _memset(world->aModels, 0, sizeof(rdModel3) * num);

    return 1;
}

rdModel3* sithModel_GetModelByIndex(int idx)
{
    SithWorld *world;
    rdModel3 *result;

    world = sithWorld_g_pCurrentWorld;
    if ( (idx & 0x8000) != 0 )
    {
        world = sithWorld_g_pStaticWorld;
        idx &= 0x7FFF;
    }
    if ( world && idx >= 0 && idx < world->numModels )
        return &world->aModels[idx];

    return NULL;
}
