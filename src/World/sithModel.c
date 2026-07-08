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

int sithModel_ReadStaticModelsListText(SithWorld *pWorld, int bSkip)
{
    int sizeModels;
    flex_t loadStep;
    flex_t loadProgress;

    if ( bSkip )
        return 0;
    stdConffile_ReadArgs();
    if ( _memcmp(stdConffile_g_entry.aArgs[0].value, "world", 6u) || _memcmp(stdConffile_g_entry.aArgs[1].value, "models", 7u) )
        return 0;
    pWorld->sizeModels = _atoi(stdConffile_g_entry.aArgs[2].value);
    if ( !pWorld->sizeModels )
        return 1;

    pWorld->aModels = (rdModel3 *)SITH_ALLOC(sizeof(rdModel3) * pWorld->sizeModels);
    if ( !pWorld->aModels )
    {
        stdPrintf(pSithHS->errorPrint, ".\\World\\sithModel.c", 164, "Memory error while reading models, line %d.\n", stdConffile_linenum, 0, 0, 0);
        return 0;
    }
    pWorld->numModels = 0;
    _memset(pWorld->aModels, 0, sizeof(rdModel3) * pWorld->sizeModels);

    sithWorld_UpdateLoadProgress(60.0);
    loadStep = 10.0 / (flex_d_t)pWorld->sizeModels;
    loadProgress = 60.0;
    while ( stdConffile_ReadArgs() )
    {
        if ( !_memcmp(stdConffile_g_entry.aArgs[0].value, "end", 4u) )
            break;
        sithModel_Load(stdConffile_g_entry.aArgs[1].value, 0);
        loadProgress = loadProgress + loadStep;
        sithWorld_UpdateLoadProgress(loadProgress);
    }
    sithWorld_UpdateLoadProgress(70.0);

    return 1;
}

void sithModel_FreeWorldModels(SithWorld *pWorld)
{
    if (!pWorld->sizeModels )
        return;

    for (int i = 0; i < pWorld->numModels; i++)
    {
        stdHashtbl_Remove(sithModel_hashtable, pWorld->aModels[i].filename);
        rdModel3_FreeEntryGeometryOnly(&pWorld->aModels[i]);
    }
    SITH_FREE(pWorld->aModels);
    pWorld->aModels = 0;
    pWorld->numModels = 0;
    pWorld->sizeModels = 0;
}

rdModel3* sithModel_Load(const char *pName, int bSkipDefault)
{
    rdModel3 *model;
    char model_fpath[128];

    model = (rdModel3 *)stdHashtbl_Find(sithModel_hashtable, pName);
    if ( model ) {
        //stdPlatform_Printf("OpenJKDF2: %s: Load %s from static jkl.\n", __func__, model_3do_fname); // Added
        return model;
    }

    if ( sithWorld_g_pLastLoadedWorld->numModels >= sithWorld_g_pLastLoadedWorld->sizeModels ) {
        stdPlatform_Printf("OpenJKDF2: %s: Too many models already loaded!\n", __func__); // Added
        return 0;
    }
    model = &sithWorld_g_pLastLoadedWorld->aModels[sithWorld_g_pLastLoadedWorld->numModels];

    _sprintf(model_fpath, "%s%c%s", "3do", '\\', pName);
    if ( !rdModel3_LoadEntry(model_fpath, model) )
    {
        if ( !bSkipDefault ) {
            stdPlatform_Printf("OpenJKDF2: %s: rdModel3_LoadEntry failed for `%s`, loading dflt.3do!\n", __func__, pName); // Added
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

uint32_t sithModel_GetModelMemUsage(rdModel3 *pModel)
{
    unsigned int result; // eax
    rdGeoset *v2; // ebx
    int v3; // edi
    rdMesh* v4; // edx
    int v5; // esi
    rdFace* v6; // ecx
    int modela; // [esp+8h] [ebp+4h]

    result = (sizeof(void*) * pModel->sizeMaterials) + (sizeof(rdHierarchyNode) * pModel->numHNodes) + sizeof(rdModel3);
    if ( pModel->numGeos )
    {
        v2 = pModel->aGeos;
        modela = pModel->numGeos;
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

int sithModel_AllocWorldModels(SithWorld *pWorld, int size)
{
    pWorld->aModels = (rdModel3 *)SITH_ALLOC(sizeof(rdModel3) * size);
    if ( !pWorld->aModels )
        return 0;

    pWorld->sizeModels = size;
    pWorld->numModels = 0;
    _memset(pWorld->aModels, 0, sizeof(rdModel3) * size);

    return 1;
}

rdModel3* sithModel_GetModelByIndex(int modelIdx)
{
    SithWorld *world;
    rdModel3 *result;

    world = sithWorld_g_pCurrentWorld;
    if ( (modelIdx & 0x8000) != 0 )
    {
        world = sithWorld_g_pStaticWorld;
        modelIdx &= 0x7FFF;
    }
    if ( world && modelIdx >= 0 && modelIdx < world->numModels )
        return &world->aModels[modelIdx];

    return NULL;
}
