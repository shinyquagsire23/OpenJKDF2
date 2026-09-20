#include "sithModel.h"

#include "Primitives/rdModel3.h"
#include "Engine/rdroid.h"
#include "World/sithWorld.h"
#include "General/stdConffile.h"
#include "stdPlatform.h"
#include "jk.h"
#include <stdlib.h>

static tHashTable* sithModel_hashtable;

/* The injected original executable still indexes aModels directly. Only the
 * source-built engine uses overflow pages; its consumers use the accessor. */
typedef struct sithModelPage {
    struct sithModelPage *next;
    uint32_t first, count;
    rdModel3 models[];
} sithModelPage;

#ifdef NO_JK_MMAP
typedef struct sithModelWorldStore {
    struct sithModelWorldStore *next;
    SithWorld *world;
    uint32_t initialCapacity;
    sithModelPage *pages;
} sithModelWorldStore;

static sithModelWorldStore *sithModel_stores;

static sithModelWorldStore *sithModel_FindStore(SithWorld *world)
{
    for (sithModelWorldStore *store = sithModel_stores; store; store = store->next)
        if (store->world == world) return store;
    return NULL;
}
#endif

/* Internal capacity lookup also permits the next, not-yet-published slot. */
static rdModel3 *sithModel_GetSlot(SithWorld *world, uint32_t index)
{
    if (!world || !world->aModels || index >= world->sizeModels) return NULL;
#ifdef NO_JK_MMAP
    sithModelWorldStore *store = sithModel_FindStore(world);
    if (!store) return NULL;
    if (index >= store->initialCapacity) {
        for (sithModelPage *page = store->pages; page; page = page->next)
            if (index >= page->first && index - page->first < page->count)
                return &page->models[index - page->first];
        return NULL;
    }
#endif
    return &world->aModels[index];
}

static sithModelPage *sithModel_NewPage(SithWorld *world)
{
#ifdef NO_JK_MMAP
    sithModelWorldStore *store = sithModel_FindStore(world);
    if (!store || world->sizeModels >= SITHMODEL_MAX_MODELS) return NULL;
    uint32_t count = world->sizeModels < 32 ? 32 : world->sizeModels;
    if (count > SITHMODEL_MAX_MODELS - world->sizeModels)
        count = SITHMODEL_MAX_MODELS - world->sizeModels;
    sithModelPage *page = SITH_ALLOC(sizeof(*page) + sizeof(rdModel3) * count);
    if (!page) return NULL;
    _memset(page, 0, sizeof(*page) + sizeof(rdModel3) * count);
    page->first = world->sizeModels;
    page->count = count;
    return page;
#else
    (void)world;
    return NULL;
#endif
}

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

    SITH_ASSERTREL(pWorld != NULL); // Added
    SITH_ASSERTREL(pWorld->aModels == NULL); // Added
    SITH_ASSERTREL(pWorld->numModels == 0); // Added
    stdConffile_ReadArgs();
    if ( _memcmp(stdConffile_g_entry.aArgs[0].value, "world", 6u) || _memcmp(stdConffile_g_entry.aArgs[1].value, "models", 7u) )
        return 0;
    char *end;
    long declared = strtol(stdConffile_g_entry.aArgs[2].value, &end, 10);
    if (end == stdConffile_g_entry.aArgs[2].value || *end || declared < 0 || declared > SITHMODEL_MAX_MODELS)
        return 0;
    sizeModels = (int)declared;
    if (!sithModel_AllocWorldModels(pWorld, sizeModels))
    {
        stdPrintf(pSithHS->errorPrint, ".\\World\\sithModel.c", 164, "Memory error while reading models, line %d.\n", stdConffile_linenum, 0, 0, 0);
        return 0;
    }
    sithWorld_UpdateLoadProgress(60.0);
    loadStep = sizeModels ? 10.0 / (flex_d_t)sizeModels : 0;
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
    SITH_ASSERTREL(pWorld != NULL); // Added
    if (!pWorld->sizeModels )
        return;

    SITH_ASSERTREL(pWorld->aModels != NULL); // Added
    for (uint32_t i = 0; i < pWorld->numModels; i++)
    {
        rdModel3 *model = sithModel_GetWorldModelByIndex(pWorld, i);
        SITH_ASSERTREL(model != NULL);
        stdHashtbl_Remove(sithModel_hashtable, model->filename);
        rdModel3_FreeEntryGeometryOnly(model);
    }
#ifdef NO_JK_MMAP
    sithModelWorldStore **link = &sithModel_stores;
    while (*link && (*link)->world != pWorld) link = &(*link)->next;
    if (*link) {
        sithModelWorldStore *store = *link;
        *link = store->next;
        while (store->pages) {
            sithModelPage *page = store->pages;
            store->pages = page->next;
            SITH_FREE(page);
        }
        SITH_FREE(store);
    }
#endif
    SITH_FREE(pWorld->aModels);
    pWorld->aModels = 0;
    pWorld->numModels = 0;
    pWorld->sizeModels = 0;
}

rdModel3* sithModel_Load(const char *pName, int bSkipDefault)
{
    rdModel3 *model;
    sithModelPage *pendingPage = NULL;
    char model_fpath[128];

    SITH_ASSERTREL(sithWorld_g_pLastLoadedWorld != NULL); // Added
    SITH_ASSERTREL(pName != NULL); // Added
    model = (rdModel3 *)stdHashtbl_Find(sithModel_hashtable, pName);
    if ( model ) {
        //stdPlatform_Printf("OpenJKDF2: %s: Load %s from static jkl.\n", __func__, model_3do_fname); // Added
        return model;
    }

    SITH_ASSERTREL(sithWorld_g_pLastLoadedWorld->numModels <= sithWorld_g_pLastLoadedWorld->sizeModels); // Added
    if (sithWorld_g_pLastLoadedWorld->numModels < SITHMODEL_MAX_MODELS &&
        sithWorld_g_pLastLoadedWorld->numModels == sithWorld_g_pLastLoadedWorld->sizeModels)
        pendingPage = sithModel_NewPage(sithWorld_g_pLastLoadedWorld);
    if (sithWorld_g_pLastLoadedWorld->numModels >= SITHMODEL_MAX_MODELS ||
        (sithWorld_g_pLastLoadedWorld->numModels >= sithWorld_g_pLastLoadedWorld->sizeModels && !pendingPage)) {
        stdPlatform_Printf("OpenJKDF2: %s: Too many models already loaded!\n", __func__); // Added
        return 0;
    }
    model = pendingPage ? &pendingPage->models[0] :
        sithModel_GetSlot(sithWorld_g_pLastLoadedWorld, sithWorld_g_pLastLoadedWorld->numModels);
    if (!model) return NULL;

    SITH_ASSERTREL(_strlen(pName) < sizeof(model_fpath)); // Added
    _sprintf(model_fpath, "%s%c%s", "3do", '\\', pName);
    if ( !rdModel3_LoadEntry(model_fpath, model) )
    {
        if (pendingPage) SITH_FREE(pendingPage);
        if ( !bSkipDefault ) {
            stdPlatform_Printf("OpenJKDF2: %s: rdModel3_LoadEntry failed for `%s`, loading dflt.3do!\n", __func__, pName); // Added
            return sithModel_Load("dflt.3do", 1);
        }
        return 0;
    }
    
    model->id = sithWorld_g_pLastLoadedWorld->numModels;
    if (sithWorld_g_pLastLoadedWorld->level_type_maybe & 1)
        model->id |= 0x8000;
    
    if (!stdHashtbl_Add(sithModel_hashtable, model->filename, model)) {
        /* A fully loaded candidate owns geometry, while its materials remain
         * world-owned. Never publish an ID for an uncached candidate. */
        rdModel3_FreeEntryGeometryOnly(model);
        _memset(model, 0, sizeof(*model));
        if (pendingPage) SITH_FREE(pendingPage);
        return NULL;
    }
#ifdef NO_JK_MMAP
    if (pendingPage) {
        sithModelWorldStore *store = sithModel_FindStore(sithWorld_g_pLastLoadedWorld);
        pendingPage->next = store->pages;
        store->pages = pendingPage;
        sithWorld_g_pLastLoadedWorld->sizeModels += pendingPage->count;
    }
#endif
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
    if (!pWorld || size < 0 || (uint32_t)size > SITHMODEL_MAX_MODELS) return 0;
    SITH_ASSERTREL(pWorld->aModels == NULL); // Added
    if (pWorld->aModels || pWorld->numModels || pWorld->sizeModels) return 0;
#ifdef NO_JK_MMAP
    if (sithModel_FindStore(pWorld)) return 0;
    if (!size) size = 32;
#else
    if (!size) return 1;
#endif
    rdModel3 *models = SITH_ALLOC(sizeof(rdModel3) * (uint32_t)size);
    if (!models)
        return 0;
#ifdef NO_JK_MMAP
    sithModelWorldStore *store = SITH_ALLOC(sizeof(*store));
    if (!store) { SITH_FREE(models); return 0; }
    store->world = pWorld;
    store->initialCapacity = (uint32_t)size;
    store->pages = NULL;
    store->next = sithModel_stores;
    sithModel_stores = store;
#endif
    _memset(models, 0, sizeof(rdModel3) * (uint32_t)size);
    pWorld->aModels = models;
    pWorld->sizeModels = size;
    pWorld->numModels = 0;

    return 1;
}

rdModel3* sithModel_GetModelByIndex(int modelIdx)
{
    SithWorld *world;

    if (modelIdx < 0 || (uint32_t)modelIdx > 0xffffu) return NULL;
    world = sithWorld_g_pCurrentWorld;
    if ( (modelIdx & 0x8000) != 0 )
    {
        world = sithWorld_g_pStaticWorld;
        modelIdx &= 0x7FFF;
    }
    return sithModel_GetWorldModelByIndex(world, modelIdx);
}

rdModel3* sithModel_GetWorldModelByIndex(SithWorld *pWorld, int modelIdx)
{
    if (!pWorld || modelIdx < 0 || (uint32_t)modelIdx >= SITHMODEL_MAX_MODELS ||
        (uint32_t)modelIdx >= pWorld->numModels) return NULL;
    return sithModel_GetSlot(pWorld, (uint32_t)modelIdx);
}
