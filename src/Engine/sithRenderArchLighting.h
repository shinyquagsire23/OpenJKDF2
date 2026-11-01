#ifndef SITHRENDER_ARCH_LIGHTING_H
#define SITHRENDER_ARCH_LIGHTING_H

/* Internal draw scope. Types, allocator and renderer declarations are supplied
 * by sithRender.c. Keep small draws on the stack; retain larger buffers between
 * draws instead of allocating/freeing once per visible model per frame. */
typedef struct SithRenderMeshLightBinding {
    rdMesh* mesh;
    flex_t* mono;
    flex_t* red;
    flex_t* green;
    flex_t* blue;
} SithRenderMeshLightBinding;

typedef struct SithRenderArchBuffer {
    struct SithRenderArchBuffer* next;
    size_t capacity;
    int inUse;
    SithRenderMeshLightBinding bindings[];
} SithRenderArchBuffer;

static SithRenderArchBuffer* sithRender_archBuffers;

static SithRenderArchBuffer* sithRender_AcquireArchBuffer(size_t count)
{
    SithRenderArchBuffer** grow = NULL;
    for (SithRenderArchBuffer** slot = &sithRender_archBuffers; *slot; slot = &(*slot)->next) {
        SithRenderArchBuffer* buffer = *slot;
        if (buffer->inUse) continue;
        if (buffer->capacity >= count) {
            buffer->inUse = 1;
            return buffer;
        }
        grow = slot;
    }
    if (count > (SIZE_MAX - sizeof(SithRenderArchBuffer)) / sizeof(SithRenderMeshLightBinding)) return NULL;
    SithRenderArchBuffer* buffer = (SithRenderArchBuffer*)SITH_ALLOC(
        sizeof(*buffer) + count * sizeof(buffer->bindings[0]));
    if (!buffer) return NULL;
    buffer->capacity = count;
    buffer->inUse = 1;
    if (grow) {
        SithRenderArchBuffer* old = *grow;
        buffer->next = old->next;
        *grow = buffer;
        SITH_FREE(old);
    }
    else {
        buffer->next = sithRender_archBuffers;
        sithRender_archBuffers = buffer;
    }
    return buffer;
}

static void sithRender_FreeArchLightingBuffers(void)
{
    for (SithRenderArchBuffer** slot = &sithRender_archBuffers; *slot;) {
        SithRenderArchBuffer* buffer = *slot;
        /* A nested callback must not invalidate an enclosing draw's snapshot. */
        if (buffer->inUse) { slot = &buffer->next; continue; }
        *slot = buffer->next;
        SITH_FREE(buffer);
    }
}

/* Model arrays belong to the shared 3DO; ARCH arrays belong to the world.
 * Preserve arbitrary bindings and leave dynamic-light scratch separately owned. */
static int sithRender_DrawLevelGeometryThing(SithThing* thing)
{
    if (thing->renderData.type != RD_THING_MODEL3) return sithRender_RenderThing(thing);
    rdModel3* model = thing->renderData.model3;
    SithWorld* world = sithWorld_g_pCurrentWorld;
    sithArchLight* arch = NULL;
    size_t meshCount = 0;
    if (!model || model->numGeos > 4) return 0;
    for (uint32_t geo = 0; geo < model->numGeos; ++geo) {
        rdGeoset* geoset = &model->aGeos[geo];
        if (geoset->numMeshes && !geoset->aMeshes) return 0;
        if (geoset->numMeshes > SIZE_MAX / sizeof(SithRenderMeshLightBinding) - meshCount) return 0;
        meshCount += geoset->numMeshes;
    }
    if (thing->archlightIdx >= 0 && thing->archlightIdx < world->numArchLights && world->aArchlights) {
        arch = &world->aArchlights[thing->archlightIdx];
        if (arch->numMeshes < 0 || (arch->numMeshes && !arch->aMeshes)) arch = NULL;
    }
    /* Every LOD uses the same ARCH mesh slots; a lower LOD may use a vertex prefix. */
    for (uint32_t geo = 0; arch && geo < model->numGeos; ++geo) {
        rdGeoset* geoset = &model->aGeos[geo];
        if (geoset->numMeshes > (uint32_t)arch->numMeshes) { arch = NULL; break; }
        for (uint32_t j = 0; j < geoset->numMeshes; ++j) {
            rdMesh* mesh = &geoset->aMeshes[j];
            sithArchLightMesh* light = &arch->aMeshes[j];
            if (mesh->numVertices < 0 || light->numVertices < mesh->numVertices
                || (mesh->numVertices && (!light->aMono || !light->aRed || !light->aGreen || !light->aBlue))) {
                arch = NULL;
                break;
            }
        }
    }
    int rgb = rdGetVertexColorMode() == 1;
    if (!meshCount || (!arch && !rgb)) return sithRender_RenderThing(thing);
    SithRenderMeshLightBinding local[32];
    SithRenderMeshLightBinding* saved = local;
    SithRenderArchBuffer* overflow = NULL;
    if (meshCount > sizeof(local) / sizeof(local[0])) {
        overflow = sithRender_AcquireArchBuffer(meshCount);
        if (!overflow) return 0; /* Fail before changing any model binding. */
        saved = overflow->bindings;
    }
    size_t slot = 0;
    for (uint32_t geo = 0; geo < model->numGeos; ++geo) {
        rdGeoset* geoset = &model->aGeos[geo];
        for (uint32_t j = 0; j < geoset->numMeshes; ++j) {
            rdMesh* mesh = &geoset->aMeshes[j];
            saved[slot++] = (SithRenderMeshLightBinding){mesh, mesh->vertices_i,
                mesh->paRedIntensities, mesh->paGreenIntensities, mesh->paBlueIntensities};
            if (!rgb) mesh->vertices_i = arch->aMeshes[j].aMono;
            else {
                mesh->paRedIntensities = arch ? arch->aMeshes[j].aRed : mesh->vertices_i;
                mesh->paGreenIntensities = arch ? arch->aMeshes[j].aGreen : mesh->vertices_i;
                mesh->paBlueIntensities = arch ? arch->aMeshes[j].aBlue : mesh->vertices_i;
            }
        }
    }
    int result = sithRender_RenderThing(thing);
    for (size_t j = 0; j < meshCount; ++j) {
        rdMesh* mesh = saved[j].mesh;
        mesh->vertices_i = saved[j].mono;
        mesh->paRedIntensities = saved[j].red;
        mesh->paGreenIntensities = saved[j].green;
        mesh->paBlueIntensities = saved[j].blue;
    }
    if (overflow) overflow->inUse = 0;
    return result;
}

#endif
