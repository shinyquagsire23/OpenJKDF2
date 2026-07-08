#include "rdThing.h"

#include "stdPlatform.h" // Added: *_ALLOC/*_FREE macros

#include "Engine/rdroid.h"
#include "Engine/rdPuppet.h"
#include "Primitives/rdMatrix.h"

rdThing* rdThing_New(SithThing *parent)
{
    rdThing *thing;

    thing = (rdThing*)RDROID_ALLOC(sizeof(rdThing));
    if ( !thing )
        return 0;
    rdThing_NewEntry(thing, parent);
    return thing;
}

int rdThing_NewEntry(rdThing *thing, SithThing *parent)
{
    thing->model3 = 0;
    thing->type = 0;
    thing->puppet = 0;
    thing->field_18 = 0;
    thing->rdFrameNum = 0;
    thing->geosetSelect = -1;
    thing->wallCel = -1;
    thing->paJointMatrices = 0;
    thing->desiredGeoMode = RD_GEOMETRY_FULL;
    thing->desiredLightMode = RD_LIGHTMODE_GOURAUD;
    thing->desiredTexMode = RD_TEXTUREMODE_2_UNK;
    thing->curGeoMode = RD_GEOMETRY_FULL;
    thing->curLightMode = RD_LIGHTMODE_GOURAUD;
    thing->curTexMode = RD_TEXTUREMODE_2_UNK;
    thing->pThing = parent;
    return 1;
}

void rdThing_Free(rdThing *thing)
{
    if ( thing )
    {
        rdThing_FreeEntry(thing);
        RDROID_FREE(thing);
    }
}

void rdThing_FreeEntry(rdThing *thing)
{
    if (thing->type == RD_THING_MODEL3)
    {
        if ( thing->paJointMatrices )
        {
            RDROID_FREE(thing->paJointMatrices);
            thing->paJointMatrices = 0;
        }
        if ( thing->hierarchyNodes2 )
        {
            RDROID_FREE((void *)thing->hierarchyNodes2); // Possible OOB write in this
            thing->hierarchyNodes2 = 0;
        }
        if ( thing->paJointAmputationFlags )
        {
            RDROID_FREE(thing->paJointAmputationFlags);
            thing->paJointAmputationFlags = 0;
        }
    }
    if ( thing->puppet )
    {
        rdPuppet_Free(thing->puppet);
        thing->puppet = 0;
    }
}

int rdThing_SetModel3(rdThing *thing, rdModel3 *model)
{
    thing->type = RD_THING_MODEL3;
    thing->model3 = model;
    thing->geosetSelect = -1;

#ifdef STDPLATFORM_HEAP_SUGGESTIONS
    int prevSuggest = pSithHS->suggestHeap(HEAP_FAST);
#endif
    thing->paJointMatrices = (rdMatrix34*)RDROID_ALLOC(sizeof(rdMatrix34) * model->numHNodes);
#ifdef STDPLATFORM_HEAP_SUGGESTIONS
    pSithHS->suggestHeap(prevSuggest);
#endif

    // moved
    if (!thing->paJointMatrices)
        return 0;

    { TWL_EXTRAM_SUGGEST(rdroid_g_pHS); // Added: word writes only
    thing->hierarchyNodes2 = (rdVector3*)RDROID_ALLOC(sizeof(rdVector3) * model->numHNodes);
    TWL_EXTRAM_RESTORE(rdroid_g_pHS); }
    // memset used to be here??

    // thing->paJointMatrices check used to be here??
    
    if (!thing->hierarchyNodes2)
        return 0;
    
    stdPlatform_Memzero32(thing->hierarchyNodes2, sizeof(rdVector3) * model->numHNodes); // Added: word-safe

    { TWL_EXTRAM_SUGGEST(rdroid_g_pHS); // Added
    thing->paJointAmputationFlags = (int *)RDROID_ALLOC(sizeof(int) * model->numHNodes);
    TWL_EXTRAM_RESTORE(rdroid_g_pHS); }
    if (!thing->paJointAmputationFlags)
        return 0;

    stdPlatform_Memzero32(thing->paJointAmputationFlags, sizeof(int) * model->numHNodes); // Added: word-safe

    rdHierarchyNode* iter = model->aHierarchyNodes;
    for (int i = 0; i < model->numHNodes; i++)
    {
        rdMatrix_Build34(&iter->posRotMatrix, &iter->rot, &iter->pos);
        iter++;
    }
    return 1;
}

int rdThing_SetCamera(rdThing *thing, rdCamera *camera)
{
    thing->type = RD_THINGTYPE_CAMERA;
    thing->camera = camera;
    return 1;
}

int rdThing_SetLight(rdThing *thing, rdLight *light)
{
    thing->type = RD_THINGTYPE_LIGHT;
    thing->light = light;
    return 1;
}

int rdThing_SetSprite3(rdThing *thing, rdSprite *sprite)
{
    thing->type = RD_THING_SPRITE3;
    thing->sprite3 = sprite;
    thing->wallCel = -1;
    return 1;
}

int rdThing_SetPolyline(rdThing *thing, rdPolyline *polyline)
{
    thing->type = RD_THING_POLYLINE;
    thing->polyline = polyline;
    thing->wallCel = -1;
    return 1;
}

int rdThing_SetParticleCloud(rdThing *thing, rdParticle *particle)
{
    thing->type = RD_THING_PARTICLE;
    thing->particlecloud = particle;
    return 1;
}

int rdThing_Draw(rdThing *thing, rdMatrix34 *m)
{
    if (!rdroid_g_curGeometryMode)
        return 0;

    switch ( thing->type )
    {
        case RD_THING_NONE:
        case RD_THINGTYPE_CAMERA:
        case RD_THINGTYPE_LIGHT:
            return 0;
        case RD_THING_MODEL3:
            return rdModel3_Draw(thing, m);
        case RD_THING_SPRITE3:
            return rdSprite_Draw(thing, m);
        case RD_THING_PARTICLE:
            return rdParticle_Draw(thing, m);
        case RD_THING_POLYLINE:
            return rdPolyline_Draw(thing, m);
    }
    
    // aaaaaaaaaaaaaaaaaa original game returns undefined for other types, this is to replicate that
    return (intptr_t)thing;
}

void rdThing_AccumulateMatrices(rdThing *thing, rdHierarchyNode *node, rdMatrix34 *acc)
{
    rdHierarchyNode *childIter;
    rdVector3 negPivot;
    rdMatrix34 matrix;

    rdMatrix_BuildTranslate34(&matrix, &node->pivot);
    rdMatrix_PostMultiply34(&matrix, &thing->paJointMatrices[node->idx]);
    if ( node->parent )
    {
        rdVector_Neg3(&negPivot, &node->parent->pivot);
        rdMatrix_PostTranslate34(&matrix, &negPivot);
    }
    rdMatrix_Multiply34(&thing->paJointMatrices[node->idx], acc, &matrix);
    if (!node->numChildren)
        return;
    
    childIter = node->child;
    for (int i = 0; i < node->numChildren; i++)
    {
        if ( !thing->paJointAmputationFlags[childIter->idx] )
            rdThing_AccumulateMatrices(thing, childIter, &thing->paJointMatrices[node->idx]);
        childIter = childIter->nextSibling;
    }
}
