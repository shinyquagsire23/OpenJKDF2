#include "rdThing.h"

#include "stdPlatform.h" // Added: *_ALLOC/*_FREE macros

#include "Engine/rdroid.h"
#include "Engine/rdPuppet.h"
#include "Primitives/rdMatrix.h"

rdThing* rdThing_New(SithThing *pThing)
{
    rdThing *thing;

    thing = (rdThing*)RDROID_ALLOC(sizeof(rdThing));
    if ( !thing )
    {
        RDLOG_ERROR("Error allocating memory for thing.\n"); // Added: J3D log
        return 0;
    }
    rdThing_NewEntry(thing, pThing);
    return thing;
}

int rdThing_NewEntry(rdThing *prdThing, SithThing *pThing)
{
    prdThing->model3 = 0;
    prdThing->type = 0;
    prdThing->puppet = 0;
    prdThing->field_18 = 0;
    prdThing->rdFrameNum = 0;
    prdThing->geosetSelect = -1;
    prdThing->wallCel = -1;
    prdThing->paJointMatrices = 0;
    prdThing->desiredGeoMode = RD_GEOMETRY_FULL;
    prdThing->desiredLightMode = RD_LIGHTMODE_GOURAUD;
    prdThing->desiredTexMode = RD_TEXTUREMODE_2_UNK;
    prdThing->curGeoMode = RD_GEOMETRY_FULL;
    prdThing->curLightMode = RD_LIGHTMODE_GOURAUD;
    prdThing->curTexMode = RD_TEXTUREMODE_2_UNK;
    prdThing->pThing = pThing;
    return 1;
}

void rdThing_Free(rdThing *pThing)
{
    if ( pThing )
    {
        rdThing_FreeEntry(pThing);
        RDROID_FREE(pThing);
    }
}

void rdThing_FreeEntry(rdThing *pThing)
{
    if (pThing->type == RD_THING_MODEL3)
    {
        if ( pThing->paJointMatrices )
        {
            RDROID_FREE(pThing->paJointMatrices);
            pThing->paJointMatrices = 0;
        }
        if ( pThing->hierarchyNodes2 )
        {
            RDROID_FREE((void *)pThing->hierarchyNodes2); // Possible OOB write in this
            pThing->hierarchyNodes2 = 0;
        }
        if ( pThing->paJointAmputationFlags )
        {
            RDROID_FREE(pThing->paJointAmputationFlags);
            pThing->paJointAmputationFlags = 0;
        }
    }
    if ( pThing->puppet )
    {
        rdPuppet_Free(pThing->puppet);
        pThing->puppet = 0;
    }
}

int rdThing_SetModel3(rdThing *thing, rdModel3 *model)
{
    RD_ASSERTREL(thing != NULL); // Added: J3D assert
    RD_ASSERTREL(model != NULL); // Added: J3D assert
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
    {
        RDLOG_ERROR("Error allocating memory for joint amputation flags.\n"); // Added: J3D log
        return 0;
    }

    stdPlatform_Memzero32(thing->paJointAmputationFlags, sizeof(int) * model->numHNodes); // Added: word-safe

    rdHierarchyNode* iter = model->aHierarchyNodes;
    for (int i = 0; i < model->numHNodes; i++)
    {
        rdMatrix_Build34(&iter->posRotMatrix, &iter->rot, &iter->pos);
        iter++;
    }
    return 1;
}

int rdThing_SetCamera(rdThing *pThing, rdCamera *pCamera)
{
    RD_ASSERTREL(pThing != NULL); // Added: J3D assert
    pThing->type = RD_THINGTYPE_CAMERA;
    pThing->camera = pCamera;
    return 1;
}

int rdThing_SetLight(rdThing *pThing, rdLight *pLight)
{
    RD_ASSERTREL(pThing != NULL); // Added: J3D assert
    pThing->type = RD_THINGTYPE_LIGHT;
    pThing->light = pLight;
    return 1;
}

int rdThing_SetSprite3(rdThing *thing, rdSprite *sprite)
{
    RD_ASSERTREL(thing != NULL); // Added: J3D assert
    thing->type = RD_THING_SPRITE3;
    thing->sprite3 = sprite;
    thing->wallCel = -1;
    return 1;
}

int rdThing_SetPolyline(rdThing *pThing, rdPolyline *pPolyline)
{
    RD_ASSERTREL(pThing != NULL); // Added: J3D assert
    pThing->type = RD_THING_POLYLINE;
    pThing->polyline = pPolyline;
    pThing->wallCel = -1;
    return 1;
}

int rdThing_SetParticleCloud(rdThing *pThing, rdParticle *pParticle)
{
    RD_ASSERTREL(pThing != NULL); // Added: J3D assert
    pThing->type = RD_THING_PARTICLE;
    pThing->particlecloud = pParticle;
    return 1;
}

int rdThing_Draw(rdThing *pThing, rdMatrix34 *pOrient)
{
    RD_ASSERTREL(pThing); // Added: J3D assert
    if (!rdroid_g_curGeometryMode)
        return 0;

    switch ( pThing->type )
    {
        case RD_THING_NONE:
        case RD_THINGTYPE_CAMERA:
        case RD_THINGTYPE_LIGHT:
            return 0;
        case RD_THING_MODEL3:
            return rdModel3_Draw(pThing, pOrient);
        case RD_THING_SPRITE3:
            return rdSprite_Draw(pThing, pOrient);
        case RD_THING_PARTICLE:
            return rdParticle_Draw(pThing, pOrient);
        case RD_THING_POLYLINE:
            return rdPolyline_Draw(pThing, pOrient);
    }
    
    // aaaaaaaaaaaaaaaaaa original game returns undefined for other types, this is to replicate that
    return (intptr_t)pThing;
}

void rdThing_AccumulateMatrices(rdThing *pThing, rdHierarchyNode *pNode, rdMatrix34 *pPlacement)
{
    rdHierarchyNode *childIter;
    rdVector3 negPivot;
    rdMatrix34 matrix;

    rdMatrix_BuildTranslate34(&matrix, &pNode->pivot);
    rdMatrix_PostMultiply34(&matrix, &pThing->paJointMatrices[pNode->idx]);
    if ( pNode->parent )
    {
        rdVector_Neg3(&negPivot, &pNode->parent->pivot);
        rdMatrix_PostTranslate34(&matrix, &negPivot);
    }
    rdMatrix_Multiply34(&pThing->paJointMatrices[pNode->idx], pPlacement, &matrix);
    if (!pNode->numChildren)
        return;
    
    childIter = pNode->child;
    for (int i = 0; i < pNode->numChildren; i++)
    {
        if ( !pThing->paJointAmputationFlags[childIter->idx] )
            rdThing_AccumulateMatrices(pThing, childIter, &pThing->paJointMatrices[pNode->idx]);
        childIter = childIter->nextSibling;
    }
}
