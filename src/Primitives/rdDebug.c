#include "rdDebug.h"

#include "Engine/rdroid.h"
#include "Engine/rdCamera.h"
#include "Raster/rdCache.h"
#include "Engine/rdClip.h"
#include "Primitives/rdPrimit3.h"
#include "Engine/rdColormap.h"

static rdMaterial rdDebug_solidMat = {0};
static rdTexture rdDebug_solidTex = {0};

void rdDebug_DrawScreenLine3(rdVector3* v1, rdVector3* v2, uint32_t color)
{
#ifndef SDL2_RENDER
    return;
#endif
    rdProcEntry* procEntry = rdCache_GetProcEntry();
    if (!procEntry)
        return;
    
    rdDebug_solidMat.num_texinfo = 8;
    rdDebug_solidMat.celIdx = 0;
    for (int i = 0; i < 8; i++)
    {
        rdDebug_solidMat.texinfos[i] = &rdDebug_solidTex;
    }
    
    //printf("%f %f %f, %f %f %f\n", v1->x, v1->y, v1->z, v2->x, v2->y, v2->z);
    
    int procFaceFlags = 1;
    
    procEntry->textureMode = 0;
    procEntry->geometryMode = 3;
    procEntry->lightingMode = 0;
    procEntry->light_flags = 0;
    procEntry->wallCel = 0;
    procEntry->type = 0;
    procEntry->extralight = 1.0;
    procEntry->material = &rdDebug_solidMat;
    procEntry->colormap = rdColormap_pCurMap;
    procEntry->vertexIntensities[0] = 1.0;
    procEntry->vertexIntensities[1] = 1.0;
    procEntry->vertexUVs[0].x = 1.0;
    procEntry->vertexUVs[0].y = 1.0;
    procEntry->vertexUVs[1].x = 1.0;
    procEntry->vertexUVs[1].y = 1.0;
    procEntry->vertices[0] = *v1;
    procEntry->vertices[1] = *v2;
    rdCache_AddProcFace(color, 2, procFaceFlags);
}

void rdDebug_DrawLine3(rdVector3* v1, rdVector3* v2, uint32_t color)
{
#ifndef SDL2_RENDER
    return;
#endif
    rdVector3 vertsOut[2];
    rdVector3 verts[2];
    
    verts[0] = *v1;
    verts[1] = *v2;
    
    // Clip the lines to the view frustum
    int out1, out2;
    rdClip_Line3Project(rdCamera_pCurCamera->pClipFrustum, &verts[0], &verts[1], &out1, &out2);

    // And project to screen coords
    rdCamera_pCurCamera->fnProjectLst(&vertsOut, &verts, 2);
    
    vertsOut[0].x = (float)(int)vertsOut[0].x + 0.0001;
    vertsOut[0].y = (float)(int)vertsOut[0].y + 0.0001;
    vertsOut[1].x = (float)(int)vertsOut[1].x - 0.0001;
    vertsOut[1].y = (float)(int)vertsOut[1].y - 0.0001;
    
    rdDebug_DrawScreenLine3(&vertsOut[0], &vertsOut[1], color);
}

void rdDebug_DrawBoundingBox(rdMatrix34* m, float radius, uint32_t color)
{
#ifndef SDL2_RENDER
    return;
#endif
    rdVector3 verts[8];
    
    rdVector3 v1, v2;
    rdVector3 r3 = {0.3*radius, 0.3*radius, 0.3*radius};
    rdVector_Zero3(&v1);
    rdVector_Zero3(&v2);
    rdVector_Sub3Acc(&v1, &r3);
    rdVector_Add3Acc(&v2, &r3);
    
    verts[0] = v1;
    
    verts[1] = v1;
    verts[1].x = v2.x + 0.0001;
    
    verts[2] = v1;
    verts[2].y = v2.y + 0.0001;
    
    verts[3] = v1;
    verts[3].x = v2.x - 0.0001;
    verts[3].y = v2.y - 0.0001;
    
    verts[4] = v2;
    
    verts[5] = v2;
    verts[5].x = v1.x - 0.0001;
    
    verts[6] = v2;
    verts[6].y = v1.y - 0.0001;
    
    verts[7] = v2;
    verts[7].x = v1.x + 0.0001;
    verts[7].y = v1.y + 0.0001;
    
    rdMatrix34 tmpMat;
    rdMatrix_Multiply34(&tmpMat, &rdCamera_pCurCamera->view_matrix, m);
    
    for (int i = 0; i < 8; i++)
    {
        rdMatrix_TransformPoint34Acc(&verts[i], &tmpMat);
    }
    
    rdDebug_DrawLine3(&verts[0], &verts[1], color);
    rdDebug_DrawLine3(&verts[0], &verts[2], color);
    rdDebug_DrawLine3(&verts[3], &verts[2], color);
    rdDebug_DrawLine3(&verts[3], &verts[1], color);
    
    rdDebug_DrawLine3(&verts[4], &verts[5], color);
    rdDebug_DrawLine3(&verts[4], &verts[6], color);
    rdDebug_DrawLine3(&verts[7], &verts[6], color);
    rdDebug_DrawLine3(&verts[7], &verts[5], color);
    
    rdDebug_DrawLine3(&verts[1], &verts[6], color);
    rdDebug_DrawLine3(&verts[2], &verts[5], color);
    rdDebug_DrawLine3(&verts[3], &verts[4], color);
    rdDebug_DrawLine3(&verts[0], &verts[7], color);
}
