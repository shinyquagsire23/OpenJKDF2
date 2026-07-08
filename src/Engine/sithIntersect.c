#include "sithIntersect.h"

#include <math.h>

#include "General/stdMath.h"
#include "World/sithSurface.h"
#include "Raster/rdFace.h"
#include "World/sithSector.h"
#include "World/sithWorld.h"
#include "World/sithThing.h"
#include "Engine/sithCollision.h"
#include "Primitives/rdMath.h"
#include "jk.h"

extern int sithCollision_bDebugCollide;

static rdVector2i sithIntersect_unkArr[3] = {
    {2, 1},
    {0, 2},
    {1, 0},
};

// Added
int sithIntersect_IsSphereInSectorBox(const rdVector3 *pos, flex_t radius, SithSector *sector)
{
    // Added
    if (!sector)
        return 0;

    if ( (sector->flags & SITH_SECTOR_HASCOLLIDEBOX) != 0
      && pos->z - radius > sector->collidebox_onecorner.z
      && pos->y - radius > sector->collidebox_onecorner.y
      && pos->x - radius > sector->collidebox_onecorner.x
      && pos->x + radius < sector->collidebox_othercorner.x
      && radius + pos->y < sector->collidebox_othercorner.y
      && radius + pos->z < sector->collidebox_othercorner.z )
    {
        return 1;
    }

    return 0;
}

//sithIntersect_sub_507EA0

int sithIntersect_IsSphereInSector(const rdVector3 *pos, flex_t radius, SithSector *sector)
{
    rdVector3 *v7; // ebp
    flex_t v8; // st7
    
    // Added
    if (!sector)
        return 0;

    if ( (sector->flags & SITH_SECTOR_HASCOLLIDEBOX) != 0
      && pos->z - radius > sector->collidebox_onecorner.z
      && pos->y - radius > sector->collidebox_onecorner.y
      && pos->x - radius > sector->collidebox_onecorner.x
      && pos->x + radius < sector->collidebox_othercorner.x
      && radius + pos->y < sector->collidebox_othercorner.y
      && radius + pos->z < sector->collidebox_othercorner.z )
    {
        return 1;
    }

    for (int i = 0; i < sector->numSurfaces; i++)
    {
        SithSurface* surface = &sector->surfaces[i];
        SithSurfaceAdjoin* pAdjoin = surface->pAdjoin;
        if ( (surface->flags & SITH_SURFACE_HAS_COLLISION)
            || (pAdjoin && pAdjoin->flags & SITHSURF_ADJOIN_ALLOW_MOVEMENT) )
        {
            v7 = sithWorld_g_pCurrentWorld->aVertices;
            v8 = stdMath_ClipNearZero(rdMath_DistancePointToPlane(pos, &surface->surfaceInfo.face.normal, &v7[*surface->surfaceInfo.face.vertexPosIdx]));
            if ( v8 < radius )
                return 0;
        }
    }
    return 1;
}

// sithIntersect_CheckFaceVerticesIntersection

int sithIntersect_CheckSphereThingIntersection(SithThing *pThing, const rdVector3 *startPos, const rdVector3 *moveNorm, flex_t moveDist, flex_t radius, SithThing *pCheck, int colflags, flex_t *pHitDistance, rdMesh **ppHitMesh, rdFace **ppHitFace, rdVector3 *hitNorm)
{
    SithThing *v11; // edi
    int result; // eax
    rdVector3 *v26; // ebp
    rdGeoset *v27; // esi
    int v28; // ebx
    int v30; // edi
    int v31; // eax
    int bFaceCollision; // [esp+10h] [ebp-4Ch]
    rdVector3 dirVec; // [esp+14h] [ebp-48h] BYREF
    rdVector3 posVec; // [esp+20h] [ebp-3Ch] BYREF
    rdMatrix34 out; // [esp+2Ch] [ebp-30h] BYREF
    uint32_t thinga; // [esp+60h] [ebp+4h]
    rdMatrix34 *a2a; // [esp+64h] [ebp+8h]
    int v39; // [esp+68h] [ebp+Ch]

    v11 = pCheck;
    bFaceCollision = 0;
    if ( (colflags & RAYCAST_80) == 0 && (pCheck->collide == SITH_COLLIDE_FACE || pThing && pThing->collide == SITH_COLLIDE_FACE) )
    {
        bFaceCollision = 1;
    }

    // MoTS added: New collision type: tree intersection (one sphere per mesh)
    int bIsTreeCollide = 0;
    flex_t collideSize = pCheck->collideSize;
    flex_t rangeSize = radius;
    if (Main_bMotsCompat) {
        if (!(colflags & 0x80u) && (pCheck->collide == SITH_COLLIDE_SPHERE_TREE || pThing && pThing->collide == SITH_COLLIDE_SPHERE_TREE) ) {
            bFaceCollision = 1;
            bIsTreeCollide = 1;
            if (pCheck->collide == SITH_COLLIDE_SPHERE_TREE) {
              collideSize = pCheck->treeSize;
            }
            else {
              rangeSize = pThing->treeSize;
              collideSize = radius;
            }
        }
    }

    flex_t unkOut;
    if (!sithIntersect_CheckSphereIntersection(startPos, moveNorm, moveDist, rangeSize, &pCheck->position, collideSize, &unkOut, bFaceCollision, colflags))
    {
        return 0;
    }

    if (!bFaceCollision && MOTS_ONLY_COND(!bIsTreeCollide))
    {
        rdVector_Sub3(hitNorm, startPos, &pCheck->position);
        rdVector_ScaleAdd3Acc(hitNorm, moveNorm, unkOut);
        rdVector_Normalize3Acc(hitNorm);
        *pHitDistance = unkOut;
        return SITHCOLLISION_THING;
    }

    if (pCheck->collide == SITH_COLLIDE_FACE || MOTS_ONLY_FLAG(pCheck->collide == SITH_COLLIDE_SPHERE_TREE))
    {
        rdVector_Copy3(&dirVec, moveNorm);
        rdVector_Copy3(&posVec, startPos);
        v39 = 0;
    }
    else
    {
        v11 = pThing;
        radius = pCheck->collideSize;
        rdVector_Neg3(&dirVec, moveNorm);
        rdVector_Copy3(&posVec, &pCheck->position);
        v39 = 1;
    }

    if (MOTS_ONLY_FLAG(bIsTreeCollide))
    {
        flex_t tmp = 3.4e+38;
        rdVector3 tmpVec;
        rdVector_Zero3(&tmpVec); // Added

        int iVar11 = sithIntersect_TreeIntersection(v11->renderData.model3->aHierarchyNodes, &posVec, &dirVec, moveDist, radius, v11, &tmp, &tmpVec, colflags);
        if (iVar11 == 0) {
            return 0;
        }

        rdVector_Copy3(hitNorm, &posVec);
        rdVector_ScaleAdd3Acc(hitNorm, &dirVec, tmp);
        rdVector_Sub3Acc(hitNorm, &tmpVec);
        rdVector_Normalize3Acc(hitNorm);
        
        if (v39) {
            rdVector_Neg3Acc(hitNorm);
        }
        *pHitDistance = tmp;
        return 1;
    }

    rdVector_Copy3(&v11->orient.scale, &v11->position);
    a2a = &v11->orient;
    rdMatrix_InvertOrtho34(&out, &v11->orient);
    rdMatrix_TransformPoint34Acc(&posVec, &out);
    rdMatrix_TransformVector34Acc(&dirVec, &out);
    v26 = hitNorm;
    v27 = v11->renderData.model3->aGeos;
    v28 = 0;
    v30 = 0;
    //printf("aaaaa %f %f %f\n", dirVec.x, dirVec.y, dirVec.z);
    for (thinga = 0; thinga < v27->numMeshes; thinga++)
    {
        v31 = sithIntersect_CheckSphereMeshIntersection(&posVec, &dirVec, moveDist, radius, &v27->aMeshes[v30], pHitDistance, ppHitFace, v26);
        if ( v31 )
        {
            v28 = v31;
            *ppHitMesh = &v27->aMeshes[v30];
            moveDist = *pHitDistance;
        }
        ++v30;
    }
    if ( v28 )
    {
        rdMatrix_TransformVector34Acc(v26, a2a);
        if ( v39 )
        {
            rdVector_Neg3Acc(v26);
        }
        v28 |= SITHCOLLISION_THING;
    }
    return v28;
}

// MoTS added: Tree collision (one sphere per mesh)
int sithIntersect_TreeIntersection(rdHierarchyNode *paNodes,rdVector3 *pPoseVec,rdVector3 *pDirVec,flex_t a4,flex_t range, SithThing *v11,flex_t *pOut,rdVector3 *pOutVec,int raycastFlags)
{
    rdModel3 *prVar1;
    int iVar2;
    uint32_t uVar3;
    rdHierarchyNode *pChildNode;
    int ret;
    flex_t local_74;
    flex_t local_70;
    rdVector3 local_6c;
    rdMatrix34 local_60;
    rdMatrix34 local_30;

    uVar3 = paNodes->meshIdx;
    ret = 0;
    if (uVar3 != 0xffffffff) {
        rdMatrix_Copy34(&local_60, &v11->orient);
        rdVector_Copy3(&local_60.scale, &v11->position);
        rdModel3_GetMeshMatrix(&v11->renderData, &local_60, uVar3, &local_30);
        rdVector_Copy3(&local_6c, &local_30.scale);
        prVar1 = v11->renderData.model3;
        uVar3 = (v11->renderData).geosetSelect;
        if (uVar3 == 0xffffffff) {
            uVar3 = prVar1->geosetSelect;
        }
        local_70 = prVar1->aGeos[uVar3].aMeshes[paNodes->meshIdx].radius * 0.75;
        iVar2 = sithIntersect_CheckSphereIntersection(pPoseVec, pDirVec, a4, range, &local_6c, local_70, &local_74, 1, raycastFlags);
        if ((iVar2 != 0) && (local_74 < *pOut)) {
            *pOut = local_74;
            rdVector_Copy3(pOutVec, &local_6c);
            ret = 1;
        }
    }

    if (paNodes->numChildren != 0) {
        pChildNode = paNodes->child;
        uint32_t local_70_2 = 0;
        do
        {
            if (((v11->renderData).paJointAmputationFlags[pChildNode->idx] == 0) &&
               (iVar2 = sithIntersect_TreeIntersection(pChildNode, pPoseVec, pDirVec, a4, range, v11, pOut, pOutVec, raycastFlags),
               iVar2 != 0)) {
                ret = 1;
            }
            pChildNode = pChildNode->nextSibling;
            local_70_2++;
        }
        while (local_70_2 < paNodes->numChildren);
    }
    return ret;
}

// sithIntersect_sub_508370

// This handles collisions with non-spherical world thing objects
// ie, tables and such
int sithIntersect_CheckSphereMeshIntersection(rdVector3 *startPos, rdVector3 *moveNorm, flex_t moveDistance, flex_t radius, rdMesh *pMesh, flex_t *hitDist, rdFace **ppHitFace, rdVector3 *hitNorm)
{
    int v11; // ecx
    rdFace *v12; // edx
    int v24; // [esp+8h] [ebp-18h]
    flex_t v25; // [esp+Ch] [ebp-14h]
    int v26; // [esp+10h] [ebp-10h]
    rdVector3 pushVel; // [esp+14h] [ebp-Ch] BYREF

    v24 = 0;
    v25 = 1.0;
    for (v26 = 0; v26 < pMesh->numFaces; v26++)
    {
        v11 = sithIntersect_CheckSphereFaceIntersectionEx(startPos, moveNorm, moveDistance, radius, &pMesh->faces[v26], pMesh->aVertices, hitDist, &pushVel, 0);
        if ( v11
          && (*hitDist < (flex_d_t)moveDistance
           || v24 != SITHCOLLISION_THINGADJOINCROSS && v11 == SITHCOLLISION_THINGADJOINCROSS
           || rdVector_Dot3(moveNorm, &pMesh->faces[v26].normal) < v25) )
        {
            //printf("%f %f %f\n", pushVel.x, pushVel.y, pushVel.z);
            v12 = &pMesh->faces[v26];
            v24 = v11;
            rdVector_Copy3(hitNorm, &pushVel);
            moveDistance = *hitDist;
            v25 = rdVector_Dot3(moveNorm, &v12->normal);
            *ppHitFace = v12;
        }
    }

    //if (v24 & 0x18)
    //printf("%x %f %f %f, %f %f %f\n", v24, pStartPos->x, pStartPos->y, pStartPos->z, pRayDirection->x, pRayDirection->y, pRayDirection->z);

    return v24;
}

// ChatGPT says:
// int sithIntersect_sub_508540(const rdVector3 *startPoint, const rdVector3 *rayDirection, flex_t maxDistance, flex_t sphereRadius, rdVector3 *intersectionPoint, flex_t collisionRadius, flex_t *distance, int bFaceCollision, int raycastFlags)
// "raySphereIntersection"
int sithIntersect_CheckSphereIntersection(const rdVector3 *startPos, const rdVector3 *moveNorm, flex_t moveDist, flex_t radius, rdVector3 *endPos, flex_t size, flex_t *hitDistance, int bCheckEndPos, int colflags)
{
    flex_d_t v15; // st7
    flex_d_t v16; // rtt
    flex_d_t v17; // st4
    flex_d_t v18; // st5
    flex_d_t v20; // rtt
    flex_d_t v21; // st6
    flex_d_t v22; // st7
    flex_d_t v24; // st7
    flex_t v33; // [esp+20h] [ebp+14h]
    rdVector3 tmp;

    rdVector_Sub3(&tmp, endPos, startPos);
    v33 = size + radius;
    if ( moveDist == 0.0 )
    {
LABEL_11:
        v24 = rdVector_Len3(&tmp);
        if ( v24 < v33 )
        {
            if ( (colflags & RAYCAST_400) != 0 )
            {
                *hitDistance = v24;
                return 1;
            }
            else
            {
                *hitDistance = 0.0;
                return 1;
            }
        }
        return 0;
    }
    v15 = rdVector_Dot3(moveNorm, &tmp); // rdMath_DistancePointToPlane(pSpherePos, pRayDirection, pStartPos);
    if ( v15 < 0.0 || v15 > v33 + moveDist )
    {
        if ( !bCheckEndPos )
            return 0;
        goto LABEL_11;
    }

    rdVector3 tmp2, tmp3;
    rdVector_Copy3(&tmp2, endPos);
    rdVector_Copy3(&tmp3, startPos);
    rdVector_ScaleAdd3Acc(&tmp3, moveNorm, v15);

    v21 = rdVector_Dist3(&tmp2, &tmp3);
    if ( v21 >= v33 )
        return 0;
    v22 = v15 - stdMath_Sqrt(v33 * v33 - v21 * v21);
    if ( v22 > moveDist || v22 < 0.0 )
    {
        *hitDistance = 0.0;
        return 1;
    }
    else
    {
        *hitDistance = v22;
        return 1;
    }
}

// ChatGPT says:
// int checkIntersectionWithFace(rdVector3 *intersectionPoint, flex_t radius, rdFace *pFace, rdVector3 *aVertices, int *intersectionType)
int sithIntersect_TestSphereFaceHit(rdVector3 *startPos, flex_t radius, rdFace *pFace, rdVector3 *aVertices, int *pHitMask)
{
    flex_d_t v10; // st7
    int v12; // edx
    int v13; // ebx
    int v14; // ebp
    int v16; // edx
    flex_d_t v17; // st7
    int v18; // eax
    int *v19; // ecx
    int v21; // edi
    int v23; // edx
    flex_d_t v25; // [esp+10h] [ebp-20h]
    int v26; // [esp+10h] [ebp-20h]
    flex_d_t v27; // [esp+14h] [ebp-1Ch]
    int v28; // [esp+14h] [ebp-1Ch]
    rdVector2 a1a; // [esp+18h] [ebp-18h] BYREF
    flex_d_t v30; // [esp+20h] [ebp-10h]
    flex_d_t v31; // [esp+24h] [ebp-Ch]
    flex_d_t v32; // [esp+28h] [ebp-8h]
    flex_d_t v33; // [esp+2Ch] [ebp-4h]
    int v34; // [esp+34h] [ebp+4h]

    //if (sithCollision_bDebugCollide)
    //printf("?? %f, %f %f %f, %f %f %f, %f %f %f\n", radius, a1->x, a1->y, a1->z, a4->x, a4->y, a4->z, pFace->normal.x, pFace->normal.y, pFace->normal.z);

    if ( pHitMask )
        *pHitMask = 0;
    v25 = stdMath_Fabs(pFace->normal.x);
    v27 = stdMath_Fabs(pFace->normal.y);
    v10 = stdMath_Fabs(pFace->normal.z);

    if ( v25 <= (flex_d_t)v27 )
    {
        if ( v27 > v10 )
        {
            v12 = 1;
        }
        else
        {
            v12 = 2;
        }
    }
    else if ( v25 > v10 )
    {
        v12 = 0;
    }
    else
    {
        v12 = 2;
    }

    if ( *(&pFace->normal.x + v12) <= 0.0 )
    {
        v13 = sithIntersect_unkArr[v12].y;
        v14 = sithIntersect_unkArr[v12].x;
    }
    else
    {
        v13 = sithIntersect_unkArr[v12].x;
        v14 = sithIntersect_unkArr[v12].y;
    }
    v16 = 0;
    v28 = v14;
    v34 = 1;
    v32 = *(&startPos->x + v13);
    v17 = *(&startPos->x + v14);
    v18 = pFace->numVertices;
    v33 = v17;
    v26 = v18;
    if ( v18 > 0 )
    {
        while ( 1 )
        {
            v19 = pFace->vertexPosIdx;
            v21 = v16 + 1;
            v23 = (v16 + 1) % v26;
            a1a.x = -*(&aVertices[v19[v16]].x + v13);
            a1a.y = -*(&aVertices[v19[v16]].x + v14);
            v30 = a1a.x + v32;
            v31 = a1a.y + v33;
            v14 = v28;
            a1a.x += *(&aVertices[v19[v23]].x + v13);
            a1a.y += *(&aVertices[v19[v23]].x + v28);
            flex_t idk = v30 * a1a.y - v31 * a1a.x;//stdMath_ClipNearZero(); // Added at some point?
            if ( idk < 0.0 )
            {
                if ( radius == 0.0 )
                    return 0;
                if ( !pHitMask )
                    return 0;
                rdVector_Normalize2Acc(&a1a);
                flex_t idk2 = v30 * a1a.y - v31 * a1a.x;
                
                // TODO: Somehow we need to return 0 here for slopes which match our current normal?

                if ( -radius > idk2 )
                    return 0;
                *pHitMask |= v34;
            }
            v16 = v21;
            v34 *= 2;
            if ( v21 >= v26 )
                return 1;
        }
    }
    return 1;
}


// This does something with whether something is a step vs barrier?
// return 0 allows jumping up on high ledges
int sithIntersect_CheckSphereFaceHitVerticesIntersection(rdVector3 *startPos, flex_t radius, rdFace *pFace, rdVector3 *aVertices, int vertHitMask, rdVector3 *pHitPos)
{
    rdFace *v6; // ecx
    unsigned int v7; // edi
    unsigned int v8; // ebx
    int *v10; // ecx
    int v11; // eax
    rdVector3 *v14; // esi
    rdVector3 *v15; // edi
    flex_d_t v16; // st7
    //char v18; // c0
    int v19; // ecx
    flex_d_t v24; // st6
    flex_t v27; // [esp+4h] [ebp-2Ch]
    int i; // [esp+8h] [ebp-28h]
    rdVector3 v29; // [esp+Ch] [ebp-24h]
    rdVector3 a1a; // [esp+18h] [ebp-18h] BYREF
    flex_t v34; // [esp+34h] [ebp+4h]

    v6 = pFace;
    v7 = pFace->numVertices;
    v8 = 0;
    v27 = radius - -1.0;
    for ( i = 0; v8 < v7; v7 = pFace->numVertices )
    {
        if ( !vertHitMask )
            break;
        if ( (vertHitMask & 1) != 0 )
        {
            v10 = v6->vertexPosIdx;
            v11 = v10[v8];
            v14 = &aVertices[v11];
            v15 = &aVertices[v10[(v8 + 1) % v7]];
            rdVector_Sub3(&a1a, v15, v14);
            v16 = rdVector_Normalize3Acc(&a1a);

            v34 = rdMath_DistancePointToPlane(startPos, &a1a, &aVertices[v10[v8]]);
            if ( -radius <= v34 && v34 - radius <= v16 )
            {
                v19 = SITHCOLLISION_THINGTOUCH;
                if ( v34 >= 0.0 )
                {
                    if ( v34 <= (flex_d_t)v16 )
                    {
                        rdVector_Copy3(&v29, v14);
                        
                        // projected point
                        rdVector_ScaleAdd3Acc(&v29, &a1a, v34);
                        v19 = SITHCOLLISION_THINGCROSS;
                    }
                    else
                    {
                        v29 = *v15;
                    }
                }
                else
                {
                    v29 = *v14;
                }
                v24 = rdVector_Dist3(startPos, &v29);
                if ( v24 <= radius && v24 < v27 )
                {
                    i = v19;
                    v27 = v24;
                    if ( pHitPos )
                        *pHitPos = v29;
                }
            }
        }
        ++v8;
        vertHitMask = (unsigned int)vertHitMask >> 1;
        v6 = pFace;
    }
    return i;
}

// Used for floor collision, probably everything tbh
int sithIntersect_CheckSphereHit(const rdVector3 *startPos, const rdVector3 *moveNorm, flex_t moveDistance, flex_t radius, rdVector3 *normal, rdVector3 *point, flex_t *pSphereHitDist, int colflags)
{
    flex_d_t v8; // st7
    flex_d_t v13; // st7
    flex_t v18; // [esp+18h] [ebp+18h]

    v8 = rdMath_DistancePointToPlane(startPos, normal, point);
    v8 = stdMath_ClipNearZero(v8);
    if ( v8 < 0.0 )
        return 0;

    v13 = v8 - radius;
    if ( v13 > moveDistance )
        return 0;

    v18 = -rdVector_Dot3(moveNorm, normal);
    if ( v13 < 0.0 )
    {
        if ( (colflags & RAYCAST_400) != 0 )
            *pSphereHitDist += radius;
        else
            *pSphereHitDist = 0.0;
        return 1;
    }
    else if ( v18 > 0.0 )
    {
        if ( v18 * moveDistance >= v13 )
        {
            *pSphereHitDist = v13 / v18;
            if ( *pSphereHitDist < 0.0 )
                *pSphereHitDist = 0.0;
            return 1;
        }
        else
        {
            return 0;
        }
    }
    else
    {
        return 0;
    }
}

// ChatGPT says: rayPlaneIntersection
int sithIntersect_CheckSphereFaceIntersectionEx(const rdVector3 *startPos, const rdVector3 *moveNorm, flex_t moveDistance, flex_t radius, rdFace *pFace, rdVector3 *aVertices, flex_t *hitDist, rdVector3 *hitNorm, int colflags)
{
    int result; // eax
    int *v18; // edx
    flex_d_t v21; // st7
    flex_d_t v25; // st7
    int v28; // esi
    flex_t v35; // edi
    int *v36; // edx
    flex_d_t v37; // st7
    rdVector3 v45; // [esp+10h] [ebp-18h] BYREF
    rdVector3 projected; // [esp+1Ch] [ebp-Ch] BYREF

    result = sithIntersect_CheckSphereHit(startPos, moveNorm, moveDistance, radius, &pFace->normal, &aVertices[*pFace->vertexPosIdx], hitDist, colflags);
    if ( result )
    {
        if ( (colflags & RAYCAST_400) != 0 || rdVector_Dot3(moveNorm, &pFace->normal) < 0.0 )
        {
            if ( *hitDist == 0.0 )
            {
                v36 = pFace->vertexPosIdx;
                rdVector_Copy3(&v45, startPos);
                v37 = rdMath_DistancePointToPlane(&v45, &pFace->normal, &aVertices[*v36]);
                v37 = stdMath_ClipNearZero(v37);
                if ( v37 != 0.0 )
                {
                    rdVector_ScaleAdd3Acc(&v45, &pFace->normal, -v37);
                }
            }
            else
            {
                rdVector_Scale3(&v45, moveNorm, *hitDist);
                v18 = pFace->vertexPosIdx;
                rdVector_Add3Acc(&v45, startPos);
                v21 = rdMath_DistancePointToPlane(&v45, &pFace->normal, &aVertices[*v18]);
                v21 = stdMath_ClipNearZero(v21);
                if ( v21 != 0.0 )
                {
                    v25 = -v21;
                    rdVector_ScaleAdd3Acc(&v45, &pFace->normal, v25);
                }
            }
            if ( hitNorm )
            {
                int tmp;
                if ( sithIntersect_TestSphereFaceHit(&v45, radius, pFace, aVertices, &tmp) )
                {
                    if ( tmp )
                        v28 = sithIntersect_CheckSphereFaceHitVerticesIntersection(&v45, radius, pFace, aVertices, tmp, &projected);
                    else
                        v28 = SITHCOLLISION_THINGADJOINCROSS;
                }
                else
                {
                    v28 = 0;
                }
                if ( v28 == SITHCOLLISION_THINGCROSS || v28 == SITHCOLLISION_THINGTOUCH )
                {
                    rdVector_Sub3(hitNorm, startPos, &projected);
                    rdVector_Normalize3Acc(hitNorm);
                    result = v28;
                }
                else
                {
                    rdVector_Copy3(hitNorm, &pFace->normal);
                    result = v28;
                }
            }
            else
            {
                v35 = radius;
                int tmp;
                if ( sithIntersect_TestSphereFaceHit(&v45, radius, pFace, aVertices, &tmp) )
                {
                    if ( tmp )
                        result = sithIntersect_CheckSphereFaceHitVerticesIntersection(&v45, v35, pFace, aVertices, tmp, 0);
                    else
                        result = SITHCOLLISION_THINGADJOINCROSS;
                }
                else
                {
                    result = 0;
                }
            }
        }
        else
        {
            result = 0;
        }
    }

    rdVector3 outSafe = {0};
    if (!hitNorm)
        hitNorm = &outSafe;
    //if (result)
    //    stdPlatform_Printf("%x: %f %f %f, %f %f %f, %f %f %f\n", result, pStartPos->x, pStartPos->y, pStartPos->z, pRayDirection->x, pRayDirection->y, pRayDirection->z, pPushVelOut->x, pPushVelOut->y, pPushVelOut->z);
    //rdVector_Scale3Acc(pPushVelOut, 0.05);
    return result;
}

// Seems to handle interaction when crossing adjoins?
int sithIntersect_CheckSphereFaceIntersection(const rdVector3 *startPos, const rdVector3 *moveNorm, flex_t moveDistance, flex_t radius, sithSurfaceInfo *pFace, rdVector3 *aVertices, flex_t *hitDist, int flags)
{
    sithSurfaceInfo *v8; // edi
    int result; // eax
    rdVector3 v15; // [esp+10h] [ebp-Ch] BYREF

    v8 = pFace;
    result = sithIntersect_CheckSphereHit(startPos, moveNorm, moveDistance, radius, &pFace->face.normal, &aVertices[*pFace->face.vertexPosIdx], hitDist, flags);
    if ( result )
    {
        if ( radius == 0.0 )
        {
            rdVector_Copy3(&v15, startPos);
            rdVector_ScaleAdd3Acc(&v15, moveNorm, *hitDist);
            
            int tmp = 0;
            result = sithIntersect_TestSphereFaceHit(&v15, radius, &v8->face, aVertices, &tmp);
            if ( result )
            {
                if ( !tmp)
                    return SITHCOLLISION_THINGADJOINCROSS;
                else
                    return sithIntersect_CheckSphereFaceHitVerticesIntersection(&v15, radius, &v8->face, aVertices, tmp, 0);
            }
        }
        else
        {
            return SITHCOLLISION_THINGADJOINCROSS;
        }
    }
    return 0;
}

int sithIntersect_CheckFaceVerticesIntersection(rdVector3 *startPos, flex_t radius, rdFace *pFace, rdVector3 *aVertices, rdVector3 *pHitPos)
{
    int side = 0;
    int result = sithIntersect_TestSphereFaceHit(startPos, radius, pFace, aVertices, &side);
    if ( !result )
        return 0;
    if ( side == 0 )
        return 4;
    return sithIntersect_CheckSphereFaceHitVerticesIntersection(startPos, radius, pFace, aVertices, side, pHitPos);
}

// sub_507EA0 and sub_508370 need struct offset verification before implementation.
// Both iterate mesh faces/aGeos calling SphereHit/sub_508400.
// Ghidra decompilation available but struct layout depends on conditional compilation.
