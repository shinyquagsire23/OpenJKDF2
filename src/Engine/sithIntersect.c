#include "sithIntersect.h"

#include <math.h>

#include "General/stdMath.h"
#include "Engine/sithAdjoin.h"
#include "Engine/sithSurface.h"
#include "Primitives/rdFace.h"
#include "World/sithSector.h"
#include "World/sithWorld.h"
#include "World/sithThing.h"
#include "Engine/sithCollision.h"
#include "Primitives/rdMath.h"
#include "jk.h"

static rdVector2i sithIntersect_unkArr[3] = {
    {2, 1},
    {0, 2},
    {1, 0},
};

int sithIntersect_IsSphereInSector(const rdVector3 *pos, float radius, sithSector *sector)
{
    rdVector3 *v7; // ebp
    double v8; // st7
    double v10; // st6
    
    // Added
    if (!sector)
        return 0;

    if ( (sector->flags & SITH_SECTOR_COLLIDEBOX) != 0
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
        sithSurface* surface = &sector->surfaces[i];
        sithAdjoin* adjoin = surface->adjoin;
        if ( (surface->surfaceFlags & SITH_SURFACE_HAS_COLLISION) != 0 || adjoin && (adjoin->flags & SITHSURF_ADJOIN_ALLOW_MOVEMENT) != 0 )
        {
            v7 = sithWorld_pCurrentWorld->vertices;
            v8 = stdMath_ClipPrecision(rdMath_DistancePointToPlane(pos, &surface->surfaceInfo.face.normal, &v7[*surface->surfaceInfo.face.vertexPosIdx]));
            if ( v8 < radius )
                return 0;
        }
    }
    return 1;
}

int sithIntersect_CollideThings(sithThing *thing, const rdVector3 *a2, const rdVector3 *a3, float a4, float a5, sithThing *a6, int raycastFlags, float *a8, rdMesh **outMesh, rdFace **a10, rdVector3 *a11)
{
    sithThing *v11; // edi
    int result; // eax
    rdVector3 *v26; // ebp
    rdGeoset *v27; // esi
    int v28; // ebx
    float *v29; // ebx
    int v30; // edi
    int v31; // eax
    int bFaceCollision; // [esp+10h] [ebp-4Ch]
    rdVector3 dirVec; // [esp+14h] [ebp-48h] BYREF
    rdVector3 posVec; // [esp+20h] [ebp-3Ch] BYREF
    rdMatrix34 out; // [esp+2Ch] [ebp-30h] BYREF
    uint32_t thinga; // [esp+60h] [ebp+4h]
    rdMatrix34 *a2a; // [esp+64h] [ebp+8h]
    int v39; // [esp+68h] [ebp+Ch]
    float v41; // [esp+74h] [ebp+18h]

    v11 = a6;
    bFaceCollision = 0;
    if ( (raycastFlags & 0x80u) == 0 && (a6->collide == SITH_COLLIDE_FACE || thing && thing->collide == SITH_COLLIDE_FACE) )
        bFaceCollision = 1;

    float unkOut;
    if ( sithIntersect_sub_508540(a2, a3, a4, a5, &a6->position, a6->collideSize, &unkOut, bFaceCollision, raycastFlags) )
    {
        if ( bFaceCollision )
        {
            if ( a6->collide == SITH_COLLIDE_FACE )
            {
                rdVector_Copy3(&dirVec, a3);
                v39 = 0;
                rdVector_Copy3(&posVec, a2);
            }
            else
            {
                v11 = thing;
                a5 = a6->collideSize;
                v39 = 1;
                rdVector_Neg3(&dirVec, a3);
                rdVector_Copy3(&posVec, &a6->position);
            }
            rdVector_Copy3(&v11->lookOrientation.scale, &v11->position);
            a2a = &v11->lookOrientation;
            rdMatrix_InvertOrtho34(&out, &v11->lookOrientation);
            rdMatrix_TransformPoint34Acc(&posVec, &out);
            rdMatrix_TransformVector34Acc(&dirVec, &out);
            v26 = a11;
            v27 = v11->rdthing.model3->geosets;
            v28 = 0;
            v41 = a4;
            v29 = a8;
            v30 = 0;
            //printf("aaaaa %f %f %f\n", dirVec.x, dirVec.y, dirVec.z);
            for (thinga = 0; thinga < v27->numMeshes; thinga++)
            {
                v31 = sithIntersect_sub_508400(&posVec, &dirVec, v41, a5, &v27->meshes[v30], v29, a10, v26);
                if ( v31 )
                {
                    v28 = v31;
                    *outMesh = &v27->meshes[v30];
                    v41 = *v29;
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
        else
        {
            rdVector_Sub3(a11, a2, &a6->position);
            rdVector_MultAcc3(a11, a3, unkOut);
            rdVector_Normalize3Acc(a11);
            *a8 = unkOut;
            return SITHCOLLISION_THING;
        }
    }
    return 0;
}

int sithIntersect_sub_508540(const rdVector3 *a1, const rdVector3 *a2, float a3, float a4, rdVector3 *a5, float a6, float *a7, int bFaceCollision, int raycastFlags)
{
    double v15; // st7
    double v16; // rtt
    double v17; // st4
    double v18; // st5
    double v20; // rtt
    long double v21; // st6
    long double v22; // st7
    int result; // eax
    long double v24; // st7
    float v33; // [esp+20h] [ebp+14h]
    float v34; // [esp+24h] [ebp+18h]
    float v35; // [esp+24h] [ebp+18h]
    float v36; // [esp+24h] [ebp+18h]
    rdVector3 tmp;

    rdVector_Sub3(&tmp, a5, a1);
    v33 = a6 + a4;
    if ( a3 == 0.0 )
    {
LABEL_11:
        v24 = rdVector_Len3(&tmp);
        if ( v24 < v33 )
        {
            if ( (raycastFlags & RAYCAST_400) != 0 )
            {
                v36 = v24;
                *a7 = v36;
                return 1;
            }
            else
            {
                *a7 = 0.0;
                return 1;
            }
        }
        return 0;
    }
    v15 = rdVector_Dot3(a2, &tmp);
    v34 = v15;
    if ( v15 < 0.0 || v34 > v33 + a3 )
    {
        if ( !bFaceCollision )
            return 0;
        goto LABEL_11;
    }

    rdVector3 tmp2, tmp3;
    rdVector_Copy3(&tmp2, a5);
    rdVector_Copy3(&tmp3, a1);
    rdVector_MultAcc3(&tmp3, a2, v34);

    v21 = rdVector_Dist3(&tmp2, &tmp3);
    if ( v21 >= v33 )
        return 0;
    v22 = v34 - stdMath_Sqrt(v33 * v33 - v21 * v21);
    v35 = v22;
    if ( v22 > a3 || v35 < 0.0 )
    {
        result = 1;
        *a7 = 0.0;
    }
    else
    {
        *a7 = v35;
        result = 1;
    }
    return result;
}

int sithIntersect_sub_508D20(const rdVector3 *pPos, const rdVector3 *pDirection, float a3, float a4, rdFace *a5, rdVector3 *a6, float *a7, rdVector3 *pPushVelOut, int raycastFlags)
{
    const rdVector3 *v11; // edi
    int result; // eax
    int *v18; // edx
    double v21; // st7
    double v25; // st7
    int v28; // esi
    float v35; // edi
    int *v36; // edx
    double v37; // st7
    rdVector3 v45; // [esp+10h] [ebp-18h] BYREF
    rdVector3 projected; // [esp+1Ch] [ebp-Ch] BYREF

    v11 = pDirection;
    result = sithIntersect_sub_508BE0(pPos, pDirection, a3, a4, &a5->normal, &a6[*a5->vertexPosIdx], a7, raycastFlags);
    if ( result )
    {
        if ( (raycastFlags & RAYCAST_400) != 0 || rdVector_Dot3(v11, &a5->normal) < 0.0 )
        {
            if ( *a7 == 0.0 )
            {
                v36 = a5->vertexPosIdx;
                rdVector_Copy3(&v45, pPos);
                v37 = rdMath_DistancePointToPlane(&v45, &a5->normal, &a6[*v36]);
                v37 = stdMath_ClipPrecision(v37);
                if ( v37 != 0.0 )
                {
                    rdVector_MultAcc3(&v45, &a5->normal, -v37);
                }
            }
            else
            {
                rdVector_Scale3(&v45, v11, *a7);
                v18 = a5->vertexPosIdx;
                rdVector_Add3Acc(&v45, pPos);
                v21 = rdMath_DistancePointToPlane(&v45, &a5->normal, &a6[*v18]);
                v21 = stdMath_ClipPrecision(v21);
                if ( v21 != 0.0 )
                {
                    v25 = -v21;
                    rdVector_MultAcc3(&v45, &a5->normal, v25);
                }
            }
            if ( pPushVelOut )
            {
                int tmp;
                if ( sithIntersect_sub_508750(&v45, a4, a5, a6, &tmp) )
                {
                    if ( tmp )
                        v28 = sithIntersect_sub_508990(&v45, a4, a5, a6, tmp, &projected);
                    else
                        v28 = SITHCOLLISION_THINGADJOINCROSS;
                }
                else
                {
                    v28 = 0;
                }
                if ( v28 == SITHCOLLISION_THINGCROSS || v28 == SITHCOLLISION_THINGTOUCH )
                {
                    rdVector_Sub3(pPushVelOut, pPos, &projected);
                    rdVector_Normalize3Acc(pPushVelOut);
                    result = v28;
                }
                else
                {
                    rdVector_Copy3(pPushVelOut, &a5->normal);
                    result = v28;
                }
            }
            else
            {
                v35 = a4;
                int tmp;
                if ( sithIntersect_sub_508750(&v45, a4, a5, a6, &tmp) )
                {
                    if ( tmp )
                        result = sithIntersect_sub_508990(&v45, v35, a5, a6, tmp, 0);
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
    if (!pPushVelOut)
        pPushVelOut = &outSafe;
    //if (result)
    //    printf("%x: %f %f %f, %f %f %f, %f %f %f\n", result, pPos->x, pPos->y, pPos->z, pDirection->x, pDirection->y, pDirection->z, pPushVelOut->x, pPushVelOut->y, pPushVelOut->z);
    //rdVector_Scale3Acc(pPushVelOut, 0.05);
    return result;
}

// Used for floor collision, probably everything tbh
int sithIntersect_sub_508BE0(const rdVector3 *a1, const rdVector3 *a2, float a3, float a4, rdVector3 *surfaceNormal, rdVector3 *a6, float *a7, int a8)
{
    double v8; // st7
    double v13; // st7
    double v16; // st7
    float v17; // [esp+4h] [ebp+4h]
    float v18; // [esp+18h] [ebp+18h]

    v8 = rdMath_DistancePointToPlane(a1, surfaceNormal, a6);
    v8 = stdMath_ClipPrecision(v8);
    if ( v8 < 0.0 )
        return 0;
    v13 = v8 - a4;
    v17 = v13;
    if ( v13 > a3 )
        return 0;
    v18 = -rdVector_Dot3(a2, surfaceNormal);
    if ( v17 < 0.0 )
    {
        if ( (a8 & 0x400) != 0 )
            *a7 = *a7 + a4;
        else
            *a7 = 0.0;
        return 1;
    }
    else if ( v18 > 0.0 )
    {
        if ( v18 * a3 >= v17 )
        {
            v16 = v17 / v18;
            *a7 = v16;
            if ( v16 < 0.0 )
                v16 = 0.0;
            *a7 = v16;
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

int sithIntersect_sub_508750(rdVector3 *a1, float a2, rdFace *a3, rdVector3 *a4, int *a5)
{
    rdFace *v5; // ecx
    double v7; // st7
    double v10; // st7
    int v12; // edx
    int v13; // ebx
    int v14; // ebp
    int v16; // edx
    double v17; // st7
    int v18; // eax
    int *v19; // ecx
    int v21; // edi
    int v23; // edx
    double v25; // [esp+10h] [ebp-20h]
    int v26; // [esp+10h] [ebp-20h]
    double v27; // [esp+14h] [ebp-1Ch]
    int v28; // [esp+14h] [ebp-1Ch]
    rdVector2 a1a; // [esp+18h] [ebp-18h] BYREF
    double v30; // [esp+20h] [ebp-10h]
    double v31; // [esp+24h] [ebp-Ch]
    double v32; // [esp+28h] [ebp-8h]
    double v33; // [esp+2Ch] [ebp-4h]
    int v34; // [esp+34h] [ebp+4h]

    //printf("?? %f, %f %f %f, %f %f %f, %f %f %f\n", a2, a1->x, a1->y, a1->z, a4->x, a4->y, a4->z, a3->normal.x, a3->normal.y, a3->normal.z);

    if ( a5 )
        *a5 = 0;
    v5 = a3;
    if ( a3->normal.x >= 0.0 )
        v25 = a3->normal.x;
    else
        v25 = -a3->normal.x;
    v7 = a3->normal.y;
    if ( v7 < 0.0 )
        v7 = -v7;
    v27 = v7;
    v10 = a3->normal.z;
    if ( v10 < 0.0 )
        v10 = -v10;

    if ( v25 <= (double)v27 )
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

    if ( *(&a3->normal.x + v12) <= 0.0 )
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
    v32 = *(&a1->x + v13);
    v17 = *(&a1->x + v14);
    v18 = a3->numVertices;
    v33 = v17;
    v26 = v18;
    if ( v18 > 0 )
    {
        while ( 1 )
        {
            v19 = v5->vertexPosIdx;
            v21 = v16 + 1;
            v23 = (v16 + 1) % v26;
            a1a.x = -*(&a4[v19[v16]].x + v13);
            a1a.y = -*(&a4[v19[v16]].x + v14);
            v30 = a1a.x + v32;
            v31 = a1a.y + v33;
            v14 = v28;
            a1a.x += *(&a4[v19[v23]].x + v13);
            a1a.y += *(&a4[v19[v23]].x + v28);
            float idk = stdMath_ClipPrecision(v30 * a1a.y - v31 * a1a.x);
            if ( idk <= 0.0 )
            {
                if ( a2 == 0.0 )
                    return 0;
                if ( !a5 )
                    return 0;
                rdVector_Normalize2Acc(&a1a);
                float idk2 = stdMath_ClipPrecision(v30 * a1a.y - v31 * a1a.x);
                
                // TODO: Somehow we need to return 0 here for slopes which match our current normal?

                if ( -a2 > idk2 )
                    return 0;
                *a5 |= v34;
            }
            v16 = v21;
            v34 *= 2;
            if ( v21 >= v26 )
                return 1;
            v5 = a3;
        }
    }
    return 1;
}

// Seems to handle interaction when crossing adjoins?
int sithIntersect_sub_5090B0(const rdVector3 *a1, const rdVector3 *a2, float a3, float a4, sithSurfaceInfo *a5, rdVector3 *a6, float *a7, int a8)
{
    sithSurfaceInfo *v8; // edi
    float *v9; // esi
    int result; // eax
    rdVector3 v15; // [esp+10h] [ebp-Ch] BYREF

    v8 = a5;
    v9 = a7;
    result = sithIntersect_sub_508BE0(a1, a2, a3, a4, &a5->face.normal, &a6[*a5->face.vertexPosIdx], a7, a8);
    if ( result )
    {
        if ( a4 == 0.0 )
        {
            rdVector_Copy3(&v15, a1);
            rdVector_MultAcc3(&v15, a2, *v9);
            
            int tmp;
            result = sithIntersect_sub_508750(&v15, a4, &v8->face, a6, &tmp);
            if ( result )
            {
                if ( !tmp)
                    return SITHCOLLISION_THINGADJOINCROSS;
                else
                    return sithIntersect_sub_508990(&v15, a4, &v8->face, a6, tmp, 0);
            }
        }
        else
        {
            return SITHCOLLISION_THINGADJOINCROSS;
        }
    }
    return 0;
}

// This handles collisions with non-spherical world thing objects
// ie, tables and such
int sithIntersect_sub_508400(rdVector3 *pPos, rdVector3 *pDirection, float a3, float a4, rdMesh *mesh, float *a6, rdFace **faceOut, rdVector3 *pPushVelOut)
{
    float *v10; // ebp
    int v11; // ecx
    rdFace *v12; // edx
    int v24; // [esp+8h] [ebp-18h]
    float v25; // [esp+Ch] [ebp-14h]
    int v26; // [esp+10h] [ebp-10h]
    rdVector3 pushVel; // [esp+14h] [ebp-Ch] BYREF

    v24 = 0;
    v25 = 1.0;
    v10 = a6;
    for (v26 = 0; v26 < mesh->numFaces; v26++)
    {
        v11 = sithIntersect_sub_508D20(pPos, pDirection, a3, a4, &mesh->faces[v26], mesh->vertices, v10, &pushVel, 0);
        if ( v11
          && (*v10 < (double)a3
           || v24 != SITHCOLLISION_THINGADJOINCROSS && v11 == SITHCOLLISION_THINGADJOINCROSS
           || rdVector_Dot3(pDirection, &mesh->faces[v26].normal) < v25) )
        {
            //printf("%f %f %f\n", pushVel.x, pushVel.y, pushVel.z);
            v12 = &mesh->faces[v26];
            v24 = v11;
            rdVector_Copy3(pPushVelOut, &pushVel);
            a3 = *a6;
            v25 = rdVector_Dot3(pDirection, &v12->normal);
            *faceOut = v12;
            
            v10 = a6;
        }
    }

    //if (v24 & 0x18)
    //printf("%x %f %f %f, %f %f %f\n", v24, pPos->x, pPos->y, pPos->z, pDirection->x, pDirection->y, pDirection->z);

    return v24;
}

// This does something with whether something is a step vs barrier?
// return 0 allows jumping up on high ledges
int sithIntersect_sub_508990(rdVector3 *a1, float a2, rdFace *a3, rdVector3 *a4, int a5, rdVector3 *pProjectedOut)
{
    rdFace *v6; // ecx
    unsigned int v7; // edi
    unsigned int v8; // ebx
    int *v10; // ecx
    int v11; // eax
    rdVector3 *v14; // esi
    rdVector3 *v15; // edi
    double v16; // st7
    //char v18; // c0
    int v19; // ecx
    double v24; // st6
    float v27; // [esp+4h] [ebp-2Ch]
    int i; // [esp+8h] [ebp-28h]
    rdVector3 v29; // [esp+Ch] [ebp-24h]
    rdVector3 a1a; // [esp+18h] [ebp-18h] BYREF
    float v34; // [esp+34h] [ebp+4h]

    v6 = a3;
    v7 = a3->numVertices;
    v8 = 0;
    v27 = a2 - -1.0;
    for ( i = 0; v8 < v7; v7 = a3->numVertices )
    {
        if ( !a5 )
            break;
        if ( (a5 & 1) != 0 )
        {
            v10 = v6->vertexPosIdx;
            v11 = v10[v8];
            v14 = &a4[v11];
            v15 = &a4[v10[(v8 + 1) % v7]];
            rdVector_Sub3(&a1a, v15, v14);
            v16 = rdVector_Normalize3Acc(&a1a);

            v34 = rdMath_DistancePointToPlane(a1, &a1a, &a4[v10[v8]]);
            if ( -a2 <= v34 && v34 - a2 <= v16 )
            {
                v19 = SITHCOLLISION_THINGTOUCH;
                if ( v34 >= 0.0 )
                {
                    if ( v34 <= (double)v16 )
                    {
                        rdVector_Copy3(&v29, v14);
                        
                        // projected point
                        rdVector_MultAcc3(&v29, &a1a, v34);
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
                v24 = rdVector_Dist3(a1, &v29);
                if ( v24 <= a2 && v24 < v27 )
                {
                    i = v19;
                    v27 = v24;
                    if ( pProjectedOut )
                        *pProjectedOut = v29;
                }
            }
        }
        ++v8;
        a5 = (unsigned int)a5 >> 1;
        v6 = a3;
    }
    return i;
}
