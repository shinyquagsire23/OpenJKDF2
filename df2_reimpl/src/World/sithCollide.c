#include "sithCollide.h"

#include <math.h>

#include "General/stdMath.h"
#include "Engine/sithAdjoin.h"
#include "Engine/sithSurface.h"
#include "Primitives/rdFace.h"
#include "World/sithSector.h"
#include "World/sithWorld.h"
#include "World/sithThing.h"
#include "jk.h"

static rdVector2i sithCollide_unkArr[3] = {
    {2, 1},
    {0, 2},
    {1, 0},
};

int sithCollide_IsSphereInSector(const rdVector3 *pos, float radius, sithSector *sector)
{
    rdVector3 *v7; // ebp
    double v8; // st7
    double v10; // st6
    
    // Added
    if (!sector)
        return 0;

    if ( (sector->flags & SITH_SF_COLLIDEBOX) != 0
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
        // i = &sector->surfaces->surfaceFlags; ; i += 23 
        if ( (surface->surfaceFlags & 4) != 0 || adjoin && (adjoin->flags & 2) != 0 )
        {
            v7 = sithWorld_pCurWorld->vertices;
            v8 = (pos->x - v7[*surface->surfaceInfo.face.vertexPosIdx].x) * surface->surfaceInfo.face.normal.x
               + (pos->y - v7[*surface->surfaceInfo.face.vertexPosIdx].y) * surface->surfaceInfo.face.normal.y
               + (pos->z - v7[*surface->surfaceInfo.face.vertexPosIdx].z) * surface->surfaceInfo.face.normal.z;
            v10 = v8;
            if ( v10 < 0.0 )
                v10 = -v8;
            if ( v10 <= 0.0000099999997 )
                v8 = 0.0;
            if ( v8 < radius )
                return 0;
        }
    }
    return 1;
}

int sithCollide_sub_5080D0(sithThing *thing, const rdVector3 *a2, const rdVector3 *a3, float a4, float a5, sithThing *a6, int a7, float *a8, rdMesh **outMesh, rdFace **a10, rdVector3 *a11)
{
    sithThing *v11; // edi
    rdVector3 *v13; // ebx
    int result; // eax
    double v15; // st6
    double v16; // st7
    rdVector3 *v17; // eax
    float v18; // ecx
    float v19; // edx
    float v20; // eax
    float v21; // ecx
    float v22; // edx
    float v23; // edx
    float v24; // eax
    float v25; // ecx
    rdVector3 *v26; // ebp
    rdGeoset *v27; // esi
    int v28; // ebx
    float *v29; // ebx
    int v30; // edi
    int v31; // eax
    rdVector3 *v32; // [esp-4h] [ebp-60h]
    int a8a; // [esp+10h] [ebp-4Ch]
    rdVector3 a1; // [esp+14h] [ebp-48h] BYREF
    rdVector3 v35; // [esp+20h] [ebp-3Ch] BYREF
    rdMatrix34 out; // [esp+2Ch] [ebp-30h] BYREF
    sithThing *thinga; // [esp+60h] [ebp+4h]
    rdMatrix34 *a2a; // [esp+64h] [ebp+8h]
    int v39; // [esp+68h] [ebp+Ch]
    int a3a; // [esp+6Ch] [ebp+10h]
    float v41; // [esp+74h] [ebp+18h]

    v11 = a6;
    a8a = 0;
    if ( (a7 & 0x80u) == 0 && (a6->collide == 3 || thing && thing->collide == 3) )
        a8a = 1;
    v13 = &a6->position;
    float unkOut;
    result = sithCollide_sub_508540(a2, a3, a4, a5, &a6->position, a6->collideSize, &unkOut, a8a, a7);
    if ( result )
    {
        if ( a8a )
        {
            if ( a6->collide == 3 )
            {
                v18 = a3->y;
                v19 = a3->z;
                a1.x = a3->x;
                v20 = a2->x;
                a1.y = v18;
                v21 = a2->y;
                a1.z = v19;
                v22 = a2->z;
                v39 = 0;
                v35.x = v20;
                v35.y = v21;
                v35.z = v22;
            }
            else
            {
                v23 = v13->x;
                a1.x = -a3->x;
                v24 = a6->position.y;
                v11 = thing;
                a5 = a6->collideSize;
                v25 = a6->position.z;
                v39 = 1;
                a1.y = -a3->y;
                a1.z = -a3->z;
                v35.x = v23;
                v35.y = v24;
                v35.z = v25;
            }
            v11->lookOrientation.scale.x = v11->position.x;
            v11->lookOrientation.scale.y = v11->position.y;
            v11->lookOrientation.scale.z = v11->position.z;
            a2a = &v11->lookOrientation;
            rdMatrix_InvertOrtho34(&out, &v11->lookOrientation);
            rdMatrix_TransformPoint34Acc(&v35, &out);
            rdMatrix_TransformVector34Acc(&a1, &out);
            v26 = a11;
            v27 = v11->rdthing.model3->geosets;
            v28 = 0;
            v41 = a4;
            a3a = 0;
            thinga = 0;
            if ( v27->numMeshes )
            {
                v29 = a8;
                v30 = 0;
                do
                {
                    v31 = sithCollide_sub_508400(&v35, &a1, v41, a5, &v27->meshes[v30], v29, a10, v26);
                    if ( v31 )
                    {
                        a3a = v31;
                        *outMesh = &v27->meshes[v30];
                        v41 = *v29;
                    }
                    ++v30;
                    thinga = (sithThing *)((char *)thinga + 1);
                }
                while ( (unsigned int)thinga < v27->numMeshes );
                v28 = a3a;
            }
            if ( v28 )
            {
                rdMatrix_TransformVector34Acc(v26, a2a);
                if ( v39 )
                {
                    v26->x = -v26->x;
                    v26->y = -v26->y;
                    v26->z = -v26->z;
                }
                v28 |= 1u;
            }
            result = v28;
        }
        else
        {
            v15 = a3->y * unkOut + a2->y - a6->position.y;
            v16 = a3->z * unkOut + a2->z - a6->position.z;
            v17 = a11;
            v32 = a11;
            a11->x = a3->x * unkOut + a2->x - v13->x;
            v17->y = v15;
            v17->z = v16;
            rdVector_Normalize3Acc(v32);
            *a8 = unkOut;
            result = 1;
        }
    }
    return result;
}

int sithCollide_sub_508540(const rdVector3 *a1, const rdVector3 *a2, float a3, float a4, rdVector3 *a5, float a6, float *a7, int a8, int a9)
{
    double v10; // st6
    double v11; // st5
    double v12; // st7
    double v15; // st7
    double v16; // rtt
    double v17; // st4
    double v18; // st5
    double v19; // st6
    double v20; // rtt
    long double v21; // st6
    long double v22; // st7
    int result; // eax
    long double v24; // st7
    float v25; // [esp+0h] [ebp-Ch]
    float v26; // [esp+4h] [ebp-8h]
    float v27; // [esp+4h] [ebp-8h]
    float v28; // [esp+8h] [ebp-4h]
    float v29; // [esp+8h] [ebp-4h]
    float v30; // [esp+10h] [ebp+4h]
    float v31; // [esp+1Ch] [ebp+10h]
    float v32; // [esp+1Ch] [ebp+10h]
    float v33; // [esp+20h] [ebp+14h]
    float v34; // [esp+24h] [ebp+18h]
    float v35; // [esp+24h] [ebp+18h]
    float v36; // [esp+24h] [ebp+18h]

    v10 = a5->x - a1->x;
    v11 = a5->y - a1->y;
    v12 = a5->z - a1->z;
    v33 = a6 + a4;
    v25 = v10;
    v26 = v11;
    v28 = v12;
    if ( a3 == 0.0 )
    {
LABEL_11:
        v24 = stdMath_Sqrt(v25 * v25 + v26 * v26 + v28 * v28);
        if ( v24 < v33 )
        {
            if ( (a9 & 0x400) != 0 )
            {
                result = 1;
                v36 = v24;
                *a7 = v36;
            }
            else
            {
                *a7 = 0.0;
                result = 1;
            }
            return result;
        }
        return 0;
    }
    v15 = a2->z * v28 + a2->y * v26 + a2->x * v25;
    v34 = v15;
    if ( v15 < 0.0 || v34 > v33 + a3 )
    {
        if ( !a8 )
            return 0;
        goto LABEL_11;
    }
    v27 = a2->y * v34 + a1->y;
    v29 = a2->z * v34 + a1->z;
    v16 = a5->y - v27;
    v17 = a5->x - (a2->x * v34 + a1->x);
    v18 = a5->z - v29;
    v31 = v17;
    v30 = v16;
    v19 = v16;
    v20 = v17 * v31;
    v32 = v18;
    v21 = stdMath_Sqrt(v20 + v19 * v30 + v18 * v32);
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

int sithCollide_sub_508D20(const rdVector3 *a1, const rdVector3 *a2, float a3, float a4, rdFace *a5, rdVector3 *a6, float *a7, rdVector3 *a8, int a9)
{
    rdFace *v9; // esi
    rdVector3 *v10; // ebp
    const rdVector3 *v11; // edi
    rdVector3 *v12; // ebx
    int result; // eax
    double v14; // st6
    double v15; // st5
    double v16; // st7
    const rdVector3 *v17; // edi
    int *v18; // edx
    double v19; // rtt
    double v20; // rt0
    double v21; // st7
    double v23; // st6
    double v25; // st7
    double v26; // st5
    double v27; // st6
    int v28; // esi
    rdVector3 *v29; // eax
    float v30; // edx
    float v31; // ecx
    double v32; // st7
    double v33; // st6
    rdVector3 *v34; // eax
    float v35; // edi
    int *v36; // edx
    double v37; // st7
    double v39; // st6
    double v41; // st7
    double v42; // st5
    double v43; // st6
    rdVector3 *v44; // [esp-4h] [ebp-2Ch]
    rdVector3 v45; // [esp+10h] [ebp-18h] BYREF
    rdVector3 a6a; // [esp+1Ch] [ebp-Ch] BYREF

    v9 = a5;
    v10 = a6;
    v11 = a2;
    v12 = &a5->normal;
    result = sithCollide_sub_508BE0(a1, a2, a3, a4, &a5->normal, &a6[*a5->vertexPosIdx], a7, a9);
    if ( result )
    {
        if ( (a9 & 0x400) != 0 || v11->y * v9->normal.y + v11->z * v9->normal.z + v12->x * v11->x < 0.0 )
        {
            if ( *a7 == 0.0 )
            {
                v36 = v9->vertexPosIdx;
                v45 = *a1;
                v37 = (v45.z - v10[*v36].z) * v9->normal.z + (v45.y - v10[*v36].y) * v9->normal.y + (v45.x - v10[*v36].x) * v12->x;
                v39 = v37;
                if ( v39 < 0.0 )
                    v39 = -v37;
                if ( v39 <= 0.0000099999997 )
                    v37 = 0.0;
                if ( v37 == 0.0 )
                {
                    v17 = a1;
                }
                else
                {
                    v41 = -v37;
                    v42 = v9->normal.y * v41 + v45.y;
                    v43 = v9->normal.z * v41 + v45.z;
                    v45.x = v12->x * v41 + v45.x;
                    v17 = a1;
                    v45.y = v42;
                    v45.z = v43;
                }
            }
            else
            {
                v14 = v11->y * *a7;
                v15 = *a7 * v11->x;
                v16 = v11->z * *a7;
                v17 = a1;
                v18 = v9->vertexPosIdx;
                v19 = v14 + a1->y;
                v20 = v16 + a1->z;
                v45.x = v15 + a1->x;
                v45.y = v19;
                v45.z = v20;
                v21 = (v45.z - v10[*v18].z) * v9->normal.z + (v45.y - v10[*v18].y) * v9->normal.y + (v45.x - v10[*v18].x) * v12->x;
                v23 = v21;
                if ( v23 < 0.0 )
                    v23 = -v23;
                if ( v23 <= 0.0000099999997 )
                    v21 = 0.0;
                if ( v21 != 0.0 )
                {
                    v25 = -v21;
                    v26 = v9->normal.y * v25 + v45.y;
                    v27 = v9->normal.z * v25 + v45.z;
                    v45.x = v12->x * v25 + v45.x;
                    v45.y = v26;
                    v45.z = v27;
                }
            }
            if ( a8 )
            {
                int tmp;
                if ( sithCollide_sub_508750(&v45, a4, v9, v10, &tmp) )
                {
                    if ( tmp )
                        v28 = sithCollide_sub_508990(&v45, a4, v9, v10, tmp, &a6a);
                    else
                        v28 = 4;
                }
                else
                {
                    v28 = 0;
                }
                if ( v28 == 8 || v28 == 16 )
                {
                    v32 = v17->y - a6a.y;
                    v33 = v17->z - a6a.z;
                    v34 = a8;
                    v44 = a8;
                    a8->x = v17->x - a6a.x;
                    v34->y = v32;
                    v34->z = v33;
                    rdVector_Normalize3Acc(v44);
                    result = v28;
                }
                else
                {
                    v29 = a8;
                    v30 = v12->y;
                    a8->x = v12->x;
                    v31 = v12->z;
                    v29->y = v30;
                    v29->z = v31;
                    result = v28;
                }
            }
            else
            {
                v35 = a4;
                int tmp;
                if ( sithCollide_sub_508750(&v45, a4, v9, v10, &tmp) )
                {
                    if ( tmp )
                        result = sithCollide_sub_508990(&v45, v35, v9, v10, tmp, 0);
                    else
                        result = 4;
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
    return result;
}

int sithCollide_sub_508BE0(const rdVector3 *a1, const rdVector3 *a2, float a3, float a4, rdVector3 *surfaceNormal, rdVector3 *a6, float *a7, int a8)
{
    double v8; // st7
    double v10; // st6
    double v13; // st7
    double v16; // st7
    float v17; // [esp+4h] [ebp+4h]
    float v18; // [esp+18h] [ebp+18h]

    v8 = (a1->y - a6->y) * surfaceNormal->y + (a1->z - a6->z) * surfaceNormal->z + (a1->x - a6->x) * surfaceNormal->x;
    v10 = v8;
    if ( v10 < 0.0 )
        v10 = -v8;
    if ( v10 <= 0.0000099999997 )
        v8 = 0.0;
    if ( v8 < 0.0 )
        return 0;
    v13 = v8 - a4;
    v17 = v13;
    if ( v13 > a3 )
        return 0;
    v18 = -(a2->y * surfaceNormal->y + a2->z * surfaceNormal->z + a2->x * surfaceNormal->x);
    if ( v17 <= 0.0 )
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

int sithCollide_sub_508750(rdVector3 *a1, float a2, rdFace *a3, rdVector3 *a4, int *a5)
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
    double v20; // st7
    int v21; // edi
    double v22; // st6
    int v23; // edx
    float v25; // [esp+10h] [ebp-20h]
    int v26; // [esp+10h] [ebp-20h]
    float v27; // [esp+14h] [ebp-1Ch]
    int v28; // [esp+14h] [ebp-1Ch]
    rdVector2 a1a; // [esp+18h] [ebp-18h] BYREF
    float v30; // [esp+20h] [ebp-10h]
    float v31; // [esp+24h] [ebp-Ch]
    float v32; // [esp+28h] [ebp-8h]
    float v33; // [esp+2Ch] [ebp-4h]
    int v34; // [esp+34h] [ebp+4h]

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
            goto LABEL_16;
        }
    }
    else if ( v25 > v10 )
    {
        v12 = 0;
        goto LABEL_16;
    }
    v12 = 2;
LABEL_16:
    if ( *(&a3->normal.x + v12) <= 0.0 )
    {
        v13 = sithCollide_unkArr[v12].y;
        v14 = sithCollide_unkArr[v12].x;
    }
    else
    {
        v13 = sithCollide_unkArr[v12].x;
        v14 = sithCollide_unkArr[v12].y;
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
            v20 = -*(&a4->x + 2 * v19[v16] + v13 + v19[v16]);
            a1a.x = v20;
            v21 = v16 + 1;
            v22 = *(&a4->x + 2 * v19[v16] + v14 + v19[v16]);
            v23 = (v16 + 1) % v26;
            v31 = -v22;
            a1a.y = v31;
            v30 = v20 + v32;
            v31 = v31 + v33;
            v14 = v28;
            a1a.x = *(&a4->x + 2 * v19[v23] + v13 + v19[v23]) + a1a.x;
            a1a.y = *(&a4->x + 2 * v19[v23] + v28 + v19[v23]) + a1a.y;
            if ( v30 * a1a.y - v31 * a1a.x < 0.0 )
            {
                if ( a2 == 0.0 )
                    return 0;
                if ( !a5 )
                    return 0;
                rdVector_Normalize2Acc(&a1a);
                if ( -a2 > v30 * a1a.y - v31 * a1a.x )
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

int sithCollide_sub_5090B0(const rdVector3 *a1, const rdVector3 *a2, float a3, float a4, sithSurfaceInfo *a5, rdVector3 *a6, float *a7, int a8)
{
    sithSurfaceInfo *v8; // edi
    float *v9; // esi
    int result; // eax
    double v11; // st7
    double v12; // st6
    rdVector3 *v13; // esi
    float v14; // ebx
    rdVector3 v15; // [esp+10h] [ebp-Ch] BYREF

    v8 = a5;
    v9 = a7;
    result = sithCollide_sub_508BE0(a1, a2, a3, a4, &a5->face.normal, &a6[*a5->face.vertexPosIdx], a7, a8);
    if ( result )
    {
        if ( a4 == 0.0 )
        {
            v11 = a2->y * *v9 + a1->y;
            v12 = a2->z * *v9 + a1->z;
            v15.x = a2->x * *v9 + a1->x;
            v13 = a6;
            v14 = a4;
            v15.y = v11;
            v15.z = v12;
            
            int tmp;
            result = sithCollide_sub_508750(&v15, a4, &v8->face, a6, &tmp);
            if ( result )
            {
                if ( !tmp)
                    result = 4;
                else
                    result = sithCollide_sub_508990(&v15, v14, &v8->face, v13, tmp, 0);
            }
        }
        else
        {
            result = 4;
        }
    }
    return result;
}

int sithCollide_sub_508400(rdVector3 *a1, rdVector3 *a2, float a3, float a4, rdMesh *mesh, float *a6, rdFace **faceOut, rdVector3 *a8)
{
    int v9; // ebx
    float *v10; // ebp
    int v11; // ecx
    rdFace *v12; // edx
    double v13; // st6
    double v14; // st4
    double v15; // st5
    double v16; // st7
    rdFace *v17; // eax
    float v18; // ebx
    float v19; // ebp
    float v20; // ebp
    double v21; // st7
    int v24; // [esp+8h] [ebp-18h]
    float v25; // [esp+Ch] [ebp-14h]
    int v26; // [esp+10h] [ebp-10h]
    rdVector3 a8a; // [esp+14h] [ebp-Ch] BYREF
    int mesha; // [esp+34h] [ebp+14h]

    v9 = 0;
    v24 = 0;
    v25 = 1.0;
    v26 = 0;
    if ( mesh->numFaces )
    {
        v10 = a6;
        mesha = 0;
        do
        {
            v11 = sithCollide_sub_508D20(a1, a2, a3, a4, (rdFace *)((char *)mesh->faces + v9), mesh->vertices, v10, &a8a, 0);
            if ( v11
              && (*v10 < (double)a3
               || v24 != 4 && v11 == 4
               || a2->z * *(float *)((char *)&mesh->faces->normal.z + v9)
                + a2->y * *(float *)((char *)&mesh->faces->normal.y + v9)
                + *(float *)((char *)&mesh->faces->normal.x + v9) * a2->x < v25) )
            {
                v12 = mesh->faces;
                v13 = a2->y;
                v14 = *(float *)((char *)&v12->normal.y + v9);
                v15 = *(float *)((char *)&v12->normal.x + v9);
                v16 = a2->z * *(float *)((char *)&v12->normal.z + v9);
                v17 = (rdFace *)((char *)v12 + v9);
                v18 = a8a.y;
                v24 = v11;
                a8->x = a8a.x;
                v19 = *a6;
                a8->y = v18;
                a3 = v19;
                v20 = a8a.z;
                v21 = v16 + v13 * v14 + v15 * a2->x;
                *faceOut = v17;
                v9 = mesha;
                a8->z = v20;
                v10 = a6;
                v25 = v21;
            }
            v9 += sizeof(rdFace);
            mesha = v9;
        }
        while ( ++v26 < mesh->numFaces );
    }
    return v24;
}

int sithCollide_sub_508990(rdVector3 *a1, float a2, rdFace *a3, rdVector3 *a4, int a5, rdVector3 *a6)
{
    rdFace *v6; // ecx
    unsigned int v7; // edi
    unsigned int v8; // ebx
    int *v10; // ecx
    int v11; // eax
    double v12; // st7
    double v13; // st6
    rdVector3 *v14; // esi
    rdVector3 *v15; // edi
    long double v16; // st7
    //char v18; // c0
    int v19; // ecx
    double v20; // st6
    double v21; // st5
    double v22; // st7
    double v23; // rt0
    long double v24; // st6
    float v26; // [esp+0h] [ebp-30h]
    float v27; // [esp+4h] [ebp-2Ch]
    int i; // [esp+8h] [ebp-28h]
    rdVector3 v29; // [esp+Ch] [ebp-24h]
    rdVector3 a1a; // [esp+18h] [ebp-18h] BYREF
    float v31; // [esp+24h] [ebp-Ch]
    float v32; // [esp+28h] [ebp-8h]
    float v33; // [esp+2Ch] [ebp-4h]
    float v34; // [esp+34h] [ebp+4h]
    float v35; // [esp+34h] [ebp+4h]
    float v36; // [esp+34h] [ebp+4h]

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
            v12 = a1->y - a4[v10[v8]].y;
            v13 = a1->z - a4[v10[v8]].z;
            v31 = a1->x - a4[v10[v8]].x;
            v14 = &a4[v11];
            v32 = v12;
            v33 = v13;
            v15 = &a4[v10[(v8 + 1) % v7]];
            a1a.x = v15->x - v14->x;
            a1a.y = v15->y - v14->y;
            a1a.z = v15->z - v14->z;
            v16 = rdVector_Normalize3Acc(&a1a);
            v34 = a1a.x * v31 + a1a.y * v32 + a1a.z * v33;
            v26 = v16;
            if ( v34 > a2 && v34 - a2 <= v26 )
            {
                v19 = 16;
                if ( v34 >= 0.0 )
                {
                    if ( v34 <= (double)v26 )
                    {
                        v29.x = v34 * a1a.x + v14->x;
                        v29.y = v34 * a1a.y + v14->y;
                        v19 = 8;
                        v29.z = v34 * a1a.z + v14->z;
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
                v20 = a1->y - v29.y;
                v21 = a1->x - v29.x;
                v22 = a1->z - v29.z;
                v35 = v21;
                v23 = v21 * v35;
                v36 = v22;
                v24 = stdMath_Sqrt(v23 + v20 * v20 + v22 * v36);
                if ( v24 <= a2 && v24 < v27 )
                {
                    i = v19;
                    v27 = v24;
                    if ( a6 )
                        *a6 = v29;
                }
            }
        }
        ++v8;
        a5 = (unsigned int)a5 >> 1;
        v6 = a3;
    }
    return i;
}
