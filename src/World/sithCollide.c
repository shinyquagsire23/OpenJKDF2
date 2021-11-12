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
        if ( (surface->surfaceFlags & SURFACEFLAGS_4) != 0 || adjoin && (adjoin->flags & 2) != 0 )
        {
            v7 = sithWorld_pCurWorld->vertices;
            v8 = stdMath_ClipPrecision(rdVector_NormalDot(pos, &v7[*surface->surfaceInfo.face.vertexPosIdx], &surface->surfaceInfo.face.normal));
            if ( v8 < radius )
                return 0;
        }
    }
    return 1;
}

int sithCollide_sub_5080D0(sithThing *thing, const rdVector3 *a2, const rdVector3 *a3, float a4, float a5, sithThing *a6, int a7, float *a8, rdMesh **outMesh, rdFace **a10, rdVector3 *a11)
{
    sithThing *v11; // edi
    int result; // eax
    rdVector3 *v26; // ebp
    rdGeoset *v27; // esi
    int v28; // ebx
    float *v29; // ebx
    int v30; // edi
    int v31; // eax
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

    float unkOut;
    result = sithCollide_sub_508540(a2, a3, a4, a5, &a6->position, a6->collideSize, &unkOut, a8a, a7);
    if ( result )
    {
        if ( a8a )
        {
            if ( a6->collide == 3 )
            {
                rdVector_Copy3(&a1, a3);
                v39 = 0;
                rdVector_Copy3(&v35, a2);
            }
            else
            {
                v11 = thing;
                a5 = a6->collideSize;
                v39 = 1;
                rdVector_Neg3(&a1, a3);
                rdVector_Copy3(&v35, &a6->position);
            }
            rdVector_Copy3(&v11->lookOrientation.scale, &v11->position);
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
                    rdVector_Neg3Acc(v26);
                }
                v28 |= 1u;
            }
            result = v28;
        }
        else
        {
            rdVector_Sub3(a11, a2, &a6->position);
            rdVector_MultAcc3(a11, a3, unkOut);
            rdVector_Normalize3Acc(a11);
            *a8 = unkOut;
            result = 1;
        }
    }
    return result;
}

int sithCollide_sub_508540(const rdVector3 *a1, const rdVector3 *a2, float a3, float a4, rdVector3 *a5, float a6, float *a7, int a8, int a9)
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
        v24 = stdMath_Sqrt(tmp.x * tmp.x + tmp.y * tmp.y + tmp.z * tmp.z);
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
    v15 = rdVector_Dot3(a2, &tmp);
    v34 = v15;
    if ( v15 < 0.0 || v34 > v33 + a3 )
    {
        if ( !a8 )
            return 0;
        goto LABEL_11;
    }
    v16 = a5->y - (a2->y * v34 + a1->y);
    v17 = a5->x - (a2->x * v34 + a1->x);
    v18 = a5->z - (a2->z * v34 + a1->z);
    v20 = v17 * v17;
    v21 = stdMath_Sqrt(v20 + v16 * v16 + v18 * v18);
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
    rdVector3 a6a; // [esp+1Ch] [ebp-Ch] BYREF

    v11 = a2;
    result = sithCollide_sub_508BE0(a1, a2, a3, a4, &a5->normal, &a6[*a5->vertexPosIdx], a7, a9);
    if ( result )
    {
        if ( (a9 & 0x400) != 0 || rdVector_Dot3(v11, &a5->normal) < 0.0 )
        {
            if ( *a7 == 0.0 )
            {
                v36 = a5->vertexPosIdx;
                rdVector_Copy3(&v45, a1);
                v37 = rdVector_NormalDot(&v45, &a6[*v36], &a5->normal);
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
                rdVector_Add3Acc(&v45, a1);
                v21 = rdVector_NormalDot(&v45, &a6[*v18], &a5->normal);
                v21 = stdMath_ClipPrecision(v21);
                if ( v21 != 0.0 )
                {
                    v25 = -v21;
                    rdVector_MultAcc3(&v45, &a5->normal, v25);
                }
            }
            if ( a8 )
            {
                int tmp;
                if ( sithCollide_sub_508750(&v45, a4, a5, a6, &tmp) )
                {
                    if ( tmp )
                        v28 = sithCollide_sub_508990(&v45, a4, a5, a6, tmp, &a6a);
                    else
                        v28 = 4;
                }
                else
                {
                    v28 = 0;
                }
                if ( v28 == 8 || v28 == 16 )
                {
                    rdVector_Sub3(a8, a1, &a6a);
                    rdVector_Normalize3Acc(a8);
                    result = v28;
                }
                else
                {
                    rdVector_Copy3(a8, &a5->normal);
                    result = v28;
                }
            }
            else
            {
                v35 = a4;
                int tmp;
                if ( sithCollide_sub_508750(&v45, a4, a5, a6, &tmp) )
                {
                    if ( tmp )
                        result = sithCollide_sub_508990(&v45, v35, a5, a6, tmp, 0);
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
    double v13; // st7
    double v16; // st7
    float v17; // [esp+4h] [ebp+4h]
    float v18; // [esp+18h] [ebp+18h]

    v8 = rdVector_NormalDot(a1, a6, surfaceNormal);
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
    int v21; // edi
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
            a1a.x = -*(&a4[v19[v16]].x + v13);
            v21 = v16 + 1;
            v23 = (v16 + 1) % v26;
            v31 = -*(&a4[v19[v16]].x + v14);
            a1a.y = v31;
            v30 = a1a.x + v32;
            v31 = v31 + v33;
            v14 = v28;
            a1a.x += *(&a4[v19[v23]].x + v13);
            a1a.y += *(&a4[v19[v23]].x + v28);
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
    rdVector3 v15; // [esp+10h] [ebp-Ch] BYREF

    v8 = a5;
    v9 = a7;
    result = sithCollide_sub_508BE0(a1, a2, a3, a4, &a5->face.normal, &a6[*a5->face.vertexPosIdx], a7, a8);
    if ( result )
    {
        if ( a4 == 0.0 )
        {
            rdVector_Copy3(&v15, a1);
            rdVector_MultAcc3(&v15, a2, *v9);
            
            int tmp;
            result = sithCollide_sub_508750(&v15, a4, &v8->face, a6, &tmp);
            if ( result )
            {
                if ( !tmp)
                    return 4;
                else
                    return sithCollide_sub_508990(&v15, a4, &v8->face, a6, tmp, 0);
            }
        }
        else
        {
            return 4;
        }
    }
    return 0;
}

int sithCollide_sub_508400(rdVector3 *a1, rdVector3 *a2, float a3, float a4, rdMesh *mesh, float *a6, rdFace **faceOut, rdVector3 *a8)
{
    float *v10; // ebp
    int v11; // ecx
    rdFace *v12; // edx
    double v21; // st7
    int v24; // [esp+8h] [ebp-18h]
    float v25; // [esp+Ch] [ebp-14h]
    int v26; // [esp+10h] [ebp-10h]
    rdVector3 a8a; // [esp+14h] [ebp-Ch] BYREF

    v24 = 0;
    v25 = 1.0;
    v26 = 0;
    if ( mesh->numFaces )
    {
        v10 = a6;
        do
        {
            v11 = sithCollide_sub_508D20(a1, a2, a3, a4, &mesh->faces[v26], mesh->vertices, v10, &a8a, 0);
            if ( v11
              && (*v10 < (double)a3
               || v24 != 4 && v11 == 4
               || rdVector_Dot3(a2, &mesh->faces[v26].normal) < v25) )
            {
                v12 = &mesh->faces[v26];
                v24 = v11;
                rdVector_Copy3(a8, &a8a);
                a3 = *a6;
                v21 = (a2->z * v12->normal.z) + (a2->y * v12->normal.y) + (v12->normal.x * a2->x);
                *faceOut = v12;
                
                v10 = a6;
                v25 = v21;
            }
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
    rdVector3 *v14; // esi
    rdVector3 *v15; // edi
    long double v16; // st7
    //char v18; // c0
    int v19; // ecx
    double v20; // st6
    double v21; // st5
    double v22; // st7
    long double v24; // st6
    float v26; // [esp+0h] [ebp-30h]
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
            v34 = a1a.x * (a1->x - a4[v10[v8]].x) + a1a.y * (a1->y - a4[v10[v8]].y) + a1a.z * (a1->z - a4[v10[v8]].z);
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
                v24 = stdMath_Sqrt((v21 * v21) + v20 * v20 + v22 * v22);
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
