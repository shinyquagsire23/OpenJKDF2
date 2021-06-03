#include "sithCollide.h"

#include <math.h>

#include "World/sithThing.h"
#include "jk.h"

int sithCollide_sub_5080D0(sithThing *thing, rdVector3 *a2, rdVector3 *a3, float a4, float a5, sithThing *a6, int a7, float *a8, rdMesh **outMesh, rdFace **a10, rdVector3 *a11)
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

int sithCollide_sub_508540(rdVector3 *a1, rdVector3 *a2, float a3, float a4, rdVector3 *a5, float a6, float *a7, int a8, int a9)
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
        v24 = sqrt(v25 * v25 + v26 * v26 + v28 * v28);
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
    v21 = sqrt(v20 + v19 * v30 + v18 * v32);
    if ( v21 >= v33 )
        return 0;
    v22 = v34 - sqrt(v33 * v33 - v21 * v21);
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
