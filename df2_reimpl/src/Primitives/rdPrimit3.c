#include "rdPrimit3.h"

#include "Primitives/rdFace.h"
#include "Engine/rdCamera.h"
#include "Engine/rdClip.h"

void rdPrimit3_ClearFrameCounters()
{
}

void rdPrimit3_ClipFace(rdClipFrustum *clipFrustum, signed int clipType, signed int clipSubtype, int sortingMethod, rdVertexIdxInfo *idxInfo, rdMeshinfo *mesh_out, rdVector2 *idkIn)
{
    rdVertexIdxInfo *v7; // eax
    rdMeshinfo *v8; // ebx
    int v9; // esi
    rdVector3 *v10; // edi
    rdVector3 *v11; // edx
    int *v12; // ecx
    int v13; // eax
    rdVector3 *v14; // ebx
    rdVertexIdxInfo *v15; // eax
    rdMeshinfo *v16; // ebx
    int v17; // esi
    rdVector3 *v18; // edi
    rdVector3 *v19; // edx
    int *v20; // ecx
    int v21; // eax
    rdVector3 *v22; // ebx
    rdVertexIdxInfo *v23; // eax
    int v24; // esi
    rdVector3 *v25; // edi
    rdVector3 *v26; // edx
    int *v27; // ecx
    int v28; // eax
    rdVector3 *v29; // ebx
    rdVertexIdxInfo *v30; // eax
    rdVector3 *v31; // edi
    rdVector3 *v32; // edx
    int *v33; // ecx
    int v34; // eax
    rdVector3 *v35; // ebx
    rdVertexIdxInfo *v36; // eax
    rdMeshinfo *v37; // ebx
    int *v38; // esi
    int v39; // ebp
    int *v40; // ecx
    rdVector3 *v41; // edx
    int v42; // esi
    int v43; // eax
    rdVector3 *v44; // edi
    double v45; // st7
    rdVector3 *v46; // esi
    int *v47; // edx
    float *v48; // edi
    int v49; // ecx
    rdVector3 *v50; // eax
    double v51; // st7
    rdVertexIdxInfo *v52; // eax
    rdMeshinfo *v53; // ebx
    int *v54; // edi
    int v55; // ebp
    rdVector3 *v56; // esi
    int *v57; // edx
    rdVector2 *v58; // ecx
    int v59; // eax
    rdVector3 *v60; // edi
    int v61; // ebx
    double v62; // st7
    int *v63; // esi
    rdVector3 *v64; // edi
    rdVector2 *v65; // ecx
    int v66; // edx
    rdVector3 *v67; // eax
    int v68; // ebx
    double v69; // st7
    rdMeshinfo *v71; // esi
    int v72; // ebx
    int *v73; // ecx
    rdVector2 *v74; // edi
    rdVector2 *v75; // eax
    rdVector3 *v76; // esi
    char *v77; // edx
    int v78; // edx
    rdVector3 *v79; // ebx
    int v80; // edx
    rdVector3 *v82; // [esp-Ch] [ebp-30h]
    rdVector3 *v83; // [esp-Ch] [ebp-30h]
    float *v84; // [esp-8h] [ebp-2Ch]
    rdVector2 *v85; // [esp-8h] [ebp-2Ch]
    int v86; // [esp-4h] [ebp-28h]
    float *v87; // [esp+10h] [ebp-14h]
    float *v88; // [esp+10h] [ebp-14h]
    float *v89; // [esp+10h] [ebp-14h]
    int v90; // [esp+14h] [ebp-10h]
    int v91; // [esp+14h] [ebp-10h]
    rdVector2 *v92; // [esp+18h] [ebp-Ch]
    rdVector2 *v93; // [esp+18h] [ebp-Ch]
    int v94; // [esp+1Ch] [ebp-8h]
    int v95; // [esp+1Ch] [ebp-8h]
    int v96; // [esp+20h] [ebp-4h]
    char *v97; // [esp+20h] [ebp-4h]
    signed int a2a; // [esp+2Ch] [ebp+8h]
    char *a2b; // [esp+2Ch] [ebp+8h]
    signed int a2c; // [esp+2Ch] [ebp+8h]
    signed int a2d; // [esp+2Ch] [ebp+8h]
    signed int a2e; // [esp+2Ch] [ebp+8h]
    rdVector3 *a3a; // [esp+30h] [ebp+Ch]
    rdVector3 *a3b; // [esp+30h] [ebp+Ch]
    rdVector3 *a3c; // [esp+30h] [ebp+Ch]
    rdVector3 *a3d; // [esp+30h] [ebp+Ch]
    rdVector3 *a3e; // [esp+30h] [ebp+Ch]
    int idxInfoa; // [esp+38h] [ebp+14h]
    int idxInfob; // [esp+38h] [ebp+14h]
    int idxInfoc; // [esp+38h] [ebp+14h]
    int idxInfod; // [esp+38h] [ebp+14h]
    int idxInfoe; // [esp+38h] [ebp+14h]
    int idxInfof; // [esp+38h] [ebp+14h]
    int idxInfog; // [esp+38h] [ebp+14h]
    int a7a; // [esp+40h] [ebp+1Ch]
    int a7b; // [esp+40h] [ebp+1Ch]

    switch ( clipType )
    {
        case 0:
            v15 = idxInfo;
            v16 = mesh_out;
            v17 = idxInfo->numVertices;
            idxInfob = idxInfo->numVertices;
            if ( idxInfob )
            {
                v18 = v15->vertices;
                v19 = mesh_out->verticesProjected;
                v20 = v15->vertexPosIdx;
                do
                {
                    v21 = *v20;
                    v22 = v19;
                    ++v20;
                    ++v19;
                    --v17;
                    *v22 = v18[v21];
                }
                while ( v17 );
                v17 = idxInfob;
                v16 = mesh_out;
            }
            v86 = v17;
            if ( rdCamera_pCurCamera->projectType == 1 )
LABEL_26:
                v16->numVertices = rdClip_Face3S(clipFrustum, v16->verticesProjected, v86);
            else
LABEL_27:
                v16->numVertices = rdClip_Face3SOrtho(clipFrustum, v16->verticesProjected, v86);
            break;
        case 1:
        case 2:
            v7 = idxInfo;
            v8 = mesh_out;
            v9 = idxInfo->numVertices;
            idxInfoa = idxInfo->numVertices;
            if ( idxInfoa )
            {
                v10 = v7->vertices;
                v11 = mesh_out->verticesProjected;
                v12 = v7->vertexPosIdx;
                do
                {
                    v13 = *v12;
                    v14 = v11;
                    ++v12;
                    ++v11;
                    --v9;
                    *v14 = v10[v13];
                }
                while ( v9 );
                v9 = idxInfoa;
                v8 = mesh_out;
            }
            if ( rdCamera_pCurCamera->projectType == 1 )
                v8->numVertices = rdClip_Face3W(clipFrustum, v8->verticesProjected, v9);
            else
                v8->numVertices = rdClip_Face3WOrtho(clipFrustum, v8->verticesProjected, v9);
            break;
        case 3:
            switch ( clipSubtype )
            {
                case 0:
                case 1:
                    v23 = idxInfo;
                    v16 = mesh_out;
                    v24 = idxInfo->numVertices;
                    idxInfoc = idxInfo->numVertices;
                    if ( !idxInfoc )
                        goto LABEL_25;
                    v25 = v23->vertices;
                    v26 = mesh_out->verticesProjected;
                    v27 = v23->vertexPosIdx;
                    do
                    {
                        v28 = *v27;
                        v29 = v26;
                        ++v27;
                        ++v26;
                        --v24;
                        *v29 = v25[v28];
                    }
                    while ( v24 );
                    v16 = mesh_out;
                    v86 = idxInfoc;
                    if ( rdCamera_pCurCamera->projectType != 1 )
                        goto LABEL_27;
                    mesh_out->numVertices = rdClip_Face3S(clipFrustum, mesh_out->verticesProjected, idxInfoc);
                    break;
                case 2:
                    v30 = idxInfo;
                    v16 = mesh_out;
                    v24 = idxInfo->numVertices;
                    idxInfod = idxInfo->numVertices;
                    if ( idxInfod )
                    {
                        v31 = v30->vertices;
                        v32 = mesh_out->verticesProjected;
                        v33 = v30->vertexPosIdx;
                        do
                        {
                            v34 = *v33;
                            v35 = v32;
                            ++v33;
                            ++v32;
                            --v24;
                            *v35 = v31[v34];
                        }
                        while ( v24 );
                        v24 = idxInfod;
                        v16 = mesh_out;
                    }
LABEL_25:
                    v86 = v24;
                    if ( rdCamera_pCurCamera->projectType == 1 )
                        goto LABEL_26;
                    goto LABEL_27;
                case 3:
                    v36 = idxInfo;
                    v37 = mesh_out;
                    v38 = idxInfo->field_18;
                    v39 = idxInfo->numVertices;
                    idxInfoe = idxInfo->numVertices;
                    if ( v38 )
                    {
                        if ( v39 )
                        {
                            a3a = v36->vertices;
                            v40 = v36->vertexPosIdx;
                            v87 = v36->field_14;
                            v41 = mesh_out->verticesProjected;
                            v42 = (char *)v38 - (char *)v40;
                            a7a = v39;
                            a2a = (char *)mesh_out->vertex_lights_maybe_ - (char *)v40;
                            do
                            {
                                v43 = *v40;
                                v44 = &a3a[*v40];
                                v41->x = v44->x;
                                v41->y = v44->y;
                                v41->z = v44->z;
                                v45 = v87[v43] + *(float *)((char *)v40 + v42);
                                if ( v45 < 0.0 )
                                {
                                    v45 = 0.0;
                                }
                                else if ( v45 > 1.0 )
                                {
                                    v45 = 1.0;
                                }
                                ++v41;
                                *(float *)((char *)v40++ + a2a) = v45;
                                --a7a;
                            }
                            while ( a7a );
                            v39 = idxInfoe;
                            v37 = mesh_out;
                        }
                    }
                    else if ( v39 )
                    {
                        v46 = mesh_out->verticesProjected;
                        v47 = v36->vertexPosIdx;
                        v48 = v36->field_14;
                        a3b = v36->vertices;
                        a2b = (char *)((char *)mesh_out->vertex_lights_maybe_ - (char *)v47);
                        a7b = v39;
                        do
                        {
                            v49 = *v47;
                            v50 = &a3b[*v47];
                            v46->x = v50->x;
                            v46->y = v50->y;
                            v46->z = v50->z;
                            if ( v48[v49] < 0.0 )
                            {
                                v51 = 0.0;
                            }
                            else if ( v48[v49] > 1.0 )
                            {
                                v51 = 1.0;
                            }
                            else
                            {
                                v51 = v48[v49];
                            }
                            ++v46;
                            *(float *)&a2b[(intptr_t)v47++] = v51;
                            --a7b;
                        }
                        while ( a7b );
                        v37 = mesh_out;
                        v39 = idxInfoe;
                    }
                    v84 = (float*)v37->vertex_lights_maybe_;
                    v82 = v37->verticesProjected;
                    if ( rdCamera_pCurCamera->projectType == 1 )
                        v37->numVertices = rdClip_Face3GS(clipFrustum, v82, v84, v39);
                    else
                        v37->numVertices = rdClip_Face3GSOrtho(clipFrustum, v82, v84, v39);
                    break;
                default:
                    return;
            }
            break;
        case 4:
            if ( clipSubtype >= 0 )
            {
                if ( clipSubtype <= 2 )
                {
                    v71 = mesh_out;
                    v72 = idxInfo->numVertices;
                    idxInfog = idxInfo->numVertices;
                    if ( idxInfog )
                    {
                        v73 = idxInfo->vertexUVIdx;
                        v74 = idxInfo->extraUV;
                        a3e = idxInfo->vertices;
                        v75 = mesh_out->vertexUVs;
                        v76 = mesh_out->verticesProjected;
                        v77 = (char *)((char *)idxInfo->vertexPosIdx - (char *)v73);
                        v97 = v77;
                        a2e = v72;
                        while ( 1 )
                        {
                            v78 = *(int *)((char *)v73++ + (intptr_t)v77);
                            ++v75;
                            v79 = v76++;
                            *v79 = a3e[v78];
                            v80 = *(v73 - 1);
                            v75[-1].x = v74[v80].x;
                            v75[-1].y = v74[v80].y;
                            v75[-1].x = idkIn->x + v75[-1].x;
                            v75[-1].y = v75[-1].y + idkIn->y;
                            if ( a2e-- == 1)
                                break;
                            v77 = v97;
                        }
                        v71 = mesh_out;
                        v72 = idxInfog;
                    }
                    v85 = v71->vertexUVs;
                    v83 = v71->verticesProjected;
                    if ( rdCamera_pCurCamera->projectType == 1 )
                        v71->numVertices = rdClip_Face3T(clipFrustum, v83, v85, v72);
                    else
                        v71->numVertices = rdClip_Face3TOrtho(clipFrustum, v83, v85, v72);
                }
                else if ( clipSubtype == 3 )
                {
                    v52 = idxInfo;
                    v53 = mesh_out;
                    v54 = idxInfo->field_18;
                    v55 = idxInfo->numVertices;
                    idxInfof = idxInfo->numVertices;
                    if ( v54 )
                    {
                        if ( v55 )
                        {
                            v56 = mesh_out->verticesProjected;
                            a3c = v52->vertices;
                            v92 = v52->extraUV;
                            v57 = v52->vertexPosIdx;
                            v88 = v52->field_14;
                            v58 = mesh_out->vertexUVs;
                            v90 = (char *)v52->vertexUVIdx - (char *)v57;
                            v96 = (char *)v54 - (char *)v57;
                            a2c = (char *)mesh_out->vertex_lights_maybe_ - (char *)v57;
                            v94 = v55;
                            do
                            {
                                v59 = *v57;
                                v60 = &a3c[*v57];
                                v56->x = v60->x;
                                v56->y = v60->y;
                                v56->z = v60->z;
                                v61 = *(int *)((char *)v57 + v90);
                                v58->x = v92[v61].x;
                                v58->y = v92[v61].y;
                                v58->x = idkIn->x + v58->x;
                                v58->y = v58->y + idkIn->y;
                                v62 = v88[v59] + *(float *)((char *)v57 + v96);
                                if ( v62 < 0.0 )
                                {
                                    v62 = 0.0;
                                }
                                else if ( v62 > 1.0 )
                                {
                                    v62 = 1.0;
                                }
                                ++v56;
                                ++v58;
                                *(float *)((char *)v57++ + a2c) = v62;
                                --v94;
                            }
                            while ( v94 );
                            v55 = idxInfof;
                            v53 = mesh_out;
                        }
                    }
                    else if ( v55 )
                    {
                        v63 = v52->vertexPosIdx;
                        v64 = mesh_out->verticesProjected;
                        a3d = v52->vertices;
                        v89 = v52->field_14;
                        v65 = mesh_out->vertexUVs;
                        v93 = v52->extraUV;
                        v91 = (char *)v52->vertexUVIdx - (char *)v63;
                        a2d = (char *)mesh_out->vertex_lights_maybe_ - (char *)v63;
                        v95 = v55;
                        do
                        {
                            v66 = *v63;
                            v67 = &a3d[*v63];
                            v64->x = v67->x;
                            v64->y = v67->y;
                            v64->z = v67->z;
                            v68 = *(int *)((char *)v63 + v91);
                            v65->x = v93[v68].x;
                            v65->y = v93[v68].y;
                            v65->x = idkIn->x + v65->x;
                            v65->y = v65->y + idkIn->y;
                            if ( v89[v66] < 0.0 )
                            {
                                v69 = 0.0;
                            }
                            else if ( v89[v66] > 1.0 )
                            {
                                v69 = 1.0;
                            }
                            else
                            {
                                v69 = v89[v66];
                            }
                            ++v64;
                            ++v65;
                            *(float *)((char *)v63++ + a2d) = v69;
                            --v95;
                        }
                        while ( v95 );
                        v53 = mesh_out;
                        v55 = idxInfof;
                    }
                    if ( rdCamera_pCurCamera->projectType == 1 )
                        v53->numVertices = rdClip_Face3GT(clipFrustum, v53->verticesProjected, v53->vertexUVs, v53->vertex_lights_maybe_, v55);
                    else
                        v53->numVertices = rdClip_Face3GTOrtho(clipFrustum, v53->verticesProjected, v53->vertexUVs, v53->vertex_lights_maybe_, v55);
                }
            }
            break;
        default:
            return;
    }
}
