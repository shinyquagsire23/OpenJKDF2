#include "rdPrimit3.h"

#include "Raster/rdFace.h"
#include "Primitives/rdPrimit2.h"
#include "Engine/rdCamera.h"
#include "Engine/rdClip.h"
#include "General/stdMath.h"

#include "jk.h"

void rdPrimit3_ClearFrameCounters()
{
}

void rdPrimit3_ClipFace(rdClipFrustum *clipFrustum, rdGeoMode_t geoMode, signed int lightMode, int texMode, rdVertexIdxInfo *idxInfo, rdMeshinfo *mesh_out, rdVector2 *idkIn)
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
    float *v38; // esi
    int v39; // ebp
    int *v40; // ecx
    rdVector3 *v41; // edx
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
    float *v54; // edi
    int v55; // ebp
    rdVector3 *v56; // esi
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
    int v91; // [esp+14h] [ebp-10h]
    rdVector2 *v92; // [esp+18h] [ebp-Ch]
    rdVector2 *v93; // [esp+18h] [ebp-Ch]
    int v95; // [esp+1Ch] [ebp-8h]
    char *v97; // [esp+20h] [ebp-4h]
    char *a2b; // [esp+2Ch] [ebp+8h]
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

    //rdPrimit3_NoClipFace(clipType, clipSubtype, sortingMethod, idxInfo, mesh_out, idkIn);
    //return;

    switch ( geoMode )
    {
        case RD_GEOMODE_NOTRENDERED:
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
            if (rdCamera_pCurCamera->projectType == rdCameraProjectType_Perspective)
LABEL_26:
                v16->numVertices = rdClip_Face3S(clipFrustum, v16->verticesProjected, v86);
            else
LABEL_27:
                v16->numVertices = rdClip_Face3SOrtho(clipFrustum, v16->verticesProjected, v86);
            break;
        case RD_GEOMODE_VERTICES:
        case RD_GEOMODE_WIREFRAME:
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
            if (rdCamera_pCurCamera->projectType == rdCameraProjectType_Perspective)
                v8->numVertices = rdClip_Face3W(clipFrustum, v8->verticesProjected, v9);
            else
                v8->numVertices = rdClip_Face3WOrtho(clipFrustum, v8->verticesProjected, v9);
            break;
        case RD_GEOMODE_SOLIDCOLOR:
            switch ( lightMode )
            {
                case RD_LIGHTMODE_FULLYLIT:
                case RD_LIGHTMODE_NOTLIT:
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
                    if ( rdCamera_pCurCamera->projectType != rdCameraProjectType_Perspective)
                        goto LABEL_27;
                    mesh_out->numVertices = rdClip_Face3S(clipFrustum, mesh_out->verticesProjected, idxInfoc);
                    break;
                case RD_LIGHTMODE_DIFFUSE:
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
                    if ( rdCamera_pCurCamera->projectType == rdCameraProjectType_Perspective)
                        goto LABEL_26;
                    goto LABEL_27;
                case RD_LIGHTMODE_GOURAUD:
                    v36 = idxInfo;
                    v37 = mesh_out;
                    v38 = idxInfo->intensities;
                    v39 = idxInfo->numVertices;
                    idxInfoe = idxInfo->numVertices;
                    if ( v38 )
                    {
                        if ( v39 )
                        {
                            a3a = v36->vertices;
                            v40 = v36->vertexPosIdx;
                            v87 = v36->paDynamicLight;
                            v41 = mesh_out->verticesProjected;
                            float* intenseIter = v38;
                            a7a = v39;
                            float* lightIter = mesh_out->paDynamicLight;
                            do
                            {
                                v43 = *v40;
                                v44 = &a3a[*v40];
                                v41->x = v44->x;
                                v41->y = v44->y;
                                v41->z = v44->z;
                                v45 = v87[v43] + *intenseIter;
                                if ( v45 < 0.0 )
                                {
                                    v45 = 0.0;
                                }
                                else if ( v45 > 1.0 )
                                {
                                    v45 = 1.0;
                                }
                                ++v41;
                                *lightIter = v45;
                                lightIter++;
                                intenseIter++;
                                v40++;
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
                        v48 = v36->paDynamicLight;
                        a3b = v36->vertices;
                        a2b = (char *)((char *)mesh_out->paDynamicLight - (char *)v47);
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
                    v84 = (float*)v37->paDynamicLight;
                    v82 = v37->verticesProjected;
                    if (rdCamera_pCurCamera->projectType == rdCameraProjectType_Perspective)
                        v37->numVertices = rdClip_Face3GS(clipFrustum, v82, v84, v39);
                    else
                        v37->numVertices = rdClip_Face3GSOrtho(clipFrustum, v82, v84, v39);
                    break;
                default:
                    return;
            }
            break;
        case RD_GEOMODE_TEXTURED:
            if ( lightMode >= RD_LIGHTMODE_FULLYLIT)
            {
                if ( lightMode <= RD_LIGHTMODE_DIFFUSE)
                {
                    v71 = mesh_out;
                    v72 = idxInfo->numVertices;
                    idxInfog = idxInfo->numVertices;
                    if ( idxInfog )
                    {
                        v73 = idxInfo->vertexUVIdx;
                        v74 = idxInfo->vertexUVs;
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
                    if (rdCamera_pCurCamera->projectType == rdCameraProjectType_Perspective)
                        v71->numVertices = rdClip_Face3T(clipFrustum, v83, v85, v72);
                    else
                        v71->numVertices = rdClip_Face3TOrtho(clipFrustum, v83, v85, v72);
                }
                else if ( lightMode == RD_LIGHTMODE_GOURAUD)
                {
                    v52 = idxInfo;
                    v53 = mesh_out;
                    v54 = idxInfo->intensities;
                    v55 = idxInfo->numVertices;
                    idxInfof = idxInfo->numVertices;
                    if ( v54 )
                    {
                        if ( v55 )
                        {
                            v56 = mesh_out->verticesProjected;
                            a3c = v52->vertices;
                            v92 = v52->vertexUVs;
                            v88 = v52->paDynamicLight;
                            v58 = mesh_out->vertexUVs;
                            //printf("%x %x\n", v52->vertexUVIdx, &v52->vertexUVIdx);
                            for (int i = 0; i < idxInfo->numVertices; i++)
                            {
                                v59 = v52->vertexPosIdx[i];
                                v60 = &a3c[v59];
                                v56->x = v60->x;
                                v56->y = v60->y;
                                v56->z = v60->z;
                                v61 = v52->vertexUVIdx[i];
                                v58->x = v92[v61].x;
                                v58->y = v92[v61].y;
                                v58->x = idkIn->x + v58->x;
                                v58->y = v58->y + idkIn->y;
                                v62 = v88[v59] + idxInfo->intensities[i];
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
                                mesh_out->paDynamicLight[i] = v62;
                            }
                            v55 = idxInfof;
                            v53 = mesh_out;
                        }
                    }
                    else if ( v55 )
                    {
                        v64 = mesh_out->verticesProjected;
                        a3d = v52->vertices;
                        v89 = v52->paDynamicLight;
                        v65 = mesh_out->vertexUVs;
                        v93 = v52->vertexUVs;
                        v95 = v55;
                        for (int i = 0; i < idxInfo->numVertices; i++)
                        {
                            v66 = v52->vertexPosIdx[i];
                            v67 = &a3d[v66];
                            v64->x = v67->x;
                            v64->y = v67->y;
                            v64->z = v67->z;
                            v68 = v52->vertexUVIdx[i];
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
                            mesh_out->paDynamicLight[i] = v69;
                            --v95;
                        }
                        v53 = mesh_out;
                        v55 = idxInfof;
                    }
                    if (rdCamera_pCurCamera->projectType == rdCameraProjectType_Perspective)
                        v53->numVertices = rdClip_Face3GT(clipFrustum, v53->verticesProjected, v53->vertexUVs, v53->paDynamicLight, v55);
                    else
                        v53->numVertices = rdClip_Face3GTOrtho(clipFrustum, v53->verticesProjected, v53->vertexUVs, v53->paDynamicLight, v55);
                }
            }
            break;
        default:
            return;
    }
}

void rdPrimit3_NoClipFace(rdGeoMode_t geoMode, signed int lightMode, int texMode, rdMeshinfo *_vertexSrc, rdMeshinfo *_vertexDst, rdVector2 *idkIn)
{
    rdMeshinfo *v6; // eax
    int v7; // esi
    rdVector3 *v8; // edi
    rdVector3 *v9; // edx
    int *v10; // ecx
    int v11; // eax
    rdVector3 *v12; // ebx
    rdMeshinfo *v13; // eax
    rdVector3 *v14; // edi
    int *v15; // ecx
    rdVector3 *v16; // edx
    int v17; // eax
    rdVector3 *v18; // ebx
    rdMeshinfo *v19; // eax
    rdVector3 *v20; // edi
    int *v21; // ecx
    rdVector3 *v22; // edx
    int v23; // eax
    rdVector3 *v24; // ebx
    rdMeshinfo *v25; // eax
    rdVector3 *v26; // edi
    int *v27; // ecx
    rdVector3 *v28; // edx
    int v29; // eax
    rdVector3 *v30; // ebx
    rdMeshinfo *v31; // eax
    rdMeshinfo *v32; // edi
    float *v33; // esi
    int v34; // ebx
    int *v35; // ecx
    rdVector3 *v36; // edx
    int v37; // esi
    int v38; // edi
    double v39; // st7
    rdVector3 *v40; // esi
    int *paPosIdx; // ecx
    char *v42; // edi
    rdVector3 *v43; // eax
    float *v44; // edx
    double v45; // st7
    rdMeshinfo *v46; // eax
    rdMeshinfo *v47; // ebp
    float *v48; // ebx
    int v49; // ecx
    rdVector2 *v50; // edi
    int *v51; // edx
    rdVector3 *v52; // esi
    rdVector2 *v53; // ecx
    int v54; // eax
    double v55; // st7
    rdVector2 *v56; // ebx
    int *v57; // edx
    rdVector3 *v58; // edi
    rdVector2 *v59; // ecx
    int v60; // eax
    float *v61; // esi
    double v62; // st7
    rdMeshinfo *v64; // esi
    int v65; // ebx
    int *v66; // ecx
    rdVector2 *v67; // edi
    rdVector2 *v68; // eax
    rdVector3 *v69; // esi
    char *v70; // edx
    int v71; // edx
    rdVector3 *v72; // ebx
    int v73; // edx
    int v75; // [esp+10h] [ebp-10h]
    int v76; // [esp+10h] [ebp-10h]
    int v77; // [esp+14h] [ebp-Ch]
    int v78; // [esp+14h] [ebp-Ch]
    int v79; // [esp+18h] [ebp-8h]
    int v80; // [esp+18h] [ebp-8h]
    int v81; // [esp+1Ch] [ebp-4h]
    char *v82; // [esp+1Ch] [ebp-4h]
    float *geometryModea; // [esp+24h] [ebp+4h]
    float *geometryModeb; // [esp+24h] [ebp+4h]
    float *geometryModec; // [esp+24h] [ebp+4h]
    float *geometryModed; // [esp+24h] [ebp+4h]
    int geometryModee; // [esp+24h] [ebp+4h]
    rdVector3 *pVertices; // [esp+28h] [ebp+8h]
    rdVector3 *pVertices_; // [esp+28h] [ebp+8h]
    rdVector3 *lightingModec; // [esp+28h] [ebp+8h]
    rdVector3 *lightingModed; // [esp+28h] [ebp+8h]
    rdVector3 *lightingModee; // [esp+28h] [ebp+8h]
    int vertexSrca; // [esp+30h] [ebp+10h]
    int vertexSrcb; // [esp+30h] [ebp+10h]
    int vertexSrcc; // [esp+30h] [ebp+10h]
    int vertexSrcd; // [esp+30h] [ebp+10h]
    int vertexSrce; // [esp+30h] [ebp+10h]
    int vertexSrcf; // [esp+30h] [ebp+10h]
    int vertexSrcg; // [esp+30h] [ebp+10h]
    int clipIdka; // [esp+38h] [ebp+18h]

    switch ( geoMode )
    {
        case RD_GEOMODE_NOTRENDERED:
            v13 = _vertexSrc;
            v7 = _vertexSrc->numVertices;
            vertexSrcb = _vertexSrc->numVertices;
            if ( !vertexSrcb )
                goto LABEL_19;
            v14 = v13->verticesProjected;
            v15 = v13->vertexPosIdx;
            v16 = _vertexDst->verticesProjected;
            do
            {
                v17 = *v15;
                v18 = v16;
                ++v15;
                ++v16;
                --v7;
                *v18 = v14[v17];
            }
            while ( v7 );
            _vertexDst->numVertices = vertexSrcb;
            return;
        case RD_GEOMODE_VERTICES:
        case RD_GEOMODE_WIREFRAME:
            v6 = _vertexSrc;
            v7 = _vertexSrc->numVertices;
            vertexSrca = _vertexSrc->numVertices;
            if ( vertexSrca )
            {
                v8 = v6->verticesProjected;
                v9 = _vertexDst->verticesProjected;
                v10 = v6->vertexPosIdx;
                do
                {
                    v11 = *v10;
                    v12 = v9;
                    ++v10;
                    ++v9;
                    --v7;
                    *v12 = v8[v11];
                }
                while ( v7 );
                _vertexDst->numVertices = vertexSrca;
            }
            else
            {
LABEL_19:
                _vertexDst->numVertices = v7;
            }
            return;
        case RD_GEOMODE_SOLIDCOLOR:
            switch ( lightMode )
            {
                case RD_LIGHTMODE_FULLYLIT:
                case RD_LIGHTMODE_NOTLIT:
                    v19 = _vertexSrc;
                    v7 = _vertexSrc->numVertices;
                    vertexSrcc = _vertexSrc->numVertices;
                    if ( !vertexSrcc )
                        goto LABEL_19;
                    v20 = v19->verticesProjected;
                    v21 = v19->vertexPosIdx;
                    v22 = _vertexDst->verticesProjected;
                    do
                    {
                        v23 = *v21;
                        v24 = v22;
                        ++v21;
                        ++v22;
                        --v7;
                        *v24 = v20[v23];
                    }
                    while ( v7 );
                    _vertexDst->numVertices = vertexSrcc;
                    return;
                case RD_LIGHTMODE_DIFFUSE:
                    v25 = _vertexSrc;
                    v7 = _vertexSrc->numVertices;
                    vertexSrcd = _vertexSrc->numVertices;
                    if ( vertexSrcd )
                    {
                        v26 = v25->verticesProjected;
                        v27 = v25->vertexPosIdx;
                        v28 = _vertexDst->verticesProjected;
                        do
                        {
                            v29 = *v27;
                            v30 = v28;
                            ++v27;
                            ++v28;
                            --v7;
                            *v30 = v26[v29];
                        }
                        while ( v7 );
                        v7 = vertexSrcd;
                    }
                    goto LABEL_19;
                case RD_LIGHTMODE_GOURAUD:
                    v31 = _vertexSrc;
                    v32 = _vertexDst;
                    v33 = _vertexSrc->intensities;
                    v34 = _vertexSrc->numVertices;
                    vertexSrce = _vertexSrc->numVertices;
                    if ( v33 )
                    {
                        if ( v34 )
                        {
                            v35 = v31->vertexPosIdx;
                            pVertices = v31->verticesProjected;
                            v36 = _vertexDst->verticesProjected;
                            geometryModea = v31->paDynamicLight;
                            float* lightIter = _vertexDst->paDynamicLight;
                            clipIdka = v34;
                            do
                            {
                                *v36 = pVertices[*v35];
                                v39 = geometryModea[*v35] + *(v33++);
                                if ( v39 < 0.0 )
                                {
                                    v39 = 0.0;
                                }
                                else if ( v39 > 1.0 )
                                {
                                    v39 = 1.0;
                                }
                                *(lightIter++) = v39;
                                ++v36;
                                ++v35;
                                --clipIdka;
                            }
                            while ( clipIdka );
                            _vertexDst->numVertices = vertexSrce;
                            return;
                        }
                    }
                    else if ( v34 )
                    {
                        v40 = _vertexDst->verticesProjected;
                        pVertices_ = v31->verticesProjected;
                        paPosIdx = v31->vertexPosIdx;
                        geometryModeb = v31->paDynamicLight;
                        float* lightIter = _vertexDst->paDynamicLight;
                        do
                        {
                            v43 = &pVertices_[*paPosIdx];
                            v40->x = v43->x;
                            v40->y = v43->y;
                            v40->z = v43->z;
                            v44 = &geometryModeb[*paPosIdx];
                            if ( *v44 < 0.0 )
                            {
                                v45 = 0.0;
                            }
                            else if ( *v44 > 1.0 )
                            {
                                v45 = 1.0;
                            }
                            else
                            {
                                v45 = *v44;
                            }
                            *(lightIter++) = v45;
                            ++v40;
                            ++paPosIdx;
                            --v34;
                        }
                        while ( v34 );
                        v32 = _vertexDst;
                        v34 = vertexSrce;
                    }
                    v32->numVertices = v34;
                    return;
                default:
                    return;
            }
        case RD_GEOMODE_TEXTURED:
            if ( lightMode < RD_LIGHTMODE_FULLYLIT)
                return;
            if ( lightMode > RD_LIGHTMODE_DIFFUSE)
            {
                if ( lightMode != RD_LIGHTMODE_GOURAUD)
                    return;
                v46 = _vertexSrc;
                v47 = _vertexDst;
                v48 = _vertexSrc->intensities;
                v49 = _vertexSrc->numVertices;
                vertexSrcf = _vertexSrc->numVertices;
                if ( v48 )
                {
                    if ( v49 )
                    {
                        v50 = v46->vertexUVs;
                        v51 = v46->vertexPosIdx;
                        lightingModec = v46->verticesProjected;
                        v52 = _vertexDst->verticesProjected;
                        int* uvIter = v46->vertexUVIdx;
                        geometryModec = v46->paDynamicLight;
                        v53 = _vertexDst->vertexUVs;
                        v79 = vertexSrcf;
                        float* lightIter = _vertexDst->paDynamicLight;
                        do
                        {
                            *v52 = lightingModec[*v51];
                            v54 = *(uvIter++);
                            v53->x = v50[v54].x;
                            v53->y = v50[v54].y;
                            v53->x = idkIn->x + v53->x;
                            v53->y = v53->y + idkIn->y;
                            v55 = geometryModec[*v51] + *(v48++);
                            if ( v55 < 0.0 )
                            {
                                v55 = 0.0;
                            }
                            else if ( v55 > 1.0 )
                            {
                                v55 = 1.0;
                            }
                            ++v52;
                            ++v53;
                            *(lightIter++) = v55;
                            v51++;
                            --v79;
                        }
                        while ( v79 );
                        _vertexDst->numVertices = vertexSrcf;
                        return;
                    }
                }
                else if ( v49 )
                {
                    v56 = v46->vertexUVs;
                    v57 = v46->vertexPosIdx;
                    v58 = _vertexDst->verticesProjected;
                    lightingModed = v46->verticesProjected;
                    geometryModed = v46->paDynamicLight;
                    v59 = _vertexDst->vertexUVs;
                    float* lightIter = _vertexDst->paDynamicLight;
                    v80 = vertexSrcf;
                    int* uvIter = v46->vertexUVIdx;
                    do
                    {
                        *v58 = lightingModed[*v57];
                        v60 = *(uvIter++);
                        v59->x = v56[v60].x;
                        v59->y = v56[v60].y;
                        v59->x = idkIn->x + v59->x;
                        v59->y = v59->y + idkIn->y;
                        v61 = &geometryModed[*v57];
                        if ( *v61 < 0.0 )
                        {
                            v62 = 0.0;
                        }
                        else if ( *v61 > 1.0 )
                        {
                            v62 = 1.0;
                        }
                        else
                        {
                            v62 = *v61;
                        }
                        ++v58;
                        ++v59;
                        v57++;
                        *(lightIter++) = v62;
                        --v80;
                    }
                    while ( v80 );
                    v47 = _vertexDst;
                }
                v47->numVertices = vertexSrcf;
                return;
            }
            v64 = _vertexDst;
            v65 = _vertexSrc->numVertices;
            vertexSrcg = _vertexSrc->numVertices;
            if ( vertexSrcg )
            {
                v66 = _vertexSrc->vertexUVIdx;
                v67 = _vertexSrc->vertexUVs;
                lightingModee = _vertexSrc->verticesProjected;
                v68 = _vertexDst->vertexUVs;
                v69 = _vertexDst->verticesProjected;
                int* idxIter = _vertexSrc->vertexPosIdx;
                geometryModee = v65;
                while ( 1 )
                {
                    v71 = *(idxIter++);
                    
                    v72 = v69++;
                    *v72 = lightingModee[v71];
                    v73 = *(v66++);
                    v68->x = v67[v73].x;
                    v68->y = v67[v73].y;
                    v68->x = idkIn->x + v68->x;
                    v68->y = v68->y + idkIn->y;
                    ++v68;
                    if ( geometryModee-- == 1 )
                        break;
                }
                v64 = _vertexDst;
                v65 = vertexSrcg;
            }
            v64->numVertices = v65;
            return;
        default:
            return;
    }
}

int rdPrimit3_GetScreenCoord(rdVector3 *vec, rdScreenPoint *screenpt)
{
    double v2; // st7
    rdVector3 v4; // [esp+0h] [ebp-18h] BYREF
    rdVector3 a2a; // [esp+Ch] [ebp-Ch] BYREF

    rdMatrix_TransformPoint34(&a2a, vec, &rdCamera_pCurCamera->view_matrix);
    if ( !rdClip_Point3(rdCamera_pCurCamera->pClipFrustum, &a2a) )
        return 0;
    rdCamera_pCurCamera->fnProject(&v4, &a2a);
    if ( screenpt )
    {
        v2 = v4.y;
        screenpt->x = (__int64)v4.x;
        screenpt->y = (__int64)v2;
        screenpt->z = v4.z;
    }
    return 1;
}

void rdPrimit3_DrawCircle(rdVector3 *pVecPos, float xOffs, float radius, int color16, int mask)
{
    float v5; // [esp+0h] [ebp-40h]
    rdVector3 vertex_out; // [esp+10h] [ebp-30h] BYREF
    rdVector3 v7; // [esp+1Ch] [ebp-24h] BYREF
    rdVector3 v8; // [esp+28h] [ebp-18h] BYREF
    rdVector3 v9; // [esp+34h] [ebp-Ch] BYREF

    // TODO is this GetScreenCoord but inlined?

    rdMatrix_TransformPoint34(&vertex_out, pVecPos, &rdCamera_pCurCamera->view_matrix);
    v7.y = vertex_out.y;
    v7.z = vertex_out.z;
    v7.x = vertex_out.x + xOffs;
    if ( vertex_out.y > 0.0 )
    {
        rdCamera_pCurCamera->fnProject(&v8, &vertex_out);
        rdCamera_pCurCamera->fnProject(&v9, &v7);
        v5 = v9.x - v8.x;
        rdPrimit2_DrawCircle(rdCamera_pCurCamera->canvas, (__int64)(v8.x - -0.5), (__int64)(v8.y - -0.5), v5, radius, color16, mask);
    }
}

//MOTS added
void rdPrimit3_NoClipFaceRGB
               (rdGeoMode_t geoMode,int lightMode,int texMode,rdMeshinfo *_vertexSrc,
               rdMeshinfo *_vertexDst,rdVector2 *idkIn)

{
    rdVector3 *prVar1;
    float *pfVar2;
    rdVector3 *prVar3;
    float *pfVar4;
    float *pfVar5;
    float *pfVar6;
    float *pfVar7;
    float *pfVar8;
    int *piVar9;
    float *pfVar10;
    intptr_t iVar11;
    float fVar12;
    rdVector2 *prVar13;
    int *piVar14;
    rdVector2 *prVar15;
    rdVector2 *prVar16;
    int *piVar17;
    rdVector3 *prVar18;
    intptr_t iVar19;
    uint32_t uVar20;
    uint32_t uVar21;
    intptr_t iVar22;
    rdVector3 *local_14;
    rdVector2 *local_10;

    uint32_t idxIter = 0;
    
    switch(geoMode) {
    case 0:
        uVar21 = _vertexSrc->numVertices;
        if (uVar21 != 0) {
            prVar3 = _vertexSrc->verticesProjected;
            piVar14 = _vertexSrc->vertexPosIdx;
            prVar18 = _vertexDst->verticesProjected;
            uVar20 = uVar21;
            do {
                iVar19 = *piVar14;
                piVar14 = piVar14 + 1;
                uVar20 = uVar20 - 1;
                prVar1 = prVar3 + iVar19;
                prVar18->x = prVar1->x;
                prVar18->y = prVar1->y;
                prVar18->z = prVar1->z;
                prVar18 = prVar18 + 1;
            } while (uVar20 != 0);
            _vertexDst->numVertices = uVar21;
            return;
        }
        break;
    case 1:
    case 2:
        uVar21 = _vertexSrc->numVertices;
        if (uVar21 != 0) {
            prVar3 = _vertexSrc->verticesProjected;
            piVar14 = _vertexSrc->vertexPosIdx;
            prVar18 = _vertexDst->verticesProjected;
            uVar20 = uVar21;
            do {
                iVar19 = *piVar14;
                piVar14 = piVar14 + 1;
                uVar20 = uVar20 - 1;
                prVar1 = prVar3 + iVar19;
                prVar18->x = prVar1->x;
                prVar18->y = prVar1->y;
                prVar18->z = prVar1->z;
                prVar18 = prVar18 + 1;
            } while (uVar20 != 0);
            _vertexDst->numVertices = uVar21;
            return;
        }
        break;
    case 3:
        switch(lightMode) {
        case 0:
        case 1:
            uVar21 = _vertexSrc->numVertices;
            if (uVar21 != 0) {
                prVar3 = _vertexSrc->verticesProjected;
                piVar14 = _vertexSrc->vertexPosIdx;
                prVar18 = _vertexDst->verticesProjected;
                uVar20 = uVar21;
                do {
                    iVar19 = *piVar14;
                    piVar14 = piVar14 + 1;
                    uVar20 = uVar20 - 1;
                    prVar1 = prVar3 + iVar19;
                    prVar18->x = prVar1->x;
                    prVar18->y = prVar1->y;
                    prVar18->z = prVar1->z;
                    prVar18 = prVar18 + 1;
                } while (uVar20 != 0);
                goto LAB_0044d6ad;
            }
            break;
        case 2:
            uVar21 = _vertexSrc->numVertices;
            if (uVar21 != 0) {
                prVar3 = _vertexSrc->verticesProjected;
                piVar14 = _vertexSrc->vertexPosIdx;
                prVar18 = _vertexDst->verticesProjected;
                uVar20 = uVar21;
                do {
                    iVar19 = *piVar14;
                    piVar14 = piVar14 + 1;
                    uVar20 = uVar20 - 1;
                    prVar1 = prVar3 + iVar19;
                    prVar18->x = prVar1->x;
                    prVar18->y = prVar1->y;
                    prVar18->z = prVar1->z;
                    prVar18 = prVar18 + 1;
                } while (uVar20 != 0);
            }
            break;
        case 3:
            if (_vertexSrc->numVertices != 0x0) {
                prVar3 = _vertexSrc->verticesProjected;
                pfVar4 = _vertexSrc->paRedIntensities;
                pfVar5 = _vertexDst->paGreenIntensities;
                pfVar6 = _vertexDst->paRedIntensities;
                prVar18 = _vertexDst->verticesProjected;
                pfVar7 = _vertexSrc->paGreenIntensities;
                piVar14 = _vertexSrc->vertexPosIdx;
                pfVar8 = _vertexSrc->paDynamicLight;
                pfVar10 = _vertexSrc->paBlueIntensities;
                float* blueIter = _vertexDst->paBlueIntensities;
                int idkIn_ = _vertexSrc->numVertices;
                idxIter = 0;
                do {
                    prVar1 = prVar3 + *piVar14;
                    prVar18->x = prVar1->x;
                    prVar18->y = prVar1->y;
                    prVar18->z = prVar1->z;
                    fVar12 = pfVar4[*piVar14] + pfVar8[*piVar14];
                    if (fVar12 < 0.0) {
                        fVar12 = 0.0;
                    }
                    else if (fVar12 > 1.0) {
                        fVar12 = 1.0;
                    }
                    *pfVar6 = fVar12;
                    fVar12 = pfVar7[*piVar14] + pfVar8[*piVar14];
                    if (fVar12 < 0.0) {
                        fVar12 = 0.0;
                    }
                    else if (fVar12 > 1.0) {
                        fVar12 = 1.0;
                    }
                    *pfVar5 = fVar12;
                    fVar12 = pfVar10[*piVar14] + pfVar8[*piVar14];
                    if (fVar12 < 0.0) {
                        fVar12 = 0.0;
                    }
                    else if (fVar12 > 1.0) {
                        fVar12 = 1.0;
                    }
                    prVar18 = prVar18 + 1;
                    *blueIter = fVar12;
                    piVar14 = piVar14 + 1;
                    pfVar5++;
                    pfVar6++;
                    blueIter++;
                    idkIn_--;
                    idxIter++;
                } while (idkIn_ != 0x0);
                _vertexDst->numVertices = _vertexSrc->numVertices;
                return;
            }
            _vertexDst->numVertices = _vertexSrc->numVertices;
            return;
        default:
            goto switchD_0044d5a4_caseD_5;
        }
        _vertexDst->numVertices = uVar21;
        return;
    case 4:
        if (-1 < lightMode) {
            if (lightMode < 3) {
                for (int i = 0; i < _vertexSrc->numVertices; i++)
                {
                    int vtxIdx = _vertexSrc->vertexPosIdx[i];
                    int uvIdx = _vertexSrc->vertexUVIdx[i];
                    _vertexDst->verticesProjected[i] = _vertexSrc->verticesProjected[vtxIdx];
                    _vertexDst->vertexUVs[i] = _vertexSrc->vertexUVs[uvIdx];
                    rdVector_Add2Acc(&_vertexDst->vertexUVs[i], idkIn);
                }

                _vertexDst->numVertices = _vertexSrc->numVertices;
            }
            else if (lightMode == 3) {
                for (int i = 0; i < _vertexSrc->numVertices; i++)
                {
                    int vtxIdx = _vertexSrc->vertexPosIdx[i];
                    int uvIdx = _vertexSrc->vertexUVIdx[i];
                    _vertexDst->verticesProjected[i] = _vertexSrc->verticesProjected[vtxIdx];
                    _vertexDst->vertexUVs[i] = _vertexSrc->vertexUVs[uvIdx];
                    rdVector_Add2Acc(&_vertexDst->vertexUVs[i], idkIn);
                    _vertexDst->paRedIntensities[i] = stdMath_Clamp(_vertexSrc->paRedIntensities[vtxIdx] + _vertexSrc->paDynamicLight[vtxIdx], 0.0, 1.0);
                    _vertexDst->paGreenIntensities[i] = stdMath_Clamp(_vertexSrc->paGreenIntensities[vtxIdx] + _vertexSrc->paDynamicLight[vtxIdx], 0.0, 1.0);
                    _vertexDst->paBlueIntensities[i] = stdMath_Clamp(_vertexSrc->paBlueIntensities[vtxIdx] + _vertexSrc->paDynamicLight[vtxIdx], 0.0, 1.0);
                }

                _vertexDst->numVertices = _vertexSrc->numVertices;
                return;
            }
        }
    default:
switchD_0044d5a4_caseD_5:
        return;
    }
LAB_0044d6ad:
    _vertexDst->numVertices = uVar21;
    return;
}


void
rdPrimit3_ClipFaceRGB
          (rdClipFrustum *clipFrustum,rdGeoMode_t geoMode,int lightMode,int texMode,
          rdMeshinfo *idxInfo,rdMeshinfo *mesh_out,rdVector2 *idkIn)
{
    rdVector3 *prVar1;
    float *pfVar2;
    rdVector3 *prVar3;
    float *pfVar5;
    float *pfVar6;
    float *pfVar7;
    float *pfVar8;
    int *piVar9;
    float *pfVar10;
    float *pfVar11;
    intptr_t iVar12;
    intptr_t iVar13;
    float fVar14;
    uint32_t uVar15;
    rdVector2 *prVar16;
    int *piVar17;
    int *piVar18;
    rdVector3 *prVar19;
    intptr_t iVar20;
    uint32_t uVar21;
    intptr_t iVar22;
    rdVector3 *local_18;
    uint32_t local_10;
    
    switch(geoMode) {
    case 0:
        uVar15 = idxInfo->numVertices;
        if (uVar15 != 0) {
            prVar3 = idxInfo->verticesProjected;
            piVar17 = idxInfo->vertexPosIdx;
            prVar19 = mesh_out->verticesProjected;
            uVar21 = uVar15;
            do {
                iVar20 = *piVar17;
                piVar17 = piVar17 + 1;
                uVar21 = uVar21 - 1;
                prVar1 = prVar3 + iVar20;
                prVar19->x = prVar1->x;
                prVar19->y = prVar1->y;
                prVar19->z = prVar1->z;
                prVar19 = prVar19 + 1;
            } while (uVar21 != 0);
        }
        iVar20 = rdCamera_pCurCamera->projectType;
        break;
    case 1:
    case 2:
        uVar15 = idxInfo->numVertices;
        if (uVar15 != 0) {
            prVar3 = idxInfo->verticesProjected;
            piVar17 = idxInfo->vertexPosIdx;
            prVar19 = mesh_out->verticesProjected;
            uVar21 = uVar15;
            do {
                iVar20 = *piVar17;
                piVar17 = piVar17 + 1;
                uVar21 = uVar21 - 1;
                prVar1 = prVar3 + iVar20;
                prVar19->x = prVar1->x;
                prVar19->y = prVar1->y;
                prVar19->z = prVar1->z;
                prVar19 = prVar19 + 1;
            } while (uVar21 != 0);
        }
        if (rdCamera_pCurCamera->projectType != rdCameraProjectType_Perspective) {
            uVar15 = rdClip_Face3WOrtho(clipFrustum,mesh_out->verticesProjected,idxInfo->numVertices);
            mesh_out->numVertices = uVar15;
            return;
        }
        uVar15 = rdClip_Face3W(clipFrustum,mesh_out->verticesProjected,idxInfo->numVertices);
        mesh_out->numVertices = uVar15;
        return;
    case 3:
        switch(lightMode) {
        case 0:
        case 1:
            uVar15 = idxInfo->numVertices;
            if (uVar15 != 0) {
                prVar3 = idxInfo->verticesProjected;
                piVar17 = idxInfo->vertexPosIdx;
                prVar19 = mesh_out->verticesProjected;
                uVar21 = uVar15;
                do {
                    iVar20 = *piVar17;
                    piVar17 = piVar17 + 1;
                    uVar21 = uVar21 - 1;
                    prVar1 = prVar3 + iVar20;
                    prVar19->x = prVar1->x;
                    prVar19->y = prVar1->y;
                    prVar19->z = prVar1->z;
                    prVar19 = prVar19 + 1;
                } while (uVar21 != 0);
                if (rdCamera_pCurCamera->projectType == rdCameraProjectType_Perspective) {
                    uVar15 = rdClip_Face3S(clipFrustum,mesh_out->verticesProjected,idxInfo->numVertices);
                    mesh_out->numVertices = uVar15;
                    return;
                }
                goto LAB_0044cb44;
            }
            break;
        case 2:
            uVar15 = idxInfo->numVertices;
            if (uVar15 != 0) {
                prVar3 = idxInfo->verticesProjected;
                piVar17 = idxInfo->vertexPosIdx;
                prVar19 = mesh_out->verticesProjected;
                uVar21 = uVar15;
                do {
                    iVar20 = *piVar17;
                    piVar17 = piVar17 + 1;
                    uVar21 = uVar21 - 1;
                    prVar1 = prVar3 + iVar20;
                    prVar19->x = prVar1->x;
                    prVar19->y = prVar1->y;
                    prVar19->z = prVar1->z;
                    prVar19 = prVar19 + 1;
                } while (uVar21 != 0);
            }
            break;
        case 3:
            if (idxInfo->numVertices != 0x0) {
                prVar3 = idxInfo->verticesProjected;
                pfVar5 = idxInfo->paRedIntensities;
                pfVar6 = idxInfo->paDynamicLight;
                prVar19 = mesh_out->verticesProjected;
                pfVar7 = idxInfo->paGreenIntensities;
                piVar17 = idxInfo->vertexPosIdx;
                pfVar8 = idxInfo->paBlueIntensities;
                pfVar10 = mesh_out->paGreenIntensities;
                pfVar11 = mesh_out->paRedIntensities;
                iVar20 = (intptr_t)pfVar10 - (intptr_t)piVar17;
                iVar22 = (intptr_t)mesh_out->paBlueIntensities - (intptr_t)piVar17;
                int idkIn_ = idxInfo->numVertices;
                do {
                    iVar12 = *piVar17;
                    prVar1 = prVar3 + iVar12;
                    prVar19->x = prVar1->x;
                    prVar19->y = prVar1->y;
                    prVar19->z = prVar1->z;
                    fVar14 = pfVar5[iVar12] + pfVar6[iVar12];
                    if (fVar14 < 0.0) {
                        fVar14 = 0.0;
                    }
                    else if (fVar14 > 1.0) {
                        fVar14 = 1.0;
                    }
                    pfVar2 = (float *)(iVar20 + (intptr_t)piVar17);
                    *(float *)((intptr_t)pfVar2 + ((intptr_t)pfVar11 - (intptr_t)pfVar10)) = fVar14;
                    fVar14 = pfVar7[iVar12] + pfVar6[iVar12];
                    if (fVar14 < 0.0) {
                        fVar14 = 0.0;
                    }
                    else if (fVar14 > 1.0) {
                        fVar14 = 1.0;
                    }
                    *pfVar2 = fVar14;
                    fVar14 = pfVar8[iVar12] + pfVar6[iVar12];
                    if (fVar14 < 0.0) {
                        fVar14 = 0.0;
                    }
                    else if (fVar14 > 1.0) {
                        fVar14 = 1.0;
                    }
                    prVar19 = prVar19 + 1;
                    *(float *)(iVar22 + (intptr_t)piVar17) = fVar14;
                    piVar17 = piVar17 + 1;
                    idkIn_ -= 1;
                } while (idkIn_ != 0x0);
            }
            uVar15 = rdClip_Face3GSRGB(clipFrustum,mesh_out->verticesProjected,
                                       mesh_out->paRedIntensities,mesh_out->paGreenIntensities,
                                       mesh_out->paBlueIntensities,idxInfo->numVertices);
            mesh_out->numVertices = uVar15;
            return;
        default:
            goto switchD_0044c964_caseD_5;
        }
        iVar20 = rdCamera_pCurCamera->projectType;
        break;
    case 4:
        if (-1 < lightMode) {
            if (lightMode < 3) {
                if (idxInfo->numVertices != 0) {
                    prVar3 = idxInfo->verticesProjected;
                    piVar17 = idxInfo->vertexUVIdx;
                    rdVector2* prVar4 = idxInfo->vertexUVs;
                    piVar9 = idxInfo->vertexPosIdx;
                    prVar16 = mesh_out->vertexUVs;
                    piVar18 = piVar17;
                    prVar19 = mesh_out->verticesProjected;
                    local_10 = idxInfo->numVertices;
                    do {
                        prVar1 = prVar3 + *piVar9;
                        prVar19->x = prVar1->x;
                        prVar19->y = prVar1->y;
                        prVar19->z = prVar1->z;
                        iVar20 = *piVar18;
                        prVar16->x = prVar4[iVar20].x;
                        prVar16->y = prVar4[iVar20].y;
                        prVar16->x = idkIn->x + prVar16->x;
                        local_10--;
                        prVar16->y = prVar16->y + idkIn->y;
                        prVar16 = prVar16 + 1;
                        piVar18 = piVar18 + 1;
                        prVar19 = prVar19 + 1;
                        piVar9++;
                    } while (local_10 != 0);
                }
#if 0
                for (int i = 0; i < idxInfo->numVertices; i++)
                {
                    int vtxIdx = idxInfo->vertexPosIdx[i];
                    int uvIdx = idxInfo->vertexUVIdx[i];
                    mesh_out->verticesProjected[i] = idxInfo->verticesProjected[vtxIdx];
                    mesh_out->vertexUVs[i] = idxInfo->vertexUVs[uvIdx];
                    rdVector_Add2Acc(&mesh_out->vertexUVs[i], idkIn);
                    //mesh_out->paRedIntensities[i] = idxInfo->paRedIntensities[i] + idxInfo->paDynamicLight[vtxIdx];
                    //mesh_out->paGreenIntensities[i] = idxInfo->paGreenIntensities[i] + idxInfo->paDynamicLight[vtxIdx];
                    //mesh_out->paBlueIntensities[i] = idxInfo->paBlueIntensities[i] + idxInfo->paDynamicLight[vtxIdx];
                }
#endif
                if (rdCamera_pCurCamera->projectType == rdCameraProjectType_Perspective) {
                    uVar15 = rdClip_Face3T(clipFrustum,mesh_out->verticesProjected,
                                           mesh_out->vertexUVs,idxInfo->numVertices);
                    mesh_out->numVertices = uVar15;
                    return;
                }
                uVar15 = rdClip_Face3TOrtho(clipFrustum,mesh_out->verticesProjected,
                                            mesh_out->vertexUVs,idxInfo->numVertices);
                mesh_out->numVertices = uVar15;
            }
            else if (lightMode == 3) {
                if (idxInfo->numVertices != 0) {
                    prVar3 = idxInfo->verticesProjected;
                    rdVector2* prVar4 = idxInfo->vertexUVs;
                    pfVar5 = idxInfo->paDynamicLight;
                    piVar17 = idxInfo->vertexPosIdx;
                    pfVar6 = idxInfo->paRedIntensities;
                    pfVar7 = idxInfo->paGreenIntensities;
                    pfVar8 = idxInfo->paBlueIntensities;
                    piVar9 = idxInfo->vertexUVIdx;

                    pfVar10 = mesh_out->paRedIntensities;
                    local_18 = mesh_out->verticesProjected;
                    prVar16 = mesh_out->vertexUVs;
                    pfVar11 = mesh_out->paGreenIntensities;
                    local_10 = idxInfo->numVertices;

                    float* redIter = mesh_out->paRedIntensities;
                    float* greenIter = mesh_out->paGreenIntensities;
                    float* blueIter = mesh_out->paBlueIntensities;

                    do {
                        iVar12 = *piVar17;
                        prVar19 = prVar3 + iVar12;
                        local_18->x = prVar19->x;
                        local_18->y = prVar19->y;
                        local_18->z = prVar19->z;
                        
                        iVar13 = *piVar9;
                        prVar16->x = prVar4[iVar13].x + idkIn->x;
                        prVar16->y = prVar4[iVar13].y + idkIn->y;;
                        fVar14 = pfVar6[iVar12] + pfVar5[iVar12];
                        if (fVar14 < 0.0) {
                            fVar14 = 0.0;
                        }
                        else if (fVar14 > 1.0) {
                            fVar14 = 1.0;
                        }
                        *redIter = fVar14;

                        fVar14 = pfVar7[iVar12] + pfVar5[iVar12];
                        if (fVar14 < 0.0) {
                            fVar14 = 0.0;
                        }
                        else if (fVar14 > 1.0) {
                            fVar14 = 1.0;
                        }
                        *greenIter = fVar14;
                        fVar14 = pfVar8[iVar12] + pfVar5[iVar12];
                        if (fVar14 < 0.0) {
                            fVar14 = 0.0;
                        }
                        else if (fVar14 > 1.0) {
                            fVar14 = 1.0;
                        }
                        local_18++;
                        *blueIter = fVar14;
                        prVar16++;
                        piVar17++;
                        local_10--;

                        redIter++;
                        greenIter++;
                        blueIter++;
                        piVar9++;
                    } while (local_10 != 0);
                }
                uVar15 = rdClip_Face3GTRGB(clipFrustum,mesh_out->verticesProjected,
                                           mesh_out->vertexUVs,
                                           mesh_out->paRedIntensities,
                                           mesh_out->paGreenIntensities,
                                           mesh_out->paBlueIntensities,
                                           idxInfo->numVertices);
                mesh_out->numVertices = uVar15;
#if 0
                for (int i = 0; i < idxInfo->numVertices; i++)
                {
                    int vtxIdx = idxInfo->vertexPosIdx[i];
                    int uvIdx = idxInfo->vertexUVIdx[i];
                    mesh_out->verticesProjected[i] = idxInfo->verticesProjected[vtxIdx];
                    mesh_out->vertexUVs[i] = idxInfo->vertexUVs[uvIdx];
                    rdVector_Add2Acc(&mesh_out->vertexUVs[i], idkIn);
                    mesh_out->paRedIntensities[i] = 1.0;//idxInfo->paRedIntensities[vtxIdx] + idxInfo->paDynamicLight[vtxIdx];
                    mesh_out->paGreenIntensities[i] = 0.0;//idxInfo->paGreenIntensities[vtxIdx] + idxInfo->paDynamicLight[vtxIdx];
                    mesh_out->paBlueIntensities[i] = 1.0;//idxInfo->paBlueIntensities[vtxIdx] + idxInfo->paDynamicLight[vtxIdx];
                }
                mesh_out->numVertices = idxInfo->numVertices;
#endif
                return;
            }
        }
    default:
switchD_0044c964_caseD_5:
        return;
    }
    if (iVar20 == 1) {
        uVar15 = rdClip_Face3S(clipFrustum,mesh_out->verticesProjected,uVar15);
        mesh_out->numVertices = uVar15;
        return;
    }
LAB_0044cb44:
    uVar15 = rdClip_Face3SOrtho(clipFrustum,mesh_out->verticesProjected,uVar15);
    mesh_out->numVertices = uVar15;
    return;
}


void rdPrimit3_ClipFaceRGBLevel
               (rdClipFrustum *clipFrustum,rdGeoMode_t geoMode,int lightMode,int texMode,
               rdVertexIdxInfo *idxInfo,rdMeshinfo *mesh_out,rdVector2 *idkIn)
{
    rdVector3 *prVar1;
    float *pfVar2;
    float fVar3;
    float fVar4;
    rdVector2 *prVar5;
    rdVector3 *prVar7;
    float *pfVar9;
    intptr_t iVar12;
    intptr_t iVar13;
    uint32_t uVar14;
    intptr_t iVar15;
    uint32_t uVar16;
    rdVector2 *prVar17;
    int *piVar18;
    int *piVar19;
    rdVector3 *prVar20;
    intptr_t iVar21;
    uint32_t uVar22;
    intptr_t iVar23;
    int *piVar24;
    rdVector3 *local_10;
    uint32_t local_8;
    
    switch(geoMode) {
    case 0:
        uVar16 = idxInfo->numVertices;
        if (uVar16 != 0) {
            prVar7 = idxInfo->vertices;
            piVar18 = idxInfo->vertexPosIdx;
            prVar20 = mesh_out->verticesProjected;
            uVar22 = uVar16;
            do {
                iVar15 = *piVar18;
                piVar18++;
                uVar22--;
                prVar1 = prVar7 + iVar15;
                rdVector_Copy3(prVar20, prVar1);
                prVar20 = prVar20 + 1;
            } while (uVar22 != 0);
        }
        iVar15 = rdCamera_pCurCamera->projectType;
        break;
    case 1:
    case 2:
        uVar16 = idxInfo->numVertices;
        if (uVar16 != 0) {
            prVar7 = idxInfo->vertices;
            piVar18 = idxInfo->vertexPosIdx;
            prVar20 = mesh_out->verticesProjected;
            uVar22 = uVar16;
            do {
                iVar15 = *piVar18;
                piVar18++;
                uVar22--;
                prVar1 = prVar7 + iVar15;
                rdVector_Copy3(prVar20, prVar1);
                prVar20++;
            } while (uVar22 != 0);
        }
        if (rdCamera_pCurCamera->projectType != rdCameraProjectType_Perspective) {
            uVar16 = rdClip_Face3WOrtho(clipFrustum,mesh_out->verticesProjected,uVar16);
            mesh_out->numVertices = uVar16;
            return;
        }
        uVar16 = rdClip_Face3W(clipFrustum,mesh_out->verticesProjected,uVar16);
        mesh_out->numVertices = uVar16;
        return;
    case 3:
        switch(lightMode) {
        case 0:
        case 1:
            uVar16 = idxInfo->numVertices;
            if (uVar16 != 0) {
                prVar7 = idxInfo->vertices;
                piVar18 = idxInfo->vertexPosIdx;
                prVar20 = mesh_out->verticesProjected;
                uVar22 = uVar16;
                do {
                    iVar15 = *piVar18;
                    piVar18++;
                    uVar22--;
                    prVar1 = prVar7 + iVar15;
                    rdVector_Copy3(prVar20, prVar1);
                    prVar20++;
                } while (uVar22 != 0);
                if (rdCamera_pCurCamera->projectType == rdCameraProjectType_Perspective) {
                    uVar16 = rdClip_Face3S(clipFrustum,mesh_out->verticesProjected,uVar16);
                    mesh_out->numVertices = uVar16;
                    return;
                }
                goto LAB_0044c4b4;
            }
            break;
        case 2:
            uVar16 = idxInfo->numVertices;
            if (uVar16 != 0) {
                prVar7 = idxInfo->vertices;
                piVar18 = idxInfo->vertexPosIdx;
                prVar20 = mesh_out->verticesProjected;
                uVar22 = uVar16;
                do {
                    iVar15 = *piVar18;
                    piVar18++;
                    uVar22--;
                    prVar1 = prVar7 + iVar15;
                    rdVector_Copy3(prVar20, prVar1);
                    prVar20++;
                } while (uVar22 != 0);
            }
            break;
        case 3:
            if (idxInfo->numVertices != 0x0) {
                prVar7 = idxInfo->vertices;
                piVar18 = idxInfo->vertexPosIdx;
                pfVar9 = idxInfo->paDynamicLight;
                prVar20 = mesh_out->verticesProjected;

                float* redIter = mesh_out->paRedIntensities;
                float* greenIter = mesh_out->paGreenIntensities;
                float* blueIter = mesh_out->paBlueIntensities;

                int idxIter = 0;
                
                for (int idkIn_ = idxInfo->numVertices; idkIn_ > 0; idkIn_--) {
                    iVar12 = *piVar18;
                    prVar1 = prVar7 + iVar12;
                    rdVector_Copy3(prVar20, prVar1);
                    *redIter = stdMath_Clamp(idxInfo->paRedIntensities[idxIter] + pfVar9[iVar12], 0.0, 1.0);
                    *greenIter = stdMath_Clamp(idxInfo->paGreenIntensities[idxIter] + pfVar9[iVar12], 0.0, 1.0);
                    *blueIter = stdMath_Clamp(idxInfo->paBlueIntensities[idxIter] + pfVar9[iVar12], 0.0, 1.0);
                    prVar20++;
                    piVar18++;

                    redIter++;
                    greenIter++;
                    blueIter++;
                    idxIter++;
                }
            }
            uVar14 = rdClip_Face3GSRGB(clipFrustum,mesh_out->verticesProjected,
                                       mesh_out->paRedIntensities,mesh_out->paGreenIntensities,
                                       mesh_out->paBlueIntensities, idxInfo->numVertices);
            mesh_out->numVertices = uVar14;
            return;
        default:
            return;
        }
        iVar15 = rdCamera_pCurCamera->projectType;
        break;
    case 4:
        if (-1 < lightMode) {
            if (lightMode < 3) {
                if (idxInfo->numVertices != 0) {
                    prVar7 = idxInfo->vertices;
                    piVar18 = idxInfo->vertexUVIdx;
                    prVar5 = idxInfo->vertexUVs;
                    piVar24 = idxInfo->vertexPosIdx;
                    prVar17 = mesh_out->vertexUVs;
                    piVar19 = piVar18;
                    prVar20 = mesh_out->verticesProjected;
                    local_8 = idxInfo->numVertices;
                    do {
                        prVar1 = prVar7 + *piVar24;
                        rdVector_Copy3(prVar20, prVar1);
                        iVar15 = *piVar19;
                        prVar17->x = prVar5[iVar15].x + idkIn->x;
                        prVar17->y = prVar5[iVar15].y + idkIn->y;
                        local_8--;
                        prVar17++;
                        piVar19++;
                        prVar20++;
                        piVar24++;
                    } while (local_8 != 0);
                }
                if (rdCamera_pCurCamera->projectType == rdCameraProjectType_Perspective) {
                    uVar16 = rdClip_Face3T(clipFrustum,mesh_out->verticesProjected,
                                           mesh_out->vertexUVs,idxInfo->numVertices);
                    mesh_out->numVertices = uVar16;
                    return;
                }
                else {
                    uVar16 = rdClip_Face3TOrtho(clipFrustum,mesh_out->verticesProjected,
                                            mesh_out->vertexUVs,idxInfo->numVertices);
                    mesh_out->numVertices = uVar16;
                }
            }
            else if (lightMode == 3) {
                if (idxInfo->numVertices != 0) {
                    prVar5 = idxInfo->vertexUVs;
                    local_10 = mesh_out->verticesProjected;
                    piVar18 = idxInfo->vertexUVIdx;
                    prVar7 = idxInfo->vertices;
                    piVar24 = idxInfo->vertexPosIdx;
                    pfVar9 = idxInfo->paDynamicLight;
                    prVar17 = mesh_out->vertexUVs;

                    float* redIter = mesh_out->paRedIntensities;
                    float* greenIter = mesh_out->paGreenIntensities;
                    float* blueIter = mesh_out->paBlueIntensities;

                    int idxIter = 0;
                    local_8 = idxInfo->numVertices;
                    do {
                        iVar12 = *piVar24;
                        prVar20 = prVar7 + iVar12;
                        rdVector_Copy3(local_10, prVar20);
                        iVar13 = *piVar18;
                        prVar17->x = prVar5[iVar13].x + idkIn->x;
                        prVar17->y = prVar5[iVar13].y + idkIn->y;
                        *redIter = stdMath_Clamp(pfVar9[iVar12] + idxInfo->paRedIntensities[idxIter], 0.0, 1.0);
                        *greenIter = stdMath_Clamp(pfVar9[iVar12] + idxInfo->paGreenIntensities[idxIter], 0.0, 1.0);
                        *blueIter = stdMath_Clamp(pfVar9[iVar12] + idxInfo->paBlueIntensities[idxIter], 0.0, 1.0);

                        local_10++;
                        prVar17++;
                        piVar24++;
                        local_8--;

                        redIter++;
                        greenIter++;
                        blueIter++;
                        idxIter++;
                        piVar18++;

                    } while (local_8 != 0);
                }
                uVar16 = rdClip_Face3GTRGB(clipFrustum,
                                           mesh_out->verticesProjected,
                                           mesh_out->vertexUVs,
                                           mesh_out->paRedIntensities,
                                           mesh_out->paGreenIntensities,
                                           mesh_out->paBlueIntensities,
                                           idxInfo->numVertices);
                mesh_out->numVertices = uVar16;

#if 0
                for (int i = 0; i < idxInfo->numVertices; i++)
                {
                    int vtxIdx = idxInfo->vertexPosIdx[i];
                    int uvIdx = idxInfo->vertexUVIdx[i];
                    mesh_out->verticesProjected[i] = idxInfo->vertices[vtxIdx];
                    mesh_out->vertexUVs[i] = idxInfo->vertexUVs[uvIdx];
                    rdVector_Add2Acc(&mesh_out->vertexUVs[i], idkIn);
                    mesh_out->paRedIntensities[i] = idxInfo->paRedIntensities[i] + idxInfo->paDynamicLight[vtxIdx];
                    mesh_out->paGreenIntensities[i] = idxInfo->paGreenIntensities[i] + idxInfo->paDynamicLight[vtxIdx];
                    mesh_out->paBlueIntensities[i] = idxInfo->paBlueIntensities[i] + idxInfo->paDynamicLight[vtxIdx];
                }
#endif
                return;
            }
        }
    default:
        return;
    }
    if (iVar15 == 1) {
        uVar16 = rdClip_Face3S(clipFrustum,mesh_out->verticesProjected,uVar16);
        mesh_out->numVertices = uVar16;
        return;
    }
LAB_0044c4b4:
    uVar16 = rdClip_Face3SOrtho(clipFrustum,mesh_out->verticesProjected,uVar16);
    mesh_out->numVertices = uVar16;
    return;
}