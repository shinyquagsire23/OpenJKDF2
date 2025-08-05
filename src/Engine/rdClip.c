#include "rdClip.h"

#include "General/stdMath.h"
#include "rdCanvas.h"
#include "jk.h"

#include <math.h>

#ifndef RDCLIP_WORK_BUFFERS_IN_STACK_MEM
#define INST_WORKBUFS
#define INST_WORKBUFS_MOTS

#define pSourceVert  rdClip_pSourceVert 
#define workIVerts rdClip_workIVerts
#define workVerts rdClip_workVerts
#define pDestVert rdClip_pDestVert
#define pDestIVert rdClip_pDestIVert
#define workTVerts rdClip_workTVerts
#define pSourceIVert rdClip_pSourceIVert
#define pSourceTVert rdClip_pSourceTVert
#define pDestTVert rdClip_pDestTVert

#ifdef JKM_LIGHTING
flex_t* pSourceRedIVert;
flex_t* pSourceGreenIVert;
flex_t* pSourceBlueIVert;

flex_t* pDestRedIVert;
flex_t* pDestGreenIVert;
flex_t* pDestBlueIVert;

flex_t workRedIVerts[32];
flex_t workGreenIVerts[32];
flex_t workBlueIVerts[32];
#endif // JKM_LIGHTING

#else // RDCLIP_WORK_BUFFERS_IN_STACK_MEM

#ifdef JKM_LIGHTING
#define INST_WORKBUFS_MOTS \
    flex_t* NO_ALIAS pSourceRedIVert; \
    flex_t* NO_ALIAS pSourceGreenIVert; \
    flex_t* NO_ALIAS pSourceBlueIVert; \
    flex_t* NO_ALIAS pDestRedIVert; \
    flex_t* NO_ALIAS pDestGreenIVert; \
    flex_t* NO_ALIAS pDestBlueIVert; \
    flex_t workRedIVerts[32]; \
    flex_t workGreenIVerts[32]; \
    flex_t workBlueIVerts[32];
#else
#define INST_WORKBUFS_MOTS
#endif

#define INST_WORKBUFS \
    rdVector3* NO_ALIAS pSourceVert; \
    flex_t workIVerts[32]; \
    rdVector3 workVerts[32]; \
    rdVector3* NO_ALIAS pDestVert; \
    flex_t* NO_ALIAS pDestIVert; \
    rdVector2 workTVerts[32]; \
    flex_t* NO_ALIAS pSourceIVert; \
    rdVector2* NO_ALIAS pSourceTVert; \
    rdVector2* NO_ALIAS pDestTVert;
#endif

// TODO: Non-GT versions...?
#ifdef RDCLIP_COPY_VERTS_TO_STACK
// TODO: alloca maybe?
/*
    rdVector3* _vertices = (rdVector3*)alloca((numVertices+numVertices/2) * sizeof(rdVector3)); \
    rdVector2* _tvertices = (rdVector2*)alloca((numVertices+(numVertices/2)) * sizeof(rdVector2)); \
    flex_t* _ivertices = (flex_t*)alloca((numVertices+(numVertices/2)) * sizeof(flex_t)); \
*/

#define INST_ARG_COPIES \
    rdClipFrustum _clipFrustum = *pClipFrustum; \
    rdVector3 _vertices[32];\
    rdVector2 _tvertices[32];\
    flex_t _ivertices[32];\
    _memcpy(_vertices, pSourceVert, numVertices*sizeof(rdVector3)); \
    _memcpy(_tvertices, pSourceTVert, numVertices*sizeof(rdVector2)); \
    _memcpy(_ivertices, pSourceIVert, numVertices*sizeof(flex_t)); \
    pClipFrustum = &_clipFrustum; \
    pSourceVert = _vertices; \
    pSourceTVert = _tvertices; \
    pSourceIVert = _ivertices;

#define INST_ARG_COPIES_T \
    rdClipFrustum _clipFrustum = *pClipFrustum; \
    rdVector3 _vertices[32];\
    rdVector2 _tvertices[32];\
    _memcpy(_vertices, pSourceVert, numVertices*sizeof(rdVector3)); \
    _memcpy(_tvertices, pSourceTVert, numVertices*sizeof(rdVector2)); \
    pClipFrustum = &_clipFrustum; \
    pSourceVert = _vertices; \
    pSourceTVert = _tvertices;

#define INST_ARG_COPIES_W \
    rdClipFrustum _clipFrustum = *pClipFrustum; \
    rdVector3 _vertices[32];\
    _memcpy(_vertices, pSourceVert, numVertices*sizeof(rdVector3)); \
    pClipFrustum = &_clipFrustum; \
    pSourceVert = _vertices;
#else
#define INST_ARG_COPIES
#define INST_ARG_COPIES_W
#define INST_ARG_COPIES_T
#endif

int rdClip_Line2(rdCanvas *canvas, signed int *pX1, signed int *pY1, signed int *pX2, signed int *pY2)
{
    unsigned int clipOutcodeX1Y1;
    signed int clipOutcodeX2Y2;
    signed int fY1_same_fY2;
    unsigned int clipCode;
    flex_d_t x_clipped;
    flex_d_t y_clipped;
    flex_t fY1;
    flex_t fX2;
    flex_t fY2;
    flex_t fX1;

    clipOutcodeX1Y1 = rdClip_CalcOutcode2(canvas, *pX1, *pY1);
    clipOutcodeX2Y2 = rdClip_CalcOutcode2(canvas, *pX2, *pY2);
    
    fX1 = (flex_d_t)*pX1;
    fX2 = (flex_d_t)*pX2;
    fY1 = (flex_d_t)*pY1;
    fY2 = (flex_d_t)*pY2;
    
    if ( !(clipOutcodeX1Y1 | clipOutcodeX2Y2) )
        return 1;
    
    if ( clipOutcodeX2Y2 & clipOutcodeX1Y1 )
        return 0;
    
    while (1)
    {
        if ( !(clipOutcodeX1Y1 | clipOutcodeX2Y2) )
            break;

        if ( clipOutcodeX2Y2 & clipOutcodeX1Y1 )
            return 0;

        clipCode = clipOutcodeX1Y1;
        if ( !clipOutcodeX1Y1 )
            clipCode = clipOutcodeX2Y2;

        if (clipCode & CLIP_TOP)
        {
            x_clipped = (fY2 == fY1) ? fX1 : (fX2 - fX1) / (fY2 - fY1) * ((flex_d_t)canvas->yStart - fY1) + fX1;
            y_clipped = (flex_d_t)canvas->yStart;
        }
        else if (clipCode & CLIP_BOTTOM)
        {
            x_clipped = (fY2 == fY1) ? fX1 : (fX2 - fX1) / (fY2 - fY1) * ((flex_d_t)canvas->heightMinusOne - fY1) + fX1;
            y_clipped = (flex_d_t)canvas->heightMinusOne;
        }
        else if (clipCode & CLIP_RIGHT)
        {
            x_clipped = (flex_d_t)canvas->widthMinusOne;
            y_clipped = (fX2 == fX1) ? fY1 : (fY2 - fY1) / (fX2 - fX1) * ((flex_d_t)canvas->widthMinusOne - fX1) + fY1;
        }
        else if (clipCode & CLIP_LEFT)
        {
            x_clipped = (flex_d_t)canvas->xStart;
            y_clipped = (fX2 == fX1) ? fY1 : (flex_t)((fY2 - fY1) / (fX2 - fX1) * ((flex_d_t)canvas->xStart - fX1) + fY1);
        }

        if (clipCode == clipOutcodeX1Y1)
        {
            fX1 = x_clipped;
            fY1 = y_clipped;
            clipOutcodeX1Y1 = rdClip_CalcOutcode2(canvas, (float)round((float)x_clipped), round((float)y_clipped));
        }
        else
        {
            fX2 = x_clipped;
            fY2 = y_clipped;
            clipOutcodeX2Y2 = rdClip_CalcOutcode2(canvas, (float)round((float)x_clipped), round((float)y_clipped));
        }
    }
    
    *pX1 = (float)round((float)fX1);
    *pY1 = (float)round((float)fY1);
    *pX2 = (float)round((float)fX2);
    *pY2 = (float)round((float)fY2);
    return 1;
}


int rdClip_CalcOutcode2(rdCanvas *canvas, int x, int y)
{
    int result = 0;

    if (x > canvas->widthMinusOne)
        result |= CLIP_RIGHT;
    else if (x < canvas->xStart)
        result |= CLIP_LEFT;

    if (y < canvas->yStart)
        result |= CLIP_TOP;
    else if (y > canvas->heightMinusOne)
        result |= CLIP_BOTTOM;

    return result;
}

int rdClip_Point3(rdClipFrustum *clipFrustum, rdVector3 *point)
{
    if ( point->y < (flex_d_t)clipFrustum->zNear )
        return 0;
    if (clipFrustum->bClipFar && point->y > (flex_d_t)clipFrustum->zFar )
        return 0;

    flex_t v4 = (rdCamera_pCurCamera->projectType == rdCameraProjectType_Perspective) ? (clipFrustum->farLeft * point->y) : (clipFrustum->orthoLeft);
    if ( v4 > point->x )
        return 0;

    flex_t v5 = (rdCamera_pCurCamera->projectType == rdCameraProjectType_Perspective) ? (clipFrustum->right * point->y) : (clipFrustum->orthoRight);
    if ( v5 < point->x )
        return 0;

    flex_t v6 = (rdCamera_pCurCamera->projectType == rdCameraProjectType_Perspective) ? (clipFrustum->farTop * point->y) : (clipFrustum->orthoTop);
    if ( v6 < point->z )
        return 0;

    flex_t v7 = (rdCamera_pCurCamera->projectType == rdCameraProjectType_Perspective) ? (clipFrustum->bottom * point->y) : (clipFrustum->orthoBottom);
    return v7 <= point->z;
}

int rdClip_Line3Project(rdClipFrustum *clipFrustum, rdVector3 *point1, rdVector3 *point2, int *out1, int *out2)
{
    flex_d_t v10; // st7
    flex_d_t v12; // st6
    flex_d_t v13; // st7
    flex_d_t v14; // st5
    flex_d_t v15; // st6
    flex_d_t v16; // st6
    flex_d_t v17; // st7
    flex_d_t v18; // st6
    flex_d_t v23; // st6
    flex_d_t v24; // st7
    flex_d_t v25; // st5
    flex_d_t v26; // st6
    flex_d_t v27; // st6
    flex_d_t v28; // st7
    flex_d_t v29; // st6
    flex_d_t v33; // st7
    flex_d_t v36; // st6
    flex_d_t v37; // st5
    flex_d_t v40; // st4
    flex_d_t v42; // st5
    flex_d_t v43; // st4
    flex_d_t v44; // st6
    flex_d_t v46; // st7
    flex_d_t v49; // st6
    flex_d_t v50; // st5
    flex_d_t v53; // st4
    flex_d_t v55; // st5
    flex_d_t v56; // st4
    flex_d_t v57; // st6
    flex_d_t v58; // rt1
    flex_d_t v63; // st7
    flex_d_t v66; // st6
    flex_d_t v67; // st5
    flex_d_t v70; // st4
    flex_d_t v72; // st5
    flex_d_t v73; // st4
    flex_d_t v74; // st6
    flex_d_t v76; // st7
    flex_d_t v79; // st6
    flex_d_t v80; // st5
    flex_d_t v83; // st4
    flex_d_t v85; // st5
    flex_d_t v86; // st4
    flex_d_t v87; // st6
    flex_d_t v88; // rt2
    flex_d_t v93; // st6
    flex_d_t v94; // st7
    flex_d_t v97; // st6
    flex_d_t v98; // st5
    flex_d_t v101; // st4
    flex_d_t v103; // st5
    flex_d_t v104; // st4
    flex_d_t v105; // st7
    flex_d_t v106; // rt0
    flex_d_t v108; // st6
    flex_d_t v109; // st7
    flex_d_t v112; // st6
    flex_d_t v113; // st5
    flex_d_t v116; // st4
    flex_d_t v118; // st5
    flex_d_t v119; // st4
    flex_d_t v120; // st7
    flex_d_t v121; // rt0
    flex_d_t v125; // st6
    flex_d_t v126; // st7
    flex_d_t v129; // st6
    flex_d_t v130; // st5
    flex_d_t v133; // st4
    flex_d_t v135; // st5
    flex_d_t v136; // st4
    flex_d_t v137; // st7
    flex_d_t v138; // rt1
    flex_d_t v140; // st6
    flex_d_t v141; // st7
    flex_d_t v144; // st6
    flex_d_t v145; // st5
    flex_d_t v148; // st4
    flex_d_t v150; // st5
    flex_d_t v151; // st4
    flex_d_t v152; // st7
    flex_d_t v153; // rt1
    flex_t frustuma; // [esp+10h] [ebp+4h]
    flex_t frustumb; // [esp+10h] [ebp+4h]
    flex_t frustumc; // [esp+10h] [ebp+4h]
    flex_t frustumd; // [esp+10h] [ebp+4h]
    flex_t frustume; // [esp+10h] [ebp+4h]
    flex_t frustumf; // [esp+10h] [ebp+4h]
    flex_t frustumg; // [esp+10h] [ebp+4h]
    flex_t frustumh; // [esp+10h] [ebp+4h]
    flex_t point1a; // [esp+14h] [ebp+8h]
    flex_t point1b; // [esp+14h] [ebp+8h]
    flex_t point1c; // [esp+14h] [ebp+8h]
    flex_t point1d; // [esp+14h] [ebp+8h]
    flex_t point1e; // [esp+14h] [ebp+8h]
    flex_t point1f; // [esp+14h] [ebp+8h]
    flex_t point1g; // [esp+14h] [ebp+8h]
    flex_t point1h; // [esp+14h] [ebp+8h]
    flex_t point1i; // [esp+14h] [ebp+8h]
    flex_t point1j; // [esp+14h] [ebp+8h]
    flex_t point1k; // [esp+14h] [ebp+8h]
    flex_t point1l; // [esp+14h] [ebp+8h]
    flex_t point2a; // [esp+18h] [ebp+Ch]
    flex_t point2b; // [esp+18h] [ebp+Ch]
    flex_t point2c; // [esp+18h] [ebp+Ch]
    flex_t point2d; // [esp+18h] [ebp+Ch]
    flex_t point2e; // [esp+18h] [ebp+Ch]
    flex_t point2f; // [esp+18h] [ebp+Ch]
    flex_t point2g; // [esp+18h] [ebp+Ch]
    flex_t point2h; // [esp+18h] [ebp+Ch]

    if ( point1->y < (flex_d_t)clipFrustum->zNear && point2->y < (flex_d_t)clipFrustum->zNear )
        return 0;

    // TODO verify
    if (point1->y < (flex_d_t)clipFrustum->zNear)
    {
        v12 = point2->z;
        v13 = (clipFrustum->zNear - point1->y) / (point2->y - point1->y);
        point1->y = clipFrustum->zNear;
        v14 = (v12 - point1->z) * v13 + point1->z;
        v15 = (point2->x - point1->x) * v13 + point1->x;
        point1->z = v14;
        point1->x = v15;
        if ( out1 )
            *out1 = 1;
    }
    else if ( point2->y < clipFrustum->zNear )
    {
        v16 = point2->x;
        v17 = (clipFrustum->zNear - point1->y) / (point2->y - point1->y);
        point2->y = clipFrustum->zNear;
        v18 = (v16 - point1->x) * v17 + point1->x;
        point2->z = (point2->z - point1->z) * v17 + point1->z;
        point2->x = v18;
        if ( out2 )
            *out2 = 1;
    }

    if (clipFrustum->bClipFar)
    {
        if ( point1->y > (flex_d_t)clipFrustum->zFar && point2->y > (flex_d_t)clipFrustum->zFar )
            return 0;

        // TODO verify
        if (point1->y <= (flex_d_t)clipFrustum->zFar)
        {
            if ( point2->y > (flex_d_t)clipFrustum->zFar )
            {
                v27 = point2->x;
                v28 = (clipFrustum->zFar - point1->y) / (point2->y - point1->y);
                point2->y = clipFrustum->zFar;
                v29 = (v27 - point1->x) * v28 + point1->x;
                point2->z = (point2->z - point1->z) * v28 + point1->z;
                point2->x = v29;
                if ( out2 )
                    *out2 = 1;
            }
        }
        else
        {
            v23 = point2->z;
            v24 = (clipFrustum->zFar - point1->y) / (point2->y - point1->y);
            point1->y = clipFrustum->zFar;
            v25 = (v23 - point1->z) * v24 + point1->z;
            v26 = (point2->x - point1->x) * v24 + point1->x;
            point1->z = v25;
            point1->x = v26;
            if ( out1 )
                *out1 = 1;
        }
    }

    if (point1->x < clipFrustum->farLeft * point1->y && point2->x < clipFrustum->farLeft * point2->y)
        return 0;
    if (point1->x >= clipFrustum->farLeft * point1->y)
    {
        if ( point2->x < clipFrustum->farLeft * point2->y)
        {
            point1c = point2->y - point1->y;
            frustumb = point2->x - point1->x;
            v46 = point2->y * point1->x - point1->y * point2->x;
            point2b = clipFrustum->farLeft * point1c - frustumb;
            if (point2b != 0.0)
            {
                v46 = v46 / point2b;
            }
            v49 = clipFrustum->farLeft * v46;
            v50 = point1c;
            if (v50 < 0.0)
                v50 = -v50;
            v53 = frustumb;
            if (v53 < 0.0)
                v53 = -v53;
            if ( v50 <= v53 )
                v55 = (v49 - point1->x) / frustumb;
            else
                v55 = (v46 - point1->y) / point1c;
            v56 = v49;
            v57 = (point2->z - point1->z) * v55;
            point2->x = v56;
            v58 = v57 + point1->z;
            point2->y = v46;
            point2->z = v58;
            if ( out2 )
                *out2 = 1;
        }
    }
    else
    {
        point1b = point2->y - point1->y;
        frustuma = point2->x - point1->x;
        v33 = point2->y * point1->x - point1->y * point2->x;
        point2a = clipFrustum->farLeft * point1b - frustuma;
        if (point2a != 0.0)
        {
            v33 = v33 / point2a;
        }
        v36 = clipFrustum->farLeft * v33;
        v37 = point1b;
        if (v37 < 0.0)
            v37 = -v37;
        v40 = frustuma;
        if ( v40 < 0.0 )
            v40 = -v40;
        if ( v37 <= v40 )
            v42 = (v36 - point1->x) / frustuma;
        else
            v42 = (v33 - point1->y) / point1b;
        v43 = v36;
        v44 = (point2->z - point1->z) * v42;
        point1->x = v43;
        point1->y = v33;
        point1->z = v44 + point1->z;
        if ( out1 )
            *out1 = 1;
    }
    point1d = clipFrustum->right * point2->y;
    if (point1->x > clipFrustum->right * point1->y && point2->x > (flex_d_t)point1d )
        return 0;
    if (point1->x <= clipFrustum->right * point1->y)
    {
        if ( point2->x > (flex_d_t)point1d )
        {
            point1f = point2->y - point1->y;
            frustumd = point2->x - point1->x;
            v76 = point2->y * point1->x - point1->y * point2->x;
            point2d = clipFrustum->right * point1f - frustumd;
            if (point2d != 0.0)
            {
                v76 = v76 / point2d;
            }
            v79 = clipFrustum->right * v76;
            v80 = point1f;
            if (v80 < 0.0)
                v80 = -v80;
            v83 = frustumd;
            if (v83 < 0.0)
                v83 = -v83;
            if ( v80 <= v83 )
                v85 = (v79 - point1->x) / frustumd;
            else
                v85 = (v76 - point1->y) / point1f;
            v86 = v79;
            v87 = (point2->z - point1->z) * v85;
            point2->x = v86;
            v88 = v87 + point1->z;
            point2->y = v76;
            point2->z = v88;
            if ( out2 )
                *out2 = 1;
        }
    }
    else
    {
        point1e = point2->y - point1->y;
        frustumc = point2->x - point1->x;
        v63 = point2->y * point1->x - point1->y * point2->x;
        point2c = clipFrustum->right * point1e - frustumc;
        if (point2c != 0.0)
        {
            v63 = v63 / point2c;
        }
        v66 = clipFrustum->right * v63;
        v67 = point1e;
        if (v67 < 0.0)
            v67 = -v67;
        v70 = frustumc;
        if (v70 < 0.0)
            v70 = -v70;
        if ( v67 <= v70 )
            v72 = (v66 - point1->x) / frustumc;
        else
            v72 = (v63 - point1->y) / point1e;
        v73 = v66;
        v74 = (point2->z - point1->z) * v72;
        point1->x = v73;
        point1->y = v63;
        point1->z = v74 + point1->z;
        if ( out1 )
            *out1 = 1;
    }
    point1g = clipFrustum->farTop * point2->y;
    if (point1->z > clipFrustum->farTop * point1->y && point2->z > (flex_d_t)point1g )
        return 0;
    if (point1->z <= clipFrustum->farTop * point1->y)
    {
        if ( point2->z > (flex_d_t)point1g )
        {
            point1i = point2->y - point1->y;
            frustumf = point2->z - point1->z;
            v108 = point2->y * point1->z - point1->y * point2->z;
            v109 = v108;
            point2f = clipFrustum->farTop * point1i - frustumf;
            if (point2f != 0.0)
            {
                v109 = v108 / point2f;
            }
            v112 = clipFrustum->farTop * v109;
            v113 = point1i;
            if (v113 < 0.0)
                v113 = -v113;
            v116 = frustumf;
            if (v116 < 0.0)
                v116 = -v116;
            if ( v113 <= v116 )
                v118 = (v112 - point1->z) / frustumf;
            else
                v118 = (v109 - point1->y) / point1i;
            v119 = v109;
            v120 = (point2->x - point1->x) * v118;
            point2->y = v119;
            v121 = v120 + point1->x;
            point2->z = v112;
            point2->x = v121;
            if ( out2 )
                *out2 = 1;
        }
    }
    else
    {
        point1h = point2->y - point1->y;
        frustume = point2->z - point1->z;
        v93 = point2->y * point1->z - point1->y * point2->z;
        v94 = v93;
        point2e = clipFrustum->farTop * point1h - frustume;
        if (point2e != 0.0)
        {
            v94 = v93 / point2e;
        }
        v97 = clipFrustum->farTop * v94;
        v98 = point1h;
        if (v98 < 0.0)
            v98 = -v98;
        v101 = frustume;
        if (v101 < 0.0) {
            v101 = -v101;
        }
        if ( v98 <= v101 )
            v103 = (v97 - point1->z) / frustume;
        else
            v103 = (v94 - point1->y) / point1h;
        v104 = v94;
        v105 = (point2->x - point1->x) * v103;
        point1->y = v104;
        v106 = v105 + point1->x;
        point1->z = v97;
        point1->x = v106;
        if ( out1 )
            *out1 = 1;
    }
    point1j = clipFrustum->bottom * point2->y;
    if (point1->z < clipFrustum->bottom * point1->y && point2->z < (flex_d_t)point1j )
        return 0;
    if (point1->z >= clipFrustum->bottom * point1->y )
    {
        if ( point2->z < (flex_d_t)point1j )
        {
            point1l = point2->y - point1->y;
            frustumh = point2->z - point1->z;
            v140 = point2->y * point1->z - point1->y * point2->z;
            v141 = v140;
            point2h = clipFrustum->bottom * point1l - frustumh;
            if (point2h != 0.0)
            {
                v141 = v140 / point2h;
            }
            v144 = clipFrustum->bottom * v141;
            v145 = point1l;
            if (v145 < 0.0)
                v145 = -v145;
            v148 = frustumh;
            if (v148 < 0.0)
                v148 = -v148;
            if ( v145 <= v148 )
                v150 = (v144 - point1->z) / frustumh;
            else
                v150 = (v141 - point1->y) / point1l;
            v151 = v141;
            v152 = (point2->x - point1->x) * v150;
            point2->y = v151;
            v153 = v152 + point1->x;
            point2->z = v144;
            point2->x = v153;
            if ( out2 )
                *out2 = 1;
        }
    }
    else
    {
        point1k = point2->y - point1->y;
        frustumg = point2->z - point1->z;
        v125 = point2->y * point1->z - point1->y * point2->z;
        v126 = v125;
        point2g = clipFrustum->bottom * point1k - frustumg;
        if (point2g != 0.0)
        {
            v126 = v125 / point2g;
        }
        v129 = clipFrustum->bottom * v126;
        v130 = point1k;
        if (v130 < 0.0)
            v130 = -v130;
        v133 = frustumg;
        if (v133 < 0.0)
            v133 = -v133;
        if ( v130 <= v133 )
            v135 = (v129 - point1->z) / frustumg;
        else
            v135 = (v126 - point1->y) / point1k;
        v136 = v126;
        v137 = (point2->x - point1->x) * v135;
        point1->y = v136;
        v138 = v137 + point1->x;
        point1->z = v129;
        point1->x = v138;
        if ( out1 )
        {
            *out1 = 1;
            return 1;
        }
    }
    return 1;
}

int rdClip_Line3Ortho(rdClipFrustum *clipFrustum, rdVector3 *point1, rdVector3 *point2, int *out1, int *out2)
{
    flex_d_t v8; // st7
    flex_d_t v10; // st6
    flex_d_t v11; // st7
    flex_d_t v12; // st5
    flex_d_t v13; // st6
    flex_d_t v14; // st6
    flex_d_t v15; // st7
    flex_d_t v16; // st6
    flex_d_t v18; // st7
    flex_d_t v21; // st6
    flex_d_t v22; // st7
    flex_d_t v23; // st5
    flex_d_t v24; // st6
    flex_d_t v25; // st6
    flex_d_t v26; // st7
    flex_d_t v27; // st6
    flex_d_t v29; // st7
    flex_d_t v31; // st7
    flex_d_t v32; // st5
    flex_d_t v33; // st6
    flex_d_t v34; // st7
    flex_d_t v35; // st5
    flex_d_t v36; // st6
    flex_d_t v38; // st7
    flex_d_t v41; // st7
    flex_d_t v42; // st5
    flex_d_t v43; // st6
    flex_d_t v44; // st7
    flex_d_t v45; // st5
    flex_d_t v46; // st6
    flex_d_t v47; // st7
    flex_d_t v48; // st5
    flex_d_t v49; // st6
    flex_d_t v50; // st7
    flex_d_t v51; // st5
    flex_d_t v52; // st6
    flex_d_t v54; // st7
    flex_d_t v56; // st7
    flex_d_t v57; // st5
    flex_d_t v58; // st6
    flex_d_t v59; // st7
    flex_d_t v60; // st5
    flex_d_t v61; // st6
    flex_t point1a; // [esp+14h] [ebp+8h]
    flex_t point1b; // [esp+14h] [ebp+8h]
    flex_t point1c; // [esp+14h] [ebp+8h]
    flex_t point1d; // [esp+14h] [ebp+8h]

    if ( point1->y < (flex_d_t)clipFrustum->zNear && point2->y < (flex_d_t)clipFrustum->zNear )
        return 0;
    v8 = point2->y;
    if (point1->y < (flex_d_t)clipFrustum->zNear)
    {
        v10 = point2->z;
        v11 = (clipFrustum->zNear - point1->y) / (v8 - point1->y);
        point1->y = clipFrustum->zNear;
        v12 = (v10 - point1->z) * v11 + point1->z;
        v13 = (point2->x - point1->x) * v11 + point1->x;
        point1->z = v12;
        point1->x = v13;
        if ( out1 )
            *out1 = 1;
    }
    else if ( v8 < clipFrustum->zNear )
    {
        v14 = point2->x;
        v15 = (clipFrustum->zNear - point1->y) / (point2->y - point1->y);
        point2->y = clipFrustum->zNear;
        v16 = (v14 - point1->x) * v15 + point1->x;
        point2->z = (point2->z - point1->z) * v15 + point1->z;
        point2->x = v16;
        if ( out2 )
            *out2 = 1;
    }
    if (clipFrustum->bClipFar)
    {
        if ( point1->y > (flex_d_t)clipFrustum->zFar && point2->y > (flex_d_t)clipFrustum->zFar )
            return 0;
        v18 = point2->y;
        if (point1->y <= (flex_d_t)clipFrustum->zFar)
        {
            if ( v18 > clipFrustum->zFar )
            {
                v25 = point2->x;
                v26 = (clipFrustum->zFar - point1->y) / (point2->y - point1->y);
                point2->y = clipFrustum->zFar;
                v27 = (v25 - point1->x) * v26 + point1->x;
                point2->z = (point2->z - point1->z) * v26 + point1->z;
                point2->x = v27;
                if ( out2 )
                    *out2 = 1;
            }
        }
        else
        {
            v21 = point2->z;
            v22 = (clipFrustum->zFar - point1->y) / (v18 - point1->y);
            point1->y = clipFrustum->zFar;
            v23 = (v21 - point1->z) * v22 + point1->z;
            v24 = (point2->x - point1->x) * v22 + point1->x;
            point1->z = v23;
            point1->x = v24;
            if ( out1 )
                *out1 = 1;
        }
    }
    point1a = clipFrustum->orthoLeft;
    if ( point1->x < (flex_d_t)point1a && point2->x < (flex_d_t)point1a )
        return 0;
    v29 = point2->x;
    if (point1->x < (flex_d_t)point1a)
    {
        v31 = (point1a - point1->x) / (v29 - point1->x);
        v32 = (point2->y - point1->y) * v31 + point1->y;
        v33 = (point2->z - point1->z) * v31 + point1->z;
        point1->x = point1a;
        point1->y = v32;
        point1->z = v33;
        if ( out1 )
            *out1 = 1;
    }
    else if ( v29 < point1a )
    {
        v34 = (point1a - point2->x) / (point2->x - point1->x);
        v35 = (point2->y - point1->y) * v34 + point2->y;
        v36 = (point2->z - point1->z) * v34 + point2->z;
        point2->x = point1a;
        point2->y = v35;
        point2->z = v36;
        if ( out2 )
            *out2 = 1;
    }
    point1b = clipFrustum->orthoRight;
    if ( point1->x > (flex_d_t)point1b && point2->x > (flex_d_t)point1b )
        return 0;
    v38 = point2->x;
    if (point1->x <= (flex_d_t)point1b)
    {
        if ( v38 > point1b )
        {
            v44 = (point1b - point2->x) / (point2->x - point1->x);
            v45 = (point2->y - point1->y) * v44 + point2->y;
            v46 = (point2->z - point1->z) * v44 + point2->z;
            point2->x = point1b;
            point2->y = v45;
            point2->z = v46;
            if ( out2 )
                *out2 = 1;
        }
    }
    else
    {
        v41 = (point1b - point1->x) / (v38 - point1->x);
        v42 = (point2->y - point1->y) * v41 + point1->y;
        v43 = (point2->z - point1->z) * v41 + point1->z;
        point1->x = point1b;
        point1->y = v42;
        point1->z = v43;
        if ( out1 )
            *out1 = 1;
    }
    point1c = clipFrustum->orthoTop;
    if ( point1->z > (flex_d_t)point1c && point2->z > (flex_d_t)point1c )
        return 0;
    if ( point1->z <= (flex_d_t)point1c )
    {
        if ( point2->z > (flex_d_t)point1c )
        {
            v50 = (point1c - point2->z) / (point2->z - point1->z);
            v51 = (point2->x - point1->x) * v50 + point2->x;
            v52 = (point2->y - point1->y) * v50 + point2->y;
            point2->z = point1c;
            point2->x = v51;
            point2->y = v52;
            if ( out2 )
                *out2 = 1;
        }
    }
    else
    {
        v47 = (point1c - point1->z) / (point2->z - point1->z);
        v48 = (point2->x - point1->x) * v47 + point1->x;
        v49 = (point2->y - point1->y) * v47 + point1->y;
        point1->z = point1c;
        point1->x = v48;
        point1->y = v49;
        if ( out1 )
            *out1 = 1;
    }
    point1d = clipFrustum->orthoBottom;
    if ( point1->z < (flex_d_t)point1d && point2->z < (flex_d_t)point1d )
        return 0;
    v54 = point2->z;
    if (point1->z >= (flex_d_t)point1d)
    {
        v56 = (point1d - point1->z) / (v54 - point1->z);
        v57 = (point2->x - point1->x) * v56 + point1->x;
        v58 = (point2->y - point1->y) * v56 + point1->y;
        point1->z = point1d;
        point1->x = v57;
        point1->y = v58;
        if ( out1 )
        {
            *out1 = 1;
            return 1;
        }
    }
    else if ( v54 < point1d )
    {
        v59 = (point1d - point2->z) / (point2->z - point1->z);
        v60 = (point2->x - point1->x) * v59 + point2->x;
        v61 = (point2->y - point1->y) * v59 + point2->y;
        point2->z = point1d;
        point2->x = v60;
        point2->y = v61;
        if ( out2 )
            *out2 = 1;
    }
    return 1;
}

int rdClip_Line3(rdClipFrustum *clipFrustum, rdVector3 *point1, rdVector3 *point2, rdVector3 *pointOut1, rdVector3 *pointOut2, int *out1, int *out2)
{
    signed int ret;
    rdVector3 vertex_out;
    rdVector3 vertex_out2;
    rdVector3 project1;
    rdVector3 project2;

    rdMatrix_TransformPoint34(&vertex_out, point1, &rdCamera_pCurCamera->view_matrix);
    rdMatrix_TransformPoint34(&vertex_out2, point2, &rdCamera_pCurCamera->view_matrix);
    if ( rdCamera_pCurCamera->projectType == rdCameraProjectType_Perspective)
        ret = rdClip_Line3Project(clipFrustum, &vertex_out, &vertex_out2, out1, out2);
    else
        ret = rdClip_Line3Ortho(clipFrustum, &vertex_out, &vertex_out2, out1, out2);

    if ( !ret )
        return 0;

    rdCamera_pCurCamera->fnProject(&project1, &vertex_out);
    rdCamera_pCurCamera->fnProject(&project2, &vertex_out2);

    if ( pointOut1 )
    {
        rdVector_Copy3(pointOut1, &project1);
    }

    if ( pointOut2 )
    {
        rdVector_Copy3(pointOut2, &project2);
    }
    return 1;
}

int rdClip_SphereInFrustrum(const rdClipFrustum* NO_ALIAS frust, const rdVector3* NO_ALIAS pos, flex_t rad)
{
    int v5; // edi
    int v9; // esi
    flex_d_t v10; // st7
    flex_d_t v11; // st7
    flex_d_t v12; // st7
    flex_d_t v13; // st7
    flex_t v14; // [esp+0h] [ebp-Ch]
    flex_t v15; // [esp+4h] [ebp-8h]
    flex_t v16; // [esp+8h] [ebp-4h]
    flex_t v17; // [esp+8h] [ebp-4h]
    flex_t frusta; // [esp+10h] [ebp+4h]
    flex_t posa; // [esp+14h] [ebp+8h]
    flex_t posb; // [esp+14h] [ebp+8h]
    flex_t posc; // [esp+14h] [ebp+8h]
    flex_t rada; // [esp+18h] [ebp+Ch]
    flex_t radb; // [esp+18h] [ebp+Ch]

    v14 = rad + pos->y;
    v5 = 1;
    frusta = pos->y - rad;
    if (v14 < (flex_d_t)frust->zNear)
        return 2;
    if ( frusta < (flex_d_t)frust->zNear )
        v5 = 0;
    if (frust->bClipFar)
    {
        if ( frusta > (flex_d_t)frust->zFar )
            return 2;
        if ( v14 > (flex_d_t)frust->zFar )
            v5 = 0;
    }

    v15 = rad + pos->z;
    v16 = pos->z - rad;
    if ( rdCamera_pCurCamera->projectType == rdCameraProjectType_Perspective)
    {
        v10 = frust->farTop * frusta;
        posa = frust->farTop * v14;
    }
    else
    {
        v10 = frust->orthoTop;
        posa = frust->orthoTop;
    }
    if ( v16 > v10 && v16 > (flex_d_t)posa )
        return 2;
    if ( v15 > v10 || v15 > (flex_d_t)posa )
        v5 = 0;
    if ( rdCamera_pCurCamera->projectType == rdCameraProjectType_Perspective)
    {
        v11 = frust->bottom * frusta;
        posb = frust->bottom * v14;
    }
    else
    {
        v11 = frust->orthoBottom;
        posb = frust->orthoBottom;
    }
    if ( v15 < v11 && v15 < (flex_d_t)posb )
        return 2;
    if ( v16 < v11 || v16 < (flex_d_t)posb )
        v5 = 0;
    v17 = pos->x + rad;
    posc = pos->x - rad;
    if ( rdCamera_pCurCamera->projectType == rdCameraProjectType_Perspective)
    {
        v12 = frust->farLeft * frusta;
        rada = frust->farLeft * v14;
    }
    else
    {
        v12 = frust->orthoLeft;
        rada = frust->orthoLeft;
    }
    if ( v17 < v12 && v17 < (flex_d_t)rada )
        return 2;
    if ( posc < v12 || posc < (flex_d_t)rada )
        v5 = 0;
    if ( rdCamera_pCurCamera->projectType == rdCameraProjectType_Perspective)
    {
        v13 = frust->right * frusta;
        radb = frust->right * v14;
    }
    else
    {
        v13 = frust->orthoRight;
        radb = frust->orthoRight;
    }
    if ( posc > v13 && posc > (flex_d_t)radb )
        return 2;
    if ( v17 > v13 || v17 > (flex_d_t)radb )
        v5 = 0;
    return v5 == 0;
}

int rdClip_Face3W(const rdClipFrustum* NO_ALIAS pClipFrustum, rdVector3* NO_ALIAS pVertices, int numVertices)
{
#ifdef EXPERIMENTAL_FIXED_POINT
    const int premultiplyA = 1;
    const int premultiplyASquared = premultiplyA*premultiplyA;
#else
    const flex_t premultiplyA = 1.0;
    const flex_t premultiplyASquared = 1.0;
#endif

    INST_WORKBUFS

    rdVector3* NO_ALIAS pVertIter; // edi
    rdVector3* NO_ALIAS pLastVertIter; // ebx
    rdVector3* NO_ALIAS pWorkVertIter; // ecx
    flex_d_t v16; // st6
    flex_d_t v19; // st5
    flex_d_t v25; // st4
    flex_d_t v33; // st3
    rdVector3* NO_ALIAS pLastDestVert; // eax
    flex_d_t v92; // st6
    flex_d_t v98; // st5
    flex_d_t v99; // st4
    rdVector3* NO_ALIAS pLastSourceVert; // eax
    flex_d_t v122; // st6
    flex_d_t v123; // st7
    flex_d_t v126; // st6
    flex_d_t v127; // st5
    flex_d_t v130; // st4
    flex_d_t v132; // st5
    flex_t* NO_ALIAS v143;
    flex_d_t v150; // st7
    flex_d_t v157; // st6
    flex_d_t v174; // st7
    int numOnScreenVertices; // [esp+10h] [ebp-20h]
    flex_t v202; // [esp+1Ch] [ebp-14h]
    flex_t v207; // [esp+1Ch] [ebp-14h]
    flex_t v209; // [esp+20h] [ebp-10h]
    flex_t numVerticese; // [esp+44h] [ebp+14h]
    
    rdClip_faceStatus = 0;
    numOnScreenVertices = 0;

    pSourceVert = pVertices;
    pDestVert = workVerts;
    
    INST_ARG_COPIES_W

    pWorkVertIter = workVerts;
    
    pVertIter = pSourceVert;
    pLastVertIter = &pSourceVert[numVertices - 1];

#if defined(RDCLIP_CLIP_ZFAR_FIRST) && !defined(TARGET_TWL)
    if (pClipFrustum->bClipFar)
    {
        for (int i = 0; i < numVertices; pLastVertIter = pVertIter++, i++)
        {
            if (pLastVertIter->y > (flex_d_t)pClipFrustum->zFar && pVertIter->y > (flex_d_t)pClipFrustum->zFar) {
                continue;
            }

            if ( pLastVertIter->y != pClipFrustum->zFar
              && pVertIter->y != pClipFrustum->zFar
              && (pLastVertIter->y > (flex_d_t)pClipFrustum->zFar || pVertIter->y > (flex_d_t)pClipFrustum->zFar) )
            {
                
                v174 = (pClipFrustum->zFar - pLastVertIter->y) / (pVertIter->y - pLastVertIter->y);
                pWorkVertIter->x = (pVertIter->x - pLastVertIter->x) * v174 + pLastVertIter->x;
                pWorkVertIter->y = pClipFrustum->zFar;
                pWorkVertIter->z = (pVertIter->z - pLastVertIter->z) * v174 + pLastVertIter->z;

                ++pWorkVertIter;
                ++numOnScreenVertices;
                rdClip_faceStatus |= CLIPSTAT_FAR;
            }
            if ( pVertIter->y <= (flex_d_t)pClipFrustum->zFar )
            {
                *pWorkVertIter = *pVertIter;
                ++pWorkVertIter;
                ++numOnScreenVertices;
            }
        }
        if ( numOnScreenVertices < 3 ) {
            return numOnScreenVertices;
        }

        numVertices = numOnScreenVertices;
        pLastSourceVert = pSourceVert;
        pLastDestVert = pDestVert;
        
        pSourceVert = pLastDestVert;
        pDestVert = pLastSourceVert;
        
        pWorkVertIter = pLastSourceVert;
        
        pVertIter = pLastDestVert;
        pLastVertIter = &pLastDestVert[numVertices - 1];
        
        numOnScreenVertices = 0;
    }
#endif
    for (int i = 0; i < numVertices; pLastVertIter = pVertIter++, i++)
    {
        flex_t nearLeftPlaneA = pClipFrustum->farLeft * pLastVertIter->y;
        flex_t nearLeftPlaneB = pClipFrustum->farLeft * pVertIter->y;
        if (pLastVertIter->x < nearLeftPlaneA && pVertIter->x < nearLeftPlaneB) {
            continue;
        }

        if ( pLastVertIter->x != nearLeftPlaneA && nearLeftPlaneB != pVertIter->x && (pLastVertIter->x < nearLeftPlaneA || pVertIter->x < nearLeftPlaneB) )
        {
            flex_t dy = (pVertIter->y - pLastVertIter->y);
            flex_t dx = (pVertIter->x - pLastVertIter->x);
            v16 = ((pVertIter->y * premultiplyA) * (pLastVertIter->x * premultiplyA)) - ((pLastVertIter->y * premultiplyA) * (pVertIter->x * premultiplyA));
            v202 = ((pClipFrustum->farLeft * dy) * premultiplyASquared) - (dx * premultiplyASquared);
            if (v202 != 0.0)
            {
                v16 = v16 / v202;
            }
            else {
                v16 = v16 / premultiplyASquared;
            }
            v19 = pClipFrustum->farLeft * v16;
            if ( stdMath_Fabs(dy) <= stdMath_Fabs(dx) )
                v25 = ((v19 * premultiplyASquared) - (pLastVertIter->x * premultiplyASquared)) / (dx * premultiplyASquared);
            else
                v25 = ((v16 * premultiplyASquared) - (pLastVertIter->y * premultiplyASquared)) / (dy * premultiplyASquared);
            
            pWorkVertIter->x = v19;
            pWorkVertIter->y = v16;
            pWorkVertIter->z = (pVertIter->z - pLastVertIter->z) * v25 + pLastVertIter->z;
            ++numOnScreenVertices;
            ++pWorkVertIter;
            rdClip_faceStatus |= CLIPSTAT_LEFT;
        }
        if ( nearLeftPlaneB <= pVertIter->x )
        {
            *pWorkVertIter = *pVertIter;
            ++numOnScreenVertices;
            ++pWorkVertIter;
        }
    }
    if ( numOnScreenVertices < 3 )
        return numOnScreenVertices;

    numVertices = numOnScreenVertices;
    pLastSourceVert = pSourceVert;
    pLastDestVert = pDestVert;
    
    pSourceVert = pLastDestVert;
    pDestVert = pLastSourceVert;
    
    pWorkVertIter = pLastSourceVert;
    
    pVertIter = pLastDestVert;
    pLastVertIter = &pLastDestVert[numVertices - 1];
    
    numOnScreenVertices = 0;
    for (int i = 0; i < numVertices; pLastVertIter = pVertIter++, i++)
    {
        flex_t rightPlaneA = pClipFrustum->right * pLastVertIter->y;
        flex_t rightPlaneB = pClipFrustum->right * pVertIter->y;
        if ( pLastVertIter->x > rightPlaneA && pVertIter->x > rightPlaneB) {
            continue;
        }

        if ( pLastVertIter->x != rightPlaneA && rightPlaneB != pVertIter->x && (pLastVertIter->x > (flex_d_t)rightPlaneA || pVertIter->x > rightPlaneB) )
        {
            flex_t dy = (pVertIter->y - pLastVertIter->y);
            flex_t dx = (pVertIter->x - pLastVertIter->x);
            v16 = ((pVertIter->y * premultiplyA) * (pLastVertIter->x * premultiplyA)) - ((pLastVertIter->y * premultiplyA) * (pVertIter->x * premultiplyA));
            v202 = ((pClipFrustum->right * dy) * premultiplyASquared) - (dx * premultiplyASquared);
            if (v202 != 0.0)
            {
                
                v16 = v16 / v202;
            }
            else {
                v16 = v16 / premultiplyASquared;
            }
            v19 = pClipFrustum->right * v16;
            if ( stdMath_Fabs(dy) <= stdMath_Fabs(dx) )
                v25 = ((v19 * premultiplyASquared) - (pLastVertIter->x * premultiplyASquared)) / (dx * premultiplyASquared);
            else
                v25 = ((v16 * premultiplyASquared) - (pLastVertIter->y * premultiplyASquared)) / (dy * premultiplyASquared);
            
            pWorkVertIter->x = v19;
            pWorkVertIter->y = v16;
            pWorkVertIter->z = ((pVertIter->z - pLastVertIter->z) * v25) + pLastVertIter->z;
            ++numOnScreenVertices;
            ++pWorkVertIter;
            rdClip_faceStatus |= CLIPSTAT_RIGHT;
        }
        if ( rightPlaneB >= pVertIter->x )
        {
            pWorkVertIter->x = pVertIter->x;
            pWorkVertIter->y = pVertIter->y;
            pWorkVertIter->z = pVertIter->z;
            ++numOnScreenVertices;
            ++pWorkVertIter;
        }
    }
    
    if ( numOnScreenVertices < 3 ) {
        return numOnScreenVertices;
    }
    
    numVertices = numOnScreenVertices;
    pLastSourceVert = pSourceVert;
    pLastDestVert = pDestVert;
    
    pSourceVert = pLastDestVert;
    pDestVert = pLastSourceVert;
    
    pWorkVertIter = pLastSourceVert;
    
    pVertIter = pLastDestVert;
    pLastVertIter = &pLastDestVert[numVertices - 1];
    
    numOnScreenVertices = 0;
    for (int i = 0; i < numVertices; pLastVertIter = pVertIter++, i++)
    {
        flex_t topPlaneA = pClipFrustum->farTop * pLastVertIter->y;
        flex_t topPlaneB = pClipFrustum->farTop * pVertIter->y;
        if (pLastVertIter->z > topPlaneA && pVertIter->z > (flex_d_t)topPlaneB) {
            continue;
        }

        if ( pLastVertIter->z != topPlaneA && pVertIter->z != topPlaneB && (pLastVertIter->z > (flex_d_t)topPlaneA || pVertIter->z > (flex_d_t)topPlaneB) )
        {
            flex_t dy = pVertIter->y - pLastVertIter->y;
            flex_t dz = pVertIter->z - pLastVertIter->z;
            v122 = ((pVertIter->y * premultiplyA) * (pLastVertIter->z * premultiplyA)) - ((pVertIter->z * premultiplyA) * (pLastVertIter->y * premultiplyA));
            v207 = (pClipFrustum->farTop * premultiplyA) * (dy* premultiplyA) - (dz * premultiplyASquared);
            if (v207 != 0.0)
            {
                v122 = v122 / v207;
            }
            else {
                v122 = v122 / premultiplyASquared;
            }
            v92 = pClipFrustum->farTop * v122;
            if ( stdMath_Fabs(dy) <= stdMath_Fabs(dz) )
                v98 = ((v92 * premultiplyASquared) - (pLastVertIter->z * premultiplyASquared)) / (dz * premultiplyASquared);
            else
                v98 = ((v122 * premultiplyASquared) - (pLastVertIter->y * premultiplyASquared)) / (dy * premultiplyASquared);
            v99 = pVertIter->x - pLastVertIter->x;
            
            pWorkVertIter->x = (v99 * v98) + pLastVertIter->x;
            pWorkVertIter->y = v122;
            pWorkVertIter->z = v92;
            ++numOnScreenVertices;
            ++pWorkVertIter;
            rdClip_faceStatus |= CLIPSTAT_TOP;
        }
        if ( pVertIter->z <= (flex_d_t)topPlaneB )
        {
            pWorkVertIter->x = pVertIter->x;
            pWorkVertIter->y = pVertIter->y;
            pWorkVertIter->z = pVertIter->z;
            ++numOnScreenVertices;
            ++pWorkVertIter;
        }
    }
    if ( numOnScreenVertices < 3 ) {
        return numOnScreenVertices;
    }

    numVertices = numOnScreenVertices;
    pLastSourceVert = pSourceVert;
    pLastDestVert = pDestVert;
    
    pSourceVert = pLastDestVert;
    pDestVert = pLastSourceVert;
    
    pWorkVertIter = pLastSourceVert;
    
    pVertIter = pLastDestVert;
    pLastVertIter = &pLastDestVert[numVertices - 1];
    
    numOnScreenVertices = 0;
    for (int i = 0; i < numVertices; pLastVertIter = pVertIter++, i++)
    {
        flex_t bottomPlaneA = pClipFrustum->bottom * pLastVertIter->y;
        flex_t bottomPlaneB = pClipFrustum->bottom * pVertIter->y;
        if (pLastVertIter->z < bottomPlaneA && pVertIter->z < (flex_d_t)bottomPlaneB) {
            continue;
        }

        if ( pLastVertIter->z != bottomPlaneA && pVertIter->z != bottomPlaneB && (pLastVertIter->z < (flex_d_t)bottomPlaneA || pVertIter->z < (flex_d_t)bottomPlaneB) )
        {
            flex_t dy = pVertIter->y - pLastVertIter->y;
            flex_t dz = pVertIter->z - pLastVertIter->z;

            v122 = (((pVertIter->y * premultiplyA) * (pLastVertIter->z * premultiplyA)) - ((pVertIter->z * premultiplyA) * (pLastVertIter->y * premultiplyA)));
            v207 = ((pClipFrustum->bottom * premultiplyA) * (dy * premultiplyA) - (dz * premultiplyASquared));
            if (v207 != 0.0)
            {
                v123 = v122 / v207;
            }
            else {
                v123 = v122 / premultiplyASquared;
            }
            v126 = (pClipFrustum->bottom * premultiplyA) * (v123 * premultiplyA);
            v127 = stdMath_Fabs(dy);
            v130 = stdMath_Fabs(dz);
            if ( v127 <= v130 ) {
                v132 = ((v126 - (pLastVertIter->z * premultiplyASquared))) / (dz * premultiplyASquared);
            }
            else {
                v132 = ((v123 - pLastVertIter->y) * premultiplyASquared) / (dy * premultiplyASquared);
            }
            pWorkVertIter->x = ((pVertIter->x - pLastVertIter->x) * v132) + pLastVertIter->x;
            pWorkVertIter->y = v123;
            pWorkVertIter->z = v126 / premultiplyASquared;
            
            ++numOnScreenVertices;
            ++pWorkVertIter;
            rdClip_faceStatus |= CLIPSTAT_BOTTOM;
        }
        if ( pVertIter->z >= (flex_d_t)bottomPlaneB )
        {
            *pWorkVertIter = *pVertIter;
            ++numOnScreenVertices;
            ++pWorkVertIter;
        }
    }

    if ( numOnScreenVertices < 3 )
        return numOnScreenVertices;

#ifndef TARGET_TWL
    numVertices = numOnScreenVertices;
    pLastSourceVert = pSourceVert;
    pLastDestVert = pDestVert;
    
    pSourceVert = pLastDestVert;
    pDestVert = pLastSourceVert;
    
    pWorkVertIter = pLastSourceVert;
    
    pVertIter = pLastDestVert;
    pLastVertIter = &pLastDestVert[numVertices - 1];
    
    numOnScreenVertices = 0;
    for (int i = 0; i < numVertices; pLastVertIter = pVertIter++, i++)
    {
        if (pLastVertIter->y < (flex_d_t)pClipFrustum->zNear && pVertIter->y < (flex_d_t)pClipFrustum->zNear) {
            continue;
        }

        if ( pLastVertIter->y != pClipFrustum->zNear
          && pVertIter->y != pClipFrustum->zNear
          && (pLastVertIter->y < (flex_d_t)pClipFrustum->zNear || pVertIter->y < (flex_d_t)pClipFrustum->zNear) )
        {
            flex_t dy = (pVertIter->y - pLastVertIter->y) * premultiplyASquared;
#ifdef EXPERIMENTAL_FIXED_POINT
            if (dy != 0.0) {
                v150 = ((pClipFrustum->zNear - pLastVertIter->y) * premultiplyASquared) / dy;
            }
            else {
                v150 = (pClipFrustum->zNear - pLastVertIter->y);
            }
#else
            v150 = ((pClipFrustum->zNear - pLastVertIter->y) * premultiplyASquared) / dy;
#endif
            pWorkVertIter->x = ((pVertIter->x - pLastVertIter->x) * v150) + pLastVertIter->x;
            pWorkVertIter->y = pClipFrustum->zNear;
            pWorkVertIter->z = (pVertIter->z - pLastVertIter->z) * v150 + pLastVertIter->z;
            rdClip_faceStatus |= CLIPSTAT_NEAR;
            ++pWorkVertIter;
            ++numOnScreenVertices;
        }
        if ( pVertIter->y >= (flex_d_t)pClipFrustum->zNear )
        {
            *pWorkVertIter = *pVertIter;
            ++numOnScreenVertices;
            ++pWorkVertIter;
        }
    }

    if ( numOnScreenVertices < 3 )
    {
        rdClip_faceStatus |= CLIPSTAT_NONE_VISIBLE; // Bug? Or did I mislabel this status
        return numOnScreenVertices;
    }
#endif

#if !defined(RDCLIP_CLIP_ZFAR_FIRST) && !defined(TARGET_TWL)
    if (pClipFrustum->bClipFar)
    {
        numVertices = numOnScreenVertices;
        pLastSourceVert = pSourceVert;
        pLastDestVert = pDestVert;
        
        pSourceVert = pLastDestVert;
        pDestVert = pLastSourceVert;
        
        pWorkVertIter = pLastSourceVert;
        
        pVertIter = pLastDestVert;
        pLastVertIter = &pLastDestVert[numVertices - 1];
        
        numOnScreenVertices = 0;
        for (int i = 0; i < numVertices; pLastVertIter = pVertIter++, i++)
        {
            if (pLastVertIter->y > (flex_d_t)pClipFrustum->zFar && pVertIter->y > (flex_d_t)pClipFrustum->zFar) {
                continue;
            }

            if ( pLastVertIter->y != pClipFrustum->zFar
              && pVertIter->y != pClipFrustum->zFar
              && (pLastVertIter->y > (flex_d_t)pClipFrustum->zFar || pVertIter->y > (flex_d_t)pClipFrustum->zFar) )
            {
                
                v174 = (pClipFrustum->zFar - pLastVertIter->y) / (pVertIter->y - pLastVertIter->y);
                pWorkVertIter->x = (pVertIter->x - pLastVertIter->x) * v174 + pLastVertIter->x;
                pWorkVertIter->y = pClipFrustum->zFar;
                pWorkVertIter->z = (pVertIter->z - pLastVertIter->z) * v174 + pLastVertIter->z;

                ++pWorkVertIter;
                ++numOnScreenVertices;
                rdClip_faceStatus |= CLIPSTAT_FAR;
            }
            if ( pVertIter->y <= (flex_d_t)pClipFrustum->zFar )
            {
                *pWorkVertIter = *pVertIter;
                ++pWorkVertIter;
                ++numOnScreenVertices;
            }
        }
        if ( numOnScreenVertices < 3 ) {
            return numOnScreenVertices;
        }
    }
#endif

    if ( pDestVert != pVertices )
    {
        _memcpy(pVertices, pDestVert, sizeof(rdVector3) * numOnScreenVertices);
    }

    return numOnScreenVertices;
}

// TVertices as in Texture Vertices, or UVs
int rdClip_Face3GT(const rdClipFrustum* NO_ALIAS pClipFrustum, rdVector3* NO_ALIAS pVertices, rdVector2* NO_ALIAS pTVertices, flex_t* NO_ALIAS pIVertices, int numVertices)
{
#ifdef EXPERIMENTAL_FIXED_POINT
    const int premultiplyA = 16;
    const int premultiplyASquared = premultiplyA*premultiplyA;
#else
    const flex_t premultiplyA = 1.0;
    const flex_t premultiplyASquared = 1.0;
#endif

    INST_WORKBUFS

    //return _rdClip_Face3GT(pClipFrustum, pVertices, pTVertices, pIVertices, numVertices);
    rdVector2* NO_ALIAS pTVertIter; // esi
    rdVector3* NO_ALIAS pVertIter; // edi
    rdVector3* NO_ALIAS pLastVertIter; // ebx
    rdVector2* NO_ALIAS pLastTVertIter; // edx
    rdVector2* NO_ALIAS pWorkTVertIter; // ebp
    rdVector3* NO_ALIAS pWorkVertIter; // ecx
    flex_d_t v16; // st6
    flex_d_t v19; // st5
    flex_d_t v25; // st4
    flex_d_t v33; // st3
    rdVector3* NO_ALIAS pLastDestVert; // eax
    flex_d_t v92; // st6
    flex_d_t v98; // st5
    flex_d_t v99; // st4
    rdVector3* NO_ALIAS pLastSourceVert; // eax
    flex_d_t v122; // st6
    flex_d_t v123; // st7
    flex_d_t v126; // st6
    flex_d_t v127; // st5
    flex_d_t v130; // st4
    flex_d_t v132; // st5
    flex_t* v143;
    flex_d_t v150; // st7
    flex_d_t v157; // st6
    flex_d_t v174; // st7
    int numOnScreenVertices; // [esp+10h] [ebp-20h]
    flex_t* NO_ALIAS pIVertIter; // [esp+14h] [ebp-1Ch]
    flex_t* NO_ALIAS pLastIVertIter; // [esp+18h] [ebp-18h]
    flex_t v202; // [esp+1Ch] [ebp-14h]
    flex_t v207; // [esp+1Ch] [ebp-14h]
    flex_t v209; // [esp+20h] [ebp-10h]
    flex_t* NO_ALIAS pWorkIVertIter; // [esp+24h] [ebp-Ch]
    flex_t numVerticese; // [esp+44h] [ebp+14h]
    rdVector2* NO_ALIAS pLastSourceTVert;
    rdVector2* NO_ALIAS pLastDestTVert;
    flex_t* NO_ALIAS pLastSourceIVert;
    flex_t* NO_ALIAS pLastDestIVert;

    rdClip_faceStatus = 0;
    numOnScreenVertices = 0;

    pSourceVert = pVertices;
    pDestVert = workVerts;
    pSourceTVert = pTVertices;
    pDestTVert = workTVerts;
    pSourceIVert = pIVertices;
    pDestIVert = workIVerts;

    INST_ARG_COPIES

    pWorkVertIter = workVerts;
    pWorkTVertIter = workTVerts;
    pWorkIVertIter = workIVerts;

    pVertIter = pSourceVert;
    pTVertIter = pSourceTVert;
    pIVertIter = pSourceIVert;
    pLastVertIter = &pSourceVert[numVertices - 1];
    pLastTVertIter = &pSourceTVert[numVertices - 1];
    pLastIVertIter = &pSourceIVert[numVertices - 1];

#ifdef RDCLIP_CLIP_ZFAR_FIRST
    if (pClipFrustum->bClipFar)
    {
        for (int i = 0; i < numVertices; pLastVertIter = pVertIter++, pLastIVertIter = pIVertIter++, pLastTVertIter = pTVertIter++, i++)
        {
            if (!(pLastVertIter->y <= (flex_d_t)pClipFrustum->zFar || pVertIter->y <= (flex_d_t)pClipFrustum->zFar)) {
                continue;
            }

            if ( pLastVertIter->y != pClipFrustum->zFar
              && pVertIter->y != pClipFrustum->zFar
              && (pLastVertIter->y > (flex_d_t)pClipFrustum->zFar || pVertIter->y > (flex_d_t)pClipFrustum->zFar) )
            {
                
                v174 = (pClipFrustum->zFar - pLastVertIter->y) / (pVertIter->y - pLastVertIter->y);
                pWorkVertIter->x = (pVertIter->x - pLastVertIter->x) * v174 + pLastVertIter->x;
                pWorkVertIter->y = pClipFrustum->zFar;
                pWorkVertIter->z = (pVertIter->z - pLastVertIter->z) * v174 + pLastVertIter->z;

                pWorkTVertIter->x = (pTVertIter->x - pLastTVertIter->x) * v174 + pLastTVertIter->x;
                pWorkTVertIter->y = (pTVertIter->y - pLastTVertIter->y) * v174 + pLastTVertIter->y;
                
                *pWorkIVertIter++ = ((*pIVertIter - *pLastIVertIter) * v174) + *pLastIVertIter;
                ++pWorkVertIter;
                ++pWorkTVertIter;
                ++numOnScreenVertices;
                rdClip_faceStatus |= CLIPSTAT_FAR;
            }
            if ( pVertIter->y <= (flex_d_t)pClipFrustum->zFar )
            {
                *pWorkVertIter = *pVertIter;
                pWorkTVertIter->x = pTVertIter->x;
                pWorkTVertIter->y = pTVertIter->y;
                ++pWorkVertIter;
                ++pWorkTVertIter;
                ++numOnScreenVertices;
                *pWorkIVertIter++ = *pIVertIter;
            }
        }
        if ( numOnScreenVertices < 3 ) {
            return numOnScreenVertices;
        }

        numVertices = numOnScreenVertices;
        pLastSourceVert = pSourceVert;
        pLastDestVert = pDestVert;
        pLastSourceTVert = pSourceTVert;
        pLastDestTVert = pDestTVert;
        pLastSourceIVert = pSourceIVert;
        pLastDestIVert = pDestIVert;

        pSourceVert = pLastDestVert;
        pDestVert = pLastSourceVert;
        pSourceTVert = pLastDestTVert;
        pDestTVert = pLastSourceTVert;
        pSourceIVert = pLastDestIVert;
        pDestIVert = pLastSourceIVert;

        pWorkVertIter = pLastSourceVert;
        pWorkTVertIter = pLastSourceTVert;
        pWorkIVertIter = pLastSourceIVert;

        pVertIter = pLastDestVert;
        pTVertIter = pLastDestTVert;
        pIVertIter = pLastDestIVert;
        pLastIVertIter = &pSourceIVert[numVertices - 1];
        pLastVertIter = &pLastDestVert[numVertices - 1];
        pLastTVertIter = &pTVertIter[numVertices - 1];

        numOnScreenVertices = 0;
    }
#endif
    for (int i = 0; i < numVertices; pLastVertIter = pVertIter++, pLastTVertIter = pTVertIter++, pLastIVertIter = pIVertIter++, i++)
    {
        flex_t nearLeftPlaneA = pClipFrustum->nearLeft * pLastVertIter->y;
        flex_t nearLeftPlaneB = pClipFrustum->nearLeft * pVertIter->y;
        if (!(nearLeftPlaneA <= pLastVertIter->x || nearLeftPlaneB <= pVertIter->x)) {
            continue;
        }

        if ( pLastVertIter->x != nearLeftPlaneA && nearLeftPlaneB != pVertIter->x && (pLastVertIter->x < nearLeftPlaneA || nearLeftPlaneB > pVertIter->x) )
        {
            flex_t dy = (pVertIter->y - pLastVertIter->y);
            flex_t dx = (pVertIter->x - pLastVertIter->x);
            v16 = ((pVertIter->y * premultiplyA) * (pLastVertIter->x * premultiplyA)) - ((pLastVertIter->y * premultiplyA) * (pVertIter->x * premultiplyA));
            v202 = ((pClipFrustum->nearLeft * dy) * premultiplyASquared) - (dx * premultiplyASquared);
            if (v202 != 0.0)
            {
                v16 = v16 / v202;
            }
            else {
                v16 = v16 / premultiplyASquared;
            }
            v19 = pClipFrustum->nearLeft * v16;
            if ( stdMath_Fabs(dy) <= stdMath_Fabs(dx) )
                v25 = ((v19 * premultiplyASquared) - (pLastVertIter->x * premultiplyASquared)) / (dx * premultiplyASquared);
            else
                v25 = ((v16 * premultiplyASquared) - (pLastVertIter->y * premultiplyASquared)) / (dy * premultiplyASquared);
            
            pWorkVertIter->x = v19;
            pWorkVertIter->y = v16;
            pWorkVertIter->z = (pVertIter->z - pLastVertIter->z) * v25 + pLastVertIter->z;
            pWorkTVertIter->x = ((pTVertIter->x - pLastTVertIter->x) * v25) + pLastTVertIter->x;
            pWorkTVertIter->y = (pTVertIter->y - pLastTVertIter->y) * v25 + pLastTVertIter->y;
            *pWorkIVertIter++ = (*pIVertIter - *pLastIVertIter) * v25 + *pLastIVertIter;
            ++numOnScreenVertices;
            ++pWorkTVertIter;
            ++pWorkVertIter;
            rdClip_faceStatus |= CLIPSTAT_LEFT;
        }
        if ( nearLeftPlaneB <= pVertIter->x )
        {
            *pWorkVertIter = *pVertIter;
            pWorkTVertIter->x = pTVertIter->x;
            pWorkTVertIter->y = pTVertIter->y;
            *pWorkIVertIter++ = *pIVertIter;
            ++numOnScreenVertices;
            ++pWorkTVertIter;
            ++pWorkVertIter;
        }
    }
    if ( numOnScreenVertices < 3 )
        return numOnScreenVertices;

    numVertices = numOnScreenVertices;
    pLastSourceVert = pSourceVert;
    pLastDestVert = pDestVert;
    pLastSourceTVert = pSourceTVert;
    pLastDestTVert = pDestTVert;
    pLastSourceIVert = pSourceIVert;
    pLastDestIVert = pDestIVert;

    pSourceVert = pLastDestVert;
    pDestVert = pLastSourceVert;
    pSourceTVert = pLastDestTVert;
    pDestTVert = pLastSourceTVert;
    pSourceIVert = pLastDestIVert;
    pDestIVert = pLastSourceIVert;

    pWorkVertIter = pLastSourceVert;
    pWorkTVertIter = pLastSourceTVert;
    pWorkIVertIter = pLastSourceIVert;

    pVertIter = pLastDestVert;
    pTVertIter = pLastDestTVert;
    pIVertIter = pLastDestIVert;
    pLastIVertIter = &pSourceIVert[numVertices - 1];
    pLastVertIter = &pLastDestVert[numVertices - 1];
    pLastTVertIter = &pTVertIter[numVertices - 1];

    numOnScreenVertices = 0;
    for (int i = 0; i < numVertices; pLastVertIter = pVertIter++, pLastIVertIter = pIVertIter++, pLastTVertIter = pTVertIter++, i++)
    {
        flex_t rightPlaneA = pClipFrustum->right * pLastVertIter->y;
        flex_t rightPlaneB = pClipFrustum->right * pVertIter->y;
        if (!(rightPlaneA >= pLastVertIter->x || rightPlaneB >= pVertIter->x)) {
            continue;
        }

        if ( pLastVertIter->x != rightPlaneA && rightPlaneB != pVertIter->x && (pLastVertIter->x > (flex_d_t)rightPlaneA || rightPlaneB < pVertIter->x) )
        {
            flex_t dy = (pVertIter->y - pLastVertIter->y);
            flex_t dx = (pVertIter->x - pLastVertIter->x);
            v16 = ((pVertIter->y * premultiplyA) * (pLastVertIter->x * premultiplyA)) - ((pLastVertIter->y * premultiplyA) * (pVertIter->x * premultiplyA));
            v202 = ((pClipFrustum->right * dy) * premultiplyASquared) - (dx * premultiplyASquared);
            if (v202 != 0.0)
            {
                
                v16 = v16 / v202;
            }
            else {
                v16 = v16 / premultiplyASquared;
            }
            v19 = pClipFrustum->right * v16;
            if ( stdMath_Fabs(dy) <= stdMath_Fabs(dx) )
                v25 = ((v19 * premultiplyASquared) - (pLastVertIter->x * premultiplyASquared)) / (dx * premultiplyASquared);
            else
                v25 = ((v16 * premultiplyASquared) - (pLastVertIter->y * premultiplyASquared)) / (dy * premultiplyASquared);
            
            pWorkVertIter->x = v19;
            pWorkVertIter->y = v16;
            pWorkVertIter->z = ((pVertIter->z - pLastVertIter->z) * v25) + pLastVertIter->z;
            pWorkTVertIter->x = ((pTVertIter->x - pLastTVertIter->x) * v25) + pLastTVertIter->x;
            pWorkTVertIter->y = ((pTVertIter->y - pLastTVertIter->y) * v25) + pLastTVertIter->y;
            *pWorkIVertIter++ = ((*pIVertIter - *pLastIVertIter) * v25) + *pLastIVertIter;
            ++numOnScreenVertices;
            ++pWorkTVertIter;
            ++pWorkVertIter;
            rdClip_faceStatus |= CLIPSTAT_RIGHT;
        }
        if ( rightPlaneB >= pVertIter->x )
        {
            pWorkVertIter->x = pVertIter->x;
            pWorkVertIter->y = pVertIter->y;
            pWorkVertIter->z = pVertIter->z;
            pWorkTVertIter->x = pTVertIter->x;
            pWorkTVertIter->y = pTVertIter->y;
            *pWorkIVertIter++ = *pIVertIter;
            ++numOnScreenVertices;
            ++pWorkTVertIter;
            ++pWorkVertIter;
        }
    }
    
    if ( numOnScreenVertices < 3 ) {
        return numOnScreenVertices;
    }
    
    numVertices = numOnScreenVertices;
    pLastSourceVert = pSourceVert;
    pLastDestVert = pDestVert;
    pLastSourceTVert = pSourceTVert;
    pLastDestTVert = pDestTVert;
    pLastSourceIVert = pSourceIVert;
    pLastDestIVert = pDestIVert;

    pSourceVert = pLastDestVert;
    pDestVert = pLastSourceVert;
    pSourceTVert = pLastDestTVert;
    pDestTVert = pLastSourceTVert;
    pSourceIVert = pLastDestIVert;
    pDestIVert = pLastSourceIVert;

    pWorkVertIter = pLastSourceVert;
    pWorkTVertIter = pLastSourceTVert;
    pWorkIVertIter = pLastSourceIVert;

    pVertIter = pLastDestVert;
    pTVertIter = pLastDestTVert;
    pIVertIter = pLastDestIVert;
    pLastIVertIter = &pSourceIVert[numVertices - 1];
    pLastVertIter = &pLastDestVert[numVertices - 1];
    pLastTVertIter = &pTVertIter[numVertices - 1];

    numOnScreenVertices = 0;
    for (int i = 0; i < numVertices; pLastVertIter = pVertIter++, pLastIVertIter = pIVertIter++, pLastTVertIter = pTVertIter++, i++)
    {
        flex_t topPlaneA = pClipFrustum->nearTop * pLastVertIter->y;
        flex_t topPlaneB = pClipFrustum->nearTop * pVertIter->y;
        if (!(pLastVertIter->z <= topPlaneA || pVertIter->z <= (flex_d_t)topPlaneB)) {
            continue;
        }

        if ( pLastVertIter->z != topPlaneA && pVertIter->z != topPlaneB && (pLastVertIter->z > (flex_d_t)topPlaneA || pVertIter->z > (flex_d_t)topPlaneB) )
        {
            flex_t dy = pVertIter->y - pLastVertIter->y;
            flex_t dz = pVertIter->z - pLastVertIter->z;
            v122 = ((pVertIter->y * premultiplyA) * (pLastVertIter->z * premultiplyA)) - ((pVertIter->z * premultiplyA) * (pLastVertIter->y * premultiplyA));
            v207 = (pClipFrustum->nearTop * premultiplyA) * (dy* premultiplyA) - (dz * premultiplyASquared);
            if (v207 != 0.0)
            {
                v122 = v122 / v207;
            }
            else {
                v122 = v122 / premultiplyASquared;
            }
            v92 = pClipFrustum->nearTop * v122;
            if ( stdMath_Fabs(dy) <= stdMath_Fabs(dz) )
                v98 = ((v92 * premultiplyASquared) - (pLastVertIter->z * premultiplyASquared)) / (dz * premultiplyASquared);
            else
                v98 = ((v122 * premultiplyASquared) - (pLastVertIter->y * premultiplyASquared)) / (dy * premultiplyASquared);
            v99 = pVertIter->x - pLastVertIter->x;
            
            pWorkVertIter->x = (v99 * v98) + pLastVertIter->x;
            pWorkVertIter->y = v122;
            pWorkVertIter->z = v92;
            pWorkTVertIter->x = ((pTVertIter->x - pLastTVertIter->x) * v98) + pLastTVertIter->x;
            pWorkTVertIter->y = ((pTVertIter->y - pLastTVertIter->y) * v98) + pLastTVertIter->y;
            *pWorkIVertIter++ = ((*pIVertIter - *pLastIVertIter) * v98) + *pLastIVertIter;
            ++numOnScreenVertices;
            ++pWorkTVertIter;
            ++pWorkVertIter;
            rdClip_faceStatus |= CLIPSTAT_TOP;
        }
        if ( pVertIter->z <= (flex_d_t)topPlaneB )
        {
            pWorkVertIter->x = pVertIter->x;
            pWorkVertIter->y = pVertIter->y;
            pWorkVertIter->z = pVertIter->z;
            pWorkTVertIter->x = pTVertIter->x;
            pWorkTVertIter->y = pTVertIter->y;
            *pWorkIVertIter++ = *pIVertIter;
            ++numOnScreenVertices;
            ++pWorkTVertIter;
            ++pWorkVertIter;
        }
    }
    if ( numOnScreenVertices < 3 ) {
        return numOnScreenVertices;
    }

    numVertices = numOnScreenVertices;
    pLastSourceVert = pSourceVert;
    pLastDestVert = pDestVert;
    pLastSourceTVert = pSourceTVert;
    pLastDestTVert = pDestTVert;
    pLastSourceIVert = pSourceIVert;
    pLastDestIVert = pDestIVert;

    pSourceVert = pLastDestVert;
    pDestVert = pLastSourceVert;
    pSourceTVert = pLastDestTVert;
    pDestTVert = pLastSourceTVert;
    pSourceIVert = pLastDestIVert;
    pDestIVert = pLastSourceIVert;

    pWorkVertIter = pLastSourceVert;
    pWorkTVertIter = pLastSourceTVert;
    pWorkIVertIter = pLastSourceIVert;

    pVertIter = pLastDestVert;
    pTVertIter = pLastDestTVert;
    pIVertIter = pLastDestIVert;
    pLastIVertIter = &pSourceIVert[numVertices - 1];
    pLastVertIter = &pLastDestVert[numVertices - 1];
    pLastTVertIter = &pTVertIter[numVertices - 1];

    numOnScreenVertices = 0;
    for (int i = 0; i < numVertices; pLastVertIter = pVertIter++, pLastTVertIter = pTVertIter++, pLastIVertIter = pIVertIter++, i++)
    {
        flex_t bottomPlaneA = pClipFrustum->bottom * pLastVertIter->y;
        flex_t bottomPlaneB = pClipFrustum->bottom * pVertIter->y;
        if (!(pLastVertIter->z >= bottomPlaneA || pVertIter->z >= (flex_d_t)bottomPlaneB)) {
            continue;
        }

        if ( pLastVertIter->z != bottomPlaneA && pVertIter->z != bottomPlaneB && (pLastVertIter->z < (flex_d_t)bottomPlaneA || pVertIter->z < (flex_d_t)bottomPlaneB) )
        {
            flex_t dy = pVertIter->y - pLastVertIter->y;
            flex_t dz = pVertIter->z - pLastVertIter->z;

            v122 = (((pVertIter->y * premultiplyA) * (pLastVertIter->z * premultiplyA)) - ((pVertIter->z * premultiplyA) * (pLastVertIter->y * premultiplyA)));
            v207 = ((pClipFrustum->bottom * premultiplyA) * (dy * premultiplyA) - (dz * premultiplyASquared));
            if (v207 != 0.0)
            {
                v123 = v122 / v207;
            }
            else {
                v123 = v122 / premultiplyASquared;
            }
            v126 = (pClipFrustum->bottom * premultiplyA) * (v123 * premultiplyA);
            v127 = stdMath_Fabs(dy);
            v130 = stdMath_Fabs(dz);
            if ( v127 <= v130 ) {
                v132 = ((v126 - (pLastVertIter->z * premultiplyASquared))) / (dz * premultiplyASquared);
            }
            else {
                v132 = ((v123 - pLastVertIter->y) * premultiplyASquared) / (dy * premultiplyASquared);
            }
            pWorkVertIter->x = ((pVertIter->x - pLastVertIter->x) * v132) + pLastVertIter->x;
            pWorkVertIter->y = v123;
            pWorkVertIter->z = v126 / premultiplyASquared;
            
            pWorkTVertIter->x = (pTVertIter->x - pLastTVertIter->x) * v132 + pLastTVertIter->x;
            pWorkTVertIter->y = (pTVertIter->y - pLastTVertIter->y) * v132 + pLastTVertIter->y;

            *pWorkIVertIter++ = (*pIVertIter - *pLastIVertIter) * v132 + *pLastIVertIter;

            ++numOnScreenVertices;
            ++pWorkVertIter;
            ++pWorkTVertIter;
            rdClip_faceStatus |= CLIPSTAT_BOTTOM;
        }
        if ( pVertIter->z >= (flex_d_t)bottomPlaneB )
        {
            *pWorkVertIter = *pVertIter;
            pWorkTVertIter->x = pTVertIter->x;
            pWorkTVertIter->y = pTVertIter->y;
            *pWorkIVertIter++ = *pIVertIter;
            ++numOnScreenVertices;
            ++pWorkVertIter;
            ++pWorkTVertIter;
        }
    }

    if ( numOnScreenVertices < 3 )
        return numOnScreenVertices;

    numVertices = numOnScreenVertices;
    pLastSourceVert = pSourceVert;
    pLastDestVert = pDestVert;
    pLastSourceTVert = pSourceTVert;
    pLastDestTVert = pDestTVert;
    pLastSourceIVert = pSourceIVert;
    pLastDestIVert = pDestIVert;

    pSourceVert = pLastDestVert;
    pDestVert = pLastSourceVert;
    pSourceTVert = pLastDestTVert;
    pDestTVert = pLastSourceTVert;
    pSourceIVert = pLastDestIVert;
    pDestIVert = pLastSourceIVert;

    pWorkVertIter = pLastSourceVert;
    pWorkTVertIter = pLastSourceTVert;
    pWorkIVertIter = pLastSourceIVert;

    pVertIter = pLastDestVert;
    pTVertIter = pLastDestTVert;
    pIVertIter = pLastDestIVert;
    pLastIVertIter = &pSourceIVert[numVertices - 1];
    pLastVertIter = &pLastDestVert[numVertices - 1];
    pLastTVertIter = &pTVertIter[numVertices - 1];

    numOnScreenVertices = 0;
    for (int i = 0; i < numVertices; pLastVertIter = pVertIter++, pLastIVertIter = pIVertIter++, pLastTVertIter = pTVertIter++, i++)
    {
        if (!(pLastVertIter->y >= (flex_d_t)pClipFrustum->zNear || pVertIter->y >= (flex_d_t)pClipFrustum->zNear)) {
            continue;
        }

        if ( pLastVertIter->y != pClipFrustum->zNear
          && pVertIter->y != pClipFrustum->zNear
          && (pLastVertIter->y < (flex_d_t)pClipFrustum->zNear || pVertIter->y < (flex_d_t)pClipFrustum->zNear) )
        {
            flex_t dy = (pVertIter->y - pLastVertIter->y) * premultiplyASquared;
#ifdef EXPERIMENTAL_FIXED_POINT
            if (dy != 0.0) {
                v150 = ((pClipFrustum->zNear - pLastVertIter->y) * premultiplyASquared) / dy;
            }
            else {
                v150 = (pClipFrustum->zNear - pLastVertIter->y);
            }
#else
            v150 = ((pClipFrustum->zNear - pLastVertIter->y) * premultiplyASquared) / dy;
#endif
            pWorkVertIter->x = ((pVertIter->x - pLastVertIter->x) * v150) + pLastVertIter->x;
            pWorkVertIter->y = pClipFrustum->zNear;
            pWorkVertIter->z = (pVertIter->z - pLastVertIter->z) * v150 + pLastVertIter->z;
            pWorkTVertIter->x = (pTVertIter->x - pLastTVertIter->x) * v150 + pLastTVertIter->x;
            pWorkTVertIter->y = (pTVertIter->y - pLastTVertIter->y) * v150 + pLastTVertIter->y;
            *pWorkIVertIter++ = (*pIVertIter - *pLastIVertIter) * v150 + *pLastIVertIter;
            rdClip_faceStatus |= CLIPSTAT_NEAR;
            ++pWorkVertIter;
            ++pWorkTVertIter;
            ++numOnScreenVertices;
        }
        if ( pVertIter->y >= (flex_d_t)pClipFrustum->zNear )
        {
            *pWorkVertIter = *pVertIter;
            pWorkTVertIter->x = pTVertIter->x;
            pWorkTVertIter->y = pTVertIter->y;
            *pWorkIVertIter++ = *pIVertIter;
            ++numOnScreenVertices;
            ++pWorkVertIter;
            ++pWorkTVertIter;
        }
    }

    if ( numOnScreenVertices < 3 )
    {
        rdClip_faceStatus |= CLIPSTAT_NONE_VISIBLE; // Bug? Or did I mislabel this status
        return numOnScreenVertices;
    }

#ifndef RDCLIP_CLIP_ZFAR_FIRST
    if (pClipFrustum->bClipFar)
    {
        numVertices = numOnScreenVertices;
        pLastSourceVert = pSourceVert;
        pLastDestVert = pDestVert;
        pLastSourceTVert = pSourceTVert;
        pLastDestTVert = pDestTVert;
        pLastSourceIVert = pSourceIVert;
        pLastDestIVert = pDestIVert;

        pSourceVert = pLastDestVert;
        pDestVert = pLastSourceVert;
        pSourceTVert = pLastDestTVert;
        pDestTVert = pLastSourceTVert;
        pSourceIVert = pLastDestIVert;
        pDestIVert = pLastSourceIVert;

        pWorkVertIter = pLastSourceVert;
        pWorkTVertIter = pLastSourceTVert;
        pWorkIVertIter = pLastSourceIVert;

        pVertIter = pLastDestVert;
        pTVertIter = pLastDestTVert;
        pIVertIter = pLastDestIVert;
        pLastIVertIter = &pSourceIVert[numVertices - 1];
        pLastVertIter = &pLastDestVert[numVertices - 1];
        pLastTVertIter = &pTVertIter[numVertices - 1];

        numOnScreenVertices = 0;
        for (int i = 0; i < numVertices; pLastVertIter = pVertIter++, pLastIVertIter = pIVertIter++, pLastTVertIter = pTVertIter++, i++)
        {
            if (!(pLastVertIter->y <= (flex_d_t)pClipFrustum->zFar || pVertIter->y <= (flex_d_t)pClipFrustum->zFar)) {
                continue;
            }

            if ( pLastVertIter->y != pClipFrustum->zFar
              && pVertIter->y != pClipFrustum->zFar
              && (pLastVertIter->y > (flex_d_t)pClipFrustum->zFar || pVertIter->y > (flex_d_t)pClipFrustum->zFar) )
            {
                
                v174 = (pClipFrustum->zFar - pLastVertIter->y) / (pVertIter->y - pLastVertIter->y);
                pWorkVertIter->x = (pVertIter->x - pLastVertIter->x) * v174 + pLastVertIter->x;
                pWorkVertIter->y = pClipFrustum->zFar;
                pWorkVertIter->z = (pVertIter->z - pLastVertIter->z) * v174 + pLastVertIter->z;

                pWorkTVertIter->x = (pTVertIter->x - pLastTVertIter->x) * v174 + pLastTVertIter->x;
                pWorkTVertIter->y = (pTVertIter->y - pLastTVertIter->y) * v174 + pLastTVertIter->y;
                
                *pWorkIVertIter++ = ((*pIVertIter - *pLastIVertIter) * v174) + *pLastIVertIter;
                ++pWorkVertIter;
                ++pWorkTVertIter;
                ++numOnScreenVertices;
                rdClip_faceStatus |= CLIPSTAT_FAR;
            }
            if ( pVertIter->y <= (flex_d_t)pClipFrustum->zFar )
            {
                *pWorkVertIter = *pVertIter;
                pWorkTVertIter->x = pTVertIter->x;
                pWorkTVertIter->y = pTVertIter->y;
                ++pWorkVertIter;
                ++pWorkTVertIter;
                ++numOnScreenVertices;
                *pWorkIVertIter++ = *pIVertIter;
            }
        }
        if ( numOnScreenVertices < 3 ) {
            return numOnScreenVertices;
        }
    }
#endif

    if ( pDestVert != pVertices )
    {
        _memcpy(pVertices, pDestVert, sizeof(rdVector3) * numOnScreenVertices);
        _memcpy(pTVertices, pDestTVert, sizeof(rdVector2) * numOnScreenVertices);
        _memcpy(pIVertices, pDestIVert, sizeof(flex_t) * numOnScreenVertices);
    }

    return numOnScreenVertices;
}

int rdClip_Face3S(rdClipFrustum *frustum, rdVector3 *vertices, int numVertices)
{
    INST_WORKBUFS

    //return _rdClip_Face3S(frustum, vertices, numVertices);
    rdVector3 *v3; // edx
    int v5; // ebp
    rdVector3 *v6; // esi
    rdVector3 *v7; // ecx
    flex_d_t v9; // st7
    flex_d_t v12; // st6
    flex_d_t v20; // st5
    flex_d_t v22; // st5
    rdVector3 *v23; // ecx
    int v24; // eax
    rdVector3 *v25; // esi
    rdVector3 *v26; // edi
    rdVector3 *v27; // ecx
    rdVector3 *v28; // edx
    flex_d_t v30; // st7
    flex_d_t v34; // st6
    flex_d_t v37; // st5
    flex_d_t v40; // st4
    flex_d_t v42; // st5
    int v43; // eax
    flex_d_t v44; // st5
    rdVector3 *v45; // ecx
    int v46; // eax
    rdVector3 *v47; // esi
    rdVector3 *v48; // edi
    rdVector3 *v49; // ecx
    rdVector3 *v50; // edx
    flex_d_t v52; // st7
    flex_d_t v56; // st5
    flex_d_t v57; // st6
    flex_d_t v60; // st5
    flex_d_t v66; // st4
    int v67; // eax
    flex_d_t v68; // st3
    rdVector3 *v69; // ecx
    int v70; // eax
    rdVector3 *v71; // esi
    rdVector3 *v72; // edi
    rdVector3 *v73; // ecx
    rdVector3 *v74; // edx
    flex_d_t v76; // st7
    flex_d_t v79; // st5
    flex_d_t v80; // st6
    flex_d_t v83; // st5
    flex_d_t v84; // st4
    flex_d_t v87; // st3
    flex_d_t v89; // st4
    int v90; // eax
    flex_d_t v91; // st3
    rdVector3 *v92; // ecx
    int v93; // eax
    rdVector3 *v94; // esi
    rdVector3 *v95; // edi
    rdVector3 *v96; // ecx
    rdVector3 *v97; // edx
    flex_d_t v98; // st7
    int v99; // eax
    rdVector3 *v100; // eax
    rdVector3 *v101; // esi
    int v102; // eax
    int v104; // eax
    rdVector3 *v105; // esi
    rdVector3 *v106; // edi
    rdVector3 *v107; // ecx
    rdVector3 *v108; // edx
    flex_d_t v109; // st7
    int v110; // eax
    rdVector3 *v111; // eax
    flex_d_t v112; // [esp+10h] [ebp-8h]
    flex_d_t v113; // [esp+10h] [ebp-8h]
    flex_d_t v114; // [esp+10h] [ebp-8h]
    flex_d_t v115; // [esp+10h] [ebp-8h]
    int v116; // [esp+14h] [ebp-4h]
    int v117; // [esp+14h] [ebp-4h]
    int v118; // [esp+14h] [ebp-4h]
    int v119; // [esp+14h] [ebp-4h]
    flex_d_t frustuma; // [esp+1Ch] [ebp+4h]
    flex_d_t frustumb; // [esp+1Ch] [ebp+4h]
    flex_d_t frustumc; // [esp+1Ch] [ebp+4h]
    flex_d_t frustumd; // [esp+1Ch] [ebp+4h]
    flex_d_t numVerticesa; // [esp+24h] [ebp+Ch]
    flex_d_t numVerticesi; // [esp+24h] [ebp+Ch]
    flex_d_t numVerticesb; // [esp+24h] [ebp+Ch]
    flex_d_t numVerticesc; // [esp+24h] [ebp+Ch]
    flex_d_t numVerticesj; // [esp+24h] [ebp+Ch]
    flex_d_t numVerticesd; // [esp+24h] [ebp+Ch]
    flex_d_t numVerticese; // [esp+24h] [ebp+Ch]
    flex_d_t numVerticesk; // [esp+24h] [ebp+Ch]
    flex_d_t numVerticesf; // [esp+24h] [ebp+Ch]
    flex_d_t numVerticesl; // [esp+24h] [ebp+Ch]
    int numVerticesg; // [esp+24h] [ebp+Ch]
    int numVerticesh; // [esp+24h] [ebp+Ch]

    v3 = vertices;
    pSourceVert = vertices;
    v5 = 0;
    v6 = workVerts;
    rdClip_faceStatus = 0;
    pDestVert = workVerts;
    v7 = &vertices[numVertices - 1];
    for (v116 = numVertices; v116 > 0; v116-- )
    {
        numVerticesa = v7->y * frustum->nearLeft;
        v9 = v3->y * frustum->nearLeft;
        if ( numVerticesa <= v7->x || v9 <= v3->x )
        {
            if ( v7->x != numVerticesa && v9 != v3->x && (v7->x < numVerticesa || v9 > v3->x) )
            {
                frustuma = v3->y - v7->y;
                v112 = v3->x - v7->x;
                v12 = v3->y * v7->x - v7->y * v3->x;
                numVerticesi = frustum->nearLeft * frustuma - v112;
                if ( numVerticesi != 0.0)
                {
                    v12 = v12 / numVerticesi;
                }
                numVerticesb = frustum->nearLeft * v12;

                if ( stdMath_Fabs(frustuma) <= stdMath_Fabs(v112) )
                    v20 = (numVerticesb - v7->x) / v112;
                else
                    v20 = (v12 - v7->y) / frustuma;
                v6->x = numVerticesb;
                v6->y = v12;
                ++v5;
                
                v22 = (v3->z - v7->z) * v20;
                rdClip_faceStatus |= CLIPSTAT_LEFT;
                v6->z = v22 + v7->z;
                ++v6;
            }
            if ( v9 <= v3->x )
            {
                v23 = v6;
                ++v5;
                ++v6;
                v23->x = v3->x;
                v23->y = v3->y;
                v23->z = v3->z;
            }
        }
        v7 = v3++;
    }
    if ( v5 < 3 )
        return v5;

    v24 = v5;
    v5 = 0;
    v25 = vertices;
    v26 = workVerts;
    pDestVert = vertices;
    pSourceVert = workVerts;
    v27 = &workVerts[v24 - 1];
    v28 = workVerts;
    for (v117 = v24; v117 > 0; v117--)
    {
        numVerticesc = frustum->right * v27->y;
        v30 = frustum->right * v28->y;
        if ( numVerticesc >= v27->x || v30 >= v28->x )
        {
            if ( v27->x != numVerticesc && v30 != v28->x && (v27->x > numVerticesc || v30 < v28->x) )
            {
                frustumb = v28->y - v27->y;
                v113 = v28->x - v27->x;
                v34 = v28->y * v27->x - v27->y * v28->x;
                numVerticesj = frustum->right * frustumb - v113;
                if ( numVerticesj != 0.0 )
                {
                    v34 = v34 / numVerticesj;
                }
                numVerticesd = frustum->right * v34;
                v37 = frustumb;
                if ( v37 < 0.0 )
                    v37 = -v37;
                v40 = v113;
                if ( v40 < 0.0 )
                    v40 = -v40;
                if ( v37 <= v40 )
                    v42 = (numVerticesd - v27->x) / v113;
                else
                    v42 = (v34 - v27->y) / frustumb;
                v25->x = numVerticesd;
                v25->y = v34;
                ++v5;
                
                v44 = (v28->z - v27->z) * v42;
                rdClip_faceStatus |= CLIPSTAT_RIGHT;
                v25->z = v44 + v27->z;
                ++v25;
            }
            if ( v30 >= v28->x )
            {
                v45 = v25;
                ++v5;
                ++v25;
                v45->x = v28->x;
                v45->y = v28->y;
                v45->z = v28->z;
                v26 = pSourceVert;
            }
        }
        v27 = v28++;
    }
    if ( v5 < 3 )
        return v5;

    v46 = v5;
    v47 = v26;
    v5 = 0;
    v48 = pDestVert;
    pDestVert = v47;
    pSourceVert = v48;
    v49 = &v48[v46 - 1];
    v50 = v48;
    for (v118 = v46; v118 > 0; v118--)
    {
        numVerticese = frustum->nearTop * v49->y;
        v52 = v50->y * frustum->nearTop;
        if ( numVerticese >= v49->z || v52 >= v50->z )
        {
            if ( v49->z != numVerticese && v52 != v50->z && (v49->z > numVerticese || v52 < v50->z) )
            {
                frustumc = v50->y - v49->y;
                v114 = v50->z - v49->z;
                v56 = v50->y * v49->z - v50->z * v49->y;
                v57 = v56;
                numVerticesk = frustum->nearTop * frustumc - v114;
                if ( numVerticesk != 0.0 )
                {
                    v57 = v56 / numVerticesk;
                }
                v60 = frustum->nearTop * v57;

                if ( stdMath_Fabs(frustumc) <= stdMath_Fabs(v114) )
                    v66 = (v60 - v49->z) / v114;
                else
                    v66 = (v57 - v49->y) / frustumc;
                ++v5;
                
                v68 = (v50->x - v49->x) * v66 + v49->x;
                rdClip_faceStatus |= CLIPSTAT_TOP;
                v47->x = v68;
                v47->y = v57;
                v47->z = v60;
                ++v47;
            }
            if ( v52 >= v50->z )
            {
                v69 = v47;
                ++v5;
                ++v47;
                v69->x = v50->x;
                v69->y = v50->y;
                v69->z = v50->z;
            }
        }
        v49 = v50++;
    }
    if ( v5 < 3 )
        return v5;

    v70 = v5;
    v71 = pSourceVert;
    v5 = 0;
    v72 = pDestVert;
    pDestVert = v71;
    pSourceVert = v72;
    v73 = &v72[v70 - 1];
    v74 = v72;

    for (v119 = v70; v119 > 0; v119--)
    {
        numVerticesf = frustum->bottom * v73->y;
        v76 = v74->y * frustum->bottom;
        if ( numVerticesf <= v73->z || v76 <= v74->z )
        {
            if ( v73->z != numVerticesf && v76 != v74->z && (v73->z < numVerticesf || v76 > v74->z) )
            {
                frustumd = v74->y - v73->y;
                v115 = v74->z - v73->z;
                v79 = v74->y * v73->z - v74->z * v73->y;
                v80 = v79;
                numVerticesl = frustum->bottom * frustumd - v115;
                if ( numVerticesl != 0.0)
                {
                    v80 = v79 / numVerticesl;
                }
                v83 = frustum->bottom * v80;
                v84 = frustumd;
                if ( v84 < 0.0 )
                    v84 = -v84;
                v87 = v115;
                if ( v87 < 0.0 )
                    v87 = -v87;
                if ( v84 <= v87 )
                    v89 = (v83 - v73->z) / v115;
                else
                    v89 = (v80 - v73->y) / frustumd;
                ++v5;
                
                v91 = (v74->x - v73->x) * v89 + v73->x;
                rdClip_faceStatus |= CLIPSTAT_BOTTOM;
                v71->x = v91;
                v71->y = v80;
                v71->z = v83;
                ++v71;
            }
            if ( v76 <= v74->z )
            {
                v92 = v71;
                ++v5;
                ++v71;
                v92->x = v74->x;
                v92->y = v74->y;
                v92->z = v74->z;
            }
        }
        v73 = v74++;
    }
    if ( v5 < 3 )
        return v5;

    v93 = v5;
    v94 = pSourceVert;
    v5 = 0;
    v95 = pDestVert;
    pDestVert = v94;
    pSourceVert = v95;
    v96 = &v95[v93 - 1];
    v97 = v95;
    for (numVerticesg = v93; numVerticesg > 0; numVerticesg--)
    {
        if ( v96->y >= frustum->zNear || v97->y >= frustum->zNear )
        {
            if ( v96->y != frustum->zNear && v97->y != frustum->zNear && (v96->y < frustum->zNear || v97->y < frustum->zNear) )
            {
                ++v5;
                v98 = (frustum->zNear - v96->y) / (v97->y - v96->y);
                v94->y = frustum->zNear;
                rdClip_faceStatus |= CLIPSTAT_NEAR;
                v94->z = (v97->z - v96->z) * v98 + v96->z;
                v94->x = (v97->x - v96->x) * v98 + v96->x;
                ++v94;
            }
            if ( v97->y >= frustum->zNear )
            {
                v100 = v94;
                ++v5;
                ++v94;
                v100->x = v97->x;
                v100->y = v97->y;
                v95 = pSourceVert;
                v100->z = v97->z;
            }
        }
        v96 = v97++;
    }
    v101 = pDestVert;
    if ( v5 < 3 )
    {
        rdClip_faceStatus |= CLIPSTAT_NONE_VISIBLE;
        return v5;
    }
    if (frustum->bClipFar)
    {
        v104 = v5;
        v105 = v95;
        v5 = 0;
        v106 = pDestVert;
        pDestVert = v105;
        pSourceVert = v106;
        v107 = &v106[v104 - 1];
        v108 = v106;

        for (numVerticesh = v104; numVerticesh > 0; numVerticesh--)
        {
            if ( v107->y <= frustum->zFar || v108->y <= frustum->zFar )
            {
                if ( v107->y != frustum->zFar
                  && v108->y != frustum->zFar
                  && (v107->y > frustum->zFar || v108->y > frustum->zFar) )
                {
                    ++v5;
                    v109 = (frustum->zFar - v107->y) / (v108->y - v107->y);
                    v105->y = frustum->zFar;
                    rdClip_faceStatus |= CLIPSTAT_FAR;
                    v105->z = (v108->z - v107->z) * v109 + v107->z;
                    v105->x = (v108->x - v107->x) * v109 + v107->x;
                    ++v105;
                }
                if ( v108->y <= frustum->zFar )
                {
                    v111 = v105;
                    ++v5;
                    v111->x = v108->x;
                    v111->y = v108->y;
                    v111->z = v108->z;
                    ++v105;
                }
            }
            v107 = v108++;
        }
        if ( v5 < 3 )
            return v5;
        v101 = pDestVert;
    }

    if ( v101 != vertices ) {
        _memcpy(vertices, pDestVert, sizeof(rdVector3) * v5);
    }
    return v5;
}

int rdClip_Face3GS(rdClipFrustum *frustum, rdVector3 *vertices, flex_t *a3, int numVertices)
{
    INST_WORKBUFS

    //return _rdClip_Face3GS(frustum, vertices, a3, numVertices);
    rdVector3 *v4; // edx
    flex_t *v5; // edi
    flex_t *v6; // ebx
    rdVector3 *v7; // ecx
    flex_t *v8; // ebp
    rdVector3 *v9; // esi
    flex_d_t v11; // st7
    flex_d_t v14; // st6
    flex_d_t v17; // st5
    flex_d_t v18; // st4
    flex_d_t v21; // st3
    flex_d_t v23; // st4
    flex_d_t v24; // st3
    flex_d_t v25; // st5
    flex_d_t v26; // rtt
    flex_d_t v27; // st4
    flex_d_t v28; // st5
    rdVector3 *v30; // eax
    signed int result; // eax
    flex_t *copy_pDestIVert; // eax
    rdVector3 *copy_pDestVert; // ebx
    flex_t *copy_pSourceIVert; // esi
    rdVector3 *copy_pSourceVert; // edi
    int v37; // ecx
    flex_t *v38; // ebp
    rdVector3 *v39; // ecx
    rdVector3 *v40; // edx
    flex_t *v41; // edi
    flex_d_t v43; // st7
    flex_d_t v47; // st6
    flex_d_t v50; // st5
    flex_d_t v51; // st4
    flex_d_t v54; // st3
    flex_d_t v56; // st4
    flex_d_t v57; // st3
    flex_d_t v58; // st5
    flex_d_t v59; // rt2
    flex_d_t v60; // st4
    flex_d_t v61; // st5
    rdVector3 *v63; // eax
    int v64; // ecx
    int v65; // edi
    int v66; // esi
    rdVector3 *v67; // ebx
    flex_t *v68; // eax
    rdVector3 *v69; // edi
    flex_t *v70; // esi
    rdVector3 *v71; // edx
    flex_t *v72; // ebp
    flex_t *v73; // ecx
    flex_t *v74; // edi
    flex_d_t v76; // st7
    flex_d_t v80; // st5
    flex_d_t v81; // st6
    flex_d_t v84; // st5
    flex_d_t v85; // st4
    flex_d_t v88; // st3
    flex_d_t v90; // st4
    flex_d_t v91; // st3
    rdVector3 *v93; // eax
    rdVector3 *v94; // ebx
    flex_t *v95; // esi
    rdVector3 *v96; // edx
    flex_t *v97; // edi
    rdVector3 *v98; // ecx
    flex_t *v99; // ebp
    flex_t *v100; // edx
    flex_d_t v102; // st7
    flex_d_t v105; // st5
    flex_d_t v106; // st6
    flex_d_t v109; // st5
    flex_d_t v110; // st4
    flex_d_t v113; // st3
    flex_d_t v115; // st4
    flex_d_t v116; // st3
    rdVector3 *v118; // eax
    flex_t *v119; // esi
    flex_t *v120; // edi
    rdVector3 *v121; // ebx
    rdVector3 *v122; // edx
    int v123; // eax
    int v124; // ebp
    rdVector3 *v125; // ecx
    flex_t *v126; // edx
    flex_d_t v127; // st7
    flex_d_t v128; // st6
    flex_d_t v129; // st5
    flex_d_t v130; // st6
    rdVector3 *v132; // ecx
    int v135; // edi
    flex_t* v136; // esi
    int v137; // edx
    flex_t *v138; // edi
    int v139; // ecx
    rdVector3 *v140; // ebx
    rdVector3 *v141; // edx
    int v142; // eax
    rdVector3 *v143; // ecx
    flex_t *v144; // edx
    flex_d_t v145; // st7
    flex_d_t v146; // st6
    flex_d_t v147; // st5
    flex_d_t v148; // st6
    rdVector3 *v150; // eax
    int v151; // [esp+10h] [ebp-10h]
    int v152; // [esp+10h] [ebp-10h]
    int v153; // [esp+10h] [ebp-10h]
    int v154; // [esp+10h] [ebp-10h]
    flex_t *v155; // [esp+10h] [ebp-10h]
    flex_t *v156; // [esp+10h] [ebp-10h]
    flex_d_t v157; // [esp+14h] [ebp-Ch]
    flex_d_t v158; // [esp+14h] [ebp-Ch]
    flex_d_t v159; // [esp+14h] [ebp-Ch]
    flex_d_t v160; // [esp+14h] [ebp-Ch]
    flex_d_t v161; // [esp+18h] [ebp-8h]
    flex_d_t v162; // [esp+18h] [ebp-8h]
    flex_d_t v163; // [esp+18h] [ebp-8h]
    flex_d_t v164; // [esp+18h] [ebp-8h]
    flex_t *v165; // [esp+18h] [ebp-8h]
    flex_t *v166; // [esp+18h] [ebp-8h]
    int v167; // [esp+1Ch] [ebp-4h]
    int v168; // [esp+1Ch] [ebp-4h]
    int v169; // [esp+1Ch] [ebp-4h]
    signed int v170; // [esp+1Ch] [ebp-4h]
    flex_d_t numVerticesa; // [esp+30h] [ebp+10h]
    flex_d_t numVerticesi; // [esp+30h] [ebp+10h]
    int numVerticesb; // [esp+30h] [ebp+10h]
    flex_d_t numVerticesc; // [esp+30h] [ebp+10h]
    flex_d_t numVerticesj; // [esp+30h] [ebp+10h]
    int numVerticesd; // [esp+30h] [ebp+10h]
    flex_d_t numVerticese; // [esp+30h] [ebp+10h]
    flex_d_t numVerticesk; // [esp+30h] [ebp+10h]
    flex_d_t numVerticesf; // [esp+30h] [ebp+10h]
    flex_d_t numVerticesl; // [esp+30h] [ebp+10h]
    int numVerticesg; // [esp+30h] [ebp+10h]
    int numVerticesh; // [esp+30h] [ebp+10h]

    v4 = vertices;
    v5 = a3;
    v6 = workIVerts;
    rdClip_faceStatus = 0;
    pSourceVert = vertices;
    pSourceIVert = a3;
    pDestVert = workVerts;
    pDestIVert = workIVerts;
    v151 = 0;
    v7 = &vertices[numVertices - 1];
    v8 = &a3[numVertices - 1];
    if ( numVertices > 0 )
    {
        v9 = workVerts;
        v167 = numVertices;
        do
        {
            numVerticesa = v7->y * frustum->nearLeft;
            v11 = frustum->nearLeft * v4->y;
            if ( numVerticesa <= v7->x || v11 <= v4->x )
            {
                if ( v7->x != numVerticesa && v11 != v4->x && (v7->x < (flex_d_t)numVerticesa || v11 > v4->x) )
                {
                    v157 = v4->y - v7->y;
                    v161 = v4->x - v7->x;
                    v14 = v4->y * v7->x - v7->y * v4->x;
                    numVerticesi = frustum->nearLeft * v157 - v161;
                    if ( numVerticesi != 0.0 )
                    {
                        v14 = v14 / numVerticesi;
                    }
                    v17 = frustum->nearLeft * v14;
                    v18 = v157;
                    if ( v18 < 0.0 )
                        v18 = -v18;
                    v21 = v161;
                    if ( v21 < 0.0 )
                        v21 = -v21;
                    if ( v18 <= v21 )
                        v23 = (v17 - v7->x) / v161;
                    else
                        v23 = (v14 - v7->y) / v157;
                    v24 = v17;
                    v25 = *v5;
                    v9->x = v24;
                    v26 = v23;
                    v9->y = v14;
                    v27 = (v25 - *v8) * v23 + *v8;
                    v28 = (v4->z - v7->z) * v26 + v7->z;
                    ++v9;
                    *v6++ = v27;
                    v9[-1].z = v28;
                    ++v151;
                    rdClip_faceStatus |= CLIPSTAT_LEFT;
                }
                if ( v11 <= v4->x )
                {
                    v30 = v9++;
                    v30->x = v4->x;
                    v30->y = v4->y;
                    v30->z = v4->z;
                    *v6 = *v5;
                    ++v151;
                    ++v6;
                }
            }
            v7 = v4;
            v8 = v5;
            ++v4;
            ++v5;
            --v167;
        }
        while ( v167 );
    }
    result = v151;
    if ( v151 >= 3 )
    {
        copy_pDestIVert = a3;
        copy_pDestVert = vertices;
        copy_pSourceIVert = workIVerts;
        copy_pSourceVert = workVerts;
        numVerticesb = v151;
        v37 = v151;
        v38 = &workIVerts[v151 - 1];
        pDestVert = vertices;
        pSourceVert = workVerts;
        pDestIVert = a3;
        pSourceIVert = workIVerts;
        v152 = 0;
        v39 = &workVerts[v37 - 1];
        v40 = workVerts;
        if ( v151 > 0 )
        {
            v41 = a3;
            v168 = numVerticesb;
            do
            {
                numVerticesc = frustum->right * v39->y;
                v43 = frustum->right * v40->y;
                if ( numVerticesc >= v39->x || v43 >= v40->x )
                {
                    if ( v39->x != numVerticesc && v43 != v40->x && (v39->x > (flex_d_t)numVerticesc || v43 < v40->x) )
                    {
                        v162 = v40->y - v39->y;
                        v158 = v40->x - v39->x;
                        v47 = v40->y * v39->x - v39->y * v40->x;
                        numVerticesj = frustum->right * v162 - v158;
                        if ( numVerticesj != 0.0 )
                        {
                            v47 = v47 / numVerticesj;
                        }
                        v50 = frustum->right * v47;
                        v51 = v162;
                        if ( v51 < 0.0 )
                            v51 = -v51;
                        v54 = v158;
                        if ( v54 < 0.0 )
                            v54 = -v54;
                        if ( v51 <= v54 )
                            v56 = (v50 - v39->x) / v158;
                        else
                            v56 = (v47 - v39->y) / v162;
                        v57 = v50;
                        v58 = *copy_pSourceIVert;
                        copy_pDestVert->x = v57;
                        v59 = v56;
                        copy_pDestVert->y = v47;
                        v60 = (v58 - *v38) * v56 + *v38;
                        v61 = (v40->z - v39->z) * v59 + v39->z;
                        ++copy_pDestVert;
                        *v41++ = v60;
                        copy_pDestVert[-1].z = v61;
                        ++v152;
                        rdClip_faceStatus |= CLIPSTAT_RIGHT;
                    }
                    if ( v43 >= v40->x )
                    {
                        v63 = copy_pDestVert++;
                        v63->x = v40->x;
                        v63->y = v40->y;
                        v63->z = v40->z;
                        *v41 = *copy_pSourceIVert;
                        ++v152;
                        ++v41;
                    }
                }
                v39 = v40;
                v38 = copy_pSourceIVert;
                ++v40;
                ++copy_pSourceIVert;
                --v168;
            }
            while ( v168 );
            copy_pSourceIVert = pSourceIVert;
            copy_pDestVert = pDestVert;
            copy_pSourceVert = pSourceVert;
            copy_pDestIVert = pDestIVert;
        }
        v64 = v152;
        if ( v152 < 3 )
            return v152;
        v65 = (intptr_t)copy_pDestVert ^ (intptr_t)copy_pSourceVert;
        v66 = (intptr_t)copy_pDestIVert ^ (intptr_t)copy_pSourceIVert;
        v67 = (rdVector3 *)(v65 ^ (intptr_t)copy_pDestVert);
        v68 = (flex_t *)(v66 ^ (intptr_t)copy_pDestIVert);
        v69 = (rdVector3 *)((intptr_t)v67 ^ v65);
        v70 = (flex_t *)((intptr_t)v68 ^ v66);
        pDestVert = v67;
        pSourceVert = v69;
        pDestIVert = v68;
        pSourceIVert = v70;
        numVerticesd = v152;
        v153 = 0;
        v71 = &v69[v64 - 1];
        v72 = &v70[v64 - 1];
        if ( v64 > 0 )
        {
            v73 = &v69->z;
            v74 = v68;
            v169 = numVerticesd;
            do
            {
                numVerticese = frustum->nearTop * v71->y;
                v76 = *(v73 - 1) * frustum->nearTop;
                if ( numVerticese >= v71->z || v76 >= *v73 )
                {
                    if ( v71->z != numVerticese && v76 != *v73 && (v71->z > (flex_d_t)numVerticese || v76 < *v73) )
                    {
                        v163 = *(v73 - 1) - v71->y;
                        v159 = *v73 - v71->z;
                        v80 = *(v73 - 1) * v71->z - *v73 * v71->y;
                        v81 = v80;
                        numVerticesk = frustum->nearTop * v163 - v159;
                        if ( numVerticesk != 0.0 )
                        {
                            v81 = v80 / numVerticesk;
                        }
                        v84 = frustum->nearTop * v81;
                        v85 = v163;
                        if ( v85 < 0.0 )
                            v85 = -v85;
                        v88 = v159;
                        if ( v88 < 0.0 )
                            v88 = -v88;
                        if ( v85 <= v88 )
                            v90 = (v84 - v71->z) / v159;
                        else
                            v90 = (v81 - v71->y) / v163;
                        v91 = (*v70 - *v72) * v90 + *v72;
                        v67->x = (*(v73 - 2) - v71->x) * v90 + v71->x;
                        ++v67;
                        v67[-1].y = v81;
                        v67[-1].z = v84;
                        *v74++ = v91;
                        ++v153;
                        rdClip_faceStatus |= CLIPSTAT_TOP;
                    }
                    if ( v76 >= *v73 )
                    {
                        v93 = v67++;
                        v93->x = *(v73 - 2);
                        v93->y = *(v73 - 1);
                        v93->z = *v73;
                        *v74 = *v70;
                        ++v153;
                        ++v74;
                    }
                }
                v71 = (rdVector3 *)(v73 - 2);
                v72 = v70;
                v73 += 3;
                ++v70;
                --v169;
            }
            while ( v169 );
        }
        result = v153;
        if ( v153 >= 3 )
        {
            v94 = pSourceVert;
            v95 = pSourceIVert;
            v96 = pDestVert;
            v97 = pDestIVert;
            pDestVert = pSourceVert;
            pSourceVert = v96;
            pDestIVert = pSourceIVert;
            pSourceIVert = v97;
            v154 = 0;
            v98 = &v96[result - 1];
            v99 = &v97[result - 1];
            if ( result > 0 )
            {
                v100 = &v96->z;
                v170 = result;
                do
                {
                    numVerticesf = frustum->bottom * v98->y;
                    v102 = *(v100 - 1) * frustum->bottom;
                    if ( numVerticesf <= v98->z || v102 <= *v100 )
                    {
                        if ( v98->z != numVerticesf && v102 != *v100 && (v98->z < (flex_d_t)numVerticesf || v102 > *v100) )
                        {
                            v164 = *(v100 - 1) - v98->y;
                            v160 = *v100 - v98->z;
                            v105 = *(v100 - 1) * v98->z - *v100 * v98->y;
                            v106 = v105;
                            numVerticesl = frustum->bottom * v164 - v160;
                            if ( numVerticesl != 0.0 )
                            {
                                v106 = v105 / numVerticesl;
                            }
                            v109 = frustum->bottom * v106;
                            v110 = v164;
                            if ( v110 < 0.0 )
                                v110 = -v110;
                            v113 = v160;
                            if ( v113 < 0.0 )
                                v113 = -v113;
                            if ( v110 <= v113 )
                                v115 = (v109 - v98->z) / v160;
                            else
                                v115 = (v106 - v98->y) / v164;
                            v116 = (*v97 - *v99) * v115 + *v99;
                            v94->x = (*(v100 - 2) - v98->x) * v115 + v98->x;
                            ++v94;
                            v94[-1].y = v106;
                            v94[-1].z = v109;
                            *v95++ = v116;
                            ++v154;
                            rdClip_faceStatus |= CLIPSTAT_BOTTOM;
                        }
                        if ( v102 <= *v100 )
                        {
                            v118 = v94++;
                            v118->x = *(v100 - 2);
                            v118->y = *(v100 - 1);
                            v118->z = *v100;
                            *v95 = *v97;
                            ++v154;
                            ++v95;
                        }
                    }
                    v98 = (rdVector3 *)(v100 - 2);
                    v99 = v97;
                    v100 += 3;
                    ++v97;
                    --v170;
                }
                while ( v170 );
            }
            result = v154;
            if ( v154 >= 3 )
            {
                v119 = pSourceIVert;
                v120 = pDestIVert;
                v121 = pSourceVert;
                v122 = pDestVert;
                v165 = &pDestIVert[v154 - 1];
                v123 = v154;
                v124 = 0;
                pDestVert = pSourceVert;
                pSourceVert = v122;
                pDestIVert = pSourceIVert;
                pSourceIVert = v120;
                v125 = &v122[v154 - 1];
                v155 = v120;
                if ( v154 > 0 )
                {
                    v126 = &v122->y;
                    numVerticesg = v123;
                    do
                    {
                        if ( v125->y >= (flex_d_t)frustum->zNear || *v126 >= (flex_d_t)frustum->zNear )
                        {
                            if ( v125->y != frustum->zNear
                              && *v126 != frustum->zNear
                              && (v125->y < (flex_d_t)frustum->zNear || *v126 < (flex_d_t)frustum->zNear) )
                            {
                                ++v124;
                                ++v119;
                                v127 = (frustum->zNear - v125->y) / (*v126 - v125->y);
                                v121->y = frustum->zNear;
                                ++v121;
                                v128 = (*v120 - *v165) * v127;
                                v121[-1].z = (v126[1] - v125->z) * v127 + v125->z;
                                v129 = v128 + *v165;
                                v130 = (*(v126 - 1) - v125->x) * v127 + v125->x;
                                *(v119 - 1) = v129;
                                v121[-1].x = v130;
                                rdClip_faceStatus |= CLIPSTAT_NEAR;
                            }
                            if ( *v126 >= (flex_d_t)frustum->zNear )
                            {
                                v132 = v121;
                                ++v124;
                                ++v121;
                                ++v119;
                                v132->x = *(v126 - 1);
                                v132->y = *v126;
                                v120 = v155;
                                v132->z = v126[1];
                                *(v119 - 1) = *v155;
                            }
                        }
                        v125 = (rdVector3 *)(v126 - 1);
                        v165 = v120;
                        v126 += 3;
                        ++v120;
                        v155 = v120;
                        --numVerticesg;
                    }
                    while (numVerticesg != 0);
                    v122 = pSourceVert;
                    v120 = pSourceIVert;
                    v121 = pDestVert;
                    v119 = pDestIVert;
                }
                if ( v124 < 3 )
                {
                    rdClip_faceStatus |= CLIPSTAT_NONE_VISIBLE;
                    return v124;
                }
                if (frustum->bClipFar)
                {
                    v135 = (intptr_t)v119 ^ (intptr_t)v120;
                    v136 = (flex_t*)(v135 ^ (intptr_t)v119);
                    v137 = (intptr_t)v121 ^ (intptr_t)v122;
                    v138 = (flex_t *)((intptr_t)v136 ^ v135);
                    v139 = v124;
                    v140 = (rdVector3 *)(v137 ^ (intptr_t)v121);
                    v141 = (rdVector3 *)((intptr_t)v140 ^ v137);
                    v166 = &v138[v124 - 1];
                    v142 = v124;
                    v124 = 0;
                    pDestVert = v140;
                    pSourceVert = v141;
                    pDestIVert = v136;
                    pSourceIVert = v138;
                    v143 = &v141[v139 - 1];
                    v156 = v138;
                    v144 = &v141->y;
                    numVerticesh = v142;
                    do
                    {
                        if ( v143->y <= (flex_d_t)frustum->zFar || *v144 <= (flex_d_t)frustum->zFar )
                        {
                            if ( v143->y != frustum->zFar
                              && *v144 != frustum->zFar
                              && (v143->y > (flex_d_t)frustum->zFar || *v144 > (flex_d_t)frustum->zFar) )
                            {
                                ++v124;
                                v145 = (frustum->zFar - v143->y) / (*v144 - v143->y);
                                v140->y = frustum->zFar;
                                ++v140;
                                v146 = (*v156 - *v166) * v145;
                                v140[-1].z = (v144[1] - v143->z) * v145 + v143->z;
                                v147 = v146 + *v166;
                                v148 = (*(v144 - 1) - v143->x) * v145 + v143->x;
                                *v136 = v147;
                                v136++;
                                v140[-1].x = v148;
                                rdClip_faceStatus |= 2;
                            }
                            if ( *v144 <= (flex_d_t)frustum->zFar )
                            {
                                v150 = v140;
                                ++v124;
                                ++v140;
                                v150->x = *(v144 - 1);
                                v150->y = *v144;
                                v150->z = v144[1];
                                *v136 = *v156;
                                v136++;
                            }
                        }
                        v143 = (rdVector3 *)(v144 - 1);
                        v166 = v156++;
                        v144 += 3;
                        --numVerticesh;
                    }
                    while ( numVerticesh );
                    if ( v124 < 3 )
                        return v124;
                    v121 = pDestVert;
                }
                if ( v121 != vertices )
                {
                    _memcpy(vertices, v121, v124 * sizeof(rdVector3));
                    _memcpy(a3, pDestIVert, sizeof(flex_t) * v124);
                }
                return v124;
            }
        }
    }
    return result;
}

// TVertices as in Texture Vertices, or UVs
int rdClip_Face3T(const rdClipFrustum* NO_ALIAS pClipFrustum, rdVector3* NO_ALIAS pVertices, rdVector2* NO_ALIAS pTVertices, int numVertices)
{
    INST_WORKBUFS

    //return _rdClip_Face3GT(pClipFrustum, pVertices, pTVertices, pIVertices, numVertices);
    rdVector2* NO_ALIAS pTVertIter; // esi
    rdVector3* NO_ALIAS pVertIter; // edi
    rdVector3* NO_ALIAS pLastVertIter; // ebx
    rdVector2* NO_ALIAS pLastTVertIter; // edx
    rdVector2* NO_ALIAS pWorkTVertIter; // ebp
    rdVector3* NO_ALIAS pWorkVertIter; // ecx
    flex_d_t v16; // st6
    flex_d_t v19; // st5
    flex_d_t v20; // st4
    flex_d_t v23; // st3
    flex_d_t v25; // st4
    flex_d_t v33; // st3
    flex_d_t v50; // st6
    flex_d_t v53; // st5
    flex_d_t v54; // st4
    flex_d_t v57; // st3
    flex_d_t v59; // st4
    rdVector3* NO_ALIAS pLastDestVert; // eax
    flex_d_t v88; // st6
    flex_d_t v92; // st6
    flex_d_t v93; // st5
    flex_d_t v96; // st4
    flex_d_t v98; // st5
    flex_d_t v99; // st4
    rdVector3* NO_ALIAS pLastSourceVert; // eax
    flex_d_t v122; // st6
    flex_d_t v123; // st7
    flex_d_t v126; // st6
    flex_d_t v127; // st5
    flex_d_t v130; // st4
    flex_d_t v132; // st5
    flex_t* NO_ALIAS v143;
    flex_d_t v150; // st7
    flex_d_t v157; // st6
    flex_d_t v174; // st7
    int numOnScreenVertices; // [esp+10h] [ebp-20h]
    flex_t v202; // [esp+1Ch] [ebp-14h]
    flex_t v203; // [esp+1Ch] [ebp-14h]
    flex_t v205; // [esp+1Ch] [ebp-14h]
    flex_t v207; // [esp+1Ch] [ebp-14h]
    flex_t v208; // [esp+20h] [ebp-10h]
    flex_t v209; // [esp+20h] [ebp-10h]
    flex_t v210; // [esp+20h] [ebp-10h]
    flex_t v211; // [esp+20h] [ebp-10h]
    flex_t v214; // [esp+24h] [ebp-Ch]
    flex_t v215; // [esp+24h] [ebp-Ch]
    flex_t numVerticese; // [esp+44h] [ebp+14h]
    rdVector2* NO_ALIAS pLastSourceTVert;
    rdVector2* NO_ALIAS pLastDestTVert;

    rdClip_faceStatus = 0;
    numOnScreenVertices = 0;

    pSourceVert = pVertices;
    pDestVert = workVerts;
    pSourceTVert = pTVertices;
    pDestTVert = workTVerts;

    INST_ARG_COPIES_T

    pWorkVertIter = workVerts;
    pWorkTVertIter = workTVerts;

    pVertIter = pSourceVert;
    pTVertIter = pSourceTVert;
    pLastVertIter = &pSourceVert[numVertices - 1];
    pLastTVertIter = &pSourceTVert[numVertices - 1];

#ifdef EXPERIMENTAL_FIXED_POINT
    const int premultiplyA = 16;
    const int premultiplyASquared = premultiplyA*premultiplyA;
#else
    const flex_t premultiplyA = 1.0;
    const flex_t premultiplyASquared = 1.0;
#endif

#ifdef RDCLIP_CLIP_ZFAR_FIRST
    if (pClipFrustum->bClipFar)
    {
        for (int i = 0; i < numVertices; pLastVertIter = pVertIter++, pLastTVertIter = pTVertIter++, i++)
        {
            if (!(pLastVertIter->y <= (flex_d_t)pClipFrustum->zFar || pVertIter->y <= (flex_d_t)pClipFrustum->zFar)) {
                continue;
            }

            if ( pLastVertIter->y != pClipFrustum->zFar
              && pVertIter->y != pClipFrustum->zFar
              && (pLastVertIter->y > (flex_d_t)pClipFrustum->zFar || pVertIter->y > (flex_d_t)pClipFrustum->zFar) )
            {
                
                v174 = (pClipFrustum->zFar - pLastVertIter->y) / (pVertIter->y - pLastVertIter->y);
                pWorkVertIter->x = (pVertIter->x - pLastVertIter->x) * v174 + pLastVertIter->x;
                pWorkVertIter->y = pClipFrustum->zFar;
                pWorkVertIter->z = (pVertIter->z - pLastVertIter->z) * v174 + pLastVertIter->z;

                pWorkTVertIter->x = (pTVertIter->x - pLastTVertIter->x) * v174 + pLastTVertIter->x;
                pWorkTVertIter->y = (pTVertIter->y - pLastTVertIter->y) * v174 + pLastTVertIter->y;
                
                ++pWorkVertIter;
                ++pWorkTVertIter;
                ++numOnScreenVertices;
                rdClip_faceStatus |= CLIPSTAT_FAR;
            }
            if ( pVertIter->y <= (flex_d_t)pClipFrustum->zFar )
            {
                *pWorkVertIter = *pVertIter;
                pWorkTVertIter->x = pTVertIter->x;
                pWorkTVertIter->y = pTVertIter->y;
                ++pWorkVertIter;
                ++pWorkTVertIter;
                ++numOnScreenVertices;
            }
        }
        if ( numOnScreenVertices < 3 ) {
            return numOnScreenVertices;
        }

        numVertices = numOnScreenVertices;
        pLastSourceVert = pSourceVert;
        pLastDestVert = pDestVert;
        pLastSourceTVert = pSourceTVert;
        pLastDestTVert = pDestTVert;
        
        pSourceVert = pLastDestVert;
        pDestVert = pLastSourceVert;
        pSourceTVert = pLastDestTVert;
        pDestTVert = pLastSourceTVert;
        
        pWorkVertIter = pLastSourceVert;
        pWorkTVertIter = pLastSourceTVert;
        
        pVertIter = pLastDestVert;
        pTVertIter = pLastDestTVert;
        pLastVertIter = &pLastDestVert[numVertices - 1];
        pLastTVertIter = &pTVertIter[numVertices - 1];

        numOnScreenVertices = 0;
    }
#endif
    for (int i = 0; i < numVertices; pLastVertIter = pVertIter++, pLastTVertIter = pTVertIter++, i++)
    {
        flex_t nearLeftPlaneA = pClipFrustum->nearLeft * pLastVertIter->y;
        flex_t nearLeftPlaneB = pClipFrustum->nearLeft * pVertIter->y;
        if (!(nearLeftPlaneA <= pLastVertIter->x || nearLeftPlaneB <= pVertIter->x)) {
            continue;
        }

        if ( pLastVertIter->x != nearLeftPlaneA && nearLeftPlaneB != pVertIter->x && (pLastVertIter->x < nearLeftPlaneA || nearLeftPlaneB > pVertIter->x) )
        {
            flex_t dy = pVertIter->y - pLastVertIter->y;
            v208 = pVertIter->x - pLastVertIter->x;
            v16 = pVertIter->y * pLastVertIter->x - pLastVertIter->y * pVertIter->x;
            v202 = pClipFrustum->nearLeft * dy - v208;
            if (v202 != 0.0)
            {
                v16 = v16 / v202;
            }
            v19 = pClipFrustum->nearLeft * v16;
            v20 = stdMath_Fabs(dy);
            v23 = stdMath_Fabs(v208);
            if ( v20 <= v23 )
                v25 = (v19 - pLastVertIter->x) / v208;
            else
                v25 = (v16 - pLastVertIter->y) / dy;
            
            pWorkVertIter->x = v19;
            pWorkVertIter->y = v16;
            pWorkVertIter->z = (pVertIter->z - pLastVertIter->z) * v25 + pLastVertIter->z;
            pWorkTVertIter->x = ((pTVertIter->x - pLastTVertIter->x) * v25) + pLastTVertIter->x;
            pWorkTVertIter->y = (pTVertIter->y - pLastTVertIter->y) * v25 + pLastTVertIter->y;
            ++numOnScreenVertices;
            ++pWorkTVertIter;
            ++pWorkVertIter;
            rdClip_faceStatus |= CLIPSTAT_LEFT;
        }
        if ( nearLeftPlaneB <= pVertIter->x )
        {
            *pWorkVertIter = *pVertIter;
            pWorkTVertIter->x = pTVertIter->x;
            pWorkTVertIter->y = pTVertIter->y;
            ++numOnScreenVertices;
            ++pWorkTVertIter;
            ++pWorkVertIter;
        }
    }
    if ( numOnScreenVertices < 3 )
        return numOnScreenVertices;

    numVertices = numOnScreenVertices;
    pLastSourceVert = pSourceVert;
    pLastDestVert = pDestVert;
    pLastSourceTVert = pSourceTVert;
    pLastDestTVert = pDestTVert;
    
    pSourceVert = pLastDestVert;
    pDestVert = pLastSourceVert;
    pSourceTVert = pLastDestTVert;
    pDestTVert = pLastSourceTVert;
    
    pWorkVertIter = pLastSourceVert;
    pWorkTVertIter = pLastSourceTVert;
    
    pVertIter = pLastDestVert;
    pTVertIter = pLastDestTVert;
    pLastVertIter = &pLastDestVert[numVertices - 1];
    pLastTVertIter = &pTVertIter[numVertices - 1];

    numOnScreenVertices = 0;
    for (int i = 0; i < numVertices; pLastVertIter = pVertIter++, pLastTVertIter = pTVertIter++, i++)
    {
        flex_t rightPlaneA = pClipFrustum->right * pLastVertIter->y;
        flex_t rightPlaneB = pClipFrustum->right * pVertIter->y;
        if (!(rightPlaneA >= pLastVertIter->x || rightPlaneB >= pVertIter->x)) {
            continue;
        }

        if ( pLastVertIter->x != rightPlaneA && rightPlaneB != pVertIter->x && (pLastVertIter->x > (flex_d_t)rightPlaneA || rightPlaneB < pVertIter->x) )
        {
            numVerticese = pVertIter->y - pLastVertIter->y;
            v209 = pVertIter->x - pLastVertIter->x;
            v50 = pVertIter->y * pLastVertIter->x - pLastVertIter->y * pVertIter->x;
            v203 = pClipFrustum->right * numVerticese - v209;
            if (v203 != 0.0)
            {
                v50 = v50 / v203;
            }
            v53 = pClipFrustum->right * v50;
            v54 = stdMath_Fabs(numVerticese);
            v57 = stdMath_Fabs(v209);
            if ( v54 <= v57 )
                v59 = (v53 - pLastVertIter->x) / v209;
            else
                v59 = (v50 - pLastVertIter->y) / numVerticese;
            
            pWorkVertIter->x = v53;
            pWorkVertIter->y = v50;
            pWorkVertIter->z = ((pVertIter->z - pLastVertIter->z) * v59) + pLastVertIter->z;
            pWorkTVertIter->x = ((pTVertIter->x - pLastTVertIter->x) * v59) + pLastTVertIter->x;
            pWorkTVertIter->y = ((pTVertIter->y - pLastTVertIter->y) * v59) + pLastTVertIter->y;
            ++numOnScreenVertices;
            ++pWorkTVertIter;
            ++pWorkVertIter;
            rdClip_faceStatus |= CLIPSTAT_RIGHT;
        }
        if ( rightPlaneB >= pVertIter->x )
        {
            pWorkVertIter->x = pVertIter->x;
            pWorkVertIter->y = pVertIter->y;
            pWorkVertIter->z = pVertIter->z;
            pWorkTVertIter->x = pTVertIter->x;
            pWorkTVertIter->y = pTVertIter->y;
            ++numOnScreenVertices;
            ++pWorkTVertIter;
            ++pWorkVertIter;
        }
    }
    
    if ( numOnScreenVertices < 3 ) {
        return numOnScreenVertices;
    }
    
    numVertices = numOnScreenVertices;
    pLastSourceVert = pSourceVert;
    pLastDestVert = pDestVert;
    pLastSourceTVert = pSourceTVert;
    pLastDestTVert = pDestTVert;
    
    pSourceVert = pLastDestVert;
    pDestVert = pLastSourceVert;
    pSourceTVert = pLastDestTVert;
    pDestTVert = pLastSourceTVert;
    
    pWorkVertIter = pLastSourceVert;
    pWorkTVertIter = pLastSourceTVert;
    
    pVertIter = pLastDestVert;
    pTVertIter = pLastDestTVert;
    pLastVertIter = &pLastDestVert[numVertices - 1];
    pLastTVertIter = &pTVertIter[numVertices - 1];

    numOnScreenVertices = 0;
    for (int i = 0; i < numVertices; pLastVertIter = pVertIter++, pLastTVertIter = pTVertIter++, i++)
    {
        flex_t topPlaneA = pClipFrustum->nearTop * pLastVertIter->y;
        flex_t topPlaneB = pClipFrustum->nearTop * pVertIter->y;
        if (!(pLastVertIter->z <= topPlaneA || pVertIter->z <= (flex_d_t)topPlaneB)) {
            continue;
        }

        if ( pLastVertIter->z != topPlaneA && pVertIter->z != topPlaneB && (pLastVertIter->z > (flex_d_t)topPlaneA || pVertIter->z > (flex_d_t)topPlaneB) )
        {
            v210 = pVertIter->y - pLastVertIter->y;
            v214 = pVertIter->z - pLastVertIter->z;
            v88 = pVertIter->y * pLastVertIter->z - pVertIter->z * pLastVertIter->y;
            v205 = pClipFrustum->nearTop * v210 - v214;
            if (v205 != 0.0)
            {
                v88 = v88 / v205;
            }
            v92 = pClipFrustum->nearTop * v88;
            v93 = stdMath_Fabs(v210);
            v96 = stdMath_Fabs(v214);
            if ( v93 <= v96 )
                v98 = (v92 - pLastVertIter->z) / v214;
            else
                v98 = (v88 - pLastVertIter->y) / v210;
            v99 = pVertIter->x - pLastVertIter->x;
            
            pWorkVertIter->x = (v99 * v98) + pLastVertIter->x;
            pWorkVertIter->y = v88;
            pWorkVertIter->z = v92;
            pWorkTVertIter->x = ((pTVertIter->x - pLastTVertIter->x) * v98) + pLastTVertIter->x;
            pWorkTVertIter->y = ((pTVertIter->y - pLastTVertIter->y) * v98) + pLastTVertIter->y;
            ++numOnScreenVertices;
            ++pWorkTVertIter;
            ++pWorkVertIter;
            rdClip_faceStatus |= CLIPSTAT_TOP;
        }
        if ( pVertIter->z <= (flex_d_t)topPlaneB )
        {
            pWorkVertIter->x = pVertIter->x;
            pWorkVertIter->y = pVertIter->y;
            pWorkVertIter->z = pVertIter->z;
            pWorkTVertIter->x = pTVertIter->x;
            pWorkTVertIter->y = pTVertIter->y;
            ++numOnScreenVertices;
            ++pWorkTVertIter;
            ++pWorkVertIter;
        }
    }
    if ( numOnScreenVertices < 3 ) {
        return numOnScreenVertices;
    }

    numVertices = numOnScreenVertices;
    pLastSourceVert = pSourceVert;
    pLastDestVert = pDestVert;
    pLastSourceTVert = pSourceTVert;
    pLastDestTVert = pDestTVert;
    
    pSourceVert = pLastDestVert;
    pDestVert = pLastSourceVert;
    pSourceTVert = pLastDestTVert;
    pDestTVert = pLastSourceTVert;
    
    pWorkVertIter = pLastSourceVert;
    pWorkTVertIter = pLastSourceTVert;
    
    pVertIter = pLastDestVert;
    pTVertIter = pLastDestTVert;
    pLastVertIter = &pLastDestVert[numVertices - 1];
    pLastTVertIter = &pTVertIter[numVertices - 1];

    numOnScreenVertices = 0;
    for (int i = 0; i < numVertices; pLastVertIter = pVertIter++, pLastTVertIter = pTVertIter++, i++)
    {
        flex_t bottomPlaneA = pClipFrustum->bottom * pLastVertIter->y;
        flex_t bottomPlaneB = pClipFrustum->bottom * pVertIter->y;
        if (!(pLastVertIter->z >= bottomPlaneA || pVertIter->z >= (flex_d_t)bottomPlaneB)) {
            continue;
        }

        if ( pLastVertIter->z != bottomPlaneA && pVertIter->z != bottomPlaneB && (pLastVertIter->z < (flex_d_t)bottomPlaneA || pVertIter->z < (flex_d_t)bottomPlaneB) )
        {
            v215 = pVertIter->y - pLastVertIter->y;
            v211 = pVertIter->z - pLastVertIter->z;

            v122 = (((pVertIter->y * premultiplyA) * (pLastVertIter->z * premultiplyA)) - ((pVertIter->z * premultiplyA) * (pLastVertIter->y * premultiplyA)));
            v207 = ((pClipFrustum->bottom * premultiplyA) * (v215 * premultiplyA) - (v211 * premultiplyASquared));
            if (v207 != 0.0)
            {
                v123 = v122 / v207;
            }
            else {
                v123 = v122 / premultiplyASquared;
            }
            v126 = (pClipFrustum->bottom * premultiplyA) * (v123 * premultiplyA);
            v127 = stdMath_Fabs(v215);
            v130 = stdMath_Fabs(v211);
            if ( v127 <= v130 ) {
                v132 = ((v126 - (pLastVertIter->z * premultiplyASquared))) / (v211 * premultiplyASquared);
            }
            else {
                v132 = ((v123 - pLastVertIter->y) * premultiplyASquared) / (v215 * premultiplyASquared);
            }
            pWorkVertIter->x = ((pVertIter->x - pLastVertIter->x) * v132) + pLastVertIter->x;
            pWorkVertIter->y = v123;
            pWorkVertIter->z = v126 / premultiplyASquared;
            
            pWorkTVertIter->x = (pTVertIter->x - pLastTVertIter->x) * v132 + pLastTVertIter->x;
            pWorkTVertIter->y = (pTVertIter->y - pLastTVertIter->y) * v132 + pLastTVertIter->y;

            ++numOnScreenVertices;
            ++pWorkVertIter;
            ++pWorkTVertIter;
            rdClip_faceStatus |= CLIPSTAT_BOTTOM;
        }
        if ( pVertIter->z >= (flex_d_t)bottomPlaneB )
        {
            *pWorkVertIter = *pVertIter;
            pWorkTVertIter->x = pTVertIter->x;
            pWorkTVertIter->y = pTVertIter->y;
            ++numOnScreenVertices;
            ++pWorkVertIter;
            ++pWorkTVertIter;
        }
    }

    if ( numOnScreenVertices < 3 )
        return numOnScreenVertices;

    numVertices = numOnScreenVertices;
    pLastSourceVert = pSourceVert;
    pLastDestVert = pDestVert;
    pLastSourceTVert = pSourceTVert;
    pLastDestTVert = pDestTVert;
    
    pSourceVert = pLastDestVert;
    pDestVert = pLastSourceVert;
    pSourceTVert = pLastDestTVert;
    pDestTVert = pLastSourceTVert;
    
    pWorkVertIter = pLastSourceVert;
    pWorkTVertIter = pLastSourceTVert;
    
    pVertIter = pLastDestVert;
    pTVertIter = pLastDestTVert;
    pLastVertIter = &pLastDestVert[numVertices - 1];
    pLastTVertIter = &pTVertIter[numVertices - 1];

    numOnScreenVertices = 0;
    for (int i = 0; i < numVertices; pLastVertIter = pVertIter++, pLastTVertIter = pTVertIter++, i++)
    {
        if (!(pLastVertIter->y >= (flex_d_t)pClipFrustum->zNear || pVertIter->y >= (flex_d_t)pClipFrustum->zNear)) {
            continue;
        }

        if ( pLastVertIter->y != pClipFrustum->zNear
          && pVertIter->y != pClipFrustum->zNear
          && (pLastVertIter->y < (flex_d_t)pClipFrustum->zNear || pVertIter->y < (flex_d_t)pClipFrustum->zNear) )
        {
            flex_t tmpdiv = (pVertIter->y - pLastVertIter->y);
#ifdef EXPERIMENTAL_FIXED_POINT
            if (tmpdiv != 0.0) {
                v150 = ((pClipFrustum->zNear - pLastVertIter->y) * premultiplyASquared) / (tmpdiv * premultiplyASquared);
            }
            else {
                v150 = (pClipFrustum->zNear - pLastVertIter->y);
            }
            if (v150 == 0.0) {
                //continue;
            }
#else
            v150 = (pClipFrustum->zNear - pLastVertIter->y) / tmpdiv;
#endif
            pWorkVertIter->x = ((pVertIter->x - pLastVertIter->x) * v150) + pLastVertIter->x;
            pWorkVertIter->y = pClipFrustum->zNear;
            pWorkVertIter->z = (pVertIter->z - pLastVertIter->z) * v150 + pLastVertIter->z;
            pWorkTVertIter->x = (pTVertIter->x - pLastTVertIter->x) * v150 + pLastTVertIter->x;
            pWorkTVertIter->y = (pTVertIter->y - pLastTVertIter->y) * v150 + pLastTVertIter->y;
            rdClip_faceStatus |= CLIPSTAT_NEAR;
            ++pWorkVertIter;
            ++pWorkTVertIter;
            ++numOnScreenVertices;
        }
        if ( pVertIter->y >= (flex_d_t)pClipFrustum->zNear )
        {
            *pWorkVertIter = *pVertIter;
            pWorkTVertIter->x = pTVertIter->x;
            pWorkTVertIter->y = pTVertIter->y;
            ++numOnScreenVertices;
            ++pWorkVertIter;
            ++pWorkTVertIter;
        }
    }

    if ( numOnScreenVertices < 3 )
    {
        rdClip_faceStatus |= CLIPSTAT_NONE_VISIBLE; // Bug? Or did I mislabel this status
        return numOnScreenVertices;
    }

#ifndef RDCLIP_CLIP_ZFAR_FIRST
    if (pClipFrustum->bClipFar)
    {
        numVertices = numOnScreenVertices;
        pLastSourceVert = pSourceVert;
        pLastDestVert = pDestVert;
        pLastSourceTVert = pSourceTVert;
        pLastDestTVert = pDestTVert;
        
        pSourceVert = pLastDestVert;
        pDestVert = pLastSourceVert;
        pSourceTVert = pLastDestTVert;
        pDestTVert = pLastSourceTVert;
        
        pWorkVertIter = pLastSourceVert;
        pWorkTVertIter = pLastSourceTVert;
        
        pVertIter = pLastDestVert;
        pTVertIter = pLastDestTVert;
        pLastVertIter = &pLastDestVert[numVertices - 1];
        pLastTVertIter = &pTVertIter[numVertices - 1];

        numOnScreenVertices = 0;
        for (int i = 0; i < numVertices; pLastVertIter = pVertIter++, pLastTVertIter = pTVertIter++, i++)
        {
            if (!(pLastVertIter->y <= (flex_d_t)pClipFrustum->zFar || pVertIter->y <= (flex_d_t)pClipFrustum->zFar)) {
                continue;
            }

            if ( pLastVertIter->y != pClipFrustum->zFar
              && pVertIter->y != pClipFrustum->zFar
              && (pLastVertIter->y > (flex_d_t)pClipFrustum->zFar || pVertIter->y > (flex_d_t)pClipFrustum->zFar) )
            {
                
                v174 = (pClipFrustum->zFar - pLastVertIter->y) / (pVertIter->y - pLastVertIter->y);
                pWorkVertIter->x = (pVertIter->x - pLastVertIter->x) * v174 + pLastVertIter->x;
                pWorkVertIter->y = pClipFrustum->zFar;
                pWorkVertIter->z = (pVertIter->z - pLastVertIter->z) * v174 + pLastVertIter->z;

                pWorkTVertIter->x = (pTVertIter->x - pLastTVertIter->x) * v174 + pLastTVertIter->x;
                pWorkTVertIter->y = (pTVertIter->y - pLastTVertIter->y) * v174 + pLastTVertIter->y;
                
                ++pWorkVertIter;
                ++pWorkTVertIter;
                ++numOnScreenVertices;
                rdClip_faceStatus |= CLIPSTAT_FAR;
            }
            if ( pVertIter->y <= (flex_d_t)pClipFrustum->zFar )
            {
                *pWorkVertIter = *pVertIter;
                pWorkTVertIter->x = pTVertIter->x;
                pWorkTVertIter->y = pTVertIter->y;
                ++pWorkVertIter;
                ++pWorkTVertIter;
                ++numOnScreenVertices;
            }
        }
        if ( numOnScreenVertices < 3 ) {
            return numOnScreenVertices;
        }
    }
#endif

    if ( pDestVert != pVertices )
    {
        _memcpy(pVertices, pDestVert, sizeof(rdVector3) * numOnScreenVertices);
        _memcpy(pTVertices, pDestTVert, sizeof(rdVector2) * numOnScreenVertices);
    }

    return numOnScreenVertices;
}
// MOTS TODO

int rdClip_Face3GSRGB(rdClipFrustum *frustum,rdVector3 *vertices,flex_t *pR,flex_t *pG,flex_t *pB,int numVertices)
{
    INST_WORKBUFS
    INST_WORKBUFS_MOTS

    flex_t fVar1;
    flex_t fVar2;
    flex_t fVar3;
    flex_t fVar4;
    flex_t fVar5;
    flex_t fVar6;
    flex_t fVar7;
    flex_t fVar8;
    flex_t fVar9;
    flex_t fVar10;
    flex_t fVar11;
    intptr_t iVar12;
    intptr_t iVar13;
    intptr_t iVar14;
    uint32_t uVar15;
    rdVector3 *prVar16;
    rdVector3 *prVar17;
    rdVector3 *prVar18;
    flex_t *pfVar19;
    rdVector3 *prVar20;
    flex_t *pfVar21;
    flex_t *pfVar22;
    flex_t *pfVar23;
    flex_t *pfVar24;
    flex_t *pfVar25;
    flex_t *pfVar26;
    flex_t *pfVar27;
    uint32_t local_30;
    flex_t *local_2c;
    flex_t *local_28;
    flex_t *local_1c;
    flex_t *local_14;
    flex_t *local_10;
    flex_t *local_c;
    flex_t *local_8;
    uint32_t local_4;
    
    rdClip_faceStatus = 0;
    local_30 = 0;
    local_2c = pR + numVertices + -1;
    pSourceBlueIVert = pB;
    local_28 = pG + numVertices + -1;
    pSourceVert = vertices;
    pSourceRedIVert = pR;
    pSourceGreenIVert = pG;
    pDestVert = workVerts;
    pDestRedIVert = workRedIVerts;
    pDestGreenIVert = workGreenIVerts;
    pDestBlueIVert = workBlueIVerts;
    if (0 < numVertices) {
        local_c = workGreenIVerts;
        iVar12 = (intptr_t)pR - (intptr_t)pB;
        iVar13 = (intptr_t)pG - (intptr_t)pB;
        local_10 = workBlueIVerts;
        pfVar26 = workRedIVerts;
        prVar20 = workVerts;
        local_4 = numVertices;
        pfVar27 = pB;
        prVar17 = vertices + numVertices + -1;
        pfVar24 = workGreenIVerts;
        prVar18 = vertices;
        local_1c = pB + numVertices + -1;
        do {
            pfVar25 = pfVar27;
            fVar11 = prVar17->y * frustum->nearLeft;
            fVar10 = frustum->nearLeft * prVar18->y;
            pfVar22 = pfVar24;
            if ((fVar11 <= prVar17->x) || (fVar10 <= prVar18->x)) {
                prVar16 = prVar20;
                pfVar27 = pfVar26;
                if (((prVar17->x != fVar11) && (prVar18->x != fVar10)) && ((prVar17->x < fVar11 || (prVar18->x < fVar10)))) {
                    fVar11 = prVar18->y - prVar17->y;
                    fVar1 = prVar18->x - prVar17->x;
                    fVar4 = frustum->nearLeft * fVar11 - fVar1;
                    fVar5 = prVar18->y * prVar17->x - prVar17->y * prVar18->x;
                    if (fVar4 != 0.0) {
                        fVar5 = fVar5 / fVar4;
                    }
                    fVar4 = frustum->nearLeft * fVar5;
                    fVar2 = fVar11;
                    if (fVar11 < 0.0) {
                        fVar2 = -fVar11;
                    }
                    fVar3 = fVar1;
                    if (fVar1 < 0.0) {
                        fVar3 = -fVar1;
                    }
                    if ((uint16_t)((uint16_t)(fVar2 < fVar3) << 8 | (uint16_t)(fVar2 == fVar3) << 0xe) == 0) {
                        fVar11 = (fVar5 - prVar17->y) / fVar11;
                    }
                    else {
                        fVar11 = (fVar4 - prVar17->x) / fVar1;
                    }
                    prVar16 = prVar20 + 1;
                    fVar1 = *(flex_t *)(iVar12 + (intptr_t)pfVar25);
                    pfVar27 = pfVar26 + 1;
                    fVar2 = *(flex_t *)(iVar13 + (intptr_t)pfVar25);
                    fVar3 = *pfVar25;
                    prVar20->x = fVar4;
                    pfVar22 = pfVar24 + 1;
                    prVar20->y = fVar5;
                    fVar4 = *local_2c;
                    fVar5 = *local_28;
                    fVar6 = *local_1c;
                    local_30 = local_30 + 1;
                    fVar7 = *local_2c;
                    fVar8 = *local_28;
                    fVar9 = *local_1c;
                    prVar20->z = (prVar18->z - prVar17->z) * fVar11 + prVar17->z;
                    *pfVar26 = (fVar1 - fVar4) * fVar11 + fVar7;
                    *pfVar24 = (fVar2 - fVar5) * fVar11 + fVar8;
                    *local_10 = (fVar3 - fVar6) * fVar11 + fVar9;
                    local_10 = local_10 + 1;
                    rdClip_faceStatus = rdClip_faceStatus | CLIPSTAT_LEFT;
                    local_c = pfVar22;
                }
                prVar20 = prVar16;
                pfVar26 = pfVar27;
                if (fVar10 <= prVar18->x) {
                    prVar20 = prVar16 + 1;
                    pfVar26 = pfVar27 + 1;
                    prVar16->x = prVar18->x;
                    prVar16->y = prVar18->y;
                    pfVar22 = local_c + 1;
                    prVar16->z = prVar18->z;
                    fVar11 = *pfVar25;
                    *pfVar27 = *(flex_t *)(iVar12 + (intptr_t)pfVar25);
                    *local_c = *(flex_t *)(iVar13 + (intptr_t)pfVar25);
                    *local_10 = fVar11;
                    local_30 = local_30 + 1;
                    local_10 = local_10 + 1;
                    local_c = pfVar22;
                }
            }
            local_2c = (flex_t *)(iVar12 + (intptr_t)pfVar25);
            local_28 = (flex_t *)(iVar13 + (intptr_t)pfVar25);
            local_4 = local_4 + -1;
            pfVar27 = pfVar25 + 1;
            prVar17 = prVar18;
            pfVar24 = pfVar22;
            prVar18 = prVar18 + 1;
            local_1c = pfVar25;
        } while (local_4 != 0);
    }
    local_4 = local_30;
    if ((intptr_t)local_30 < 3) {
        return local_30;
    }
    pDestRedIVert = pR;
    pSourceRedIVert = workRedIVerts;
    pDestGreenIVert = pG;
    pSourceGreenIVert = workGreenIVerts;
    pSourceVert = workVerts;
    pDestVert = vertices;
    pDestBlueIVert = pB;
    pfVar27 = workBlueIVerts;
    iVar12 = local_30 - 1;
    local_2c = pSourceRedIVert + (local_30 - 1);
    local_30 = 0;
    local_28 = pSourceGreenIVert + (local_4 - 1);
    pSourceBlueIVert = pfVar27;
    if (0 < (intptr_t)local_4) {
        local_c = pG;
        iVar13 = (intptr_t)pSourceRedIVert - (intptr_t)pfVar27;
        iVar14 = (intptr_t)pSourceGreenIVert - (intptr_t)pfVar27;
        local_8 = pB;
        local_10 = pR;
        prVar20 = vertices;
        pfVar24 = pfVar27;
        prVar17 = pSourceVert + iVar12;
        pfVar26 = pR;
        prVar18 = pSourceVert;
        local_1c = pfVar27 + (local_4 - 1);
        do {
            pfVar25 = pfVar24;
            fVar11 = frustum->right * prVar17->y;
            fVar10 = frustum->right * prVar18->y;
            pfVar22 = pfVar26;
            if (((uint16_t)((uint16_t)(prVar17->x < fVar11) << 8 | (uint16_t)(prVar17->x == fVar11) << 0xe) != 0) || ((uint16_t)((uint16_t)(prVar18->x < fVar10) << 8 | (uint16_t)(prVar18->x == fVar10) << 0xe) != 0)) {
                prVar16 = prVar20;
                if (((prVar17->x != fVar11) && (prVar18->x != fVar10)) && (((uint16_t)((uint16_t)(prVar17->x < fVar11) << 8 | (uint16_t)(prVar17->x == fVar11) << 0xe) == 0 || ((uint16_t)((uint16_t)(prVar18->x < fVar10) << 8 | (uint16_t)(prVar18->x == fVar10) << 0xe) == 0)))) {
                    fVar11 = prVar18->y - prVar17->y;
                    fVar1 = prVar18->x - prVar17->x;
                    fVar4 = frustum->right * fVar11 - fVar1;
                    fVar5 = prVar18->y * prVar17->x - prVar17->y * prVar18->x;
                    if (fVar4 != 0.0) {
                        fVar5 = fVar5 / fVar4;
                    }
                    fVar4 = frustum->right * fVar5;
                    fVar2 = fVar11;
                    if (fVar11 < 0.0) {
                        fVar2 = -fVar11;
                    }
                    fVar3 = fVar1;
                    if (fVar1 < 0.0) {
                        fVar3 = -fVar1;
                    }
                    if ((uint16_t)((uint16_t)(fVar2 < fVar3) << 8 | (uint16_t)(fVar2 == fVar3) << 0xe) == 0) {
                        fVar11 = (fVar5 - prVar17->y) / fVar11;
                    }
                    else {
                        fVar11 = (fVar4 - prVar17->x) / fVar1;
                    }
                    prVar16 = prVar20 + 1;
                    fVar1 = *(flex_t *)(iVar13 + (intptr_t)pfVar25);
                    pfVar22 = pfVar26 + 1;
                    fVar2 = *(flex_t *)(iVar14 + (intptr_t)pfVar25);
                    fVar3 = *pfVar25;
                    prVar20->x = fVar4;
                    prVar20->y = fVar5;
                    fVar4 = *local_2c;
                    fVar5 = *local_28;
                    fVar6 = *local_1c;
                    local_30 = local_30 + 1;
                    fVar7 = *local_2c;
                    fVar8 = *local_28;
                    fVar9 = *local_1c;
                    prVar20->z = (prVar18->z - prVar17->z) * fVar11 + prVar17->z;
                    *pfVar26 = (fVar1 - fVar4) * fVar11 + fVar7;
                    *local_c = (fVar2 - fVar5) * fVar11 + fVar8;
                    local_c = local_c + 1;
                    *local_8 = (fVar3 - fVar6) * fVar11 + fVar9;
                    rdClip_faceStatus = rdClip_faceStatus | CLIPSTAT_RIGHT;
                    local_10 = pfVar22;
                    local_8 = local_8 + 1;
                }
                prVar20 = prVar16;
                if ((uint16_t)((uint16_t)(prVar18->x < fVar10) << 8 | (uint16_t)(prVar18->x == fVar10) << 0xe) != 0) {
                    prVar20 = prVar16 + 1;
                    prVar16->x = prVar18->x;
                    prVar16->y = prVar18->y;
                    pfVar22 = local_10 + 1;
                    prVar16->z = prVar18->z;
                    *local_10 = *(flex_t *)(iVar13 + (intptr_t)pfVar25);
                    *local_c = *(flex_t *)(iVar14 + (intptr_t)pfVar25);
                    *local_8 = *pfVar25;
                    local_30 = local_30 + 1;
                    local_c = local_c + 1;
                    local_8 = local_8 + 1;
                    local_10 = pfVar22;
                }
            }
            local_2c = (flex_t *)(iVar13 + (intptr_t)pfVar25);
            local_28 = (flex_t *)(iVar14 + (intptr_t)pfVar25);
            local_4 = local_4 - 1;
            pfVar24 = pfVar25 + 1;
            prVar17 = prVar18;
            pfVar26 = pfVar22;
            prVar18 = prVar18 + 1;
            local_1c = pfVar25;
        } while (local_4 != 0);
    }
    uVar15 = local_30;
    local_c = pSourceRedIVert;
    local_14 = pSourceGreenIVert;
    pfVar24 = pDestBlueIVert;
    local_4 = local_30;
    if (2 < (intptr_t)local_30) {
        pSourceRedIVert = pDestRedIVert;
        local_2c = pDestRedIVert + (local_30 - 1);
        pSourceGreenIVert = pDestGreenIVert;
        local_28 = pDestGreenIVert + (local_30 - 1);
        local_1c = pDestBlueIVert + (local_30 - 1);
        pSourceBlueIVert = pDestBlueIVert;
        local_30 = 0;
        prVar20 = pDestVert + (uVar15 - 1);
        local_4 = 0;
        pfVar26 = local_c;
        pfVar22 = local_14;
        prVar17 = pSourceVert;
        prVar18 = pDestVert;
        if (0 < (intptr_t)uVar15) {
            pfVar25 = &pDestVert->z;
            iVar12 = (intptr_t)pDestRedIVert - (intptr_t)pDestBlueIVert;
            iVar13 = (intptr_t)pDestGreenIVert - (intptr_t)pDestBlueIVert;
            local_4 = uVar15;
            prVar16 = pSourceVert;
            pfVar19 = pDestBlueIVert;
            pfVar23 = local_c;
            pDestRedIVert = local_c;
            pDestBlueIVert = pfVar27;
            pDestGreenIVert = local_14;
            prVar17 = pSourceVert;
            pSourceVert = pDestVert;
            local_8 = pfVar27;
            uVar15 = local_4;
            do {
                local_4 = uVar15;
                pDestVert = prVar17;
                pfVar21 = pfVar19;
                fVar11 = frustum->nearTop * prVar20->y;
                fVar10 = pfVar25[-1] * frustum->nearTop;
                pfVar27 = pfVar23;
                if (((uint16_t)((uint16_t)(prVar20->z < fVar11) << 8 | (uint16_t)(prVar20->z == fVar11) << 0xe) != 0) || ((uint16_t)((uint16_t)(*pfVar25 < fVar10) << 8 | (uint16_t)(*pfVar25 == fVar10) << 0xe) != 0)) {
                    prVar17 = prVar16;
                    if (((prVar20->z != fVar11) && (*pfVar25 != fVar10)) && (((uint16_t)((uint16_t)(prVar20->z < fVar11) << 8 | (uint16_t)(prVar20->z == fVar11) << 0xe) == 0 || ((uint16_t)((uint16_t)(*pfVar25 < fVar10) << 8 | (uint16_t)(*pfVar25 == fVar10) << 0xe) == 0)))) {
                        fVar11 = pfVar25[-1] - prVar20->y;
                        fVar1 = *pfVar25 - prVar20->z;
                        fVar4 = frustum->nearTop * fVar11 - fVar1;
                        fVar5 = prVar20->z * pfVar25[-1] - prVar20->y * *pfVar25;
                        if (fVar4 != 0.0) {
                            fVar5 = fVar5 / fVar4;
                        }
                        fVar4 = frustum->nearTop * fVar5;
                        fVar2 = fVar11;
                        if (fVar11 < 0.0) {
                            fVar2 = -fVar11;
                        }
                        fVar3 = fVar1;
                        if (fVar1 < 0.0) {
                            fVar3 = -fVar1;
                        }
                        if ((uint16_t)((uint16_t)(fVar2 < fVar3) << 8 | (uint16_t)(fVar2 == fVar3) << 0xe) == 0) {
                            fVar11 = (fVar5 - prVar20->y) / fVar11;
                        }
                        else {
                            fVar11 = (fVar4 - prVar20->z) / fVar1;
                        }
                        prVar17 = prVar16 + 1;
                        fVar1 = *(flex_t *)((intptr_t)pfVar21 + iVar12);
                        pfVar27 = pfVar23 + 1;
                        fVar2 = *(flex_t *)((intptr_t)pfVar21 + iVar13);
                        fVar3 = *pfVar21;
                        fVar6 = *local_2c;
                        fVar7 = *local_28;
                        fVar8 = *local_1c;
                        prVar16->x = (((rdVector3 *)(pfVar25 + -2))->x - prVar20->x) * fVar11 + prVar20->x;
                        prVar16->y = fVar5;
                        prVar16->z = fVar4;
                        local_30 = local_30 + 1;
                        fVar4 = *local_28;
                        fVar5 = *local_1c;
                        *pfVar23 = (fVar1 - fVar6) * fVar11 + *local_2c;
                        *local_14 = (fVar2 - fVar7) * fVar11 + fVar4;
                        local_14 = local_14 + 1;
                        *local_8 = (fVar3 - fVar8) * fVar11 + fVar5;
                        local_8 = local_8 + 1;
                        rdClip_faceStatus = rdClip_faceStatus | 4;
                        local_c = pfVar27;
                    }
                    prVar16 = prVar17;
                    if ((uint16_t)((uint16_t)(*pfVar25 < fVar10) << 8 | (uint16_t)(*pfVar25 == fVar10) << 0xe) != 0) {
                        prVar16 = prVar17 + 1;
                        prVar17->x = ((rdVector3 *)(pfVar25 + -2))->x;
                        prVar17->y = pfVar25[-1];
                        pfVar27 = local_c + 1;
                        prVar17->z = *pfVar25;
                        *local_c = *(flex_t *)((intptr_t)pfVar21 + iVar12);
                        *local_14 = *(flex_t *)((intptr_t)pfVar21 + iVar13);
                        *local_8 = *pfVar21;
                        local_30 = local_30 + 1;
                        local_14 = local_14 + 1;
                        local_8 = local_8 + 1;
                        local_c = pfVar27;
                    }
                }
                prVar20 = (rdVector3 *)(pfVar25 + -2);
                local_2c = (flex_t *)(iVar12 + (intptr_t)pfVar21);
                local_28 = (flex_t *)(iVar13 + (intptr_t)pfVar21);
                pfVar25 = pfVar25 + 3;
                uVar15 = local_4 - 1;
                local_4 = local_30;
                pfVar19 = pfVar21 + 1;
                pfVar23 = pfVar27;
                pfVar26 = pDestRedIVert;
                pfVar27 = pDestBlueIVert;
                pfVar22 = pDestGreenIVert;
                prVar17 = pDestVert;
                prVar18 = pSourceVert;
                local_1c = pfVar21;
            } while (uVar15 != 0);
        }
        pSourceVert = prVar18;
        pDestVert = prVar17;
        pDestGreenIVert = pfVar22;
        pDestBlueIVert = pfVar27;
        pDestRedIVert = pfVar26;
        prVar20 = pSourceVert;
        local_c = pSourceRedIVert;
        local_14 = pSourceGreenIVert;
        pfVar27 = pDestBlueIVert;
        if (2 < (intptr_t)local_4) {
            pSourceVert = pDestVert;
            pSourceRedIVert = pDestRedIVert;
            pSourceGreenIVert = pDestGreenIVert;
            local_2c = pDestRedIVert + (local_4 - 1);
            local_28 = pDestGreenIVert + (local_4 - 1);
            local_1c = pDestBlueIVert + (local_4 - 1);
            pSourceBlueIVert = pDestBlueIVert;
            local_30 = 0;
            prVar17 = pDestVert + (local_4 - 1);
            uVar15 = 0;
            pfVar26 = local_c;
            pfVar22 = local_14;
            prVar18 = prVar20;
            if (0 < (intptr_t)local_4) {
                local_8 = pfVar24;
                pfVar25 = &pDestVert->z;
                iVar12 = (intptr_t)pDestRedIVert - (intptr_t)pDestBlueIVert;
                iVar13 = (intptr_t)pDestGreenIVert - (intptr_t)pDestBlueIVert;
                pfVar19 = pDestBlueIVert;
                pfVar23 = local_c;
                pDestRedIVert = local_c;
                pDestBlueIVert = pfVar24;
                pDestGreenIVert = local_14;
                pDestVert = prVar20;
                do {
                    pfVar21 = pfVar19;
                    fVar11 = frustum->bottom * prVar17->y;
                    fVar10 = pfVar25[-1] * frustum->bottom;
                    pfVar24 = pfVar23;
                    if ((fVar11 <= prVar17->z) || (fVar10 <= *pfVar25)) {
                        prVar18 = prVar20;
                        if (((prVar17->z != fVar11) && (*pfVar25 != fVar10)) && ((prVar17->z < fVar11 || (*pfVar25 < fVar10)))) {
                            fVar11 = pfVar25[-1] - prVar17->y;
                            fVar1 = *pfVar25 - prVar17->z;
                            fVar4 = frustum->bottom * fVar11 - fVar1;
                            fVar5 = prVar17->z * pfVar25[-1] - prVar17->y * *pfVar25;
                            if (fVar4 != 0.0) {
                                fVar5 = fVar5 / fVar4;
                            }
                            fVar4 = frustum->bottom * fVar5;
                            fVar2 = fVar11;
                            if (fVar11 < 0.0) {
                                fVar2 = -fVar11;
                            }
                            fVar3 = fVar1;
                            if (fVar1 < 0.0) {
                                fVar3 = -fVar1;
                            }
                            if ((uint16_t)((uint16_t)(fVar2 < fVar3) << 8 | (uint16_t)(fVar2 == fVar3) << 0xe) == 0) {
                                fVar11 = (fVar5 - prVar17->y) / fVar11;
                            }
                            else {
                                fVar11 = (fVar4 - prVar17->z) / fVar1;
                            }
                            prVar18 = prVar20 + 1;
                            fVar1 = *(flex_t *)((intptr_t)pfVar21 + iVar12);
                            pfVar24 = pfVar23 + 1;
                            fVar2 = *(flex_t *)((intptr_t)pfVar21 + iVar13);
                            fVar3 = *pfVar21;
                            fVar6 = *local_2c;
                            fVar7 = *local_28;
                            fVar8 = *local_1c;
                            prVar20->x = (((rdVector3 *)(pfVar25 + -2))->x - prVar17->x) * fVar11 + prVar17->x;
                            prVar20->y = fVar5;
                            prVar20->z = fVar4;
                            local_30 = local_30 + 1;
                            fVar4 = *local_28;
                            fVar5 = *local_1c;
                            *pfVar23 = (fVar1 - fVar6) * fVar11 + *local_2c;
                            *local_14 = (fVar2 - fVar7) * fVar11 + fVar4;
                            local_14 = local_14 + 1;
                            *local_8 = (fVar3 - fVar8) * fVar11 + fVar5;
                            local_8 = local_8 + 1;
                            rdClip_faceStatus = rdClip_faceStatus | 8;
                            local_c = pfVar24;
                        }
                        prVar20 = prVar18;
                        if (fVar10 <= *pfVar25) {
                            prVar20 = prVar18 + 1;
                            prVar18->x = ((rdVector3 *)(pfVar25 + -2))->x;
                            prVar18->y = pfVar25[-1];
                            pfVar24 = local_c + 1;
                            prVar18->z = *pfVar25;
                            *local_c = *(flex_t *)((intptr_t)pfVar21 + iVar12);
                            *local_14 = *(flex_t *)((intptr_t)pfVar21 + iVar13);
                            *local_8 = *pfVar21;
                            local_30 = local_30 + 1;
                            local_14 = local_14 + 1;
                            local_8 = local_8 + 1;
                            local_c = pfVar24;
                        }
                    }
                    prVar17 = (rdVector3 *)(pfVar25 + -2);
                    local_2c = (flex_t *)(iVar12 + (intptr_t)pfVar21);
                    local_28 = (flex_t *)(iVar13 + (intptr_t)pfVar21);
                    pfVar25 = pfVar25 + 3;
                    local_4 = local_4 - 1;
                    uVar15 = local_30;
                    pfVar19 = pfVar21 + 1;
                    pfVar23 = pfVar24;
                    pfVar26 = pDestRedIVert;
                    pfVar24 = pDestBlueIVert;
                    pfVar22 = pDestGreenIVert;
                    prVar18 = pDestVert;
                    local_1c = pfVar21;
                } while (local_4 != 0);
            }
            pDestVert = prVar18;
            pDestGreenIVert = pfVar22;
            pDestBlueIVert = pfVar24;
            pDestRedIVert = pfVar26;
            local_4 = uVar15;
            prVar20 = pSourceVert;
            pfVar26 = pSourceRedIVert;
            local_c = pSourceGreenIVert;
            pfVar24 = pDestBlueIVert;
            if (2 < (intptr_t)local_4) {
                local_30 = 0;
                pSourceVert = pDestVert;
                pSourceRedIVert = pDestRedIVert;
                local_2c = pDestRedIVert + (local_4 - 1);
                pSourceGreenIVert = pDestGreenIVert;
                local_28 = pDestGreenIVert + (local_4 - 1);
                pSourceBlueIVert = pDestBlueIVert;
                local_1c = pDestBlueIVert + (local_4 - 1);
                prVar17 = pDestVert + (local_4 - 1);
                numVertices = 0;
                pfVar22 = pfVar26;
                pfVar25 = local_c;
                if (0 < (intptr_t)local_4) {
                    pfVar19 = &pDestVert->y;
                    local_8 = pfVar27;
                    iVar12 = (intptr_t)pDestRedIVert - (intptr_t)pDestBlueIVert;
                    iVar13 = (intptr_t)pDestGreenIVert - (intptr_t)pDestBlueIVert;
                    pfVar23 = pDestBlueIVert;
                    prVar18 = prVar20;
                    pDestRedIVert = pfVar26;
                    pDestBlueIVert = pfVar27;
                    pDestGreenIVert = local_c;
                    pDestVert = prVar20;
                    local_10 = pfVar26;
                    do {
                        numVertices = local_4;
                        pfVar21 = pfVar23;
                        if ((frustum->zNear <= prVar17->y) || (prVar20 = prVar18, frustum->zNear <= *pfVar19)) {
                            if (((prVar17->y != frustum->zNear) && (*pfVar19 != frustum->zNear)) && ((prVar17->y < frustum->zNear || (*pfVar19 < frustum->zNear)))) {
                                fVar8 = (frustum->zNear - prVar17->y) / (*pfVar19 - prVar17->y);
                                prVar18->y = frustum->zNear;
                                local_30 = local_30 + 1;
                                fVar11 = *(flex_t *)((intptr_t)pfVar21 + iVar12);
                                fVar10 = *(flex_t *)((intptr_t)pfVar21 + iVar13);
                                fVar1 = *pfVar21;
                                fVar4 = *local_2c;
                                fVar5 = *local_28;
                                prVar18->z = (pfVar19[1] - prVar17->z) * fVar8 + prVar17->z;
                                fVar2 = *local_1c;
                                fVar3 = *local_2c;
                                fVar6 = *local_28;
                                fVar7 = *local_1c;
                                prVar18->x = (((rdVector3 *)(pfVar19 + -1))->x - prVar17->x) * fVar8 + prVar17->x;
                                *pfVar26 = (fVar11 - fVar4) * fVar8 + fVar3;
                                prVar18 = prVar18 + 1;
                                pfVar26 = pfVar26 + 1;
                                *local_c = (fVar10 - fVar5) * fVar8 + fVar6;
                                local_c = local_c + 1;
                                *local_8 = (fVar1 - fVar2) * fVar8 + fVar7;
                                local_8 = local_8 + 1;
                                rdClip_faceStatus = rdClip_faceStatus | 1;
                                local_10 = pfVar26;
                            }
                            prVar20 = prVar18;
                            if (frustum->zNear <= *pfVar19) {
                                prVar20 = prVar18 + 1;
                                prVar18->x = ((rdVector3 *)(pfVar19 + -1))->x;
                                prVar18->y = *pfVar19;
                                pfVar26 = local_10 + 1;
                                prVar18->z = pfVar19[1];
                                *local_10 = *(flex_t *)((intptr_t)pfVar21 + iVar12);
                                *local_c = *(flex_t *)((intptr_t)pfVar21 + iVar13);
                                *local_8 = *pfVar21;
                                local_30 = local_30 + 1;
                                local_c = local_c + 1;
                                local_8 = local_8 + 1;
                                local_10 = pfVar26;
                            }
                        }
                        prVar17 = (rdVector3 *)(pfVar19 + -1);
                        local_2c = (flex_t *)(iVar12 + (intptr_t)pfVar21);
                        local_28 = (flex_t *)(iVar13 + (intptr_t)pfVar21);
                        pfVar19 = pfVar19 + 3;
                        local_4 = numVertices + -1;
                        pfVar23 = pfVar21 + 1;
                        numVertices = local_30;
                        prVar18 = prVar20;
                        pfVar22 = pDestRedIVert;
                        pfVar27 = pDestBlueIVert;
                        pfVar25 = pDestGreenIVert;
                        prVar20 = pDestVert;
                        local_1c = pfVar21;
                    } while (local_4 != 0);
                }
                pDestVert = prVar20;
                pDestGreenIVert = pfVar25;
                pDestBlueIVert = pfVar27;
                pDestRedIVert = pfVar22;
                pfVar27 = pSourceRedIVert;
                local_8 = pSourceGreenIVert;
                if (numVertices < 3) {
                    rdClip_faceStatus = rdClip_faceStatus | CLIPSTAT_NONE_VISIBLE;
                    return numVertices;
                }
                local_4 = numVertices;
                if (frustum->bClipFar) {
                    pSourceRedIVert = pDestRedIVert;
                    pSourceGreenIVert = pDestGreenIVert;
                    local_30 = 0;
                    pSourceBlueIVert = pDestBlueIVert;
                    local_28 = pDestGreenIVert + (numVertices - 1);
                    local_2c = pDestRedIVert + (numVertices - 1);
                    local_1c = pDestBlueIVert + (numVertices - 1);
                    prVar20 = pDestVert + (numVertices - 1);
                    pfVar26 = local_8;
                    prVar17 = pSourceVert;
                    prVar18 = pDestVert;
                    if (0 < numVertices) {
                        iVar12 = (intptr_t)pDestRedIVert - (intptr_t)pDestBlueIVert;
                        pfVar19 = &pDestVert->y;
                        iVar13 = (intptr_t)pDestGreenIVert - (intptr_t)pDestBlueIVert;
                        local_c = pfVar24;
                        pfVar22 = pDestBlueIVert;
                        pfVar25 = pfVar27;
                        prVar16 = pSourceVert;
                        pDestRedIVert = pfVar27;
                        pDestBlueIVert = pfVar24;
                        pDestGreenIVert = local_8;
                        prVar17 = pSourceVert;
                        pSourceVert = pDestVert;
                        do {
                            pDestVert = prVar17;
                            pfVar23 = pfVar22;
                            fVar11 = frustum->zFar;
                            if ((prVar20->y <= fVar11) || (fVar11 = frustum->zFar, pfVar27 = pfVar25, prVar17 = prVar16, (*pfVar19 <= fVar11))) {
                                if (((prVar20->y != frustum->zFar) && (*pfVar19 != frustum->zFar)) && ((fVar11 = frustum->zFar, (uint16_t)((uint16_t)(prVar20->y < fVar11) << 8 | (uint16_t)(prVar20->y == fVar11) << 0xe) == 0 || (fVar11 = frustum->zFar, (uint16_t)((uint16_t)(*pfVar19 < fVar11) << 8 | (uint16_t)(*pfVar19 == fVar11) << 0xe) == 0)))) {
                                    fVar8 = (frustum->zFar - prVar20->y) / (*pfVar19 - prVar20->y);
                                    prVar16->y = frustum->zFar;
                                    local_30 = local_30 + 1;
                                    fVar11 = *(flex_t *)((intptr_t)pfVar23 + iVar12);
                                    fVar10 = *(flex_t *)((intptr_t)pfVar23 + iVar13);
                                    fVar1 = *pfVar23;
                                    fVar4 = *local_2c;
                                    fVar5 = *local_28;
                                    prVar16->z = (pfVar19[1] - prVar20->z) * fVar8 + prVar20->z;
                                    fVar2 = *local_1c;
                                    fVar3 = *local_2c;
                                    fVar6 = *local_28;
                                    fVar7 = *local_1c;
                                    prVar16->x = (((rdVector3 *)(pfVar19 + -1))->x - prVar20->x) * fVar8 + prVar20->x;
                                    *pfVar25 = (fVar11 - fVar4) * fVar8 + fVar3;
                                    *local_8 = (fVar10 - fVar5) * fVar8 + fVar6;
                                    local_8 = local_8 + 1;
                                    *local_c = (fVar1 - fVar2) * fVar8 + fVar7;
                                    prVar16 = prVar16 + 1;
                                    pfVar25 = pfVar25 + 1;
                                    local_c = local_c + 1;
                                    rdClip_faceStatus = rdClip_faceStatus | 2;
                                }
                                fVar11 = frustum->zFar;
                                pfVar27 = pfVar25;
                                prVar17 = prVar16;
                                if ((uint16_t)((uint16_t)(*pfVar19 < fVar11) << 8 | (uint16_t)(*pfVar19 == fVar11) << 0xe) != 0) {
                                    prVar17 = prVar16 + 1;
                                    pfVar27 = pfVar25 + 1;
                                    prVar16->x = ((rdVector3 *)(pfVar19 + -1))->x;
                                    prVar16->y = *pfVar19;
                                    fVar11 = *pfVar23;
                                    prVar16->z = pfVar19[1];
                                    *pfVar25 = *(flex_t *)((intptr_t)pfVar23 + iVar12);
                                    *local_8 = *(flex_t *)((intptr_t)pfVar23 + iVar13);
                                    local_8 = local_8 + 1;
                                    *local_c = fVar11;
                                    local_30 = local_30 + 1;
                                    local_c = local_c + 1;
                                }
                            }
                            prVar20 = (rdVector3 *)(pfVar19 + -1);
                            local_2c = (flex_t *)(iVar12 + (intptr_t)pfVar23);
                            local_28 = (flex_t *)(iVar13 + (intptr_t)pfVar23);
                            pfVar19 = pfVar19 + 3;
                            numVertices = numVertices + -1;
                            pfVar22 = pfVar23 + 1;
                            pfVar25 = pfVar27;
                            prVar16 = prVar17;
                            pfVar27 = pDestRedIVert;
                            pfVar24 = pDestBlueIVert;
                            pfVar26 = pDestGreenIVert;
                            prVar17 = pDestVert;
                            prVar18 = pSourceVert;
                            local_1c = pfVar23;
                        } while (numVertices != 0);
                    }
                    pSourceVert = prVar18;
                    pDestVert = prVar17;
                    pDestGreenIVert = pfVar26;
                    pDestBlueIVert = pfVar24;
                    pDestRedIVert = pfVar27;
                    local_4 = local_30;
                    if ((intptr_t)local_30 < 3) {
                        return local_30;
                    }
                }
                if (pDestVert != vertices) {
                    prVar20 = pDestVert;
                    memcpy(vertices, prVar20, local_4 * sizeof(rdVector3));
                    
                    pfVar27 = pDestRedIVert;
                    memcpy(pR, pfVar27, local_4 * sizeof(flex_t));
                    
                    pfVar27 = pDestGreenIVert;
                    memcpy(pG, pfVar27, local_4 * sizeof(flex_t));
                    
                    pfVar27 = pDestBlueIVert;
                    memcpy(pB, pfVar27, local_4 * sizeof(flex_t));
                }
            }
        }
    }
    return local_4;
}


int rdClip_Face3GTRGB(const rdClipFrustum* NO_ALIAS pFrustum,rdVector3 *paVertices,rdVector2 *paUvs,flex_t *pR,flex_t *pG,flex_t *pB, int numVertices)
{
    INST_WORKBUFS
    INST_WORKBUFS_MOTS

    flex_t fVar1;
    flex_t fVar2;
    flex_t fVar3;
    flex_t fVar4;
    flex_t fVar5;
    flex_t fVar6;
    flex_t fVar7;
    flex_t fVar8;
    flex_t fVar9;
    flex_t fVar10;
    flex_t fVar11;
    flex_t fVar12;
    flex_t fVar13;
    flex_t fVar14;
    flex_t fVar15;
    intptr_t iVar16;
    intptr_t iVar17;
    rdVector3 *prVar18;
    rdVector3 *prVar19;
    rdVector3 *prVar20;
    flex_t *pfVar21;
    flex_t *pfVar23;
    flex_t *pfVar24;
    rdVector2 *prVar25;
    intptr_t iVar26;
    intptr_t iVar27;
    rdVector2 *prVar28;
    flex_t *pfVar29;
    flex_t *pfVar30;
    rdVector2 *prVar31;
    rdVector2 *prVar32;
    rdVector2 *prVar33;
    flex_t *pfVar34;
    intptr_t local_44;
    rdVector3 *local_40;
    flex_t *local_3c;
    flex_t *local_38;
    flex_t *local_34;
    flex_t *local_30;
    flex_t *local_2c;
    rdVector2 *local_28;
    rdVector3 *local_24;
    flex_t *local_1c;
    intptr_t local_18;
    flex_t *local_14;
    flex_t *local_10;
    flex_t *local_c;
    uint32_t local_8;
    uint32_t local_4;
    
    rdClip_faceStatus = 0;
    local_44 = 0;
    local_3c = pR + numVertices + -1;
    local_38 = pG + numVertices + -1;
    pSourceBlueIVert = pB;
    local_40 = paVertices + numVertices + -1;
    pSourceVert = paVertices;
    pDestVert = workVerts;
    pSourceTVert = paUvs;
    pDestTVert = workTVerts;
    pSourceRedIVert = pR;
    pSourceGreenIVert = pG;
    pDestRedIVert = workRedIVerts;
    pDestGreenIVert = workGreenIVerts;
    pDestBlueIVert = workBlueIVerts;
    local_24 = paVertices;
    if (0 < numVertices) {
        local_30 = workBlueIVerts;
        local_2c = workGreenIVerts;
        iVar26 = (intptr_t)pR - (intptr_t)pB;
        local_10 = workRedIVerts;
        iVar27 = (intptr_t)pG - (intptr_t)pB;
        local_18 = numVertices;
        pfVar34 = pB;
        prVar19 = workVerts;
        prVar25 = paUvs;
        prVar33 = paUvs + numVertices + -1;
        prVar28 = workTVerts;
        local_34 = pB + numVertices + -1;
        do {
            prVar31 = prVar25;
            pfVar30 = pfVar34;
            fVar14 = pFrustum->nearLeft * local_40->y;
            fVar15 = pFrustum->nearLeft * local_24->y;
            if ((fVar14 <= local_40->x) || (prVar18 = prVar19, prVar32 = prVar28, fVar15 <= local_24->x)) {
                if (((local_40->x != fVar14) && (local_24->x != fVar15)) && ((local_40->x < fVar14 || (local_24->x < fVar15)))) {
                    fVar14 = local_24->y - local_40->y;
                    fVar1 = local_24->x - local_40->x;
                    fVar7 = pFrustum->nearLeft * fVar14 - fVar1;
                    fVar8 = local_24->y * local_40->x - local_40->y * local_24->x;
                    if (fVar7 != 0.0) {
                        fVar8 = fVar8 / fVar7;
                    }
                    fVar7 = pFrustum->nearLeft * fVar8;
                    fVar2 = fVar14;
                    if (fVar14 < 0.0) {
                        fVar2 = -fVar14;
                    }
                    fVar3 = fVar1;
                    if (fVar1 < 0.0) {
                        fVar3 = -fVar1;
                    }
                    if ((uint16_t)((uint16_t)(fVar2 < fVar3) << 8 | (uint16_t)(fVar2 == fVar3) << 0xe) == 0) {
                        fVar14 = (fVar8 - local_40->y) / fVar14;
                    }
                    else {
                        fVar14 = (fVar7 - local_40->x) / fVar1;
                    }
                    fVar1 = prVar31->x;
                    fVar2 = prVar33->x;
                    fVar3 = *(flex_t *)(iVar26 + (intptr_t)pfVar30);
                    fVar4 = *(flex_t *)(iVar27 + (intptr_t)pfVar30);
                    fVar5 = prVar33->x;
                    fVar6 = *pfVar30;
                    prVar19->x = fVar7;
                    prVar19->y = fVar8;
                    fVar7 = local_24->z;
                    prVar28->x = (fVar1 - fVar2) * fVar14 + fVar5;
                    fVar1 = prVar31->y;
                    fVar8 = *local_3c;
                    fVar2 = *local_38;
                    fVar5 = *local_34;
                    fVar9 = prVar33->y;
                    fVar10 = prVar33->y;
                    fVar11 = *local_3c;
                    fVar12 = *local_38;
                    fVar13 = *local_34;
                    prVar19->z = (fVar7 - local_40->z) * fVar14 + local_40->z;
                    prVar28->y = (fVar1 - fVar9) * fVar14 + fVar10;
                    *local_10 = (fVar3 - fVar8) * fVar14 + fVar11;
                    *local_2c = (fVar4 - fVar2) * fVar14 + fVar12;
                    prVar19 = prVar19 + 1;
                    *local_30 = (fVar6 - fVar5) * fVar14 + fVar13;
                    prVar28 = prVar28 + 1;
                    local_44 = local_44 + 1;
                    local_10 = local_10 + 1;
                    local_2c = local_2c + 1;
                    local_30 = local_30 + 1;
                    rdClip_faceStatus = rdClip_faceStatus | CLIPSTAT_LEFT;
                }
                prVar18 = prVar19;
                prVar32 = prVar28;
                if (fVar15 <= local_24->x) {
                    prVar18 = prVar19 + 1;
                    prVar32 = prVar28 + 1;
                    prVar19->x = local_24->x;
                    prVar19->y = local_24->y;
                    prVar19->z = local_24->z;
                    prVar28->x = prVar31->x;
                    prVar28->y = prVar31->y;
                    *local_10 = *(flex_t *)(iVar26 + (intptr_t)pfVar30);
                    local_10 = local_10 + 1;
                    *local_2c = *(flex_t *)(iVar27 + (intptr_t)pfVar30);
                    *local_30 = *pfVar30;
                    local_44 = local_44 + 1;
                    local_2c = local_2c + 1;
                    local_30 = local_30 + 1;
                }
            }
            local_3c = (flex_t *)(iVar26 + (intptr_t)pfVar30);
            local_38 = (flex_t *)(iVar27 + (intptr_t)pfVar30);
            local_18 = local_18 + -1;
            pfVar34 = pfVar30 + 1;
            prVar19 = prVar18;
            prVar25 = prVar31 + 1;
            prVar33 = prVar31;
            prVar28 = prVar32;
            local_40 = local_24;
            local_34 = pfVar30;
            local_24 = local_24 + 1;
        } while (local_18 != 0);
    }
    local_c = (flex_t *)local_44;
    if (2 < (intptr_t)local_44) {
        pDestVert = paVertices;
        pSourceVert = workVerts;
        pDestTVert = paUvs;
        pSourceTVert = workTVerts;
        pDestRedIVert = pR;
        pSourceRedIVert = workRedIVerts;
        pDestGreenIVert = pG;
        pSourceGreenIVert = workGreenIVerts;
        pDestBlueIVert = pB;
        pSourceBlueIVert = workBlueIVerts;
        local_44 = 0;
        local_3c = pSourceRedIVert + ((intptr_t)local_c - 1);
        local_38 = pSourceGreenIVert + ((intptr_t)local_c - 1);
        if (0 < (intptr_t)local_c) {
            local_14 = pB;
            local_10 = pR;
            iVar27 = (intptr_t)pSourceRedIVert - (intptr_t)pSourceBlueIVert;
            iVar26 = (intptr_t)pSourceGreenIVert - (intptr_t)pSourceBlueIVert;
            local_1c = pG;
            prVar19 = paVertices;
            pfVar34 = pSourceBlueIVert;
            prVar25 = pSourceTVert + ((intptr_t)local_c - 1);
            prVar18 = pSourceVert;
            prVar33 = paUvs;
            prVar28 = pSourceTVert;
            local_40 = pSourceVert + ((intptr_t)local_c - 1);
            local_34 = pSourceBlueIVert + ((intptr_t)local_c - 1);
            do {
                prVar20 = prVar18;
                pfVar30 = pfVar34;
                fVar14 = pFrustum->right * local_40->y;
                fVar15 = pFrustum->right * prVar20->y;
                if (((uint16_t)((uint16_t)(local_40->x < fVar14) << 8 | (uint16_t)(local_40->x == fVar14) << 0xe) != 0) || (prVar18 = prVar19, prVar31 = prVar33, (uint16_t)((uint16_t)(prVar20->x < fVar15) << 8 | (uint16_t)(prVar20->x == fVar15) << 0xe) != 0)) {
                    if (((local_40->x != fVar14) && (prVar20->x != fVar15)) && (((uint16_t)((uint16_t)(local_40->x < fVar14) << 8 | (uint16_t)(local_40->x == fVar14) << 0xe) == 0 || ((uint16_t)((uint16_t)(prVar20->x < fVar15) << 8 | (uint16_t)(prVar20->x == fVar15) << 0xe) == 0)))) {
                        fVar14 = prVar20->y - local_40->y;
                        fVar1 = prVar20->x - local_40->x;
                        fVar7 = pFrustum->right * fVar14 - fVar1;
                        fVar8 = prVar20->y * local_40->x - local_40->y * prVar20->x;
                        if (fVar7 != 0.0) {
                            fVar8 = fVar8 / fVar7;
                        }
                        fVar7 = pFrustum->right * fVar8;
                        fVar2 = fVar14;
                        if (fVar14 < 0.0) {
                            fVar2 = -fVar14;
                        }
                        fVar3 = fVar1;
                        if (fVar1 < 0.0) {
                            fVar3 = -fVar1;
                        }
                        if ((uint16_t)((uint16_t)(fVar2 < fVar3) << 8 | (uint16_t)(fVar2 == fVar3) << 0xe) == 0) {
                            fVar14 = (fVar8 - local_40->y) / fVar14;
                        }
                        else {
                            fVar14 = (fVar7 - local_40->x) / fVar1;
                        }
                        fVar1 = prVar28->x;
                        fVar2 = prVar25->x;
                        fVar3 = *(flex_t *)(iVar27 + (intptr_t)pfVar30);
                        fVar4 = *(flex_t *)(iVar26 + (intptr_t)pfVar30);
                        fVar5 = prVar25->x;
                        fVar6 = *pfVar30;
                        prVar19->x = fVar7;
                        prVar19->y = fVar8;
                        fVar7 = prVar20->z;
                        prVar33->x = (fVar1 - fVar2) * fVar14 + fVar5;
                        fVar1 = prVar28->y;
                        fVar8 = *local_3c;
                        fVar2 = *local_38;
                        fVar5 = *local_34;
                        fVar9 = prVar25->y;
                        fVar10 = prVar25->y;
                        fVar11 = *local_3c;
                        fVar12 = *local_38;
                        fVar13 = *local_34;
                        prVar19->z = (fVar7 - local_40->z) * fVar14 + local_40->z;
                        prVar33->y = (fVar1 - fVar9) * fVar14 + fVar10;
                        *local_10 = (fVar3 - fVar8) * fVar14 + fVar11;
                        *local_1c = (fVar4 - fVar2) * fVar14 + fVar12;
                        prVar19 = prVar19 + 1;
                        *local_14 = (fVar6 - fVar5) * fVar14 + fVar13;
                        prVar33 = prVar33 + 1;
                        local_44 = local_44 + 1;
                        local_10 = local_10 + 1;
                        local_1c = local_1c + 1;
                        local_14 = local_14 + 1;
                        rdClip_faceStatus = rdClip_faceStatus | CLIPSTAT_RIGHT;
                    }
                    prVar18 = prVar19;
                    prVar31 = prVar33;
                    if ((uint16_t)((uint16_t)(prVar20->x < fVar15) << 8 | (uint16_t)(prVar20->x == fVar15) << 0xe) != 0) {
                        prVar18 = prVar19 + 1;
                        prVar31 = prVar33 + 1;
                        prVar19->x = prVar20->x;
                        prVar19->y = prVar20->y;
                        prVar19->z = prVar20->z;
                        prVar33->x = prVar28->x;
                        prVar33->y = prVar28->y;
                        *local_10 = *(flex_t *)(iVar27 + (intptr_t)pfVar30);
                        local_10 = local_10 + 1;
                        *local_1c = *(flex_t *)(iVar26 + (intptr_t)pfVar30);
                        *local_14 = *pfVar30;
                        local_44 = local_44 + 1;
                        local_1c = local_1c + 1;
                        local_14 = local_14 + 1;
                    }
                }
                local_3c = (flex_t *)(iVar27 + (intptr_t)pfVar30);
                local_38 = (flex_t *)(iVar26 + (intptr_t)pfVar30);
                local_c = (flex_t *)((intptr_t)local_c - 1);
                prVar19 = prVar18;
                pfVar34 = pfVar30 + 1;
                prVar25 = prVar28;
                prVar18 = prVar20 + 1;
                prVar33 = prVar31;
                prVar28 = prVar28 + 1;
                local_40 = prVar20;
                local_34 = pfVar30;
            } while (local_c != (flex_t *)0x0);
        }
        local_4 = local_44;
        local_10 = pSourceRedIVert;
        prVar25 = pSourceTVert;
        local_1c = pSourceGreenIVert;
        pfVar34 = pDestBlueIVert;
        local_c = pSourceBlueIVert;
        if ((intptr_t)local_44 < 3) {
            return local_44;
        }
        pSourceTVert = pDestTVert;
        pSourceRedIVert = pDestRedIVert;
        pSourceGreenIVert = pDestGreenIVert;
        pDestBlueIVert = pSourceBlueIVert;
        pSourceBlueIVert = pfVar34;
        local_44 = 0;
        local_40 = pDestVert + (local_4 - 1);
        local_3c = pDestRedIVert + (local_4 - 1);
        local_38 = pDestGreenIVert + (local_4 - 1);
        if ((intptr_t)local_4 < 1) {
            local_8 = 0;
            pDestRedIVert = local_10;
            pDestGreenIVert = local_1c;
            pDestTVert = prVar25;
            prVar19 = pSourceVert;
            pSourceVert = pDestVert;
        }
        else {
            pfVar30 = &pDestVert->z;
            iVar27 = (intptr_t)pDestRedIVert - (intptr_t)pfVar34;
            iVar26 = (intptr_t)pDestGreenIVert - (intptr_t)pfVar34;
            prVar18 = pSourceVert;
            prVar33 = pDestTVert;
            prVar28 = pDestTVert + (local_4 - 1);
            pDestRedIVert = local_10;
            pDestGreenIVert = local_1c;
            pDestTVert = prVar25;
            prVar19 = pSourceVert;
            pSourceVert = pDestVert;
            local_34 = pfVar34 + (local_4 - 1);
            do {
                pDestVert = prVar19;
                prVar31 = prVar33;
                pfVar23 = pfVar34;
                fVar14 = pFrustum->nearTop * local_40->y;
                fVar15 = pfVar30[-1] * pFrustum->nearTop;
                if (((uint16_t)((uint16_t)(local_40->z < fVar14) << 8 | (uint16_t)(local_40->z == fVar14) << 0xe) != 0) || (prVar19 = prVar18, prVar32 = prVar25, (uint16_t)((uint16_t)(*pfVar30 < fVar15) << 8 | (uint16_t)(*pfVar30 == fVar15) << 0xe) != 0)) {
                    if (((local_40->z != fVar14) && (*pfVar30 != fVar15)) && (((uint16_t)((uint16_t)(local_40->z < fVar14) << 8 | (uint16_t)(local_40->z == fVar14) << 0xe) == 0 || ((uint16_t)((uint16_t)(*pfVar30 < fVar15) << 8 | (uint16_t)(*pfVar30 == fVar15) << 0xe) == 0)))) {
                        fVar14 = pfVar30[-1] - local_40->y;
                        fVar1 = *pfVar30 - local_40->z;
                        fVar7 = pFrustum->nearTop * fVar14 - fVar1;
                        fVar8 = local_40->z * pfVar30[-1] - local_40->y * *pfVar30;
                        if (fVar7 != 0.0) {
                            fVar8 = fVar8 / fVar7;
                        }
                        fVar7 = pFrustum->nearTop * fVar8;
                        fVar2 = fVar14;
                        if (fVar14 < 0.0) {
                            fVar2 = -fVar14;
                        }
                        fVar3 = fVar1;
                        if (fVar1 < 0.0) {
                            fVar3 = -fVar1;
                        }
                        if ((uint16_t)((uint16_t)(fVar2 < fVar3) << 8 | (uint16_t)(fVar2 == fVar3) << 0xe) == 0) {
                            fVar14 = (fVar8 - local_40->y) / fVar14;
                        }
                        else {
                            fVar14 = (fVar7 - local_40->z) / fVar1;
                        }
                        fVar1 = ((rdVector3 *)(pfVar30 + -2))->x;
                        fVar2 = local_40->x;
                        fVar3 = *(flex_t *)((intptr_t)pfVar23 + iVar27);
                        fVar4 = *(flex_t *)((intptr_t)pfVar23 + iVar26);
                        fVar5 = *pfVar23;
                        fVar6 = *local_3c;
                        fVar9 = *local_38;
                        prVar25->x = (prVar31->x - prVar28->x) * fVar14 + prVar28->x;
                        fVar10 = prVar31->y;
                        fVar11 = *local_34;
                        fVar12 = prVar28->y;
                        local_44 = local_44 + 1;
                        prVar18->x = (fVar1 - fVar2) * fVar14 + local_40->x;
                        prVar18->y = fVar8;
                        fVar1 = prVar28->y;
                        fVar8 = *local_3c;
                        fVar2 = *local_38;
                        fVar13 = *local_34;
                        prVar18->z = fVar7;
                        prVar25->y = (fVar10 - fVar12) * fVar14 + fVar1;
                        *local_10 = (fVar3 - fVar6) * fVar14 + fVar8;
                        local_10 = local_10 + 1;
                        prVar18 = prVar18 + 1;
                        *local_1c = (fVar4 - fVar9) * fVar14 + fVar2;
                        prVar25 = prVar25 + 1;
                        local_1c = local_1c + 1;
                        *local_c = (fVar5 - fVar11) * fVar14 + fVar13;
                        rdClip_faceStatus = rdClip_faceStatus | 4;
                        local_c = local_c + 1;
                    }
                    prVar19 = prVar18;
                    prVar32 = prVar25;
                    if ((uint16_t)((uint16_t)(*pfVar30 < fVar15) << 8 | (uint16_t)(*pfVar30 == fVar15) << 0xe) != 0) {
                        prVar19 = prVar18 + 1;
                        prVar32 = prVar25 + 1;
                        prVar18->x = ((rdVector3 *)(pfVar30 + -2))->x;
                        prVar18->y = pfVar30[-1];
                        prVar18->z = *pfVar30;
                        prVar25->x = prVar31->x;
                        prVar25->y = prVar31->y;
                        *local_10 = *(flex_t *)((intptr_t)pfVar23 + iVar27);
                        local_10 = local_10 + 1;
                        *local_1c = *(flex_t *)((intptr_t)pfVar23 + iVar26);
                        *local_c = *pfVar23;
                        local_44 = local_44 + 1;
                        local_1c = local_1c + 1;
                        local_c = local_c + 1;
                    }
                }
                local_40 = (rdVector3 *)(pfVar30 + -2);
                local_3c = (flex_t *)(iVar27 + (intptr_t)pfVar23);
                local_38 = (flex_t *)(iVar26 + (intptr_t)pfVar23);
                pfVar30 = pfVar30 + 3;
                local_4 = local_4 - 1;
                prVar18 = prVar19;
                pfVar34 = pfVar23 + 1;
                prVar33 = prVar31 + 1;
                prVar28 = prVar31;
                local_8 = local_44;
                prVar25 = prVar32;
                prVar19 = pDestVert;
                local_34 = pfVar23;
            } while (local_4 != 0);
        }
        pDestVert = prVar19;
        local_c = pSourceRedIVert;
        prVar25 = pSourceTVert;
        local_1c = pSourceGreenIVert;
        pfVar34 = pDestBlueIVert;
        local_10 = pSourceBlueIVert;
        if ((intptr_t)local_8 < 3) {
            return local_8;
        }
        local_44 = 0;
        pSourceTVert = pDestTVert;
        pSourceRedIVert = pDestRedIVert;
        pSourceGreenIVert = pDestGreenIVert;
        pDestBlueIVert = pSourceBlueIVert;
        pSourceBlueIVert = pfVar34;
        local_38 = pDestGreenIVert + (local_8 - 1);
        local_40 = pDestVert + (local_8 - 1);
        local_28 = pDestTVert + (local_8 - 1);
        local_3c = pDestRedIVert + (local_8 - 1);
        pfVar30 = local_c;
        pfVar23 = local_1c;
        prVar33 = prVar25;
        prVar19 = pSourceVert;
        prVar18 = pDestVert;
        if (0 < (intptr_t)local_8) {
            iVar26 = (intptr_t)pDestRedIVert - (intptr_t)pfVar34;
            iVar27 = (intptr_t)pDestGreenIVert - (intptr_t)pfVar34;
            pfVar21 = &pDestVert->z;
            prVar20 = pSourceVert;
            prVar28 = pDestTVert;
            pfVar29 = local_c;
            pDestRedIVert = local_c;
            pDestGreenIVert = local_1c;
            pDestTVert = prVar25;
            prVar19 = pSourceVert;
            pSourceVert = pDestVert;
            local_34 = pfVar34 + (local_8 - 1);
            do {
                pDestVert = prVar19;
                prVar31 = prVar28;
                pfVar24 = pfVar34;
                fVar14 = pFrustum->bottom * local_40->y;
                fVar15 = pfVar21[-1] * pFrustum->bottom;
                pfVar30 = pfVar29;
                if ((fVar14 <= local_40->z) || (fVar15 <= *pfVar21)) {
                    prVar19 = prVar20;
                    prVar33 = prVar25;
                    if (((local_40->z != fVar14) && (*pfVar21 != fVar15)) && ((local_40->z < fVar14 || (*pfVar21 < fVar15)))) {
                        fVar14 = pfVar21[-1] - local_40->y;
                        fVar1 = *pfVar21 - local_40->z;
                        fVar7 = pFrustum->bottom * fVar14 - fVar1;
                        fVar8 = local_40->z * pfVar21[-1] - local_40->y * *pfVar21;
                        if (fVar7 != 0.0) {
                            fVar8 = fVar8 / fVar7;
                        }
                        fVar7 = pFrustum->bottom * fVar8;
                        fVar2 = fVar14;
                        if (fVar14 < 0.0) {
                            fVar2 = -fVar14;
                        }
                        fVar3 = fVar1;
                        if (fVar1 < 0.0) {
                            fVar3 = -fVar1;
                        }
                        if ((uint16_t)((uint16_t)(fVar2 < fVar3) << 8 | (uint16_t)(fVar2 == fVar3) << 0xe) == 0) {
                            fVar14 = (fVar8 - local_40->y) / fVar14;
                        }
                        else {
                            fVar14 = (fVar7 - local_40->z) / fVar1;
                        }
                        fVar1 = ((rdVector3 *)(pfVar21 + -2))->x;
                        fVar2 = local_40->x;
                        fVar3 = *(flex_t *)((intptr_t)pfVar24 + iVar26);
                        fVar4 = *(flex_t *)((intptr_t)pfVar24 + iVar27);
                        fVar5 = *pfVar24;
                        fVar6 = *local_3c;
                        fVar9 = *local_38;
                        prVar25->x = (prVar31->x - local_28->x) * fVar14 + local_28->x;
                        fVar10 = prVar31->y;
                        fVar11 = *local_34;
                        local_44 = local_44 + 1;
                        fVar12 = local_28->y;
                        prVar20->x = (fVar1 - fVar2) * fVar14 + local_40->x;
                        prVar20->y = fVar8;
                        fVar1 = local_28->y;
                        fVar8 = *local_3c;
                        fVar2 = *local_38;
                        prVar19 = prVar20 + 1;
                        prVar33 = prVar25 + 1;
                        pfVar30 = pfVar29 + 1;
                        fVar13 = *local_34;
                        prVar20->z = fVar7;
                        prVar25->y = (fVar10 - fVar12) * fVar14 + fVar1;
                        *pfVar29 = (fVar3 - fVar6) * fVar14 + fVar8;
                        *local_1c = (fVar4 - fVar9) * fVar14 + fVar2;
                        *local_10 = (fVar5 - fVar11) * fVar14 + fVar13;
                        local_1c = local_1c + 1;
                        local_10 = local_10 + 1;
                        rdClip_faceStatus = rdClip_faceStatus | 8;
                        local_c = pfVar30;
                    }
                    prVar20 = prVar19;
                    prVar25 = prVar33;
                    if (fVar15 <= *pfVar21) {
                        prVar20 = prVar19 + 1;
                        prVar25 = prVar33 + 1;
                        prVar19->x = ((rdVector3 *)(pfVar21 + -2))->x;
                        prVar19->y = pfVar21[-1];
                        pfVar30 = local_c + 1;
                        prVar19->z = *pfVar21;
                        prVar33->x = prVar31->x;
                        prVar33->y = prVar31->y;
                        *local_c = *(flex_t *)((intptr_t)pfVar24 + iVar26);
                        *local_1c = *(flex_t *)((intptr_t)pfVar24 + iVar27);
                        *local_10 = *pfVar24;
                        local_44 = local_44 + 1;
                        local_1c = local_1c + 1;
                        local_10 = local_10 + 1;
                        local_c = pfVar30;
                    }
                }
                local_40 = (rdVector3 *)(pfVar21 + -2);
                local_3c = (flex_t *)(iVar26 + (intptr_t)pfVar24);
                local_38 = (flex_t *)(iVar27 + (intptr_t)pfVar24);
                pfVar21 = pfVar21 + 3;
                local_8 = local_8 - 1;
                pfVar34 = pfVar24 + 1;
                prVar28 = prVar31 + 1;
                pfVar29 = pfVar30;
                pfVar30 = pDestRedIVert;
                pfVar23 = pDestGreenIVert;
                prVar33 = pDestTVert;
                prVar19 = pDestVert;
                prVar18 = pSourceVert;
                local_34 = pfVar24;
                local_28 = prVar31;
            } while (local_8 != 0);
        }
        pSourceVert = prVar18;
        pDestVert = prVar19;
        pDestTVert = prVar33;
        pDestGreenIVert = pfVar23;
        pDestRedIVert = pfVar30;
        numVertices = local_44;
        prVar18 = pSourceVert;
        prVar19 = pDestVert;
        prVar33 = pDestTVert;
        pfVar23 = pDestGreenIVert;
        local_10 = pSourceRedIVert;
        prVar25 = pSourceTVert;
        local_1c = pSourceGreenIVert;
        pfVar30 = pDestBlueIVert;
        pfVar34 = pDestRedIVert;
        local_c = pSourceBlueIVert;
        if (2 < (intptr_t)local_44) {
            pDestVert = pSourceVert;
            pSourceVert = prVar19;
            pDestTVert = pSourceTVert;
            pSourceTVert = prVar33;
            local_44 = 0;
            pDestRedIVert = pSourceRedIVert;
            pSourceRedIVert = pfVar34;
            local_3c = pfVar34 + (numVertices - 1);
            pDestGreenIVert = pSourceGreenIVert;
            pSourceGreenIVert = pfVar23;
            local_38 = pfVar23 + (numVertices - 1);
            pDestBlueIVert = pSourceBlueIVert;
            pSourceBlueIVert = pfVar30;
            prVar20 = prVar19 + (numVertices - 1);
            if (0 < numVertices) {
                pfVar21 = &prVar19->y;
                iVar26 = (intptr_t)pfVar34 - (intptr_t)pfVar30;
                iVar27 = (intptr_t)pfVar23 - (intptr_t)pfVar30;
                local_34 = pfVar30 + (numVertices - 1);
                local_28 = prVar33 + (numVertices - 1);
                do {
                    prVar28 = prVar33;
                    pfVar34 = pfVar30;
                    if ((pFrustum->zNear <= prVar20->y) || (pFrustum->zNear <= *pfVar21)) {
                        prVar19 = prVar18;
                        prVar33 = prVar25;
                        if (((prVar20->y != pFrustum->zNear) && (*pfVar21 != pFrustum->zNear)) && ((prVar20->y < pFrustum->zNear || (*pfVar21 < pFrustum->zNear)))) {
                            fVar13 = (pFrustum->zNear - prVar20->y) / (*pfVar21 - prVar20->y);
                            prVar18->y = pFrustum->zNear;
                            local_44 = local_44 + 1;
                            fVar14 = prVar28->x;
                            fVar15 = local_28->x;
                            fVar1 = local_28->x;
                            fVar7 = *(flex_t *)((intptr_t)pfVar34 + iVar26);
                            fVar8 = *(flex_t *)((intptr_t)pfVar34 + iVar27);
                            fVar2 = *pfVar34;
                            prVar18->z = (pfVar21[1] - prVar20->z) * fVar13 + prVar20->z;
                            fVar3 = ((rdVector3 *)(pfVar21 + -1))->x;
                            fVar4 = prVar20->x;
                            fVar5 = *local_3c;
                            fVar6 = *local_38;
                            fVar9 = *local_34;
                            prVar25->x = (fVar14 - fVar15) * fVar13 + fVar1;
                            fVar14 = prVar28->y;
                            fVar15 = local_28->y;
                            fVar1 = local_28->y;
                            prVar19 = prVar18 + 1;
                            prVar33 = prVar25 + 1;
                            fVar10 = *local_3c;
                            fVar11 = *local_38;
                            fVar12 = *local_34;
                            prVar18->x = (fVar3 - fVar4) * fVar13 + prVar20->x;
                            prVar25->y = (fVar14 - fVar15) * fVar13 + fVar1;
                            *local_10 = (fVar7 - fVar5) * fVar13 + fVar10;
                            local_10 = local_10 + 1;
                            *local_1c = (fVar8 - fVar6) * fVar13 + fVar11;
                            *local_c = (fVar2 - fVar9) * fVar13 + fVar12;
                            local_1c = local_1c + 1;
                            local_c = local_c + 1;
                            rdClip_faceStatus = rdClip_faceStatus | 1;
                        }
                        prVar18 = prVar19;
                        prVar25 = prVar33;
                        if (pFrustum->zNear <= *pfVar21) {
                            prVar18 = prVar19 + 1;
                            prVar25 = prVar33 + 1;
                            prVar19->x = ((rdVector3 *)(pfVar21 + -1))->x;
                            prVar19->y = *pfVar21;
                            prVar19->z = pfVar21[1];
                            prVar33->x = prVar28->x;
                            prVar33->y = prVar28->y;
                            *local_10 = *(flex_t *)((intptr_t)pfVar34 + iVar26);
                            *local_1c = *(flex_t *)((intptr_t)pfVar34 + iVar27);
                            *local_c = *pfVar34;
                            local_44 = local_44 + 1;
                            local_10 = local_10 + 1;
                            local_1c = local_1c + 1;
                            local_c = local_c + 1;
                        }
                    }
                    prVar20 = (rdVector3 *)(pfVar21 + -1);
                    local_3c = (flex_t *)(iVar26 + (intptr_t)pfVar34);
                    local_38 = (flex_t *)(iVar27 + (intptr_t)pfVar34);
                    pfVar21 = pfVar21 + 3;
                    numVertices = numVertices - 1;
                    pfVar30 = pfVar34 + 1;
                    prVar33 = prVar28 + 1;
                    local_34 = pfVar34;
                    local_28 = prVar28;
                } while (numVertices != 0);
            }
            numVertices = local_44;
            prVar18 = pSourceVert;
            prVar19 = pDestVert;
            prVar33 = pDestTVert;
            pfVar23 = pDestGreenIVert;
            local_10 = pSourceRedIVert;
            prVar25 = pSourceTVert;
            local_14 = pSourceGreenIVert;
            pfVar30 = pDestBlueIVert;
            pfVar34 = pDestRedIVert;
            local_c = pSourceBlueIVert;
            if ((intptr_t)local_44 < 3) {
                rdClip_faceStatus = rdClip_faceStatus | CLIPSTAT_NONE_VISIBLE;
                return local_44;
            }
            if (pFrustum->bClipFar) {
                pDestVert = pSourceVert;
                pSourceVert = prVar19;
                pDestTVert = pSourceTVert;
                pSourceTVert = prVar33;
                pDestRedIVert = pSourceRedIVert;
                pSourceRedIVert = pfVar34;
                pDestGreenIVert = pSourceGreenIVert;
                pSourceGreenIVert = pfVar23;
                pDestBlueIVert = pSourceBlueIVert;
                pSourceBlueIVert = pfVar30;
                local_3c = pfVar34 + (local_44 - 1);
                local_38 = pfVar23 + (local_44 - 1);
                prVar20 = prVar19 + (local_44 - 1);
                iVar26 = local_44 - 1;
                iVar27 = local_44 - 1;
                local_44 = 0;
                if (0 < numVertices) {
                    pfVar21 = &prVar19->y;
                    iVar16 = (intptr_t)pfVar34 - (intptr_t)pfVar30;
                    iVar17 = (intptr_t)pfVar23 - (intptr_t)pfVar30;
                    local_34 = pfVar30 + iVar27;
                    local_28 = prVar33 + iVar26;
                    do {
                        prVar28 = prVar33;
                        pfVar34 = pfVar30;
                        fVar14 = pFrustum->zFar;
                        if (((uint16_t)((uint16_t)(prVar20->y < fVar14) << 8 | (uint16_t)(prVar20->y == fVar14) << 0xe) != 0) || (fVar14 = pFrustum->zFar, (uint16_t)((uint16_t)(*pfVar21 < fVar14) << 8 | (uint16_t)(*pfVar21 == fVar14) << 0xe) != 0)) {
                            prVar19 = prVar18;
                            prVar33 = prVar25;
                            if (((prVar20->y != pFrustum->zFar) && (*pfVar21 != pFrustum->zFar)) && ((fVar14 = pFrustum->zFar, (uint16_t)((uint16_t)(prVar20->y < fVar14) << 8 | (uint16_t)(prVar20->y == fVar14) << 0xe) == 0 || (fVar14 = pFrustum->zFar, (uint16_t)((uint16_t)(*pfVar21 < fVar14) << 8 | (uint16_t)(*pfVar21 == fVar14) << 0xe) == 0)))) {
                                fVar13 = (pFrustum->zFar - prVar20->y) / (*pfVar21 - prVar20->y);
                                prVar18->y = pFrustum->zFar;
                                local_44 = local_44 + 1;
                                fVar14 = prVar28->x;
                                fVar15 = local_28->x;
                                fVar1 = local_28->x;
                                fVar7 = *(flex_t *)((intptr_t)pfVar34 + iVar16);
                                fVar8 = *(flex_t *)((intptr_t)pfVar34 + iVar17);
                                prVar18->z = (pfVar21[1] - prVar20->z) * fVar13 + prVar20->z;
                                fVar2 = ((rdVector3 *)(pfVar21 + -1))->x;
                                fVar3 = prVar20->x;
                                prVar25->x = (fVar14 - fVar15) * fVar13 + fVar1;
                                fVar14 = prVar28->y;
                                fVar15 = local_28->y;
                                fVar1 = *local_3c;
                                fVar4 = *pfVar34;
                                fVar5 = *local_38;
                                fVar6 = *local_34;
                                prVar19 = prVar18 + 1;
                                prVar33 = prVar25 + 1;
                                fVar9 = local_28->y;
                                fVar10 = *local_3c;
                                fVar11 = *local_38;
                                fVar12 = *local_34;
                                prVar18->x = (fVar2 - fVar3) * fVar13 + prVar20->x;
                                prVar25->y = (fVar14 - fVar15) * fVar13 + fVar9;
                                *local_10 = (fVar7 - fVar1) * fVar13 + fVar10;
                                local_10 = local_10 + 1;
                                *local_14 = (fVar8 - fVar5) * fVar13 + fVar11;
                                local_14 = local_14 + 1;
                                *local_c = (fVar4 - fVar6) * fVar13 + fVar12;
                                local_c = local_c + 1;
                                rdClip_faceStatus = rdClip_faceStatus | 2;
                            }
                            fVar14 = pFrustum->zFar;
                            prVar18 = prVar19;
                            prVar25 = prVar33;
                            if ((uint16_t)((uint16_t)(*pfVar21 < fVar14) << 8 | (uint16_t)(*pfVar21 == fVar14) << 0xe) != 0) {
                                prVar18 = prVar19 + 1;
                                prVar25 = prVar33 + 1;
                                prVar19->x = ((rdVector3 *)(pfVar21 + -1))->x;
                                prVar19->y = *pfVar21;
                                prVar19->z = pfVar21[1];
                                prVar33->x = prVar28->x;
                                prVar33->y = prVar28->y;
                                *local_10 = *(flex_t *)((intptr_t)pfVar34 + iVar16);
                                *local_14 = *(flex_t *)((intptr_t)pfVar34 + iVar17);
                                *local_c = *pfVar34;
                                local_44 = local_44 + 1;
                                local_10 = local_10 + 1;
                                local_14 = local_14 + 1;
                                local_c = local_c + 1;
                            }
                        }
                        prVar20 = (rdVector3 *)(pfVar21 + -1);
                        local_3c = (flex_t *)(iVar16 + (intptr_t)pfVar34);
                        local_38 = (flex_t *)(iVar17 + (intptr_t)pfVar34);
                        pfVar21 = pfVar21 + 3;
                        numVertices = numVertices - 1;
                        pfVar30 = pfVar34 + 1;
                        prVar33 = prVar28 + 1;
                        local_34 = pfVar34;
                        local_28 = prVar28;
                    } while (numVertices != 0);
                }
                if ((intptr_t)local_44 < 3) {
                    return local_44;
                }
            }
            if (pDestVert != paVertices) {
                memcpy(paVertices, pDestVert, local_44 * sizeof(rdVector3));
                memcpy(paUvs, pDestTVert, local_44 * sizeof(rdVector2));
                memcpy(pR, pDestRedIVert, local_44 * sizeof(flex_t));
                memcpy(pG, pDestGreenIVert, local_44 * sizeof(flex_t));
                memcpy(pB, pDestBlueIVert, local_44 * sizeof(flex_t));
                
                return local_44;
            }
        }
    }
    return local_44;
}
