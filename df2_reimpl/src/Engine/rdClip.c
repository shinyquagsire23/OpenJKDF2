#include "rdClip.h"

#include "rdCanvas.h"
#include "jk.h"

int rdClip_Line2(rdCanvas *canvas, signed int *pX1, signed int *pY1, signed int *pX2, signed int *pY2)
{
    unsigned int clipOutcodeX1Y1;
    signed int clipOutcodeX2Y2;
    signed int fY1_same_fY2;
    unsigned int clipCode;
    double x_clipped;
    double y_clipped;
    float fY1;
    float fX2;
    float fY2;
    float fX1;

    clipOutcodeX1Y1 = rdClip_CalcOutcode2(canvas, *pX1, *pY1);
    clipOutcodeX2Y2 = rdClip_CalcOutcode2(canvas, *pX2, *pY2);
    
    fX1 = (double)*pX1;
    fX2 = (double)*pX2;
    fY1 = (double)*pY1;
    fY2 = (double)*pY2;
    
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
            x_clipped = (fY2 == fY1) ? fX1 : (fX2 - fX1) / (fY2 - fY1) * ((double)canvas->yStart - fY1) + fX1;
            y_clipped = (double)canvas->yStart;
        }
        else if (clipCode & CLIP_BOTTOM)
        {
            x_clipped = (fY2 == fY1) ? fX1 : (fX2 - fX1) / (fY2 - fY1) * ((double)canvas->heightMinusOne - fY1) + fX1;
            y_clipped = (double)canvas->heightMinusOne;
        }
        else if (clipCode & CLIP_RIGHT)
        {
            x_clipped = (double)canvas->widthMinusOne;
            y_clipped = (fX2 == fX1) ? fY1 : (fY2 - fY1) / (fX2 - fX1) * ((double)canvas->widthMinusOne - fX1) + fY1;
        }
        else if (clipCode & CLIP_LEFT)
        {
            x_clipped = (double)canvas->xStart;
            y_clipped = (fX2 == fX1) ? fY1 : (float)((fY2 - fY1) / (fX2 - fX1) * ((double)canvas->xStart - fX1) + fY1);
        }

        if (clipCode == clipOutcodeX1Y1)
        {
            fX1 = x_clipped;
            fY1 = y_clipped;
            clipOutcodeX1Y1 = rdClip_CalcOutcode2(canvas, (int)x_clipped, (int)y_clipped);
        }
        else
        {
            fX2 = x_clipped;
            fY2 = y_clipped;
            clipOutcodeX2Y2 = rdClip_CalcOutcode2(canvas, (int)x_clipped, (int)y_clipped);
        }
    }
    
    *pX1 = (int)fX1;
    *pY1 = (int)fY1;
    *pX2 = (int)fX2;
    *pY2 = (int)fY2;
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
    if ( point->y < (double)clipFrustum->field_0.y )
        return 0;
    if (clipFrustum->field_0.x && point->y > (double)clipFrustum->field_0.z )
        return 0;

    float v4 = (rdCamera_pCurCamera->projectType == 1) ? (clipFrustum->field_24 * point->y) : (clipFrustum->field_C);
    if ( v4 > point->x )
        return 0;

    float v5 = (rdCamera_pCurCamera->projectType == 1) ? (clipFrustum->field_28 * point->y) : (clipFrustum->field_14);
    if ( v5 < point->x )
        return 0;

    float v6 = (rdCamera_pCurCamera->projectType == 1) ? (clipFrustum->field_1C * point->y) : (clipFrustum->field_10);
    if ( v6 < point->z )
        return 0;

    float v7 = (rdCamera_pCurCamera->projectType == 1) ? (clipFrustum->field_20 * point->y) : (clipFrustum->field_18);
    return v7 <= point->z;
}

int rdClip_Line3Project(rdClipFrustum *clipFrustum, rdVector3 *point1, rdVector3 *point2, int *out1, int *out2)
{
    double v10; // st7
    double v12; // st6
    double v13; // st7
    double v14; // st5
    double v15; // st6
    double v16; // st6
    double v17; // st7
    double v18; // st6
    double v23; // st6
    double v24; // st7
    double v25; // st5
    double v26; // st6
    double v27; // st6
    double v28; // st7
    double v29; // st6
    double v33; // st7
    double v36; // st6
    double v37; // st5
    double v40; // st4
    double v42; // st5
    double v43; // st4
    double v44; // st6
    double v46; // st7
    double v49; // st6
    double v50; // st5
    double v53; // st4
    double v55; // st5
    double v56; // st4
    double v57; // st6
    double v58; // rt1
    double v63; // st7
    double v66; // st6
    double v67; // st5
    double v70; // st4
    double v72; // st5
    double v73; // st4
    double v74; // st6
    double v76; // st7
    double v79; // st6
    double v80; // st5
    double v83; // st4
    double v85; // st5
    double v86; // st4
    double v87; // st6
    double v88; // rt2
    double v93; // st6
    double v94; // st7
    double v97; // st6
    double v98; // st5
    double v101; // st4
    double v103; // st5
    double v104; // st4
    double v105; // st7
    double v106; // rt0
    double v108; // st6
    double v109; // st7
    double v112; // st6
    double v113; // st5
    double v116; // st4
    double v118; // st5
    double v119; // st4
    double v120; // st7
    double v121; // rt0
    double v125; // st6
    double v126; // st7
    double v129; // st6
    double v130; // st5
    double v133; // st4
    double v135; // st5
    double v136; // st4
    double v137; // st7
    double v138; // rt1
    double v140; // st6
    double v141; // st7
    double v144; // st6
    double v145; // st5
    double v148; // st4
    double v150; // st5
    double v151; // st4
    double v152; // st7
    double v153; // rt1
    float frustuma; // [esp+10h] [ebp+4h]
    float frustumb; // [esp+10h] [ebp+4h]
    float frustumc; // [esp+10h] [ebp+4h]
    float frustumd; // [esp+10h] [ebp+4h]
    float frustume; // [esp+10h] [ebp+4h]
    float frustumf; // [esp+10h] [ebp+4h]
    float frustumg; // [esp+10h] [ebp+4h]
    float frustumh; // [esp+10h] [ebp+4h]
    float point1a; // [esp+14h] [ebp+8h]
    float point1b; // [esp+14h] [ebp+8h]
    float point1c; // [esp+14h] [ebp+8h]
    float point1d; // [esp+14h] [ebp+8h]
    float point1e; // [esp+14h] [ebp+8h]
    float point1f; // [esp+14h] [ebp+8h]
    float point1g; // [esp+14h] [ebp+8h]
    float point1h; // [esp+14h] [ebp+8h]
    float point1i; // [esp+14h] [ebp+8h]
    float point1j; // [esp+14h] [ebp+8h]
    float point1k; // [esp+14h] [ebp+8h]
    float point1l; // [esp+14h] [ebp+8h]
    float point2a; // [esp+18h] [ebp+Ch]
    float point2b; // [esp+18h] [ebp+Ch]
    float point2c; // [esp+18h] [ebp+Ch]
    float point2d; // [esp+18h] [ebp+Ch]
    float point2e; // [esp+18h] [ebp+Ch]
    float point2f; // [esp+18h] [ebp+Ch]
    float point2g; // [esp+18h] [ebp+Ch]
    float point2h; // [esp+18h] [ebp+Ch]

    if ( point1->y < (double)clipFrustum->field_0.y && point2->y < (double)clipFrustum->field_0.y )
        return 0;

    // TODO verify
    if (point1->y < (double)clipFrustum->field_0.y)
    {
        v12 = point2->z;
        v13 = (clipFrustum->field_0.y - point1->y) / (point2->y - point1->y);
        point1->y = clipFrustum->field_0.y;
        v14 = (v12 - point1->z) * v13 + point1->z;
        v15 = (point2->x - point1->x) * v13 + point1->x;
        point1->z = v14;
        point1->x = v15;
        if ( out1 )
            *out1 = 1;
    }
    else if ( point2->y < clipFrustum->field_0.y )
    {
        v16 = point2->x;
        v17 = (clipFrustum->field_0.y - point1->y) / (point2->y - point1->y);
        point2->y = clipFrustum->field_0.y;
        v18 = (v16 - point1->x) * v17 + point1->x;
        point2->z = (point2->z - point1->z) * v17 + point1->z;
        point2->x = v18;
        if ( out2 )
            *out2 = 1;
    }

    if (clipFrustum->field_0.x)
    {
        if ( point1->y > (double)clipFrustum->field_0.z && point2->y > (double)clipFrustum->field_0.z )
            return 0;

        // TODO verify
        if (point1->y <= (double)clipFrustum->field_0.z)
        {
            if ( point2->y > (double)clipFrustum->field_0.z )
            {
                v27 = point2->x;
                v28 = (clipFrustum->field_0.z - point1->y) / (point2->y - point1->y);
                point2->y = clipFrustum->field_0.z;
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
            v24 = (clipFrustum->field_0.z - point1->y) / (point2->y - point1->y);
            point1->y = clipFrustum->field_0.z;
            v25 = (v23 - point1->z) * v24 + point1->z;
            v26 = (point2->x - point1->x) * v24 + point1->x;
            point1->z = v25;
            point1->x = v26;
            if ( out1 )
                *out1 = 1;
        }
    }

    if (point1->x < clipFrustum->field_24 * point1->y && point2->x < clipFrustum->field_24 * point2->y)
        return 0;
    if (point1->x >= clipFrustum->field_24 * point1->y)
    {
        if ( point2->x < clipFrustum->field_24 * point2->y)
        {
            point1c = point2->y - point1->y;
            frustumb = point2->x - point1->x;
            v46 = point2->y * point1->x - point1->y * point2->x;
            point2b = clipFrustum->field_24 * point1c - frustumb;
            if (point2b != 0.0)
            {
                v46 = v46 / point2b;
            }
            v49 = clipFrustum->field_24 * v46;
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
        point2a = clipFrustum->field_24 * point1b - frustuma;
        if (point2a != 0.0)
        {
            v33 = v33 / point2a;
        }
        v36 = clipFrustum->field_24 * v33;
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
    point1d = clipFrustum->field_28 * point2->y;
    if (point1->x > clipFrustum->field_28 * point1->y && point2->x > (double)point1d )
        return 0;
    if (point1->x <= clipFrustum->field_28 * point1->y)
    {
        if ( point2->x > (double)point1d )
        {
            point1f = point2->y - point1->y;
            frustumd = point2->x - point1->x;
            v76 = point2->y * point1->x - point1->y * point2->x;
            point2d = clipFrustum->field_28 * point1f - frustumd;
            if (point2d != 0.0)
            {
                v76 = v76 / point2d;
            }
            v79 = clipFrustum->field_28 * v76;
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
        point2c = clipFrustum->field_28 * point1e - frustumc;
        if (point2c != 0.0)
        {
            v63 = v63 / point2c;
        }
        v66 = clipFrustum->field_28 * v63;
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
    point1g = clipFrustum->field_1C * point2->y;
    if (point1->z > clipFrustum->field_1C * point1->y && point2->z > (double)point1g )
        return 0;
    if (point1->z <= clipFrustum->field_1C * point1->y)
    {
        if ( point2->z > (double)point1g )
        {
            point1i = point2->y - point1->y;
            frustumf = point2->z - point1->z;
            v108 = point2->y * point1->z - point1->y * point2->z;
            v109 = v108;
            point2f = clipFrustum->field_1C * point1i - frustumf;
            if (point2f != 0.0)
            {
                v109 = v108 / point2f;
            }
            v112 = clipFrustum->field_1C * v109;
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
        point2e = clipFrustum->field_1C * point1h - frustume;
        if (point2e != 0.0)
        {
            v94 = v93 / point2e;
        }
        v97 = clipFrustum->field_1C * v94;
        v98 = point1h;
        if (v98 < 0.0)
            v98 = -v98;
        v101 = frustume;
        if (v101 < 0.0)
            v101 = -v101;
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
    point1j = clipFrustum->field_20 * point2->y;
    if (point1->z < clipFrustum->field_20 * point1->y && point2->z < (double)point1j )
        return 0;
    if (point1->z >= clipFrustum->field_20 * point1->y )
    {
        if ( point2->z < (double)point1j )
        {
            point1l = point2->y - point1->y;
            frustumh = point2->z - point1->z;
            v140 = point2->y * point1->z - point1->y * point2->z;
            v141 = v140;
            point2h = clipFrustum->field_20 * point1l - frustumh;
            if (point2h != 0.0)
            {
                v141 = v140 / point2h;
            }
            v144 = clipFrustum->field_20 * v141;
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
        point2g = clipFrustum->field_20 * point1k - frustumg;
        if (point2g != 0.0)
        {
            v126 = v125 / point2g;
        }
        v129 = clipFrustum->field_20 * v126;
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
    double v8; // st7
    double v10; // st6
    double v11; // st7
    double v12; // st5
    double v13; // st6
    double v14; // st6
    double v15; // st7
    double v16; // st6
    double v18; // st7
    double v21; // st6
    double v22; // st7
    double v23; // st5
    double v24; // st6
    double v25; // st6
    double v26; // st7
    double v27; // st6
    double v29; // st7
    double v31; // st7
    double v32; // st5
    double v33; // st6
    double v34; // st7
    double v35; // st5
    double v36; // st6
    double v38; // st7
    double v41; // st7
    double v42; // st5
    double v43; // st6
    double v44; // st7
    double v45; // st5
    double v46; // st6
    double v47; // st7
    double v48; // st5
    double v49; // st6
    double v50; // st7
    double v51; // st5
    double v52; // st6
    double v54; // st7
    double v56; // st7
    double v57; // st5
    double v58; // st6
    double v59; // st7
    double v60; // st5
    double v61; // st6
    float point1a; // [esp+14h] [ebp+8h]
    float point1b; // [esp+14h] [ebp+8h]
    float point1c; // [esp+14h] [ebp+8h]
    float point1d; // [esp+14h] [ebp+8h]

    if ( point1->y < (double)clipFrustum->field_0.y && point2->y < (double)clipFrustum->field_0.y )
        return 0;
    v8 = point2->y;
    if (point1->y < (double)clipFrustum->field_0.y)
    {
        v10 = point2->z;
        v11 = (clipFrustum->field_0.y - point1->y) / (v8 - point1->y);
        point1->y = clipFrustum->field_0.y;
        v12 = (v10 - point1->z) * v11 + point1->z;
        v13 = (point2->x - point1->x) * v11 + point1->x;
        point1->z = v12;
        point1->x = v13;
        if ( out1 )
            *out1 = 1;
    }
    else if ( v8 < clipFrustum->field_0.y )
    {
        v14 = point2->x;
        v15 = (clipFrustum->field_0.y - point1->y) / (point2->y - point1->y);
        point2->y = clipFrustum->field_0.y;
        v16 = (v14 - point1->x) * v15 + point1->x;
        point2->z = (point2->z - point1->z) * v15 + point1->z;
        point2->x = v16;
        if ( out2 )
            *out2 = 1;
    }
    if (clipFrustum->field_0.x)
    {
        if ( point1->y > (double)clipFrustum->field_0.z && point2->y > (double)clipFrustum->field_0.z )
            return 0;
        v18 = point2->y;
        if (point1->y <= (double)clipFrustum->field_0.z)
        {
            if ( v18 > clipFrustum->field_0.z )
            {
                v25 = point2->x;
                v26 = (clipFrustum->field_0.z - point1->y) / (point2->y - point1->y);
                point2->y = clipFrustum->field_0.z;
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
            v22 = (clipFrustum->field_0.z - point1->y) / (v18 - point1->y);
            point1->y = clipFrustum->field_0.z;
            v23 = (v21 - point1->z) * v22 + point1->z;
            v24 = (point2->x - point1->x) * v22 + point1->x;
            point1->z = v23;
            point1->x = v24;
            if ( out1 )
                *out1 = 1;
        }
    }
    point1a = clipFrustum->field_C;
    if ( point1->x < (double)point1a && point2->x < (double)point1a )
        return 0;
    v29 = point2->x;
    if (point1->x < (double)point1a)
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
    point1b = clipFrustum->field_14;
    if ( point1->x > (double)point1b && point2->x > (double)point1b )
        return 0;
    v38 = point2->x;
    if (point1->x <= (double)point1b)
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
    point1c = clipFrustum->field_10;
    if ( point1->z > (double)point1c && point2->z > (double)point1c )
        return 0;
    if ( point1->z <= (double)point1c )
    {
        if ( point2->z > (double)point1c )
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
    point1d = clipFrustum->field_18;
    if ( point1->z < (double)point1d && point2->z < (double)point1d )
        return 0;
    v54 = point2->z;
    if (point1->z >= (double)point1d)
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
    if ( rdCamera_pCurCamera->projectType == rdCameraProjectType_Ortho)
        ret = rdClip_Line3Project(clipFrustum, &vertex_out, &vertex_out2, out1, out2);
    else
        ret = rdClip_Line3Ortho(clipFrustum, &vertex_out, &vertex_out2, out1, out2);

    if ( !ret )
        return 0;

    rdCamera_pCurCamera->project(&project1, &vertex_out);
    rdCamera_pCurCamera->project(&project2, &vertex_out2);

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

int rdClip_SphereInFrustrum(rdClipFrustum *frust, rdVector3 *pos, float rad)
{
    int v5; // edi
    int v9; // esi
    double v10; // st7
    double v11; // st7
    double v12; // st7
    double v13; // st7
    float v14; // [esp+0h] [ebp-Ch]
    float v15; // [esp+4h] [ebp-8h]
    float v16; // [esp+8h] [ebp-4h]
    float v17; // [esp+8h] [ebp-4h]
    float frusta; // [esp+10h] [ebp+4h]
    float posa; // [esp+14h] [ebp+8h]
    float posb; // [esp+14h] [ebp+8h]
    float posc; // [esp+14h] [ebp+8h]
    float rada; // [esp+18h] [ebp+Ch]
    float radb; // [esp+18h] [ebp+Ch]

    v14 = rad + pos->y;
    v5 = 1;
    frusta = pos->y - rad;
    if (v14 < (double)frust->field_0.y)
        return 2;
    if ( frusta < (double)frust->field_0.y )
        v5 = 0;
    if (frust->field_0.x)
    {
        if ( frusta > (double)frust->field_0.z )
            return 2;
        if ( v14 > (double)frust->field_0.z )
            v5 = 0;
    }

    v15 = rad + pos->z;
    v16 = pos->z - rad;
    if ( rdCamera_pCurCamera->projectType == rdCameraProjectType_Ortho)
    {
        v10 = frust->field_1C * frusta;
        posa = frust->field_1C * v14;
    }
    else
    {
        v10 = frust->field_10;
        posa = frust->field_10;
    }
    if ( v16 > v10 && v16 > (double)posa )
        return 2;
    if ( v15 > v10 || v15 > (double)posa )
        v5 = 0;
    if ( rdCamera_pCurCamera->projectType == rdCameraProjectType_Ortho)
    {
        v11 = frust->field_20 * frusta;
        posb = frust->field_20 * v14;
    }
    else
    {
        v11 = frust->field_18;
        posb = frust->field_18;
    }
    if ( v15 < v11 && v15 < (double)posb )
        return 2;
    if ( v16 < v11 || v16 < (double)posb )
        v5 = 0;
    v17 = pos->x + rad;
    posc = pos->x - rad;
    if ( rdCamera_pCurCamera->projectType == rdCameraProjectType_Ortho)
    {
        v12 = frust->field_24 * frusta;
        rada = frust->field_24 * v14;
    }
    else
    {
        v12 = frust->field_C;
        rada = frust->field_C;
    }
    if ( v17 < v12 && v17 < (double)rada )
        return 2;
    if ( posc < v12 || posc < (double)rada )
        v5 = 0;
    if ( rdCamera_pCurCamera->projectType == rdCameraProjectType_Ortho)
    {
        v13 = frust->field_28 * frusta;
        radb = frust->field_28 * v14;
    }
    else
    {
        v13 = frust->field_14;
        radb = frust->field_14;
    }
    if ( posc > v13 && posc > (double)radb )
        return 2;
    if ( v17 > v13 || v17 > (double)radb )
        v5 = 0;
    return v5 == 0;
}

int rdClip_Face3W(rdClipFrustum *frustum, rdVector3 *vertices, int numVertices)
{
    rdVector3 *v3; // edx
    int v5; // ebp
    rdVector3 *v6; // esi
    rdVector3 *v7; // ecx
    double v9; // st7
    //char v10; // c0
    double v12; // st6
    //char v13; // c3
    double v15; // st5
    //char v16; // c0
    double v18; // st4
    //char v19; // c0
    double v20; // st5
    double v22; // st5
    rdVector3 *v23; // ecx
    int v24; // eax
    rdVector3 *v25; // esi
    rdVector3 *v26; // edi
    rdVector3 *v27; // ecx
    rdVector3 *v28; // edx
    double v30; // st7
    //unsigned __int8 v31; // c0
    //unsigned __int8 v32; // c3
    double v34; // st6
    //char v35; // c3
    double v37; // st5
    //char v38; // c0
    double v40; // st4
    //char v41; // c0
    double v42; // st5
    double v44; // st5
    rdVector3 *v45; // ecx
    int v46; // eax
    rdVector3 *v47; // esi
    rdVector3 *v48; // edi
    rdVector3 *v49; // ecx
    rdVector3 *v50; // edx
    double v52; // st7
    //unsigned __int8 v53; // c0
    //unsigned __int8 v54; // c3
    double v56; // st5
    double v57; // st6
    //char v58; // c3
    double v60; // st5
    double v61; // st4
    //char v62; // c0
    double v64; // st3
    //char v65; // c0
    double v66; // st4
    double v68; // st3
    rdVector3 *v69; // ecx
    int v70; // eax
    rdVector3 *v71; // esi
    rdVector3 *v72; // edi
    rdVector3 *v73; // ecx
    rdVector3 *v74; // edx
    double v76; // st7
    //char v77; // c0
    double v79; // st5
    double v80; // st6
    //char v81; // c3
    double v83; // st5
    double v84; // st4
    //char v85; // c0
    double v87; // st3
    //char v88; // c0
    double v89; // st4
    double v91; // st3
    rdVector3 *v92; // ecx
    int v93; // eax
    rdVector3 *v94; // esi
    rdVector3 *v95; // edi
    rdVector3 *v96; // ecx
    rdVector3 *v97; // edx
    double v98; // st7
    rdVector3 *v100; // eax
    rdVector3 *v101; // esi
    int v104; // eax
    rdVector3 *v105; // esi
    rdVector3 *v106; // edi
    rdVector3 *v107; // ecx
    rdVector3 *v108; // edx
    double v109; // st7
    rdVector3 *v111; // eax
    float v112; // [esp+10h] [ebp-8h]
    float v113; // [esp+10h] [ebp-8h]
    float v114; // [esp+10h] [ebp-8h]
    float v115; // [esp+10h] [ebp-8h]
    int v116; // [esp+14h] [ebp-4h]
    int v117; // [esp+14h] [ebp-4h]
    int v118; // [esp+14h] [ebp-4h]
    int v119; // [esp+14h] [ebp-4h]
    float frustuma; // [esp+1Ch] [ebp+4h]
    float frustumb; // [esp+1Ch] [ebp+4h]
    float frustumc; // [esp+1Ch] [ebp+4h]
    float frustumd; // [esp+1Ch] [ebp+4h]
    float numVerticesa; // [esp+24h] [ebp+Ch]
    float numVerticesi; // [esp+24h] [ebp+Ch]
    float numVerticesb; // [esp+24h] [ebp+Ch]
    float numVerticesc; // [esp+24h] [ebp+Ch]
    float numVerticesj; // [esp+24h] [ebp+Ch]
    float numVerticesd; // [esp+24h] [ebp+Ch]
    float numVerticese; // [esp+24h] [ebp+Ch]
    float numVerticesk; // [esp+24h] [ebp+Ch]
    float numVerticesf; // [esp+24h] [ebp+Ch]
    float numVerticesl; // [esp+24h] [ebp+Ch]
    int numVerticesg; // [esp+24h] [ebp+Ch]
    int numVerticesh; // [esp+24h] [ebp+Ch]

    v3 = vertices;
    pSourceVert = vertices;
    v5 = 0;
    v6 = workVerts;
    rdClip_faceStatus = 0;
    pDestVert = workVerts;
    v7 = &vertices[numVertices - 1];
    if ( numVertices > 0 )
    {
        v116 = numVertices;
        do
        {
            numVerticesa = frustum->field_24 * v7->y;
            v9 = frustum->field_24 * v3->y;
            if ( numVerticesa <= v7->x || v9 <= v3->x )
            {
                if ( v7->x != numVerticesa && v9 != v3->x && (v7->x < (double)numVerticesa || v9 > v3->x) )
                {
                    frustuma = v3->y - v7->y;
                    v112 = v3->x - v7->x;
                    v12 = v3->y * v7->x - v7->y * v3->x;
                    numVerticesi = frustum->field_24 * frustuma - v112;
                    if (numVerticesi != 0.0)
                    {
                        v12 = v12 / numVerticesi;
                    }
                    numVerticesb = frustum->field_24 * v12;
                    v15 = frustuma;
                    if (v15 < 0.0)
                        v15 = -v15;
                    v18 = v112;
                    if (v18 < 0.0)
                        v18 = -v18;
                    if ( v15 <= v18 )
                        v20 = (numVerticesb - v7->x) / v112;
                    else
                        v20 = (v12 - v7->y) / frustuma;
                    v6->x = numVerticesb;
                    v6->y = v12;
                    ++v5;
                    ++v6;
                    v22 = (v3->z - v7->z) * v20;
                    rdClip_faceStatus |= 0x10;
                    v6[-1].z = v22 + v7->z;
                }
                if ( v9 <= v3->x )
                {
                    v23 = v6;
                    ++v5;
                    ++v6;
                    *v23 = *v3;
                }
            }
            v7 = v3++;
            --v116;
        }
        while ( v116 );
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
    v117 = v24;
    do
    {
        numVerticesc = frustum->field_28 * v27->y;
        v30 = frustum->field_28 * v28->y;
        if ( numVerticesc >= v27->x || v30 >= v28->x )
        {
            if ( v27->x != numVerticesc && v30 != v28->x && (v27->x > (double)numVerticesc || v30 < v28->x) )
            {
                frustumb = v28->y - v27->y;
                v113 = v28->x - v27->x;
                v34 = v28->y * v27->x - v27->y * v28->x;
                numVerticesj = frustum->field_28 * frustumb - v113;
                if ( numVerticesj != 0 )
                {
                    v34 = v34 / numVerticesj;
                }
                numVerticesd = frustum->field_28 * v34;
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
                ++v25;
                rdClip_faceStatus |= 0x20;
                v44 = (v28->z - v27->z) * v42;
                v25[-1].z = v44 + v27->z;
            }
            if ( v30 >= v28->x )
            {
                v45 = v25;
                ++v5;
                ++v25;
                v45->x = v28->x;
                v45->y = v28->y;
                v26 = pSourceVert;
                v45->z = v28->z;
            }
        }
        v27 = v28++;
        --v117;
    }
    while ( v117 );
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
    v118 = v46;
    do
    {
        numVerticese = frustum->field_1C * v49->y;
        v52 = v50->y * frustum->field_1C;
        if ( numVerticese >= v49->z || v52 >= v50->z )
        {
            if ( v49->z != numVerticese && v52 != v50->z && (v49->z > (double)numVerticese || v52 < v50->z) )
            {
                frustumc = v50->y - v49->y;
                v114 = v50->z - v49->z;
                v56 = v50->y * v49->z - v50->z * v49->y;
                v57 = v56;
                numVerticesk = frustum->field_1C * frustumc - v114;
                if (numVerticesk != 0.0)
                {
                    
                    v57 = v56 / numVerticesk;
                }
                v60 = frustum->field_1C * v57;
                v61 = frustumc;
                if (v61 < 0.0)
                    v61 = -v61;
                v64 = v114;
                if ( v64 < 0.0 )
                    v64 = -v64;
                if ( v61 <= v64 )
                    v66 = (v60 - v49->z) / v114;
                else
                    v66 = (v57 - v49->y) / frustumc;
                ++v5;
                ++v47;
                v68 = (v50->x - v49->x) * v66 + v49->x;
                rdClip_faceStatus |= 0x4;
                v47[-1].x = v68;
                v47[-1].y = v57;
                v47[-1].z = v60;
            }
            if ( v52 >= v50->z )
            {
                v69 = v47;
                ++v5;
                ++v47;
                v69->x = v50->x;
                v69->y = v50->y;
                v48 = pSourceVert;
                v69->z = v50->z;
            }
        }
        v49 = v50++;
        --v118;
    }
    while ( v118 );
    if ( v5 < 3 )
        return v5;
    v70 = v5;
    v71 = v48;
    v5 = 0;
    v72 = pDestVert;
    pDestVert = v71;
    pSourceVert = v72;
    v73 = &v72[v70 - 1];
    v74 = v72;
    v119 = v70;
    do
    {
        numVerticesf = frustum->field_20 * v73->y;
        v76 = v74->y * frustum->field_20;
        if ( numVerticesf <= v73->z || v76 <= v74->z )
        {
            if ( v73->z != numVerticesf && v76 != v74->z && (v73->z < (double)numVerticesf || v76 > v74->z) )
            {
                frustumd = v74->y - v73->y;
                v115 = v74->z - v73->z;
                v79 = v74->y * v73->z - v74->z * v73->y;
                v80 = v79;
                numVerticesl = frustum->field_20 * frustumd - v115;
                if ( numVerticesl != 0.0 )
                {
                    v80 = v79 / numVerticesl;
                }
                v83 = frustum->field_20 * v80;
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
                ++v71;
                v91 = (v74->x - v73->x) * v89 + v73->x;
                rdClip_faceStatus |= 8;
                v71[-1].x = v91;
                v71[-1].y = v80;
                v71[-1].z = v83;
            }
            if ( v76 <= v74->z )
            {
                v92 = v71;
                ++v5;
                ++v71;
                v92->x = v74->x;
                v92->y = v74->y;
                v72 = pSourceVert;
                v92->z = v74->z;
            }
        }
        v73 = v74++;
        --v119;
    }
    while ( v119 );
    if ( v5 < 3 )
        return v5;
    v93 = v5;
    v94 = v72;
    v5 = 0;
    v95 = pDestVert;
    pDestVert = v94;
    pSourceVert = v95;
    v96 = &v95[v93 - 1];
    v97 = v95;
    numVerticesg = v93;
    do
    {
        if ( v96->y >= (double)frustum->field_0.y || v97->y >= (double)frustum->field_0.y )
        {
            if ( v96->y != frustum->field_0.y && v97->y != frustum->field_0.y && (v96->y < (double)frustum->field_0.y || v97->y < (double)frustum->field_0.y) )
            {
                ++v5;
                v98 = (frustum->field_0.y - v96->y) / (v97->y - v96->y);
                v94->y = frustum->field_0.y;
                ++v94;
                rdClip_faceStatus |= 1;
                v94[-1].z = (v97->z - v96->z) * v98 + v96->z;
                v94[-1].x = (v97->x - v96->x) * v98 + v96->x;
            }
            if ( v97->y >= (double)frustum->field_0.y )
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
        --numVerticesg;
    }
    while ( numVerticesg );
    v101 = pDestVert;
    if ( v5 < 3 )
    {
        rdClip_faceStatus |= 0x40;
        return v5;
    }
    if (frustum->field_0.x)
    {
        v104 = v5;
        v105 = v95;
        v5 = 0;
        v106 = pDestVert;
        pDestVert = v105;
        pSourceVert = v106;
        v107 = &v106[v104 - 1];
        v108 = v106;
        numVerticesh = v104;
        do
        {
            if ( v107->y <= (double)frustum->field_0.z || v108->y <= (double)frustum->field_0.z )
            {
                if ( v107->y != frustum->field_0.z
                  && v108->y != frustum->field_0.z
                  && (v107->y > (double)frustum->field_0.z || v108->y > (double)frustum->field_0.z) )
                {
                    ++v5;
                    v109 = (frustum->field_0.z - v107->y) / (v108->y - v107->y);
                    v105->y = frustum->field_0.z;
                    ++v105;
                    rdClip_faceStatus |= 0x2;
                    v105[-1].z = (v108->z - v107->z) * v109 + v107->z;
                    v105[-1].x = (v108->x - v107->x) * v109 + v107->x;
                }
                if ( v108->y <= (double)frustum->field_0.z )
                {
                    v111 = v105;
                    ++v5;
                    ++v105;
                    *v111 = *v108;
                }
            }
            v107 = v108++;
            --numVerticesh;
        }
        while ( numVerticesh );
        if ( v5 < 3 )
            return v5;
        v101 = pDestVert;
    }
    if ( v101 != vertices )
        _memcpy(vertices, pDestVert, 4 * ((unsigned int)(sizeof(rdVector3) * v5) >> 2));
    return v5;
}
