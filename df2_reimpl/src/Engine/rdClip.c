#include "rdClip.h"

#include "rdCanvas.h"
#include "jk.h"

#include <math.h>

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
    for (v116 = numVertices; v116 > 0; v116--)
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

int rdClip_Face3GT(rdClipFrustum *frustum, rdVector3 *vertices, rdVector2 *uvs, float *a4, int numVertices)
{
    float *v5; // ecx
    rdVector2 *v6; // esi
    rdVector3 *v7; // edi
    rdVector3 *v8; // ebx
    rdVector2 *v9; // edx
    rdVector2 *v10; // ebp
    rdVector3 *v11; // ecx
    double v13; // st7
    //char v14; // c0
    double v16; // st6
    //char v17; // c3
    double v19; // st5
    double v20; // st4
    //char v21; // c0
    double v23; // st3
    //char v24; // c0
    double v25; // st4
    double v26; // st3
    double v27; // st2
    double v28; // st5
    double v29; // rtt
    double v30; // st3
    double v31; // st5
    double v32; // rt1
    double v33; // st3
    double v34; // st5
    double v35; // rt2
    rdVector3 *v37; // eax
    signed int result; // eax
    rdVector2 *v39; // esi
    rdVector3 *v40; // ebp
    rdVector2 *v41; // edx
    rdVector3 *v42; // edi
    rdVector2 *v43; // ebx
    rdVector3 *v44; // ecx
    double v46; // st7
    //unsigned __int8 v47; // c0
    //unsigned __int8 v48; // c3
    double v50; // st6
    //char v51; // c3
    double v53; // st5
    double v54; // st4
    //char v55; // c0
    double v57; // st3
    //char v58; // c0
    double v59; // st4
    double v60; // st3
    double v61; // st2
    double v62; // st5
    double v63; // rt0
    double v64; // st3
    double v65; // st5
    double v66; // rt2
    double v67; // st3
    double v68; // st5
    double v69; // rtt
    rdVector3 *v71; // eax
    int v72; // ebx
    unsigned int v73; // eax
    rdVector3 *v74; // eax
    unsigned int v75; // esi
    rdVector2 *v76; // esi
    unsigned int v77; // ecx
    //bool v78; // cc
    rdVector3 *v79; // ebx
    rdVector2 *v80; // edi
    rdVector2 *v81; // ebp
    rdVector3 *v82; // edx
    rdVector3 *v83; // ecx
    //unsigned __int8 v85; // c0
    //unsigned __int8 v86; // c3
    double v88; // st6
    double v89; // st7
    //char v90; // c3
    double v92; // st6
    double v93; // st5
    //char v94; // c0
    double v96; // st4
    //char v97; // c0
    double v98; // st5
    double v99; // st4
    double v100; // st3
    double v101; // rt1
    double v102; // st4
    double v103; // rt2
    rdVector3 *v105; // edi
    unsigned int v106; // ebp
    rdVector2 *v107; // ebp
    rdVector3 *v108; // eax
    unsigned int v109; // edx
    rdVector3 *v110; // ecx
    float *v111; // edx
    int v112; // edi
    rdVector3 *v113; // ebx
    rdVector2 *v114; // edi
    rdVector2 *v115; // esi
    rdVector2 *v116; // ebp
    rdVector3 *v117; // edx
    rdVector3 *v118; // ecx
    //char v120; // c0
    double v122; // st6
    double v123; // st7
    //char v124; // c3
    double v126; // st6
    double v127; // st5
    //char v128; // c0
    double v130; // st4
    //char v131; // c0
    double v132; // st5
    double v133; // st4
    double v134; // st3
    double v135; // rt2
    double v136; // st4
    double v137; // rtt
    rdVector3 *v139; // edi
    int v140; // esi
    unsigned int v141; // ebp
    rdVector2 *v142; // ebp
    unsigned int v143; // edx
    int v144; // eax
    rdVector3 *v145; // ecx
    rdVector2 *v146; // esi
    rdVector3 *v147; // ebx
    rdVector2 *v148; // edi
    rdVector3 *v149; // edx
    double v150; // st7
    double v151; // st5
    double v152; // st6
    double v153; // st4
    double v154; // st5
    double v155; // rt1
    double v156; // st5
    double v157; // st6
    rdVector3 *v159; // ecx
    float *v160; // edx
    rdVector2 *v161; // ebp
    rdVector3 *v162; // esi
    rdVector3 *v163; // ecx
    unsigned int v165; // ebp
    rdVector2 *v166; // ebp
    unsigned int v167; // edx
    int v168; // eax
    rdVector3 *v169; // ecx
    rdVector2 *v170; // esi
    rdVector3 *v171; // ebx
    rdVector2 *v172; // edi
    rdVector3 *v173; // edx
    double v174; // st7
    double v175; // st5
    double v176; // st6
    double v177; // st4
    double v178; // st5
    double v179; // st4
    double v180; // st6
    double v181; // rt2
    rdVector3 *v183; // ecx
    int v184; // [esp+10h] [ebp-20h]
    int v185; // [esp+10h] [ebp-20h]
    int v186; // [esp+10h] [ebp-20h]
    int v187; // [esp+10h] [ebp-20h]
    int v188; // [esp+10h] [ebp-20h]
    int v189; // [esp+10h] [ebp-20h]
    float *v190; // [esp+14h] [ebp-1Ch]
    float *v191; // [esp+14h] [ebp-1Ch]
    float *v192; // [esp+14h] [ebp-1Ch]
    float *v193; // [esp+14h] [ebp-1Ch]
    float *v194; // [esp+14h] [ebp-1Ch]
    float *v195; // [esp+14h] [ebp-1Ch]
    float *v196; // [esp+18h] [ebp-18h]
    float *v197; // [esp+18h] [ebp-18h]
    float *v198; // [esp+18h] [ebp-18h]
    float *v199; // [esp+18h] [ebp-18h]
    float *v200; // [esp+18h] [ebp-18h]
    float *v201; // [esp+18h] [ebp-18h]
    float v202; // [esp+1Ch] [ebp-14h]
    float v203; // [esp+1Ch] [ebp-14h]
    float v204; // [esp+1Ch] [ebp-14h]
    float v205; // [esp+1Ch] [ebp-14h]
    float v206; // [esp+1Ch] [ebp-14h]
    float v207; // [esp+1Ch] [ebp-14h]
    float v208; // [esp+20h] [ebp-10h]
    float v209; // [esp+20h] [ebp-10h]
    float v210; // [esp+20h] [ebp-10h]
    float v211; // [esp+20h] [ebp-10h]
    float *v212; // [esp+24h] [ebp-Ch]
    float *v213; // [esp+24h] [ebp-Ch]
    float v214; // [esp+24h] [ebp-Ch]
    float v215; // [esp+24h] [ebp-Ch]
    int v216; // [esp+28h] [ebp-8h]
    int v217; // [esp+28h] [ebp-8h]
    float *v218; // [esp+28h] [ebp-8h]
    float *v219; // [esp+28h] [ebp-8h]
    int v220; // [esp+2Ch] [ebp-4h]
    int v221; // [esp+2Ch] [ebp-4h]
    int v222; // [esp+2Ch] [ebp-4h]
    int v223; // [esp+2Ch] [ebp-4h]
    float numVerticesa; // [esp+44h] [ebp+14h]
    float numVerticesb; // [esp+44h] [ebp+14h]
    int numVerticesc; // [esp+44h] [ebp+14h]
    float numVerticesd; // [esp+44h] [ebp+14h]
    float numVerticese; // [esp+44h] [ebp+14h]
    int numVerticesf; // [esp+44h] [ebp+14h]
    float numVerticesg; // [esp+44h] [ebp+14h]
    int numVerticesh; // [esp+44h] [ebp+14h]
    float numVerticesi; // [esp+44h] [ebp+14h]
    float *numVerticesj; // [esp+44h] [ebp+14h]
    float *numVerticesk; // [esp+44h] [ebp+14h]

    v5 = a4;
    rdClip_faceStatus = 0;
    v184 = 0;
    v6 = uvs;
    v7 = vertices;
    pSourceVert = vertices;
    v8 = &vertices[numVertices - 1];
    pDestVert = workVerts;
    pSourceTVert = uvs;
    pDestTVert = workTVerts;
    pSourceIVert = a4;
    pDestIVert = workIVerts;
    v9 = &uvs[numVertices - 1];
    v196 = &a4[numVertices - 1];
    v190 = a4;
    if ( numVertices > 0 )
    {
        v212 = workIVerts;
        v10 = workTVerts;
        v11 = workVerts;
        v216 = numVertices;
        do
        {
            numVerticesa = frustum->field_30 * v8->y;
            v13 = frustum->field_30 * v7->y;
            if ( numVerticesa <= v8->x || v13 <= v7->x )
            {
                if ( v8->x != numVerticesa && v13 != v7->x && (v8->x < (double)numVerticesa || v13 > v7->x) )
                {
                    numVerticesb = v7->y - v8->y;
                    v208 = v7->x - v8->x;
                    v16 = v7->y * v8->x - v8->y * v7->x;
                    v202 = frustum->field_30 * numVerticesb - v208;
                    if (v202 != 0.0)
                    {
                        v16 = v16 / v202;
                    }
                    v19 = frustum->field_30 * v16;
                    v20 = numVerticesb;
                    if (v20 < 0.0)
                        v20 = -v20;
                    v23 = v208;
                    if (v23 < 0.0)
                        v23 = -v23;
                    if ( v20 <= v23 )
                        v25 = (v19 - v8->x) / v208;
                    else
                        v25 = (v16 - v8->y) / numVerticesb;
                    ++v11;
                    ++v10;
                    v26 = (v6->x - v9->x) * v25;
                    v27 = v19;
                    v28 = *v190;
                    v11[-1].x = v27;
                    v29 = v26 + v9->x;
                    v11[-1].y = v16;
                    v30 = v28;
                    v31 = v7->z;
                    v32 = v30 - *v196;
                    v10[-1].x = v29;
                    v33 = v31 - v8->z;
                    v34 = (v6->y - v9->y) * v25 + v9->y;
                    v35 = v32 * v25 + *v196;
                    v11[-1].z = v33 * v25 + v8->z;
                    v10[-1].y = v34;
                    *v212++ = v35;
                    ++v184;
                    rdClip_faceStatus |= 0x10;
                }
                if ( v13 <= v7->x )
                {
                    v37 = v11++;
                    ++v10;
                    *v37 = *v7;
                    v10[-1].x = v6->x;
                    v10[-1].y = v6->y;
                    ++v184;
                    *v212++ = *v190;
                }
            }
            v8 = v7;
            v196 = v190++;
            v9 = v6;
            ++v7;
            ++v6;
            --v216;
        }
        while ( v216 );
        v7 = vertices;
        v5 = a4;
    }
    if ( v184 < 3 )
        return v184;
    pDestVert = v7;
    numVerticesc = v184;
    pDestTVert = uvs;
    v39 = workTVerts;
    pSourceVert = workVerts;
    pSourceTVert = workTVerts;
    pDestIVert = v5;
    pSourceIVert = workIVerts;
    v185 = 0;
    v40 = &workVerts[numVerticesc - 1];
    v41 = &workTVerts[numVerticesc - 1];
    v191 = workIVerts;
    v197 = &workIVerts[numVerticesc - 1];
    v42 = workVerts;
    v43 = pDestTVert;
    v44 = pDestVert;
    v213 = pDestIVert;
    v217 = numVerticesc;
    do
    {
        numVerticesd = frustum->field_28 * v40->y;
        v46 = frustum->field_28 * v42->y;
        if ( numVerticesd >= v40->x || v46 >= v42->x )
        {
            if ( v40->x != numVerticesd && v46 != v42->x && (v40->x > (double)numVerticesd || v46 < v42->x) )
            {
                numVerticese = v42->y - v40->y;
                v209 = v42->x - v40->x;
                v50 = v42->y * v40->x - v40->y * v42->x;
                v203 = frustum->field_28 * numVerticese - v209;
                if (v203 != 0.0)
                {
                    
                    v50 = v50 / v203;
                }
                v53 = frustum->field_28 * v50;
                v54 = numVerticese;
                if ( v54 < 0.0 )
                    v54 = -v54;
                v57 = v209;
                if ( v57 < 0.0 )
                    v57 = -v57;
                if ( v54 <= v57 )
                    v59 = (v53 - v40->x) / v209;
                else
                    v59 = (v50 - v40->y) / numVerticese;
                ++v44;
                ++v43;
                v60 = (v39->x - v41->x) * v59;
                v61 = v53;
                v62 = *v191;
                v44[-1].x = v61;
                v63 = v60 + v41->x;
                v44[-1].y = v50;
                v64 = v62;
                v65 = v42->z;
                v66 = v64 - *v197;
                v43[-1].x = v63;
                v67 = v65 - v40->z;
                v68 = (v39->y - v41->y) * v59 + v41->y;
                v69 = v66 * v59 + *v197;
                v44[-1].z = v67 * v59 + v40->z;
                v43[-1].y = v68;
                *v213++ = v69;
                ++v185;
                rdClip_faceStatus |= 0x20;
            }
            if ( v46 >= v42->x )
            {
                v71 = v44++;
                ++v43;
                v71->x = v42->x;
                v71->y = v42->y;
                v71->z = v42->z;
                v43[-1].x = v39->x;
                v43[-1].y = v39->y;
                ++v185;
                *v213++ = *v191;
            }
        }
        v40 = v42;
        v197 = v191++;
        v41 = v39;
        ++v42;
        ++v39;
        --v217;
    }
    while ( v217 );
    v72 = v185;
    if ( v185 < 3 )
        goto LABEL_127;
    v186 = 0;
    v73 = (unsigned int)pDestVert ^ (unsigned int)pSourceVert;
    pDestVert = pSourceVert;
    v74 = (rdVector3 *)((unsigned int)pSourceVert ^ v73);
    pSourceVert = v74;
    v75 = (unsigned int)pDestTVert ^ (unsigned int)pSourceTVert;
    pDestTVert = pSourceTVert;
    v76 = (rdVector2 *)((unsigned int)pSourceTVert ^ v75);
    pSourceTVert = v76;
    v77 = (unsigned int)pDestIVert ^ (unsigned int)pSourceIVert;
    pDestIVert = pSourceIVert;
    pSourceIVert = (float *)((unsigned int)pSourceIVert ^ v77);
    numVerticesf = v72;
    v198 = (float *)(((unsigned int)pDestIVert ^ v77) + 4 * v72 - 4);
    v79 = &v74[v72 - 1];
    v80 = &v76[numVerticesf - 1];
    v192 = (float *)((unsigned int)pDestIVert ^ v77);
    if ( v72 > 0 )
    {
        v81 = pDestTVert;
        v82 = v74;
        v218 = pDestIVert;
        v83 = pDestVert;
        v220 = numVerticesf;
        do
        {
            v204 = frustum->field_2C * v79->y;
            numVerticesg = v82->y * frustum->field_2C;
            if ( v79->z <= v204 || v82->z <= (double)numVerticesg )
            {
                if ( v79->z != v204 && v82->z != numVerticesg && (v79->z > (double)v204 || v82->z > (double)numVerticesg) )
                {
                    v210 = v82->y - v79->y;
                    v214 = v82->z - v79->z;
                    v88 = v82->y * v79->z - v82->z * v79->y;
                    v89 = v88;
                    v205 = frustum->field_2C * v210 - v214;
                    if (v205 != 0.0)
                    {
                        v89 = v88 / v205;
                    }
                    v92 = frustum->field_2C * v89;
                    v93 = v210;
                    if ( v93 < 0.0 )
                        v93 = -v93;
                    v96 = v214;
                    if ( v96 < 0.0 )
                        v96 = -v96;
                    if ( v93 <= v96 )
                        v98 = (v92 - v79->z) / v214;
                    else
                        v98 = (v89 - v79->y) / v210;
                    v99 = v82->x - v79->x;
                    ++v83;
                    ++v81;
                    v100 = *v192 - *v198;
                    ++v186;
                    v81[-1].x = (v76->x - v80->x) * v98 + v80->x;
                    v101 = v99 * v98;
                    v102 = (v76->y - v80->y) * v98 + v80->y;
                    v103 = v100 * v98 + *v198;
                    v83[-1].x = v101 + v79->x;
                    v83[-1].y = v89;
                    v83[-1].z = v92;
                    v81[-1].y = v102;
                    *v218++ = v103;
                    rdClip_faceStatus |= 0x4;
                }
                if ( v82->z <= (double)numVerticesg )
                {
                    v105 = v83++;
                    ++v81;
                    v105->x = v82->x;
                    v105->y = v82->y;
                    v105->z = v82->z;
                    v81[-1].x = v76->x;
                    v81[-1].y = v76->y;
                    ++v186;
                    *v218++ = *v192;
                }
            }
            v79 = v82++;
            v198 = v192++;
            v80 = v76++;
            --v220;
        }
        while ( v220 );
    }
    result = v186;
    if ( v186 >= 3 )
    {
        v106 = (unsigned int)pDestTVert ^ (unsigned int)pSourceTVert;
        pDestTVert = pSourceTVert;
        v107 = (rdVector2 *)((unsigned int)pSourceTVert ^ v106);
        v108 = pSourceVert;
        v109 = (unsigned int)pDestIVert ^ (unsigned int)pSourceIVert;
        v110 = pDestVert;
        pDestVert = pSourceVert;
        pDestIVert = pSourceIVert;
        v111 = (float *)((unsigned int)pSourceIVert ^ v109);
        pSourceVert = v110;
        numVerticesh = v186;
        pSourceTVert = v107;
        v112 = v186;
        pSourceIVert = v111;
        v187 = 0;
        v113 = &v110[v112 - 1];
        v114 = &v107[numVerticesh - 1];
        v193 = v111;
        v199 = &v111[numVerticesh - 1];
        v115 = v107;
        if (v186 > 0)
        {
            v116 = pDestTVert;
            v117 = v110;
            v219 = pDestIVert;
            v118 = v108;
            v221 = numVerticesh;
            do
            {
                v206 = frustum->field_20 * v113->y;
                numVerticesi = v117->y * frustum->field_20;
                if ( v113->z >= v206 || v117->z >= (double)numVerticesi )
                {
                    if ( v113->z != v206 && v117->z != numVerticesi && (v113->z < (double)v206 || v117->z < (double)numVerticesi) )
                    {
                        v215 = v117->y - v113->y;
                        v211 = v117->z - v113->z;
                        v122 = v117->y * v113->z - v117->z * v113->y;
                        v123 = v122;
                        v207 = frustum->field_20 * v215 - v211;
                        if (v207 != 0.0)
                        {
                            v123 = v122 / v207;
                        }
                        v126 = frustum->field_20 * v123;
                        v127 = v215;
                        if ( v127 < 0.0 )
                            v127 = -v127;
                        v130 = v211;
                        if ( v130 < 0.0 )
                            v130 = -v130;
                        if ( v127 <= v130 )
                            v132 = (v126 - v113->z) / v211;
                        else
                            v132 = (v123 - v113->y) / v215;
                        v133 = v117->x - v113->x;
                        ++v118;
                        ++v116;
                        v134 = *v193 - *v199;
                        ++v187;
                        v116[-1].x = (v115->x - v114->x) * v132 + v114->x;
                        v135 = v133 * v132;
                        v136 = (v115->y - v114->y) * v132 + v114->y;
                        v137 = v134 * v132 + *v199;
                        v118[-1].x = v135 + v113->x;
                        v118[-1].y = v123;
                        v118[-1].z = v126;
                        v116[-1].y = v136;
                        *v219++ = v137;
                        rdClip_faceStatus |= 0x8;
                    }
                    if ( v117->z >= (double)numVerticesi )
                    {
                        v139 = v118++;
                        ++v116;
                        *v139 = *v117;
                        v116[-1].x = v115->x;
                        v116[-1].y = v115->y;
                        ++v187;
                        *v219++ = *v193;
                    }
                }
                v113 = v117++;
                v199 = v193++;
                v114 = v115++;
                --v221;
            }
            while ( v221 );
            v110 = pSourceVert;
            v108 = pDestVert;
            v111 = pSourceIVert;
            v107 = pSourceTVert;
        }
        v140 = v187;
        if ( v187 < 3 )
            return v187;
        v72 = 0;
        v188 = 0;
        pDestVert = v110;
        pSourceVert = v108;
        v141 = (unsigned int)pDestTVert ^ (unsigned int)v107;
        pDestTVert = (rdVector2 *)(v141 ^ (unsigned int)pDestTVert);
        v142 = (rdVector2 *)((unsigned int)pDestTVert ^ v141);
        pSourceTVert = v142;
        v143 = (unsigned int)pDestIVert ^ (unsigned int)v111;
        pDestIVert = (float *)(v143 ^ (unsigned int)pDestIVert);
        v144 = v140;
        pSourceIVert = (float *)((unsigned int)pDestIVert ^ v143);

        v200 = (float *)(((unsigned int)pDestIVert ^ v143) + 4 * v140 - 4);
        v194 = (float *)((unsigned int)pDestIVert ^ v143);
        v145 = &pSourceVert[v140 - 1];
        v146 = &v142[v140 - 1];
        if ( v140 <= 0 )
        {
            v161 = pSourceTVert;
            v163 = pSourceVert;
            v162 = pDestVert;
            v160 = pSourceIVert;
        }
        else
        {
            v147 = pDestVert;
            numVerticesj = pDestIVert;
            v148 = pDestTVert;
            v149 = pSourceVert;
            v222 = v144;
            do
            {
                if ( v145->y >= (double)frustum->field_0.y || v149->y >= (double)frustum->field_0.y )
                {
                    if ( v145->y != frustum->field_0.y
                      && v149->y != frustum->field_0.y
                      && (v145->y < (double)frustum->field_0.y || v149->y < (double)frustum->field_0.y) )
                    {
                        ++v147;
                        v150 = (frustum->field_0.y - v145->y) / (v149->y - v145->y);
                        v147[-1].y = frustum->field_0.y;
                        ++v148;
                        ++v188;
                        v151 = (v142->x - v146->x) * v150 + v146->x;
                        v152 = *v194 - *v200;
                        v147[-1].z = (v149->z - v145->z) * v150 + v145->z;
                        v153 = v151;
                        v154 = v149->x - v145->x;
                        v148[-1].x = v153;
                        v155 = v154 * v150;
                        v156 = (v142->y - v146->y) * v150 + v146->y;
                        v157 = v152 * v150 + *v200;
                        v147[-1].x = v155 + v145->x;
                        v148[-1].y = v156;
                        *numVerticesj++ = v157;
                        rdClip_faceStatus |= 1;
                    }
                    if ( v149->y >= (double)frustum->field_0.y )
                    {
                        v159 = v147++;
                        ++v148;
                        *v159 = *v149;
                        v148[-1].x = v142->x;
                        v148[-1].y = v142->y;
                        ++v188;
                        *numVerticesj++ = *v194;
                    }
                }
                v145 = v149++;
                v200 = v194++;
                v146 = v142++;
                --v222;
            }
            while ( v222 );
            v160 = pSourceIVert;
            v161 = pSourceTVert;
            v162 = pDestVert;
            v163 = pSourceVert;
            v72 = v188;
        }
        if ( v72 < 3 )
        {
            rdClip_faceStatus |= 0x40;
            return v72;
        }
        if (frustum->field_0.x)
        {
            v165 = (unsigned int)pDestTVert ^ (unsigned int)v161;
            pDestVert = v163;
            pDestTVert = (rdVector2 *)(v165 ^ (unsigned int)pDestTVert);
            v166 = (rdVector2 *)((unsigned int)pDestTVert ^ v165);
            v167 = (unsigned int)pDestIVert ^ (unsigned int)v160;
            pSourceVert = v162;
            pSourceTVert = v166;
            pDestIVert = (float *)(v167 ^ (unsigned int)pDestIVert);
            v168 = v72;
            pSourceIVert = (float *)((unsigned int)pDestIVert ^ v167);
            v189 = 0;
            v201 = (float *)(((unsigned int)pDestIVert ^ v167) + 4 * v72 - 4);
            v169 = &v162[v72 - 1];
            v170 = &v166[v72 - 1];
            v195 = (float *)((unsigned int)pDestIVert ^ v167);
            v171 = pDestVert;
            numVerticesk = pDestIVert;
            v172 = pDestTVert;
            v173 = pSourceVert;
            v223 = v168;
            do
            {
                if ( v169->y <= (double)frustum->field_0.z || v173->y <= (double)frustum->field_0.z )
                {
                    if ( v169->y != frustum->field_0.z
                      && v173->y != frustum->field_0.z
                      && (v169->y > (double)frustum->field_0.z || v173->y > (double)frustum->field_0.z) )
                    {
                        ++v171;
                        v174 = (frustum->field_0.z - v169->y) / (v173->y - v169->y);
                        v171[-1].y = frustum->field_0.z;
                        ++v172;
                        ++v189;
                        v175 = (v166->x - v170->x) * v174 + v170->x;
                        v176 = *v195;
                        v171[-1].z = (v173->z - v169->z) * v174 + v169->z;
                        v177 = v175;
                        v178 = v173->x - v169->x;
                        v172[-1].x = v177;
                        v179 = (v176 - *v201) * v174;
                        v180 = (v166->y - v170->y) * v174 + v170->y;
                        v181 = v179 + *v201;
                        v171[-1].x = v178 * v174 + v169->x;
                        v172[-1].y = v180;
                        *numVerticesk++ = v181;
                        rdClip_faceStatus |= 0x2;
                    }
                    if ( v173->y <= (double)frustum->field_0.z )
                    {
                        v183 = v171++;
                        ++v172;
                        *v183 = *v173;
                        v172[-1].x = v166->x;
                        v172[-1].y = v166->y;
                        ++v189;
                        *numVerticesk++ = *v195;
                    }
                }
                v169 = v173++;
                v201 = v195++;
                v170 = v166++;
                --v223;
            }
            while ( v223 );
            v72 = v189;
            if ( v189 < 3 )
                goto LABEL_127;
            v162 = pDestVert;
        }
        if ( v162 != vertices )
        {
            _memcpy(vertices, v162, sizeof(rdVector3) * v72);
            _memcpy(uvs, pDestTVert, sizeof(rdVector2) * v72);
            _memcpy(a4, pDestIVert, sizeof(float) * v72);
        }
LABEL_127:
        result = v72;
    }
    return result;
}

int rdClip_Face3S(rdClipFrustum *frustum, rdVector3 *vertices, int numVertices)
{
    rdVector3 *v3; // edx
    int v5; // ebp
    rdVector3 *v6; // esi
    rdVector3 *v7; // ecx
    double v9; // st7
    double v12; // st6
    double v20; // st5
    double v22; // st5
    rdVector3 *v23; // ecx
    int v24; // eax
    rdVector3 *v25; // esi
    rdVector3 *v26; // edi
    rdVector3 *v27; // ecx
    rdVector3 *v28; // edx
    double v30; // st7
    double v34; // st6
    double v37; // st5
    double v40; // st4
    double v42; // st5
    int v43; // eax
    double v44; // st5
    rdVector3 *v45; // ecx
    int v46; // eax
    rdVector3 *v47; // esi
    rdVector3 *v48; // edi
    rdVector3 *v49; // ecx
    rdVector3 *v50; // edx
    double v52; // st7
    double v56; // st5
    double v57; // st6
    double v60; // st5
    double v66; // st4
    int v67; // eax
    double v68; // st3
    rdVector3 *v69; // ecx
    int v70; // eax
    rdVector3 *v71; // esi
    rdVector3 *v72; // edi
    rdVector3 *v73; // ecx
    rdVector3 *v74; // edx
    double v76; // st7
    double v79; // st5
    double v80; // st6
    double v83; // st5
    double v84; // st4
    double v87; // st3
    double v89; // st4
    int v90; // eax
    double v91; // st3
    rdVector3 *v92; // ecx
    int v93; // eax
    rdVector3 *v94; // esi
    rdVector3 *v95; // edi
    rdVector3 *v96; // ecx
    rdVector3 *v97; // edx
    double v98; // st7
    int v99; // eax
    rdVector3 *v100; // eax
    rdVector3 *v101; // esi
    int v102; // eax
    int v104; // eax
    rdVector3 *v105; // esi
    rdVector3 *v106; // edi
    rdVector3 *v107; // ecx
    rdVector3 *v108; // edx
    double v109; // st7
    int v110; // eax
    rdVector3 *v111; // eax
    double v112; // [esp+10h] [ebp-8h]
    double v113; // [esp+10h] [ebp-8h]
    double v114; // [esp+10h] [ebp-8h]
    double v115; // [esp+10h] [ebp-8h]
    int v116; // [esp+14h] [ebp-4h]
    int v117; // [esp+14h] [ebp-4h]
    int v118; // [esp+14h] [ebp-4h]
    int v119; // [esp+14h] [ebp-4h]
    double frustuma; // [esp+1Ch] [ebp+4h]
    double frustumb; // [esp+1Ch] [ebp+4h]
    double frustumc; // [esp+1Ch] [ebp+4h]
    double frustumd; // [esp+1Ch] [ebp+4h]
    double numVerticesa; // [esp+24h] [ebp+Ch]
    double numVerticesi; // [esp+24h] [ebp+Ch]
    double numVerticesb; // [esp+24h] [ebp+Ch]
    double numVerticesc; // [esp+24h] [ebp+Ch]
    double numVerticesj; // [esp+24h] [ebp+Ch]
    double numVerticesd; // [esp+24h] [ebp+Ch]
    double numVerticese; // [esp+24h] [ebp+Ch]
    double numVerticesk; // [esp+24h] [ebp+Ch]
    double numVerticesf; // [esp+24h] [ebp+Ch]
    double numVerticesl; // [esp+24h] [ebp+Ch]
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
        numVerticesa = v7->y * frustum->field_30;
        v9 = v3->y * frustum->field_30;
        if ( numVerticesa <= v7->x || v9 <= v3->x )
        {
            if ( v7->x != numVerticesa && v9 != v3->x && (v7->x < numVerticesa || v9 > v3->x) )
            {
                frustuma = v3->y - v7->y;
                v112 = v3->x - v7->x;
                v12 = v3->y * v7->x - v7->y * v3->x;
                numVerticesi = frustum->field_30 * frustuma - v112;
                if ( numVerticesi != 0.0)
                {
                    v12 = v12 / numVerticesi;
                }
                numVerticesb = frustum->field_30 * v12;

                if ( fabs(frustuma) <= fabs(v112) )
                    v20 = (numVerticesb - v7->x) / v112;
                else
                    v20 = (v12 - v7->y) / frustuma;
                v6->x = numVerticesb;
                v6->y = v12;
                ++v5;
                
                v22 = (v3->z - v7->z) * v20;
                rdClip_faceStatus |= 0x10;
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
        numVerticesc = frustum->field_28 * v27->y;
        v30 = frustum->field_28 * v28->y;
        if ( numVerticesc >= v27->x || v30 >= v28->x )
        {
            if ( v27->x != numVerticesc && v30 != v28->x && (v27->x > numVerticesc || v30 < v28->x) )
            {
                frustumb = v28->y - v27->y;
                v113 = v28->x - v27->x;
                v34 = v28->y * v27->x - v27->y * v28->x;
                numVerticesj = frustum->field_28 * frustumb - v113;
                if ( numVerticesj != 0.0 )
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
                
                v44 = (v28->z - v27->z) * v42;
                rdClip_faceStatus |= 0x20;
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
            }
        }
        v27 = v28++;
    }
    if ( v5 < 3 )
        return v5;

    v46 = v5;
    v47 = pSourceVert;
    v5 = 0;
    v48 = pDestVert;
    pDestVert = v47;
    pSourceVert = v48;
    v49 = &v48[v46 - 1];
    v50 = v48;
    for (v118 = v46; v118 > 0; v118--)
    {
        numVerticese = frustum->field_2C * v49->y;
        v52 = v50->y * frustum->field_2C;
        if ( numVerticese >= v49->z || v52 >= v50->z )
        {
            if ( v49->z != numVerticese && v52 != v50->z && (v49->z > numVerticese || v52 < v50->z) )
            {
                frustumc = v50->y - v49->y;
                v114 = v50->z - v49->z;
                v56 = v50->y * v49->z - v50->z * v49->y;
                v57 = v56;
                numVerticesk = frustum->field_2C * frustumc - v114;
                if ( numVerticesk != 0.0 )
                {
                    v57 = v56 / numVerticesk;
                }
                v60 = frustum->field_2C * v57;

                if ( fabs(frustumc) <= fabs(v114) )
                    v66 = (v60 - v49->z) / v114;
                else
                    v66 = (v57 - v49->y) / frustumc;
                ++v5;
                
                v68 = (v50->x - v49->x) * v66 + v49->x;
                rdClip_faceStatus |= 0x4;
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
        numVerticesf = frustum->field_20 * v73->y;
        v76 = v74->y * frustum->field_20;
        if ( numVerticesf <= v73->z || v76 <= v74->z )
        {
            if ( v73->z != numVerticesf && v76 != v74->z && (v73->z < numVerticesf || v76 > v74->z) )
            {
                frustumd = v74->y - v73->y;
                v115 = v74->z - v73->z;
                v79 = v74->y * v73->z - v74->z * v73->y;
                v80 = v79;
                numVerticesl = frustum->field_20 * frustumd - v115;
                if ( numVerticesl != 0.0)
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
                
                v91 = (v74->x - v73->x) * v89 + v73->x;
                rdClip_faceStatus |= 0x8;
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
        if ( v96->y >= frustum->field_0.y || v97->y >= frustum->field_0.y )
        {
            if ( v96->y != frustum->field_0.y && v97->y != frustum->field_0.y && (v96->y < frustum->field_0.y || v97->y < frustum->field_0.y) )
            {
                ++v5;
                v98 = (frustum->field_0.y - v96->y) / (v97->y - v96->y);
                v94->y = frustum->field_0.y;
                rdClip_faceStatus |= 1;
                v94->z = (v97->z - v96->z) * v98 + v96->z;
                v94->x = (v97->x - v96->x) * v98 + v96->x;
                ++v94;
            }
            if ( v97->y >= frustum->field_0.y )
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
        rdClip_faceStatus |= 0x40;
        return v5;
    }
    if (frustum->field_0.x != 0.0)
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
            if ( v107->y <= frustum->field_0.z || v108->y <= frustum->field_0.z )
            {
                if ( v107->y != frustum->field_0.z
                  && v108->y != frustum->field_0.z
                  && (v107->y > frustum->field_0.z || v108->y > frustum->field_0.z) )
                {
                    ++v5;
                    v109 = (frustum->field_0.z - v107->y) / (v108->y - v107->y);
                    v105->y = frustum->field_0.z;
                    rdClip_faceStatus |= 0x2;
                    v105->z = (v108->z - v107->z) * v109 + v107->z;
                    v105->x = (v108->x - v107->x) * v109 + v107->x;
                    ++v105;
                }
                if ( v108->y <= frustum->field_0.z )
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

int rdClip_Face3GS(rdClipFrustum *frustum, rdVector3 *vertices, float *a3, int numVertices)
{
    rdVector3 *v4; // edx
    float *v5; // edi
    float *v6; // ebx
    rdVector3 *v7; // ecx
    float *v8; // ebp
    rdVector3 *v9; // esi
    double v11; // st7
    double v14; // st6
    double v17; // st5
    double v18; // st4
    double v21; // st3
    double v23; // st4
    double v24; // st3
    double v25; // st5
    double v26; // rtt
    double v27; // st4
    double v28; // st5
    rdVector3 *v30; // eax
    signed int result; // eax
    float *copy_pDestIVert; // eax
    rdVector3 *copy_pDestVert; // ebx
    float *copy_pSourceIVert; // esi
    rdVector3 *copy_pSourceVert; // edi
    int v37; // ecx
    float *v38; // ebp
    rdVector3 *v39; // ecx
    rdVector3 *v40; // edx
    float *v41; // edi
    double v43; // st7
    double v47; // st6
    double v50; // st5
    double v51; // st4
    double v54; // st3
    double v56; // st4
    double v57; // st3
    double v58; // st5
    double v59; // rt2
    double v60; // st4
    double v61; // st5
    rdVector3 *v63; // eax
    int v64; // ecx
    int v65; // edi
    int v66; // esi
    rdVector3 *v67; // ebx
    float *v68; // eax
    rdVector3 *v69; // edi
    float *v70; // esi
    rdVector3 *v71; // edx
    float *v72; // ebp
    float *v73; // ecx
    float *v74; // edi
    double v76; // st7
    double v80; // st5
    double v81; // st6
    double v84; // st5
    double v85; // st4
    double v88; // st3
    double v90; // st4
    double v91; // st3
    rdVector3 *v93; // eax
    rdVector3 *v94; // ebx
    float *v95; // esi
    rdVector3 *v96; // edx
    float *v97; // edi
    rdVector3 *v98; // ecx
    float *v99; // ebp
    float *v100; // edx
    double v102; // st7
    double v105; // st5
    double v106; // st6
    double v109; // st5
    double v110; // st4
    double v113; // st3
    double v115; // st4
    double v116; // st3
    rdVector3 *v118; // eax
    float *v119; // esi
    float *v120; // edi
    rdVector3 *v121; // ebx
    rdVector3 *v122; // edx
    int v123; // eax
    int v124; // ebp
    rdVector3 *v125; // ecx
    float *v126; // edx
    double v127; // st7
    double v128; // st6
    double v129; // st5
    double v130; // st6
    rdVector3 *v132; // ecx
    int v135; // edi
    float* v136; // esi
    int v137; // edx
    float *v138; // edi
    int v139; // ecx
    rdVector3 *v140; // ebx
    rdVector3 *v141; // edx
    int v142; // eax
    rdVector3 *v143; // ecx
    float *v144; // edx
    double v145; // st7
    double v146; // st6
    double v147; // st5
    double v148; // st6
    rdVector3 *v150; // eax
    int v151; // [esp+10h] [ebp-10h]
    int v152; // [esp+10h] [ebp-10h]
    int v153; // [esp+10h] [ebp-10h]
    int v154; // [esp+10h] [ebp-10h]
    float *v155; // [esp+10h] [ebp-10h]
    float *v156; // [esp+10h] [ebp-10h]
    float v157; // [esp+14h] [ebp-Ch]
    float v158; // [esp+14h] [ebp-Ch]
    float v159; // [esp+14h] [ebp-Ch]
    float v160; // [esp+14h] [ebp-Ch]
    float v161; // [esp+18h] [ebp-8h]
    float v162; // [esp+18h] [ebp-8h]
    float v163; // [esp+18h] [ebp-8h]
    float v164; // [esp+18h] [ebp-8h]
    float *v165; // [esp+18h] [ebp-8h]
    float *v166; // [esp+18h] [ebp-8h]
    int v167; // [esp+1Ch] [ebp-4h]
    int v168; // [esp+1Ch] [ebp-4h]
    int v169; // [esp+1Ch] [ebp-4h]
    signed int v170; // [esp+1Ch] [ebp-4h]
    float numVerticesa; // [esp+30h] [ebp+10h]
    float numVerticesi; // [esp+30h] [ebp+10h]
    int numVerticesb; // [esp+30h] [ebp+10h]
    float numVerticesc; // [esp+30h] [ebp+10h]
    float numVerticesj; // [esp+30h] [ebp+10h]
    int numVerticesd; // [esp+30h] [ebp+10h]
    float numVerticese; // [esp+30h] [ebp+10h]
    float numVerticesk; // [esp+30h] [ebp+10h]
    float numVerticesf; // [esp+30h] [ebp+10h]
    float numVerticesl; // [esp+30h] [ebp+10h]
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
            numVerticesa = v7->y * frustum->field_30;
            v11 = frustum->field_30 * v4->y;
            if ( numVerticesa <= v7->x || v11 <= v4->x )
            {
                if ( v7->x != numVerticesa && v11 != v4->x && (v7->x < (double)numVerticesa || v11 > v4->x) )
                {
                    v157 = v4->y - v7->y;
                    v161 = v4->x - v7->x;
                    v14 = v4->y * v7->x - v7->y * v4->x;
                    numVerticesi = frustum->field_30 * v157 - v161;
                    if ( numVerticesi != 0.0 )
                    {
                        v14 = v14 / numVerticesi;
                    }
                    v17 = frustum->field_30 * v14;
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
                    rdClip_faceStatus |= 0x10;
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
                numVerticesc = frustum->field_28 * v39->y;
                v43 = frustum->field_28 * v40->y;
                if ( numVerticesc <= v39->x || v43 >= v40->x )
                {
                    if ( v39->x != numVerticesc && v43 != v40->x && (v39->x > (double)numVerticesc || v43 < v40->x) )
                    {
                        v162 = v40->y - v39->y;
                        v158 = v40->x - v39->x;
                        v47 = v40->y * v39->x - v39->y * v40->x;
                        numVerticesj = frustum->field_28 * v162 - v158;
                        if ( numVerticesj != 0.0 )
                        {
                            v47 = v47 / numVerticesj;
                        }
                        v50 = frustum->field_28 * v47;
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
                        rdClip_faceStatus |= 0x20;
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
        v65 = (unsigned int)copy_pDestVert ^ (unsigned int)copy_pSourceVert;
        v66 = (unsigned int)copy_pDestIVert ^ (unsigned int)copy_pSourceIVert;
        v67 = (rdVector3 *)(v65 ^ (unsigned int)copy_pDestVert);
        v68 = (float *)(v66 ^ (unsigned int)copy_pDestIVert);
        v69 = (rdVector3 *)((unsigned int)v67 ^ v65);
        v70 = (float *)((unsigned int)v68 ^ v66);
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
                numVerticese = frustum->field_2C * v71->y;
                v76 = *(v73 - 1) * frustum->field_2C;
                if ( numVerticese >= v71->z || v76 >= *v73 )
                {
                    if ( v71->z != numVerticese && v76 != *v73 && (v71->z > (double)numVerticese || v76 < *v73) )
                    {
                        v163 = *(v73 - 1) - v71->y;
                        v159 = *v73 - v71->z;
                        v80 = *(v73 - 1) * v71->z - *v73 * v71->y;
                        v81 = v80;
                        numVerticesk = frustum->field_2C * v163 - v159;
                        if ( numVerticesk != 0.0 )
                        {
                            v81 = v80 / numVerticesk;
                        }
                        v84 = frustum->field_2C * v81;
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
                        rdClip_faceStatus |= 0x4;
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
                    numVerticesf = frustum->field_20 * v98->y;
                    v102 = *(v100 - 1) * frustum->field_20;
                    if ( numVerticesf <= v98->z || v102 <= *v100 )
                    {
                        if ( v98->z != numVerticesf && v102 != *v100 && (v98->z < (double)numVerticesf || v102 > *v100) )
                        {
                            v164 = *(v100 - 1) - v98->y;
                            v160 = *v100 - v98->z;
                            v105 = *(v100 - 1) * v98->z - *v100 * v98->y;
                            v106 = v105;
                            numVerticesl = frustum->field_20 * v164 - v160;
                            if ( numVerticesl != 0.0 )
                            {
                                v106 = v105 / numVerticesl;
                            }
                            v109 = frustum->field_20 * v106;
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
                            rdClip_faceStatus |= 0x8;
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
                        if ( v125->y >= (double)frustum->field_0.y || *v126 >= (double)frustum->field_0.y )
                        {
                            if ( v125->y != frustum->field_0.y
                              && *v126 != frustum->field_0.y
                              && (v125->y < (double)frustum->field_0.y || *v126 < (double)frustum->field_0.y) )
                            {
                                ++v124;
                                ++v119;
                                v127 = (frustum->field_0.y - v125->y) / (*v126 - v125->y);
                                v121->y = frustum->field_0.y;
                                ++v121;
                                v128 = (*v120 - *v165) * v127;
                                v121[-1].z = (v126[1] - v125->z) * v127 + v125->z;
                                v129 = v128 + *v165;
                                v130 = (*(v126 - 1) - v125->x) * v127 + v125->x;
                                *(v119 - 1) = v129;
                                v121[-1].x = v130;
                                rdClip_faceStatus |= 1;
                            }
                            if ( *v126 >= (double)frustum->field_0.y )
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
                    rdClip_faceStatus |= 0x40;
                    return v124;
                }
                if (frustum->field_0.x)
                {
                    v135 = (unsigned int)v119 ^ (unsigned int)v120;
                    v136 = (float*)(v135 ^ (unsigned int)v119);
                    v137 = (unsigned int)v121 ^ (unsigned int)v122;
                    v138 = (float *)((unsigned int)v136 ^ v135);
                    v139 = v124;
                    v140 = (rdVector3 *)(v137 ^ (unsigned int)v121);
                    v141 = (rdVector3 *)((unsigned int)v140 ^ v137);
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
                        if ( v143->y <= (double)frustum->field_0.z || *v144 <= (double)frustum->field_0.z )
                        {
                            if ( v143->y != frustum->field_0.z
                              && *v144 != frustum->field_0.z
                              && (v143->y > (double)frustum->field_0.z || *v144 > (double)frustum->field_0.z) )
                            {
                                ++v124;
                                v145 = (frustum->field_0.z - v143->y) / (*v144 - v143->y);
                                v140->y = frustum->field_0.z;
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
                            if ( *v144 <= (double)frustum->field_0.z )
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
                    _memcpy(a3, pDestIVert, sizeof(float) * v124);
                }
                return v124;
            }
        }
    }
    return result;
}
