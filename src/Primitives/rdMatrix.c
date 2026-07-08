#include "rdMatrix.h"

#include "jk.h"
#include <math.h>
#include "General/stdMath.h"
#include "stdPlatform.h" // Added: word-safe matrix copies (dest may be an extram-resident thing)

const rdMatrix34 rdroid_identMatrix34 = {{1.0, 0.0, 0.0}, 
                                         {0.0, 1.0, 0.0}, 
                                         {0.0, 0.0, 1.0},
                                         {0.0, 0.0, 0.0}};

const rdMatrix44 rdroid_identMatrix44 = {{1.0, 0.0, 0.0, 0.0},
                                         {0.0, 1.0, 0.0, 0.0}, 
                                         {0.0, 0.0, 1.0, 0.0}, 
                                         {0.0, 0.0, 0.0, 1.0}};

void rdMatrix_Build34(rdMatrix34* NO_ALIAS res, const rdVector3* NO_ALIAS pyr, const rdVector3* NO_ALIAS pos)
{
    flex_t x_rad_sin, x_rad_cos;
    flex_t y_rad_sin, y_rad_cos;
    flex_t z_rad_sin, z_rad_cos;

    stdMath_SinCos(pyr->x, &x_rad_sin, &x_rad_cos);
    stdMath_SinCos(pyr->y, &y_rad_sin, &y_rad_cos);
    stdMath_SinCos(pyr->z, &z_rad_sin, &z_rad_cos);
    res->rvec.x = -(z_rad_sin * y_rad_sin) * x_rad_sin + (z_rad_cos * y_rad_cos);
    res->rvec.y = ((z_rad_sin * y_rad_cos) * x_rad_sin) + (z_rad_cos * y_rad_sin);
    res->rvec.z = -z_rad_sin * x_rad_cos;
    res->lvec.x = -y_rad_sin * x_rad_cos;
    res->lvec.y = (y_rad_cos * x_rad_cos);
    res->lvec.z = x_rad_sin;
    res->uvec.x = ((z_rad_cos * y_rad_sin) * x_rad_sin) + (z_rad_sin * y_rad_cos);
    res->uvec.y = -x_rad_sin * (y_rad_cos * z_rad_cos) + (y_rad_sin*z_rad_sin);
    res->uvec.z = z_rad_cos * x_rad_cos;
    res->scale.x = pos->x;
    res->scale.y = pos->y;
    res->scale.z = pos->z;
}

void rdMatrix_BuildFromLook34(rdMatrix34* NO_ALIAS mat, const rdVector3* NO_ALIAS look)
{
    rdVector_Copy3(&mat->lvec, look);

    mat->rvec.x = (mat->lvec.y * 1.0) - (mat->lvec.z * 0.0);
    mat->rvec.y = (mat->lvec.z * 0.0) - (mat->lvec.x * 1.0);
    mat->rvec.z = (mat->lvec.x * 0.0) - (mat->lvec.y * 0.0);
    if (rdVector_Normalize3Acc(&mat->rvec) == 0.0)
    {
        mat->uvec.x = (mat->lvec.z * 0.0) - (mat->lvec.y * 0.0);
        mat->uvec.y = (mat->lvec.x * 0.0) - (mat->lvec.z * 1.0);
        mat->uvec.z = (mat->lvec.y * 1.0) - (mat->lvec.x * 0.0);
        rdVector_Normalize3Acc(&mat->uvec);
        mat->rvec.x = mat->uvec.z * mat->lvec.y - mat->uvec.y * mat->lvec.z;
        mat->rvec.y = (mat->uvec.x * mat->lvec.z) - (mat->uvec.z * mat->lvec.x);
        mat->rvec.z = (mat->uvec.y * mat->lvec.x) - (mat->uvec.x * mat->lvec.y);
    }
    else
    {
        mat->uvec.x = (mat->lvec.z * mat->rvec.y) - (mat->rvec.z * mat->lvec.y);
        mat->uvec.y = (mat->rvec.z * mat->lvec.x) - (mat->lvec.z * mat->rvec.x);
        mat->uvec.z = (mat->lvec.y * mat->rvec.x) - (mat->lvec.x * mat->rvec.y);
    }
}

void rdMatrix_BuildCamera34(rdMatrix34 *out, const rdVector3 *rot, const rdVector3 *pos)
{
    rdVector3 a, b;
    rdVector_Neg3(&a, rot);
    rdVector_Neg3(&b, pos);
    rdMatrix_Build34(out, &a, &b);
}

void rdMatrix_InvertOrtho34(rdMatrix34 *dest, const rdMatrix34 *src)
{
    dest->rvec.y = src->lvec.x;
    dest->lvec.z = src->uvec.y;
    dest->uvec.x = src->rvec.z;
    dest->rvec.z = src->uvec.x;
    dest->rvec.x = src->rvec.x;
    dest->lvec.x = src->rvec.y;
    dest->lvec.y = src->lvec.y;
    dest->uvec.y = src->lvec.z;
    dest->uvec.z = src->uvec.z;
    dest->scale.x = -((src->rvec.y * src->scale.y) + (src->rvec.z * src->scale.z) + (src->rvec.x * src->scale.x));
    dest->scale.y = -(src->lvec.x * src->scale.x + src->lvec.z * src->scale.z + src->lvec.y * src->scale.y);
    dest->scale.z = -((src->uvec.y * src->scale.y) + (src->uvec.x * src->scale.x) + (src->uvec.z * src->scale.z));
}

void rdMatrix_Build44(rdMatrix44 *out, const rdVector3 *rot, const rdVector3 *pos)
{
    flex_t x_rad_sin, x_rad_cos;
    flex_t y_rad_sin, y_rad_cos;
    flex_t z_rad_sin, z_rad_cos;

    stdMath_SinCos(rot->x, &x_rad_sin, &x_rad_cos);
    stdMath_SinCos(rot->y, &y_rad_sin, &y_rad_cos);
    stdMath_SinCos(rot->z, &z_rad_sin, &z_rad_cos);

    out->vA.x = x_rad_sin  * -(z_rad_sin * y_rad_sin) + (z_rad_cos * y_rad_cos);
    out->vA.y = x_rad_sin  *  (z_rad_sin * y_rad_cos) + (z_rad_cos * y_rad_sin);
    out->vA.z = -z_rad_sin * x_rad_cos;
    out->vA.w = 0.0;
    out->vB.x = -y_rad_sin * x_rad_cos;
    out->vB.y = y_rad_cos  * x_rad_cos;
    out->vB.z = x_rad_sin;
    out->vB.w = 0.0;
    out->vC.x = x_rad_sin  * (z_rad_cos * y_rad_sin) + (z_rad_sin * y_rad_cos);
    out->vC.y = -x_rad_sin * (z_rad_cos * y_rad_cos) + (z_rad_sin * y_rad_sin);
    out->vC.z = z_rad_cos  * x_rad_cos;
    out->vC.w = 0.0;
    out->vD.x = pos->x;
    out->vD.y = pos->y;
    out->vD.z = pos->z;
    out->vD.w = 1.0;
}

void rdMatrix_BuildRotate34(rdMatrix34 *mat, const rdVector3 *pyr)
{
    rdVector3 zeroVec = {0,0,0}; // TODO this is a global const
    rdMatrix_Build34(mat, pyr, &zeroVec);
}

void rdMatrix_BuildInverseRotate34(rdMatrix34 *out, const rdVector3 *rot)
{
    flex_t x_rad_sin, x_rad_cos;
    flex_t y_rad_sin, y_rad_cos;
    flex_t z_rad_sin, z_rad_cos;

    stdMath_SinCos(rot->x, &x_rad_sin, &x_rad_cos);
    stdMath_SinCos(rot->y, &y_rad_sin, &y_rad_cos);
    stdMath_SinCos(rot->z, &z_rad_sin, &z_rad_cos);

    out->rvec.x = (z_rad_sin * y_rad_sin) * x_rad_sin + (z_rad_cos * y_rad_cos);
    out->rvec.y = (y_rad_sin) * x_rad_cos;
    out->rvec.z = ((z_rad_cos * y_rad_sin) * x_rad_sin) - z_rad_sin * y_rad_cos;
    out->lvec.x = ((z_rad_sin * y_rad_cos) * x_rad_sin) - (z_rad_cos * y_rad_sin);
    out->lvec.y = (y_rad_cos * x_rad_cos);
    out->lvec.z = ((z_rad_cos * y_rad_cos) * x_rad_sin) + (z_rad_sin * y_rad_sin);
    out->uvec.x = (z_rad_sin * x_rad_cos);
    out->uvec.y = -x_rad_sin;
    out->uvec.z = (z_rad_cos * x_rad_cos);
    out->scale.x = 0.0;
    out->scale.y = 0.0;
    out->scale.z = 0.0;
}

void rdMatrix_BuildRotate44(rdMatrix44 *out, const rdVector3 *rot)
{
    rdVector3 zeroVec = {0,0,0}; // TODO this is a global const
    rdMatrix_Build44(out, rot, &zeroVec);
}

void rdMatrix_BuildTranslate34(rdMatrix34 *mat, const rdVector3 *vec)
{
    stdPlatform_Memcpy32(mat, &rdroid_identMatrix34, sizeof(rdMatrix34));
    rdVector_Copy3(&mat->scale, vec);
}

void rdMatrix_BuildTranslate44(rdMatrix44 *out, const rdVector3 *tV)
{
    stdPlatform_Memcpy32(out, &rdroid_identMatrix44, sizeof(rdMatrix44));
    out->vD.x = tV->x;
    out->vD.y = tV->y;
    out->vD.z = tV->z;
    out->vD.w = 1.0;
}

void rdMatrix_BuildScale34(rdMatrix34 *mat, const rdVector3 *scale)
{
    mat->rvec.x = scale->x;
    mat->rvec.y = 0.0;
    mat->rvec.z = 0.0;
    
    mat->lvec.x = 0.0;
    mat->lvec.y = scale->y;
    mat->lvec.z = 0.0;
    
    mat->uvec.x = 0.0;
    mat->uvec.y = 0.0;
    mat->uvec.z = scale->z;

    mat->scale.x = 0.0;
    mat->scale.y = 0.0;
    mat->scale.z = 0.0;
}

void rdMatrix_BuildScale44(rdMatrix44 *out, const rdVector3 *scale)
{
    out->vA.x = scale->x;
    out->vA.y = 0.0;
    out->vA.z = 0.0;
    out->vA.w = 0.0;
    
    out->vB.x = 0.0;
    out->vB.y = scale->y;
    out->vB.z = 0.0;
    out->vB.w = 0.0;
    
    out->vC.x = 0.0;
    out->vC.y = 0.0;
    out->vC.z = scale->z;
    out->vC.w = 0.0;

    out->vD.x = 0.0;
    out->vD.y = 0.0;
    out->vD.z = 0.0;
    out->vD.w = 1.0;
}

void rdMatrix_BuildFromVectorAngle34(rdMatrix34* NO_ALIAS mat, const rdVector3* NO_ALIAS vec, flex_t angle)
{
    flex_t v12;
    flex_t v44;
    flex_t v51;
    flex_t angleRad_sin, angleRad_cos;

    stdMath_SinCos(angle, &angleRad_sin, &angleRad_cos);
    if ( vec->z >= 1.0 )
    {
        mat->rvec.x = angleRad_cos;
        mat->lvec.y = angleRad_cos;
        mat->lvec.x = -angleRad_sin;
        mat->rvec.y = angleRad_sin;
        mat->rvec.z = 0.0;
        mat->lvec.z = 0.0;
        mat->uvec.x = 0.0;
        mat->uvec.y = 0.0;
        mat->uvec.z = 1.0;
        mat->scale.x = 0.0;
        mat->scale.y = 0.0;
        mat->scale.z = 0.0;
        return;
    }
    if ( vec->z <= -1.0 )
    {
        mat->rvec.x = angleRad_cos;
        mat->lvec.y = angleRad_cos;
        mat->rvec.y = -angleRad_sin;
        mat->lvec.x = angleRad_sin;
        mat->rvec.z = 0.0;
        mat->lvec.z = 0.0;
        mat->uvec.x = 0.0;
        mat->uvec.y = 0.0;
        mat->uvec.z = 1.0;
        mat->scale.x = 0.0;
        mat->scale.y = 0.0;
        mat->scale.z = 0.0;
        return;
    }
    v12 = vec->x * vec->x;
    v44 = vec->y * vec->y;
    v51 = 1.0 - v12 - v44;
    mat->rvec.x = (((angleRad_cos * v12) * v51 + (angleRad_cos * v44)) / (1.0 - v51)) + (vec->z * vec->x * (1.0 - angleRad_cos));
    mat->scale.x = 0.0;
    mat->scale.y = 0.0;
    mat->lvec.y = (((angleRad_cos * v44) * v51 + (angleRad_cos * v12)) / (1.0 - v51)) + v44;
    mat->uvec.z = ((angleRad_cos * v12) + (angleRad_cos * v44)) + v51;
    mat->rvec.y = (vec->z * angleRad_sin) + ((vec->y * vec->x) * (1.0 - angleRad_cos));
    mat->lvec.x = ((vec->y * vec->x) * (1.0 - angleRad_cos)) - (vec->z * angleRad_sin);
    mat->rvec.z = ((vec->z * vec->x) * (1.0 - angleRad_cos)) - ((vec->y) * angleRad_sin);
    mat->lvec.z = ((vec->z * vec->y) * (1.0 - angleRad_cos)) + (vec->x * angleRad_sin);
    mat->uvec.x = ((vec->z * vec->x) * (1.0 - angleRad_cos)) + ((vec->y) * angleRad_sin);
    mat->uvec.y = ((vec->z * vec->y) * (1.0 - angleRad_cos)) - (vec->x * angleRad_sin);
    mat->scale.z = 0.0;
}

// MOTS altered
void rdMatrix_LookAt(rdMatrix34 *mat, const rdVector3* NO_ALIAS eyePos, const rdVector3* NO_ALIAS lookPos, flex_t angle)
{
    flex_t v7;
    flex_t v11;
    flex_t v12;
    flex_t v24;
    flex_t v25;
    rdMatrix34 tmp;

    mat->lvec.x = lookPos->x - eyePos->x;
    mat->lvec.y = lookPos->y - eyePos->y;
    mat->lvec.z = lookPos->z - eyePos->z;
    rdVector_Normalize3Acc(&mat->lvec);
    rdMatrix_BuildFromVectorAngle34(&tmp, &mat->lvec, angle);
    v7 = stdMath_Fabs((mat->lvec.y * 0.0) + (mat->lvec.x * 0.0) + (mat->lvec.z * 1.0));
    if ( v7 <= 0.999 )
    {
        v24 = tmp.rvec.x * 0.0 + tmp.lvec.x * 0.0 + tmp.uvec.x * 1.0;
        v25 = tmp.rvec.y * 0.0 + tmp.lvec.y * 0.0 + tmp.uvec.y * 1.0;
        v12 = tmp.rvec.z * 0.0 + tmp.lvec.z * 0.0;
        v11 = tmp.uvec.z * 1.0;
    }
    else if ( mat->lvec.z <= 0.0 )
    {
        v24 = tmp.rvec.x * 0.0 + tmp.lvec.x * 1.0 + tmp.uvec.x * 0.0;
        v25 = tmp.rvec.y * 0.0 + tmp.lvec.y * 1.0 + tmp.uvec.y * 0.0;
        v12 = tmp.rvec.z * 0.0 + tmp.lvec.z * 1.0;
        v11 = tmp.uvec.z * 0.0;
    }
    else
    {
        v24 = tmp.rvec.x * -0.0 + tmp.lvec.x * -1.0 + tmp.uvec.x * -0.0;
        v25 = tmp.lvec.y * -1.0 + tmp.uvec.y * -0.0 + tmp.rvec.y * -0.0;
        v11 = tmp.rvec.z * -0.0;
        v12 = tmp.lvec.z * -1.0 + tmp.uvec.z * -0.0;
    }
    mat->rvec.x = mat->lvec.y * (v12 + v11) - mat->lvec.z * v25;
    mat->rvec.y = (mat->lvec.z * v24) - mat->lvec.x * (v12 + v11);
    mat->rvec.z = mat->lvec.x * v25 - mat->lvec.y * v24;
    rdVector_Normalize3Acc(&mat->rvec);
    mat->uvec.x = (mat->rvec.y * mat->lvec.z) - (mat->rvec.z * mat->lvec.y);
    mat->uvec.y = (mat->rvec.z * mat->lvec.x) - (mat->lvec.z * mat->rvec.x);
    mat->uvec.z = (mat->lvec.y * mat->rvec.x) - (mat->rvec.y * mat->lvec.x);
    rdVector_Normalize3Acc(&mat->uvec);
    mat->scale.x = eyePos->x;
    mat->scale.y = eyePos->y;
    mat->scale.z = eyePos->z;
}

void rdMatrix_ExtractAngles34(const rdMatrix34* NO_ALIAS mat, rdVector3 *pyr)
{
    flex_t v7; // ST08_4
    flex_t v9; // ST24_4
    flex_t v11; // ST00_4
    flex_d_t v13; // st7
    flex_t v17; // ST00_4
    flex_d_t v19; // st7
    flex_d_t v22; // st7
    flex_d_t v23; // st7
    flex_d_t v25; // st6
    flex_t v30; // [esp+18h] [ebp-10h]
    flex_t v31; // [esp+1Ch] [ebp-Ch]
    flex_t v32; // [esp+20h] [ebp-8h]
    flex_t v33; // [esp+2Ch] [ebp+4h]
    flex_t v34; // [esp+30h] [ebp+8h]
    flex_t v35; // [esp+30h] [ebp+8h]

    v33 = stdMath_Sqrt((mat->lvec.y * mat->lvec.y) + (mat->lvec.x * mat->lvec.x));
    if ( v33 < 0.001 )
    {
        pyr->z = 90.0 - stdMath_ArcSin3(mat->rvec.x);
        
        if ( -mat->lvec.y > 0.0 && mat->lvec.z > 0.0 || -mat->rvec.y < 0.0 && mat->lvec.z < 0.0 )
            pyr->z = -pyr->z;
        pyr->y = 0.0;
    }
    else
    {
        pyr->y = 90.0 - stdMath_ArcSin3(mat->lvec.y / v33);
        if (mat->lvec.x > 0.0)
            pyr->y = -pyr->y;
    }
    if ( v33 >= 0.001 )
    {
        v7 = (mat->lvec.y * mat->lvec.y) + (mat->lvec.x * mat->lvec.x);
        v22 = v7 / v33;
        if ( v22 < 1.0 )
        {
            v34 = v22;
            pyr->x = 90.0 - stdMath_ArcSin3(v34);
        }
        else
        {
            pyr->x = 0.0;
        }
    }
    else
    {
        pyr->x = 90.0;
    }
    if ( mat->lvec.z < 0.0 )
        pyr->x = -pyr->x;
    v23 = -mat->lvec.y;
    v25 = stdMath_Sqrt(v23 * v23 + (mat->lvec.x * mat->lvec.x));
    if (v25 >= 0.001)
    {
        v35 = (v23 * -mat->rvec.x + -mat->rvec.y * mat->lvec.x) / v25;
        if ( v35 < 1.0 )
        {
            if ( v35 > -1.0 )
                pyr->z = 90.0 - stdMath_ArcSin3(v35);
            else
                pyr->z = 180.0;
        }
        else
        {
            pyr->z = 0.0;
        }
        v9 = -mat->rvec.z;
        if ( v9 < 0.0 )
            pyr->z = -pyr->z;
    }
}

void rdMatrix_Normalize34(rdMatrix34 *mat)
{
    mat->uvec.x = (mat->rvec.y * mat->lvec.z) - (mat->rvec.z * mat->lvec.y);
    mat->uvec.y = (mat->rvec.z * mat->lvec.x) - (mat->lvec.z * mat->rvec.x);
    mat->uvec.z = (mat->lvec.y * mat->rvec.x) - (mat->rvec.y * mat->lvec.x);

    rdVector_Normalize3Acc(&mat->lvec);
    rdVector_Normalize3Acc(&mat->uvec);

    mat->rvec.x = (mat->uvec.z * mat->lvec.y) - (mat->uvec.y * mat->lvec.z);
    mat->rvec.y = (mat->lvec.z * mat->uvec.x) - (mat->uvec.z * mat->lvec.x);
    mat->rvec.z = (mat->uvec.y * mat->lvec.x) - (mat->lvec.y * mat->uvec.x);
}

void rdMatrix_Identity34(rdMatrix34 *out)
{
    stdPlatform_Memcpy32(out, &rdroid_identMatrix34, sizeof(*out));
}

void rdMatrix_Identity44(rdMatrix44 *out)
{
    stdPlatform_Memcpy32(out, &rdroid_identMatrix44, sizeof(*out));
}

// Added: word-safe copy -- destinations are frequently fields of aThings that
// may live in word-addressable-only memory (NDS extram)
void rdMatrix_Copy34(rdMatrix34 *dst, const rdMatrix34 *src)
{
    stdPlatform_Memcpy32(dst, src, sizeof(rdMatrix34));
}

void rdMatrix_Copy44(rdMatrix44 *dst, const rdMatrix44 *src)
{
    stdPlatform_Memcpy32(dst, src, sizeof(rdMatrix44));
}

void rdMatrix_Copy34to44(rdMatrix44 *dst, const rdMatrix34 *src)
{
    dst->vA.x = src->rvec.x;
    dst->vB.x = src->lvec.x;
    dst->vA.y = src->rvec.y;
    dst->vB.y = src->lvec.y;
    dst->vA.z = src->rvec.z;
    dst->vB.z = src->lvec.z;
    dst->vA.w = 0.0;
    dst->vB.w = 0.0;
    dst->vC.x = src->uvec.x;
    dst->vC.w = 0.0;
    dst->vC.y = src->uvec.y;
    dst->vD.x = src->scale.x;
    dst->vC.z = src->uvec.z;
    dst->vD.y = src->scale.y;
    dst->vD.z = src->scale.z;
    dst->vD.w = 1.0;
}

void rdMatrix_Copy44to34(rdMatrix34 *dst, const rdMatrix44 *src)
{
    dst->rvec.x = src->vA.x;
    dst->rvec.y = src->vA.y;
    dst->rvec.z = src->vA.z;
    dst->lvec.x = src->vB.x;
    dst->lvec.y = src->vB.y;
    dst->lvec.z = src->vB.z;
    dst->uvec.x = src->vC.x;
    dst->uvec.y = src->vC.y;
    dst->uvec.z = src->vC.z;
    dst->scale.x = src->vD.x;
    dst->scale.y = src->vD.y;
    dst->scale.z = src->vD.z;
}

void rdMatrix_Transpose44(rdMatrix44 *out, const rdMatrix44 *src)
{
    rdMatrix44 tmp;

    tmp.vA.x = src->vA.x;
    tmp.vA.y = src->vB.x;
    tmp.vA.z = src->vC.x;
    tmp.vA.w = src->vD.x;
    tmp.vB.x = src->vA.y;
    tmp.vB.y = src->vB.y;
    tmp.vB.z = src->vC.y;
    tmp.vB.w = src->vD.y;
    tmp.vC.x = src->vA.z;
    tmp.vC.y = src->vB.z;
    tmp.vC.z = src->vC.z;
    tmp.vC.w = src->vD.z;
    tmp.vD.x = src->vA.w;
    tmp.vD.y = src->vB.w;
    tmp.vD.z = src->vC.w;
    tmp.vD.w = src->vD.w;
    stdPlatform_Memcpy32(out, &tmp, sizeof(rdMatrix44));
}

void rdMatrix_Multiply34(rdMatrix34* NO_ALIAS dest, const rdMatrix34* NO_ALIAS a, const rdMatrix34* NO_ALIAS b)
{
    dest->rvec.x = (a->uvec.x * b->rvec.z)
                  + (b->rvec.y * a->lvec.x)
                  + (b->rvec.x * a->rvec.x);
    dest->rvec.y = (a->rvec.y * b->rvec.x)
                  + (a->lvec.y * b->rvec.y)
                  + (a->uvec.y * b->rvec.z);
    dest->rvec.z = (a->rvec.z * b->rvec.x)
                  + (a->uvec.z * b->rvec.z)
                  + (a->lvec.z * b->rvec.y);
    dest->lvec.x = (b->lvec.x * a->rvec.x)
                  + (b->lvec.z * a->uvec.x)
                  + (b->lvec.y * a->lvec.x);
    dest->lvec.y = (b->lvec.z * a->uvec.y)
                  + (b->lvec.y * a->lvec.y)
                  + (b->lvec.x * a->rvec.y);
    dest->lvec.z = (b->lvec.z * a->uvec.z)
                  + (a->lvec.z * b->lvec.y)
                  + (b->lvec.x * a->rvec.z);
    dest->uvec.x = (b->uvec.x * a->rvec.x)
                  + (b->uvec.y * a->lvec.x)
                  + (b->uvec.z * a->uvec.x);
    dest->uvec.y = (b->uvec.x * a->rvec.y)
                  + (b->uvec.y * a->lvec.y)
                  + (b->uvec.z * a->uvec.y);
    dest->uvec.z = (b->uvec.z * a->uvec.z)
                  + (b->uvec.x * a->rvec.z)
                  + (b->uvec.y * a->lvec.z);
    dest->scale.x = (b->scale.x * a->rvec.x)
                   + (b->scale.z * a->uvec.x)
                   + (b->scale.y * a->lvec.x)
                   + a->scale.x;
    dest->scale.y = (b->scale.x * a->rvec.y)
                   + (b->scale.y * a->lvec.y)
                   + (b->scale.z * a->uvec.y)
                   + a->scale.y;
    dest->scale.z = (b->scale.y * a->lvec.z) 
                   + (b->scale.x * a->rvec.z) 
                   + (b->scale.z * a->uvec.z) 
                   + a->scale.z;
}

void rdMatrix_Multiply44(rdMatrix44 *out, const rdMatrix44 *mat1, const rdMatrix44 *mat2)
{
    out->vA.x = mat2->vA.y * mat1->vB.x + mat1->vD.x * mat2->vA.w + mat1->vC.x * mat2->vA.z + mat2->vA.x * mat1->vA.x;
    out->vA.y = mat1->vA.y * mat2->vA.x + mat1->vC.y * mat2->vA.z + mat1->vD.y * mat2->vA.w + mat1->vB.y * mat2->vA.y;
    out->vA.z = mat1->vA.z * mat2->vA.x + mat1->vC.z * mat2->vA.z + mat1->vD.z * mat2->vA.w + mat1->vB.z * mat2->vA.y;
    out->vA.w = mat1->vA.w * mat2->vA.x + mat1->vC.w * mat2->vA.z + mat1->vD.w * mat2->vA.w + mat1->vB.w * mat2->vA.y;
    out->vB.x = mat2->vB.x * mat1->vA.x + mat2->vB.w * mat1->vD.x + mat2->vB.y * mat1->vB.x + mat2->vB.z * mat1->vC.x;
    out->vB.y = mat2->vB.x * mat1->vA.y + mat2->vB.z * mat1->vC.y + mat2->vB.w * mat1->vD.y + mat2->vB.y * mat1->vB.y;
    out->vB.z = mat2->vB.x * mat1->vA.z + mat2->vB.z * mat1->vC.z + mat2->vB.w * mat1->vD.z + mat2->vB.y * mat1->vB.z;
    out->vB.w = mat2->vB.x * mat1->vA.w + mat2->vB.w * mat1->vD.w + mat2->vB.z * mat1->vC.w + mat2->vB.y * mat1->vB.w;
    out->vC.x = mat2->vC.x * mat1->vA.x + mat2->vC.z * mat1->vC.x + mat2->vC.y * mat1->vB.x + mat2->vC.w * mat1->vD.x;
    out->vC.y = mat2->vC.x * mat1->vA.y + mat2->vC.y * mat1->vB.y + mat2->vC.w * mat1->vD.y + mat2->vC.z * mat1->vC.y;
    out->vC.z = mat2->vC.x * mat1->vA.z + mat2->vC.y * mat1->vB.z + mat2->vC.z * mat1->vC.z + mat2->vC.w * mat1->vD.z;
    out->vC.w = mat2->vC.x * mat1->vA.w + mat2->vC.y * mat1->vB.w + mat2->vC.w * mat1->vD.w + mat2->vC.z * mat1->vC.w;
    out->vD.x = mat2->vD.x * mat1->vA.x + mat2->vD.z * mat1->vC.x + mat2->vD.y * mat1->vB.x + mat2->vD.w * mat1->vD.x;
    out->vD.y = mat2->vD.w * mat1->vD.y + mat2->vD.y * mat1->vB.y + mat2->vD.x * mat1->vA.y + mat2->vD.z * mat1->vC.y;
    out->vD.z = mat2->vD.z * mat1->vC.z + mat2->vD.y * mat1->vB.z + mat2->vD.w * mat1->vD.z + mat2->vD.x * mat1->vA.z;
    out->vD.w = mat2->vD.w * mat1->vD.w + mat2->vD.y * mat1->vB.w + mat2->vD.x * mat1->vA.w + mat2->vD.z * mat1->vC.w;
}

void rdMatrix_PreMultiply34(rdMatrix34 *a, const rdMatrix34 *b)
{
    rdMatrix34 tmp;
    stdPlatform_Memcpy32(&tmp, a, sizeof(tmp));
    rdMatrix_Multiply34(a, &tmp, b);
}

void rdMatrix_PreMultiply44(rdMatrix44 *mat1, const rdMatrix44 *mat2)
{
    rdMatrix44 tmp;
    stdPlatform_Memcpy32(&tmp, mat1, sizeof(tmp));
    rdMatrix_Multiply44(mat1, &tmp, mat2);
}

void rdMatrix_PostMultiply34(rdMatrix34 *a, const rdMatrix34 *b)
{
    rdMatrix34 tmp;
    stdPlatform_Memcpy32(&tmp, a, sizeof(tmp));
    rdMatrix_Multiply34(a, b, &tmp);
}

void rdMatrix_PostMultiply44(rdMatrix44 *mat1, const rdMatrix44 *mat2)
{
    rdMatrix44 tmp;
    stdPlatform_Memcpy32(&tmp, mat1, sizeof(tmp));
    rdMatrix_Multiply44(mat1, mat2, &tmp);
}

void rdMatrix_PreRotate34(rdMatrix34 *mat, const rdVector3 *pyr)
{
    rdMatrix34 tmp;

    rdMatrix_BuildRotate34(&tmp, pyr);
    rdMatrix_PreMultiply34(mat, &tmp);
}

void rdMatrix_PreRotate44(rdMatrix44 *out, const rdVector3 *rot)
{
    rdMatrix44 a;

    rdMatrix_BuildRotate44(&a, rot);
    rdMatrix_PreMultiply44(out, &a);
}

void rdMatrix_PostRotate34(rdMatrix34 *mat, const rdVector3 *vecPYR)
{
    rdMatrix34 a;

    rdMatrix_BuildRotate34(&a, vecPYR);
    rdMatrix_PostMultiply34(mat, &a);
}

void rdMatrix_PostRotate44(rdMatrix44 *out, const rdVector3 *rot)
{
    rdMatrix44 a;

    rdMatrix_BuildRotate44(&a, rot);
    rdMatrix_PostMultiply44(out, &a);
}

void rdMatrix_PreTranslate34(rdMatrix34 *mat, const rdVector3 *vec)
{
    rdMatrix34 mat2;

    stdPlatform_Memcpy32(&mat2, &rdroid_identMatrix34, sizeof(mat2));
    mat2.scale.x = vec->x;
    mat2.scale.y = vec->y;
    mat2.scale.z = vec->z;
    rdMatrix_PreMultiply34(mat, &mat2);
}

void rdMatrix_PreTranslate44(rdMatrix44 *out, const rdVector3 *tV)
{
    rdMatrix44 mTmp;

    stdPlatform_Memcpy32(&mTmp, &rdroid_identMatrix44, sizeof(mTmp));
    mTmp.vD.w = 1.0;
    mTmp.vD.x = tV->x;
    mTmp.vD.y = tV->y;
    mTmp.vD.z = tV->z;
    rdMatrix_PreMultiply44(out, &mTmp);
}

void rdMatrix_PostTranslate34(rdMatrix34 *pMat, const rdVector3 *pVec)
{
    rdMatrix34 mat2;

    stdPlatform_Memcpy32(&mat2, &rdroid_identMatrix34, sizeof(mat2));
    mat2.scale.x = pVec->x;
    mat2.scale.y = pVec->y;
    mat2.scale.z = pVec->z;
    rdMatrix_PostMultiply34(pMat, &mat2);
}

void rdMatrix_PostTranslate44(rdMatrix44 *out, const rdVector3 *tV)
{
    rdMatrix44 mTmp;

    stdPlatform_Memcpy32(&mTmp, &rdroid_identMatrix44, sizeof(mTmp));
    mTmp.vD.w = 1.0;
    mTmp.vD.x = tV->x;
    mTmp.vD.y = tV->y;
    mTmp.vD.z = tV->z;
    rdMatrix_PostMultiply44(out, &mTmp);
}

void rdMatrix_PreScale34(rdMatrix34 *mat, const rdVector3 *vec)
{
    rdMatrix34 tmp;

    tmp.rvec.y = 0.0;
    tmp.rvec.z = 0.0;
    tmp.lvec.x = 0.0;
    tmp.rvec.x = vec->x;
    tmp.lvec.y = vec->y;
    tmp.uvec.z = vec->z;
    tmp.scale.x = 0.0;
    tmp.scale.y = 0.0;
    tmp.lvec.z = 0.0;
    tmp.uvec.x = 0.0;
    tmp.uvec.y = 0.0;
    tmp.scale.z = 0.0;
    rdMatrix_PreMultiply34(mat, &tmp);
}

void rdMatrix_PreScale44(rdMatrix44 *out, const rdVector4 *scale)
{
    rdMatrix44 tmp;

    tmp.vA.y = 0.0;
    tmp.vA.z = 0.0;
    tmp.vB.x = 0.0;
    tmp.vA.x = scale->x;
    tmp.vB.y = scale->y;
    tmp.vC.z = scale->z;
    tmp.vD.x = 0.0;
    tmp.vD.y = 0.0;
    tmp.vB.z = 0.0;
    tmp.vC.x = 0.0;
    tmp.vC.y = 0.0;
    tmp.vA.w = 1.0;
    tmp.vD.z = 0.0;
    rdMatrix_PreMultiply44(out, &tmp);
}

void rdMatrix_PostScale34(rdMatrix34 *mat, const rdVector3 *vec)
{
    rdMatrix34 tmp;

    tmp.rvec.y = 0.0;
    tmp.rvec.z = 0.0;
    tmp.lvec.x = 0.0;
    tmp.rvec.x = vec->x;
    tmp.lvec.y = vec->y;
    tmp.uvec.z = vec->z;
    tmp.scale.x = 0.0;
    tmp.scale.y = 0.0;
    tmp.lvec.z = 0.0;
    tmp.uvec.x = 0.0;
    tmp.uvec.y = 0.0;
    tmp.scale.z = 0.0;
    rdMatrix_PostMultiply34(mat, &tmp);
}

void rdMatrix_PostScale44(rdMatrix44 *out, const rdVector4 *scale)
{
    rdMatrix44 tmp;

    tmp.vA.y = 0.0;
    tmp.vA.z = 0.0;
    tmp.vB.x = 0.0;
    tmp.vA.x = scale->x;
    tmp.vB.y = scale->y;
    tmp.vC.z = scale->z;
    tmp.vD.x = 0.0;
    tmp.vD.y = 0.0;
    tmp.vB.z = 0.0;
    tmp.vC.x = 0.0;
    tmp.vC.y = 0.0;
    tmp.vA.w = 1.0;
    tmp.vD.z = 0.0;
    rdMatrix_PostMultiply44(out, &tmp);
}

void rdMatrix_SetRowVector34(rdMatrix34 *m, int row, const rdVector3 *in)
{
    *(&m->rvec + row) = *in;
}

void rdMatrix_SetRowVector44(rdMatrix44 *m, int row, const rdVector4 *in)
{
    *(&m->vA + row) = *in;
}

void rdMatrix_GetRowVector34(rdMatrix34 *m, int row, rdVector3 *out)
{
    rdVector3 *v3;

    v3 = &m->rvec + row;
    rdVector_Copy3(out, v3);
}

void rdMatrix_GetRowVector44(rdMatrix44 *m, int row, rdVector4 *out)
{
    rdVector4 *v3;

    v3 = &m->vA + row;
    rdVector_Copy4(out, v3);
}

void rdMatrix_TransformVector34(rdVector3 *dest, const rdVector3 *src, const rdMatrix34 *mat)
{
    flex_d_t v3; // st5
    flex_d_t v4; // st4
    flex_d_t v5; // st3
    flex_d_t v6; // st6
    flex_d_t v7; // st7
    flex_d_t v8; // rt2
    flex_d_t v9; // st3
    flex_d_t v10; // st4
    flex_d_t v11; // st5

    v3 = mat->uvec.y;
    v4 = mat->lvec.y;
    v5 = mat->uvec.z;
    v6 = mat->lvec.z;
    v7 = src->z;
    dest->x = mat->uvec.x * v7 + mat->lvec.x * src->y + mat->rvec.x * src->x;
    v8 = v5;
    v9 = src->z;
    v10 = v3 * v7 + v4 * src->y + mat->rvec.y * src->x;
    v11 = src->y;
    dest->y = v10;
    dest->z = v8 * v9 + v6 * v11 + mat->rvec.z * src->x;
}

void rdMatrix_TransformVectorOrtho34(rdVector3* NO_ALIAS dest, const rdVector3* NO_ALIAS src, const rdMatrix34 *mat)
{
    flex_d_t v3; // st5
    flex_d_t v4; // st4
    flex_d_t v5; // st3
    flex_d_t v6; // st6
    flex_d_t v7; // st7
    flex_d_t v8; // rt2
    flex_d_t v9; // st3
    flex_d_t v10; // st4
    flex_d_t v11; // st5

    v3 = mat->lvec.z;
    v4 = mat->lvec.y;
    v5 = mat->uvec.z;
    v6 = mat->uvec.y;
    v7 = src->z;
    dest->x = mat->rvec.z * v7 + mat->rvec.y * src->y + mat->rvec.x * src->x;
    v8 = v5;
    v9 = src->z;
    v10 = v3 * v7 + v4 * src->y + mat->lvec.x * src->x;
    v11 = src->y;
    dest->y = v10;
    dest->z = v8 * v9 + v6 * v11 + mat->uvec.x * src->x;
}

void rdMatrix_TransformVector34Acc(rdVector3* NO_ALIAS dest, const rdMatrix34 *mat)
{
    rdVector3 tmp;

    tmp.x = mat->uvec.x * dest->z + mat->lvec.x * dest->y + mat->rvec.x * dest->x;
    tmp.y = mat->lvec.y * dest->y + mat->uvec.y * dest->z + mat->rvec.y * dest->x;
    tmp.z = mat->uvec.z * dest->z + mat->lvec.z * dest->y + mat->rvec.z * dest->x;
    *dest = tmp;
}

void rdMatrix_TransformVector44(rdMatrix44 *pOut, const rdVector4 *pTrans4, const rdMatrix44 *pIn)
{
    pOut->vA.x = (pIn->vD.x * pTrans4->w + pIn->vC.x * pTrans4->z) + (pIn->vB.x * pTrans4->y + pIn->vA.x * pTrans4->x);
    pOut->vA.y = (pIn->vD.y * pTrans4->w + pIn->vC.y * pTrans4->z) + (pIn->vB.y * pTrans4->y + pIn->vA.y * pTrans4->x);
    pOut->vA.z = (pIn->vD.z * pTrans4->w + pIn->vC.z * pTrans4->z) + (pIn->vB.z * pTrans4->y + pIn->vA.z * pTrans4->x);
    pOut->vA.w = (pIn->vD.w * pTrans4->w + pIn->vC.w * pTrans4->z) + (pIn->vB.w * pTrans4->y + pIn->vA.w * pTrans4->x);
}

void rdMatrix_TransformVector44Acc(rdVector4 *a1, const rdMatrix44 *a2)
{
    flex_t v2; // ST00_4
    flex_t v3; // ST04_4
    flex_t v4; // ST08_4
    flex_d_t v5; // st6
    flex_d_t v6; // st7

    v2 = a2->vC.x * a1->z + a2->vD.x * a1->w + a2->vB.x * a1->y + a2->vA.x * a1->x;
    v3 = a2->vC.y * a1->z + a2->vD.y * a1->w + a2->vB.y * a1->y + a2->vA.y * a1->x;
    v4 = a2->vC.z * a1->z + a2->vD.z * a1->w + a2->vB.z * a1->y + a2->vA.z * a1->x;
    v5 = a2->vA.w * a1->x;
    v6 = a2->vC.w * a1->z + a2->vD.w * a1->w + a2->vB.w * a1->y;
    a1->x = v2;
    a1->y = v3;
    a1->z = v4;
    a1->w = v6 + v5;
}

void rdMatrix_TransformPoint34(rdVector3* NO_ALIAS dest, const rdVector3* NO_ALIAS src, const rdMatrix34 *mat)
{
    dest->x = mat->lvec.x * src->y + mat->uvec.x * src->z + mat->rvec.x * src->x + mat->scale.x;
    dest->y = (mat->lvec.y * src->y + mat->uvec.y * src->z + mat->rvec.y * src->x) + mat->scale.y;
    dest->z = mat->uvec.z * src->z + mat->lvec.z * src->y + mat->rvec.z * src->x + mat->scale.z;
}

void rdMatrix_TransformPoint34Acc(rdVector3* NO_ALIAS dest, const rdMatrix34 *mat)
{
    rdVector3 tmp;
    stdPlatform_Memcpy32(&tmp, dest, sizeof(tmp));
    
    rdMatrix_TransformPoint34(dest, &tmp, mat);
}

void rdMatrix_TransformPoint44(rdVector4 *a1, const rdVector4 *a2, const rdMatrix44 *a3)
{
    a1->x = (a3->vB.x * a2->y) + (a3->vC.x * a2->z) + (a3->vA.x * a2->x) + a3->vD.x;
    a1->y = (a3->vB.y * a2->y) + (a3->vC.y * a2->z) + (a3->vA.y * a2->x) + a3->vD.y;
    a1->z = (a3->vB.z * a2->y) + (a3->vC.z * a2->z) + (a3->vA.z * a2->x) + a3->vD.z;
    a1->w = (a3->vB.w * a2->y) + (a3->vC.w * a2->z) + (a3->vA.w * a2->x) + a3->vD.z;
}

void rdMatrix_TransformPoint44Acc(rdVector4 *a1, const rdMatrix44 *a2)
{
    rdVector4 tmp;
    stdPlatform_Memcpy32(&tmp, a1, sizeof(tmp));
    
    rdMatrix_TransformPoint44(a1, &tmp, a2);
}

void rdMatrix_TransformPointList34(const rdMatrix34 *mat, const rdVector3 *aSrc, rdVector3 *aDest, int size)
{
    for (int i = 0; i < size; i++)
    {
        rdMatrix_TransformPoint34(&aDest[i], &aSrc[i], mat);
    }
}

void rdMatrix_TransformPointLst44(const rdMatrix44 *m, const rdVector4 *in, rdVector4 *out, int num)
{
    for (int i = 0; i < num; i++)
    {
        rdMatrix_TransformPoint44(&out[i], &in[i], m);
    }
}

// Added
void rdMatrix_Print34(const rdMatrix34 *m)
{
    jk_printf("%f %f %f\n", m->rvec.x, m->rvec.y, m->rvec.z);
    jk_printf("%f %f %f\n", m->lvec.x, m->lvec.y, m->lvec.z);
    jk_printf("%f %f %f\n", m->uvec.x, m->uvec.y, m->uvec.z);
    jk_printf("%f %f %f\n", m->scale.x, m->scale.y, m->scale.z);
    jk_printf("--------\n");
}
