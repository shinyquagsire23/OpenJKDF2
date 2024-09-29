#include "rdMatrix.h"

#include "jk.h"
#include <math.h>
#include "General/stdMath.h"

const rdMatrix34 rdroid_identMatrix34 = {{1.0, 0.0, 0.0}, 
                                         {0.0, 1.0, 0.0}, 
                                         {0.0, 0.0, 1.0},
                                         {0.0, 0.0, 0.0}};

const rdMatrix44 rdroid_identMatrix44 = {{1.0, 0.0, 0.0, 0.0},
                                         {0.0, 1.0, 0.0, 0.0}, 
                                         {0.0, 0.0, 1.0, 0.0}, 
                                         {0.0, 0.0, 0.0, 1.0}};

void rdMatrix_Build34(rdMatrix34 *out, const rdVector3 *rot, const rdVector3 *pos)
{
    float x_rad_sin, x_rad_cos;
    float y_rad_sin, y_rad_cos;
    float z_rad_sin, z_rad_cos;
    rdVector3 *scale;

    scale = &out->scale;

    stdMath_SinCos(rot->x, &x_rad_sin, &x_rad_cos);
    stdMath_SinCos(rot->y, &y_rad_sin, &y_rad_cos);
    stdMath_SinCos(rot->z, &z_rad_sin, &z_rad_cos);
    out->rvec.x = -(z_rad_sin * y_rad_sin) * x_rad_sin + (z_rad_cos * y_rad_cos);
    out->rvec.y = ((z_rad_sin * y_rad_cos) * x_rad_sin) + (z_rad_cos * y_rad_sin);
    out->rvec.z = -z_rad_sin * x_rad_cos;
    out->lvec.x = -y_rad_sin * x_rad_cos;
    out->lvec.y = (y_rad_cos * x_rad_cos);
    out->lvec.z = x_rad_sin;
    out->uvec.x = ((z_rad_cos * y_rad_sin) * x_rad_sin) + (z_rad_sin * y_rad_cos);
    out->uvec.y = -x_rad_sin * (y_rad_cos * z_rad_cos) + (y_rad_sin*z_rad_sin);
    out->uvec.z = z_rad_cos * x_rad_cos;
    scale->x = pos->x;
    scale->y = pos->y;
    scale->z = pos->z;
}

void rdMatrix_BuildFromLook34(rdMatrix34 *out, const rdVector3 *lookAt)
{
    rdVector_Copy3(&out->lvec, lookAt);

    out->rvec.x = (out->lvec.y * 1.0) - (out->lvec.z * 0.0);
    out->rvec.y = (out->lvec.z * 0.0) - (out->lvec.x * 1.0);
    out->rvec.z = (out->lvec.x * 0.0) - (out->lvec.y * 0.0);
    if (rdVector_Normalize3Acc(&out->rvec) == 0.0)
    {
        out->uvec.x = (out->lvec.z * 0.0) - (out->lvec.y * 0.0);
        out->uvec.y = (out->lvec.x * 0.0) - (out->lvec.z * 1.0);
        out->uvec.z = (out->lvec.y * 1.0) - (out->lvec.x * 0.0);
        rdVector_Normalize3Acc(&out->uvec);
        out->rvec.x = out->uvec.z * out->lvec.y - out->uvec.y * out->lvec.z;
        out->rvec.y = (out->uvec.x * out->lvec.z) - (out->uvec.z * out->lvec.x);
        out->rvec.z = (out->uvec.y * out->lvec.x) - (out->uvec.x * out->lvec.y);
    }
    else
    {
        out->uvec.x = (out->lvec.z * out->rvec.y) - (out->rvec.z * out->lvec.y);
        out->uvec.y = (out->rvec.z * out->lvec.x) - (out->lvec.z * out->rvec.x);
        out->uvec.z = (out->lvec.y * out->rvec.x) - (out->lvec.x * out->rvec.y);
    }
}

void rdMatrix_BuildCamera34(rdMatrix34 *out, const rdVector3 *rot, const rdVector3 *pos)
{
    rdVector3 a, b;
    rdVector_Neg3(&a, rot);
    rdVector_Neg3(&b, pos);
    rdMatrix_Build34(out, &a, &b);
}

void rdMatrix_InvertOrtho34(rdMatrix34 *out, const rdMatrix34 *in)
{
    out->rvec.y = in->lvec.x;
    out->lvec.z = in->uvec.y;
    out->uvec.x = in->rvec.z;
    out->rvec.z = in->uvec.x;
    out->rvec.x = in->rvec.x;
    out->lvec.x = in->rvec.y;
    out->lvec.y = in->lvec.y;
    out->uvec.y = in->lvec.z;
    out->uvec.z = in->uvec.z;
    out->scale.x = -((in->rvec.y * in->scale.y) + (in->rvec.z * in->scale.z) + (in->rvec.x * in->scale.x));
    out->scale.y = -(in->lvec.x * in->scale.x + in->lvec.z * in->scale.z + in->lvec.y * in->scale.y);
    out->scale.z = -((in->uvec.y * in->scale.y) + (in->uvec.x * in->scale.x) + (in->uvec.z * in->scale.z));
}

void rdMatrix_Build44(rdMatrix44 *out, const rdVector3 *rot, const rdVector3 *pos)
{
    float x_rad_sin, x_rad_cos;
    float y_rad_sin, y_rad_cos;
    float z_rad_sin, z_rad_cos;

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

void rdMatrix_BuildRotate34(rdMatrix34 *out, const rdVector3 *rot)
{
    rdVector3 zeroVec = {0,0,0}; // TODO this is a global const
    rdMatrix_Build34(out, rot, &zeroVec);
}

void rdMatrix_BuildInverseRotate34(rdMatrix34 *out, const rdVector3 *rot)
{
    float x_rad_sin, x_rad_cos;
    float y_rad_sin, y_rad_cos;
    float z_rad_sin, z_rad_cos;

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

void rdMatrix_BuildTranslate34(rdMatrix34 *out, const rdVector3 *tV)
{
    _memcpy(out, &rdroid_identMatrix34, sizeof(rdMatrix34));
    rdVector_Copy3(&out->scale, tV);
}

void rdMatrix_BuildTranslate44(rdMatrix44 *out, const rdVector3 *tV)
{
    _memcpy(out, &rdroid_identMatrix44, sizeof(rdMatrix44));
    out->vD.x = tV->x;
    out->vD.y = tV->y;
    out->vD.z = tV->z;
    out->vD.w = 1.0;
}

void rdMatrix_BuildScale34(rdMatrix34 *out, const rdVector3 *scale)
{
    out->rvec.x = scale->x;
    out->rvec.y = 0.0;
    out->rvec.z = 0.0;
    
    out->lvec.x = 0.0;
    out->lvec.y = scale->y;
    out->lvec.z = 0.0;
    
    out->uvec.x = 0.0;
    out->uvec.y = 0.0;
    out->uvec.z = scale->z;

    out->scale.x = 0.0;
    out->scale.y = 0.0;
    out->scale.z = 0.0;
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

void rdMatrix_BuildFromVectorAngle34(rdMatrix34 *out, const rdVector3 *v, float angle)
{
    float v12;
    float v44;
    float v51;
    float angleRad_sin, angleRad_cos;

    stdMath_SinCos(angle, &angleRad_sin, &angleRad_cos);
    if ( v->z >= 1.0 )
    {
        out->rvec.x = angleRad_cos;
        out->lvec.y = angleRad_cos;
        out->lvec.x = -angleRad_sin;
        out->rvec.y = angleRad_sin;
        out->rvec.z = 0.0;
        out->lvec.z = 0.0;
        out->uvec.x = 0.0;
        out->uvec.y = 0.0;
        out->uvec.z = 1.0;
        out->scale.x = 0.0;
        out->scale.y = 0.0;
        out->scale.z = 0.0;
        return;
    }
    if ( v->z <= -1.0 )
    {
        out->rvec.x = angleRad_cos;
        out->lvec.y = angleRad_cos;
        out->rvec.y = -angleRad_sin;
        out->lvec.x = angleRad_sin;
        out->rvec.z = 0.0;
        out->lvec.z = 0.0;
        out->uvec.x = 0.0;
        out->uvec.y = 0.0;
        out->uvec.z = 1.0;
        out->scale.x = 0.0;
        out->scale.y = 0.0;
        out->scale.z = 0.0;
        return;
    }
    v12 = v->x * v->x;
    v44 = v->y * v->y;
    v51 = 1.0 - v12 - v44;
    out->rvec.x = (((angleRad_cos * v12) * v51 + (angleRad_cos * v44)) / (1.0 - v51)) + (v->z * v->x * (1.0 - angleRad_cos));
    out->scale.x = 0.0;
    out->scale.y = 0.0;
    out->lvec.y = (((angleRad_cos * v44) * v51 + (angleRad_cos * v12)) / (1.0 - v51)) + v44;
    out->uvec.z = ((angleRad_cos * v12) + (angleRad_cos * v44)) + v51;
    out->rvec.y = (v->z * angleRad_sin) + ((v->y * v->x) * (1.0 - angleRad_cos));
    out->lvec.x = ((v->y * v->x) * (1.0 - angleRad_cos)) - (v->z * angleRad_sin);
    out->rvec.z = ((v->z * v->x) * (1.0 - angleRad_cos)) - ((v->y) * angleRad_sin);
    out->lvec.z = ((v->z * v->y) * (1.0 - angleRad_cos)) + (v->x * angleRad_sin);
    out->uvec.x = ((v->z * v->x) * (1.0 - angleRad_cos)) + ((v->y) * angleRad_sin);
    out->uvec.y = ((v->z * v->y) * (1.0 - angleRad_cos)) - (v->x * angleRad_sin);
    out->scale.z = 0.0;
}

// MOTS altered
void rdMatrix_LookAt(rdMatrix34 *out, const rdVector3 *v1, const rdVector3 *v2, float angle)
{
    float v7;
    float v11;
    float v12;
    float v24;
    float v25;
    rdMatrix34 tmp;

    out->lvec.x = v2->x - v1->x;
    out->lvec.y = v2->y - v1->y;
    out->lvec.z = v2->z - v1->z;
    rdVector_Normalize3Acc(&out->lvec);
    rdMatrix_BuildFromVectorAngle34(&tmp, &out->lvec, angle);
    v7 = (out->lvec.y * 0.0) + (out->lvec.x * 0.0) + (out->lvec.z * 1.0);
    if ( v7 < 0.0 )
        v7 = -v7;
    if ( v7 <= 0.999 )
    {
        v24 = tmp.rvec.x * 0.0 + tmp.lvec.x * 0.0 + tmp.uvec.x * 1.0;
        v25 = tmp.rvec.y * 0.0 + tmp.lvec.y * 0.0 + tmp.uvec.y * 1.0;
        v12 = tmp.rvec.z * 0.0 + tmp.lvec.z * 0.0;
        v11 = tmp.uvec.z * 1.0;
    }
    else if ( out->lvec.z <= 0.0 )
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
    out->rvec.x = out->lvec.y * (v12 + v11) - out->lvec.z * v25;
    out->rvec.y = (out->lvec.z * v24) - out->lvec.x * (v12 + v11);
    out->rvec.z = out->lvec.x * v25 - out->lvec.y * v24;
    rdVector_Normalize3Acc(&out->rvec);
    out->uvec.x = (out->rvec.y * out->lvec.z) - (out->rvec.z * out->lvec.y);
    out->uvec.y = (out->rvec.z * out->lvec.x) - (out->lvec.z * out->rvec.x);
    out->uvec.z = (out->lvec.y * out->rvec.x) - (out->rvec.y * out->lvec.x);
    rdVector_Normalize3Acc(&out->uvec);
    out->scale.x = v1->x;
    out->scale.y = v1->y;
    out->scale.z = v1->z;
}

void rdMatrix_ExtractAngles34(const rdMatrix34 *in, rdVector3 *out)
{
    float v7; // ST08_4
    float v9; // ST24_4
    float v11; // ST00_4
    double v13; // st7
    float v17; // ST00_4
    double v19; // st7
    double v22; // st7
    double v23; // st7
    long double v25; // st6
    float v30; // [esp+18h] [ebp-10h]
    float v31; // [esp+1Ch] [ebp-Ch]
    float v32; // [esp+20h] [ebp-8h]
    float v33; // [esp+2Ch] [ebp+4h]
    float v34; // [esp+30h] [ebp+8h]
    float v35; // [esp+30h] [ebp+8h]

    v33 = stdMath_Sqrt((in->lvec.y * in->lvec.y) + (in->lvec.x * in->lvec.x));
    if ( v33 < 0.001 )
    {
        v13 = 90.0 - stdMath_ArcSin3(in->rvec.x);
        
        // TODO ?? some floating point comparison, ah 41h
        if ( -in->lvec.y > 0.0 && in->lvec.z > 0.0 || -in->rvec.y < 0.0 && in->lvec.z < 0.0 )
            v13 = -v13;
        out->z = v13;
        out->y = 0.0;
    }
    else
    {
        out->y = 90.0 - stdMath_ArcSin3(in->lvec.y / v33);
        if (in->lvec.x > 0.0) // TODO ?? some floating point comparison, ah 41h
            out->y = -out->y;
    }
    if ( v33 >= 0.001 )
    {
        v7 = (in->lvec.y * in->lvec.y) + (in->lvec.x * in->lvec.x);
        v22 = v7 / v33;
        if ( v22 < 1.0 )
        {
            v34 = v22;
            out->x = 90.0 - stdMath_ArcSin3(v34);
        }
        else
        {
            out->x = 0.0;
        }
    }
    else
    {
        out->x = 90.0;
    }
    if ( in->lvec.z < 0.0 )
        out->x = -out->x;
    v23 = -in->lvec.y;
    v25 = stdMath_Sqrt(v23 * v23 + (in->lvec.x * in->lvec.x));
    if (v25 >= 0.001) // TODO verify
    {
        v35 = (v23 * -in->rvec.x + -in->rvec.y * in->lvec.x) / v25;
        if ( v35 < 1.0 )
        {
            if ( v35 > -1.0 )
                out->z = 90.0 - stdMath_ArcSin3(v35);
            else
                out->z = 180.0;
        }
        else
        {
            out->z = 0.0;
        }
        v9 = -in->rvec.z;
        if ( v9 < 0.0 )
            out->z = -out->z;
    }
}

void rdMatrix_Normalize34(rdMatrix34 *m)
{
    m->uvec.x = (m->rvec.y * m->lvec.z) - (m->rvec.z * m->lvec.y);
    m->uvec.y = (m->rvec.z * m->lvec.x) - (m->lvec.z * m->rvec.x);
    m->uvec.z = (m->lvec.y * m->rvec.x) - (m->rvec.y * m->lvec.x);

    rdVector_Normalize3Acc(&m->lvec);
    rdVector_Normalize3Acc(&m->uvec);

    m->rvec.x = (m->uvec.z * m->lvec.y) - (m->uvec.y * m->lvec.z);
    m->rvec.y = (m->lvec.z * m->uvec.x) - (m->uvec.z * m->lvec.x);
    m->rvec.z = (m->uvec.y * m->lvec.x) - (m->lvec.y * m->uvec.x);
}

void rdMatrix_Identity34(rdMatrix34 *out)
{
    _memcpy(out, &rdroid_identMatrix34, sizeof(*out));
}

void rdMatrix_Identity44(rdMatrix44 *out)
{
    _memcpy(out, &rdroid_identMatrix44, sizeof(*out));
}

void rdMatrix_Copy34(rdMatrix34 *dst, rdMatrix34 *src)
{
    _memcpy(dst, src, sizeof(rdMatrix34));
}

void rdMatrix_Copy44(rdMatrix44 *dst, rdMatrix44 *src)
{
    _memcpy(dst, src, sizeof(rdMatrix44));
}

void rdMatrix_Copy34to44(rdMatrix44 *dst, rdMatrix34 *src)
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

void rdMatrix_Copy44to34(rdMatrix34 *dst, rdMatrix44 *src)
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

void rdMatrix_Transpose44(rdMatrix44 *out, rdMatrix44 *src)
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
    _memcpy(out, &tmp, sizeof(rdMatrix44));
}

void rdMatrix_Multiply34(rdMatrix34 *out, const rdMatrix34 *mat1, const rdMatrix34 *mat2)
{
    out->rvec.x = (mat1->uvec.x * mat2->rvec.z)
                  + (mat2->rvec.y * mat1->lvec.x)
                  + (mat2->rvec.x * mat1->rvec.x);
    out->rvec.y = (mat1->rvec.y * mat2->rvec.x)
                  + (mat1->lvec.y * mat2->rvec.y)
                  + (mat1->uvec.y * mat2->rvec.z);
    out->rvec.z = (mat1->rvec.z * mat2->rvec.x)
                  + (mat1->uvec.z * mat2->rvec.z)
                  + (mat1->lvec.z * mat2->rvec.y);
    out->lvec.x = (mat2->lvec.x * mat1->rvec.x)
                  + (mat2->lvec.z * mat1->uvec.x)
                  + (mat2->lvec.y * mat1->lvec.x);
    out->lvec.y = (mat2->lvec.z * mat1->uvec.y)
                  + (mat2->lvec.y * mat1->lvec.y)
                  + (mat2->lvec.x * mat1->rvec.y);
    out->lvec.z = (mat2->lvec.z * mat1->uvec.z)
                  + (mat1->lvec.z * mat2->lvec.y)
                  + (mat2->lvec.x * mat1->rvec.z);
    out->uvec.x = (mat2->uvec.x * mat1->rvec.x)
                  + (mat2->uvec.y * mat1->lvec.x)
                  + (mat2->uvec.z * mat1->uvec.x);
    out->uvec.y = (mat2->uvec.x * mat1->rvec.y)
                  + (mat2->uvec.y * mat1->lvec.y)
                  + (mat2->uvec.z * mat1->uvec.y);
    out->uvec.z = (mat2->uvec.z * mat1->uvec.z)
                  + (mat2->uvec.x * mat1->rvec.z)
                  + (mat2->uvec.y * mat1->lvec.z);
    out->scale.x = (mat2->scale.x * mat1->rvec.x)
                   + (mat2->scale.z * mat1->uvec.x)
                   + (mat2->scale.y * mat1->lvec.x)
                   + mat1->scale.x;
    out->scale.y = (mat2->scale.x * mat1->rvec.y)
                   + (mat2->scale.y * mat1->lvec.y)
                   + (mat2->scale.z * mat1->uvec.y)
                   + mat1->scale.y;
    out->scale.z = (mat2->scale.y * mat1->lvec.z) 
                   + (mat2->scale.x * mat1->rvec.z) 
                   + (mat2->scale.z * mat1->uvec.z) 
                   + mat1->scale.z;
}

void rdMatrix_Multiply44(rdMatrix44 *out, rdMatrix44 *mat1, rdMatrix44 *mat2)
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

void rdMatrix_PreMultiply34(rdMatrix34 *mat1, rdMatrix34 *mat2)
{
    rdMatrix34 tmp;
    _memcpy(&tmp, mat1, sizeof(tmp));
    rdMatrix_Multiply34(mat1, &tmp, mat2);
}

void rdMatrix_PreMultiply44(rdMatrix44 *mat1, rdMatrix44 *mat2)
{
    rdMatrix44 tmp;
    _memcpy(&tmp, mat1, sizeof(tmp));
    rdMatrix_Multiply44(mat1, &tmp, mat2);
}

void rdMatrix_PostMultiply34(rdMatrix34 *mat1, rdMatrix34 *mat2)
{
    rdMatrix34 tmp;
    _memcpy(&tmp, mat1, sizeof(tmp));
    rdMatrix_Multiply34(mat1, mat2, &tmp);
}

void rdMatrix_PostMultiply44(rdMatrix44 *mat1, rdMatrix44 *mat2)
{
    rdMatrix44 tmp;
    _memcpy(&tmp, mat1, sizeof(tmp));
    rdMatrix_Multiply44(mat1, mat2, &tmp);
}

void rdMatrix_PreRotate34(rdMatrix34 *out, rdVector3 *rot)
{
    rdMatrix34 tmp;

    rdMatrix_BuildRotate34(&tmp, rot);
    rdMatrix_PreMultiply34(out, &tmp);
}

void rdMatrix_PreRotate44(rdMatrix44 *out, rdVector3 *rot)
{
    rdMatrix44 a;

    rdMatrix_BuildRotate44(&a, rot);
    rdMatrix_PreMultiply44(out, &a);
}

void rdMatrix_PostRotate34(rdMatrix34 *out, rdVector3 *rot)
{
    rdMatrix34 a;

    rdMatrix_BuildRotate34(&a, rot);
    rdMatrix_PostMultiply34(out, &a);
}

void rdMatrix_PostRotate44(rdMatrix44 *out, rdVector3 *rot)
{
    rdMatrix44 a;

    rdMatrix_BuildRotate44(&a, rot);
    rdMatrix_PostMultiply44(out, &a);
}

void rdMatrix_PreTranslate34(rdMatrix34 *out, rdVector3 *trans)
{
    rdMatrix34 mat2;

    _memcpy(&mat2, &rdroid_identMatrix34, sizeof(mat2));
    mat2.scale.x = trans->x;
    mat2.scale.y = trans->y;
    mat2.scale.z = trans->z;
    rdMatrix_PreMultiply34(out, &mat2);
}

void rdMatrix_PreTranslate44(rdMatrix44 *out, rdVector3 *tV)
{
    rdMatrix44 mTmp;

    _memcpy(&mTmp, &rdroid_identMatrix44, sizeof(mTmp));
    mTmp.vD.w = 1.0;
    mTmp.vD.x = tV->x;
    mTmp.vD.y = tV->y;
    mTmp.vD.z = tV->z;
    rdMatrix_PreMultiply44(out, &mTmp);
}

void rdMatrix_PostTranslate34(rdMatrix34 *out, rdVector3 *trans)
{
    rdMatrix34 mat2;

    _memcpy(&mat2, &rdroid_identMatrix34, sizeof(mat2));
    mat2.scale.x = trans->x;
    mat2.scale.y = trans->y;
    mat2.scale.z = trans->z;
    rdMatrix_PostMultiply34(out, &mat2);
}

void rdMatrix_PostTranslate44(rdMatrix44 *out, rdVector3 *tV)
{
    rdMatrix44 mTmp;

    _memcpy(&mTmp, &rdroid_identMatrix44, sizeof(mTmp));
    mTmp.vD.w = 1.0;
    mTmp.vD.x = tV->x;
    mTmp.vD.y = tV->y;
    mTmp.vD.z = tV->z;
    rdMatrix_PostMultiply44(out, &mTmp);
}

void rdMatrix_PreScale34(rdMatrix34 *out, rdVector3 *scale)
{
    rdMatrix34 tmp;

    tmp.rvec.y = 0.0;
    tmp.rvec.z = 0.0;
    tmp.lvec.x = 0.0;
    tmp.rvec.x = scale->x;
    tmp.lvec.y = scale->y;
    tmp.uvec.z = scale->z;
    tmp.scale.x = 0.0;
    tmp.scale.y = 0.0;
    tmp.lvec.z = 0.0;
    tmp.uvec.x = 0.0;
    tmp.uvec.y = 0.0;
    tmp.scale.z = 0.0;
    rdMatrix_PreMultiply34(out, &tmp);
}

void rdMatrix_PreScale44(rdMatrix44 *out, rdVector4 *scale)
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

void rdMatrix_PostScale34(rdMatrix34 *out, rdVector3 *scale)
{
    rdMatrix34 tmp;

    tmp.rvec.y = 0.0;
    tmp.rvec.z = 0.0;
    tmp.lvec.x = 0.0;
    tmp.rvec.x = scale->x;
    tmp.lvec.y = scale->y;
    tmp.uvec.z = scale->z;
    tmp.scale.x = 0.0;
    tmp.scale.y = 0.0;
    tmp.lvec.z = 0.0;
    tmp.uvec.x = 0.0;
    tmp.uvec.y = 0.0;
    tmp.scale.z = 0.0;
    rdMatrix_PostMultiply34(out, &tmp);
}

void rdMatrix_PostScale44(rdMatrix44 *out, rdVector4 *scale)
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

void rdMatrix_SetRowVector34(rdMatrix34 *m, int row, rdVector3 *in)
{
    *(&m->rvec + row) = *in;
}

void rdMatrix_SetRowVector44(rdMatrix44 *m, int row, rdVector4 *in)
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

void rdMatrix_TransformVector34(rdVector3 *out, const rdVector3 *v, const rdMatrix34 *m)
{
    double v3; // st5
    double v4; // st4
    double v5; // st3
    double v6; // st6
    double v7; // st7
    double v8; // rt2
    double v9; // st3
    double v10; // st4
    double v11; // st5

    v3 = m->uvec.y;
    v4 = m->lvec.y;
    v5 = m->uvec.z;
    v6 = m->lvec.z;
    v7 = v->z;
    out->x = m->uvec.x * v7 + m->lvec.x * v->y + m->rvec.x * v->x;
    v8 = v5;
    v9 = v->z;
    v10 = v3 * v7 + v4 * v->y + m->rvec.y * v->x;
    v11 = v->y;
    out->y = v10;
    out->z = v8 * v9 + v6 * v11 + m->rvec.z * v->x;
}

void rdMatrix_TransformVector34Acc_0(rdVector3 *a1, const rdVector3 *a2, const rdMatrix34 *a3)
{
    double v3; // st5
    double v4; // st4
    double v5; // st3
    double v6; // st6
    double v7; // st7
    double v8; // rt2
    double v9; // st3
    double v10; // st4
    double v11; // st5

    v3 = a3->lvec.z;
    v4 = a3->lvec.y;
    v5 = a3->uvec.z;
    v6 = a3->uvec.y;
    v7 = a2->z;
    a1->x = a3->rvec.z * v7 + a3->rvec.y * a2->y + a3->rvec.x * a2->x;
    v8 = v5;
    v9 = a2->z;
    v10 = v3 * v7 + v4 * a2->y + a3->lvec.x * a2->x;
    v11 = a2->y;
    a1->y = v10;
    a1->z = v8 * v9 + v6 * v11 + a3->uvec.x * a2->x;
}

void rdMatrix_TransformVector34Acc(rdVector3 *pAcc, const rdMatrix34 *pIn)
{
    rdVector3 tmp;

    tmp.x = pIn->uvec.x * pAcc->z + pIn->lvec.x * pAcc->y + pIn->rvec.x * pAcc->x;
    tmp.y = pIn->lvec.y * pAcc->y + pIn->uvec.y * pAcc->z + pIn->rvec.y * pAcc->x;
    tmp.z = pIn->uvec.z * pAcc->z + pIn->lvec.z * pAcc->y + pIn->rvec.z * pAcc->x;
    *pAcc = tmp;
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
    float v2; // ST00_4
    float v3; // ST04_4
    float v4; // ST08_4
    double v5; // st6
    double v6; // st7

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

void rdMatrix_TransformPoint34(rdVector3 *vOut, const rdVector3 *vIn, const rdMatrix34 *camera)
{
    vOut->x = camera->lvec.x * vIn->y + camera->uvec.x * vIn->z + camera->rvec.x * vIn->x + camera->scale.x;
    vOut->y = (camera->lvec.y * vIn->y + camera->uvec.y * vIn->z + camera->rvec.y * vIn->x) + camera->scale.y;
    vOut->z = camera->uvec.z * vIn->z + camera->lvec.z * vIn->y + camera->rvec.z * vIn->x + camera->scale.z;
}

void rdMatrix_TransformPoint34Acc(rdVector3 *a1, const rdMatrix34 *a2)
{
    rdVector3 tmp;
    _memcpy(&tmp, a1, sizeof(tmp));
    
    rdMatrix_TransformPoint34(a1, &tmp, a2);
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
    _memcpy(&tmp, a1, sizeof(tmp));
    
    rdMatrix_TransformPoint44(a1, &tmp, a2);
}

void rdMatrix_TransformPointLst34(const rdMatrix34 *m, const rdVector3 *in, rdVector3 *out, int num)
{
    for (int i = 0; i < num; i++)
    {
        rdMatrix_TransformPoint34(&out[i], &in[i], m);
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


int rdMatrix_ExtractAxisAngle34(rdMatrix34* m, rdVector3* axis, float* angle)
{
	float trace = m->rvec.x + m->lvec.y + m->uvec.z;

	if (trace <= -1)
	{
		if (m->rvec.x >= m->lvec.y && m->rvec.x >= m->uvec.z)
		{
			float r = 1 + m->rvec.x - m->lvec.y - m->uvec.z;
			if (r <= 1e-6f)
				return 0;

			r = stdMath_Sqrt(r);
			axis->x = 0.5f * r;
			axis->y = m->lvec.x / r;
			axis->z = m->uvec.x / r;
		}
		else if (m->lvec.y >= m->uvec.z)
		{
			float r = 1 + m->lvec.y - m->rvec.x - m->uvec.z;
			if (r <= 1e-6f)
				return 0;

			r = stdMath_Sqrt(r);
			axis->y = 0.5f * r;
			axis->x = m->lvec.x / r;
			axis->z = m->uvec.y / r;
		}
		else
		{
			float r = 1 + m->lvec.y - m->rvec.x - m->uvec.z;
			if (r <= 1e-6f)
				return 0;
			r = stdMath_Sqrt(r);
			axis->z = 0.5f * r;
			axis->x = m->uvec.x / r;
			axis->y = m->uvec.y / r;
		}
		*angle = 180.0f;
	}
	else if (trace >= 3)
	{
		rdVector_Set3(axis, 0.0f, 0.0f, 1.0f);
		*angle = 0;
	}
	else
	{
		axis->x = m->lvec.z - m->uvec.y;
		axis->y = m->uvec.x - m->rvec.z;
		axis->z = m->rvec.y - m->lvec.x;
		float r = rdVector_Dot3(axis, axis);
		if (r <= 1e-6f)
			return 0;

		rdVector_InvScale3Acc(axis, stdMath_Sqrt(r));
		*angle = 90.0f - stdMath_ArcSin3((trace - 1.0f) / 2.0f);

	}
	return 1;
}

void rdMatrix_BuildFromAxisAngle34(rdMatrix34* m, const rdVector3* axis, float angle)
{
	float c, s, t;
	rdVector3 sv, tv;

	angle = stdMath_NormalizeAngleAcute(angle);

	stdMath_SinCos(angle, &s, &c);

	t = 1.0f - c;

	rdVector_Scale3(&sv, axis, s);
	rdVector_Scale3(&tv, axis, t);

	m->rvec.x = tv.x * axis->x + c;
	m->rvec.y = tv.x * axis->y - sv.z;
	m->rvec.z = tv.x * axis->z + sv.y;

	m->lvec.x = tv.x * axis->y + sv.z;
	m->lvec.y = tv.y * axis->y + c;
	m->lvec.z = tv.y * axis->z - sv.x;

	m->uvec.x = tv.x * axis->z - sv.y;
	m->uvec.y = tv.y * axis->z + sv.x;
	m->uvec.z = tv.z * axis->z + c;

	m->scale.x = m->scale.y = m->scale.z = 0.0f;
}

void rdMatrix_Invert44(rdMatrix44* out, const rdMatrix44* m)
{
	float A2323 = m->vC.z * m->vD.w - m->vC.w * m->vD.z;
	float A1323 = m->vC.y * m->vD.w - m->vC.w * m->vD.y;
	float A1223 = m->vC.y * m->vD.z - m->vC.z * m->vD.y;
	float A0323 = m->vC.x * m->vD.w - m->vC.w * m->vD.x;
	float A0223 = m->vC.x * m->vD.z - m->vC.z * m->vD.x;
	float A0123 = m->vC.x * m->vD.y - m->vC.y * m->vD.x;
	float A2313 = m->vB.z * m->vD.w - m->vB.w * m->vD.z;
	float A1313 = m->vC.z * m->vD.w - m->vB.w * m->vD.y;
	float A1213 = m->vB.y * m->vD.z - m->vB.z * m->vD.y;
	float A2312 = m->vB.z * m->vC.w - m->vB.w * m->vC.z;
	float A1312 = m->vB.y * m->vC.w - m->vB.w * m->vC.y;
	float A1212 = m->vB.y * m->vC.z - m->vB.z * m->vC.y;
	float A0313 = m->vB.x * m->vD.w - m->vB.w * m->vD.x;
	float A0213 = m->vB.x * m->vD.z - m->vB.z * m->vD.x;
	float A0312 = m->vB.x * m->vC.w - m->vB.w * m->vC.x;
	float A0212 = m->vB.x * m->vC.z - m->vB.z * m->vC.x;
	float A0113 = m->vB.x * m->vD.y - m->vB.y * m->vD.x;
	float A0112 = m->vB.x * m->vC.y - m->vB.y * m->vC.x;
	float det = m->vA.x * (m->vB.y * A2323 - m->vB.z * A1323 + m->vB.w * A1223)
		- m->vA.y * (m->vB.x * A2323 - m->vB.z * A0323 + m->vB.w * A0223)
		+ m->vA.z * (m->vB.x * A1323 - m->vB.y * A0323 + m->vB.w * A0123)
		- m->vA.w * (m->vB.x * A1223 - m->vB.y * A0223 + m->vB.z * A0123);
	det = 1 / det;

	rdVector_Set4(&out->vA,
			det * (m->vB.y * A2323 - m->vB.z * A1323 + m->vB.w * A1223),
			det * -(m->vA.y * A2323 - m->vA.z * A1323 + m->vA.w * A1223),
			det * (m->vA.y * A2313 - m->vA.z * A1313 + m->vA.w * A1213),
			det * -(m->vA.y * A2312 - m->vA.z * A1312 + m->vA.w * A1212)
	);
	rdVector_Set4(&out->vB,
		   det * -(m->vB.x * A2323 - m->vB.z * A0323 + m->vB.w * A0223),
		   det * (m->vA.x * A2323 - m->vA.z * A0323 + m->vA.w * A0223),
		   det * -(m->vA.x * A2313 - m->vA.z * A0313 + m->vA.w * A0213),
		   det * (m->vA.x * A2312 - m->vA.z * A0312 + m->vA.w * A0212)
	);
	rdVector_Set4(&out->vC,
		   det * (m->vB.x * A1323 - m->vB.y * A0323 + m->vB.w * A0123),
		   det * -(m->vA.x * A1323 - m->vA.y * A0323 + m->vA.w * A0123),
		   det * (m->vA.x * A1313 - m->vA.y * A0313 + m->vA.w * A0113),
		   det * -(m->vA.x * A1312 - m->vA.y * A0312 + m->vA.w * A0112)
	);
	rdVector_Set4(&out->vD,
		   det * -(m->vB.x * A1223 - m->vB.y * A0223 + m->vB.z * A0123),
		   det * (m->vA.x * A1223 - m->vA.y * A0223 + m->vA.z * A0123),
		   det * -(m->vA.x * A1213 - m->vA.y * A0213 + m->vA.z * A0113),
		   det * (m->vA.x * A1212 - m->vA.y * A0212 + m->vA.z * A0112)
 );
}

// build a perspective projection matrix from horizontal fov and aspect ratio
// note: this also maps from Z-up world space to Y-up clip-space
void rdMatrix_BuildPerspective44(rdMatrix44* out, float fov, float aspect, float znear, float zfar)
{
	// todo: do we actually want opengl depth?
	float f = stdMath_Tan(fov / 2);
	rdVector_Set4(&out->vA, 1.0f / f, 0.0f,                0.0f,                                 0.0f);
	rdVector_Set4(&out->vB, 0.0f,     0.0f,                (zfar + znear) / (zfar - znear),      1.0f);
	rdVector_Set4(&out->vC, 0.0f,     1.0f / (f * aspect), 0.0f,                                 0.0f);
	rdVector_Set4(&out->vD, 0.0f,     0.0f,                2.0f * zfar * znear / (znear - zfar), 0.0f);
}

void rdMatrix_BuildOrthographic44(rdMatrix44* out, float left, float right, float top, float bottom, float znear, float zfar)
{
	out->vA.x = 2.0f / (right - left);
	out->vA.y = 0.0f;
	out->vA.z = 0.0f;
	out->vA.w = 0.0f;
	out->vB.x = 0.0f;
	out->vB.y = 2.0f / (top - bottom);
	out->vB.z = 0.0f;
	out->vB.w = 0.0f;
	out->vC.x = 0.0f;
	out->vC.y = 0.0f;
	out->vC.z = -2.0f / (zfar - znear);
	out->vC.w = 0.0f;
	out->vD.x = (left + right) / (left - right);
	out->vD.y = (bottom + top) / (bottom - top);
	out->vD.z = -(zfar + znear) / (zfar - znear);
	out->vD.w = 1.0f;
}

void rdMatrix_BuildLookAt34(rdMatrix34* out, const rdVector3* viewer, const rdVector3* target, const rdVector3* up)
{
	rdVector3 lvec;
	rdVector_Sub3(&lvec, target, viewer);
	rdVector_Normalize3Acc(&lvec);

	rdVector3 rvec;
	rdVector_Cross3(&rvec, &lvec, up);
	rdVector_Normalize3Acc(&rvec);

	rdVector3 uvec;
	rdVector_Cross3(&uvec, &lvec, &rvec);
	rdVector_Normalize3Acc(&uvec);

	rdVector_Set3(&out->rvec, rvec.x, lvec.x, uvec.x);
	rdVector_Set3(&out->lvec, rvec.y, lvec.y, uvec.y);
	rdVector_Set3(&out->uvec, rvec.z, lvec.z, uvec.z);
	rdVector_Set3(&out->scale, -rdVector_Dot3(&rvec, viewer), -rdVector_Dot3(&lvec, viewer), -rdVector_Dot3(&uvec, viewer));
}

int rdMatrix_Compare44(const rdMatrix44* a, const rdMatrix44* b)
{
	return memcmp(a, b, sizeof(rdMatrix44));
}