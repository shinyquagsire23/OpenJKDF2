#include "rdVector.h"

#include <math.h>
#include "rdMatrix.h"
#include "General/stdMath.h"
#include "Primitives/rdMath.h"

#ifdef TARGET_TWL
#include <nds.h>
#endif

const rdVector2 rdroid_zeroVector2 = {0.0, 0.0};
const rdVector3 rdroid_zeroVector3 = {0.0,0.0,0.0};
const rdVector3 rdroid_xVector3 = {1.0,0.0,0.0};
const rdVector3 rdroid_yVector3 = {0.0,1.0,0.0};
const rdVector3 rdroid_zVector3 = {0.0,0.0,1.0};

rdVector2* rdVector_Set2(rdVector2* dest, flex_t x, flex_t y)
{
    dest->x = x;
    dest->y = y;
    return dest;
}

rdVector3* rdVector_Set3(rdVector3* dest, flex_t x, flex_t y, flex_t z)
{
    dest->x = x;
    dest->y = y;
    dest->z = z;
    return dest;
}

rdVector4* rdVector_Set4(rdVector4* dest, flex_t x, flex_t y, flex_t z, flex_t w)
{
    dest->x = x;
    dest->y = y;
    dest->z = z;
    dest->w = w;
    return dest;
}

void rdVector_Copy2(rdVector2* dest, const rdVector2* src)
{
    dest->x = src->x;
    dest->y = src->y;
}

void rdVector_Copy3(rdVector3* dest, const rdVector3* src)
{
    dest->x = src->x;
    dest->y = src->y;
    dest->z = src->z;
}

void rdVector_Copy4(rdVector4* dest, const rdVector4* src)
{
    dest->x = src->x;
    dest->y = src->y;
    dest->z = src->z;
    dest->w = src->w;
}

rdVector2* rdVector_Neg2(rdVector2* dest, const rdVector2* src)
{
    dest->x = -src->x;
    dest->y = -src->y;
    return dest;
}

rdVector3* rdVector_Neg3(rdVector3* dest, const rdVector3* src)
{
    dest->x = -src->x;
    dest->y = -src->y;
    dest->z = -src->z;
    return dest;
}

rdVector4* rdVector_Neg4(rdVector4* dest, const rdVector4* src)
{
    dest->x = -src->x;
    dest->y = -src->y;
    dest->z = -src->z;
    dest->w = -src->w;
    return dest;
}

rdVector2* rdVector_Neg2Acc(rdVector2* a)
{
    a->x = -a->x;
    a->y = -a->y;
    return a;
}

rdVector3* rdVector_Neg3Acc(rdVector3* a)
{
    a->x = -a->x;
    a->y = -a->y;
    a->z = -a->z;
    return a;
}

rdVector4* rdVector_Neg4Acc(rdVector4* a)
{
    a->x = -a->x;
    a->y = -a->y;
    a->z = -a->z;
    a->w = -a->w;
    return a;
}

rdVector2* rdVector_Add2(rdVector2* c, const rdVector2* a, const rdVector2* b)
{
    c->x = a->x + b->x;
    c->y = a->y + b->y;
    return c;
}

rdVector3* rdVector_Add3(rdVector3* c, const rdVector3* a, const rdVector3* b)
{
    c->x = a->x + b->x;
    c->y = a->y + b->y;
    c->z = a->z + b->z;
    return c;
}

rdVector4* rdVector_Add4(rdVector4* c, const rdVector4* a, const rdVector4* b)
{
    c->x = a->x + b->x;
    c->y = a->y + b->y;
    c->z = a->z + b->z;
    c->w = a->w + b->w;
    return c;
}

rdVector2* rdVector_Add2Acc(rdVector2* a, const rdVector2* b)
{
    a->x = b->x + a->x;
    a->y = b->y + a->y;
    return a;
}

rdVector3* rdVector_Add3Acc(rdVector3* a, const rdVector3* b)
{
    a->x = b->x + a->x;
    a->y = b->y + a->y;
    a->z = b->z + a->z;
    return a;
}

rdVector4* rdVector_Add4Acc(rdVector4* a, const rdVector4* b)
{
    a->x = b->x + a->x;
    a->y = b->y + a->y;
    a->z = b->z + a->z;
    a->w = b->w + a->w;
    return a;
}


rdVector2* rdVector_Sub2(rdVector2* c, const rdVector2* a, const rdVector2* b)
{
    c->x = a->x - b->x;
    c->y = a->y - b->y;
    return c;
}

rdVector3* rdVector_Sub3(rdVector3* c, const rdVector3* a, const rdVector3* b)
{
    c->x = a->x - b->x;
    c->y = a->y - b->y;
    c->z = a->z - b->z;
    return c;
}

rdVector4* rdVector_Sub4(rdVector4* c, const rdVector4* a, const rdVector4* b)
{
    c->x = a->x - b->x;
    c->y = a->y - b->y;
    c->z = a->z - b->z;
    c->w = a->w - b->w;
    return c;
}

rdVector2* rdVector_Sub2Acc(rdVector2* a, const rdVector2* b)
{
    a->x = -b->x + a->x;
    a->y = -b->y + a->y;
    return a;
}

rdVector3* rdVector_Sub3Acc(rdVector3* a, const rdVector3* b)
{
    a->x = -b->x + a->x;
    a->y = -b->y + a->y;
    a->z = -b->z + a->z;
    return a;
}

rdVector4* rdVector_Sub4Acc(rdVector4* a, const rdVector4* b)
{
    a->x = -b->x + a->x;
    a->y = -b->y + a->y;
    a->z = -b->z + a->z;
    a->w = -b->w + a->w;
    return a;
}

flex_t rdVector_Dot2(const rdVector2* a, const rdVector2* b)
{
    return (a->x * b->x) + (a->y * b->y);
}

flex_t rdVector_Dot3(const rdVector3* a, const rdVector3* b)
{
    return (a->x * b->x) + (a->y * b->y) + (a->z * b->z);
}

flex_t rdVector_Dot4(const rdVector4* a, const rdVector4* b)
{
    return (a->x * b->x) + (a->y * b->y) + (a->z * b->z) + (a->w * b->w);
}

void rdVector_Cross3(rdVector3 *dest, const rdVector3 *v1, const rdVector3 *v2)
{
    dest->x = (v2->z * v1->y) - (v1->z * v2->y);
    dest->y = (v1->z * v2->x) - (v2->z * v1->x);
    dest->z = (v2->y * v1->x) - (v1->y * v2->x);
}

void rdVector_Cross3Acc(rdVector3 *dest, const rdVector3 *v2)
{
    dest->x = (v2->z * dest->y) - (dest->z * v2->y);
    dest->y = (dest->z * v2->x) - (v2->z * dest->x);
    dest->z = (v2->y * dest->x) - (dest->y * v2->x);
}

flex_t rdVector_Len2(const rdVector2* v)
{
    return stdMath_Sqrt(rdVector_Dot2(v,v));
}

flex_t rdVector_Len3(const rdVector3* vec)
{
#if defined(TARGET_TWL) && defined(EXPERIMENTAL_FIXED_POINT)
    int64_t val = ((int64_t)vec->x.to_raw()*vec->x.to_raw())+((int64_t)vec->y.to_raw()*vec->y.to_raw())+((int64_t)vec->z.to_raw()*vec->z.to_raw());
    return sqrt64fixed_mine_2(val);
#else
    return stdMath_Sqrt(rdVector_Dot3(vec,vec));
#endif
}

flex_t rdVector_Len4(const rdVector4* a)
{
    return stdMath_Sqrt(rdVector_Dot4(a,a));
}

flex_t rdVector_Normalize2(rdVector2 *dest, const rdVector2 *src)
{
    flex_t len = rdVector_Len2(src);
    if (len == 0.0)
    {
        dest->x = src->x;
        dest->y = src->y;
    }
    else
    {
        dest->x = src->x / len;
        dest->y = src->y / len;
    }
    return len;
}

flex_t rdVector_Normalize3(rdVector3 *dest, const rdVector3 *src)
{
#if defined(TARGET_TWL) && defined(EXPERIMENTAL_FIXED_POINT)
#if 0
    static int last_frame = 0;
    static int num_sqrts = 0;
    extern int std3D_frameCount;
    if (last_frame != std3D_frameCount) {
        printf("norms %d\n", num_sqrts);
        last_frame = std3D_frameCount;
        num_sqrts = 0;
    }
    num_sqrts += 1;
#endif

    flex_t len = sqrt64fixed_mine_2(((int64_t)src->x.to_raw()*src->x.to_raw())+((int64_t)src->y.to_raw()*src->y.to_raw())+((int64_t)src->z.to_raw()*src->z.to_raw()));
    //flex_t len = rdVector_Len3(v2);
    if (len == 0.0)
    {
        dest->x = src->x;
        dest->y = src->y;
        dest->z = src->z;
    }
    else
    {
        dest->x = divflex_mine(src->x, len);
        dest->y = divflex_mine(src->y, len);
        dest->z = divflex_mine(src->z, len);

        //v1->x = f32toflex(divf32_mine(flextof32(v2->x), flextof32(len)));
        //v1->y = f32toflex(divf32_mine(flextof32(v2->y), flextof32(len)));
        //v1->z = f32toflex(divf32_mine(flextof32(v2->z), flextof32(len)));
    }
    return len;
#else
    flex_t len = rdVector_Len3(src);
    if (len == 0.0)
    {
        dest->x = src->x;
        dest->y = src->y;
        dest->z = src->z;
    }
    else
    {
        dest->x = src->x / len;
        dest->y = src->y / len;
        dest->z = src->z / len;
    }
    return len;
#endif
}

flex_t rdVector_Normalize3Quick(rdVector3 *v1, const rdVector3 *v2)
{
    flex_t series_1;
    flex_t series_2;
    flex_t series_3;

    flex_t x_pos = (v2->x >= 0.0) ? v2->x : -v2->x;
    flex_t y_pos = (v2->y >= 0.0) ? v2->y : -v2->y;
    flex_t z_pos = (v2->z >= 0.0) ? v2->z : -v2->z;

    series_1 = x_pos;
    series_2 = z_pos;
    series_3 = y_pos;

    if (z_pos <= y_pos)
    {
        if (x_pos < y_pos)
        {
            series_3 = x_pos;
            series_1 = y_pos;
            if (z_pos > x_pos)
            {
                series_2 = x_pos;
                series_3 = z_pos;
            }
        }
    }
    else if (z_pos <= x_pos)
    {
        series_2 = y_pos;
        series_3 = z_pos;
    }
    else
    {
        series_2 = x_pos;
        series_1 = z_pos;
        if (y_pos < x_pos)
        {
            series_2 = y_pos;
            series_3 = x_pos;
        }
    }

    flex_t len = ((0.34375 * series_3) + (0.25 * series_2) + series_1);
    flex_t len_recip = 1.0 / len;
    v1->x = v2->x * len_recip;
    v1->y = v2->y * len_recip;
    v1->z = v2->z * len_recip;
    return len;
}

flex_t rdVector_Normalize4(rdVector4 *dest, const rdVector4 *src)
{
    flex_t len = rdVector_Len4(src);
    if (len == 0.0)
    {
        dest->x = src->x;
        dest->y = src->y;
        dest->z = src->z;
        dest->w = src->w;
    }
    else
    {
        dest->x = src->x / len;
        dest->y = src->y / len;
        dest->z = src->z / len;
        dest->w = src->w / len;
    }
    return len;
}

flex_t rdVector_Normalize2Acc(rdVector2 *vec)
{
    flex_t len = rdVector_Len2(vec);
    if (len == 0.0)
    {
        vec->x = vec->x;
        vec->y = vec->y;
    }
    else
    {
        vec->x = vec->x / len;
        vec->y = vec->y / len;
    }
    return len;
}

flex_t rdVector_Normalize3Acc(rdVector3 *vec)
{
    flex_t len = rdVector_Len3(vec);
    if (len == 0.0)
    {
        vec->x = vec->x;
        vec->y = vec->y;
        vec->z = vec->z;
    }
    else
    {
        vec->x = vec->x / len;
        vec->y = vec->y / len;
        vec->z = vec->z / len;
    }
    return len;
}

flex_t rdVector_Normalize3QuickAcc(rdVector3 *src)
{
    flex_t series_1;
    flex_t series_2;
    flex_t series_3;

    flex_t x_pos = (src->x >= 0.0) ? src->x : -src->x;
    flex_t y_pos = (src->y >= 0.0) ? src->y : -src->y;
    flex_t z_pos = (src->z >= 0.0) ? src->z : -src->z;

    series_1 = x_pos;
    series_2 = z_pos;
    series_3 = y_pos;

    if (z_pos <= y_pos)
    {
        if (x_pos < y_pos)
        {
            series_3 = x_pos;
            series_1 = y_pos;
            if (z_pos > x_pos)
            {
                series_2 = x_pos;
                series_3 = z_pos;
            }
        }
    }
    else if (z_pos <= x_pos)
    {
        series_2 = y_pos;
        series_3 = z_pos;
    }
    else
    {
        series_2 = x_pos;
        series_1 = z_pos;
        if (y_pos < x_pos)
        {
            series_2 = y_pos;
            series_3 = x_pos;
        }
    }

    flex_t len = ((0.34375 * series_3) + (0.25 * series_2) + series_1);
    // Added: prevent div 0
    if (len == 0.0) {
        len = 0.00000001;
    }
    flex_t len_recip = 1.0 / len;
    src->x = src->x * len_recip;
    src->y = src->y * len_recip;
    src->z = src->z * len_recip;
    return len;
}

flex_t rdVector_Normalize4Acc(rdVector4 *vec)
{
    flex_t len = rdVector_Len4(vec);
    if (len == 0.0)
    {
        vec->x = vec->x;
        vec->y = vec->y;
        vec->z = vec->z;
        vec->w = vec->w;
    }
    else
    {
        vec->x = vec->x / len;
        vec->y = vec->y / len;
        vec->z = vec->z / len;
        vec->w = vec->w / len;
    }
    return len;
}

rdVector2* rdVector_Scale2(rdVector2 *dest, const rdVector2 *src, flex_t scalar)
{
    dest->x = src->x * scalar;
    dest->y = src->y * scalar;
    return dest;
}

rdVector3* rdVector_Scale3(rdVector3 *dest, const rdVector3 *src, flex_t scalar)
{
    dest->x = src->x * scalar;
    dest->y = src->y * scalar;
    dest->z = src->z * scalar;
    return dest;
}

rdVector4* rdVector_Scale4(rdVector4 *dest, const rdVector4 *src, flex_t scalar)
{
    dest->x = src->x * scalar;
    dest->y = src->y * scalar;
    dest->z = src->z * scalar;
    dest->w = src->w * scalar;
    return dest;
}

rdVector2* rdVector_Scale2Acc(rdVector2 *v, flex_t scalar)
{
    v->x = v->x * scalar;
    v->y = v->y * scalar;
    return v;
}

rdVector3* rdVector_Scale3Acc(rdVector3 *v, flex_t scalar)
{
    v->x = v->x * scalar;
    v->y = v->y * scalar;
    v->z = v->z * scalar;
    return v;
}

rdVector4* rdVector_Scale4Acc(rdVector4 *v, flex_t scalar)
{
    v->x = v->x * scalar;
    v->y = v->y * scalar;
    v->z = v->z * scalar;
    v->w = v->w * scalar;
    return v;
}

rdVector2* rdVector_InvScale2(rdVector2 *dest, const rdVector2 *src, flex_t scalar)
{
    dest->x = src->x / scalar;
    dest->y = src->y / scalar;
    return dest;
}

rdVector3* rdVector_InvScale3(rdVector3 *dest, const rdVector3 *src, flex_t scalar)
{
    dest->x = src->x / scalar;
    dest->y = src->y / scalar;
    dest->z = src->z / scalar;
    return dest;
}

rdVector4* rdVector_InvScale4(rdVector4 *dest, const rdVector4 *src, flex_t scalar)
{
    dest->x = src->x / scalar;
    dest->y = src->y / scalar;
    dest->z = src->z / scalar;
    dest->w = src->w / scalar;
    return dest;
}

rdVector2* rdVector_InvScale2Acc(rdVector2 *v, flex_t scalar)
{
    v->x = v->x / scalar;
    v->y = v->y / scalar;
    return v;
}

rdVector3* rdVector_InvScale3Acc(rdVector3 *v, flex_t scalar)
{
    v->x = v->x / scalar;
    v->y = v->y / scalar;
    v->z = v->z / scalar;
    return v;
}

rdVector4* rdVector_InvScale4Acc(rdVector4 *v, flex_t scalar)
{
    v->x = v->x / scalar;
    v->y = v->y / scalar;
    v->z = v->z / scalar;
    v->w = v->w / scalar;
    return v;
}

void rdVector_Rotate3(rdVector3 *vec, const rdVector3 *pivot, const rdVector3 *pyr)
{
    rdMatrix34 tmp;

    rdMatrix_BuildRotate34(&tmp, pyr);
    rdMatrix_TransformVector34(vec, pivot, &tmp);
}

void rdVector_Rotate3Acc(rdVector3 *vec, const rdVector3 *pyr)
{
    rdMatrix34 tmp;

    rdMatrix_BuildRotate34(&tmp, pyr);
    rdMatrix_TransformVector34Acc(vec, &tmp);
}

void rdVector_ExtractAngle(const rdVector3 *v1, rdVector3 *out)
{
    out->x = stdMath_ArcSin3(v1->z);
    out->y = stdMath_ArcTan4(v1->y, v1->x);
    out->z = 0.0;
}

// Added
flex_t rdVector_Dist3(const rdVector3 *a, const rdVector3 *b)
{
    rdVector3 tmp;
    
    rdVector_Sub3(&tmp, a, b);
    return rdVector_Len3(&tmp);
}

// Added
flex_t rdVector_DistSquared3(const rdVector3 *v1, const rdVector3 *v2)
{
    rdVector3 tmp;
    
    rdVector_Sub3(&tmp, v1, v2);
    return rdVector_Dot3(&tmp,&tmp);
}

rdVector3* rdVector_ScaleAdd3Acc(rdVector3 *dest, const rdVector3 *src, flex_t scalar)
{
    dest->x += src->x * scalar;
    dest->y += src->y * scalar;
    dest->z += src->z * scalar;
    return dest;
}

void rdVector_Zero3(rdVector3 *v)
{
    rdVector_Copy3(v, &rdroid_zeroVector3);
}

void rdVector_Zero2(rdVector2 *v)
{
    rdVector_Copy2(v, &rdroid_zeroVector2);
}

int rdVector_IsZero3(const rdVector3* v)
{
    return (v->x == 0.0 && v->y == 0.0 && v->z == 0.0);
}

flex_t rdVector_NormalDot(const rdVector3* v1, const rdVector3* v2, const rdVector3* norm)
{
    return rdMath_DistancePointToPlane(v1, norm, v2);
}

void rdVector_AbsRound3(rdVector3* v)
{
    v->x = stdMath_ClipNearZero(stdMath_Fabs(v->x));
    v->y = stdMath_ClipNearZero(stdMath_Fabs(v->y));
    v->z = stdMath_ClipNearZero(stdMath_Fabs(v->z));
}

void rdVector_ClipPrecision3(rdVector3* v)
{
    v->x = stdMath_ClipNearZero(v->x);
    v->y = stdMath_ClipNearZero(v->y);
    v->z = stdMath_ClipNearZero(v->z);
}

void rdVector_NormalizeAngleAcute3(rdVector3* v)
{
    v->x = stdMath_NormalizeAngleAcute(v->x);
    v->y = stdMath_NormalizeAngleAcute(v->y);
    v->z = stdMath_NormalizeAngleAcute(v->z);
}

void rdVector_ClampRange3(rdVector3* v, flex_t minVal, flex_t maxVal)
{
    if (v->x < minVal)
    {
        v->x = minVal;
    }
    
    if (v->x > maxVal)
    {
        v->x = maxVal;
    }
    
    if (v->y < minVal)
    {
        v->y = minVal;
    }
    
    if (v->y > maxVal)
    {
        v->y = maxVal;
    }
    
    if (v->z < minVal)
    {
        v->z = minVal;
    }
    
    if (v->z > maxVal)
    {
        v->z = maxVal;
    }
}

void rdVector_ClampValue3(rdVector3* v, flex_t val)
{
    flex_t valAbs = val;
    if (valAbs < 0.0)
    {
        valAbs = -valAbs;
    }

    rdVector_ClampRange3(v, -valAbs, valAbs);
}
