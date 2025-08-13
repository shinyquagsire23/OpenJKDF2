#include "rdMath.h"

#include "General/stdMath.h"

void rdMath_CalcSurfaceNormal(rdVector3 *out, rdVector3 *edge1, rdVector3 *edge2, rdVector3 *edge3)
{
    rdVector3 a;
    rdVector3 b;

    rdVector_Sub3(&b, edge2, edge1);
    rdVector_Sub3(&a, edge3, edge1);
    rdVector_Normalize3Acc(&b);
    rdVector_Normalize3Acc(&a);
    rdVector_Cross3(out, &b, &a);
    rdVector_Normalize3Acc(out);

    rdMath_ClampVector(out, 0.000001);
}

flex_t rdMath_DistancePointToPlane(const rdVector3 *light, const rdVector3 *normal, const rdVector3 *vertex)
{
  return (light->y - vertex->y) * normal->y + (light->z - vertex->z) * normal->z + (light->x - vertex->x) * normal->x;
}

flex_t rdMath_DeltaAngleNormalizedAbs(rdVector3 *a1, rdVector3 *a2)
{
    flex_t v2 = rdVector_Dot3(a1, a2);
    if ( v2 == 1.0 )
        return 0.0;
    return 90.0 - stdMath_ArcSin1(v2);
}

flex_t rdMath_DeltaAngleNormalized(rdVector3 *a1, rdVector3 *a2, rdVector3 *a3)
{
    flex_t v4 = stdMath_Clamp(rdVector_Dot3(a1, a2), -1.0, 1.0);

    if ( v4 == 1.0 )
        return 0.0;
    if ( v4 == -1.0 )
        return 180.0;
    
    flex_t v7 = 90.0 - stdMath_ArcSin1(v4);
    
    rdVector3 tmp;
    rdVector_Cross3(&tmp, a1, a2);
    if ( rdVector_Dot3(&tmp, a3) <= 0.0 )
        return -v7;
    else
        return v7;
}

void rdMath_ClampVector(rdVector3* out, flex_t minVal)
{
    if ( (out->x < 0.0 ? -out->x : out->x) >= minVal )
        out->x = out->x;
    else
        out->x = 0.0;
        
    if ( (out->y < 0.0 ? -out->y : out->y) >= minVal )
        out->y = out->y;
    else
        out->y = 0.0;
        
    if ( (out->z < 0.0 ? -out->z : out->z) >= minVal )
        out->z = out->z;
    else
        out->z = 0.0;
}

int rdMath_PointsCollinear(rdVector3 *a1, rdVector3 *a2, rdVector3 *a3)
{
    rdVector3 a;
    rdVector3 b;

    rdVector_Sub3(&b, a2, a1);
    rdVector_Sub3(&a, a3, a1);
    rdVector_Normalize3Acc(&b);
    rdVector_Normalize3Acc(&a);

    flex_t v16 = rdVector_Dot3(&a, &b);
    if ( v16 < 0.0 )
        v16 = -v16;
    return (v16 >= 0.99900001 && v16 <= 1.001);
}

// added
void rdMath_ClampVectorRange(rdVector3* out, flex_t minVal, flex_t maxVal)
{
    out->x = rdMath_clampf(out->x, minVal, maxVal);
    out->y = rdMath_clampf(out->y, minVal, maxVal);
    out->z = rdMath_clampf(out->z, minVal, maxVal);
}

flex_t rdMath_clampf(flex_t d, flex_t min, flex_t max)
{
  const flex_t t = d < min ? min : d;
  return t > max ? max : t;
}
