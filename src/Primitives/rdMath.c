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

float rdMath_DistancePointToPlane(const rdVector3 *light, const rdVector3 *normal, const rdVector3 *vertex)
{
  return (light->y - vertex->y) * normal->y + (light->z - vertex->z) * normal->z + (light->x - vertex->x) * normal->x;
}

float rdMath_DeltaAngleNormalizedAbs(rdVector3 *a1, rdVector3 *a2)
{
    float v2 = rdVector_Dot3(a1, a2);
    if ( v2 == 1.0 )
        return 0.0;
    return 90.0 - stdMath_ArcSin1(v2);
}

float rdMath_DeltaAngleNormalized(rdVector3 *a1, rdVector3 *a2, rdVector3 *a3)
{
    float v4 = rdVector_Dot3(a1, a2);
    if ( v4 < -1.0 ) // TODO clamp macro
    {
        v4 = -1.0;
    }
    else if ( v4 > 1.0 )
    {
        v4 = 1.0;
    }

    if ( v4 == 1.0 )
        return 0.0;
    if ( v4 == -1.0 )
        return 180.0;
    
    float v7 = 90.0 - stdMath_ArcSin1(v4);
    
    rdVector3 tmp;
    rdVector_Cross3(&tmp, a1, a2);
    if ( rdVector_Dot3(&tmp, a3) <= 0.0 )
        return -v7;
    else
        return v7;
}

void rdMath_ClampVector(rdVector3* out, float minVal)
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

    float v16 = rdVector_Dot3(&a, &b);
    if ( v16 < 0.0 )
        v16 = -v16;
    return (v16 >= 0.99900001 && v16 <= 1.001);
}

// added
void rdMath_ClampVectorRange(rdVector3* out, float minVal, float maxVal)
{
    out->x = rdMath_clampf(out->x, minVal, maxVal);
    out->y = rdMath_clampf(out->y, minVal, maxVal);
    out->z = rdMath_clampf(out->z, minVal, maxVal);
}

float rdMath_clampf(float d, float min, float max)
{
  const float t = d < min ? min : d;
  return t > max ? max : t;
}
