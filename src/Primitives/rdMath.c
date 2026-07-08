#include "rdMath.h"

#include "General/stdMath.h"

void rdMath_CalcSurfaceNormal(rdVector3 *pDestNormal, rdVector3 *pVert1, rdVector3 *pVert2, rdVector3 *pVert3)
{
    rdVector3 a;
    rdVector3 b;

    rdVector_Sub3(&b, pVert2, pVert1);
    rdVector_Sub3(&a, pVert3, pVert1);
    rdVector_Normalize3Acc(&b);
    rdVector_Normalize3Acc(&a);
    rdVector_Cross3(pDestNormal, &b, &a);
    rdVector_Normalize3Acc(pDestNormal);

    rdMath_ClipVector3Acc(pDestNormal, 0.000001);
}

flex_t rdMath_DistancePointToPlane(const rdVector3 *pPoint, const rdVector3 *pPlaneNormal, const rdVector3 *pPointOnPlane)
{
  return (pPoint->y - pPointOnPlane->y) * pPlaneNormal->y + (pPoint->z - pPointOnPlane->z) * pPlaneNormal->z + (pPoint->x - pPointOnPlane->x) * pPlaneNormal->x;
}

flex_t rdMath_DeltaAngleNormalizedAbs(rdVector3 *pVectorX, rdVector3 *pVectorY)
{
    flex_t v2 = rdVector_Dot3(pVectorX, pVectorY);
    if ( v2 == 1.0 )
        return 0.0;
    return 90.0 - stdMath_ArcSin1(v2);
}

flex_t rdMath_DeltaAngleNormalized(rdVector3 *pVectorX, rdVector3 *pVectorY, rdVector3 *pVectorZ)
{
    flex_t v4 = stdMath_Clamp(rdVector_Dot3(pVectorX, pVectorY), -1.0, 1.0);

    if ( v4 == 1.0 )
        return 0.0;
    if ( v4 == -1.0 )
        return 180.0;
    
    flex_t v7 = 90.0 - stdMath_ArcSin1(v4);
    
    rdVector3 tmp;
    rdVector_Cross3(&tmp, pVectorX, pVectorY);
    if ( rdVector_Dot3(&tmp, pVectorZ) <= 0.0 )
        return -v7;
    else
        return v7;
}

void rdMath_ClipVector3Acc(rdVector3* vect, flex_t minVal)
{
    if ( (vect->x < 0.0 ? -vect->x : vect->x) >= minVal )
        vect->x = vect->x;
    else
        vect->x = 0.0;
        
    if ( (vect->y < 0.0 ? -vect->y : vect->y) >= minVal )
        vect->y = vect->y;
    else
        vect->y = 0.0;
        
    if ( (vect->z < 0.0 ? -vect->z : vect->z) >= minVal )
        vect->z = vect->z;
    else
        vect->z = 0.0;
}

int rdMath_PointsCollinear(rdVector3 *p1, rdVector3 *p2, rdVector3 *p3)
{
    rdVector3 a;
    rdVector3 b;

    rdVector_Sub3(&b, p2, p1);
    rdVector_Sub3(&a, p3, p1);
    rdVector_Normalize3Acc(&b);
    rdVector_Normalize3Acc(&a);

    flex_t v16 = rdVector_Dot3(&a, &b);
    if ( v16 < 0.0 )
        v16 = -v16;
    return (v16 >= 0.99900001 && v16 <= 1.001);
}

// added
void rdMath_ClampVector3Acc(rdVector3* vect, flex_t minVal, flex_t maxVal)
{
    vect->x = rdMath_clampf(vect->x, minVal, maxVal);
    vect->y = rdMath_clampf(vect->y, minVal, maxVal);
    vect->z = rdMath_clampf(vect->z, minVal, maxVal);
}

flex_t rdMath_clampf(flex_t d, flex_t min, flex_t max)
{
  const flex_t t = d < min ? min : d;
  return t > max ? max : t;
}
