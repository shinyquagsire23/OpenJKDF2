#ifndef _RDMATH_H
#define _RDMATH_H

#include "Primitives/rdVector.h"

#define rdMath_CalcSurfaceNormal_ADDR (0x0046D250)
#define rdMath_DistancePointToPlane_ADDR (0x0046D3C0)
#define rdMath_DeltaAngleNormalizedAbs_ADDR (0x0046D400)
#define rdMath_DeltaAngleNormalized_ADDR (0x0046D450)
#define rdMath_ClipVector3Acc_ADDR (0x0046D570)
#define rdMath_PointsCollinear_ADDR (0x0046D600)

MATH_FUNC FAST_FUNC flex_t rdMath_DistancePointToPlane(const rdVector3 *pPoint, const rdVector3 *pPlaneNormal, const rdVector3 *pPointOnPlane);
MATH_FUNC void rdMath_CalcSurfaceNormal(rdVector3 *pDestNormal, rdVector3 *pVert1, rdVector3 *pVert2, rdVector3 *pVert3);
MATH_FUNC flex_t rdMath_DeltaAngleNormalizedAbs(rdVector3 *pVectorX, rdVector3 *pVectorY);
MATH_FUNC flex_t rdMath_DeltaAngleNormalized(rdVector3 *pVectorX, rdVector3 *pVectorY, rdVector3 *pVectorZ);
MATH_FUNC void rdMath_ClipVector3Acc(rdVector3* vect, flex_t minVal);
MATH_FUNC int rdMath_PointsCollinear(rdVector3 *p1, rdVector3 *p2, rdVector3 *p3);

MATH_FUNC void rdMath_ClampVector3Acc(rdVector3* vect, flex_t minVal, flex_t maxVal);
MATH_FUNC flex_t rdMath_clampf(flex_t d, flex_t min, flex_t max);

#endif // _RDMATH_H
