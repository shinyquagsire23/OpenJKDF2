#ifndef _RDMATH_H
#define _RDMATH_H

#include "Primitives/rdVector.h"

#define rdMath_CalcSurfaceNormal_ADDR (0x0046D250)
#define rdMath_DistancePointToPlane_ADDR (0x0046D3C0)
#define rdMath_DeltaAngleNormalizedAbs_ADDR (0x0046D400)
#define rdMath_DeltaAngleNormalized_ADDR (0x0046D450)
#define rdMath_ClampVector_ADDR (0x0046D570)
#define rdMath_PointsCollinear_ADDR (0x0046D600)

MATH_FUNC flex_t rdMath_DistancePointToPlane(const rdVector3 *light, const rdVector3 *normal, const rdVector3 *vertex);
MATH_FUNC void rdMath_CalcSurfaceNormal(rdVector3 *out, rdVector3 *edge1, rdVector3 *edge2, rdVector3 *edge3);
MATH_FUNC flex_t rdMath_DeltaAngleNormalizedAbs(rdVector3 *a1, rdVector3 *a2);
MATH_FUNC flex_t rdMath_DeltaAngleNormalized(rdVector3 *a1, rdVector3 *a2, rdVector3 *a3);
MATH_FUNC void rdMath_ClampVector(rdVector3* out, flex_t minVal);
MATH_FUNC int rdMath_PointsCollinear(rdVector3 *a1, rdVector3 *a2, rdVector3 *a3);

MATH_FUNC void rdMath_ClampVectorRange(rdVector3* out, flex_t minVal, flex_t maxVal);
MATH_FUNC flex_t rdMath_clampf(flex_t d, flex_t min, flex_t max);

#endif // _RDMATH_H
