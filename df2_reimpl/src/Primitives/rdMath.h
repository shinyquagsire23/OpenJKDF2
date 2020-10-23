#ifndef _RDMATH_H
#define _RDMATH_H

#include "Primitives/rdVector.h"

#define rdMath_CalcSurfaceNormal_ADDR (0x0046D250)
#define rdMath_DistancePointToPlane_ADDR (0x0046D3C0)
#define rdMath_DeltaAngleNormalizedAbs_ADDR (0x0046D400)
#define rdMath_DeltaAngleNormalized_ADDR (0x0046D450)
#define rdMath_ClampVector_ADDR (0x0046D570)
#define rdMath_PointsCollinear_ADDR (0x0046D600)

float rdMath_DistancePointToPlane(rdVector3 *light, rdVector3 *normal, rdVector3 *vertex);


#endif // _RDMATH_H
