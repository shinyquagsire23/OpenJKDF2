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
static int (__cdecl *rdMath_PointsCollinear)(rdVector3 *a1, rdVector3 *a2, rdVector3 *a3) = (void*)rdMath_PointsCollinear_ADDR;
static void (__cdecl *rdMath_CalcSurfaceNormal)(rdVector3 *out, rdVector3 *edge1, rdVector3 *edge2, rdVector3 *edge3) = (void*)rdMath_CalcSurfaceNormal_ADDR;


#endif // _RDMATH_H
