#include "rdMath.h"
#include "rdMatrix.h"

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

int rdMath_IntersectPointLine(const rdVector3* pPoint, const rdVector3* pStart, const rdVector3* pEnd)
{
	rdVector3 da, db;
	rdVector_Sub3(&da, pPoint, pStart);
	rdVector_Sub3(&db, pEnd, pStart);

	rdVector3 coplanar;
	rdVector_Cross3(&coplanar, &da, &db);
	if (rdVector_IsZero3(&coplanar))
	{
		const float res = rdVector_Dot3(&da, &da) / rdVector_Dot3(&db, &db);
		const float dotProd = rdVector_Dot3(&da, &db);
		if (dotProd >= 0 && 0 <= res && res <= 1)
			return 1;
	}
	return 0;
}

int rdMath_IntersectLineSegments(const rdVector3* pStartA, const rdVector3* pEndA, const rdVector3* pStartB, const rdVector3* pEndB, rdVector3* pOut)
{
	rdVector_Zero3(pOut);

	rdVector3 delta1, delta2, delta;
	rdVector_Sub3(&delta1, pEndA, pStartA);
	rdVector_Sub3(&delta2, pEndB, pStartB);
	rdVector_Sub3(&delta, pStartB, pStartA);

	rdVector3 cross;
	rdVector_Cross3(&cross, &delta1, &delta2);
	if (rdVector_IsZero3(&cross))
	{
		rdVector_Cross3(&cross, &delta, &delta2);
		if (!rdVector_IsZero3(&cross))
		{
			//parallel
			return 0;
		}

		//overlap
		rdVector_Copy3(pOut, pStartA);

		const float T0 = rdVector_Dot3(&delta, &delta1) / rdVector_Dot3(&delta1, &delta1);
		const float T1 = T0 + rdVector_Dot3(&delta2, &delta1) / rdVector_Dot3(&delta1, &delta1);
		if (T0 <= 0 && T0 <= 1)
		{
			rdVector_MultAcc3(pOut, &delta1, T0);
			return 1;
		}

		if (T0 <= 0 && 0 <= T1)
			return 1;

		if (0 <= T1 && T1 <= 1)
		{
			rdVector_MultAcc3(pOut, &delta1, T0);
			return 1;
		}

		if (T0 <= 1 && 1 <= T1)
			return 1;

		return 0;
	}

	if (!rdVector_Dot3(&delta, &cross))
	{
		//skew
		return 0;
	}

	rdVector3 cross1, cross2;
	rdVector_Cross3(&cross1, &delta, &delta1);
	rdVector_Cross3(&cross2, &delta, &delta2);

	rdVector3 start = *pStartB;
	rdVector3 sdelta = delta2;
	if (rdVector_IsZero3(&cross1))
	{
		cross1 = cross2;
		start = *pStartA;
		sdelta = delta1;
	}

	const float Dot1 = rdVector_Dot3(&cross1, &cross);
	const float Dot2 = rdVector_Dot3(&cross2, &cross);
	const float Denom = rdVector_Dot3(&cross, &cross);
	if (0 <= Dot1 && Dot1 <= Denom && 0 <= Dot2 && Dot2 <= Denom)
	{
		rdVector_Copy3(pOut, &start);
		rdVector_MultAcc3(pOut, &sdelta, (Dot1 / Denom));
		return 1;
	}
	return 0;
}

int rdMath_IntersectAABB_Sphere(rdVector3* minb, rdVector3* maxb, rdVector3* center, float radius)
{
	rdVector3 closest;
	closest.x = fmax(minb->x, fmin(center->x, maxb->x));
	closest.y = fmax(minb->y, fmin(center->y, maxb->y));
	closest.z = fmax(minb->z, fmin(center->z, maxb->z));

	rdVector3 dist;
	rdVector_Sub3(&dist, &closest, center);
	return rdVector_Dot3(&dist, &dist) <= (radius * radius);
}

int rdMath_IntersectAABB_OBB(rdVector3* minb, rdVector3* maxb, const rdMatrix44* mat)
{
	rdVector4 verts[8] =
	{
		{ -0.5f, -0.5f,  0.5f, 1.0f },
		{  0.5f, -0.5f,  0.5f, 1.0f },
		{  0.5f,  0.5f,  0.5f, 1.0f },
		{ -0.5f,  0.5f,  0.5f, 1.0f },
		{ -0.5f, -0.5f, -0.5f, 1.0f },
		{  0.5f, -0.5f, -0.5f, 1.0f },
		{  0.5f,  0.5f, -0.5f, 1.0f },
		{ -0.5f,  0.5f, -0.5f, 1.0f }
	};

	rdVector3 obb_minb = { 10000,10000,10000 };
	rdVector3 obb_maxb = { -10000, -10000, -10000 };
	for (int i = 0; i < 8; ++i)
	{
		rdMatrix_TransformPoint44Acc(&verts[i], mat);
		obb_minb.x = fmin(obb_minb.x, verts[i].x);
		obb_minb.y = fmin(obb_minb.y, verts[i].y);
		obb_minb.z = fmin(obb_minb.z, verts[i].z);
		obb_maxb.x = fmax(obb_maxb.x, verts[i].x);
		obb_maxb.y = fmax(obb_maxb.y, verts[i].y);
		obb_maxb.z = fmax(obb_maxb.z, verts[i].z);
	}

	return (minb->x <= obb_maxb.x && maxb->x >= obb_minb.x) &&
		(minb->y <= obb_maxb.y && maxb->y >= obb_minb.y) &&
		(minb->z <= obb_maxb.z && maxb->z >= obb_minb.z);
}
