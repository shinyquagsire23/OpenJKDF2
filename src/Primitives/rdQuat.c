#include "rdQuat.h"

#include <math.h>
#include "rdMatrix.h"
#include "General/stdMath.h"
#include "Primitives/rdMath.h"

void rdQuat_Set(rdQuat* out, float x, float y, float z, float w)
{
	out->x = x;
	out->y = y;
	out->z = z;
	out->w = w;
}

void rdQuat_BuildFromAxisAngle(rdQuat* out, rdVector3* axis, float angle)
{
	float s, c;
	stdMath_SinCos(angle * 0.5f, &s, &c);
	out->w = c;
	out->x = axis->x * s;
	out->y = axis->y * s;
	out->z = axis->z * s;
}

void rdQuat_BuildFromVector(rdQuat* out, rdVector3* axis)
{
	rdQuat q0, q1, q2;
	rdQuat_BuildFromAxisAngle(&q0, &rdroid_zVector3, axis->y);
	rdQuat_BuildFromAxisAngle(&q1, &rdroid_xVector3, axis->x);
	rdQuat_BuildFromAxisAngle(&q2, &rdroid_yVector3, axis->z);
	rdQuat_Mul(out, &q0, &q1);
	rdQuat_MulAcc(out, &q2);
}

void rdQuat_ExtractAxisAngle(rdQuat* q, rdVector3* axis, float* angle)
{
	*angle = 2.0f * acosf(q->w);

	float omega = *angle / sinf(*angle * 0.5f);
	axis->x = q->x * omega;
	axis->y = q->y * omega;
	axis->z = q->z * omega;
}

void rdQuat_Mul(rdQuat* out, rdQuat* qa, rdQuat* qb)
{
	rdVector3 v1;
	v1.x = qa->x;
	v1.y = qa->y;
	v1.z = qa->z;

	rdVector3 v2;
	v2.x = qb->x;
	v2.y = qb->y;
	v2.z = qb->z;

	out->w = qa->w * qb->w - rdVector_Dot3(&v1, &v2);

	rdVector3 vp;
	rdVector_Cross3(&vp, &v1, &v2);

	out->x = v2.x * qa->w + v1.x * qa->w - vp.x;
	out->y = v2.y * qa->w + v1.y * qa->w - vp.y;
	out->z = v2.z * qa->w + v1.z * qa->w - vp.z;
}

void rdQuat_MulAcc(rdQuat* qa, rdQuat* qb)
{
	rdVector3 vp;
	vp.x = qb->x * qa->w + qa->x * qb->w - (qa->y * qb->z - qa->z * qb->y);
	vp.y = qb->y * qa->w + qa->y * qb->w - (qa->z * qb->x - qa->x * qb->z);
	vp.z = qb->z * qa->w + qa->z * qb->w - (qa->x * qb->y - qa->y * qb->x);
	qa->w = qa->w * qb->w - (qa->x * qb->x + qa->y * qb->y + qa->z * qb->z);
	qa->x = vp.x;
	qa->y = vp.y;
	qa->z = vp.z;
}

float rdQuat_LenSq(rdQuat* q)
{
	return q->x * q->x + q->y * q->y + q->z * q->z + q->w * q->w;
}

void rdQuat_Conjugate(rdQuat* out, const rdQuat* q)
{
	out->w =  q->w;
	out->x = -q->x;
	out->y = -q->y;
	out->z = -q->z;
}

void rdQuat_ConjugateAcc(rdQuat* q)
{
	q->x = -q->x;
	q->y = -q->y;
	q->z = -q->z;
}

void rdQuat_TransformVector(rdVector3* out, const rdQuat* q, const rdVector3* v)
{
	rdQuat vq;
	rdQuat_Set(&vq, v->x, v->y, v->z, 0.0f);

	rdQuat qh;
	rdQuat_Conjugate(&qh, q);

	rdQuat r;
	rdQuat_Mul(&r, q, &vq);
	rdQuat_MulAcc(&r, &qh);

	float len = rdQuat_LenSq(q);
	out->x = r.x / len;
	out->y = r.y / len;
	out->z = r.z / len;
}

void rdQuat_ToMatrix(rdMatrix34* out, const rdQuat* q)
{
	float sqw = q->w * q->w;
	float sqx = q->x * q->x;
	float sqy = q->y * q->y;
	float sqz = q->z * q->z;

	float invs = 1.0f / (sqx + sqy + sqz + sqw);

	float xy = q->x * q->y;
	float zw = q->z * q->w;

	float m00 = (sqx - sqy - sqz + sqw) * invs;
	float m11 = (-sqx + sqy - sqz + sqw) * invs;
	float m22 = (-sqx - sqy + sqz + sqw) * invs;

	float m10 = 2.0f * (xy + zw) * invs;
	float m01 = 2.0f * (xy - zw) * invs;

	float xz = q->x * q->z;
	float yw = q->y * q->w;

	float m20 = 2.0f * (xz - yw) * invs;
	float m02 = 2.0f * (xz + yw) * invs;

	float yz = q->y * q->z;
	float xw = q->x * q->w;

	float m21 = 2.0f * (yz + xw) * invs;
	float m12 = 2.0f * (yz - xw) * invs;

	out->rvec.x = m00;
	out->rvec.y = m01;
	out->rvec.z = m02;

	out->lvec.x = m10;
	out->lvec.y = m11;
	out->lvec.z = m12;

	out->uvec.x = m20;
	out->uvec.y = m21;
	out->uvec.z = m22;

	out->scale.x = out->scale.y = out->scale.z = 0.0f;
}

void rdQuat_Slerp(rdQuat* out, const rdQuat* qa, const rdQuat* qb, const float c)
{
	float comega = qa->x * qb->x + qa->y * qb->y + qa->z * qb->z + qa->w * qb->w;

	rdQuat q2;	
	if (comega < 0.0f)
	{
		comega = -comega;
		q2.x = -qb->x;
		q2.y = -qb->y;
		q2.z = -qb->z;
		q2.w = -qb->w;
	}
	else
	{
		q2 = *qb;
	}

	float k1, k2;
	if (1.0f - comega > 0.000001f)
	{
		// fixme: use stdMath stuff
		float omega = acos(comega);
		float sinfomega = sin(omega);
		k1 = sin((1 - c) * omega) / sinfomega;
		k2 = sin(c * omega) / sinfomega;
	}
	else
	{
		k1 = 1.0f - c;
		k2 = c;
	}

	out->x = qa->x * k1 + q2.x * k2;
	out->y = qa->y * k1 + q2.y * k2;
	out->z = qa->z * k1 + q2.z * k2;
	out->w = qa->w * k1 + q2.w * k2;
}
