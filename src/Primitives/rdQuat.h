#ifndef _RDQUAT_H
#define _RDQUAT_H

#include "types.h"

typedef struct rdQuat
{
	float x;
	float y;
	float z;
	float w;
} rdQuat;

void rdQuat_Set(rdQuat* out, float x, float y, float z, float w);

void rdQuat_BuildFromAxisAngle(rdQuat* out, rdVector3* axis, float angle);
void rdQuat_BuildFromVector(rdQuat* out, rdVector3* axis);

void rdQuat_ExtractAxisAngle(rdQuat* q, rdVector3* axis, float* angle);

void rdQuat_Mul(rdQuat* out, rdQuat* qa, rdQuat* qb);
void rdQuat_MulAcc(rdQuat* qa, rdQuat* qb);

float rdQuat_LenSq(rdQuat* q);

void rdQuat_TransformVector(rdVector3* out, const rdQuat* q, const rdVector3* v);

void rdQuat_Conjugate(rdQuat* out, const rdQuat* q);
void rdQuat_ConjugateAcc(rdQuat* q);

void rdQuat_ToMatrix(rdMatrix34* out, const rdQuat* q);
void rdQuat_Slerp(rdQuat* out, const rdQuat* qa, const rdQuat* qb, const float c);

#endif // _RDQUAT_H
