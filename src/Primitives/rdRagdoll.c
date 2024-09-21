#include "rdRagdoll.h"

#define _USE_MATH_DEFINES
#include <math.h>

#include "Engine/rdroid.h"
#include "General/stdConffile.h"
#include "stdPlatform.h"
#include "Primitives/rdVector.h"
#include "Primitives/rdMatrix.h"
#include "Primitives/rdMath.h"
#include "Engine/rdPuppet.h"
#include "Engine/rdClip.h"
#include "Win95/std.h"
#include "Primitives/rdPrimit3.h"
#include "Primitives/rdDebug.h"
#include "General/stdString.h"

#ifdef RAGDOLLS

#include "General/stdMath.h"

ragdollLoader_t pRagdollLoader;
ragdollUnloader_t pRagdollUnloader;

ragdollLoader_t rdRagdollSkeleton_RegisterLoader(ragdollLoader_t loader)
{
	ragdollLoader_t result = pRagdollLoader;
	pRagdollLoader = loader;
	return result;
}

ragdollUnloader_t rdRagdollSkeleton_RegisterUnloader(ragdollUnloader_t unloader)
{
	ragdollUnloader_t result = pRagdollUnloader;
	pRagdollUnloader = unloader;
	return result;
}

void rdRagdoll_GetJointPos(rdVector3* out, rdRagdoll* pRagdoll, rdRagdollJoint* pJoint)
{
	rdVector_Zero3(out);

	rdRagdollTri* pTri = &pRagdoll->pSkel->paTris[pJoint->tri];

	float weight = 0.0f;
	for (int v = 0; v < 3; ++v)
	{
		if (pJoint->vert[v] != -1)
		{
			rdVector_Add3Acc(out, &pRagdoll->paParticles[pTri->vert[pJoint->vert[v]]].pos);
			++weight;
		}
	}

	if (weight > 0.0)
		weight = 1.0f / weight;

	rdVector_Scale3Acc(out, weight);
}

void rdRagdoll_CalculateJointRadius(rdRagdollJoint* pJoint, rdRagdoll* pRagdoll, rdVector3* pJointCenter)
{
	pJoint->radius = 0;
	
	rdRagdollTri* pTri = &pRagdoll->pSkel->paTris[pJoint->tri];
	for (int v = 0; v < 3; ++v)
	{
		if (pJoint->vert[v] != -1)
		{
			float distToCenter = rdVector_Dist3(&pRagdoll->paParticles[pTri->vert[pJoint->vert[v]]].pos, pJointCenter);
			if(distToCenter > pJoint->radius)
				pJoint->radius = distToCenter;
		}
	}

	// if the radius is 0 then we're only using 1 vertex, so use the particle radius
	if (pJoint->radius <= 0.000001f)
		pJoint->radius = pRagdoll->paParticles[pTri->vert[pJoint->vert[0]]].radius;
}

void rdRagdoll_ApplyDistConstraints(rdRagdoll* pRagdoll)
{
	for (int i = 0; i < pRagdoll->pSkel->numDist; ++i)
	{
		rdRagdollDistConstraint* pConstraint = &pRagdoll->pSkel->paDistConstraints[i];

		rdRagdollParticle* pParticle0 = &pRagdoll->paParticles[pConstraint->vert[0]];
		rdRagdollParticle* pParticle1 = &pRagdoll->paParticles[pConstraint->vert[1]];

		rdVector3 delta;
		rdVector_Sub3(&delta, &pParticle1->pos, &pParticle0->pos);
		rdVector_Normalize3Acc(&delta);

		rdVector3 center;
		rdVector_Add3(&center, &pParticle0->pos, &pParticle1->pos);
		rdVector_Scale3Acc(&center, 0.5f);
		
		rdVector_Scale3Acc(&delta, pRagdoll->paDistConstraintDists[i] * 0.5f);

		rdVector3 offset1;
		rdVector_Sub3(&offset1, &center, &delta);

		rdVector3 offset2;
		rdVector_Add3(&offset2, &center, &delta);

		if (!(pParticle0->flags & RD_RAGDOLL_PINNED))
		{
			rdVector_Add3Acc(&pParticle0->nextPosAcc, &offset1);
			pParticle0->nextPosWeight++;
		}
		
		if (!(pParticle1->flags & RD_RAGDOLL_PINNED))
		{
			rdVector_Add3Acc(&pParticle1->nextPosAcc, &offset2);
			pParticle1->nextPosWeight++;
		}
	}
}

void rdRagdoll_ApplyRotConstraint(rdRagdoll* pRagdoll, rdRagdollTri* pTri0, rdRagdollTri* pTri1, float angle, rdVector3* pAxis)
{
	rdVector3 v0[3], v1[3];
	
	rdVector3 c0, c1;
	rdVector_Zero3(&c0);
	rdVector_Zero3(&c1);

	// calculate the center of each triangle
	for (int k = 0; k < 3; ++k)
	{
		rdVector_Copy3(&v0[k], &pRagdoll->paParticles[pTri0->vert[k]].pos);
		rdVector_Copy3(&v1[k], &pRagdoll->paParticles[pTri1->vert[k]].pos);

		rdVector_Add3Acc(&c0, &v0[k]);
		rdVector_Add3Acc(&c1, &v1[k]);
	}
	rdVector_InvScale3Acc(&c0, 3.0f);
	rdVector_InvScale3Acc(&c1, 3.0f);

	float w0 = 0.0f, w1 = 0.0f;
	for (int k = 0; k < 3; ++k)
	{
		// remove center		
		rdVector_Sub3Acc(&v0[k], &c0);
		rdVector_Sub3Acc(&v1[k], &c1);

		// calculate small rotation to conserve angular momentum
		rdVector3 tmp0, tmp1;
		rdVector_Cross3(&tmp0, pAxis, &v0[k]);
		rdVector_Cross3(&tmp1, pAxis, &v1[k]);
		w0 += rdVector_Len3(&tmp0);		
		w1 += rdVector_Len3(&tmp1);
	}

	// adjust
	angle /= w0 + w1 + 1e-9f;

	// build rotation matrices
	rdMatrix34 rot0, rot1;
	rdMatrix_BuildFromAxisAngle34(&rot0, pAxis, angle * w1);
	rdMatrix_BuildFromAxisAngle34(&rot1, pAxis,-angle * w0);

	for (int k = 0; k < 3; ++k)
	{
		rdRagdollParticle* pParticle0 = &pRagdoll->paParticles[pTri0->vert[k]];
		rdRagdollParticle* pParticle1 = &pRagdoll->paParticles[pTri1->vert[k]];

		if (!(pParticle0->flags & RD_RAGDOLL_PINNED))
		{
			// rotate
			rdMatrix_TransformPoint34Acc(&v0[k], &rot0);
			
			// add center
			rdVector_Add3Acc(&v0[k], &c0);

			// accumulate
			rdVector_Add3Acc(&pParticle0->nextPosAcc, &v0[k]);
			pParticle0->nextPosWeight++;
		}

		if (!(pParticle1->flags & RD_RAGDOLL_PINNED))
		{
			// rotate
			rdMatrix_TransformPoint34Acc(&v1[k], &rot1);

			// add center
			rdVector_Add3Acc(&v1[k], &c1);
		
			// accumulate
			rdVector_Add3Acc(&pParticle1->nextPosAcc, &v1[k]);
			pParticle1->nextPosWeight++;
		}
	}
}

void rdRagdoll_ApplyRotConstraints(rdRagdoll* pRagdoll)
{
	for (int i = 0; i < pRagdoll->pSkel->numRot; ++i)
	{
		rdRagdollRotConstraint* pConstraint = &pRagdoll->pSkel->paRotConstraints[i];

		rdMatrix34 rot;
		rdMatrix_InvertOrtho34(&rot, &pRagdoll->paTris[pConstraint->tri[0]]);
		rdMatrix_PostMultiply34(&rot, &pConstraint->middle);
		rdMatrix_PostMultiply34(&rot, &pRagdoll->paTris[pConstraint->tri[1]]);

		rdVector3 axis;
		float angle;
		if(!rdMatrix_ExtractAxisAngle34(&rot, &axis, &angle))
			continue;

		angle = pConstraint->maxangle - fabs(angle);
		if (angle >= 0)
			continue;

		rdRagdoll_ApplyRotConstraint(pRagdoll, &pRagdoll->pSkel->paTris[pConstraint->tri[0]], &pRagdoll->pSkel->paTris[pConstraint->tri[1]], angle, &axis);
	}
}

void rdRagdoll_UpdateTriangles(rdRagdoll* pRagdoll)
{
	for (int i = 0; i < pRagdoll->pSkel->numTris; ++i)
	{
		rdRagdollTri* pTri = &pRagdoll->pSkel->paTris[i];
		rdMatrix34* pMat = &pRagdoll->paTris[i];

		const rdVector3* pPos0 = &pRagdoll->paParticles[pTri->vert[0]].pos;
		const rdVector3* pPos1 = &pRagdoll->paParticles[pTri->vert[1]].pos;
		const rdVector3* pPos2 = &pRagdoll->paParticles[pTri->vert[2]].pos;

		rdVector_Sub3(&pMat->uvec, pPos1, pPos0);
		rdVector_Normalize3Acc(&pMat->uvec);

		rdVector_Sub3(&pMat->rvec, pPos2, pPos0);
		rdVector_Normalize3Acc(&pMat->rvec);

		rdVector_Cross3(&pMat->lvec, &pMat->uvec, &pMat->rvec);
		rdVector_Normalize3Acc(&pMat->lvec);

		rdVector_Cross3(&pMat->rvec, &pMat->lvec, &pMat->uvec);
		rdVector_Normalize3Acc(&pMat->rvec);
	}
}

void rdRagdoll_UpdateBounds(rdRagdoll* pRagdoll)
{
	rdVector_Zero3(&pRagdoll->center);
	for (int i = 0; i < pRagdoll->numParticles; ++i)
	{
		rdRagdollParticle* pParticle = &pRagdoll->paParticles[i];
		rdVector_Add3Acc(&pRagdoll->center, &pParticle->pos);
	}
	rdVector_InvScale3Acc(&pRagdoll->center, (float)pRagdoll->numParticles);

	pRagdoll->radius = 0.0f;
	for (int i = 0; i < pRagdoll->numParticles; ++i)
	{
		rdRagdollParticle* pParticle = &pRagdoll->paParticles[i];
		pRagdoll->radius = fmax(pRagdoll->radius, rdVector_Dist3(&pParticle->pos, &pRagdoll->center));
	}
}

void rdRagdoll_CalculateRotFriction(rdRagdoll* pRagdoll)
{
	for (int i = 0; i < pRagdoll->pSkel->numRotFric; ++i)
	{
		rdRagdollRotFriction* pRotFric = &pRagdoll->pSkel->paRotFrictions[i];
		rdMatrix_InvertOrtho34(&pRagdoll->paRotFricMatrices[i], &pRagdoll->paTris[pRotFric->tri[1]]);
		rdMatrix_PreMultiply34(&pRagdoll->paRotFricMatrices[i], &pRagdoll->paTris[pRotFric->tri[0]]);
	}
}

void rdRagdoll_ApplyRotFriction(rdRagdoll* pRagdoll, float deltaSeconds, float friction, float angleThreshold)
{
	float thresholdDt = angleThreshold * deltaSeconds;
	float frictionDt = 1.0f - pow(friction, deltaSeconds * 1000.0f);

	rdRagdoll_UpdateTriangles(pRagdoll);

	for (int i = 0; i < pRagdoll->pSkel->numRotFric; ++i)
	{
		rdRagdollRotFriction* pRotFric = &pRagdoll->pSkel->paRotFrictions[i];

		rdMatrix34 rot;
		rdMatrix_InvertOrtho34(&rot, &pRagdoll->paTris[pRotFric->tri[0]]);
		rdMatrix_PostMultiply34(&rot, &pRagdoll->paRotFricMatrices[i]);
		rdMatrix_PostMultiply34(&rot, &pRagdoll->paTris[pRotFric->tri[1]]);

		rdVector3 axis;
		float angle;
		if (!rdMatrix_ExtractAxisAngle34(&rot, &axis, &angle))
			continue;

		angle *= -(stdMath_Fabs(angle) >= thresholdDt ? frictionDt : 1.0f);
		if (stdMath_Fabs(angle) < 0.5f)
			continue;

		rdRagdoll_ApplyRotConstraint(pRagdoll, &pRagdoll->pSkel->paTris[pRotFric->tri[0]], &pRagdoll->pSkel->paTris[pRotFric->tri[1]], angle, &axis);
	}

	for (int i = 0; i < pRagdoll->numParticles; ++i)
	{
		rdRagdollParticle* pParticle = &pRagdoll->paParticles[i];
		if (pParticle->nextPosWeight)
			rdVector_InvScale3(&pParticle->pos, &pParticle->nextPosAcc, pParticle->nextPosWeight);

		rdVector_Zero3(&pParticle->nextPosAcc);
		pParticle->nextPosWeight = 0.0f;
	}
}

void rdRagdoll_Stop(rdRagdoll* pRagdoll)
{
	// force the expire time to be higher than current
	pRagdoll->expireMs = sithTime_curMs + 1;
}

int rdRagdoll_TrisHaveSharedVerts(rdRagdollTri* pTri0, rdRagdollTri* pTri1)
{
	for (int i = 0; i < 3; ++i)
	{
		for (int j = 0; j < 3; ++j)
		{
			if (pTri0->vert[i] == pTri1->vert[j])
				return 1;
		}
	}
	return 0;
}

void rdRagdoll_BuildParticles(rdThing* pThing, rdVector3* pInitialVel)
{
	rdVector3 thingVel;
	rdVector_Scale3(&thingVel, pInitialVel, sithTime_deltaSeconds);

	for (int i = 0; i < pThing->pRagdoll->numParticles; i++)
	{
		rdVector3 offset;

		rdRagdollParticle* pParticle = &pThing->pRagdoll->paParticles[i];
		rdRagdollVert* pVert = &pThing->pRagdoll->pSkel->paVerts[i];

		rdVector_Copy3(&pParticle->pos, &pThing->hierarchyNodeMatrices[pVert->node].scale);
		rdMatrix_TransformVector34(&offset, &pVert->offset, &pThing->hierarchyNodeMatrices[pVert->node]);
		rdVector_Add3Acc(&pParticle->pos, &offset);

		rdVector_Copy3(&pParticle->lastPos, &pThing->hierarchyNodeMatrices[pVert->node].scale);
		rdMatrix_TransformVector34(&offset, &pVert->offset, &pThing->hierarchyNodeMatrices[pVert->node]);
		rdVector_Add3Acc(&pParticle->lastPos, &offset);

		// add the initial velocity
		rdVector_Add3Acc(&pParticle->pos, &thingVel);

		rdVector_Zero3(&pParticle->nextPosAcc);
		pParticle->nextPosWeight = 0.0f;

		pParticle->flags = pVert->flags;

		// todo: we're gonna need a better way of deciding how big of a radius to make for each particle
		if (pThing->pRagdoll->pModel->hierarchyNodes[pVert->node].meshIdx != -1)
			pParticle->radius = pThing->pRagdoll->pModel->geosets[0].meshes[pThing->pRagdoll->pModel->hierarchyNodes[pVert->node].meshIdx].radius * 0.35f;
		else
			pParticle->radius = 0.01f;

		// the particle contains a dummy thing for collision handling
		sithThing_DoesRdThingInit(&pParticle->thing);
		pParticle->thing.thingIdx = -1;
		pParticle->thing.signature = -1;
		pParticle->thing.thing_id = -1;
		pParticle->thing.type = SITH_THING_ACTOR;
		pParticle->thing.collide = SITH_COLLIDE_SPHERE;
		pParticle->thing.moveSize = pParticle->radius;
		pParticle->thing.collideSize = pParticle->radius;
		pParticle->thing.moveType = SITH_MT_PHYSICS;
		pParticle->thing.prev_thing = pThing->parentSithThing;
		pParticle->thing.child_signature = pThing->parentSithThing->signature;

		_memcpy(&pParticle->thing.physicsParams, &pThing->parentSithThing->physicsParams, sizeof(sithThingPhysParams));
		pParticle->thing.physicsParams.physflags = 0;
		rdMatrix_Identity34(&pParticle->thing.lookOrientation); // don't think we care about orientation?
		pParticle->thing.parentThing = pThing->parentSithThing;
	}
}

void rdRagdoll_BuildJointMatrices(rdRagdoll* pRagdoll)
{
	for (int i = 0; i < pRagdoll->pSkel->numJoints; ++i)
	{
		rdRagdollJoint* pJoint = &pRagdoll->pSkel->paJoints[i];
		rdMatrix_Identity34(&pRagdoll->paJointMatrices[i]);

		rdRagdollTri* pTri = &pRagdoll->pSkel->paTris[pJoint->tri];

		rdVector3* pPos0 = &pRagdoll->paParticles[pTri->vert[0]].pos;
		rdVector3* pPos1 = &pRagdoll->paParticles[pTri->vert[1]].pos;
		rdVector3* pPos2 = &pRagdoll->paParticles[pTri->vert[2]].pos;

		rdMatrix34 m;
		rdVector_Sub3(&m.uvec, pPos1, pPos0);
		rdVector_Normalize3Acc(&m.uvec);

		rdVector_Sub3(&m.rvec, pPos2, pPos0);
		rdVector_Normalize3Acc(&m.rvec);

		rdVector_Cross3(&m.lvec, &m.uvec, &m.rvec);
		rdVector_Normalize3Acc(&m.lvec);

		rdVector_Cross3(&m.rvec, &m.lvec, &m.uvec);
		rdVector_Normalize3Acc(&m.rvec);

		rdRagdoll_GetJointPos(&m.scale, pRagdoll, pJoint);

		rdRagdoll_CalculateJointRadius(pJoint, pRagdoll, &m.scale);

		rdMatrix34 invMat;
		rdMatrix_InvertOrtho34(&invMat, &m);
		rdMatrix_Multiply34(&pRagdoll->paJointTris[i], &invMat, &pRagdoll->paPoseMatrices[pJoint->node]);
	}
}

void rdRagdoll_BuildRagdoll(rdRagdoll* pRagdoll, rdVector3* pInitialVel)
{
	rdRagdoll_BuildParticles(pRagdoll->pThing, pInitialVel);
	rdRagdoll_BuildJointMatrices(pRagdoll);

	// update constraint distances
	for (int i = 0; i < pRagdoll->pSkel->numDist; ++i)
	{
		rdRagdollDistConstraint* pConstraint = &pRagdoll->pSkel->paDistConstraints[i];
		rdRagdollParticle* pParticle0 = &pRagdoll->paParticles[pConstraint->vert[0]];
		rdRagdollParticle* pParticle1 = &pRagdoll->paParticles[pConstraint->vert[1]];
		pRagdoll->paDistConstraintDists[i] = rdVector_Dist3(&pParticle0->pos, &pParticle1->pos);
	}

	// update triangle matrices
	rdRagdoll_UpdateTriangles(pRagdoll);
	for (int i = 0; i < pRagdoll->pSkel->numRot; ++i)
	{
		rdRagdollRotConstraint* pConstraint = &pRagdoll->pSkel->paRotConstraints[i];
		rdMatrix_InvertOrtho34(&pConstraint->middle, &pRagdoll->paTris[pConstraint->tri[1]]);
		rdMatrix_PreMultiply34(&pConstraint->middle, &pRagdoll->paTris[pConstraint->tri[0]]);
	}

	rdRagdoll_UpdateBounds(pRagdoll);
}

int rdRagdoll_AllocRagdollData(rdRagdoll* pRagdoll)
{
	pRagdoll->numParticles = pRagdoll->pSkel->numVerts;
	pRagdoll->paParticles = (rdRagdollParticle*)rdroid_pHS->alloc(sizeof(rdRagdollParticle) * pRagdoll->numParticles);
	if (!pRagdoll->paParticles)
		return 0;

	pRagdoll->paPoseMatrices = (rdMatrix34*)rdroid_pHS->alloc(sizeof(rdMatrix34) * pRagdoll->pModel->numHierarchyNodes);
	if (!pRagdoll->paPoseMatrices)
		return 0;

	pRagdoll->paJointMatrices = (rdMatrix34*)rdroid_pHS->alloc(sizeof(rdMatrix34) * pRagdoll->pSkel->numJoints);
	if (!pRagdoll->paJointMatrices)
		return 0;

	pRagdoll->paJointTris = (rdMatrix34*)rdroid_pHS->alloc(sizeof(rdMatrix34) * pRagdoll->pSkel->numJoints);
	if (!pRagdoll->paJointTris)
		return 0;

	pRagdoll->paTris = (rdMatrix34*)rdroid_pHS->alloc(sizeof(rdMatrix34) * pRagdoll->pSkel->numTris);
	if (!pRagdoll->paTris)
		return 0;

	pRagdoll->paRotFricMatrices = (rdMatrix34*)rdroid_pHS->alloc(sizeof(rdMatrix34) * pRagdoll->pSkel->numRotFric);
	if (!pRagdoll->paRotFricMatrices)
		return 0;

	pRagdoll->paDistConstraintDists = (float*)rdroid_pHS->alloc(sizeof(float) * pRagdoll->pSkel->numDist);
	if (!pRagdoll->paDistConstraintDists)
		return 0;

	// clear it all
	_memset(pRagdoll->paParticles, 0, sizeof(rdRagdollParticle) * pRagdoll->numParticles);
	_memcpy(pRagdoll->paPoseMatrices, pRagdoll->pThing->hierarchyNodeMatrices, sizeof(rdMatrix34) * pRagdoll->pModel->numHierarchyNodes);
	_memset(pRagdoll->paJointMatrices, 0, sizeof(rdMatrix34) * pRagdoll->pSkel->numJoints);
	_memset(pRagdoll->paJointTris, 0, sizeof(rdMatrix34) * pRagdoll->pSkel->numJoints);
	_memset(pRagdoll->paTris, 0, sizeof(rdMatrix34) * pRagdoll->pSkel->numTris);
	_memset(pRagdoll->paRotFricMatrices, 0, sizeof(rdMatrix34) * pRagdoll->pSkel->numRotFric);
	_memset(pRagdoll->paDistConstraintDists, 0, sizeof(float) * pRagdoll->pSkel->numDist);

	return 1;
}

void rdRagdoll_NewEntry(rdThing* pThing, rdVector3* pInitialVel)
{
	if (!pThing->model3 || !pThing->model3->pSkel)
		return;

	rdRagdoll* pRagdoll = (rdRagdoll*)rdroid_pHS->alloc(sizeof(rdRagdoll));
	pThing->pRagdoll = pRagdoll;
	if (!pRagdoll)
		return;

	_memset(pRagdoll, 0, sizeof(rdRagdoll));

	pRagdoll->pModel = pThing->model3;
	pRagdoll->pThing = pThing;
	pRagdoll->pSkel = pRagdoll->pModel->pSkel;
	pRagdoll->lastTimeStep = sithTime_deltaSeconds;

	if(!rdRagdoll_AllocRagdollData(pRagdoll))
		return;
	rdRagdoll_BuildRagdoll(pRagdoll, pInitialVel);
}

void rdRagdoll_FreeEntry(rdRagdoll* pRagdoll)
{
	if (pRagdoll->paParticles)
	{
		rdroid_pHS->free(pRagdoll->paParticles);
		pRagdoll->paParticles = 0;
	}
	pRagdoll->numParticles = 0;

	if (pRagdoll->paPoseMatrices)
	{
		rdroid_pHS->free(pRagdoll->paPoseMatrices);
		pRagdoll->paPoseMatrices = 0;
	}

	if (pRagdoll->paJointMatrices)
	{
		rdroid_pHS->free(pRagdoll->paJointMatrices);
		pRagdoll->paJointMatrices = 0;
	}

	if (pRagdoll->paJointTris)
	{
		rdroid_pHS->free(pRagdoll->paJointTris);
		pRagdoll->paJointTris = 0;
	}

	if (pRagdoll->paDistConstraintDists)
	{
		rdroid_pHS->free(pRagdoll->paDistConstraintDists);
		pRagdoll->paDistConstraintDists = 0;
	}

	if (pRagdoll->paTris)
	{
		rdroid_pHS->free(pRagdoll->paTris);
		pRagdoll->paTris = 0;
	}
}

rdRagdollSkeleton* rdRagdollSkeleton_New(char* path)
{
	if (pRagdollLoader)
		return (rdRagdollSkeleton*)pRagdollLoader(path, 0);

	rdRagdollSkeleton* pSkel = (rdRagdollSkeleton*)rdroid_pHS->alloc(sizeof(rdRagdollSkeleton));
	if (pSkel)
	{
		if (rdRagdollSkeleton_LoadEntry(pSkel, path))
			return pSkel;
		rdRagdollSkeleton_Free(pSkel);
	}

	return 0;
}

int rdRagdollSkeleton_LoadEntry(rdRagdollSkeleton* pSkel, const char* fpath)
{
	int idx;
	int idx2;
	int num;
	int numDist;
	rdRagdollVert* vert;
	rdRagdollTri* tri;
	rdRagdollJoint* joint;
	rdRagdollDistConstraint* distConstraint;
	rdRagdollRotConstraint* rotConstraint;
	int counter;

	stdString_SafeStrCopy(pSkel->name, stdFileFromPath(fpath), 0x20);

	if (!stdConffile_OpenRead(fpath))
		return 0;

	if (!stdConffile_ReadLine())
		goto done_close;

	if (_sscanf(stdConffile_aLine, "vertices %d", &pSkel->numVerts) != 1)
		goto done_close;

	pSkel->paVerts = (rdRagdollVert*)rdroid_pHS->alloc(sizeof(rdRagdollVert) * pSkel->numVerts);
	if (!pSkel->paVerts)
		goto done_close;

	counter = 0;
	for (idx = 0; idx < pSkel->numVerts; idx++)
	{
		vert = &pSkel->paVerts[idx];
		vert->offset.x = vert->offset.y = vert->offset.z = 0.0f;
		if (!stdConffile_ReadLine()
			|| _sscanf(
				stdConffile_aLine,
				" %d: %d %x %f %f %f",
				&num,
				&vert->node,
				&vert->flags,
				&vert->offset.x,
				&vert->offset.y,
				&vert->offset.z) < 3)
		{
			goto done_close;
		}
		++counter;
	}

	if (counter != pSkel->numVerts)
	{
		rdroid_pHS->errorPrint("OpenJKDF2: vertex count mismatch in articulated figure %s, expected %d, got %d\n", fpath, pSkel->numVerts, counter);
		goto done_close;
	}

	if (!stdConffile_ReadLine())
		goto done_close;

	if (_sscanf(stdConffile_aLine, "triangles %d", &pSkel->numTris) != 1)
		goto done_close;

	pSkel->paTris = (rdRagdollTri*)rdroid_pHS->alloc(sizeof(rdRagdollTri) * pSkel->numTris);
	if (!pSkel->paTris)
		goto done_close;

	counter = 0;
	for (idx = 0; idx < pSkel->numTris; idx++)
	{
		tri = &pSkel->paTris[idx];
		if (!stdConffile_ReadLine()
			|| _sscanf(
				stdConffile_aLine,
				" %d: %d %d %d",
				&num,
				&tri->vert[0],
				&tri->vert[1],
				&tri->vert[2]) != 4)
		{
			goto done_close;
		}
		++counter;
	}

	if (counter != pSkel->numTris)
	{
		rdroid_pHS->errorPrint("OpenJKDF2: triangle count mismatch in articulated figure %s, expected %d, got %d\n", fpath, pSkel->numTris, counter);
		goto done_close;
	}

	if (!stdConffile_ReadLine())
		goto done_close;

	if (_sscanf(stdConffile_aLine, "joints %d", &pSkel->numJoints) != 1)
		goto done_close;

	pSkel->paJoints = (rdRagdollJoint*)rdroid_pHS->alloc(sizeof(rdRagdollJoint) * pSkel->numJoints);
	if (!pSkel->paJoints)
		goto done_close;

	counter = 0;
	for (idx = 0; idx < pSkel->numJoints; idx++)
	{
		joint = &pSkel->paJoints[idx];
		joint->vert[0] = joint->vert[1] = joint->vert[2] = -1;
		if (!stdConffile_ReadLine()
			|| _sscanf(
				stdConffile_aLine,
				" %d: %d %d %d %d %d",
				&num,
				&joint->node,
				&joint->tri,
				&joint->vert[0],
				&joint->vert[1],
				&joint->vert[2]) < 4)
		{
			goto done_close;
		}
		++counter;
	}

	if (counter != pSkel->numJoints)
	{
		rdroid_pHS->errorPrint("OpenJKDF2: joint count mismatch in articulated figure %s, expected %d, got %d\n", fpath, pSkel->numJoints, counter);
		goto done_close;
	}

	if (!stdConffile_ReadLine())
		goto done_close;

	if (_sscanf(stdConffile_aLine, "distance constraints %d", &pSkel->numDist) != 1)
		goto done_close;

	numDist = pSkel->numDist;
	pSkel->numDist += 3 * pSkel->numTris; // each triangle has constraints between them
	pSkel->paDistConstraints = (rdRagdollDistConstraint*)rdroid_pHS->alloc(sizeof(rdRagdollDistConstraint) * pSkel->numDist);
	if (!pSkel->paDistConstraints)
		goto done_close;

	counter = 0;
	for (idx = 0; idx < numDist; idx++)
	{
		distConstraint = &pSkel->paDistConstraints[idx];
		if (!stdConffile_ReadLine()
			|| _sscanf(
				stdConffile_aLine,
				" %d: %d %d",
				&num,
				&distConstraint->vert[0],
				&distConstraint->vert[1]) != 3)
		{
			goto done_close;
		}
		++counter;
	}

	if (counter != numDist)
	{
		rdroid_pHS->errorPrint("OpenJKDF2: distance constraint count mismatch in articulated figure %s, expected %d, got %d\n", fpath, numDist, counter);
		goto done_close;
	}

	if (!stdConffile_ReadLine())
		goto done_close;

	if (_sscanf(stdConffile_aLine, "angular constraints %d", &pSkel->numRot) != 1)
		goto done_close;

	pSkel->paRotConstraints = (rdRagdollRotConstraint*)rdroid_pHS->alloc(sizeof(rdRagdollRotConstraint) * pSkel->numRot);
	if (!pSkel->paRotConstraints)
		goto done_close;

	counter = 0;
	for (idx = 0; idx < pSkel->numRot; idx++)
	{
		rotConstraint = &pSkel->paRotConstraints[idx];
		if (!stdConffile_ReadLine()
			|| _sscanf(
				stdConffile_aLine,
				" %d: %d %d %f",
				&num,
				&rotConstraint->tri[0],
				&rotConstraint->tri[1],
				&rotConstraint->maxangle) != 4)
		{
			goto done_close;
		}
		++counter;
	}

	if (counter != pSkel->numRot)
	{
		rdroid_pHS->errorPrint("OpenJKDF2: angular constraint count mismatch in articulated figure %s, expected %d, got %d\n", fpath, pSkel->numRot, counter);
		goto done_close;
	}

	// validate
	for (idx = 0; idx < pSkel->numTris; ++idx)
	{
		for(idx2 = 0; idx2 < 3; ++idx2)
		{
			if (pSkel->paTris[idx].vert[idx2] < 0 || pSkel->paTris[idx].vert[idx2] >= pSkel->numVerts)
			{
				rdroid_pHS->errorPrint("OpenJKDF2: invalid vertex %d at index %d in triangle setup %d in articulated figure %s\n", pSkel->paTris[idx].vert[idx2], idx2, idx, fpath);
				goto done_close;
			}
		}
	}

	for (idx = 0; idx < pSkel->numJoints; ++idx)
	{
		if (pSkel->paJoints[idx].tri < 0 || pSkel->paJoints[idx].tri >= pSkel->numTris)
		{
			rdroid_pHS->errorPrint("OpenJKDF2: invalid triangle %d for joint setup %d in articulated figure %s\n", pSkel->paJoints[idx].tri, idx, fpath);
			goto done_close;
		}

		for (idx2 = 0; idx2 < 3; ++idx2)
		{
			if (pSkel->paJoints[idx].vert[idx2] < -1 || pSkel->paJoints[idx].vert[idx2] >= 3)
			{
				rdroid_pHS->errorPrint("OpenJKDF2: invalid vertex %d at index %d for joint setup %d, must be range 0-2 or -1 to mark unused\n", pSkel->paJoints[idx].vert[idx2], idx2, idx, fpath);
				goto done_close;
			}
		}
	}

	for (idx = 0; idx < numDist; ++idx)
	{
		for (idx2 = 0; idx2 < 2; ++idx2)
		{
			if (pSkel->paDistConstraints[idx].vert[idx2] < 0 || pSkel->paDistConstraints[idx].vert[idx2] >= pSkel->numVerts)
			{
				rdroid_pHS->errorPrint("OpenJKDF2: invalid vertex %d at index %d for distance constraint %d in articulated figure %s\n", pSkel->paDistConstraints[idx].vert[idx2], idx2, idx, fpath);
				goto done_close;
			}
		}
	}


	for (idx = 0; idx < pSkel->numRot; ++idx)
	{
		for (idx2 = 0; idx2 < 2; ++idx2)
		{
			if (pSkel->paRotConstraints[idx].tri[idx2] < 0 || pSkel->paRotConstraints[idx].tri[idx2] >= pSkel->numTris)
			{
				rdroid_pHS->errorPrint("OpenJKDF2: invalid triangle %d at index %d for angular constraint %d in articulated figure %s\n", pSkel->paRotConstraints[idx].tri[idx2], idx2, idx, fpath);
				goto done_close;
			}
		}
	}

	// create the tri constraints
	for (idx = 0; idx < pSkel->numTris; ++idx)
	{
		int distIdx = idx * 3 + numDist;

		distConstraint = &pSkel->paDistConstraints[distIdx + 0];
		distConstraint->vert[0] = pSkel->paTris[idx].vert[0];
		distConstraint->vert[1] = pSkel->paTris[idx].vert[1];

		distConstraint = &pSkel->paDistConstraints[distIdx + 1];
		distConstraint->vert[0] = pSkel->paTris[idx].vert[1];
		distConstraint->vert[1] = pSkel->paTris[idx].vert[2];

		distConstraint = &pSkel->paDistConstraints[distIdx + 2];
		distConstraint->vert[0] = pSkel->paTris[idx].vert[0];
		distConstraint->vert[1] = pSkel->paTris[idx].vert[2];
	}

	// build a list for rotation friction from shared triangles
	pSkel->numRotFric = 0;
	pSkel->paRotFrictions = (rdRagdollRotFriction*)rdroid_pHS->alloc(sizeof(rdRagdollRotFriction) * pSkel->numTris * pSkel->numTris); // allocate enough for all tris to start
	if (!pSkel->paRotFrictions)
		goto done_close;

	for (idx = 0; idx < pSkel->numTris; idx++)
	{
		for (idx2 = idx + 1; idx2 < pSkel->numTris; ++idx2)
		{
			if (rdRagdoll_TrisHaveSharedVerts(&pSkel->paTris[idx], &pSkel->paTris[idx2]))
			{
				pSkel->paRotFrictions[pSkel->numRotFric].tri[0] = idx;
				pSkel->paRotFrictions[pSkel->numRotFric].tri[1] = idx2;
				++pSkel->numRotFric;
			}
		}
	}

	// shrink or free
	if(pSkel->numRotFric)
		pSkel->paRotFrictions = (rdRagdollRotFriction*)rdroid_pHS->realloc(pSkel->paRotFrictions, sizeof(rdRagdollRotFriction) * pSkel->numRotFric);
	else
		rdroid_pHS->free(pSkel->paRotFrictions);

	stdConffile_Close();
	return 1;	

done_close:
	stdConffile_Close();
	return 0;
}

void rdRagdollSkeleton_FreeEntry(rdRagdollSkeleton* pSkel)
{
	if (pSkel->paVerts)
	{
		rdroid_pHS->free(pSkel->paVerts);
		pSkel->paVerts = 0;
	}
	pSkel->numVerts = 0;

	if (pSkel->paTris)
	{
		rdroid_pHS->free(pSkel->paTris);
		pSkel->paTris = 0;
	}
	pSkel->numTris = 0;

	if (pSkel->paJoints)
	{
		rdroid_pHS->free(pSkel->paJoints);
		pSkel->paJoints = 0;
	}
	pSkel->numJoints = 0;

	if (pSkel->paDistConstraints)
	{
		rdroid_pHS->free(pSkel->paDistConstraints);
		pSkel->paDistConstraints = 0;
	}
	pSkel->numDist = 0;

	if (pSkel->paRotConstraints)
	{
		rdroid_pHS->free(pSkel->paRotConstraints);
		pSkel->paRotConstraints = 0;
	}
	pSkel->numRot = 0;
}


void rdRagdollSkeleton_Free(rdRagdollSkeleton* pSkel)
{
	if (pSkel)
	{
		if (pRagdollUnloader)
		{
			pRagdollUnloader(pSkel);
		}
		else
		{
			rdRagdollSkeleton_FreeEntry(pSkel);
			rdroid_pHS->free(pSkel);
		}
	}
}

void rdRagdollSkeleton_SetupModel(rdRagdollSkeleton* pSkel, rdModel3* pModel)
{
	// assign the joint to the hierarchy node so it knows which matrix to grab
	for (int i = 0; i < pSkel->numJoints; ++i)
	{
		rdRagdollJoint* pJoint = &pSkel->paJoints[i];
		if (pJoint->node < 0 || pJoint->node >= pModel->numHierarchyNodes)
		{
			printf("Hiearchy node %d referenced by ragdoll joint %d for model %s is invalid\n", pJoint->node, i, pModel->filename);
			continue;
		}

		rdHierarchyNode* pNode = &pModel->hierarchyNodes[pJoint->node];
		if (pNode->skelJoint != -1)
		{
			printf("Hiearchy node %d for model %s already has an associated ragdoll joint %d, skpping\n", pJoint->node, pModel->filename, pNode->skelJoint);
			continue;
		}

		pNode->skelJoint = i;
	}
}

#endif