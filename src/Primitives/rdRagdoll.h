#ifndef _RDRAGDOLL_H
#define _RDRAGDOLL_H

#include "types.h"
#include "globals.h"

#include "Primitives/rdVector.h"
#include "Raster/rdFace.h"
#include "Engine/rdMaterial.h"
#include "Primitives/rdMatrix.h"

#ifdef RAGDOLLS
typedef struct rdRagdollVert
{
	int node;
	uint32_t flags;
	rdVector3 offset;
} rdRagdollVert;

typedef struct rdRagdollTri
{
	int vert[3];
} rdRagdollTri;

typedef struct rdRagdollJoint
{
	int node;
	int tri;
	int vert[3];
} rdRagdollJoint;

typedef struct rdRagdollDistConstraint
{
	int vert[2];
} rdRagdollDistConstraint;

typedef struct rdRagdollRotConstraint
{
	int tri[2];
	float maxangle;
	rdMatrix34 middle;
} rdRagdollRotConstraint;

typedef struct rdRagdollRotFriction
{
	int tri[2];
} rdRagdollRotFriction;

typedef struct rdRagdollSkeleton
{
	char name[32];
	int numVerts;
	rdRagdollVert* paVerts;
	int numTris;
	rdRagdollTri* paTris;
	int numJoints;
	rdRagdollJoint* paJoints;
	int numDist;
	rdRagdollDistConstraint* paDistConstraints;
	int numRot;
	rdRagdollRotConstraint* paRotConstraints;
	int numRotFric;
	rdRagdollRotFriction* paRotFrictions;
} rdRagdollSkeleton;

typedef enum rdRagdollParticleFlags
{
	RD_RAGDOLL_PINNED = 0x1,
} rdRagdollParticleFlags;

typedef struct rdRagdollParticle
{
	uint32_t flags;
	rdVector3 pos;
	rdVector3 lastPos;
	rdVector3 nextPosAcc;
	rdVector3 forces;
	float nextPosWeight;
	float radius;
	int collided;
} rdRagdollParticle;

typedef struct rdRagdoll
{
	rdRagdollSkeleton* pSkel;
	rdModel3* pModel;
	rdThing* pThing;
	rdVector3 center;
	float radius;
	int numParticles;
	rdRagdollParticle* paParticles;
	rdMatrix34* paPoseMatrices;
	rdMatrix34* paJointMatrices;
	rdMatrix34* paJointTris;
	rdMatrix34* paTris;
	rdMatrix34* paRotFricMatrices;
	float* paDistConstraintDists;
	float lastTimeStep;
	int collisions;
	int expireMs;
} rdRagdoll;

void rdRagdoll_NewEntry(rdThing* pThing, rdVector3* pInitialVel);
void rdRagdoll_FreeEntry(rdRagdoll* pRagdoll);

void rdRagdoll_GetJointPos(rdVector3* out, rdRagdoll* pRagdoll, rdRagdollJoint* pJoint);

void rdRagdoll_ApplyDistConstraints(rdRagdoll* pRagdoll);
void rdRagdoll_ApplyRotConstraints(rdRagdoll* pRagdoll);
void rdRagdoll_UpdateTriangles(rdRagdoll* pRagdoll);
void rdRagdoll_UpdateBounds(rdRagdoll* pRagdoll);

void rdRagdoll_CalculateRotFriction(rdRagdoll* pRagdoll);
void rdRagdoll_ApplyRotFriction(rdRagdoll* pRagdoll, float deltaSeconds, float friction, float angleThreshold);

int rdRagdollSkeleton_LoadEntry(rdRagdollSkeleton* pSkel, const char* fpath);
void rdRagdollSkeleton_FreeEntry(rdRagdollSkeleton* pSkel);

ragdollLoader_t rdRagdollSkeleton_RegisterLoader(ragdollLoader_t loader);
ragdollUnloader_t rdRagdollSkeleton_RegisterUnloader(ragdollUnloader_t unloader);

rdRagdollSkeleton* rdRagdollSkeleton_New(char* path);
void rdRagdollSkeleton_Free(rdRagdollSkeleton* pSkel);

void rdRagdollSkeleton_SetupModel(rdRagdollSkeleton* pSkel, rdModel3* pModel);

#endif


#endif // _RDRAGDOLL_H
