#ifndef _RDRAYCAST_H
#define _RDRAYCAST_H

// Added: whole module is new to OpenJKDF2 — CPU ray-vs-rdModel3 picking,
// decompiled from DroidWorks.exe (Ghidra 0x47f5e0-0x47fe3f; the DW engine's
// rdRaycast compile unit). DroidWorks uses it for droid-part picking in the
// editor and for dwLaser_TraceBeam's mirror raytrace.
//
// Call tree: CastRay@47fdb0 -> RayModel@47f870 (geoset select) ->
// RayNode@47f8b0 (recursive over hierarchy nodes, honors joint amputation)
// -> RayMesh@47f970 (inverse-transforms the ray into mesh space by the
// thing's joint matrix) -> RayFace@47fa50 (front-face-only ray/plane hit via
// RayPlane@47f6c0, then even-odd point-in-polygon on the dominant normal
// axis). RaySphere@47f5e0 is a standalone ray-vs-point+radius helper.
//
// The hit record (rdRaycastHit, DW binary 0x38 bytes) lives in types.h.
//
// NOTE: the binary's neighboring rdRaycast_ClearPickBuffer@47f560 and
// rdModel3_SetLoad/FreeEntryHook@47fe40/50 are NOT raycast code (render-frame
// canvas clear + loader hooks) and are intentionally not part of this module.

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

// Added: returns 1 when the ray hits the sphere at pCenter with the given
// radius (point-projection test; rays starting past the center still hit if
// the origin is inside the radius). @47f5e0
int rdRaycast_RaySphere(const rdVector3* pRayOrigin, const rdVector3* pRayDir, const rdVector3* pCenter, flex_t radius);

// Added: ray vs (point,normal) plane. Returns 1 on a hit with t > 0 (or when
// the ray origin lies on the plane, which records t = 0 unconditionally).
// When pHit is non-NULL the hit is only recorded (worldHitPos, localHitPos
// and distance) if t improves pHit->distance; a non-improving t returns 0.
// @47f6c0
int rdRaycast_RayPlane(const rdVector3* pRayOrigin, const rdVector3* pRayDir, const rdVector3* pPlanePoint, const rdVector3* pNormal, rdRaycastHit* pHit);

// Added: ray vs one face of a mesh; front side only (faces whose plane the
// origin is behind are culled). ppVertices points at the mesh's vertex-array
// pointer (mirrors the binary, which passes &pMesh->aVertices). @47fa50
int rdRaycast_RayFace(const rdVector3* pRayOrigin, const rdVector3* pRayDir, rdFace* pFace, rdVector3** ppVertices, rdRaycastHit* pHit);

// Added: ray vs every face of a mesh. The ray is inverse-transformed into
// mesh space by pNodeMat; on a hit, pHit->pMesh is set and worldHitPos is
// recomputed from localHitPos through pNodeMat. @47f970
int rdRaycast_RayMesh(const rdVector3* pRayOrigin, const rdVector3* pRayDir, rdMesh* pMesh, const rdMatrix34* pNodeMat, rdRaycastHit* pHit);

// Added: recursive hierarchy-node walk: tests the node's mesh (if any)
// against pThing->paJointMatrices[node->idx], then recurses into children
// whose paJointAmputationFlags entry is clear. Returns 1 if anything hit.
// @47f8b0
int rdRaycast_RayNode(const rdVector3* pRayOrigin, const rdVector3* pRayDir, rdThing* pThing, rdGeoset* pGeoset, rdHierarchyNode* pNode, rdRaycastHit* pHit);

// Added: ray vs a model rdThing's selected geoset, starting at the root
// hierarchy node. pThing->paJointMatrices must be current (callers rebuild
// via rdPuppet_BuildJointMatrices when rdFrameNum is stale). @47f870
int rdRaycast_RayModel(const rdVector3* pRayOrigin, const rdVector3* pRayDir, rdThing* pThing, rdRaycastHit* pHit);

// Added: top-level convenience: raycast pThing's model and return the best
// hit face + ray distance. Outputs are only written on a hit. @47fdb0
int rdRaycast_CastRay(const rdVector3* pRayOrigin, const rdVector3* pRayDir, rdThing* pThing, rdFace** ppHitFace, flex_t* pHitDist);

#ifdef __cplusplus
}
#endif

#endif // _RDRAYCAST_H
