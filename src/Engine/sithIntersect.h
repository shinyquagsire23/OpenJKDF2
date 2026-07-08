#ifndef _SITHINTERSECT_H
#define _SITHINTERSECT_H

#include "types.h"

#define sithIntersect_sub_507EA0_ADDR (0x00507EA0)
#define sithIntersect_IsSphereInSector_ADDR (0x00507F30)
#define sithIntersect_sub_508070_ADDR (0x00508070)
#define sithIntersect_CheckSphereThingIntersection_ADDR (0x005080D0)
#define sithIntersect_sub_508370_ADDR (0x00508370)
#define sithIntersect_CheckSphereMeshIntersection_ADDR (0x00508400)
#define sithIntersect_CheckSphereIntersection_ADDR (0x00508540)
#define sithIntersect_TestSphereFaceHit_ADDR (0x00508750)
#define sithIntersect_CheckSphereFaceHitVerticesIntersection_ADDR (0x00508990)
#define sithIntersect_CheckSphereHit_ADDR (0x00508BE0)
#define sithIntersect_CheckSphereFaceIntersectionEx_ADDR (0x00508D20)
#define sithIntersect_CheckSphereFaceIntersection_ADDR (0x005090B0)

// Added: helper
MATH_FUNC int sithIntersect_IsSphereInSectorBox(const rdVector3 *pos, flex_t radius, sithSector *sector);

// sithIntersect_sub_507EA0
int sithIntersect_CheckFaceVerticesIntersection(rdVector3 *a1, flex_t a2, rdFace *a3, rdVector3 *a4, rdVector3 *pProjectedOut);
MATH_FUNC int sithIntersect_IsSphereInSector(const rdVector3 *pos, flex_t radius, sithSector *sector);
// sithIntersect_CheckFaceVerticesIntersection
MATH_FUNC int sithIntersect_CheckSphereThingIntersection(sithThing* thing, const rdVector3* a2, const rdVector3* a3, flex_t a4, flex_t a5, sithThing* a6, int raycastFlags, flex_t* a8, rdMesh** outMesh, rdFace** a10, rdVector3* a11);
MATH_FUNC int sithIntersect_TreeIntersection(rdHierarchyNode *paNodes,rdVector3 *pPoseVec,rdVector3 *pDirVec,flex_t a4,flex_t range, sithThing *v11,flex_t *pOut,rdVector3 *pOutVec,int raycastFlags);
// sithIntersect_sub_508370
MATH_FUNC int sithIntersect_CheckSphereMeshIntersection(rdVector3 *a1, rdVector3 *a2, flex_t a3, flex_t a4, rdMesh *mesh, flex_t *a6, rdFace **faceOut, rdVector3 *a8);
MATH_FUNC int sithIntersect_CheckSphereIntersection(const rdVector3 *a1, const rdVector3 *a2, flex_t a3, flex_t a4, rdVector3 *a5, flex_t a6, flex_t *a7, int a8, int a9);
MATH_FUNC int sithIntersect_TestSphereFaceHit(rdVector3 *a1, flex_t a2, rdFace *a3, rdVector3 *a4, int *a5);
MATH_FUNC int sithIntersect_CheckSphereFaceHitVerticesIntersection(rdVector3 *a1, flex_t a2, rdFace *a3, rdVector3 *a4, int a5, rdVector3 *a6);
MATH_FUNC int sithIntersect_CheckSphereHit(const rdVector3* pStartPos, const rdVector3* pRayDirection, flex_t moveDistance, flex_t radius, rdVector3* surfaceNormal, rdVector3* a6, flex_t* pSphereHitDist, int flags);
MATH_FUNC int sithIntersect_CheckSphereFaceIntersectionEx(const rdVector3 *a1, const rdVector3 *a2, flex_t a3, flex_t a4, rdFace *a5, rdVector3 *a6, flex_t *a7, rdVector3 *a8, int raycastFlags);
MATH_FUNC int sithIntersect_CheckSphereFaceIntersection(const rdVector3* pStartPos, const rdVector3* pRayDirection, flex_t moveDistance, flex_t radius, sithSurfaceInfo* a5, rdVector3* a6, flex_t* pSphereHitDist, int flags);


#if 0
static int (*sithIntersect_IsSphereInSector)(rdVector3 *pos, flex_t radius, sithSector *sector) = (void*)sithIntersect_IsSphereInSector_ADDR;
static int (*sithIntersect_CheckSphereIntersection)(rdVector3 *a1, rdVector3 *a2, flex_t a3, flex_t a4, rdVector3 *a5, flex_t a6, flex_t *a7, int a8, int a9) = (void*)sithIntersect_CheckSphereIntersection_ADDR;
static int (*sithIntersect_CheckSphereThingIntersection)(sithThing *thing, rdVector3 *a2, rdVector3 *a3, flex_t a4, flex_t a5, sithThing *a6, int a7, flex_t *a8, rdMesh **outMesh, rdFace **a10, rdVector3 *a11) = (void*)sithIntersect_CheckSphereThingIntersection_ADDR;
static int (*sithIntersect_TestSphereFaceHit)(rdVector3 *a1, flex_t a2, rdFace *a3, rdVector3 *a4, int *a5) = (void*)sithIntersect_TestSphereFaceHit_ADDR;
static int (*sithIntersect_CheckSphereFaceIntersection)(const rdVector3 *a1, const rdVector3 *a2, flex_t a3, flex_t a4, sithSurfaceInfo *a5, rdVector3 *a6, flex_t *a7, int raycastFlags) = (void*)sithIntersect_CheckSphereFaceIntersection_ADDR;
#endif

//static int (*_sithIntersect_sub_508D20)(const rdVector3 *a1, const rdVector3 *a2, flex_t a3, flex_t a4, rdFace *a5, rdVector3 *a6, flex_t *a7, rdVector3 *a8, int raycastFlags) = (void*)sithIntersect_CheckSphereFaceIntersectionEx_ADDR;
//static int (*_sithIntersect_SphereHit)(rdVector3 *a1, rdVector3 *a2, flex_t a3, flex_t a4, rdVector3 *surfaceNormal, rdVector3 *a6, flex_t *a7, int raycastFlags) = (void*)sithIntersect_CheckSphereHit_ADDR;

//static int (*sithIntersect_CheckSphereFaceHitVerticesIntersection)(rdVector3 *a1, flex_t a2, rdFace *a3, rdVector3 *a4, int a5, rdVector3 *a6) = (void*)sithIntersect_CheckSphereFaceHitVerticesIntersection_ADDR;
//static int (*sithIntersect_CheckSphereMeshIntersection)(const rdVector3 *a1, const rdVector3 *a2, flex_t a3, flex_t a4, rdMesh *mesh, flex_t *a6, rdFace **faceOut, rdVector3 *a8) = (void*)sithIntersect_CheckSphereMeshIntersection_ADDR;

#endif // _SITHINTERSECT_H
