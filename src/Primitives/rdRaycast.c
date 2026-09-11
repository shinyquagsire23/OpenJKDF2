// Added: whole module is new to OpenJKDF2 — CPU ray-vs-rdModel3 picking,
// decompiled from DroidWorks.exe (Ghidra 0x47f5e0-0x47fe3f). See rdRaycast.h
// for the call-tree overview. No module state (pure functions), so there is
// no _Startup.
//
// Faithfulness notes:
//  - The DW binary seeds "no hit yet" distances with float bits 0x7f7fc99e
//    (~3.4019e38). We use the codebase's usual 3.4e38 sentinel (same idiom as
//    sithCollision.c); both simply mean "farther than any real hit".
//  - Epsilon squashes mirror the binary exactly: |x| <= 1e-5 -> 0.

#include "Primitives/rdRaycast.h"

#include "Primitives/rdMatrix.h"
#include "Primitives/rdModel3.h"

// Added
int rdRaycast_RaySphere(const rdVector3* pRayOrigin, const rdVector3* pRayDir, const rdVector3* pCenter, flex_t radius)
{
    flex_t t;
    flex_t dx, dy, dz;

    // Project the center onto the ray; behind the origin = miss.
    t = pRayDir->z * (pCenter->z - pRayOrigin->z)
      + pRayDir->y * (pCenter->y - pRayOrigin->y)
      + pRayDir->x * (pCenter->x - pRayOrigin->x);
    if (t < 0.0)
        return 0;

    dx = (pRayDir->x * t + pRayOrigin->x) - pCenter->x;
    dy = (pRayDir->y * t + pRayOrigin->y) - pCenter->y;
    dz = (pRayDir->z * t + pRayOrigin->z) - pCenter->z;
    if (dz * dz + dy * dy + dx * dx <= radius * radius)
        return 1;
    return 0;
}

// Added
int rdRaycast_RayPlane(const rdVector3* pRayOrigin, const rdVector3* pRayDir, const rdVector3* pPlanePoint, const rdVector3* pNormal, rdRaycastHit* pHit)
{
    flex_t denom, num, t;

    denom = pNormal->x * pRayDir->x + pNormal->z * pRayDir->z + pNormal->y * pRayDir->y;
    if (denom < 0.0 ? (-denom <= 0.00001) : (denom <= 0.00001))
        denom = 0.0;
    if (denom == 0.0)
        return 0; // ray parallel to the plane

    num = (pPlanePoint->z - pRayOrigin->z) * pNormal->z
        + (pPlanePoint->y - pRayOrigin->y) * pNormal->y
        + (pPlanePoint->x - pRayOrigin->x) * pNormal->x;
    if (num < 0.0 ? (-num <= 0.00001) : (num <= 0.00001))
        num = 0.0;

    if (num == 0.0)
    {
        // Ray origin lies on the plane: record a t = 0 hit at the origin.
        // Quirk kept from the binary: this does NOT test against the current
        // best pHit->distance — it overwrites it with 0 unconditionally.
        if (pHit)
        {
            pHit->worldHitPos = *pRayOrigin;
            pHit->localHitPos = *pRayOrigin;
            pHit->distance = 0.0;
        }
        return 1;
    }

    t = num / denom;
    if (t > 0.0)
    {
        if (!pHit)
            return 1;
        if (t < pHit->distance)
        {
            pHit->worldHitPos.x = pRayDir->x * t + pRayOrigin->x;
            pHit->worldHitPos.y = pRayDir->y * t + pRayOrigin->y;
            pHit->worldHitPos.z = pRayDir->z * t + pRayOrigin->z;
            pHit->localHitPos = pHit->worldHitPos;
            pHit->distance = t;
            return 1;
        }
    }
    return 0;
}

// Added
int rdRaycast_RayFace(const rdVector3* pRayOrigin, const rdVector3* pRayDir, rdFace* pFace, rdVector3** ppVertices, rdRaycastHit* pHit)
{
    rdRaycastHit tmpHit;
    rdVector3* aVertices;
    rdVector3* pV0;
    flex_t d, nx, ny, nz;
    flex_t* pPoint;
    int a1, a2; // dominant-axis projection: test in the (a1, a2) plane
    int bInside;
    uint32_t i, numVertices;

    tmpHit.pMesh = NULL;
    tmpHit.pFace = NULL;
    tmpHit.distance = 3.4e38; // binary: float bits 0x7f7fc99e (~FLT_MAX)
    if (pHit)
        tmpHit = *pHit;

    aVertices = *ppVertices;
    pV0 = &aVertices[pFace->vertexPosIdx[0]];

    // Front-face-only: cull when the ray origin is on/behind the face plane.
    d = pFace->normal.x * (pRayOrigin->x - pV0->x)
      + pFace->normal.z * (pRayOrigin->z - pV0->z)
      + pFace->normal.y * (pRayOrigin->y - pV0->y);
    if (d < 0.0 ? (-d <= 0.00001) : (d <= 0.00001))
        d = 0.0;
    if (d <= 0.0)
        return 0;

    if (!rdRaycast_RayPlane(pRayOrigin, pRayDir, pV0, &pFace->normal, &tmpHit))
        return 0;

    // Pick the two projection axes by dropping the dominant normal axis.
    // (Rewritten from the binary's branch ladder; matches it on all ties.)
    nx = pFace->normal.x;
    if (nx < 0.0)
        nx = -nx;
    ny = pFace->normal.y;
    if (ny < 0.0)
        ny = -ny;
    nz = pFace->normal.z;
    if (nz < 0.0)
        nz = -nz;
    if (nx >= ny && nx >= nz)
    {
        a1 = 1;
        a2 = 2;
    }
    else if (ny >= nx && ny >= nz)
    {
        a1 = 0;
        a2 = 2;
    }
    else
    {
        a1 = 0;
        a2 = 1;
    }

    // Even-odd point-in-polygon: cast a ray from the plane-hit point toward
    // -a1 and count edge crossings.
    pPoint = (flex_t*)&tmpHit.localHitPos;
    numVertices = pFace->numVertices;
    bInside = 0;
    for (i = 0; i < numVertices; i++)
    {
        flex_t* pVi = (flex_t*)&aVertices[pFace->vertexPosIdx[i]];
        flex_t* pVj = (flex_t*)&aVertices[pFace->vertexPosIdx[(i + 1) % numVertices]];
        int bOutsideSpan, bJBefore;
        flex_t slope, side;

        if (pVi[a2] == pVj[a2])
            continue; // edge parallel to the test ray

        // Does the edge span the point's a2 coordinate?
        bOutsideSpan = (pPoint[a2] <= pVi[a2]);
        if (pVj[a2] < pPoint[a2])
            bOutsideSpan = !bOutsideSpan;
        if (bOutsideSpan)
            continue;

        bJBefore = (pVj[a1] < pPoint[a1]);
        if (pPoint[a1] <= pVi[a1] && !bJBefore)
            continue; // edge entirely on the +a1 side: the -a1 ray misses it

        if (pPoint[a1] > pVi[a1] && bJBefore)
        {
            // Edge entirely on the -a1 side: definite crossing.
            bInside = !bInside;
            continue;
        }

        // Edge straddles the point in a1: solve for which side the point is.
        slope = (pVj[a2] - pVi[a2]) / (pVj[a1] - pVi[a1]);
        side = ((pVj[a2] - pPoint[a2]) - (pVj[a1] - pPoint[a1]) * slope) / slope;
        if (side < 0.0 ? (-side <= 0.00001) : (side <= 0.00001))
            side = 0.0;
        if (side > 0.0)
            bInside = !bInside;
    }

    if (!bInside)
        return 0;
    if (pHit)
    {
        *pHit = tmpHit;
        pHit->pFace = pFace;
    }
    return 1;
}

// Added
int rdRaycast_RayMesh(const rdVector3* pRayOrigin, const rdVector3* pRayDir, rdMesh* pMesh, const rdMatrix34* pNodeMat, rdRaycastHit* pHit)
{
    rdMatrix34 invMat;
    rdVector3 localOrigin;
    rdVector3 localDir;
    uint32_t i;
    int bHit = 0;

    // Bring the ray into mesh space.
    rdMatrix_InvertOrtho34(&invMat, pNodeMat);
    localOrigin = *pRayOrigin;
    rdMatrix_TransformPoint34Acc(&localOrigin, &invMat);
    localDir = *pRayDir;
    rdMatrix_TransformVector34Acc(&localDir, &invMat);

    for (i = 0; i < (uint32_t)pMesh->numFaces; i++)
    {
        if (rdRaycast_RayFace(&localOrigin, &localDir, &pMesh->faces[i], &pMesh->aVertices, pHit))
        {
            bHit = 1;
            if (pHit)
            {
                pHit->pMesh = pMesh;
                rdMatrix_TransformPoint34(&pHit->worldHitPos, &pHit->localHitPos, pNodeMat);
            }
        }
    }
    return bHit;
}

// Added
int rdRaycast_RayNode(const rdVector3* pRayOrigin, const rdVector3* pRayDir, rdThing* pThing, rdGeoset* pGeoset, rdHierarchyNode* pNode, rdRaycastHit* pHit)
{
    rdHierarchyNode* pChild;
    uint32_t i;
    int bHit = 0;

    if (pNode->meshIdx != 0xFFFFFFFF)
    {
        bHit = rdRaycast_RayMesh(pRayOrigin, pRayDir,
                                 &pGeoset->aMeshes[pNode->meshIdx],
                                 &pThing->paJointMatrices[pNode->idx], pHit);
    }

    pChild = pNode->child;
    for (i = 0; i < pNode->numChildren; i++)
    {
        if (pThing->paJointAmputationFlags[pChild->idx] == 0)
        {
            if (rdRaycast_RayNode(pRayOrigin, pRayDir, pThing, pGeoset, pChild, pHit))
                bHit = 1;
        }
        pChild = pChild->nextSibling;
    }
    return bHit;
}

// Added
int rdRaycast_RayModel(const rdVector3* pRayOrigin, const rdVector3* pRayDir, rdThing* pThing, rdRaycastHit* pHit)
{
    rdModel3* pModel = pThing->model3;
    uint32_t geosetIdx = pThing->geosetSelect;

    if (geosetIdx == 0xFFFFFFFF)
        geosetIdx = pModel->geosetSelect;

    return rdRaycast_RayNode(pRayOrigin, pRayDir, pThing,
                             &pModel->aGeos[geosetIdx],
                             pModel->aHierarchyNodes, pHit);
}

// Added
int rdRaycast_CastRay(const rdVector3* pRayOrigin, const rdVector3* pRayDir, rdThing* pThing, rdFace** ppHitFace, flex_t* pHitDist)
{
    rdRaycastHit hit;

    hit.pMesh = NULL;
    hit.pFace = NULL;
    hit.distance = 3.4e38; // binary: float bits 0x7f7fc99e (~FLT_MAX)
    if (rdRaycast_RayModel(pRayOrigin, pRayDir, pThing, &hit))
    {
        *ppHitFace = hit.pFace;
        *pHitDist = hit.distance;
        return 1;
    }
    return 0;
}
