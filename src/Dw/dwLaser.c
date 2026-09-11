// dwLaser — DroidWorks per-world laser/beam pool (see dwLaser.h).
//
// Ghidra (DroidWorks.exe) 0x46aa90-0x46b5cx. Pool entries are tDwLaser
// (types.h): each carries an INLINE solid-color rdMaterial whose texinfos[0]
// points at the entry's own INLINE rdTexinfo (header.solidColor = beam
// color); rdCache proc entries reference that material directly, which is
// why dwLaser_Add re-points texinfos[0] on every pool realloc.

#include "Dw/dwLaser.h"

#include "Cog/sithCog.h"
#include "Engine/rdCamera.h"
#include "Engine/rdPuppet.h"
#include "Engine/sithCollision.h"
#include "Primitives/rdMatrix.h"
#include "Primitives/rdPrimit3.h"
#include "Primitives/rdRaycast.h"
#include "Primitives/rdVector.h"
#include "Raster/rdCache.h"
#include "Engine/rdroid.h" // rdSetSortingMethod (dwLaser_DrawAll)
#include "jk.h"
#include "globals.h" // sithWorld_g_pCurrentWorld

#include <ctype.h>

uint32_t dwLaser_nextId = 1; // binary: 0x52d988, initial 1

// Quad vertex index list handed to rdPrimit3_ClipFace (binary: 0x52d978).
static const int dwLaser_aQuadVertIdx[4] = { 0, 1, 2, 3 };

// Note: no binary counterpart — statics reset for the soft-reset loop only.
void dwLaser_Startup()
{
    dwLaser_nextId = 1;
}

// @0x46aa90
void dwLaser_Draw(tDwLaser* pLaser)
{
    if (pLaser->pTargetThing)
    {
        dwLaser_DrawBeamSegment(&pLaser->pOwnerThing->position, &pLaser->pTargetThing->position, &pLaser->material, pLaser->width);
        return;
    }
    dwLaser_TraceBeam(pLaser);
}

// @0x46aad0
void dwLaser_DrawBeamSegment(const rdVector3* pFrom, const rdVector3* pTo, rdMaterial* pMaterial, flex_t width)
{
    rdVector3 dir;
    rdVector3 side;
    rdVector3 up;
    rdVector3 aQuad[4];

    rdVector_Sub3(&dir, (rdVector3*)pTo, (rdVector3*)pFrom);
    rdVector_Normalize3Acc(&dir);

    // Build two beam-aligned perpendicular axes from a swizzled seed.
    up.x = dir.y;
    up.y = dir.z;
    up.z = dir.x;
    rdVector_Normalize3Acc(&up);
    side.x = up.z * dir.y - up.y * dir.z;
    side.y = up.x * dir.z - up.z * dir.x;
    side.z = up.y * dir.x - up.x * dir.y;
    rdVector_Normalize3Acc(&side);
    up.x = side.z * dir.y - side.y * dir.z;
    up.y = side.x * dir.z - side.z * dir.x;
    up.z = side.y * dir.x - side.x * dir.y;
    rdVector_Normalize3Acc(&up);

    // First quad: widened along `up`.
    up.x = up.x * width;
    up.y = up.y * width;
    up.z = up.z * width;
    aQuad[0].x = pFrom->x - up.x;
    aQuad[0].y = pFrom->y - up.y;
    aQuad[0].z = pFrom->z - up.z;
    aQuad[1].x = up.x + pFrom->x;
    aQuad[1].y = up.y + pFrom->y;
    aQuad[1].z = up.z + pFrom->z;
    aQuad[2].x = up.x + pTo->x;
    aQuad[2].y = up.y + pTo->y;
    aQuad[2].z = up.z + pTo->z;
    aQuad[3].x = pTo->x - up.x;
    aQuad[3].y = pTo->y - up.y;
    aQuad[3].z = pTo->z - up.z;
    dwLaser_DrawQuad(aQuad, pMaterial);

    // Second quad: widened along `side` (cross billboard).
    side.x = side.x * width;
    side.y = side.y * width;
    side.z = side.z * width;
    aQuad[0].x = pFrom->x - side.x;
    aQuad[0].y = pFrom->y - side.y;
    aQuad[0].z = pFrom->z - side.z;
    aQuad[1].x = side.x + pFrom->x;
    aQuad[1].y = side.y + pFrom->y;
    aQuad[1].z = side.z + pFrom->z;
    aQuad[2].x = side.x + pTo->x;
    aQuad[2].y = side.y + pTo->y;
    aQuad[2].z = side.z + pTo->z;
    aQuad[3].x = pTo->x - side.x;
    aQuad[3].y = pTo->y - side.y;
    aQuad[3].z = pTo->z - side.z;
    dwLaser_DrawQuad(aQuad, pMaterial);
}

// @0x46adb0
void dwLaser_DrawQuad(rdVector3* aQuad, rdMaterial* pMaterial)
{
    rdProcEntry* pProc;
    rdMeshinfo srcInfo;
    rdMeshinfo dstInfo;
    rdVector2 uvOffset;
    rdVector3 edge1;
    rdVector3 edge2;
    rdVector3 aViewVerts[4];
    rdVector3 aClipVerts[32];

    srcInfo.aVertices = aViewVerts;
    srcInfo.paDynamicLight = NULL;
    srcInfo.intensities = NULL;
    srcInfo.aTexVerticies = NULL;
    rdMatrix_TransformPoint34(&aViewVerts[0], &aQuad[0], &rdCamera_g_pCurCamera->orient);
    rdMatrix_TransformPoint34(&aViewVerts[1], &aQuad[1], &rdCamera_g_pCurCamera->orient);
    rdMatrix_TransformPoint34(&aViewVerts[2], &aQuad[2], &rdCamera_g_pCurCamera->orient);
    rdMatrix_TransformPoint34(&aViewVerts[3], &aQuad[3], &rdCamera_g_pCurCamera->orient);

    pProc = rdCache_GetProcEntry();
    if (!pProc)
        return;

    dstInfo.verticesOrig = pProc->aVertices;
    dstInfo.aVertices = aClipVerts;
    dstInfo.aTexVerticies = pProc->aTexVerticies;
    dstInfo.paDynamicLight = pProc->vertexIntensities;
    srcInfo.numVertices = 4;
    srcInfo.vertexPosIdx = (int*)dwLaser_aQuadVertIdx;
    srcInfo.vertexUVIdx = NULL;
    pProc->material = pMaterial;
    pProc->geometryMode = RD_GEOMETRY_SOLID;
    pProc->lightingMode = RD_LIGHTMODE_FULLYLIT;
    pProc->textureMode = RD_TEXTUREMODE_AFFINE;
    pProc->wallCel = 0;
    pProc->type = 0;
    pProc->extralight = 1.0;
    uvOffset.x = 0.0; // Note: left uninitialized in the binary; unused for solid geometry
    uvOffset.y = 0.0;
    rdPrimit3_ClipFace(rdCamera_g_pCurCamera->pClipFrustum, RD_GEOMETRY_SOLID, RD_LIGHTMODE_FULLYLIT, RD_TEXTUREMODE_AFFINE, &srcInfo, &dstInfo, &uvOffset);
    if (!dstInfo.numVertices)
        return;

    // Backface flag from the world-space quad winding vs the camera position.
    rdVector_Sub3(&edge1, &aQuad[1], &aQuad[2]);
    rdVector_Normalize3Acc(&edge1);
    rdVector_Sub3(&edge2, &aQuad[3], &aQuad[2]);
    rdVector_Normalize3Acc(&edge2);
    if ((aQuad[1].x - rdCamera_g_camMatrix.scale.x) * (edge2.z * edge1.y - edge2.y * edge1.z)
      + (aQuad[1].z - rdCamera_g_camMatrix.scale.z) * (edge2.y * edge1.x - edge2.x * edge1.y)
      + (aQuad[1].y - rdCamera_g_camMatrix.scale.y) * (edge2.x * edge1.z - edge2.z * edge1.x) <= 0.0)
    {
        pProc->light_flags = 1;
    }
    else
    {
        pProc->light_flags = 0;
    }

    rdCamera_g_pCurCamera->pfProjectList(dstInfo.verticesOrig, dstInfo.aVertices, dstInfo.numVertices);
    rdCache_AddProcFace(0, dstInfo.numVertices, 1);
}

// @0x46b010
void dwLaser_TraceBeam(tDwLaser* pLaser)
{
    SithThing* pOwner;
    SithSector* pSector;
    SithCollision* pCol;
    rdMaterial* pHitMat;
    rdVector3 pos;
    rdVector3 dir;
    rdVector3 hitNorm;
    rdVector3 end;
    flex_t hitDist, d, ad;
    uint32_t bounce;
    int bMirror, bHitResolved;

    pOwner = pLaser->pOwnerThing;
    pSector = pOwner->sector;
    // Quirk kept from the binary: DW guards the owner sector against -1.
    if (pSector == (SithSector*)(intptr_t)-1)
        return;
    if (!pSector) // Added: NULL guard (OpenJKDF2 uses NULL for "no sector")
        return;

    pos = pOwner->position;
    dir = pOwner->orient.lvec;
    for (bounce = 0; bounce < 8; bounce++)
    {
        pHitMat = NULL;
        bMirror = 0;
        bHitResolved = 0;
        hitDist = 4000.0;
        sithCollision_SearchForCollisions(pSector, NULL, &pos, &dir, 4000.0, pLaser->width, RAYCAST_100 | RAYCAST_2);
        pCol = sithCollision_PopStack();
        while (pCol && !bHitResolved)
        {
            hitDist = pCol->distance;
            if ((pCol->type & SITHCOLLISION_THING) && pCol->pThingCollided
                && pCol->pThingCollided->renderData.type == RD_THING_MODEL3)
            {
                SithThing* pThing = pCol->pThingCollided;
                rdMatrix34 placement;
                rdFace* pHitFace;
                flex_t t;

                rdMatrix_Copy34(&placement, &pThing->orient);
                rdMatrix_PostTranslate34(&placement, &pThing->position);
                if (pThing->renderData.rdFrameNum != rdroid_frameTrue)
                    rdPuppet_BuildJointMatrices(&pThing->renderData, &pThing->orient);
                if (rdRaycast_CastRay(&pos, &dir, &pThing->renderData, &pHitFace, &t))
                {
                    bHitResolved = 1;
                    hitDist = t;
                    pHitMat = pHitFace->material;
                    pSector = pThing->sector;
                    hitNorm = pHitFace->normal;
                    // Note: mirrors the binary — the mesh-local face normal is
                    // rotated by the thing placement only (any hierarchy-node
                    // rotation is ignored).
                    rdMatrix_TransformVector34Acc(&hitNorm, &placement);
                    sithCog_ThingSendMessage(pThing, pLaser->pOwnerThing, 41); // DW COG message 41 "laserhit"
                }
            }
            else if ((pCol->type & SITHCOLLISION_WORLD) && pCol->surface)
            {
                pSector = pCol->surface->pSector;
                pHitMat = pCol->surface->surfaceInfo.face.material;
                hitNorm = pCol->surface->surfaceInfo.face.normal;
                bHitResolved = 1;
                sithCog_SurfaceSendMessage(pCol->surface, pLaser->pOwnerThing, 41); // DW COG message 41 "laserhit"
            }
            if (!bHitResolved)
                pCol = sithCollision_PopStack();
        }
        sithCollision_DecreaseStackLevel();

        end.x = hitDist * dir.x + pos.x;
        end.y = hitDist * dir.y + pos.y;
        end.z = hitDist * dir.z + pos.z;
        dwLaser_DrawBeamSegment(&pos, &end, &pLaser->material, pLaser->width);

        // Bounce only off materials whose name starts with "MIR".
        if (pHitMat
            && toupper((unsigned char)pHitMat->mat_fpath[0]) == 'M'
            && toupper((unsigned char)pHitMat->mat_fpath[1]) == 'I'
            && toupper((unsigned char)pHitMat->mat_fpath[2]) == 'R')
        {
            bMirror = 1;
        }
        if (!bMirror)
            return;

        // Reflect: dir += 2 * |dot(n, dir)| * n (dot is negative on a
        // front-face hit, so this is the standard reflection).
        d = hitNorm.z * dir.z + hitNorm.y * dir.y + hitNorm.x * dir.x;
        pos = end;
        ad = d;
        if (d < 0.0)
            ad = -d;
        hitNorm.x = hitNorm.x * ad;
        hitNorm.y = hitNorm.y * ad;
        hitNorm.z = hitNorm.z * ad;
        dir.x = hitNorm.x + hitNorm.x + dir.x;
        dir.y = hitNorm.y + hitNorm.y + dir.y;
        dir.z = hitNorm.z + hitNorm.z + dir.z;
        rdVector_Normalize3Acc(&dir);
    }
}

// @0x46b3f0
tDwLaser* dwLaser_Add(SithWorld* pWorld, SithThing* pOwnerThing, SithThing* pTargetThing, int color, flex_t width)
{
    tDwLaser* pEntry;
    int32_t count;
    int32_t i;

    // Reuse the first free slot.
    count = pWorld->numDwLasers;
    for (i = 0; i < count; i++)
    {
        if (!pWorld->aDwLasers[i].pOwnerThing)
            break;
    }

    if (i == count)
    {
        // Pool full (or absent): grow by 5 slots (binary: 0x474 = 5 * 0xe4).
        tDwLaser* pNew;
        int32_t j;
        if (!pWorld->aDwLasers)
            pNew = (tDwLaser*)(*pSithHS->alloc)(sizeof(tDwLaser) * 5);
        else
            pNew = (tDwLaser*)(*pSithHS->realloc)(pWorld->aDwLasers, sizeof(tDwLaser) * (count + 5));
        if (!pNew)
            return NULL;
        _memset(&pNew[count], 0, sizeof(tDwLaser) * 5);
        // The pool may have moved: re-point every old entry's inline-texinfo
        // self-pointer (rdCache proc entries hold &entry->material).
        for (j = 0; j < count; j++)
            pNew[j].material.texinfos[0] = &pNew[j].texinfo;
        pWorld->aDwLasers = pNew;
        pWorld->numDwLasers = count + 5;
        pEntry = &pNew[count];
    }
    else
    {
        pEntry = &pWorld->aDwLasers[i];
    }

    _memset(pEntry, 0, sizeof(tDwLaser));
    pEntry->id = dwLaser_nextId++;
    pEntry->pOwnerThing = pOwnerThing;
    pEntry->pTargetThing = pTargetThing;
    pEntry->width = width;
    // Inline solid-color material: 8bpp paletted, one texinfo, whose
    // header.solidColor carries the beam color index.
    pEntry->texinfo.header.solidColor = color;
    pEntry->material.texFormat.is16bit = 0;
    pEntry->texinfo.header.texture_type = 1;
    pEntry->material.texFormat.bpp = 8;
    pEntry->material.num_texinfo = 1;
    pEntry->material.curCelNum = 0;
    pEntry->material.texinfos[0] = &pEntry->texinfo;
    return pEntry;
}

// @0x46b530
tDwLaser* dwLaser_FindByThing(SithWorld* pWorld, SithThing* pThing)
{
    int32_t i;
    for (i = 0; i < pWorld->numDwLasers; i++)
    {
        if (pWorld->aDwLasers[i].pOwnerThing == pThing)
            return &pWorld->aDwLasers[i];
    }
    return NULL;
}

// @0x46b570
tDwLaser* dwLaser_FindById(SithWorld* pWorld, uint32_t id)
{
    int32_t i;
    for (i = 0; i < pWorld->numDwLasers; i++)
    {
        if (pWorld->aDwLasers[i].pOwnerThing && pWorld->aDwLasers[i].id == id)
            return &pWorld->aDwLasers[i];
    }
    return NULL;
}

// @0x46b5b0
void dwLaser_Remove(SithWorld* pWorld, tDwLaser* pLaser)
{
    pLaser->pOwnerThing = NULL;
}

// @0x46b5c0
void dwLaser_Free(SithWorld* pWorld)
{
    pWorld->numDwLasers = 0;
    if (pWorld->aDwLasers)
    {
        (*pSithHS->free)(pWorld->aDwLasers);
        pWorld->aDwLasers = NULL;
    }
}

// The binary's sithRender_DrawLasers@0x45e780 (sithRender unit there; lives
// here because src/Dw is retro-excluded while sithRender.c is shared). Called
// from sithRender_Draw each frame under Main_bDwCompat.
void dwLaser_DrawAll()
{
    SithWorld* pWorld = sithWorld_g_pCurrentWorld;
    int32_t i;

    if (!pWorld)
        return;
    rdSetSortingMethod(2);
    for (i = 0; i < pWorld->numDwLasers; i++)
    {
        tDwLaser* pLaser = &pWorld->aDwLasers[i];
        SithThing* pOwner = pLaser->pOwnerThing;
        SithThing* pTarget;
        if (!pOwner)
            continue;
        pTarget = pLaser->pTargetThing;
        if ((!pTarget || (pTarget->type != SITH_THING_FREE && !(pTarget->flags & SITH_TF_DESTROYED)))
            && pOwner->type != SITH_THING_FREE && !(pOwner->flags & SITH_TF_DESTROYED))
        {
            dwLaser_Draw(pLaser);
        }
        else
        {
            dwLaser_Remove(pWorld, pLaser);
        }
    }
}
