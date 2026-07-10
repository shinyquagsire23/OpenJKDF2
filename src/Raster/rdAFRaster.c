#include "rdAFRaster.h"

#include "Engine/rdCamera.h"
#include "Engine/rdActive.h"
#include "Win95/stdDisplay.h"
#include "jk.h"

#ifdef RDRASTER_SOFTWARE_RENDERER

#include <math.h>

// Shading axes for the textured span-sampler template (rdAFRaster_span.h, RDA_SHADE).
#define RDA_FLAT    0   // raw texel (no light table)
#define RDA_LIT     1   // one constant light row through the light table
#define RDA_GOURAUD 2   // per-pixel interpolated light level through the light table

// Scratch flat color passed from rdAFRaster_DrawNGonLW to the standalone span drawer
// (JK.EXE DAT_0086ad0c). Write-before-read transient (set per face), so it carries no
// state across frames and needs no _Startup reset.
static uint8_t rdAFRaster_curColor;

// Per-face texture params latched by the DrawNGon flush and read by the span samplers
// (JK.EXE DAT_0086ad08/ad10/ad18/ace0/ace4/ace8). Write-before-read per face, so no reset.
static const uint8_t* rdAFRaster_curTexels;
static uint32_t rdAFRaster_curUMask;
static uint32_t rdAFRaster_curVMask;
static int      rdAFRaster_curVShift;
static int      rdAFRaster_curMip;                // mip level (perspective sampler u/v right-shift)
static int32_t  rdAFRaster_curURoundBias;
static int32_t  rdAFRaster_curVRoundBias;
static const uint8_t* rdAFRaster_curLightTable;   // LAT/LS: pre-offset light row; GAT/GS/*IT: table base

// Round a float to the nearest integer (matches JK.EXE's x87 ROUND closely enough for
// sub-pixel edge setup).
static flex_t rdAFRaster_Round(flex_t f)
{
    return (flex_t)floorf((float)f + 0.5f);
}

// Reinterpret a span interpolant slot's raw bits back to a float (the perspective u/z, v/z
// slots hold float bits written via rdActive's FloatToSlot).
static flex_t rdAFRaster_SlotToFloat(int32_t bits)
{
    union { flex_t f; int32_t i; } u;
    u.i = bits;
    return u.f;
}

// ---------------------------------------------------------------------------------------
// Wireframe (LW) family — geometryMode 2. Span drawer plots only each span's two endpoint
// pixels, so a filled polygon renders as its outline. Edge interpolant "i" = per-vertex 1/z.
// ---------------------------------------------------------------------------------------

int rdAFRaster_SetupEdgeNGonLW(rdEdge* pEdge, rdActiveFace* pFace, int vA, int vB)
{
    rdProcEntry* pProc = pFace->pProcEntry;
    rdVector3* pVerts = pProc->aVertices;
    const flex_t* pRcpZ = (const flex_t*)pFace->reserved_004;

    flex_t yaRound = rdAFRaster_Round(pVerts[vA].y);
    flex_t ybRound = rdAFRaster_Round(pVerts[vB].y);
    int yaI = (int)yaRound;
    int ybI = (int)ybRound;
    int dy = ybI - yaI;

    pEdge->numLines = dy;
    if (dy == 0)
        return 0;

    if (dy < 0)
    {
        pEdge->leftOrRightFlag = 0;
        pEdge->yStart = ybI;
        pEdge->numLines = -dy;
        pEdge->pfnAdvance = rdAFRaster_AdvanceRightEdgeNGonLW;
        if (-dy < 2)
        {
            pEdge->sortX = (int)rdAFRaster_Round(pVerts[vB].x * 65536.0f);
            pEdge->i = pRcpZ[vB];
            return 1;
        }
        flex_t yFrac = ybRound - pVerts[vB].y;
        flex_t invDy = 1.0f / (pVerts[vA].y - pVerts[vB].y);
        flex_t dxdy = (pVerts[vA].x - pVerts[vB].x) * invDy;
        pEdge->dSortX = (int)rdAFRaster_Round(dxdy * 65536.0f);
        pEdge->sortX = (int)rdAFRaster_Round((dxdy * yFrac + pVerts[vB].x) * 65536.0f);
        flex_t di = (pRcpZ[vA] - pRcpZ[vB]) * invDy;
        pEdge->di = di;
        pEdge->i = yFrac * di + pRcpZ[vB];
    }
    else
    {
        pEdge->leftOrRightFlag = 1;
        pEdge->yStart = yaI;
        pEdge->pfnAdvance = rdAFRaster_AdvanceLeftEdgeNGonLW;
        if (dy < 2)
        {
            pEdge->sortX = (int)rdAFRaster_Round(pVerts[vA].x * 65536.0f);
            pEdge->i = pRcpZ[vA];
            return 1;
        }
        flex_t yFrac = yaRound - pVerts[vA].y;
        flex_t invDy = 1.0f / (pVerts[vB].y - pVerts[vA].y);
        flex_t dxdy = (pVerts[vB].x - pVerts[vA].x) * invDy;
        pEdge->dSortX = (int)rdAFRaster_Round(dxdy * 65536.0f);
        pEdge->sortX = (int)rdAFRaster_Round((dxdy * yFrac + pVerts[vA].x) * 65536.0f);
        flex_t di = (pRcpZ[vB] - pRcpZ[vA]) * invDy;
        pEdge->di = di;
        pEdge->i = yFrac * di + pRcpZ[vA];
    }
    return 1;
}

void rdAFRaster_AdvanceLeftEdgeNGonLW(rdEdge* pEdge)
{
    pEdge->sortX += pEdge->dSortX;
    pEdge->i += pEdge->di;
}

void rdAFRaster_AdvanceRightEdgeNGonLW(rdEdge* pEdge)
{
    pEdge->sortX += pEdge->dSortX;
    pEdge->i += pEdge->di;
}

void rdAFRaster_DrawNGonLW(rdActiveFace* pFace)
{
    uint8_t color = (uint8_t)pFace->color;
    rdAFRaster_curColor = color;

    rdActiveSpan* pSpan = pFace->pFirstSpan;
    if (pSpan == NULL)
        return;

    tVBuffer* pVBuffer = rdCamera_g_pCurCamera->pCanvas->pVBuffer;
    uint32_t stride = pVBuffer->format.rowSize;
    uint8_t* pBase = (uint8_t*)pVBuffer->surface_lock_alloc;
    if (pBase == NULL)
        return;
    int fbW = pVBuffer->format.width;
    int fbH = pVBuffer->format.height;
    rdActiveSpan* pPoolBegin = rdActive_pSpanPoolBegin();
    rdActiveSpan* pPoolEnd = rdActive_pSpanPoolEnd();

    do
    {
        int xStart = pSpan->xStart;
        int width = pSpan->width;
        int y = pSpan->y;
        rdActiveSpan* pNext = pSpan->pNextSpan;
        if (pNext != NULL && (pNext < pPoolBegin || pNext >= pPoolEnd))
            pNext = NULL;

        if (y >= 0 && y < fbH)
        {
            uint8_t* pRow = pBase + y * stride;
            int xEnd = xStart + width - 1;
            if (xStart >= 0 && xStart < fbW)
                stdPlatform_WriteByte16(pRow + xStart, color);
            if (xEnd >= 0 && xEnd < fbW)
                stdPlatform_WriteByte16(pRow + xEnd, color);
        }

        pSpan = pNext;
    } while (pSpan != NULL);
}

void rdAFRaster_DrawSpanNGonLW_8(rdActiveSpan* pSpan)
{
    uint8_t color = rdAFRaster_curColor;
    tVBuffer* pVBuffer = rdCamera_g_pCurCamera->pCanvas->pVBuffer;
    uint8_t* pPixel = (uint8_t*)pVBuffer->surface_lock_alloc
                    + pSpan->xStart + pSpan->y * pVBuffer->format.rowSize;
    stdPlatform_WriteByte16(pPixel, color);
    stdPlatform_WriteByte16(pPixel + pSpan->width - 1, color);
}

// ---------------------------------------------------------------------------------------
// Gradient / mip setup, shared by the textured families.
// ---------------------------------------------------------------------------------------

// Select the mip level for a face from its distance (mirrors JK's thresholds), clamped to the
// material's mip count. Shared by the affine and perspective setups.
static int rdAFRaster_SelectMip(rdProcEntry* pProc, int numMipsMinus1)
{
    int mip = 0;
    flex_t dist = pProc->z_min;
    if (numMipsMinus1 == 1)
    {
        if (rdroid_aMipDistances.y < dist) mip = 1;
    }
    else if (numMipsMinus1 == 2)
    {
        if (rdroid_aMipDistances.x < dist) mip = (rdroid_aMipDistances.y < dist) ? 2 : 1;
    }
    else if (numMipsMinus1 >= 3)
    {
        if (rdroid_aMipDistances.x < dist)
        {
            mip = 1;
            if (rdroid_aMipDistances.y < dist)
            {
                mip = 2;
                if (rdroid_aMipDistances.z < dist) mip = 3;
            }
        }
    }
    return mip;
}

// Affine gradient setup (JK CalcAffineGradients): per-vertex 1/z into the face scratch (the edge
// "i" interpolant), mip select, and a round-nearest U/V bias. JK's full 3-vertex screen-space
// gradient SOLVE is dropped — on the affine path BuildSpans derives per-span u/v from the edge
// endpoints, so those gradients are unused (see the P3 note in PROGRESS.md).
static void rdAFRaster_CalcAffineGradients(rdActiveFace* pFace, int numMipsMinus1)
{
    rdProcEntry* pProc = pFace->pProcEntry;
    flex_t* pRcpZ = (flex_t*)pFace->reserved_004;
    for (int i = 0; i < (int)pProc->numVertices; i++)
        pRcpZ[i] = (flex_t)1.0 / pProc->aVertices[i].z;

    pFace->shift = rdAFRaster_SelectMip(pProc, numMipsMinus1);
    pFace->uRoundBias = 0x8000;
    pFace->vRoundBias = 0x8000;
}

// Perspective gradient setup (JK CalcPerspGradients): the perspective edge setup computes per-
// vertex u/z, v/z, 1/z directly (linear in screen space), so — as with CalcAffineGradients — JK's
// screen-space gradient SOLVE is not needed here; this just selects the mip and the round bias.
static void rdAFRaster_CalcPerspGradients(rdActiveFace* pFace, int numMipsMinus1)
{
    pFace->shift = rdAFRaster_SelectMip(pFace->pProcEntry, numMipsMinus1);
    pFace->uRoundBias = 0x8000;
    pFace->vRoundBias = 0x8000;
}

// Resolve a texinfo's selected mip into the face's texel base + wrap masks + shifts (shared by
// every textured family — affine and perspective). Locks nothing (the flush locks at draw time).
static void rdAFRaster_SetupTexParams(rdActiveFace* pFace, rdTexinfo* pTexinfo, int perspective)
{
    rdTexture* pTexture = pTexinfo->texture_ptr;
    if (perspective)
        rdAFRaster_CalcPerspGradients(pFace, (int)pTexture->num_mipmaps - 1);
    else
        rdAFRaster_CalcAffineGradients(pFace, (int)pTexture->num_mipmaps - 1);

    // Clamp the distance-selected mip to one that has a resident surface (a material can declare
    // more mips than it keeps CPU surfaces for). Don't gate on surface_lock_alloc: it is NULL
    // while unlocked on desktop (texels live in the SDL surface); the flush locks at draw time.
    int mip = pFace->shift;
    if (mip < 0)
        mip = 0;
    while (mip > 0 && pTexture->texture_struct[mip] == NULL)
        mip--;
    pFace->shift = mip;

    tVBuffer* pMip = pTexture->texture_struct[mip];
    pFace->pTexMip = pMip;
    if (pMip == NULL)
    {
        pFace->pTexels = NULL;
        return;
    }
    int vShift = (int)pTexture->width_bitcnt - mip;   // log2(mipWidth)

    pFace->pTexels = pMip->surface_lock_alloc;
    pFace->texFormatKey = (int)pMip->format.rowSize;
    pFace->vShift = vShift;
    pFace->uMask = (pTexture->width_minus_1  >> mip) << 16;
    pFace->vMask = (pTexture->height_minus_1 >> mip) << vShift;
}

// ---------------------------------------------------------------------------------------
// Affine (AT) edge family: interpolate x, 1/z (i), and 16.16 texture u,v down the edge (u/v in
// the uPersp/vPersp slots, which rdActive_EmitSpan's affine branch reads). Used by all AT
// variants (FAT/LAT/GAT + masked). GAT additionally interpolates the per-vertex intensity.
// ---------------------------------------------------------------------------------------

int rdAFRaster_SetupEdgeNGonFAT(rdEdge* pEdge, rdActiveFace* pFace, int vA, int vB)
{
    rdProcEntry* pProc = pFace->pProcEntry;
    rdVector3* pVerts = pProc->aVertices;
    rdVector2* pUVs = pProc->aTexVerticies;
    const flex_t* pRcpZ = (const flex_t*)pFace->reserved_004;

    flex_t yaRound = rdAFRaster_Round(pVerts[vA].y);
    flex_t ybRound = rdAFRaster_Round(pVerts[vB].y);
    int yaI = (int)yaRound;
    int ybI = (int)ybRound;
    int dy = ybI - yaI;

    pEdge->numLines = dy;
    if (dy == 0)
        return 0;

    if (dy > 0)
    {
        pEdge->leftOrRightFlag = 1;
        pEdge->yStart = yaI;
        pEdge->pfnAdvance = rdAFRaster_AdvanceLeftEdgeNGonFAT;
        if (dy < 2)
        {
            pEdge->sortX  = (int)rdAFRaster_Round(pVerts[vA].x * 65536.0f);
            pEdge->uPersp = (int)rdAFRaster_Round(pUVs[vA].x * 65536.0f);
            pEdge->vPersp = (int)rdAFRaster_Round(pUVs[vA].y * 65536.0f);
            pEdge->i = pRcpZ[vA];
            return 1;
        }
        flex_t yFrac = yaRound - pVerts[vA].y;
        flex_t invDy = 1.0f / (pVerts[vB].y - pVerts[vA].y);
        flex_t dxdy = (pVerts[vB].x - pVerts[vA].x) * invDy;
        pEdge->dSortX = (int)rdAFRaster_Round(dxdy * 65536.0f);
        pEdge->sortX  = (int)rdAFRaster_Round((dxdy * yFrac + pVerts[vA].x) * 65536.0f);
        flex_t dudy = (pUVs[vB].x - pUVs[vA].x) * invDy;
        pEdge->duPersp = (int)rdAFRaster_Round(dudy * 65536.0f);
        pEdge->uPersp  = (int)rdAFRaster_Round((dudy * yFrac + pUVs[vA].x) * 65536.0f);
        flex_t dvdy = (pUVs[vB].y - pUVs[vA].y) * invDy;
        pEdge->dvPersp = (int)rdAFRaster_Round(dvdy * 65536.0f);
        pEdge->vPersp  = (int)rdAFRaster_Round((dvdy * yFrac + pUVs[vA].y) * 65536.0f);
        flex_t di = (pRcpZ[vB] - pRcpZ[vA]) * invDy;
        pEdge->di = di;
        pEdge->i  = yFrac * di + pRcpZ[vA];
    }
    else
    {
        pEdge->leftOrRightFlag = 0;
        pEdge->yStart = ybI;
        pEdge->numLines = -dy;
        pEdge->pfnAdvance = rdAFRaster_AdvanceRightEdgeNGonFAT;
        if (-dy < 2)
        {
            pEdge->sortX  = (int)rdAFRaster_Round(pVerts[vB].x * 65536.0f);
            pEdge->uPersp = (int)rdAFRaster_Round(pUVs[vB].x * 65536.0f);
            pEdge->vPersp = (int)rdAFRaster_Round(pUVs[vB].y * 65536.0f);
            pEdge->i = pRcpZ[vB];
            return 1;
        }
        flex_t yFrac = ybRound - pVerts[vB].y;
        flex_t invDy = 1.0f / (pVerts[vA].y - pVerts[vB].y);
        flex_t dxdy = (pVerts[vA].x - pVerts[vB].x) * invDy;
        pEdge->dSortX = (int)rdAFRaster_Round(dxdy * 65536.0f);
        pEdge->sortX  = (int)rdAFRaster_Round((dxdy * yFrac + pVerts[vB].x) * 65536.0f);
        flex_t dudy = (pUVs[vA].x - pUVs[vB].x) * invDy;
        pEdge->duPersp = (int)rdAFRaster_Round(dudy * 65536.0f);
        pEdge->uPersp  = (int)rdAFRaster_Round((dudy * yFrac + pUVs[vB].x) * 65536.0f);
        flex_t dvdy = (pUVs[vA].y - pUVs[vB].y) * invDy;
        pEdge->dvPersp = (int)rdAFRaster_Round(dvdy * 65536.0f);
        pEdge->vPersp  = (int)rdAFRaster_Round((dvdy * yFrac + pUVs[vB].y) * 65536.0f);
        flex_t di = (pRcpZ[vA] - pRcpZ[vB]) * invDy;
        pEdge->di = di;
        pEdge->i  = yFrac * di + pRcpZ[vB];
    }
    return 1;
}

void rdAFRaster_AdvanceLeftEdgeNGonFAT(rdEdge* pEdge)
{
    pEdge->sortX  += pEdge->dSortX;
    pEdge->i      += pEdge->di;
    pEdge->uPersp += pEdge->duPersp;
    pEdge->vPersp += pEdge->dvPersp;
}

void rdAFRaster_AdvanceRightEdgeNGonFAT(rdEdge* pEdge)
{
    pEdge->sortX  += pEdge->dSortX;
    pEdge->i      += pEdge->di;
    pEdge->uPersp += pEdge->duPersp;
    pEdge->vPersp += pEdge->dvPersp;
}

// Interpolate the per-vertex gouraud intensity (proc vertexIntensities, pre-scaled 0..63 by
// AddActiveFace) into the edge z slot, which rdActive_EmitSpan reads for lightingMode 3. Shared
// by the affine (GAT) and perspective (GIT) gouraud edges (both add z on top of their base edge).
static void rdAFRaster_SetupEdgeGouraudZ(rdEdge* pEdge, rdActiveFace* pFace, int vA, int vB)
{
    rdProcEntry* pProc = pFace->pProcEntry;
    rdVector3* pVerts = pProc->aVertices;
    const flex_t* pIntensity = pProc->vertexIntensities;

    int yaI = (int)rdAFRaster_Round(pVerts[vA].y);
    int ybI = (int)rdAFRaster_Round(pVerts[vB].y);
    int dy = ybI - yaI;

    int vTop;
    flex_t yTopRound;
    if (dy > 0)
    {
        vTop = vA;
        yTopRound = rdAFRaster_Round(pVerts[vA].y);
    }
    else
    {
        vTop = vB;
        yTopRound = rdAFRaster_Round(pVerts[vB].y);
    }

    int numLines = (dy > 0) ? dy : -dy;
    if (numLines < 2)
    {
        pEdge->z = (int)rdAFRaster_Round(pIntensity[vTop] * 65536.0f);
        return;
    }
    int vBot = (dy > 0) ? vB : vA;
    flex_t yFrac = yTopRound - pVerts[vTop].y;
    flex_t invDy = 1.0f / (pVerts[vBot].y - pVerts[vTop].y);
    flex_t dzdy = (pIntensity[vBot] - pIntensity[vTop]) * invDy;
    pEdge->dz = (int)rdAFRaster_Round(dzdy * 65536.0f);
    pEdge->z  = (int)rdAFRaster_Round((dzdy * yFrac + pIntensity[vTop]) * 65536.0f);
}

void rdAFRaster_AdvanceLeftEdgeNGonGAT(rdEdge* pEdge)
{
    pEdge->sortX  += pEdge->dSortX;
    pEdge->i      += pEdge->di;
    pEdge->uPersp += pEdge->duPersp;
    pEdge->vPersp += pEdge->dvPersp;
    pEdge->z      += pEdge->dz;
}

void rdAFRaster_AdvanceRightEdgeNGonGAT(rdEdge* pEdge)
{
    pEdge->sortX  += pEdge->dSortX;
    pEdge->i      += pEdge->di;
    pEdge->uPersp += pEdge->duPersp;
    pEdge->vPersp += pEdge->dvPersp;
    pEdge->z      += pEdge->dz;
}

int rdAFRaster_SetupEdgeNGonGAT(rdEdge* pEdge, rdActiveFace* pFace, int vA, int vB)
{
    if (!rdAFRaster_SetupEdgeNGonFAT(pEdge, pFace, vA, vB))
        return 0;
    rdAFRaster_SetupEdgeGouraudZ(pEdge, pFace, vA, vB);
    pEdge->pfnAdvance = (pEdge->leftOrRightFlag != 0)
                      ? rdAFRaster_AdvanceLeftEdgeNGonGAT
                      : rdAFRaster_AdvanceRightEdgeNGonGAT;
    return 1;
}

// ---------------------------------------------------------------------------------------
// Perspective (IT) edge family: interpolate x, 1/z (i), u/z (u), v/z (v) down the edge, all as
// floats (rdActive_EmitSpan's perspective branch reads the u/v/i float slots). Used by all IT
// variants (FIT/LIT/GIT + masked). GIT additionally interpolates the per-vertex intensity.
// ---------------------------------------------------------------------------------------

int rdAFRaster_SetupEdgeNGonFIT(rdEdge* pEdge, rdActiveFace* pFace, int vA, int vB)
{
    rdProcEntry* pProc = pFace->pProcEntry;
    rdVector3* pVerts = pProc->aVertices;
    rdVector2* pUVs = pProc->aTexVerticies;

    flex_t yaRound = rdAFRaster_Round(pVerts[vA].y);
    flex_t ybRound = rdAFRaster_Round(pVerts[vB].y);
    int yaI = (int)yaRound;
    int ybI = (int)ybRound;
    int dy = ybI - yaI;

    pEdge->numLines = dy;
    if (dy == 0)
        return 0;

    flex_t ozA = 1.0f / pVerts[vA].z, ozB = 1.0f / pVerts[vB].z;
    flex_t uozA = pUVs[vA].x * ozA, uozB = pUVs[vB].x * ozB;
    flex_t vozA = pUVs[vA].y * ozA, vozB = pUVs[vB].y * ozB;

    if (dy > 0)
    {
        pEdge->leftOrRightFlag = 1;
        pEdge->yStart = yaI;
        pEdge->pfnAdvance = rdAFRaster_AdvanceLeftEdgeNGonFIT;
        if (dy < 2)
        {
            pEdge->sortX = (int)rdAFRaster_Round(pVerts[vA].x * 65536.0f);
            pEdge->i = ozA; pEdge->u = uozA; pEdge->v = vozA;
            return 1;
        }
        flex_t yFrac = yaRound - pVerts[vA].y;
        flex_t invDy = 1.0f / (pVerts[vB].y - pVerts[vA].y);
        flex_t dxdy = (pVerts[vB].x - pVerts[vA].x) * invDy;
        pEdge->dSortX = (int)rdAFRaster_Round(dxdy * 65536.0f);
        pEdge->sortX  = (int)rdAFRaster_Round((dxdy * yFrac + pVerts[vA].x) * 65536.0f);
        pEdge->di = (ozB  - ozA)  * invDy; pEdge->i = yFrac * pEdge->di + ozA;
        pEdge->du = (uozB - uozA) * invDy; pEdge->u = yFrac * pEdge->du + uozA;
        pEdge->dv = (vozB - vozA) * invDy; pEdge->v = yFrac * pEdge->dv + vozA;
    }
    else
    {
        pEdge->leftOrRightFlag = 0;
        pEdge->yStart = ybI;
        pEdge->numLines = -dy;
        pEdge->pfnAdvance = rdAFRaster_AdvanceRightEdgeNGonFIT;
        if (-dy < 2)
        {
            pEdge->sortX = (int)rdAFRaster_Round(pVerts[vB].x * 65536.0f);
            pEdge->i = ozB; pEdge->u = uozB; pEdge->v = vozB;
            return 1;
        }
        flex_t yFrac = ybRound - pVerts[vB].y;
        flex_t invDy = 1.0f / (pVerts[vA].y - pVerts[vB].y);
        flex_t dxdy = (pVerts[vA].x - pVerts[vB].x) * invDy;
        pEdge->dSortX = (int)rdAFRaster_Round(dxdy * 65536.0f);
        pEdge->sortX  = (int)rdAFRaster_Round((dxdy * yFrac + pVerts[vB].x) * 65536.0f);
        pEdge->di = (ozA  - ozB)  * invDy; pEdge->i = yFrac * pEdge->di + ozB;
        pEdge->du = (uozA - uozB) * invDy; pEdge->u = yFrac * pEdge->du + uozB;
        pEdge->dv = (vozA - vozB) * invDy; pEdge->v = yFrac * pEdge->dv + vozB;
    }
    return 1;
}

void rdAFRaster_AdvanceLeftEdgeNGonFIT(rdEdge* pEdge)
{
    pEdge->sortX += pEdge->dSortX;
    pEdge->i     += pEdge->di;
    pEdge->u     += pEdge->du;
    pEdge->v     += pEdge->dv;
}

void rdAFRaster_AdvanceRightEdgeNGonFIT(rdEdge* pEdge)
{
    pEdge->sortX += pEdge->dSortX;
    pEdge->i     += pEdge->di;
    pEdge->u     += pEdge->du;
    pEdge->v     += pEdge->dv;
}

void rdAFRaster_AdvanceLeftEdgeNGonGIT(rdEdge* pEdge)
{
    pEdge->sortX += pEdge->dSortX;
    pEdge->i     += pEdge->di;
    pEdge->u     += pEdge->du;
    pEdge->v     += pEdge->dv;
    pEdge->z     += pEdge->dz;
}

void rdAFRaster_AdvanceRightEdgeNGonGIT(rdEdge* pEdge)
{
    pEdge->sortX += pEdge->dSortX;
    pEdge->i     += pEdge->di;
    pEdge->u     += pEdge->du;
    pEdge->v     += pEdge->dv;
    pEdge->z     += pEdge->dz;
}

int rdAFRaster_SetupEdgeNGonGIT(rdEdge* pEdge, rdActiveFace* pFace, int vA, int vB)
{
    if (!rdAFRaster_SetupEdgeNGonFIT(pEdge, pFace, vA, vB))
        return 0;
    rdAFRaster_SetupEdgeGouraudZ(pEdge, pFace, vA, vB);
    pEdge->pfnAdvance = (pEdge->leftOrRightFlag != 0)
                      ? rdAFRaster_AdvanceLeftEdgeNGonGIT
                      : rdAFRaster_AdvanceRightEdgeNGonGIT;
    return 1;
}

// ---------------------------------------------------------------------------------------
// Solid (S) family: flat-color fill, no texture. FS/LS use the wireframe edge (x + 1/z only);
// GS adds the per-vertex gouraud intensity. The flush fills each span (not just the endpoints).
// ---------------------------------------------------------------------------------------

void rdAFRaster_AdvanceLeftEdgeNGonGS(rdEdge* pEdge)
{
    pEdge->sortX += pEdge->dSortX;
    pEdge->i     += pEdge->di;
    pEdge->z     += pEdge->dz;
}

void rdAFRaster_AdvanceRightEdgeNGonGS(rdEdge* pEdge)
{
    pEdge->sortX += pEdge->dSortX;
    pEdge->i     += pEdge->di;
    pEdge->z     += pEdge->dz;
}

int rdAFRaster_SetupEdgeNGonGS(rdEdge* pEdge, rdActiveFace* pFace, int vA, int vB)
{
    if (!rdAFRaster_SetupEdgeNGonLW(pEdge, pFace, vA, vB))
        return 0;
    rdAFRaster_SetupEdgeGouraudZ(pEdge, pFace, vA, vB);
    pEdge->pfnAdvance = (pEdge->leftOrRightFlag != 0)
                      ? rdAFRaster_AdvanceLeftEdgeNGonGS
                      : rdAFRaster_AdvanceRightEdgeNGonGS;
    return 1;
}

// ---------------------------------------------------------------------------------------
// Shared textured flush: latch the face's texture/light params into the sampler globals (locking
// the mip on desktop to expose its texels), then run the given span sampler over the face's span
// list. (JK's flush also exports UVs to a D3D vbuffer / writes a HW depth buffer as a second pass;
// both are hardware-assist with no effect in a pure-software present, so omitted.)
// ---------------------------------------------------------------------------------------

static void rdAFRaster_DrawNGonCommon(rdActiveFace* pFace, void (*pfnSpan)(rdActiveSpan*))
{
    rdActiveSpan* pSpan = pFace->pFirstSpan;
    if (pSpan == NULL)
        return;

    tVBuffer* pVBuffer = rdCamera_g_pCurCamera->pCanvas->pVBuffer;
    if (pVBuffer->surface_lock_alloc == NULL || pVBuffer->format.format.is16bit)
        return;

    const uint8_t* pTexels = (const uint8_t*)pFace->pTexels;
    int lockedMip = 0;
    if (pTexels == NULL && pFace->pTexMip != NULL)
    {
        stdDisplay_VBufferLock(pFace->pTexMip);
        pTexels = (const uint8_t*)pFace->pTexMip->surface_lock_alloc;
        lockedMip = 1;
    }
    if (pTexels == NULL)
        return;

    rdAFRaster_curTexels = pTexels;
    rdAFRaster_curUMask = pFace->uMask;
    rdAFRaster_curVMask = pFace->vMask;
    rdAFRaster_curVShift = pFace->vShift;
    rdAFRaster_curMip = pFace->shift;
    rdAFRaster_curURoundBias = pFace->uRoundBias;
    rdAFRaster_curVRoundBias = pFace->vRoundBias;
    rdAFRaster_curLightTable = pFace->pLightTable;

    rdActiveSpan* pPoolBegin = rdActive_pSpanPoolBegin();
    rdActiveSpan* pPoolEnd = rdActive_pSpanPoolEnd();

    do
    {
        rdActiveSpan* pNext = pSpan->pNextSpan;
        if (pNext != NULL && (pNext < pPoolBegin || pNext >= pPoolEnd))
            pNext = NULL;
        pfnSpan(pSpan);
        pSpan = pNext;
    } while (pSpan != NULL);

    if (lockedMip)
        stdDisplay_VBufferUnlock(pFace->pTexMip);
}

// --- Textured span samplers: one per Grim DrawSpanNGon<V>_8 symbol, emitted from the ONE
// template rdAFRaster_span.h (machine-generated by gen_rda_variants.py). ---

#define RDA_NAME rdAFRaster_DrawSpanNGonFAT_8
#define RDA_PERSP 0
#define RDA_MASKED 0
#define RDA_SHADE RDA_FLAT
#include "rdAFRaster_span.h"

#define RDA_NAME rdAFRaster_DrawSpanNGonLAT_8
#define RDA_PERSP 0
#define RDA_MASKED 0
#define RDA_SHADE RDA_LIT
#include "rdAFRaster_span.h"

#define RDA_NAME rdAFRaster_DrawSpanNGonGAT_8
#define RDA_PERSP 0
#define RDA_MASKED 0
#define RDA_SHADE RDA_GOURAUD
#include "rdAFRaster_span.h"

#define RDA_NAME rdAFRaster_DrawSpanNGonMFAT_8
#define RDA_PERSP 0
#define RDA_MASKED 1
#define RDA_SHADE RDA_FLAT
#include "rdAFRaster_span.h"

#define RDA_NAME rdAFRaster_DrawSpanNGonMLAT_8
#define RDA_PERSP 0
#define RDA_MASKED 1
#define RDA_SHADE RDA_LIT
#include "rdAFRaster_span.h"

#define RDA_NAME rdAFRaster_DrawSpanNGonMGAT_8
#define RDA_PERSP 0
#define RDA_MASKED 1
#define RDA_SHADE RDA_GOURAUD
#include "rdAFRaster_span.h"

#define RDA_NAME rdAFRaster_DrawSpanNGonFIT_8
#define RDA_PERSP 1
#define RDA_MASKED 0
#define RDA_SHADE RDA_FLAT
#include "rdAFRaster_span.h"

#define RDA_NAME rdAFRaster_DrawSpanNGonLIT_8
#define RDA_PERSP 1
#define RDA_MASKED 0
#define RDA_SHADE RDA_LIT
#include "rdAFRaster_span.h"

#define RDA_NAME rdAFRaster_DrawSpanNGonGIT_8
#define RDA_PERSP 1
#define RDA_MASKED 0
#define RDA_SHADE RDA_GOURAUD
#include "rdAFRaster_span.h"

#define RDA_NAME rdAFRaster_DrawSpanNGonMFIT_8
#define RDA_PERSP 1
#define RDA_MASKED 1
#define RDA_SHADE RDA_FLAT
#include "rdAFRaster_span.h"

#define RDA_NAME rdAFRaster_DrawSpanNGonMLIT_8
#define RDA_PERSP 1
#define RDA_MASKED 1
#define RDA_SHADE RDA_LIT
#include "rdAFRaster_span.h"

#define RDA_NAME rdAFRaster_DrawSpanNGonMGIT_8
#define RDA_PERSP 1
#define RDA_MASKED 1
#define RDA_SHADE RDA_GOURAUD
#include "rdAFRaster_span.h"

// --- Textured DrawNGon<V> flushers: latch the face's tex/light params + run the sampler
// over its span list (all share rdAFRaster_DrawNGonCommon). ---
static void rdAFRaster_DrawNGonFAT(rdActiveFace* pFace) { rdAFRaster_DrawNGonCommon(pFace, rdAFRaster_DrawSpanNGonFAT_8); }
static void rdAFRaster_DrawNGonLAT(rdActiveFace* pFace) { rdAFRaster_DrawNGonCommon(pFace, rdAFRaster_DrawSpanNGonLAT_8); }
static void rdAFRaster_DrawNGonGAT(rdActiveFace* pFace) { rdAFRaster_DrawNGonCommon(pFace, rdAFRaster_DrawSpanNGonGAT_8); }
static void rdAFRaster_DrawNGonMFAT(rdActiveFace* pFace) { rdAFRaster_DrawNGonCommon(pFace, rdAFRaster_DrawSpanNGonMFAT_8); }
static void rdAFRaster_DrawNGonMLAT(rdActiveFace* pFace) { rdAFRaster_DrawNGonCommon(pFace, rdAFRaster_DrawSpanNGonMLAT_8); }
static void rdAFRaster_DrawNGonMGAT(rdActiveFace* pFace) { rdAFRaster_DrawNGonCommon(pFace, rdAFRaster_DrawSpanNGonMGAT_8); }
static void rdAFRaster_DrawNGonFIT(rdActiveFace* pFace) { rdAFRaster_DrawNGonCommon(pFace, rdAFRaster_DrawSpanNGonFIT_8); }
static void rdAFRaster_DrawNGonLIT(rdActiveFace* pFace) { rdAFRaster_DrawNGonCommon(pFace, rdAFRaster_DrawSpanNGonLIT_8); }
static void rdAFRaster_DrawNGonGIT(rdActiveFace* pFace) { rdAFRaster_DrawNGonCommon(pFace, rdAFRaster_DrawSpanNGonGIT_8); }
static void rdAFRaster_DrawNGonMFIT(rdActiveFace* pFace) { rdAFRaster_DrawNGonCommon(pFace, rdAFRaster_DrawSpanNGonMFIT_8); }
static void rdAFRaster_DrawNGonMLIT(rdActiveFace* pFace) { rdAFRaster_DrawNGonCommon(pFace, rdAFRaster_DrawSpanNGonMLIT_8); }
static void rdAFRaster_DrawNGonMGIT(rdActiveFace* pFace) { rdAFRaster_DrawNGonCommon(pFace, rdAFRaster_DrawSpanNGonMGIT_8); }

// ---------------------------------------------------------------------------------------
// Solid (S) flushers: fill every pixel of each span (unlike the LW wireframe endpoints).
// ---------------------------------------------------------------------------------------

// Constant-color fill (FS flat / LS lit — the light level is baked into pFace->color at setup).
static void rdAFRaster_DrawNGonSolidFlatCommon(rdActiveFace* pFace)
{
    rdActiveSpan* pSpan = pFace->pFirstSpan;
    if (pSpan == NULL)
        return;
    tVBuffer* pVBuffer = rdCamera_g_pCurCamera->pCanvas->pVBuffer;
    uint8_t* pBase = (uint8_t*)pVBuffer->surface_lock_alloc;
    if (pBase == NULL)
        return;
    uint32_t stride = pVBuffer->format.rowSize;
    int fbW = pVBuffer->format.width;
    int fbH = pVBuffer->format.height;
    uint8_t color = (uint8_t)pFace->color;
    rdActiveSpan* pPoolBegin = rdActive_pSpanPoolBegin();
    rdActiveSpan* pPoolEnd = rdActive_pSpanPoolEnd();

    do
    {
        rdActiveSpan* pNext = pSpan->pNextSpan;
        if (pNext != NULL && (pNext < pPoolBegin || pNext >= pPoolEnd))
            pNext = NULL;
        int y = pSpan->y;
        if (y >= 0 && y < fbH)
        {
            int xStart = pSpan->xStart;
            int count = pSpan->width;
            if (xStart < 0) { count += xStart; xStart = 0; }
            if (xStart + count > fbW) count = fbW - xStart;
            uint8_t* pRow = pBase + y * stride + xStart;
            for (int i = 0; i < count; i++)
                stdPlatform_WriteByte16(pRow + i, color);
        }
        pSpan = pNext;
    } while (pSpan != NULL);
}

static void rdAFRaster_DrawNGonFS(rdActiveFace* pFace) { rdAFRaster_DrawNGonSolidFlatCommon(pFace); }
static void rdAFRaster_DrawNGonLS(rdActiveFace* pFace) { rdAFRaster_DrawNGonSolidFlatCommon(pFace); }

// Gouraud solid: the fill color is the raw solid index mapped per-pixel through the light table by
// the interpolated intensity (span.z / dz), mirroring the GAT/GS sampler shading.
static void rdAFRaster_DrawNGonGS(rdActiveFace* pFace)
{
    rdActiveSpan* pSpan = pFace->pFirstSpan;
    if (pSpan == NULL)
        return;
    tVBuffer* pVBuffer = rdCamera_g_pCurCamera->pCanvas->pVBuffer;
    uint8_t* pBase = (uint8_t*)pVBuffer->surface_lock_alloc;
    if (pBase == NULL)
        return;
    uint32_t stride = pVBuffer->format.rowSize;
    int fbW = pVBuffer->format.width;
    int fbH = pVBuffer->format.height;
    uint8_t color = (uint8_t)pFace->color;
    const uint8_t* pLight = pFace->pLightTable;
    if (pLight == NULL)
    {
        rdAFRaster_DrawNGonSolidFlatCommon(pFace);
        return;
    }
    rdActiveSpan* pPoolBegin = rdActive_pSpanPoolBegin();
    rdActiveSpan* pPoolEnd = rdActive_pSpanPoolEnd();

    do
    {
        rdActiveSpan* pNext = pSpan->pNextSpan;
        if (pNext != NULL && (pNext < pPoolBegin || pNext >= pPoolEnd))
            pNext = NULL;
        int y = pSpan->y;
        if (y >= 0 && y < fbH)
        {
            int xStart = pSpan->xStart;
            int count = pSpan->width;
            int32_t dz = pSpan->dz;
            uint32_t zAcc = (uint32_t)pSpan->z;
            if (xStart < 0)
            {
                zAcc += (uint32_t)dz * (uint32_t)(-xStart);
                count += xStart;
                xStart = 0;
            }
            if (xStart + count > fbW) count = fbW - xStart;
            uint8_t* pRow = pBase + y * stride + xStart;
            for (int i = 0; i < count; i++)
            {
                uint32_t light = (zAcc & 0x3f0000) >> 8;
                stdPlatform_WriteByte16(pRow + i, pLight[light + color]);
                zAcc += (uint32_t)dz;
            }
        }
        pSpan = pNext;
    } while (pSpan != NULL);
}

// ---------------------------------------------------------------------------------------
// Face setups: pick the mip/texels + light params + install the family's draw + edge callbacks.
// One per Grim SetupNGon<V>. Called by rdActive_AddActiveFace's per-mode dispatch.
// ---------------------------------------------------------------------------------------

// Wireframe.
void rdAFRaster_SetupNGonLW_0(rdActiveFace* pFace, rdTexinfo* pTexinfo)
{
    rdProcEntry* pProc = pFace->pProcEntry;
    rdVector3* pVerts = pProc->aVertices;
    flex_t* pRcpZ = (flex_t*)pFace->reserved_004;
    for (int i = 0; i < (int)pProc->numVertices; i++)
        pRcpZ[i] = (flex_t)1.0 / pVerts[i].z;

    pFace->pfnDrawSpan = rdAFRaster_DrawNGonLW;
    pFace->pfnSetupEdge = rdAFRaster_SetupEdgeNGonLW;
    pFace->color = pTexinfo->header.solidColor;
}

// Affine textured (AT).
void rdAFRaster_SetupNGonFAT(rdActiveFace* pFace, rdTexinfo* pTexinfo)
{
    rdAFRaster_SetupTexParams(pFace, pTexinfo, 0);
    pFace->pfnDrawSpan = rdAFRaster_DrawNGonFAT;
    pFace->pfnSetupEdge = rdAFRaster_SetupEdgeNGonFAT;
}

void rdAFRaster_SetupNGonLAT(rdActiveFace* pFace, rdTexinfo* pTexinfo, int lightLevel)
{
    rdAFRaster_SetupTexParams(pFace, pTexinfo, 0);
    pFace->pfnDrawSpan = rdAFRaster_DrawNGonLAT;
    pFace->pfnSetupEdge = rdAFRaster_SetupEdgeNGonFAT;
    pFace->pLightTable = pFace->pProcEntry->colormap->lightlevel + lightLevel * 256;
}

void rdAFRaster_SetupNGonGAT(rdActiveFace* pFace, rdTexinfo* pTexinfo)
{
    rdAFRaster_SetupTexParams(pFace, pTexinfo, 0);
    pFace->pfnDrawSpan = rdAFRaster_DrawNGonGAT;
    pFace->pfnSetupEdge = rdAFRaster_SetupEdgeNGonGAT;
    pFace->pLightTable = pFace->pProcEntry->colormap->lightlevel;
}

void rdAFRaster_SetupNGonMFAT(rdActiveFace* pFace, rdTexinfo* pTexinfo)
{
    rdAFRaster_SetupTexParams(pFace, pTexinfo, 0);
    pFace->pfnDrawSpan = rdAFRaster_DrawNGonMFAT;
    pFace->pfnSetupEdge = rdAFRaster_SetupEdgeNGonFAT;
}

void rdAFRaster_SetupNGonMLAT(rdActiveFace* pFace, rdTexinfo* pTexinfo, int lightLevel)
{
    rdAFRaster_SetupTexParams(pFace, pTexinfo, 0);
    pFace->pfnDrawSpan = rdAFRaster_DrawNGonMLAT;
    pFace->pfnSetupEdge = rdAFRaster_SetupEdgeNGonFAT;
    pFace->pLightTable = pFace->pProcEntry->colormap->lightlevel + lightLevel * 256;
}

void rdAFRaster_SetupNGonMGAT(rdActiveFace* pFace, rdTexinfo* pTexinfo)
{
    rdAFRaster_SetupTexParams(pFace, pTexinfo, 0);
    pFace->pfnDrawSpan = rdAFRaster_DrawNGonMGAT;
    pFace->pfnSetupEdge = rdAFRaster_SetupEdgeNGonGAT;
    pFace->pLightTable = pFace->pProcEntry->colormap->lightlevel;
}

// Perspective textured (IT).
void rdAFRaster_SetupNGonFIT(rdActiveFace* pFace, rdTexinfo* pTexinfo)
{
    rdAFRaster_SetupTexParams(pFace, pTexinfo, 1);
    pFace->pfnDrawSpan = rdAFRaster_DrawNGonFIT;
    pFace->pfnSetupEdge = rdAFRaster_SetupEdgeNGonFIT;
}

void rdAFRaster_SetupNGonLIT(rdActiveFace* pFace, rdTexinfo* pTexinfo, int lightLevel)
{
    rdAFRaster_SetupTexParams(pFace, pTexinfo, 1);
    pFace->pfnDrawSpan = rdAFRaster_DrawNGonLIT;
    pFace->pfnSetupEdge = rdAFRaster_SetupEdgeNGonFIT;
    pFace->pLightTable = pFace->pProcEntry->colormap->lightlevel + lightLevel * 256;
}

void rdAFRaster_SetupNGonGIT(rdActiveFace* pFace, rdTexinfo* pTexinfo)
{
    rdAFRaster_SetupTexParams(pFace, pTexinfo, 1);
    pFace->pfnDrawSpan = rdAFRaster_DrawNGonGIT;
    pFace->pfnSetupEdge = rdAFRaster_SetupEdgeNGonGIT;
    pFace->pLightTable = pFace->pProcEntry->colormap->lightlevel;
}

void rdAFRaster_SetupNGonMFIT(rdActiveFace* pFace, rdTexinfo* pTexinfo)
{
    rdAFRaster_SetupTexParams(pFace, pTexinfo, 1);
    pFace->pfnDrawSpan = rdAFRaster_DrawNGonMFIT;
    pFace->pfnSetupEdge = rdAFRaster_SetupEdgeNGonFIT;
}

void rdAFRaster_SetupNGonMLIT(rdActiveFace* pFace, rdTexinfo* pTexinfo, int lightLevel)
{
    rdAFRaster_SetupTexParams(pFace, pTexinfo, 1);
    pFace->pfnDrawSpan = rdAFRaster_DrawNGonMLIT;
    pFace->pfnSetupEdge = rdAFRaster_SetupEdgeNGonFIT;
    pFace->pLightTable = pFace->pProcEntry->colormap->lightlevel + lightLevel * 256;
}

void rdAFRaster_SetupNGonMGIT(rdActiveFace* pFace, rdTexinfo* pTexinfo)
{
    rdAFRaster_SetupTexParams(pFace, pTexinfo, 1);
    pFace->pfnDrawSpan = rdAFRaster_DrawNGonMGIT;
    pFace->pfnSetupEdge = rdAFRaster_SetupEdgeNGonGIT;
    pFace->pLightTable = pFace->pProcEntry->colormap->lightlevel;
}

// Solid (S) — per-vertex 1/z into scratch (for the wireframe-style edge), install the fill flush.
static void rdAFRaster_SetupSolidRcpZ(rdActiveFace* pFace)
{
    rdProcEntry* pProc = pFace->pProcEntry;
    flex_t* pRcpZ = (flex_t*)pFace->reserved_004;
    for (int i = 0; i < (int)pProc->numVertices; i++)
        pRcpZ[i] = (flex_t)1.0 / pProc->aVertices[i].z;
}

void rdAFRaster_SetupNGonFS(rdActiveFace* pFace, rdTexinfo* pTexinfo)
{
    rdAFRaster_SetupSolidRcpZ(pFace);
    pFace->pfnDrawSpan = rdAFRaster_DrawNGonFS;
    pFace->pfnSetupEdge = rdAFRaster_SetupEdgeNGonLW;
    pFace->color = pTexinfo->header.solidColor & 0xFF;   // flat: no darkening
}

void rdAFRaster_SetupNGonLS(rdActiveFace* pFace, rdTexinfo* pTexinfo, int lightLevel)
{
    rdAFRaster_SetupSolidRcpZ(pFace);
    pFace->pfnDrawSpan = rdAFRaster_DrawNGonLS;
    pFace->pfnSetupEdge = rdAFRaster_SetupEdgeNGonLW;
    // Lit: bake the constant light level into the solid color through the light table.
    const uint8_t* pLight = pFace->pProcEntry->colormap->lightlevel;
    pFace->color = pLight[lightLevel * 256 + (pTexinfo->header.solidColor & 0xFF)];
}

void rdAFRaster_SetupNGonGS(rdActiveFace* pFace, rdTexinfo* pTexinfo)
{
    rdAFRaster_SetupSolidRcpZ(pFace);
    pFace->pfnDrawSpan = rdAFRaster_DrawNGonGS;
    pFace->pfnSetupEdge = rdAFRaster_SetupEdgeNGonGS;
    pFace->color = pTexinfo->header.solidColor & 0xFF;   // raw index; light applied per pixel
    pFace->pLightTable = pFace->pProcEntry->colormap->lightlevel;
}

#endif // RDRASTER_SOFTWARE_RENDERER
