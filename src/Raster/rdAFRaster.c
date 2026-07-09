#include "rdAFRaster.h"

#include "Engine/rdCamera.h"
#include "Engine/rdActive.h"
#include "Win95/stdDisplay.h"
#include "jk.h"

#ifdef RDRASTER_SOFTWARE_RENDERER

#include <math.h>

// Scratch flat color passed from rdAFRaster_DrawNGonLW to the standalone span drawer
// (JK.EXE DAT_0086ad0c). Write-before-read transient (set per face), so it carries no
// state across frames and needs no _Startup reset.
static uint8_t rdAFRaster_curColor;

// Per-face texture params latched by rdAFRaster_DrawNGonFAT and read by the span sampler
// (JK.EXE DAT_0086ad08/ad10/ad18/ace0/ace4/ace8). Write-before-read per face, so no reset.
static const uint8_t* rdAFRaster_curTexels;
static uint32_t rdAFRaster_curUMask;
static uint32_t rdAFRaster_curVMask;
static int      rdAFRaster_curVShift;
static int32_t  rdAFRaster_curURoundBias;
static int32_t  rdAFRaster_curVRoundBias;
static const uint8_t* rdAFRaster_curLightTable;   // LAT: pre-offset light row; GAT: table base

// Round a float to the nearest integer (matches JK.EXE's x87 ROUND closely enough for
// sub-pixel edge setup).
static flex_t rdAFRaster_Round(flex_t f)
{
    return (flex_t)floorf((float)f + 0.5f);
}

// Face setup for the wireframe mode: precompute per-vertex reciprocal depth (used as the
// interpolated edge value), install the edge/draw callbacks, and latch the flat color.
void rdAFRaster_SetupNGonLW_0(rdActiveFace* pFace, rdTexinfo* pTexinfo)
{
    rdProcEntry* pProc = pFace->pProcEntry;
    rdVector3* pVerts = pProc->aVertices;
    // Per-vertex 1/z lives in the face's setup-scratch region (face+0x04..); the LW edge
    // setup interpolates it as the edge "i" value.
    flex_t* pRcpZ = (flex_t*)pFace->reserved_004;

    for (int i = 0; i < (int)pProc->numVertices; i++)
        pRcpZ[i] = (flex_t)1.0 / pVerts[i].z;

    pFace->pfnDrawSpan = rdAFRaster_DrawNGonLW;
    pFace->pfnSetupEdge = rdAFRaster_SetupEdgeNGonLW;
    pFace->color = pTexinfo->header.solidColor;
}

// Build one active edge between screen vertices vA and vB. The sign of the vertical span
// decides whether it is the span's left edge (downward) or right edge (upward). Returns 0
// for a horizontal (zero-height) edge, which the AET drops.
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
        // Upward edge -> the span's right edge.
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
        // Downward edge -> the span's left edge.
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

// Per-scanline edge step: advance X and the interpolated 1/z by their deltas.
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

// Flush one face's span list: plot the two endpoint pixels of every span (wireframe).
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
    if (pBase == NULL)   // Added: surface must be locked for direct pixel access
        return;
    // Added: spans from frustum-clipped geometry can still reach a pixel or two past the
    // framebuffer edge; clip endpoints so the byte writes never leave the surface.
    int fbW = pVBuffer->format.width;
    int fbH = pVBuffer->format.height;
    // Added: defensively bound the span-list walk to the pool. The multi-face depth-sort
    // in BuildSpans can currently produce a stray pNextSpan on complex scenes; stop the
    // walk at any link that leaves the pool rather than dereference garbage.
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
            // Word-safe byte writes: the vbuffer can live in word-addressable VRAM/extram
            // where raw 8-bit stores are dropped (see HEAP_WORD_ADDRESSABLE in CLAUDE.md).
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

// Standalone single-span drawer (uses the color latched by rdAFRaster_DrawNGonLW).
void rdAFRaster_DrawSpanNGonLW_8(rdActiveSpan* pSpan)
{
    uint8_t color = rdAFRaster_curColor;
    tVBuffer* pVBuffer = rdCamera_g_pCurCamera->pCanvas->pVBuffer;
    uint8_t* pPixel = (uint8_t*)pVBuffer->surface_lock_alloc
                    + pSpan->xStart + pSpan->y * pVBuffer->format.rowSize;
    stdPlatform_WriteByte16(pPixel, color);
    stdPlatform_WriteByte16(pPixel + pSpan->width - 1, color);
}

// =====================================================================================
// Flat affine textured (FAT) family — geometryMode 4 (RD_GEOMETRY_FULL), textureMode 0
// (affine/linear texmap), lightingMode 0 (flat). This is the first genuinely texture-
// sampling path: each span walks the texture in screen-linear (u,v) steps and writes real
// texels. Grim's SetupNGon{F,G,L}AT all share rdAFRaster_CalcAffineGradients ("AT" = Affine
// Textured); the flat variant is FAT. (JK.EXE labels its @0047bcc0 "SetupNGonFAT", but that
// one calls CalcPerspGradients — a mislabel; the real affine flat setup is JK sub_4777A0.)
// =====================================================================================

// Precompute the per-vertex reciprocal depth (the edge "i"/depth-sort interpolant), select
// the mip level from the face distance, and set the sub-texel U/V round bias.
//
// JK.EXE's rdAFRaster_CalcAffineGradients additionally runs a 3-vertex screen-space solve for
// the U/V gradient SIGNS, purely to choose a 0x8000-vs-0x7fff round bias that trims texel-seam
// shimmer. Those gradients are otherwise unused on the textureMode==0 (FAT) path — BuildSpans
// derives each span's U/V from the two edge endpoints via the 1/n LUT — so we use standard
// round-to-nearest (0x8000) on both axes and skip the solve. (The full solve returns when the
// affine-BuildSpans/textureMode==1 families that consume dU/dV land.)
static void rdAFRaster_CalcAffineGradients(rdActiveFace* pFace, int numMipsMinus1)
{
    rdProcEntry* pProc = pFace->pProcEntry;
    flex_t* pRcpZ = (flex_t*)pFace->reserved_004;
    for (int i = 0; i < (int)pProc->numVertices; i++)
        pRcpZ[i] = (flex_t)1.0 / pProc->aVertices[i].z;

    // Mip level by face distance vs rdroid_aMipDistances, capped at the mips the material has.
    // The first threshold differs with mip count exactly as JK: .y for a 2-mip material, else .x.
    int mip = 0;
    flex_t dist = pProc->z_min;
    if (numMipsMinus1 == 1)
    {
        if (rdroid_aMipDistances.y < dist)
            mip = 1;
    }
    else if (numMipsMinus1 == 2)
    {
        if (rdroid_aMipDistances.x < dist)
            mip = (rdroid_aMipDistances.y < dist) ? 2 : 1;
    }
    else if (numMipsMinus1 >= 3)
    {
        if (rdroid_aMipDistances.x < dist)
        {
            mip = 1;
            if (rdroid_aMipDistances.y < dist)
            {
                mip = 2;
                if (rdroid_aMipDistances.z < dist)
                    mip = 3;
            }
        }
    }

    pFace->shift = mip;
    pFace->uRoundBias = 0x8000;
    pFace->vRoundBias = 0x8000;
}

// Shared texture-param resolution for all affine textured families (FAT/LAT/GAT): run the
// gradients (mip select + reciprocal-z), pick a resident mip, and derive the texel base + wrap
// masks. Installs the common FAT edge callback (LAT reuses it; GAT overrides with its own).
static void rdAFRaster_SetupTexParams(rdActiveFace* pFace, rdTexinfo* pTexinfo)
{
    rdTexture* pTexture = pTexinfo->texture_ptr;
    rdAFRaster_CalcAffineGradients(pFace, (int)pTexture->num_mipmaps - 1);

    // Always install an edge callback; BuildEdges needs pfnSetupEdge even if the texels turn
    // out to be non-resident (in which case the draw callback no-ops on the NULL pTexels).
    pFace->pfnSetupEdge = rdAFRaster_SetupEdgeNGonFAT;

    // Clamp the distance-selected mip to one that actually exists. On the desktop GL path a
    // material may declare more mips than it keeps CPU surfaces for (texture_struct[mip] NULL),
    // which would otherwise NULL-deref. Note: surface_lock_alloc is NULL while unlocked on
    // desktop (texels live in the SDL surface), so DON'T gate on it here — the draw callback
    // locks the mip at draw time to get the pixels.
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
        pFace->pTexels = NULL;   // no mip surface -> the draw callback skips this face
        return;
    }
    int vShift = (int)pTexture->width_bitcnt - mip;   // log2(mipWidth)

    pFace->pTexels = pMip->surface_lock_alloc;   // resident on TWL/DC; NULL(->lock) on desktop
    pFace->texFormatKey = (int)pMip->format.rowSize;  // JK sampler-variant key; unused (general sampler)
    pFace->vShift = vShift;
    pFace->uMask = (pTexture->width_minus_1  >> mip) << 16;       // (mipWidth-1) << 16
    pFace->vMask = (pTexture->height_minus_1 >> mip) << vShift;   // (mipHeight-1) << vShift
}

// Face setup for FAT (flat): resolve the texture and install the plain texel-copy span drawer.
void rdAFRaster_SetupNGonFAT(rdActiveFace* pFace, rdTexinfo* pTexinfo)
{
    rdAFRaster_SetupTexParams(pFace, pTexinfo);
    pFace->pfnDrawSpan = rdAFRaster_DrawNGonFAT;
}

// Face setup for LAT (lit): as FAT, plus a single per-face light row (colormap->lightlevel +
// lightLevel*256) that the span drawer maps every texel through. lightLevel is 0..63.
void rdAFRaster_SetupNGonLAT(rdActiveFace* pFace, rdTexinfo* pTexinfo, int lightLevel)
{
    rdAFRaster_SetupTexParams(pFace, pTexinfo);
    pFace->pfnDrawSpan = rdAFRaster_DrawNGonLAT;
    pFace->pLightTable = pFace->pProcEntry->colormap->lightlevel + lightLevel * 256;
}

// Face setup for GAT (gouraud): as FAT, but the light index is interpolated per-pixel, so the
// span drawer indexes the light table base (colormap->lightlevel) by [intensity*256 + texel].
// Uses the gouraud edge setup, which additionally interpolates the per-vertex intensity.
void rdAFRaster_SetupNGonGAT(rdActiveFace* pFace, rdTexinfo* pTexinfo)
{
    rdAFRaster_SetupTexParams(pFace, pTexinfo);
    pFace->pfnDrawSpan = rdAFRaster_DrawNGonGAT;
    pFace->pfnSetupEdge = rdAFRaster_SetupEdgeNGonGAT;
    pFace->pLightTable = pFace->pProcEntry->colormap->lightlevel;
}

// Build one active edge for a FAT face: like the LW edge setup but also interpolating the
// texture (u,v) coordinates along the edge (stored in the uPersp/vPersp slots, which the
// textureMode==0 branch of rdActive_EmitSpan reads).
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
        // Downward edge -> the span's left edge.
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
        // Upward edge -> the span's right edge.
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

// Per-scanline edge step for FAT: advance X, intensity, and the texture (u,v) by their deltas.
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

// Shared flush for all affine textured families: latch the face's texture + light params into
// the sampler globals (locking the mip on desktop to expose its texels) and run the given span
// sampler over the face's span list. (JK.EXE's flush also exports UV coords to a D3D vbuffer as
// a second pass — a hardware-assist path with no effect in a pure-software present, so omitted.)
static void rdAFRaster_DrawNGonCommon(rdActiveFace* pFace, void (*pfnSpan)(rdActiveSpan*))
{
    rdActiveSpan* pSpan = pFace->pFirstSpan;
    if (pSpan == NULL)
        return;

    // Only the general 8bpp samplers are ported; skip if the framebuffer isn't 8bpp paletted.
    tVBuffer* pVBuffer = rdCamera_g_pCurCamera->pCanvas->pVBuffer;
    if (pVBuffer->surface_lock_alloc == NULL || pVBuffer->format.format.is16bit)
        return;

    // Resolve the texel base. On TWL/DC the mip's surface_lock_alloc is a persistent buffer; on
    // the desktop GL path the 8bpp pixels live in the SDL surface and are only exposed while the
    // vbuffer is locked, so lock it here (cheap: a pointer + SDL_LockSurface) and unlock after.
    const uint8_t* pTexels = (const uint8_t*)pFace->pTexels;
    int lockedMip = 0;
    if (pTexels == NULL && pFace->pTexMip != NULL)
    {
        stdDisplay_VBufferLock(pFace->pTexMip);
        pTexels = (const uint8_t*)pFace->pTexMip->surface_lock_alloc;
        lockedMip = 1;
    }
    if (pTexels == NULL)
        return;   // texture not resident

    rdAFRaster_curTexels = pTexels;
    rdAFRaster_curUMask = pFace->uMask;
    rdAFRaster_curVMask = pFace->vMask;
    rdAFRaster_curVShift = pFace->vShift;
    rdAFRaster_curURoundBias = pFace->uRoundBias;
    rdAFRaster_curVRoundBias = pFace->vRoundBias;
    rdAFRaster_curLightTable = pFace->pLightTable;   // ignored by the flat (FAT) sampler

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

void rdAFRaster_DrawNGonFAT(rdActiveFace* pFace) { rdAFRaster_DrawNGonCommon(pFace, rdAFRaster_DrawSpanNGonFAT_8); }
void rdAFRaster_DrawNGonLAT(rdActiveFace* pFace) { rdAFRaster_DrawNGonCommon(pFace, rdAFRaster_DrawSpanNGonLAT_8); }
void rdAFRaster_DrawNGonGAT(rdActiveFace* pFace) { rdAFRaster_DrawNGonCommon(pFace, rdAFRaster_DrawSpanNGonGAT_8); }

// General 8bpp affine texture span sampler (JK.EXE sub_4B5E70, the width-agnostic default).
// Walks the span left-to-right stepping (u,v) linearly in screen space and copying texels.
void rdAFRaster_DrawSpanNGonFAT_8(rdActiveSpan* pSpan)
{
    tVBuffer* pVBuffer = rdCamera_g_pCurCamera->pCanvas->pVBuffer;
    uint32_t stride = pVBuffer->format.rowSize;

    // Clip the span to the framebuffer (geometry clipped to the canvas can still land a pixel
    // or two outside); advance the texture coords across any left-clipped pixels.
    int fbW = pVBuffer->format.width;
    int fbH = pVBuffer->format.height;
    int y = pSpan->y;
    if (y < 0 || y >= fbH)
        return;

    int xStart = pSpan->xStart;
    int count = pSpan->width;
    int32_t du = pSpan->du;
    int32_t dv = pSpan->dv;
    uint32_t uAcc = (uint32_t)pSpan->u + (uint32_t)rdAFRaster_curURoundBias;
    uint32_t vAcc = (uint32_t)pSpan->v + (uint32_t)rdAFRaster_curVRoundBias;

    if (xStart < 0)
    {
        int skip = -xStart;
        if (skip >= count)
            return;
        uAcc += (uint32_t)du * (uint32_t)skip;
        vAcc += (uint32_t)dv * (uint32_t)skip;
        xStart = 0;
        count -= skip;
    }
    if (xStart + count > fbW)
        count = fbW - xStart;
    if (count <= 0)
        return;

    const uint8_t* pTexels = rdAFRaster_curTexels;
    uint32_t uMask = rdAFRaster_curUMask;
    uint32_t vMask = rdAFRaster_curVMask;
    int vshiftAmt = 0x10 - rdAFRaster_curVShift;
    uint8_t* pDst = (uint8_t*)pVBuffer->surface_lock_alloc + xStart + y * stride;

    for (int i = 0; i < count; i++)
    {
        uint32_t col = (uAcc & uMask) >> 16;
        uint32_t row = (vAcc >> vshiftAmt) & vMask;
        // Word-safe byte write (the vbuffer can live in word-addressable VRAM/extram).
        stdPlatform_WriteByte16(pDst + i, pTexels[row + col]);
        uAcc += (uint32_t)du;
        vAcc += (uint32_t)dv;
    }
}

// Lit (LAT) span sampler (JK.EXE sub_4B6500): like FAT, but each texel is remapped through the
// per-face light row (colormap->lightlevel + lightLevel*256) latched by the flush.
void rdAFRaster_DrawSpanNGonLAT_8(rdActiveSpan* pSpan)
{
    tVBuffer* pVBuffer = rdCamera_g_pCurCamera->pCanvas->pVBuffer;
    uint32_t stride = pVBuffer->format.rowSize;
    int fbW = pVBuffer->format.width;
    int fbH = pVBuffer->format.height;
    int y = pSpan->y;
    if (y < 0 || y >= fbH)
        return;

    int xStart = pSpan->xStart;
    int count = pSpan->width;
    int32_t du = pSpan->du;
    int32_t dv = pSpan->dv;
    uint32_t uAcc = (uint32_t)pSpan->u + (uint32_t)rdAFRaster_curURoundBias;
    uint32_t vAcc = (uint32_t)pSpan->v + (uint32_t)rdAFRaster_curVRoundBias;

    if (xStart < 0)
    {
        int skip = -xStart;
        if (skip >= count)
            return;
        uAcc += (uint32_t)du * (uint32_t)skip;
        vAcc += (uint32_t)dv * (uint32_t)skip;
        xStart = 0;
        count -= skip;
    }
    if (xStart + count > fbW)
        count = fbW - xStart;
    if (count <= 0)
        return;

    const uint8_t* pTexels = rdAFRaster_curTexels;
    const uint8_t* pLight = rdAFRaster_curLightTable;
    uint32_t uMask = rdAFRaster_curUMask;
    uint32_t vMask = rdAFRaster_curVMask;
    int vshiftAmt = 0x10 - rdAFRaster_curVShift;
    uint8_t* pDst = (uint8_t*)pVBuffer->surface_lock_alloc + xStart + y * stride;

    for (int i = 0; i < count; i++)
    {
        uint32_t col = (uAcc & uMask) >> 16;
        uint32_t row = (vAcc >> vshiftAmt) & vMask;
        stdPlatform_WriteByte16(pDst + i, pLight[pTexels[row + col]]);
        uAcc += (uint32_t)du;
        vAcc += (uint32_t)dv;
    }
}

// Gouraud (GAT) span sampler (JK.EXE sub_4B6BA0): like LAT, but the light-table row is chosen
// per-pixel from the interpolated intensity (span.z, stepped by span.dz), so each texel maps
// through lightTable[((z>>16)&0x3f)*256 + texel].
void rdAFRaster_DrawSpanNGonGAT_8(rdActiveSpan* pSpan)
{
    tVBuffer* pVBuffer = rdCamera_g_pCurCamera->pCanvas->pVBuffer;
    uint32_t stride = pVBuffer->format.rowSize;
    int fbW = pVBuffer->format.width;
    int fbH = pVBuffer->format.height;
    int y = pSpan->y;
    if (y < 0 || y >= fbH)
        return;

    int xStart = pSpan->xStart;
    int count = pSpan->width;
    int32_t du = pSpan->du;
    int32_t dv = pSpan->dv;
    int32_t dz = pSpan->dz;
    uint32_t uAcc = (uint32_t)pSpan->u + (uint32_t)rdAFRaster_curURoundBias;
    uint32_t vAcc = (uint32_t)pSpan->v + (uint32_t)rdAFRaster_curVRoundBias;
    uint32_t zAcc = (uint32_t)pSpan->z;

    if (xStart < 0)
    {
        int skip = -xStart;
        if (skip >= count)
            return;
        uAcc += (uint32_t)du * (uint32_t)skip;
        vAcc += (uint32_t)dv * (uint32_t)skip;
        zAcc += (uint32_t)dz * (uint32_t)skip;
        xStart = 0;
        count -= skip;
    }
    if (xStart + count > fbW)
        count = fbW - xStart;
    if (count <= 0)
        return;

    const uint8_t* pTexels = rdAFRaster_curTexels;
    const uint8_t* pLight = rdAFRaster_curLightTable;
    uint32_t uMask = rdAFRaster_curUMask;
    uint32_t vMask = rdAFRaster_curVMask;
    int vshiftAmt = 0x10 - rdAFRaster_curVShift;
    uint8_t* pDst = (uint8_t*)pVBuffer->surface_lock_alloc + xStart + y * stride;

    for (int i = 0; i < count; i++)
    {
        uint32_t col = (uAcc & uMask) >> 16;
        uint32_t row = (vAcc >> vshiftAmt) & vMask;
        uint32_t light = (zAcc & 0x3f0000) >> 8;   // ((z >> 16) & 0x3f) * 256
        stdPlatform_WriteByte16(pDst + i, pLight[light + pTexels[row + col]]);
        uAcc += (uint32_t)du;
        vAcc += (uint32_t)dv;
        zAcc += (uint32_t)dz;
    }
}

// Gouraud edge step (JK.EXE sub_479290): the FAT step plus the interpolated intensity (z).
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

// Gouraud edge setup (JK.EXE sub_479310): the FAT edge plus the per-vertex intensity (proc
// vertexIntensities, pre-scaled to 0..63 by AddActiveFace) interpolated into the edge z slot,
// which rdActive_EmitSpan reads for lightingMode 3. Delegates the shared x/u/v/i math to the
// FAT edge setup, then adds z and swaps in the gouraud advance.
int rdAFRaster_SetupEdgeNGonGAT(rdEdge* pEdge, rdActiveFace* pFace, int vA, int vB)
{
    if (!rdAFRaster_SetupEdgeNGonFAT(pEdge, pFace, vA, vB))
        return 0;

    rdProcEntry* pProc = pFace->pProcEntry;
    rdVector3* pVerts = pProc->aVertices;
    const flex_t* pIntensity = pProc->vertexIntensities;

    int yaI = (int)rdAFRaster_Round(pVerts[vA].y);
    int ybI = (int)rdAFRaster_Round(pVerts[vB].y);
    int dy = ybI - yaI;

    int vTop, vBot;
    flex_t yTopRound;
    if (dy > 0)
    {
        vTop = vA; vBot = vB;
        yTopRound = rdAFRaster_Round(pVerts[vA].y);
        pEdge->pfnAdvance = rdAFRaster_AdvanceLeftEdgeNGonGAT;
    }
    else
    {
        vTop = vB; vBot = vA;
        yTopRound = rdAFRaster_Round(pVerts[vB].y);
        pEdge->pfnAdvance = rdAFRaster_AdvanceRightEdgeNGonGAT;
    }

    int numLines = (dy > 0) ? dy : -dy;
    if (numLines < 2)
    {
        pEdge->z = (int)rdAFRaster_Round(pIntensity[vTop] * 65536.0f);
        return 1;
    }

    flex_t yFrac = yTopRound - pVerts[vTop].y;
    flex_t invDy = 1.0f / (pVerts[vBot].y - pVerts[vTop].y);
    flex_t dzdy = (pIntensity[vBot] - pIntensity[vTop]) * invDy;
    pEdge->dz = (int)rdAFRaster_Round(dzdy * 65536.0f);
    pEdge->z  = (int)rdAFRaster_Round((dzdy * yFrac + pIntensity[vTop]) * 65536.0f);
    return 1;
}

#endif // RDRASTER_SOFTWARE_RENDERER
