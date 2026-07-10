#include "rdActive.h"

#include "Engine/rdCanvas.h"
#include "Engine/rdCamera.h"
#include "Raster/rdAFRaster.h"
#include "jk.h"

#ifdef RDRASTER_SOFTWARE_RENDERER
// Software-rasterizer working pools. numActiveFaces caps at 0x3ff and numActiveSpans at
// 0x7ff, so the pools hold 1024 faces (~512 KB) and 2048 spans (~176 KB). These are
// present only when the software path is compiled in.
// TODO(integration): for TARGET_TWL / TARGET_DREAMCAST, gate the caps / place the pools
// in extram to reclaim RAM (see PROGRESS.md).
#define RDACTIVE_MAX_FACES 1024
#define RDACTIVE_MAX_SPANS 2048

static rdActiveFace aActiveFaces[RDACTIVE_MAX_FACES];
static rdActiveSpan aActiveSpans[RDACTIVE_MAX_SPANS];
static int yCurScanLine;   // scanline currently being rasterized by rdActive_DrawScene

// Exposed so the rdAFRaster draw callbacks can validate a span-list link points into the
// pool before following it (defensive against list corruption on complex scenes).
rdActiveSpan* rdActive_pSpanPoolBegin(void) { return aActiveSpans; }
rdActiveSpan* rdActive_pSpanPoolEnd(void)   { return &aActiveSpans[RDACTIVE_MAX_SPANS]; }
#endif

int rdActive_Startup()
{
#ifdef RDRASTER_SOFTWARE_RENDERER
    // Working pools are re-populated from index 0 every frame (counters reset in
    // rdActive_AdvanceFrame), but zero them here so the soft-reset loop in main.c
    // never leaves stale pointers behind when swapping JK.EXE/JKM.EXE functionality.
    _memset(aActiveFaces, 0, sizeof(aActiveFaces));
    _memset(aActiveSpans, 0, sizeof(aActiveSpans));
    yCurScanLine = 0;
#endif
    return 1;
}

void rdActive_AdvanceFrame()
{
    rdCanvas* pCanvas = rdCamera_g_pCurCamera->pCanvas;
    int yStart = pCanvas->yStart;
    int numLines = pCanvas->heightMinusOne - yStart + 1;

    // Reset the active-edge table to just its head/tail sentinels.
    // Added: JK uses -65536 (its geometry is viewport-clipped so edge X >= 0); ours can
    // project to negative X, so the head sentinel must be a true lower bound or the
    // advance-step's left-bubble walks off the front of the list.
    activeEdgeHead.sortX = INT32_MIN;
    activeEdgeHead.next = &activeEdgeTail;
    activeEdgeHead.prev = NULL;
    activeEdgeTail.sortX = 0x7FFFFFFF;
    activeEdgeTail.prev = &activeEdgeHead;
    activeEdgeTail.next = NULL;

    // Clear the per-scanline new/remove edge buckets over the canvas range.
    // These are main-RAM global arrays, so a byte-wise clear is fine here.
    _memset(&apNewActiveEdges[yStart], 0, numLines * sizeof(rdEdge*));
    _memset(&apRemoveActiveEdges[yStart], 0, numLines * sizeof(rdEdge*));

    yMinEdge = 0x7FFFFFFF;
    yMaxEdge = 0;
    numActiveFaces = 0;
    numActiveEdges = 0;
    numActiveSpans = 0;
}

void rdActive_ClearFrameCounters()
{
    rdActive_drawnFaces = 0;
}

#ifdef RDRASTER_SOFTWARE_RENDERER
// Round a 16.16 fixed value up to the next whole pixel (ceil for non-negative X).
static int rdActive_CeilFixed(int x)
{
    if (x & 0xffff)
        x = (x + 0x10000) & 0xffff0000;
    return x;
}

// Store raw float bits into a span interpolant slot without converting. The slots
// carry either 16.16 fixed values or float bits depending on the raster mode.
static int32_t rdActive_FloatToSlot(flex_t f)
{
    union { flex_t f; int32_t i; } u;
    u.f = f;
    return u.i;
}

// Clamp a light intensity to [0, 1] (matches JK's AddActiveFace lighting clamps).
static flex_t rdActive_Clamp01(flex_t f)
{
    if (f < 0.0f) return 0.0f;
    if (f > 1.0f) return 1.0f;
    return f;
}

// Draw and detach every accumulated span (one list per active face). Also invoked
// mid-frame by rdActive_EmitSpan when the span pool fills up.
void rdActive_FlushSpans()
{
    for (int i = 0; i < numActiveFaces; i++)
    {
        rdActiveFace* pFace = &aActiveFaces[i];
        if (pFace->pFirstSpan)
        {
            pFace->pfnDrawSpan(pFace);
            pFace->pFirstSpan = NULL;
            pFace->pLastSpan = NULL;
        }
    }
    numActiveSpans = 0;
}

// Depth test used by BuildSpans: does pNew (whose left edge is pEdge on this scanline)
// sort in front of pOther? Faces carry a packed 16.16 depth key at pProcEntry+0x68
// (named vertexColorMode by the HW path). When the low halves match, the high halves
// order the faces; otherwise the light-intensity interpolated along pOther at pEdge's
// X breaks the tie (higher wins).
static int rdActive_FaceInFront(rdActiveFace* pNew, rdEdge* pEdge, rdActiveFace* pOther)
{
    uint32_t newKey   = pNew->pProcEntry->vertexColorMode;
    uint32_t otherKey = pOther->pProcEntry->vertexColorMode;
    if (((otherKey ^ newKey) & 0xffff) == 0)
    {
        if ((otherKey >> 16) < (newKey >> 16))
            return 1;
        if ((otherKey >> 16) > (newKey >> 16))
            return 0;
        // High halves equal: fall through to the intensity tie-break.
    }

    rdEdge* pOtherLeft = pOther->pLeftEdge;
    if (pOtherLeft == NULL)   // Added: face not yet fully edged this scanline
        return 0;
    flex_t frac = (flex_t)(pEdge->sortX - pOtherLeft->sortX) * (flex_t)(1.0 / 65536.0);
    flex_t otherI = pOther->dIntensity * frac + pOtherLeft->i;
    if (pEdge->i > otherI)
        return 1;
    if (pEdge->i == otherI && pNew->dIntensity > pOther->dIntensity)
        return 1;
    return 0;
}

// Emit one horizontal span for the currently front-most face pFront, spanning from its
// running spanStartX to xEnd (16.16, already rounded up to a whole pixel).
static void rdActive_EmitSpan(rdActiveFace* pFront, int xEnd)
{
    int width = (xEnd - pFront->spanStartX) >> 16;
    if (width <= 0)
        return;

    // Added: real geometry can present a face with only one edge live on a scanline
    // (degenerate/odd-wound faces); skip rather than dereference a missing edge.
    if (pFront->pLeftEdge == NULL || pFront->pRightEdge == NULL)
        return;

    if ((uint32_t)numActiveSpans > RDACTIVE_MAX_SPANS - 1)
        rdActive_FlushSpans();   // pool full -> draw everything accumulated and reset

    rdActiveSpan* pSpan = &aActiveSpans[numActiveSpans];
    numActiveSpans++;

    rdEdge* pLeft = pFront->pLeftEdge;
    rdEdge* pRight = pFront->pRightEdge;
    rdProcEntry* pProc = pFront->pProcEntry;
    int startX = pFront->spanStartX;
    int shift = pFront->shift & 0x1f;

    pSpan->xStart = startX >> 16;
    pSpan->width = width;
    pSpan->y = yCurScanLine;
    pSpan->pNextSpan = NULL;

    // Whole-pixel width across the edge span, used to index the reciprocal LUTs.
    int edgePixels = (rdActive_CeilFixed(pRight->sortX) - rdActive_CeilFixed(pLeft->sortX)) >> 16;
    // Added: real geometry can span partially/fully off-screen; clamp to the LUT range so
    // the reciprocal lookups below never read out of bounds.
    if (edgePixels < 0)
        edgePixels = 0;
    else if (edgePixels > 2047)
        edgePixels = 2047;
    // Sub-pixel distance from the left edge to this span's start.
    int subFixed = startX - pLeft->sortX;
    flex_t subFrac = (flex_t)subFixed * (flex_t)(1.0 / 65536.0);

    pSpan->i = rdActive_FloatToSlot(pFront->dIntensity * subFrac + pLeft->i);

    if (pProc->geometryMode == 4)   // textured
    {
        if (pProc->textureMode == 0)   // affine (AT): linear 16.16 u/v across the span
        {
            int oneOverN = rdRaster_aOneOverNFixed[edgePixels];
            int duPersp = (int)(((int64_t)(pRight->uPersp - pLeft->uPersp) * oneOverN) >> 16);
            pSpan->du = duPersp >> shift;
            pSpan->u = (int)((((int64_t)subFixed * duPersp) >> 16) + pLeft->uPersp) >> shift;
            int dvPersp = (int)(((int64_t)(pRight->vPersp - pLeft->vPersp) * oneOverN) >> 16);
            pSpan->dv = dvPersp >> shift;
            pSpan->v = (int)((((int64_t)subFixed * dvPersp) >> 16) + pLeft->vPersp) >> shift;
        }
        else   // perspective (IT): interpolate u/z, v/z, 1/z (all linear in screen space) from
               // the edge float slots (edge.u=u/z, edge.v=v/z, edge.i=1/z); the IT sampler
               // divides u/z by 1/z per pixel. Slots hold float bits (oneOverZ/dOneOverZ direct).
        {
            flex_t invN = rdRaster_aOneOverNFlex[edgePixels];   // 1 / edgePixels
            flex_t duoz = (pRight->u - pLeft->u) * invN;
            flex_t dvoz = (pRight->v - pLeft->v) * invN;
            flex_t dooz = (pRight->i - pLeft->i) * invN;
            pSpan->u  = rdActive_FloatToSlot(pLeft->u + duoz * subFrac);
            pSpan->du = rdActive_FloatToSlot(duoz);
            pSpan->v  = rdActive_FloatToSlot(pLeft->v + dvoz * subFrac);
            pSpan->dv = rdActive_FloatToSlot(dvoz);
            pSpan->oneOverZ  = pLeft->i + dooz * subFrac;
            pSpan->dOneOverZ = dooz;
        }
    }
    else
    {
        pSpan->u = pFront->color;   // flat shading stashes the packed color here
    }

    if (pProc->lightingMode == 3)   // gouraud -> per-pixel depth/fog gradient
    {
        int dz = (int)(((int64_t)(pRight->z - pLeft->z) * rdRaster_aOneOverNFixed[edgePixels]) >> 16);
        if (dz < 0 && dz > -0x51e)   // clamp small negative slopes to flat
            dz = 0;
        pSpan->dz = dz;
        pSpan->z = (int)(((int64_t)subFixed * dz) >> 16) + pLeft->z;
    }

    // Append to this face's per-frame span list.
    if (pFront->pFirstSpan == NULL)
        pFront->pFirstSpan = pSpan;
    else
        pFront->pLastSpan->pNextSpan = pSpan;
    pFront->pLastSpan = pSpan;
}

// Walk the sorted active-edge table for the current scanline, tracking which face is
// front-most as edges open and close, and emit a span for the visible face across each
// stretch of X where the front-most face stays the same.
void rdActive_BuildSpans()
{
    if (numActiveEdges == 0)
        return;

    rdActiveFace* pFront = NULL;   // current front-most (visible) face

    for (rdEdge* pEdge = activeEdgeHead.next; pEdge != &activeEdgeTail; pEdge = pEdge->next)
    {
        rdActiveFace* pFace = (rdActiveFace*)pEdge->pFace;

        if (pEdge->leftOrRightFlag == 0)   // right edge -> a face is closing
        {
            if (--pFace->numEdgesActive != 0)
                continue;

            if (pFace == pFront)
            {
                // The visible face just ended: flush its span up to here and fall back
                // to the next face behind it.
                int xEnd = rdActive_CeilFixed(pEdge->sortX);
                rdActive_EmitSpan(pFront, xEnd);
                pFront = pFront->prevFace;
                if (pFront != NULL)
                {
                    pFront->spanStartX = xEnd;
                    pFront->nextFace = NULL;
                }
            }
            else
            {
                // A hidden face ended: just unlink it from the active-face list.
                if (pFace->prevFace != NULL)
                    pFace->prevFace->nextFace = pFace->nextFace;
                if (pFace->nextFace != NULL)
                    pFace->nextFace->prevFace = pFace->prevFace;
            }
        }
        else   // left edge -> a face is opening
        {
            if (++pFace->numEdgesActive != 1)
                continue;

            rdProcEntry* pProc = pFace->pProcEntry;
            if (pProc->geometryMode != 4 || pProc->textureMode != 1)
            {
                // Seed the face's per-pixel intensity gradient from its two edges.
                int edgePixels = rdActive_CeilFixed(pFace->pRightEdge->sortX)
                               - rdActive_CeilFixed(pFace->pLeftEdge->sortX);
                flex_t grad = (pFace->pRightEdge->i - pFace->pLeftEdge->i)
                            * rdRaster_aOneOverNFlex[edgePixels >> 16];
                pFace->dIntensity = grad;
                pFace->dIntensityFixed = (int32_t)(grad * 65536.0f + (grad < 0.0f ? -0.5f : 0.5f));
            }

            int xHere = rdActive_CeilFixed(pEdge->sortX);
            if (pFront == NULL)
            {
                pFace->nextFace = NULL;
                pFace->prevFace = NULL;
                pFace->spanStartX = xHere;
                pFront = pFace;
            }
            else if (rdActive_FaceInFront(pFace, pEdge, pFront))
            {
                // New face is in front: flush the old front's span, then take over.
                rdActive_EmitSpan(pFront, xHere);
                pFace->prevFace = pFront;
                pFront->nextFace = pFace;
                pFace->nextFace = NULL;
                pFace->spanStartX = xHere;
                pFront = pFace;
            }
            else
            {
                // Hidden: insert into the depth-sorted list behind pFront (no span).
                rdActiveFace* pAfter = pFront;
                rdActiveFace* pCand = pFront->prevFace;
                while (pCand != NULL && !rdActive_FaceInFront(pFace, pEdge, pCand))
                {
                    pAfter = pCand;
                    pCand = pCand->prevFace;
                }
                if (pCand != NULL)
                {
                    pAfter->prevFace = pFace;
                    pCand->nextFace = pFace;
                    pFace->prevFace = pCand;
                    pFace->nextFace = pAfter;
                }
                else
                {
                    pAfter->prevFace = pFace;
                    pFace->nextFace = pAfter;
                    pFace->prevFace = NULL;
                }
            }
        }
    }
}

// Admit one cached proc face into the active-face pool: clamp its modes against the
// renderer's current caps, pick the material cel/mip, initialize the pool entry, and hand
// off to the rdAFRaster family setup routine that matches its geometry/shading mode.
//
// P3 status: only RD_GEOMETRY_WIREFRAME is ported so far. Solid/textured faces
// (RD_GEOMETRY_SOLID / RD_GEOMETRY_FULL) are dropped for now rather than admitted with
// uninitialized callbacks — see the rdAFRaster Setup*NGon families still to be ported.
int rdActive_AddActiveFace(rdProcEntry* pProcEntry)
{
    if ((uint32_t)numActiveFaces > 0x3ff)
        return 0;

    int geometryMode = pProcEntry->geometryMode;
    if (geometryMode > rdroid_g_curGeometryMode)
        geometryMode = rdroid_g_curGeometryMode;
    int lightingMode = pProcEntry->lightingMode;
    if (lightingMode > rdroid_g_curLightingMode)
        lightingMode = rdroid_g_curLightingMode;
    int textureMode = pProcEntry->textureMode;
    if (textureMode > rdroid_curTextureMode)
        textureMode = rdroid_curTextureMode;
    if (geometryMode == RD_GEOMETRY_NONE)
        return 0;

    rdActiveFace* pFace = &aActiveFaces[numActiveFaces];
    pFace->pProcEntry = pProcEntry;
    pFace->pFirstSpan = NULL;
    pFace->pLastSpan = NULL;
    pFace->pLeftEdge = NULL;
    pFace->pRightEdge = NULL;
    pFace->numEdgesActive = 0;

    // Resolve the material cel/mip to a texinfo (NULL for untextured/no material).
    rdMaterial* pMaterial = pProcEntry->material;
    rdTexinfo* pTexinfo = NULL;
    if (pMaterial != NULL)
    {
        int cel = pProcEntry->wallCel;
        if (cel == -1)
            cel = pMaterial->curCelNum;
        if (cel < 0)
        {
            cel = 0;
        }
        else
        {
            int maxCel = pMaterial->num_texinfo - 1;
            if (cel > maxCel)
                cel = maxCel;
        }
        pTexinfo = pMaterial->texinfos[cel];
        // A textured face whose texture lacks the "full" flag falls back to solid.
        if (geometryMode == RD_GEOMETRY_FULL && (pTexinfo->header.texture_type & 8) == 0)
            geometryMode = RD_GEOMETRY_SOLID;
    }

    // Ported families (the full rdAFRaster affine active-edge matrix): wireframe (LW), solid
    // (FS/LS/GS), affine textured (FAT/LAT/GAT + masked), perspective textured (FIT/LIT/GIT +
    // masked). Drop the Z-buffered path, the custom per-face hook, or a material-less face so
    // BuildEdges/BuildSpans never touch an uninitialized callback.
    if (lightingMode < 0 || lightingMode >= 5
        || (pProcEntry->extraData & 1) != 0
        || rdroid_curZBufferMethod != 1
        || pTexinfo == NULL)
    {
        return 0;
    }

    // Shading class shared by every textured/solid family (mirrors JK's AddActiveFace 0..63 light
    // math and rdZRaster_DrawFace): flat = no darkening; lit = one constant level; gouraud =
    // per-vertex. Lit/gouraud need a colormap light table (else fall back to flat).
    const uint8_t* pLightBase = (pProcEntry->colormap != NULL && pProcEntry->colormap->lightlevel != NULL)
                              ? pProcEntry->colormap->lightlevel : NULL;
    flex_t ambient = (rdroid_g_curRenderOptions & 2) ? pProcEntry->ambientLight : 0.0f;
    int shade = 0;         // 0 = flat (F), 1 = lit (L), 2 = gouraud (G)
    int lightLevel = 63;
    if (lightingMode == RD_LIGHTMODE_FULLYLIT || pLightBase == NULL)
    {
        shade = 0;
    }
    else if (lightingMode == RD_LIGHTMODE_GOURAUD)
    {
        shade = 2;
        for (int vi = 0; vi < (int)pProcEntry->numVertices; vi++)
        {
            flex_t vl = rdActive_Clamp01(pProcEntry->vertexIntensities[vi] + pProcEntry->extralight);
            if (vl < ambient)
                vl = ambient;
            pProcEntry->vertexIntensities[vi] = vl * 63.0f;
        }
    }
    else   // NOTLIT / DIFFUSE
    {
        shade = 1;
        flex_t level = (lightingMode == RD_LIGHTMODE_NOTLIT)
                     ? rdActive_Clamp01(pProcEntry->extralight)
                     : rdActive_Clamp01(pProcEntry->extralight + pProcEntry->light_level_static);
        if (level < ambient)
            level = ambient;
        lightLevel = (int)(level * 63.0f + 0.5f);
        if (lightLevel < 0) lightLevel = 0;
        else if (lightLevel > 63) lightLevel = 63;
    }

    if (geometryMode == RD_GEOMETRY_WIREFRAME)
    {
        rdAFRaster_SetupNGonLW_0(pFace, pTexinfo);
    }
    else if (geometryMode == RD_GEOMETRY_SOLID)
    {
        if (shade == 0)      rdAFRaster_SetupNGonFS(pFace, pTexinfo);
        else if (shade == 1) rdAFRaster_SetupNGonLS(pFace, pTexinfo, lightLevel);
        else                 rdAFRaster_SetupNGonGS(pFace, pTexinfo);
    }
    else if (geometryMode == RD_GEOMETRY_FULL && pTexinfo->texture_ptr != NULL)
    {
        int masked = (pTexinfo->texture_ptr->alpha_en & 1) != 0;   // transparent texel-0 texture
        int persp = (textureMode == 1);                            // 0 = affine (AT); 1 = perspective (IT)
        if (!persp)
        {
            if (!masked)
            {
                if (shade == 0)      rdAFRaster_SetupNGonFAT(pFace, pTexinfo);
                else if (shade == 1) rdAFRaster_SetupNGonLAT(pFace, pTexinfo, lightLevel);
                else                 rdAFRaster_SetupNGonGAT(pFace, pTexinfo);
            }
            else
            {
                if (shade == 0)      rdAFRaster_SetupNGonMFAT(pFace, pTexinfo);
                else if (shade == 1) rdAFRaster_SetupNGonMLAT(pFace, pTexinfo, lightLevel);
                else                 rdAFRaster_SetupNGonMGAT(pFace, pTexinfo);
            }
        }
        else
        {
            if (!masked)
            {
                if (shade == 0)      rdAFRaster_SetupNGonFIT(pFace, pTexinfo);
                else if (shade == 1) rdAFRaster_SetupNGonLIT(pFace, pTexinfo, lightLevel);
                else                 rdAFRaster_SetupNGonGIT(pFace, pTexinfo);
            }
            else
            {
                if (shade == 0)      rdAFRaster_SetupNGonMFIT(pFace, pTexinfo);
                else if (shade == 1) rdAFRaster_SetupNGonMLIT(pFace, pTexinfo, lightLevel);
                else                 rdAFRaster_SetupNGonMGIT(pFace, pTexinfo);
            }
        }
    }
    else
    {
        return 0;
    }

    rdActive_drawnFaces++;
    numActiveFaces++;
    return 1;
}

// Admit every cached proc face into the active-face pool, then build each face's edges
// and drop them into the per-scanline new/remove buckets used by rdActive_DrawScene.
void rdActive_BuildEdges()
{
    for (int i = 0; i < rdCache_numProcFaces; i++)
        rdActive_AddActiveFace(&rdCache_aProcFaces[i]);

    // Added: clamp edge scanlines to the canvas. The per-scanline buckets only cover
    // [yStart, heightMinusOne], and geometry can project a few pixels outside the viewport
    // (or to a negative Y), which would index the buckets out of bounds / into uncleared
    // (stale) slots and corrupt the active-edge table.
    rdCanvas* pCanvas = rdCamera_g_pCurCamera->pCanvas;
    int yTop = pCanvas->yStart;
    int yBot = pCanvas->heightMinusOne;

    rdEdge* pEdge = aActiveEdges;
    for (int faceIdx = 0; faceIdx < numActiveFaces; faceIdx++)
    {
        rdActiveFace* pFace = &aActiveFaces[faceIdx];
        int numVertices = pFace->pProcEntry->numVertices;

        int vA = 0;
        while (vA < numVertices)
        {
            int vNext = vA + 1;
            int vWrapped = (vNext >= numVertices) ? 0 : vNext;   // last -> first

            int vStart, vEnd;
            if (pFace->pProcEntry->light_flags == 0)
            {
                vStart = vA;        vEnd = vWrapped;
            }
            else
            {
                vStart = vWrapped;  vEnd = vA;
            }

            if (pFace->pfnSetupEdge(pEdge, pFace, vStart, vEnd))
            {
                pEdge->pFace = pFace;

                // Added: clip the edge's scanline span into the canvas. Advancing the
                // interpolants (via pfnAdvance) keeps sortX / intensity correct for the
                // new top; then trim the bottom. A fully off-canvas edge is dropped.
                while (pEdge->yStart < yTop && pEdge->numLines > 0)
                {
                    pEdge->pfnAdvance(pEdge);
                    pEdge->yStart++;
                    pEdge->numLines--;
                }
                if (pEdge->yStart + pEdge->numLines - 1 > yBot)
                    pEdge->numLines = yBot - pEdge->yStart + 1;
                if (pEdge->numLines <= 0)
                {
                    vA = vNext;
                    continue;
                }

                // Insert into apNewActiveEdges[yStart], sorted ascending by sortX.
                rdEdge* pBucket = apNewActiveEdges[pEdge->yStart];
                if (pBucket == NULL || pEdge->sortX <= pBucket->sortX)
                {
                    apNewActiveEdges[pEdge->yStart] = pEdge;
                    pEdge->next = pBucket;
                }
                else
                {
                    rdEdge* pIns = pBucket;
                    for (rdEdge* pNext = pBucket->next;
                         pNext != NULL && pNext->sortX < pEdge->sortX;
                         pNext = pNext->next)
                        pIns = pNext;
                    pEdge->next = pIns->next;
                    pIns->next = pEdge;
                }

                // Register the edge for removal once the scan passes its last line.
                int yEnd = pEdge->yStart + pEdge->numLines - 1;
                pEdge->nextRemove = apRemoveActiveEdges[yEnd];
                apRemoveActiveEdges[yEnd] = pEdge;

                if (pEdge->yStart < yMinEdge)
                    yMinEdge = pEdge->yStart;
                if (yEnd > yMaxEdge)
                    yMaxEdge = yEnd;

                pEdge++;
                numActiveEdges++;
            }
            vA = vNext;
        }
    }
}

// Scan the whole frame top to bottom: fold new edges into the AET, emit spans, retire
// finished edges, and step the surviving edges one scanline (re-sorting any that cross).
void rdActive_DrawScene()
{
    rdActive_BuildEdges();

    for (yCurScanLine = yMinEdge; (uint32_t)yCurScanLine <= (uint32_t)yMaxEdge; yCurScanLine++)
    {
        // (1) Merge this scanline's new edges into the sorted AET; hook each into its
        //     owning face's left/right slot. Both lists are sorted ascending by sortX,
        //     so pScan only ever advances (JK unrolls this walk x4).
        rdEdge* pScan = activeEdgeHead.next;
        for (rdEdge* pNew = apNewActiveEdges[yCurScanLine]; pNew != NULL; )
        {
            rdEdge* pNextNew = pNew->next;
            while (pScan->sortX < pNew->sortX)
                pScan = pScan->next;

            rdEdge* pPrev = pScan->prev;
            pNew->next = pScan;
            pNew->prev = pPrev;
            pPrev->next = pNew;
            pScan->prev = pNew;

            rdActiveFace* pFace = (rdActiveFace*)pNew->pFace;
            if (pNew->leftOrRightFlag == 0)
                pFace->pRightEdge = pNew;
            else
                pFace->pLeftEdge = pNew;

            pNew = pNextNew;
        }

        // (2) Emit spans for the faces visible on this scanline.
        rdActive_BuildSpans();

        // (3) Retire edges whose final scanline was this one.
        for (rdEdge* pRem = apRemoveActiveEdges[yCurScanLine]; pRem != NULL; )
        {
            rdEdge* pNextRem = pRem->nextRemove;
            pRem->next->prev = pRem->prev;
            pRem->prev->next = pRem->next;
            pRem = pNextRem;
        }

        // (4) Advance every surviving edge one scanline; bubble any that moved left back
        //     into sorted position.
        for (rdEdge* pEdge = activeEdgeHead.next; pEdge != &activeEdgeTail; )
        {
            pEdge->pfnAdvance(pEdge);
            if (pEdge->sortX < pEdge->prev->sortX)
            {
                rdEdge* pNext = pEdge->next;
                pNext->prev = pEdge->prev;
                pEdge->prev->next = pNext;

                rdEdge* pWalk = pEdge->prev->prev;
                while (pEdge->sortX < pWalk->sortX)
                    pWalk = pWalk->prev;

                rdEdge* pAfter = pWalk->next;
                pEdge->prev = pWalk;
                pEdge->next = pAfter;
                pAfter->prev = pEdge;
                pWalk->next = pEdge;
                pEdge = pNext;
            }
            else
            {
                pEdge = pEdge->next;
            }
        }
    }

    // Flush any spans still buffered after the last scanline.
    rdActive_FlushSpans();
}
#endif // RDRASTER_SOFTWARE_RENDERER
