// dwImageDraw — DroidWorks 2D drawing primitives (Ghidra 0x446480-0x4477bx).
//
// Draws into a locked surface described by dwImageBits {pDesc, pPixels,
// stride} / dwImageDesc {format, width, height, bpp}. All primitives are
// 8bpp; the binary routes every 16bpp fill/run through a shared CRT no-op
// (RLE_decompress_type2), reproduced here as empty stubs.
//
// Blend/shade tables come from the engine's CURRENT colormap
// (rdColormap_pCurMap, binary DAT_005542b8):
//   ->transparency (+0x338): 256x256 mix table, dest' = tbl[dest*256 + color]
//   ->lightlevel   (+0x330): 64x256 brightness ramp, dest' = ramp[level*256 + dest]
//
// Genuinely-C unit: no vtables/ctors/EH frames in any function; translated as
// pure C per the DW language policy (DW/DECOMP_PROGRESS.md).

#include "Dw/dwImageDraw.h"

#include "Dw/dwImage.h"
#include "Dw/dwRect.h"
#include "Engine/rdColormap.h"
#include "globals.h" // rdColormap_pCurMap

// ------------------------------------------------------------------
// Per-bpp solid-fill run helpers + function tables

// @446480 — fill `count` bytes at pDest with color (dword-at-a-time).
static void dwImageDraw_FillRunH8(void* pDest, int color, unsigned int count)
{
    uint8_t c = (uint8_t)color;
    uint32_t fill = (uint32_t)c | ((uint32_t)c << 8) | ((uint32_t)c << 16) | ((uint32_t)c << 24);
    uint32_t* p32 = (uint32_t*)pDest;
    for (unsigned int n = count >> 2; n != 0; n--)
    {
        *p32++ = fill;
    }
    uint8_t* p8 = (uint8_t*)p32;
    for (count &= 3; count != 0; count--)
    {
        *p8++ = c;
    }
}

// @4464b0 — fill `count` bytes spaced `stride` apart with color.
static void dwImageDraw_FillRunV8(void* pDest, int stride, int color, int count)
{
    uint8_t* p = (uint8_t*)pDest;
    for (; count != 0; count--)
    {
        *p = (uint8_t)color;
        p += stride;
    }
}

// 16bpp entries: the binary points both tables' [2] slots at a shared CRT
// no-op (RLE_decompress_type2@0x449180) — 16bpp fills draw nothing.
static void dwImageDraw_FillRunH16(void* pDest, int color, unsigned int count)
{
    (void)pDest; (void)color; (void)count;
}

static void dwImageDraw_FillRunV16(void* pDest, int stride, int color, int count)
{
    (void)pDest; (void)stride; (void)color; (void)count;
}

typedef void (*dwImageDraw_fillRunHFunc_t)(void* pDest, int color, unsigned int count);
typedef void (*dwImageDraw_fillRunVFunc_t)(void* pDest, int stride, int color, int count);

// @52a210 / @52a218 — indexed by pDesc->bpp (1 = 8bpp, 2 = 16bpp stub).
// [0] is never referenced (the binary's tables start at index 1).
static const dwImageDraw_fillRunHFunc_t dwImageDraw_aFillRunH[3] = { NULL, dwImageDraw_FillRunH8, dwImageDraw_FillRunH16 };
static const dwImageDraw_fillRunVFunc_t dwImageDraw_aFillRunV[3] = { NULL, dwImageDraw_FillRunV8, dwImageDraw_FillRunV16 };

// ------------------------------------------------------------------
// Circle

// Plot one pixel clipped to pBounds (left/top inclusive, right/bottom
// exclusive) — the per-pixel check the binary inlines 4x per step.
static void dwImageDraw_CirclePlot(uint8_t* pPixels, int stride, dwRect* pBounds, int x, int y, uint8_t color)
{
    if (x >= pBounds->left && x < pBounds->right && y >= pBounds->top && y < pBounds->bottom)
    {
        pPixels[y * stride + x] = color;
    }
}

// The 4-way symmetric plot: (cx±x, cy±r). The binary emits this block before
// the loop with x==0 too (plotting the top/bottom points twice).
static void dwImageDraw_CirclePlot4(uint8_t* pPixels, int stride, dwRect* pBounds, int cx, int cy, int x, int r, uint8_t color)
{
    dwImageDraw_CirclePlot(pPixels, stride, pBounds, cx + x, cy + r, color);
    dwImageDraw_CirclePlot(pPixels, stride, pBounds, cx + x, cy - r, color);
    dwImageDraw_CirclePlot(pPixels, stride, pBounds, cx - x, cy + r, color);
    dwImageDraw_CirclePlot(pPixels, stride, pBounds, cx - x, cy - r, color);
}

// @4464e0 — Bresenham (second-order midpoint) circle outline, 8bpp only.
void dwImageDraw_Circle(dwImageBits* pBits, dwPoint* pCenter, int16_t radius, int color, dwRect* pClip)
{
    dwImageDesc* pDesc = pBits->pDesc;
    if ((uint8_t)(pDesc->bpp << 3) != 8) // low 5 bits == 1 (8bpp)
        return;

    int stride = pBits->stride;
    uint8_t* pPixels = (uint8_t*)pBits->pPixels;
    int16_t cx = pCenter->x;
    int16_t cy = pCenter->y;

    if (radius < 0)
        return;

    dwRect bounds;
    bounds.left = 0;
    bounds.top = 0;
    bounds.right = (int16_t)pDesc->width;
    bounds.bottom = (int16_t)pDesc->height;
    if (pClip)
        dwRect_Clip(&bounds, pClip);

    // All state is int16 in the binary; keep the exact wraparound semantics.
    int16_t r = radius;      // shrinks to -1
    int16_t x = 0;
    int16_t twoX = 0;        // 2*x
    int16_t twoR = (int16_t)(radius * 2);
    int16_t d = (int16_t)(-2 * radius + 2);

    dwImageDraw_CirclePlot4(pPixels, stride, &bounds, cx, cy, 0, r, (uint8_t)color);
    do
    {
        if (d < 0)
        {
            if ((int16_t)((d + r) * 2 - 1) < 1)
            {
                x++;
                twoX += 2;
                d = (int16_t)(d + 1 + twoX);
            }
            else
            {
                twoX += 2;
                x++;
                r--;
                twoR -= 2;
                d = (int16_t)(d + 2 + (x - r) * 2);
            }
        }
        else if (d < 1) // d == 0
        {
            twoX += 2;
            x++;
            twoR -= 2;
            r--;
            d = (int16_t)(d + 2 + (x - r) * 2);
        }
        else if ((int16_t)((d - x) * 2 - 1) < 1)
        {
            twoX += 2;
            x++;
            twoR -= 2;
            r--;
            d = (int16_t)(d + 2 + (x - r) * 2);
        }
        else
        {
            twoR -= 2;
            r--;
            d = (int16_t)(d + (1 - twoR));
        }
        dwImageDraw_CirclePlot4(pPixels, stride, &bounds, cx, cy, x, r, (uint8_t)color);
    } while (r >= 0);
}

// ------------------------------------------------------------------
// Rect fills

// @4468c0
void dwImageDraw_FillRect(dwImageBits* pBits, dwRect* pRect, int color, dwRect* pClip)
{
    dwRect rect = *pRect; // stack copy; the clip modifies it
    if (pClip)
        dwRect_Clip(&rect, pClip);

    uint16_t width = (uint16_t)(rect.right - rect.left);
    unsigned int bpp = pBits->pDesc->bpp;
    dwImageDraw_fillRunHFunc_t pFillH = dwImageDraw_aFillRunH[bpp];
    if (width != 0 && pBits->pPixels)
    {
        uint8_t* pRow = (uint8_t*)pBits->pPixels + rect.left * (int)bpp + rect.top * pBits->stride;
        for (int16_t y = rect.top; y < rect.bottom; y++)
        {
            pFillH(pRow, color, width);
            pRow += pBits->stride;
        }
    }
}

// @446970 — translucent overlay, 8bpp only.
void dwImageDraw_BlendRect(dwImageBits* pBits, dwRect* pRect, int color, dwRect* pClip)
{
    if ((uint8_t)(pBits->pDesc->bpp << 3) != 8)
        return;

    dwRect rect = *pRect;
    if (pClip)
        dwRect_Clip(&rect, pClip);

    int16_t width = (int16_t)(rect.right - rect.left);
    if (width == 0)
        return;

    uint8_t* pRow = (uint8_t*)pBits->pPixels + rect.top * pBits->stride + rect.left;
    for (int16_t y = rect.top; y < rect.bottom; y++)
    {
        uint8_t* pTbl = (uint8_t*)rdColormap_pCurMap->transparency;
        uint8_t* p = pRow;
        for (uint16_t n = (uint16_t)width; n != 0; n--)
        {
            *p = pTbl[(unsigned int)*p * 0x100 + (color & 0xff)];
            p++;
        }
        pRow += pBits->stride;
    }
}

// @446a40 — rect outline with per-edge clip visibility.
void dwImageDraw_FrameRect(dwImageBits* pBits, dwRect* pRect, int color, dwRect* pClip)
{
    dwImageDesc* pDesc = pBits->pDesc;
    int16_t x0 = pRect->left;
    int16_t y0 = pRect->top;
    int16_t x1 = pRect->right;
    int16_t y1 = pRect->bottom;
    int16_t clipL = 0;
    int16_t clipT = 0;
    int16_t clipR = (int16_t)pDesc->width;
    int16_t clipB = (int16_t)pDesc->height;

    if (pClip)
    {
        if (pClip->left > 0)
            clipL = pClip->left;
        if (pClip->top > 0)
            clipT = pClip->top;
        if (pClip->right < clipR)
            clipR = pClip->right;
        if (pClip->bottom < clipB)
            clipB = pClip->bottom;
    }

    // Clamp; each edge is drawn only when it wasn't clipped away.
    int16_t cx0 = (x0 < clipL) ? clipL : x0;
    int bDrawLeft = (x0 >= clipL);
    int16_t cy0 = (y0 < clipT) ? clipT : y0;
    int bDrawTop = (y0 >= clipT);
    int16_t cx1 = (clipR < x1) ? clipR : x1;
    int bDrawRight = (clipR >= x1);
    int16_t cy1 = (clipB < y1) ? clipB : y1;
    int bDrawBottom = (clipB >= y1);

    if (cx0 < clipR && cy0 < clipB && clipL <= cx1 && clipT <= cy1 && cx0 < cx1 && cy0 < cy1)
    {
        unsigned int bpp = pDesc->bpp;
        dwImageDraw_fillRunHFunc_t pFillH = dwImageDraw_aFillRunH[bpp];
        dwImageDraw_fillRunVFunc_t pFillV = dwImageDraw_aFillRunV[bpp];
        uint8_t* pPixels = (uint8_t*)pBits->pPixels;
        int stride = pBits->stride;

        if (bDrawTop)
            pFillH(pPixels + stride * cy0 + bpp * cx0, color, (unsigned int)(cx1 - cx0));
        if (bDrawLeft)
            pFillV(pPixels + bpp * cx0 + cy0 * stride, stride, color, cy1 - cy0);
        if (bDrawBottom)
            pFillH(pPixels + stride * (cy1 - 1) + bpp * cx0, color, (unsigned int)(cx1 - cx0));
        if (bDrawRight)
            pFillV(pPixels + bpp * (cx1 - 1) + cy0 * stride, stride, color, cy1 - cy0);
    }
}

// @446c80 — darken by pct (0..100 -> ramp level 0..63), 8bpp only. The caller
// pre-clips (no clip parameter in the binary either).
void dwImageDraw_ShadeRect(dwImageBits* pBits, dwRect* pRect, int pct)
{
    if ((uint8_t)(pBits->pDesc->bpp << 3) != 8)
        return;

    unsigned int level = ((unsigned int)(pct & 0xff) * 0x40) / 100;
    if (level > 0x3f)
        level = 0x3f;

    uint16_t width = (uint16_t)(pRect->right - pRect->left);
    if (width == 0)
        return;

    int stride = pBits->stride;
    uint8_t* pRow = (uint8_t*)pBits->pPixels + pRect->top * stride + pRect->left;
    for (int16_t y = pRect->top; y < pRect->bottom; y++)
    {
        uint8_t* pRamp = (uint8_t*)rdColormap_pCurMap->lightlevel;
        uint8_t* p = pRow;
        for (unsigned int n = width; n != 0; n--)
        {
            *p = pRamp[level * 0x100 + (unsigned int)*p];
            p++;
        }
        pRow += stride;
    }
}

// ------------------------------------------------------------------
// Lines

// @447080 — vertical run for the y-major octants: `count` pixels stepping by
// the surface stride, then advance the cursor by xStep (the cross step).
static void dwImageDraw_LineRunVert(dwImageBits* pBits, uint8_t** ppCursor, int16_t xStep, int16_t count, int color)
{
    if (count != 0)
    {
        for (int n = count; n != 0; n--)
        {
            **ppCursor = (uint8_t)color;
            *ppCursor += pBits->stride;
        }
    }
    *ppCursor += xStep;
}

// @4470c0 — horizontal run for the x-major octants: `count` pixels stepping
// by xStep, then advance the cursor by the stride.
static void dwImageDraw_LineRunHoriz(dwImageBits* pBits, uint8_t** ppCursor, int16_t xStep, int16_t count, int color)
{
    if (count != 0)
    {
        for (int n = count; n != 0; n--)
        {
            **ppCursor = (uint8_t)color;
            *ppCursor += xStep;
        }
    }
    *ppCursor += pBits->stride;
}

typedef void (*dwImageDraw_lineRunFunc_t)(dwImageBits* pBits, uint8_t** ppCursor, int16_t xStep, int16_t count, int color);

// 16bpp line runs are the same shared no-op stub as the fills.
static void dwImageDraw_LineRun16(dwImageBits* pBits, uint8_t** ppCursor, int16_t xStep, int16_t count, int color)
{
    (void)pBits; (void)ppCursor; (void)xStep; (void)count; (void)color;
}

// @447100 — Cohen-Sutherland clip; clamps *pP0/*pP1 into pBounds in place.
// Outcodes: 8 = y >= bottom, 4 = y < top, 2 = x >= right, 1 = x < left.
int dwImageDraw_ClipLine(dwRect* pBounds, dwPoint* pP0, dwPoint* pP1)
{
    int code0 = 0;
    if (pP0->y >= pBounds->bottom)
        code0 = 8;
    else if (pP0->y < pBounds->top)
        code0 = 4;
    if (pP0->x >= pBounds->right)
        code0 |= 2;
    else if (pP0->x < pBounds->left)
        code0 |= 1;

    int code1 = 0;
    if (pP1->y >= pBounds->bottom)
        code1 = 8;
    else if (pP1->y < pBounds->top)
        code1 = 4;
    if (pP1->x >= pBounds->right)
        code1 |= 2;
    else if (pP1->x < pBounds->left)
        code1 |= 1;

    if (code0 & code1)
        return 0;
    if ((code0 | code1) == 0)
        return 1;

    if (pP0->x == pP1->x)
    {
        // Vertical line: clamp both ys into [top, bottom).
        if (pP0->y < pBounds->top)
            pP0->y = pBounds->top;
        else if (pP0->y >= pBounds->bottom)
            pP0->y = pBounds->bottom - 1;
        if (pP1->y < pBounds->top)
        {
            pP1->y = pBounds->top;
            return 1;
        }
        if (pP1->y >= pBounds->bottom)
            pP1->y = pBounds->bottom - 1;
        return 1;
    }
    if (pP0->y == pP1->y)
    {
        // Horizontal line: clamp both xs into [left, right).
        if (pP0->x < pBounds->left)
            pP0->x = pBounds->left;
        else if (pP0->x >= pBounds->right)
            pP0->x = pBounds->right - 1;
        if (pP1->x < pBounds->left)
        {
            pP1->x = pBounds->left;
            return 1;
        }
        if (pP1->x >= pBounds->right)
            pP1->x = pBounds->right - 1;
        return 1;
    }

    // General case: slope-intercept clamps with round-half-up (the binary
    // computes x + 0.5 on the FPU then truncates via __ftol). Deltas are
    // taken from the ORIGINAL endpoints before any clamping.
    double fDx = (double)(pP1->x - pP0->x);
    double fDy = (double)(pP1->y - pP0->y);
    int origX0 = pP0->x;
    int origY0 = pP0->y;

    if (code0 != 0)
    {
        if (pP0->x < pBounds->left)
        {
            pP0->y = (int16_t)(int)((double)(pBounds->left - origX0) * fDy / fDx + (double)origY0 + 0.5);
            pP0->x = pBounds->left;
        }
        else if (pP0->x >= pBounds->right)
        {
            pP0->y = (int16_t)(int)((double)origY0 - (double)(origX0 - (pBounds->right - 1)) * fDy / fDx + 0.5);
            pP0->x = pBounds->right - 1;
        }
        if (pP0->y < pBounds->top)
        {
            pP0->x = (int16_t)(int)((double)(pBounds->top - pP0->y) * fDx / fDy + (double)pP0->x + 0.5);
            pP0->y = pBounds->top;
        }
        else if (pP0->y >= pBounds->bottom)
        {
            pP0->x = (int16_t)(int)((double)pP0->x - (double)(pP0->y - (pBounds->bottom - 1)) * fDx / fDy + 0.5);
            pP0->y = pBounds->bottom - 1;
        }
    }
    if (code1 != 0)
    {
        if (pP1->x < pBounds->left)
        {
            pP1->y = (int16_t)(int)((double)(pBounds->left - pP1->x) * fDy / fDx + (double)pP1->y + 0.5);
            pP1->x = pBounds->left;
        }
        else if (pP1->x >= pBounds->right)
        {
            pP1->y = (int16_t)(int)((double)pP1->y - (double)(pP1->x - (pBounds->right - 1)) * fDy / fDx + 0.5);
            pP1->x = pBounds->right - 1;
        }
        if (pP1->y < pBounds->top)
        {
            pP1->x = (int16_t)(int)((double)(pBounds->top - pP1->y) * fDx / fDy + (double)pP1->x + 0.5);
            pP1->y = pBounds->top;
        }
        else if (pP1->y >= pBounds->bottom)
        {
            pP1->x = (int16_t)(int)((double)pP1->x - (double)(pP1->y - (pBounds->bottom - 1)) * fDx / fDy + 0.5);
            pP1->y = pBounds->bottom - 1;
        }
    }

    // Final containment check — diagonal clamps can still land outside.
    if (pP0->x >= pBounds->left && pP0->x < pBounds->right
        && pP1->x >= pBounds->left && pP1->x < pBounds->right
        && pP0->y >= pBounds->top && pP0->y < pBounds->bottom
        && pP1->y >= pBounds->top && pP1->y < pBounds->bottom)
    {
        return 1;
    }
    return 0;
}

// @446d50 — run-length-slice Bresenham line (Abrash-style: whole runs of the
// minor axis per step), clipped to {0,0,w,h} ∩ pClip.
void dwImageDraw_Line(dwImageBits* pBits, dwPoint* pP0, dwPoint* pP1, int color, dwRect* pClip)
{
    dwImageDesc* pDesc = pBits->pDesc;

    dwRect bounds;
    bounds.left = 0;
    bounds.top = 0;
    bounds.right = (int16_t)pDesc->width;
    bounds.bottom = (int16_t)pDesc->height;
    if (pClip)
        dwRect_Clip(&bounds, pClip);

    dwPoint p0 = *pP0;
    dwPoint p1 = *pP1;

    if (bounds.right == bounds.left || bounds.bottom == bounds.top)
        return;
    if (!dwImageDraw_ClipLine(&bounds, &p0, &p1))
        return;

    dwImageDraw_lineRunFunc_t pRunHoriz = NULL;
    dwImageDraw_lineRunFunc_t pRunVert = NULL;
    if (pDesc->bpp == 1)
    {
        pRunHoriz = dwImageDraw_LineRunHoriz;
        pRunVert = dwImageDraw_LineRunVert;
    }
    else if (pDesc->bpp == 2)
    {
        pRunHoriz = dwImageDraw_LineRun16;
        pRunVert = dwImageDraw_LineRun16;
    }

    if (p1.y < p0.y)
    {
        dwPoint tmp = p0;
        p0 = p1;
        p1 = tmp;
    }

    int16_t dx = (int16_t)(p1.x - p0.x);
    int dy = p1.y - p0.y; // >= 0
    int16_t xStep = (int16_t)pDesc->bpp;
    if (dx < 0)
    {
        xStep = -xStep;
        dx = (int16_t)-dx;
    }

    uint8_t* pCursor = (uint8_t*)pBits->pPixels + p0.y * pBits->stride + p0.x * (int)pDesc->bpp;

    if (dx == 0)
    {
        dwImageDraw_aFillRunV[pDesc->bpp](pCursor, pBits->stride, color, dy);
        return;
    }
    if (dy == 0)
    {
        dwImageDraw_aFillRunH[pDesc->bpp](pCursor, color, (unsigned int)dx);
        return;
    }

    if (dy <= dx)
    {
        // X-major: horizontal runs.
        int wholeStep = dx / dy;
        int adjUp = (dx % dy) * 2;
        int errorTerm = (dx % dy) - dy * 2;
        int finalCount = (int16_t)wholeStep / 2 + 1;
        int initialCount = finalCount;
        if ((int16_t)adjUp == 0 && (wholeStep & 1) == 0)
            initialCount = (int16_t)wholeStep / 2;
        if (wholeStep & 1)
            errorTerm += dy;

        pRunHoriz(pBits, &pCursor, xStep, (int16_t)initialCount, color);
        for (int16_t i = 0; i < dy - 1; i++)
        {
            errorTerm += adjUp;
            int runLen = wholeStep;
            if ((int16_t)errorTerm > 0)
            {
                runLen = wholeStep + 1;
                errorTerm -= dy * 2;
            }
            pRunHoriz(pBits, &pCursor, xStep, (int16_t)runLen, color);
        }
        pRunHoriz(pBits, &pCursor, xStep, (int16_t)finalCount, color);
    }
    else
    {
        // Y-major: vertical runs.
        int wholeStep = dy / dx;
        int adjUp = (dy % dx) * 2;
        int errorTerm = (dy % dx) - dx * 2;
        int finalCount = (int16_t)wholeStep / 2 + 1;
        int initialCount = finalCount;
        if ((int16_t)adjUp == 0 && (wholeStep & 1) == 0)
            initialCount = (int16_t)wholeStep / 2;
        if (wholeStep & 1)
            errorTerm += dx;

        pRunVert(pBits, &pCursor, xStep, (int16_t)initialCount, color);
        for (int16_t i = 0; i < dx - 1; i++)
        {
            errorTerm += adjUp;
            int runLen = wholeStep;
            if ((int16_t)errorTerm > 0)
            {
                runLen = wholeStep + 1;
                errorTerm -= dx * 2;
            }
            pRunVert(pBits, &pCursor, xStep, (int16_t)runLen, color);
        }
        pRunVert(pBits, &pCursor, xStep, (int16_t)finalCount, color);
    }
}

// ------------------------------------------------------------------
// Triangle blend

// @447710 — vertical blend span at column x, [yTop, yBottom) ∩ pClip.
void dwImageDraw_BlendColumn(dwImageBits* pBits, int16_t x, int16_t yTop, int16_t yBottom, int color, dwRect* pClip)
{
    if ((uint8_t)(pBits->pDesc->bpp << 3) != 8)
        return;
    if (x < pClip->left || x >= pClip->right)
        return;
    if (yTop >= pClip->bottom)
        return;
    if (yBottom < pClip->top)
        return;
    if (yTop < pClip->top)
        yTop = pClip->top;
    if (yBottom > pClip->bottom)
        yBottom = pClip->bottom;
    if (yTop >= yBottom)
        return;

    uint8_t* p = (uint8_t*)pBits->pPixels + yTop * pBits->stride + x;
    if ((int16_t)(yBottom - yTop) > 0)
    {
        for (int n = (int16_t)(yBottom - yTop); n != 0; n--)
        {
            uint8_t* pTbl = (uint8_t*)rdColormap_pCurMap->transparency;
            *p = pTbl[(unsigned int)*p * 0x100 + (color & 0xff)];
            p += pBits->stride;
        }
    }
}

// @447520 — translucent filled triangle: apex *pApex, vertical opposite edge
// at paEnds[0].x spanning paEnds[0].y..paEnds[1].y. Interpolates both edges
// with a truncated-division DDA and blends one column at a time.
// NOTE (faithful): x coordinates are zero-extended from their int16 storage,
// and a zero-width triangle (apex.x == paEnds[0].x) divides by zero, exactly
// like the binary.
void dwImageDraw_FillTriBlend(dwImageBits* pBits, int color, dwPoint* pApex, dwPoint* paEnds, dwRect* pClip)
{
    int x0 = (uint16_t)pApex->x;
    int y0 = (uint16_t)pApex->y;
    int x1 = (uint16_t)paEnds[0].x;
    int16_t dyB = (int16_t)(paEnds[0].y - y0);
    int16_t dyC = (int16_t)(paEnds[1].y - y0);

    int dx = x1 - x0;              // zero-extended difference (binary quirk)
    int dx16 = (int16_t)dx;        // divisor
    int stepB = dyB / dx16;
    int remB = dyB % dx16;
    if (remB < 0)
        remB = -remB;
    int stepC = dyC / dx16;
    int remC = dyC % dx16;
    if (remC < 0)
        remC = -remC;

    int errB = -dx;
    int errC = -dx;
    int yTop = y0;
    int yBot = y0;
    int xCur = x0;

    // Fast-forward both edge interpolators when the apex starts left of the
    // clip rect.
    int skip = (int)(uint16_t)pClip->left - x0;
    if ((int16_t)skip > 0)
    {
        int t = (int16_t)((int16_t)errB + (int16_t)skip * (int16_t)remB);
        errB = t % dx16;
        yTop = y0 + (t / dx16 + skip) * stepB;
        if ((int16_t)errB > 0)
        {
            yTop += stepB;
            errB -= dx;
        }
        t = (int16_t)((int16_t)errC + (int16_t)skip * (int16_t)remC);
        errC = t % dx16;
        yBot = y0 + (t / dx16 + skip) * stepC;
        xCur = (uint16_t)pClip->left;
        if ((int16_t)errC > 0)
        {
            yBot += stepC;
            errC -= dx;
        }
    }

    for (int count = (int16_t)x1 - (int16_t)xCur; count > 0; count--)
    {
        dwImageDraw_BlendColumn(pBits, (int16_t)xCur, (int16_t)yTop, (int16_t)yBot, color, pClip);

        errB += remB;
        xCur++;
        yTop += stepB;
        while ((int16_t)errB > 0)
        {
            yTop += (dyB < 0) ? -1 : 1;
            errB -= dx;
        }

        errC += remC;
        yBot += stepC;
        while ((int16_t)errC > 0)
        {
            yBot += (dyC < 0) ? -1 : 1;
            errC -= dx;
        }
    }
}
