// dwRect — DroidWorks short-LTRB rectangle helpers (see dwRect.h).
//
// Ghidra (DroidWorks.exe): dwRect_ContainsPoint@0x406570 (COMDAT),
// dwRect_Set@0x418850 (COMDAT), dwRect_Overlaps@0x444180,
// dwRect_Clip@0x4441f0, dwRect_Union@0x444270.
//
// All five were __thiscall in the binary (`this` = the first rect); the C
// translation passes it as the first parameter per DW/DECOMP_PROGRESS.md.

#include "Dw/dwRect.h"

int dwRect_ContainsPoint(dwRect* pRect, int16_t x, int16_t y)
{
    if (pRect->left <= x && x < pRect->right && pRect->top <= y && y < pRect->bottom)
    {
        return 1;
    }
    return 0;
}

void dwRect_Set(dwRect* pRect, int16_t left, int16_t top, int16_t right, int16_t bottom)
{
    pRect->left = left;
    pRect->top = top;
    pRect->right = right;
    pRect->bottom = bottom;
}

int dwRect_Overlaps(dwRect* pRect, dwRect* pOther)
{
    int16_t left, top, right, bottom;

    left = pRect->left;
    if (pRect->left <= pOther->left)
        left = pOther->left;

    right = pRect->right;
    if (pOther->right <= pRect->right)
        right = pOther->right;

    top = pOther->top;
    if (pOther->top < pRect->top)
        top = pRect->top;

    bottom = pOther->bottom;
    if (pRect->bottom < pOther->bottom)
        bottom = pRect->bottom;

    // <= on purpose: touching rects (zero-area intersection) count as
    // overlapping (relied on by dwDisplay_AddDirtyRect's coalescing).
    if (left <= right && top <= bottom)
    {
        return 1;
    }
    return 0;
}

void dwRect_Clip(dwRect* pRect, dwRect* pClip)
{
    int16_t left, top, right, bottom;

    left = pRect->left;
    if (pRect->left <= pClip->left)
        left = pClip->left;
    pRect->left = left;

    right = pRect->right;
    if (pClip->right <= pRect->right)
        right = pClip->right;
    pRect->right = right;

    top = pClip->top;
    if (pClip->top < pRect->top)
        top = pRect->top;
    pRect->top = top;

    bottom = pRect->bottom;
    if (pClip->bottom <= pRect->bottom)
        bottom = pClip->bottom;
    pRect->bottom = bottom;

    if ((int16_t)(right - left) < 1 || (int16_t)(bottom - top) < 1)
    {
        pRect->left = 0;
        pRect->top = 0;
        pRect->right = 0;
        pRect->bottom = 0;
    }
}

void dwRect_Union(dwRect* pRect, dwRect* pOther)
{
    int16_t v;

    // Empty dest -> copy source wholesale (binary copies as two dwords).
    if (pRect->right == pRect->left || pRect->bottom == pRect->top)
    {
        *pRect = *pOther;
        return;
    }

    // Empty source -> nothing to add.
    if (pOther->right == pOther->left || pOther->bottom == pOther->top)
    {
        return;
    }

    v = pRect->left;
    if (pOther->left <= pRect->left)
        v = pOther->left;
    pRect->left = v;

    v = pOther->right;
    if (pOther->right < pRect->right)
        v = pRect->right;
    pRect->right = v;

    v = pRect->top;
    if (pOther->top <= pRect->top)
        v = pOther->top;
    pRect->top = v;

    v = pRect->bottom;
    if (pRect->bottom <= pOther->bottom)
        v = pOther->bottom;
    pRect->bottom = v;
}
