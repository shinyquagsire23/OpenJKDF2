// dwCursor — DroidWorks software mouse cursor with save-under
// double-buffering.
//
// Decompiled from DroidWorks.exe, unit range 0x443340-0x44391x. The cursor
// table is filled by a C++ static ctor (dwCursor_TableInit @0x443350, CRT
// thunk @0x443340); here dwCursor_Startup() runs it instead. The sprite and
// save-under tVBuffers are allocated/freed by dwDisplay
// (dwDisplay_CreateCursorSprites / dwDisplay_FreeCursors).
//
// Flow (flicker semantics — ordering is load-bearing):
//   Draw:        save the back-buffer pixels under the cursor into
//                pSaveUnder, then blit the sprite (color-key 0) into the
//                BACK buffer at pos - hotspot.
//   Present:     (dwDisplay) Draw -> full back->front copy -> RestoreUnder,
//                so the frame that reaches the screen has the cursor but the
//                working buffer never keeps it.
//   Redraw:      incremental per-mouse-move update — Draw, copy the new
//                cursor rect AND the previous cursor rect back->front,
//                remember the new rect, RestoreUnder.
//
// Buffer mapping + "front active" flag: the binary tested the front
// tVBuffer's first dword (nonzero = DDraw primary = fullscreen = software
// cursor active; zero = windowed GDI = OS cursor). Note: in the SDL3
// adaptation the software cursor is always used once a mode is set, so those
// tests map to `dwDisplay_pFrontVBuf != NULL`.
//
// Compiled as C++ (dwCursor_SetCursor has an MSVC EH frame around a stack
// dwImageVBuf); the API keeps C linkage via dwCursor.h.

#include "Dw/dwCursor.h"

#include "Dw/dwDisplay.h"
#include "Dw/dwImage.h"
#include "Dw/dwImageVBuf.h"

#include "jk.h"
#include "stdPlatform.h"
// These engine headers have no extern "C" guards of their own — wrap at include site.
extern "C" {
#include "Win95/stdDisplay.h"
#include "Platform/stdControl.h"
}

// Module globals (all reset in dwCursor_Startup; soft-reset rule).
dwCursorEntry dwCursor_aCursors[DWCURSOR_NUM_CURSORS]; // binary: filled by the static ctor
int dwCursor_curIdx = 0;
dwPoint dwCursor_pos = { 0, 0 };   // binary: 0x541bf8 (dwWidget/dwSegment write it directly)
int16_t dwCursor_drawX = 0;        // Note: int32 globals in the binary, but only the low
int16_t dwCursor_drawY = 0;        //       16 bits are ever written/read
rdRect dwCursor_prevRect = { 0, 0, 0, 0 };
int dwCursor_bPrevValid = 0;
tVBuffer* dwCursor_pSprite = NULL;    // 32x32 sprite, allocated by dwDisplay
tVBuffer* dwCursor_pSaveUnder = NULL; // 32x32 save-under, allocated by dwDisplay

// Note: no binary counterpart — statics reset for the soft-reset loop.
// Deliberately does not free loaded images or the sprite VBuffers
// (dwDisplay_FreeCursors owns that; run it first on a live display).
void dwCursor_Startup()
{
    _memset(dwCursor_aCursors, 0, sizeof(dwCursor_aCursors));
    dwCursor_curIdx = 0;
    dwCursor_pos.x = 0;
    dwCursor_pos.y = 0;
    dwCursor_drawX = 0;
    dwCursor_drawY = 0;
    dwCursor_prevRect.x = 0;
    dwCursor_prevRect.y = 0;
    dwCursor_prevRect.width = 0;
    dwCursor_prevRect.height = 0;
    dwCursor_bPrevValid = 0;
    dwCursor_pSprite = NULL;
    dwCursor_pSaveUnder = NULL;

    dwCursor_TableInit();
}

// @443350 (CRT static-ctor body; thunk @443340)
void dwCursor_TableInit()
{
    dwCursor_aCursors[0].pFilename = NULL;
    dwCursor_aCursors[0].pImage = NULL;
    dwCursor_aCursors[0].hotX = 0;
    dwCursor_aCursors[0].hotY = 0;
    dwCursor_aCursors[1].pFilename = "curArrow.rle";
    dwCursor_aCursors[1].pImage = NULL;
    dwCursor_aCursors[1].hotX = 0;
    dwCursor_aCursors[1].hotY = 0;
    dwCursor_aCursors[2].pFilename = "curHand.rle";
    dwCursor_aCursors[2].pImage = NULL;
    dwCursor_aCursors[2].hotX = 7;
    dwCursor_aCursors[2].hotY = 13;
    dwCursor_aCursors[3].pFilename = "curHelp.rle";
    dwCursor_aCursors[3].pImage = NULL;
    dwCursor_aCursors[3].hotX = 2;
    dwCursor_aCursors[3].hotY = 2;
    dwCursor_aCursors[4].pFilename = "curWait.rle";
    dwCursor_aCursors[4].pImage = NULL;
    dwCursor_aCursors[4].hotX = 6;
    dwCursor_aCursors[4].hotY = 9;
    dwCursor_aCursors[5].pFilename = "curPaintYellow.rle";
    dwCursor_aCursors[5].pImage = NULL;
    dwCursor_aCursors[5].hotX = 20;
    dwCursor_aCursors[5].hotY = 26;
    dwCursor_aCursors[6].pFilename = "curPaintPurple.rle";
    dwCursor_aCursors[6].pImage = NULL;
    dwCursor_aCursors[6].hotX = 20;
    dwCursor_aCursors[6].hotY = 26;
    dwCursor_aCursors[7].pFilename = "curPaintRed.rle";
    dwCursor_aCursors[7].pImage = NULL;
    dwCursor_aCursors[7].hotX = 20;
    dwCursor_aCursors[7].hotY = 26;
    dwCursor_aCursors[8].pFilename = "curPaintPink.rle";
    dwCursor_aCursors[8].pImage = NULL;
    dwCursor_aCursors[8].hotX = 20;
    dwCursor_aCursors[8].hotY = 26;
    dwCursor_aCursors[9].pFilename = "curPaintWhite.rle";
    dwCursor_aCursors[9].pImage = NULL;
    dwCursor_aCursors[9].hotX = 20;
    dwCursor_aCursors[9].hotY = 26;
    dwCursor_aCursors[10].pFilename = "curPaintGreen.rle";
    dwCursor_aCursors[10].pImage = NULL;
    dwCursor_aCursors[10].hotX = 20;
    dwCursor_aCursors[10].hotY = 26;
    dwCursor_aCursors[11].pFilename = "curPaintBlue.rle";
    dwCursor_aCursors[11].pImage = NULL;
    dwCursor_aCursors[11].hotX = 20;
    dwCursor_aCursors[11].hotY = 26;
    dwCursor_aCursors[12].pFilename = "curPaintBrown.rle";
    dwCursor_aCursors[12].pImage = NULL;
    dwCursor_aCursors[12].hotX = 20;
    dwCursor_aCursors[12].hotY = 26;
    dwCursor_aCursors[13].pFilename = "curPaintGray.rle";
    dwCursor_aCursors[13].pImage = NULL;
    dwCursor_aCursors[13].hotX = 20;
    dwCursor_aCursors[13].hotY = 26;
}

// @443500
void dwCursor_Redraw()
{
    rdRect rect;

    if (dwCursor_curIdx != 0 && dwDisplay_pFrontVBuf) // binary: front tVBuffer's DDraw flag @0x6b17c0
    {
        // binary: DAT_0065be00, the Window WM_ACTIVATE flag
        if (g_window_active)
        {
            if (dwCursor_Draw(&rect))
            {
                stdDisplay_VBufferCopy(dwDisplay_pFrontVBuf, dwDisplay_pBackVBuf,
                                       rect.x, rect.y, &rect, 0);
                if (dwCursor_bPrevValid)
                {
                    stdDisplay_VBufferCopy(dwDisplay_pFrontVBuf, dwDisplay_pBackVBuf,
                                           dwCursor_prevRect.x, dwCursor_prevRect.y,
                                           &dwCursor_prevRect, 0);
                }
                dwCursor_prevRect.x = rect.x;
                dwCursor_prevRect.y = rect.y;
                dwCursor_prevRect.width = rect.width;
                dwCursor_prevRect.height = rect.height;
                dwCursor_bPrevValid = 1;
                dwCursor_RestoreUnder(&rect);
                // Note: added — the binary blitted straight onto the visible
                // primary surface; here the front buffer must be pushed to
                // the window explicitly.
                stdDisplay_DDrawGdiSurfaceFlip();
                return;
            }
        }
        dwCursor_bPrevValid = 0;
    }
}

// @4435f0
int dwCursor_Draw(rdRect* pOutRect)
{
    int bDrawn = 0;

    if (dwCursor_curIdx != 0 && dwDisplay_pFrontVBuf)
    {
        dwCursorEntry* pEntry = &dwCursor_aCursors[dwCursor_curIdx];
        // Note: guard added — the binary dereferenced pImage unconditionally
        // (its cursor .rle files always load); ours may be missing while the
        // dwImage loaders are stubbed.
        if (!pEntry->pImage)
            return 0;

        int16_t left = (int16_t)(dwCursor_pos.x - pEntry->hotX);
        dwCursor_drawX = left;
        int16_t top = (int16_t)(dwCursor_pos.y - pEntry->hotY);
        dwCursor_drawY = top;
        // right/bottom from the UNCLIPPED position (binary order).
        int16_t right = (int16_t)(left + (int16_t)pEntry->pImage->desc.width);
        int16_t bottom = (int16_t)(top + (int16_t)pEntry->pImage->desc.height);

        if (left < 0)
            left = 0;
        if (top < 0)
            top = 0;
        if ((int16_t)dwDisplay_pFrontVBuf->format.width <= right)
            right = (int16_t)dwDisplay_pFrontVBuf->format.width;
        if ((int16_t)dwDisplay_pFrontVBuf->format.height <= bottom)
            bottom = (int16_t)dwDisplay_pFrontVBuf->format.height;

        pOutRect->x = left;
        pOutRect->y = top;
        pOutRect->width = right - left;
        pOutRect->height = bottom - top;

        if (dwCursor_pSprite && pOutRect->width > 0 && pOutRect->height > 0)
        {
            bDrawn = 1;
            // Save the back-buffer pixels under the cursor.
            stdDisplay_VBufferCopy(dwCursor_pSaveUnder, dwDisplay_pBackVBuf, 0, 0, pOutRect, 0);
            // Blit the sprite into the back buffer (color-key 0).
            // Binary quirk kept: the source rect origin stays (0,0) even when
            // the cursor was clipped at the left/top edge.
            pOutRect->x = 0;
            pOutRect->y = 0;
            stdDisplay_VBufferCopy(dwDisplay_pBackVBuf, dwCursor_pSprite, left, top, pOutRect, 1);
            pOutRect->x = left;
            pOutRect->y = top;
        }
    }
    return bDrawn;
}

// @443720
void dwCursor_RestoreUnder(rdRect* pRect)
{
    rdRect rect;

    if (dwCursor_curIdx != 0 && dwDisplay_pFrontVBuf)
    {
        rect.x = 0;
        rect.y = 0;
        rect.width = pRect->width;
        rect.height = pRect->height;
        stdDisplay_VBufferCopy(dwDisplay_pBackVBuf, dwCursor_pSaveUnder,
                               pRect->x, pRect->y, &rect, 0);
    }
}

// @443780
void dwCursor_SetCursor(int idx)
{
    if (dwCursor_curIdx == idx)
        return;
    dwCursor_curIdx = idx;

    dwCursorEntry* pEntry = &dwCursor_aCursors[idx];
    if (!pEntry->pImage)
    {
        if (pEntry->pFilename && pEntry->pFilename[0])
            pEntry->pImage = dwImage_LoadFile((char*)pEntry->pFilename);
        if (!pEntry->pImage)
            goto show_hide;
    }

    if (dwCursor_pSprite)
    {
        stdDisplay_ClearRect(dwCursor_pSprite, 0, NULL);
        {
            // Wrap the sprite VBuffer, lock it, and blit the cursor image in
            // (binary: stack dwImageVBuf + vtbl +0x0c Lock / image vtbl +0x04
            // Blit / +0x10 Unlock, under an EH frame).
            dwImageVBuf spriteImg(dwCursor_pSprite);
            dwImageBits destBits;
            destBits.pDesc = &spriteImg.desc;
            destBits.pPixels = NULL;
            destBits.stride = 0;
            if (spriteImg.Lock(&destBits.pPixels, &destBits.stride))
            {
                pEntry->pImage->Blit(&destBits, 0, 0, NULL);
                spriteImg.Unlock();
            }
        }
    }

show_hide:
    // Binary: Win32 ShowCursor loops forcing the visibility counter fully
    // below/above zero. Note: stdControl_ShowMouseCursor keeps the same
    // counter semantics; the actual OS cursor is managed by the engine's
    // window layer. The "front active" test maps as described at file top.
    if (idx == 0 || dwDisplay_pFrontVBuf)
    {
        int refCount = stdControl_ShowMouseCursor(0);
        while (refCount >= 0)
            refCount = stdControl_ShowMouseCursor(0);
    }
    else
    {
        int refCount = stdControl_ShowMouseCursor(1);
        while (refCount < 0)
            refCount = stdControl_ShowMouseCursor(1);
    }
}

// @4438d0
void dwCursor_Precache(int idx)
{
    dwCursorEntry* pEntry = &dwCursor_aCursors[idx];
    if (!pEntry->pImage && pEntry->pFilename && pEntry->pFilename[0])
        pEntry->pImage = dwImage_LoadFile((char*)pEntry->pFilename);
}
