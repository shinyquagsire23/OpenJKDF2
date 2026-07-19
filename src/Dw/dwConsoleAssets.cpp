// dwConsoleAssets — see dwConsoleAssets.h for the unit overview. OpenJKDF2-side
// (no binary counterpart); C++ because the dwImage class is only visible here.

#include "dwConsoleAssets.h"

#ifdef PLATFORM_DROIDWORKS

#include "Dw/dwFont.h"
#include "Dw/dwImage.h"
#include "Dw/stdBitmapRle2.h"
#include "Engine/rdColormap.h"
#include "General/stdString.h"
#include "stdPlatform.h"
#include "jk.h"

// These engine headers have no extern "C" guards of their own — wrap at
// include site (same pattern as dwCursor.cpp).
extern "C" {
#include "Win95/stdDisplay.h"
}

int dwConsoleAssets_Ready()
{
    // dwFont_Startup (part of dw_Startup, first frame) creates the cache; the
    // DW VFS (dwMain_pHS) is already up by then (dwMain_Startup).
    return dwFont_pCache != NULL;
}

// Fill a fresh 0x300 stdBitmap palette with a gray ramp (index i -> (i,i,i)).
static void dwConsoleAssets_GrayRampPalette(void* pPalette)
{
    uint8_t* pPal = (uint8_t*)pPalette;
    for (int i = 0; i < 256; i++)
    {
        pPal[(i * 3) + 0] = (uint8_t)i;
        pPal[(i * 3) + 1] = (uint8_t)i;
        pPal[(i * 3) + 2] = (uint8_t)i;
    }
}

// Allocate a 1-mip 8bpp stdBitmap (width x height) with a locked-and-filled
// pixel buffer. Mirrors the tail of stdBitmap_LoadEntryFromFile (vbuffer +
// SDL2_RENDER GPU-tracking arrays). Palette buffer is allocated but left to
// the caller to fill. Returns NULL on failure.
static stdBitmap* dwConsoleAssets_NewBitmap8(int width, int height)
{
    rdTexFormat fmt;
    _memset(&fmt, 0, sizeof(fmt));
    fmt.bpp = 8; // is16bit = 0; 8bpp has no channel masks (stdDisplay_VBufferNew)

    stdBitmap* pBmp = stdBitmap_New(1 /*numMips*/, 2 /*palFmt: palette present*/, 0, 0, &fmt);
    if (!pBmp)
        return NULL;

    tRasterInfo ri;
    _memset(&ri, 0, sizeof(ri));
    ri.width = width;
    ri.height = height;
    _memcpy(&ri.format, &fmt, sizeof(fmt));

    tVBuffer* pVBuf = stdDisplay_VBufferNew(&ri, 0, 0, 0);
    if (!pVBuf)
    {
        stdBitmap_Free(pBmp);
        return NULL;
    }
    pBmp->mipSurfaces[0] = pVBuf;

    pBmp->palette = STD_ALLOC(0x300);
    if (!pBmp->palette)
    {
        stdBitmap_Free(pBmp);
        return NULL;
    }

#ifdef SDL2_RENDER
    pBmp->aTextureIds = (uint32_t*)STD_ALLOC(sizeof(uint32_t));
    pBmp->abLoadedToGPU = (int*)STD_ALLOC(sizeof(int));
    pBmp->paDataDepthConverted = (void**)STD_ALLOC(sizeof(void*));
    if (!pBmp->aTextureIds || !pBmp->abLoadedToGPU || !pBmp->paDataDepthConverted)
    {
        stdBitmap_Free(pBmp);
        return NULL;
    }
    *pBmp->aTextureIds = 0;
    *pBmp->abLoadedToGPU = 0;
    *pBmp->paDataDepthConverted = NULL;
#endif

    return pBmp;
}

stdFont* dwConsoleAssets_LoadFont(const char* pName)
{
    dwFont laf;
    dwFont_Load(&laf, pName);
    if (!laf.pHeader || !laf.paGlyphs || !laf.pPixelData)
        return NULL;

    int firstChar = laf.pHeader->firstChar;
    int lastChar = laf.pHeader->lastChar;
    int numChars = lastChar - firstChar + 1;
    if (numChars <= 0 || numChars > 1024)
        return NULL;

    // Vertical extent of the strip: glyph tops sit at (baseline + yOffset),
    // yOffset is the signed baseline offset (dwFont_DrawGlyph8). Glyph records
    // are indexed directly by (ch - firstChar), as in the binary.
    int minYOff = 0;
    int maxBottom = 0;
    for (int i = 0; i < numChars; i++)
    {
        dwFontGlyph* pGlyph = &laf.paGlyphs[i];
        if (pGlyph->width <= 0 || !pGlyph->height)
            continue;
        if (pGlyph->yOffset < minYOff)
            minYOff = pGlyph->yOffset;
        if (pGlyph->yOffset + (int)pGlyph->height > maxBottom)
            maxBottom = pGlyph->yOffset + (int)pGlyph->height;
    }

    int stripH = maxBottom - minYOff;
    if (stripH <= 0)
        return NULL;
    int baseline = -minYOff;

    // Strip width: one cell per glyph, cell width = the .laf advance width.
    int stripW = 0;
    for (int i = 0; i < numChars; i++)
    {
        int adv = laf.paGlyphs[i].advanceWidth;
        if (adv < 1)
            adv = 1;
        stripW += adv;
    }

    stdBitmap* pBmp = dwConsoleAssets_NewBitmap8(stripW, stripH);
    if (!pBmp)
        return NULL;

    // .laf pixels are a monochrome coverage mask (0 = transparent, 0xff =
    // solid); a gray ramp makes coverage double as whiteness.
    dwConsoleAssets_GrayRampPalette(pBmp->palette);

    // stdFont + its inline charset entries in one allocation, exactly like
    // stdFont_Load (sizeof(stdFont) already carries the first entry).
    size_t totalAlloc = sizeof(stdFontEntry) * (lastChar - firstChar) + sizeof(stdFont);
    stdFont* pFont = (stdFont*)STD_ALLOC(totalAlloc);
    if (!pFont)
    {
        stdBitmap_Free(pBmp);
        return NULL;
    }
    _memset(pFont, 0, totalAlloc);
    pFont->charsetHead.pEntries = &pFont->charsetHead.entries;
    pFont->charsetHead.charFirst = (uint16_t)firstChar;
    pFont->charsetHead.charLast = (uint16_t)lastChar;
    pFont->pBitmap = pBmp;

#ifdef SITH_DEBUG_STRUCT_NAMES
    stdString_SafeStrCopy(pFont->name, pName, 32);
#endif
#ifndef OPTIMIZE_AWAY_UNUSED_FIELDS
    stdString_SafeStrCopy((char*)pBmp->fpath, "FONTSTRIP", 32);
#endif

    // Bake the glyph cells.
    tVBuffer* pVBuf = pBmp->mipSurfaces[0];
    stdDisplay_VBufferLock(pVBuf);
    uint8_t* pStrip = (uint8_t*)pVBuf->surface_lock_alloc;
    _memset(pStrip, 0, pVBuf->format.rowSize * stripH);

    int curX = 0;
    for (int i = 0; i < numChars; i++)
    {
        dwFontGlyph* pGlyph = &laf.paGlyphs[i];
        int adv = pGlyph->advanceWidth;
        if (adv < 1)
            adv = 1;

        pFont->charsetHead.pEntries[i].glyphTexX = curX;
        pFont->charsetHead.pEntries[i].glyphWidth = adv;

        int dstX = curX + pGlyph->xOffset;
        int dstY = baseline + pGlyph->yOffset;
        int w = pGlyph->width;
        int h = pGlyph->height;

        // Clamp into the strip (a couple of glyphs have xOffset -1).
        int srcX = 0;
        if (dstX < 0) { srcX = -dstX; w += dstX; dstX = 0; }
        if (w > stripW - dstX)
            w = stripW - dstX;
        if (h > stripH - dstY)
            h = stripH - dstY;

        if (w > 0 && h > 0 && dstY >= 0)
        {
            uint8_t* pSrc = pGlyph->pPixels + srcX;
            for (int row = 0; row < h; row++)
            {
                uint8_t* pDstRow = pStrip + (dstY + row) * pVBuf->format.rowSize + dstX;
                uint8_t* pSrcRow = pSrc + row * pGlyph->width;
                for (int col = 0; col < w; col++)
                {
                    if (pSrcRow[col])
                        pDstRow[col] = pSrcRow[col];
                }
            }
        }

        curX += adv;
    }
    stdDisplay_VBufferUnlock(pVBuf);

    // marginY = 0: glyph advance (incl. spacing) is fully baked into the cells,
    // and the console derives line height from the strip height alone.
    pFont->marginY = 0;
    pFont->marginX = (firstChar <= ' ' && ' ' <= lastChar)
        ? pFont->charsetHead.pEntries[' ' - firstChar].glyphWidth : 4;
    pFont->field_28 = (int16_t)'?';

    // Same monospace metric jkQuakeConsole_Startup computes for the JK font.
    int num = lastChar - firstChar;
    if (num < 1)
        num = 1;
    int averageW = 0;
    int largestW = 0;
    for (int i = 0; i < num; i++)
    {
        int w = pFont->charsetHead.pEntries[i].glyphWidth;
        char theChar = (char)(i + firstChar);
        averageW += w;
        if (w > largestW && theChar != ' ' && theChar != '\t')
            largestW = w;
    }
    averageW /= num;
    pFont->monospaceW = (int16_t)((averageW + averageW + largestW) / 3);

    return pFont;
}

stdBitmap* dwConsoleAssets_LoadBitmap(const char* pPath, const char* pCmpName)
{
    // LoadFile16 forces the decode-into-buffer path on an 8bpp display, so the
    // image is always lockable (same entry the dwGuiScreen BACKGROUND uses).
    dwImage* pImg = stdBitmapRle2_LoadFile16((char*)pPath);
    if (!pImg)
        return NULL;

    void* pPixels = NULL;
    int stride = 0;
    if (!pImg->Lock(&pPixels, &stride) || !pPixels)
    {
        delete pImg;
        return NULL;
    }

    int w = pImg->desc.width;
    int h = pImg->desc.height;
    if (pImg->desc.bpp != 1 || w <= 0 || h <= 0)
    {
        pImg->Unlock();
        delete pImg;
        return NULL;
    }

    stdBitmap* pBmp = dwConsoleAssets_NewBitmap8(w, h);
    if (pBmp)
    {
        tVBuffer* pVBuf = pBmp->mipSurfaces[0];
        stdDisplay_VBufferLock(pVBuf);
        uint8_t* pDst = (uint8_t*)pVBuf->surface_lock_alloc;
        uint8_t* pSrc = (uint8_t*)pPixels;
        for (int row = 0; row < h; row++)
            _memcpy(pDst + row * pVBuf->format.rowSize, pSrc + row * stride, w);
        stdDisplay_VBufferUnlock(pVBuf);

        // Take the image's intended palette from its screen colormap so the
        // console shade looks right no matter which screen palette is live.
        rdColormap* pCmp = rdColormap_Load((char*)pCmpName);
        if (pCmp)
        {
            _memcpy(pBmp->palette, pCmp->colors, 0x300);
            rdColormap_Free(pCmp);
        }
        else
        {
            dwConsoleAssets_GrayRampPalette(pBmp->palette);
        }
    }

    pImg->Unlock();
    delete pImg;
    return pBmp;
}

#endif // PLATFORM_DROIDWORKS
