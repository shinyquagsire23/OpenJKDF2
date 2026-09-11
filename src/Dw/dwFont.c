// dwFont — DroidWorks bitmap-font module (Ghidra 0x447f20-0x448d5x).
//
// Loads/caches `<name>.laf` bitmap fonts through dwMain_pHS file ops; draws
// into 8bpp locked surfaces (16bpp = no-op stubs, exactly like the binary).
// Glyph blending (pixel bytes 1/2) uses the engine's current colormap's
// transparency table (rdColormap_pCurMap, binary DAT_005542b8).
//
// Genuinely-C unit: __thiscall entry points over a plain handle struct, but
// no ctors/dtors/vtables/EH frames — pure C per the DW language policy.

#include "Dw/dwFont.h"

#include "Dw/dwImage.h"
#include "Dw/dwRect.h"
#include "Engine/rdColormap.h"
#include "General/stdHashtbl.h"
#include "General/stdLinkList.h" // tLinkListNode (tHashLink) definition
#include "globals.h" // rdColormap_pCurMap
#include "stdPlatform.h"

#include <ctype.h>
#include <string.h>

// The DW host-services pointer (dwMain.c; binary dwHS @0x6b6258).
extern HostServices* dwMain_pHS;

// name -> cached font block (binary: 0x541d38).
tHashTable* dwFont_pCache = NULL;

// @447f20
int dwFont_Startup()
{
    dwFont_pCache = stdHashtbl_New(10);
    return dwFont_pCache != NULL;
}

// @447f40 — frees every cached font block (node values), then the table.
void dwFont_Shutdown()
{
    if (!dwFont_pCache)
        return;

    for (int i = 0; i < dwFont_pCache->numNodes; i++)
    {
        for (tHashLink* pNode = &dwFont_pCache->aSymbols[i]; pNode && pNode->value; pNode = pNode->next)
        {
            dwMain_pHS->free(pNode->value);
        }
    }
    stdHashtbl_Free(dwFont_pCache);
    dwFont_pCache = NULL; // Note: the binary leaves the stale pointer; nulled for the soft-reset loop.
}

// @447fa0 — fill the handle for pName, loading "<pName>.laf" on a cache miss.
// Cached block layout:
//   [name\0][u32 numGlyphs][dwFontHeader][u16 charMap[n]][dwFontGlyph[n]][pixels]
// NOTE (faithful): the header/glyph arrays inside the block are only byte-
// aligned (offset depends on the name length), and the ".laf" append assumes
// the name fits the 32-byte path buffer (strncpy limit 30).
dwFont* dwFont_Load(dwFont* pFont, const char* pName)
{
    pFont->pHeader = NULL;
    pFont->paCharMap = NULL;
    pFont->paGlyphs = NULL;
    pFont->pPixelData = NULL;

    size_t nameLen = strlen(pName);

    char* pCached = (char*)stdHashtbl_Find(dwFont_pCache, pName);
    if (pCached)
    {
        int32_t numGlyphs;
        memcpy(&numGlyphs, pCached + nameLen + 1, 4);
        pFont->pHeader = (dwFontHeader*)(pCached + nameLen + 5);
        pFont->paCharMap = (uint16_t*)(pFont->pHeader + 1);
        pFont->paGlyphs = (dwFontGlyph*)((char*)pFont->paCharMap + numGlyphs * 2);
        pFont->pPixelData = (uint8_t*)(pFont->paGlyphs + numGlyphs);
        return pFont;
    }

    char aPath[32];
    strncpy(aPath, pName, 0x1e);
    strcpy(aPath + nameLen, ".laf"); // binary: strcpy of the @0x52a288 suffix at name end

    stdFile_t hFile = dwMain_pHS->fileOpen(aPath, "rb");
    if (!hFile)
        return pFont;

    uint32_t numGlyphs;
    uint32_t pixelDataSize;
    uint32_t v32;
    dwMain_pHS->fileRead(hFile, &numGlyphs, 4); // file's glyph count; recomputed from the char range below
    dwMain_pHS->fileRead(hFile, &pixelDataSize, 4);

    uint32_t aHeader[12]; // staged dwFontHeader
    memset(aHeader, 0, sizeof(aHeader));
    dwMain_pHS->fileRead(hFile, &v32, 4);
    aHeader[1] = v32 & 0xffff; // lineHeight
    dwMain_pHS->fileRead(hFile, &v32, 4);
    aHeader[2] = v32 & 0xffff; // bpp
    dwMain_pHS->fileRead(hFile, &v32, 4);
    aHeader[3] = v32 & 0xffff; // field_C
    dwMain_pHS->fileRead(hFile, &v32, 4);
    aHeader[4] = v32 & 0xffff; // field_10
    dwMain_pHS->fileRead(hFile, &v32, 4);
    uint32_t firstChar = v32 & 0xff;
    aHeader[7] = firstChar;
    dwMain_pHS->fileRead(hFile, &v32, 4);
    uint32_t lastChar = v32 & 0xff;
    aHeader[8] = lastChar;
    numGlyphs = lastChar - firstChar + 1;

    // Binary: name NUL + u32 count + 0x30 header + per-glyph (u16 charmap +
    // 0x18 glyph record), i.e. numGlyphs*0x1a + 0x35. Sized with sizeof here
    // instead: on 64-bit dwFontGlyph grows to 0x20 (pPixels pointer), and the
    // binary's constants under-allocate by 8*numGlyphs — the pixel-data fread
    // then corrupted the heap past the block (caught by ASAN).
    char* pBlock = (char*)dwMain_pHS->alloc((uint32_t)(pixelDataSize + numGlyphs * (2 + sizeof(dwFontGlyph)) + 5 + sizeof(dwFontHeader) + nameLen));
    if (!pBlock)
    {
        // Note: original calls JK.EXE-style jk_logtofile(); no direct analog here.
        stdPlatform_Printf("Font memory allocation failed: %s\n", pName);
        dwMain_pHS->fileClose(hFile);
        return pFont;
    }

    strcpy(pBlock, pName);
    stdHashtbl_Add(dwFont_pCache, pBlock, pBlock);

    memcpy(pBlock + nameLen + 1, &numGlyphs, 4);
    pFont->pHeader = (dwFontHeader*)(pBlock + nameLen + 5);
    memcpy(pFont->pHeader, aHeader, 0x30);

    pFont->paCharMap = (uint16_t*)(pFont->pHeader + 1);
    dwMain_pHS->fileRead(hFile, pFont->paCharMap, numGlyphs * 2);

    dwFontGlyph* pGlyph = (dwFontGlyph*)((char*)pFont->paCharMap + numGlyphs * 2);
    pFont->paGlyphs = pGlyph;
    pFont->pPixelData = (uint8_t*)(pGlyph + numGlyphs);

    // NOTE (faithful): the binary tracks min/max yOffset here but never
    // stores them — pHeader->minYOffset/maxYOffset stay 0 (dead stores kept
    // for traceability).
    int minYOffset = 0;
    int maxYOffset = 0;
    for (uint32_t i = 0; i < numGlyphs; i++, pGlyph++)
    {
        uint8_t v8;
        dwMain_pHS->fileRead(hFile, &v32, 4);
        pGlyph->pixelOffset = v32;
        dwMain_pHS->fileRead(hFile, &v8, 1);
        pGlyph->advanceWidth = (int8_t)v8;
        dwMain_pHS->fileRead(hFile, &v8, 1);
        pGlyph->xOffset = (int8_t)v8;
        dwMain_pHS->fileRead(hFile, &v8, 1);
        pGlyph->yOffset = (int8_t)v8;
        dwMain_pHS->fileRead(hFile, &v8, 1);
        pGlyph->field_7 = (int8_t)v8;
        dwMain_pHS->fileRead(hFile, &v32, 4);
        pGlyph->width = (int32_t)v32;
        dwMain_pHS->fileRead(hFile, &v32, 4);
        pGlyph->height = (uint16_t)v32; // dword store in the binary covers the pad too
        pGlyph->pad_12 = (uint16_t)(v32 >> 16);
        pGlyph->loadedFlag = 1;
        pGlyph->pPixels = pFont->pPixelData + pGlyph->pixelOffset;
        if (pGlyph->yOffset < minYOffset)
            minYOffset = pGlyph->yOffset;
        if (maxYOffset < pGlyph->yOffset)
            maxYOffset = pGlyph->yOffset;
    }
    (void)minYOffset;
    (void)maxYOffset;

    dwMain_pHS->fileRead(hFile, pFont->pPixelData, pixelDataSize);
    dwMain_pHS->fileClose(hFile);
    return pFont;
}

// @448390
int dwFont_GetCharWidth(dwFont* pFont, char ch)
{
    int c = ch; // sign-extends; chars >= 0x80 fall outside the range
    int firstChar = pFont->pHeader->firstChar;
    if (c >= firstChar && c <= pFont->pHeader->lastChar)
    {
        return pFont->paGlyphs[c - firstChar].advanceWidth;
    }
    return 0;
}

// @4483c0 — len 0 measures the whole string; stops early at NUL.
int dwFont_MeasureString(dwFont* pFont, const char* pStr, int len)
{
    if (len == 0)
        len = (int)strlen(pStr);

    int width = 0;
    while (len != 0)
    {
        len--;
        if (*pStr == '\0')
            break;
        width += dwFont_GetCharWidth(pFont, *pStr);
        pStr++;
    }
    return width;
}

// ------------------------------------------------------------------
// Glyph blits

// @448410 — unclipped 8bpp glyph blit; advances pPos->x by the advance width.
void dwFont_DrawGlyph8(dwFont* pFont, dwImageBits* pBits, dwPoint* pPos, char ch, uint8_t color)
{
    int c = ch;
    int firstChar = pFont->pHeader->firstChar;
    if (c < firstChar || c > pFont->pHeader->lastChar)
        return;

    dwFontGlyph* pGlyph = &pFont->paGlyphs[c - firstChar];
    int stride = pBits->stride;
    uint8_t* pSrc = pGlyph->pPixels;
    uint8_t* pDst = (uint8_t*)pBits->pPixels + (pGlyph->yOffset + pPos->y) * stride + pGlyph->xOffset + pPos->x;
    int width = pGlyph->width;

    if (pGlyph->height != 0)
    {
        for (int rows = pGlyph->height; rows != 0; rows--)
        {
            if ((int16_t)pGlyph->width != 0)
            {
                for (int n = (int16_t)pGlyph->width; n != 0; n--)
                {
                    uint8_t s = *pSrc++;
                    if (s != 0)
                    {
                        uint8_t out = color;
                        if (s != 0xff)
                        {
                            if (s == 1)
                            {
                                out = ((uint8_t*)rdColormap_pCurMap->transparency)[(unsigned int)color * 0x100 + *pDst];
                            }
                            else
                            {
                                out = s; // any other byte is written raw
                                if (s == 2)
                                    out = ((uint8_t*)rdColormap_pCurMap->transparency)[(unsigned int)*pDst * 0x100 + color];
                            }
                        }
                        *pDst = out;
                    }
                    pDst++;
                }
            }
            pDst += stride - width;
        }
    }
    pPos->x += pGlyph->advanceWidth;
}

// @448520 — 16bpp stub (empty in the binary).
void dwFont_DrawGlyph16(dwFont* pFont, dwImageBits* pBits, dwPoint* pPos, char ch, uint8_t color)
{
    (void)pFont; (void)pBits; (void)pPos; (void)ch; (void)color;
}

// @448530 — bpp dispatch.
void dwFont_DrawGlyph(dwFont* pFont, dwImageBits* pBits, dwPoint* pPos, char ch, uint8_t color)
{
    uint8_t v = (uint8_t)(pBits->pDesc->bpp << 3); // low 5 bits of bpp
    if (v == 8)
        dwFont_DrawGlyph8(pFont, pBits, pPos, ch, color);
    else if (v == 0x10)
        dwFont_DrawGlyph16(pFont, pBits, pPos, ch, color);
}

// @448580 — clipped 8bpp glyph blit; advances pPos->x, then clamps it to
// pClip->right.
void dwFont_DrawGlyphClipped8(dwFont* pFont, dwImageBits* pBits, dwPoint* pPos, char ch, uint8_t color, dwRect* pClip)
{
    int c = ch;
    int firstChar = pFont->pHeader->firstChar;
    if (c < firstChar || c > pFont->pHeader->lastChar)
        return;

    dwFontGlyph* pGlyph = &pFont->paGlyphs[c - firstChar];
    int16_t glyphTop = (int16_t)(pPos->y + pGlyph->yOffset);
    uint8_t* pSrc = pGlyph->pPixels;
    int16_t drawHeight = (int16_t)pGlyph->height;

    int16_t d = (int16_t)(pClip->top - glyphTop);
    if (d > 0)
    {
        pSrc += pGlyph->width * d;
        drawHeight -= d;
        glyphTop = pClip->top;
    }
    d = (int16_t)((drawHeight - pClip->bottom) + glyphTop);
    if (d > 0)
        drawHeight -= d;

    if (drawHeight > 0)
    {
        int16_t glyphLeft = (int16_t)(pGlyph->xOffset + pPos->x);
        int16_t drawWidth = (int16_t)pGlyph->width;

        d = (int16_t)(pClip->left - glyphLeft);
        if (d > 0)
        {
            pSrc += d;
            drawWidth -= d;
            glyphLeft = pClip->left;
        }
        d = (int16_t)((drawWidth - pClip->right) + glyphLeft);
        if (d > 0)
            drawWidth -= d;

        if (drawWidth > 0)
        {
            int stride = pBits->stride;
            uint8_t* pDst = (uint8_t*)pBits->pPixels + glyphTop * stride + glyphLeft;
            int srcStride = pGlyph->width;
            for (int rows = drawHeight; rows != 0; rows--)
            {
                for (int n = drawWidth; n != 0; n--)
                {
                    uint8_t s = *pSrc++;
                    if (s != 0)
                    {
                        uint8_t out = color;
                        if (s != 0xff)
                        {
                            if (s == 1)
                            {
                                out = ((uint8_t*)rdColormap_pCurMap->transparency)[(unsigned int)color * 0x100 + *pDst];
                            }
                            else
                            {
                                out = s;
                                if (s == 2)
                                    out = ((uint8_t*)rdColormap_pCurMap->transparency)[(unsigned int)*pDst * 0x100 + color];
                            }
                        }
                        *pDst = out;
                    }
                    pDst++;
                }
                pSrc += srcStride - drawWidth;
                pDst += stride - drawWidth;
            }
        }
    }

    pPos->x += pGlyph->advanceWidth;
    if (pClip->right < pPos->x)
        pPos->x = pClip->right;
}

// @448730 — 16bpp stub (empty in the binary).
void dwFont_DrawGlyphClipped16(dwFont* pFont, dwImageBits* pBits, dwPoint* pPos, char ch, uint8_t color, dwRect* pClip)
{
    (void)pFont; (void)pBits; (void)pPos; (void)ch; (void)color; (void)pClip;
}

// @448740 — bpp dispatch.
void dwFont_DrawGlyphClipped(dwFont* pFont, dwImageBits* pBits, dwPoint* pPos, char ch, uint8_t color, dwRect* pClip)
{
    uint8_t v = (uint8_t)(pBits->pDesc->bpp << 3);
    if (v == 8)
        dwFont_DrawGlyphClipped8(pFont, pBits, pPos, ch, color, pClip);
    else if (v == 0x10)
        dwFont_DrawGlyphClipped16(pFont, pBits, pPos, ch, color, pClip);
}

// ------------------------------------------------------------------
// Layout

// @448850 — number of chars of pStr (up to '\n'/NUL) that fit in maxWidth px;
// backs up to the previous whitespace while the line overflows. Note: the
// binary uses the CRT ctype isspace here.
int dwFont_FindLineBreak(dwFont* pFont, const char* pStr, unsigned int maxWidth)
{
    const char* pScan = pStr;
    while (*pScan != '\0' && *pScan != '\n')
        pScan++;

    int len = (int)(pScan - pStr);
    unsigned int width = (unsigned int)dwFont_MeasureString(pFont, pStr, len);
    while (width > maxWidth)
    {
        while (pScan > pStr && !isspace((unsigned char)*pScan))
            pScan--;
        if (pScan == pStr)
            break;
        len = (int)(pScan - pStr);
        width = (unsigned int)dwFont_MeasureString(pFont, pStr, len);
        pScan--;
    }
    return len;
}

// @448790 — word-wrap up to maxChars into pRect's width. *pOut ends at
// (left + width of the final partial line, top + summed line heights); the
// bpp inset added up front is subtracted again at the end (faithful).
void dwFont_MeasureWrappedExtent(dwPoint* pOut, dwFont* pFont, dwRect* pRect, const char* pStr, unsigned int maxChars)
{
    pOut->x = pRect->left;
    pOut->y = pRect->top;
    pOut->y += (int16_t)pFont->pHeader->bpp;
    int maxWidth = (int16_t)(pRect->right - pRect->left);

    const char* pWalk = pStr;
    unsigned int remaining = maxChars;
    // NOTE (faithful): the loop re-tests the FIRST char of the original
    // string, not the walker.
    while (*pStr != '\0' && remaining != 0)
    {
        unsigned int lineLen = (unsigned int)dwFont_FindLineBreak(pFont, pWalk, (unsigned int)maxWidth);
        if (lineLen == 0 || lineLen >= remaining)
        {
            pOut->x += (int16_t)dwFont_MeasureString(pFont, pWalk, (int)remaining);
            remaining = 0;
        }
        else
        {
            const char* pNext = pWalk + lineLen;
            pOut->y += (int16_t)pFont->pHeader->lineHeight;
            while (*pNext != '\0' && isspace((unsigned char)*pNext))
                pNext++;
            remaining -= (unsigned int)(pNext - pWalk);
            pWalk = pNext;
        }
    }
    pOut->y -= (int16_t)pFont->pHeader->bpp;
}

// ------------------------------------------------------------------
// String draws

// @4488c0 — single-line draw at *pPos (not advanced), truncated at both ends
// against the clipped bounds with a 2x'W'-width soft margin. When the line is
// vertically clipped it falls back to a plain clipped glyph walk.
void dwFont_DrawStringClipped(dwImageBits* pBits, dwFont* pFont, dwPoint* pPos, const char* pStr, uint8_t color, dwRect* pClip)
{
    if (!pStr)
        return;

    dwRect bounds;
    bounds.left = 0;
    bounds.top = 0;
    bounds.right = (int16_t)pBits->pDesc->width;
    bounds.bottom = (int16_t)pBits->pDesc->height;
    if (pClip)
        dwRect_Clip(&bounds, pClip);

    dwPoint cursor = *pPos;
    if ((int16_t)(cursor.y - (int16_t)pFont->pHeader->bpp) < bounds.top
        || bounds.bottom <= (int16_t)((int16_t)pFont->pHeader->field_C + cursor.y))
    {
        // Vertically clipped: plain clipped walk.
        while (*pStr != '\0' && cursor.x < bounds.right)
        {
            dwFont_DrawGlyphClipped(pFont, pBits, &cursor, *pStr, color, &bounds);
            pStr++;
        }
        return;
    }

    int16_t wWidth = (int16_t)dwFont_GetCharWidth(pFont, 'W');

    // Phase 1: fast-skip glyphs fully left of bounds.left - 2*'W'.
    while (*pStr != '\0')
    {
        if ((int)bounds.left - 2 * wWidth <= (int)cursor.x)
            break;
        cursor.x += (int16_t)dwFont_GetCharWidth(pFont, *pStr);
        pStr++;
    }
    // Phase 2: clipped draw across the left edge.
    while (*pStr != '\0' && cursor.x < bounds.left)
    {
        dwFont_DrawGlyphClipped(pFont, pBits, &cursor, *pStr, color, &bounds);
        pStr++;
    }
    // Phase 3: unclipped draw through the middle.
    while (*pStr != '\0')
    {
        if (bounds.right - 2 * wWidth <= (int)cursor.x)
            break;
        dwFont_DrawGlyph(pFont, pBits, &cursor, *pStr, color);
        pStr++;
    }
    // Phase 4: clipped draw across the right edge.
    while (*pStr != '\0' && cursor.x < bounds.right)
    {
        dwFont_DrawGlyphClipped(pFont, pBits, &cursor, *pStr, color, &bounds);
        pStr++;
    }
}

// @448a60 — word-wrapped multiline draw into pRect (clipped additionally by
// pClip); bCentered centers each line horizontally.
void dwFont_DrawTextWrapped(dwImageBits* pBits, dwFont* pFont, dwRect* pRect, const char* pStr, uint8_t color, dwRect* pClip, int bCentered)
{
    if (!pStr)
        return;

    dwRect bounds;
    bounds.left = 0;
    bounds.top = 0;
    bounds.right = (int16_t)pBits->pDesc->width;
    bounds.bottom = (int16_t)pBits->pDesc->height;
    dwRect_Clip(&bounds, pRect);
    if (pClip)
        dwRect_Clip(&bounds, pClip);

    dwPoint cursor;
    cursor.x = pRect->left;
    cursor.y = (int16_t)(pRect->top + (int16_t)pFont->pHeader->bpp);
    int maxWidth = (int16_t)(pRect->right - pRect->left);

    while (*pStr != '\0')
    {
        int lineLen = dwFont_FindLineBreak(pFont, pStr, (unsigned int)maxWidth);
        int lineWidth = dwFont_MeasureString(pFont, pStr, lineLen);
        if (bCentered)
            cursor.x += (int16_t)(maxWidth - lineWidth) / 2;

        for (; lineLen != 0; lineLen--)
        {
            dwFont_DrawGlyphClipped(pFont, pBits, &cursor, *pStr, color, &bounds);
            pStr++;
        }
        cursor.x = pRect->left;
        cursor.y += (int16_t)pFont->pHeader->lineHeight;
        while (*pStr != '\0' && isspace((unsigned char)*pStr))
            pStr++;
    }
}

// @448b90 — word-wrapped multiline draw with per-line x alignment:
// 1 = shift left by the free width, 2 = right-align, 3 = center.
void dwFont_DrawTextAligned(dwImageBits* pBits, dwFont* pFont, dwRect* pRect, const char* pStr, uint8_t color, dwRect* pClip, int align)
{
    if (!pStr)
        return;

    dwRect bounds;
    bounds.left = 0;
    bounds.top = 0;
    bounds.right = (int16_t)pBits->pDesc->width;
    bounds.bottom = (int16_t)pBits->pDesc->height;
    dwRect_Clip(&bounds, pRect);
    if (pClip)
        dwRect_Clip(&bounds, pClip);

    dwPoint cursor;
    cursor.x = pRect->left;
    cursor.y = (int16_t)(pRect->top + (int16_t)pFont->pHeader->bpp);
    int maxWidth = (int16_t)(pRect->right - pRect->left);

    while (*pStr != '\0')
    {
        int lineLen = dwFont_FindLineBreak(pFont, pStr, (unsigned int)maxWidth);
        int16_t lineWidth = (int16_t)dwFont_MeasureString(pFont, pStr, lineLen);
        switch (align)
        {
        case 1:
            cursor.x += (int16_t)((lineWidth + pRect->left) - pRect->right);
            break;
        case 2:
            cursor.x += (int16_t)((pRect->right - pRect->left) - lineWidth);
            break;
        case 3:
            cursor.x += (int16_t)((pRect->right - pRect->left) - lineWidth) / 2;
            break;
        }

        for (; lineLen != 0; lineLen--)
        {
            dwFont_DrawGlyphClipped(pFont, pBits, &cursor, *pStr, color, &bounds);
            pStr++;
        }
        cursor.x = pRect->left;
        cursor.y += (int16_t)pFont->pHeader->lineHeight;
        while (*pStr != '\0' && isspace((unsigned char)*pStr))
            pStr++;
    }
}

// @448d00
void dwFont_DrawText(dwImageBits* pBits, dwFont* pFont, dwRect* pRect, const char* pStr, uint8_t color, dwRect* pClip)
{
    dwFont_DrawTextWrapped(pBits, pFont, pRect, pStr, color, pClip, 0);
}

// @448d30
void dwFont_DrawTextCentered(dwImageBits* pBits, dwFont* pFont, dwRect* pRect, const char* pStr, uint8_t color, dwRect* pClip)
{
    dwFont_DrawTextWrapped(pBits, pFont, pRect, pStr, color, pClip, 1);
}
