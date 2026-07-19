#ifndef _DWFONT_H
#define _DWFONT_H

// dwFont — DroidWorks bitmap-font module: loads/caches `<name>.laf` fonts and
// measures, word-wraps, and draws text onto a locked 8bpp image surface
// (16bpp glyph draws are no-op stubs in the binary).
//
// A loaded font lives in ONE cached heap block laid out as
//   [name\0][u32 numGlyphs][dwFontHeader 0x30][u16 charMap[n]][dwFontGlyph[n]][pixels]
// keyed by name in dwFont_pCache; the dwFont handle just points into it.
//
// Glyph pixels: 0 = transparent, 0xff = solid draw color, 1 = blend the draw
// color over the dest, 2 = blend the dest over the draw color (both via the
// current colormap's transparency table); any other byte is written raw.
//
// Ghidra (DroidWorks.exe) 0x447f20-0x448d5x, 18 functions (see the
// per-function @addresses below). Genuinely-C unit: the glyph/measure entry
// points are __thiscall over the plain dwFont handle struct, but there are no
// ctors/dtors/vtables/EH frames — translated as pure C with the handle as the
// explicit first parameter.

#include "Dw/dwTypes.h"
#include "Dw/dwRect.h"

#ifdef __cplusplus
extern "C" {
#endif

// Owned by the dwImage unit (src/Dw/dwImage.h); repeating the typedef here is
// valid C11/C++ and keeps this header self-contained.
typedef struct dwImageBits dwImageBits;
// Owned by General/stdHashtbl.h.
typedef struct tHashTable tHashTable;

// On-disk-ordered font header (0x30). Staged from the first dwords of the
// .laf file; minYOffset/maxYOffset are ALWAYS 0 — the loader tracks them in
// locals but never stores them (faithful to the binary).
typedef struct dwFontHeader
{
    uint32_t field_0;    // 0x00: never written (zeroed)
    uint32_t lineHeight; // 0x04: line advance for wrapped draws
    uint32_t bpp;        // 0x08: 1|2; the low byte doubles as the first-line top y-inset
    uint32_t field_C;    // 0x0c: text cell height (used by DrawStringClipped's vertical test)
    uint32_t field_10;   // 0x10: unused here (4th header dword from the file)
    int32_t minYOffset;  // 0x14: always 0 (see above)
    int32_t maxYOffset;  // 0x18: always 0 (see above)
    int32_t firstChar;   // 0x1c: first glyph's char code (file value & 0xff)
    int32_t lastChar;    // 0x20: last glyph's char code (file value & 0xff)
    uint32_t reserved[3];// 0x24: zeroed
} dwFontHeader; // 0x30

typedef struct dwFontGlyph
{
    uint32_t pixelOffset; // 0x00: offset into the font's pixel data
    int8_t advanceWidth;  // 0x04
    int8_t xOffset;       // 0x05
    int8_t yOffset;       // 0x06: signed baseline offset
    int8_t field_7;       // 0x07
    uint8_t* pPixels;     // 0x08: absolute pointer (pPixelData + pixelOffset)
    int32_t width;        // 0x0c: pixel width == row stride in the glyph data
    uint16_t height;      // 0x10
    uint16_t pad_12;      // 0x12: high half of the height dword from the file
    int32_t loadedFlag;   // 0x14: set to 1 by the loader
} dwFontGlyph; // 0x18

// The user-held handle (0x10): four pointers into the shared cached block.
typedef struct dwFont
{
    dwFontHeader* pHeader;
    uint16_t* paCharMap;
    dwFontGlyph* paGlyphs;
    uint8_t* pPixelData;
} dwFont;

// name -> cached font block (binary: 0x541d38).
extern tHashTable* dwFont_pCache;

// @447f20 — creates the cache; returns nonzero on success.
int dwFont_Startup();
// @447f40 — frees every cached font block, then the cache itself.
void dwFont_Shutdown();

// @447fa0 — fill *pFont for pName (loads "<pName>.laf" via dwMain_pHS on a
// cache miss). On failure the handle's pointers stay NULL. Returns pFont.
dwFont* dwFont_Load(dwFont* pFont, const char* pName);

// @448390 — advance width of ch (0 when outside [firstChar, lastChar]).
int dwFont_GetCharWidth(dwFont* pFont, char ch);
// @4483c0 — summed advance of up to len chars (len 0 = strlen), stops at NUL.
int dwFont_MeasureString(dwFont* pFont, const char* pStr, int len);

// @448410 / @448520 / @448530 — draw one glyph at *pPos (unclipped) and
// advance pPos->x; the plain entry dispatches on the surface bpp.
void dwFont_DrawGlyph8(dwFont* pFont, dwImageBits* pBits, dwPoint* pPos, char ch, uint8_t color);
void dwFont_DrawGlyph16(dwFont* pFont, dwImageBits* pBits, dwPoint* pPos, char ch, uint8_t color); // no-op stub
void dwFont_DrawGlyph(dwFont* pFont, dwImageBits* pBits, dwPoint* pPos, char ch, uint8_t color);

// @448580 / @448730 / @448740 — clipped variant; also clamps pPos->x to
// pClip->right after advancing.
void dwFont_DrawGlyphClipped8(dwFont* pFont, dwImageBits* pBits, dwPoint* pPos, char ch, uint8_t color, dwRect* pClip);
void dwFont_DrawGlyphClipped16(dwFont* pFont, dwImageBits* pBits, dwPoint* pPos, char ch, uint8_t color, dwRect* pClip); // no-op stub
void dwFont_DrawGlyphClipped(dwFont* pFont, dwImageBits* pBits, dwPoint* pPos, char ch, uint8_t color, dwRect* pClip);

// @448790 — word-wrap up to maxChars of pStr into pRect's width; *pOut gets
// (left + last-line width, top + summed line heights).
void dwFont_MeasureWrappedExtent(dwPoint* pOut, dwFont* pFont, dwRect* pRect, const char* pStr, unsigned int maxChars);
// @448850 — chars of pStr (up to '\n'/NUL) that fit in maxWidth px, backing
// up to the previous whitespace when the line overflows.
int dwFont_FindLineBreak(dwFont* pFont, const char* pStr, unsigned int maxWidth);

// @4488c0 — single-line draw at *pPos, truncated at both ends against pClip
// with a 2x'W'-width soft margin (used by scrolling name fields).
void dwFont_DrawStringClipped(dwImageBits* pBits, dwFont* pFont, dwPoint* pPos, const char* pStr, uint8_t color, dwRect* pClip);

// @448a60 — word-wrapped multiline draw into pRect (bCentered: center each
// line); @448b90 — same with align 1/2/3 x-adjust per line; @448d00/@448d30
// — DrawTextWrapped wrappers (left / centered).
void dwFont_DrawTextWrapped(dwImageBits* pBits, dwFont* pFont, dwRect* pRect, const char* pStr, uint8_t color, dwRect* pClip, int bCentered);
void dwFont_DrawTextAligned(dwImageBits* pBits, dwFont* pFont, dwRect* pRect, const char* pStr, uint8_t color, dwRect* pClip, int align);
void dwFont_DrawText(dwImageBits* pBits, dwFont* pFont, dwRect* pRect, const char* pStr, uint8_t color, dwRect* pClip);
void dwFont_DrawTextCentered(dwImageBits* pBits, dwFont* pFont, dwRect* pRect, const char* pStr, uint8_t color, dwRect* pClip);

#ifdef __cplusplus
}
#endif

#endif // _DWFONT_H
