// dwGuiHypText — the DroidWorks base rich/hyperlinked-text control:
// dwGuiHypText (+ its inline animation elements T/S/W and the ten stock
// format callbacks) and the dwGuiPartText (PARTTEXT) subclass.
//
// Decompiled from DroidWorks.exe range 0x437d60-0x439150 (callbacks
// 0x437d60-0x438140, elements 0x438150-0x43853x, dwGuiHypText
// 0x438540-0x43904x, dwGuiPartText 0x439050-0x439150). vtables:
// dwGuiHypText_vtbl @0x51fc00 (19 slots: dwWidget's 18 + the new +0x48
// SetText), dwGuiPartText_vtbl @0x51fc50, elements @0x51fbb0/0x51fbe0/
// 0x51fbf0 (3 slots each). See Dw/dwGuiHypText.h for the class map.
//
// Translation notes:
//  - The line-run ring is hand-rolled (dwGuiHypTextRun) because the binary's
//    nodes carry the payload INLINE (0x24 bytes) — dwList only handles the
//    0xc pData nodes (still used for the element list).
//  - The binary's __ftol truncates toward zero; the reveal/scroll offsets are
//    computed as x + 0.5 (FSUB of a -0.5 double) before the truncation, i.e.
//    round-half-up for positive values. Mirrored with double math + C casts.
//  - dwGuiPartText's part-name lookups use the real dwPart layouts (P5,
//    Dw/dwPart.h); the 0xBBC sender is viewed via dwMissionInfoView until
//    dwGuiMission (P6) lands the real record — see the view's TODO below.
//  - ctype calls (toupper/isdigit/isspace) use the (unsigned char) cast per
//    the dwFont.c/dwConfFile.cpp precedent; the binary sign-extended the
//    char into the CRT table lookups.
//
// No module statics — no dwGuiHypText_Startup needed (soft-reset rule).

#include "Dw/dwGuiHypText.h"

#include "Dw/dwColormap.h"

#include "jk.h"
#include "stdPlatform.h"

#include <ctype.h>

#include "Dw/dwPart.h" // dwPart blueprint records + dwPart_FindBlueprint (P5)

// The 0xBBC part-selection broadcast's SENDER is a dwMissionInfo record
// (owner: dwGuiMission, P6 — dwMission_ParseInfo @41c530 parses it). Only a
// read-only view is declared here, with the record's leading members in
// BINARY ORDER (offsets are the 32-bit binary's).
// TODO(dw-decomp): replace with the real dwMissionInfo when dwGuiMission
// (P6) lands — that unit MUST declare these leading members in this order
// (dwGuiDroidPreview's 0xBBC handler reads the same two fields).
typedef struct dwMissionInfoView
{
    int32_t bValid;             // 0x00
    int32_t missionType;        // 0x04: DEPLOYMENT=5/SECRET=1/FINAL=2/CRYSTAL=3/TGROUND=4
    uint8_t rewardIdx;          // 0x08: selected REWARD slot (read as a byte,
                                //       clamped to 2; Ghidra leaves it unnamed)
    dwString name;              // 0x0c: record id
    dwString displayName;       // 0x18: NAME keyword
    dwString briefing;          // 0x24: BRIEFING keyword
    dwString aRequirements[3];  // 0x30: REQUIREMENT keyword
    dwString voiceover;         // 0x54: VOICEOVER keyword
    dwPoint mapPoint;           // 0x60: DEPLOYMENT map point
    dwList objectives;          // 0x64: objective records
    dwString aRewardParts[3];   // 0x68: REWARD part blueprint names
} dwMissionInfoView;

// ---- line-run ring helpers (binary: inlined at every use site) --------------

// Append a run for [pStr, pStr+len) at the ring tail, measuring its pixel
// width. drawLen/drawX start 0 (Layout resets them after alignment).
static void dwGuiHypText_AppendRun(dwGuiHypTextRun** ppRuns, char* pStr, int len, dwFont* pFont)
{
    dwGuiHypTextRun* pRun;
    dwGuiHypTextRun* pTail;

    pRun = new dwGuiHypTextRun;
    pRun->startChar = 0;
    pRun->drawLen = 0;
    pRun->drawX = 0;
    pRun->pStr = pStr;
    pRun->len = len;
    pRun->width = dwFont_MeasureString(pFont, pStr, len);
    pRun->xOffset = 0;

    pTail = (*ppRuns)->pPrev;
    pRun->pNext = pTail->pNext;
    pRun->pPrev = pTail;
    pTail->pNext = pRun;
    pRun->pNext->pPrev = pRun;
}

// Unlink + free every run node, leaving the sentinel self-linked (binary:
// dwList_FreeNodeRange / per-node UnlinkNode+free, inlined).
static void dwGuiHypText_FreeRunNodes(dwGuiHypTextRun* pSentinel)
{
    dwGuiHypTextRun* pRun;
    dwGuiHypTextRun* pNext;

    pRun = pSentinel->pNext;
    while (pRun != pSentinel)
    {
        pNext = pRun->pNext;
        pRun->pPrev->pNext = pNext;
        pNext->pPrev = pRun->pPrev;
        pRun->pNext = NULL;
        pRun->pPrev = NULL;
        delete pRun;
        pRun = pNext;
    }
}

// ---- stock format callbacks -------------------------------------------------

// @437d60 (dwGuiHypText_WrapNone) — the whole string (embedded '\n' and all)
// as ONE run; the width parameter is ignored.
void dwGuiHypText_WrapNone(dwString* pText, dwFont* pFont, int width, dwGuiHypTextRun** ppRuns)
{
    (void)width;
    dwGuiHypText_AppendRun(ppRuns, pText->pBuffer, (int)pText->length, pFont);
}

// @437de0 (dwGuiHypText_WrapWords) — greedy word wrap: accumulate glyph
// widths until the line overflows (or '\n'/NUL), back up to the previous
// whitespace (a single over-long word at line start is instead extended to
// the next whitespace), emit the run, skip the inter-word whitespace.
// Note: the back-up scan is translated pointer-for-pointer — including the
// binary's quirk of probing one byte BEFORE the string buffer when an
// over-long word sits at the very start of the text (benign heap read; the
// escape path can emit a length -1 run exactly like the original).
void dwGuiHypText_WrapWords(dwString* pText, dwFont* pFont, int width, dwGuiHypTextRun** ppRuns)
{
    char* pLine;
    char* pEnd;
    char* pScan;
    char c;
    int lineWidth;
    int bSpace;

    pLine = pText->pBuffer;
    c = *pLine;
    while (c != '\0')
    {
        lineWidth = 0;
        pEnd = pLine;
        if (width >= 0)
        {
            do
            {
                c = *pEnd;
                if (c == '\0' || c == '\n')
                    break;
                lineWidth += dwFont_GetCharWidth(pFont, c);
                pEnd++;
            } while (lineWidth <= width);
        }
        if (lineWidth > width)
        {
            // Back up to the whitespace before the overflowing char.
            bSpace = isspace((unsigned char)pEnd[-1]);
            pScan = pEnd;
            for (;;)
            {
                pEnd = pScan - 1;
                if (bSpace != 0)
                    break;
                if (pEnd < pLine)
                    goto emit_run; // quirk preserved (see the function note)
                bSpace = isspace((unsigned char)pScan[-2]);
                pScan = pEnd;
            }
            if (pEnd == pLine)
            {
                // Single word wider than the line: emit it whole.
                c = *pEnd;
                while (c != '\0' && !isspace((unsigned char)*pEnd))
                {
                    c = pEnd[1];
                    pEnd++;
                }
            }
        }
emit_run:
        dwGuiHypText_AppendRun(ppRuns, pLine, (int)(pEnd - pLine), pFont);
        // Skip the whitespace run to the next word.
        c = *pEnd;
        while (c != '\0' && isspace((unsigned char)*pEnd))
        {
            c = pEnd[1];
            pEnd++;
        }
        c = *pEnd;
        pLine = pEnd;
    }
}

// @437f10
void dwGuiHypText_HAlignLeft(dwGuiHypTextRun* pRun, int width)
{
    (void)width;
    pRun->xOffset = 0;
}

// @437f20
void dwGuiHypText_HAlignRight(dwGuiHypTextRun* pRun, int width)
{
    pRun->xOffset = (int16_t)((int16_t)width - (int16_t)pRun->width);
}

// @437f40 — 16-bit difference, then a signed integer halving.
void dwGuiHypText_HAlignCenter(dwGuiHypTextRun* pRun, int width)
{
    pRun->xOffset = (int16_t)((int16_t)((int16_t)width - (int16_t)pRun->width) / 2);
}

// @437f60
int dwGuiHypText_VAlignTop(dwGuiHypTextRun** ppRuns, dwFont* pFont, dwRect* pRect)
{
    (void)ppRuns;
    (void)pFont;
    (void)pRect;
    return 0;
}

// @437f90 — rect height minus (line height x run count). Note: only the low
// 16 bits of the return are meaningful (the binary leaves garbage above
// them; both consumers truncate to short).
int dwGuiHypText_VAlignBottom(dwGuiHypTextRun** ppRuns, dwFont* pFont, dwRect* pRect)
{
    dwGuiHypTextRun* pSentinel;
    dwGuiHypTextRun* pRun;
    int totalHeight;

    totalHeight = 0;
    pSentinel = *ppRuns;
    for (pRun = pSentinel->pNext; pRun != pSentinel; pRun = pRun->pNext)
    {
        totalHeight += (int)pFont->pHeader->lineHeight;
    }
    return (int16_t)(pRect->bottom - pRect->top) - totalHeight;
}

// @437f70
int dwGuiHypText_VAlignCenter(dwGuiHypTextRun** ppRuns, dwFont* pFont, dwRect* pRect)
{
    return (int16_t)dwGuiHypText_VAlignBottom(ppRuns, pFont, pRect) / 2;
}

// @437fe0 (dwGuiHypText_DrawGlyphsNormal) — draw drawLen glyphs starting at
// pStr + startChar; *pPos is advanced per glyph by dwFont.
void dwGuiHypText_DrawGlyphsNormal(dwImageBits* pBits, dwPoint* pPos, dwFont* pFont, uint8_t color, dwGuiHypTextRun* pRun, dwRect* pClip)
{
    char* pCh;
    int count;

    pCh = pRun->pStr + pRun->startChar;
    for (count = pRun->drawLen; count != 0; count--)
    {
        if (pClip == NULL)
            dwFont_DrawGlyph(pFont, pBits, pPos, *pCh, color);
        else
            dwFont_DrawGlyphClipped(pFont, pBits, pPos, *pCh, color, pClip);
        pCh++;
    }
}

// @438070 (dwGuiHypText_DrawGlyphsShadow) — per glyph, first a shadow copy
// offset (+1,+1) in the colormap's transparent/black index, then the normal
// glyph on top (both positions advance in step).
void dwGuiHypText_DrawGlyphsShadow(dwImageBits* pBits, dwPoint* pPos, dwFont* pFont, uint8_t color, dwGuiHypTextRun* pRun, dwRect* pClip)
{
    dwPoint shadowPos;
    char* pCh;
    int count;
    uint8_t shadowColor;

    shadowColor = (uint8_t)dwColormap_transparentIdx;
    count = pRun->drawLen;
    shadowPos.x = (int16_t)(pPos->x + 1);
    shadowPos.y = (int16_t)(pPos->y + 1);
    pCh = pRun->pStr + pRun->startChar;
    for (; count != 0; count--)
    {
        if (pClip == NULL)
            dwFont_DrawGlyph(pFont, pBits, &shadowPos, *pCh, shadowColor);
        else
            dwFont_DrawGlyphClipped(pFont, pBits, &shadowPos, *pCh, shadowColor, pClip);
        if (pClip == NULL)
            dwFont_DrawGlyph(pFont, pBits, pPos, *pCh, color);
        else
            dwFont_DrawGlyphClipped(pFont, pBits, pPos, *pCh, color, pClip);
        pCh++;
    }
}

// ---- inline elements ---------------------------------------------------------

// @438170 (dwGuiHypText_Elem_DtorDelete — the scalar-deleting dtor shared by
// all three element vtables; the base dtor body is empty).
dwGuiHypTextElem::~dwGuiHypTextElem()
{
}

// @438150 (dwGuiHypText_ElemT_Ctor)
dwGuiHypText_ElemT::dwGuiHypText_ElemT(float revealDuration)
{
    this->revealDuration = revealDuration;
    this->accumTime = 0.0f;
    this->totalLen = 0;
    this->curReveal = 0;
}

// vtbl +0x04 @438190 (dwGuiHypText_ElemT_Update) — reveal
// round(totalLen * min(accumTime / revealDuration, 1)) chars, distributed
// front-to-back across the runs; repaint only when the count changes.
void dwGuiHypText_ElemT::Update(dwGuiHypText* pOwner, float dt, dwGuiHypTextRun** ppRuns)
{
    dwGuiHypTextRun* pSentinel;
    dwGuiHypTextRun* pRun;
    uint32_t reveal;
    uint32_t runLen;
    float ratio;

    this->accumTime = dt + this->accumTime;
    ratio = this->accumTime / this->revealDuration;
    if (!(ratio <= 1.0f))
        ratio = 1.0f;
    // Note: binary form is __ftol(totalLen * ratio - (-0.5)) — round-half-up.
    reveal = (uint32_t)((double)this->totalLen * (double)ratio + 0.5);
    if (reveal != this->curReveal)
    {
        this->curReveal = reveal;
        pSentinel = *ppRuns;
        for (pRun = pSentinel->pNext; pRun != pSentinel; pRun = pRun->pNext)
        {
            runLen = (uint32_t)pRun->len;
            if (runLen < reveal)
            {
                reveal -= runLen;
                pRun->drawLen = (int32_t)runLen;
            }
            else
            {
                pRun->drawLen = (int32_t)reveal;
                reveal = 0;
            }
        }
        pOwner->Invalidate();
    }
}

// vtbl +0x08 @438250 (dwGuiHypText_ElemT_Layout) — restart the reveal:
// nothing drawn, totalLen re-summed from the fresh runs.
void dwGuiHypText_ElemT::Layout(dwGuiHypText* pOwner, dwGuiHypTextRun** ppRuns, dwFont* pFont)
{
    dwGuiHypTextRun* pSentinel;
    dwGuiHypTextRun* pRun;

    (void)pOwner;
    (void)pFont;
    this->accumTime = 0.0f;
    this->curReveal = 0;
    this->totalLen = 0;
    pSentinel = *ppRuns;
    for (pRun = pSentinel->pNext; pRun != pSentinel; pRun = pRun->pNext)
    {
        this->totalLen += pRun->len;
        pRun->drawLen = 0;
    }
}

// @4382b0 (dwGuiHypText_ElemS_Ctor)
dwGuiHypText_ElemS::dwGuiHypText_ElemS(float speed)
{
    this->accumTime = 0.0f;
    this->speed = speed;
    this->totalWidth = 0;
}

// vtbl +0x04 @4382d0 (dwGuiHypText_ElemS_Update) — marquee: shift every
// run's drawX by round(speed * accumTime) px from the off-screen start edge
// (right edge when scrolling left, -totalWidth when scrolling right); once
// fully off the far side, Clear() the owner's text.
void dwGuiHypText_ElemS::Update(dwGuiHypText* pOwner, float dt, dwGuiHypTextRun** ppRuns)
{
    dwGuiHypTextRun* pSentinel;
    dwGuiHypTextRun* pRun;
    int offset;

    this->accumTime = dt + this->accumTime;
    // Note: binary form is __ftol(speed * accumTime - (-0.5)).
    offset = (int)((double)this->speed * (double)this->accumTime + 0.5);
    if (this->speed >= 0.0f)
        offset -= (int16_t)this->totalWidth;
    else
        offset += (int16_t)(pOwner->layoutRect.right - pOwner->layoutRect.left);

    pSentinel = *ppRuns;
    for (pRun = pSentinel->pNext; pRun != pSentinel; pRun = pRun->pNext)
    {
        pRun->drawX = (int16_t)(pRun->xOffset + (int16_t)offset);
    }

    if (this->speed < 0.0f)
    {
        // Fully off the left edge (full-width totalWidth here, unlike the
        // 16-bit truncation in the offset base — faithful).
        if (this->totalWidth + offset < 0)
            pOwner->Clear();
    }
    else if (this->speed > 0.0f && (int)(int16_t)(pOwner->layoutRect.right - pOwner->layoutRect.left) < offset)
    {
        pOwner->Clear();
    }
    pOwner->Invalidate();
}

// vtbl +0x08 @4383b0 (dwGuiHypText_ElemS_Layout) — restart the scroll;
// totalWidth = the widest run's pixel width.
void dwGuiHypText_ElemS::Layout(dwGuiHypText* pOwner, dwGuiHypTextRun** ppRuns, dwFont* pFont)
{
    dwGuiHypTextRun* pSentinel;
    dwGuiHypTextRun* pRun;

    (void)pOwner;
    (void)pFont;
    this->accumTime = 0.0f;
    this->totalWidth = 0;
    pSentinel = *ppRuns;
    for (pRun = pSentinel->pNext; pRun != pSentinel; pRun = pRun->pNext)
    {
        if (this->totalWidth < pRun->width)
            this->totalWidth = pRun->width;
    }
}

// @438400 (dwGuiHypText_ElemW_Ctor)
dwGuiHypText_ElemW::dwGuiHypText_ElemW(float wipeDuration)
{
    this->accumTime = 0.0f;
    this->wipeDuration = wipeDuration;
}

// vtbl +0x04 @438420 (dwGuiHypText_ElemW_Update) — reveal wipe: while the
// owner's layoutRect has not reached the widget rect, grow it from the
// widget's top-left by accumTime/wipeDuration of the full size (truncating
// __ftol, no rounding bias here), clamped to the widget extent.
void dwGuiHypText_ElemW::Update(dwGuiHypText* pOwner, float dt, dwGuiHypTextRun** ppRuns)
{
    uint16_t w;
    uint16_t h;
    float ratio;

    (void)ppRuns;
    if (pOwner->layoutRect.right != pOwner->right || pOwner->layoutRect.bottom != pOwner->bottom)
    {
        this->accumTime = dt + this->accumTime;
        ratio = this->accumTime / this->wipeDuration;
        w = (uint16_t)(int32_t)((float)(int16_t)(pOwner->right - pOwner->left) * ratio);
        h = (uint16_t)(int32_t)((float)(int16_t)(pOwner->bottom - pOwner->top) * ratio);
        if ((int)w > (int)(int16_t)(pOwner->right - pOwner->left))
            w = (uint16_t)(pOwner->right - pOwner->left);
        if ((int)h > (int)(int16_t)(pOwner->bottom - pOwner->top))
            h = (uint16_t)(pOwner->bottom - pOwner->top);
        pOwner->layoutRect.left = pOwner->left;
        pOwner->layoutRect.top = pOwner->top;
        pOwner->layoutRect.right = (int16_t)(pOwner->left + w);
        pOwner->layoutRect.bottom = (int16_t)(pOwner->top + h);
        pOwner->Invalidate();
    }
}

// vtbl +0x08 @438500 (dwGuiHypText_ElemW_Layout) — restart the wipe: zero
// the owner's layout/clip rect entirely (the first Update tick snaps
// left/top back onto the widget rect).
void dwGuiHypText_ElemW::Layout(dwGuiHypText* pOwner, dwGuiHypTextRun** ppRuns, dwFont* pFont)
{
    (void)ppRuns;
    (void)pFont;
    this->accumTime = 0.0f;
    pOwner->layoutRect.left = 0;
    pOwner->layoutRect.top = 0;
    pOwner->layoutRect.right = 0;
    pOwner->layoutRect.bottom = 0;
}

// ---- dwGuiHypText --------------------------------------------------------------

// Shared head of both ctors (the binary duplicates this inline).
// - The run sentinel is allocated run-sized with uninitialized payload
//   (faithful; only its links are used).
// - The dwFont handle is heap-owned; the binary stored NULL when the 0x10
//   allocation failed — unreachable with new (noted, same as other units).
// - yOffset is left uninitialized by the binary until Layout(); zeroed here.

// @438690 (dwGuiHypText_Ctor) — defaults + "<format>" code-string parse.
// Grammar (verified against the disassembly, constants @0x51fbc0-0x51fbdc):
// a decimal literal accumulates into a float (integer digits via
// acc = digit - acc * -10.0; fractional digits via acc += digit * scale,
// scale *= 0.1 after a '.'; '-' TOGGLES the pending sign, which is re-applied
// after every digit; any other char resets the accumulator) and the next
// letter consumes it. S/T/W append an element only when the value is
// nonzero.
dwGuiHypText::dwGuiHypText(dwRect* pRect, void* pNotify, char* pFontName, uint8_t color, char* pFormat)
    : dwWidget(pRect)
{
    char* p;
    float acc;
    float scale;
    float digit;
    uint8_t bNeg;

    this->pNotify = pNotify;
    this->layoutRect = *pRect;
    this->pFont = NULL;
    this->color = color;
    this->yOffset = 0; // Note: uninitialized in the binary until Layout()
    this->pRuns = new dwGuiHypTextRun; // run-sized sentinel, links only
    this->pRuns->pNext = this->pRuns;
    this->pRuns->pPrev = this->pRuns;
    this->pfnHAlign = dwGuiHypText_HAlignLeft;
    this->pfnVAlign = dwGuiHypText_VAlignTop;
    this->pfnWrap = dwGuiHypText_WrapWords;
    this->pfnDrawGlyphs = dwGuiHypText_DrawGlyphsNormal;
    // (the elements dwList member ctor allocated its own sentinel)

    this->pFont = dwFont_Load(new dwFont, pFontName);

    if (pFormat != NULL && *pFormat != '\0')
    {
        acc = 0.0f;
        scale = 1.0f;
        bNeg = 0;
        for (p = pFormat; *p != '\0'; p++)
        {
            switch (toupper((unsigned char)*p))
            {
            case 'B':
                this->pfnWrap = dwGuiHypText_WrapWords;
                break;
            case 'C':
                this->pfnHAlign = dwGuiHypText_HAlignCenter;
                break;
            case 'D':
                this->pfnWrap = dwGuiHypText_WrapNone;
                break;
            case 'L':
                this->pfnHAlign = dwGuiHypText_HAlignLeft;
                break;
            case 'N':
                this->pfnDrawGlyphs = dwGuiHypText_DrawGlyphsNormal;
                break;
            case 'O':
                this->pfnDrawGlyphs = dwGuiHypText_DrawGlyphsShadow;
                break;
            case 'P':
                this->pfnVAlign = dwGuiHypText_VAlignBottom;
                break;
            case 'R':
                this->pfnHAlign = dwGuiHypText_HAlignRight;
                break;
            case 'U':
                this->pfnVAlign = dwGuiHypText_VAlignTop;
                break;
            case 'V':
                this->pfnVAlign = dwGuiHypText_VAlignCenter;
                break;
            case 'S':
                if (acc != 0.0f)
                    this->elements.InsertAfter(this->elements.pSentinel->pPrev, new dwGuiHypText_ElemS(acc));
                break;
            case 'T':
                if (acc != 0.0f)
                    this->elements.InsertAfter(this->elements.pSentinel->pPrev, new dwGuiHypText_ElemT(acc));
                break;
            case 'W':
                if (acc != 0.0f)
                    this->elements.InsertAfter(this->elements.pSentinel->pPrev, new dwGuiHypText_ElemW(acc));
                break;
            }
            if (!isdigit((unsigned char)*p))
            {
                if (*p == '-')
                {
                    bNeg = !bNeg;
                }
                else if (*p == '.')
                {
                    if (scale == 1.0f)
                        scale = 0.1f;
                }
                else
                {
                    acc = 0.0f;
                    scale = 1.0f;
                    bNeg = 0;
                }
            }
            else
            {
                digit = (float)(*p - '0');
                if (!(scale < 1.0f))
                {
                    acc = digit - acc * -10.0f; // binary's exact expression (== acc * 10 + digit)
                }
                else
                {
                    acc = acc + digit * scale;
                    scale = scale * 0.1f;
                }
                // Re-apply the pending sign after every digit.
                if (bNeg)
                {
                    if (!(acc < 0.0f))
                        acc = -acc;
                }
                else if (acc < 0.0f)
                {
                    acc = -acc;
                }
            }
        }
    }
}

// @438540 (dwGuiHypText_CtorEx) — callback-injection ctor for the CtorEx
// family subclasses (dwGuiTextBlock/dwGuiSpeech/dwGuiBriefLine, later
// units); no format parse, one optional pre-built element appended.
dwGuiHypText::dwGuiHypText(dwRect* pRect, void* pNotify, char* pFontName, uint8_t color,
                           dwGuiHypTextHAlignFn pfnHAlign, dwGuiHypTextVAlignFn pfnVAlign,
                           dwGuiHypTextWrapFn pfnWrap, dwGuiHypTextDrawGlyphsFn pfnDrawGlyphs,
                           dwGuiHypTextElem* pElem)
    : dwWidget(pRect)
{
    this->pNotify = pNotify;
    this->layoutRect = *pRect;
    this->pFont = NULL;
    this->color = color;
    this->yOffset = 0; // Note: uninitialized in the binary until Layout()
    this->pRuns = new dwGuiHypTextRun; // run-sized sentinel, links only
    this->pRuns->pNext = this->pRuns;
    this->pRuns->pPrev = this->pRuns;
    this->pfnHAlign = pfnHAlign;
    this->pfnVAlign = pfnVAlign;
    this->pfnWrap = pfnWrap;
    this->pfnDrawGlyphs = pfnDrawGlyphs;

    this->pFont = dwFont_Load(new dwFont, pFontName);

    if (pElem != NULL)
        this->elements.InsertAfter(this->elements.pSentinel->pPrev, pElem);
}

// @438ac0 (dwGuiHypText_Dtor; scalar-deleting wrapper @438670)
dwGuiHypText::~dwGuiHypText()
{
    dwListNode* pNode;
    dwListNode* pNext;
    dwGuiHypTextElem* pElem;

    if (this->pFont != NULL)
    {
        // @504190: the binary's dwFont handle "dtor" is a lone RET (the
        // glyph block is owned by the dwFont cache) — only the handle
        // allocation is released.
        delete this->pFont;
    }

    // Delete every element through its virtual dtor, freeing the list node
    // first (binary order kept), then the remaining ring + sentinel.
    pNode = this->elements.pSentinel->pNext;
    while (pNode != this->elements.pSentinel)
    {
        pElem = (dwGuiHypTextElem*)pNode->pData;
        pNext = pNode->pNext;
        this->elements.UnlinkFreeNode(pNode);
        if (pElem != NULL)
            delete pElem;
        pNode = pNext;
    }
    this->elements.Free();

    // Line-run ring + its sentinel.
    dwGuiHypText_FreeRunNodes(this->pRuns);
    delete this->pRuns;

    this->text.Free(); // idempotent; the member dtor runs again after this
    // (dwWidget base dtor implicit)
}

// vtbl +0x14 @438c20 (dwGuiHypText_Update) — tick every element (they
// Invalidate the owner themselves when something moved).
void dwGuiHypText::Update(float dt)
{
    dwListNode* pSentinel;
    dwListNode* pNode;

    if (this->bEnabled == 0)
        return;
    pSentinel = this->elements.pSentinel;
    for (pNode = pSentinel->pNext; pNode != pSentinel; pNode = pNode->pNext)
    {
        ((dwGuiHypTextElem*)pNode->pData)->Update(this, dt, &this->pRuns);
    }
}

// vtbl +0x18 @438f10 (recovered fn; Ghidra: dwGuiHypText_sub_438F10) —
// guarded hover notify: only when a pNotify payload was given, dispatch
// { 0x7531, pNotify, 0, NULL } to dwWidget_pDefault and report handled.
int dwGuiHypText::OnHover(int16_t x, int16_t y)
{
    (void)x;
    (void)y;
    if (this->pNotify == NULL)
        return 0;
    return this->OnHoverNotify(this->pNotify); // dispatches + returns 1
}

// vtbl +0x44 @438e20 (dwGuiHypText_Draw)
void dwGuiHypText::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    dwGuiHypTextRun* pRun;
    dwPoint pos;
    dwRect clip;
    int16_t y;

    clip = *pClipRect;
    dwRect_Clip(&clip, &this->layoutRect);
    if ((int16_t)(clip.right - clip.left) == 0 || (int16_t)(clip.bottom - clip.top) == 0)
        return;

    // First baseline: layout top + the font header's top y-inset (the low
    // byte of the header bpp dword — see dwFont.h) + the v-align offset.
    y = (int16_t)(this->layoutRect.top + (int16_t)this->pFont->pHeader->bpp + this->yOffset);
    for (pRun = this->pRuns->pNext; pRun != this->pRuns; pRun = pRun->pNext)
    {
        pos.x = (int16_t)(pRun->drawX + this->layoutRect.left);
        pos.y = y;
        this->pfnDrawGlyphs(pDestBits, &pos, this->pFont, this->color, pRun, &clip);
        y = (int16_t)(pos.y + (int16_t)this->pFont->pHeader->lineHeight);
    }
}

// vtbl +0x48 @438cf0 (dwGuiHypText_SetText) — NEW virtual. Quirk preserved:
// the new text is APPENDED to the current buffer when it differs (callers
// that want a replace Free() the string first — dwGuiPartText, the
// dwGuiAnimView caption builder).
void dwGuiHypText::SetText(char* pText)
{
    if (!dwString_Equals(this->text.pBuffer, pText))
    {
        this->text.Append(pText, 0);
        this->Layout();
    }
}

// @438c80 (dwGuiHypText_Clear) — drop the text and the line runs (element
// state untouched — a following Layout() resets it), repaint.
void dwGuiHypText::Clear()
{
    this->text.Free();
    dwGuiHypText_FreeRunNodes(this->pRuns);
    this->Invalidate(); // vtbl +0x34
}

// @438d20 (dwGuiHypText_Layout) — full reflow.
void dwGuiHypText::Layout()
{
    dwGuiHypTextRun* pRun;
    dwListNode* pNode;

    dwGuiHypText_FreeRunNodes(this->pRuns);
    if (this->text.length == 0)
        return; // note: no Invalidate on the empty-text path (faithful)

    this->pfnWrap(&this->text, this->pFont,
                  (int16_t)(this->layoutRect.right - this->layoutRect.left), &this->pRuns);

    for (pRun = this->pRuns->pNext; pRun != this->pRuns; pRun = pRun->pNext)
    {
        this->pfnHAlign(pRun, (int16_t)(this->layoutRect.right - this->layoutRect.left));
        // Reset the live draw fields from the layout fields.
        pRun->startChar = 0;
        pRun->drawLen = pRun->len;
        pRun->drawX = pRun->xOffset;
    }

    this->yOffset = (int16_t)this->pfnVAlign(&this->pRuns, this->pFont, &this->layoutRect);

    for (pNode = this->elements.pSentinel->pNext; pNode != this->elements.pSentinel; pNode = pNode->pNext)
    {
        ((dwGuiHypTextElem*)pNode->pData)->Layout(this, &this->pRuns, this->pFont);
    }

    this->Invalidate(); // vtbl +0x34
}

// ---- dwGuiPartText --------------------------------------------------------------

// @439050 (dwGuiPartText_Ctor)
dwGuiPartText::dwGuiPartText(dwRect* pRect, void* pNotify, char* pFontName, uint8_t color,
                             char* pFormat, void* pSourcePart)
    : dwGuiHypText(pRect, pNotify, pFontName, color, pFormat)
{
    if (pSourcePart != NULL)
    {
        // Show the blueprint's display name immediately (binary: reads
        // pSourcePart+0x24 = dwPart displayName.pBuffer, then virtual
        // SetText — which APPENDS, hence the Free() first).
        this->text.Free();
        this->SetText(((dwPart*)pSourcePart)->displayName.pBuffer); // vtbl +0x48
    }
}

// @4390f0 (dwGuiPartText_Dtor; scalar-deleting wrapper @4390d0) — vptr
// re-point + base dtor only, both implicit here.
dwGuiPartText::~dwGuiPartText()
{
}

// vtbl +0x1c @439100 (dwGuiPartText_OnMessage) — part-selection broadcast.
// Always returns 0 (the binary returns with the low byte cleared, so the
// message keeps broadcasting).
int dwGuiPartText::OnMessage(dwWidgetMsg* pMsg)
{
    dwMissionInfoView* pSender;
    dwPart* pPart;
    uint8_t slot;

    if (pMsg->code == 0xBBC && pMsg->pSender != NULL)
    {
        // Binary: slot = byte @sender+0x08 clamped to 2; name = the sender's
        // REWARD part-name array entry (dwString[3] @0x68, pBuffer read);
        // then show the blueprint's display name.
        pSender = (dwMissionInfoView*)pMsg->pSender;
        slot = pSender->rewardIdx;
        if (slot > 2)
            slot = 2;
        pPart = dwPart_FindBlueprint(pSender->aRewardParts[slot].pBuffer);
        if (pPart != NULL)
        {
            this->text.Free();
            this->SetText(pPart->displayName.pBuffer); // vtbl +0x48 (SetText APPENDS)
        }
    }
    return 0;
}
