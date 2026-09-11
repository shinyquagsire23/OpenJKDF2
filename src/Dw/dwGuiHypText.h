#ifndef _DWGUIHYPTEXT_H
#define _DWGUIHYPTEXT_H

// dwGuiHypText — the DroidWorks base rich/hyperlinked-text control, plus its
// PARTTEXT subclass:
//
//   dwGuiHypText   (0x48, vtbl 0x51fc00, ctors @438690/@438540) — dwWidget
//                  subclass that word-wraps a dwString into a ring of "line
//                  runs", aligns them through four pluggable format
//                  callbacks (wrap / h-align / v-align / draw-glyphs) and
//                  animates them through a list of inline ELEMENTS:
//                    T = typewriter char-reveal over a duration,
//                    S = horizontal marquee scroll at px/sec,
//                    W = rectangular reveal wipe over a duration.
//                  The plain ctor parses a "<format>" code string (see the
//                  grammar note on the ctor); the extended ctor (@438540,
//                  dwGuiHypText_CtorEx) takes the four callbacks + one
//                  pre-built element directly (used by the dwGuiTextBlock /
//                  dwGuiSpeech / dwGuiBriefLine family, later units).
//   dwGuiPartText  (0x48, vtbl 0x51fc50, ctor @439050) — PARTTEXT control:
//                  direct subclass adding NO fields; overrides only the dtor
//                  and OnMessage (msg 0xBBC -> shows the selected droid
//                  part's display name).
//
// Element classes (3-slot vtables {DtorDelete, Update, Layout}):
//   dwGuiHypText_ElemT (0x14, vtbl 0x51fbb0) / _ElemS (0x10, vtbl 0x51fbe0) /
//   _ElemW (0x0c, vtbl 0x51fbf0); shared scalar-deleting dtor @438170.
//   (dwGuiBriefTextElem, a later unit, is an ElemT alias.)
//
// Ghidra (DroidWorks.exe) range 0x437d60-0x439150: the ten stock format
// callbacks (0x437d60-0x438140) + elements (0x438150-0x43853x) + dwGuiHypText
// (0x438540-0x43904x) + dwGuiPartText (0x439050-0x439150). Verifiably C++
// (vtables, ctor/dtor pairs, MSVC EH frames) -> C++ classes.
//
// No module statics — no dwGuiHypText_Startup needed (soft-reset rule).

#include "Dw/dwTypes.h"
#include "Dw/dwRect.h"

#ifdef __cplusplus
struct dwGuiHypText;
struct dwGuiPartText;
extern "C" {
#else
// C++ classes; opaque in the C view.
typedef struct dwGuiHypText dwGuiHypText;
typedef struct dwGuiPartText dwGuiPartText;
#endif

// (no C-callable entry points — section kept for symmetry)

#ifdef __cplusplus
} // extern "C"

#include "Dw/dwWidget.h"
#include "Dw/dwList.h"
#include "Dw/dwString.h"
#include "Dw/dwFont.h"
#include "Dw/dwImage.h"

// ---- line runs ---------------------------------------------------------------
//
// One wrapped line of text, kept in a circular doubly-linked ring with a
// heap-allocated sentinel (dwGuiHypText::pRuns). Unlike dwList, the payload
// is INLINE in the node (binary node size 0x24; the sentinel is allocated
// with the same size but only its links are used — quirk preserved).
// pfnHAlign computes xOffset from the measured width; Layout then resets the
// live draw fields (startChar/drawLen/drawX) from the layout fields
// (0/len/xOffset), and the elements animate the draw fields afterwards.

struct dwGuiHypTextRun
{
    dwGuiHypTextRun* pNext; // 0x00
    dwGuiHypTextRun* pPrev; // 0x04
    int32_t startChar;      // 0x08: first char of the run to draw (always 0 in stock code)
    int32_t drawLen;        // 0x0c: chars to draw (ElemT reveal shrinks this)
    int16_t drawX;          // 0x10: current x offset from the layout rect's left (ElemS scroll moves this)
    char* pStr;             // 0x14: run text (points INTO dwGuiHypText::text.pBuffer)
    int32_t len;            // 0x18: run length in chars
    int32_t width;          // 0x1c: measured pixel width (dwFont_MeasureString)
    int16_t xOffset;        // 0x20: aligned x offset (pfnHAlign result)
}; // binary sizeof 0x24

// ---- format callbacks ----------------------------------------------------------
//
// The four pluggable families. Stock implementations below; the CtorEx-based
// subclasses (dwGuiTextBlock etc, later units) install their own.
// Note: the binary passed the run PAYLOAD pointer (node + 0x08) to the
// h-align/draw-glyphs callbacks; the 64-bit translation passes the run node
// itself (same object, explicit fields).

// Split pText into line runs appended to *ppRuns (width in pixels).
typedef void (*dwGuiHypTextWrapFn)(dwString* pText, dwFont* pFont, int width, dwGuiHypTextRun** ppRuns);
// Compute pRun->xOffset for a line of the given pixel width.
typedef void (*dwGuiHypTextHAlignFn)(dwGuiHypTextRun* pRun, int width);
// Return the vertical offset (int16 in the low bits) of the text block
// inside pRect; *ppRuns is the run sentinel.
typedef int (*dwGuiHypTextVAlignFn)(dwGuiHypTextRun** ppRuns, dwFont* pFont, dwRect* pRect);
// Draw one run's glyphs at *pPos (advanced per glyph by dwFont), clipped to
// pClip when non-NULL.
typedef void (*dwGuiHypTextDrawGlyphsFn)(dwImageBits* pBits, dwPoint* pPos, dwFont* pFont, uint8_t color, dwGuiHypTextRun* pRun, dwRect* pClip);

// Stock callback implementations (also the ctor's format-code targets).
// Whole string (incl. '\n') as ONE run; width ignored. @437d60
void dwGuiHypText_WrapNone(dwString* pText, dwFont* pFont, int width, dwGuiHypTextRun** ppRuns);
// Greedy word wrap on whitespace; '\n' forces a break; a single word wider
// than the line is emitted whole. @437de0
void dwGuiHypText_WrapWords(dwString* pText, dwFont* pFont, int width, dwGuiHypTextRun** ppRuns);
// @437f10 / @437f20 / @437f40
void dwGuiHypText_HAlignLeft(dwGuiHypTextRun* pRun, int width);
void dwGuiHypText_HAlignRight(dwGuiHypTextRun* pRun, int width);
void dwGuiHypText_HAlignCenter(dwGuiHypTextRun* pRun, int width);
// @437f60 / @437f70 / @437f90 (Top returns 0; Bottom returns rect height -
// summed line heights; Center halves Bottom's result)
int dwGuiHypText_VAlignTop(dwGuiHypTextRun** ppRuns, dwFont* pFont, dwRect* pRect);
int dwGuiHypText_VAlignCenter(dwGuiHypTextRun** ppRuns, dwFont* pFont, dwRect* pRect);
int dwGuiHypText_VAlignBottom(dwGuiHypTextRun** ppRuns, dwFont* pFont, dwRect* pRect);
// @437fe0 / @438070 (Shadow first draws every glyph offset (+1,+1) in
// dwColormap_transparentIdx, then the normal pass on top)
void dwGuiHypText_DrawGlyphsNormal(dwImageBits* pBits, dwPoint* pPos, dwFont* pFont, uint8_t color, dwGuiHypTextRun* pRun, dwRect* pClip);
void dwGuiHypText_DrawGlyphsShadow(dwImageBits* pBits, dwPoint* pPos, dwFont* pFont, uint8_t color, dwGuiHypTextRun* pRun, dwRect* pClip);

// ---- inline elements -----------------------------------------------------------
//
// Polymorphic animation attachments ticked by dwGuiHypText::Update and reset
// by Layout. Binary vtables are 3 slots: +0x00 scalar-deleting dtor (shared
// COMDAT @438170), +0x04 Update, +0x08 Layout. The base class below has no
// binary struct of its own (each element embeds only the vptr + own fields).

struct dwGuiHypTextElem
{
    // @438170 (dwGuiHypText_Elem_DtorDelete, shared by all three vtables;
    // the base dtor body is trivial)
    virtual ~dwGuiHypTextElem();
    // vtbl +0x04 — advance the animation; ppRuns = &owner->pRuns.
    virtual void Update(dwGuiHypText* pOwner, float dt, dwGuiHypTextRun** ppRuns) = 0;
    // vtbl +0x08 — reset animation state after a re-layout.
    virtual void Layout(dwGuiHypText* pOwner, dwGuiHypTextRun** ppRuns, dwFont* pFont) = 0;
};

// 'T' — typewriter: reveals round(totalLen * min(accumTime/revealDuration, 1))
// chars across the runs, front to back. Binary struct 0x14, vtbl 0x51fbb0.
struct dwGuiHypText_ElemT : dwGuiHypTextElem
{
    float revealDuration; // 0x04 (Ghidra: field_0x4): seconds for the full reveal
    float accumTime;      // 0x08
    int32_t totalLen;     // 0x0c (Ghidra: totalWidth): total chars across all runs
    uint32_t curReveal;   // 0x10: chars currently revealed

    dwGuiHypText_ElemT(float revealDuration);                                    // @438150
    virtual void Update(dwGuiHypText* pOwner, float dt, dwGuiHypTextRun** ppRuns); // @438190
    virtual void Layout(dwGuiHypText* pOwner, dwGuiHypTextRun** ppRuns, dwFont* pFont); // @438250
};

// 'S' — marquee scroll: shifts every run's drawX by round(speed * accumTime)
// px, starting off-screen (right edge when speed < 0, -totalWidth when
// speed >= 0); Clear()s the owner once fully scrolled off. Binary struct
// 0x10, vtbl 0x51fbe0.
struct dwGuiHypText_ElemS : dwGuiHypTextElem
{
    float accumTime;    // 0x04
    float speed;        // 0x08: px/sec (sign = direction)
    int32_t totalWidth; // 0x0c: widest run's pixel width

    dwGuiHypText_ElemS(float speed);                                             // @4382b0
    virtual void Update(dwGuiHypText* pOwner, float dt, dwGuiHypTextRun** ppRuns); // @4382d0
    virtual void Layout(dwGuiHypText* pOwner, dwGuiHypTextRun** ppRuns, dwFont* pFont); // @4383b0
};

// 'W' — reveal wipe: grows the owner's layoutRect (which Draw clips to) from
// the widget's top-left toward its full rect over wipeDuration seconds.
// Binary struct 0x0c, vtbl 0x51fbf0.
struct dwGuiHypText_ElemW : dwGuiHypTextElem
{
    float accumTime;    // 0x04
    float wipeDuration; // 0x08 (Ghidra: pWord — misnamed): seconds for the full wipe

    dwGuiHypText_ElemW(float wipeDuration);                                      // @438400
    virtual void Update(dwGuiHypText* pOwner, float dt, dwGuiHypTextRun** ppRuns); // @438420
    virtual void Layout(dwGuiHypText* pOwner, dwGuiHypTextRun** ppRuns, dwFont* pFont); // @438500
};

// ---- dwGuiHypText ---------------------------------------------------------------
//
// Binary layout: dwWidget base @0x00 (0xe) + pNotify@0x10 + text@0x14 +
// layoutRect@0x20 + pFont@0x28 + color@0x2c + yOffset@0x2e + pRuns@0x30 +
// pfnHAlign@0x34 + pfnVAlign@0x38 + pfnWrap@0x3c + pfnDrawGlyphs@0x40 +
// elements@0x44 — sizeof 0x48. vtable @0x51fc00 (dwGuiHypText_vtbl):
// overrides dtor/Update/OnHover/Draw and appends ONE new slot, +0x48 SetText.

struct dwGuiHypText : dwWidget
{
    void* pNotify;                          // 0x10 (Ghidra: m_floatParam — misnamed):
                                            //      OnHover notification payload; NULL = no hover notify
    dwString text;                          // 0x14 (Ghidra: m_text)
    dwRect layoutRect;                      // 0x20 (Ghidra: rectL/T/R/B): the text area
                                            //      (ctor copy of *pRect). Doubles as Draw's clip rect —
                                            //      ElemW animates it as the reveal wipe.
    dwFont* pFont;                          // 0x28: owned heap handle (dwFont_Load)
    uint8_t color;                          // 0x2c (Ghidra: m_drawFlag): glyph color index
    int16_t yOffset;                        // 0x2e (Ghidra: m_yOffset): pfnVAlign result
    dwGuiHypTextRun* pRuns;                 // 0x30 (Ghidra: pLineRuns): line-run ring sentinel
    dwGuiHypTextHAlignFn pfnHAlign;         // 0x34
    dwGuiHypTextVAlignFn pfnVAlign;         // 0x38
    dwGuiHypTextWrapFn pfnWrap;             // 0x3c
    dwGuiHypTextDrawGlyphsFn pfnDrawGlyphs; // 0x40
    dwList elements;                        // 0x44 (Ghidra: pElements): dwGuiHypTextElem* payloads

    // @438690 (dwGuiHypText_Ctor) — dwWidget(pRect) base + defaults
    // (HAlignLeft/VAlignTop/WrapWords/DrawGlyphsNormal), then parses pFormat:
    // a decimal value (digits/'-'/'.') accumulates and the NEXT letter
    // consumes it —
    //   L/C/R = h-align left/center/right   U/V/P = v-align top/center/bottom
    //   B/D   = wrap words / no wrap        N/O   = draw normal / shadowed
    //   S/T/W = append ElemS(value px/s) / ElemT(value sec) / ElemW(value sec)
    //           (skipped when the accumulated value is 0)
    // e.g. "BLN" (dwGuiAnimView captions), "0.05T..." typewriter reveals.
    dwGuiHypText(dwRect* pRect, void* pNotify, char* pFontName, uint8_t color, char* pFormat);

    // @438540 (dwGuiHypText_CtorEx) — same base setup, but the four format
    // callbacks are passed directly and pElem (may be NULL) is appended to
    // the element list. No format-string parse.
    dwGuiHypText(dwRect* pRect, void* pNotify, char* pFontName, uint8_t color,
                 dwGuiHypTextHAlignFn pfnHAlign, dwGuiHypTextVAlignFn pfnVAlign,
                 dwGuiHypTextWrapFn pfnWrap, dwGuiHypTextDrawGlyphsFn pfnDrawGlyphs,
                 dwGuiHypTextElem* pElem);

    // @438ac0 (dwGuiHypText_Dtor; scalar-deleting wrapper @438670) — frees
    // the font handle, deletes every element (virtual dtor) + both rings.
    virtual ~dwGuiHypText();

    // vtbl +0x14 @438c20 (dwGuiHypText_Update) — when enabled, ticks every
    // element (elements repaint via the owner's Invalidate themselves).
    virtual void Update(float dt);

    // vtbl +0x18 @438f10 (recovered fn; Ghidra: dwGuiHypText_sub_438F10) —
    // guarded hover notify: when pNotify is set, dispatches { 0x7531,
    // pNotify, 0, NULL } to dwWidget_pDefault and returns 1; else 0.
    virtual int OnHover(int16_t x, int16_t y);

    // vtbl +0x44 @438e20 (dwGuiHypText_Draw) — clips *pClipRect to
    // layoutRect (empty -> skip), then draws each run through pfnDrawGlyphs;
    // baseline = layoutRect.top + font header y-inset + yOffset, advancing
    // by the font line height per run.
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);

    // NEW virtual — appended after dwWidget's +0x44 Draw.
    // vtbl +0x48 @438cf0 (dwGuiHypText_SetText) — if pText differs from the
    // current buffer (dwString_Equals), APPENDS it (quirk: callers Free()
    // the string first for a replace) and re-Layout()s.
    virtual void SetText(char* pText);

    // -- non-virtual methods ---------------------------------------------------

    // @438c80 (dwGuiHypText_Clear) — frees the text and every line run
    // (elements/layout state untouched), then Invalidate()s.
    void Clear();

    // @438d20 (dwGuiHypText_Layout) — full reflow: free runs; when text is
    // non-empty: pfnWrap -> per-run pfnHAlign + draw-field reset ->
    // pfnVAlign (yOffset) -> per-element Layout -> Invalidate.
    void Layout();
};

// ---- dwGuiPartText ---------------------------------------------------------------
//
// PARTTEXT keyword control. Binary layout identical to dwGuiHypText (0x48,
// no new fields). vtable @0x51fc50 (dwGuiPartText_vtbl): overrides only
// +0x00 dtor and +0x1c OnMessage.

struct dwGuiPartText : dwGuiHypText
{
    // @439050 (dwGuiPartText_Ctor) — forwards to the dwGuiHypText format
    // ctor; when pSourcePart (a dwPart blueprint) is given, immediately
    // shows its display name (text.Free() + virtual SetText).
    dwGuiPartText(dwRect* pRect, void* pNotify, char* pFontName, uint8_t color,
                  char* pFormat, void* pSourcePart);

    // @4390f0 (dwGuiPartText_Dtor; scalar-deleting wrapper @4390d0) — vptr
    // re-point + base dtor only (implicit here).
    virtual ~dwGuiPartText();

    // vtbl +0x1c @439100 (dwGuiPartText_OnMessage) — msg 0xBBC (part
    // selected): resolve the sender's selected slot part name via
    // dwPart_FindBlueprint and show the blueprint's display name.
    // Always returns 0 (the broadcast keeps going).
    virtual int OnMessage(dwWidgetMsg* pMsg);
};

#endif // __cplusplus

#endif // _DWGUIHYPTEXT_H
