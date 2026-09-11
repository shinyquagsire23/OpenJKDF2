#ifndef _DWGUITEXTMISC_H
#define _DWGUITEXTMISC_H

// dwGuiTextMisc — six small DroidWorks text/decorator control classes from
// three contiguous compile units:
//
//   dwGuiTextPopup  (0x78, vtbl 0x51fce8, 0x4399b0-0x439bxx) — TEXTPOPUP: a
//                   dwGuiTextButton that also carries two toggle strings and
//                   optionally an image, reusing the dwWorkshopCtrl
//                   image-name dwStrings as its string storage.
//   dwGuiTextSlider (0x34, vtbl 0x51fd38, 0x439c10-0x439f1x) — TEXTSLIDER:
//                   horizontally scrolling-text marquee.
//   dwGuiTextSpitter(0x70, vtbl 0x51fd88, 0x439f20-0x43a69x) — TEXTSPITTER:
//                   per-character fly-in reveal (chars slide in from an edge
//                   and "land" one by one, with a tick sound).
//   dwGuiTextStrip  (0x30, vtbl 0x51fdd8, 0x43a6a0-0x43a8bx) — TEXTSTRIP:
//                   scrolling translucent colored strip (marquee decoration).
//   dwGuiTimer      (0x20, vtbl 0x51fe28, 0x43a8c0-0x43aa2x) — TIMER/
//                   SPITTIMER/STRIPTIMER: timed show/hide DECORATOR wrapping
//                   another control (derives dwWcChildDecorator).
//   dwGuiTypewriter (0x48, vtbl 0x51fe78, 0x43aa30-0x43ae3x) — TYPEWRITER:
//                   time-fraction-driven prefix reveal with a tick sound
//                   (used by dwGuiStatus / dwGuiInGame / dwGuiReference).
//
// Decompiled from DroidWorks.exe 0x4399b0-0x43ae3f. Verifiably C++ (vtables,
// ctor/dtor pairs, MSVC EH frames) -> C++ classes.
//
// No module statics — no dwGuiTextMisc_Startup needed (soft-reset rule).

#include "Dw/dwTypes.h"
#include "Dw/dwRect.h"
#include "Dw/dwWidget.h" // dual-language (dwWidget opaque in the C view)

#ifdef __cplusplus
struct dwGuiTextPopup;
struct dwGuiTextSlider;
struct dwGuiTextSpitter;
struct dwGuiTextStrip;
struct dwGuiTimer;
struct dwGuiTypewriter;
extern "C" {
#else
// C++ classes; opaque in the C view.
typedef struct dwGuiTextPopup dwGuiTextPopup;
typedef struct dwGuiTextSlider dwGuiTextSlider;
typedef struct dwGuiTextSpitter dwGuiTextSpitter;
typedef struct dwGuiTextStrip dwGuiTextStrip;
typedef struct dwGuiTimer dwGuiTimer;
typedef struct dwGuiTypewriter dwGuiTypewriter;
#endif

// ---- C-callable entry points ------------------------------------------------

// Invented C shim (no binary counterpart): `new dwGuiTimer(pTarget, startTime,
// duration)` as a dwWidget*, for C/C++ units that only hold the base pointer
// (dwWorkshopCtrl.cpp's dwWcEntryPanel::ShowEntry). The timer OWNS pTarget
// (deletes it in its dtor).
dwWidget* dwGuiTimer_New(dwWidget* pTarget, float startTime, float duration);

#ifdef __cplusplus
} // extern "C"

#include "Dw/dwWorkshopCtrl.h" // dwWcChildDecorator (dwGuiTimer base)
#include "Dw/dwGuiButton.h"    // dwGuiTextButton (dwGuiTextPopup base)
#include "Dw/dwString.h"
#include "Dw/dwFont.h"
#include "Dw/dwImage.h"

// ---- dwGuiTextPopup -----------------------------------------------------------
//
// Binary layout: dwGuiTextButton @0x00, NO new fields — sizeof 0x78. vtable
// @0x51fce8 (dwGuiTextPopup_vtbl); overrides only +0x00 dtor and +0x44 Draw
// (everything else — mouse handling, +0x18 OnHover hover-notify, +0x3c/+0x40
// image loads, +0x48 HitTest — inherits the dwGuiTextButton/dwWorkshopCtrl
// bases; the binary's +0x18 slot @439ad0 is the same shared COMDAT as
// dwWorkshopCtrl::OnHover).
//
// FIELD REUSE QUIRK (faithful): the dwWorkshopCtrl image-name dwStrings are
// repurposed as the popup's two toggle strings — imageNameNormal@0x14 =
// display text, imageNamePressed@0x30 = alt text. When BOTH are non-empty and
// the display text is not "RmicroscopeGR.rle" (the reference-screen
// microscope-zoom image), the ctor latches bHot = bChecked = 1 ("text mode");
// otherwise the strings double as image filenames for the base's lazy loads.
// TEXTPOPUP keyword (dwGuiScreen_CreateControl @430f6d, dwGuiReference).

struct dwGuiTextPopup : dwGuiTextButton
{
    // @4399b0 (dwGuiTextPopup_Ctor) — base(pRect, pLabel, pFontName,
    // colorNormal, pSndOff, colorHot, pSndClick, "CTextRollover.WAV" hover
    // snd, cmdId, bAltDraw); assigns the two toggle strings into the base
    // image-name slots, latches text mode (see above), re-assigns labelText
    // (redundant — the base already set it; binary quirk), then a DIRECT
    // (non-virtual) dwWorkshopCtrl::EnsureImages.
    dwGuiTextPopup(dwRect* pRect, char* pLabel, char* pFontName,
                   uint8_t colorNormal, uint8_t colorHot, int cmdId,
                   char* pDisplayText, char* pSndOff, char* pAltText,
                   char* pSndClick, uint8_t bAltDraw);

    // @439ac0 (dwGuiTextPopup_Dtor; scalar-deleting wrapper @439aa0) — vptr
    // re-point + base dtor only (implicit here).
    virtual ~dwGuiTextPopup();

    // vtbl +0x44 @439b00 — EnsureImages (virtual); blit pImagePressed when
    // bHot else pImageNormal (when loaded); then, while bChecked or bHot and
    // a font + label exist, draw labelText in a rect vertically centered on
    // the font line height, colorHot when bHot else colorNormal (NOTE: color
    // keys on bHot ONLY — unlike dwGuiTextButton::Draw's bChecked||bHot).
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);
};

// ---- dwGuiTextSlider -----------------------------------------------------------
//
// Binary layout: dwWidget @0x00 + fields from 0x10 — sizeof 0x34. vtable
// @0x51fd38 (dwGuiTextSlider_vtbl), 19 slots: overrides dtor/+0x14 Update/
// +0x44 Draw and appends the NEW +0x48 SetText (this class's own slot; its
// body @439d80 is COMDAT-shared with dwGuiTypewriter's +0x48).
//
// Marquee: scrollRect starts one rect-width left of the widget (right edge at
// widget left, width = widget width - 50) and slides right; the advance per
// tick is width * (totalTime / scrollSpeed) px (scrollSpeed = seconds per
// full width; the total keeps accumulating, so the slide accelerates —
// binary quirk). On overshoot it snaps to left+50 with the right edge AT the
// widget right, where the `scrollR < right` gate then stops all further
// motion (single slide). Draw: label at scrollRect, 1px-offset shadow pass in
// dwColormap_transparentIdx first (shadowColor is stored but NEVER used —
// binary quirk), both clipped to pClipRect ∩ scrollRect; nothing draws while
// scrollSpeed == 0.

struct dwGuiTextSlider : dwWidget
{
    dwString label;      // 0x10
    uint8_t textColor;   // 0x1c
    uint8_t shadowColor; // 0x1d: stored by the ctor, never read (see above)
    dwFont* pFont;       // 0x20: owned heap handle (dwFont_Load)
    float scrollTimer;   // 0x24: accumulated seconds (Ghidra typed int; the code is float)
    float scrollSpeed;   // 0x28: seconds per full-width slide (0 = draw nothing)
    dwRect scrollRect;   // 0x2c (Ghidra: scrollL/T/R/B shorts): the marquee rect

    // @439c10 (dwGuiTextSlider_Ctor)
    dwGuiTextSlider(dwRect* pRect, char* pFontName, uint8_t textColor,
                    float scrollSpeed, uint8_t shadowColor, char* pText);
    // @439d10 (dwGuiTextSlider_Dtor; scalar-deleting wrapper @439cf0) — the
    // font handle "dtor" @504190 is a lone RET; only the handle is freed.
    virtual ~dwGuiTextSlider();

    // vtbl +0x14 @439db0
    virtual void Update(float dt);
    // vtbl +0x44 @439e60
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);

    // NEW virtual — appended after dwWidget's +0x44 Draw.
    // vtbl +0x48 @439d80 (dwGuiTextSlider_SetText, COMDAT shared with
    // dwGuiTypewriter) — scrollTimer = 0; label = pText; Invalidate.
    virtual void SetText(char* pText);
};

// ---- dwGuiTextSpitter -----------------------------------------------------------
//
// Binary layout: dwWidget @0x00 + fields from 0x10 — sizeof 0x70. vtable
// @0x51fd88 (dwGuiTextSpitter_vtbl), 19 slots: overrides dtor/+0x14 Update/
// +0x44 Draw + NEW +0x48 SetText @43a1a0.
//
// Character fly-in reveal: the current char slides from the widget's right
// edge toward the end of the revealed text (mode == 0; mode != 0 reveals
// from the BACK, the char sliding right from beyond the left edge) and
// "lands", growing landRect by one char width and playing spitSound per
// landing. The flying char is drawn by rendering the whole remaining string
// clipped to charRect, and the landed text by rendering the (over-appended)
// `revealed` working string clipped to landRect — the clip rects, not the
// string contents, bound what is visible (binary quirk: mode 0 APPENDS the
// whole remaining tail to `revealed` on every landing). Completion is
// detected when the two cursors reach the same CHARACTER VALUE at the same
// wrapped x-extent (quirky but faithful). color2 != 0 switches Draw to a
// plain centered shadowed draw of the unlanded tail (no animation drawn).

struct dwGuiTextSpitter : dwWidget
{
    dwString text;      // 0x10: full source text
    uint8_t color1;     // 0x1c: glyph color
    uint8_t color2;     // 0x1d: nonzero = static centered draw mode (see above)
    dwFont* pFont;      // 0x20: owned heap handle (dwFont_Load)
    dwRect charRect;    // 0x24 (Ghidra: unnamed): the flying char's rect
    dwRect landRect;    // 0x2c (Ghidra: unnamed): the landed-text rect (grows per landing)
    dwString revealed;  // 0x34: working string for the landed text
    float revealTimer;  // 0x40: accumulated seconds (never reset — the fly-in accelerates)
    char* pFwdChar;     // 0x44 (Ghidra: fwdIndex, typed int): front reveal cursor (into text.pBuffer)
    char* pEndChar;     // 0x48 (Ghidra: endIndex, typed int): back reveal cursor (last char)
    int32_t charWidth;  // 0x4c: advance width of the current char
    int32_t accumWidth; // 0x50: summed landed width (mode != 0 counts down from the full width)
    int32_t bDone;      // 0x54
    int32_t mode;       // 0x58: 0 = forward (front) reveal, else reverse (back) reveal
    dwPoint extentFwd;  // 0x5c (Ghidra: typed int): wrapped extent up to pFwdChar
    dwPoint extentEnd;  // 0x60 (Ghidra: typed int): wrapped extent up to pEndChar
    dwString spitSound; // 0x64: per-landing tick sound name

    // @439f20 (dwGuiTextSpitter_Ctor)
    dwGuiTextSpitter(dwRect* pRect, char* pFontName, uint8_t color1, int mode,
                     char* pSpitSound, uint8_t color2, char* pText);
    // @43a0f0 (dwGuiTextSpitter_Dtor; scalar-deleting wrapper @43a0d0) —
    // free the font handle, stop the tick when still playing; strings free
    // via member dtors here.
    virtual ~dwGuiTextSpitter();

    // vtbl +0x14 @43a230
    virtual void Update(float dt);
    // vtbl +0x44 @43a4e0
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);

    // NEW virtual — appended after dwWidget's +0x44 Draw.
    // vtbl +0x48 @43a1a0 (dwGuiTextSpitter_SetText) — text = pText;
    // Invalidate. QUIRK: does NOT reset the reveal state/cursors.
    virtual void SetText(char* pText);

    // -- non-virtual methods ---------------------------------------------------

    // @43a1c0 (dwGuiTextSpitter_UpdateCharExtent) — charWidth = width of
    // *pCh; reset charRect to the fly-in start: mode 0 just past the widget's
    // RIGHT edge, else charWidth left of the widget's LEFT edge.
    void UpdateCharExtent(char* pCh);
};

// ---- dwGuiTextStrip -----------------------------------------------------------
//
// Binary layout: dwWidget @0x00 + fields from 0x10 — sizeof 0x30. vtable
// @0x51fdd8 (dwGuiTextStrip_vtbl), 18 slots: overrides only dtor/+0x14
// Update/+0x44 Draw (NO SetText slot). Same marquee state machine as
// dwGuiTextSlider, but Draw blend-fills the scroll rect with `color` instead
// of drawing text; `label` is default-constructed and never used (binary
// quirk — dead field).

struct dwGuiTextStrip : dwWidget
{
    uint8_t color;     // 0x10: strip blend color index
    float scrollTimer; // 0x14: accumulated seconds (Ghidra typed int; the code is float)
    float scrollSpeed; // 0x18: seconds per full-width slide (0 = draw nothing)
    dwString label;    // 0x1c: dead field (never assigned/read after the ctor)
    dwRect scrollRect; // 0x28 (Ghidra: scrollL/T/R/B shorts)

    // @43a6a0 (dwGuiTextStrip_Ctor)
    dwGuiTextStrip(dwRect* pRect, uint8_t color, float scrollSpeed);
    // @43a760 (dwGuiTextStrip_Dtor; scalar-deleting wrapper @43a740) — label
    // free + base only (implicit here).
    virtual ~dwGuiTextStrip();

    // vtbl +0x14 @43a7b0 — identical math to dwGuiTextSlider::Update.
    virtual void Update(float dt);
    // vtbl +0x44 @43a860
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);
};

// ---- dwGuiTimer -----------------------------------------------------------
//
// Binary layout: dwWcChildDecorator @0x00 (0x14; Ghidra's pTarget@0x10 IS the
// decorator's pChild) + fields from 0x14 — sizeof 0x20. vtable @0x51fe28
// (dwGuiTimer_vtbl): every slot is the dwWcChildDecorator forwarder except
// +0x00 dtor (the binary body @43a9d0 re-points the vptr and repeats the
// decorator dtor — FreeImages + delete child; implicit here) and +0x14
// Update. TIMER keyword (dwGuiScreen_CreateControl2 @430fed parses
// "TIMER <startTime> <duration> <child control...>"), also built directly by
// dwWcEntryPanel::ShowEntry (through the dwGuiTimer_New shim above).
//
// Behavior: the wrapped child starts Disabled; once elapsed exceeds
// startTime it is Enabled (shown); once elapsed exceeds duration (when
// nonzero) it is Disabled again (+ Invalidate). The child's Update(dt) is
// forwarded EVERY tick, shown or not — and note this Update does not check
// this->bEnabled itself (containers gate it; binary quirk).

struct dwGuiTimer : dwWcChildDecorator
{
    float startTime; // 0x14: seconds until the child is shown
    float duration;  // 0x18: seconds until the child is hidden again (0 = never)
    float elapsed;   // 0x1c

    // @43a8c0 (dwGuiTimer_Ctor) — decorator base (widget rect copied from
    // the child); Disable()s the child when it starts enabled; elapsed = 0.
    dwGuiTimer(dwWidget* pTarget, float startTime, float duration);
    // (no own dtor — @43a9d0/@43a9b0 are exactly ~dwWcChildDecorator)

    // vtbl +0x14 @43a940
    virtual void Update(float dt);
};

// ---- dwGuiTypewriter -----------------------------------------------------------
//
// Binary layout: dwWidget @0x00 + fields from 0x10 — sizeof 0x48. vtable
// @0x51fe78 (dwGuiTypewriter_vtbl), 19 slots: overrides dtor/+0x14 Update/
// +0x44 Draw + NEW +0x48 SetText (the SAME COMDAT body @439d80 as
// dwGuiTextSlider::SetText — both classes keep their timer at 0x24 and their
// text dwString at 0x10, so the shared body works for both).
//
// Time-driven prefix reveal: revealed = the first
// round(text.length * min(revealTimer / revealDuration, 1)) chars, with a
// tick sound looping while the reveal grows and stopped once complete.
// Draw: shadow pass at (+1,+1) in dwColormap_transparentIdx, then the
// revealed prefix in textColor; bRightAlign shifts the draw rect left by the
// FULL text's measured width from the right edge (the reveal grows toward
// its final right-aligned position). color2 is stored but never read
// (binary quirk — dead field).

struct dwGuiTypewriter : dwWidget
{
    dwString text;        // 0x10: full source text
    uint8_t textColor;    // 0x1c
    uint8_t color2;       // 0x1d: dead field (stored, never read)
    dwFont* pFont;        // 0x20: owned heap handle (dwFont_Load)
    float revealTimer;    // 0x24: accumulated seconds
    float revealDuration; // 0x28: seconds for the full reveal (0 = draw nothing)
    dwString revealed;    // 0x2c: current visible prefix
    dwString tickSound;   // 0x38: per-char tick sound name
    uint8_t bRightAlign;  // 0x44

    // @43aa30 (dwGuiTypewriter_Ctor)
    dwGuiTypewriter(dwRect* pRect, char* pFontName, uint8_t textColor,
                    float revealDuration, char* pTickSound, uint8_t color2,
                    uint8_t bRightAlign, char* pText);
    // @43ab30 (dwGuiTypewriter_Dtor; scalar-deleting wrapper @43ab10) —
    // free the font handle, stop the tick when still playing.
    virtual ~dwGuiTypewriter();

    // vtbl +0x14 @43abe0
    virtual void Update(float dt);
    // vtbl +0x44 @43acd0
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);

    // NEW virtual — appended after dwWidget's +0x44 Draw.
    // vtbl +0x48 @439d80 (COMDAT shared with dwGuiTextSlider::SetText) —
    // revealTimer = 0; text = pText; Invalidate.
    virtual void SetText(char* pText);
};

#endif // __cplusplus

#endif // _DWGUITEXTMISC_H
