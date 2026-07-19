#ifndef _DWGUITEXTBLOCK_H
#define _DWGUITEXTBLOCK_H

// dwGuiTextBlock — the DroidWorks TEXTBLOCK control: a multi-line rich-text
// block whose <...> markup spawns clickable rollover hyperlink children.
//
//   dwGuiTextBlock (0xd0, ctor @436d90) — MSVC MULTIPLE INHERITANCE:
//                  primary base dwWidgetGroup@0x00 (container of the link
//                  hotspot children) + secondary base dwGuiHypText@0x14
//                  (text layout/render). Two binary vtables:
//                  dwGuiTextBlock_vtbl@0x51fb68 (primary) and
//                  dwGuiTextBlock_HypText_vtbl@0x51fb18 (secondary subobject
//                  — its slots are this-adjustor thunks @437d00-437d50 that
//                  subtract 0x14 and re-enter the primary methods). In C++
//                  that is simply `struct dwGuiTextBlock : dwWidgetGroup,
//                  dwGuiHypText` — the compiler emits the thunks.
//
// Behavior: the ctor strips the markup (ParseMarkup) and hands the plain
// text to the dwGuiHypText base. Update runs a text-reveal animation over
// ~1 second (revealTime scales the hyptext rect; the visible wipe itself is
// the base's ElemW when the format string asks for one) while looping the
// reveal/typewriter sound; on completion it re-parses the markup
// (BuildLinkWidgets) and spawns one dwGuiTextRollover child per link
// (CreateLinkWidget: target "HL" -> command 0x1b58, "URL" -> 0x1b61).
// OnHover routes to the link child under the cursor, else sends the stock
// { 0x7531, pHoverNotify } hover message.
//
// Ghidra (DroidWorks.exe) range 0x436d90-0x437d5x (six MI thunks at the
// tail). Verifiably C++ (two vtables, ctor/dtor pair, MSVC EH frames) ->
// C++ class.
//
// ⚠ MI note: BOTH bases embed a dwWidget (rect + bEnabled). The binary keeps
// them equal only because both base ctors get the same rect; the code below
// reads the GROUP's copy for markup metrics (binary EBP+0x06) and the
// HYPTEXT's copy in Update's reveal math (binary ESI+0x1a..0x20) — every
// access is base-qualified to preserve that exactly.
//
// No module statics — no dwGuiTextBlock_Startup needed (soft-reset rule).

#include "Dw/dwTypes.h"
#include "Dw/dwRect.h"

#ifdef __cplusplus
struct dwGuiTextBlock;
extern "C" {
#else
// C++ class; opaque in the C view.
typedef struct dwGuiTextBlock dwGuiTextBlock;
#endif

// (no C-callable entry points — section kept for symmetry)

#ifdef __cplusplus
} // extern "C"

#include "Dw/dwWidgetGroup.h"
#include "Dw/dwGuiHypText.h"
#include "Dw/dwString.h"
#include "Dw/dwFont.h"

// Binary layout: dwWidgetGroup base @0x00 (0x14) + dwGuiHypText base @0x14
// (0x48) + own fields from 0x5c — sizeof 0xd0.

struct dwGuiTextBlock : dwWidgetGroup, dwGuiHypText
{
    dwString displayText;  // 0x5c: working text (markup progressively stripped)
    dwString linkTarget;   // 0x68: current link's target ("HL"/"URL"/topic ref)
    dwString linkAnchor;   // 0x74: current link's visible anchor text
    dwString tagName;      // 0x80: current link's "=name" suffix (e.g. topic name)
    uint8_t hAlign;        // 0x8d: alignment code forwarded to the rollover children
    uint8_t vAlign;        // 0x8e
    dwFont* pFont;         // 0x90: OWN font handle (the hyptext base holds another
                           //       handle to the same font; both heap-owned)
    dwString fontName;     // 0x94: font name kept for the rollover children
    float revealTime;      // 0xa0: seconds since the reveal started (reveal spans 1s)
    int16_t revealL;       // 0xa4: reveal progress rect (grows from the widget's
    int16_t revealT;       // 0xa6  top-left to its full size; drives the sound +
    int16_t revealR;       // 0xa8  BuildLinkWidgets timing, not the paint clip)
    int16_t revealB;       // 0xaa
    dwPoint linkPos;       // 0xac: wrapped-text position of the link being built
                           //       (dwFont_MeasureWrappedExtent output)
    dwString sourceMarkup; // 0xb0: pristine markup (BuildLinkWidgets re-parses it)
    void* pHoverNotify;    // 0xbc (Ghidra: originX/originY — misnamed): OnHover
                           //       notification payload; NULL = no hover notify.
                           //       NOTE: hides nothing — the dwGuiHypText base's own
                           //       pNotify stays NULL (ctor passes 0).
    dwString revealSound;  // 0xc0: looped typewriter/reveal sound name
    uint8_t bRevealWDone;  // 0xcc: reveal width/height "done" flags — the binary
    uint8_t bRevealHDone;  // 0xcd  sets both unconditionally each reveal tick

    // @436d90 (dwGuiTextBlock_Ctor) — bases: dwWidgetGroup(pRect) +
    // dwGuiHypText(pRect, NULL, pFontName, color, pFormat) (the FORMAT-string
    // ctor — pFormat may attach the visible wipe/typewriter elements). Then,
    // unless the markup is the literal " " placeholder: ParseMarkup() +
    // Clear() + text.Free() + virtual SetText(displayText).
    dwGuiTextBlock(dwRect* pRect, char* pFontName, uint8_t color, uint8_t hAlign,
                   uint8_t vAlign, char* pFormat, char* pRevealSoundName, void* pNotify,
                   char* pMarkup);

    // @436fa0 (dwGuiTextBlock_Dtor; scalar-deleting wrapper @436f80) — frees
    // the own font handle; the string members and both bases (hyptext text/
    // runs/elements, then the group's child DELETE) unwind implicitly in
    // exactly the binary's order.
    virtual ~dwGuiTextBlock();

    // vtbl +0x04 @437710 / +0x08 @437730 — plain forwards to the GROUP's
    // handlers (the overrides exist to give both bases' vtables one unified
    // behavior; the compiler emits the secondary-vtable thunks).
    virtual int OnMouseMove(int16_t x, int16_t y);
    virtual int OnMouseDown(int16_t x, int16_t y);

    // vtbl +0x14 @437a70 — the reveal animation (see the class comment).
    // Gated on the HYPTEXT base's bEnabled: when disabled, force-disables
    // any enabled link children instead.
    virtual void Update(float dt);

    // vtbl +0x18 @437750 — first link child containing (x,y) gets OnHover;
    // else the stock { 0x7531, pHoverNotify } dispatch. Returns 1 (or the
    // child's result).
    virtual int OnHover(int16_t x, int16_t y);

    // vtbl +0x44 @437cd0 — dwGuiHypText::Draw (which clips *pClipRect to its
    // layout rect IN PLACE — the group's children then inherit that clip,
    // faithful), then dwWidgetGroup::Draw.
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);

    // -- non-virtual methods ---------------------------------------------------

    // @437190 — ctor-time markup strip: removes every <...> tag pair from
    // displayText while recording the LAST link's target/anchor/tagName.
    // (Literal translation of the binary's pointer walk — see the .cpp.)
    void ParseMarkup();

    // @4373f0 — reveal-completion pass: resets displayText from sourceMarkup
    // and re-walks the markup, calling CreateLinkWidget for every link with
    // its measured wrapped-text position.
    void BuildLinkWidgets();

    // @437800 — build one dwGuiTextRollover hotspot child for a link
    // (target "HL" -> command 0x1b58, "URL" -> 0x1b61; other targets are
    // dropped). The strings arrive BY VALUE (the binary copy-constructs
    // temporaries and the callee frees them). Wired to the real
    // dwGuiTextRollover (dwGuiWidgets unit).
    void CreateLinkWidget(dwString anchor, dwString target, dwPoint pos);
};

#endif // __cplusplus

#endif // _DWGUITEXTBLOCK_H
