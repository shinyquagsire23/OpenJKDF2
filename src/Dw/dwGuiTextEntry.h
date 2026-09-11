#ifndef _DWGUITEXTENTRY_H
#define _DWGUITEXTENTRY_H

// dwGuiTextEntry — the DroidWorks single-line editable text/name box, plus
// its reference-search subclass:
//
//   dwGuiTextEntry (0x40, vtbl 0x51fca0, ctor @439160) — dwWidget subclass
//                  editing an EXTERNAL dwString in place (pText — the caller
//                  owns the string; e.g. the droid-name / save-name /
//                  find-query buffers). Click to begin editing (grabs
//                  dwWidget_pMouseTarget), click outside to end; drag
//                  selection, blinking 2px caret (0.7s period), Enter/^C
//                  commits. Typed chars are filtered to printable non-
//                  filename-special chars (\ / : * ? < > | " . rejected) so
//                  the same control doubles as a filename entry.
//   dwGuiFindEntry (0x44, vtbl 0x51ec70, ctor @413c20) — dwGuiFind (topic
//                  search) subclass; adds messageCode@0x40 and overrides
//                  OnMessage to mirror an incoming message's payload string
//                  into pText (the query box follows the type-ahead list).
//                  RECLASSIFIED out of the dwFlic address span (it is built
//                  by the dwGuiFind factory @4135c7).
//
// Ghidra (DroidWorks.exe) ranges 0x439160-0x4399ax (dwGuiTextEntry) and
// 0x413c20-0x413ccx (dwGuiFindEntry). Verifiably C++ (vtables, ctor/dtor
// pairs, MSVC EH frames) -> C++ classes.
//
// Notification fields (binary 0x20/0x24/0x28 — Ghidra left them unnamed):
// three int notification message CODES dispatched to dwWidget_pDefault with
// pText->pBuffer as the payload:
//   msgEditNotify@0x20 — sent by BOTH BeginEdit and EndEdit (edit state
//                        changed); ALSO reused as the OnHover payload
//                        (pSender) of the stock { 0x7531 } hover message.
//   msgChanged@0x24    — sent by OnKey after any keystroke that played the
//                        WTextEntry.wav feedback (insert/backspace/arrows).
//   msgCommit@0x28     — sent by OnKey on Enter (0x0d) / 0x03 after EndEdit.
//
// No module statics — no dwGuiTextEntry_Startup needed (soft-reset rule).

#include "Dw/dwTypes.h"
#include "Dw/dwRect.h"

#ifdef __cplusplus
struct dwGuiTextEntry;
struct dwGuiFindEntry;
extern "C" {
#else
// C++ classes; opaque in the C view.
typedef struct dwGuiTextEntry dwGuiTextEntry;
typedef struct dwGuiFindEntry dwGuiFindEntry;
#endif

// (no C-callable entry points — section kept for symmetry)

#ifdef __cplusplus
} // extern "C"

#include "Dw/dwWidget.h"
#include "Dw/dwString.h"
#include "Dw/dwFont.h"

// ---- dwGuiTextEntry ---------------------------------------------------------
//
// Binary layout: dwWidget base @0x00 (0xe) + bEditable@0x10 + bDragging@0x11 +
// pFont@0x14 + textColor@0x18 + cursorColor@0x19 + pText@0x1c +
// msgEditNotify@0x20 + msgChanged@0x24 + msgCommit@0x28 + maxLen@0x2c +
// selAnchor@0x30 + selEnd@0x34 + bCursorBlinkOn@0x38 + blinkTimer@0x3c —
// sizeof 0x40. vtable @0x51fca0 (dwGuiTextEntry_vtbl, 18 slots): overrides
// dtor/OnMouseMove/OnMouseDown/OnMouseUp/OnKey/Update/OnHover/Draw.

struct dwGuiTextEntry : dwWidget
{
    uint8_t bEditable;       // 0x10: currently in edit mode (has the caret)
    uint8_t bDragging;       // 0x11: left button down, extending the selection
    dwFont* pFont;           // 0x14: owned heap handle (dwFont_Load)
    uint8_t textColor;       // 0x18: glyph + caret color index
    uint8_t cursorColor;     // 0x19: selection-band fill color index
    dwString* pText;         // 0x1c: EXTERNAL string edited in place (not owned)
    int32_t msgEditNotify;   // 0x20 (Ghidra: unnamed): see the header comment
    int32_t msgChanged;      // 0x24 (Ghidra: unnamed)
    int32_t msgCommit;       // 0x28 (Ghidra: unnamed)
    int32_t maxLen;          // 0x2c: max chars (ctor: 0x400)
    uint32_t selAnchor;      // 0x30 (Ghidra: int): caret / selection anchor (char index)
    uint32_t selEnd;         // 0x34 (Ghidra: int): selection end; == selAnchor -> plain caret
    uint8_t bCursorBlinkOn;  // 0x38: caret currently visible
    float blinkTimer;        // 0x3c: seconds into the current 0.7s blink phase

    // @439160 — dwWidget(pRect) base; not editable, maxLen 0x400. Quirk
    // preserved: selEnd starts at pText->length + 1 (one PAST the length;
    // BeginEdit renormalizes it).
    dwGuiTextEntry(dwRect* pRect, char* pFontName, uint8_t textColor, uint8_t cursorColor,
                   dwString* pText, int32_t msgEditNotify, int32_t msgChanged, int32_t msgCommit);

    // @439250 (dwGuiTextEntry_Dtor; scalar-deleting wrapper @439230) — frees
    // the font handle only (pText is the caller's).
    virtual ~dwGuiTextEntry();

    // vtbl +0x04 @439500 — while dragging, extend the selection to the char
    // under x and repaint. Always returns 0.
    virtual int OnMouseMove(int16_t x, int16_t y);

    // vtbl +0x08 @439470 — inside the rect (or not yet editing): BeginEdit;
    // when already editing and the click is OUTSIDE: EndEdit and FORWARD the
    // click to dwWidget_pDefault->OnMouseDown (the screen behind). Either
    // way, when editing afterwards: start a drag and place the caret via
    // HitTestCaret. Returns 1 (or the forwarded handler's result).
    virtual int OnMouseDown(int16_t x, int16_t y);

    // vtbl +0x0c @4394f0 — stop dragging. Always returns 0.
    virtual int OnMouseUp(int16_t x, int16_t y);

    // vtbl +0x10 @439530 — the editor. Ignored unless editing and repeat!=0.
    //   0x03/0x0d: EndEdit + msgCommit notify.
    //   0x08:      backspace (collapse caret -> delete previous char).
    //   0x1c/0x1d: caret left/right (selection collapses).
    //   printable (isalpha/isdigit/isgraph/space, minus \ / : * ? < > | " .):
    //     replace selection; insert if it fits the width (right-left-1 px)
    //     and maxLen.
    // Keystrokes that "did something" replay WTextEntry.wav (PlayRestart) and
    // send msgChanged. Returns bEditable.
    virtual int OnKey(int key, int repeat);

    // vtbl +0x14 @4397a0 — 0.7s caret blink (timer accumulates even when not
    // editing; faithful).
    virtual void Update(float dt);

    // vtbl +0x18 @4392c0 — hover notify: when msgEditNotify is set, dispatch
    // { 0x7531, (void*)msgEditNotify, 0, NULL } and return 1; else 0.
    virtual int OnHover(int16_t x, int16_t y);

    // vtbl +0x44 @439810 — when editing: selection band (cursorColor), 2px
    // caret (textColor, when blink-on and no selection), color-7 frame; then
    // the text (left+2, vertically centered on the font line height).
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);

    // -- non-virtual methods ---------------------------------------------------

    // @439310 — enter edit mode: grab dwWidget_pMouseTarget, reset the blink,
    // select all (selAnchor 0, selEnd length), msgEditNotify notify.
    void BeginEdit();

    // @439370 — leave edit mode: release the mouse target (when ours),
    // msgEditNotify notify.
    void EndEdit();

    // @4393d0 — erase [min,max) of the selection from pText; caret collapses
    // to the selection start. (Called with an empty selection by backspace:
    // erases nothing, still repaints.)
    void DeleteSelection();

    // @439410 — map a screen x to a char index: walks glyph widths from the
    // widget's left edge until the remaining distance is used up.
    uint32_t HitTestCaret(int16_t x);
};

// ---- dwGuiFindEntry ---------------------------------------------------------
//
// Binary layout: dwGuiTextEntry base @0x00 (0x40) + messageCode@0x40 —
// sizeof 0x44. vtable @0x51ec70 (dwGuiFindEntry_vtbl): overrides only
// +0x00 dtor and +0x1c OnMessage.

struct dwGuiFindEntry : dwGuiTextEntry
{
    int32_t messageCode; // 0x40: OnMessage code to mirror (e.g. 0x1B7B)

    // @413c20 — forwards to the base ctor with msgCommit FORCED to 0x1b79
    // (7033); the caller's msgCommit argument is accepted but IGNORED
    // (faithful — the binary never reads its 8th argument).
    dwGuiFindEntry(dwRect* pRect, char* pFontName, uint8_t textColor, uint8_t cursorColor,
                   dwString* pText, int32_t msgEditNotify, int32_t msgChanged,
                   int32_t msgCommitIgnored, int32_t messageCode);

    // @413c90 (dwGuiFindEntry_Dtor; scalar-deleting wrapper @413c70) — vptr
    // re-point + base dtor only (implicit here).
    virtual ~dwGuiFindEntry();

    // vtbl +0x1c @413ca0 — when pMsg->code == messageCode: pText->Assign the
    // message payload string (pMsg->pSender) and repaint. Always returns 0
    // (the broadcast keeps going).
    virtual int OnMessage(dwWidgetMsg* pMsg);
};

#endif // __cplusplus

#endif // _DWGUITEXTENTRY_H
