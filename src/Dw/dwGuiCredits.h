#ifndef _DWGUICREDITS_H
#define _DWGUICREDITS_H

// dwGuiCredits — the 'credits' end-credits SCROLL SCREEN.
// DroidWorks.exe unit range: 0x40af10-0x40b93f (plus the compiler-generated
// secondary dtor thunk @40ba60 and the shared screen-OnHover COMDAT @40ba70,
// which belongs to dwGuiScreen).
//
// MSVC MI (binary): primary dwGuiCredits_vtbl @0x51e8c0 (dwGuiScreen shape),
// secondary dwGuiCredits_scn_vtbl @0x51e8a8 (dwSegment lifecycle) — in this
// translation simply `struct dwGuiCredits : dwGuiScreen`.
//
// The credits.cmp CREDITS keyword loads the scroll-line list; each line is
// encoded as: byte0 = font selector ('S' section / 'N' name / 'T' or default
// title, see GetLineFont), byte1 = layout ('!' centered, '/' two-column split
// at the marked '/', anything else = blank spacing line), byte2.. = text.
// Update scrolls at scrollSpeed px/s, retiring lines that scroll off the top;
// when the list is exhausted and the tail scrolls past the top it advances
// the segment flow. Draw renders the visible window; a one-shot
// dwSound_FadeMusic(0, ...) fires when the credits tail crosses the rect's
// vertical middle (timed so the music dies as the scroll ends). The
// DROID_DANCE keyword hosts the disco droid viewer (dwGuiDroidDance — P6
// wave 2, currently a loud stub).
//
// Built by dwGuiOptions_OnMessage (menu command 6000+4, 'Credits') and by
// dwGuiInGame_EndMission's final-mission flow (P6 wave 2).
//
// Compiled as C++ (two vtables, ctor/dtor pair, MSVC EH frames).

#include "Dw/dwTypes.h"

#ifdef __cplusplus
struct dwGuiCredits;
extern "C" {
#else
typedef struct dwGuiCredits dwGuiCredits; // C++ class; opaque in the C view
#endif

// Note: no binary counterpart — the unit owns no module statics; kept for
// the project-wide soft-reset convention.
void dwGuiCredits_Startup(void);

// Added: C-callable factory — allocates the credits screen and returns its
// dwSegment subobject (for dwSegment_Push). Consumed by dwGuiInGame_EndMission
// (dw_Startup's end-of-game flow in P7 will also use it).
struct dwSegment;
struct dwSegment* dwGuiCredits_New(void);

#ifdef __cplusplus
} // extern "C"

#include "Dw/dwGuiScreen.h"
#include "Dw/dwList.h"
#include "Dw/dwRect.h"
#include "Dw/dwFont.h"

// Binary layout: dwGuiScreen base @0x00 (0xc8) + own fields below — sizeof
// 0xf4. Primary vtbl @0x51e8c0 overrides dtor/OnKey(+0x10)/Update(+0x14)/
// Draw(+0x44)/CreateControl(+0x48); secondary @0x51e8a8 overrides
// Activate(+0x00) (Deactivate stays the dwGuiScreen base).
struct dwGuiCredits : dwGuiScreen
{
    float scrollAccum;        // 0xc8: accumulated Update time (sec)
    float scrollSpeed;        // 0xcc: scroll rate px/s (CREDITS ParseFloat;
                              //       also the fade-time divisor in Draw)
    dwFont* pSectionFont;     // 0xd0: SECTION_FONT ('S' lines)
    dwFont* pNameFont;        // 0xd4: NAME_FONT ('N' lines)
    dwFont* pTitleFont;       // 0xd8: TITLE_FONT ('T'/default lines)
    uint8_t colorIdx;         // 0xdc: text color (CREDITS ParseULong)
    dwRect creditsRect;       // 0xde: scroll window (CREDITS ParseRect;
                              //       Ghidra: creditsRectL/T/R/B shorts)
    uint8_t bSoundTriggered;  // 0xe6: one-shot music-fade latch
    dwList creditLines;       // 0xe8 (Ghidra: pCreditLines): dwString* payloads,
                              //      one per credits line (owned)
    dwListNode* pCurrentLine; // 0xec: scroll cursor — the topmost line still
                              //       on/below the window top
    int16_t scrollY;          // 0xf0: pCurrentLine's y relative to creditsRect
    int16_t scrollBaseline;   // 0xf2: last frame's bottom-anchored scroll pos

    // @40af10 (dwGuiCredits_Ctor) — dwGuiScreen("credits", NULL) + zeroed
    // fields (pCurrentLine starts NULL until the CREDITS keyword parses).
    dwGuiCredits();

    // @40b000 (dwGuiCredits_Dtor; scalar-deleting wrapper @40afe0; secondary
    // thunk @40ba60) — frees the three fonts + every credit line string/node.
    virtual ~dwGuiCredits();

    // ---- dwWidget/dwGuiScreen overrides (primary vtbl @0x51e8c0) -----------
    // vtbl +0x10 @40b1b0 — ESC requests the segment advance; returns 0
    // (REPLACES the base cheat-code OnKey).
    virtual int OnKey(int key, int repeat);
    // vtbl +0x14 @40b1d0 — scroll: rebase scrollY from scrollSpeed *
    // scrollAccum, retire lines fully above the top, advance the segment
    // when the list is exhausted and the tail passed the top; Invalidate +
    // tick the controls group (the droid-dance child).
    virtual void Update(float dt);
    // vtbl +0x44 @40b340 — base screen draw, then the visible credit lines
    // (font by line prefix; '!' centered / '/' two-column) clipped to the
    // widget rect; one-shot music fade when the tail crosses the middle.
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);
    // vtbl +0x48 @40b580 — DROID_DANCE/SECTION_FONT/NAME_FONT/TITLE_FONT/
    // CREDITS keywords; falls back to the base factory.
    virtual dwWidget* CreateControl(char* pKeyword, dwConfFile* pConf);

    // ---- dwSegment overrides (secondary vtbl @0x51e8a8) --------------------
    // +0x00 @40b170 — base screen Activate (hide cursor on success), restart
    // the segment clock, start DiscoBaby.wav.
    virtual int Activate();

    // ---- non-virtual ----------------------------------------------------------
    // @40b300 — font for a credit line by its first char ('S'/'N'/'T';
    // default + NULL/empty = title font).
    dwFont* GetLineFont(char* pLineText);
};

#endif // __cplusplus

#endif // _DWGUICREDITS_H
