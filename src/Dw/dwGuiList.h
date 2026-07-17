#ifndef _DWGUILIST_H
#define _DWGUILIST_H

// dwGuiList / dwGuiSpeech / dwGuiDroidDance — three DroidWorks in-game GUI
// controls that share one compile unit.
//
//   dwGuiList       (0x5c, vtbl 0x51e798, ctor @409fc0) — dwGuiHypText
//                   subclass: an interactive, vertically-stacked list of
//                   text items. Concrete use is the IN-GAME CONVERSATION
//                   RESPONSE MENU (the player's clickable dialog choices,
//                   appended by dwCog_AddResponse). Clicking an item
//                   dispatches command 0x1f40 (8000) with the item as sender.
//   dwGuiSpeech     (0x5c, vtbl 0x51e7e8, ctor @40a8a0) — dwGuiHypText
//                   subclass: a single CHARACTER SPEECH caption line (the NPC
//                   currently-spoken line + the sound it plays). SetText binds
//                   a caption + a "timed item" + a sound; Clear stops the sound
//                   and expires the timed item.
//   dwGuiDroidDance (0x598, vtbl 0x51e850, ctor @40ab70) — dwGuiQuickView
//                   subclass: the DROID_DANCE 3D "disco" viewer. Builds 7
//                   groups of randomly-generated droids and cycles through them
//                   on a 12-second timer, playing each group's active/dance
//                   anims. Built by dwGuiCredits on the "DROID_DANCE" keyword;
//                   also used by the reference room. It overrides ONLY the
//                   scalar-deleting dtor and Update; Draw / OnHover / OnMessage
//                   / LayoutNodes are all INHERITED unchanged from
//                   dwGuiQuickView (confirmed against vtbl 0x51e850).
//
// Decompiled from DroidWorks.exe, unit range 0x409fc0-0x40adbf. Verifiably C++
// (vtables, ctor/dtor pairs, MSVC EH frames) -> C++ classes.
//
// No module statics -> no dwGuiList_Startup needed (soft-reset rule).

#include "Dw/dwTypes.h"
#include "Dw/dwRect.h"

#ifndef __cplusplus

// C++ classes; opaque in the C view.
typedef struct dwGuiList dwGuiList;
typedef struct dwGuiSpeech dwGuiSpeech;
typedef struct dwGuiDroidDance dwGuiDroidDance;
typedef struct dwWidget dwWidget; // returned (as an opaque handle) by the C FFI

#else // __cplusplus

#include "Dw/dwGuiHypText.h"   // dwGuiList / dwGuiSpeech base
#include "Dw/dwGuiQuickView.h" // dwGuiDroidDance base (: dwGuiViewBox)
#include "Dw/dwList.h"         // dwList / dwListNode
#include "Dw/dwString.h"       // dwString (embedded in the list item)

// ---- dwGuiListItem -----------------------------------------------------------
//
// One entry of a dwGuiList (binary node payload, sizeof 0x28). textA is the
// wrapped/displayed text; textB / data / val are caller-defined metadata (the
// COG response layer keys off them). rect is the item's laid-out bounds
// (recomputed by Relayout, used for hit-testing + hover highlighting).

struct dwGuiListItem
{
    void* data;      // 0x00: caller-defined payload
    int32_t val;     // 0x04: caller-defined value
    dwString textA;  // 0x08: displayed (wrapped) text
    dwString textB;  // 0x14: secondary caller-defined text
    int16_t left;    // 0x20
    int16_t top;     // 0x22
    int16_t right;   // 0x24
    int16_t bottom;  // 0x26
}; // binary sizeof 0x28

// ---- dwGuiList ---------------------------------------------------------------
//
// Binary layout: dwGuiHypText base @0x00 (0x48) + pItems@0x48 +
// colorHighlight@0x4c + colorFlag2@0x4d + drawStyle@0x4e + bLayoutInvalid@0x52
// + pHoverItem@0x54 + pPressedItem@0x58 — sizeof 0x5c. vtable @0x51e798:
// overrides DtorDelete / OnMouseMove / OnMouseDown / OnMouseUp / Draw; inherits
// Update / OnHover / SetText from dwGuiHypText.

struct dwGuiList : dwGuiHypText
{
    dwListNode* pItems;          // 0x48: heap sentinel of a dwGuiListItem* list
    uint8_t colorHighlight;      // 0x4c: glyph color for the hovered item
    uint8_t colorFlag2;          // 0x4d: secondary flag color
    uint32_t drawStyle;          // 0x4e: FillTriBlend apex (a packed dwPoint)
    uint8_t bLayoutInvalid;      // 0x52: 1 once a click has been committed
    dwGuiListItem* pHoverItem;   // 0x54: item under the cursor (NULL = none)
    dwGuiListItem* pPressedItem; // 0x58: item captured on mouse-down

    // @409fc0 (dwGuiList_Ctor). NOTE: the a / pFontName parameters are ordered
    // to match the (Ghidra-derived) dwMain.c placeholder + its dwGuiInGame
    // caller: `a` (float) carries the base text color, `pFontName` the font
    // name (the binary's own arg order is the reverse — see the .cpp note).
    dwGuiList(dwRect* pRect, float a, char* pFontName, uint8_t colorHi,
              uint8_t colorFlag2, void* pStyle);

    // @40a0c0 (dwGuiList_Dtor; DtorDelete @40a0a0) — free every item (both
    // dwStrings) + the list, then the base dtor.
    virtual ~dwGuiList();

    // vtbl +0x04 @40a5e0 — refresh the hover item unless the point is still
    // over the current one; never consumes the event.
    virtual int OnMouseMove(int16_t x, int16_t y);
    // vtbl +0x08 @40a630 — capture the pressed item + become the mouse target.
    virtual int OnMouseDown(int16_t x, int16_t y);
    // vtbl +0x0c @40a690 — on release over the pressed item, dispatch command
    // 0x1f40 (item = sender) and latch bLayoutInvalid.
    virtual int OnMouseUp(int16_t x, int16_t y);
    // vtbl +0x44 @40a710 — shaded/framed/tri-blended panel + each run's glyphs
    // (hovered item drawn in colorHighlight).
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);

    // -- non-virtual methods ---------------------------------------------------

    // @40a200 — recompute every item's rect (wrapping textA into the shared run
    // ring), re-align + reset the runs, re-layout the elements, then refresh
    // the hover item.
    void Relayout();
    // @40a3b0 — free every item, Relayout, clear bLayoutInvalid.
    void Clear();
    // @40a430 — append an item {data, val, textA, textB} and Relayout.
    void AddItem(void* pData, int val, char* pTextA, char* pTextB);
    // @40a550 — set pHoverItem to the item containing (x, y) (or NULL).
    void UpdateHoverItem(int16_t x, int16_t y);
};

// ---- dwGuiSpeech -------------------------------------------------------------
//
// Binary layout: dwGuiHypText base @0x00 (0x48) + drawStyle@0x48 +
// pTimedItem@0x4c + soundName@0x50 — sizeof 0x5c. vtable @0x51e7e8: overrides
// only DtorDelete + Draw; inherits everything else from dwGuiHypText.

struct dwGuiSpeech : dwGuiHypText
{
    uint32_t drawStyle;   // 0x48 (Ghidra: field48): FillTriBlend apex (packed dwPoint)
    void* pTimedItem;     // 0x4c: response item expired (its +0x14 = curMs) on Clear
    dwString soundName;   // 0x50: name of the speech sound currently playing

    // @40a8a0 (dwGuiSpeech_Ctor). notify -> the base OnHover payload;
    // color (low byte) -> base glyph color; pStyle's first dword -> drawStyle.
    dwGuiSpeech(dwRect* pRect, int notify, char* pFontName, uint32_t color, void* pStyle);

    // @40a990 (dwGuiSpeech_Dtor; DtorDelete @40a970) — free soundName + base.
    virtual ~dwGuiSpeech();

    // vtbl +0x44 @40aa90 — panel (only when there is caption text) + the base
    // dwGuiHypText::Draw.
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);

    // -- non-virtual methods ---------------------------------------------------

    // @40a9e0 (dwGuiSpeech_SetText) — replace the caption (virtual SetText),
    // bind the timed item, and remember the sound name. Called by
    // dwCog_PlayCharacterSpeech. Distinct from the inherited 1-arg SetText.
    using dwGuiHypText::SetText;
    void SetText(char* pText, void* pTimedItem, char* pSoundName);

    // @40aa30 (dwGuiSpeech_Clear) — stop the speech sound + free all samples,
    // and expire the timed item (stamps its +0x14 with the current game time).
    void Clear();
};

// ---- dwGuiDroidDance ---------------------------------------------------------
//
// Binary layout: dwGuiQuickView base @0x00 (0x574) + danceTimer@0x574 +
// groupIdx@0x578 + aGroups[7]@0x57c — sizeof 0x598. The inherited
// dwGuiQuickView::pNodes holds the CURRENTLY-ANIMATING (shared) part nodes;
// aGroups OWNS the 7 randomly-generated droids. vtable @0x51e850: overrides
// only DtorDelete + Update.

struct dwGuiDroidDance : dwGuiQuickView
{
    float danceTimer;    // 0x574: seconds until the next group swap
    int32_t groupIdx;    // 0x578: index of the group currently dancing
    dwList aGroups[7];   // 0x57c: 7 owned droids (each a dwPartNode* list)

    // @40ab70 (dwGuiDroidDance_Ctor) — build 7 random droids, pick one, play
    // its active anims, danceTimer = 12s, LayoutNodes.
    dwGuiDroidDance(dwRect* pRect);

    // @40acf0 (dwGuiDroidDance_Dtor; DtorDelete @40acd0) — empty the shared
    // active list (payloads owned by aGroups), destruct the 7 owned groups,
    // then the base dtor.
    virtual ~dwGuiDroidDance();

    // vtbl +0x14 @40adb0 — fade the active anims; when danceTimer expires pick
    // a new random group, stop the old anims, play the new group's, reset the
    // timer, LayoutNodes.
    virtual void Update(float dt);
};

#endif // __cplusplus

// ---- C FFI -------------------------------------------------------------------
//
// The dwGuiInGame factory allocates the object raw (pHS->alloc) then calls
// these C-linkage ctors; Clear is invoked from the HUD segment loop. These
// implement the dwMain.c placeholders of the same name (delete those).

#ifdef __cplusplus
extern "C" {
#endif

dwGuiList* dwGuiList_Ctor(dwGuiList* pThis, dwRect* pRect, float a, char* pFont,
                          uint8_t c, uint8_t d, void* pPoint);
void dwGuiList_Clear(dwGuiList* pList);
dwGuiSpeech* dwGuiSpeech_Ctor(dwGuiSpeech* pThis, dwRect* pRect, int a, char* pFont,
                              uint32_t c, void* pPoint);
void dwGuiSpeech_Clear(dwGuiSpeech* pSpeech);

// Added: C shim over `new dwGuiDroidDance(pRect)` (dwGuiCredits is C++ and can
// `new` directly; provided for any C-side factory). Returns a dwWidget*.
dwWidget* dwGuiDroidDance_New(dwRect* pRect);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // _DWGUILIST_H
