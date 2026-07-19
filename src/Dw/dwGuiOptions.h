#ifndef _DWGUIOPTIONS_H
#define _DWGUIOPTIONS_H

// dwGuiOptions — the main-menu / sign-in / options flow.
// DroidWorks.exe unit range: 0x423180-0x42607f. FOUR widget/screen classes +
// TWO dwSegment sequencers:
//
//   dwGuiRanking  (0x38, vtbl 0x51f250, : dwWidget) — the STATS_JOB mission
//                 rank/requirements card: mission name, GOAL list for the
//                 mission's current rank tier (with live checkboxes read from
//                 the in-game inventory), a REQUIREMENTS list, and the
//                 APPRENTICE/DESIGNER/MASTER rank row with the earned rank
//                 highlighted. Fed a dwMission* by widget message 0xBBC.
//   dwGuiLongAgo  (0xd4, vtbls 0x51f308/0x51f2f0, : dwGuiScreen) — the
//                 'longago' Star-Wars-intro card: a palette-fade state
//                 machine (0.5s fade-in, 4s hold, 4s fade-out) over the
//                 static screen, then advances the segment flow.
//   dwGuiOpening  (0x44, vtbl 0x51f358, : dwMovie) — the 'Opening.san' text
//                 crawl: Activate pre-renders opening.txt into a tall 8bpp
//                 crawl bitmap; Draw projects it in perspective over the
//                 movie frames (frames 100..622 of the SMUSH playback).
//   dwGuiOptions  (0xfc, vtbls 0x51f3b0/0x51f398, : dwGuiScreen) — ONE screen
//                 class hosting SIX sub-screens {optMain,optHelp,optGame,
//                 optGameNew,optGameLoad,optSetup} (.ifc scripts) swapped by
//                 LoadSubScreen; the msg-6000 command switch drives the whole
//                 menu flow (new/load/delete game, credits, replays, setup).
//   dwGuiIntroSeg (0x18, vtbl 0x51ee28, : dwSegment) — the new-player intro
//                 sequencer: longago -> Opening crawl -> tutorial prompt +
//                 sign-in videos -> workshop / options.
//   dwGuiOptionsEnterSeg (0x1c, vtbl 0x51ee10, : dwSegment; Ghidra
//                 "dwGuiOptions_EnterSeg") — plays OStart[2].san then pushes
//                 the options screen at a given sub-screen index. This is the
//                 segment the dwGuiScreen msg-0x65 command constructs.
//
// SMUSH (.san) playback runs via libsmusher (P8): the movie segments play
// for real and the crawl scrolls/fades off the frame counter.
//
// Compiled as C++ (vtables, ctor/dtor pairs, MSVC EH frames). The segment
// factories keep C linkage for the C boot flow (dwMain, P7).

#include "Dw/dwTypes.h"

#ifdef __cplusplus
struct dwGuiRanking;
struct dwGuiLongAgo;
struct dwGuiOpening;
struct dwGuiOptions;
struct dwGuiIntroSeg;
struct dwGuiOptionsEnterSeg;
extern "C" {
#else
// C++ classes; opaque in the C view.
typedef struct dwGuiRanking dwGuiRanking;
typedef struct dwGuiLongAgo dwGuiLongAgo;
typedef struct dwGuiOpening dwGuiOpening;
typedef struct dwGuiOptions dwGuiOptions;
typedef struct dwGuiIntroSeg dwGuiIntroSeg;
typedef struct dwGuiOptionsEnterSeg dwGuiOptionsEnterSeg;
#endif

typedef struct dwSegment dwSegment; // Dw/dwSegment.h (repeated typedef is valid C11/C++)
typedef struct dwImage dwImage;     // Dw/dwImage.h

// Reset the whole game-progress state for a fresh/loaded profile: player +
// workspace names back to the DFLT_* string-table defaults, stats flags
// cleared, workspace part nodes freed, missions relocked (bDone/rank cleared,
// bUnlocked = missionType==NORMAL, first unlocked becomes
// dwCore_pCurrentMission), blueprints re-marked available unless RESTRICTED.
// Called by the new/load/delete-game commands here; dwGuiInGame (P6 wave 2)
// has no binary xref. @424ae0
void dwGuiOptions_ResetGameState(void);

// Added: C factory for dwGuiOptionsEnterSeg (the binary constructed it
// inline: alloc 0x1c + dwSegment_Ctor + fields + vtbl 0x51ee10). Callers:
// dwGuiScreen_OnMessage msg 0x65 (screenIndex 0 — wire the TODO stub there)
// and the P7 boot flow (StartOpeningCutscenes, screenIndex 0).
dwSegment* dwGuiOptions_NewEnterSeg(int screenIndex);

// The full-screen movie SEGMENT factory, by filename extension
// (case-insensitive): FLC/FLI -> new dwFlicSeg(pFilename, pOverlayImage),
// SAN -> new dwSmushSeg(pFilename, pOverlayImage-as-context). Unknown/missing
// extensions (and BLN — compared nowhere here) log "Error opening animation"
// and return NULL. @4029c0 (Ghidra: jkSmack_SmackPlay — a version-tracking
// misnomer; this is the segment twin of dwAnim_Open and physically belongs
// to the dwAnim/dwMovie unit, P3 — implemented in dwGuiOptions.cpp for now,
// relocation to dwMovie.cpp is the orchestrator's call.)
dwSegment* dwMovie_OpenSeg(const char* pFilename, dwImage* pOverlayImage);

// Note: no binary counterpart — the unit owns no module statics; kept for
// the project-wide soft-reset convention.
void dwGuiOptions_Startup(void);

#ifdef __cplusplus
} // extern "C"

#include "Dw/dwWidget.h"
#include "Dw/dwGuiScreen.h"
#include "Dw/dwMovie.h"
#include "Dw/dwSegment.h"
#include "Dw/dwString.h"
#include "Dw/dwRect.h"
#include "Dw/dwFont.h"
#include "Dw/dwList.h"

struct dwMission;         // Dw/dwMission.h
struct dwGuiTextEntry;    // Dw/dwGuiTextEntry.h
struct dwGuiScrollBox;    // Dw/dwGuiWidgets.h
struct dwGuiScrollBar;    // Dw/dwGuiWidgets.h
struct dwGuiScrollButton; // Dw/dwGuiWidgets.h

// ---- dwGuiRanking ------------------------------------------------------------
//
// Binary layout: dwWidget base @0x00 (0xe) + fields from 0x10 — sizeof 0x38.
// vtable @0x51f250 (dwGuiRanking_vtbl): overrides dtor/OnHover/OnMessage/Draw
// (Update is the inherited dwGui_NullVirtual default).
//
// Field-name note: Ghidra's bAltAlign/rankIndex labels are wrong — both are
// COLOR indices (they feed dwFont draw color params); kept as labelColor/
// valueColor here with the Ghidra names in comments.

struct dwGuiRanking : dwWidget
{
    dwMission* pMission;    // 0x10 (Ghidra: pPlayerData): the displayed mission
                            //      (ctor: dwCore_pCurrentMission; msg 0xBBC
                            //      sender replaces it)
    dwFont* pFontLabel;     // 0x14: header font (mission name, RANKING:)
    uint8_t labelColor;     // 0x18 (Ghidra: bAltAlign): header/line/checkbox color
    dwFont* pFontValue;     // 0x1c: list font (goal/requirement rows, rank row)
    uint8_t valueColor;     // 0x20 (Ghidra: rankIndex): row-text color; also the
                            //      highlight for the earned rank's name
    uint8_t aRankColors[3]; // 0x21-0x23 (Ghidra: colorR/G/B): APPRENTICE/
                            //      DESIGNER/MASTER label colors (all set to the
                            //      dimmed valueColor; the earned rank gets the
                            //      full valueColor)
    // Localized header strings (string-table storage — NOT owned):
    char* strRequirements;  // 0x24
    char* strRanking;       // 0x28
    char* strApprentice;    // 0x2c
    char* strDesigner;      // 0x30
    char* strMaster;        // 0x34

    // @423180 (dwGuiRanking_Ctor) — dwWidget(pRect); loads the two fonts,
    // localizes the five header strings, then seeds the colors/mission by
    // self-sending { 0xBBC, dwCore_pCurrentMission }.
    dwGuiRanking(dwRect* pRect, char* pFontLabelName, uint8_t labelColor,
                 char* pFontValueName, uint8_t valueColor);

    // @4232f0 (dwGuiRanking_Dtor; scalar-deleting wrapper @4232d0) — frees
    // the two font handles.
    virtual ~dwGuiRanking();

    // vtbl +0x18 @4239d0 — dispatch { 0x7531, (void*)0x791b } (the hover
    // help-text notification); return 1.
    virtual int OnHover(int16_t x, int16_t y);

    // vtbl +0x1c @423a00 — 0xBBC: adopt pMsg->pSender as the mission, dim
    // the three rank colors from valueColor (half-brightness closest-match
    // over palette entries 5..147), highlight the earned rank, Invalidate.
    // Returns 0.
    virtual int OnMessage(dwWidgetMsg* pMsg);

    // vtbl +0x44 @423370 — the full card: mission name + goal rows (with
    // inventory-live checkboxes) + REQUIREMENTS rows + RANKING: rank row.
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);
};

// ---- dwGuiLongAgo ------------------------------------------------------------
//
// Binary layout: dwGuiScreen base @0x00 (0xc8) + fadeState@0xc8 +
// palFadeId@0xcc + fadeTimer@0xd0 — sizeof 0xd4. Primary vtbl @0x51f308
// overrides dtor/OnKey(+0x10)/Update(+0x14); secondary @0x51f2f0 overrides
// Activate/Deactivate.

struct dwGuiLongAgo : dwGuiScreen
{
    int32_t fadeState;  // 0xc8: 0 = fading in, 1 = holding, 2 = fading out
    int32_t palFadeId;  // 0xcc: stdPalEffects request id (-1 until Activate)
    float fadeTimer;    // 0xd0: seconds in the current fade phase

    // @423e80 (dwGuiLongAgo_Ctor) — dwGuiScreen("longago", NULL).
    dwGuiLongAgo();

    // @423ee0 (dwGuiLongAgo_Dtor; scalar-deleting wrapper @423ec0; secondary
    // thunk @424ad0) — no own resources (base teardown only).
    virtual ~dwGuiLongAgo();

    // vtbl +0x10 @424220 — ESC requests the segment advance, then the base
    // (cheat-code) OnKey.
    virtual int OnKey(int key, int repeat);

    // vtbl +0x14 @424110 — the fade state machine: fade-in over 0.5s, hold
    // 4s, fade-out over 4s then advance; pushes the fade level through
    // stdPalEffects every tick, then ticks the controls group.
    virtual void Update(float dt);

    // scn vtbl +0x00 @423ef0 — base Activate, hide the cursor, clear the
    // screen to the transparent index, request a stdPalEffects fade slot at
    // level 0 (fully dark) and refresh the palette.
    virtual int Activate();

    // scn vtbl +0x04 @423fd0 — base Deactivate, clear BOTH buffers (fill +
    // present + fill), restore fade level 1, release the fade slot.
    virtual void Deactivate();
};

// ---- dwGuiOpening ------------------------------------------------------------
//
// Binary layout: dwMovie base @0x00 (0x40) + pCrawlImage@0x40 — sizeof 0x44.
// vtable @0x51f358: overrides Activate (+0x00, Ghidra: BuildCrawl), dtor
// (+0x14) and Draw (+0x18, Ghidra: dwGuiOpening_Update — a slot mislabel).

struct dwGuiOpening : dwMovie
{
    dwImage* pCrawlImage; // 0x40: the pre-rendered crawl text bitmap
                          //      (600 x lineHeight*lineCount, 8bpp; owned)

    // @424250 (dwGuiOpening_Ctor) — dwMovie("Opening.san").
    dwGuiOpening();

    // @424290 (dwGuiOpening_Dtor; scalar-deleting wrapper @424270) — deletes
    // the crawl image.
    virtual ~dwGuiOpening();

    // vtbl +0x00 @4242f0 (Ghidra: dwGuiOpening_BuildCrawl — the Activate
    // slot) — loads opening.cmp, renders every opening.txt line (byte0
    // format: '!' centered / '$' blank / '*' justified / default left) into
    // the tall crawl bitmap with the file's font, then dwMovie::Activate().
    virtual int Activate();

    // vtbl +0x18 @424730 (Ghidra: dwGuiOpening_Update — really the Draw
    // slot) — base overlay draw, then the perspective-projected crawl:
    // 430 dest scanlines (y 50..479) each box-filter-resampled from the
    // crawl bitmap (dwGuiOpening_ResampleSpan), scrolling with the SMUSH
    // frame counter over frames 100..622 (fade-out from frame 590).
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);
};

// ---- dwGuiOptions ------------------------------------------------------------
//
// Binary layout: dwGuiScreen base @0x00 (0xc8) + own fields below — sizeof
// 0xfc. Primary vtbl @0x51f3b0 overrides dtor/Update(+0x14)/OnMessage(+0x1c)/
// CreateControl(+0x48); secondary @0x51f398 overrides Activate/Deactivate.

struct dwGuiOptions : dwGuiScreen
{
    dwGuiTextEntry* pNameEntry;        // 0xc8: PLAYERNAME edit box (editing enteredName)
    dwGuiScrollBox* pScrollBox;        // 0xcc: SCROLLBOX profile list
    dwGuiScrollBar* pNameScrollBar;    // 0xd0: NAMESCROLLBAR
    dwGuiScrollButton* pScrollUpBtn;   // 0xd4: SCROLLUPBUTTON
    dwGuiScrollButton* pScrollDownBtn; // 0xd8: SCROLLDOWNBUTTON
                                       // (all owned by the controls group;
                                       //  cleared on Deactivate)
    dwString enteredName;              // 0xdc: PLAYERNAME text (new-game name)
    uint8_t bNoProfiles;               // 0xe8: no profiles existed at ctor time
                                       //      (first-run: new-game launches the
                                       //      full intro sequence)
    int32_t screenIndex;               // 0xec: current sub-screen index (0-5)
    dwString selectedName;             // 0xf0: SCROLLBOX selection (profile name)

    // @424c30 (dwGuiOptions_Ctor) — dwGuiScreen(subScreenNames[screenIndex],
    // NULL); creates the options.txt string table (base pStringTable);
    // bNoProfiles = (dwPlayer_EnumProfiles found none).
    // Note: the binary zeroes only pNameEntry, leaving the other four
    // control pointers uninitialized until CreateControl — all zeroed here.
    dwGuiOptions(int screenIndex);

    // @424e10 (dwGuiOptions_Dtor; scalar-deleting wrapper @424df0; secondary
    // thunk @426070) — frees the two dwStrings (implicit here).
    virtual ~dwGuiOptions();

    // vtbl +0x14 @425830 — forward the tick to the controls group only.
    virtual void Update(float dt);

    // vtbl +0x1c @424f50 — THE menu command switch on (code - 6000); see the
    // case comments in dwGuiOptions.cpp. Chains to the base OnMessage unless
    // the LOAD/DELETE commands fully handled the message.
    virtual int OnMessage(dwWidgetMsg* pMsg);

    // vtbl +0x48 @425900 — SCROLLBOX (+ profile list fill) / TEXT_TOGGLE /
    // BGT_/SZE_/MVOL_/SVOL_SCROLLBAR (setting-seeded scrollbars) /
    // PLAYERNAME / SCROLLUP/DOWNBUTTON / NAMESCROLLBAR / CUTSCENE
    // (stats-flag-gated replay entries); falls back to the base factory.
    virtual dwWidget* CreateControl(char* pKeyword, dwConfFile* pConf);

    // scn vtbl +0x00 @424e80 — clear the selection, base Activate (lazy
    // LoadControls), then begin editing the name box.
    virtual int Activate();

    // scn vtbl +0x04 @424ec0 — rebuild dwPlayer_profileDir from
    // basePath + dwPlayer_name + '\', base Deactivate, drop the five
    // control pointers (the controls group owns/frees the widgets).
    virtual void Deactivate();

    // @425850 (dwGuiOptions_LoadSubScreen) — scriptName =
    // "<subScreenNames[index]>.ifc", destroy the current controls, then
    // virtual Deactivate() + Activate() to rebuild.
    void LoadSubScreen(int index);
};

// ---- dwGuiIntroSeg -----------------------------------------------------------
//
// Binary layout: dwSegment @0x00 (0x14) + state@0x14 — sizeof 0x18. vtable
// @0x51ee28: overrides only Activate (+0x00 @423b10, Ghidra:
// dwGuiIntroSeg_Update — the manager re-Activates it after each interruption,
// which is what steps the state machine).

struct dwGuiIntroSeg : dwSegment
{
    int32_t state; // 0x14: 0 = longago next, 1 = Opening crawl next,
                   //       2 = tutorial prompt + sign-in videos, 3 = done

    // (ctor inlined at the construction site — dwGuiOptions_OnMessage 0xD)
    dwGuiIntroSeg();

    // vtbl +0x00 @423b10 — run the state machine: state 0/1 interrupt the
    // flow with the longago screen / Opening crawl (returning here); state 2
    // asks DLG_WORKTUT (tutorial y/n), enumerates profiles and stacks the
    // JawaOut/SignIn videos + workshop/options entry accordingly; state 3
    // requests the advance (this segment retires).
    virtual int Activate();
};

// ---- dwGuiOptionsEnterSeg ------------------------------------------------------
//
// Binary layout: dwSegment @0x00 (0x14) + screenIndex@0x14 + bStarted@0x18 —
// sizeof 0x1c. vtable dwGuiOptions_EnterSeg_vtbl @0x51ee10: overrides only
// Activate (+0x00 @425fa0, Ghidra: dwGuiOptions_EnterSeg_Update).

struct dwGuiOptionsEnterSeg : dwSegment
{
    int32_t screenIndex; // 0x14: sub-screen the options screen opens at
    int32_t bStarted;    // 0x18: the OStart movie already ran

    // (ctor inlined at the construction sites — dwGuiScreen_OnMessage 0x65,
    // dwGuiIntroSeg::Activate, StartOpeningCutscenes)
    dwGuiOptionsEnterSeg(int screenIndex);

    // vtbl +0x00 @425fa0 — first activation: start option.wav and interrupt
    // with the OStart.san (OStart2.san for indices 2/3) movie, returning
    // here; second activation: push-and-advance into the options screen.
    virtual int Activate();
};

#endif // __cplusplus

#endif // _DWGUIOPTIONS_H
