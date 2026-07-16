#ifndef _DWGUISCREEN_H
#define _DWGUISCREEN_H

// dwGuiScreen — THE foundational DroidWorks SCREEN base class. Every DW
// screen (dwWorkshop, dwGuiStatus, dwGuiReference, dwGuiMissionMap,
// dwGuiInGame, dwGuiOptions, dwGuiCredits, dwGuiLoadSave, dwGuiFind, ...)
// derives from it.
//
// Decompiled from DroidWorks.exe, unit range 0x42f930-0x43214f, plus the base
// EnsureImages/FreeImages defaults @0x432150/0x432170 (physically just past
// the unit end, mis-binned into the dwGuiWidgets range) and two shared-COMDAT
// forwarder slot bodies: Update(dt) @0x41c510 (Ghidra: mis-attributed
// dwGuiMission_ForwardUpdate) and OnHover @0x40ba70 (undetected fn in the
// dwGuiCredits range).
//
// MSVC multiple inheritance (binary): PRIMARY vtable dwGuiScreen_vtbl
// @0x51f770 (dwWidget shape + 2 NEW slots: +0x48 CreateControl factory,
// +0x4c CheckCheatCodes) with this = obj+0; SECONDARY "scn" vtable
// dwGuiScreen_scn_vtbl @0x51f7c0 (the 6-slot dwSegment lifecycle iface) for
// the dwSegment subobject embedded at binary obj+0x10. In this translation
// that is simply `struct dwGuiScreen : dwWidget, dwSegment` — the compiler
// generates the this-adjustor thunks the binary carried by hand.
//
// NOTE the screen does NOT derive dwWidgetGroup: it derives dwWidget and
// EMBEDS a full-screen dwWidgetGroup member ("controls" @binary 0x50) that
// owns the child controls built by LoadControls; the input/tick/draw
// overrides forward into that member. (An earlier survey mislabeled the
// embedded group's vptr/bEnabled/children fields as pFocusChild/
// bHasFocusChild/pControlsList.)
//
// A screen is an app-flow segment: the dwSegment side is what dwSegment_Push/
// _Tick drive. Activate (Ghidra: dwGuiScreen_OnActivate) lazily builds the
// controls from "<name>.cmp", loads the screen colormap and starts the
// AMBIENT music; Deactivate (dwGuiScreen_OnHide) flushes the tooltip and
// frees cached sound samples; Update(void) (dwGuiScreen_SegUpdate) is the
// per-frame tick: ~45Hz widget Update broadcast, tooltip idle timing (0.75s
// hover), tutorial auto-exit, and the dirty-rect repaint + present.
//
// Widget-side extras: OnKey is the CHEAT-CODE entry point (rolls typed chars
// into a 15-char ring buffer; Enter/Ctrl-C submits it to virtual
// CheckCheatCodes — SOMONEY/FITTO/BEEFCAKE/DEFCON0-3/MST3K in the base);
// OnMessage handles the screen-switch command codes 0x65-0x6c and the
// tutorial enter/exit messages 0x792a/0x7932 (hidden tutorial-exit hotspots
// dispatch dwWidgetMsg {0x7932, 0, 0, 0}); Draw paints background image +
// controls + the hover tooltip.
//
// Compiled as C++ (two vtables, ctor/dtor pair, MSVC EH frames). The class is
// C++-only; C consumers see the opaque typedef plus the C-linkage free
// functions below (dwGuiScreen_LocalizeString is THE game-wide string-table
// lookup used by every text-building unit).

#include "Dw/dwTypes.h"
#include "Dw/dwWidget.h" // dwWidget base + dwWidgetMsg + dwRect

#ifdef __cplusplus
struct dwGuiScreen;    // C++ class below
struct dwStringTable;  // real class in Dw/dwStringTable.h (C++-only header)
extern "C" {
#else
typedef struct dwGuiScreen dwGuiScreen;       // C++ class; opaque in the C view
typedef struct dwStringTable dwStringTable;   // C++ class; opaque in the C view
#endif

typedef struct dwConfFile dwConfFile; // Dw/dwConfFile.h (plain-C struct; repeated typedef is valid C11/C++)

// ---- plain-C shared types ---------------------------------------------------

// One LABEL/LABEL_RECT record (binary alloc 0xc): a screen rect plus the
// localized tooltip/label text (pText points INTO a string table — not
// owned). The screen's `labels` list holds these; the tooltip machinery
// (OnMouseMove hover tracking + Update(void) idle timing + Draw) reads them.
typedef struct dwGuiScreenLabel
{
    int16_t left;   // 0x00
    int16_t top;    // 0x02
    int16_t right;  // 0x04
    int16_t bottom; // 0x06
    char* pText;    // 0x08: localized text (string-table storage, not owned)
} dwGuiScreenLabel;

// ---- C-linkage free functions -----------------------------------------------

// THE game-wide string-table lookup: skips leading whitespace, then looks the
// key up in pTable (when non-NULL), falling back to the global table
// dwCore_pGlobalStrings; returns the localized string's buffer, or the
// trimmed key itself when no table has it (callers use `result == input` as
// the "not found" test). ⚠ pStr must be non-NULL (the binary dereferences it
// unconditionally). @42fed0
char* dwGuiScreen_LocalizeString(char* pStr, dwStringTable* pTable);

// The COMMON control factory shared by every screen: builds the keyword ->
// control classes that need no screen state (ANIMATION/ANIM_PLAY/BUTTON/
// BUTTON_BLINK/BUTTON_TEXT[_LEFT]/HELPRECT/IMAGE/INDICATOR/QUICKVIEW/
// RADIOGROUP/RECT/SCROLLBAR/STATS_DROID/STATS_JOB/STATS_PART/TEXT/TOGGLE).
// pStringTable is the caller screen's local table (for text localization).
// Returns the new control or NULL (unknown keywords log "Unrecognized UI
// control"). The virtual dwGuiScreen::CreateControl falls back here; the only
// other binary caller is dwEnding_OnActivate. Returns dwWidget* (opaque in
// the C view). @42ff60 (Ghidra: dwGuiScreen_CreateControl — the free
// function, distinct from the virtual factory slot @430a10)
#ifdef __cplusplus
dwWidget* dwGuiScreen_CreateControl(char* pKeyword, dwConfFile* pConf, dwStringTable* pStringTable);
#else
struct dwWidget* dwGuiScreen_CreateControl(char* pKeyword, dwConfFile* pConf, dwStringTable* pStringTable);
#endif

// Note: no binary counterpart — the unit owns no module statics; kept for the
// project-wide soft-reset convention (and as the seam if statics appear).
void dwGuiScreen_Startup(void);

#ifdef __cplusplus
} // extern "C"

#include "Dw/dwWidgetGroup.h"
#include "Dw/dwSegment.h"
#include "Dw/dwString.h"
#include "Dw/dwList.h"
#include "Dw/dwFont.h" // dwFont handle (plain-C struct)

struct dwAnim;   // Dw/dwAnim.h (tutorial FLC widget)
struct dwImage;  // Dw/dwImage.h (background/snapshot images)

struct dwGuiScreen : dwWidget, dwSegment
{
    // (binary: dwWidget base @0x00, dwSegment subobject @0x10)
    // Members below in binary field ORDER (offsets differ on 64-bit).

    dwString scriptName;        // 0x24: "<ctor name>.cmp" — the controls script
                                //       parsed by LoadControls on first Activate
    dwString colormapName;      // 0x30: COLORMAP keyword; loaded on Activate
                                //       (and immediately on 16bpp displays)
    dwString musicName;         // 0x3c: AMBIENT keyword; dwSound_SetMusic on
                                //       Activate + tutorial exit
    dwImage* pBgImage;          // 0x48: background image (ctor param copy, or
                                //       BACKGROUND keyword; later BACKGROUND
                                //       lines composite onto it)
    dwImage* pSnapshotImage;    // 0x4c: 60%-shaded screen snapshot captured by
                                //       the 0x66/0x68 screen-switch commands
                                //       and handed to the spawned sub-screen;
                                //       freed on (re-)Activate. (Ghidra's
                                //       struct labeled 0x48/0x4c swapped.)
    dwWidgetGroup controls;     // 0x50: EMBEDDED full-screen group owning the
                                //       controls built by LoadControls
                                //       (children list = binary 0x60)
    dwFont* pTooltipFont;       // 0x68: LABEL_INFO font (heap dwFont handle)
    uint8_t tooltipBgColor;     // 0x6c: LABEL_INFO 1st color (tooltip fill)
    uint8_t tooltipTextColor;   // 0x6d: LABEL_INFO 2nd color (tooltip text)
    dwGuiScreenLabel* pTooltipTarget; // 0x70: label record under the cursor
                                      //       (points into `labels`, not owned)
    dwRect tooltipRect;         // 0x74: tooltip box (laid out in Update(void))
    uint8_t bTooltipVisible;    // 0x7c
    float hoverStartSec;        // 0x80: GetElapsed() when the cursor entered
                                //       pTooltipTarget (tooltip shows after 0.75s)
    dwList labels;              // 0x84: dwGuiScreenLabel* payloads (owned)
    dwStringTable* pStringTable;// 0x88: STRINGTABLE keyword (screen-local table)
    float lastTickSec;          // 0x8c: last widget-Update broadcast time
                                //       (ticks at >= 0.022s intervals)
    uint8_t bActive;            // 0x90: one-shot "pick a control" mode (msg
                                //       0x7530 arms it; OnMouseDown/Up use it)
    dwWidget* pPickedWidget;    // 0x94: HitTest result captured by OnMouseDown
                                //       while bActive (OnHover'd on mouse-up)
    uint8_t bModal;             // 0x98: tutorial playback in progress (0x792a
                                //       sets, 0x7932 clears; gates Esc + tooltip)
    uint8_t bTutorialHold;      // 0x99: set by subclasses to hold the tutorial
                                //       open after the cue playlist drains
                                //       (never set in this unit; cleared on exit)
    dwString tutorialMusicName; // 0x9c: TUTORIAL 2nd token (tutorial music)
    dwString tutorialRecName;   // 0xa8: TUTORIAL 1st token (.rec input-cue file
                                //       replayed by dwSegment_Play)
    dwAnim* pTutorialAnim;      // 0xb4: TUTORIAL FLC widget; re-appended to
                                //       `controls` + played on 0x792a, stopped
                                //       + unlinked on 0x7932 (owned)
    uint8_t cheatIndex;         // 0xb8: ring index into cheatBuffer
    char cheatBuffer[0xf];      // 0xb9: typed cheat-code ring (NUL-rolled)
    // (binary sizeof 0xc8)

    // pName = screen name (scriptName becomes "<pName>.cmp" when non-empty);
    // pBgSrc = optional source image copied into pBgImage (8bpp display: a
    // screen-sized stdBitmapRle2 copy; 16bpp: an owned dwImageVBuf copy).
    // @42f930 (dwGuiScreen_Ctor)
    dwGuiScreen(const char* pName, dwImage* pBgSrc);

    // Frees images/tutorial anim/string table/tooltip font/labels; the
    // embedded `controls` group dtor then deletes the child controls.
    // @42fb30 (dwGuiScreen_Dtor; scalar-deleting wrapper @42fb10 = primary
    // vtbl +0x00, shared by the secondary vtbl's +0x14 thunk @432290)
    virtual ~dwGuiScreen();

    // ---- dwWidget overrides (primary vtbl @0x51f770, slot order) -----------
    virtual int OnMouseMove(int16_t x, int16_t y);  // +0x04 @4318a0 — tooltip hover tracking, then forward to `controls`
    virtual int OnMouseDown(int16_t x, int16_t y);  // +0x08 @431980 — pick mode capture, else forward
    virtual int OnMouseUp(int16_t x, int16_t y);    // +0x0c @4319f0 — pick mode resolve (OnHover the picked widget), else forward
    virtual int OnKey(int key, int repeat);         // +0x10 @431ad0 — Esc exits a tutorial; cheat-code ring; forward
    virtual void Update(float dt);                  // +0x14 @41c510 (shared COMDAT; Ghidra: dwGuiMission_ForwardUpdate) — forward to `controls`
    virtual int OnHover(int16_t x, int16_t y);      // +0x18 @40ba70 (undetected COMDAT) — forward to `controls`
    virtual int OnMessage(dwWidgetMsg* pMsg);       // +0x1c @4312d0 — screen-switch commands 0x65-0x6c, 0x96 advance, 0x7530 pick mode, 0x792a/0x7932 tutorial; forward
    virtual void EnsureImages();                    // +0x3c @432150 — tutorial anim + `controls`
    virtual void FreeImages();                      // +0x40 @432170 — tutorial anim + `controls`
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect); // +0x44 @431240 — background + controls + tooltip

    // ---- NEW virtual slots (appended after dwWidget's +0x44) ---------------
    // The keyword -> control factory called per script line by LoadControls.
    // Handles the screen-level keywords (BACKGROUND/AMBIENT/CLOCK/COLORMAP/
    // LABEL_INFO/LABEL/LABEL_RECT/STRINGTABLE/TEXTPOPUP/TIMER/TUTORIAL/
    // WIDGETBAR) and falls back to the common dwGuiScreen_CreateControl.
    // Subclass screens override this slot (their Ghidra *_CreateControl).
    // +0x48 @430a10 (Ghidra: dwGuiScreen_CreateControl2)
    virtual dwWidget* CreateControl(char* pKeyword, dwConfFile* pConf);
    // Cheat-code matcher fed by OnKey on Enter/Ctrl-C. Base cheats:
    // SOMONEY/FITTO/BEEFCAKE/DEFCON0-3/MST3K (subclasses override and chain).
    // +0x4c @431f50 (dwGuiScreen_CheckCheatCodes)
    virtual void CheckCheatCodes(char* pCode);

    // ---- dwSegment overrides (secondary "scn" vtbl @0x51f7c0, slot order) --
    virtual int Activate();    // +0x00 @431b90 (Ghidra: dwGuiScreen_OnActivate) — lazy LoadControls, free snapshot, colormap, pDefault=this, cursor, music, Invalidate
    virtual void Deactivate(); // +0x04 @431c30 (Ghidra: dwGuiScreen_OnHide) — flush tooltip, clear pDefault, free cached sound samples
    virtual void Suspend();    // +0x08 @431a70 (Ghidra: dwGuiScreen_SegSuspend) — dispatch {0x7932} (exit tutorial), Disable(), base Suspend
    virtual void Resume();     // +0x0c @431ab0 (Ghidra: dwGuiScreen_SegResume) — Enable(), base Resume, pDefault=this
    virtual void Update();     // +0x10 @431c60 (Ghidra: dwGuiScreen_SegUpdate) — tutorial auto-exit, ~45Hz widget tick, tooltip idle, repaint+present
    // (+0x14 = the compiler's dtor thunk @432290 — implicit here)

    // ---- non-virtual methods ------------------------------------------------

    // Parse the controls script: per line, keyword -> virtual CreateControl;
    // non-NULL results are appended to `controls`' child list. Ends with a
    // (virtual) Invalidate. @42fdf0 (dwGuiScreen_LoadControls)
    void LoadControls(char* pScriptPath);

    // If a tooltip target is latched: dirty its rect and clear target +
    // visibility. @42ff30 (dwGuiScreen_FlushTooltipDirty)
    void FlushTooltipDirty();

    // Repaint this screen into the locked display surface — every dirty rect
    // (or one full-screen pass when dwMain_bFullRedraw). Does NOT present.
    // @431e90 (dwGuiScreen_RenderActive)
    void RenderActive();
};

#endif // __cplusplus

#endif // _DWGUISCREEN_H
