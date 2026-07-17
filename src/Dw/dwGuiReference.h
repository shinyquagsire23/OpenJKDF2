#ifndef _DWGUIREFERENCE_H
#define _DWGUIREFERENCE_H

// dwGuiReference — the "reference" ROOM screen (the in-game encyclopedia /
// droid-parts reference browser). A dwGuiScreen subclass (MSVC MI: primary
// vtbl 0x51f710, secondary "scn" vtbl 0x51f6f8) that hosts:
//   - a topic browser + per-topic .ifc "info card" control scripts rebuilt on
//     the fly (BuildDynamicControls) as the selected page changes,
//   - the material-properties GRAPH + scrollable PULLDOWN_MENU content
//     controls (owned by the dwRef unit — Dw/dwRef.h),
//   - the CONTROLPANEL hotspot container (Dw/dwControlPanel.h),
//   - the RefIntro.san / RefRoom.san intro videos (PlayIntroVideo), and
//   - the parental-lockout-gated LAUNCH_URL "go to the web site" flow.
//
// Decompiled from DroidWorks.exe, unit range 0x42a240-0x42f92f. Struct 0x124
// (dwGuiScreen base 0xc8 + the fields below). This unit also OWNS three helper
// classes: dwGuiRefRadioGroup + dwGuiRefRadioButton (a radio-button tab list —
// physically defined in Dw/dwGuiMission.h, which landed them early because
// dwGuiObjectiveBtn derives the button; this header REUSES them via that
// include and adds the missing AddCategory factory helper) and dwGuiRefTile (a
// nested-frame decoration widget, defined here).
//
// Everything verifiably C++ (two vtables, ctor/dtor pair, MSVC EH frames).
//
// ⚠ TRANSLATION STATUS (updated 2026-07-17): the three giant screen methods
// (Activate/OnMessage/Update), BuildDynamicControls, the data/lifecycle methods,
// dwGuiRefTile, the internet helpers and the GRAPH/PULLDOWN_MENU/CONTROLPANEL/
// CAT_RADIOGROUP/BUTTONHELPRECT/ICON_ANIM_PLAY factory branches are now fully
// translated. The "base-overlay ambiguity" was resolved via the disassembly:
// scn-side methods (Activate) get the dwSegment subobject as `this` (+0x10) —
// the C++ compiler regenerates that thunk, so real member access is exact; the
// decompiler's `param_1_00[1].FIELD` overlay names were heuristic (no struct)
// and the actual code uses direct this-relative offsets that match this struct.
// REMAINING stubs: PlayIntroVideo (belongs on a small dwGuiRefIntroSeg dwSegment
// subclass reached via dwGuiScreen msg 0x6a — recipe in .cpp) and BuildAnimViewer
// (ANIM_VIEWER/BACKDROP/BILEVEL/STILL_FRAME CreateControl branches; the Ghidra
// decompile is register-corrupted — needs a disasm-level pass). Both fall
// through to the base factory today. See dwGuiReference.cpp.

#include "Dw/dwTypes.h"
#include "Dw/dwRect.h"

#ifdef __cplusplus
struct dwGuiReference;
struct dwGuiRefTile;
struct dwConfFile;
extern "C" {
#else
typedef struct dwGuiReference dwGuiReference;
typedef struct dwGuiRefTile dwGuiRefTile;
typedef struct dwConfFile dwConfFile;
#endif

// No binary counterpart; kept for the project-wide soft-reset convention.
void dwGuiReference_Startup(void);

#ifdef __cplusplus
} // extern "C"

// dwGuiMission.h carries the canonical dwGuiRefRadioGroup / dwGuiRefRadioButton
// class definitions (owner = THIS unit; landed there early). REUSE them — do
// not redefine. This include pulls in dwGuiScreen + dwWidget + dwWidgetGroup +
// dwString + dwList too.
#include "Dw/dwGuiMission.h"

// @42a6f0 (dwGuiRefRadioGroup_AddCategory) — the CAT_RADIOGROUP / CP_RADIOGROUP
// per-item factory helper (a __thiscall on the group in the binary; rendered
// here as a free function taking the group first). Allocates a 0x54
// dwGuiRefRadioButton for one category line and AddButton()s it to pGroup.
// Owner: dwGuiReference (deliberately omitted from dwGuiMission.h).
void dwGuiRefRadioGroup_AddCategory(dwGuiRefRadioGroup* pGroup, dwRect* pRect, char* pImgNormal,
                                    char* pSndOff, char* pImgPressed, char* pSndClick, int cmdId);

// ---- dwGuiRefTile ---------------------------------------------------------------
//
// dwWidget base @0x00 (0xe) + color@0x10 + count@0x11 — sizeof 0x12. vtable
// @0x51... overrides only DtorDelete(+0x00) and Draw(+0x44). A decoration that
// draws `count` nested (shrinking) frame rectangles in palette color `color`.
// Built by dwControlPanel's RECT keyword (recipe in dwControlPanel.cpp).

struct dwGuiRefTile : dwWidget
{
    uint8_t color; // 0x10: frame color index
    uint8_t count; // 0x11: number of nested frames (1 = a single frame)

    // @42a890 (dwGuiRefTile_Ctor)
    dwGuiRefTile(dwRect* pRect, uint8_t color, uint8_t count);
    // @42a8e0 (dwGuiRefTile_Dtor; scalar-deleting wrapper @42a8c0)
    virtual ~dwGuiRefTile();
    // vtbl +0x44 @42a8f0 (dwGuiRefTile_Draw)
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);
};

// ---- dwGuiReference -------------------------------------------------------------

struct dwGuiReference : dwGuiScreen
{
    dwList pTopicList;          // 0xc8: browsed-topic string-item list
    dwString currentFile;       // 0xcc: current topic filename (localized)
    uint8_t bReloadPending;     // 0xd8: Update rebuilds the page when set
    uint8_t bIntroPending;      // 0xd9: play the intro video on first activate
    dwWidgetGroup* pContentGroup;// 0xdc: the primary content sub-group
    dwString path;              // 0xe0: ctor sub-path argument
    dwWidgetGroup* pChildEc;    // 0xec: content sub-group 2
    dwWidgetGroup* pChildF0;    // 0xf0: content sub-group 3
    dwWidgetGroup* pChildF4;    // 0xf4: content sub-group 4
    dwWidgetGroup* pChildF8;    // 0xf8: content sub-group 5
    dwString scratchFC;         // 0xfc: scratch filename
    uint8_t bReloadMaterials;   // 0x108: Update rebuilds the Materials page
    uint8_t bSuppressStill;     // 0x109: STILL_FRAME suppression flag
    int32_t menuMode;           // 0x10c: current sub-menu category (0..5)
    int32_t field_110;          // 0x110: (zeroed by the ctor)
    dwString scratch114;        // 0x114: scratch topic path
    uint8_t byte120;            // 0x120
    uint8_t bInternetOk;        // 0x121: CheckInternet result

    // @42a990 (dwGuiReference_Ctor) — dwGuiScreen("reference", NULL); pSubPath
    // seeds `path`.
    dwGuiReference(char* pSubPath);

    // @42aac0 (dwGuiReference_Dtor; scalar-deleting wrapper @42aaa0 = vtbl
    // +0x00; scn dtor thunk @42f920).
    virtual ~dwGuiReference();

    // ---- dwWidget-side overrides (primary vtbl @0x51f710) ----
    virtual int OnMessage(dwWidgetMsg* pMsg);                     // +0x1c @42ba30
    virtual void EnsureImages();                                  // +0x3c @42f740 (Ghidra: EnsureLoaded)
    virtual void FreeImages();                                    // +0x40 @42f7a0
    // +0x48 @42d740 — the reference keyword factory (GRAPH/PULLDOWN_MENU/
    // CONTROLPANEL/CAT_RADIOGROUP/HELP/ICON_ANIM_PLAY + the text controls).
    virtual dwWidget* CreateControl(char* pKeyword, dwConfFile* pConf);
    virtual void Update(float dt);                                // +0x14 @42ed50

    // ---- dwSegment-side overrides (scn vtbl @0x51f6f8) ----
    virtual int Activate();  // @42b300 (Ghidra: dwGuiReference_OnActivate)

    // ---- non-virtual helpers ----
    // Re-parse a topic .ifc sub-section, dispatching each keyword through the
    // virtual CreateControl and appending the result into one of the content
    // groups. @42ae40. Callers pass 5 groups; the compiled body only reads the
    // first three as params (pGroupDefault/pGroupHeader/pGroupDynamic) plus
    // this->pContentGroup + this->pChildF8 — the last two params are dead but
    // kept to match the call sites. Returns 0 only on the STILL_FRAME early-out.
    char BuildDynamicControls(const char* pConfName, dwWidgetGroup* pGroupDefault,
                              dwWidgetGroup* pGroupHeader, dwWidgetGroup* pGroupDynamic,
                              dwWidgetGroup* pGroupUnused4, dwWidgetGroup* pGroupUnused5);
    // Intro-video state machine (RefIntro/RefRoom/RStart .san). @42f800
    int PlayIntroVideo();
    // Internet-launch gates (Win32 in the binary; portable stubs here). @42b7e0/@42b830/@42b920
    int HasBrowser();
    int CheckInternet();
    int ReadBrowserRegistry();
};

#endif // __cplusplus

#endif // _DWGUIREFERENCE_H
