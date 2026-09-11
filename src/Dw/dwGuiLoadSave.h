#ifndef _DWGUILOADSAVE_H
#define _DWGUILOADSAVE_H

// dwGuiLoadSave — the 'lsdroid' droid SAVE/LOAD SCREEN (dwGuiScreen subclass).
//
// Decompiled from DroidWorks.exe, unit range 0x40ba90-0x40ce9f (the map row
// lists 0x40b940-0x40d17f, but 0x40b940 is the shared dwList_Ctor COMDAT,
// 0x40ba60 is dwGuiCredits' segment dtor thunk, and 0x40cea0+ is
// dwWorkshopDroidEditor — all translated elsewhere).
//
// MSVC multiple inheritance (binary): PRIMARY vtable dwGuiLoadSave_vtbl
// @0x51e930 (dwWidget shape + screen extras), SECONDARY/segment vtable
// dwGuiLoadSave_scn_vtbl @0x51e918 (dwSegment lifecycle @obj+0x10; the tail
// re-shares the primary). In this translation simply
// `struct dwGuiLoadSave : dwGuiScreen`.
//
// An animated slide panel over the global assembled-droid workspace
// (dwCore_pWorkspaceNodes = dwPartNode list + dwCore_workspaceName = the
// droid's name). The panel slides IN on Activate and slides OUT (then
// dwSegment_RequestAdvance -> return to the workshop) after a save/load.
// Controls: DROIDBOX (3D preview IMAGE) / LOADSAVENAME (dwGuiTextEntry bound
// to dwCore_workspaceName) / FILESCROLLBAR / SCROLLBOX (saved-droid file
// list, populated by listing *.drd and reading each file's NAME) / scroll
// up/down buttons / BUTTON_LOAD / BUTTON_SAVE / BUTTON_REC.
//
// OnMessage command codes 0xfa3-0xfa8: 0xfa3 file selected / 0xfa4 RECYCLE
// (gyesno DLG_RECYCLE -> delete the .drd + RemoveSelected) / 0xfa5 SAVE
// (trim name, empty -> DLG_MUSTNAME, exists -> gyesno DLG_REPLACE, then
// dwGuiWidgets_SaveDroidToFile + slide out) / 0xfa6 LOAD (free the workspace
// nodes + dwGuiWidgets_LoadDroidFromFile) -> 0xfa7 slide out / 0xfa8 name
// entry activate.
//
// This is the optGameLoad target: dwGuiScreen's screen-switch command 0x68
// should push a dwGuiLoadSave.
//
// Compiled as C++ (two vtables, ctor/dtor pair, MSVC EH frames).

#include "Dw/dwTypes.h"

#ifdef __cplusplus
struct dwGuiLoadSave;
extern "C" {
#else
typedef struct dwGuiLoadSave dwGuiLoadSave; // C++ class; opaque in the C view
#endif

// Note: no binary counterpart — the unit owns no module statics; kept for the
// project-wide soft-reset convention.
void dwGuiLoadSave_Startup(void);

// Added: C-callable factory — allocates the load/save screen over the given
// dimmed screen snapshot and returns its dwSegment subobject (for
// dwSegment_Push). pBgSnapshot is dwGuiScreen's captured backdrop (the
// dwGuiScreen msg-0x68 pSnapshotImage); it is BOTH the base background and the
// slide-out blit source (binary ctor's single arg, stored at 0xc8).
struct dwSegment;
struct dwImage;
struct dwSegment* dwGuiLoadSave_New(struct dwImage* pBgSnapshot);

#ifdef __cplusplus
} // extern "C"

#include "Dw/dwGuiScreen.h"
#include "Dw/dwGuiWidgets.h"  // dwGuiScrollBar / dwGuiScrollBox / dwGuiScrollButton
#include "Dw/dwGuiTextEntry.h"
#include "Dw/dwConfFile.h"

struct dwImage; // Dw/dwImage.h (the slide-out snapshot)

// Binary layout: dwGuiScreen base @0x00 (0xc8) + own fields below — sizeof
// 0xfc. Primary vtbl @0x51e930, segment vtbl @0x51e918.
struct dwGuiLoadSave : dwGuiScreen
{
    dwImage* pSnapshot;                // 0xc8: dimmed screen snapshot (== the
                                       //       base pBgImage; blitted by
                                       //       StartSlideOut during the slide)
    uint8_t bEditNameMode;             // 0xcc: name-entry (save) mode active
    dwWidget* pDroidBoxImage;          // 0xd0: DROIDBOX (base IMAGE) — the 3D
                                       //       preview snapshot; dynamically
                                       //       added/removed from `controls`
                                       //       during the slide (owned here)
    dwGuiTextEntry* pNameEntry;        // 0xd4: LOADSAVENAME (bound to
                                       //       dwCore_workspaceName)
    dwGuiScrollBar* pFileScrollBar;    // 0xd8: FILESCROLLBAR
    dwGuiScrollBox* pFileScrollBox;    // 0xdc: SCROLLBOX (saved-droid list)
    dwWidget* pScrollUpButton;         // 0xe0: SCROLLUPBUTTON (dwGuiScrollButton)
    dwWidget* pScrollDownButton;       // 0xe4: SCROLLDOWNBUTTON
    dwWidget* pButtonLoad;             // 0xe8: BUTTON_LOAD
    dwWidget* pButtonSave;             // 0xec: BUTTON_SAVE
    dwWidget* pButtonRecycle;          // 0xf0: BUTTON_REC
    float slideTimer;                  // 0xf4: accumulated slide time (sec)
    float slideDir;                    // 0xf8: +320 slide-out+exit, -320
                                       //       slide-in, 0 idle
    // (binary sizeof 0xfc)

    // @40ba90 (dwGuiLoadSave_Ctor) — dwGuiScreen("lsdroid", pBgSnapshot) +
    // zeroed fields; pBgSnapshot stored at 0xc8 too.
    dwGuiLoadSave(dwImage* pBgSnapshot);

    // @40bb30 (dwGuiLoadSave_Dtor; scalar-deleting wrapper @40bb10; segment
    // dtor thunk @40ce90) — FreeImages, detach + delete the droidbox image
    // (it may or may not still be attached to `controls`), then the base
    // dtor tears down the rest.
    virtual ~dwGuiLoadSave();

    // ---- dwWidget/dwGuiScreen overrides (primary vtbl @0x51e930) -----------
    virtual int OnMouseDown(int16_t x, int16_t y); // +0x08 @40c160 — consume clicks while sliding
    virtual int OnKey(int key, int repeat);        // +0x10 @40c110 — Esc during slide fast-forwards it
    virtual void Update(float dt);                 // +0x14 @40bc10 — panel slide anim
    virtual int OnMessage(dwWidgetMsg* pMsg);      // +0x1c @40c190 — command codes 0xfa3-0xfa8
    virtual void EnsureImages();                   // +0x3c @40ccd0 — base + every control
    virtual void FreeImages();                     // +0x40 @40cd70 — base + every control
    virtual dwWidget* CreateControl(char* pKeyword, dwConfFile* pConf); // +0x48 @40c5a0

    // ---- dwSegment overrides (segment vtbl @0x51e918) ----------------------
    virtual int Activate();     // +0x00 @40beb0 — free stale scrollbox items, base activate, start slide-in + WLSPanelAmb loop
    virtual void Deactivate();  // +0x04 @40bea0 — free cached sound samples

    // ---- non-virtual --------------------------------------------------------
    // @40bff0 — enable/disable the buttons + scroll controls from
    // workspace-empty state, the scrollbox selection and its scroll flag.
    void RefreshWidgets();
    // @40bdc0 — re-attach the droidbox image to `controls`, arm the slide-out.
    void StartSlideOut();
    // (@40ce30 dwGuiLoadSave_ClearList: the scrollbox-population temp list is
    //  freed inline via dwList::Free — the binary's node-free + free-sentinel
    //  pair is exactly dwList::Free.)
};

#endif // __cplusplus

#endif // _DWGUILOADSAVE_H
