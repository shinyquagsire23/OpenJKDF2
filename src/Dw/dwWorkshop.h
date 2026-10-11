#ifndef _DWWORKSHOP_H
#define _DWWORKSHOP_H

// dwWorkshop — the 'workshop' droid-editor SCREEN singleton: the screen
// hosting the droid-assembly workspace (dwWorkshopDroidEditor), the blueprint
// fly-out, the tool palette and the droid viewer. dwGuiScreen subclass.
//
// Decompiled from DroidWorks.exe.
// MSVC MI (binary): primary dwWorkshop_vtbl (this = obj+0),
// secondary dwWorkshop_scn_vtbl (the dwSegment lifecycle iface for
// the subobject @obj+0x10; its +0x14 dtor thunk dwWorkshop_ScnDtorThunk). In this translation
// that is simply `struct dwWorkshop : dwGuiScreen` — the compiler generates
// the this-adjustor thunks.
//
// Singleton: dwWorkshop_pSingleton, built once by
// dwWorkshop_CreateSingleton (binary callers: dw_Startup [P7] and
// dwGuiIntroSeg_Update [dwGuiOptions unit]) and pushed onto the
// dwSegment stack by the app flow; the dtor clears the global.
//
// CreateControl keywords (over the dwGuiScreen base factory): ARROWBALL /
// BLUEPRINTS / BUILD/PAINT / CARGO/NORMAL / DANCE (sets the dance-music wav,
// no control) / DROID_EDITOR (also latches the editor rect as the screen's
// paint-cursor zone) / DROID_NAME / HELP / PALETTE / PANCONTROL (also latches
// the view rect used for the grab cursor) / PART_IMAGE.
//
// The screen ties the workshop chrome to the shared workspace droid (the
// dwPartNode list dwCore_pWorkspaceNodes): (de)activation restarts/stops the
// part anims and swaps the music to danceSound while the droid dances; an
// idle timer (nextDanceTime, 180..300s) periodically pokes the help layer
// with a { 0x7531, 0x7929 } hover-notify.
//
// Compiled as C++ (two vtables, ctor/dtor pair, MSVC EH frames). C consumers
// see the opaque typedef + the C-linkage functions below.

#include "Dw/dwTypes.h"

#ifdef __cplusplus
struct dwWorkshop;
extern "C" {
#else
typedef struct dwWorkshop dwWorkshop; // C++ class; opaque in the C view
#endif

// The workshop screen singleton dwWorkshop_pSingleton (NULL until CreateSingleton;
// cleared by the dtor and by dwWorkshop_Startup).
extern dwWorkshop* dwWorkshop_pSingleton;

// Build the singleton when it does not exist yet (new dwWorkshop; a failed
// allocation leaves the global NULL). Binary callers: dw_Startup (P7),
// dwGuiIntroSeg_Update (dwGuiOptions).
void dwWorkshop_CreateSingleton(void);

// Note: no binary counterpart — resets the module global for OpenJKDF2's
// soft-reset loop (the singleton object itself is owned by the segment
// stack / dwSegment_Shutdown teardown).
void dwWorkshop_Startup(void);

#ifdef __cplusplus
} // extern "C"

#include "Dw/dwGuiScreen.h"
#include "Dw/dwString.h"
#include "Dw/dwRect.h"

struct dwWorkshop : dwGuiScreen
{
    // (binary: dwGuiScreen base 0x00-0xc7; own fields from 0xc8 — sizeof 0xf0)
    uint8_t bPaintMode;      // 0xc8: paint tool selected (msg 0x7e9 on / 0x7ea off)
    uint8_t paintColorIdx;   // 0xc9: armed paint-color SLOT (msg 0x7d3 payload;
                             //       selects cursor sprite 4+slot — the editor
                             //       maps the same slot to the palette color)
    dwRect paintRect;        // 0xca: the DROID_EDITOR control's rect (paint
                             //       cursor zone; latched by CreateControl)
    dwRect viewRect;         // 0xd2: the PANCONTROL control's rect (grab
                             //       cursor zone; latched by CreateControl)
    dwString danceSound;     // 0xdc: dance music wav (init "dance.wav";
                             //       DANCE keyword overrides)
    uint8_t bIdleAnims;      // 0xe8: part idle anims running (msg 0x7d4 toggles)
    uint8_t bActiveAnims;    // 0xe9: dance anims running (msg 0x7e3 toggles)
    uint8_t bRotateCalcSound;// 0xea: WRotateCalc.wav loop playing (msgs 0x7de-0x7e1)
    float nextDanceTime;     // 0xec: GetElapsed() deadline of the next idle
                             //       dance poke (now + rand*120/32768 + 180)

    // dwWorkshop_Ctor — dwGuiScreen("workshop", NULL) + zeroed state
    // + danceSound "dance.wav".
    dwWorkshop();

    // dwWorkshop_Dtor (scalar-deleting wrapper dwWorkshop_DtorDelete, secondary
    // thunk dwWorkshop_ScnDtorThunk) — clears dwWorkshop_pSingleton;
    // danceSound freed by its member dtor.
    virtual ~dwWorkshop();

    // ---- dwWidget/dwGuiScreen overrides (primary dwWorkshop_vtbl) -----------
    // vtbl +0x04 dwWorkshop_OnMouseMove — cursor shaping, then the base tooltip/forwarding:
    // pick mode (base bActive) -> cursor 3; inside viewRect -> grab cursor 2;
    // paint armed + inside paintRect -> paint cursor (4 + paintColorIdx);
    // else arrow (1).
    virtual int OnMouseMove(int16_t x, int16_t y);
    // vtbl +0x14 dwWorkshop_Update — statsFlags-0x4000000 tutorial-advance latch (fires
    // dwSegment_RequestAdvance once the cue playlist drains), the idle dance
    // poke ({ 0x7531, 0x7929 } + reseed), then ticks the embedded `controls`.
    // NOTE: does NOT chain the base Update (replaces the controls forward).
    virtual void Update(float dt);
    // vtbl +0x1c dwWorkshop_OnMessage — workshop commands (codes in dwWorkshop.cpp);
    // everything else chains to dwGuiScreen::OnMessage.
    virtual int OnMessage(dwWidgetMsg* pMsg);
    // vtbl +0x48 dwWorkshop_CreateControl — the workshop control factory (keywords above);
    // unknown keywords fall back to dwGuiScreen::CreateControl.
    virtual dwWidget* CreateControl(char* pKeyword, dwConfFile* pConf);

    // ---- dwSegment overrides (secondary "scn" dwWorkshop_scn_vtbl) --------------
    // +0x00 dwWorkshop_OnActivate — base Activate; on success (and
    // when idle anims are on) restart every part anim and the dance music,
    // then broadcast the current-mission reward ({ 0xbbc, pCurrentMission }),
    // the workspace body type ({ 0x7e4, 1|2 }, first torso/loco slotMask hit)
    // and { 0x7dc }; a pending statsFlags-0x10000000 tutorial request becomes
    // { 0x792a } (flag swapped for 0x80000000). Always reseeds nextDanceTime.
    virtual int Activate();
    // +0x04 dwWorkshop_OnDeactivate — while idle anims run: restore
    // the screen music when dancing (and not in a tutorial), stop every part
    // anim; then base Deactivate.
    virtual void Deactivate();
};

#endif // __cplusplus

#endif // _DWWORKSHOP_H
