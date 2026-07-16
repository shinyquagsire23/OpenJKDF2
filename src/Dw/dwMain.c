#include "Dw/dwMain.h"

#include "Dw/dwRect.h"
#include "Dw/dwInits.h"
#include "Dw/dwDisplay.h"
#include "Dw/dwCursor.h"
#include "Dw/dwMovie.h" // dwMovie_Startup (C view)
#include "Dw/dwWidget.h" // dwWidget_Startup (C view)
#include "Dw/dwSegment.h" // dwSegment_Startup/_Shutdown/_FreePlaylist (C view)
#include "Dw/dwColormap.h"
#include "Dw/dwFont.h"
#include "Dw/dwControlPanel.h" // dwControlPanel_Startup (C view)
#include "Dw/dwPart.h"      // dwPart_Startup (C view)
#include "Dw/dwPlayer.h"    // dwPlayer_Startup (C view)
#include "Dw/dwCog.h"       // dwCog_Startup
#include "Dw/dwCamera.h"    // dwCamera_Startup
#include "Dw/dwLaser.h"     // dwLaser_Startup
#include "Dw/dwDroidStats.h" // dwDroidStats_Startup (C view)
#include "Dw/dwWorkshop.h"  // dwWorkshop_Startup (C view)
#include "Dw/dwWorkshopDroidEditor.h" // dwWorkshopDroidEditor_Startup (C view)
#include "Dw/dwGuiMission.h" // dwGuiMission_Startup (C view)
#include "Dw/dwGuiOptions.h" // dwGuiOptions_Startup (C view)
#include "Dw/dwGuiCredits.h" // dwGuiCredits_Startup (C view)
#include "Dw/dwEnding.h"    // dwEnding_Startup (C view)
#include "stdPlatform.h"
#include "globals.h" // pHS

// DroidWorks app-layer core. Stub for now — the decompiled dw_Startup /
// dwMain_MainLoopTick / boot-segment flow lands in P7 (DW/DECOMP_PROGRESS.md).

// ------------------------------------------------------------------
// TODO(dw-decomp): temporary cross-unit placeholders until the owning units
// land. Remove each line when its owner unit is translated.
HostServices* dwMain_pHS = NULL;                            // owner: dwMain proper (dw_hostServices @0x53d988); pointed at engine pHS in Startup for now
typedef struct dwStringTable dwStringTable;                 // C++ class (Dw/dwStringTable.h is C++-only); opaque here
typedef struct dwListNode dwListNode;                       // C++-side list node (Dw/dwList.h is C++-only); opaque here
typedef struct dwWidget dwWidget;                           // C++ class; opaque here
typedef struct dwSegment dwSegment;                         // C++ class; opaque here
typedef struct dwImage dwImage;                             // C++ class; opaque here
dwStringTable* dwCore_pGlobalStrings = NULL;                // owner: dw core P7 (@0x53d958); NULL = dwGuiScreen_LocalizeString falls back to the key
uint8_t dwMain_bFullRedraw = 0;                             // owner: dwMain P7 (@0x53e854); 0 = dirty-rect draws (faithful default)
dwListNode* dwCore_pBlueprintList = NULL;                   // owner: dw core P7 (@0x53d964); consumers (dwWcBlueprints) unreachable until the boot flow exists
dwListNode* dwCore_pWorkspaceNodes = NULL;                  // owner: dw core P7 (@0x53d984); same
dwListNode* dwCore_pMissionList = NULL;                     // owner: dw core P7 (@0x53d95c); consumers (dwPlayer .plr MISSIONS, dwGuiScreen cheats) NULL-guard / unreachable
typedef struct dwMission dwMission;                         // C++ class (Dw/dwMission.h); opaque here
dwMission* dwCore_pCurrentMission = NULL;                   // owner: dw core P7 (@0x53d954); the selected mission record (declared in Dw/dwMission.h)
// dwGuiInGame (P6 wave 2a) landed — its 6 placeholders (dwGuiInGame_New/
// CheckDroidValid/pActive/PlayVoiceLine/ConsolePrint/UpdateViewSize) are now
// real in dwGuiInGame.cpp and were deleted from here.
//
// --- Placeholders dwGuiInGame.cpp still depends on (satisfy the link) ---------
// Opaque handles for the not-yet-translated widgets (real types land in P6w2b).
typedef struct dwGuiList dwGuiList;
typedef struct dwGuiSpeech dwGuiSpeech;
typedef struct dwGuiIndicator dwGuiIndicator;
typedef struct dwHelp dwHelp;
typedef struct dwRect dwRect;

// owner: dwMain proper (P7) — the two default DW material loader callbacks
// re-registered by dwGuiInGame_EndMission. NULL until the material cache lands.
rdMaterialLoader_t dwMain_MaterialLoaderCb = NULL;
rdMaterialUnloader_t dwMain_MaterialUnloaderCb = NULL;

// owner: P8 sith-engine diff audit — DW-forked engine globals with no repo twin.
// Cosmetic/gameplay state only reached once a mission is running (P7 boot flow).
uint8_t* DAT_006478f8 = NULL;                               // stdDisplay current video-mode record
int _DAT_006915f0 = 0, _DAT_00691528 = 0, _DAT_0069158c = 0; // DW sith control latches
float _DAT_0069a658 = 0.0f;                                 // DW inventory battery-capacity global
int DAT_0054518c = 0, DAT_00545190 = 0, DAT_00545194 = 0, DAT_005b7200 = 0, DAT_00546880 = 0; // MST3K render counters
uint32_t DAT_0053e810 = 0, DAT_0053e814 = 0;               // DW load-progress bar bounds
float _DAT_00528698 = 0.0f, _DAT_0052869c = 0.0f, _DAT_005286c0 = 0.0f, _DAT_005286d4 = 0.0f; // chatter timing
const char* PTR_s_GHCA009_wav_00528688[] = { 0 };          // ambient chatter wav tables (unrecovered)
const char* PTR_s_GHCA006_wav_00528678[] = { 0 };
const char* PTR_s_GHCA058_wav_005286c8[] = { 0 };
const char* PTR_s_GHCA048_wav_005286a8[] = { 0 };

// owner: P8 sith-engine diff audit — DW-forked sith internals (no repo twin).
void sithCamera_sub_44B190(void) {}                        // DW cam-slot-7 setup
void sithControl_FUN_00456da0(void) {}                     // DW control-fn registration

// owner: dwGuiList / dwHelp (P6 wave 2b) — HUD child widgets.
void dwGuiIndicator_SetProgress(dwGuiIndicator* pInd, float t) { (void)pInd; (void)t; }
void dwGuiIndicator_Show(dwGuiIndicator* pInd) { (void)pInd; }
void dwGuiIndicator_Hide(dwGuiIndicator* pInd) { (void)pInd; }
dwGuiList* dwGuiList_Ctor(dwGuiList* pThis, dwRect* pRect, float a, char* pFont, uint8_t c, uint8_t d, void* pPoint)
{ (void)pRect; (void)a; (void)pFont; (void)c; (void)d; (void)pPoint; return pThis; }
void dwGuiList_Clear(dwGuiList* pList) { (void)pList; }
dwGuiSpeech* dwGuiSpeech_Ctor(dwGuiSpeech* pThis, dwRect* pRect, int a, char* pFont, uint32_t c, void* pPoint)
{ (void)pRect; (void)a; (void)pFont; (void)c; (void)pPoint; return pThis; }
void dwGuiSpeech_Clear(dwGuiSpeech* pSpeech) { (void)pSpeech; }
dwHelp* dwHelp_Ctor(dwHelp* pThis, dwRect* pRect, int a, int speakerCode)
{ (void)pRect; (void)a; (void)speakerCode; return pThis; }

// owner: dwGuiStatus (P6w2b) / dwGuiOptions (has NewEnterSeg, needs New) /
// dwMain dwCompleteMovie (P7) — screens pushed by dwGuiInGame_EndMission.
dwSegment* dwGuiStatus_New(dwMission* pMission, float itemPct, float healthPct, int32_t chargeMax)
{ (void)pMission; (void)itemPct; (void)healthPct; (void)chargeMax; return NULL; }
dwSegment* dwGuiOptions_New(int index) { (void)index; return NULL; }
dwSegment* dwCompleteMovie_New(int idx) { (void)idx; return NULL; }
// owner: dwCog part 1 (P8) — the 34-verb registration table.
void dwCog_RegisterVerbs(void)
{
    stdPlatform_Printf("TODO(dw-decomp): dwCog_RegisterVerbs stub (owner dwCog part 1 P8)\n");
}
// owner: dw core part 2 (P7) — items.inv parse / inventory icon free.
void dw_ParseInventoryTypes(void)
{
    stdPlatform_Printf("TODO(dw-decomp): dw_ParseInventoryTypes stub (owner dw core P7)\n");
}
void dw_FreeInventoryIcons(void) {}
// owner: dwMain proper (P7) — the material recolor cache singleton (@0x53d950,
// struct 0x187c). Stubs no-op: parts render untinted until P7.
void dwMain_MaterialCache_RecolorMasked(rdMaterial* pMaterial, int matchColor, int newColor)
{
    (void)pMaterial; (void)matchColor; (void)newColor;
}
void dwMain_MaterialCache_Disable(void) {}
void dwMain_MaterialCache_Enable(void) {}
// ------------------------------------------------------------------

static int dwMain_bInitted = 0;
static int dwMain_bPrintedStub = 0;
// P7 seam: the boot flow (dw_Startup) sets this after pushing the initial
// segment(s) + dwSegment_RequestAdvance. Until then dwMain_GuiAdvance must NOT
// call dwSegment_Tick — dwSegment_bQuit starts 0 (= quit), so ticking an
// un-booted empty stack would exit the app immediately.
static int dwMain_bBooted = 0;

int dwMain_Startup()
{
    // Statics reset (soft-reset loop rule)
    dwMain_bInitted = 0;
    dwMain_bPrintedStub = 0;
    dwMain_bBooted = 0;
    dwMain_pHS = pHS; // TODO(dw-decomp): becomes the DW-owned HostServices (dw_hostServices) in P7

    stdPlatform_Printf("OpenJKDF2: %s — DroidWorks mode scaffolding (app layer not yet implemented)\n", __func__);

    // Bring up the DW VFS (dwGob + inits hooked fileOpen). In the original this
    // is the first thing dw_Startup does.
    inits_Startup(pHS);

    // CRT-static-ctor replacements (dirty-rect list, cursor table, segment
    // cue playlist) + module static resets. The binary ran the static ctors
    // before WinMain; they must precede any dwDisplay_Open.
    dwDisplay_Startup();
    dwCursor_Startup();
    dwMovie_Startup();
    dwWidget_Startup();
    dwSegment_Startup();
    dwColormap_Startup();
    dwFont_Startup();
    dwControlPanel_Startup(); // binary: called from dw_Startup @419d40 (dw_aPartSlotColors fill)
    // P5 wave: statics resets (soft-reset loop rule; the binary's state came
    // from .data/BSS/CRT static ctors).
    dwPart_Startup();
    dwPlayer_Startup();
    dwCog_Startup();
    dwCamera_Startup();
    dwLaser_Startup();
    dwDroidStats_Startup();
    dwWorkshop_Startup();
    dwWorkshopDroidEditor_Startup();
    dwGuiMission_Startup();
    dwGuiOptions_Startup();
    dwGuiCredits_Startup();
    dwEnding_Startup();
    // Note: dwSound_Startup deferred to the P7 boot flow (spawns the worker
    // thread; the dwSound C API NULL-guards the manager until then).
    // Note: dwSith_Startup is NOT a statics reset — it is DW's sith engine
    // bring-up, called by the dw_Startup boot flow (P7).

    // Temporary P1 exercise: resolve a few known assets through the full
    // hooked-open chain (ext table -> base paths -> GOB basename index).
    // TODO(dw-decomp): remove once real consumers (dwConfFile/dwStringTable
    // callers) exercise the VFS in P3+.
    {
        static const char* aProbes[] = { "options.cmp", "maptut.rec", "items.inv", "notafile.cmp" };
        for (int i = 0; i < 4; i++) {
            stdPlatform_Printf("dwMain: probe %-14s -> %s\n", aProbes[i],
                               inits_FileExists(aProbes[i]) ? "FOUND" : "missing");
        }
    }

    dwMain_bInitted = 1;
    return 1;
}

void dwMain_Shutdown()
{
    if (!dwMain_bInitted)
        return;

    stdPlatform_Printf("OpenJKDF2: %s\n", __func__);
    dwSegment_Shutdown();
    dwSegment_FreePlaylist(); // header rule: run before the next dwSegment_Startup
    dwFont_Shutdown();
    inits_Shutdown();
    dwMain_bInitted = 0;
    dwMain_bPrintedStub = 0;
}

void dwMain_GuiAdvance()
{
    // Added (P7 draft — main-loop hookup): the engine's outer Window/SDL loop
    // calls jkMain_GuiAdvance -> here once per frame (this REPLACES DroidWorks'
    // own WinMain message pump, binary Window_sub_506FC0 driven by dwMain_Run
    // @41b250). Body mirrors dwMain_MainLoopTick @41b6d0: tick the active
    // segment stack for one frame; a false (0) return means quit was requested
    // (the binary calls DestroyWindow) — we ask the engine's loop to unwind via
    // g_should_exit instead.
    //
    // NOTE: input pumping + the SDL event loop are already owned by the engine
    // (Window/stdControl feed jkMain), so this side only advances the DW
    // segment/present pipeline. dwSegment_Tick handles input-cue replay,
    // segment Update, and presentation internally.
    if (!dwMain_bBooted) {
        // Boot flow (dw_Startup: build blueprints/missions, push the workshop +
        // intro/options boot segments, RequestAdvance) is still P7. Until it
        // runs there is nothing to tick and dwSegment_bQuit==0 would quit.
        if (!dwMain_bPrintedStub) {
            stdPlatform_Printf("OpenJKDF2: dwMain_GuiAdvance ready — awaiting P7 dw_Startup boot flow (segment stack empty)\n");
            dwMain_bPrintedStub = 1;
        }
        return;
    }

    if (!dwSegment_Tick())
        g_should_exit = 1;
}
