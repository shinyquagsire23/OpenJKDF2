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
// owner: dwGuiInGame (P6 wave 2) — mission-screen factory (returns the dwSegment
// subobject of new(0x284) dwGuiInGame_Ctor@41f2a0) + assembled-droid check @41f6f0.
// The wave-2 agent must export exactly these two symbols (delete these then).
dwSegment* dwGuiInGame_New(dwMission* pMission) { (void)pMission; return NULL; }
int dwGuiInGame_CheckDroidValid(void) { return 0; }
typedef struct dwGuiInGame dwGuiInGame;                     // C++ class; opaque here
dwGuiInGame* dwGuiInGame_pActive = NULL;                    // owner: dwGuiInGame P6 wave 2 (@0x53e800); running-mission screen or NULL
// owner: dwGuiInGame (P6) — HUD voice line + Cammy caption / console line /
// per-frame SCREEN_SIZE viewport control callback (registered by dwSith_Startup).
void dwGuiInGame_PlayVoiceLine(const char* pCammyText, const char* pWavName, uint32_t priority)
{
    (void)pCammyText; (void)pWavName; (void)priority;
}
void dwGuiInGame_ConsolePrint(const char* pText) { (void)pText; }
int dwGuiInGame_UpdateViewSize(SithThing* pPlayer, flex_t deltaSecs)
{
    (void)pPlayer; (void)deltaSecs;
    return 0;
}
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

int dwMain_Startup()
{
    // Statics reset (soft-reset loop rule)
    dwMain_bInitted = 0;
    dwMain_bPrintedStub = 0;
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
    if (!dwMain_bPrintedStub) {
        stdPlatform_Printf("OpenJKDF2: dwMain_GuiAdvance — DW app layer tick (stub)\n");
        dwMain_bPrintedStub = 1;
    }
}
