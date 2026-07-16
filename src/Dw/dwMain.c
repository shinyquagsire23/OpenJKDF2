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
dwStringTable* dwCore_pGlobalStrings = NULL;                // owner: dw core P7 (@0x53d958); NULL = dwGuiScreen_LocalizeString falls back to the key
uint8_t dwMain_bFullRedraw = 0;                             // owner: dwMain P7 (@0x53e854); 0 = dirty-rect draws (faithful default)
dwListNode* dwCore_pBlueprintList = NULL;                   // owner: dw core P7 (@0x53d964); consumers (dwWcBlueprints) unreachable until the boot flow exists
dwListNode* dwCore_pWorkspaceNodes = NULL;                  // owner: dw core P7 (@0x53d984); same
// owner: dwGuiMission (P6) @41c0f0 — modal yes/no dialog; 5000 = YES / 5001 = NO.
// Stub answers NO (the safe default for "randomize droid?"-style confirms).
int dwGuiDialog_RunModal(const char* pConfName, const char* pMsgKey)
{
    stdPlatform_Printf("TODO(dw-decomp): dwGuiDialog_RunModal(%s, %s) stub -> NO (owner dwGuiMission P6)\n", pConfName, pMsgKey);
    return 5001;
}
// owner: dwDroidStats (P5) @40fae0 — random-droid generator; stub no-op.
void dwDroidStats_AutoBuildRandom(int bodyType, dwListNode** ppWorkspaceList)
{
    (void)bodyType; (void)ppWorkspaceList;
    stdPlatform_Printf("TODO(dw-decomp): dwDroidStats_AutoBuildRandom stub (owner dwDroidStats P5)\n");
}
// owner: dwGuiTextMisc (P4 batch 2) — dwGuiTimer decorator factory (C shim
// invented by the dwWorkshopCtrl unit; the dwGuiTextMisc agent must export
// it). Stub returns the child unwrapped: shown always, no timed show/hide.
dwWidget* dwGuiTimer_New(dwWidget* pTarget, float startTime, float duration)
{
    (void)startTime; (void)duration;
    stdPlatform_Printf("TODO(dw-decomp): dwGuiTimer_New stub — child unwrapped (owner dwGuiTextMisc P4b2)\n");
    return pTarget;
}
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
    // Note: dwSound_Startup deferred to the P7 boot flow (spawns the worker
    // thread; the dwSound C API NULL-guards the manager until then).

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
