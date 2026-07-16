#include "Dw/dwMain.h"

#include "Dw/dwRect.h"
#include "Dw/dwInits.h"
#include "Dw/dwDisplay.h"
#include "Dw/dwCursor.h"
#include "Dw/dwMovie.h" // dwMovie_Startup (C view)
#include "stdPlatform.h"
#include "globals.h" // pHS

// DroidWorks app-layer core. Stub for now — the decompiled dw_Startup /
// dwMain_MainLoopTick / boot-segment flow lands in P7 (DW/DECOMP_PROGRESS.md).

// ------------------------------------------------------------------
// TODO(dw-decomp): temporary cross-unit placeholders until the owning units
// land. Remove each line when its owner unit is translated.
HostServices* dwMain_pHS = NULL;                            // owner: dwMain proper (dw_hostServices @0x53d988); pointed at engine pHS in Startup for now
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

    // CRT-static-ctor replacements (dirty-rect list, cursor table). The
    // binary ran these before WinMain; they must precede any dwDisplay_Open.
    dwDisplay_Startup();
    dwCursor_Startup();
    dwMovie_Startup();

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
