#include "Dw/dwMain.h"

#include "Dw/dwRect.h"
#include "stdPlatform.h"
#include "globals.h" // pHS

// DroidWorks app-layer core. Stub for now — the decompiled dw_Startup /
// dwMain_MainLoopTick / boot-segment flow lands in P7 (DW/DECOMP_PROGRESS.md).

// ------------------------------------------------------------------
// TODO(dw-decomp): temporary cross-unit placeholders until the owning units
// land. Remove each line when its owner unit is translated.
HostServices* dwMain_pHS = NULL;                            // owner: dwMain proper (dw_hostServices @0x53d988); pointed at engine pHS in Startup for now
void dwDisplay_AddDirtyRect(dwRect* pRect) { (void)pRect; } // owner: dwDisplay (P2)
void dwDisplay_Present(void) {}                             // owner: dwDisplay (P2)
tVBuffer* dwDisplay_pBackVBuf = NULL;                       // owner: dwDisplay (P2)
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

    dwMain_bInitted = 1;
    return 1;
}

void dwMain_Shutdown()
{
    if (!dwMain_bInitted)
        return;

    stdPlatform_Printf("OpenJKDF2: %s\n", __func__);
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
