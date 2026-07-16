#include "Dw/dwMain.h"

#include "stdPlatform.h"

// DroidWorks app-layer core. Stub for now — the decompiled dw_Startup /
// dwMain_MainLoopTick / boot-segment flow lands in P7 (DW/DECOMP_PROGRESS.md).

static int dwMain_bInitted = 0;
static int dwMain_bPrintedStub = 0;

int dwMain_Startup()
{
    // Statics reset (soft-reset loop rule)
    dwMain_bInitted = 0;
    dwMain_bPrintedStub = 0;

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
