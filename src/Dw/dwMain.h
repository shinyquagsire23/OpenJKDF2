#ifndef _DWMAIN_H
#define _DWMAIN_H

// DroidWorks app-layer entry points (OpenJKDF2-side wrappers).
//
// These are the seams the rest of OpenJKDF2 calls when Main_bDroidWorks is
// set. The decompiled originals (dw_Startup @419bd0, dwMain_MainLoopTick,
// the boot dwSegment) land here in P7 (see DW/DECOMP_PROGRESS.md); until
// then these are stubs so the -droidworks path links and runs.

#include "Dw/dwTypes.h"

#ifdef PLATFORM_DROIDWORKS
// dwMain is compiled as C++ (dwMain.cpp) but the boot seams are called from C
// (jkMain.c) — keep C linkage so the symbols match.
#ifdef __cplusplus
extern "C" {
#endif
int  dwMain_Startup();     // called from Main_Startup when Main_bDroidWorks
void dwMain_Shutdown();    // called from Main_Shutdown when Main_bDroidWorks
void dwMain_GuiAdvance();  // per-frame app tick, diverted from jkMain_GuiAdvance
#ifdef __cplusplus
}
#endif
#else
// Retro targets exclude src/Dw/*.c from the build; Main_bDroidWorks is never
// set there, so the call sites compile to dead no-ops.
#define dwMain_Startup() (0)
#define dwMain_Shutdown()
#define dwMain_GuiAdvance()
#endif // PLATFORM_DROIDWORKS

#endif // _DWMAIN_H
