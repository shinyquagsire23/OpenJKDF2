#ifndef _DWSITH_H
#define _DWSITH_H

// dwSith — DroidWorks sith-engine bring-up/teardown glue
// (Ghidra dwSith_Startup @41f170 / dwSith_Shutdown @41f270, plus the two
// callbacks it registers: dwGuiInGame_SithPrintHook @423070 and the
// "touchofdeath" AI instinct @4230a0, program=DroidWorks.exe).
//
// dwSith_Startup is DW's equivalent of jkMain's sith bring-up: it starts the
// sith core/camera/control/console, registers the DW COG verbs + AI instinct,
// opens static.jkl, parses items.inv, hooks the console print + per-frame
// control callbacks, and detaches the engine's material/model/keyframe
// loader hooks (saving them here; dwGuiInGame_StartMission re-installs them
// when a mission world opens).

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

// The binary's rdModel3 "per-entry load/free hook" setters (@0x47fe40/0x47fe50
// over globals @0x5561e0/0x5561e4) turned out to be DW's build of the repo's
// EXISTING rdModel3_RegisterLoader/RegisterUnloader (same swap-and-return
// shape; the hook checks in rdModel3_Load/rdModel3_Free match the binary call
// sites exactly). No engine addition needed — the repo typedefs are reused.
typedef model3Loader_t dwModel3LoadEntryHook_t;
typedef model3Unloader_t dwModel3FreeEntryHook_t;

// Engine loader hooks saved by dwSith_Startup (read back by
// dwGuiInGame_StartMission, P6).
extern rdMaterialLoader_t dwSith_pfnPrevMaterialLoader;         // @0x53e818
extern rdMaterialUnloader_t dwSith_pfnPrevMaterialUnloader;     // @0x53e80c
extern dwModel3LoadEntryHook_t dwSith_pfnPrevModel3LoadHook;    // @0x53e81c
extern dwModel3FreeEntryHook_t dwSith_pfnPrevModel3FreeHook;    // @0x53e804
extern keyframeLoader_t dwSith_pfnPrevKeyframeLoader;           // @0x53e824
extern keyframeUnloader_t dwSith_pfnPrevKeyframeUnloader;       // @0x53e820

int dwSith_Startup(HostServices* pHS); // @41f170
void dwSith_Shutdown();                // @41f270

// @423070 — sithConsole print hook: mirrors engine prints to the log and the
// in-game HUD console. (Ghidra bins it as dwGuiInGame_*, but it is only
// referenced by dwSith_Startup, so it lives here.)
int dwGuiInGame_SithPrintHook(const char* pText);

// @4230a0 (Ghidra: FUN_004230a0_Instinct_TouchOfDeath) — the "touchofdeath"
// AI instinct registered by dwSith_Startup.
int dwSith_Instinct_TouchOfDeath(SithAIControlBlock* pLocal, SithAIInstinct* pInstinct, SithAIInstinctState* pState, int32_t event, intptr_t pObject);

#ifdef __cplusplus
}
#endif

#endif // _DWSITH_H
