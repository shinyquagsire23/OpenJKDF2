// dwSith — DroidWorks sith-engine bring-up/teardown glue
// (Ghidra dwSith_Startup @41f170 / dwSith_Shutdown @41f270 + the two
// callbacks they register @423070/@4230a0).
//
// Pure C unit. See dwSith.h for the role summary. The saved engine loader
// hooks are re-installed by dwGuiInGame_StartMission (P6) when a mission
// world opens — DW runs its GUI phases with the loaders detached so
// material/model/keyframe lookups fall back to the raw file loaders.

#include "Dw/dwSith.h"

#include "AI/sithAI.h"
#include "Cog/sithCog.h"
#include "Devices/sithConsole.h"
#include "Devices/sithControl.h"
#include "Engine/sithCamera.h"
#include "Engine/rdKeyframe.h"
#include "Engine/rdMaterial.h"
#include "Main/sithMain.h"
#include "stdPlatform.h"
#include "globals.h" // sithTime_g_msecGameTime

// TODO(dw-decomp): provided by dwCog part 1 (P8) — registers the 34 DW COG
// verbs (dwplaycharacterspeech/dwfreezeplayer/.../dwgetactivatebin).
extern void dwCog_RegisterVerbs();
// TODO(dw-decomp): provided by dw core part 2 (P7) — items.inv parser.
extern void dw_ParseInventoryTypes();
// TODO(dw-decomp): provided by dw core part 2 (P7) — frees the parsed
// inventory icon images.
extern void dw_FreeInventoryIcons();
// TODO(dw-decomp): provided by dwGuiInGame (P6) — HUD console line print.
extern void dwGuiInGame_ConsolePrint(const char* pText);
// TODO(dw-decomp): provided by dwGuiInGame (P6) — per-frame control callback
// applying the SCREEN_SIZE setting to the 3D viewport.
extern int dwGuiInGame_UpdateViewSize(SithThing* pPlayer, flex_t deltaSecs);
// The binary's rdModel3 hook setters @0x47fe40/50 are DW's build of the
// repo's existing rdModel3_RegisterLoader/RegisterUnloader (see dwSith.h).
#include "Primitives/rdModel3.h"

// ---- module globals (binary @0x53e804-0x53e824, dwSith-owned) ------------
rdMaterialLoader_t dwSith_pfnPrevMaterialLoader = NULL;       // @0x53e818
rdMaterialUnloader_t dwSith_pfnPrevMaterialUnloader = NULL;   // @0x53e80c
dwModel3LoadEntryHook_t dwSith_pfnPrevModel3LoadHook = NULL;  // @0x53e81c
dwModel3FreeEntryHook_t dwSith_pfnPrevModel3FreeHook = NULL;  // @0x53e804
keyframeLoader_t dwSith_pfnPrevKeyframeLoader = NULL;         // @0x53e824
keyframeUnloader_t dwSith_pfnPrevKeyframeUnloader = NULL;     // @0x53e820

// @423070 — sithConsole print hook installed by dwSith_Startup: mirrors every
// engine console print to the log and the in-game HUD console.
// Note: the binary appends to its debug log via jk_logtofile("SITH: %s\n");
// stdPlatform_Printf is the repo-side analog. Returns 1 (the binary's hook
// slot is void; sithConsole ignores the result).
int dwGuiInGame_SithPrintHook(const char* pText)
{
    stdPlatform_Printf("SITH: %s\n", pText);
    dwGuiInGame_ConsolePrint(pText);
    return 1;
}

// @4230a0 (Ghidra: FUN_004230a0_Instinct_TouchOfDeath) — "touchofdeath"
// instinct (registered with updateModes=6, blockModes=0, triggerEvents=4):
// while armed (pState->param0 != 0), a periodic update (event 0) disarms it
// and sends USER7 to the owning thing; a touch (SITHAI_EVENTTOUCHED) by the
// actor's distractor thing after the cooldown re-arms it, sends USER6
// (source = the thing itself), and schedules the next update after
// intArg[1] ms.
// Note: the binary stores the cooldown deadline (ms) as an integer in the
// control-block slot the stock engine uses as aim-error (field_264); stored
// here as a flex_t value (exact for DW-length sessions).
int dwSith_Instinct_TouchOfDeath(SithAIControlBlock* pLocal, SithAIInstinct* pInstinct, SithAIInstinctState* pState, int32_t event, intptr_t pObject)
{
    if (event == 0)
    {
        if (pState->param0 != 0.0)
        {
            pState->param0 = 0.0;
            sithCog_ThingSendMessage(pLocal->thing, NULL, SITH_MESSAGE_USER7);
            pLocal->field_264 = (flex_t)(sithTime_g_msecGameTime + pInstinct->intArg[0]);
        }
        return 0;
    }
    if (event == SITHAI_EVENTTOUCHED && pObject != 0 && pObject == (intptr_t)pLocal->pDistractor
        && (uint32_t)pLocal->field_264 <= sithTime_g_msecGameTime)
    {
        pState->param0 = 1.0;
        sithCog_ThingSendMessage(pLocal->thing, pLocal->thing, SITH_MESSAGE_USER6);
        pState->nextUpdate = sithTime_g_msecGameTime + pInstinct->intArg[1];
        pLocal->field_264 = (flex_t)(sithTime_g_msecGameTime + pInstinct->intArg[0] + pInstinct->intArg[1]);
    }
    return 0;
}

// @41f170 — DW's sith bring-up (the dwApp boot segment calls this from
// dw_Startup, P7). Returns 1 only when the core engine started; the DW-side
// registrations below run regardless (faithful).
int dwSith_Startup(HostServices* pHS)
{
    int bResult = 0;

    // The DroidWorks reduced-engine startup (Main_Startup's Main_bDroidWorks
    // branch) brings up only the shared render layer + Video; dw_Startup owns the
    // rest of the sith engine here. ⚠ sithCamera_Startup is NOT called here —
    // Video_Startup (run by the reduced branch) already calls it, so re-calling
    // would double-init (SITH_ASSERTREL sithCamera_bStartup==0). sithControl_
    // Startup is otherwise only called by jkControl_Startup, which the reduced
    // branch skips, so dw_Startup owns it.
    if (sithMain_Startup(pHS) && sithControl_Startup())
    {
        sithConsole_Startup(0x40);
        sithConsole_Open(0x10);
        bResult = 1;
    }

    dwCog_RegisterVerbs();
    sithAI_RegisterInstinct("touchofdeath", dwSith_Instinct_TouchOfDeath, 6, 0, SITHAI_EVENTTOUCHED);
    sithOpenStatic("static.jkl");
    dw_ParseInventoryTypes();
    sithConsole_RegisterPrintFunctions(dwGuiInGame_SithPrintHook, NULL);
    // Note: the binary registers its sithControl_HandlePlayer twin (@457430,
    // which also dispatches the DW tool keys -> dwCog_ActivateTool; the
    // repo-side tool-key dispatch is an engine edit, see the P5 report).
    sithControl_RegisterControlCallback(sithControl_HandlePlayer);
    sithControl_RegisterControlCallback(dwGuiInGame_UpdateViewSize);

    // Detach (and save) the engine's loader hooks; dwGuiInGame_StartMission
    // re-installs them when a mission world opens.
    dwSith_pfnPrevMaterialLoader = rdMaterial_RegisterLoader(NULL);
    dwSith_pfnPrevMaterialUnloader = rdMaterial_RegisterUnloader(NULL);
    dwSith_pfnPrevModel3LoadHook = rdModel3_RegisterLoader(NULL);
    dwSith_pfnPrevModel3FreeHook = rdModel3_RegisterUnloader(NULL);
    dwSith_pfnPrevKeyframeLoader = rdKeyframe_RegisterLoader(NULL);
    dwSith_pfnPrevKeyframeUnloader = rdKeyframe_RegisterUnloader(NULL); // Note: Ghidra calls this slot rdKeyframe_Unk8_Close
    return bResult;
}

// @41f270 — teardown mirror (binary sithMain_FUN_00458550 = sithCloseStatic).
void dwSith_Shutdown()
{
    sithCloseStatic();
    dw_FreeInventoryIcons();
    sithConsole_Close();
    sithConsole_Shutdown();
    sithClose();
    sithControl_Shutdown();
    sithCamera_Shutdown();
    sithShutdown();
}
