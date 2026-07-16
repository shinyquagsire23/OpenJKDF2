#ifndef _DWCOG_H
#define _DWCOG_H

// dwCog part 2 — DroidWorks droid-tool "activate/use" interaction dispatch
// (Ghidra 0x44c270-0x44cc4f, program=DroidWorks.exe).
//
// When the player acts (Activate key -> sithPlayerActions_Activate /
// sithControl tool keys -> dwCog_ActivateTool; or clicks an inventory item ->
// dwCog_UseItem), DW casts a fan of rays in front of the droid
// (dwCog_ScanAndInteract/dwCog_ScanRay), classifies whatever was hit by the
// COG messages its linked COGs declare handlers for (dwCog_GetThingCaps/
// GetSurfaceCaps/GetCogCaps), picks the highest-priority applicable message
// (dwCog_SelectMessage), plays a puppet "reach" animation, and delivers the
// message on the animation's trigger marker (dwCog_ScanPuppetCallback ->
// dwCog_SendPendingMessage).
//
// The COG verb layer (dwCog part 1, 0x408780-0x4093xx incl. the
// dwfreezeplayer/dwunfreezeplayer verb wrappers and dwCog_RegisterVerbs) is
// P8 — NOT here.

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef PLATFORM_DROIDWORKS
// Retro targets exclude src/Dw/* from the build; the shared-engine call sites
// (sithPlayerActions_Activate / sithControl tool keys) compile to dead no-ops
// (same pattern as dwMain.h).
#define dwCog_ActivateTool(pSource, toolSlot)
#define dwCog_UseItem(pSource, invBin)
#else

// DW-extended COG message numbers. DW reuses the numeric range MOTS later
// used for its own messages (41-46); the DwCompat symbol names registered in
// sithCog_Startup (src/Cog/sithCog.c, Main_bDwCompat block) are the source of
// truth for the names below. 1/26 (activate/taken) are stock sith messages.
enum DW_MESSAGE
{
    DW_MESSAGE_LASERHIT  = 41, // 0x29 (sent by dwLaser, not this unit)
    DW_MESSAGE_CUT       = 42, // 0x2a
    DW_MESSAGE_INJECTED  = 43, // 0x2b
    DW_MESSAGE_POWERPLUG = 44, // 0x2c
    DW_MESSAGE_WELDED    = 45, // 0x2d
    DW_MESSAGE_TUGGED    = 46, // 0x2e
    DW_MESSAGE_CONVERSE  = 47, // 0x2f (delivered immediately, no reach anim)
    DW_MESSAGE_USED      = 48, // 0x30
};

// Capability bits. A COG declaring a handler for a DW message contributes the
// matching bit to its thing/surface's object-caps (dwCog_GetCogCaps); the
// assembled droid's stats record contributes the droid/tool caps that are
// intersected against them (dwGuiInGame_StartMission fills dwCog_droidCaps/
// toolCaps1/toolCaps2 from the stats record).
enum DW_CAP
{
    DWCOG_CAP_TAKEN     = 0x800,        // -> SITH_MESSAGE_TAKEN (26)
    DWCOG_CAP_TUGGED    = 0x2000,       // -> DW_MESSAGE_TUGGED
    DWCOG_CAP_CUT       = 0x4000,       // -> DW_MESSAGE_CUT
    DWCOG_CAP_INJECTED  = 0x8000,       // -> DW_MESSAGE_INJECTED
    DWCOG_CAP_POWERPLUG = 0x10000,      // -> DW_MESSAGE_POWERPLUG
    DWCOG_CAP_WELDED    = 0x20000,      // -> DW_MESSAGE_WELDED
    DWCOG_CAP_LONGREACH = 0x80000,      // droid caps only (Maybe): scan length = model radius instead of collideSize*1.5
    DWCOG_CAP_CONVERSE  = 0x100000,     // -> DW_MESSAGE_CONVERSE (also the body-slot "can converse" droid cap)
    DWCOG_CAP_USED      = 0x10000000,   // -> DW_MESSAGE_USED
    DWCOG_CAP_ACTIVATE  = 0x40000000,   // -> SITH_MESSAGE_ACTIVATE (1)
};

// ---- module globals shared across units --------------------------------
// Written by dwGuiInGame_StartMission (P6) from the assembled droid's stats
// record (+0x30/+0x34/+0x3c); dwCog_droidCaps is also read by the DW physics
// twin (sithPhysics_FUN_0045b070) and dwGuiInGame_SegUpdate.
extern uint32_t dwCog_droidCaps; // @0x541dc8
extern uint32_t dwCog_toolCaps2; // @0x541dcc
extern uint32_t dwCog_toolCaps1; // @0x541dd0
extern int dwCog_bInteractBusy;  // @0x541dd4 (reach anim in progress)
extern int dwCog_pendingMessage; // @0x541dd8 (queued DW_MESSAGE, 0 = none)

// Added: module reset for the soft-reset loop (the binary has no dwCog
// startup; part 1's dwCog_RegisterVerbs is the only registration entry).
void dwCog_Startup();

int dwCog_FreezePlayer();   // @44c270 (refcounted; zeroes motion + sets SITH_AF_CONTROLSDISABLED)
int dwCog_UnfreezePlayer(); // @44c2e0
void dwCog_ActivateTool(SithThing* pSource, int toolSlot); // @44c320 (0=body, 1/2=tool arms)
void dwCog_ScanAndInteract(SithThing* pSource, uint32_t reqCaps, int toolSlot); // @44c400
int dwCog_ScanRay(SithThing* pSource, const rdMatrix34* pOrient, const rdVector3* pStartPos, SithSector* pSector, flex_t rayDist, uint32_t reqCaps); // @44c820
uint32_t dwCog_GetThingCaps(SithThing* pThing);       // @44c8e0
uint32_t dwCog_GetCogCaps(sithCog* pCog);             // @44c960
uint32_t dwCog_GetSurfaceCaps(SithSurface* pSurface); // @44ca30
int dwCog_SelectMessage(uint32_t objCaps, uint32_t reqCaps); // @44ca80
void dwCog_UseItem(SithThing* pSource, int invBin);   // @44cb20 (inventory click)
void dwCog_GetActivateBin(sithCog* pCtx);             // @44cb90 (verb "dwgetactivatebin", registered by part 1/P8)
void dwCog_SendPendingMessage();                      // @44cbb0
void dwCog_ScanPuppetCallback(SithThing* pThing, int32_t track, uint32_t markerType); // @44cc10

#endif // PLATFORM_DROIDWORKS

#ifdef __cplusplus
}
#endif

#endif // _DWCOG_H
