// dwCog part 2 — DroidWorks droid-tool "activate/use" interaction dispatch
// (Ghidra 0x44c270-0x44cc4f).
//
// Flow: player Activate (sithPlayerActions_Activate / sithControl tool keys)
// -> dwCog_ActivateTool, or inventory click -> dwCog_UseItem
// -> dwCog_ScanAndInteract casts a fan of rays (0,-30,+30,-60,+60,-75,+75 deg
//    net, applied as cumulative -30/+60/-90/+120/-135/+150 pre-rotations)
//    via dwCog_ScanRay (sithCollision_SearchForCollisions along orient.lvec)
// -> each hit thing/surface is classified by the COG messages its linked COGs
//    declare handlers for (dwCog_GetThingCaps/GetSurfaceCaps/GetCogCaps)
// -> dwCog_SelectMessage intersects object caps with the tool's requested
//    caps and picks the highest-priority message
// -> a puppet "reach" anim plays (submode 9/10 = the DW .pup fire3/fire4
//    slots repurposed as tool-arm reaches); on marker 0x10 the queued message
//    is delivered (dwCog_ScanPuppetCallback -> dwCog_SendPendingMessage).
//    DW_MESSAGE_CONVERSE is delivered immediately with no animation.
//
// Pure C unit (procedural, no vtables/EH). The COG verb wrappers
// (dwCog_FreezePlayerVerb/UnfreezePlayerVerb @408fd0/408fe0) and
// dwCog_RegisterVerbs are dwCog part 1 (P8), not here.

#include "Dw/dwCog.h"
#include "Dw/dwWidget.h" // dwWidgetMsg + dwWidget_DispatchMsg (HUD refresh)

#include "Cog/sithCog.h"
#include "Cog/sithCogExec.h"
#include "Engine/sithCollision.h"
#include "Engine/sithPuppet.h"
#include "Primitives/rdMatrix.h"
#include "Primitives/rdModel3.h"
#include "Primitives/rdVector.h"
#include "World/sithSurface.h"
#include "jk.h" // _rand
#include "globals.h" // sithWorld_g_pCurrentWorld, sithTime_g_msecGameTime, g_debugmodeFlags, sithCog_aThingLinks/aSurfaceLinks

// TODO(dw-decomp): provided by dwGuiInGame (P6) — HUD voice line + Cammy
// caption (pCammyText may be NULL; priority gates against the running line).
extern void dwGuiInGame_PlayVoiceLine(const char* pCammyText, const char* pWavName, uint32_t priority);

// ---- module globals (binary @0x541db8-0x541ddc) -------------------------
static SithThing* dwCog_pHitThing = NULL;         // @0x541db8 (scan result)
static SithSurface* dwCog_pHitSurface = NULL;     // @0x541dbc (scan result)
static int dwCog_activateBin = 0;                 // @0x541dc0 (inventory bin used; read by the dwgetactivatebin verb)
static SithThing* dwCog_pInteractSource = NULL;   // @0x541dc4 (activator)
uint32_t dwCog_droidCaps = 0;                     // @0x541dc8 (set by dwGuiInGame_StartMission)
uint32_t dwCog_toolCaps2 = 0;                     // @0x541dcc (set by dwGuiInGame_StartMission)
uint32_t dwCog_toolCaps1 = 0;                     // @0x541dd0 (set by dwGuiInGame_StartMission)
int dwCog_bInteractBusy = 0;                      // @0x541dd4 (reach anim in progress)
int dwCog_pendingMessage = 0;                     // @0x541dd8 (queued DW_MESSAGE)
static int dwCog_freezeCount = 0;                 // @0x541ddc (dwCog_FreezePlayer refcount)

// Added: reset module statics for the soft-reset loop (no binary equivalent;
// the binary relies on process teardown).
void dwCog_Startup()
{
    dwCog_pHitThing = NULL;
    dwCog_pHitSurface = NULL;
    dwCog_activateBin = 0;
    dwCog_pInteractSource = NULL;
    dwCog_droidCaps = 0;
    dwCog_toolCaps2 = 0;
    dwCog_toolCaps1 = 0;
    dwCog_bInteractBusy = 0;
    dwCog_pendingMessage = 0;
    dwCog_freezeCount = 0;
}

// @44c270 — refcounted player freeze: while frozen the player actor has
// SITH_AF_CONTROLSDISABLED set and all motion zeroed. Impl behind the
// dwfreezeplayer verb wrapper (part 1).
int dwCog_FreezePlayer()
{
    dwCog_freezeCount++;
    if (dwCog_freezeCount != 0) // faithful: only skipped on wrap to 0
    {
        SithThing* pPlayer = sithWorld_g_pCurrentWorld->pLocalPlayer;
        pPlayer->actorParams.flags |= SITH_AF_CONTROLSDISABLED;
        rdVector_Zero3(&pPlayer->physicsParams.vel);
        rdVector_Zero3(&pPlayer->physicsParams.angularVelocity);
        rdVector_Zero3(&pPlayer->physicsParams.acceleration);
        rdVector_Zero3(&pPlayer->physicsParams.field_1F8);
    }
    return dwCog_freezeCount;
}

// @44c2e0
int dwCog_UnfreezePlayer()
{
    if ((unsigned int)dwCog_freezeCount > 1)
    {
        dwCog_freezeCount--;
        return dwCog_freezeCount;
    }
    dwCog_freezeCount = 0;
    sithWorld_g_pCurrentWorld->pLocalPlayer->actorParams.flags &= ~SITH_AF_CONTROLSDISABLED;
    return dwCog_freezeCount;
}

// @44c320 — activate tool arm `toolSlot` (0 = body/converse, 1/2 = tool
// arms; auto-swaps 1<->2 when the requested arm is empty but the other
// isn't). Body activation with no converse cap plays a random "huh?" grunt.
void dwCog_ActivateTool(SithThing* pSource, int toolSlot)
{
    uint32_t reqCaps;

    if (toolSlot == 2 && dwCog_toolCaps2 == 0 && dwCog_toolCaps1 != 0)
    {
        toolSlot = 1;
    }
    else if (toolSlot == 1 && dwCog_toolCaps2 != 0 && dwCog_toolCaps1 == 0)
    {
        toolSlot = 2;
    }

    if (toolSlot == 0)
    {
        reqCaps = dwCog_droidCaps & DWCOG_CAP_CONVERSE;
        if (reqCaps == 0)
        {
            if ((flex_t)_rand() * 3.051851e-05 < 0.5)
                dwGuiInGame_PlayVoiceLine(NULL, "GHCA053.wav", 0);
            else
                dwGuiInGame_PlayVoiceLine(NULL, "GHCA028.wav", 0);
        }
    }
    else
    {
        reqCaps = dwCog_toolCaps2;
        if (toolSlot != 2)
        {
            reqCaps = 0;
            if (toolSlot == 1)
                reqCaps = dwCog_toolCaps1;
        }
    }

    if (reqCaps != 0 && !dwCog_bInteractBusy)
    {
        dwCog_pInteractSource = pSource;
        dwCog_pHitThing = NULL;
        dwCog_pHitSurface = NULL;
        dwCog_activateBin = 0;
        dwCog_ScanAndInteract(pSource, reqCaps, toolSlot);
    }
}

// @44c400 — fan-raycast in front of pSource, queue the selected message, and
// play the reach anim (or deliver immediately for DW_MESSAGE_CONVERSE).
// Ray lengths are 1/cos(net angle) corrected so every probe reaches the same
// frontal plane; DWCOG_CAP_LONGREACH swaps the base length for the droid
// model's radius.
void dwCog_ScanAndInteract(SithThing* pSource, uint32_t reqCaps, int toolSlot)
{
    rdMatrix34 orient;
    rdVector3 eyePos;
    rdVector3 pyr;
    flex_t rayLen;
    int submode;

    dwCog_pInteractSource = pSource;
    dwCog_pHitThing = NULL;
    dwCog_pHitSurface = NULL;

    _memcpy(&orient, &pSource->orient, sizeof(orient));
    rdVector_Copy3(&eyePos, &pSource->position);
    if (pSource->type == SITH_THING_ACTOR || pSource->type == SITH_THING_PLAYER)
    {
        rdMatrix_PreRotate34(&orient, &pSource->actorParams.headPYR);
        rdVector_Add3Acc(&eyePos, &pSource->actorParams.eyeOffset);
    }

    SithSector* pSector = sithCollision_FindSectorInRadius(pSource->sector, &pSource->position, &eyePos, 0.0);
    if (!pSector)
        return;

    if (dwCog_droidCaps & DWCOG_CAP_LONGREACH)
        rayLen = pSource->renderData.model3->radius;
    else
        rayLen = pSource->collideSize * 1.5;
    if (reqCaps == DWCOG_CAP_CONVERSE)
        rayLen = rayLen * 1.25;

    if (!dwCog_ScanRay(pSource, &orient, &eyePos, pSector, rayLen, reqCaps))
    {
        rdVector_Set3(&pyr, -30.0, 0.0, 0.0);
        rdMatrix_PreRotate34(&orient, &pyr);
        if (!dwCog_ScanRay(pSource, &orient, &eyePos, pSector, rayLen * 1.1547005, reqCaps))
        {
            rdVector_Set3(&pyr, 60.0, 0.0, 0.0);
            rdMatrix_PreRotate34(&orient, &pyr);
            if (!dwCog_ScanRay(pSource, &orient, &eyePos, pSector, rayLen * 1.1547005, reqCaps))
            {
                rdVector_Set3(&pyr, -90.0, 0.0, 0.0);
                rdMatrix_PreRotate34(&orient, &pyr);
                if (!dwCog_ScanRay(pSource, &orient, &eyePos, pSector, rayLen + rayLen, reqCaps))
                {
                    rdVector_Set3(&pyr, 120.0, 0.0, 0.0);
                    rdMatrix_PreRotate34(&orient, &pyr);
                    if (!dwCog_ScanRay(pSource, &orient, &eyePos, pSector, rayLen + rayLen, reqCaps))
                    {
                        rdVector_Set3(&pyr, -135.0, 0.0, 0.0);
                        rdMatrix_PreRotate34(&orient, &pyr);
                        if (!dwCog_ScanRay(pSource, &orient, &eyePos, pSector, rayLen * 3.8637033, reqCaps))
                        {
                            rdVector_Set3(&pyr, 150.0, 0.0, 0.0);
                            rdMatrix_PreRotate34(&orient, &pyr);
                            dwCog_ScanRay(pSource, &orient, &eyePos, pSector, rayLen * 3.8637033, reqCaps);
                        }
                    }
                }
            }
        }
    }

    if (dwCog_pendingMessage == DW_MESSAGE_CONVERSE)
    {
        dwCog_SendPendingMessage();
        return;
    }

    if (toolSlot != 0)
    {
        // DW .pup submodes 9/10 (the fire3/fire4 slots) are the tool-arm
        // reach animations for slots 2/1 respectively.
        submode = 9;
        if (toolSlot == 1)
            submode = 10;

        if (!pSource->pPuppetClass
            || !pSource->pPuppetClass->modes[pSource->puppet->majorMode].keyframe[submode].keyframe
            || (g_debugmodeFlags & DEBUGFLAG_IN_EDITOR))
        {
            dwCog_SendPendingMessage();
        }
        else
        {
            if (sithPuppet_PlayMode(pSource, submode, dwCog_ScanPuppetCallback) >= 0)
                dwCog_bInteractBusy = 1;
            if (dwCog_bInteractBusy && dwCog_pendingMessage != 0)
                dwCog_FreezePlayer();
        }

        if (reqCaps == DWCOG_CAP_USED && dwCog_pendingMessage == 0
            && pSource == sithWorld_g_pCurrentWorld->pLocalPlayer)
        {
            if (0.5 <= (flex_t)_rand() * 3.051851e-05)
                dwGuiInGame_PlayVoiceLine(NULL, "GHCA056.wav", 0);
            else
                dwGuiInGame_PlayVoiceLine(NULL, "GHCA062.wav", 0);
        }
    }
}

// @44c820 — cast one ray along pOrient->lvec; classify hits until a message
// applies. Returns 1 when a message was queued (dwCog_pendingMessage +
// dwCog_pHitThing/pHitSurface set), 0 otherwise. Note (faithful): every
// popped hit overwrites pHit*/pendingMessage, including cap-less ones.
int dwCog_ScanRay(SithThing* pSource, const rdMatrix34* pOrient, const rdVector3* pStartPos, SithSector* pSector, flex_t rayDist, uint32_t reqCaps)
{
    SithCollision* pHit;
    uint32_t objCaps;
    int bFound = 0;

    sithCollision_SearchForCollisions(pSector, NULL, pStartPos, &pOrient->lvec, rayDist, 0.025, RAYCAST_2);
    do
    {
        pHit = sithCollision_PopStack();
        if (!pHit)
            break;
        objCaps = 0;
        if (pHit->type & SITHCOLLISION_WORLD)
        {
            objCaps = dwCog_GetSurfaceCaps(pHit->surface);
            dwCog_pHitSurface = pHit->surface;
            dwCog_pHitThing = NULL;
        }
        else if ((pHit->type & SITHCOLLISION_THING) && pHit->pThingCollided != pSource)
        {
            objCaps = dwCog_GetThingCaps(pHit->pThingCollided);
            dwCog_pHitSurface = NULL;
            dwCog_pHitThing = pHit->pThingCollided;
        }
        dwCog_pendingMessage = dwCog_SelectMessage(objCaps, reqCaps);
        if (dwCog_pendingMessage != 0)
            bFound = 1;
    } while (!bFound);
    sithCollision_DecreaseStackLevel();
    return bFound;
}

// @44c8e0 — OR together the caps of every COG linked to pThing (class cog,
// capture cog, and all signature-matching thing links).
uint32_t dwCog_GetThingCaps(SithThing* pThing)
{
    uint32_t caps = 0;

    if (pThing->flags & SITH_TF_CAPTURED)
    {
        if (pThing->pCog)
            caps = dwCog_GetCogCaps(pThing->pCog);
        if (pThing->pCaptureCog)
            caps |= dwCog_GetCogCaps(pThing->pCaptureCog);
        for (uint32_t i = 0; i < (uint32_t)sithCog_numThingLinks; i++)
        {
            SithCogThingLink* pLink = &sithCog_aThingLinks[i];
            if (pLink->thing == pThing && pLink->signature == (int32_t)pThing->signature)
                caps |= dwCog_GetCogCaps(pLink->cog);
        }
    }
    return caps;
}

// @44c960 — map a COG's declared message handlers to capability bits.
uint32_t dwCog_GetCogCaps(sithCog* pCog)
{
    uint32_t caps = 0;
    SithCogScript* pScript = pCog->pScript;

    for (uint32_t i = 0; i < pScript->numHandlers; i++)
    {
        switch (pScript->aHandlers[i].trigId)
        {
        case SITH_MESSAGE_ACTIVATE:
            caps |= DWCOG_CAP_ACTIVATE;
            break;
        case SITH_MESSAGE_TAKEN:
            caps |= DWCOG_CAP_TAKEN;
            break;
        case DW_MESSAGE_CUT:
            caps |= DWCOG_CAP_CUT;
            break;
        case DW_MESSAGE_INJECTED:
            caps |= DWCOG_CAP_INJECTED;
            break;
        case DW_MESSAGE_POWERPLUG:
            caps |= DWCOG_CAP_POWERPLUG;
            break;
        case DW_MESSAGE_WELDED:
            caps |= DWCOG_CAP_WELDED;
            break;
        case DW_MESSAGE_TUGGED:
            caps |= DWCOG_CAP_TUGGED;
            break;
        case DW_MESSAGE_CONVERSE:
            caps |= DWCOG_CAP_CONVERSE;
            break;
        case DW_MESSAGE_USED:
            caps |= DWCOG_CAP_USED;
            break;
        }
    }
    return caps;
}

// @44ca30 — OR together the caps of every COG linked to pSurface.
uint32_t dwCog_GetSurfaceCaps(SithSurface* pSurface)
{
    uint32_t caps = 0;

    if (pSurface->flags & SITH_SURFACE_COG_LINKED)
    {
        for (uint32_t i = 0; i < (uint32_t)sithCog_numSurfaceLinks; i++)
        {
            SithCogSurfaceLink* pLink = &sithCog_aSurfaceLinks[i];
            if (pLink->surface == pSurface)
                caps |= dwCog_GetCogCaps(pLink->cog);
        }
    }
    return caps;
}

// @44ca80 — intersect object caps with the tool's requested caps and return
// the highest-priority COG message (0 = none). DEBUGFLAG_IN_EDITOR ignores
// the request mask entirely.
int dwCog_SelectMessage(uint32_t objCaps, uint32_t reqCaps)
{
    uint32_t caps = reqCaps & objCaps;

    if (g_debugmodeFlags & DEBUGFLAG_IN_EDITOR)
        caps = objCaps;
    if (caps != 0)
    {
        if (caps & DWCOG_CAP_POWERPLUG)
            return DW_MESSAGE_POWERPLUG;
        if (caps & DWCOG_CAP_WELDED)
            return DW_MESSAGE_WELDED;
        if (caps & DWCOG_CAP_INJECTED)
            return DW_MESSAGE_INJECTED;
        if (caps & DWCOG_CAP_CUT)
            return DW_MESSAGE_CUT;
        if (caps & DWCOG_CAP_TUGGED)
            return DW_MESSAGE_TUGGED;
        if (caps & DWCOG_CAP_TAKEN)
            return SITH_MESSAGE_TAKEN;
        if (caps & DWCOG_CAP_ACTIVATE)
            return SITH_MESSAGE_ACTIVATE;
        if (caps & DWCOG_CAP_CONVERSE)
            return DW_MESSAGE_CONVERSE;
        if (caps & DWCOG_CAP_USED)
            return DW_MESSAGE_USED;
    }
    return 0;
}

// @44cb20 — inventory-item click: if a tool arm has the grab cap
// (DWCOG_CAP_TAKEN) request DW_MESSAGE_USED through that arm; otherwise scan
// with no request (body, no anim).
void dwCog_UseItem(SithThing* pSource, int invBin)
{
    int toolSlot = 0;
    uint32_t reqCaps = 0;

    if (dwCog_toolCaps2 & DWCOG_CAP_TAKEN)
    {
        toolSlot = 2;
        reqCaps = DWCOG_CAP_USED;
    }
    else if (dwCog_toolCaps1 & DWCOG_CAP_TAKEN)
    {
        toolSlot = 1;
        reqCaps = DWCOG_CAP_USED;
    }

    if (!dwCog_bInteractBusy)
    {
        dwCog_pHitThing = NULL;
        dwCog_pHitSurface = NULL;
        dwCog_pInteractSource = pSource;
        dwCog_activateBin = invBin;
        dwCog_ScanAndInteract(pSource, reqCaps, toolSlot);
    }
}

// @44cb90 — COG verb "dwgetactivatebin" (registered by dwCog_RegisterVerbs,
// part 1/P8): pushes the inventory bin the running interaction came from.
void dwCog_GetActivateBin(sithCog* pCtx)
{
    sithCogExec_PushInt(pCtx, dwCog_activateBin);
}

// @44cbb0 — deliver the queued message to the scan hit.
void dwCog_SendPendingMessage()
{
    if (dwCog_pHitThing)
    {
        sithCog_ThingSendMessage(dwCog_pHitThing, dwCog_pInteractSource, dwCog_pendingMessage);
        dwCog_pendingMessage = 0;
        return;
    }
    sithCog_SurfaceSendMessage(dwCog_pHitSurface, dwCog_pInteractSource, dwCog_pendingMessage);
    dwCog_pendingMessage = 0;
}

// @44cc10 — reach-anim track callback: marker 0x10 (the reach apex) delivers
// the queued message and unfreezes; track end (marker 0) clears the busy
// flag. Always falls through to the engine default handler.
void dwCog_ScanPuppetCallback(SithThing* pThing, int32_t track, uint32_t markerType)
{
    if (markerType == 0)
    {
        dwCog_bInteractBusy = 0;
    }
    else if (markerType == 0x10 && dwCog_pendingMessage != 0)
    {
        dwCog_SendPendingMessage();
        dwCog_UnfreezePlayer();
    }
    sithPuppet_DefaultCallback(pThing, track, markerType);
}


// =========================================================================
// dwCog verb layer (part 1, @409360 dwCog_RegisterVerbs). Each verb is
// `void dwCog_Verb(sithCog*)`. DW-data verbs that poke C++ structs go through
// C-callable typed accessors (dw{Mission,Part}_*) because the binary's raw
// field offsets are 32-bit-specific and wrong in this 64-bit port.
// =========================================================================

// Typed accessors implemented in the owning C++ modules.
extern void dwMission_SetUnlockedByName(const char* pName, int bUnlocked);
extern int  dwPart_SetAvailableByName(const char* pName, int bAvailable);
extern int  dwCog_WorkspaceHasPart(const char* pName);
extern void dwGuiInGame_RequestEndMission(void); // sets bEndRequested (0x124)
extern int  dwGuiInGame_GetCammyMsgCode(void);   // reads cammyMsgCode (0x174)
extern int  dwGuiInGame_GetDroidHeadType(void);  // droid stats voiceChars pair
extern int  dwGuiInGame_GetDroidCaps(int mask);  // droid capFlags & mask
extern int  dwGuiInGame_GetArmStrength(void);    // max(maxLoadLeft, maxLoadRight)
extern void dwGuiInGame_ShowCammyTextVerb(int msgCode); // ShowCammyText(id)
extern void dwGuiInGame_SetRefTopicVerb(char* pTopic);  // SetRefTopic(str)
extern void dwGuiInGame_ClearDialog(void);       // clear response menu + NPC caption

// dwplaymovie deps (C++ modules; all extern "C", so C linkage matches). The
// dwSegment type stays opaque here — we only pass the pointers through.
typedef struct dwSegment dwSegment;
extern dwSegment* dwSegment_pActive;
extern dwSegment* dwMovie_OpenSeg(const char* pFilename, void* pOverlayImage);
extern void       dwSegment_InterruptWith(dwSegment* pReturnTo, dwSegment* pInterrupt);

// Inventory verbs. The engine impls (defined in Cog/sithCogFunction{Thing,
// Player}.c but not exposed in their headers) already register plain setinv/
// changeinv/setinvavailable; the DW verbs OVERRIDE those registrations with a
// wrapper that also broadcasts a HUD inventory-bar refresh. dwCog_RegisterVerbs
// runs at dwSith_Startup, AFTER the engine registration, so the DW wrapper wins
// (sithCog_RegisterFunction replaces a duplicate-named symbol's value).
extern void sithCogFunctionThing_SetInventory(sithCog* pCtx);
extern void sithCogFunctionThing_ChangeInventory(sithCog* pCtx);
extern void sithCogFunctionPlayer_SetInvAvailable(sithCog* pCtx);
// dwsetupcrystalinventory body (typed mission-list walk in dwMission.cpp).
extern void dwMission_SetupCrystalInventory(void);

// @408fc0 (dwCog_EnableJump) / @408fb0 (dwCog_DisableJump) — toggle the actor
// flag that gates jumping on the player thing. Verbs take no args (registered
// as cog funcs, so the ignored ctx is present). Guarded vs a NULL world/player.
void dwCog_EnableJump(sithCog* pCtx)
{
    (void)pCtx;
    if (sithWorld_g_pCurrentWorld && sithWorld_g_pCurrentWorld->pLocalPlayer)
        sithWorld_g_pCurrentWorld->pLocalPlayer->actorParams.flags &= ~SITH_AF_4000000;
}
void dwCog_DisableJump(sithCog* pCtx)
{
    (void)pCtx;
    if (sithWorld_g_pCurrentWorld && sithWorld_g_pCurrentWorld->pLocalPlayer)
        sithWorld_g_pCurrentWorld->pLocalPlayer->actorParams.flags |= SITH_AF_4000000;
}

// @408e90 (dwCog_GetCameraPosition) — push the current camera's world position
// (binary cam+100 = SithCamera.lookPos), or the zero vector when no camera.
void dwCog_GetCameraPosition(sithCog* pCtx)
{
    if (sithCamera_g_pCurCamera)
    {
        sithCogExec_PushVector(pCtx, &sithCamera_g_pCurCamera->lookPos);
        return;
    }
    rdVector3 zero = { 0.0, 0.0, 0.0 };
    sithCogExec_PushVector(pCtx, &zero);
}

// @408ee0 (dwCog_GetCameraSector) — push the id of the camera's current sector
// (binary **(cam+0x18) = SithCamera.sector->id), or 0 when no camera/sector.
void dwCog_GetCameraSector(sithCog* pCtx)
{
    if (sithCamera_g_pCurCamera && sithCamera_g_pCurCamera->sector)
    {
        sithCogExec_PushInt(pCtx, sithCamera_g_pCurCamera->sector->id);
        return;
    }
    sithCogExec_PushInt(pCtx, 0);
}

// @409010 (dwCog_EndMission, registered as BOTH dwendmission + dwendlevel) —
// request mission end (SegUpdate acts on the flag next frame).
void dwCog_EndMission(sithCog* pCtx)
{
    (void)pCtx;
    dwGuiInGame_RequestEndMission();
}

// @408fa0 (dwCog_GetMissionText) — push the last Cammy-caption message code.
void dwCog_GetMissionText(sithCog* pCtx)
{
    sithCogExec_PushInt(pCtx, dwGuiInGame_GetCammyMsgCode());
}

// @409020 (dwCog_EnableMission) / @409060 — unlock/lock a mission by id name.
void dwCog_EnableMission(sithCog* pCtx)
{
    dwMission_SetUnlockedByName(sithCogExec_PopString(pCtx), 1);
}
void dwCog_DisableMission(sithCog* pCtx)
{
    dwMission_SetUnlockedByName(sithCogExec_PopString(pCtx), 0);
}

// @408f60 (dwCog_EnablePart) / @408f90 — set a blueprint's bAvailable flag.
void dwCog_EnablePart(sithCog* pCtx)
{
    dwPart_SetAvailableByName(sithCogExec_PopString(pCtx), 1);
}
void dwCog_DisablePart(sithCog* pCtx)
{
    dwPart_SetAvailableByName(sithCogExec_PopString(pCtx), 0);
}

// @408e50 (dwCog_CheckForPart) — 1 if the named part is in the workspace droid.
void dwCog_CheckForPart(sithCog* pCtx)
{
    sithCogExec_PushInt(pCtx, dwCog_WorkspaceHasPart(sithCogExec_PopString(pCtx)));
}

// @408fd0 (dwCog_FreezePlayerVerb) / @408fe0 — thin verb wrappers over the
// part-2 freeze/unfreeze refcounted controls-disable helpers.
void dwCog_FreezePlayerVerb(sithCog* pCtx)
{
    (void)pCtx;
    dwCog_FreezePlayer();
}
void dwCog_UnfreezePlayerVerb(sithCog* pCtx)
{
    (void)pCtx;
    dwCog_UnfreezePlayer();
}

// @408eb0 (dwCog_GetPlayerHeadType) — push the assembled droid's head/voice code.
void dwCog_GetPlayerHeadType(sithCog* pCtx)
{
    sithCogExec_PushInt(pCtx, dwGuiInGame_GetDroidHeadType());
}

// @408f60 (dwCog_CheckDroidCaps) — push (droid capFlags & poppedMask).
void dwCog_CheckDroidCaps(sithCog* pCtx)
{
    int mask = sithCogExec_PopInt(pCtx);
    sithCogExec_PushInt(pCtx, dwGuiInGame_GetDroidCaps(mask));
}

// @408f90 (dwCog_GetArmStrength) — push the droid's arm LOAD (max of the two arms).
void dwCog_GetArmStrength(sithCog* pCtx)
{
    sithCogExec_PushInt(pCtx, dwGuiInGame_GetArmStrength());
}

// @408de0 (dwCog_SetMissionText) — show the Cammy caption for a message id.
void dwCog_SetMissionText(sithCog* pCtx)
{
    dwGuiInGame_ShowCammyTextVerb(sithCogExec_PopInt(pCtx));
}

// @409310 (dwCog_SetRefTopic) — set the in-mission reference topic file.
void dwCog_SetRefTopic(sithCog* pCtx)
{
    dwGuiInGame_SetRefTopicVerb(sithCogExec_PopString(pCtx));
}

// @408d60 (dwCog_ClearDialog) — clear the response menu + the NPC speech caption.
void dwCog_ClearDialog(sithCog* pCtx)
{
    (void)pCtx;
    dwGuiInGame_ClearDialog();
}

// @409330 (dwCog_PlayMovie) — pop a filename, open it as a movie segment and
// interrupt the active segment with it (returns to the active seg when done).
void dwCog_PlayMovie(sithCog* pCtx)
{
    char* pName = sithCogExec_PopString(pCtx);
    if (pName != NULL && *pName != '\0')
    {
        dwSegment* pMovie = dwMovie_OpenSeg(pName, NULL);
        if (pMovie != NULL)
            dwSegment_InterruptWith(dwSegment_pActive, pMovie);
    }
}

// The HUD inventory-bar refresh the DW inventory verbs issue after mutating a
// bin: OnMessage(0x1f4b) delivered to dwWidget_pDefault (the active screen/HUD,
// pTarget/pOverride both NULL). No-op when no screen is active or the code is
// unhandled. Binary: each verb builds this dwWidgetMsg on the stack and calls
// the mislabeled dwWidget_DispatchMsg@0x444d00 — factored here.
static void dwCog_HudRefreshInventory(void)
{
    dwWidgetMsg msg;
    msg.code = 0x1f4b;
    msg.pSender = NULL;
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);
}

// @409150 (dwCog_SetInv "setinv") — engine setinv + HUD refresh.
void dwCog_SetInv(sithCog* pCtx)
{
    sithCogFunctionThing_SetInventory(pCtx);
    dwCog_HudRefreshInventory();
}
// @409190 (dwCog_ChangeInv "changeinv") — engine changeinv + HUD refresh.
void dwCog_ChangeInv(sithCog* pCtx)
{
    sithCogFunctionThing_ChangeInventory(pCtx);
    dwCog_HudRefreshInventory();
}
// @4091d0 (dwCog_SetInvAvailable "setinvavailable") — engine setinvavailable + HUD refresh.
void dwCog_SetInvAvailable(sithCog* pCtx)
{
    sithCogFunctionPlayer_SetInvAvailable(pCtx);
    dwCog_HudRefreshInventory();
}
// @409210 (dwCog_SetupCrystalInventory "dwsetupcrystalinventory") — grant
// crystal inventory bins for completed crystal missions, then HUD refresh.
void dwCog_SetupCrystalInventory(sithCog* pCtx)
{
    (void)pCtx;
    dwMission_SetupCrystalInventory();
    dwCog_HudRefreshInventory();
}

void dwCog_RegisterVerbs(void)
{
    // --- READY (wired) ---------------------------------------------------
    sithCog_RegisterFunction(sithCog_g_pSymbolTable, dwCog_GetActivateBin,   "dwgetactivatebin");
    sithCog_RegisterFunction(sithCog_g_pSymbolTable, dwCog_FreezePlayerVerb, "dwfreezeplayer");
    sithCog_RegisterFunction(sithCog_g_pSymbolTable, dwCog_UnfreezePlayerVerb, "dwunfreezeplayer");
    sithCog_RegisterFunction(sithCog_g_pSymbolTable, dwCog_EnablePart,       "dwenablepart");
    sithCog_RegisterFunction(sithCog_g_pSymbolTable, dwCog_DisablePart,      "dwdisablepart");
    sithCog_RegisterFunction(sithCog_g_pSymbolTable, dwCog_EnableMission,    "dwenablemission");
    sithCog_RegisterFunction(sithCog_g_pSymbolTable, dwCog_DisableMission,   "dwdisablemission");
    sithCog_RegisterFunction(sithCog_g_pSymbolTable, dwCog_CheckForPart,     "dwcheckforpart");
    sithCog_RegisterFunction(sithCog_g_pSymbolTable, dwCog_EnableJump,       "dwenablejump");
    sithCog_RegisterFunction(sithCog_g_pSymbolTable, dwCog_DisableJump,      "dwdisablejump");
    sithCog_RegisterFunction(sithCog_g_pSymbolTable, dwCog_GetCameraPosition,"dwgetcameraposition");
    sithCog_RegisterFunction(sithCog_g_pSymbolTable, dwCog_GetCameraSector,  "dwgetcamerasector");
    sithCog_RegisterFunction(sithCog_g_pSymbolTable, dwCog_EndMission,       "dwendmission");
    sithCog_RegisterFunction(sithCog_g_pSymbolTable, dwCog_EndMission,       "dwendlevel");
    sithCog_RegisterFunction(sithCog_g_pSymbolTable, dwCog_GetMissionText,   "dwgetmissiontext");

    // droid-stats-record queries (read the baked-droid stats via accessors)
    sithCog_RegisterFunction(sithCog_g_pSymbolTable, dwCog_GetPlayerHeadType,"dwgetplayerheadtype");
    sithCog_RegisterFunction(sithCog_g_pSymbolTable, dwCog_CheckDroidCaps,   "dwcheckdroidcaps");
    sithCog_RegisterFunction(sithCog_g_pSymbolTable, dwCog_GetArmStrength,   "dwgetarmstrength");
    // caption / dialog / movie
    sithCog_RegisterFunction(sithCog_g_pSymbolTable, dwCog_SetMissionText,   "dwsetmissiontext");
    sithCog_RegisterFunction(sithCog_g_pSymbolTable, dwCog_SetRefTopic,      "dwsetreftopic");
    sithCog_RegisterFunction(sithCog_g_pSymbolTable, dwCog_ClearDialog,      "dwcleardialog");
    sithCog_RegisterFunction(sithCog_g_pSymbolTable, dwCog_PlayMovie,        "dwplaymovie");

    // --- inventory verbs: the DW wrappers OVERRIDE the engine's plain
    //     setinv/changeinv/setinvavailable registrations (registered earlier by
    //     the sithCogFunctionThing/Player startup) with the same engine call
    //     PLUS a HUD inventory-bar refresh (dwWidget_DispatchMsg 0x1f4b).
    //     dwsetupcrystalinventory grants crystal bins from completed missions.
    sithCog_RegisterFunction(sithCog_g_pSymbolTable, dwCog_SetInv,          "setinv");
    sithCog_RegisterFunction(sithCog_g_pSymbolTable, dwCog_ChangeInv,       "changeinv");
    sithCog_RegisterFunction(sithCog_g_pSymbolTable, dwCog_SetInvAvailable, "setinvavailable");
    sithCog_RegisterFunction(sithCog_g_pSymbolTable, dwCog_SetupCrystalInventory, "dwsetupcrystalinventory");

    // --- BLOCKED (need not-yet-ported deps) ------------------------------
    // dwenableescape / dwdisableescape write binary field_0x110 which the port
    //   maps to dwGuiInGame::bConvPending (conversation state), NOT an escape
    //   flag — a real offset/semantics conflict. Left unwired until resolved
    //   (writing bConvPending here would corrupt conversation handling).
    // Still BLOCKED:
    // - voice/caption playback (dwplaycharacterspeech/dwplayplayerspeech/
    //   dwplaycammyspeech): the deps now EXIST (dwSoundSample_GetLengthMs,
    //   dwGuiInGame::PlayVoiceLineEx/StopVoiceLine/ClearPlayerSpeech, the
    //   dwGuiSpeech caption), BUT dwGuiInGame::PlayVoiceLineEx is currently
    //   short-circuited (`return;`) from the in-game bring-up — un-stub + a
    //   runtime pass is required before wiring these. Also needs a port of
    //   dwCog_GetPlayerSpeechPath@408950 (head-type wav remapper).
    // - conversation response menu (dwaddresponse/dwgetplayerresponse/
    //   dwplayplayerresponse): the binary reads field_0x120 as the SELECTED
    //   response item (+4 = id, +0x1c = wav), but the port + Ghidra ctor plate
    //   both label 0x120 pConversationCog(sithCog*) — an unresolved offset/
    //   semantics conflict; resolve which field holds the selected item first.
    // - dwenableescape/dwdisableescape: binary field_0x110 maps to the port's
    //   dwGuiInGame::bConvPending (conversation state) — writing it would
    //   corrupt conversations. Resolve the real Esc-gating field first.
    // - dwflashinventory: needs the dwWcButtonBlink inventory button
    //   (field_0x194, currently unmodelled on dwGuiInGame).
    //   See DW/decomp_tools/cog_verb_survey.md for the full per-verb deps.
}

