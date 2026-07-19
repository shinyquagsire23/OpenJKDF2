// dwMission — mission-record parsing + the workshop<->mission sequencer.
//
// DroidWorks.exe: dwMission_ParseInfo@41c530 / ParseObjective@41c960 /
// ClearObjectives@41c920 (0x41c0f0 dwGuiMission unit) + dwMission_FreeInfo
// @41a530 (dw part2) + dwMissionSequence Reset@41ea50 / Advance@41ea60
// (vtbl 0x51f7d8: dwSegment subclass overriding Activate; dtor slot = the
// shared trivial stub @41a7b0).
//
// Compiled as C++ (the binary functions carry MSVC EH frames around their
// dwString/objective locals; dwMissionSequence is a real class). The record
// API keeps C linkage via dwMission.h.
//
// SKIPPED here (P6, dwGuiMission screens): dwGuiDialog/dwGuiMissionMap/
// dwGuiBrief* classes of the 0x41c0f0 unit, and the dwMissionTransIn/Out
// slide anims @41eb90/41ee60 — dwMissionSequence::Activate reaches them
// through the TODO factory externs below.

#include "Dw/dwMission.h"

#include "Dw/dwColormap.h"
#include "Dw/dwString.h"       // dwString_Equals
#include "stdPlatform.h"

// Unguarded C engine headers — wrap for correct C++<->C linkage (matches the
// src/Dw sibling convention, e.g. dwGuiInGame.cpp).
extern "C" {
#include "globals.h"           // SithThing / SithWorld / sithWorld_g_pCurrentWorld
#include "Gameplay/sithInventory.h" // sithInventory_SetInventory[Available]
}

#include <stdlib.h>

// ------------------------------------------------------------------
// Cross-unit externs
// ------------------------------------------------------------------

// TODO(dw-decomp): provided by dwGuiMission (P6). Creation shims for the
// three segments the sequencer spawns:
//  - dwMissionTransIn_New:  binary `new(0x3d0)` + dwMissionTransIn_Ctor@41eb90
//    (dwAnim subclass, vtbl 0x51f0c0 — TransToM.flc slide-in + MPanel*.wav cues)
//  - dwGuiMissionMap_New:   binary `new(0xf4)` + dwGuiMissionMap_Ctor@41db20;
//    the binary then used object+0x10 (the MI dwSegment base) — in C++ the
//    shim just upcasts the screen to dwSegment*.
//  - dwMissionTransOut_New: binary `new(0x3d0)` + dwMissionTransOut_Ctor@41ee60
//    (TransFromM.flc slide-out).
extern "C" dwSegment* dwMissionTransIn_New(dwImage* pBgImage);
extern "C" dwSegment* dwGuiMissionMap_New(dwImage* pBgImage);
extern "C" dwSegment* dwMissionTransOut_New(dwImage* pBgImage);

// ------------------------------------------------------------------
// Mission records
// ------------------------------------------------------------------

// C-callable helper for the dwCog dwenablemission/dwdisablemission verbs
// (@dwCog_EnableMission/@dwCog_DisableMission): find a mission by its id name
// (dwMission::name) on dwCore_pMissionList and set its bUnlocked flag. Typed
// access here so the C verb layer avoids the 32-bit binary's raw field offsets.
extern "C" void dwMission_SetUnlockedByName(const char* pName, int bUnlocked)
{
    if (dwCore_pMissionList == NULL)
        return;
    for (dwListNode* pNode = dwCore_pMissionList->pNext; pNode != dwCore_pMissionList;
         pNode = pNode->pNext)
    {
        dwMission* pMission = (dwMission*)pNode->pData;
        if (dwString_Equals(pMission->name.pBuffer, pName))
        {
            pMission->bUnlocked = (uint8_t)(bUnlocked ? 1 : 0);
            return;
        }
    }
}

// C-callable helper for the dwCog dwsetupcrystalinventory verb
// (@dwCog_SetupCrystalInventory@409210): walk dwCore_pMissionList and, for each
// "crystal" mission (missionType == 1), grant the local player an inventory bin
// starting at 0x22 — amount 1.0 + mark-available for a COMPLETED mission
// (rank != 0, advancing the bin), or amount 0 + not-available otherwise (bin
// not advanced, matching the binary). Typed access here keeps the raw 32-bit
// binary field offsets out of the C verb layer; the verb layer issues the
// HUD-refresh broadcast afterward.
extern "C" void dwMission_SetupCrystalInventory(void)
{
    SithThing* pPlayer = sithWorld_g_pCurrentWorld ? sithWorld_g_pCurrentWorld->pLocalPlayer : NULL;
    if (pPlayer == NULL || dwCore_pMissionList == NULL)
        return;
    int bin = 0x22;
    for (dwListNode* pNode = dwCore_pMissionList->pNext; pNode != dwCore_pMissionList;
         pNode = pNode->pNext)
    {
        dwMission* pMission = (dwMission*)pNode->pData;
        if (pMission->missionType != 1)
            continue;
        if (pMission->rank == 0)
        {
            sithInventory_SetInventory(pPlayer, bin, 0.0f);
            sithInventory_SetInventoryAvailable(pPlayer, bin, 0);
        }
        else
        {
            sithInventory_SetInventory(pPlayer, bin, 1.0f);
            sithInventory_SetInventoryAvailable(pPlayer, bin, 1);
            bin++;
        }
    }
}

// DEFCONn cheat: set the current mission's earned rank to n (binary writes the
// trailing digit to dwCore_pCurrentMission's int @+8 = dwMission::rank).
extern "C" void dwMission_SetCurrentRank(int rank)
{
    if (dwCore_pCurrentMission != NULL)
        dwCore_pCurrentMission->rank = (uint8_t)rank;
}

// SOMONEY cheat: unlock every mission on the list.
extern "C" void dwMission_UnlockAll(void)
{
    if (dwCore_pMissionList == NULL)
        return;
    for (dwListNode* pNode = dwCore_pMissionList->pNext; pNode != dwCore_pMissionList;
         pNode = pNode->pNext)
    {
        ((dwMission*)pNode->pData)->bUnlocked = 1;
    }
}

// @41c960 (dwMission_ParseObjective) — parse "<code> <param> <label...>"
// from the current line into pObj.
// Note: the binary default-ctor'd pObj->label here (it received raw memory);
// the translation receives a `new`-constructed record, so label is already
// empty — the Assign below matches the binary's net effect.
extern "C" dwMissionObjective* dwMission_ParseObjective(dwMissionObjective* pObj, dwConfFile* pConf)
{
    uint32_t tmp;

    pObj->bRequirement = 0;
    pObj->bFlag = 0;
    tmp = 0;
    dwConfFile_ParseULong(pConf, &tmp);
    pObj->code = (uint8_t)tmp;
    dwConfFile_ParseULong(pConf, &tmp);
    pObj->param = tmp;
    pObj->label.AssignCStr(pConf->pCursor);
    return pObj;
}

// @41c530 (dwMission_ParseInfo) — parse one mission record (positioned on
// the "BEGIN <name>" line) until END/EOF.
extern "C" dwMission* dwMission_ParseInfo(dwMission* pMission, dwConfFile* pConf)
{
    char* pToken;
    dwMissionObjective* pObj;
    dwList* pObjectiveList;
    uint32_t idx;
    int bDone;

    pMission->bUnlocked = 0;
    pMission->bDone = 0;
    pMission->missionType = 0;
    pMission->rank = 0;
    pMission->mapPos.x = 0;
    pMission->mapPos.y = 0;

    // Objective list sentinel (binary: bare alloc(0xc) + self-link — the
    // inlined dwList ctor).
    pObjectiveList = (dwList*)&pMission->pObjectives;
    pMission->pObjectives = (dwListNode*)malloc(sizeof(dwListNode));
    pMission->pObjectives->pNext = pMission->pObjectives;
    pMission->pObjectives->pPrev = pMission->pObjectives;
    pMission->pObjectives->pData = NULL; // Note: binary left the sentinel payload uninitialized

    // "BEGIN <name>": the id token is the next token on the current line.
    dwConfFile_ParseString(pConf, &pMission->name);

    bDone = 0;
    while (!pConf->bEof && !bDone)
    {
        dwConfFile_ReadLine(pConf);
        pToken = dwConfFile_NextToken(pConf);
        if (dwString_Equals(pToken, "BRIEFING"))
        {
            pMission->briefing.Assign(pConf->pCursor, 0);
        }
        else if (dwString_Equals(pToken, "DEPLOYMENT"))
        {
            pMission->missionType = DW_MISSION_DEPLOYMENT;
        }
        else if (dwString_Equals(pToken, "END"))
        {
            bDone = 1;
        }
        else if (dwString_Equals(pToken, "MAP"))
        {
            dwConfFile_ParsePoint(pConf, &pMission->mapPos);
        }
        else if (dwString_Equals(pToken, "NAME"))
        {
            pMission->displayName.Assign(pConf->pCursor, 0);
        }
        else if (dwString_Equals(pToken, "GOAL"))
        {
            pObj = dwMission_ParseObjective(new dwMissionObjective, pConf);
            pObjectiveList->InsertAfter(pMission->pObjectives->pPrev, pObj);
        }
        else if (dwString_Equals(pToken, "REQUIREMENT"))
        {
            pObj = dwMission_ParseObjective(new dwMissionObjective, pConf);
            pObj->bRequirement = 1;
            pObjectiveList->InsertAfter(pMission->pObjectives->pPrev, pObj);
        }
        else if (dwString_Equals(pToken, "REWARD"))
        {
            idx = 0;
            dwConfFile_ParseULong(pConf, &idx);
            if (idx < 3)
            {
                pToken = dwConfFile_NextToken(pConf);
                pMission->aRewards[idx].AssignCStr(pToken);
            }
        }
        else if (dwString_Equals(pToken, "VIDEO"))
        {
            idx = 0;
            dwConfFile_ParseULong(pConf, &idx);
            if (idx < 3)
            {
                pToken = dwConfFile_NextToken(pConf);
                pMission->aVideoNames[idx].AssignCStr(pToken);
            }
        }
        else if (dwString_Equals(pToken, "VOICEOVER"))
        {
            pToken = dwConfFile_NextToken(pConf);
            pMission->voiceover.AssignCStr(pToken);
        }
        else if (dwString_Equals(pToken, "SECRET"))
        {
            pMission->missionType = DW_MISSION_SECRET;
        }
        else if (dwString_Equals(pToken, "TGROUND"))
        {
            pMission->missionType = DW_MISSION_TGROUND;
        }
        else if (dwString_Equals(pToken, "FINAL"))
        {
            pMission->missionType = DW_MISSION_FINAL;
        }
        else if (dwString_Equals(pToken, "CRYSTAL"))
        {
            pMission->missionType = DW_MISSION_CRYSTAL;
        }
        else if (pToken && *pToken)
        {
            stdPlatform_Printf("Mission: unrecognized keyword %s\n", pToken); // binary: jk_logtofile
        }
    }

    // Untyped missions start unlocked (SECRET/FINAL/... stay locked until
    // dwPlayer_LoadPlr / gameplay unlocks them).
    if (pMission->missionType == DW_MISSION_NORMAL)
        pMission->bUnlocked = 1;
    return pMission;
}

// @41c920 (dwMission_ClearObjectives)
extern "C" void dwMission_ClearObjectives(dwMission* pMission)
{
    dwListNode* pNode;

    for (pNode = pMission->pObjectives->pNext; pNode != pMission->pObjectives; pNode = pNode->pNext)
    {
        ((dwMissionObjective*)pNode->pData)->bFlag = 0;
    }
}

// @41a530 (dwMission_FreeInfo) — free every owned string + the objective
// list. The record itself is NOT freed (dw_Shutdown does that after).
// Note: the binary freed rewards/videos via the MSVC vector-dtor helper and
// swept the objective ring twice (payload pass, then a leftover-node pass
// before freeing the sentinel); net effect is identical.
extern "C" void dwMission_FreeInfo(dwMission* pMission)
{
    dwListNode* pNode;
    dwListNode* pNext;
    dwMissionObjective* pObj;
    int i;

    for (i = 2; i >= 0; i--)
        pMission->aRewards[i].Free();

    for (pNode = pMission->pObjectives->pNext; pNode != pMission->pObjectives; pNode = pNext)
    {
        pNext = pNode->pNext;
        pObj = (dwMissionObjective*)pNode->pData;
        free(pNode);
        if (pObj)
            delete pObj; // binary: dwString_Free(label) + FreeHandle
    }
    free(pMission->pObjectives); // the sentinel

    pMission->voiceover.Free();
    for (i = 2; i >= 0; i--)
        pMission->aVideoNames[i].Free();
    pMission->briefing.Free();
    pMission->displayName.Free();
    pMission->name.Free();
}

// C-side creation/destruction shims (see dwMission.h — dw_Startup's
// alloc+ParseInfo pair / dw_Shutdown's FreeInfo+free pair).
extern "C" dwMission* dwMission_New(dwConfFile* pConf)
{
    return dwMission_ParseInfo(new dwMission, pConf);
}

extern "C" void dwMission_Delete(dwMission* pMission)
{
    if (pMission)
    {
        dwMission_FreeInfo(pMission);
        delete pMission; // dwString dtors re-Free (idempotent)
    }
}

// ------------------------------------------------------------------
// dwMissionSequence (vtbl 0x51f7d8)
// ------------------------------------------------------------------

// Ctor (inlined in dwGuiScreen_OnMessage @43146x: alloc 0x1c + dwSegment_Ctor
// + pBgImage/phase stores + vtbl 0x51f7d8).
dwMissionSequence::dwMissionSequence(dwImage* pBgImage_)
    : dwSegment()
    , pBgImage(pBgImage_)
    , phase(0)
{
}

// @41ea50 (dwMissionSequence_Reset) — called by dwGuiStatus_OnMessage to
// replay the sequence from the workshop.
void dwMissionSequence::Reset()
{
    this->phase = 0;
}

// vtbl +0x00 @41ea60 (dwMissionSequence_Advance) — the 3-phase state
// machine. Always returns 1.
int dwMissionSequence::Activate()
{
    dwSegment* pSeg = NULL;

    dwColormap_Load((char*)"Workshop2.cmp");
    if (this->phase == 0)
    {
        pSeg = dwMissionTransIn_New(this->pBgImage);
    }
    else if (this->phase == 1)
    {
        pSeg = dwGuiMissionMap_New(this->pBgImage);
    }
    // phase >= 2 (or an alloc failure above, in the binary) -> slide back out
    if (!pSeg)
    {
        pSeg = dwMissionTransOut_New(this->pBgImage);
    }

    if (this->phase == 2)
    {
        // Final leg: queue the slide-out and retire this sequencer.
        dwSegment_PushAndAdvance(pSeg);
    }
    else
    {
        this->phase = (this->phase != 0) + 1; // 0 -> 1, 1 -> 2
        // Run pSeg now, coming back to the active segment (this sequencer)
        // afterwards. Note: the binary InterruptWith takes only pInterrupt
        // and reads the active-segment global itself; the translation's
        // 2-arg form is passed that same global.
        dwSegment_InterruptWith(dwSegment_pActive, pSeg);
    }
    return 1;
}
