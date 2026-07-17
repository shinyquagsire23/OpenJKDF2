#ifndef _DWMISSION_H
#define _DWMISSION_H

// dwMission — mission-record parsing (.MIS master list) + the workshop<->
// mission panel-slide sequencer.
// DroidWorks.exe: dwMission_ParseInfo@41c530 / ParseObjective@41c960 /
// ClearObjectives@41c920 (in the 0x41c0f0 dwGuiMission unit) +
// dwMission_FreeInfo@41a530 (dw part2 range) + dwMissionSequence
// Reset@41ea50 / Advance@41ea60 (vtbl 0x51f7d8).
//
// dw_Startup enumerates *.MIS, scans each for a "BEGIN <name>" line and
// dwMission_ParseInfo's one record per BEGIN into the global mission list
// (dwCore_pMissionList). dwPlayer_Load/SavePlr persist the per-profile
// unlocked/rank/done state; the P6 screens (dwGuiMissionMap/dwGuiStatus/
// dwGuiInGame) consume the rest.
//
// Implemented in dwMission.cpp (compiled as C++: MSVC EH frames + dwString
// members; dwMissionSequence is a real dwSegment subclass). The record API
// keeps C linkage for the C boot flow (dwMain.c, P7).

#include "Dw/dwTypes.h"
#include "Dw/dwString.h"   // dual-language: class for C++, opaque typedef for C
#include "Dw/dwRect.h"     // dwPoint
#include "Dw/dwConfFile.h" // dwConfFile (C API, dual-language)

#ifdef __cplusplus

#include "Dw/dwList.h"
#include "Dw/dwSegment.h"
#include "Dw/dwImage.h"

// One GOAL/REQUIREMENT line of a mission record.
// Binary: 0x18-byte malloc'd record, ctor'd by dwMission_ParseObjective.
struct dwMissionObjective
{
    dwString label;      // 0x00: objective text (rest of the conf line)
    uint8_t code;        // 0x0c: first ULong on the line (objective id/COG code)
    uint32_t param;      // 0x10: second ULong (count/parameter)
    uint8_t bRequirement;// 0x14: 1 = REQUIREMENT line (0 = GOAL)
    uint8_t bFlag;       // 0x15: runtime complete/shown flag (dwMission_ClearObjectives zeroes)
}; // sizeof 0x18 in the binary

// One mission record. Binary: 0x8c-byte malloc'd record (dw_Startup
// `alloc(0x8c)` @419f7d), ctor'd by dwMission_ParseInfo.
// NOTE (translation): records must be created via dwMission_New (or C++
// `new dwMission` + dwMission_ParseInfo) — the binary ctor'd raw memory, the
// translation relies on the default-constructed dwString members instead.
struct dwMission
{
    uint8_t bUnlocked;       // 0x00: available on the map (init: missionType == DW_MISSION_NORMAL; .plr-persisted)
    uint8_t bDone;           // 0x01: .plr-persisted "<done>" flag — set by
                             //       dwGuiMissionMap msg 0xBBA when the BRIEFING
                             //       is shown; gates deploy (BeginDeploy refuses +
                             //       blinks the BRIEFING button while 0)
    int32_t missionType;     // 0x04: dwMissionType keyword (0 when none given)
    uint8_t rank;            // 0x08: earned rank, 0 = none / 1 = Scavenger /
                             //       2 = Apprentice / 3 = Master (.plr-persisted;
                             //       dwGuiObjectiveBtn's icon table order).
                             //       DUAL USE as an index: min(rank, 2) selects
                             //       the aRewards/REWARD slot (0xBBC handlers:
                             //       dwGuiPartText/dwGuiDroidPreview/PARTTEXT) and
                             //       rank < 3 selects the aVideoNames/VIDEO
                             //       briefing (else Master.brf)
    dwString name;           // 0x0c: id token ("BEGIN <name>"; matched by dwPlayer_LoadPlr)
    dwString displayName;    // 0x18: NAME <rest of line>
    dwString briefing;       // 0x24: BRIEFING <rest of line> (.brf key)
    dwString aVideoNames[3]; // 0x30: VIDEO <n> <name> (n = 0..2)
    dwString voiceover;      // 0x54: VOICEOVER <name>
    dwPoint mapPos;          // 0x60: MAP <x> <y> (mission-select map marker)
    dwListNode* pObjectives; // 0x64: sentinel of the GOAL/REQUIREMENT list (dwMissionObjective*)
    dwString aRewards[3];    // 0x68: REWARD <n> <name> (n = 0..2)
}; // sizeof 0x8c in the binary

// The workshop<->mission panel-slide SEQUENCER: a dwSegment whose Activate
// (Ghidra: dwMissionSequence_Advance) runs a 3-phase state machine — phase 0
// interrupts the flow with the TransToM.flc slide-in anim (returning here),
// phase 1 with the dwGuiMissionMap screen, phase 2 pushes the TransFromM.flc
// slide-out and retires itself. Constructed inline by dwGuiScreen_OnMessage
// msg 0x65+1 (@43146x: alloc 0x1c, vtbl 0x51f7d8, pBgImage = the screen's
// dimmed background snapshot); dwGuiStatus_OnMessage calls Reset to replay.
struct dwMissionSequence : dwSegment
{
    dwImage* pBgImage; // 0x14: background image handed to the trans anims + map screen
    int phase;         // 0x18: 0 = TransIn next, 1 = MissionMap next, 2 = TransOut next

    // (ctor inlined at the dwGuiScreen_OnMessage construction site)
    dwMissionSequence(dwImage* pBgImage);

    // vtbl +0x00 @41ea60 (dwMissionSequence_Advance)
    virtual int Activate();

    // @41ea50 (dwMissionSequence_Reset) — restart the sequence at phase 0
    void Reset();
};

extern "C" {
#else
typedef struct dwMission dwMission;                   // C++ struct (dwString members); opaque in the C view
typedef struct dwMissionObjective dwMissionObjective; // same
typedef struct dwMissionSequence dwMissionSequence;   // C++ class; opaque in the C view
typedef struct dwListNode dwListNode;                 // C++-side list node (Dw/dwList.h is C++-only); opaque here
#endif

// missionType keyword values (dwMission_ParseInfo)
enum dwMissionType
{
    DW_MISSION_NORMAL     = 0, // no type keyword — starts unlocked
    DW_MISSION_SECRET     = 1,
    DW_MISSION_FINAL      = 2,
    DW_MISSION_CRYSTAL    = 3,
    DW_MISSION_TGROUND    = 4, // training ground
    DW_MISSION_DEPLOYMENT = 5,
};

// TODO(dw-decomp): provided by dw core (P7) — the global mission list
// sentinel (@0x53d95c/0x53d990 region; dwList of dwMission*), filled by
// dw_Startup from *.MIS. Declared here so consumers share one declaration.
extern dwListNode* dwCore_pMissionList;

// TODO(dw-decomp): provided by dw core (P7) — the currently selected mission
// (@0x53d954; written by dwGuiMissionMap_SelectObjective, read by the
// map/briefing controls, dwGuiInGame and dwGuiStatus). Declared here so
// consumers share one declaration; defined as a dwMain.c placeholder until
// the P7 boot flow owns it.
extern dwMission* dwCore_pCurrentMission;

// dwCog dwenablemission/dwdisablemission verb helper (C-callable; typed access).
void dwMission_SetUnlockedByName(const char* pName, int bUnlocked);

// Parse ONE mission record out of pConf (positioned ON the "BEGIN <name>"
// line: the name is the next token) until its END line. Returns pMission.
// @41c530 (this = pMission in the binary)
dwMission* dwMission_ParseInfo(dwMission* pMission, dwConfFile* pConf);

// Parse one GOAL/REQUIREMENT payload: <code> <param> <label...>. Does not
// set bRequirement=1 (the REQUIREMENT branch of ParseInfo does). Returns
// pObj. @41c960
dwMissionObjective* dwMission_ParseObjective(dwMissionObjective* pObj, dwConfFile* pConf);

// Zero every objective's runtime bFlag. @41c920
void dwMission_ClearObjectives(dwMission* pMission);

// Free the record's strings + objective list (the record itself is NOT
// freed, matching the binary — dw_Shutdown frees it after). @41a530
void dwMission_FreeInfo(dwMission* pMission);

// C-side creation/destruction shims (no single binary counterpart — they
// bundle dw_Startup's `alloc(0x8c) + ParseInfo` pair and dw_Shutdown's
// `FreeInfo + free` pair so the C boot flow can drive the C++ record type).
dwMission* dwMission_New(dwConfFile* pConf);
void dwMission_Delete(dwMission* pMission);

#ifdef __cplusplus
}
#endif

#endif // _DWMISSION_H
