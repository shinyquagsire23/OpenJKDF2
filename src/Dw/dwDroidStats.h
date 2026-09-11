#ifndef _DWDROIDSTATS_H
#define _DWDROIDSTATS_H

// dwDroidStats — the assembled-droid STATS + BAKED MODEL record (data class,
// NOT a widget) + the random-droid generator.
//
// Decompiled from DroidWorks.exe @0x40eb60-0x40fdff. The dwGuiStatsDroid
// display widget sharing the compile unit (@0x40fe00-0x410a2f) is NOT here —
// it is a P6 GUI class.
//
// The record (binary sizeof 0x4ac, allocated with operator new by
// dwGuiInGame_BuildDroidStats @4220d8, freed with Free() + delete in
// dwGuiInGame_Dtor) bakes the workshop droid (the dwPartNode tree on
// dwCore_pWorkspaceNodes) into:
//  (1) aggregate game stats (dwDroidStatsTotals — also used STANDALONE on the
//      stack by dwGuiStatsDroid_Refresh),
//  (2) ONE merged rdModel3 (every part's meshes/nodes/materials concatenated,
//      hierarchy re-wired across part boundaries; name 'Steve_Austin'),
//  (3) per-anim-slot MERGED rdKeyframes (each part's track re-based onto the
//      merged skeleton) + a DW puppet-class mode table over them,
//  (4) bounding boxes (droid height -> model.insertOffset.z, eye offset,
//      whole-workspace size).
//
// ⚠ Merged-model aliasing: MergeGeometry raw-copies rdMesh/rdHierarchyNode
// records, so the merged meshes SHARE vertex/face/material storage with the
// per-node part models. The record must be Free()d while its part nodes are
// still alive, and the merged model must never go through rdModel3_Free —
// Free() releases exactly the three arrays Build() allocated.
//
// Random-droid generator (AutoBuildRandom + PickRandomPart +
// AutoAttachChildren): clears the workspace, seeds a random LOCOMOTION part,
// then recursively fills every attach slot with a random compatible part.
// Used by dwWcPalette_OnMessage (landed, dwWorkshopCtrl.cpp) and
// dwGuiDroidDance (P6).

#include "Dw/dwTypes.h"

#ifdef __cplusplus
struct dwListNode; // full definition in Dw/dwList.h (C++-only header)
extern "C" {
#else
typedef struct dwListNode dwListNode; // C++-side list node (Dw/dwList.h); opaque here
#endif

// ---- C-visible API ---------------------------------------------------------

// Reset module statics. No binary equivalent (added per the soft-reset rule);
// the unit owns no module-level state — see the note in dwDroidStats.cpp.
void dwDroidStats_Startup(void);

// @40fae0 — clear the workspace list (deleting every dwPartNode) and build a
// random droid into it. bodyType = the body-slot mask the picked blueprints'
// MODE must contain (1 NORMAL / 2 CARGO); ppWorkspaceList = &dwCore_pWorkspaceNodes.
// Broadcasts workshop refresh messages 0x7d6/0x7dc/0x7db when done.
void dwDroidStats_AutoBuildRandom(int bodyType, dwListNode** ppWorkspaceList);

// @40edd0 — append every workspace part's SOUNDS entries to pSoundClass (the
// player droid's sithSoundClass): sithSound_Load + a 0x1c sithSoundClassEntry
// per sound, chained per soundclass id. droidCapFlags is passed by the binary
// caller (record capFlags) but never read (dead parameter, kept for ABI).
// Called by dwGuiInGame_StartMission (P6).
void dwDroidStats_BuildSoundList(sithSoundClass* pSoundClass, uint32_t droidCapFlags);

#ifdef __cplusplus
} // extern "C"

#include "Dw/dwPart.h" // dwPart / dwPartNode (C++ view)
#include "Primitives/rdModel3.h" // full rdModel3 definition (embedded by value; has extern "C" guards)

// ---- dwDroidStatsTotals ----------------------------------------------------
//
// Binary 0x68-byte stats accumulator; the record embeds one at offset 0, and
// dwGuiStatsDroid_Refresh (P6) also runs one standalone on the stack.
// Binary offsets in comments; member ORDER is the contract (64-bit rule).

struct dwDroidStatsTotals
{
    int32_t numHNodes;        // 0x00: sum of part models' numHNodes
    int32_t numMeshes;        // 0x04: sum of geoset-0 numMeshes
    int32_t numFaces;         // 0x08: sum of per-mesh numFaces
    int32_t numVertices;      // 0x0c: sum of per-mesh numVertices
    int32_t numMaterials;     // 0x10: sum of sizeMaterials
    float mass;               // 0x14: sum of blueprint MASS
    float massMagnetic;       // 0x18: mass of parts with capFlags bit 0x10
                              //       (>25% of total keeps capFlags bit 0x10 set)
    float power;              // 0x1c: sum of blueprint power (mass*THRUST/1000)
    float staticFriction;     // 0x20: sum of STATIC
    float drag;               // 0x24: sum of DRAG
    int16_t batteryCapacity;  // 0x28: sum of BATTERY over non-BATTERY-type parts
    int16_t batteryCharge;    // 0x2a: sum of node charge (dwPartNode::slotIdx16)
    float drain;              // 0x2c: sum of DRAIN rates (power-usage class)
    uint32_t capFlags;        // 0x30: OR of all blueprint capFlags (-> dwCog_droidCaps)
    uint32_t toolCapsLeft;    // 0x34: capFlags & 0x5023f800 of UNMIRRORED (left) parts
    uint8_t maxLoadLeft;      // 0x38: max LOAD of unmirrored parts w/ capFlags bit 0x40000000
    uint32_t toolCapsRight;   // 0x3c: capFlags & 0x5023f800 of MIRRORED (right) parts
    uint8_t maxLoadRight;     // 0x40: max LOAD of mirrored parts w/ capFlags bit 0x40000000
    float durabilityMass;     // 0x44: sum of DURABILITY * MASS
    float durability;         // 0x48: durabilityMass / mass (weighted average)
    uint8_t aAnimPresent[24]; // 0x4c: per anim slot: some part has that ANIMATIONS
                              //       entry ([20] mirrors [9], [21] mirrors [10])
    char voiceChars[2];       // 0x64: last part VOICE pair seen (⚠ NOT cleared by
                              //       ClearTotals — faithful; starts as heap/stack garbage)

    // @40eb60 — zero every field EXCEPT voiceChars (faithful quirk).
    void ClearTotals();

    // @40ebb0 — accumulate one part node (blueprint stats + model counts);
    // recurses into attached children when bRecurse is set.
    void AccumulatePart(dwPartNode* pNode, int bRecurse);
};

// ---- dwPuppetClass ---------------------------------------------------------
//
// The DW engine's SithPuppetClass (24-anim-slot variant — layout DIFFERS from
// the repo's JK SithPuppetClass). dwGuiInGame_StartMission (P6) points
// pThing->pPuppetClass straight at the record's embedded instance; adapting
// that to the repo puppet is P6's problem. Binary 0x348, record @+0x104
// (Build zeroes the whole struct).

struct dwPuppetClass
{
    char name[32];                          // 0x00: zeroed by Build (the merged class is anonymous)
    SithPuppetClassSubmode aModes[2][24];   // 0x20: per-anim-slot {keyframe, flags|0x48, lowPri,
                                            //       highPri}; Build fills mode 0 only, mode 1
                                            //       stays zeroed (DW's 2-mode 24-anim variant of
                                            //       JK's 6-mode 42-anim class)
    int32_t aJoints[10];                    // 0x320: [0] head node idx, [1] neck (= head) node idx
                                            //        (HEAD part), [2] torso node idx (TORSO part);
                                            //        rest zeroed (MergeGeometry)
}; // binary sizeof 0x348

// ---- dwDroidStats ----------------------------------------------------------

struct dwDroidStats
{
    dwDroidStatsTotals totals;         // 0x000
    rdModel3 model;                    // 0x068: the MERGED model ('Steve_Austin');
                                       //        geoset 0 only; insertOffset.z = droid
                                       //        height (root pos.z - bbox min.z)
    rdVector3 eyeOffset;               // 0x0ec: (0, 0, torso bbox height) -> the player
                                       //        thing's actorParams.eyeOffset (P6)
    rdVector3 size;                    // 0x0f8: whole-workspace bbox size (x/y/z)
    dwPuppetClass puppetClass;         // 0x104
    rdKeyframe* apMergedKeyframes[24]; // 0x44c: merged per-anim-slot keyframes
                                       //        (slots 18/19 rwalk/rdance stay NULL —
                                       //        mirrored parts merge INTO 2/17)
    // binary sizeof 0x4ac. No ctor/dtor in the binary: dwGuiInGame does
    // `new dwDroidStats` + Build(), later Free() + delete (nothing here owns
    // heap state before Build runs).

    // @40ef00 — bake the workspace droid rooted at pRoot (the node whose
    // partType == DW_PARTTYPE_NONE). Returns this.
    dwDroidStats* Build(dwPartNode* pRoot);

    // @40f420 — release the merged mesh/node/material arrays + the 24 merged
    // keyframes (the ONLY teardown; see the aliasing warning at file top).
    void Free();

    // @40f4c0 — recursively concatenate pNode's model into the merged model
    // (meshes/nodes/materials + hierarchy re-wiring) and merge its per-slot
    // keyframes onto the merged skeleton. *ppTorsoNode receives the TORSO
    // part's node. parentNodeIdx = merged-node index the part mounts on
    // (-1 for the root); materialBase = merged-material write base.
    void MergeGeometry(dwPartNode* pNode, dwPartNode** ppTorsoNode,
                       int parentNodeIdx, int materialBase);
};

#endif // __cplusplus

#endif // _DWDROIDSTATS_H
