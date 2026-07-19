// dwDroidStats — assembled-droid stat baking + merged model/keyframes + the
// random-droid generator.
//
// Decompiled from DroidWorks.exe @0x40eb60-0x40fdff (the dwGuiStatsDroid
// widget at 0x40fe00+ in the same compile unit is P6). See dwDroidStats.h for
// the record layout/aliasing notes.
//
// Engine mapping (verified against the repo twins):
//   rdKeyframe_FUN_0047d8f0 -> rdKeyframe_LoadEntry (load .key into a
//                              caller-provided rdKeyframe)
//   rdKeyframe_FreeEntry    -> rdKeyframe_FreeEntry
//   rdKeyframe_FUN_0047de40 -> rdKeyframe_Free
//   rdModel3_FUN_00480ed0   -> local dwDroidStats_CalcMergedRadii (see the
//                              Note there — the repo's rdModel3_CalcRadii twin
//                              writes mesh->field_64 where the DW binary
//                              writes mesh->radius)
//   stdBitmapRle_FUN_00444d00 -> dwWidget_DispatchMsg (mislabeled shared COMDAT)
//   dwHS @0x6b6258          -> dwMain_pHS
//
// Allocators: the binary allocates everything through dwHS. Kept as
// dwMain_pHS->alloc (dwKeyframe.cpp precedent); the merged keyframes are later
// released through rdKeyframe_Free/FreeEntry (rdroid HS) and the soundclass
// entries through the sith world teardown (pSithHS) — all of these resolve to
// the same underlying allocator, and stdPlatform_TrackedFree tolerates
// cross-HS pointers (no header prefix).

#include "Dw/dwDroidStats.h"

#include "Dw/dwList.h"
#include "Dw/dwWidget.h"   // dwWidgetMsg + dwWidget_DispatchMsg
#include "Dw/dwKeyframe.h" // dwKeyframe_Clone/Resample/AddMidMarker/BuildJointDeltas

#include "jk.h"
#include "stdPlatform.h"

#include "Primitives/rdModel3.h" // has extern "C" guards
#include "Primitives/rdMatrix.h" // has extern "C" guards (rdroid_identMatrix34)
#include "Primitives/rdVector.h" // has extern "C" guards
// These engine headers have no extern "C" guards of their own — wrap at the
// include site.
extern "C" {
#include "Engine/rdKeyframe.h"
#include "Engine/rdroid.h" // rdModel3_fRadius via globals.h
#include "Devices/sithSound.h"
#include "World/sithSoundClass.h"
}

extern "C" HostServices* dwMain_pHS; // the DW host-services pointer (dwMain.c); binary global dwHS @0x6b6258

// Workspace part-node list + blueprint registry list (dwList sentinels).
// Defined by the dwMain.c placeholder block until the dw core (P7) lands.
extern "C" dwListNode* dwCore_pWorkspaceNodes; // @0x53d984
extern "C" dwListNode* dwCore_pBlueprintList;  // @0x53d964

// Anim-slot name table (binary rdata @0x52bc78; same 24 entries as
// dwPart_aAnimKeywords — [0] is the binary's "--RESERVED--" placeholder,
// never hit because no blueprint fills aAnimNames[0]).
static const char* dwDroidStats_aAnimNames[24] = {
    "--RESERVED--",
    "stand", "walk", "run", "walkback", "strafeleft", "straferight",
    "turnleft", "turnright", "lfunc", "rfunc", "leap", "rising", "drop",
    "fall", "fidget", "fidget2", "dance", "rwalk", "rdance", "ltug", "rtug",
    "attack", "death",
};

// Anim-slot indices used by name below.
enum
{
    DW_ANIM_WALK = 2,
    DW_ANIM_RUN = 3,
    DW_ANIM_WALKBACK = 4,
    DW_ANIM_STRAFELEFT = 5,
    DW_ANIM_STRAFERIGHT = 6,
    DW_ANIM_TURNLEFT = 7,
    DW_ANIM_TURNRIGHT = 8,
    DW_ANIM_LFUNC = 9,
    DW_ANIM_RFUNC = 10,
    DW_ANIM_DANCE = 17,
    DW_ANIM_RWALK = 18,
    DW_ANIM_RDANCE = 19,
    DW_ANIM_LTUG = 20,
    DW_ANIM_RTUG = 21,
};

// ---------------------------------------------------------------------------
// Module statics
// ---------------------------------------------------------------------------

// No binary equivalent (added per the soft-reset rule). This unit owns NO
// module-level mutable state — the tables above are const, and every global
// it touches (dwCore_* lists, dwPart_count*) is owned/reset elsewhere.
extern "C" void dwDroidStats_Startup(void)
{
}

// ---------------------------------------------------------------------------
// dwDroidStatsTotals
// ---------------------------------------------------------------------------

// @40eb60 — zero every field EXCEPT voiceChars (the binary's field-by-field
// clear stops at the anim-flag array; faithful).
void dwDroidStatsTotals::ClearTotals()
{
    this->numHNodes = 0;
    this->numMeshes = 0;
    this->numFaces = 0;
    this->numVertices = 0;
    this->numMaterials = 0;
    this->mass = 0.0f;
    this->massMagnetic = 0.0f;
    this->power = 0.0f;
    this->staticFriction = 0.0f;
    this->drag = 0.0f;
    this->batteryCapacity = 0;
    this->batteryCharge = 0;
    this->drain = 0.0f;
    this->capFlags = 0;
    this->toolCapsLeft = 0;
    this->maxLoadLeft = 0;
    this->toolCapsRight = 0;
    this->maxLoadRight = 0;
    this->durabilityMass = 0.0f;
    this->durability = 0.0f;
    _memset(this->aAnimPresent, 0, sizeof(this->aAnimPresent));
}

// @40ebb0 — accumulate one part node's blueprint stats + model counts.
void dwDroidStatsTotals::AccumulatePart(dwPartNode* pNode, int bRecurse)
{
    dwPart* pBp = pNode->pPart;
    rdModel3* pModel = pNode->pModel3;
    uint32_t i;

    this->numHNodes += pModel->numHNodes;
    this->numMeshes += pModel->aGeos[0].numMeshes;
    for (i = 0; i < pModel->aGeos[0].numMeshes; i++)
    {
        this->numFaces += pModel->aGeos[0].aMeshes[i].numFaces;
        this->numVertices += pModel->aGeos[0].aMeshes[i].numVertices;
    }
    this->numMaterials += pModel->sizeMaterials;

    this->capFlags |= pBp->capFlags;
    uint32_t maskedCaps = pBp->capFlags & 0x5023f800; // tool-capability bits
    if (!pNode->bMirrored)
        this->toolCapsLeft |= maskedCaps;
    else
        this->toolCapsRight |= maskedCaps;

    if (pBp->capFlags & 0x40000000) // lifting-capable part: track the best LOAD per side
    {
        if (!pNode->bMirrored)
        {
            if (this->maxLoadLeft < pBp->loadCapacity)
                this->maxLoadLeft = pBp->loadCapacity;
        }
        else if (this->maxLoadRight < pBp->loadCapacity)
        {
            this->maxLoadRight = pBp->loadCapacity;
        }
    }

    for (i = 0; i < 24; i++)
    {
        if (pBp->aAnimNames[i].length != 0)
            this->aAnimPresent[i] = 1;
    }
    // ltug/rtug are derived from lfunc/rfunc (see dwDroidStats::Build).
    this->aAnimPresent[DW_ANIM_RTUG] = this->aAnimPresent[DW_ANIM_RFUNC];
    this->aAnimPresent[DW_ANIM_LTUG] = this->aAnimPresent[DW_ANIM_LFUNC];

    if (bRecurse)
    {
        for (int32_t slot = 0; slot < pNode->slotCount; slot++)
        {
            if (pNode->aSlots[slot].pChild)
                this->AccumulatePart(pNode->aSlots[slot].pChild, bRecurse);
        }
    }

    if (pBp->type != DW_PARTTYPE_BATTERY)
        this->batteryCapacity = (int16_t)(this->batteryCapacity + pBp->battery);
    this->batteryCharge = (int16_t)(this->batteryCharge + pNode->slotIdx16);

    this->drain += pBp->drainRate;
    this->mass += pBp->mass;
    if (pBp->capFlags & 0x10)
        this->massMagnetic += pBp->mass;
    this->durabilityMass += (float)pBp->durability * pBp->mass;
    this->durability = this->durabilityMass / this->mass;
    // Cap bit 0x10 survives only when >25% of the droid's mass carries it.
    if (this->massMagnetic / this->mass <= 0.25f)
        this->capFlags &= ~0x10u;
    else
        this->capFlags |= 0x10;

    this->power += pBp->power;
    this->staticFriction += pBp->staticFriction;
    this->drag += pBp->drag;

    if (pBp->voiceChars[0] != 0)
    {
        this->voiceChars[0] = pBp->voiceChars[0];
        this->voiceChars[1] = pBp->voiceChars[1];
    }
}

// ---------------------------------------------------------------------------
// merged-keyframe helpers (unit-internal)
// ---------------------------------------------------------------------------

// @40f8e0 — initialize one merged anim keyframe: name, flags 3, 15 fps,
// numFrames 0, and a zeroed numNodes-joint track. Note: the binary leaves the
// header's other fields (id, marker arrays) UNINITIALIZED after the raw
// alloc — faithful (Build's callers never read them before they're written).
static void dwDroidStats_InitAnimEntry(rdKeyframe* pEntry, const char* pName, int32_t numNodes)
{
#ifdef SITH_DEBUG_STRUCT_NAMES
    _strncpy(pEntry->name, pName, 0x1f);
    pEntry->name[0x1f] = 0;
#else
    (void)pName;
#endif
    pEntry->type = 0;
    pEntry->fps = 15.0f;
    pEntry->numFrames = 0;
    pEntry->numMarkers = 0;
    pEntry->flags = 3;
    pEntry->numJoints = numNodes;
    pEntry->numJoints2 = numNodes;
    pEntry->aNodes = (rdJoint*)dwMain_pHS->alloc(numNodes * sizeof(rdJoint));
    _memset(pEntry->aNodes, 0, numNodes * sizeof(rdJoint));
}

// @40fa50 — rescale a keyframe's joint entries from its current numFrames to
// numFrames (single-entry joints snap to frame 0) and rebuild the deltas.
// The caller updates pKeyframe->numFrames afterwards.
static void dwDroidStats_GrowKeyframe(rdKeyframe* pKeyframe, uint32_t numFrames)
{
    for (uint32_t i = 0; i < pKeyframe->numJoints2; i++)
    {
        rdJoint* pJoint = &pKeyframe->aNodes[i];
        if (pJoint->numEntries == 1)
        {
            pJoint->aEntries[0].frameNum = 0.0f;
        }
        else if (pJoint->numEntries > 1)
        {
            for (uint32_t j = 0; j < pJoint->numEntries; j++)
            {
                pJoint->aEntries[j].frameNum =
                    (pJoint->aEntries[j].frameNum * (float)numFrames) / (float)pKeyframe->numFrames;
            }
            dwKeyframe_BuildJointDeltas(pJoint, numFrames);
        }
    }
}

// @40f950 — merge a part's loaded keyframe into a merged track: equalize
// frame counts, copy the joints in at jointBase (re-basing nodeNum and
// STEALING the entry arrays so rdKeyframe_FreeEntry on the source skips
// them), OR the flags/type, and append the markers (8-slot cap).
static void dwDroidStats_MergeKeyframe(rdKeyframe* pDst, rdKeyframe* pSrc, int32_t jointBase)
{
    uint32_t i;

    if (pDst->numFrames < pSrc->numFrames)
    {
        dwDroidStats_GrowKeyframe(pDst, pSrc->numFrames);
        pDst->numFrames = pSrc->numFrames;
    }
    else if (pSrc->numFrames != pDst->numFrames)
    {
        dwDroidStats_GrowKeyframe(pSrc, pDst->numFrames);
    }

    for (i = 0; i < pSrc->numJoints2; i++)
        pDst->aNodes[jointBase + i] = pSrc->aNodes[i]; // raw copy (binary: one dword copy across the track)
    for (i = 0; i < pSrc->numJoints2; i++)
    {
        rdJoint* pDstJoint = &pDst->aNodes[jointBase + i];
        if (pDstJoint->numEntries != 0)
        {
            pDstJoint->nodeNum += jointBase;
            // Steal the entries: the source (a stack-loaded keyframe) is
            // about to be rdKeyframe_FreeEntry'd.
            pSrc->aNodes[i].aEntries = NULL;
            pSrc->aNodes[i].numEntries = 0;
        }
    }

    pDst->type |= pSrc->type;
    pDst->flags |= pSrc->flags;

    if (pSrc->numMarkers != 0)
    {
        for (i = 0; i < pSrc->numMarkers; i++)
        {
            if (pDst->numMarkers > 7)
                return;
            pDst->markers.marker_float[pDst->numMarkers] = pSrc->markers.marker_float[i];
            pDst->markers.marker_int[pDst->numMarkers] = pSrc->markers.marker_int[i];
            pDst->numMarkers = pDst->numMarkers + 1;
        }
    }
}

// Local twin of the binary's rdModel3_FUN_00480ed0 (the engine's
// rdModel3_CalcRadii shape): per-mesh culling radius = 1.1 * max vertex
// length, then the recursive posed-model radius. Note: the repo's
// rdModel3_CalcRadii writes the per-mesh result to mesh->field_64; the DW
// binary (and the culling code) uses mesh->radius, so this stays local.
static void dwDroidStats_CalcMergedRadii(rdModel3* pModel)
{
    for (uint32_t i = 0; i < pModel->aGeos[0].numMeshes; i++)
    {
        rdMesh* pMesh = &pModel->aGeos[0].aMeshes[i];
        float maxDist = 0.0f;
        for (int32_t j = 0; j < pMesh->numVertices; j++)
        {
            float dist = rdVector_Len3(&pMesh->aVertices[j]);
            if (maxDist < dist)
                maxDist = dist;
        }
        pMesh->radius = maxDist * 0.1f + maxDist;
    }
    rdModel3_fRadius = 0.0;
    rdModel3_BuildExpandedRadius(pModel, pModel->aHierarchyNodes, &rdroid_identMatrix34);
    pModel->radius = rdModel3_fRadius * 0.1f + rdModel3_fRadius;
}

// ---------------------------------------------------------------------------
// dwDroidStats
// ---------------------------------------------------------------------------

// @40f4c0
void dwDroidStats::MergeGeometry(dwPartNode* pNode, dwPartNode** ppTorsoNode,
                                 int parentNodeIdx, int materialBase)
{
    uint32_t i;

    if (pNode->pPart->type == DW_PARTTYPE_TORSO)
        *ppTorsoNode = pNode;

    rdModel3* pSrc = pNode->pModel3;
    int meshBase = this->model.aGeos[0].numMeshes;
    int nodeBase = this->model.numHNodes;

    // Concatenate geoset-0 meshes (raw copies — vertex/face storage stays
    // SHARED with the part model; see the header warning).
    rdMesh* pDstMeshes = &this->model.aGeos[0].aMeshes[meshBase];
    for (i = 0; i < pSrc->aGeos[0].numMeshes; i++)
        pDstMeshes[i] = pSrc->aGeos[0].aMeshes[i];
    this->model.aGeos[0].numMeshes += pSrc->aGeos[0].numMeshes;

    // Concatenate hierarchy nodes.
    rdHierarchyNode* pDstNodes = &this->model.aHierarchyNodes[nodeBase];
    for (i = 0; i < pSrc->numHNodes; i++)
        pDstNodes[i] = pSrc->aHierarchyNodes[i];
    this->model.numHNodes += pSrc->numHNodes;

    // Re-base the copied nodes' intra-model links onto the merged arrays.
    for (i = 0; i < pSrc->numHNodes; i++)
    {
        rdHierarchyNode* pDstNode = &pDstNodes[i];
        rdHierarchyNode* pSrcNode = &pSrc->aHierarchyNodes[i];
        if (pSrcNode->parent)
            pDstNode->parent = &this->model.aHierarchyNodes[nodeBase + (pSrcNode->parent - pSrc->aHierarchyNodes)];
        if (pSrcNode->child)
            pDstNode->child = &this->model.aHierarchyNodes[nodeBase + (pSrcNode->child - pSrc->aHierarchyNodes)];
        if (pSrcNode->nextSibling)
            pDstNode->nextSibling = &this->model.aHierarchyNodes[nodeBase + (pSrcNode->nextSibling - pSrc->aHierarchyNodes)];
        if (pDstNode->meshIdx != 0xFFFFFFFF)
            pDstNode->meshIdx += meshBase;
        pDstNode->idx = nodeBase + i;
    }

    // Graft this part's root node under the parent's attach node.
    if (parentNodeIdx != -1)
    {
        rdHierarchyNode* pParentNode = &this->model.aHierarchyNodes[parentNodeIdx];
        pDstNodes[0].nextSibling = pParentNode->child;
        pParentNode->child = &pDstNodes[0];
        pParentNode->numChildren = pParentNode->numChildren + 1;
        pDstNodes[0].parent = pParentNode;
    }

    // The HEAD part's first node drives the puppet head+neck joints; the
    // TORSO part's first node the torso joint.
    if (pNode->pPart->type == DW_PARTTYPE_HEAD)
    {
        this->puppetClass.aJoints[1] = nodeBase; // neck
        this->puppetClass.aJoints[0] = nodeBase; // head
    }
    else if (pNode->pPart->type == DW_PARTTYPE_TORSO)
    {
        this->puppetClass.aJoints[2] = nodeBase; // torso
    }

    // Merge this part's per-slot keyframes onto the merged skeleton.
    for (uint32_t slot = 0; slot < 24; slot++)
    {
        if (slot == DW_ANIM_RWALK || slot == DW_ANIM_RDANCE)
            continue; // no merged track — mirrored parts merge INTO walk/dance
        rdKeyframe* pDstKf = this->apMergedKeyframes[slot];
        uint32_t srcSlot = slot;
        // A part with no 'run' anim contributes its 'walk' to the run track.
        if (slot == DW_ANIM_RUN && pNode->pPart->aAnimNames[DW_ANIM_RUN].length == 0)
            srcSlot = DW_ANIM_WALK;
        if (pNode->bMirrored)
        {
            if (srcSlot == DW_ANIM_WALK)
                srcSlot = DW_ANIM_RWALK;
            else if (srcSlot == DW_ANIM_DANCE)
                srcSlot = DW_ANIM_RDANCE;
        }
        // lfunc comes from unmirrored parts only, rfunc from mirrored only.
        if (srcSlot == DW_ANIM_LFUNC && pNode->bMirrored)
            continue;
        if (srcSlot == DW_ANIM_RFUNC && !pNode->bMirrored)
            continue;

        dwString* pAnimName = &pNode->pPart->aAnimNames[srcSlot];
        if (pDstKf && pAnimName->length != 0)
        {
            rdKeyframe localKf;
            if (rdKeyframe_LoadEntry(pAnimName->pBuffer, &localKf))
            {
                switch (pNode->pPart->type)
                {
                case DW_PARTTYPE_HEAD:
                    localKf.type = 8;
                    break;
                case DW_PARTTYPE_ARM:
                case DW_PARTTYPE_AFFECTOR:
                case DW_PARTTYPE_CARGOARM:
                    localKf.type = pNode->bMirrored ? 4 : 2;
                    break;
                case DW_PARTTYPE_LOCOMOTION:
                    localKf.type = 0x70;
                    break;
                case DW_PARTTYPE_TORSO:
                    localKf.type = 1;
                    break;
                default:
                    break;
                }
                dwDroidStats_MergeKeyframe(pDstKf, &localKf, nodeBase);
                rdKeyframe_FreeEntry(&localKf);
            }
        }
    }

    // Copy this part's materials. ⚠ Faithful quirk: every CHILD of one
    // parent gets the same materialBase (parent base + parent count), so
    // siblings overwrite each other's material slots — harmless in practice
    // because the mesh faces keep their own material indices per part model
    // copy, and DW part materials repeat across parts.
    for (i = 0; i < pSrc->sizeMaterials; i++)
        this->model.aMaterials[materialBase + i] = pSrc->aMaterials[i];

    for (int32_t slot = 0; slot < pNode->slotCount; slot++)
    {
        if (pNode->aSlots[slot].pChild)
        {
            this->MergeGeometry(pNode->aSlots[slot].pChild, ppTorsoNode,
                                (int)(pNode->aSlots[slot].pNode - pSrc->aHierarchyNodes) + nodeBase,
                                materialBase + pSrc->sizeMaterials);
        }
    }
}

// @40ef00
dwDroidStats* dwDroidStats::Build(dwPartNode* pRoot)
{
    uint32_t slot;
    rdVector3 vMin;
    rdVector3 vMax;

    this->totals.ClearTotals();
    _memset(&this->model, 0, sizeof(this->model));          // binary: 0x21-dword clear @+0x68
    _memset(&this->puppetClass, 0, sizeof(this->puppetClass)); // binary: 0xd2-dword clear @+0x104
    _memset(this->apMergedKeyframes, 0, sizeof(this->apMergedKeyframes));

    _strncpy(this->model.filename, "Steve_Austin", 0x1f);
    this->model.filename[0x1f] = 0;

    this->totals.AccumulatePart(pRoot, 1);

    // Merged-geometry buffers (released only by Free(); the binary does not
    // NULL-check the mesh/node allocations — kept).
    this->model.aGeos[0].aMeshes =
        (rdMesh*)dwMain_pHS->alloc(this->totals.numMeshes * sizeof(rdMesh));
    this->model.aHierarchyNodes =
        (rdHierarchyNode*)dwMain_pHS->alloc(this->totals.numHNodes * sizeof(rdHierarchyNode));
    rdMaterial** paMaterials =
        (rdMaterial**)dwMain_pHS->alloc(this->totals.numMaterials * sizeof(rdMaterial*));
    this->model.aMaterials = paMaterials;
    if (!paMaterials)
    {
        this->model.sizeMaterials = 0;
    }
    else
    {
        _memset(paMaterials, 0, this->totals.numMaterials * sizeof(rdMaterial*));
        this->model.sizeMaterials = this->totals.numMaterials;
    }

    // One merged keyframe per present anim slot (rwalk/rdance are instead
    // derived by time-mirroring walk/dance below).
    for (slot = 0; slot < 24; slot++)
    {
        if (slot == DW_ANIM_RWALK || slot == DW_ANIM_RDANCE)
            continue;
        if (!this->totals.aAnimPresent[slot])
            continue;
        rdKeyframe* pKf = (rdKeyframe*)dwMain_pHS->alloc(sizeof(rdKeyframe));
        this->apMergedKeyframes[slot] = pKf;
        if (pKf)
            dwDroidStats_InitAnimEntry(pKf, dwDroidStats_aAnimNames[slot], this->totals.numHNodes);
    }

    dwPartNode* pTorsoNode = NULL;
    this->MergeGeometry(pRoot, &pTorsoNode, -1, 0);
    this->model.numGeos = 1;
    dwDroidStats_CalcMergedRadii(&this->model);

    // Droid height: root position above the droid's bbox floor -> the merged
    // model's insertOffset.z.
    rdVector_Set3(&vMin, 3.4e38f, 3.4e38f, 3.4e38f);
    rdVector_Set3(&vMax, -3.4e38f, -3.4e38f, -3.4e38f);
    pRoot->DrawAt(&vMin, &vMax); // bbox accumulate (renders nothing)
    pRoot->GetPosition(&vMax);
    this->model.insertOffset.z = vMax.z - vMin.z;

    // Whole-workspace bbox size.
    rdVector_Set3(&vMin, 3.4e38f, 3.4e38f, 3.4e38f);
    rdVector_Set3(&vMax, -3.4e38f, -3.4e38f, -3.4e38f);
    for (dwListNode* pIter = dwCore_pWorkspaceNodes->pNext; pIter != dwCore_pWorkspaceNodes;
         pIter = pIter->pNext)
    {
        ((dwPartNode*)pIter->pData)->DrawAt(&vMin, &vMax);
    }
    this->size.x = vMax.x - vMin.x;
    this->size.y = vMax.y - vMin.y;
    this->size.z = vMax.z - vMin.z;

    // Eye offset = torso bbox height.
    if (pTorsoNode == NULL)
    {
        rdVector_Zero3(&this->eyeOffset);
    }
    else
    {
        rdVector_Set3(&vMin, 3.4e38f, 3.4e38f, 3.4e38f);
        rdVector_Set3(&vMax, -3.4e38f, -3.4e38f, -3.4e38f);
        pTorsoNode->DrawAt(&vMin, &vMax);
        this->eyeOffset.x = 0.0f;
        this->eyeOffset.y = 0.0f;
        this->eyeOffset.z = vMax.z - vMin.z;
    }

    rdKeyframe** apKf = this->apMergedKeyframes;

    // walkback := time-mirrored walk when absent.
    if (apKf[DW_ANIM_WALK] && !apKf[DW_ANIM_WALKBACK])
    {
        apKf[DW_ANIM_WALKBACK] = dwKeyframe_Clone(apKf[DW_ANIM_WALK]);
        if (apKf[DW_ANIM_WALKBACK])
            dwKeyframe_Resample(apKf[DW_ANIM_WALKBACK]);
    }
    // strafeleft/straferight: mirror whichever side is missing.
    if (apKf[DW_ANIM_STRAFELEFT] == NULL)
    {
        if (apKf[DW_ANIM_STRAFERIGHT])
        {
            apKf[DW_ANIM_STRAFELEFT] = dwKeyframe_Clone(apKf[DW_ANIM_STRAFERIGHT]);
            if (apKf[DW_ANIM_STRAFELEFT])
                dwKeyframe_Resample(apKf[DW_ANIM_STRAFELEFT]);
        }
    }
    else if (apKf[DW_ANIM_STRAFERIGHT] == NULL)
    {
        apKf[DW_ANIM_STRAFERIGHT] = dwKeyframe_Clone(apKf[DW_ANIM_STRAFELEFT]);
        if (apKf[DW_ANIM_STRAFERIGHT])
            dwKeyframe_Resample(apKf[DW_ANIM_STRAFERIGHT]);
    }
    // turnleft/turnright: same.
    if (apKf[DW_ANIM_TURNLEFT] == NULL)
    {
        if (apKf[DW_ANIM_TURNRIGHT])
        {
            apKf[DW_ANIM_TURNLEFT] = dwKeyframe_Clone(apKf[DW_ANIM_TURNRIGHT]);
            if (apKf[DW_ANIM_TURNLEFT])
                dwKeyframe_Resample(apKf[DW_ANIM_TURNLEFT]);
        }
    }
    else if (apKf[DW_ANIM_TURNRIGHT] == NULL)
    {
        apKf[DW_ANIM_TURNRIGHT] = dwKeyframe_Clone(apKf[DW_ANIM_TURNLEFT]);
        if (apKf[DW_ANIM_TURNRIGHT])
            dwKeyframe_Resample(apKf[DW_ANIM_TURNRIGHT]);
    }
    // ltug/rtug := lfunc/rfunc copies (no time-mirror).
    if (apKf[DW_ANIM_LFUNC] && !apKf[DW_ANIM_LTUG])
        apKf[DW_ANIM_LTUG] = dwKeyframe_Clone(apKf[DW_ANIM_LFUNC]);
    if (apKf[DW_ANIM_RFUNC] && !apKf[DW_ANIM_RTUG])
        apKf[DW_ANIM_RTUG] = dwKeyframe_Clone(apKf[DW_ANIM_RFUNC]);

    dwKeyframe_AddMidMarker(apKf[DW_ANIM_LFUNC], 0x10); // NULL-safe
    dwKeyframe_AddMidMarker(apKf[DW_ANIM_RFUNC], 0x10);

    if (apKf[DW_ANIM_DANCE])
        apKf[DW_ANIM_DANCE]->flags |= 1;
    if (apKf[DW_ANIM_LTUG])
        apKf[DW_ANIM_LTUG]->flags |= 1;
    if (apKf[DW_ANIM_RTUG])
        apKf[DW_ANIM_RTUG]->flags |= 1;

    // Puppet-class mode table over the merged keyframes (entries for missing
    // slots stay zeroed from the region clear above).
    for (slot = 0; slot < 24; slot++)
    {
        if (this->apMergedKeyframes[slot] == NULL)
            continue;
        SithPuppetClassSubmode* pMode = &this->puppetClass.aModes[0][slot];
        pMode->keyframe = this->apMergedKeyframes[slot];
        switch (slot)
        {
        case 1: // stand
        case 15: // fidget
        case 16: // fidget2
            pMode->flags = 0;
            pMode->lowPri = 0;
            pMode->highPri = 0;
            break;
        case 2: // walk
        case 3: // run
        case 4: // walkback
        case 5: // strafeleft
        case 6: // straferight
            pMode->flags = 1;
            pMode->lowPri = 2;
            pMode->highPri = 2;
            break;
        case 9: // lfunc
        case 10: // rfunc
            pMode->flags = 2;
            pMode->lowPri = 3;
            pMode->highPri = 3;
            break;
        case 11: // leap
        case 12: // rising
        case 13: // drop
        case 14: // fall
        case 17: // dance
        case 20: // ltug
        case 21: // rtug
            pMode->flags = 0;
            pMode->lowPri = 3;
            pMode->highPri = 3;
            break;
        default:
            pMode->flags = 0;
            pMode->lowPri = 2;
            pMode->highPri = 2;
            break;
        }
        pMode->flags |= 0x48;
    }

    return this;
}

// @40f420
void dwDroidStats::Free()
{
    if (this->model.aGeos[0].aMeshes)
    {
        dwMain_pHS->free(this->model.aGeos[0].aMeshes);
        this->model.aGeos[0].aMeshes = NULL;
        this->model.aGeos[0].numMeshes = 0;
    }
    if (this->model.aHierarchyNodes)
    {
        dwMain_pHS->free(this->model.aHierarchyNodes);
        this->model.aHierarchyNodes = NULL;
        this->model.numHNodes = 0;
    }
    if (this->model.aMaterials)
    {
        dwMain_pHS->free(this->model.aMaterials);
        this->model.sizeMaterials = 0;
        this->model.aMaterials = NULL;
    }
    for (int i = 0; i < 24; i++)
    {
        if (this->apMergedKeyframes[i])
        {
            rdKeyframe_Free(this->apMergedKeyframes[i]);
            this->apMergedKeyframes[i] = NULL;
        }
    }
}

// ---------------------------------------------------------------------------
// player-droid soundclass (dwGuiInGame_StartMission)
// ---------------------------------------------------------------------------

// @40edd0 — see the header comment. droidCapFlags is dead (kept for ABI).
extern "C" void dwDroidStats_BuildSoundList(sithSoundClass* pSoundClass, uint32_t droidCapFlags)
{
    (void)droidCapFlags;

    for (dwListNode* pIter = dwCore_pWorkspaceNodes->pNext; pIter != dwCore_pWorkspaceNodes;
         pIter = pIter->pNext)
    {
        dwPart* pBp = ((dwPartNode*)pIter->pData)->pPart;
        for (int i = 0; i < 94; i++)
        {
            if (pBp->aSoundNames[i].length == 0)
                continue;
            sithSound* pSound = sithSound_Load(pBp->aSoundNames[i].pBuffer, 1);
            if (!pSound)
                continue;
            sithSound_LoadFileData(pSound);

            sithSoundClassEntry* pEntry =
                (sithSoundClassEntry*)dwMain_pHS->alloc(sizeof(sithSoundClassEntry));
            if (!pEntry)
                continue;
            _memset(pEntry, 0, sizeof(*pEntry));
            pEntry->sound = pSound;
            pEntry->playflags = 0x880;
            if (i == 8 || i == 6) // lrunhard / lwalkhard: looping walk cycles
                pEntry->playflags = 0x881;
            pEntry->minRadius = 0.5f;
            pEntry->maxRadius = 2.5f;
            pEntry->maxVolume = 1.0f;

            if (pSoundClass->entries[i] == NULL)
            {
                pSoundClass->entries[i] = pEntry;
                pEntry->numEntries = 1;
            }
            else
            {
                sithSoundClassEntry* pTail = pSoundClass->entries[i];
                int count = 1;
                for (sithSoundClassEntry* pNext = pTail->pNextMode; pNext;
                     pNext = pNext->pNextMode)
                {
                    count = count + 1;
                    pTail = pNext;
                }
                pTail->pNextMode = pEntry;
                pSoundClass->entries[i]->numEntries = count + 1;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// random-droid generator
// ---------------------------------------------------------------------------

// @40fc10 — pick a random OWNED blueprint accepting slot type `type` and
// body-slot mask `bodyType`. ⚠ Faithful: loops forever (and takes rand()%0)
// when no counted/available blueprint matches — the shipping data always has
// at least one available part per slot type.
static dwPart* dwDroidStats_PickRandomPart(int type, uint32_t bodyType)
{
    uint32_t count = 0;

    switch (type)
    {
    case DW_PARTTYPE_HEAD:
        count = dwPart_countHeads;
        break;
    case DW_PARTTYPE_ARM_MIRROR:
    case DW_PARTTYPE_ARM:
        count = dwPart_countArms;
        break;
    case DW_PARTTYPE_AFFECTOR_MIRROR:
    case DW_PARTTYPE_AFFECTOR:
        count = dwPart_countAffectors;
        break;
    case DW_PARTTYPE_LOCOMOTION:
        if (bodyType == 1)
            count = dwPart_countLocoNormal;
        if (bodyType == 2)
            count = dwPart_countLocoCargo;
        break;
    case DW_PARTTYPE_TORSO:
        if (bodyType == 1)
            count = dwPart_countTorsoNormal;
        if (bodyType == 2)
            count = dwPart_countTorsoCargo;
        break;
    case DW_PARTTYPE_CARGOARM_MIRROR:
    case DW_PARTTYPE_CARGOARM:
        count = dwPart_countCargoArms;
        break;
    default:
        break;
    }

    dwPart* pResult = NULL;
    do
    {
        int remaining = (int)((uint32_t)_rand() % count) + 1;
        dwListNode* pIter = dwCore_pBlueprintList->pNext;
        dwPart* pBp;
        while (1)
        {
            pBp = (dwPart*)pIter->pData;
            // Mirror pairs count as the same slot type (1<->3, 7<->8, 2<->4).
            int bTypeMatch =
                (pBp->type == type)
                || (pBp->type == DW_PARTTYPE_ARM_MIRROR && type == DW_PARTTYPE_ARM)
                || (pBp->type == DW_PARTTYPE_ARM && type == DW_PARTTYPE_ARM_MIRROR)
                || (pBp->type == DW_PARTTYPE_CARGOARM_MIRROR && type == DW_PARTTYPE_CARGOARM)
                || (pBp->type == DW_PARTTYPE_CARGOARM && type == DW_PARTTYPE_CARGOARM_MIRROR)
                || (pBp->type == DW_PARTTYPE_AFFECTOR_MIRROR && type == DW_PARTTYPE_AFFECTOR)
                || (pBp->type == DW_PARTTYPE_AFFECTOR && type == DW_PARTTYPE_AFFECTOR_MIRROR);
            if (bTypeMatch && (pBp->slotMask & bodyType) != 0)
                remaining = remaining - 1;
            if (remaining == 0)
                break;
            pIter = pIter->pNext;
        }
        if (pBp->bAvailable)
            pResult = pBp;
    } while (pResult == NULL);
    return pResult;
}

// @40fd40 — fill each of pParent's attach slots with a random compatible
// part, appending every created node to the workspace list, then recurse.
static void dwDroidStats_AutoAttachChildren(dwPartNode* pParent, uint32_t bodyType,
                                            dwListNode** ppWorkspaceList)
{
    dwList* pList = (dwList*)ppWorkspaceList; // the handle IS the sentinel pointer

    dwPartSlot* pSlot = &pParent->aSlots[0];
    for (int32_t i = pParent->slotCount; i != 0; i--, pSlot++)
    {
        dwPart* pPicked = dwDroidStats_PickRandomPart(pSlot->type, bodyType);
        if (pPicked)
        {
            dwPartNode* pChild = pPicked->CreateNode();
            if (pChild)
            {
                // Charge the node with the blueprint's battery capacity.
                pChild->slotIdx16 = (int16_t)(pChild->slotIdx16 + pPicked->battery);
                pList->InsertAfter((*ppWorkspaceList)->pPrev, pChild); // push-back
                pChild->AttachToSlot(pParent, pSlot);
                dwDroidStats_AutoAttachChildren(pChild, bodyType, ppWorkspaceList);
            }
        }
    }
}

// @40fae0 — see the header comment. Exact signature shared with the
// dwWorkshopCtrl.cpp consumer (and formerly the dwMain.c placeholder).
extern "C" void dwDroidStats_AutoBuildRandom(int bodyType, dwListNode** ppWorkspaceList)
{
    dwList* pList = (dwList*)ppWorkspaceList;
    dwListNode* pSentinel = *ppWorkspaceList;
    dwListNode* pIter;
    dwWidgetMsg msg;

    // Delete every workspace part node...
    for (pIter = pSentinel->pNext; pIter != pSentinel; pIter = pIter->pNext)
    {
        dwPartNode* pNode = (dwPartNode*)pIter->pData;
        if (pNode)
            delete pNode; // binary: dwPartNode_Dtor + free
    }
    // ...then free all the list nodes.
    pIter = pSentinel->pNext;
    while (pIter != pSentinel)
    {
        dwListNode* pNext = pIter->pNext;
        pList->UnlinkFreeNode(pIter);
        pIter = pNext;
    }

    // Seed a random LOCOMOTION part and grow the droid from it.
    dwPart* pPicked = dwDroidStats_PickRandomPart(DW_PARTTYPE_LOCOMOTION, (uint32_t)bodyType);
    if (pPicked)
    {
        dwPartNode* pRoot = pPicked->CreateNode();
        if (pRoot)
        {
            pRoot->slotIdx16 = (int16_t)(pRoot->slotIdx16 + pPicked->battery);
            pList->InsertAfter(pSentinel->pPrev, pRoot); // push-back
            dwDroidStats_AutoAttachChildren(pRoot, (uint32_t)bodyType, ppWorkspaceList);
        }
    }

    // Broadcast the workshop refresh commands to the default widget.
    msg.code = 0x7d6;
    msg.pSender = NULL;
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);
    msg.code = 0x7dc;
    dwWidget_DispatchMsg(&msg, NULL);
    msg.code = 0x7db;
    dwWidget_DispatchMsg(&msg, NULL);
}
