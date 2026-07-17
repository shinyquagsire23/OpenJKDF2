// dwPart — droid-part BLUEPRINT class + dwPartNode — part scene-graph node.
//
// Decompiled from DroidWorks.exe (dwPartNode 0x4267a0-0x426d6f + spillover
// @426d70/427060; dwPart 0x4271b0-0x42873f). See dwPart.h for the full class
// notes, the field maps, and the engine-label -> repo-function table.
//
// Module statics: the two keyword hashtables + the per-type blueprint
// counters + dwPart_maxDrain (+ the dwPart_hashBlueprints registry pointer,
// whose lifecycle belongs to dw_Startup/dw_Shutdown, P7). All reset in
// dwPart_Startup.
//
// Engine mapping notes:
//  - jk_logtofile -> stdPlatform_Printf (per the dwAnim/dwConfFile precedent).
//  - The binary's keyword hashtables live in the DW-modified engine startups
//    (sithPuppet_Startup / sithSoundClass_Startup); the repo engine keeps
//    JK's own tables, so dwPart_Startup builds private copies from the DW
//    binary's keyword lists (@0x52bc7c anims / @0x52c4ac sounds).

#include "Dw/dwPart.h"

#include "Dw/dwControlPanel.h" // dw_aPartSlotColors
#include "Dw/dwImage.h"

#include "jk.h"
#include "stdPlatform.h"

#include "Primitives/rdModel3.h" // has extern "C" guards
#include "Primitives/rdMatrix.h" // has extern "C" guards
// These engine headers have no extern "C" guards of their own — wrap at the
// include site.
extern "C" {
#include "Engine/rdThing.h"
#include "Engine/rdPuppet.h"
#include "Engine/rdKeyframe.h"
#include "Engine/rdroid.h" // rdroid_frameTrue via globals.h
}

// TODO(dw-decomp): provided by dwMain (P7) — the material recolor cache
// (singleton @0x53d950, struct 0x187c). The binary calls these as __thiscall
// methods on that singleton (dwPartNode_CollectContacts loads ECX from
// 0x53d950); the P7 unit must export these C wrappers over it.
extern "C" void dwMain_MaterialCache_RecolorMasked(rdMaterial* pMaterial, int matchColor, int newColor);
extern "C" void dwMain_MaterialCache_Disable(void);
extern "C" void dwMain_MaterialCache_Enable(void);

// CPU ray-vs-model tests (rdRaycast unit, landed this wave; hit record =
// rdRaycastHit in types.h). Header has its own extern "C" guards.
#include "Primitives/rdRaycast.h"

// ---------------------------------------------------------------------------
// Module statics
// ---------------------------------------------------------------------------

extern "C" {
tHashTable* dwPart_hashBlueprints = NULL;   // @0x53e7b4 (created/filled by dw_Startup, P7)
tHashTable* dwPart_hashAnimKeywords = NULL; // @0x542714
tHashTable* dwPart_hashSoundKeywords = NULL;// @0x545df4

int dwPart_countHeads = 0;       // @0x53e844
int dwPart_countArms = 0;        // @0x53e830
int dwPart_countAffectors = 0;   // @0x53e838
int dwPart_countLocoNormal = 0;  // @0x53e83c
int dwPart_countLocoCargo = 0;   // @0x53e834
int dwPart_countTorsoNormal = 0; // @0x53e840
int dwPart_countTorsoCargo = 0;  // @0x53e84c
int dwPart_countCargoArms = 0;   // @0x53e848

float dwPart_maxDrain = 0.0f;    // @0x53e850
}

// ANIMATIONS keyword -> aAnimNames index (DW binary table @0x52bc7c,
// inserted with values 1..23 by the DW sithPuppet_Startup). [0] unused.
static const char* dwPart_aAnimKeywords[24] = {
    NULL,
    "stand", "walk", "run", "walkback", "strafeleft", "straferight",
    "turnleft", "turnright", "lfunc", "rfunc", "leap", "rising", "drop",
    "fall", "fidget", "fidget2", "dance", "rwalk", "rdance", "ltug", "rtug",
    "attack", "death",
};

// SOUNDS keyword -> aSoundNames index (DW binary table @0x52c4ac, values
// 1..93 from the DW sithSoundClass_Startup — exactly JK's soundclass keys).
static const char* dwPart_aSoundKeywords[94] = {
    NULL,
    "create", "activate", "startmove", "stopmove", "moving",
    "lwalkhard", "rwalkhard", "lrunhard", "rrunhard",
    "lwalkmetal", "rwalkmetal", "lrunmetal", "rrunmetal",
    "lwalkwater", "rwalkwater", "lrunwater", "rrunwater",
    "lwalkpuddle", "rwalkpuddle", "lrunpuddle", "rrunpuddle",
    "lwalkearth", "rwalkearth", "lrunearth", "rrunearth",
    "enterwater", "enterwaterslow", "exitwater", "exitwaterslow",
    "lswimsurface", "rswimsurface", "treadsurface",
    "lswimunder", "rswimunder", "treadunder",
    "jump", "jumpmetal", "jumpwater", "jumpearth",
    "landhard", "landmetal", "landwater", "landpuddle", "landearth", "landhurt",
    "hithard", "hitmetal", "hitearth", "deflected",
    "scrapehard", "scrapemetal", "scrapeearth", "hitdamaged",
    "falling", "corpsehit", "hurtimpact", "hurtenergy", "hurtfire",
    "hurtspecial", "drowning", "death1", "death2", "deathunder", "drowned",
    "splattered", "pant", "breath", "gasp",
    "fire1", "fire2", "fire3", "fire4",
    "curious", "alert", "idle", "gloat", "fear", "boast", "happy", "victory",
    "help", "flee", "search", "calm", "surprise",
    "reserved1", "reserved2", "reserved3", "reserved4", "reserved5",
    "reserved6", "reserved7", "reserved8",
};

// No binary equivalent (see file top) — soft-reset entry point.
extern "C" void dwPart_Startup(void)
{
    int i;

    if (dwPart_hashAnimKeywords)
        stdHashtbl_Free(dwPart_hashAnimKeywords);
    if (dwPart_hashSoundKeywords)
        stdHashtbl_Free(dwPart_hashSoundKeywords);

    dwPart_hashAnimKeywords = stdHashtbl_New(0x30); // binary size @0x454e10
    for (i = 1; i < 24; i++)
        stdHashtbl_Add(dwPart_hashAnimKeywords, dwPart_aAnimKeywords[i], (void*)(intptr_t)i);

    dwPart_hashSoundKeywords = stdHashtbl_New(0xbc); // binary size @0x460150
    for (i = 1; i < 94; i++)
        stdHashtbl_Add(dwPart_hashSoundKeywords, dwPart_aSoundKeywords[i], (void*)(intptr_t)i);

    // The registry itself is created + filled + freed by dw_Startup /
    // dw_Shutdown (P7) — only the pointer is reset here.
    dwPart_hashBlueprints = NULL;

    dwPart_countHeads = 0;
    dwPart_countArms = 0;
    dwPart_countAffectors = 0;
    dwPart_countLocoNormal = 0;
    dwPart_countLocoCargo = 0;
    dwPart_countTorsoNormal = 0;
    dwPart_countTorsoCargo = 0;
    dwPart_countCargoArms = 0;
    dwPart_maxDrain = 0.0f;
}

// @4271b0 (dwPart_FindBlueprint)
extern "C" dwPart* dwPart_FindBlueprint(const char* pName)
{
    if (pName == NULL || *pName == 0)
        return NULL;
    return (dwPart*)stdHashtbl_Find(dwPart_hashBlueprints, pName);
}

// Workspace node list sentinel (@0x53d984), owned by dw core / dwDroidStats.
extern "C" dwListNode* dwCore_pWorkspaceNodes;

// C-callable helper for the dwCog dwenablepart/dwdisablepart verbs: set a
// blueprint's bAvailable flag by name. Typed access (the binary's `+5` offset
// is 32-bit-specific). Returns 1 if the blueprint was found.
extern "C" int dwPart_SetAvailableByName(const char* pName, int bAvailable)
{
    dwPart* pPart = dwPart_FindBlueprint(pName);
    if (pPart == NULL)
        return 0;
    pPart->bAvailable = (uint8_t)(bAvailable ? 1 : 0);
    return 1;
}

// Blueprint list sentinel (@0x53d964).
extern "C" dwListNode* dwCore_pBlueprintList;

// FITTO cheat: set bAvailable on every blueprint.
extern "C" void dwPart_SetAllAvailable(int bAvailable)
{
    if (dwCore_pBlueprintList == NULL)
        return;
    for (dwListNode* pNode = dwCore_pBlueprintList->pNext; pNode != dwCore_pBlueprintList;
         pNode = pNode->pNext)
    {
        ((dwPart*)pNode->pData)->bAvailable = (uint8_t)(bAvailable ? 1 : 0);
    }
}

// C-callable helper for the dwCog dwcheckforpart verb: 1 if a part with the
// given blueprint name is present in the current workspace droid.
extern "C" int dwCog_WorkspaceHasPart(const char* pName)
{
    if (dwCore_pWorkspaceNodes == NULL)
        return 0;
    for (dwListNode* pNode = dwCore_pWorkspaceNodes->pNext; pNode != dwCore_pWorkspaceNodes;
         pNode = pNode->pNext)
    {
        dwPartNode* pPartNode = (dwPartNode*)pNode->pData;
        if (pPartNode && pPartNode->pPart &&
            dwString_Equals(pPartNode->pPart->name.pBuffer, pName))
        {
            return 1;
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// dwPartNode
// ---------------------------------------------------------------------------

// @4267a0 (dwPartNode_Ctor)
dwPartNode::dwPartNode(dwPart* pOwner, rdModel3* pModel)
{
    this->pPart = pOwner;
    this->pModel3 = pModel;
    this->bMirrored = 0;
    this->slotIdx16 = 0;
    this->animTrack = -1;
    rdMatrix_Identity34(&this->transform); // binary: 12-dword copy of the identity const @0x520fb8

    rdThing_NewEntry(&this->thing, NULL);
    rdThing_SetModel3(&this->thing, this->pModel3);
    // rdPuppet_New already stores itself in thing.puppet; the binary
    // re-assigns the return value to the same field (0x1c) — mirrored here.
    this->thing.puppet = rdPuppet_New(&this->thing);

    _memset(this->aContacts, 0, sizeof(this->aContacts));
    this->InitSlotsFromModel();
}

// @426830 (dwPartNode_Dtor)
dwPartNode::~dwPartNode()
{
    this->StopAnim();
    if (this->pModel3 != NULL)
        rdModel3_Free(this->pModel3); // binary: rdModel3_sub_480BE0
    rdThing_FreeEntry(&this->thing);  // frees joint arrays + the puppet
    this->pPart->Release();
}

// @426860 (dwPartNode_GetPosition)
void dwPartNode::GetPosition(rdVector3* pOut) const
{
    pOut->x = this->transform.scale.x;
    pOut->y = this->transform.scale.y;
    pOut->z = this->transform.scale.z;
}

// @4268d0 (dwPartNode_Translate)
void dwPartNode::Translate(const rdVector3* pDelta)
{
    this->transform.scale.x += pDelta->x;
    this->transform.scale.y += pDelta->y;
    this->transform.scale.z += pDelta->z;
}

// @426880 (dwPartNode_DrawAt) — bbox accumulation, no pixels (see header).
void dwPartNode::DrawAt(rdVector3* pMin, rdVector3* pMax)
{
    if (this->partType != DW_PARTTYPE_NONE && this->pAttachSlot != NULL)
        this->pAttachData->GetSlotMatrix(this->pAttachSlot, &this->transform);
    dwPart_DrawThing(&this->thing, &this->transform, pMin, pMax);
}

// @426900 (dwPartNode_Draw)
void dwPartNode::Draw()
{
    uint32_t i;

    if (this->partType != DW_PARTTYPE_NONE && this->pAttachSlot != NULL)
        this->pAttachData->GetSlotMatrix(this->pAttachSlot, &this->transform);
    rdThing_Draw(&this->thing, &this->transform);
    for (i = 0; this->slotCount != 0 && i < (uint32_t)this->slotCount; i++)
    {
        if (this->aSlots[i].pChild != NULL)
            this->aSlots[i].pChild->Draw();
    }
}

// @426970 (dwPartNode_DrawHighlighted)
void dwPartNode::DrawHighlighted()
{
    rdGeoMode_t prevGeoMode;
    uint32_t i;

    if (this->partType != DW_PARTTYPE_NONE && this->pAttachSlot != NULL)
        this->pAttachData->GetSlotMatrix(this->pAttachSlot, &this->transform);
    prevGeoMode = this->thing.curGeoMode;
    this->thing.curGeoMode = RD_GEOMETRY_FULL; // 4
    rdThing_Draw(&this->thing, &this->transform);
    this->thing.curGeoMode = prevGeoMode;
    for (i = 0; this->slotCount != 0 && i < (uint32_t)this->slotCount; i++)
    {
        if (this->aSlots[i].pChild != NULL)
            this->aSlots[i].pChild->DrawHighlighted();
    }
}

// @4269f0 (dwPartNode_UpdateTransform) — draws the blueprint's preview thing
// at this node's transform, driven by this node's puppet.
void dwPartNode::UpdateTransform()
{
    this->pPart->BuildPreviewModel(&this->transform, this->thing.puppet, this->bMirrored);
}

// @426a10 (dwPartNode_SetDrawFlag4Rec)
void dwPartNode::SetDrawFlag4Rec()
{
    uint32_t i;

    this->thing.curGeoMode = RD_GEOMETRY_FULL; // 4
    for (i = 0; this->slotCount != 0 && i < (uint32_t)this->slotCount; i++)
    {
        if (this->aSlots[i].pChild != NULL)
            this->aSlots[i].pChild->SetDrawFlag4Rec();
    }
}

// @426a50 (dwPartNode_SetDrawFlag2Rec)
void dwPartNode::SetDrawFlag2Rec()
{
    uint32_t i;

    this->thing.curGeoMode = RD_GEOMETRY_WIREFRAME; // 2
    for (i = 0; this->slotCount != 0 && i < (uint32_t)this->slotCount; i++)
    {
        if (this->aSlots[i].pChild != NULL)
            this->aSlots[i].pChild->SetDrawFlag2Rec();
    }
}

// @426a90 (dwPartNode_RaycastHit)
int dwPartNode::RaycastHit(rdVector3* pOrigin, rdVector3* pDir, void* pHitOut)
{
    rdVector3 pos;

    this->GetPosition(&pos);
    if (!rdRaycast_RaySphere(pOrigin, pDir, &pos, this->pModel3->radius))
        return 0;
    return rdRaycast_RayModel(pOrigin, pDir, &this->thing, (rdRaycastHit*)pHitOut) != 0;
}

// @426af0 (dwPartNode_CollectContacts) — "paint": recolor + record the pair.
void dwPartNode::CollectContacts(int matchColor, int newColor)
{
    uint32_t i;

    for (i = 0; i < this->pModel3->sizeMaterials; i++)
    {
        dwMain_MaterialCache_RecolorMasked(this->pModel3->aMaterials[i], matchColor, newColor);
    }
    for (i = 0; i < 9; i++)
    {
        if (this->aContacts[i][0] == (uint8_t)matchColor || this->aContacts[i][0] == 0)
        {
            this->aContacts[i][0] = (uint8_t)matchColor;
            this->aContacts[i][1] = (uint8_t)newColor;
            return;
        }
    }
    // All 9 entries taken by other colors: pair silently not recorded (faithful).
}

// @426b60 (dwPartNode_PlayIdleAnim) — "walk" (or "rwalk" when mirrored).
void dwPartNode::PlayIdleAnim()
{
    rdKeyframe* pKeyframe;

    if (this->bMirrored == 0)
        pKeyframe = this->pPart->GetAnimKeyframe0();
    else
        pKeyframe = this->pPart->GetAnimKeyframe1();
    if (pKeyframe != NULL)
        this->PlayAnimTrack(pKeyframe);
}

// @426b90 (dwPartNode_PlayActiveAnim) — "dance"/"rdance", else idle.
void dwPartNode::PlayActiveAnim()
{
    rdKeyframe* pKeyframe;

    if (this->bMirrored == 0)
        pKeyframe = this->pPart->GetAnimKeyframe2();
    else
        pKeyframe = this->pPart->GetAnimKeyframe3();
    if (pKeyframe != NULL)
        this->PlayAnimTrack(pKeyframe);
    else
        this->PlayIdleAnim();
}

// @426bc0 (dwPartNode_PlayAnimTrack)
void dwPartNode::PlayAnimTrack(rdKeyframe* pKeyframe)
{
    if (pKeyframe == NULL)
        return;
    if (this->animTrack != -1)
        this->StopAnim();
    // Faithful quirk: a full track list makes AddTrack return -1 and
    // PlayTrack is still called with it (as in the binary).
    this->animTrack = rdPuppet_AddTrack(this->thing.puppet, pKeyframe, 0, 0);
    rdPuppet_PlayTrack(this->thing.puppet, this->animTrack);
}

// @426c10 (dwPartNode_FadeAnim) — advances the anim + cycles material cels.
void dwPartNode::FadeAnim(float deltaSecs)
{
    if (this->animTrack != -1)
    {
        rdPuppet_UpdateTracks(this->thing.puppet, deltaSecs);
        dwPart_AdvanceModelFrame(this->pModel3);
    }
}

// @426c40 (dwPartNode_StopAnim)
void dwPartNode::StopAnim()
{
    if (this->animTrack != -1)
    {
        rdPuppet_RemoveTrack(this->thing.puppet, this->animTrack);
        this->animTrack = -1;
    }
}

// @426c70 (dwPartNode_AttachToSlot)
void dwPartNode::AttachToSlot(dwPartNode* pParent, dwPartSlot* pSlot)
{
    if (this->partType != pSlot->type)
        this->Mirror();
    pSlot->pChildTypePtr = &this->partType;
    pSlot->pChild = this;
    this->pAttachSlot = pSlot;
    this->pAttachData = pParent;
}

// @426cc0 (dwPartNode_DetachFromSlot)
void dwPartNode::DetachFromSlot()
{
    if (this->partType == DW_PARTTYPE_NONE || this->pAttachSlot == NULL)
        return;
    this->pAttachSlot->pChildTypePtr = NULL;
    this->pAttachSlot->pChild = NULL;
    this->pAttachSlot = NULL;
    this->pAttachData = NULL;
}

// @426d10 (dwPartNode_GetSlotPosition) — `this` = the PARENT owning pSlot.
void dwPartNode::GetSlotPosition(dwPartSlot* pSlot, rdVector3* pOut)
{
    rdMatrix34* pMat;

    pMat = &this->thing.paJointMatrices[pSlot->pNode->idx];
    pOut->x = pMat->scale.x;
    pOut->y = pMat->scale.y;
    pOut->z = pMat->scale.z;
}

// @426d40 (dwPartNode_GetSlotMatrix) — `this` = the PARENT owning pSlot.
void dwPartNode::GetSlotMatrix(dwPartSlot* pSlot, rdMatrix34* pOut)
{
    *pOut = this->thing.paJointMatrices[pSlot->pNode->idx];
}

// Shared "is an arm-side part type" test (binary: inlined 4-way compares).
static int dwPartNode_IsArmType(int type)
{
    return type == DW_PARTTYPE_ARM || type == DW_PARTTYPE_CARGOARM
        || type == DW_PARTTYPE_ARM_MIRROR || type == DW_PARTTYPE_CARGOARM_MIRROR;
}

// @426d70 (dwPartNode_InitSlotsFromModel) — classify the model's dummy nodes
// (meshIdx == -1): the parentless one is the MOUNT (except LOCOMOTION, whose
// root dummy is a child slot); childless ones are attach SLOTS whose
// node->type tags the accepted part type.
void dwPartNode::InitSlotsFromModel()
{
    rdHierarchyNode* pNode;
    int i;
    int slotType;
    int bSlot, bMount;

    this->slotCount = 0;
    _memset(this->aSlots, 0, sizeof(this->aSlots));
    this->pMountNode = NULL;
    this->pAttachSlot = NULL;
    this->pAttachData = NULL;
    this->partType = DW_PARTTYPE_NONE;

    pNode = this->pModel3->aHierarchyNodes;
    for (i = 0; i < (int)this->pModel3->numHNodes; i++, pNode++)
    {
        if (pNode->meshIdx != 0xFFFFFFFF)
            continue;
        bSlot = 0;
        bMount = 0;
        if (pNode->parent == NULL)
        {
            if (this->pPart->type == DW_PARTTYPE_LOCOMOTION)
                bSlot = 1;
            else
                bMount = 1;
        }
        else if (pNode->child == NULL)
        {
            bSlot = 1;
        }

        if (bMount)
        {
            this->pMountNode = pNode;
            this->partType = this->pPart->type;
            if (this->bMirrored != 0)
            {
                switch (this->pPart->type)
                {
                case DW_PARTTYPE_ARM_MIRROR:      this->partType = DW_PARTTYPE_ARM; break;
                case DW_PARTTYPE_AFFECTOR_MIRROR: this->partType = DW_PARTTYPE_AFFECTOR; break;
                case DW_PARTTYPE_ARM:             this->partType = DW_PARTTYPE_ARM_MIRROR; break;
                case DW_PARTTYPE_AFFECTOR:        this->partType = DW_PARTTYPE_AFFECTOR_MIRROR; break;
                case DW_PARTTYPE_CARGOARM_MIRROR: this->partType = DW_PARTTYPE_CARGOARM; break;
                case DW_PARTTYPE_CARGOARM:        this->partType = DW_PARTTYPE_CARGOARM_MIRROR; break;
                default: break;
                }
            }
        }
        else if (bSlot)
        {
            this->aSlots[this->slotCount].pNode = pNode;
            slotType = DW_PARTTYPE_NONE;
            if (pNode->type != 0x10) // 0x10 = explicitly untyped dummy: skip
            {
                if (pNode->type == 1)
                    slotType = DW_PARTTYPE_TORSO;
                else if (pNode->type == 8)
                    slotType = DW_PARTTYPE_HEAD;
                else if (pNode->type == 4)
                    slotType = dwPartNode_IsArmType(this->pPart->type) ? DW_PARTTYPE_AFFECTOR_MIRROR
                                                                       : DW_PARTTYPE_ARM_MIRROR;
                else if (pNode->type == 2)
                    slotType = dwPartNode_IsArmType(this->pPart->type) ? DW_PARTTYPE_AFFECTOR
                                                                       : DW_PARTTYPE_ARM;
                else if (pNode->type == 3)
                    slotType = (this->pPart->type == DW_PARTTYPE_CARGOARM) ? DW_PARTTYPE_AFFECTOR
                                                                           : DW_PARTTYPE_CARGOARM;
                else if (pNode->type == 5)
                    slotType = (this->pPart->type == DW_PARTTYPE_CARGOARM_MIRROR)
                                   ? DW_PARTTYPE_AFFECTOR_MIRROR
                                   : DW_PARTTYPE_CARGOARM_MIRROR;
                else
                    stdPlatform_Printf("%s has incorrectly labelled nodes!\n",
                                       this->pPart->name.pBuffer); // binary: jk_logtofile
            }
            this->aSlots[this->slotCount].type = slotType;
            if (slotType != DW_PARTTYPE_NONE)
                this->slotCount++;
        }
    }
}

// @427060 (dwPartNode_Mirror)
void dwPartNode::Mirror()
{
    dwPartNode* apSaved[4];
    rdModel3* pOldModel;
    int newType;
    uint32_t i;

    newType = this->partType;
    switch (this->partType)
    {
    case DW_PARTTYPE_ARM_MIRROR:      newType = DW_PARTTYPE_ARM; break;
    case DW_PARTTYPE_AFFECTOR_MIRROR: newType = DW_PARTTYPE_AFFECTOR; break;
    case DW_PARTTYPE_ARM:             newType = DW_PARTTYPE_ARM_MIRROR; break;
    case DW_PARTTYPE_AFFECTOR:        newType = DW_PARTTYPE_AFFECTOR_MIRROR; break;
    case DW_PARTTYPE_CARGOARM_MIRROR: newType = DW_PARTTYPE_CARGOARM; break;
    case DW_PARTTYPE_CARGOARM:        newType = DW_PARTTYPE_CARGOARM_MIRROR; break;
    default: break;
    }
    if (newType == this->partType)
        return; // not a mirrorable part type

    this->bMirrored = (this->bMirrored == 0);

    // Detach (and remember) the attached children.
    apSaved[0] = apSaved[1] = apSaved[2] = apSaved[3] = NULL;
    for (i = 0; this->slotCount != 0 && i < (uint32_t)this->slotCount; i++)
    {
        apSaved[i] = this->aSlots[i].pChild;
        if (apSaved[i] != NULL)
            apSaved[i]->DetachFromSlot();
    }

    // Swap in the (un)mirrored model and replay the recorded paint pairs.
    pOldModel = this->pModel3;
    this->pModel3 = this->pPart->BuildModel(this->bMirrored);
    rdModel3_Free(pOldModel);
    for (i = 0; i < 9; i++)
    {
        if (this->aContacts[i][0] != this->aContacts[i][1])
            this->CollectContacts(this->aContacts[i][0], this->aContacts[i][1]);
    }
    // Note: direct model swap as in the binary (no rdThing_SetModel3) — the
    // mirror model shares the node count, so the joint arrays stay valid.
    this->thing.model3 = this->pModel3;

    this->InitSlotsFromModel();
    for (i = 0; this->slotCount != 0 && i < (uint32_t)this->slotCount; i++)
    {
        if (apSaved[i] != NULL)
            apSaved[i]->AttachToSlot(this, &this->aSlots[i]);
    }
    this->StopAnim();
}

// ---------------------------------------------------------------------------
// dwPart
// ---------------------------------------------------------------------------

// @4271d0 (dwPart_ParseBlueprint) — the conf-record ctor/parser.
dwPart::dwPart(dwConfFile* pConf)
    : name(), displayName(), desc(), spinFlcName(),
      modelName(), modelNameMirror(), materials()
{
    char* pTok;
    uint32_t ulongVal;
    float floatVal;
    float thrustScaled; // THRUST * 0.001 (0 until THRUST parses — see `power`)
    int bDone;
    rdThing* pThing;

    this->refCount = 0;
    this->bRestricted = 0;
    this->bAvailable = 1;
    this->type = DW_PARTTYPE_NONE;
    this->slotMask = 3;
    this->pImage = NULL;
    this->pIcon = NULL;
    this->voiceChars[0] = 0;
    this->voiceChars[1] = 0;
    this->battery = 0;
    this->drainRate = 0.0f;
    this->loadCapacity = 0;
    this->durability = 1;
    this->mass = 100.0f;
    this->power = 0.0f;
    this->staticFriction = 0.0f;
    this->drag = 0.0f;
    this->capFlags = 0x10;
    this->pPreviewModel = NULL;
    this->pPreviewModelMirror = NULL;
    this->keyframe0 = NULL;
    this->keyframe1 = NULL;
    this->keyframe2 = NULL;
    this->keyframe3 = NULL;

    pThing = &this->thing;
    _memset(pThing, 0, sizeof(*pThing)); // binary: 18-dword clear before NewEntry
    rdThing_NewEntry(pThing, NULL);
    pThing->curGeoMode = RD_GEOMETRY_FULL;    // 4
    pThing->curLightMode = RD_LIGHTMODE_FULLYLIT; // 0

    // The record head: the blueprint id is the rest of the current line.
    this->name.AssignCStr(pConf->pCursor);
    this->displayName.AssignString(&this->name);

    thrustScaled = 0.0f;
    bDone = 0;
    while (!pConf->bEof && !bDone)
    {
        dwConfFile_ReadLine(pConf);
        pTok = dwConfFile_NextToken(pConf);
        if (dwString_Equals(pTok, "END_PART"))
        {
            bDone = 1;
        }
        else if (dwString_Equals(pTok, "ANIMATIONS"))
        {
            this->ParseAnims(pConf);
            if (this->aAnimNames[5].length != 0) // [5] = "strafeleft"
                this->capFlags |= 2;
        }
        else if (dwString_Equals(pTok, "BATTERY"))
        {
            dwConfFile_ParseULong(pConf, &ulongVal);
            this->battery = (uint16_t)ulongVal;
        }
        else if (dwString_Equals(pTok, "DRAG"))
        {
            dwConfFile_ParseFloat(pConf, &this->drag);
        }
        else if (dwString_Equals(pTok, "DRAIN"))
        {
            dwConfFile_ParseULong(pConf, &ulongVal);
            this->drainRate = (float)ulongVal * 0.016666668f; // per 60Hz tick
            if (dwPart_maxDrain < this->drainRate)
                dwPart_maxDrain = this->drainRate;
        }
        else if (dwString_Equals(pTok, "DURABILITY"))
        {
            dwConfFile_ParseULong(pConf, &ulongVal);
            this->durability = (uint8_t)ulongVal;
        }
        else if (dwString_Equals(pTok, "STATIC"))
        {
            dwConfFile_ParseFloat(pConf, &this->staticFriction);
        }
        else if (dwString_Equals(pTok, "ICON"))
        {
            pTok = dwConfFile_NextToken(pConf);
            this->pIcon = dwImage_LoadFile(pTok);
        }
        else if (dwString_Equals(pTok, "IMAGE"))
        {
            pTok = dwConfFile_NextToken(pConf);
            this->pImage = dwImage_LoadFile(pTok);
        }
        else if (dwString_Equals(pTok, "LOAD"))
        {
            dwConfFile_ParseULong(pConf, &ulongVal);
            this->loadCapacity = (uint8_t)ulongVal;
        }
        else if (dwString_Equals(pTok, "LORES"))
        {
            pTok = dwConfFile_NextToken(pConf);
            this->modelName.AssignCStr(pTok);
            pTok = dwConfFile_NextToken(pConf);
            if (pTok != NULL && *pTok != 0)
                this->modelNameMirror.AssignCStr(pTok);
        }
        else if (dwString_Equals(pTok, "NAME"))
        {
            this->displayName.Assign(pConf->pCursor, 0); // rest of the line
        }
        else if (dwString_Equals(pTok, "DESC"))
        {
            this->desc.Assign(pConf->pCursor, 0);
        }
        else if (dwString_Equals(pTok, "MATERIALS"))
        {
            pTok = dwConfFile_NextToken(pConf);
            while (pTok != NULL && *pTok != 0)
            {
                this->materials.InsertAfter(this->materials.pSentinel->pPrev,
                                            new dwString(pTok, 0)); // push-back
                pTok = dwConfFile_NextToken(pConf);
            }
        }
        else if (dwString_Equals(pTok, "MASS"))
        {
            dwConfFile_ParseFloat(pConf, &this->mass);
            this->power = this->mass * thrustScaled;
        }
        else if (dwString_Equals(pTok, "MODE"))
        {
            pTok = dwConfFile_NextToken(pConf);
            if (dwString_Equals(pTok, "CARGO"))
                this->slotMask = 2;
            else if (dwString_Equals(pTok, "NORMAL"))
                this->slotMask = 1;
        }
        else if (dwString_Equals(pTok, "SOUNDS"))
        {
            this->ParseSounds(pConf);
        }
        else if (dwString_Equals(pTok, "RESTRICTED"))
        {
            this->bRestricted = 1;
            this->bAvailable = 0;
        }
        else if (dwString_Equals(pTok, "SPIN"))
        {
            this->spinFlcName.Assign(pConf->pCursor, 0);
        }
        else if (dwString_Equals(pTok, "THRUST"))
        {
            dwConfFile_ParseFloat(pConf, &floatVal);
            thrustScaled = floatVal * 0.001f;
            this->power = this->mass * thrustScaled;
        }
        else if (dwString_Equals(pTok, "TYPE"))
        {
            pTok = dwConfFile_NextToken(pConf);
            if (dwString_Equals(pTok, "TORSO"))
            {
                this->type = DW_PARTTYPE_TORSO;
                if (this->slotMask & 1)
                    this->slotMask = 1;
            }
            else if (dwString_Equals(pTok, "HEAD"))
            {
                this->type = DW_PARTTYPE_HEAD;
                this->capFlags |= 0x80100000;
            }
            else if (dwString_Equals(pTok, "ARM"))
            {
                this->type = DW_PARTTYPE_ARM;
                this->capFlags |= 0x40001000;
                if (this->slotMask & 1)
                    this->slotMask = 1;
            }
            else if (dwString_Equals(pTok, "CARGOARM"))
            {
                this->type = DW_PARTTYPE_CARGOARM;
                this->capFlags |= 0x40001000;
                if (this->slotMask & 2)
                    this->slotMask = 2;
            }
            else if (dwString_Equals(pTok, "AFFECTOR"))
            {
                this->type = DW_PARTTYPE_AFFECTOR;
                this->capFlags |= 0x1000;
            }
            else if (dwString_Equals(pTok, "LOCOMOTION"))
            {
                this->type = DW_PARTTYPE_LOCOMOTION;
                this->staticFriction = 0.3f;
                this->drag = 3.0f;
                if ((this->slotMask & 1) == 0)
                {
                    this->capFlags |= 0x20000000;
                }
                else
                {
                    this->slotMask = 1;
                    this->capFlags |= 0x2000000b;
                }
            }
            else if (dwString_Equals(pTok, "BATTERY"))
            {
                this->type = DW_PARTTYPE_BATTERY;
            }
            else if (dwString_Equals(pTok, "SPECIAL"))
            {
                this->type = DW_PARTTYPE_SPECIAL;
            }
        }
        else if (dwString_Equals(pTok, "VOICE"))
        {
            pTok = dwConfFile_NextToken(pConf);
            if (pTok != NULL && pTok[0] != 0 && pTok[1] != 0)
            {
                this->voiceChars[0] = pTok[0];
                this->voiceChars[1] = pTok[1];
            }
        }
        else if (dwString_Equals(pTok, "GENERATOR"))    this->capFlags |= 4;
        else if (dwString_Equals(pTok, "WHEELED"))      this->capFlags &= 0xfffffff4;
        else if (dwString_Equals(pTok, "NONMAGNETIC"))  this->capFlags &= ~0x10u;
        else if (dwString_Equals(pTok, "INFRARED"))     this->capFlags |= 0x20;
        else if (dwString_Equals(pTok, "CONFORM"))      this->capFlags |= 0x40;
        else if (dwString_Equals(pTok, "WIDEANGLE"))    this->capFlags |= 0x80;
        else if (dwString_Equals(pTok, "NARROW"))       this->capFlags |= 0x400;
        else if (dwString_Equals(pTok, "CORROSION"))    this->capFlags |= 0x100;
        else if (dwString_Equals(pTok, "MEDICAL"))      this->capFlags |= 0x200;
        else if (dwString_Equals(pTok, "GRAB"))         this->capFlags |= 0x800;
        else if (dwString_Equals(pTok, "NOPUSH"))       this->capFlags &= ~0x1000u;
        else if (dwString_Equals(pTok, "PUSH"))         this->capFlags |= 0x1000;
        else if (dwString_Equals(pTok, "TUG"))          this->capFlags |= 0x2000;
        else if (dwString_Equals(pTok, "CUTTER"))       this->capFlags |= 0x4000;
        else if (dwString_Equals(pTok, "SYRINGE"))      this->capFlags |= 0x8000;
        else if (dwString_Equals(pTok, "POWER_PLUG"))   this->capFlags |= 0x10000;
        else if (dwString_Equals(pTok, "WELDER"))       this->capFlags |= 0x20000;
        else if (dwString_Equals(pTok, "LIGHT"))        this->capFlags |= 0x40000;
        else if (dwString_Equals(pTok, "TREAD"))        this->capFlags |= 0x80000;
        else if (dwString_Equals(pTok, "MOVE"))         this->capFlags |= 0x20000000;
        else if (dwString_Equals(pTok, "REACH"))        this->capFlags |= 0x40000000;
        else if (dwString_Equals(pTok, "SEE"))          this->capFlags |= 0x80000000;
        else if (dwString_Equals(pTok, "NOTALK"))       this->capFlags &= ~0x100000u;
        else if (dwString_Equals(pTok, "FINE_MANIP"))   this->capFlags |= 0x200000;
        else if (pTok != NULL && *pTok != 0)
        {
            stdPlatform_Printf("Part Blueprint: unrecognized keyword %s\n", pTok); // binary: jk_logtofile
        }
    }

    // Name-derived defaults.
    if (this->modelName.length == 0)
    {
        this->modelName.AssignString(&this->name);
        this->modelName.Append(".3do", 4);
    }
    if (this->type != DW_PARTTYPE_SPECIAL)
    {
        if (this->spinFlcName.length == 0)
        {
            this->spinFlcName.AssignString(&this->name);
            this->spinFlcName.Append(".flc", 4);
        }
        if (this->pIcon == NULL)
        {
            dwString tmp(this->name);
            tmp.Append("ICON.rle", 8);
            this->pIcon = dwImage_LoadFile(tmp.pBuffer);
            tmp.Free();
        }
        if (this->pImage == NULL)
        {
            dwString tmp(this->name);
            tmp.Append(".rle", 4);
            this->pImage = dwImage_LoadFile(tmp.pBuffer);
            tmp.Free();
        }
    }

    // Per-(type, slotMask) blueprint counters (random-droid generator input).
    switch (this->type)
    {
    case DW_PARTTYPE_HEAD:
        dwPart_countHeads++;
        break;
    case DW_PARTTYPE_ARM_MIRROR:
    case DW_PARTTYPE_ARM:
        dwPart_countArms++;
        break;
    case DW_PARTTYPE_AFFECTOR_MIRROR:
    case DW_PARTTYPE_AFFECTOR:
        dwPart_countAffectors++;
        break;
    case DW_PARTTYPE_LOCOMOTION:
        if (this->slotMask & 1)
            dwPart_countLocoNormal++;
        if (this->slotMask & 2)
            dwPart_countLocoCargo++;
        break;
    case DW_PARTTYPE_TORSO:
        if (this->slotMask & 1)
            dwPart_countTorsoNormal++;
        if (this->slotMask & 2)
            dwPart_countTorsoCargo++;
        break;
    case DW_PARTTYPE_CARGOARM_MIRROR:
    case DW_PARTTYPE_CARGOARM:
        dwPart_countCargoArms++;
        break;
    default:
        break;
    }
}

// @427ef0 (dwPart_Dtor)
dwPart::~dwPart()
{
    dwListNode* pNode;
    dwListNode* pNext;

    this->FreeModels();
    this->FreeKeyframes();
    if (this->pImage != NULL)
        delete this->pImage; // binary: vtbl slot 0 (scalar-deleting dtor, flag 1)
    if (this->pIcon != NULL)
        delete this->pIcon;
    // Material name payloads, then the list nodes + sentinel.
    for (pNode = this->materials.pSentinel->pNext; pNode != this->materials.pSentinel; pNode = pNext)
    {
        pNext = pNode->pNext;
        if (pNode->pData != NULL)
            delete (dwString*)pNode->pData;
    }
    this->materials.Free();
    // The dwString members/arrays free themselves (idempotent dtors).
}

// @4280b0 (dwPart_ParseAnims)
void dwPart::ParseAnims(dwConfFile* pConf)
{
    char* pTok;
    intptr_t idx;

    while (!pConf->bEof)
    {
        dwConfFile_ReadLine(pConf);
        pTok = dwConfFile_NextToken(pConf);
        if (dwString_Equals(pTok, "END_ANIMS"))
            return;
        idx = (intptr_t)stdHashtbl_Find(dwPart_hashAnimKeywords, pTok);
        if (idx != 0)
        {
            pTok = dwConfFile_NextToken(pConf);
            this->aAnimNames[idx].AssignCStr(pTok);
        }
    }
}

// @428120 (dwPart_ParseSounds)
void dwPart::ParseSounds(dwConfFile* pConf)
{
    char* pTok;
    intptr_t idx;

    while (!pConf->bEof)
    {
        dwConfFile_ReadLine(pConf);
        pTok = dwConfFile_NextToken(pConf);
        if (dwString_Equals(pTok, "END_SOUNDS"))
            return;
        idx = (intptr_t)stdHashtbl_Find(dwPart_hashSoundKeywords, pTok);
        if (idx != 0)
        {
            pTok = dwConfFile_NextToken(pConf);
            this->aSoundNames[idx].AssignCStr(pTok);
        }
    }
}

// @4281a0 (dwPart_CreateNode)
dwPartNode* dwPart::CreateNode()
{
    rdModel3* pModel;
    dwPartNode* pNode;

    pModel = this->BuildModel(0);
    if (pModel == NULL)
        return NULL;
    pNode = new dwPartNode(this, pModel);
    if (pNode != NULL)
        this->refCount++;
    return pNode;
}

// @428210 (dwPart_BuildModel)
rdModel3* dwPart::BuildModel(uint8_t bMirrored)
{
    rdModel3* pModel;
    rdMaterial* pMat;
    uint32_t color;
    uint32_t i, j;

    pModel = rdModel3_Load(bMirrored ? this->modelNameMirror.pBuffer
                                     : this->modelName.pBuffer); // binary: rdModel3_sub_47FEA0
    if (pModel != NULL)
    {
        // Repaint every texinfo's solid color with the part-type slot color.
        color = dw_aPartSlotColors[this->type];
        for (i = 0; i < pModel->sizeMaterials; i++)
        {
            pMat = pModel->aMaterials[i];
            for (j = 0; j < pMat->num_texinfo; j++)
                pMat->texinfos[j]->header.solidColor = color;
        }
    }
    return pModel;
}

// @428290 (dwPart_Release)
void dwPart::Release()
{
    this->refCount--;
    if (this->refCount == 0)
    {
        this->FreeModels();
        this->FreeKeyframes();
    }
}

// @4282b0 (dwPart_GetAnimKeyframe0) — lazy "walk" (aAnimNames[2]).
rdKeyframe* dwPart::GetAnimKeyframe0()
{
    if (this->keyframe0 == NULL && this->aAnimNames[2].length != 0)
        this->keyframe0 = rdKeyframe_Load(this->aAnimNames[2].pBuffer);
    return this->keyframe0;
}

// @4282f0 (dwPart_GetAnimKeyframe2) — lazy "dance" (aAnimNames[17]).
rdKeyframe* dwPart::GetAnimKeyframe2()
{
    if (this->keyframe2 == NULL && this->aAnimNames[17].length != 0)
        this->keyframe2 = rdKeyframe_Load(this->aAnimNames[17].pBuffer);
    return this->keyframe2;
}

// @428330 (dwPart_GetAnimKeyframe1) — lazy "rwalk" (aAnimNames[18]).
rdKeyframe* dwPart::GetAnimKeyframe1()
{
    if (this->keyframe1 == NULL && this->aAnimNames[18].length != 0)
        this->keyframe1 = rdKeyframe_Load(this->aAnimNames[18].pBuffer);
    return this->keyframe1;
}

// @428370 (dwPart_GetAnimKeyframe3) — lazy "rdance" (aAnimNames[19]).
rdKeyframe* dwPart::GetAnimKeyframe3()
{
    if (this->keyframe3 == NULL && this->aAnimNames[19].length != 0)
        this->keyframe3 = rdKeyframe_Load(this->aAnimNames[19].pBuffer);
    return this->keyframe3;
}

// @4283b0 (dwPart_FreeKeyframes)
void dwPart::FreeKeyframes()
{
    if (this->keyframe0 != NULL)
    {
        rdKeyframe_Free(this->keyframe0); // binary: rdKeyframe_FUN_0047de40
        this->keyframe0 = NULL;
    }
    if (this->keyframe1 != NULL)
    {
        rdKeyframe_Free(this->keyframe1);
        this->keyframe1 = NULL;
    }
    if (this->keyframe2 != NULL)
    {
        rdKeyframe_Free(this->keyframe2);
        this->keyframe2 = NULL;
    }
    if (this->keyframe3 != NULL)
    {
        rdKeyframe_Free(this->keyframe3);
        this->keyframe3 = NULL;
    }
}

// @428420 (dwPart_FreeModels)
void dwPart::FreeModels()
{
    if (this->pPreviewModel != NULL)
    {
        rdModel3_Free(this->pPreviewModel);
        this->pPreviewModel = NULL;
    }
    if (this->pPreviewModelMirror != NULL)
    {
        rdModel3_Free(this->pPreviewModelMirror);
        this->pPreviewModelMirror = NULL;
    }
    rdThing_FreeEntry(&this->thing);
}

// @428470 (dwPart_BuildPreviewModel) — draw the shared preview thing at
// pMatrix, temporarily driven by pPuppet.
void dwPart::BuildPreviewModel(rdMatrix34* pMatrix, rdPuppet* pPuppet, uint8_t bMirrored)
{
    rdModel3* pModel;
    rdThing* pOldRenderData;

    if (bMirrored == 0)
    {
        if (this->pPreviewModel == NULL)
        {
            dwMain_MaterialCache_Disable();
            this->pPreviewModel = this->BuildModel(0);
            dwMain_MaterialCache_Enable();
        }
        pModel = this->pPreviewModel;
    }
    else
    {
        if (this->pPreviewModelMirror == NULL)
        {
            dwMain_MaterialCache_Disable();
            this->pPreviewModelMirror = this->BuildModel(1);
            dwMain_MaterialCache_Enable();
        }
        pModel = this->pPreviewModelMirror;
    }

    // Note: the binary calls rdThing_SetModel3 on every draw, re-allocating
    // the joint arrays each time (a leak in the original). The previous
    // arrays are freed first here (thing.puppet is NULL outside this call,
    // so FreeEntry only drops the arrays).
    rdThing_FreeEntry(&this->thing);
    rdThing_SetModel3(&this->thing, pModel);

    pOldRenderData = pPuppet->renderData;
    pPuppet->renderData = &this->thing;
    this->thing.puppet = pPuppet;
    rdThing_Draw(&this->thing, pMatrix);
    this->thing.puppet = NULL;
    pPuppet->renderData = pOldRenderData;
}

// ---------------------------------------------------------------------------
// Model bbox helpers (Ghidra "Draw" names; they accumulate a bbox — no pixels)
// ---------------------------------------------------------------------------

// @428540 (dwPart_DrawThing)
extern "C" void dwPart_DrawThing(rdThing* pThing, rdMatrix34* pPlacement, rdVector3* pMin, rdVector3* pMax)
{
    rdModel3* pModel;
    int geoset;

    geoset = pThing->geosetSelect;
    pModel = pThing->model3;
    if (geoset == -1)
        geoset = pModel->geosetSelect;
    if (pThing->rdFrameNum != (uint32_t)rdroid_frameTrue) // binary: DAT_005542c0
        rdPuppet_BuildJointMatrices(pThing, pPlacement);  // binary: rdPuppet_FUN_00482790
    dwPart_DrawNodeTree(pThing, &pModel->aGeos[geoset], pModel->aHierarchyNodes, pMin, pMax);
}

// @428590 (dwPart_DrawNodeTree)
extern "C" void dwPart_DrawNodeTree(rdThing* pThing, rdGeoset* pGeoset, rdHierarchyNode* pNode,
                                    rdVector3* pMin, rdVector3* pMax)
{
    rdHierarchyNode* pChild;
    uint32_t i;

    if (pNode->meshIdx != 0xFFFFFFFF)
    {
        dwPart_AccumNodeBBox(&pGeoset->aMeshes[pNode->meshIdx],
                             &pThing->paJointMatrices[pNode->idx], pMin, pMax);
    }
    pChild = pNode->child;
    for (i = 0; pNode->numChildren != 0 && i < pNode->numChildren; i++)
    {
        if (pThing->paJointAmputationFlags[pChild->idx] == 0)
            dwPart_DrawNodeTree(pThing, pGeoset, pChild, pMin, pMax);
        pChild = pChild->nextSibling;
    }
}

// @428630 (dwPart_AccumNodeBBox)
extern "C" void dwPart_AccumNodeBBox(rdMesh* pMesh, rdMatrix34* pMatrix, rdVector3* pMin, rdVector3* pMax)
{
    rdVector3 v;
    uint32_t i;

    for (i = 0; i < (uint32_t)pMesh->numVertices; i++)
    {
        rdMatrix_TransformPoint34(&v, &pMesh->aVertices[i], pMatrix);
        if (v.x < pMin->x) pMin->x = v.x;
        if (v.y < pMin->y) pMin->y = v.y;
        if (v.z < pMin->z) pMin->z = v.z;
        if (v.x > pMax->x) pMax->x = v.x;
        if (v.y > pMax->y) pMax->y = v.y;
        if (v.z > pMax->z) pMax->z = v.z;
    }
}

// @428700 (dwPart_AdvanceModelFrame)
extern "C" void dwPart_AdvanceModelFrame(rdModel3* pModel)
{
    rdMaterial* pMat;
    uint32_t i;

    for (i = 0; i < pModel->sizeMaterials; i++)
    {
        pMat = pModel->aMaterials[i];
        if (pMat != NULL && pMat->num_texinfo > 1)
            pMat->curCelNum = (pMat->curCelNum + 1) % pMat->num_texinfo;
    }
}
