#ifndef _DWPART_H
#define _DWPART_H

// dwPart — the refcounted droid-part BLUEPRINT class (a part-type definition
// parsed from a "Part Blueprint" conf record) + dwPartNode — a droid-part
// scene-graph NODE (an assembled/displayed part instance; the workshop droid
// is a tree of these hanging off the dwCore_pWorkspaceNodes list).
//
// Decompiled from DroidWorks.exe:
//   dwPartNode  0x4267a0-0x426d6f (+ spillover InitSlotsFromModel @426d70,
//               Mirror @427060 — physically binned in the dwDroidView unit)
//   dwPart      0x4271b0-0x42873f
// Verifiably C++ (dwString members, MSVC EH frames/ExceptionList in
// ParseBlueprint/Dtor/CreateNode) -> C++ classes.
//
// ⚠ Correction to the old Ghidra plate: dwPartNode is NOT polymorphic and
// its ctor's first argument is NOT a vtable — it is the owning dwPart*
// blueprint (field 0x00). Proven by dwPartNode_InitSlotsFromModel reading
// *(this->field0 + 8) as the blueprint's part TYPE and *(this->field0 +
// 0x18) as the blueprint name buffer, and by dwPart_CreateNode passing its
// own `this` there (and bumping this->refCount on success).
//
// Blueprint lifecycle: dw_Startup (P7) parses every PLS blueprint record
// (operator new(0x670) + the dwPart conf ctor), registers it in
// dwPart_hashBlueprints and keeps it on dwCore_pBlueprintList. Nodes ref the
// blueprint: dwPart::CreateNode -> refCount++; dwPartNode dtor ->
// dwPart::Release (refCount--; at 0 the CACHED preview models/keyframes are
// dropped — the blueprint object itself stays alive in the registry).
//
// Engine mapping (DW-binary label -> repo):
//   rdModel3_sub_47FEA0   -> rdModel3_Load      (loader-hook aware)
//   rdModel3_sub_480BE0   -> rdModel3_Free      (unloader-hook aware)
//   rdKeyframe_FUN_0047d8a0 -> rdKeyframe_Load  / _FUN_0047de40 -> rdKeyframe_Free
//   rdPuppet_FUN_004820c0 -> rdPuppet_New, _00482170 -> rdPuppet_AddTrack,
//   _00482680 -> rdPuppet_UpdateTracks, _00482790 -> rdPuppet_BuildJointMatrices
//   DAT_005542c0          -> rdroid_frameTrue

#include "Dw/dwTypes.h"

#ifdef __cplusplus
extern "C" {
#include "General/stdHashtbl.h" // no extern "C" guards of its own — wrap here
}
#else
#include "General/stdHashtbl.h"
#endif

// DW part-type ids (dwPart::type / dwPartNode::partType / attach-slot type).
// The TYPE keyword sets the right-hand variant (ARM=3/AFFECTOR=4/CARGOARM=8);
// the paired value is what dwPartNode::Mirror swaps to (1<->3, 2<->4, 7<->8).
enum DW_PARTTYPE
{
    DW_PARTTYPE_HEAD = 0,
    DW_PARTTYPE_ARM_MIRROR = 1,      // mirrored ARM
    DW_PARTTYPE_AFFECTOR_MIRROR = 2, // mirrored AFFECTOR
    DW_PARTTYPE_ARM = 3,             // TYPE ARM
    DW_PARTTYPE_AFFECTOR = 4,        // TYPE AFFECTOR
    DW_PARTTYPE_LOCOMOTION = 5,      // TYPE LOCOMOTION (chassis)
    DW_PARTTYPE_TORSO = 6,           // TYPE TORSO
    DW_PARTTYPE_CARGOARM_MIRROR = 7, // mirrored CARGOARM
    DW_PARTTYPE_CARGOARM = 8,        // TYPE CARGOARM
    DW_PARTTYPE_BATTERY = 9,         // TYPE BATTERY
    DW_PARTTYPE_SPECIAL = 10,        // TYPE SPECIAL (no default images/FLC)
    DW_PARTTYPE_NONE = 11,           // default / "no attach" root marker
};

#ifdef __cplusplus
struct dwPart;
struct dwPartNode;
extern "C" {
#else
// C++ classes; opaque in the C view.
typedef struct dwPart dwPart;
typedef struct dwPartNode dwPartNode;
#endif

// ---- module statics (reset in dwPart_Startup) -------------------------------

// Blueprint registry: part NAME -> dwPart*. Global @0x53e7b4. The table is
// CREATED + filled + freed by dw_Startup/dw_Shutdown (owner dwMain, P7);
// this unit only defines the global and looks it up.
extern tHashTable* dwPart_hashBlueprints;

// ANIMATIONS-section keyword -> aAnimNames index (1..23). Global @0x542714.
// Note: the binary builds this inside the DW-modified sithPuppet_Startup
// (@0x454deb) from the DW engine's 23-entry anim-name list; the repo engine
// keeps JK's own table, so this unit owns a private copy built in
// dwPart_Startup (same keys/indices — list recovered from @0x52bc7c).
extern tHashTable* dwPart_hashAnimKeywords;

// SOUNDS-section keyword -> aSoundNames index (1..93). Global @0x545df4.
// Binary home: the DW sithSoundClass_Startup (@0x460176; keys @0x52c4ac =
// exactly JK's 93 soundclass names). Built in dwPart_Startup here.
extern tHashTable* dwPart_hashSoundKeywords;

// Per-(type, slotMask) blueprint counters, bumped once per parsed blueprint
// (read by dwDroidStats_PickRandomPart — the random-droid generator, P5).
extern int dwPart_countHeads;       // @0x53e844: type 0
extern int dwPart_countArms;        // @0x53e830: types 1/3
extern int dwPart_countAffectors;   // @0x53e838: types 2/4
extern int dwPart_countLocoNormal;  // @0x53e83c: type 5, slotMask & 1
extern int dwPart_countLocoCargo;   // @0x53e834: type 5, slotMask & 2
extern int dwPart_countTorsoNormal; // @0x53e840: type 6, slotMask & 1
extern int dwPart_countTorsoCargo;  // @0x53e84c: type 6, slotMask & 2
extern int dwPart_countCargoArms;   // @0x53e848: types 7/8

// Highest DRAIN rate seen across all blueprints (units/sec at 60fps ticks).
extern float dwPart_maxDrain; // @0x53e850

// Reset the module statics + (re)build the two keyword tables. No binary
// equivalent (see the per-global notes above) — added per the soft-reset
// rule; call before parsing any blueprint.
void dwPart_Startup(void);

// @4271b0 — NULL/empty-safe stdHashtbl_Find on dwPart_hashBlueprints.
dwPart* dwPart_FindBlueprint(const char* pName);

// dwCog verb helpers (C-callable; typed access to the C++ blueprint/node structs).
int dwPart_SetAvailableByName(const char* pName, int bAvailable); // dwenablepart/dwdisablepart
int dwCog_WorkspaceHasPart(const char* pName);                    // dwcheckforpart

#ifdef __cplusplus
} // extern "C"

#include "types.h" // rdThing/rdMatrix34/rdVector3 by value + engine fwd typedefs
#include "Dw/dwString.h"
#include "Dw/dwList.h"
#include "Dw/dwConfFile.h"
#include "Dw/dwImage.h"

// ---- dwPartNode -----------------------------------------------------------
//
// Binary struct dwPartNode, 0xf4. Plain (non-virtual) class. Each node OWNS
// a private rdModel3 instance of its blueprint's model (freed in the dtor)
// so per-node recolors (CollectContacts) and mirroring don't leak into other
// instances of the same part.

// One attach slot (0x10, four per node @0x9c). A slot is a leaf DUMMY
// hierarchy node of the model (meshIdx == -1) whose node->type tags what
// part type plugs in there (mapping in InitSlotsFromModel).
struct dwPartSlot
{
    int32_t type;              // 0x00: DW_PARTTYPE_* accepted here (0xb = unused slot)
    rdHierarchyNode* pNode;    // 0x04: the model dummy node (idx indexes paJointMatrices)
    int32_t* pChildTypePtr;    // 0x08: &attachedChild->partType (NULL when empty)
    dwPartNode* pChild;        // 0x0c: attached child node (NULL when empty)
}; // sizeof 0x10

struct dwPartNode
{
    dwPart* pPart;             // 0x00: owning blueprint (refcounted; NOT a vtable — see file top)
    uint8_t bMirrored;         // 0x04 (Ghidra: flag): mirrored-model variant active
    rdThing thing;             // 0x08: render thing over pModel3 (puppet @+0x14,
                               //       paJointMatrices @+0x20, curGeoMode @+0x34)
    rdModel3* pModel3;         // 0x50: OWNED model instance (rdModel3_Load per node)
    rdMatrix34 transform;      // 0x54: placement (translation = .scale @0x78)
    int16_t slotIdx16;         // 0x84: .drd "slot index" (persisted verbatim; only
                               //       read/added by the .drd io — meaning uncertain)
    int32_t partType;          // 0x88: DW_PARTTYPE_* (mirror-remapped; 0xb = never attaches)
    rdHierarchyNode* pMountNode; // 0x8c: the model's root dummy node (where THIS part
                               //       mounts on its parent; NULL for LOCOMOTION)
    dwPartSlot* pAttachSlot;   // 0x90: the parent slot we are attached to (NULL = detached)
    dwPartNode* pAttachData;   // 0x94: the parent node we are attached to
    int32_t slotCount;         // 0x98 (Ghidra: childCount): populated entries in aSlots
    dwPartSlot aSlots[4];      // 0x9c: child attach slots found on the model
    int32_t animTrack;         // 0xdc: active rdPuppet track (-1 = none)
    uint8_t aContacts[9][2];   // 0xe0 (Ghidra: contact list): applied paint pairs
                               //       {matchColor, newColor}; (0,0) = free entry
    // (0xf2: 2 pad bytes)

    // @4267a0 — takes ownership of pModel; identity transform; builds the
    // rdThing + rdPuppet, then InitSlotsFromModel().
    dwPartNode(dwPart* pOwner, rdModel3* pModel);
    // @426830 — StopAnim, free the owned model + rdThing entry (which frees
    // the puppet), then pPart->Release().
    ~dwPartNode();

    void GetPosition(rdVector3* pOut) const;      // @426860: transform translation
    void Translate(const rdVector3* pDelta);      // @4268d0

    // @426880 — accumulate this node's world-space vertex bbox into
    // pMin/pMax (re-derives transform from the attach slot first). Despite
    // the Ghidra "Draw" name this renders nothing (see dwPart_DrawThing).
    void DrawAt(rdVector3* pMin, rdVector3* pMax);

    void Draw();                                  // @426900: rdThing_Draw + recurse children
    void DrawHighlighted();                       // @426970: as Draw with curGeoMode forced 4
    void UpdateTransform();                       // @4269f0: pPart->BuildPreviewModel(...) —
                                                  //   draws the blueprint preview thing driven
                                                  //   by THIS node's puppet
    void SetDrawFlag4Rec();                       // @426a10: thing.curGeoMode = 4 (full), recurse
    void SetDrawFlag2Rec();                       // @426a50: thing.curGeoMode = 2 (wireframe), recurse

    // @426a90 — coarse sphere test then rdRaycast_RayModel (hit record 0x38,
    // rdRaycast unit). Returns nonzero on hit.
    int RaycastHit(rdVector3* pOrigin, rdVector3* pDir, void* pHitOut);

    // @426af0 — "paint": recolor every model material through the dwMain
    // material cache (matchColor -> newColor) and record the pair in
    // aContacts (first entry whose byte0 == matchColor or == 0; silently
    // dropped when all 9 are taken).
    void CollectContacts(int matchColor, int newColor);

    void PlayIdleAnim();                          // @426b60: keyframe0/1 ("walk"/"rwalk")
    void PlayActiveAnim();                        // @426b90: keyframe2/3 ("dance"/"rdance"), else idle
    void PlayAnimTrack(rdKeyframe* pKeyframe);    // @426bc0
    void FadeAnim(float deltaSecs);               // @426c10: rdPuppet_UpdateTracks + material cel cycle
    void StopAnim();                              // @426c40

    // @426c70 — attach THIS node into pSlot of pParent; mirrors this node
    // first when its partType doesn't match the slot type.
    void AttachToSlot(dwPartNode* pParent, dwPartSlot* pSlot);
    void DetachFromSlot();                        // @426cc0

    // `this` = the PARENT node owning pSlot (matrices come from this->thing).
    void GetSlotPosition(dwPartSlot* pSlot, rdVector3* pOut); // @426d10
    void GetSlotMatrix(dwPartSlot* pSlot, rdMatrix34* pOut);  // @426d40

    // @426d70 — classify the model's dummy nodes into pMountNode + aSlots
    // (and mirror-remap partType when bMirrored).
    void InitSlotsFromModel();

    // @427060 — swap to the mirrored part type/model: detach children,
    // rebuild the model (mirror variant), replay the paint pairs, re-find
    // slots, re-attach the children by slot ordinal.
    void Mirror();
};

// ---- dwPart -----------------------------------------------------------
//
// Binary struct dwPart, 0x670. Field offsets below are the 32-bit binary's
// (member ORDER is what matters here — never rely on offsets in this port).

struct dwPart
{
    int32_t refCount;          // 0x00: live dwPartNode instances
    uint8_t bRestricted;       // 0x04: RESTRICTED keyword
    uint8_t bAvailable;        // 0x05: unlocked/visible (init 1; RESTRICTED clears;
                               //       toggled by dwCog_Enable/DisablePart)
    int32_t type;              // 0x08: DW_PARTTYPE_* (init 0xb)
    uint32_t slotMask;         // 0x0c (MODE keyword): body-slot mask — 1 NORMAL,
                               //       2 CARGO, 3 both (init 3)
    dwString name;             // 0x10: blueprint id (registry key; conf record head)
    dwString displayName;      // 0x1c: NAME keyword (init = name)
    dwString desc;             // 0x28: DESC keyword
    dwString spinFlcName;      // 0x34: SPIN keyword (default name + ".flc")
    dwImage* pImage;           // 0x40: IMAGE keyword (default name + ".rle")
    dwImage* pIcon;            // 0x44: ICON keyword (default name + "ICON.rle");
                               //       the dwWcBlueprints grid cell image
    dwString modelName;        // 0x48: LORES 1st token (default name + ".3do")
    dwString modelNameMirror;  // 0x54: LORES 2nd token (mirror-variant model)
    dwList materials;          // 0x60: dwString* payloads (MATERIALS keyword)
    char voiceChars[2];        // 0x64: VOICE keyword (two chars)
    dwString aAnimNames[24];   // 0x68: ANIMATIONS section, indexed by
                               //       dwPart_hashAnimKeywords (1..23; [0] unused)
    dwString aSoundNames[94];  // 0x188: SOUNDS section, indexed by
                               //       dwPart_hashSoundKeywords (1..93; [0] unused)
    uint16_t battery;          // 0x5f0: BATTERY keyword
    float drainRate;           // 0x5f4: DRAIN keyword / 60 (per-tick drain)
    uint8_t loadCapacity;      // 0x5f8: LOAD keyword
    uint8_t durability;        // 0x5f9: DURABILITY keyword (init 1)
    float mass;                // 0x5fc: MASS keyword (init 100.0)
    float power;               // 0x600: mass * THRUST * 0.001 (recomputed on
                               //       whichever of MASS/THRUST parses last)
    float staticFriction;      // 0x604: STATIC keyword (LOCOMOTION default 0.3)
    float drag;                // 0x608: DRAG keyword (LOCOMOTION default 3.0)
    uint32_t capFlags;         // 0x60c: capability bits (init 0x10; see the
                               //       keyword table in dwPart.cpp)
    rdThing thing;             // 0x610: shared PREVIEW thing (BuildPreviewModel)
    rdModel3* pPreviewModel;   // 0x658: cached preview model (lazy)
    rdModel3* pPreviewModelMirror; // 0x65c: cached mirrored preview model (lazy)
    rdKeyframe* keyframe0;     // 0x660: cached "walk" keyframe (aAnimNames[2])
    rdKeyframe* keyframe1;     // 0x664: cached "rwalk" keyframe (aAnimNames[18])
    rdKeyframe* keyframe2;     // 0x668: cached "dance" keyframe (aAnimNames[17])
    rdKeyframe* keyframe3;     // 0x66c: cached "rdance" keyframe (aAnimNames[19])

    // @4271d0 (dwPart_ParseBlueprint) — the conf-record ctor/parser: inits
    // every field, then consumes keywords until END_PART/EOF, then applies
    // the name-derived defaults and bumps the type counters.
    dwPart(dwConfFile* pConf);
    // @427ef0 (dwPart_Dtor) — free models/keyframes/images/material strings.
    ~dwPart();

    void ParseAnims(dwConfFile* pConf);   // @4280b0: until END_ANIMS
    void ParseSounds(dwConfFile* pConf);  // @428120: until END_SOUNDS

    // @4281a0 — BuildModel(0) + new dwPartNode(this, model); refCount++ on
    // success. NULL when the model failed to load.
    dwPartNode* CreateNode();

    // @428210 — rdModel3_Load a FRESH instance of modelName/modelNameMirror
    // and repaint every texinfo's solidColor with dw_aPartSlotColors[type]
    // (the slot-marker color). Caller owns the returned model.
    rdModel3* BuildModel(uint8_t bMirrored);

    // @428290 — refCount--; at zero drop the cached preview models +
    // keyframes (the blueprint object itself stays registered).
    void Release();

    rdKeyframe* GetAnimKeyframe0(); // @4282b0: lazy "walk"   (aAnimNames[2])
    rdKeyframe* GetAnimKeyframe2(); // @4282f0: lazy "dance"  (aAnimNames[17])
    rdKeyframe* GetAnimKeyframe1(); // @428330: lazy "rwalk"  (aAnimNames[18])
    rdKeyframe* GetAnimKeyframe3(); // @428370: lazy "rdance" (aAnimNames[19])

    void FreeKeyframes(); // @4283b0
    void FreeModels();    // @428420: cached previews + the preview rdThing entry

    // @428470 — draw the blueprint's shared preview thing at pMatrix,
    // temporarily driven by pPuppet (the caller node's): lazily build the
    // (mirrored) preview model with the material recolor cache DISABLED,
    // swap pPuppet->rdthing to the preview thing, rdThing_Draw, restore.
    void BuildPreviewModel(rdMatrix34* pMatrix, rdPuppet* pPuppet, uint8_t bMirrored);
};

// ---- model bbox helpers (operate on rdThing/rdModel3, not the blueprint) ----
// Despite the Ghidra "Draw" names these render NOTHING: they accumulate the
// world-space vertex bounding box of a posed model (dwDroidView view-extent
// fitting). All @ addresses in the dwPart unit.
extern "C" {

// @428540 — refresh joint matrices when stale (rdFrameNum vs rdroid_frameTrue)
// then walk the selected geoset's hierarchy accumulating into pMin/pMax.
void dwPart_DrawThing(rdThing* pThing, rdMatrix34* pPlacement, rdVector3* pMin, rdVector3* pMax);

// @428590 — recursive node walk (skips amputated joints).
void dwPart_DrawNodeTree(rdThing* pThing, rdGeoset* pGeoset, rdHierarchyNode* pNode,
                         rdVector3* pMin, rdVector3* pMax);

// @428630 — min/max every mesh vertex transformed by pMatrix.
void dwPart_AccumNodeBBox(rdMesh* pMesh, rdMatrix34* pMatrix, rdVector3* pMin, rdVector3* pMax);

// @428700 — advance every multi-cel material to its next cel (the "model
// frame" tick used while a part animates).
void dwPart_AdvanceModelFrame(rdModel3* pModel);

} // extern "C"

#endif // __cplusplus

#endif // _DWPART_H
