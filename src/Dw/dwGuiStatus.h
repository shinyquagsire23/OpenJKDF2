#ifndef _DWGUISTATUS_H
#define _DWGUISTATUS_H

// dwGuiStatus — the mission STATUS / debriefing SCREEN ("Status"), plus the
// shared dwGuiPicture control that COMDAT-tails this unit.
//
// Decompiled from DroidWorks.exe, unit range 0x434d50-0x436d7f. dwGuiStatus
// @0x434d50 (primary vtbl 0x51fa80 / segment vtbl 0x51fa68); dwGuiPicture
// @0x4365d0 (vtbl 0x51fad0) lives at the tail and is reused by dwRef /
// dwGuiStatus / dwGuiReference.
//
// dwGuiStatus shows the player's mission result: rank progression icons, the
// SPEED/DAMAGE/POWER gauges, and per-goal typewriter lines, then on exit
// saves the player profile (dwPlayer_SavePlr). It is pushed by
// dwGuiInGame_EndMission (the debrief). MSVC multiple inheritance
// (dwGuiScreen pattern) -> `struct dwGuiStatus : dwGuiScreen`.
//
// ⚠ This is a "big-fish" screen: the binary struct is NOT rigidly typed (the
// analyst flagged a base-offset shift between the ctor/OnMessage view — obj+0
// — and the OnActivate/OnDeactivate view — obj+0x10). The field map below is
// reconciled to obj+0 (matching the ctor); see the .cpp for the derivation.
//
// dwGuiPicture is an id-keyed image-swap picture box (dwWidgetGroup subclass):
// AddImage builds a {name,id} set, OnMessage/SelectById swaps the shown image
// by matching a code/id, AddText spawns positioned dwGuiHypText captions, and
// Draw blits the current image then the caption children.
//
// Compiled as C++ (vtables, ctor/dtor pairs, MSVC EH frames).

#include "Dw/dwTypes.h"

#ifdef __cplusplus
struct dwGuiStatus;
struct dwGuiPicture;
struct dwGuiPictureItem;
struct dwMission; // Dw/dwMission.h
extern "C" {
#else
typedef struct dwGuiStatus dwGuiStatus;
typedef struct dwGuiPicture dwGuiPicture;
typedef struct dwGuiPictureItem dwGuiPictureItem;
typedef struct dwMission dwMission;
#endif

// Note: no binary counterpart — resets this unit's module statics (the
// achievement-flag bitmask) for the project-wide soft-reset loop.
void dwGuiStatus_Startup(void);

// Added: C-callable factory — allocates the debrief screen and returns its
// dwSegment subobject (for dwSegment_Push). Consumed by
// dwGuiInGame_EndMission (OWNS the former dwMain.c placeholder of this name).
//   pMission   = the completed mission record (0xBBC-style context)
//   itemPct    = POWER gauge fill (was the inventory/item fraction)
//   healthPct  = DAMAGE gauge fill (player health fraction)
//   chargeMax  = CLOCK elapsed-seconds seed
struct dwSegment;
struct dwSegment* dwGuiStatus_New(dwMission* pMission, float itemPct, float healthPct, int chargeMax);

#ifdef __cplusplus
} // extern "C"

#include "Dw/dwGuiScreen.h"
#include "Dw/dwWidgetGroup.h"
#include "Dw/dwString.h"
#include "Dw/dwList.h"
#include "Dw/dwRect.h"
#include "Dw/dwConfFile.h"

struct dwImage; // Dw/dwImage.h

// ---- dwGuiPicture ----------------------------------------------------------
//
// Binary: dwWidgetGroup base @0x00 (0x14) + fields below — sizeof 0x2c.
// vtable @0x51fad0.

// One id->image entry (binary 0x10, no vptr).
struct dwGuiPictureItem
{
    dwString imageName; // 0x00
    int32_t id;         // 0x0c

    dwGuiPictureItem(const char* pImageName, int id)
        : imageName(pImageName, 0), id(id) {}
    ~dwGuiPictureItem() {}
};

struct dwGuiPicture : dwWidgetGroup
{
    dwList items;        // 0x14: dwGuiPictureItem* payloads (the id->image set)
    dwImage* pImage;     // 0x18: currently displayed image (owned)
    int16_t posX;        // 0x1c (Ghidra: field1c): ctor posPair.x (stored, unused in draw)
    int16_t posY;        // 0x1e (Ghidra: field1e): ctor posPair.y
    dwString imageName;  // 0x20: current image's name

    // @4365d0 (dwGuiPicture_Ctor) — dwWidgetGroup(pRect); imageName =
    // pImageName; EnsureLoaded. posPair packs an (x,y) short pair. (Ghidra
    // mislabeled the rect arg "pParent"; every caller passes a rect.)
    dwGuiPicture(dwRect* pRect, const char* pImageName, int32_t posPair);

    // @436690 (dwGuiPicture_Dtor; scalar-deleting wrapper @436670) — FreeImage
    // + delete every item; the base group dtor deletes the caption children.
    virtual ~dwGuiPicture();

    // vtbl +0x18 @436b60 — hover consume (returns 1).
    virtual int OnHover(int16_t x, int16_t y);
    // vtbl +0x1c @4368c0 — match pMsg->code to an item id -> swap the image;
    // then forward to the caption children (dwWidgetGroup::OnMessage).
    virtual int OnMessage(dwWidgetMsg* pMsg);
    // vtbl +0x3c @436bd0 (EnsureLoaded) — lazily load pImage, then broadcast.
    virtual void EnsureImages();
    // vtbl +0x40 @436c00 (FreeImage) — delete pImage, then broadcast.
    virtual void FreeImages();
    // vtbl +0x44 @436b90 — EnsureImages, blit pImage at (left,top), draw captions.
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);

    // -- non-virtual methods --------------------------------------------------
    // @436960 — append a {pImageName, id} entry to the set.
    void AddImage(char* pImageName, uint32_t id);
    // @436a00 — spawn a dwGuiHypText caption child at (left+x, top+y).
    void AddText(char* pText, int x, int y, int color, char* pFont);
    // @436ae0 — swap the shown image to the entry whose id == id.
    void SelectById(int id);
};

// Added: C++-linkage factory for the shared dwGuiPicture (this unit owns the
// class). dwRef (dwRefGraph markers) builds picture boxes through this — matches
// its `extern dwWidget* dwGuiPicture_New(...)` forward decl (C++ linkage).
// posPair packs an (x,y) short pair (callers that don't offset pass 0).
dwWidget* dwGuiPicture_New(dwRect* pRect, const char* pImgName, int posPair);

// ---- dwGuiStatus ------------------------------------------------------------
//
// Binary: dwGuiScreen base @0x00 (0xc8) + own fields below — sizeof ~0x138.
// Field offsets reconciled to obj+0. Primary vtbl 0x51fa80, segment 0x51fa68.

struct dwGuiStatus : dwGuiScreen
{
    dwMission* pContext;      // 0xc8: the completed mission record
    uint8_t bChildBuilt;      // 0xcc: controls built once (OnActivate latch)
    dwString sound;           // 0xd0: end-of-mission congratulation .san movie
    uint8_t bStatsBuilt;      // 0xdc: BuildControls stat-section latch
    uint8_t savedRank;        // 0xdd: mission rank saved on activate/restored on hide
    uint8_t altRank;          // 0xde: displayed (possibly bumped) rank tier
    dwString speech;          // 0xe0: debrief voiceover clip (speech.pBuffer @0xe8 = playing handle)
    dwRect rankIconRect0;     // 0xec: droid-reward preview slot
    int32_t rankImageIdx;     // 0xf4: index into the rank-image table (0 = none)
    dwRect rankRect;          // 0xf8: RANKRECT — where pRankImage is centered
    dwImage* pRankImage;      // 0x100: current rank icon (owned)
    dwRect rankIconRect1;     // 0x104: rank-NAME text slot (Arial24BA)
    dwRect rankIconRect3;     // 0x10c: reward part-name text slot
    dwRect rankIconRect2;     // 0x114: goals-list layout anchor
    uint8_t bBlinkOn;         // 0x11c: text-caret blink phase
    float blinkTimer;         // 0x120: seconds into the 0.7s blink period
    dwWidget* pGoalsText;     // 0x124: GOALS_INCOMPLETE header hyptext
    dwWidgetGroup* pGroup;    // 0x128: sub-group for the completion header/preview
    float itemPct;            // 0x12c: POWER gauge fill (ctor arg 2)
    float healthPct;          // 0x130: DAMAGE gauge fill (ctor arg 3)
    int32_t chargeMax;        // 0x134: CLOCK elapsed-seconds seed (ctor arg 4)

    // @434d50 (dwGuiStatus_Ctor) — dwGuiScreen("Status", NULL); savedRank/
    // altRank seeded from pContext->rank; stat pointers zeroed.
    dwGuiStatus(dwMission* pContext, float itemPct, float healthPct, int chargeMax);

    // @434ee0 (dwGuiStatus_Dtor; scalar-deleting wrapper @434ec0; segment
    // thunk @4365c0) — FreeImages, delete pGroup + its children, free the two
    // strings; the base dtor tears down the rest.
    virtual ~dwGuiStatus();

    // ---- primary vtbl (0x51fa80) overrides ---------------------------------
    virtual void Update(float dt);                 // +0x14 @436400 — text blink timer
    virtual int OnMessage(dwWidgetMsg* pMsg);      // +0x1c @435180 — 30000 stop speech / 0x96 dismiss
    virtual void EnsureImages();                   // +0x3c @436520 (EnsureLoaded)
    virtual void FreeImages();                     // +0x40 @436570
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect); // +0x44 @436480 — rank icon centered
    virtual dwWidget* CreateControl(char* pKeyword, dwConfFile* pConf); // +0x48 @4352e0

    // ---- segment vtbl (0x51fa68) overrides ---------------------------------
    virtual int Activate();    // +0x00 @434ff0 — layout rank rects + BuildControls once
    virtual void Deactivate(); // +0x04 @435120 — stop speech + SavePlr

    // ---- non-virtual --------------------------------------------------------
    // @4356f0 — build the per-goal typewriter lines + rank name/icon + reward
    // preview + the mission-progression achievement state machine.
    void BuildControls();
};

#endif // __cplusplus

#endif // _DWGUISTATUS_H
