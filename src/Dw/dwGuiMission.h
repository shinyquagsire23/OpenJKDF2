#ifndef _DWGUIMISSION_H
#define _DWGUIMISSION_H

// dwGuiMission — the mission-select MAP / briefing screen cluster:
//
//   dwGuiDialog       (0xd8, dwGuiDialog_vtbl / scn dwGuiDialog_scn_vtbl) — modal message-box
//                     SCREEN (dwGuiScreen subclass over a 60%-shaded screen
//                     snapshot; DLG_TEXT control shows the localized message
//                     key) + the game-wide runner dwGuiDialog_RunModal
//                     ("gyesno"/"gmessage" confs; returns 5000 YES / 5001 NO).
//   dwGuiBriefText    (0x4c, dwGuiBriefText_vtbl) — the mission-briefing caption
//                     widget (dwAnimBase subclass): plays a VO wav and shows a
//                     timed sequence of caption IMAGES from a .brf conf,
//                     revealed through a growing ragged-edged circle around
//                     the mission's map anchor point.
//   dwGuiObjectiveBtn (0x5c, dwGuiObjectiveBtn_vtbl) — one mission marker on the galaxy
//                     map: a dwGuiRefRadioButton whose icon reflects the
//                     mission type + earned rank; hover broadcasts
//                     { 0xBBB, dwMission* }, select { 0xBBC, dwMission* }.
//   dwGuiBriefLine    (0x54, dwGuiBriefLine_vtbl) — JOB_NAME / JOB_DESCRIPTION
//                     dwGuiHypText line showing the selected mission's
//                     displayName ('N' mode) or briefing text ('B' mode, with
//                     a 5s typewriter reveal element).
//   dwGuiBriefTextElem(0x14, dwGuiBriefTextElem_vtbl) — dwGuiHypText_ElemT subclass that
//                     loops "WTextAppear.wav" while the reveal runs.
//   dwGuiMissionMap   (0xf4, dwGuiMissionMap_vtbl / scn dwGuiMissionMap_scn_vtbl) — the 'map'
//                     mission-select/briefing SCREEN itself (the middle phase
//                     of dwMissionSequence): objective radio buttons per
//                     unlocked mission, zoom-box fly-to, briefing playback,
//                     deploy flow into dwGuiInGame.
//   dwMissionTransIn/Out (0x3d0, dwMissionTransIn_vtbl/dwMissionTransOut_vtbl) — the workshop<->map
//                     panel-slide dwFlicSeg movies (TransToM/FromM.flc) with
//                     frame-cued MPanel*.wav sounds.
//
// Plus (landed here EARLY, owner dwGuiReference P6 — see the note below):
//   dwGuiRefRadioGroup  (0x18, dwGuiRefRadioGroup_vtbl) — radio-button container.
//   dwGuiRefRadioButton (0x54, dwGuiRefRadioButton_vtbl) — toggling dwWorkshopCtrl that
//                     deselects its group sibling.
//
// Ghidra (DroidWorks.exe) (the unit's
// dwMission_ParseInfo/ParseObjective/ClearObjectives and dwMissionSequence
// members are in Dw/dwMission.h; dwSith_Startup is dwSith.c). The
// dwGuiRefRadio* pair is in the dwGuiReference range.
// Everything verifiably C++ (vtables, ctor/dtor pairs, MSVC EH frames).
//
// ⚠ OWNERSHIP NOTE (for the dwGuiReference P6 translator): dwGuiRefRadioGroup
// and dwGuiRefRadioButton are defined HERE because dwGuiObjectiveBtn derives
// the button and dwGuiMissionMap constructs the group. When dwGuiReference
// lands, REUSE these classes (do not redefine); the group's AddCategory
// (RADIOGROUP/CP_RADIOGROUP conf-line helper) is intentionally NOT
// implemented here — it belongs to that unit's factory work.

#include "Dw/dwTypes.h"
#include "Dw/dwRect.h"

#ifdef __cplusplus
struct dwGuiDialog;
struct dwGuiBriefText;
struct dwGuiObjectiveBtn;
struct dwGuiBriefLine;
struct dwGuiBriefTextElem;
struct dwGuiMissionMap;
struct dwMissionTransIn;
struct dwMissionTransOut;
struct dwGuiRefRadioGroup;
struct dwGuiRefRadioButton;
struct dwSegment; // Dw/dwSegment.h
struct dwImage;   // Dw/dwImage.h
extern "C" {
#else
// C++ classes; opaque in the C view.
typedef struct dwGuiDialog dwGuiDialog;
typedef struct dwGuiBriefText dwGuiBriefText;
typedef struct dwGuiObjectiveBtn dwGuiObjectiveBtn;
typedef struct dwGuiBriefLine dwGuiBriefLine;
typedef struct dwGuiBriefTextElem dwGuiBriefTextElem;
typedef struct dwGuiMissionMap dwGuiMissionMap;
typedef struct dwMissionTransIn dwMissionTransIn;
typedef struct dwMissionTransOut dwMissionTransOut;
typedef struct dwGuiRefRadioGroup dwGuiRefRadioGroup;
typedef struct dwGuiRefRadioButton dwGuiRefRadioButton;
typedef struct dwSegment dwSegment;
typedef struct dwImage dwImage;
#endif

// ---- C-linkage API ------------------------------------------------------------

// THE game-wide modal yes/no//message runner: broadcasts { 0x7532 } (screen
// switching), builds a dwGuiDialog over pConfName ("gyesno"/"gmessage" ->
// "<name>.cmp") showing the localized pMsgKey, captures the mouse, plays
// CError.wav and runs it as the dwSegment overlay until its OnMessage stores
// a result. Returns 5000 (YES/OK) or 5001 (NO/CANCEL); 0 when the app-running
// flag is down (pre-P7 boot flow — see the loop note in dwGuiMission.cpp).
int dwGuiDialog_RunModal(const char* pConfName, const char* pMsgKey);

// dwMissionSequence phase factories (Dw/dwMission.h externs these; no single
// binary counterpart — they bundle the sequencer's `new(size) + Ctor` pairs
// inside dwMissionSequence_Advance so dwMission.cpp needs no class
// definitions). Each returns the new segment (for the screen: its dwSegment
// subobject).
dwSegment* dwMissionTransIn_New(dwImage* pBgImage);  // new dwMissionTransIn dwMissionTransIn_Ctor
dwSegment* dwGuiMissionMap_New(dwImage* pBgImage);   // new dwGuiMissionMap dwGuiMissionMap_Ctor
dwSegment* dwMissionTransOut_New(dwImage* pBgImage); // new dwMissionTransOut dwMissionTransOut_Ctor

// Note: no binary counterpart — the unit owns no module statics (the shared
// current-mission global dwCore_pCurrentMission is dw-core P7 state); kept
// for the project-wide soft-reset convention.
void dwGuiMission_Startup(void);

#ifdef __cplusplus
} // extern "C"

#include "Dw/dwGuiScreen.h"
#include "Dw/dwWidgetGroup.h"
#include "Dw/dwWorkshopCtrl.h" // dwGuiRefRadioButton base + dwWcButtonBlink
#include "Dw/dwGuiHypText.h"   // dwGuiBriefLine base + ElemT
#include "Dw/dwAnim.h"         // dwAnimBase (dwGuiBriefText base) + dwAnim
#include "Dw/dwMovie.h"        // dwFlicSeg (dwMissionTrans* base)
#include "Dw/dwMission.h"      // dwMission record
#include "Dw/dwString.h"
#include "Dw/dwList.h"
#include "Dw/dwFont.h"
#include "Dw/dwImage.h"

struct dwGuiZoomBox; // Dw/dwGuiButton.h

// ---- dwGuiRefRadioGroup / dwGuiRefRadioButton ---------------------------------
//
// (Owner dwGuiReference P6 — see the ownership note at the top.)
//
// The group is a dwWidgetGroup whose children are dwGuiRefRadioButtons; it
// tracks the selected one and deselects the previous on a switch. Binary
// layout: dwWidgetGroup @0x00 (0x14) + pSelected@0x14 — sizeof 0x18. vtable
// dwGuiRefRadioGroup_vtbl overrides only the dtor.

struct dwGuiRefRadioGroup : dwWidgetGroup
{
    dwGuiRefRadioButton* pSelected; // 0x14: current selection (not owned)

    // dwGuiRefRadioGroup_Ctor
    dwGuiRefRadioGroup(dwRect* pRect);

    // dwGuiRefRadioGroup_Dtor (scalar-deleting wrapper dwGuiRefRadioGroup_DtorDelete) —
    // body is the inlined base group dtor (children deleted there).
    virtual ~dwGuiRefRadioGroup();

    // Append pBtn to the children; the FIRST button added is auto-Select()ed
    // (quirk: the select fires BEFORE the insert, exactly as in the binary).
    // dwGuiRefRadioGroup_AddButton
    void AddButton(dwGuiRefRadioButton* pBtn);

    // Deselect the previous selection (when different) and latch pBtn.
    // dwGuiRefRadioGroup_SetSelected
    void SetSelected(dwGuiRefRadioButton* pBtn);

    // (dwGuiRefRadioGroup_AddCategory intentionally not here — owner
    // dwGuiReference; it news a 0x54 dwGuiRefRadioButton from one conf line.)
};

// Toggling image button bound to a group. Binary layout: dwWorkshopCtrl
// @0x00 (0x50) + pGroup@0x50 (Ghidra: pPayload) — sizeof 0x54. vtable
// dwGuiRefRadioButton_vtbl overrides only the dtor and OnMouseDown.

struct dwGuiRefRadioButton : dwWorkshopCtrl
{
    dwGuiRefRadioGroup* pGroup; // 0x50 (Ghidra: pPayload): owning group

    // dwGuiRefRadioButton_Ctor — dwWorkshopCtrl(pRect, ..., cmdId,
    // /*bToggle*/1).
    dwGuiRefRadioButton(dwGuiRefRadioGroup* pGroup, dwRect* pRect,
                        char* pImgNormal, char* pSndOff, char* pImgPressed,
                        char* pSndClick, int cmdId);

    // dwGuiRefRadioButton_Dtor (scalar-deleting wrapper dwGuiRefRadioButton_DtorDelete)
    virtual ~dwGuiRefRadioButton();

    // vtbl +0x08 dwGuiRefRadioButton_OnMouseDown — only when not already selected (bHot): base
    // toggle, then on a hit latch this as the group selection.
    virtual int OnMouseDown(int16_t x, int16_t y);

    // dwGuiRefRadioButton_Select — when not selected: bPressed = 0,
    // bHot = 1, group->SetSelected(this), Invalidate.
    void Select();
    // dwGuiRefRadioButton_Deselect — bPressed = 0, bHot = 0,
    // Invalidate.
    void Deselect();
};

// ---- dwGuiDialog ----------------------------------------------------------------
//
// Binary layout: dwGuiScreen @0x00 (0xc8) + msgKey dwString@0xc8 +
// pResult@0xd4 — sizeof 0xd8. dwGuiDialog_vtbl (scn dwGuiDialog_scn_vtbl) overrides only
// the dtor, OnMessage and CreateControl.

struct dwGuiDialog : dwGuiScreen
{
    dwString msgKey; // 0xc8: string-table key of the message text
    int* pResult;    // 0xd4: RunModal's result slot (5000/5001)

    // dwGuiDialog_Ctor — dwGuiScreen(pConfName, NULL), then
    // captures the current screen (60%-shaded copy) as pBgImage.
    dwGuiDialog(const char* pConfName, const char* pMsgKey, int* pResult);

    // dwGuiDialog_Dtor (scalar-deleting wrapper dwGuiDialog_DtorDelete) — frees
    // msgKey (member dtor here) + base.
    virtual ~dwGuiDialog();

    // vtbl +0x1c dwGuiDialog_OnMessage — codes 5000/0x1389: *pResult = code, return 1
    // (RunModal's loop ends); everything else -> base.
    virtual int OnMessage(dwWidgetMsg* pMsg);

    // vtbl +0x48 dwGuiDialog_CreateControl — "DLG_TEXT <rect> <font> <color>": a dwGuiHypText
    // (left/top-aligned, word-wrapped) showing the LOCALIZED msgKey;
    // fall back to the base factory.
    virtual dwWidget* CreateControl(char* pKeyword, dwConfFile* pConf);
};

// ---- dwGuiBriefText -------------------------------------------------------------
//
// One "<time> <image>" caption line of a .brf conf.
// Binary: 0x10-byte malloc'd record { float @0x00; dwString @0x04 }.
struct dwGuiBriefTextLine
{
    float timeSec;      // 0x00: caption switch time (sec since Play)
    dwString imageName; // 0x04: caption image (.rle) name

    dwGuiBriefTextLine(float timeSec, const char* pImageName)
        : timeSec(timeSec), imageName(pImageName, 0) {}
};

// Binary layout: dwAnimBase @0x00 (0x1c) + fields below — sizeof 0x4c.
// dwGuiBriefText_vtbl overrides dtor/OnKey/Update/OnMessage/Draw/Play/Stop.
//
// .brf conf format: line 1 = the VO wav name; every further line =
// "<float time> <image.rle>". state: 0 idle, 1 = circle reveal growing,
// 2 = fully revealed, 3 = collapsing (Stop). The caption image is revealed
// through a circle around (anchorX, anchorY) whose radius animates over 1s
// to revealMax (the farthest widget corner), with a ragged 4-line wobble
// pattern on the edge (aWobble in dwGuiMission.cpp).

struct dwGuiBriefText : dwAnimBase
{
    int32_t state;           // 0x1c: see above
    int16_t anchorX;         // 0x20: reveal-circle center (the mission mapPos)
    int16_t anchorY;         // 0x22
    int16_t revealPos;       // 0x24: current circle radius (px)
    int16_t revealMax;       // 0x26: full radius (distance to farthest corner)
    float revealElapsedSec;  // 0x28 (Ghidra: elapsedSec): reveal/collapse time
    float lineTimeSec;       // 0x2c (Ghidra: field_0x2c): caption-line clock
    uint8_t bSoundPending;   // 0x30: start the VO on the next Update
    dwString soundName;      // 0x34: VO wav (line 1 of the conf)
    dwList lines;            // 0x40 (Ghidra: pLines): dwGuiBriefTextLine* payloads
    dwListNode* pCurLineNode;// 0x44 (Ghidra: pCurLineNode): next caption line
    dwImage* pCurImage;      // 0x48 (Ghidra: pCurGlyph): current caption image

    // dwGuiBriefText_Ctor — dwAnimBase(pRect, msgCode, 0); parses
    // pConfName; precaches the VO sample; revealMax = round(distance from
    // *pAnchor to the farthest widget corner).
    dwGuiBriefText(dwRect* pRect, dwPoint* pAnchor, const char* pConfName, int msgCode);

    // dwGuiBriefText_Dtor (scalar-deleting wrapper dwGuiBriefText_DtorDelete)
    virtual ~dwGuiBriefText();

    // vtbl +0x10 dwGuiBriefText_OnKey — ESC -> virtual Stop. Returns 0.
    virtual int OnKey(int key, int repeat);
    // vtbl +0x14 dwGuiBriefText_Update — VO start (finish msg 0xC1D), circle grow/collapse
    // + dirty rects, timed caption-line image switching.
    virtual void Update(float dt);
    // vtbl +0x1c dwGuiBriefText_OnMessage — 0xC1D (VO finished) -> virtual Stop; then base.
    virtual int OnMessage(dwWidgetMsg* pMsg);
    // vtbl +0x44 dwGuiBriefText_Draw — state 2: plain blit; states 1/3: the wobbled
    // circular-reveal row copy out of the locked caption image.
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);
    // vtbl +0x48 dwGuiBriefText_Play — reset clocks, state = 1, load the first caption
    // image, re-precache the VO, base Play.
    virtual void Play();
    // vtbl +0x4c dwGuiBriefText_Stop — state = 3 (collapse), mirror the elapsed clock,
    // fade the VO out. Idempotent while already collapsing.
    virtual void Stop();
};

// ---- dwGuiObjectiveBtn ----------------------------------------------------------
//
// Binary layout: dwGuiRefRadioButton @0x00 (0x54) + pMission@0x54 (Ghidra:
// objectiveIndex — misnamed, it is the dwMission record) + pFont@0x58 —
// sizeof 0x5c. dwGuiObjectiveBtn_vtbl overrides dtor/OnMouseMove/OnMouseDown/
// EnsureImages/FreeImages/Draw.

struct dwGuiObjectiveBtn : dwGuiRefRadioButton
{
    dwMission* pMission; // 0x54: the mission this marker represents (not owned)
    dwFont* pFont;       // 0x58: "Arial14BA" label font (owned heap handle)

    // dwGuiObjectiveBtn_Ctor — dwGuiRefRadioButton(pGroup, pRect,
    // NULLs, cmdId 0x791f); loads the icon; sndClick = "WMissionLocate.wav".
    dwGuiObjectiveBtn(dwGuiRefRadioGroup* pGroup, dwRect* pRect, dwMission* pMission);

    // dwGuiObjectiveBtn_Dtor (scalar-deleting wrapper dwGuiObjectiveBtn_DtorDelete)
    virtual ~dwGuiObjectiveBtn();

    // vtbl +0x04 dwGuiObjectiveBtn_OnMouseMove (undetected fn, recovered from the vtable) — on a
    // HitTest hit broadcast { 0xBBB, pMission } and return 1.
    virtual int OnMouseMove(int16_t x, int16_t y);
    // vtbl +0x08 dwGuiObjectiveBtn_OnMouseDown (undetected fn) — base radio select; on a hit
    // broadcast { 0xBBC, pMission } (the mission-selected message).
    virtual int OnMouseDown(int16_t x, int16_t y);
    // vtbl +0x3c (Ghidra: dwGuiObjectiveBtn_LoadImage) — pick the
    // marker icon from missionType + rank (NORMAL: the 4-entry rank table;
    // SECRET/CRYSTAL: earned vs MSecretIcon; FINAL: MScroll_Icon); the ONE
    // image is aliased into both pImageNormal and pImagePressed.
    virtual void EnsureImages();
    // vtbl +0x40 (Ghidra: dwGuiObjectiveBtn_FreeImage) — single
    // delete of the aliased image.
    virtual void FreeImages();
    // vtbl +0x44 dwGuiObjectiveBtn_Draw — base image draw, then the mission displayName:
    // "#X" names draw only glyph X centered (and only while rank == 0);
    // otherwise the name is drawn shadowed under the marker.
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);
};

// ---- dwGuiBriefTextElem ---------------------------------------------------------
//
// dwGuiHypText_ElemT alias (no own fields, sizeof 0x14, dwGuiBriefTextElem_vtbl
// overriding Update + dtor): loops "WTextAppear.wav" while the typewriter
// reveal runs, stops it when done (dtor silences it instantly).

struct dwGuiBriefTextElem : dwGuiHypText_ElemT
{
    // dwGuiBriefTextElem_Ctor
    dwGuiBriefTextElem(float revealDuration);
    // dwGuiBriefTextElem_Dtor (scalar-deleting wrapper dwGuiBriefTextElem_DtorDelete;
    // the base-dtor COMDATs dwGuiBriefTextElem_BaseDtor/dwGuiBriefTextElem_BaseDtorDelete are implicit here)
    virtual ~dwGuiBriefTextElem();
    // vtbl +0x04 dwGuiBriefTextElem_Update (undetected fn, recovered from the vtable)
    virtual void Update(dwGuiHypText* pOwner, float dt, dwGuiHypTextRun** ppRuns);
};

// ---- dwGuiBriefLine -------------------------------------------------------------
//
// Binary layout: dwGuiHypText @0x00 (0x48) + modeText dwString@0x48 (Ghidra:
// text) — sizeof 0x54. dwGuiBriefLine_vtbl overrides only dtor + OnMessage.
// modeText comes from the conf line's tail; its FIRST char selects what to
// show: 'N' = mission displayName, 'B' = mission briefing text (with a 5s
// dwGuiBriefTextElem typewriter reveal added at construction).

struct dwGuiBriefLine : dwGuiHypText
{
    dwString modeText; // 0x48: mode selector ('N'/'B' first char)

    // dwGuiBriefLine_Ctor — dwGuiHypText format ctor + modeText;
    // when pMission is set, shows its field per the mode immediately.
    dwGuiBriefLine(dwRect* pRect, void* pNotify, char* pFontName, uint8_t color,
                   char* pFormat, char* pModeText, dwMission* pMission);

    // dwGuiBriefLine_Dtor (scalar-deleting wrapper dwGuiBriefLine_DtorDelete)
    virtual ~dwGuiBriefLine();

    // vtbl +0x1c dwGuiBriefLine_OnMessage (undetected fn, recovered from the vtable) — msg
    // 0xBBC (mission selected): re-show the sender mission's field per the
    // mode. Always returns 0 (the broadcast keeps going).
    virtual int OnMessage(dwWidgetMsg* pMsg);
};

// ---- dwGuiMissionMap ------------------------------------------------------------
//
// Binary layout: dwGuiScreen @0x00 (0xc8) + fields below — sizeof 0xf4.
// Primary dwGuiMissionMap_vtbl overrides dtor/OnMessage/EnsureImages/FreeImages/
// CreateControl; scn dwGuiMissionMap_scn_vtbl overrides Activate/Deactivate.
//
// Screen name "map" (map.cmp); mission data comes from dwCore_pMissionList /
// dwCore_pCurrentMission. Message map (OnMessage):
//   0xBB8 deploy (BeginDeploy)      0xBB9 close (RequestAdvance)
//   0xBBA show briefing             0xBBC mission selected (SelectObjective)
//   0xBEA/0xBEB store briefMode     0xC1D briefing VO done -> stop jawa anim
//   0x2328 (9000) sender 0xC1C = briefing caption finished -> restore radios
//   0x7530/0x7531 -> stop briefing caption + jawa anim

struct dwGuiMissionMap : dwGuiScreen
{
    dwRect mapRect;                  // 0xc8: MAP keyword rect (galaxy map area)
    dwGuiRefRadioGroup* pRadioGroup; // 0xd0: objective buttons (owned via children)
    dwGuiZoomBox* pZoomBox;          // 0xd4: fly-to reticle (owned via children)
    dwGuiHypText* pMissionText;      // 0xd8: ⚠ never assigned anywhere in the
                                     //       binary (SelectObjective's SetText
                                     //       block is dead code) — kept faithful
    int16_t reserved_0xdc[4];        // 0xdc: zeroed by the ctor, never read
    int32_t briefMode;               // 0xe4: last 0xBEA/0xBEB message code
    dwGuiBriefText* pBriefText;      // 0xe8: active briefing caption (owned via children)
    dwAnim* pJawaAnim;               // 0xec: JAWA_ANIM decoration (owned via children)
    dwWcButtonBlink* pBriefingBlink; // 0xf0: BRIEFING_BUTTON (owned via children)

    // dwGuiMissionMap_Ctor — dwGuiScreen("map", pBgImage).
    dwGuiMissionMap(dwImage* pBgImage);

    // dwGuiMissionMap_Dtor (scalar-deleting wrapper dwGuiMissionMap_DtorDelete; the
    // scn dtor thunk dwGuiMissionMap_ScnDtorThunk is compiler-made) — FreeImages + base.
    virtual ~dwGuiMissionMap();

    // ---- dwWidget-side overrides (primary dwGuiMissionMap_vtbl) ----
    virtual int OnMessage(dwWidgetMsg* pMsg);                     // +0x1c dwGuiMissionMap_OnMessage
    virtual void EnsureImages();                                  // +0x3c dwGuiMissionMap_EnsureImages
    virtual void FreeImages();                                    // +0x40 dwGuiMissionMap_FreeImages
    // +0x48 dwGuiMissionMap_CreateControl — keywords HELP / JOB_DESCRIPTION / JOB_NAME / JAWA_ANIM /
    // MAP / PART_BOUNDS / PARTTEXT / BRIEFING_BUTTON; fall back to the base.
    virtual dwWidget* CreateControl(char* pKeyword, dwConfFile* pConf);

    // ---- dwSegment-side overrides (scn dwGuiMissionMap_scn_vtbl) ----
    // dwGuiMissionMap_OnActivate — base Activate, rebuild the
    // objective radio group from every unlocked mission, broadcast
    // { 0xBBC, dwCore_pCurrentMission }.
    virtual int Activate();
    // dwGuiMissionMap_OnDeactivate — broadcast { 0x7532 }, destroy
    // the briefing caption, stop the jawa anim + WTextAppear.wav, base.
    virtual void Deactivate();

    // ---- non-virtual methods ----
    // dwGuiMissionMap_SelectObjective — latch dwCore_pCurrentMission,
    // blink the BRIEFING button while un-briefed, (re)create the zoom box on
    // mapRect and fly it to the mission's map position.
    void SelectObjective(dwMission* pMission);
    // dwGuiMissionMap_BeginDeploy — tear down the briefing caption;
    // refuse (hover-notify 0x7921) until the briefing was viewed; validate
    // the droid; then push this screen + the mission dwGuiInGame (preceded by
    // the DEPLOYMENT-type training mission when one exists) onto the segment
    // stack and advance.
    void BeginDeploy();
};

// ---- dwMissionTransIn / dwMissionTransOut -----------------------------------------
//
// Binary layout: dwFlicSeg @0x00 (0x3cc) + cueState@0x3cc — sizeof 0x3d0.
// vtables dwMissionTransIn_vtbl / dwMissionTransOut_vtbl override Activate/Deactivate/Update (+ the
// shared dtor, Ghidra: dwMissionTrans_Dtor). Full-screen FLC panel
// slides between the workshop and the mission map, with per-frame sound cues
// (MPanel*.wav; the Move loops fade in over 0.1s and out at the next cue).

struct dwMissionTransIn : dwFlicSeg
{
    int32_t cueState; // 0x3cc: sound-cue state machine position

    // dwMissionTransIn_Ctor — dwFlicSeg("TransToM.flc", pBgImage).
    dwMissionTransIn(dwImage* pBgImage);
    virtual ~dwMissionTransIn(); // shared dwMissionTrans_Dtor

    // vtbl +0x00 (Ghidra: dwMissionTransIn_PreloadSounds) — precache
    // the 6 cue wavs, then base Activate.
    virtual int Activate();
    // vtbl +0x04 (Ghidra: dwMissionTransIn_StopSounds) — fade the
    // cue sounds out (0.1s), free cached samples, base Deactivate.
    virtual void Deactivate();
    // vtbl +0x10 dwMissionTransIn_Update — base Update, then the frame-cued sound machine
    // (Begin @0 / Move1 loop @1 / Middle @9 / Move2 loop @10 / End @18 /
    // ScreenAppear @22).
    virtual void Update();
};

struct dwMissionTransOut : dwFlicSeg
{
    int32_t cueState; // 0x3cc

    // dwMissionTransOut_Ctor — dwFlicSeg("TransFromM.flc", pBgImage).
    dwMissionTransOut(dwImage* pBgImage);
    virtual ~dwMissionTransOut(); // shared dwMissionTrans_Dtor

    virtual int Activate();    // vtbl +0x00 PreloadSounds
    virtual void Deactivate(); // vtbl +0x04 StopSounds
    // vtbl +0x10 dwMissionTransOut_Update — mirrored cue order (ScreenVanish @0 / End @9 /
    // Move2 loop @12 / Middle @21 / Move1 loop @22 / Begin @29).
    virtual void Update();
};

#endif // __cplusplus

#endif // _DWGUIMISSION_H
