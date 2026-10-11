#ifndef _DWWORKSHOPCTRL_H
#define _DWWORKSHOPCTRL_H

// dwWorkshopCtrl — the droid-workshop control cluster: the two-state
// image/toggle button BASE class every workshop chrome control derives from,
// plus this compile unit's control classes:
//
//   dwWorkshopCtrl       (0x50, dwWorkshopCtrl_vtbl) — two-state image button
//                        (BUTTON/TOGGLE conf keywords). Base of
//                        dwGuiTextButton (Dw/dwGuiButton.h) ->
//                        dwGuiTextPopup/dwGuiTimer (later units).
//   dwWcButtonBlink      (0x74, dwWcButtonBlink_vtbl) — dwWorkshopCtrl + a third
//                        "blink" image flashed at 0.5s intervals
//                        (BUTTON_BLINK keyword).
//   dwWcEntryPanel       (0x40, dwWcEntryPanel_vtbl) — data-driven popup panel:
//                        a background image + three timed dwGuiHypText
//                        captions selected by entry id.
//   dwWcMaterials        (0x68, MI dwWcMaterials_vtbl primary/dwWcMaterials_group_vtbl group) —
//                        material-swatch panel: dwAnimBase + dwWidgetGroup
//                        (same MI shape as dwGuiAnimView) with two
//                        independently cycling material rows (WOOD/RUBBER/
//                        GLASS), per-combination anims and a still image.
//   dwWcBlueprints       (0x38, dwWcBlueprints_vtbl) — the blueprint fly-out grid
//                        (BLUEPRINTS keyword): draws every available dwPart
//                        blueprint image in a grid over a translucent cone.
//   dwWcChildDecorator   (0x14, dwWcChildDecorator_vtbl) — single-child forwarding
//                        decorator base (every virtual forwards to pChild).
//                        Also derived by dwGuiTimer (dwGuiTextMisc, later).
//   dwWcPalette          (0x20, dwWcPalette_vtbl) — dwWcChildDecorator that
//                        swaps its child between the build/paint tool
//                        buttons with FLC transition anims (PALETTE keyword),
//                        and runs the droid RANDOMIZE command.
//
// The unit ALSO owns five dwGuiButton subclasses (dwWcArrows/dwWcBuildButton/
// dwWcPaintButton/dwWcBuildPaintButton/dwWcCargoNormalButton) — those are
// declared in Dw/dwGuiButton.h (they need the dwGuiButton base, and
// dwGuiButton.h includes THIS header for dwGuiTextButton), but their method
// bodies live in dwWorkshopCtrl.cpp, mirroring the binary's compile unit.
//
// Decompiled from DroidWorks.exe. Verifiably
// C++ (vtables, ctor/dtor pairs, MSVC EH frames) -> C++ classes.
//
// No module statics — no dwWorkshopCtrl_Startup needed (soft-reset rule).

#include "Dw/dwTypes.h"
#include "Dw/dwRect.h"

#ifdef __cplusplus
struct dwWorkshopCtrl;
struct dwWcButtonBlink;
struct dwWcEntryPanel;
struct dwWcMaterials;
struct dwWcBlueprints;
struct dwWcChildDecorator;
struct dwWcPalette;
extern "C" {
#else
// C++ classes; opaque in the C view.
typedef struct dwWorkshopCtrl dwWorkshopCtrl;
typedef struct dwWcButtonBlink dwWcButtonBlink;
typedef struct dwWcEntryPanel dwWcEntryPanel;
typedef struct dwWcMaterials dwWcMaterials;
typedef struct dwWcBlueprints dwWcBlueprints;
typedef struct dwWcChildDecorator dwWcChildDecorator;
typedef struct dwWcPalette dwWcPalette;
#endif

// (no C-callable entry points — section kept for symmetry)

#ifdef __cplusplus
} // extern "C"

#include "Dw/dwWidget.h"
#include "Dw/dwWidgetGroup.h"
#include "Dw/dwAnim.h" // dwAnimBase (dwWcMaterials base) + dwAnim player
#include "Dw/dwString.h"
#include "Dw/dwList.h"
#include "Dw/dwImage.h"

struct dwGuiHypText; // Dw/dwGuiHypText.h (only pointers held here)
struct dwPart;       // Dw/dwPart.h — blueprint records (dwWcBlueprints grid)

// ---- dwWorkshopCtrl -----------------------------------------------------------
//
// Binary layout: dwWidget base @0x00 (0xe) + fields from 0x10 — sizeof 0x50.
// dwWorkshopCtrl_vtbl, 19 slots: dwWidget's 18 plus ONE
// new virtual appended after +0x44 Draw:
//   +0x48 HitTest(x, y) -> bool dwWorkshopCtrl_HitTest — the overridable point-on-control
//   test used by the mouse handlers (distinct from dwWidget's +0x38
//   HitTest(dwPoint*) -> widget*, which stays the base implementation).
//
// Behavior: a momentary (bToggle == 0) or toggling (bToggle != 0) image
// button. bHot is the visual "pressed/lit" state (selects pImagePressed in
// Draw); bPressed latches the mouse capture for the momentary mode. The
// button dispatches { cmdId, 0, 0, NULL } to dwWidget_pDefault on toggle
// (mouse-down) or on release-over-the-button (mouse-up), plays sndClick when
// turning on and sndOff when turning off, and notifies hover as
// { 0x7531, cmdId }.

struct dwWorkshopCtrl : dwWidget
{
    dwImage* pImageNormal;      // 0x10: lazily loaded from imageNameNormal
    dwString imageNameNormal;   // 0x14
    dwString sndOff;            // 0x20: sound when turning OFF (may be empty)
    dwImage* pImagePressed;     // 0x2c: lazily loaded from imageNamePressed
    dwString imageNamePressed;  // 0x30
    dwString sndClick;          // 0x3c: sound when turning ON (defaults to
                                //       "CGenButton.wav" when empty)
    int32_t cmdId;              // 0x48: command dispatched to the screen
    uint8_t bToggle;            // 0x4c: 0 = momentary, 1 = toggle (TOGGLE keyword)
    uint8_t bPressed;           // 0x4d: momentary press latched (mouse captured)
    uint8_t bHot;               // 0x4e: visual on/pressed state

    // dwWorkshopCtrl_Ctor — dwWidget(pRect); assigns both image
    // names, EnsureImages()es immediately, and defaults sndClick to
    // "CGenButton.wav" when pSndClick was empty/NULL.
    dwWorkshopCtrl(dwRect* pRect, char* pImgNormal, char* pSndOff,
                   char* pImgPressed, char* pSndClick, int cmdId, uint8_t bToggle);

    // dwWorkshopCtrl_Dtor (scalar-deleting wrapper dwWorkshopCtrl_DtorDelete) —
    // FreeImages + the four string frees (member dtors here).
    virtual ~dwWorkshopCtrl();

    // vtbl +0x04 dwWorkshopCtrl_OnMouseMove — only while bPressed (momentary drag): track
    // HitTest(x, y) into bHot (+ Invalidate on change). Returns bPressed.
    virtual int OnMouseMove(int16_t x, int16_t y);
    // vtbl +0x08 dwWorkshopCtrl_OnMouseDown — toggle mode: flip bHot, play sndClick/sndOff,
    // Invalidate, dispatch { cmdId }. Momentary: latch bPressed/bHot,
    // capture dwWidget_pMouseTarget, play sndClick, Invalidate (no dispatch
    // until mouse-up). Returns whether the point hit.
    virtual int OnMouseDown(int16_t x, int16_t y);
    // vtbl +0x0c dwWorkshopCtrl_OnMouseUp — momentary only: release the capture; if it was
    // still hot: play sndOff, Invalidate, dispatch { cmdId }.
    virtual int OnMouseUp(int16_t x, int16_t y);
    // vtbl +0x18 (shared COMDAT, Ghidra: dwGuiTextPopup_OnHover) —
    // dispatch { 0x7531, (void*)cmdId, 0, NULL }; return 1.
    virtual int OnHover(int16_t x, int16_t y);
    // vtbl +0x3c (Ghidra: dwWorkshopCtrl_EnsureImagesLoaded) — lazy
    // dwImage_LoadFile of both images (NULL-guarded: LoadFile is a P8 stub).
    virtual void EnsureImages();
    // vtbl +0x40 dwWorkshopCtrl_FreeImages — delete both images.
    virtual void FreeImages();
    // vtbl +0x44 dwWorkshopCtrl_Draw — EnsureImages, then blit pImagePressed when bHot
    // else pImageNormal at (left, top).
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);

    // NEW virtual — appended after dwWidget's +0x44 Draw.
    // vtbl +0x48 (Ghidra: dwWorkshopCtrl_HitTest) — 1 when (x, y) is
    // inside the widget rect (left/top incl., right/bottom excl.).
    // Subclasses override for non-rectangular hit shapes.
    virtual int HitTest(int16_t x, int16_t y);
    using dwWidget::HitTest; // keep the +0x38 HitTest(dwPoint*) visible
};

// ---- dwWcButtonBlink -----------------------------------------------------------
//
// Binary layout: dwWorkshopCtrl @0x00 + own fields from 0x50 — sizeof 0x74.
// dwWcButtonBlink_vtbl. BUTTON_BLINK: while blinking, the button alternates
// between its normal image and pBlinkImage every 0.5s (constants =
// 0.5f period, = 0.0f threshold), playing blinkSound on each
// visible flip. Clicking the button stops the blink.

struct dwWcButtonBlink : dwWorkshopCtrl
{
    dwImage* pBlinkImage;    // 0x50: lazily loaded from blinkImageName
    dwString blinkImageName; // 0x54
    dwString blinkSound;     // 0x60: optional per-flip sound
    uint8_t bBlinking;       // 0x6c
    uint8_t bBlinkState;     // 0x6d: current phase (1 = blink image shown)
    float blinkTimer;        // 0x70: seconds until the next flip

    // dwWcButtonBlink_Ctor — base(..., cmdId, /*bToggle*/0);
    // assigns blinkImageName (always) and blinkSound (only when non-NULL),
    // EnsureImages()es immediately.
    dwWcButtonBlink(dwRect* pRect, char* pImgNormal, char* pSndOff,
                    char* pImgPressed, char* pSndClick, char* pBlinkImg,
                    char* pBlinkSnd, int cmdId);

    // dwWcButtonBlink_Dtor (scalar-deleting wrapper dwWcButtonBlink_DtorDelete)
    virtual ~dwWcButtonBlink();

    // vtbl +0x0c dwWcButtonBlink_OnMouseUp (recovered fn, no Ghidra name) — base OnMouseUp;
    // when the click completed (was hot, now not), stop blinking.
    virtual int OnMouseUp(int16_t x, int16_t y);
    // vtbl +0x14 dwWcButtonBlink_Update — blink timing: while bBlinking, count blinkTimer
    // down by dt; on each 0.5s underflow flip bBlinkState; if the phase
    // changed: Invalidate + play blinkSound.
    virtual void Update(float dt);
    // vtbl +0x18 dwWcButtonBlink_OnHover (recovered fn) — dispatch { 0x7531, (void*)cmdId,
    // bBlinking ? 1 : 0, NULL }; return 1.
    virtual int OnHover(int16_t x, int16_t y);
    // vtbl +0x3c dwWcButtonBlink_EnsureImagesLoaded — base EnsureImages + lazy pBlinkImage load.
    virtual void EnsureImages();
    // vtbl +0x40 dwWcButtonBlink_FreeImages — delete pBlinkImage + base FreeImages.
    virtual void FreeImages();
    // vtbl +0x44 dwWcButtonBlink_Draw — image priority: bHot -> pImagePressed, else
    // blink phase -> pBlinkImage (when loaded), else pImageNormal.
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);

    // bBlinking = bBlinkState = 1; blinkTimer = 0.5s; Invalidate.
    void StartBlink();
    // bBlinking = bBlinkState = 0; Invalidate.
    void StopBlink();
};

// ---- dwWcEntryPanel -----------------------------------------------------------
//
// Binary layout: dwWidget @0x00 + fields from 0x10 — sizeof 0x40. vtable
// dwWcEntryPanel_vtbl. A popup info panel: a background image
// plus up to three simultaneously visible dwGuiHypText captions, each
// wrapped in a dwGuiTimer decorator for timed show/hide. Entries are added
// up front (AddEntry) and selected by id (OnMessage code / ShowById).

// One panel entry (0x38; freed by dwWcEntry_Dtor / dwWcEntry_DtorDelete
// _DtorDelete). Ghidra: /DW struct dwWcEntry.
struct dwWcEntry
{
    dwRect rect;       // 0x00 (Ghidra: field0/field4): caption rect (absolute)
    dwString text;     // 0x08 (Ghidra: strDisplay): caption text
    dwString fontName; // 0x14 (Ghidra: strAlt): caption font
    uint8_t color;     // 0x20 (Ghidra: colorIdx): glyph color index
    int32_t id;        // 0x24: entry id matched by OnMessage/ShowById
    int16_t kind;      // 0x28: caption slot selector (1/2/other; see ShowById)
    char* pMarkup;     // 0x2c: BORROWED reveal-value string spliced into the
                       //       hyptext format markup (not owned/freed)
    float showTime;    // 0x30: dwGuiTimer show delay (sec)
    float hideTime;    // 0x34: dwGuiTimer hide time (sec, 0 = never)

    dwWcEntry(dwRect rect, char* pText, char* pFontName, uint8_t color,
              int id, int16_t kind, char* pMarkup, float showTime, float hideTime);
    ~dwWcEntry(); // frees fontName then text
};

struct dwWcEntryPanel : dwWidget
{
    dwWidget* pTimer0;        // 0x10: dwGuiTimer wrapping pHypText0 (kind 1)
    dwWidget* pTimer1;        // 0x14: dwGuiTimer wrapping pHypText2 (kind 2)
    dwWidget* pTimer2;        // 0x18: dwGuiTimer wrapping pHypText1 (other kinds)
    dwList entries;           // 0x1c (Ghidra: pEntries): dwWcEntry* payloads
    dwGuiHypText* pHypText0;  // 0x20: caption for kind == 1
    dwGuiHypText* pHypText1;  // 0x24: caption for other kinds
    dwGuiHypText* pHypText2;  // 0x28: caption for kind == 2
    dwImage* pImage;          // 0x2c: background image (lazy from name)
    dwString name;            // 0x30: background image filename
    void* pContext;           // 0x3c: OnHover notification payload

    // dwWcEntryPanel_Ctor — dwWidget(pRect); assigns the
    // background name, EnsureImages()es immediately.
    dwWcEntryPanel(dwRect* pRect, char* pName, void* pContext);

    // dwWcEntryPanel_Dtor (scalar-deleting wrapper dwWcEntryPanel_DtorDelete) —
    // FreeImages, delete the three timers (each deletes its wrapped
    // caption), free every entry + the list.
    virtual ~dwWcEntryPanel();

    // vtbl +0x14 dwWcEntryPanel_Update — tick the three timers (when enabled).
    virtual void Update(float dt);
    // vtbl +0x18 (shared COMDAT, Ghidra: dwGuiIndicator_OnHover) —
    // dispatch { 0x7531, pContext, 0, NULL }; return 1.
    virtual int OnHover(int16_t x, int16_t y);
    // vtbl +0x1c dwWcEntryPanel_OnMessage — show EVERY entry whose id == pMsg->code (the
    // loop does not stop at the first match). Returns 0.
    virtual int OnMessage(dwWidgetMsg* pMsg);
    // vtbl +0x3c (Ghidra: dwWcEntryPanel_EnsureImagesLoaded)
    virtual void EnsureImages();
    // vtbl +0x40 dwWcEntryPanel_FreeImages
    virtual void FreeImages();
    // vtbl +0x44 dwWcEntryPanel_Draw — blit the background at (left, top); then, ONLY
    // when all three captions exist, draw them (each clipped to its own
    // rect) in slot order 0, 2, 1.
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);

    // dwWcEntryPanel_AddEntry — append a dwWcEntry (rect BY VALUE,
    // as in the binary).
    void AddEntry(dwRect rect, char* pText, char* pFontName, uint8_t color,
                  int id, int16_t kind, char* pMarkup, float showTime, float hideTime);

    // dwWcEntryPanel_ShowById — show every entry whose id matches.
    void ShowById(int id);

    // Added: the shared per-entry show body (the binary duplicates this
    // sequence inline in OnMessage and ShowById; single helper here, same
    // behavior): kind selects the caption/timer slot pair (1 -> pHypText0/
    // pTimer0, 2 -> pHypText2/pTimer1, else pHypText1/pTimer2 — the
    // crosswiring is the binary's); delete the slot's old timer (which
    // deletes the old caption), build a dwGuiHypText with format
    // "DCO<entry->pMarkup>T" (Draw-shadowed/Center/wrap-none + typewriter
    // reveal), set its text, and wrap it in a dwGuiTimer(showTime, hideTime).
    void ShowEntry(dwWcEntry* pEntry);
};

// ---- dwWcMaterials -----------------------------------------------------------
//
// Binary layout: dwAnimBase @0x00 (primary MI base, 0x1c) + dwWidgetGroup
// @0x1c (secondary MI base, 0x14) + own fields from 0x30 — sizeof 0x68.
// vtables: primary dwWcMaterials_vtbl (dwAnimBase shape, 20 slots;
// +0x48/+0x4c stay dwAnimBase_Play/Stop), secondary dwWcMaterials_group_vtbl
// (dwWidgetGroup shape; overridden slots are this-adjustor thunks).
// Same MI pattern as dwGuiAnimView — real C++ MI here.
//
// Role: the workshop's material panel. Two label rows (built by AddLabel as
// disabled dwGuiHypText group children; row A at top+5, row B at top+0xa0)
// each cycle WOOD(7) -> RUBBER(8) -> GLASS(9) on their message codes (0x1bc8
// row A / 0x1bc9 row B); the currently selected label per row is the enabled
// one (pSwatchA/pSwatchB). Each material COMBINATION maps to an item
// (AddEntry) carrying an anim + still image, keyed by code = 0x1bbc +
// matIdxA + matIdxB (+2 when A==RUBBER, +4 when A==GLASS); message 0x1b62
// plays the matching item's anim, 0x1b63 stops it.

// One material item (0x2c; freed by dwWcMaterialsEntry_Dtor /
// dwWcMaterialsEntry_DtorDelete _DtorDelete). Same shape as dwGuiAnimViewItem.
struct dwWcMaterialsEntry
{
    dwString animFile;  // 0x00 (Ghidra: name): .FLC for this combination
    int32_t code;       // 0x0c (Ghidra: value): 0x1bbc-based combination code
    uint8_t flag;       // 0x10: stored by AddEntry, never read in this unit
    dwString imageFile; // 0x14 (Ghidra: textA): still image for this combination
    dwString extraFile; // 0x20 (Ghidra: textB): stored, never read in this unit

    dwWcMaterialsEntry(char* pAnimFile, int code, uint8_t flag,
                       char* pImageFile, char* pExtraFile);
    ~dwWcMaterialsEntry();
};

struct dwWcMaterials : dwAnimBase, dwWidgetGroup
{
    dwList items;             // 0x30 (Ghidra: pItems): dwWcMaterialsEntry* payloads
    int32_t msgSwatchA;       // 0x34 (Ghidra: msgCode0) = 0x1bc8: row-A cycle message
    int32_t msgSwatchB;       // 0x38 (Ghidra: msgCode1) = 0x1bc9: row-B cycle message
    int32_t curCode;          // 0x3c (Ghidra: msgCode2): scratch combination code,
                              //      reset to 0x1bbc at the end of every OnMessage
    dwAnim* pAnim;            // 0x40 (Ghidra: field_40): current combination anim
    int32_t matIdxA;          // 0x44 (Ghidra: matIdx): row-A material (7/8/9)
    int32_t matIdxB;          // 0x48 (Ghidra: matIdxDefault): row-B material (7/8/9)
    dwGuiHypText* pSwatchA;   // 0x4c (Ghidra: swatchA): row A's enabled label
    dwGuiHypText* pSwatchB;   // 0x50 (Ghidra: swatchB): row B's enabled label
    dwImage* pImage;          // 0x54: current still image
    void* pContext;           // 0x58: OnHover notification payload
    dwString imageName;       // 0x5c (Ghidra: name): current still-image filename

    // dwWcMaterials_Ctor — dwAnimBase(pRect, 0, 1) +
    // dwWidgetGroup(pRect); assigns the still-image name, EnsureImages()es,
    // then matIdxA = matIdxB = 7 (WOOD).
    dwWcMaterials(dwRect* pRect, char* pImageName, void* pContext);

    // dwWcMaterials_Dtor (scalar-deleting wrapper dwWcMaterials_DtorDelete, group
    // thunk dwWcMaterials_DtorDelete_Thunk) — FreeImages, delete pAnim, free every item + the item
    // list (group children/imageName/bases implicit here).
    virtual ~dwWcMaterials();

    // vtbl +0x14 dwWcMaterials_Update (group thunk dwWcMaterials_Update_Thunk) — tick pAnim (when enabled),
    // then the group children.
    virtual void Update(float dt);
    // vtbl +0x18 dwWcMaterials_OnHover (group thunk dwWcMaterials_OnHover_Thunk) — dispatch { 0x7531,
    // pContext, 0, NULL }; return 1.
    virtual int OnHover(int16_t x, int16_t y);
    // vtbl +0x1c dwWcMaterials_OnMessage (group thunk dwWcMaterials_OnMessage_Thunk) — the material logic (see
    // the class comment); chains to dwAnimBase::OnMessage.
    virtual int OnMessage(dwWidgetMsg* pMsg);
    // vtbl +0x3c dwWcMaterials_EnsureImagesLoaded (group thunk dwWcMaterials_EnsureLoaded_Thunk; Ghidra:
    // dwWcMaterials_EnsureImagesLoaded) — lazy still image + group children.
    virtual void EnsureImages();
    // vtbl +0x40 dwWcMaterials_FreeImages (group thunk dwWcMaterials_FreeImages_Thunk) — drop the still image +
    // group children.
    virtual void FreeImages();
    // vtbl +0x44 dwWcMaterials_Draw (group thunk dwWcMaterials_Draw_Thunk) — when enabled: still image
    // at the GROUP rect origin + pAnim (clipped to its rect); the two
    // enabled swatch labels are drawn even when disabled as a whole.
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);

    // select row A's / row B's label whose text equals
    // the (dwCore_pGlobalStrings-localized) material name: disable the old
    // enabled label, enable the match, Invalidate the group.
    void HighlightSwatchA(char* pMatName);
    void HighlightSwatchB(char* pMatName);

    // append a dwWcMaterialsEntry to items.
    void AddEntry(char* pAnimFile, int code, uint8_t flag, char* pImageFile, char* pExtraFile);

    // push-front a DISABLED dwGuiHypText label child at
    // (pos + group origin, size), format "BLN" (wrap/left/normal), showing
    // pText. The material rows are built from these.
    void AddLabel(char* pText, dwPoint pos, dwPoint size, uint8_t color, char* pFontName);

    // swap in the FIRST item's still image (when it has one) and
    // highlight WOOD on both rows.
    void RefreshSelection();

    // (Ghidra: dwWcMaterials_ClearItems) — helper: unlink+free every
    // node of a list, virtually deleting non-NULL payloads (sentinel kept).
    // Used on the group children in the binary dtor; ~dwWidgetGroup covers
    // that here. (dwWcMaterials_ListCopyHead is a trivial iterator
    // COMDAT — not translated.)
};

// ---- dwWcBlueprints -----------------------------------------------------------
//
// Binary layout: dwWidget @0x00 + fields from 0x10 — sizeof 0x38 (alloc size
// in dwWorkshop_CreateControl; the Ghidra /DW struct is 8 bytes short).
// dwWcBlueprints_vtbl. The blueprint fly-out: BuildGrid lays out every
// AVAILABLE blueprint whose slot mask and part type pass the current filters
// into a grid; Draw renders a translucent cone (widget-left mid-height ->
// the grid's left edge) and the blueprint images (hovered one full-color,
// the rest through the colormap). While shown it CAPTURES the mouse
// (dwWidget_pMouseTarget = this); clicking a cell dispatches the selection,
// clicking elsewhere closes and re-forwards the click.
//
// Messages: 0x7e4 (body type 1/2) -> slotMask; 0x7e5 (part-type bits from
// dwWcBuildButton) -> typeBits + BuildGrid/Invalidate; 0x7e6 -> Hide.
// Cell click: { 0x7d1, pBlueprint } + { 0x7e6, pBlueprint }; hover cell:
// { 0x7d0, pBlueprint }.

struct dwWcBlueprints : dwWidget
{
    int16_t xIndent;      // 0x10 (Ghidra: cols — misnamed): grid x indent from left (ctor arg)
    int16_t gridX;        // 0x12: left edge of the grid
    int16_t gridTop;      // 0x14
    int16_t gridRight;    // 0x16
    int16_t gridBottom;   // 0x18
    uint8_t bShown;       // 0x1a: fly-out is open
    uint8_t backdropColor;// 0x1b: cone blend color (0x46)
    uint32_t slotMask;    // 0x1c: blueprint slot-mask filter (init 1; msg 0x7e4)
    uint32_t typeBits;    // 0x20: 1<<type filter bits (init 0; msg 0x7e5)
    dwPart* pHover;       // 0x24: hovered blueprint record (Dw/dwPart.h)
    dwRect hoverRect;     // 0x28: screen rect of the hovered cell
    int16_t cellW;        // 0x30: widest eligible blueprint image
    int16_t cellH;        // 0x32: tallest eligible blueprint image
    int16_t cols;         // 0x34: grid columns
    // (0x36 pad)

    // dwWcBlueprints_Ctor — dwWidget(pRect); zeroes state.
    // Note: cellW/cellH/cols stay unset until BuildGrid in the binary;
    // zero-initialized here.
    dwWcBlueprints(dwRect* pRect, int16_t xIndent);

    // dwWcBlueprints_Dtor (scalar-deleting wrapper dwWcBlueprints_DtorDelete) —
    // Hide() when still shown.
    virtual ~dwWcBlueprints();

    // vtbl +0x04 dwWcBlueprints_OnMouseMove — hover tracking: map the point to a grid cell,
    // walk the filtered blueprint list to that index, dispatch { 0x7d0,
    // pBlueprint } and update pHover/hoverRect (dirty rects on change).
    // Returns 0 (the capture keeps feeding it).
    virtual int OnMouseMove(int16_t x, int16_t y);
    // vtbl +0x08 dwWcBlueprints_OnMouseDown — inside the hovered cell: play WSelectModel.wav,
    // dispatch { 0x7d1, pHover } + { 0x7e6, pHover }. Elsewhere: dispatch
    // { 0x7e6 }, Hide(), and re-forward the click to the released target.
    virtual int OnMouseDown(int16_t x, int16_t y);
    // vtbl +0x1c dwWcBlueprints_OnMessage
    virtual int OnMessage(dwWidgetMsg* pMsg);
    // vtbl +0x44 dwWcBlueprints_Draw
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);

    // measure the eligible blueprints, lay out the grid (rows
    // balanced; a single row of more than 3 becomes two), clear the hover
    // state, set bShown and CAPTURE the mouse. (The mouse capture happens
    // even when nothing is eligible — binary quirk.)
    void BuildGrid();
    // release the capture, clear bShown, Invalidate.
    void Hide();
};

// ---- dwWcChildDecorator -----------------------------------------------------------
//
// Binary layout: dwWidget @0x00 + dwWidget* pChild @0x10 — sizeof 0x14.
// dwWcChildDecorator_vtbl. Single-child forwarding
// decorator: every virtual forwards to pChild (Enable/Disable/Move also
// update this widget's own state; Draw goes through DrawChild). The dtor
// FreeImages()es and DELETES the child. Subclasses: dwWcPalette (below) and
// dwGuiTimer (dwGuiTextMisc unit, later).

struct dwWcChildDecorator : dwWidget
{
    dwWidget* pChild; // 0x10: owned

    // No standalone binary ctor — subclasses inline this exact sequence
    // (widget rect copied FROM the child, e.g. dwWcPalette_Ctor).
    dwWcChildDecorator(dwWidget* pChildWidget);

    virtual ~dwWcChildDecorator();                    // dwWcChildDecorator_DtorDelete
    virtual int OnMouseMove(int16_t x, int16_t y);
    virtual int OnMouseDown(int16_t x, int16_t y);
    virtual int OnMouseUp(int16_t x, int16_t y);
    virtual int OnKey(int key, int repeat);
    virtual void Update(float dt);
    virtual int OnHover(int16_t x, int16_t y);
    virtual int OnMessage(dwWidgetMsg* pMsg);
    virtual void Enable();                            // own bEnabled + child
    virtual void Disable();
    virtual void Move(int16_t dx, int16_t dy);        // own rect + child
    virtual void EnsureImages();                      // Ghidra: dwWcChildDecorator_EnsureLoaded
    virtual void FreeImages();
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect); // pChild->DrawChild
};

// ---- dwWcPalette -----------------------------------------------------------
//
// Binary layout: dwWcChildDecorator @0x00 + fields from 0x14 — sizeof 0x20.
// dwWcPalette_vtbl (only the dtor and OnMessage differ
// from the decorator base). The build/paint TOOL PALETTE: its child cycles
// build button -> WBuildPaint.flc -> paint button -> WPaintBuild.flc ->
// build button, driven by messages 0x7e7/0x7e8 (mode requests from the
// BUILD/PAINT toggle) and the FLC finish notifications (0x2328 re-dispatched
// as 0x7e9/0x7ea). Message 0x7eb runs the droid RANDOMIZE (confirmation
// dialog + dwDroidStats_AutoBuildRandom).
//
// modes: 0 = build button ("wcbuildn" biped / "wcbuildc" cargo by variant),
// 1 = paint button, 2 = build->paint anim, 3 = paint->build anim.

struct dwWcPalette : dwWcChildDecorator
{
    int32_t mode;              // 0x14
    int32_t variant;           // 0x18: body type (1 biped / 2 cargo; msg 0x7e4)
    uint8_t bRandomConfirmed;  // 0x1c (Ghidra: flag): RANDOMIZE re-confirm latch
                               //      (cleared by msg 0x7dd)

    // dwWcPalette_Ctor — child = new dwWcBuildButton("wcbuildn",
    // pRect); decorator base takes the child's rect; mode 0, variant 1.
    dwWcPalette(dwRect* pRect);

    // dwWcPalette_Dtor (scalar-deleting wrapper dwWcPalette_DtorDelete) — body is
    // exactly the decorator dtor (no own resources).
    virtual ~dwWcPalette();

    // vtbl +0x1c dwWcPalette_OnMessage — the mode/randomize logic; ALWAYS forwards the
    // message to the child afterwards.
    virtual int OnMessage(dwWidgetMsg* pMsg);

    // swap the child for the given mode (deletes the old child).
    void SetMode(int newMode);
};

#endif // __cplusplus

#endif // _DWWORKSHOPCTRL_H
