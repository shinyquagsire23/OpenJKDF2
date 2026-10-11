#ifndef _DWGUIBUTTON_H
#define _DWGUIBUTTON_H

// dwGuiButton — the DroidWorks "button blob" (.bbl) control family:
//
//   dwGuiButton     (0x38, dwGuiButton_vtbl) — multi-frame image button loaded
//                   from a .bbl conf file (COUNT/BUTTON/ALLUP/MASK/STICKY/
//                   RADIO keywords). Hit-testing reads the MASK image's
//                   pixel value = the button id under the cursor. Appends
//                   TWO new virtuals after dwWidget's +0x44 Draw:
//                   +0x48 OnButtonPressed(id) / +0x4c OnButtonReleased(id)
//                   (both default no-ops) — the subclass action hooks.
//   dwGuiTextButton (0x78, dwGuiTextButton_vtbl) — text-caption push button
//                   (BUTTON_TEXT[_LEFT] keywords); derives dwWorkshopCtrl.
//   dwGuiZoomBox    (0x34, dwGuiZoomBox_vtbl) — animated zoom/targeting reticle:
//                   crosshair bars converge on a point, then a palette-
//                   cycled triple circle flashes.
//   dwGuiClock      (0x20, dwGuiClock_vtbl) — HH:MM:SS elapsed-time display
//                   (CLOCK keyword).
//
// This header ALSO declares the dwGuiButton subclasses OWNED BY THE
// dwWorkshopCtrl COMPILE UNIT (their method bodies are in dwWorkshopCtrl.cpp,
// mirroring the binary's unit layout): dwWcArrows, dwWcBuildButton,
// dwWcPaintButton, dwWcBuildPaintButton, dwWcCargoNormalButton. They live
// here because they need the dwGuiButton base while dwGuiTextButton needs
// dwWorkshopCtrl — so dwGuiButton.h includes dwWorkshopCtrl.h (acyclic).
//
// Decompiled from DroidWorks.exe (+ the wc-button bodies). Verifiably C++ ->
// C++ classes.
//
// No module statics — no dwGuiButton_Startup needed (soft-reset rule).

#include "Dw/dwTypes.h"
#include "Dw/dwRect.h"

#ifdef __cplusplus
struct dwGuiButton;
struct dwGuiTextButton;
struct dwGuiZoomBox;
struct dwGuiClock;
struct dwWcArrows;
struct dwWcBuildButton;
struct dwWcPaintButton;
struct dwWcBuildPaintButton;
struct dwWcCargoNormalButton;
extern "C" {
#else
// C++ classes; opaque in the C view.
typedef struct dwGuiButton dwGuiButton;
typedef struct dwGuiTextButton dwGuiTextButton;
typedef struct dwGuiZoomBox dwGuiZoomBox;
typedef struct dwGuiClock dwGuiClock;
typedef struct dwWcArrows dwWcArrows;
typedef struct dwWcBuildButton dwWcBuildButton;
typedef struct dwWcPaintButton dwWcPaintButton;
typedef struct dwWcBuildPaintButton dwWcBuildPaintButton;
typedef struct dwWcCargoNormalButton dwWcCargoNormalButton;
#endif

// (no C-callable entry points — section kept for symmetry)

#ifdef __cplusplus
} // extern "C"

#include "Dw/dwWidget.h"
#include "Dw/dwWorkshopCtrl.h" // dwGuiTextButton base
#include "Dw/dwString.h"
#include "Dw/dwImage.h"
#include "Dw/dwFont.h"

// ---- dwGuiButton -----------------------------------------------------------
//
// Binary layout: dwWidget base @0x00 (0xe) + fields from 0x10 — sizeof 0x38.
// dwGuiButton_vtbl (unlabeled in Ghidra: "dwWorkshopCtrl_vtbl[20]"), 20
// slots: dwWidget's 18 + the two action hooks (defaults dwGui_NullVirtual
// dwGui_NullVirtual).
//
// .bbl grammar (ParseBlob): COUNT %lu (button frames), BUTTON <id> <image>,
// ALLUP <image> (the no-button-shown frame), MASK <image> (8bpp id mask),
// STICKY (press latches), RADIO (implies STICKY; can't untoggle by
// re-clicking). shownButtonId selects the drawn frame (0 = ALLUP);
// activeButtonId tracks the pressed interaction.

struct dwGuiButton : dwWidget
{
    uint8_t bSticky;          // 0x10
    uint8_t bRadio;           // 0x11
    int32_t activeButtonId;   // 0x14
    int32_t shownButtonId;    // 0x18
    int32_t numButtons;       // 0x1c
    dwImage* hAllUpImage;     // 0x20
    dwImage** paButtonImages; // 0x24: numButtons entries (lazy)
    dwImage* hMaskImage;      // 0x28: hit-test id mask
    dwString* pAllUpName;     // 0x2c
    dwString** paButtonNames; // 0x30: numButtons entries
    dwString* pMaskName;      // 0x34

    // dwGuiButton_Ctor — dwWidget(pRect); ParseBlob("<pName>.bbl")
    // then EnsureImages() immediately.
    dwGuiButton(char* pName, dwRect* pRect);

    // dwGuiButton_Dtor (scalar-deleting wrapper dwGuiButton_DtorDelete, COMDAT
    // copy dwWcButton_DtorDelete shared by several subclass vtables)
    virtual ~dwGuiButton();

    // vtbl +0x04 dwGuiButton_OnMouseMove — while a non-sticky press is active: track
    // whether the cursor is still on the pressed button id into
    // shownButtonId (+ Invalidate on change). Returns 0.
    virtual int OnMouseMove(int16_t x, int16_t y);
    // vtbl +0x08 dwGuiButton_OnMouseDown — id = HitTest(x, y); SetPressed(id); non-sticky
    // also captures the mouse + Invalidates. Returns id != 0.
    virtual int OnMouseDown(int16_t x, int16_t y);
    // vtbl +0x0c dwGuiButton_OnMouseUp — non-sticky release: clear the shown frame,
    // OnButtonPressed(id) when released over the pressed button.
    virtual int OnMouseUp(int16_t x, int16_t y);
    // vtbl +0x3c (Ghidra: dwGuiButton_EnsureImagesLoaded) — lazy
    // ALLUP/frames/mask loads (mask via the 16bpp RLE loader — P8 stub).
    virtual void EnsureImages();
    // vtbl +0x40 dwGuiButton_FreeImages
    virtual void FreeImages();
    // vtbl +0x44 dwGuiButton_Draw — frame = paButtonImages[shownButtonId-1] when a
    // frame is shown, else the ALLUP image; blit at (left, top).
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);

    // NEW virtuals — appended after dwWidget's +0x44 Draw; both default
    // no-ops (dwGui_NullVirtual). NOTE the Ghidra names of the
    // dwWcArrows overrides ("dwWcArrows_HitTest"/"dwWcArrows_OnAction") are
    // misleading — these slots are the press/release ACTION hooks:
    // vtbl +0x48 — a button was activated (sticky SetPressed, or a
    // completed non-sticky click over buttonId).
    virtual void OnButtonPressed(int buttonId);
    // vtbl +0x4c — a button was deactivated (toggle-off / radio switch /
    // momentary release).
    virtual void OnButtonReleased(int buttonId);

    // -- non-virtual methods ---------------------------------------------------

    // dwGuiButton_HitTest — button id under (x, y): 0 unless the
    // point is in the widget rect and the MASK image is loaded; reads the
    // mask pixel at (x-left, y-top) as the id. QUIRK preserved: BOTH the x
    // and y bounds pre-checks compare against the mask WIDTH.
    int HitTest(int16_t x, int16_t y);
    using dwWidget::HitTest; // keep the +0x38 virtual HitTest(dwPoint*) visible

    // the state machine: re-press of the shown button toggles it
    // off (unless RADIO); a new id releases the old one, becomes
    // active+shown, and fires OnButtonPressed when STICKY.
    void SetPressed(int buttonId);
    // clear active/shown; OnButtonReleased(old) when one was shown.
    void ClearPressed();

    // dwGuiButton_FreeResources — virtual FreeImages(), then free
    // the three name strings + the name array.
    void FreeResources();
    // dwGuiButton_ParseBlob — (re)load the .bbl file (syntax
    // errors logged; the binary's log fn jk_logtofile is a retail no-op).
    void ParseBlob(char* pFilePath);
};

// ---- dwWorkshopCtrl-unit subclasses (bodies in dwWorkshopCtrl.cpp) --------------

// ARROWBALL "wcarrows.bbl" rotate control (dwWcArrows_vtbl, no new fields).
// Buttons 1-4 = rotate arrows (held: commands repeat via press/release on
// mouse-move), button 5 = position reset. Command table[id]:
// { 0x7de, 0x7df, 0x7e0, 0x7e1, 0x7db }.
struct dwWcArrows : dwGuiButton
{
    dwWcArrows(dwRect* pRect);                        // dwWcArrows_Ctor
    virtual ~dwWcArrows();                            // dwWcArrows_DtorDelete
    virtual int OnMouseMove(int16_t x, int16_t y);    // base, then press/release the arrow under the cursor
    virtual int OnMouseDown(int16_t x, int16_t y);    // base, then press the arrow immediately (hold-to-rotate)
    virtual int OnHover(int16_t x, int16_t y);        // dispatch { 0x7531, 0x7de }; return 1
    virtual void OnButtonPressed(int buttonId);       // Ghidra: dwWcArrows_HitTest — misnamed
    virtual void OnButtonReleased(int buttonId);      // Ghidra: dwWcArrows_OnAction
};

// Part-category picker (dwWcBuildButton_vtbl; "wcbuildn"/"wcbuildc" .bbl by body
// type — see dwWcPalette). Pressing button id 1-6 dispatches the part-type
// bit set { 0x18a, 0x20, 0x14, 0x200, 0x1, 0x40 } as { 0x7e5, bits } (opens
// the dwWcBlueprints fly-out); releasing dispatches { 0x7e6 } (closes it).
struct dwWcBuildButton : dwGuiButton
{
    dwWcBuildButton(char* pName, dwRect* pRect);
    virtual ~dwWcBuildButton();                       // DtorDelete COMDAT dwWcButton_DtorDelete
    virtual int OnHover(int16_t x, int16_t y);        // (recovered fn) — { 0x7531, 0x7e5, hitId }
    virtual int OnMessage(dwWidgetMsg* pMsg);         // (recovered fn) — 0x7e6 -> ClearPressed
    virtual void OnButtonPressed(int buttonId);       // (recovered fn) — WPartButton.wav + { 0x7e5, bits }
    virtual void OnButtonReleased(int buttonId);      // (recovered fn) — { 0x7e6 }
};

// Paint-color picker "wcpaint.bbl" (dwWcPaintButton_vtbl). Pressing button id
// dispatches { 0x7d3, id } (select paint color id); releasing { 0x7d3, 0 }.
struct dwWcPaintButton : dwGuiButton
{
    dwWcPaintButton(dwRect* pRect);
    virtual ~dwWcPaintButton();                       // DtorDelete COMDAT dwWcButton_DtorDelete
    virtual int OnHover(int16_t x, int16_t y);        // (recovered fn) — { 0x7531, 0x7d3, hitId }
    virtual int OnMessage(dwWidgetMsg* pMsg);         // (recovered fn) — { 0x7d3, 0 } while shown -> ClearPressed
    virtual void OnButtonPressed(int buttonId);       // (recovered fn) — WPaintSelect.wav + { 0x7d3, id }
    virtual void OnButtonReleased(int buttonId);      // (recovered fn) — { 0x7d3, 0 }
};

// BUILD/PAINT mode toggle "wcbuildpaint.bbl" (dwWcBuildPaintButton_vtbl; ctor inlined in
// dwWorkshop_CreateControl, alloc 0x38). Button 1 = build (0x7e7),
// button 2 = paint (0x7e8).
struct dwWcBuildPaintButton : dwGuiButton
{
    // Binary: inline ctor — dwGuiButton("wcbuildpaint", pRect); SetPressed(2).
    dwWcBuildPaintButton(dwRect* pRect);
    virtual ~dwWcBuildPaintButton();
    virtual int OnHover(int16_t x, int16_t y);        // (recovered fn) — { 0x7531, hit==1 ? 0x7e7 : 0x7e8 }
    virtual void OnButtonPressed(int buttonId);       // (recovered fn) — { id==1 ? 0x7e7 : 0x7e8 } + Invalidate
    virtual void OnButtonReleased(int buttonId);      // (shared tiny body) — Invalidate only
};

// CARGO/NORMAL body-type switch "wccargonorm.bbl" (dwWcCargoNormalButton_vtbl; ctor
// inlined in dwWorkshop_CreateControl, alloc 0x3c). Button 1 =
// biped, button 2 = cargo; switching with parts in the workspace asks
// DLG_BUILDBIPED/DLG_BUILDCARGO (gyesno) and dispatches { 0x7d5 } (clear
// droid) + { 0x7e4, 1|2 } on confirm.
struct dwWcCargoNormalButton : dwGuiButton
{
    uint8_t bSuppressConfirm; // 0x38: skip the confirmation dialog (set by
                              //       the inline ctor around its initial
                              //       SetPressed(2))

    // Binary: inline ctor — dwGuiButton("wccargonorm", pRect);
    // bSuppressConfirm = 1; SetPressed(2); bSuppressConfirm = 0.
    dwWcCargoNormalButton(dwRect* pRect);
    virtual ~dwWcCargoNormalButton();
    virtual int OnHover(int16_t x, int16_t y);        // (recovered fn) — { 0x7531, 0x7e4 } when hit
    virtual int OnMessage(dwWidgetMsg* pMsg);         // (recovered fn) — 0x7e4: mirror the mode into shownButtonId
    virtual void OnButtonPressed(int buttonId);       // (recovered fn) — confirm + { 0x7d5 } + { 0x7e4, 1|2 }
    virtual void OnButtonReleased(int buttonId);      // (shared tiny body) — Invalidate only
};

// ---- dwGuiTextButton -----------------------------------------------------------
//
// Binary layout: dwWorkshopCtrl @0x00 + fields from 0x50 — sizeof 0x78.
// dwGuiTextButton_vtbl. A text push button drawn with
// dwFont (no images — the base ctor gets NULL image names): colorHot while
// hovered (bChecked) or pressed (bHot), optional hover sound, optional
// centered-wrapped draw. OnMouseDown/+0x48 HitTest/OnHover stay the
// dwWorkshopCtrl bases.

struct dwGuiTextButton : dwWorkshopCtrl
{
    uint8_t bChecked;      // 0x50: HOVER latch (mouse inside; captures the mouse)
    dwString labelText;    // 0x54
    uint8_t bAltDraw;      // 0x60: 1 = centered word-wrapped draw
    dwFont* hFont;         // 0x64: owned heap handle (dwFont_Load)
    uint8_t colorNormal;   // 0x68
    uint8_t colorHot;      // 0x69
    dwString secondaryText;// 0x6c: HOVER SOUND name (played on hover-enter)

    // dwGuiTextButton_Ctor — base(pRect, NULL, pSndOff, NULL,
    // pSndClick, cmdId, /*bToggle*/0); loads the font when given.
    dwGuiTextButton(dwRect* pRect, char* pLabel, char* pFontName,
                    uint8_t colorNormal, char* pSndOff, uint8_t colorHot,
                    char* pSndClick, char* pHoverSnd, int cmdId, uint8_t bAltDraw);

    // dwGuiTextButton_Dtor (scalar-deleting wrapper dwGuiTextButton_DtorDelete) —
    // frees the font handle (sithRender_Open = lone RET in the binary; the glyph
    // block is owned by the dwFont cache) + the two strings.
    virtual ~dwGuiTextButton();

    // vtbl +0x04 dwGuiTextButton_OnMouseMove — hover tracking while idle: HitTest(x, y) drives
    // bChecked (enter: capture + Invalidate + hover sound; leave: release +
    // Invalidate). While pressed/hot: clears bChecked and defers to the base.
    virtual int OnMouseMove(int16_t x, int16_t y);
    // vtbl +0x0c dwGuiTextButton_OnMouseUp — clear bChecked, then the base.
    virtual int OnMouseUp(int16_t x, int16_t y);
    // vtbl +0x44 dwGuiTextButton_Draw — color = (bChecked || bHot) ? colorHot :
    // colorNormal; bAltDraw ? dwFont_DrawTextCentered : dwFont_DrawText.
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);
};

// ---- dwGuiZoomBox -----------------------------------------------------------
//
// Binary layout: dwWidget @0x00 + fields from 0x10 — sizeof 0x34. vtable
// (unlabeled in Ghidra: "dwGuiTextButton_vtbl[20]"). Animated
// targeting reticle: SetTarget starts a 5-state easing sequence at a point —
// 1: circle shrinks from the far-corner distance to 5px,
// 2: (swap) crosshair grows back out to 20px at quarter speed,
// 3: crosshair shrinks to 5px (swap),
// 4: circle grows to 25px,
// 5: hold — triple circle with a palette-cycled flash color.
// States 2/3 draw crosshair bars, the others concentric circles.

struct dwGuiZoomBox : dwWidget
{
    float accumTime;     // 0x10: seconds in the current state (state 5: total)
    uint8_t color;       // 0x14: base color index
    dwPoint pt;          // 0x16: target point (SetTarget)
    float speed;         // 0x1c: base px/sec (ctor)
    float startRadius;   // 0x20
    float targetRadius;  // 0x24
    float curRadius;     // 0x28
    float curSpeed;      // 0x2c
    int32_t state;       // 0x30: 0 = idle, 1-5 as above

    // dwGuiZoomBox_Ctor
    dwGuiZoomBox(dwRect* pRect, float speed, uint8_t color);
    // dwGuiZoomBox_Dtor (scalar-deleting wrapper dwGuiZoomBox_DtorDelete)
    virtual ~dwGuiZoomBox();

    // vtbl +0x14 dwGuiZoomBox_Update — ease curRadius start->target at curSpeed; on
    // arrival advance the state (recursing with the overshoot time so the
    // animation stays continuous) and Invalidate.
    virtual void Update(float dt);
    // vtbl +0x44 dwGuiZoomBox_Draw
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);

    // dwGuiZoomBox_SetTarget — start the sequence at *pPt:
    // radius = distance to the farthest widget corner, target 5px, state 1.
    void SetTarget(dwPoint* pPt);
};

// ---- dwGuiClock -----------------------------------------------------------
//
// Binary layout: dwWidget @0x00 + fields from 0x10 — sizeof 0x20. vtable
// (unlabeled in Ghidra: "dwGuiTextButton_vtbl[44]"). Draws
// "%02u:%02u:%02u" centered in the widget rect; while bRunning the elapsed
// seconds are re-derived from the sith game clock each Draw (there is no
// Update override — the clock advances in Draw, binary quirk).

struct dwGuiClock : dwWidget
{
    dwFont* pFont;      // 0x10: owned heap handle
    uint8_t color;      // 0x14
    int32_t elapsedSec; // 0x18 (Ghidra: elapsedMs — misnamed; it is seconds)
    int32_t bRunning;   // 0x1c

    // dwGuiClock_Ctor — NOTE: rect passed BY VALUE in the binary.
    dwGuiClock(dwRect rect, char* pFontName, uint8_t color, int bRunning, int elapsedSec);
    // dwGuiClock_Dtor (scalar-deleting wrapper dwGuiClock_DtorDelete)
    virtual ~dwGuiClock();

    // vtbl +0x44 dwGuiClock_Draw — bRunning: elapsedSec = round(game ms * 0.001);
    // draw (elapsed/3600)%60 : (elapsed%3600)/60 : elapsed%60.
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);
};

#endif // __cplusplus

#endif // _DWGUIBUTTON_H
