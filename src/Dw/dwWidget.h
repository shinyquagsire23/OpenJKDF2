#ifndef _DWWIDGET_H
#define _DWWIDGET_H

// dwWidget — THE DroidWorks GUI base class. Every DW control/screen derives
// from this (or from dwWidgetGroup, which derives from this).
//
// Decompiled from DroidWorks.exe, unit range 0x442390-0x4429dx (ctor/dtor,
// Invalidate/DrawChild, the widget.rec input recorder and the shared Win32
// message pump dwWidget_MsgHandler), plus the base virtual default bodies
// that physically live in other units' ranges:
//   - no-op/stub defaults @0x401850-0x4018f6 (mis-binned as dwAnim)
//   - dwGui_NullVirtual @0x407ee0 (Update default, dwGuiButton unit)
//   - dwGui_OnMessageDefault @0x404220 (OnMessage default, dwWorkshopCtrl unit)
//   - no-op EnsureImages/FreeImages default @0x402cc0 (dwAnim unit)
//   - no-op Draw default @0x442540
//   - dwWidget_OnHoverNotify @0x419780 (shared COMDAT, dwHelp unit gap)
//   - dwWidget_DispatchMsg @0x444d00 (shared COMDAT, mislabeled
//     stdBitmapRle_FUN_00444d00 in Ghidra)
//
// Binary layout: { void* vptr@0x00; u8 bEnabled@0x04; i16 left@0x06,
// top@0x08, right@0x0a, bottom@0x0c } — sizeof 0xe; derived classes add
// fields from 0x10. The four inline shorts are a dwRect-compatible LTRB quad
// (see GetRectPtr()). The 64-bit translation keeps the field ORDER; offsets
// naturally differ (8-byte vptr).
//
// vtable @0x5200f8 (dwWidget_vtbl) — see the slot comments on the virtual
// methods below. Slot semantics (proven 2026-07-12, see DW/PROGRESS.md):
// +0x14 Update(dt) is the per-frame tick (NO drawing); +0x44 Draw is the
// actual dirty-rect-driven paint.
//
// Input routing: the FIRST widget constructed installs dwWidget_MsgHandler
// via Window_AddMsgHandler (refcounted by dwWidget_count; removed when the
// last widget dies). The handler routes keyboard messages to
// dwWidget_pDefault (the active screen) and mouse messages to
// dwWidget_pMouseTarget (falling back to pDefault), both only while
// target->bEnabled. Ctrl+Shift+RightClick toggles the widget.rec input
// recorder ('D'/'U'/'K' event lines, replayed by dwSegment_Tick).

#include "Dw/dwTypes.h"
#include "Dw/dwRect.h"

#ifdef __cplusplus
struct dwWidget; // C++ class below
extern "C" {
#else
typedef struct dwWidget dwWidget; // C++ class; opaque in the C view
#endif

// ---- Plain-C types + the one C-callable entry point ------------------------

typedef struct dwImageBits dwImageBits; // Dw/dwImage.h (plain-C struct)

// GUI notification/command message (built on the stack by senders; 0x10
// bytes in the binary). code 0 and -1 are "no message" and are never
// dispatched.
typedef struct dwWidgetMsg
{
    int32_t code;      // 0x00: command/notification id (e.g. 0x7531 hover)
    void* pSender;     // 0x04: sender-defined payload (usually the sending
                       //       control or its notify field)
    int32_t param;     // 0x08: extra parameter (zeroed by most senders)
    dwWidget* pTarget; // 0x0c: explicit target widget, or NULL to deliver to
                       //       dwWidget_pDefault
} dwWidgetMsg;

// Deliver a message to a widget's OnMessage (vtbl +0x1c). Target selection:
// pOverrideWidget if non-NULL, else pMsg->pTarget, else dwWidget_pDefault.
// Dispatches only when the target exists, is enabled, and pMsg->code is
// neither 0 nor -1; returns the handler's result, else 0.
// pMsg is a dwWidgetMsg* (void* keeps the C surface header-light — dwSound.c's
// finish-message dispatch calls this with an opaque pointer).
// @444d00 (Ghidra: stdBitmapRle_FUN_00444d00 — mislabeled; __thiscall on the
// msg, i.e. originally a dwWidgetMsg method)
uint32_t dwWidget_DispatchMsg(void* pMsg, void* pOverrideWidget);

// Note: no binary counterpart — resets the module globals/statics for
// OpenJKDF2's soft-reset loop (closes a live recording, uninstalls a stale
// msg handler if any widget leaked). C linkage so dwMain.c can wire it.
void dwWidget_Startup(void);

#ifdef __cplusplus
} // extern "C"

// ---- C++ class (verifiably C++ in the binary: vtable @0x5200f8 + ctor/dtor
// pairs + scalar-deleting dtor at slot 0) ------------------------------------

struct dwWidget
{
    // (vptr @0x00 in the binary)
    uint8_t bEnabled;                     // 0x04: input/tick gating flag
    int16_t left, top, right, bottom;     // 0x06..0x0d: widget rect (LTRB,
                                          // dwRect-compatible inline quad)

    // Full-screen widget: rect = (0, 0, mode width, mode height) from
    // stdDisplay_pCurVideoMode (binary global 0x6478f8). @442390
    dwWidget();
    // Widget covering *pRect. @442400
    dwWidget(dwRect* pRect);

    // Declaration order below == binary vtable slot order.
    // Warns (jk_logtofile) when destroying dwWidget_pDefault; clears the
    // pDefault/pMouseTarget globals when they point here; uninstalls
    // dwWidget_MsgHandler when the last widget dies.
    virtual ~dwWidget();                              // vtbl +0x00 @4423e0 (DtorDelete; body @442440, COMDAT copy @409fb0)
    virtual int OnMouseMove(int16_t x, int16_t y);    // vtbl +0x04 @401850 (default: return 0)
    virtual int OnMouseDown(int16_t x, int16_t y);    // vtbl +0x08 @401850 (default: return 0)
    virtual int OnMouseUp(int16_t x, int16_t y);      // vtbl +0x0c @401850 (default: return 0)
    virtual int OnKey(int key, int repeat);           // vtbl +0x10 @401850 (default: return 0)
    virtual void Update(float dt);                    // vtbl +0x14 @407ee0 (dwGui_NullVirtual) — per-frame tick, NO drawing
    virtual int OnHover(int16_t x, int16_t y);        // vtbl +0x18 @401850 (default: return 0)
    virtual int OnMessage(dwWidgetMsg* pMsg);         // vtbl +0x1c @404220 (dwGui_OnMessageDefault: return 0)
    virtual void Enable();                            // vtbl +0x20 @401860 (bEnabled = 1)
    virtual void Disable();                           // vtbl +0x24 @401870 (bEnabled = 0)
    virtual void Move(int16_t dx, int16_t dy);        // vtbl +0x28 @401880 (translate rect)
    virtual int ContainsPoint(dwPoint* pPt);          // vtbl +0x2c @4018a0 (left/top incl., right/bottom excl.)
    virtual void GetRect(dwRect* pRect);              // vtbl +0x30 @4018d0 — CLIPS *pRect to the widget rect (dwRect_Clip)
    virtual void Invalidate();                        // vtbl +0x34 @4424a0 (dwDisplay_AddDirtyRect on the widget rect)
    virtual dwWidget* HitTest(dwPoint* pPt);          // vtbl +0x38 @4018e0 (this if ContainsPoint, else NULL)
    virtual void EnsureImages();                      // vtbl +0x3c @402cc0 (default: no-op)
    virtual void FreeImages();                        // vtbl +0x40 @402cc0 (default: no-op)
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect); // vtbl +0x44 @442540 (default: no-op) — THE paint, dirty-rect driven

    // -- non-virtual methods --------------------------------------------------

    // Draw THIS widget as a child of a container: builds the effective clip
    // rect = dest bounds ∩ pClipRect (when non-NULL) ∩ this widget's rect
    // (via virtual GetRect), then calls virtual Draw with it — skipped when
    // the result is empty. Called per-child by dwWidgetGroup::Draw. @4424b0
    void DrawChild(dwImageBits* pDestBits, dwRect* pClipRect);

    // Shared COMDAT OnHover override body used by the dwGuiScrollBar /
    // dwGuiFindScrollBar / dwControlPanelHelpRect vtables (+0x18): dispatches
    // { code = 0x7531, pSender, 0, NULL } to dwWidget_pDefault and returns 1.
    // Note: the binary body has the OnHover(x, y) signature and reads the
    // DERIVED class's field at +0x10 as pSender; that raw offset does not
    // survive the 64-bit layout, so the sender is an explicit parameter here —
    // subclasses implement OnHover(x, y) as `return OnHoverNotify(<field>);`.
    // @419780
    int OnHoverNotify(void* pSender);

    // Added: the widget rect viewed as a dwRect (the binary passed &this->left
    // around as a rect pointer; the four shorts are layout-identical).
    dwRect* GetRectPtr() { return (dwRect*)&this->left; }
};

// ---- module globals (all reset by dwWidget_Startup) -------------------------

extern dwWidget* dwWidget_pDefault;     // binary: 0x541c00 — keyboard/message
                                        // target (the active screen; set by
                                        // dwGuiScreen and friends)
extern dwWidget* dwWidget_pMouseTarget; // binary: 0x541bfc — mouse-capture
                                        // target override (NULL -> pDefault)
extern int dwWidget_count;              // binary: 0x541c04 — live-widget
                                        // refcount for the msg-handler install
extern int dwWidget_bInputDisabled;     // binary: 0x541c18 — gates mouse input
                                        // (see DisableInput/EnableInput)
extern uint8_t dwWidget_bCaptured;      // binary: 0x541c08 — left button is
                                        // down (mouse captured)

// ---- free functions ----------------------------------------------------------

// Gate mouse input off/on (keyboard is unaffected). @4425c0 / @4425d0
void dwWidget_DisableInput();
void dwWidget_EnableInput();

// widget.rec input recorder (toggled by Ctrl+Shift+RightClick in the msg
// handler; the cue lines are replayed by dwSegment_Tick).
// RecordStart opens pFilename ("w") and arms recording (the start tick is
// latched on the first recorded event). @442550
void dwWidget_RecordStart(char* pFilename);
// @442590
void dwWidget_RecordStop();
// Append one "%09.4f\t%c\t%lu\t%lu\n" line (time in seconds since the first
// event; evt = 'D' mouse-down / 'U' mouse-up / 'K' key). @442960
void dwWidget_RecordEvent(char evt, uint32_t a, uint32_t b);

// The shared window message pump (WindowHandler_t; installed/removed by the
// dwWidget ctor/dtor refcount). Routes WM_KEYDOWN/WM_CHAR to
// dwWidget_pDefault->OnKey, WM_MOUSEMOVE/WM_LBUTTONDOWN/WM_LBUTTONUP to the
// mouse target, presents on WM_PAINT, and toggles the recorder on
// Ctrl+Shift+WM_RBUTTONDOWN. Always returns 0. @4425e0
int dwWidget_MsgHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, LRESULT* pResult);

#endif // __cplusplus

#endif // _DWWIDGET_H
