#ifndef _DWCONTROLPANEL_H
#define _DWCONTROLPANEL_H

// dwControlPanel — conf-driven container of hotspot controls, plus its inner
// dwControlPanelHelpRect help-hotspot widget.
//
// Decompiled from DroidWorks.exe, unit range 0x4096c0-0x409faf (9 functions;
// the trailing dwWidget-dtor COMDAT thunk @0x409fb0 belongs to dwWidget).
//
//   dwControlPanel     (0x28, vtbl 0x51e708) — dwWidgetGroup subclass built
//                      ONLY by dwGuiReference_CreateControl (keyword
//                      CONTROLPANEL: rect + help code + .cp filename). Parses
//                      its .cp conf file at construction (EnsureLoaded guard:
//                      only while the child list is empty) into child
//                      controls, one per conf line:
//                        RECT          -> dwGuiRefTile        (dwGuiReference, P6 — stubbed)
//                        HELPRECT      -> dwControlPanelHelpRect (below)
//                        BUTTON        -> dwWorkshopCtrl      (Dw/dwWorkshopCtrl.h)
//                        CP_RADIOGROUP -> dwGuiRefRadioGroup  (dwGuiReference, P6 — stubbed)
//                      OnHover forwards to the child under the cursor, else
//                      notifies the panel-default help code.
//   dwControlPanelHelpRect (0x14, vtbl 0x51e750) — invisible hover hotspot:
//                      a bare dwWidget whose OnHover dispatches
//                      { 0x7531, helpCode } to the active screen (the help
//                      control displays the matching help text). Also built
//                      by the shared screen factory (dwGuiScreen.cpp's
//                      HELPRECT branch — a wire-up once this lands).
//
// ⚠ dwControlPanel_Startup @0x4096c0 (called from dw_Startup) does NOT touch
// control-panel state: it only initializes the SHARED table
// dw_aPartSlotColors[10] (part connector-type -> DW palette color index for
// the 3D slot markers, read by dwPart_BuildModel and
// dwWorkshopDroidEditor_Draw). The table lives in this unit in the binary, so
// it is owned here.
//
// Compiled as C++ (vtables, ctor/dtor pairs, MSVC EH frames). The classes are
// C++-only; C consumers see the opaque typedefs plus the C-linkage surface
// below.

#include "Dw/dwTypes.h"
#include "Dw/dwRect.h"

#ifdef __cplusplus
struct dwControlPanel;         // C++ class below
struct dwControlPanelHelpRect; // C++ class below
extern "C" {
#else
typedef struct dwControlPanel dwControlPanel;                 // C++ class; opaque in the C view
typedef struct dwControlPanelHelpRect dwControlPanelHelpRect; // C++ class; opaque in the C view
#endif

// ---- C-linkage surface ------------------------------------------------------

// Part connector-type -> DW palette color index for the 3D slot markers.
// Binary: uchar[10] @0x53d6b8. Readers: dwPart_BuildModel +
// dwWorkshopDroidEditor_Draw (which special-cases type 6 -> [5]).
extern uint8_t dw_aPartSlotColors[10];

// Fill dw_aPartSlotColors with its constant table (the function's ONLY job —
// see the unit note above). Called from dw_Startup in the binary; the
// orchestrator wires dwMain_Startup to call this. @4096c0
void dwControlPanel_Startup(void);

#ifdef __cplusplus
} // extern "C"

#include "Dw/dwWidget.h"      // dwWidget base + dwWidgetMsg + dwImageBits
#include "Dw/dwWidgetGroup.h" // dwWidgetGroup base (child list + forwarding)
#include "Dw/dwString.h"
#include "Dw/dwConfFile.h"

struct dwStringTable; // Dw/dwStringTable.h (C++-only header; only a pointer here)

// ---- dwControlPanel -----------------------------------------------------------
//
// Binary layout: dwWidgetGroup base @0x00 (0x14) + fields from 0x14 — sizeof
// 0x28. vtable @0x51e708 (dwControlPanel_vtbl), the plain 18-slot dwWidget
// shape; overridden slots: +0x00 dtor, +0x18 OnHover, +0x44 Draw (a verbatim
// pass-through). Everything else is inherited from dwWidgetGroup.
//
// Child order note: LoadFromConf PREPENDS each parsed control
// (InsertAfter(pSentinel)), so the children iterate in REVERSE conf order —
// faithful to the binary (the last conf line wins OnHover ties).

struct dwControlPanel : dwWidgetGroup
{
    dwString confName;           // 0x14: the .cp conf filename (localized token
                                 //       from the CONTROLPANEL line)
    dwStringTable* pStringTable; // 0x20 (Ghidra: pScreen — really the owner
                                 //       screen's string table; only used for
                                 //       dwGuiScreen_LocalizeString in ParseControl)
    int32_t helpCode;            // 0x24 (Ghidra: pSourceConf — MISNOMER: the
                                 //       ParseULong'd panel-default help code,
                                 //       dispatched as { 0x7531, helpCode } when
                                 //       the cursor hovers empty panel space)

    // @409710 (dwControlPanel_Ctor) — dwWidgetGroup(pRect) (the binary passed
    // the 8-byte rect BY VALUE; a pointer here, same as every other control),
    // confName = pConfName, helpCode = code, pStringTable = pTable only when
    // non-NULL (pre-zeroed), then EnsureLoaded(): the .cp file is parsed at
    // construction, not lazily.
    dwControlPanel(dwRect* pRect, uint32_t code, char* pConfName, dwStringTable* pTable);

    // @4097b0 (dwControlPanel_Dtor; scalar-deleting wrapper @409790, vtbl
    // +0x00) — deletes every child + frees its list node itself (leaving the
    // ~dwWidgetGroup loops that follow as no-ops), then the confName dwString
    // dtor + base dtor run (binary order preserved by C++ dtor sequencing).
    virtual ~dwControlPanel();

    // vtbl +0x18 @409920 — forward hover to the FIRST child whose rect
    // contains (x, y) (left/top inclusive, right/bottom exclusive; NO enabled
    // check — reads the rect fields directly, not virtual ContainsPoint);
    // when no child hits, OnHoverNotify(helpCode) clears/retargets the help
    // display and returns 1.
    virtual int OnHover(int16_t x, int16_t y);

    // vtbl +0x44 @409f70 — verbatim pass-through to dwWidgetGroup::Draw
    // (kept as a real override to mirror the binary vtable).
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);

    // -- non-virtual methods --------------------------------------------------

    // Parse the .cp file only while the child list is empty (guard around
    // LoadFromConf(confName.pBuffer)). Only caller: the ctor. @409ab0
    void EnsureLoaded();

    // Open pFilename (whole body skipped when NULL), then per line:
    // ReadLine + NextToken -> ParseControl; every non-NULL control is
    // PREPENDED to children. Ends with virtual Invalidate() + Close.
    // Quirk (faithful): bEof is tested BEFORE each ReadLine, so the final
    // EOF-hitting line still runs through ParseControl. @4099d0
    void LoadFromConf(char* pFilename);

    // The keyword factory for one conf line (CP_RADIOGROUP consumes its item
    // lines too). Returns the new control or NULL (unknown keywords are
    // silently ignored — no log in the binary). @409ad0
    dwWidget* ParseControl(char* pKeyword, dwConfFile* pConf);
};

// ---- dwControlPanelHelpRect ---------------------------------------------------
//
// Binary layout: dwWidget base @0x00 (0xe) + helpCode @0x10 — sizeof 0x14.
// vtable @0x51e750 (dwControlPanelHelpRect_vtbl); overridden slots: +0x00
// dtor (@409f90, body = the dwWidget dtor via COMDAT thunk @409fb0) and
// +0x18 OnHover (= the shared dwWidget_OnHoverNotify COMDAT @419780 reading
// binary +0x10 as the msg sender).

struct dwControlPanelHelpRect : dwWidget
{
    int32_t helpCode; // 0x10: help id dispatched as { 0x7531, helpCode }
                      //       (Ghidra: helpCode; dwGuiScreen.cpp's HELPRECT
                      //       recipe called it msgParam)

    // No standalone ctor in the binary — both factories build it INLINE:
    // dwWidget(pRect), helpCode = code, vptr = 0x51e750
    // (dwControlPanel::ParseControl @409ef5; dwGuiScreen_CreateControl's
    // HELPRECT branch is the same shape).
    dwControlPanelHelpRect(dwRect* pRect, int32_t code);

    // vtbl +0x00 @409f90 (DtorDelete; the dtor body is dwWidget's own via the
    // thunk @409fb0 — no fields to destroy).
    virtual ~dwControlPanelHelpRect();

    // vtbl +0x18 @419780 (shared dwWidget_OnHoverNotify COMDAT): dispatch
    // { 0x7531, helpCode, 0, NULL } to dwWidget_pDefault and return 1.
    virtual int OnHover(int16_t x, int16_t y);
};

#endif // __cplusplus

#endif // _DWCONTROLPANEL_H
