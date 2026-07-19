#ifndef _DWGUISTATSDROID_H
#define _DWGUISTATSDROID_H

// dwGuiStatsDroid — the STATS_DROID display widget: an assembled-droid
// stat-sheet control that shows the workspace droid's aggregate stats
// (name / mass / magnetic / durability / L+R arm strength / speed /
// power-usage / power) plus a live POWER% gauge during missions.
//
// Decompiled from DroidWorks.exe @0x40fe00-0x410a2f (vtbl @0x51ea90; alloc
// 0xf8; derives dwWidget). It SHARES a compile unit with the dwDroidStats data
// class (@0x40eb60-0x40fdff, translated in P5, dwDroidStats.cpp) — this file is
// only the GUI widget. The stats themselves are recomputed on demand from the
// workspace (dwCore_pWorkspaceNodes) via an embedded dwDroidStatsTotals
// accumulator; it does NOT read a persisted dwDroidStats record.
//
// Verifiably C++ (vtable + ctor/dtor + MSVC EH frames) -> C++ class.

#include "Dw/dwWidget.h"      // base class + dwWidgetMsg
#include "Dw/dwFont.h"        // dwFont*
#include "Dw/dwDroidStats.h"  // dwDroidStatsTotals (embedded) + accumulator API

#ifndef __cplusplus

typedef struct dwGuiStatsDroid dwGuiStatsDroid; // C++ class; opaque in the C view

#else // __cplusplus

struct dwGuiStatsDroid : dwWidget
{
    dwDroidStatsTotals totals; // 0x10: recomputed stat accumulator (0x68)
    dwFont* pFont1;            // 0x78: label font
    uint8_t colorLabel;        // 0x7c
    dwFont* pFont2;            // 0x80: value font
    uint8_t colorValue;        // 0x84
    char* labelDroidName;      // 0x88: "DROID_NAME:"
    char* labelTotalMass;      // 0x8c: "TOTAL_MASS:"
    char massValue[20];        // 0x90: formatted total mass (MASS_FMT)
    char* labelMagnetic;       // 0xa4: "MAGNETIC:"
    char* magneticValue;       // 0xa8: NO / YES
    char* labelDurability;     // 0xac: "DURABILITY:"
    char* durabilityValue;     // 0xb0: NONE..HIGH
    char* labelLArm;           // 0xb4: "L_ARM_STRENGTH:"
    char* lArmValue;           // 0xb8: NONE..HIGH
    char* labelRArm;           // 0xbc: "R_ARM_STRENGTH:"
    char* rArmValue;           // 0xc0: NONE..HIGH
    char* labelSpeed;          // 0xc4: "SPEED:"
    char speedValue[20];       // 0xc8: formatted speed (SPEED_FMT)
    char* labelPowerUsage;     // 0xdc: "POWER_USAGE:"
    char* powerUsageValue;     // 0xe0: NONE..HIGH
    char* labelPower;          // 0xe4: "POWER:"
    char powerValue[6];        // 0xe8: formatted power % ("%lu%%" or "0%%")
    int16_t powerCur;          // 0xee: currently-shown battery charge
    int16_t powerTarget;       // 0xf0: gauge target charge
    int16_t powerStart;        // 0xf2: gauge start charge (for the tween)
    float animTimeAccum;       // 0xf4: seconds since the gauge tween started

    // @40fe00 — dwWidget(pRect); loads the two fonts; localizes 9 labels;
    // then Refresh() bakes the initial stat strings.
    dwGuiStatsDroid(dwRect* pRect, char* pFont1Name, uint8_t colorLabel,
                    char* pFont2Name, uint8_t colorValue);
    // @40fff0 (DtorDelete @40ffd0) — frees the two fonts.
    virtual ~dwGuiStatsDroid();

    // @410070 — dispatch hover-help {0x7531, 0x791a}; return 1.
    virtual int OnHover(int16_t x, int16_t y) override;
    // @4100a0 — 0x7dc/0x7dd: Refresh + Invalidate; 0x7ec: Invalidate.
    virtual int OnMessage(dwWidgetMsg* pMsg) override;
    // @4103b0 — animate the power gauge toward its target (or, in a mission,
    // snap it to the live player energy).
    virtual void Update(float dt) override;
    // @410500 — draw the stat rows + the power gauge.
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect) override;

    // @4100e0 (non-virtual) — recompute totals from the workspace and format
    // every value string.
    void Refresh();
};

#endif // __cplusplus

#endif // _DWGUISTATSDROID_H
