#ifndef _DWENDING_H
#define _DWENDING_H

// dwEnding — the end-game graduation "certificate" sequence.
// DroidWorks.exe unit range: 0x410a30-0x410d5f (vtbl dwEnding_vtbl @0x51eaf8,
// struct dwEnding 0x48).
//
// A dwMovie subclass (NOT dwAnim — the ctor chains dwMovie_Ctor("ending.san"))
// that plays the ending.san SMUSH movie and overlays a printed graduation
// certificate: the player's earned rank (averaged over the normal missions'
// rank scores on dwCore_pMissionList) plus the player's name, built from
// certificate.ifc / certificate.txt via the common dwGuiScreen_CreateControl
// factory into the dwMovie overlay group. A rank-indexed congratulation
// voice-over (ENJB018/019/010.wav) plays once the movie passes frame 0x168;
// the certificate controls draw only while the movie frame is in
// [0x186, 0x1e8] (the window where the certificate is on screen).
//
// Constructed by dwGuiOptions_OnMessage (menu replay, msg 6000+0x1e — this
// wave) and dwGuiInGame_EndMission @42092d (on completing the FINAL mission —
// P6 wave 2); pushed onto the dwSegment stack.
//
// SMUSH playback is stubbed (policy, see DW/DECOMP_PROGRESS.md): the base
// dwSmushSeg::Activate takes the open-failure path, so the segment finishes
// on its next Update and neither the VO trigger nor the certificate draw
// window is reached until the P8 SMUSH unit lands (they key off the SMUSH
// frame counter below).
//
// Compiled as C++ (vtable + ctor/dtor pair + MSVC EH frame in Activate).

#include "Dw/dwTypes.h"

#ifdef __cplusplus
struct dwEnding;
extern "C" {
#else
typedef struct dwEnding dwEnding; // C++ class; opaque in the C view
#endif

// TODO(dw-decomp): owned by the untranslated lecSmush/SmushPlay engine unit
// (P8) — the SMUSH playback frame counter (binary DAT_0068b1c4, written by
// lecSmush per decoded frame). Placeholder DEFINED in dwEnding.cpp (always 0
// while SMUSH is stubbed); the P8 unit must adopt it and this declaration
// should move with it. Read by dwEnding + dwGuiOpening (dwGuiOptions.cpp).
extern uint32_t lecSmush_frameNum; // @0x68b1c4

// Note: no binary counterpart — resets the module's placeholder global for
// the soft-reset loop.
void dwEnding_Startup(void);

#ifdef __cplusplus
} // extern "C"

#include "Dw/dwMovie.h"

// Binary layout: dwMovie base @0x00 (0x40) + rankIndex@0x40 + bVoicePlayed@
// 0x44 — sizeof 0x48. vtable @0x51eaf8 (dwEnding_vtbl, dwMovie 7-slot shape):
// overrides Activate (+0x00), Update (+0x10), dtor (+0x14) and Draw (+0x18).
struct dwEnding : dwMovie
{
    int32_t rankIndex;     // 0x40: averaged rank, 0-based after Activate
                           //       (indexes the VO / rank-name tables)
    uint8_t bVoicePlayed;  // 0x44: congratulation VO fired (Update one-shot)

    // @410a30 (dwEnding_Ctor) — dwMovie("ending.san"); bVoicePlayed = 0.
    // Note: the binary leaves rankIndex uninitialized until Activate;
    // zero-initialized here.
    dwEnding();

    // @410a70 (dwEnding_Dtor; scalar-deleting wrapper @410a50 = vtbl +0x14) —
    // vptr re-point + base dtors only (implicit here).
    virtual ~dwEnding();

    // vtbl +0x00 @410a80 (dwEnding_OnActivate) — loads ending.cmp, averages
    // the normal missions' ranks into rankIndex, preloads the rank VO, and
    // builds the certificate controls from certificate.ifc (RANK_NAME /
    // PLAYER_NAME lines get their text injected via the +0x48 SetText
    // virtual) into the movie overlay; chains to dwMovie::Activate().
    virtual int Activate();

    // vtbl +0x10 @410cb0 (dwEnding_Update) — once the SMUSH frame counter
    // passes 0x168: play the rank congratulation VO once; base Update.
    virtual void Update();

    // vtbl +0x18 @410cf0 (dwEnding_Draw) — draw the certificate overlay only
    // while the SMUSH frame counter is in (0x185, 0x1e9).
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);
};

#endif // __cplusplus

#endif // _DWENDING_H
