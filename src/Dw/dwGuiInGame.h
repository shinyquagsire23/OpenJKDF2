#ifndef _DWGUIINGAME_H
#define _DWGUIINGAME_H

// dwGuiInGame — the IN-GAME HUD / live-gameplay MISSION SCREEN (the screen that
// runs the sith engine live) + its nested dwGuiInGamePause dialog.
//
// dwGuiScreen subclass, MSVC multiple inheritance (primary vtbl 0x51f180,
// segment/scn vtbl 0x51f168). IS a dwSegment: dwGuiMissionMap deploy news the
// screen and pushes its dwSegment subobject onto the segment stack. While it is
// the active segment the world is open: StartMission (the Activate slot) opens
// the world + builds the player droid from the assembled workshop parts (via
// dwDroidStats) + rewrites the player thing's physics/camera/inventory and
// writes the dwCog caps; SegUpdate (the Update slot) ticks gauges + ambient
// GHCA*.wav chatter + energy drain + the death fade; EndMission tears the world
// down and pushes the dwGuiStatus debriefing.
//
// Decompiled from DroidWorks.exe unit range 0x41f2a0-0x42317f. Two functions in
// that window belong to dwSith.c (dwGuiInGame_SithPrintHook @0x423070 and
// dwSith_Instinct_TouchOfDeath @0x4230a0) and dwMain.c (dwMain_Run @0x41b250,
// dwMain_VerifyInstallation @0x41b280) and are NOT translated here.
//
// GLOBAL dwGuiInGame_pActive @0x53e800 = the running-mission screen (obj+0) or
// NULL. Cross-unit: dwHelp speaker-code 0x6b routes player speech here; the HUD
// voice line + Cammy caption + console print are exported as C shims below
// (dwCog.c / dwSith.c call them). dwGuiMissionMap deploy + dwGuiScreen msg-0x67
// call dwGuiInGame_New / dwGuiInGame_CheckDroidValid.
//
// The screen struct is left un-rigid (big-fish screen precedent, same as
// dwGuiOptions/dwGuiStatus): members are declared in binary field ORDER with
// @0xNN comments but the exact offsets do not matter on 64-bit. The deep engine
// surgery in StartMission/SegUpdate/EndMission/RebuildViewport references many
// DW-forked sith-engine internals that have no OpenJKDF2 counterpart yet; those
// are forward-declared in the .cpp and reported as unresolved externs (owner:
// P7 boot flow / P8 engine diff audit).

#include "Dw/dwTypes.h"
#include "Dw/dwRect.h"

#ifdef __cplusplus
struct dwGuiInGame;
struct dwGuiInGamePause;
struct dwMission;   // Dw/dwMission.h
struct dwSegment;   // Dw/dwSegment.h
extern "C" {
#else
typedef struct dwGuiInGame dwGuiInGame;           // C++ class; opaque in the C view
typedef struct dwGuiInGamePause dwGuiInGamePause; // C++ class; opaque in the C view
typedef struct dwMission dwMission;
typedef struct dwSegment dwSegment;
#endif

// The HUD reads the player inventory descriptor table through the repo's
// SithInventoryType / sithInventory_g_aTypes (Gameplay/sithInventory.h). ⚠ The
// DW build repurposes SithInventoryType::hudBitmap as a dwImage* (its
// dwImageDesc gives the icon dims); dwGuiInGame/dwGuiInvBar cast it.

// ---- the running-mission screen (0 when no mission is live) ------------------
// (real definition of the placeholder previously in dwMain.c) @0x53e800
extern dwGuiInGame* dwGuiInGame_pActive;

// ---- C-linkage API (shims C units call; own the ex-dwMain.c placeholders) ---

// Mission-screen factory: `new dwGuiInGame(pMission)`, returning the screen's
// dwSegment subobject (dwGuiMissionMap deploy + dwGuiScreen msg-0x67 push this).
// @41f2a0 (bundles the binary's new(0x284) + Ctor).
dwSegment* dwGuiInGame_New(dwMission* pMission);

// Validate the assembled workshop droid before deploy: runs a stats pass over
// dwCore_pWorkspaceNodes and, on failure, shows the matching gmessage dialog
// (DLG_EMPTY/DLG_NOLOCO/DLG_DETACHED/DLG_NOPOWER/DLG_NOEYES/DLG_MULTIPLE) and
// returns 0; returns 1 when the droid is deployable. @41f6f0
int dwGuiInGame_CheckDroidValid(void);

// HUD voice line: shows a Cammy caption (msgCode) and/or plays a VO wav, gated
// by priority against the currently-playing line. pCammyText is the message
// code (as in the binary's PlayVoiceLine signature). @422180
void dwGuiInGame_PlayVoiceLine(const char* pCammyText, const char* pWavName, uint32_t priority);

// HUD console print: appends pText to the on-screen console ring (only when the
// console cheat is enabled). @423020
void dwGuiInGame_ConsolePrint(const char* pText);

// Per-frame sithControl callback (registered by dwSith_Startup): reads the
// grow/shrink-viewport keys and broadcasts the SCREEN_SIZE change (msg 0x1788)
// to the active screen. Returns 0. @422a60
int dwGuiInGame_UpdateViewSize(SithThing* pPlayer, flex_t deltaSecs);

// DW COG verb accessors (the C dwCog verb layer can't reach the C++ struct
// fields directly). @409010 dwendmission/dwendlevel request; @408fa0
// dwgetmissiontext read. Both no-op / return 0 when no mission is live.
void dwGuiInGame_RequestEndMission(void);
int  dwGuiInGame_GetCammyMsgCode(void);

// Note: no binary counterpart — resets dwGuiInGame_pActive for the soft-reset
// loop (the unit's only module-level state).
void dwGuiInGame_Startup(void);

#ifdef __cplusplus
} // extern "C"

#include "Dw/dwGuiScreen.h"
#include "Dw/dwWidgetGroup.h"
#include "Dw/dwGuiMission.h" // dwGuiDialog base (dwGuiInGamePause) + dwMission
#include "Dw/dwString.h"
#include "Dw/dwFont.h"

// Cross-unit control classes referenced only as pointers (forward-declared;
// several live in sibling P6-wave-2 units that have not landed yet).
struct dwGuiHypText;   // Dw/dwGuiHypText.h (CAMMY_TEXT / HELPTEXT)
struct dwGuiIndicator; // dwHelp.cpp (SPEED/DAMAGE/POWER gauges) — sibling unit
struct dwGuiSpeech;    // dwGuiList.cpp (NPCSPEECH) — sibling unit
struct dwGuiList;      // dwGuiList.cpp (PLAYERSPEECH) — sibling unit
struct dwDroidStats;   // Dw/dwDroidStats.h (baked player droid)
struct sithCog;        // engine (conversation cog)
struct rdCanvas;       // engine (3D HUD viewport)

// ---- dwGuiInGame -------------------------------------------------------------
//
// Binary sizeof 0x284, base dwGuiScreen @0x00 (0xc8). Members below in binary
// field ORDER. Segment-slot method bodies address the object through the
// dwSegment subobject (binary obj+0x10) — irrelevant in this C++ translation
// (each method's `this` is the full object).

struct dwGuiInGame : dwGuiScreen
{
    dwMission* pMissionInfo;      // 0xc8: ctor arg (dwMission record; +4 missionType)
    rdCanvas* pViewCanvas;        // 0xcc: 3D HUD viewport canvas (RebuildViewport;
                                  //       the binary embeds it by value + reads
                                  //       canvas+4 as the "already open" flag)
    float aimCenterX;             // 0xd4: viewport screen center (dwCamera aim)
    float aimCenterY;             // 0xd8
    dwDroidStats* pDroidStats;    // 0x10c: baked player droid (BuildDroidStats; freed in Dtor)
    uint8_t bConvPending;         // 0x110: a conversation cog just started (ctor=1)
    dwGuiSpeech* pNpcSpeech;      // 0x114: NPCSPEECH caption
    dwGuiList* pPlayerSpeech;     // 0x118: PLAYERSPEECH response menu
    uint8_t bConvActive;          // 0x11c: conversation in progress
    sithCog* pConversationCog;    // 0x120
    uint8_t bEndRequested;        // 0x124: mission end requested (SegUpdate ends it)
    uint8_t bDying;               // 0x125: death fade running
    uint32_t deathStartMs;        // 0x128: death fade start (sithTime ms)
    int32_t deathFadeHandle;      // 0x12c: stdPalEffects fade request (init -1)
    uint8_t field_0x130;          // 0x130: (ctor zeroes; unread)
    dwWidgetGroup overlayGroup;   // 0x138: OVERLAY controls (children @0x148)
    dwRect viewRect;              // 0x14c: VIEWRECT (HUD 3D viewport LTRB)
    dwRect insetRect;             // 0x154: game-speed-inset viewport LTRB (RebuildViewport)
    dwGuiHypText* pCammyText;     // 0x15c: CAMMY_TEXT caption
    dwGuiIndicator* pSpeedGauge;  // 0x160: SPEED
    dwGuiIndicator* pDamageGauge; // 0x164: DAMAGE
    dwGuiIndicator* pPowerGauge;  // 0x168: POWER
    dwGuiHypText* pHelpText;      // 0x16c: HELPTEXT
    dwWidget* pHideHelp;          // 0x170: HIDEHELP toggle
    uint32_t cammyMsgCode;        // 0x174: last Cammy caption message code
    dwString currentVoiceWav;     // 0x178: currently-playing VO wav name
    uint32_t voicePriority;       // 0x184: its priority
    uint8_t bVoicePlaying;        // 0x188: a VO line is showing/playing
    uint32_t voiceEndMs;          // 0x18c: VO/caption auto-clear time (sithTime ms)
    uint32_t field_0x190;         // 0x190: (ctor zeroes; unread)
    uint32_t field_0x194;         // 0x194: (ctor zeroes; unread)
    uint8_t bVoiceEnabled;        // 0x198: voice/caption enabled (ctor=1)
    flex_t lastHealth;            // 0x19c: previous-frame health (hurt-chatter delta)
    float chatterTimerLow;        // 0x1a0: low-power ambient chatter accumulator
    float chatterTimerHurt;       // 0x1a4: damage ambient chatter accumulator
    float chatterTimerIdle;       // 0x1a8: idle ambient chatter accumulator
    float chatterTimerHappy;      // 0x1ac: healthy ambient chatter accumulator
    dwFont* pConsoleFont;         // 0x1b0: "Arial12" console/debug font (owned)
    uint8_t bShowDebugOverlay;    // 0x1b4: debug FPS/position overlay cheat
    int32_t debugFrameCount;      // 0x1b8: frames drawn (FPS counter)
    uint32_t debugNowMs;          // 0x1bc: last debug-overlay draw time
    int32_t debugWindowStartFrame;// 0x1c0: FPS window start frame
    uint32_t debugWindowStartMs;  // 0x1c4: FPS window start time
    uint8_t bConsoleOn;           // 0x1c8: HUD console cheat enabled
    int32_t consoleWriteIdx;      // 0x1cc: console ring write cursor (0..0xe)
    dwString consoleLines[0xf];   // 0x1d0: 15-line console ring (0xc each)
    // binary sizeof 0x284

    // @41f2a0 (dwGuiInGame_Ctor) — dwGuiScreen("gameplay"-cmp base, NULL);
    // stores pMission; zeroes the HUD state; loads the Arial12 console font.
    dwGuiInGame(dwMission* pMission);

    // @41f4a0 (dwGuiInGame_Dtor; scalar-deleting wrapper @41f480; scn thunk
    // @423160) — EndMission if active, FreeImages, free the droid stats, unlink
    // + delete the CAMMY/HELP controls, free the voice/console strings + overlay.
    virtual ~dwGuiInGame();

    // ---- dwWidget-side overrides (primary vtbl @0x51f180) ----
    virtual int OnMouseMove(int16_t x, int16_t y);               // +0x04 @421540 — velocity cursor, then base
    virtual int OnMouseUp(int16_t x, int16_t y);                 // +0x0c @4209e0 — pick-mode dispatch, then base
    virtual int OnKey(int key, int repeat);                      // +0x10 @421630 — Esc/P pause dialog, H holster
    virtual int OnMessage(dwWidgetMsg* pMsg);                    // +0x1c @4218d0 — HUD command routing
    virtual void EnsureImages();                                 // +0x3c @421fd0 — overlay + CAMMY/HELP images
    virtual void FreeImages();                                   // +0x40 @422010
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect);// +0x44 @421ca0 — viewport border + 3D + debug/console overlay
    virtual dwWidget* CreateControl(char* pKeyword, dwConfFile* pConf); // +0x48 @422370 — HUD control factory
    virtual void CheckCheatCodes(char* pCode);                   // +0x4c @422ae0 — FLY/DANKE/BEEFCAKE/... in-game cheats

    // ---- dwSegment-side overrides (scn vtbl @0x51f168) ----
    virtual int Activate();    // +0x00 @41f9e0 (StartMission) — open the world + build the player droid
    virtual void Deactivate(); // +0x04 @420410 (OnHide) — stop sounds, fade to transparent, base OnHide
    virtual void Suspend();    // +0x08 @420be0 (Pause) — pause time + mixer, base Suspend
    virtual void Resume();     // +0x0c @420c00 (Resume) — resume mixer + time, base Resume
    virtual void Update();     // +0x10 @420c20 (SegUpdate) — gauges + chatter + energy drain + death fade

    // ---- non-virtual methods ----
    void EndMission();         // @4205e0 — evaluate win/lose, tear down the world, push the debriefing
    void StopSounds();         // @420580 — stop the VO + conversation sounds + speech
    void StopVoiceLine();      // @422100 — stop the current VO wav
    void ClearCammyText();     // @422160 — stop VO + clear the Cammy caption
    void ClearPlayerSpeech();  // @4214d0 — clear the response menu + conversation state
    void SetRefTopic(char* pTopic); // @421510 — set the reference topic + blink the reference button
    void ShowCammyText(uint32_t msgCode); // @4222e0 — localize + show the Cammy caption
    void PlayVoiceLineEx(uint32_t msgCode, char* pWavName, uint32_t priority, char bForce); // @4221a0
    void BuildDroidStats(SithThing* pPlayer); // @422050 — bake the workspace droid into pDroidStats
    int RebuildViewport();     // @420a70 — build the HUD 3D viewport canvas + camera from viewRect
};

// ---- dwGuiInGamePause --------------------------------------------------------
//
// The "DLG_PAUSED" pause dialog (a dwGuiDialog subclass built inline by OnKey on
// P/Esc). Binary: dwGuiDialog @0x00 (0xd8) + no own fields — sizeof 0xd8. vtbls
// @0x51f1e8 (primary) / @0x51f1d0 (scn) override only OnKey/OnMessage/dtor.

struct dwGuiInGamePause : dwGuiDialog
{
    // @  (built inline in dwGuiInGame::OnKey via dwGuiDialog("gmessage",
    // "DLG_PAUSED", &s_pausedResult)); no ctor body of its own beyond installing
    // the two vtables — modelled here as a thin ctor.
    dwGuiInGamePause();

    // @421880 (dwGuiInGamePause_Dtor; scalar-deleting wrapper @421860; scn thunk
    // @423170) — base dwGuiDialog dtor.
    virtual ~dwGuiInGamePause();

    // vtbl +0x10 @421840 — any key resumes: RequestAdvance, then base OnKey.
    virtual int OnKey(int key, int repeat);
    // vtbl +0x1c @421810 — OK (5000) resumes: RequestAdvance, then base OnMessage.
    virtual int OnMessage(dwWidgetMsg* pMsg);
};

#endif // __cplusplus

#endif // _DWGUIINGAME_H
