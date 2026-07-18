// dwGuiInGame — the in-game HUD / live-gameplay MISSION SCREEN + its nested
// dwGuiInGamePause dialog. See Dw/dwGuiInGame.h for the role summary, the
// segment lifecycle and the (un-rigid) struct/vtable maps.
//
// Decompiled from DroidWorks.exe unit range 0x41f2a0-0x42317f (excluding the
// dwSith.c / dwMain.c functions that share the window — see the header note).
// Per-function @addresses below. Compiled as C++ (two vtables, ctor/dtor pair,
// MSVC EH frames).
//
// Engine-name mapping (Ghidra DW name -> OpenJKDF2 repo name):
//   sithWorld_pCurrentWorld       -> sithWorld_g_pCurrentWorld
//   ->playerThing                 -> ->pLocalPlayer
//   sithTime_curMs                -> sithTime_g_msecGameTime
//   sithTime_deltaSeconds         -> sithTime_g_frameTimeFlex
//   thing->typeParams.actorParams -> thing->actorParams   (repo anon union)
//   thing->physParams.physicsParams -> thing->physicsParams
//   thing->renderData             -> thing->rdthing
//
// ⚠ FIDELITY NOTE: this screen runs the sith engine live. StartMission /
// SegUpdate / EndMission / RebuildViewport reference many DW-forked or unnamed
// sith-engine internals (sithRender_FUN_*, sithMain_FUN_*, sithControl_FUN_*,
// sithSoundMixer_FUN_*, sithInventory_FUN_*, stdPalEffects_*, rdCanvas_New,
// ...). None exist in OpenJKDF2 yet; they are forward-declared below with their
// Ghidra names and reported as UNRESOLVED EXTERNS (owner: P7 boot flow / P8
// sith diff audit). The unit compiles but does not LINK standalone until that
// engine work lands — consistent with the tracker's phasing. A few binary
// details that depend on the DW-forked SithThing/rdKeyframe layouts (the
// weapon-param bit pokes, the merged-keyframe z-rebase scan, the load-screen
// double-buffer text) are preserved as documented raw-offset blocks / Notes.

#include "Dw/dwGuiInGame.h"

#include "Dw/dwGuiInvBar.h"    // INVENTORY factory
#include "Dw/dwGuiHypText.h"   // CAMMY_TEXT / HELPTEXT controls + stock callbacks
#include "Dw/dwGuiList.h"      // dwGuiList/dwGuiSpeech full defs (sizeof in PLAYERSPEECH/NPCSPEECH)
#include "Dw/dwHelp.h"         // dwHelp full def (sizeof in HELP factory)
#include "Dw/dwGuiMission.h"   // dwGuiDialog base + dwGuiDialog_RunModal
#include "Dw/dwDroidStats.h"   // baked player droid record
#include "Dw/dwCog.h"          // dwCog_droidCaps/toolCaps + dwCog_UnfreezePlayer
#include "Dw/dwPlayer.h"       // dw_viewSizePct / dw_settingMusicVol / statsFlags / SavePlr
#include "Dw/dwSith.h"         // dwSith_pfnPrev* loader hooks (re-installed here)
#include "Dw/dwDisplay.h"      // dwDisplay_pScreenImage / Present / pSwBuffer
#include "Dw/dwCursor.h"       // dwCursor_SetCursor / dwCursor_curIdx
#include "Dw/dwColormap.h"     // dwColormap_transparentIdx / dwColormap_Apply
#include "Dw/dwImage.h"        // dwImage_LoadFile / dwImage_CallBlit / dwImage_Delete
#include "Dw/dwImageDraw.h"    // dwImageDraw_FillRect
#include "Dw/dwSound.h"        // dwSound_SetMusic / dwSound_Play / dwSound_Stop
#include "Dw/dwConfFile.h"     // conf parsing
#include "Dw/dwString.h"
#include "Dw/dwStringTable.h"
#include "Dw/dwSegment.h"      // segment manager
#include "Dw/dwWorkshopCtrl.h" // dwWcButtonBlink (REFERENCE/INVENTORY buttons)
#include "Dw/dwGuiWidgets.h"   // dwGuiScrollBar (VIEWSIZE)
#include "Dw/dwGuiWidgetBar.h" // dwGuiWidgetBar (WIDGETBAR)
#include "Dw/dwMain.h"         // dwMain_pHS + dwMain_MaterialLoaderCb/UnloaderCb
#include "Dw/dwFont.h"

#include "jk.h"
#include "globals.h" // SithThing / SithWorld / sithWorld_g_pCurrentWorld / sithTime_g_*
#include "stdPlatform.h"

// Real repo engine functions (correct signatures from their own headers).
// Guarded engine headers (carry their own extern "C").
#include "Engine/sithCamera.h"
#include "Engine/rdCamera.h"
#include "Engine/rdMaterial.h"
#include "Primitives/rdModel3.h"
#include "Engine/rdCanvas.h"       // Added: rdCanvas_NewEntry (ex dw_rdCanvas_New)
#include "General/stdPalEffects.h" // Added: stdPalEffects_UpdatePalette/NewRequest

// Unguarded C engine headers — wrap in extern "C" for correct C++<->C linkage
// (matches the src/Dw sibling convention, e.g. dwDroidView.cpp).
extern "C" {
#include "Engine/sithRender.h"
#include "Engine/sithPhysics.h"
#include "Gameplay/sithTime.h"
#include "Cog/sithCog.h"
#include "Gameplay/sithInventory.h"
#include "Engine/rdThing.h"
#include "Engine/rdKeyframe.h"
#include "Engine/rdPuppet.h"        // Added: rdPuppet_New (ex rdPuppet_New)
#include "Engine/rdroid.h"          // Added: rdAdvanceFrame/rdFinishFrame/rdSetZBufferMethod
#include "Devices/sithControl.h"    // Added: sithControl_BindControl/GetKey
#include "Devices/sithSoundMixer.h" // Added: UpdateMusicVolume/StopAll/ResumeAll
#include "World/sithWorld.h"        // Added: sithWorld_SetLoadProgressCallback
#include "Win95/stdDisplay.h"       // Added: stdDisplay_GetPalette
#include "Platform/stdControl.h"    // stdControl_MessageHandler/ToggleMouse/ReadControls
#include "Main/sithMain.h"          // sithClose/Mode1Init/sithUpdate/sithDrawScene/sithOpenPostProcess
#include "Main/sithCommand.h"       // sithCommand_Fly
#include "Platform/std3D.h"         // Added: std3D_PurgeEntireTextureCache
#include "Raster/rdZRaster.h"       // Added: rdZRaster_BeginFrame
}

#include <math.h>            // sqrtf
#include <ctype.h>           // isspace
extern "C" {
#include "Win95/Window.h"    // Window_AddMsgHandler/RemoveMsgHandler (wrap: matches dwWidget.cpp sibling convention)
}

// ----------------------------------------------------------------------------
// DW-engine internals (forward-declared; see the FIDELITY NOTE). Ghidra names
// kept for traceability; none resolve until P7/P8.
// ----------------------------------------------------------------------------
extern "C" {
extern HostServices* dwMain_pHS; // the DW host-services pointer (dwMain.c)
// dwMain default material loaders restored on EndMission (owner: dwMain P7).
// TODO(dw-decomp): provided by dwMain (P7).
extern rdMaterialLoader_t dwMain_MaterialLoaderCb;
extern rdMaterialUnloader_t dwMain_MaterialUnloaderCb;

extern dwListNode* dwCore_pWorkspaceNodes; // @0x53d984 (workspace dwPartNode list sentinel)
extern dwString dwCore_currentRefFile;     // reference-room current topic file

// ---- Genuinely DW-forked / DW-internal engine globals with no repo twin ----
// (kept as documented externs; owner: P8 sith-engine diff audit).
// TODO(dw-decomp): DW-forked, no repo twin (P8 sith-engine diff audit).
extern uint8_t* DAT_006478f8; // stdDisplay current video-mode record (aspect @+4, viewport shorts @+8/+0xc)
extern int _DAT_006915f0, _DAT_00691528, _DAT_0069158c; // DW sith-engine control latches
extern float _DAT_0069a658; // DW inventory battery-capacity global
extern int DAT_0054518c, DAT_00545190, DAT_00545194, DAT_005b7200, DAT_00546880; // render debug stat counters (MST3K overlay)
extern uint32_t DAT_0053e810, DAT_0053e814; // DW load-progress bar bounds (cosmetic loader UI)

// Ambient chatter wav string tables (contents not recovered from the binary).
// TODO(dw-decomp): populate from DroidWorks.exe .rdata (owner P8).
extern const char* PTR_s_GHCA009_wav_00528688[];
extern const char* PTR_s_GHCA006_wav_00528678[];
extern const char* PTR_s_GHCA058_wav_005286c8[];
extern const char* PTR_s_GHCA048_wav_005286a8[];
extern float _DAT_00528698, _DAT_0052869c, _DAT_005286c0, _DAT_005286d4;

// ---- DW-forked sith-engine internals with no OpenJKDF2 twin -----------------
// (kept as documented externs; owner: P8 sith-engine diff audit).
// TODO(dw-decomp): DW-forked, no repo twin (P8 sith-engine diff audit).
//   sithCamera_sub_44B190  = DW variant of sithCamera_ResetAllCameras that also
//     wires + selects camera slot 7 (the DW HUD chase cam; JK's has no slot 7).
//   sithControl_FUN_00456da0 = DW control-function registration (registers the
//     DW-specific control funcs 0xc/0xd/0xe with DW thresholds).
void sithControl_FUN_00456da0(void);

// TODO(dw-decomp): dwGuiIndicator gauges — provided by dwHelp (P6 wave 2).
void dwGuiIndicator_SetProgress(dwGuiIndicator* pInd, float t);
void dwGuiIndicator_Show(dwGuiIndicator* pInd);
void dwGuiIndicator_Hide(dwGuiIndicator* pInd);
// TODO(dw-decomp): dwGuiList/dwGuiSpeech — provided by dwGuiList (P6 wave 2).
dwGuiList* dwGuiList_Ctor(dwGuiList* pThis, dwRect* pRect, float a, char* pFont, uint8_t c, uint8_t d, void* pPoint);
void dwGuiList_Clear(dwGuiList* pList);
dwGuiSpeech* dwGuiSpeech_Ctor(dwGuiSpeech* pThis, dwRect* pRect, int a, char* pFont, uint32_t c, void* pPoint);
void dwGuiSpeech_Clear(dwGuiSpeech* pSpeech);
// dwHelp control — provided by dwHelp (P6 wave 2b).
dwHelp* dwHelp_Ctor(dwHelp* pThis, dwRect* pRect, char* pAnimName, int speakerCode);

// Debriefing / end-game screens pushed by EndMission (sibling P6w2 / P7).
// TODO(dw-decomp): dwGuiStatus (P6 wave 2), dwGuiOptions/Credits/dwEnding
// (landed), dwCompleteMovie (P7 dwMain).
dwSegment* dwGuiStatus_New(dwMission* pMission, float itemPct, float healthPct, int32_t chargeMax);
dwSegment* dwGuiOptions_New(int index);         // dwGuiOptions.cpp
dwSegment* dwGuiCredits_New(void);              // dwGuiCredits.cpp
dwSegment* dwEnding_New(void);                  // dwEnding.cpp
dwSegment* dwCompleteMovie_New(int idx);        // dwMain (P7)
dwSegment* dwGuiReference_NewIntroSeg(void);    // dwGuiReference.cpp (msg 0x6a)
}

// Named float constants (Ghidra DAT_<bits> labels).
static const float DWF_NEG60 = -60.0f;    // 0xc2700000
static const float DWF_FOV_WIDE = 120.0f; // 0x42f00000
static const float DWF_FOV_MED  = 70.0f;  // 0x428c0000
static const float DWF_FOV_NARROW = 90.0f;// 0x42b40000

// HELPTEXT format callbacks (defined at file end).
static void dwGuiInGame_HelpTextLayout(dwString* pText, dwFont* pFont, int width, dwGuiHypTextRun** ppRuns);
static void dwGuiInGame_HelpTextDraw(dwImageBits* pBits, dwPoint* pPos, dwFont* pFont, uint8_t color, dwGuiHypTextRun* pRun, dwRect* pClip);

// The pause dialog.s shared modal-result slot (binary DAT_0053e808).
static int dwGuiInGamePause_result = 0;

// ----------------------------------------------------------------------------
// module state + init
// ----------------------------------------------------------------------------

dwGuiInGame* dwGuiInGame_pActive = NULL; // @0x53e800 (real def; ex-dwMain.c placeholder)

extern "C" void dwGuiInGame_Startup(void)
{
    dwGuiInGame_pActive = NULL;
}

// DW COG verb accessors (dwCog.c is C, this struct is C++). @409010 dwCog_EndMission
// sets field_0x124 (bEndRequested); @408fa0 dwCog_GetMissionText reads field_0x174
// (cammyMsgCode). Both no-op / return 0 when no mission is live.
extern "C" void dwGuiInGame_RequestEndMission(void)
{
    if (dwGuiInGame_pActive)
        dwGuiInGame_pActive->bEndRequested = 1;
}

extern "C" int dwGuiInGame_GetCammyMsgCode(void)
{
    return dwGuiInGame_pActive ? (int)dwGuiInGame_pActive->cammyMsgCode : 0;
}

// --- droid-stats-record query verbs (read pDroidStats->totals, which is
//     byte-identical 32/64-bit — all scalar fields). All read binary offsets
//     into field_0x10c (== pDroidStats): capFlags@0x30, maxLoadLeft@0x38,
//     maxLoadRight@0x40, voiceChars@0x64. Return 0 when no droid is baked.
// @408eb0 dwCog_GetPlayerHeadType — the last part VOICE pair; when the first
// char is 'B' the second char is the answer (faithful branch).
extern "C" int dwGuiInGame_GetDroidHeadType(void)
{
    if (!dwGuiInGame_pActive || !dwGuiInGame_pActive->pDroidStats)
        return 0;
    dwDroidStatsTotals* pT = &dwGuiInGame_pActive->pDroidStats->totals;
    int v = (unsigned char)pT->voiceChars[0];
    if (v == 0x42)
        v = (unsigned char)pT->voiceChars[1];
    return v;
}

// @408f60 dwCog_CheckDroidCaps — (droid capFlags & mask).
extern "C" int dwGuiInGame_GetDroidCaps(int mask)
{
    if (!dwGuiInGame_pActive || !dwGuiInGame_pActive->pDroidStats)
        return 0;
    return (int)(dwGuiInGame_pActive->pDroidStats->totals.capFlags & (uint32_t)mask);
}

// @408f90 dwCog_GetArmStrength — max(maxLoadLeft, maxLoadRight).
extern "C" int dwGuiInGame_GetArmStrength(void)
{
    if (!dwGuiInGame_pActive || !dwGuiInGame_pActive->pDroidStats)
        return 0;
    dwDroidStatsTotals* pT = &dwGuiInGame_pActive->pDroidStats->totals;
    uint8_t l = pT->maxLoadLeft, r = pT->maxLoadRight;
    return (int)(l < r ? r : l);
}

// --- dialog / caption verbs (wrap the already-real dwGuiInGame methods) ---
// @408de0 dwCog_SetMissionText -> ShowCammyText(id).
extern "C" void dwGuiInGame_ShowCammyTextVerb(int msgCode)
{
    if (dwGuiInGame_pActive)
        dwGuiInGame_pActive->ShowCammyText((uint32_t)msgCode);
}

// @409310 dwCog_SetRefTopic -> SetRefTopic(str).
extern "C" void dwGuiInGame_SetRefTopicVerb(char* pTopic)
{
    if (dwGuiInGame_pActive)
        dwGuiInGame_pActive->SetRefTopic(pTopic);
}

// @408d60 dwCog_ClearDialog — clear the response menu + conversation state,
// then (if an NPC caption exists) stop its speech sound and drop its text.
extern "C" void dwGuiInGame_ClearDialog(void)
{
    if (!dwGuiInGame_pActive)
        return;
    dwGuiInGame_pActive->ClearPlayerSpeech();
    dwGuiSpeech* pNpc = dwGuiInGame_pActive->pNpcSpeech;
    if (pNpc != NULL)
    {
        dwGuiSpeech_Clear(pNpc);        // @40aa30: stop its speech sound + wake the timed cog
        pNpc->dwGuiHypText::Clear();    // @438c80: free the caption text + line runs —
                                        // the dialog box draws while text is non-empty,
                                        // so this is what dismisses it (binary calls
                                        // dwGuiHypText_Clear here; dwGuiSpeech::Clear
                                        // HIDES the base method, it must be qualified)
    }
}

// --- COG voice/caption verb helpers ----------------------------------------
// The dwCog part-1 speech verbs (dwplaycharacterspeech/dwplayplayerspeech/
// dwplaycammyspeech) reach the C++ speech objects through these extern-C shims;
// the verbs themselves (arg popping + cog-timer arming) live in dwCog.c.

// @408780 body: clear any player response menu, play an NPC/character VO line,
// and show its localized caption on the NPCSPEECH widget. Returns the caption
// duration in ms — the real VO wav length when one plays, else a reading-time
// fallback (~77ms/char of the text key: strlen*1000/13, round-half-up). pCtx is
// stored as the caption's timed-item so clearing it wakes the waiting cog early.
extern "C" uint32_t dwGuiInGame_PlayCharacterSpeech(sithCog* pCtx, char* pWav, char* pTextKey)
{
    if (dwGuiInGame_pActive == NULL)
        return 0;
    dwGuiInGame* p = dwGuiInGame_pActive;
    p->ClearPlayerSpeech();

    int nText = (pTextKey != NULL) ? (int)_strlen(pTextKey) : 0;
    uint32_t lenMs = (uint32_t)(int)((float)nText * 0.076923079f * 1000.0f + 0.5f);

    if (pWav != NULL && *pWav != '\0')
    {
        p->StopVoiceLine();
        dwSoundSample* pSample = dwSound_Play(pWav);
        if (pSample != NULL)
            lenMs = pSample->GetLengthMs();
    }
    if (p->pNpcSpeech != NULL && dw_settingShowText)
    {
        char* pLoc = dwGuiScreen_LocalizeString(pTextKey, p->pStringTable);
        p->pNpcSpeech->SetText(pLoc, (void*)pCtx, pWav);
    }
    return lenMs;
}

// currentVoiceWav.length != 0 — a VO/caption line is currently active.
// @408ca0 gate: dwCog_PlayPlayerSpeech only speaks when nothing is playing.
extern "C" int dwGuiInGame_HasActiveVoice(void)
{
    return (dwGuiInGame_pActive != NULL && dwGuiInGame_pActive->currentVoiceWav.length != 0);
}

// The assembled droid's two head-type code chars (dwDroidStats voiceChars[0..1],
// binary field_0x10c + 0x64/0x65). Returns 0 when no droid is baked.
extern "C" int dwGuiInGame_GetDroidHeadChars(char* pOut2)
{
    if (dwGuiInGame_pActive == NULL || dwGuiInGame_pActive->pDroidStats == NULL)
        return 0;
    dwDroidStatsTotals* pT = &dwGuiInGame_pActive->pDroidStats->totals;
    pOut2[0] = pT->voiceChars[0];
    pOut2[1] = pT->voiceChars[1];
    return 1;
}

// Play a resolved player-speech wav. Returns its length in ms, or -1 when no
// sample started (the verb arms the cog timer whenever a sample plays).
extern "C" int32_t dwGuiInGame_PlaySpeechWav(char* pWav)
{
    dwSoundSample* pSample = dwSound_Play(pWav);
    if (pSample == NULL)
        return -1;
    return (int32_t)pSample->GetLengthMs();
}

// @408c60 dwCog_PlayCammySpeech -> PlayVoiceLineEx(msgCode, wav, priority, 0):
// show a Cammy caption + play its VO, priority-gated against the running line.
extern "C" void dwGuiInGame_PlayCammySpeech(int msgCode, char* pWav, int priority)
{
    if (dwGuiInGame_pActive != NULL)
        dwGuiInGame_pActive->PlayVoiceLineEx((uint32_t)msgCode, pWav, (uint32_t)priority, 0);
}

// --- conversation response-menu verb helpers -------------------------------
// @408880 dwCog_AddResponse: append a response to the PLAYERSPEECH menu. The
// item's data = the owning conversation cog (woken/notified when it is picked),
// val = the response id, textA = the localized display text, textB = the VO wav.
// No-op when no response menu exists (binary gates on pPlayerSpeech).
extern "C" void dwGuiInGame_AddResponse(sithCog* pCtx, int id, char* pTextKey, char* pWav)
{
    if (dwGuiInGame_pActive == NULL || dwGuiInGame_pActive->pPlayerSpeech == NULL)
        return;
    char* pLoc = dwGuiScreen_LocalizeString(pTextKey, dwGuiInGame_pActive->pStringTable);
    dwGuiInGame_pActive->pPlayerSpeech->AddItem((void*)pCtx, id, pLoc, pWav);
}

// @408d20 dwCog_GetPlayerResponse: the id (val) of the selected response, or 0.
extern "C" int dwGuiInGame_GetSelectedResponseId(void)
{
    if (dwGuiInGame_pActive == NULL || dwGuiInGame_pActive->pSelectedResponse == NULL)
        return 0;
    return dwGuiInGame_pActive->pSelectedResponse->val;
}

// @408b60 dwCog_PlayPlayerResponse body: play the selected response's VO wav
// (textB, item+0x1c). Returns its length in ms, or -1 when nothing plays (no
// selection / empty wav / no sample).
extern "C" int32_t dwGuiInGame_PlaySelectedResponse(void)
{
    if (dwGuiInGame_pActive == NULL)
        return -1;
    dwGuiListItem* pItem = dwGuiInGame_pActive->pSelectedResponse;
    if (pItem == NULL)
        return -1;
    char* pWav = pItem->textB.pBuffer;
    if (pWav == NULL || *pWav == '\0')
        return -1;
    dwSoundSample* pSample = dwSound_Play(pWav);
    if (pSample == NULL)
        return -1;
    return (int32_t)pSample->GetLengthMs();
}

// @4089c0/@4089e0 dwCog_Enable/DisableEscape: gate whether the Esc key runs
// StopSounds during a conversation (obj+0x110).
extern "C" void dwGuiInGame_SetEscapeEnabled(int bEnabled)
{
    if (dwGuiInGame_pActive != NULL)
        dwGuiInGame_pActive->bEscapeEnabled = (uint8_t)(bEnabled != 0);
}

// @409300 dwCog_FlashInventory body: start the HUD inventory button blinking
// (obj+0x194). No-op when no mission is live or the HUD has no INVENTORY_BUTTON.
extern "C" void dwGuiInGame_FlashInventoryButton(void)
{
    if (dwGuiInGame_pActive != NULL && dwGuiInGame_pActive->pInventoryButton != NULL)
        dwGuiInGame_pActive->pInventoryButton->StartBlink();
}

// Find pWidget's node in pList and unlink+free it (widget kept). Mirrors the
// binary's inline sentinel walks (dwGuiScreen.cpp precedent).
static void dwGuiInGame_UnlinkWidgetNode(dwList* pList, void* pWidget)
{
    for (dwListNode* pNode = pList->pSentinel->pNext; pNode != pList->pSentinel; pNode = pNode->pNext)
    {
        if (pNode->pData == pWidget)
        {
            pList->UnlinkFreeNode(pNode);
            return;
        }
    }
}

// @41f910 — the world-loader progress callback (installed via
// sithWorld_sub_44CDF0). Locks the screen surface, draws the growing progress
// bar between DAT_0053e810/814, presents. Note: the binary interpolates the
// bar with a load-fraction global whose source Ghidra lost; a single fill of
// the current extent is kept (behaviour is cosmetic, off the mission path).
static void dwGuiInGame_DrawLoadProgress(void)
{
    void* pPixels;
    int stride;
    if (dwImage_CallLock((dwImage*)dwDisplay_pScreenImage, &pPixels, &stride) == 0)
        return;
    dwRect bar;
    bar.left = (int16_t)DAT_0053e810;
    bar.top = 0;
    bar.right = (int16_t)DAT_0053e814;
    bar.bottom = 0;
    // dwImageDraw_FillRect(bits, &bar, 0x8b, NULL) — omitted: needs a locked
    // dwImageBits with a pDesc, not exposed by dwImage_CallLock here.
    (void)bar;
    dwImage_CallUnlock((dwImage*)dwDisplay_pScreenImage);
    dwDisplay_Present();
}

// ----------------------------------------------------------------------------
// ctor / dtor
// ----------------------------------------------------------------------------

// @41f2a0 — the base ctor screen-name string @0x5287b8 is "hud" (the base
// LoadControls loads "hud.ifc"). (Was guessed "ingame", which never resolved.)
dwGuiInGame::dwGuiInGame(dwMission* pMission)
    : dwGuiScreen("hud", NULL)
{
    this->pMissionInfo = pMission;
    this->pViewCanvas = NULL;
    this->aimCenterX = 0;
    this->aimCenterY = 0;
    this->pDroidStats = NULL;
    this->bEscapeEnabled = 1; // binary ctor: obj+0x110 = 1 (Esc enabled by default)
    this->pNpcSpeech = NULL;
    this->pPlayerSpeech = NULL;
    this->bConvActive = 0;
    this->pSelectedResponse = NULL;
    this->bEndRequested = 0;
    this->bDying = 0;
    this->deathStartMs = 0;
    this->deathFadeHandle = -1;
    this->bHolstered = 0;
    this->viewRect.left = this->viewRect.top = this->viewRect.right = this->viewRect.bottom = 0;
    this->insetRect.left = this->insetRect.top = this->insetRect.right = this->insetRect.bottom = 0;
    this->pCammyText = NULL;
    this->pSpeedGauge = NULL;
    this->pDamageGauge = NULL;
    this->pPowerGauge = NULL;
    this->pHelpText = NULL;
    this->pHideHelp = NULL;
    this->cammyMsgCode = 0;
    this->voicePriority = 0;
    this->bVoicePlaying = 0;
    this->voiceEndMs = 0;
    this->pReferenceButton = NULL;
    this->pInventoryButton = NULL;
    this->bVoiceEnabled = 1;
    this->lastHealth = 0;
    this->chatterTimerLow = 0;
    this->chatterTimerHurt = 0;
    this->chatterTimerIdle = 0;
    this->chatterTimerHappy = 0;
    this->pConsoleFont = NULL;
    this->bShowDebugOverlay = 0;
    this->debugFrameCount = 0;
    this->debugNowMs = 0;
    this->debugWindowStartFrame = 0;
    this->debugWindowStartMs = 0;
    this->bConsoleOn = 0;
    this->consoleWriteIdx = 0;
    this->pConsoleFont = dwFont_Load(new dwFont, "Arial12");
}

// @41f4a0 (scalar-deleting wrapper @41f480; scn thunk @423160)
dwGuiInGame::~dwGuiInGame()
{
    if (dwGuiInGame_pActive == this)
        EndMission();
    FreeImages();
    if (this->pDroidStats != NULL)
    {
        this->pDroidStats->Free();
        delete this->pDroidStats;
    }
    dwGuiInGame_UnlinkWidgetNode(&this->controls.children, this->pHelpText);
    if (this->pHelpText != NULL)
        delete this->pHelpText;
    dwGuiInGame_UnlinkWidgetNode(&this->controls.children, this->pHideHelp);
    if (this->pHideHelp != NULL)
        delete this->pHideHelp;
    for (int i = 0; i < 0xf; i++)
        this->consoleLines[i].Free();
    this->currentVoiceWav.Free();
    // overlayGroup + base dwGuiScreen dtors run implicitly.
}

// ----------------------------------------------------------------------------
// segment lifecycle: StartMission (Activate) — @41f9e0
// ----------------------------------------------------------------------------

int dwGuiInGame::Activate()
{
    char bActivated = 0;

    // Re-install the DW loader hooks the GUI phases detached (dwSith saved them).
    rdMaterial_RegisterLoader(dwSith_pfnPrevMaterialLoader);
    rdMaterial_RegisterUnloader(dwSith_pfnPrevMaterialUnloader);
    rdModel3_RegisterLoader((model3Loader_t)dwSith_pfnPrevModel3LoadHook);
    rdModel3_RegisterUnloader((model3Unloader_t)dwSith_pfnPrevModel3FreeHook);
    rdKeyframe_RegisterLoader((keyframeLoader_t)dwSith_pfnPrevKeyframeLoader);
    rdKeyframe_RegisterUnloader((keyframeUnloader_t)dwSith_pfnPrevKeyframeUnloader);

    dwSound_SetMusic(NULL, 1);
    sithSoundMixer_UpdateMusicVolume((float)dw_settingMusicVol * 0.01f);

    if (dwGuiInGame_pActive == this)
    {
        stdPlatform_Printf("Re-entering mission: %s\n", this->pMissionInfo->name.pBuffer);
        bActivated = (char)dwGuiScreen::Activate();
    }
    else if (dwGuiInGame_pActive == NULL)
    {
        dwPlayer_SavePlr();
        dwGuiInGame_pActive = this;
        stdPlatform_Printf("Starting mission: %s\n", this->pMissionInfo->name.pBuffer);
        jkPlayer_setDiff = (this->pMissionInfo->rank < 3) ? this->pMissionInfo->rank : 2;

        sithControl_FUN_00456da0();
        Window_AddMsgHandler(stdControl_MessageHandler);
        stdControl_ToggleMouse();
        this->bEndRequested = 0;

        if (this->pStringTable == NULL)
        {
            dwString tblName(this->pMissionInfo->name.pBuffer, 0);
            tblName.Append(".txt", 4);
            this->pStringTable = new dwStringTable(tblName.pBuffer);
            tblName.Free();
        }

        if (this->pMissionInfo->missionType == 5)
        {
            sithWorld_SetLoadProgressCallback(NULL);
        }
        else
        {
            // Note: the DW loader callback is void(void); the repo callback type
            // takes a float (load %) it ignores — cdecl-safe to pass extra arg.
            sithWorld_SetLoadProgressCallback((sithWorldProgressCallback_t)dwGuiInGame_DrawLoadProgress);
            // Note: the binary here double-buffers a localized "LOADING" caption
            // over Loading.rle; omitted (cosmetic, needs a locked dwImageBits).
            sithRender_Close(); // Not sure, no-op in any case
        }

        dwString jklName(this->pMissionInfo->name.pBuffer, 0);
        jklName.Append(".jkl", 4);
        int bLoaded = sithMain_Mode1Init(jklName.pBuffer);
        if (bLoaded != 0)
        {
            dwSound_SetMusic(NULL, 1);
            this->colormapName.AssignCStr(sithWorld_g_pCurrentWorld->colormaps->colormap_fname);
            bActivated = (char)dwGuiScreen::Activate();
            if (bActivated != 0)
            {
                uint32_t rflags = sithRender_GetRenderFlags();
                sithRender_SetRenderFlags(rflags | 2);
                sithRender_SetGeoMode(4);
                sithRender_SetLightingMode(3);
                sithRender_SetTexMode(1);
                sithCamera_ResetAllCameras();
                RebuildViewport();
                sithCamera_SetCurrentCamera(&sithCamera_g_aCameras[7]);

                SithThing* pThing = sithWorld_g_pCurrentWorld->pLocalPlayer;
                BuildDroidStats(pThing);
                dwDroidStats* pStats = this->pDroidStats;
                if (pStats != NULL)
                {
                    // Swap the player thing's model/puppet for the baked droid.
                    rdThing_FreeEntry(&pThing->renderData);
                    rdThing_SetModel3(&pThing->renderData, &pStats->model);
                    pThing->pPuppetClass = (SithPuppetClass*)&pStats->puppetClass;
                    // Note: binary hardcodes the 32-bit sithPuppet size (0x24);
                    // use sizeof for 64-bit safety.
                    sithPuppet* pPuppet = (sithPuppet*)(*dwMain_pHS->alloc)(sizeof(sithPuppet));
                    pThing->puppet = pPuppet;
                    if (pPuppet != NULL)
                        stdPlatform_Memset32(pPuppet, 0, sizeof(sithPuppet));
                    if (pThing->renderData.puppet == NULL)
                        rdPuppet_New(&pThing->renderData);
                    if (pThing->pSoundClass != NULL)
                        dwDroidStats_BuildSoundList(pThing->pSoundClass, pStats->totals.capFlags);

                    // Write the DW COG capability masks from the baked record
                    // (CRITICAL cross-unit effect — dwCog reads these).
                    dwCog_droidCaps = pStats->totals.capFlags;
                    dwCog_toolCaps2 = pStats->totals.toolCapsLeft;
                    dwCog_toolCaps1 = pStats->totals.toolCapsRight;

                    // Camera FOV by capability.
                    float fov = DWF_FOV_NARROW;
                    if (dwCog_droidCaps & 0x80)
                        fov = DWF_FOV_WIDE;
                    else if (dwCog_droidCaps & 0x400)
                        fov = DWF_FOV_MED;
                    rdCamera_SetFOV(&sithCamera_g_aCameras[7].rdCamera, fov);

                    // Droid height from the workspace bbox.
                    float half = pStats->size.z * 0.5f;
                    if ((dwCog_droidCaps & 0x80000) == 0)
                    {
                        if (half < pStats->size.x) half = pStats->size.x;
                        if (half < pStats->size.y) half = pStats->size.y;
                    }
                    else
                    {
                        if (pStats->size.x < half) half = pStats->size.x;
                        if (pStats->size.y < half) half = pStats->size.y;
                    }
                    float newHeight = half * 0.5f;
                    if (newHeight < 0.05f) newHeight = 0.05f;

                    // Physics tuning from the baked stats (repo SithThing fields).
                    float posZ = pThing->position.z;
                    pThing->physicsParams.height = newHeight;
                    pThing->collideSize = newHeight;
                    pThing->moveSize = newHeight;
                    pThing->position.z = newHeight + posZ;
                    sithPhysics_FindFloor(pThing, 1);
                    uint32_t pflags = pThing->physicsParams.flags;
                    pThing->physicsParams.mass = pStats->totals.mass * 2.2f;
                    if ((pStats->totals.capFlags & 0x40) == 0)
                        pflags &= 0xffffffef;
                    else
                        pflags |= 0x10;
                    pThing->physicsParams.flags = pflags;
                    float maxThrust0 = pThing->actorParams.maxThrust;
                    pThing->physicsParams.airDrag = pStats->totals.drag;
                    pThing->physicsParams.staticDrag = pStats->totals.staticFriction;
                    float thrust = pStats->totals.power / pStats->totals.mass;
                    pThing->actorParams.maxThrust = thrust;
                    pThing->physicsParams.maxVelocity = thrust / pThing->physicsParams.airDrag;
                    float maxHp = pStats->totals.durability * 0.2f * pThing->actorParams.maxHealth;
                    pThing->actorParams.maxHealth = maxHp;
                    pThing->actorParams.health = maxHp;
                    pThing->actorParams.eyeOffset.x = pStats->eyeOffset.x;
                    pThing->actorParams.eyeOffset.y = pStats->eyeOffset.y;
                    pThing->actorParams.eyeOffset.z = pStats->eyeOffset.z;
                    // TODO(dw-decomp): the binary also (a) bit-pokes DW-forked
                    // weaponParams aim/deflection floats (@typeParams+0x44/48/64),
                    // (b) tunes jumpSpeed via maxThrust ratio + 1.21 factor, and
                    // (c) z-rebases the merged model + every merged rdKeyframe by
                    // the height delta (record scan 0..0x4ac). These depend on
                    // the DW SithThing/rdKeyframe layouts (P8 sith diff audit).
                    (void)maxThrust0; (void)DWF_NEG60;

                    if ((pStats->totals.capFlags & 1) == 0)
                        _DAT_006915f0 = 0;
                    while (dwCog_UnfreezePlayer() != 0) { }
                    if ((pStats->totals.capFlags & 2) == 0)
                    {
                        _DAT_00691528 = 0;
                        _DAT_0069158c = 0;
                    }
                }

                sithOpenPostProcess();
                dwCog_bInteractBusy = 0;
                dwCog_pendingMessage = 0;
                if (this->pMissionInfo->missionType == 5)
                    pThing->collide = 0;
                sithInventory_SetInventoryAvailable(pThing, 10, (dwCog_droidCaps & 0x20) != 0);
                if ((dwCog_droidCaps & 0x40000) == 0)
                {
                    sithInventory_SetInventoryAvailable(pThing, 0xb, 0);
                }
                else
                {
                    sithInventory_SetInventoryAvailable(pThing, 0xb, 1);
                    pThing->actorParams.lightOffset.x = 0.0f;
                    pThing->actorParams.lightOffset.y = 0.0f;
                    pThing->actorParams.lightOffset.z = 0.0f;
                }
                sithInventory_SetInventoryAvailable(pThing, 0xc, (dwCog_droidCaps & 0x100) != 0);
                _DAT_0069a658 = (float)(uint16_t)pStats->totals.batteryCapacity;
                sithInventory_SetInventory(pThing, 0x14, (float)(uint16_t)pStats->totals.batteryCharge);
                pThing->actorParams.flags |= 0x40;
            }
        }
        dwSegment::ResetClock();
        jklName.Free();
    }

    stdControl_ReadControls();
    this->voicePriority = 0;
    this->bVoicePlaying = 0;
    this->voiceEndMs = 0;
    if (this->pMissionInfo->missionType == 4)
    {
        // FINAL-type: broadcast the "mission selected" message (0xBBC) to the HUD.
        dwWidgetMsg m = { 0xbbc, NULL, 0, NULL };
        dwWidget_DispatchMsg(&m, NULL);
    }
    return (bActivated != 0 && g_sithMode != 0) ? 1 : 0;
}

// ----------------------------------------------------------------------------
// segment lifecycle: OnHide / Pause / Resume / SegUpdate
// ----------------------------------------------------------------------------

// @420410
void dwGuiInGame::Deactivate()
{
    if (this->deathFadeHandle >= 0)
    {
        stdPalEffects_FreeRequest(this->deathFadeHandle);
        this->deathFadeHandle = -1;
    }
    StopSounds();
    dwGuiScreen::Deactivate();
    // On a normal (non-training) exit, fade the HUD viewport to transparent.
    if ((stdPalEffects_numEffectRequests != 0 || this->bDying != 0) && this->pMissionInfo->missionType != 5)
    {
        // Note: the binary paints two transparent fills through the locked
        // screen surface; omitted (needs a locked dwImageBits). Present twice.
        dwDisplay_Present();
        dwDisplay_Present();
    }
    dwColormap_Apply();
}

// @420580
void dwGuiInGame::StopSounds()
{
    StopVoiceLine();
    dwGuiListItem* pItem = this->pSelectedResponse;
    if (pItem != NULL)
    {
        // Stop the selected response's VO wav (textB, char* at item+0x1c) and,
        // if it owns a conversation cog (item->data), wake it now so its script
        // stops waiting on the (now-cancelled) response.
        if (pItem->textB.length != 0)
        {
            dwSound_Stop(pItem->textB.pBuffer);
            if (dwSound_pManager) dwSound_pManager->FreeAllSamples();
        }
        sithCog* pCog = (sithCog*)pItem->data;
        if (pCog != NULL)
            pCog->msecTimerTimeout = sithTime_g_msecGameTime;
    }
    if (this->pNpcSpeech != NULL)
        dwGuiSpeech_Clear(this->pNpcSpeech);
}

// @420be0
void dwGuiInGame::Suspend()
{
    sithTime_Pause();
    sithSoundMixer_StopAll();
    dwGuiScreen::Suspend();
}

// @420c00
void dwGuiInGame::Resume()
{
    sithSoundMixer_ResumeAll();
    sithTime_Resume();
    dwGuiScreen::Resume();
    stdPalEffects_RefreshPalette();
}

// @420c20 — per-frame mission tick. See the FIDELITY NOTE (movement-sound +
// physics reads touch DW-forked SithThing fields; the gauge/chatter/energy/
// death/voice logic is preserved).
void dwGuiInGame::Update()
{
    SithThing* pThing = sithWorld_g_pCurrentWorld->pLocalPlayer;

    // A response was selected (bConvActive) and it carries a conversation cog:
    // notify that cog (DW message 0x2f = 47) and clear the pending flag.
    if (this->pSelectedResponse != NULL && this->pSelectedResponse->data != NULL
        && this->bConvActive != 0)
    {
        this->bConvActive = 0;
        sithCog_SendMessage((sithCog*)this->pSelectedResponse->data,
                            (SITH_MESSAGE)0x2f, 0, 0, 0, 0, 0);
    }

    // Auto-clear a finished Cammy caption.
    if (this->bVoicePlaying != 0 && this->voiceEndMs <= sithTime_g_msecGameTime)
    {
        char* pCammy = this->pCammyText ? this->pCammyText->text.pBuffer : NULL;
        if (pCammy == NULL || *pCammy == '\0')
        {
            this->bVoicePlaying = 0;
            ClearCammyText();
        }
    }

    stdPalEffects_UpdatePalette(stdDisplay_GetPalette());

    // 'H' holster toggle (sithControl key 0x26): edge-toggle bHolstered — it
    // flips on key-down while unholstered, or key-up while holstered — then set
    // the cursor (0 = holstered; else aim/normal per the base pick mode).
    int bHolsterKey = sithControl_GetKey(0x26, NULL);
    char wasHolstered = this->bHolstered;
    if ((wasHolstered == 0) ? (bHolsterKey != 0) : (bHolsterKey == 0))
    {
        this->bHolstered = (wasHolstered == 0) ? 1 : 0;
        int idx = (this->bHolstered == 0) ? (this->bActive ? 3 : 1) : 0;
        dwCursor_SetCursor(idx);
    }

    float speed = 0.0f;
    // Run the sith world tick (control apply -> player movement, physics, AI,
    // sithCog_ProcessCogs) while the mission is live. ⚠ The gate is bEndRequested
    // (obj+0x124): SegUpdate's `this` is the dwSegment subobject (obj+0x10), so
    // the binary's `[this+0x114]` is obj+0x124, NOT pNpcSpeech (obj+0x114) — the
    // prior mistranslation skipped the entire sim once NPCSPEECH existed.
    if (this->bEndRequested == 0 && g_sithMode != 0)
    {
        sithUpdate();
        // TODO(dw-decomp): movement-driven servo-sound pitch/volume + energy
        // drain read pThing->physicsParams.vel/maxVelocity/angularVelocity and
        // drive sithSoundClass/sithSoundMixer — DW-forked layout (P8). The
        // per-frame Invalidate is kept.
        Invalidate();
    }

    // Gauges (dwGuiIndicator; SPEED = velocity/maxVelocity, DAMAGE = health,
    // POWER = battery/max).
    float maxVel = pThing->physicsParams.maxVelocity;
    if (this->pSpeedGauge != NULL)
        dwGuiIndicator_SetProgress(this->pSpeedGauge, (maxVel != 0.0f) ? (speed / maxVel) : 0.0f);
    float healthFrac = pThing->actorParams.health / pThing->actorParams.maxHealth;
    if (this->pDamageGauge != NULL)
        dwGuiIndicator_SetProgress(this->pDamageGauge, healthFrac);
    if (this->pDamageGauge != NULL)
        (healthFrac > 0.3f ? dwGuiIndicator_Hide : dwGuiIndicator_Show)(this->pDamageGauge);

    float invMax = sithInventory_GetInventoryMaximum(pThing, 0x14);
    float cur = sithInventory_GetInventory(pThing, 0x14);
    float powerFrac = (invMax != 0.0f) ? (cur / invMax) : 0.0f;
    if (this->pPowerGauge != NULL)
        dwGuiIndicator_SetProgress(this->pPowerGauge, powerFrac);
    if (this->pPowerGauge != NULL)
        (powerFrac > 0.3f ? dwGuiIndicator_Hide : dwGuiIndicator_Show)(this->pPowerGauge);

    // Ambient GHCA*.wav chatter (low power / hurt / idle / happy).
    // Added: faithful selector — the binary computes (int)(rand() * 3.05185e-5f
    // * count) over win32 rand() (0..0x7fff); mask to 15 bits so platform
    // RAND_MAX differences can't index out of the table. (An earlier `% 3` fix
    // guessed the table sizes; the real ones are 4/2/3/6 — see dwMain.cpp.)
    #define DW_CHATTER_PICK(count) ((int)((float)(_rand() & 0x7fff) * 3.05185e-05f * (float)(count)))
    const char* pWav = NULL;
    this->chatterTimerHappy += sithTime_g_frameTimeFlex;
    this->chatterTimerLow += sithTime_g_frameTimeFlex;
    if (powerFrac <= 0.33f)
    {
        float inv10 = sithInventory_GetInventory(pThing, 0x10);
        if (inv10 == 0.0f || this->chatterTimerLow < _DAT_00528698)
        {
            if (!(this->chatterTimerLow < _DAT_0052869c && (powerFrac > 0.15f || this->chatterTimerLow < _DAT_00528698)))
            {
                pWav = PTR_s_GHCA009_wav_00528688[DW_CHATTER_PICK(4)]; // binary: ×4, 4-entry table
                this->chatterTimerLow = 0;
                this->chatterTimerHappy = 0;
            }
        }
        else
        {
            pWav = "GHCA011.wav";
            this->chatterTimerLow = 0;
            this->chatterTimerHappy = 0;
        }
    }
    this->chatterTimerHurt += sithTime_g_frameTimeFlex;
    if (pWav == NULL && 5.0f < this->lastHealth - pThing->actorParams.health)
    {
        // Binary quirk: this site scales by ×1, so it effectively always plays
        // GHCA006 (entry [1] GHCA007 is unreachable; kept for fidelity).
        pWav = PTR_s_GHCA006_wav_00528678[DW_CHATTER_PICK(1)];
        this->chatterTimerHurt = 0;
        this->chatterTimerHappy = 0;
    }
    this->lastHealth = pThing->actorParams.health;
    if (speed == 0.0f
        // Note: binary reads [pNpcSpeech+0x1c] = text (dwString @0x14) .pBuffer
        // (@+8); the raw offset is wrong on 64-bit (crashed) — use the member.
        && (this->pNpcSpeech == NULL || this->pNpcSpeech->text.pBuffer == NULL || *this->pNpcSpeech->text.pBuffer == '\0')
        && (this->pPlayerSpeech == NULL))
    {
        this->chatterTimerIdle += sithTime_g_frameTimeFlex;
        if (pWav == NULL && _DAT_005286d4 <= this->chatterTimerIdle)
        {
            pWav = PTR_s_GHCA058_wav_005286c8[DW_CHATTER_PICK(3)]; // binary: ×3, 3-entry table
            this->chatterTimerIdle = 0;
            this->chatterTimerHappy = 0;
        }
    }
    else
    {
        this->chatterTimerIdle = 0;
    }
    if (pWav == NULL && healthFrac >= 0.8f && powerFrac >= 0.8f && _DAT_005286c0 <= this->chatterTimerHappy)
    {
        pWav = PTR_s_GHCA048_wav_005286a8[DW_CHATTER_PICK(6)]; // binary: ×6, 6-entry table
        this->chatterTimerHappy = 0;
    }
    if (pWav != NULL && 0.0f < pThing->actorParams.health)
        PlayVoiceLineEx(0, (char*)pWav, 0, 0);

    dwGuiScreen::Update();

    if (this->bEndRequested != 0)
    {
        EndMission();
        return;
    }
    if (this->bDying == 0)
    {
        if (cur <= 0.0f || pThing->actorParams.health <= 0.0f)
        {
            this->bDying = 1;
            this->deathStartMs = sithTime_g_msecGameTime;
            this->deathFadeHandle = stdPalEffects_NewRequest(2);
        }
    }
    else
    {
        float t = (float)(sithTime_g_msecGameTime - this->deathStartMs) / 2000.0f;
        if (1.0f <= t)
        {
            this->bEndRequested = 1;
            return;
        }
        if (this->deathFadeHandle >= 0)
        {
            stdPalEffects_SetFade(this->deathFadeHandle, 1.0f - t);
            stdPalEffects_UpdatePalette(stdDisplay_GetPalette());
        }
    }
}

// ----------------------------------------------------------------------------
// EndMission — @4205e0
// ----------------------------------------------------------------------------

void dwGuiInGame::EndMission()
{
    StopSounds();
    bool bMissionType = false;
    bool bAllObjectivesDone = false;
    SithThing* pThing = sithWorld_g_pCurrentWorld->pLocalPlayer;
    float invMax = sithInventory_GetInventoryMaximum(pThing, 0x14);
    float invCur = sithInventory_GetInventory(pThing, 0x14);
    float maxHp = pThing->actorParams.maxHealth;
    float hp = pThing->actorParams.health;
    int32_t chargeMax = (int32_t)invMax;

    int missionType = this->pMissionInfo->missionType;
    if (missionType != 5 && missionType != 4)
    {
        bMissionType = true;
        sithCog_BroadcastMessage((SITH_MESSAGE)0x16, 0, 0, 0, 0);
        uint8_t rank = this->pMissionInfo->rank;
        if (rank > 2) rank = 2;
        // Walk the mission objectives; an objective of this rank is satisfied
        // when its inventory bin is owned. (dwMissionObjective: type@0xc,
        // invBin@0x10, satisfied-flag@0x15 — DW record.)
        dwListNode* pSentinel = this->pMissionInfo->pObjectives;
        bAllObjectivesDone = true;
        for (dwListNode* pNode = pSentinel->pNext; pNode != pSentinel; pNode = pNode->pNext)
        {
            uint8_t* pObj = (uint8_t*)pNode->pData;
            pObj[0x15] = 0;
            if (pObj[0xc] == rank)
            {
                flex_t owned = sithInventory_GetInventory(pThing, *(int*)(pObj + 0x10));
                if (owned == 0.0f)
                    bAllObjectivesDone = false;
                else
                    pObj[0x15] = 1;
            }
        }
    }

    Window_RemoveMsgHandler(stdControl_MessageHandler);
    sithCamera_Close();
    sithClose();
    dwGuiInGame_pActive = NULL;
    rdMaterial_RegisterLoader(dwMain_MaterialLoaderCb);
    rdMaterial_RegisterUnloader(dwMain_MaterialUnloaderCb);
    rdModel3_RegisterLoader(NULL);
    rdModel3_RegisterUnloader(NULL);
    rdKeyframe_RegisterLoader(NULL);
    rdKeyframe_RegisterUnloader(NULL);
    sithRender_Close(); // Not sure, but no-op in any case

    if (bMissionType)
    {
        if (bAllObjectivesDone)
        {
            if (this->pMissionInfo->missionType == 2) // FINAL win -> end-game sequence
            {
                dwSegment_Pop();
                dwSegment_Release(dwSegment_pActive);
                dwSegment_Pop();
                dwSegment_Release(dwSegment_pActive);
                dwSegment_Push(dwGuiOptions_New(0));
                dwSegment_Push(dwGuiCredits_New());
                dwPlayer_statsFlags |= 0x10;
                dwSegment_Push(dwEnding_New());
                this->pMissionInfo->rank = 3;
                dwPlayer_SavePlr();
            }
            else
            {
                float itemPct = (invMax != 0.0f) ? (invCur / invMax) : 0.0f;
                float hpPct = (maxHp != 0.0f) ? (hp / maxHp) : 0.0f;
                dwSegment_Push(dwGuiStatus_New(this->pMissionInfo, itemPct, hpPct, chargeMax));
                dwSegment_Push(dwCompleteMovie_New(_rand() % 3));
            }
        }
        else
        {
            float itemPct = (invMax != 0.0f) ? (invCur / invMax) : 0.0f;
            float hpPct = (maxHp != 0.0f) ? (hp / maxHp) : 0.0f;
            dwSegment_Push(dwGuiStatus_New(this->pMissionInfo, itemPct, hpPct, chargeMax));
        }
    }
    if (dwSegment_pActive != NULL)
        dwSegment_RequestAdvance();
}

// ----------------------------------------------------------------------------
// RebuildViewport — @420a70
// ----------------------------------------------------------------------------

int dwGuiInGame::RebuildViewport()
{
    if (this->pViewCanvas != NULL)
        sithRender_Open();

    // Inset the viewRect by the (100 - dw_viewSizePct) % on each axis.
    int w = this->viewRect.right - this->viewRect.left;
    int h = this->viewRect.bottom - this->viewRect.top;
    int16_t insetX = (int16_t)((w - (int)((short)w * dw_viewSizePct) / 100) >> 1);
    this->insetRect.left = insetX + this->viewRect.left;
    this->insetRect.right = this->viewRect.right - insetX;
    int16_t insetY = (int16_t)((h - (int)((uint32_t)((short)h * dw_viewSizePct) / 100)) >> 1);
    this->insetRect.top = this->viewRect.top + insetY;
    this->insetRect.bottom = this->viewRect.bottom - insetY;

    this->pViewCanvas = (rdCanvas*)(*dwMain_pHS->alloc)(sizeof(rdCanvas));
    // In-place canvas over the DW back buffer (binary: 8-arg rdCanvas_New — the
    // repo NewEntry adds a trailing a9/field_14 not present in the DW call, pass
    // 0; matches the dwGui3DView sibling). DAT_006b5a40 == dwDisplay_pBackVBuf.
    rdCanvas_NewEntry(this->pViewCanvas, 3, dwDisplay_pBackVBuf, dwDisplay_pSwBuffer,
                 this->insetRect.left, this->insetRect.top, this->insetRect.right - 1, this->insetRect.bottom - 1, 0);
    this->aimCenterX = (float)(this->insetRect.left + this->insetRect.right) * 0.5f;
    this->aimCenterY = (float)(this->insetRect.bottom + this->insetRect.top) * 0.5f;
    // Note: the binary reads the aspect from its stdDisplay video-mode record
    // (DAT_006478f8+4). In OpenJKDF2 that IS the repo's stdDisplay_pCurVideoMode
    // (dwDisplay_SetMode routes through stdDisplay_SetMode) — JK passes the same
    // stdDisplay_pCurVideoMode->widthMaybe field here. DAT_006478f8 is an unset
    // DW-fork placeholder, so use the real global.
    return sithCamera_Open(this->pViewCanvas, stdDisplay_pCurVideoMode->widthMaybe);
}

// ----------------------------------------------------------------------------
// BuildDroidStats — @422050
// ----------------------------------------------------------------------------

void dwGuiInGame::BuildDroidStats(SithThing* pPlayer)
{
    (void)pPlayer;
    void* pRoot = NULL;
    for (dwListNode* pNode = dwCore_pWorkspaceNodes->pNext; pNode != dwCore_pWorkspaceNodes; pNode = pNode->pNext)
    {
        if (((dwPartNode*)pNode->pData)->partType == 0xb) // DW_PARTTYPE_NONE (root)
        {
            pRoot = pNode->pData;
            break;
        }
    }
    if (pRoot != NULL)
        this->pDroidStats = (new dwDroidStats)->Build((dwPartNode*)pRoot);
}

// ----------------------------------------------------------------------------
// voice line / cammy caption / console
// ----------------------------------------------------------------------------

// @422100
void dwGuiInGame::StopVoiceLine()
{
    if (this->currentVoiceWav.length != 0)
    {
        dwSound_Stop(this->currentVoiceWav.pBuffer);
        if (dwSound_pManager) dwSound_pManager->FreeAllSamples();
    }
    this->currentVoiceWav.AssignCStr("");
    this->voicePriority = 0;
}

// @422160
void dwGuiInGame::ClearCammyText()
{
    StopVoiceLine();
    this->pCammyText->Clear();
}

// @422180
void dwGuiInGame_PlayVoiceLine(const char* pCammyText, const char* pWavName, uint32_t priority)
{
    // Binary: __thiscall on dwGuiInGame_pActive. pCammyText is the caption
    // message code (as in the binary's PlayVoiceLine signature).
    if (dwGuiInGame_pActive != NULL)
        dwGuiInGame_pActive->PlayVoiceLineEx((uint32_t)(uintptr_t)pCammyText, (char*)pWavName, priority, 0);
}

// @4221a0
void dwGuiInGame::PlayVoiceLineEx(uint32_t msgCode, char* pWavName, uint32_t priority, char bForce)
{
    // Added: pWavName may be NULL (caption-only lines); the dwString_Equals
    // fast-path below deref's it, so guard.
    if (pWavName == NULL)
        pWavName = (char*)"";
    if (this->currentVoiceWav.length != 0 && dwString_Equals(this->currentVoiceWav.pBuffer, pWavName))
    {
        if (priority > this->voicePriority)
            this->voicePriority = priority;
        return;
    }
    // Note: binary [pNpcSpeech+0x1c] = text.pBuffer; raw offset wrong on 64-bit.
    char* pNpc = this->pNpcSpeech ? this->pNpcSpeech->text.pBuffer : NULL;
    bool bNpcIdle = (pNpc == NULL || *pNpc == '\0');
    bool bNoResponse = (this->pPlayerSpeech == NULL);
    if (this->voicePriority <= priority && bNpcIdle && bNoResponse && this->pMissionInfo->missionType != 5)
    {
        if (this->currentVoiceWav.length != 0 && (this->bVoiceEnabled != 0 || bForce != 0))
            ClearCammyText();
        ShowCammyText(msgCode);
        this->voicePriority = priority;
        uint32_t lenMs = 0;
        if ((this->bVoiceEnabled != 0 || bForce != 0))
        {
            void* pSample = dwSound_Play(pWavName);
            if (pSample != NULL)
            {
                lenMs = ((dwSoundSample*)pSample)->GetLengthMs();
                this->currentVoiceWav.AssignCStr(pWavName);
            }
        }
        this->bVoicePlaying = 1;
        this->voiceEndMs = lenMs + sithTime_g_msecGameTime;
    }
}

// @4222e0
void dwGuiInGame::ShowCammyText(uint32_t msgCode)
{
    this->cammyMsgCode = msgCode;
    char key[12];
    _sprintf(key, "%05lu", (unsigned long)msgCode);
    void* pEntry = NULL;
    if (this->pStringTable != NULL)
        pEntry = this->pStringTable->Find(key);

    // Added: nullptr check
    if (!this->pCammyText) {
        stdPlatform_Printf("OpenJKDF2: this->pCammyText is NULL!\n");
        return;
    }

    this->pCammyText->text.Free();
    if (pEntry != NULL)
    {
        this->pCammyText->SetText(*(char**)((char*)pEntry + 8));
    }
    else
    {
        this->pCammyText->SetText(NULL);
        this->voicePriority = 0;
    }
}

// @4214d0
void dwGuiInGame::ClearPlayerSpeech()
{
    if (this->pPlayerSpeech != NULL)
        dwGuiList_Clear(this->pPlayerSpeech);
    this->pSelectedResponse = NULL;
    this->bConvActive = 0;
}

// @421510
void dwGuiInGame::SetRefTopic(char* pTopic)
{
    if (pTopic != NULL && *pTopic != '\0')
    {
        dwCore_currentRefFile.Assign(pTopic, 0);
        // (a REFERENCE_BUTTON blink follows in the binary via pReferenceButton;
        // that button pointer is stored @0x190 in the binary, not modelled.)
    }
}

// (ConsolePrint is the C shim dwGuiInGame_ConsolePrint, defined below.)

// ----------------------------------------------------------------------------
// input
// ----------------------------------------------------------------------------

// @421540
int dwGuiInGame::OnMouseMove(int16_t x, int16_t y)
{
    int r = dwGuiScreen::OnMouseMove(x, y);
    if (this->pTooltipFont == NULL && dwCursor_curIdx != 1 && dwCursor_curIdx != 3
        && sithWorld_g_pCurrentWorld != NULL && sithWorld_g_pCurrentWorld->pLocalPlayer != NULL)
    {
        SithThing* pThing = sithWorld_g_pCurrentWorld->pLocalPlayer;
        rdVector3* v = &pThing->physicsParams.vel;
        float mag = sqrtf(v->z * v->z + v->y * v->y + v->x * v->x);
        if (mag < 0.0f) mag = -mag;
        if (mag <= 1e-05f) mag = 0.0f;
        if (mag == 0.0f)
            dwCursor_SetCursor(this->bActive ? 3 : 1);
    }
    Invalidate();
    return r;
}

// @4209e0
int dwGuiInGame::OnMouseUp(int16_t x, int16_t y)
{
    if (this->bActive != 0 && this->pPickedWidget == NULL)
    {
        bool bInView = !(x < this->viewRect.left || this->viewRect.right <= x
                         || y < this->viewRect.top || this->viewRect.bottom <= y);
        if (bInView)
        {
            // Binary dispatches a (lost-in-decompile) message on a click in the
            // 3D viewport. TODO(dw-decomp): recover the message payload.
            dwWidgetMsg m = { 0, NULL, 0, NULL };
            dwWidget_DispatchMsg(&m, NULL);
        }
    }
    dwGuiScreen::OnMouseUp(x, y);
    return 0;
}

// @421630
int dwGuiInGame::OnKey(int key, int repeat)
{
    int handled = dwGuiScreen::OnKey(key, repeat);
    if (handled == 0 && g_sithMode != 0)
    {
        switch ((char)key)
        {
        case '\x01': // Esc
        case 'P':
        case 'p':
        {
            dwGuiInGamePause* pPause = new dwGuiInGamePause();
            dwSegment_InterruptWith(dwSegment_pActive, static_cast<dwSegment*>(pPause));
            break;
        }
        case '\x1b': // ESC: training exits; else (if Esc enabled) stop sounds
            if (this->pMissionInfo->missionType == 5)
                dwSegment_RequestAdvance();
            else if (this->bEscapeEnabled != 0)
                StopSounds();
            break;
        case '*':
        case 'H':
        case 'h':
        {
            // Holster: for each selectable, non-toggle inventory item currently
            // available, drop it.
            SithThing* pThing = sithWorld_g_pCurrentWorld->pLocalPlayer;
            for (uint32_t i = 0; i < 0x32; i++)
            {
                uint32_t flags = sithInventory_g_aTypes[i].flags;
                if ((flags & 8) != 0 && (flags & 2) == 0
                    && sithInventory_IsInventoryAvailable(pThing, i) != 0)
                    sithInventory_BinSendActivate(pThing, i);
            }
            break;
        }
        }
    }
    return handled;
}

// ----------------------------------------------------------------------------
// OnMessage — @4218d0
// ----------------------------------------------------------------------------

int dwGuiInGame::OnMessage(dwWidgetMsg* pMsg)
{
    int handled = 0;
    switch (pMsg->code)
    {
    case 0x96: // quit mission
        handled = 1;
        if (this->bEndRequested == 0 && g_sithMode != 0
            && (this->pMissionInfo->missionType == 5
                || dwGuiDialog_RunModal("gyesno", "DLG_MISSIONQUIT") == 5000))
            dwSegment_RequestAdvance();
        break;
    case 0x6a: // REFERENCE_BUTTON / InDex: launch the reference-intro segment
    {
        handled = 1;
        // The binary installs the reference-intro segment (dwGuiRefIntroSeg,
        // vtable 0x51f238). ⚠ A bare dwSegment here NEVER advances (its base
        // Update is a no-op and never RequestAdvances) -> the segment stack
        // sticks on a do-nothing overlay and the game freezes. Use the real
        // factory so the intro -> reference-room chain runs.
        dwSegment* pSeg = dwGuiReference_NewIntroSeg();
        if (pSeg != NULL)
            dwSegment_InterruptWith(dwSegment_pActive, pSeg);
        break;
    }
    case 0x1f40: // (== 8000) a response menu item was clicked: remember it +
                 // flag the conversation cog for msg 0x2f on the next SegUpdate
        this->bConvActive = 1;
        this->pSelectedResponse = (dwGuiListItem*)pMsg->pSender;
        break;
    case 0x1788: // set game-speed % -> rebuild the 3D viewport
        if ((uintptr_t)pMsg->pSender != dw_viewSizePct && g_sithMode != 0)
        {
            dw_viewSizePct = (uint32_t)(uintptr_t)pMsg->pSender;
            sithCamera_Close();
            RebuildViewport();
        }
        break;
    case 0x1f41: // help toggle: mark handled while HELPTEXT has runs
        if (this->pHelpText != NULL)
        {
            dwList* pRuns = &this->pHelpText->elements;
            if (pRuns->pSentinel != pRuns->pSentinel->pNext)
                handled = 1;
        }
        break;
    case 0x1f42: // toggle voice enabled
        this->bVoiceEnabled = (this->bVoiceEnabled == 0);
        if (this->bVoiceEnabled == 0)
            StopVoiceLine();
        break;
    case 0x1f43: // HELP/CAMMY link click (unlink + re-append the two texts)
    case 0x1f44:
        if (this->pHelpText != NULL)
            dwGuiInGame_UnlinkWidgetNode(&this->controls.children, this->pHelpText);
        if (this->pHideHelp != NULL)
            dwGuiInGame_UnlinkWidgetNode(&this->controls.children, this->pHideHelp);
        Invalidate();
        break;
    }
    if (handled == 0)
        handled = dwGuiScreen::OnMessage(pMsg);
    return handled;
}

// ----------------------------------------------------------------------------
// draw / images
// ----------------------------------------------------------------------------

// @421ca0
void dwGuiInGame::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    EnsureImages();
    if (dw_viewSizePct != 100)
    {
        // Letterbox the viewRect around the inset viewport with transparent fills.
        dwRect r;
        r.left = this->viewRect.left; r.top = this->viewRect.top;
        r.right = this->viewRect.right; r.bottom = this->insetRect.top;
        dwImageDraw_FillRect(pDestBits, &r, dwColormap_transparentIdx, pClipRect);
        r.top = this->insetRect.bottom; r.bottom = this->viewRect.bottom;
        dwImageDraw_FillRect(pDestBits, &r, dwColormap_transparentIdx, pClipRect);
        r.top = this->viewRect.top; r.bottom = this->viewRect.bottom;
        r.left = this->viewRect.left; r.right = this->insetRect.left;
        dwImageDraw_FillRect(pDestBits, &r, dwColormap_transparentIdx, pClipRect);
        r.left = this->insetRect.right; r.right = this->viewRect.right;
        dwImageDraw_FillRect(pDestBits, &r, dwColormap_transparentIdx, pClipRect);
    }

    rdAdvanceFrame();
#ifdef RDRASTER_SOFTWARE_RENDERER
    // Added: render the world 3D through the software (CPU) rasterizer when the r_softwareRenderer
    // cvar is on. Acceleration is set to 0 so rdCache_Flush takes its software branch; the world +
    // weapon draw is redirected into a dedicated full-resolution buffer (presented full-screen by
    // std3D_DrawMenu), keeping Video_menuBuffer as the 640x480-logical HUD overlay composited on top.
    // When the cvar is OFF, none of this runs and the normal hardware (GL) path renders the frame.
    int rdsw_bActive = rdroid_bSoftwareRenderer;
    int rdsw_savedAccel = rdroid_curAcceleration;
    tVBuffer* rdsw_pWorldBuf = NULL;
    tVBuffer* rdsw_pSavedVBuf = NULL;
    tVBuffer* rdsw_pRenderBuf = NULL;
    // On a hardware->software transition, free the material GL textures the hardware path uploaded:
    // the software rasterizer samples texels from the system-RAM SDL surfaces and never touches VRAM,
    // so those textures are dead weight while SW is active. They re-upload lazily (texture_loaded is
    // reset) if the user switches back to hardware. (UI/HUD textures are a separate cache, untouched.)
    static int rdsw_bWasActive = 0;
    if (rdsw_bActive && !rdsw_bWasActive)
        std3D_PurgeEntireTextureCache();
    rdsw_bWasActive = rdsw_bActive;
    if (rdsw_bActive)
    {
        rdroid_curAcceleration = 0;
        // The world buffer matches the menu buffer dims, so redirecting the canvas at it leaves the
        // canvas geometry unchanged. (std3D_DrawMenu samples only a 640x480 sub-rect of the menu
        // buffer, which is why rendering the world there put it in a corner.)
        rdsw_pWorldBuf = Video_swEnsureWorldBuffer();
        rdsw_pRenderBuf = rdsw_pWorldBuf;
        if (rdsw_pWorldBuf && Video_pCanvas)
        {
            rdsw_pSavedVBuf = Video_pCanvas->pVBuffer;
            Video_pCanvas->pVBuffer = rdsw_pWorldBuf;
            // Clear to fill color (index 0) so untouched pixels present transparent (menu shader
            // discards index 0), matching the per-frame Video_pMenuBuffer fill for the world.
            stdDisplay_VBufferLock(rdsw_pWorldBuf);
            stdDisplay_VBufferFill(rdsw_pWorldBuf, Video_fillColor, 0);
        }
        else
        {
            // No world buffer yet — fall back to the menu buffer (renders into the corner, as before).
            rdsw_pRenderBuf = Video_pMenuBuffer;
            // The software rasterizer writes pixels directly, so the canvas surface must be
            // locked (surface_lock_alloc is NULL otherwise on the accelerated present path).
            stdDisplay_VBufferLock(Video_pMenuBuffer);
        }
#ifdef RDRASTER_SW_ZBUFFER
        // Clear the software depth buffer for the frame BEFORE the world is drawn. This must happen
        // here (not only via std3D_ClearZBuffer) because rdCamera_AdvanceFrame clears JK's software
        // z-buffer by filling canvas->d3d_vbuf on the accel<=0 path, so the std3D hook never fires at
        // scene start — leaving the depth buffer unallocated until DrawPov clears it (hence the world
        // only appeared once a POV weapon existed).
        rdZRaster_BeginFrame(rdsw_pRenderBuf);
#endif
    }
#endif
    sithDrawScene(); // render the 3D world into the viewport
    rdFinishFrame();
#ifdef RDRASTER_SOFTWARE_RENDERER
    // Added: close the software-render bracket (mirrors jkGame_Update's post-DrawPov close). Unlock
    // the world buffer, restore the canvas to the menu/HUD buffer, flag the world for present (so
    // std3D_PresentSWWorld pushes Video_pSwWorldBuffer and std3D_DrawMenu skips its own menu quad —
    // the HUD is folded in later by Video_swCompositeOverlaysIntoWorld in dwDisplay_Present), and
    // restore acceleration. DW has no first-person weapon, so there is no DrawPov between the world
    // draw and this close. Without this the world buffer never presents (blank 3D view).
    if (rdsw_bActive)
    {
        if (rdsw_pWorldBuf && Video_pCanvas)
        {
            stdDisplay_VBufferUnlock(rdsw_pWorldBuf);
            Video_pCanvas->pVBuffer = rdsw_pSavedVBuf; // restore the menu-buffer canvas for the HUD
            Video_swWorldPresentPending = 1;           // world rendered this frame → present it
        }
        else
        {
            stdDisplay_VBufferUnlock(Video_pMenuBuffer);
        }
        rdroid_curAcceleration = rdsw_savedAccel;
    }
#endif

    dwRect clip = *pClipRect;
    dwRect_Union(&clip, &this->viewRect);
    ((dwWidget*)&this->overlayGroup)->DrawChild(pDestBits, &clip);
    dwGuiScreen::Draw(pDestBits, &clip);

    // Debug FPS/position overlay (toggle-hud cheat).
    if (this->bShowDebugOverlay && this->pConsoleFont != NULL)
    {
        this->debugFrameCount++;
        int now = stdPlatform_GetTimeMsec();
        this->debugNowMs = now;
        SithThing* pThing = sithWorld_g_pCurrentWorld->pLocalPlayer;
        int span = now - (int)this->debugWindowStartMs;
        _sprintf(std_g_genBuffer, "%02.3f  X:%02.4f Y:%02.4f Z:%02.4f  %3ds %3da %3dz %4dp %3dfo",
                 (span != 0) ? ((double)(this->debugFrameCount - this->debugWindowStartFrame) * 1000.0 / (double)span) : 0.0,
                 (double)pThing->position.x, (double)pThing->position.y, (double)pThing->position.z,
                 DAT_0054518c, DAT_00545190, DAT_00545194, DAT_005b7200, DAT_00546880);
        dwPoint pt; pt.x = this->viewRect.left; pt.y = this->viewRect.top;
        dwFont_DrawStringClipped(pDestBits, this->pConsoleFont, &pt, std_g_genBuffer, 0, pClipRect);
        if ((uint32_t)(now - (int)this->debugWindowStartMs) > 1000)
        {
            this->debugWindowStartMs = now;
            this->debugWindowStartFrame = this->debugFrameCount;
        }
    }

    // HUD console ring (console cheat).
    if (this->bConsoleOn && this->pConsoleFont != NULL)
    {
        int16_t x = this->viewRect.left;
        int16_t y = this->viewRect.top + 0x46;
        for (int i = 0; i < 0xf; i++)
        {
            dwString* pLine = &this->consoleLines[(i + this->consoleWriteIdx) % 0xf];
            if (pLine->length != 0)
            {
                dwPoint pt; pt.x = x + 0xf; pt.y = y;
                dwFont_DrawStringClipped(pDestBits, this->pConsoleFont, &pt, pLine->pBuffer, 0, pClipRect);
                y += (int16_t)this->pConsoleFont->pHeader->lineHeight;
            }
        }
    }
}

// @421fd0
void dwGuiInGame::EnsureImages()
{
    dwGuiScreen::EnsureImages();
    ((dwWidget*)&this->overlayGroup)->EnsureImages();
    if (this->pHelpText != NULL)
        this->pHelpText->EnsureImages();
    if (this->pHideHelp != NULL)
        this->pHideHelp->EnsureImages();
}

// @422010
void dwGuiInGame::FreeImages()
{
    dwGuiScreen::FreeImages();
    ((dwWidget*)&this->overlayGroup)->FreeImages();
    if (this->pHelpText != NULL)
        this->pHelpText->FreeImages();
    if (this->pHideHelp != NULL)
        this->pHideHelp->FreeImages();
}

// ----------------------------------------------------------------------------
// CreateControl — @422370
// ----------------------------------------------------------------------------

dwWidget* dwGuiInGame::CreateControl(char* pKeyword, dwConfFile* pConf)
{
    if (dwString_Equals(pKeyword, "VIEWRECT"))
    {
        rdSetZBufferMethod(RD_ZBUFFER_READ_WRITE); // binary: rd_FUN_0047eb60(2)
        dwConfFile_ParseRect(pConf, &this->viewRect);
        return NULL;
    }
    if (dwString_Equals(pKeyword, "VIEWSIZE"))
    {
        char* tok = dwConfFile_NextToken(pConf);
        dwWidget* pW = dwGuiScreen::CreateControl(tok, pConf);
        if (pW != NULL)
            ((dwGuiScrollBar*)pW)->SetValue(dw_viewSizePct);
        return pW;
    }
    if (dwString_Equals(pKeyword, "HELP"))
    {
        dwRect r; r.left = r.top = r.right = r.bottom = 0;
        return (dwWidget*)dwHelp_Ctor((dwHelp*)(*dwMain_pHS->alloc)(sizeof(dwHelp)), &r, 0, 0x6b); // sizeof, not 32-bit 0x5c
    }
    if (dwString_Equals(pKeyword, "HELPTEXT"))
    {
        dwRect r; r.left = r.top = r.right = r.bottom = 0;
        dwConfFile_ParseRect(pConf, &r);
        char* pFontName = dwConfFile_NextToken(pConf);
        uint32_t color = 0;
        dwConfFile_ParseULong(pConf, &color);
        char* pText = dwGuiScreen_LocalizeString((char*)"HUD_HELP_PC", dwGuiInGame_pActive->pStringTable);
        dwGuiHypText* pHT = new dwGuiHypText(&r, (void*)0x1f43, pFontName, (uint8_t)color,
                                             dwGuiHypText_HAlignLeft, dwGuiHypText_VAlignTop,
                                             (dwGuiHypTextWrapFn)dwGuiInGame_HelpTextLayout,
                                             (dwGuiHypTextDrawGlyphsFn)dwGuiInGame_HelpTextDraw, NULL);
        this->pHelpText = pHT;
        pHT->text.Free();
        pHT->SetText(pText);
        return NULL;
    }
    if (dwString_Equals(pKeyword, "HIDEHELP"))
    {
        char* tok = dwConfFile_NextToken(pConf);
        this->pHideHelp = dwGuiScreen::CreateControl(tok, pConf);
        return NULL;
    }
    if (dwString_Equals(pKeyword, "INVENTORY"))
    {
        dwRect r; r.left = r.top = r.right = r.bottom = 0;
        dwConfFile_ParseRect(pConf, &r);
        uint32_t cellSpacing = 0;
        dwConfFile_ParseULong(pConf, &cellSpacing);
        char* pFontName = dwConfFile_NextToken(pConf);
        uint32_t textColor = 0;
        dwConfFile_ParseULong(pConf, &textColor);
        return (dwWidget*)new dwGuiInvBar(&r, (int16_t)cellSpacing, pFontName, (uint8_t)textColor);
    }
    if (dwString_Equals(pKeyword, "PLAYERSPEECH"))
    {
        dwRect r; r.left = r.top = r.right = r.bottom = 0;
        dwConfFile_ParseRect(pConf, &r);
        char* pFontName = dwConfFile_NextToken(pConf);
        uint32_t a = 0, b = 0, c = 0; dwPoint pt = { 0, 0 };
        dwConfFile_ParseULong(pConf, &a);
        dwConfFile_ParseULong(pConf, &b);
        dwConfFile_ParseULong(pConf, &c);
        dwConfFile_ParsePoint(pConf, &pt);
        // Note: alloc sizeof(dwGuiList), not the binary's 32-bit 0x5c — on 64-bit the C++ object is
        // larger (8-byte pointers/vptr), so the hardcoded size undersized the buffer and the
        // placement-new'd fields (pItems) overflowed it -> crash on Draw.
        this->pPlayerSpeech = dwGuiList_Ctor((dwGuiList*)(*dwMain_pHS->alloc)(sizeof(dwGuiList)), &r, (float)a, pFontName, (uint8_t)b, (uint8_t)c, &pt);
        return (dwWidget*)this->pPlayerSpeech;
    }
    if (dwString_Equals(pKeyword, "NPCSPEECH"))
    {
        dwRect r; r.left = r.top = r.right = r.bottom = 0;
        dwConfFile_ParseRect(pConf, &r);
        char* pFontName = dwConfFile_NextToken(pConf);
        uint32_t color = 0; dwPoint pt = { 0, 0 };
        dwConfFile_ParseULong(pConf, &color);
        dwConfFile_ParsePoint(pConf, &pt);
        this->pNpcSpeech = dwGuiSpeech_Ctor((dwGuiSpeech*)(*dwMain_pHS->alloc)(sizeof(dwGuiSpeech)), &r, 0, pFontName, color, &pt);
        return (dwWidget*)this->pNpcSpeech;
    }
    if (dwString_Equals(pKeyword, "CAMMY_TEXT"))
    {
        char* pFmt = dwConfFile_NextToken(pConf);
        dwRect r; r.left = r.top = r.right = r.bottom = 0;
        dwConfFile_ParseRect(pConf, &r);
        char* pFontName = dwConfFile_NextToken(pConf);
        uint32_t color = 0;
        dwConfFile_ParseULong(pConf, &color);
        char* pText = dwGuiScreen_LocalizeString(pConf->pCursor, this->pStringTable);
        dwGuiHypText* pHT = new dwGuiHypText(&r, (void*)0x1f43, pFontName, (uint8_t)color, pFmt);
        this->pCammyText = pHT;
        pHT->text.Free();
        pHT->SetText(pText);
        return (dwWidget*)this->pCammyText;
    }
    if (dwString_Equals(pKeyword, "SPEED"))
    {
        char* tok = dwConfFile_NextToken(pConf);
        dwWidget* pW = dwGuiScreen::CreateControl(tok, pConf);
        if (pW == NULL) return NULL;
        this->pSpeedGauge = (dwGuiIndicator*)pW;
        dwGuiIndicator_SetProgress(this->pSpeedGauge, 0.0f);
        return pW;
    }
    if (dwString_Equals(pKeyword, "DAMAGE"))
    {
        char* tok = dwConfFile_NextToken(pConf);
        dwWidget* pW = dwGuiScreen::CreateControl(tok, pConf);
        if (pW == NULL) return NULL;
        this->pDamageGauge = (dwGuiIndicator*)pW;
        dwGuiIndicator_SetProgress(this->pDamageGauge, 0.0f);
        return pW;
    }
    if (dwString_Equals(pKeyword, "POWER"))
    {
        char* tok = dwConfFile_NextToken(pConf);
        dwWidget* pW = dwGuiScreen::CreateControl(tok, pConf);
        if (pW == NULL) return NULL;
        this->pPowerGauge = (dwGuiIndicator*)pW;
        dwGuiIndicator_SetProgress(this->pPowerGauge, 0.0f);
        return pW;
    }
    if (dwString_Equals(pKeyword, "REFERENCE_BUTTON"))
    {
        // @422370: stored @0x190 — the InDex button (dwGuiScreen msg-0x6a).
        this->pReferenceButton = (dwWcButtonBlink*)dwGuiScreen::CreateControl((char*)"BUTTON_BLINK", pConf);
        return (dwWidget*)this->pReferenceButton;
    }
    if (dwString_Equals(pKeyword, "INVENTORY_BUTTON"))
    {
        // @422370: stored @0x194 — dwflashinventory blinks this button.
        this->pInventoryButton = (dwWcButtonBlink*)dwGuiScreen::CreateControl((char*)"BUTTON_BLINK", pConf);
        return (dwWidget*)this->pInventoryButton;
    }
    if (dwString_Equals(pKeyword, "WIDGETBAR"))
    {
        dwWidget* pW = dwGuiScreen::CreateControl(pKeyword, pConf);
        ((dwGuiWidgetBar*)pW)->SelectIndex(0);
        pW->Update(5.0f); // vtbl +0x14 (binary &DAT_40a00000 = 5.0)
        return pW;
    }
    if (dwString_Equals(pKeyword, "OVERLAY"))
    {
        char* tok = dwConfFile_NextToken(pConf);
        dwWidget* pW = dwGuiScreen::CreateControl(tok, pConf);
        if (pW != NULL)
            this->overlayGroup.children.InsertAfter(this->overlayGroup.children.pSentinel, pW);
        return NULL;
    }
    if (dwString_Equals(pKeyword, "CLOCK"))
    {
        if (this->pMissionInfo->missionType == 5)
            return NULL; // no clock on training missions
    }
    return dwGuiScreen::CreateControl(pKeyword, pConf);
}

// ----------------------------------------------------------------------------
// UpdateViewSize (sithControl callback) — @422a60
// ----------------------------------------------------------------------------

int dwGuiInGame_UpdateViewSize(SithThing* pPlayer, flex_t deltaSecs)
{
    (void)pPlayer; (void)deltaSecs;
    int size = (int)dw_viewSizePct;
    int grow[3]; sithControl_GetKey(0x24, grow);
    int shrink[3]; sithControl_GetKey(0x25, shrink);
    int newSize = size + grow[0] * 10 - shrink[0] * 10;
    if ((uint32_t)newSize > 100) newSize = 100;
    if ((uint32_t)newSize < 0x32) newSize = 0x32;
    dwWidgetMsg m = { 0x1788, (void*)(intptr_t)newSize, 0, NULL };
    dwWidget_DispatchMsg(&m, NULL);
    return 0;
}

// ----------------------------------------------------------------------------
// CheckCheatCodes — @422ae0
// ----------------------------------------------------------------------------

void dwGuiInGame::CheckCheatCodes(char* pCode)
{
    if (sithWorld_g_pCurrentWorld == NULL || g_sithMode == 0)
        return;
    SithThing* pThing = sithWorld_g_pCurrentWorld->pLocalPlayer;

    if (dwString_Equals(pCode, "SPEED2"))
    {
        pThing->physicsParams.maxVelocity = 8.0f;
        // (binary also sets weaponParams.numDeflectionBounces = 8.0 — DW field)
    }
    else if (dwString_Equals(pCode, "FLY"))
    {
        sithCommand_Fly(NULL, NULL);
    }
    else if (dwString_Equals(pCode, "DANKE"))
    {
        pThing->actorParams.health = pThing->actorParams.maxHealth;
    }
    else if (dwString_Equals(pCode, "BEEFCAKE"))
    {
        sithInventory_SetInventory(pThing, 0x14, sithInventory_GetInventoryMaximum(pThing, 0x14));
    }
    else if (dwString_Equals(pCode, "TUFFY"))
    {
        pThing->actorParams.flags ^= 8;
    }
    else if (dwString_Equals(pCode, "GETEM"))
    {
        for (uint32_t i = 0; i < 0x32; i++)
        {
            if ((sithInventory_g_aTypes[i].flags & 2) != 0)
            {
                sithInventory_SetInventoryAvailable(pThing, i, 1);
                sithInventory_SetInventory(pThing, i, sithInventory_GetInventoryMaximum(pThing, i));
            }
        }
    }
    else if (dwString_Equals(pCode, "MST3K")) // toggle-hud (binary DAT_005289e8)
    {
        this->bShowDebugOverlay = (this->bShowDebugOverlay == 0);
        Invalidate();
    }
    else if (dwString_Equals(pCode, "CONSOLE")) // toggle console (binary DAT_005289e0)
    {
        this->bConsoleOn = (this->bConsoleOn == 0);
        if (this->bConsoleOn)
            dwGuiInGame_ConsolePrint("Console On");
        Invalidate();
    }
    else if (dwString_Equals(pCode, "KINGME"))
    {
        if (sithCamera_g_pCurCamera == &sithCamera_g_aCameras[0])
        {
            sithCamera_SetCurrentCamera(&sithCamera_g_aCameras[7]);
            sithCamera_Update(&sithCamera_g_aCameras[7]);
        }
        else
        {
            sithCamera_SetCurrentCamera(&sithCamera_g_aCameras[0]);
            sithCamera_Update(&sithCamera_g_aCameras[0]);
        }
    }
    else if (dwString_Equals(pCode, "TARDIS"))
    {
        sithControl_BindControl(0x1a, 0xe, 0);
    }
    else if (dwString_Equals(pCode, "BAMBAM") && sithWorld_g_pStaticWorld != NULL)
    {
        // Note: was a raw-offset walk of the static world's cog list (binary
        // +0x150 numCogs / +0x158 aCogs); use repo fields for 64-bit safety.
        for (int ci = 0; ci < sithWorld_g_pStaticWorld->numCogs; ci++)
        {
            sithCog* pCog = &sithWorld_g_pStaticWorld->aCogs[ci];
            if (dwString_Equals(pCog->pScript->aName, "00_CHEAT.cog"))
                sithCog_SendMessage(pCog, (SITH_MESSAGE)0x1b, 0, 0, 0, 0, 0);
        }
    }
    dwGuiScreen::CheckCheatCodes(pCode);
}

// ----------------------------------------------------------------------------
// HELPTEXT callbacks — @422e30 / @422ee0
// ----------------------------------------------------------------------------

// @422e30 (dwGuiHypTextWrapFn) — build one run per '$'-delimited segment.
static void dwGuiInGame_HelpTextLayout(dwString* pText, dwFont* pFont, int width, dwGuiHypTextRun** ppRuns)
{
    (void)width;
    char* p = pText ? pText->pBuffer : NULL;
    while (p != NULL && *p != '\0')
    {
        char* q = p;
        while (*q != '\0' && *q != '$')
            q++;
        int len = (int)(q - p);
        dwGuiHypTextRun* pRun = (dwGuiHypTextRun*)_malloc(sizeof(dwGuiHypTextRun));
        pRun->startChar = 0;
        pRun->drawLen = 0;
        pRun->drawX = 0;
        pRun->pStr = p;
        pRun->len = len;
        pRun->width = dwFont_MeasureString(pFont, p, len);
        pRun->xOffset = 0;
        // append before the sentinel
        dwGuiHypTextRun* pSentinel = *ppRuns;
        pRun->pNext = pSentinel->pNext;
        pRun->pPrev = pSentinel;
        pSentinel->pNext->pPrev = pRun;
        pSentinel->pNext = pRun;
        p = (*q == '$') ? q + 1 : q;
    }
}

// @422ee0 (dwGuiHypTextDrawGlyphsFn) — draw the run right-aligned to a 0x3c
// column then continue left, glyph by glyph.
static void dwGuiInGame_HelpTextDraw(dwImageBits* pBits, dwPoint* pPos, dwFont* pFont, uint8_t color,
                                     dwGuiHypTextRun* pRun, dwRect* pClip)
{
    int len = pRun->len;
    char* pStr = pRun->pStr + pRun->startChar;
    int16_t x0 = pPos->x;
    // measure the leading token (up to a space) and right-align it into [x0, x0+0x3c)
    char* pTok = pStr;
    while (*pTok != '\0' && !isspace((unsigned char)*pTok))
        pTok++;
    int16_t tokW = dwFont_MeasureString(pFont, pStr, (int)(pTok - pStr));
    int16_t rightX = (int16_t)((x0 + 0x3c) - tokW);
    if (pPos->x < rightX)
        pPos->x = rightX;
    while (len != 0 && !isspace((unsigned char)*pStr))
    {
        if (pClip == NULL)
            dwFont_DrawGlyph(pFont, pBits, pPos, *pStr, color);
        else
            dwFont_DrawGlyphClipped(pFont, pBits, pPos, *pStr, color, pClip);
        pStr++;
        len--;
    }
    pPos->x = x0 + 0x3c;
    for (; len != 0; len--)
    {
        if (pClip == NULL)
            dwFont_DrawGlyph(pFont, pBits, pPos, *pStr, color);
        else
            dwFont_DrawGlyphClipped(pFont, pBits, pPos, *pStr, color, pClip);
        pStr++;
    }
}

// ----------------------------------------------------------------------------
// ConsolePrint (C shim) — @423020
// ----------------------------------------------------------------------------

void dwGuiInGame_ConsolePrint(const char* pText)
{
    dwGuiInGame* p = dwGuiInGame_pActive;
    if (p != NULL && p->bConsoleOn != 0)
    {
        p->consoleLines[p->consoleWriteIdx].AssignCStr(pText);
        p->consoleWriteIdx = (p->consoleWriteIdx + 1) % 0xf;
        p->Invalidate();
    }
}

// ----------------------------------------------------------------------------
// CheckDroidValid + factory — @41f6f0 / @41f2a0
// ----------------------------------------------------------------------------

int dwGuiInGame_CheckDroidValid(void)
{
    dwDroidStatsTotals totals;
    totals.ClearTotals();
    int locoCount = 0;
    int detachedCount = 0;
    for (dwListNode* pNode = dwCore_pWorkspaceNodes->pNext; pNode != dwCore_pWorkspaceNodes; pNode = pNode->pNext)
    {
        dwPartNode* pPart = (dwPartNode*)pNode->pData;
        if (pPart->partType != 0xb && pPart->pAttachData == NULL)
            detachedCount++;
        if (pPart->pPart->type == 5) // LOCOMOTION
            locoCount++;
        totals.AccumulatePart(pPart, 0);
    }

    if (dwCore_pWorkspaceNodes == dwCore_pWorkspaceNodes->pNext)
    {
        dwGuiDialog_RunModal("gmessage", "DLG_EMPTY");
        return 0;
    }
    if ((totals.capFlags & 0x20000000) == 0)
    {
        dwGuiDialog_RunModal("gmessage", "DLG_NOLOCO");
        return 0;
    }
    if (locoCount >= 2)
    {
        dwGuiDialog_RunModal("gmessage", "DLG_MULTIPLE");
        return 0;
    }
    if (detachedCount != 0)
    {
        dwGuiDialog_RunModal("gmessage", "DLG_DETACHED");
        return 0;
    }
    if ((totals.capFlags & 0x80000000) != 0)
    {
        if (totals.batteryCharge != 0)
            return 1;
        dwGuiDialog_RunModal("gmessage", "DLG_NOPOWER");
        return 0;
    }
    dwGuiDialog_RunModal("gmessage", "DLG_NOEYES");
    return 0;
}

dwSegment* dwGuiInGame_New(dwMission* pMission)
{
    return static_cast<dwSegment*>(new dwGuiInGame(pMission));
}

// ============================================================================
// dwGuiInGamePause (nested pause dialog)
// ============================================================================

// built inline in dwGuiInGame::OnKey — dwGuiDialog("gmessage","DLG_PAUSED", slot)
dwGuiInGamePause::dwGuiInGamePause()
    : dwGuiDialog("gmessage", "DLG_PAUSED", &dwGuiInGamePause_result)
{
}

// @421880 (scalar-deleting wrapper @421860; scn thunk @423170)
dwGuiInGamePause::~dwGuiInGamePause()
{
}

// @421840
int dwGuiInGamePause::OnKey(int key, int repeat)
{
    dwSegment_RequestAdvance();
    return dwGuiScreen::OnKey(key, repeat);
}

// @421810
int dwGuiInGamePause::OnMessage(dwWidgetMsg* pMsg)
{
    if (pMsg->code == 5000)
        dwSegment_RequestAdvance();
    return dwGuiDialog::OnMessage(pMsg);
}
