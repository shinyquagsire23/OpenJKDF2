// dwGuiOptions — main-menu / sign-in / options flow (DroidWorks.exe
// 0x423180-0x42607f): dwGuiRanking + dwGuiLongAgo + dwGuiOpening +
// dwGuiOptions + the dwGuiIntroSeg / dwGuiOptionsEnterSeg sequencers.
// See Dw/dwGuiOptions.h for the per-class notes.

#include "Dw/dwGuiOptions.h"

#include "Dw/dwGuiCredits.h"   // menu command 6000+4
#include "Dw/dwEnding.h"       // menu command 6000+0x1e + lecSmush_frameNum
#include "Dw/dwWorkshop.h"     // dwWorkshop_CreateSingleton/_pSingleton (intro flow)
#include "Dw/dwMission.h"      // dwMission record + dwCore_pMissionList
#include "Dw/dwPlayer.h"       // profiles + shared settings
#include "Dw/dwPart.h"         // blueprint records (ResetGameState) + dwPartNode
#include "Dw/dwSound.h"        // music/menu volume
#include "Dw/dwCursor.h"       // dwCursor_SetCursor
#include "Dw/dwColormap.h"     // dwColormap_Load/SetDisplayPalette/transparentIdx
#include "Dw/dwConfFile.h"
#include "Dw/dwStringTable.h"
#include "Dw/dwDisplay.h"      // dwDisplay_pScreenImage/Present
#include "Dw/dwImage.h"
#include "Dw/dwImageVBuf.h"
#include "Dw/dwImageDraw.h"    // FillRect/FrameRect/Line
#include "Dw/dwGuiTextEntry.h" // PLAYERNAME control
#include "Dw/dwGuiWidgets.h"   // scroll box/bar/buttons
#include "Dw/dwWidgetGroup.h"

#include "stdPlatform.h"

// Engine headers/globals without extern "C" guards of their own — wrap at the
// include site. globals.h provides rdColormap_pCurMap (palette + light-level
// ramp) and sithWorld_g_pCurrentWorld (the in-game inventory checkboxes).
extern "C" {
#include "globals.h"
#include "General/stdColor.h"        // stdColor_FindClosest
#include "General/stdPalEffects.h"   // fade request/SetFade/UpdatePalette
#include "Win95/stdDisplay.h"        // stdDisplay_GetPalette
#include "Gameplay/sithInventory.h"  // sithInventory_GetInventory
#include "Devices/sithSoundMixer.h"  // sithSoundMixer_UpdateMusicVolume
}

// dw-core globals owned by the P7 boot flow (dwMain.c placeholders /
// dwInits.cpp temporaries) — same per-file extern pattern as the other units.
extern "C" dwStringTable* dwCore_pGlobalStrings; // @0x53d958
extern "C" dwListNode* dwCore_pWorkspaceNodes;   // @0x53d984
extern "C" dwListNode* dwCore_pBlueprintList;    // @0x53d964
extern "C" dwString dwCore_workspaceName;        // @0x53d978

#include <ctype.h> // isspace (binary CRT FUN_00507d80)

// ---------------------------------------------------------------------------
// Cross-unit externs (not yet translated — declared + reported, not implemented)
// ---------------------------------------------------------------------------

// TODO(dw-decomp): provided by dw core (P7) — the currently-selected mission
// record (binary DAT_0053d954; written by dwGuiOptions_ResetGameState +
// dwGuiMissionMap, read by dwGuiRanking/dwGuiStatus). Needs a dwMain.c
// placeholder alongside dwCore_pMissionList.
extern "C" dwMission* dwCore_pCurrentMission; // @0x53d954

// TODO(dw-decomp): provided by dwGuiInGame (P6 wave 2) — the running-mission
// screen instance (NULL outside gameplay). dwGuiRanking's checkboxes go live
// against the player inventory while it is set.
typedef struct dwGuiInGame dwGuiInGame;
extern "C" dwGuiInGame* dwGuiInGame_pActive; // @0x53e800

// TODO(dw-decomp): needs a one-line addition to dwSegment.cpp/.h — clear the
// module-static quit flag dwSegment_bQuit (@0x53e8ac; set by
// dwSegment_SignalQuit). The binary's menu command 6000+0xa stores 0 to it
// directly ("cancel quit" from the confirm-quit sub-screen).
extern "C" void dwSegment_CancelQuit(void);

// dwGuiDialog_RunModal — dwMain.c placeholder until dwGuiMission (P6) lands.
extern "C" int dwGuiDialog_RunModal(const char* pConfName, const char* pMsgKey);

// stdBitmapRle2 image factory — P8 placeholder implemented in dwAnim.cpp
// (returns NULL until the engine-side unit lands).
extern "C" dwImage* stdBitmapRle2_Instantiate(int16_t width, int16_t height, int bpp); // @442df0

// ---------------------------------------------------------------------------
// Module data
// ---------------------------------------------------------------------------

// @0x51f378 (referenced as dwGuiOpening_vtbl+0x20 by Ghidra): the six
// sub-screen script names, indexed by dwGuiOptions::screenIndex.
static const char* dwGuiOptions_aSubScreenNames[6] = {
    "optMain",     // 0
    "optHelp",     // 1
    "optGame",     // 2
    "optGameNew",  // 3
    "optGameLoad", // 4
    "optSetup",    // 5
};

// Note: no binary counterpart — the unit owns no module statics.
extern "C" void dwGuiOptions_Startup(void)
{
}

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

// Free a dwPlayer_EnumProfiles result list: heap dwString payloads + nodes +
// sentinel (the binary inlines this at each of its three users).
static void dwGuiOptions_FreeProfileList(dwList* pList)
{
    dwListNode* pNode = pList->pSentinel->pNext;
    while (pNode != pList->pSentinel)
    {
        dwListNode* pNext = pNode->pNext;
        dwString* pStr = (dwString*)pNode->pData;
        if (pStr != NULL)
            delete pStr;
        pNode = pNext;
    }
    pList->Free();
}

// Lock the screen image and fill it with the transparent (black) palette
// index (dwGuiLongAgo's blackouts). Binary: inline Lock + dwImageDraw_FillRect
// + Unlock, full-screen rect from the display mode dims.
static void dwGuiOptions_BlackoutScreen(void)
{
    dwImage* pImg = (dwImage*)dwDisplay_pScreenImage;
    if (pImg == NULL)
        return;
    void* pPixels = NULL;
    int stride = 0;
    pImg->Lock(&pPixels, &stride);
    dwImageBits bits;
    bits.pDesc = &pImg->desc;
    bits.pPixels = pPixels;
    bits.stride = stride;
    dwRect full;
    full.left = 0;
    full.top = 0;
    full.right = (int16_t)pImg->desc.width;
    full.bottom = (int16_t)pImg->desc.height;
    dwImageDraw_FillRect(&bits, &full, dwColormap_transparentIdx, NULL);
    pImg->Unlock();
}

// ---------------------------------------------------------------------------
// dwMovie_OpenSeg — the movie-SEGMENT factory
// ---------------------------------------------------------------------------

// @4029c0 (Ghidra: jkSmack_SmackPlay — VT-inherited misnomer). Physically part
// of the dwAnim/dwMovie unit (P3, missed there); implemented here because
// this unit and the boot flow are its callers. FLC/FLI -> dwFlicSeg,
// SAN -> dwSmushSeg (libsmusher playback since P8).
extern "C" dwSegment* dwMovie_OpenSeg(const char* pFilename, dwImage* pOverlayImage)
{
    dwSegment* pSeg = NULL;
    char* pExt = (char*)pFilename;
    dwString_FindExtension(&pExt);
    if (*pExt == '\0')
    {
        // Note: binary logs via jk_logtofile — mapped to stdPlatform_Printf
        // like the rest of the DW translation (see dwAnim.cpp).
        stdPlatform_Printf("Animation file has no extension: %s\n", pFilename);
        return NULL;
    }
    pExt++;
    if (dwString_Equals(pExt, "FLI") || dwString_Equals(pExt, "FLC"))
    {
        pSeg = new dwFlicSeg(pFilename, pOverlayImage);
    }
    else if (dwString_Equals(pExt, "SAN"))
    {
        pSeg = new dwSmushSeg(pFilename, pOverlayImage);
    }
    if (pSeg == NULL)
        stdPlatform_Printf("Error opening animation: %s\n", pFilename); // binary: jk_logtofile
    return pSeg;
}

// ---------------------------------------------------------------------------
// dwGuiRanking — the STATS_JOB mission rank/requirements card
// ---------------------------------------------------------------------------

// @423180 (dwGuiRanking_Ctor)
dwGuiRanking::dwGuiRanking(dwRect* pRect, char* pFontLabelName, uint8_t labelColor_,
                           char* pFontValueName, uint8_t valueColor_)
    : dwWidget(pRect)
{
    this->pMission = dwCore_pCurrentMission;
    this->pFontLabel = NULL;
    this->labelColor = labelColor_;
    this->pFontValue = NULL;
    this->valueColor = valueColor_;
    this->aRankColors[0] = 0;
    this->aRankColors[1] = 0;
    this->aRankColors[2] = 0;
    if (pFontLabelName != NULL)
        this->pFontLabel = dwFont_Load(new dwFont, pFontLabelName);
    if (pFontValueName != NULL)
        this->pFontValue = dwFont_Load(new dwFont, pFontValueName);
    this->strRequirements = dwGuiScreen_LocalizeString((char*)"REQUIREMENTS", NULL);
    this->strRanking = dwGuiScreen_LocalizeString((char*)"RANKING:", NULL);
    this->strApprentice = dwGuiScreen_LocalizeString((char*)"APPRENTICE", NULL);
    this->strDesigner = dwGuiScreen_LocalizeString((char*)"DESIGNER", NULL);
    this->strMaster = dwGuiScreen_LocalizeString((char*)"MASTER", NULL);

    // seed the colors/mission by self-sending the mission-changed message
    dwWidgetMsg msg;
    msg.code = 0xbbc;
    msg.pSender = this->pMission;
    msg.param = 0;
    msg.pTarget = NULL;
    this->OnMessage(&msg);
}

// @4232f0 (dwGuiRanking_Dtor; scalar-deleting wrapper @4232d0)
dwGuiRanking::~dwGuiRanking()
{
    // (binary: no-op font "dtor" @504190 + free — see dwFont.h conventions)
    if (this->pFontLabel != NULL)
        delete this->pFontLabel;
    if (this->pFontValue != NULL)
        delete this->pFontValue;
}

// vtbl +0x18 @4239d0 (dwGuiRanking_OnHover)
int dwGuiRanking::OnHover(int16_t x, int16_t y)
{
    (void)x;
    (void)y;
    dwWidgetMsg msg;
    msg.code = 0x7531;
    msg.pSender = (void*)0x791b; // help-text id payload
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);
    return 1;
}

// vtbl +0x1c @423a00 (dwGuiRanking_OnMessage)
int dwGuiRanking::OnMessage(dwWidgetMsg* pMsg)
{
    if (pMsg->code == 0xbbc)
    {
        this->pMission = (dwMission*)pMsg->pSender;
        uint8_t dimColor = this->valueColor;
        if (dimColor > 4)
        {
            // Dim to half brightness (binary: x * 0x4040404080 >> 0x27 ≈ x/2)
            // and find the closest palette match among entries 5..147, biased
            // back by the +5 the search skipped.
            rdColor24* paColors = rdColormap_pCurMap->colors;
            flex_t r = (flex_t)(uint32_t)(((uint64_t)paColors[dimColor].r * 0x4040404080ull) >> 0x27);
            flex_t g = (flex_t)(uint32_t)(((uint64_t)paColors[dimColor].g * 0x4040404080ull) >> 0x27);
            flex_t b = (flex_t)(uint32_t)(((uint64_t)paColors[dimColor].b * 0x4040404080ull) >> 0x27);
            dimColor = (uint8_t)(stdColor_FindClosest(&paColors[5], 0x8f, r, g, b) + 5);
        }
        this->aRankColors[0] = dimColor;
        this->aRankColors[1] = dimColor;
        this->aRankColors[2] = dimColor;
        if (this->pMission != NULL && this->pMission->rank != 0)
        {
            // binary: (&valueColor)[rank] — unclamped; assumes rank <= 3
            this->aRankColors[this->pMission->rank - 1] = this->valueColor;
        }
        this->Invalidate();
    }
    return 0;
}

// vtbl +0x44 @423370 (dwGuiRanking_Draw)
void dwGuiRanking::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    if (this->pMission == NULL || this->pFontLabel == NULL || this->pFontValue == NULL)
        return;

    int16_t x0 = this->left + 2;
    int16_t x1 = this->right - 2;
    int16_t yBottom = this->bottom - 2;
    int16_t labelH = (int16_t)this->pFontLabel->pHeader->lineHeight;
    int16_t valueH = (int16_t)this->pFontValue->pHeader->lineHeight;
    dwPoint p0;
    dwPoint p1;
    dwRect r;
    p0.x = x0;
    p0.y = 0;
    p1.x = x1;
    p1.y = 0;

    // ---- bottom section: "RANKING:" header + the three rank names ----------
    int16_t rankingY = yBottom - valueH - labelH - 4;
    r.left = x0;
    r.top = rankingY;
    r.right = x1;
    r.bottom = yBottom;
    dwFont_DrawText(pDestBits, this->pFontLabel, &r, this->strRanking, this->labelColor, pClipRect);
    int16_t lineY = rankingY + labelH + 1;
    p0.y = lineY;
    p1.y = lineY;
    dwImageDraw_Line(pDestBits, &p0, &p1, this->labelColor, pClipRect);
    r.top = lineY + 1;
    int16_t third = (int16_t)((x1 - x0) / 3);
    r.right = x0 + third - 2;
    dwFont_DrawTextAligned(pDestBits, this->pFontValue, &r, this->strApprentice, this->aRankColors[0], pClipRect, 3);
    r.left += third;
    r.right += third;
    dwFont_DrawTextAligned(pDestBits, this->pFontValue, &r, this->strDesigner, this->aRankColors[1], pClipRect, 3);
    r.left += third;
    r.right += third;
    dwFont_DrawTextAligned(pDestBits, this->pFontValue, &r, this->strMaster, this->aRankColors[2], pClipRect, 3);

    // ---- top section: mission name -----------------------------------------
    r.left = this->left + 2;
    r.top = this->top + 2;
    r.right = this->right - 2;
    r.bottom = r.top + labelH;
    dwFont_DrawText(pDestBits, this->pFontLabel, &r, this->pMission->displayName.pBuffer,
                    this->labelColor, pClipRect);
    lineY = this->top + 2 + labelH + 1;
    p0.y = lineY;
    p1.y = lineY;
    dwImageDraw_Line(pDestBits, &p0, &p1, this->labelColor, pClipRect);

    // ---- GOAL rows for the mission's current rank tier ----------------------
    int16_t listTop = lineY + 1;
    int16_t rowH = (int16_t)((rankingY - listTop - valueH - 3) / 6); // 6 rows fit
    int16_t rowY = listTop + (int16_t)((rowH - valueH) / 2);
    r.left = this->left + 2;
    r.top = rowY;
    r.right = this->right - 2;
    r.bottom = rowY + rowH;
    int16_t q = valueH / 4;
    int16_t half = valueH / 2;
    dwRect box;
    box.left = r.left + q;
    box.top = r.top + q;
    box.right = r.left + q + half;
    box.bottom = r.top + q + half;
    r.left += valueH; // text starts after the checkbox band

    uint8_t tier = this->pMission->rank;
    if (tier > 2)
        tier = 2;
    dwListNode* pSentinel = this->pMission->pObjectives;
    for (dwListNode* pNode = pSentinel->pNext; pNode != pSentinel; pNode = pNode->pNext)
    {
        dwMissionObjective* pObj = (dwMissionObjective*)pNode->pData;
        if (pObj->code != tier || pObj->bRequirement != 0)
            continue;
        dwFont_DrawText(pDestBits, this->pFontValue, &r, pObj->label.pBuffer, this->valueColor, pClipRect);
        uint8_t bChecked = pObj->bFlag;
        if (dwGuiInGame_pActive != NULL)
        {
            if (sithInventory_GetInventory(sithWorld_g_pCurrentWorld->pLocalPlayer, (int)pObj->param) != 0.0)
                bChecked = 1;
        }
        if (bChecked != 0)
            dwImageDraw_FillRect(pDestBits, &box, this->labelColor, pClipRect);
        else
            dwImageDraw_FrameRect(pDestBits, &box, this->labelColor, pClipRect);
        r.top += rowH;
        r.bottom += rowH;
        box.top += rowH;
        box.bottom += rowH;
    }

    // ---- REQUIREMENTS header + rows -----------------------------------------
    r.left = this->left + 2;
    r.bottom = r.top + valueH;
    dwFont_DrawText(pDestBits, this->pFontValue, &r, this->strRequirements, this->labelColor, pClipRect);
    lineY = r.top + valueH + 1;
    p0.y = lineY;
    p1.y = lineY;
    dwImageDraw_Line(pDestBits, &p0, &p1, this->labelColor, pClipRect);
    r.top = lineY + 1;
    r.bottom = r.top + rowH;
    box.left = this->left + 2 + q;
    box.top = r.top + q;
    box.right = box.left + half;
    box.bottom = r.top + q + half;
    r.left = this->left + 2 + valueH;
    for (dwListNode* pNode = pSentinel->pNext; pNode != pSentinel; pNode = pNode->pNext)
    {
        dwMissionObjective* pObj = (dwMissionObjective*)pNode->pData;
        if (pObj->code != tier || pObj->bRequirement == 0)
            continue;
        dwFont_DrawText(pDestBits, this->pFontValue, &r, pObj->label.pBuffer, this->valueColor, pClipRect);
        uint8_t bChecked = pObj->bFlag;
        if (dwGuiInGame_pActive != NULL)
        {
            if (sithInventory_GetInventory(sithWorld_g_pCurrentWorld->pLocalPlayer, (int)pObj->param) != 0.0)
                bChecked = 1;
        }
        if (bChecked != 0)
            dwImageDraw_FillRect(pDestBits, &box, this->labelColor, pClipRect);
        else
            dwImageDraw_FrameRect(pDestBits, &box, this->labelColor, pClipRect);
        r.top += rowH;
        r.bottom += rowH;
        box.top += rowH;
        box.bottom += rowH;
    }
}

// ---------------------------------------------------------------------------
// dwGuiIntroSeg — the new-player intro sequencer
// ---------------------------------------------------------------------------

// (ctor inlined at the construction site — dwGuiOptions::OnMessage 0xD)
dwGuiIntroSeg::dwGuiIntroSeg()
{
    this->state = 0;
}

// vtbl +0x00 @423b10 (Ghidra: dwGuiIntroSeg_Update — the Activate slot; the
// segment manager re-Activates this segment after every interruption, which
// steps the state machine)
int dwGuiIntroSeg::Activate()
{
    dwSegment* pNext = NULL;
    while (pNext == NULL && this->state != 3)
    {
        if (this->state == 0)
        {
            pNext = static_cast<dwSegment*>(new dwGuiLongAgo());
            this->state = 1;
        }
        else if (this->state == 1)
        {
            pNext = new dwGuiOpening();
            this->state = 2;
        }
        else if (this->state == 2)
        {
            int answer = dwGuiDialog_RunModal("tutoryn", "DLG_WORKTUT");
            if (answer == 5000)
                dwPlayer_statsFlags |= 0x10000000;

            dwList profiles;
            dwPlayer_EnumProfiles(&profiles);
            dwSegment* pMovie = NULL;
            if (profiles.pSentinel->pNext == profiles.pSentinel)
            {
                // no profile directories exist yet (first-ever player)
                if (answer == 5000)
                {
                    // tutorial accepted: JawaOut -> workshop (tutorial armed)
                    // -> options new-game screen afterwards
                    dwSegment_Push(dwGuiOptions_NewEnterSeg(3));
                    dwPlayer_statsFlags |= 0x4000000;
                    dwWorkshop_CreateSingleton();
                    if (dwWorkshop_pSingleton != NULL)
                        dwSegment_Push(static_cast<dwSegment*>(static_cast<dwGuiScreen*>(dwWorkshop_pSingleton)));
                    pMovie = dwMovie_OpenSeg("JawaOut.san", NULL);
                }
                else
                {
                    // tutorial declined: SignIn -> options new-game -> JawaOut
                    pMovie = dwMovie_OpenSeg("JawaOut.san", NULL);
                    if (pMovie != NULL)
                        dwSegment_Push(pMovie);
                    dwSegment_Push(dwGuiOptions_NewEnterSeg(3));
                    pMovie = dwMovie_OpenSeg("SignIn.san", NULL);
                }
            }
            else
            {
                pMovie = dwMovie_OpenSeg("JawaOut.san", NULL);
            }
            if (pMovie != NULL)
                dwSegment_Push(pMovie);
            this->state = 3;
            dwGuiOptions_FreeProfileList(&profiles);
        }
    }

    dwSound_SetMusic(NULL, 1);
    if (pNext != NULL)
    {
        // interrupt the flow with the next intro piece, returning here
        // (binary InterruptWith reads the active segment — which is this)
        dwSegment_InterruptWith(dwSegment_pActive, pNext);
        return 1;
    }
    if (this->state == 3)
        dwSegment_RequestAdvance();
    return 1;
}

// ---------------------------------------------------------------------------
// dwGuiOptionsEnterSeg — OStart movie -> options screen
// ---------------------------------------------------------------------------

// (ctor inlined at the construction sites)
dwGuiOptionsEnterSeg::dwGuiOptionsEnterSeg(int screenIndex_)
{
    this->screenIndex = screenIndex_;
    this->bStarted = 0;
}

// vtbl +0x00 @425fa0 (Ghidra: dwGuiOptions_EnterSeg_Update — the Activate slot)
int dwGuiOptionsEnterSeg::Activate()
{
    dwSegment* pSeg = NULL;
    if (this->bStarted == 0)
    {
        dwSound_SetMusic("option.wav", 1);
        const char* pName = (this->screenIndex == 3 || this->screenIndex == 2) ? "OStart2.san" : "OStart.san";
        pSeg = dwMovie_OpenSeg(pName, NULL);
    }
    if (pSeg == NULL)
        pSeg = static_cast<dwSegment*>(new dwGuiOptions(this->screenIndex));
    if (this->bStarted == 0)
    {
        this->bStarted = 1;
        dwSegment_InterruptWith(dwSegment_pActive, pSeg);
    }
    else
    {
        dwSegment_PushAndAdvance(pSeg);
    }
    return 1;
}

// Added: C factory (the binary constructed the segment inline at each site).
extern "C" dwSegment* dwGuiOptions_NewEnterSeg(int screenIndex)
{
    return new dwGuiOptionsEnterSeg(screenIndex);
}

// Added: C factory for the options SCREEN itself. dwGuiInGame_EndMission's
// FINAL path pushes it (binary @dwGuiInGame_EndMission: dwGuiOptions_Ctor(0) +
// dwSegment_Push). Was a NULL link placeholder in dwMain.cpp until this landed.
extern "C" dwSegment* dwGuiOptions_New(int index)
{
    return static_cast<dwSegment*>(new dwGuiOptions(index));
}

// ---------------------------------------------------------------------------
// dwGuiLongAgo — the palette-fade intro card
// ---------------------------------------------------------------------------

// @423e80 (dwGuiLongAgo_Ctor)
dwGuiLongAgo::dwGuiLongAgo()
    : dwGuiScreen("longago", NULL)
{
    this->fadeState = 0;
    this->palFadeId = -1;
    this->fadeTimer = 0.0f;
}

// @423ee0 (dwGuiLongAgo_Dtor; scalar-deleting wrapper @423ec0; secondary
// thunk @424ad0) — the binary body is just the inlined base teardown.
dwGuiLongAgo::~dwGuiLongAgo()
{
}

// scn vtbl +0x00 @423ef0 (dwGuiLongAgo_OnActivate)
int dwGuiLongAgo::Activate()
{
    int ret = dwGuiScreen::Activate();
    dwCursor_SetCursor(0);
    dwGuiOptions_BlackoutScreen();
    this->palFadeId = stdPalEffects_NewRequest(1);
    stdPalEffects_SetFade(this->palFadeId, 0.0);
    stdPalEffects_UpdatePalette(stdDisplay_GetPalette());
    return ret;
}

// scn vtbl +0x04 @423fd0 (dwGuiLongAgo_OnDeactivate)
void dwGuiLongAgo::Deactivate()
{
    dwGuiScreen::Deactivate();
    // clear BOTH buffers to black around the flip, then restore the palette
    dwGuiOptions_BlackoutScreen();
    dwDisplay_Present();
    dwGuiOptions_BlackoutScreen();
    stdPalEffects_SetFade(this->palFadeId, 1.0);
    stdPalEffects_UpdatePalette(stdDisplay_GetPalette());
    stdPalEffects_FreeRequest((uint32_t)this->palFadeId);
}

// vtbl +0x14 @424110 (dwGuiLongAgo_Update)
void dwGuiLongAgo::Update(float dt)
{
    float fade = 1.0f;
    this->fadeTimer += dt;
    if (this->fadeState == 0)
    {
        if (this->fadeTimer < 0.5f)
        {
            fade = this->fadeTimer / 0.5f;
        }
        else
        {
            this->fadeState = 1;
            this->fadeTimer -= 0.5f;
        }
    }
    if (this->fadeState == 1 && this->fadeTimer >= 4.0f)
    {
        this->fadeState = 2;
        this->fadeTimer -= 4.0f;
    }
    if (this->fadeState == 2)
    {
        if (this->fadeTimer < 4.0f)
        {
            fade = 1.0f - this->fadeTimer / 4.0f;
        }
        else
        {
            dwSegment_RequestAdvance();
            fade = 0.0f;
        }
    }
    stdPalEffects_SetFade(this->palFadeId, fade);
    stdPalEffects_UpdatePalette(stdDisplay_GetPalette());
    this->controls.Update(dt);
}

// vtbl +0x10 @424220 (dwGuiLongAgo_OnKey)
int dwGuiLongAgo::OnKey(int key, int repeat)
{
    if ((char)key == '\x1b')
        dwSegment_RequestAdvance();
    return dwGuiScreen::OnKey(key, repeat);
}

// ---------------------------------------------------------------------------
// dwGuiOpening — the 'Opening.san' text crawl
// ---------------------------------------------------------------------------

// @424250 (dwGuiOpening_Ctor)
dwGuiOpening::dwGuiOpening()
    : dwMovie("Opening.san")
{
    this->pCrawlImage = NULL;
}

// @424290 (dwGuiOpening_Dtor; scalar-deleting wrapper @424270)
dwGuiOpening::~dwGuiOpening()
{
    if (this->pCrawlImage != NULL)
        delete this->pCrawlImage; // binary: vtbl[0](1) virtual delete
}

// vtbl +0x00 @4242f0 (Ghidra: dwGuiOpening_BuildCrawl — the Activate slot).
// Pre-renders opening.txt into the tall crawl bitmap. Line format: byte0 =
// '!' centered / '$' blank spacer / '*' justified (Bresenham-distributed gap
// widening) / anything else left-aligned; the rest of the line is the text.
// Rendering stops at the first EMPTY line (binary quirk).
int dwGuiOpening::Activate()
{
    dwFont* pFont = NULL;

    dwColormap_Load((char*)"opening.cmp");
    dwConfFile conf;
    dwConfFile_Open(&conf, "opening.txt");
    dwConfFile_ReadLine(&conf);
    char* pTok = dwConfFile_NextToken(&conf);
    if (pTok != NULL && *pTok != '\0')
        pFont = dwFont_Load(new dwFont, pTok);

    dwList lines;
    int16_t lineCount = 0;
    while (conf.bEof == 0)
    {
        dwConfFile_ReadLine(&conf);
        if (conf.pCursor != NULL)
        {
            dwString* pStr = new dwString(conf.pCursor, 0);
            lines.InsertAfter(lines.pSentinel->pPrev, pStr);
            lineCount++;
        }
    }

    if (pFont != NULL)
    {
        int16_t lineH = (int16_t)pFont->pHeader->lineHeight;
        dwImage* pImg = stdBitmapRle2_Instantiate(600, (int16_t)(lineH * lineCount), 8);
        this->pCrawlImage = pImg;
        if (pImg != NULL)
        {
            void* pPixels = NULL;
            int stride = 0;
            pImg->Lock(&pPixels, &stride);
            dwImageBits bits;
            bits.pDesc = &pImg->desc;
            bits.pPixels = pPixels;
            bits.stride = stride;
            int16_t crawlW = (int16_t)pImg->desc.width;
            int16_t lineY = 0;
            for (dwListNode* pNode = lines.pSentinel->pNext; pNode != lines.pSentinel; pNode = pNode->pNext)
            {
                dwString* pStr = (dwString*)pNode->pData;
                if (pStr->length == 0)
                    break; // binary: the first empty line ends the crawl
                char* pText = pStr->pBuffer;
                dwPoint pen;
                pen.x = 0;
                // header +0x08's low byte doubles as the glyph top y-inset
                pen.y = lineY + (int16_t)pFont->pHeader->bpp;
                int16_t measured = (int16_t)dwFont_MeasureString(pFont, pText + 1, pStr->length - 1);
                int16_t remaining = crawlW - measured;
                int count = (int)pStr->length;
                int16_t perGap = 0;
                int gaps = 0;
                int rem = 0;
                int bres = 0;
                char fmt = pText[0];
                if (fmt == '!')
                {
                    pen.x += (int16_t)(remaining / 2); // centered
                }
                else if (fmt == '$')
                {
                    count = 1; // blank spacer — no glyphs
                }
                else if (fmt == '*')
                {
                    // justified: distribute the remaining width across the gaps
                    gaps = (int)pStr->length - 1;
                    perGap = (int16_t)(remaining / gaps);
                    rem = remaining % gaps;
                    bres = -gaps;
                }
                const char* pCh = pText;
                while (--count != 0)
                {
                    pCh++;
                    dwFont_DrawGlyph(pFont, &bits, &pen, *pCh, 1);
                    bres += rem;
                    pen.x += perGap;
                    while ((int16_t)bres > 0)
                    {
                        bres -= gaps;
                        pen.x++;
                    }
                }
                lineY += lineH;
            }
            pImg->Unlock();
        }
        delete pFont; // binary: no-op font "dtor" @504190 + free
    }

    int ret = dwMovie::Activate();

    // free the line strings + nodes + sentinel
    dwListNode* pNode = lines.pSentinel->pNext;
    while (pNode != lines.pSentinel)
    {
        dwListNode* pNext = pNode->pNext;
        dwString* pStr = (dwString*)pNode->pData;
        if (pStr != NULL)
            delete pStr;
        pNode = pNext;
    }
    lines.Free();

    dwConfFile_Close(&conf);
    return ret;
}

// @4249b0 (dwGuiOpening_ResampleSpan) — horizontal box-filter resample of one
// crawl-bitmap row into one dest scanline: each output pixel averages the
// source pixel and its one-step-right neighbor (the final pixel samples only
// itself), scales by `color` (the crawl fade level 0..0x3f), and maps the
// result through the colormap light-level ramp against base color 0xd8.
// pRowSpan and pSrcStride exist in the binary signature but are DEAD — the
// vertical-averaging loop they imply executes exactly once.
static void dwGuiOpening_ResampleSpan(uint8_t* pDst, int dstWidth, uint8_t* pSrc,
                                      int16_t srcWidth, int rowSpan, int srcStride, int color)
{
    (void)rowSpan;   // dead in the binary (see above)
    (void)srcStride; // only reachable through the dead vertical loop

    int16_t count = (int16_t)dstWidth;
    if (count == 0)
        return;
    int step = (int)srcWidth / (int)count;
    int rem = (int)srcWidth % (int)count;
    int bres = -dstWidth;
    int remaining = dstWidth - 1;
    uint8_t* pRamp = (uint8_t*)rdColormap_pCurMap->lightlevel;
    for (;;)
    {
        uint32_t sum;
        uint32_t div;
        if ((int16_t)remaining == 0)
        {
            sum = pSrc[0];
            div = 1;
        }
        else
        {
            sum = (uint32_t)pSrc[0] + (uint32_t)pSrc[step];
            div = 2;
        }
        if (sum != 0)
        {
            uint32_t v = (sum * (uint32_t)color + (div >> 1)) / div;
            *pDst = pRamp[v * 0x100 + 0xd8];
        }
        pSrc += step;
        bres += rem;
        pDst++;
        if ((int16_t)bres >= 0)
        {
            bres -= dstWidth;
            pSrc++;
        }
        if ((int16_t)remaining == 0)
            break;
        remaining--;
    }
}

// vtbl +0x18 @424730 (Ghidra: dwGuiOpening_Update — really the Draw slot).
// Perspective crawl projection over the SMUSH frames: for each of the 430
// dest scanlines (screen y 50..479) compute the crawl source row via the
// rational scroll map N(u)/D(u), the narrowing x-inset (210 at the top row,
// 0 at the bottom), and resample the row. Scroll spans SMUSH frames
// 100..622; the crawl fades out from frame 590.
// Note: the FPU expression tree is reproduced in float precision (the binary
// evaluates parts of it at x87 double width) — flagged for re-verification
// now that SMUSH playback lands the frame counter for real (P8).
void dwGuiOpening::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    dwMovie::Draw(pDestBits, pClipRect);

    dwImage* pCrawl = this->pCrawlImage;
    if (pCrawl == NULL)
        return;
    uint32_t frame = lecSmush_frameNum;
    if (frame < 100 || frame >= 0x26f)
        return;
    int fade = 0x3f;
    if (frame >= 0x24e)
        fade = 0x3f - (int)((63 * (frame - 0x24e)) / 33);

    void* pPixels = NULL;
    int stride = 0;
    pCrawl->Lock(&pPixels, &stride);

    int t = (int)frame - 100;
    int crawlH = (int)pCrawl->desc.height;
    uint8_t* pDstRow = (uint8_t*)pDestBits->pPixels + 50 * pDestBits->stride;

    // scroll state: S sweeps 2*crawlH*(t/523 - 1) -> bottom row shows source
    // row 2*crawlH*t/523 (the whole crawl passes over 523 frames)
    float S = 2.0f * ((float)t * 0.0019120459f * (float)crawlH) - (float)(2 * crawlH);
    float A = S * 0.05f;
    float B = (S + (float)(2 * crawlH)) * 0.16666667f - A;

    for (int row = 0; row < 0x1ae; row++, pDstRow += pDestBits->stride)
    {
        float u1 = ((float)row - 0.6f) * 0.0023255814f; // row top edge in 0..1
        float d1 = 0.05f + u1 * 0.11666667f;
        float xW = -1800.0f * d1 + 300.0f;              // = 210 * (1 - u1)
        int srcY = (int)((A + u1 * B) / d1 + 0.5f);
        if ((int16_t)srcY < 0)
            continue;
        if (srcY >= crawlH)
            continue;
        float u2 = ((float)row + 0.6f) * 0.0023255814f; // row bottom edge
        float d2 = 0.05f + u2 * 0.11666667f;
        int srcEnd = (int)((A + u2 * B) / d2 + 0.5f);
        if ((int16_t)srcEnd < 0)
            srcEnd = 0;
        if (srcEnd >= crawlH)
            srcEnd = crawlH - 1;
        int xIn = (int)(xW + 0.5f);
        dwGuiOpening_ResampleSpan(pDstRow + xIn + 0x14, 2 * (300 - xIn),
                                  (uint8_t*)pPixels + stride * srcY,
                                  (int16_t)pCrawl->desc.width,
                                  srcEnd - srcY, stride, fade);
    }
    pCrawl->Unlock();
}

// ---------------------------------------------------------------------------
// dwGuiOptions_ResetGameState — fresh-profile game state
// ---------------------------------------------------------------------------

// @424ae0. Note: every dwCore_* global here is NULL-guarded — they are
// dwMain.c placeholders (NULL) until the P7 boot flow lands; the binary's
// lists always exist.
extern "C" void dwGuiOptions_ResetGameState(void)
{
    dwString* pDefault;

    dwPlayer_name.Free();
    if (dwCore_pGlobalStrings != NULL)
    {
        pDefault = dwCore_pGlobalStrings->Find("DFLT_PLAYER");
        if (pDefault != NULL)
            dwPlayer_name.AssignString(pDefault);
    }
    dwCore_workspaceName.Free();
    if (dwCore_pGlobalStrings != NULL)
    {
        pDefault = dwCore_pGlobalStrings->Find("DFLT_NAME");
        if (pDefault != NULL)
            dwCore_workspaceName.AssignString(pDefault);
    }
    dwPlayer_statsFlags = 0;

    // destroy the workspace droid (part nodes + their list nodes)
    if (dwCore_pWorkspaceNodes != NULL)
    {
        for (dwListNode* pNode = dwCore_pWorkspaceNodes->pNext; pNode != dwCore_pWorkspaceNodes; pNode = pNode->pNext)
        {
            dwPartNode* pPart = (dwPartNode*)pNode->pData;
            if (pPart != NULL)
                delete pPart;
        }
        ((dwList*)&dwCore_pWorkspaceNodes)->FreeNodeRange(dwCore_pWorkspaceNodes->pNext, dwCore_pWorkspaceNodes);
    }

    // relock the missions; the first NORMAL mission becomes current
    dwCore_pCurrentMission = NULL;
    if (dwCore_pMissionList != NULL)
    {
        for (dwListNode* pNode = dwCore_pMissionList->pNext; pNode != dwCore_pMissionList; pNode = pNode->pNext)
        {
            dwMission* pMission = (dwMission*)pNode->pData;
            pMission->bDone = 0;
            pMission->rank = 0;
            pMission->bUnlocked = (pMission->missionType == 0);
            if (dwCore_pCurrentMission == NULL && pMission->bUnlocked)
                dwCore_pCurrentMission = pMission;
        }
    }

    // blueprints available again unless RESTRICTED
    if (dwCore_pBlueprintList != NULL)
    {
        for (dwListNode* pNode = dwCore_pBlueprintList->pNext; pNode != dwCore_pBlueprintList; pNode = pNode->pNext)
        {
            dwPart* pPart = (dwPart*)pNode->pData;
            pPart->bAvailable = (pPart->bRestricted == 0) ? 1 : 0;
        }
    }
}

// ---------------------------------------------------------------------------
// dwGuiOptions — the screen class
// ---------------------------------------------------------------------------

// @424c30 (dwGuiOptions_Ctor)
dwGuiOptions::dwGuiOptions(int screenIndex_)
    : dwGuiScreen(dwGuiOptions_aSubScreenNames[screenIndex_], NULL)
{
    this->pNameEntry = NULL;
    // Note: the binary leaves these four uninitialized until CreateControl
    this->pScrollBox = NULL;
    this->pNameScrollBar = NULL;
    this->pScrollUpBtn = NULL;
    this->pScrollDownBtn = NULL;
    this->bNoProfiles = 0;
    this->screenIndex = screenIndex_;
    this->pStringTable = new dwStringTable("options.txt"); // base member; freed by the base dtor

    dwList profiles;
    dwPlayer_EnumProfiles(&profiles);
    if (profiles.pSentinel->pNext == profiles.pSentinel)
        this->bNoProfiles = 1;
    dwGuiOptions_FreeProfileList(&profiles);
}

// @424e10 (dwGuiOptions_Dtor; scalar-deleting wrapper @424df0; secondary
// thunk @426070) — frees selectedName + enteredName (implicit dwString dtors).
dwGuiOptions::~dwGuiOptions()
{
}

// @4256c0 (dwGuiOptions_IsDuplicateName) — 1 when pName equals any existing
// profile directory's basename (case-insensitive).
static char dwGuiOptions_IsDuplicateName(dwString* pName)
{
    char bDup = 0;
    dwList profiles;
    dwPlayer_EnumProfiles(&profiles);
    for (dwListNode* pNode = profiles.pSentinel->pNext;
         pNode != profiles.pSentinel && bDup == 0;
         pNode = pNode->pNext)
    {
        char* pPath = ((dwString*)pNode->pData)->pBuffer;
        dwString_FindFilename(&pPath);
        if (dwString_Equals(pName->pBuffer, pPath))
            bDup = 1;
    }
    dwGuiOptions_FreeProfileList(&profiles);
    return bDup;
}

// scn vtbl +0x00 @424e80 (dwGuiOptions_OnActivate)
int dwGuiOptions::Activate()
{
    // (binary: AssignCStr from the shared empty-string BSS byte @0x53d6c4)
    this->selectedName.AssignCStr("");
    int ret = dwGuiScreen::Activate();
    if (this->pNameEntry != NULL)
        this->pNameEntry->BeginEdit();
    return ret;
}

// scn vtbl +0x04 @424ec0 (dwGuiOptions_OnDeactivate)
void dwGuiOptions::Deactivate()
{
    if (dwPlayer_name.length == 0)
    {
        dwPlayer_profileDir.Free();
    }
    else
    {
        dwPlayer_profileDir.AssignString(&dwPlayer_basePath);
        dwPlayer_profileDir.Append(dwPlayer_name.pBuffer, dwPlayer_name.length);
        dwPlayer_profileDir.Append("\\", 1);
    }
    dwGuiScreen::Deactivate();
    this->pNameEntry = NULL;
    this->pScrollBox = NULL;
    this->pNameScrollBar = NULL;
    this->pScrollUpBtn = NULL;
    this->pScrollDownBtn = NULL;
}

// vtbl +0x14 @425830 (dwGuiOptions_Update)
void dwGuiOptions::Update(float dt)
{
    this->controls.Update(dt);
}

// @425850 (dwGuiOptions_LoadSubScreen)
void dwGuiOptions::LoadSubScreen(int index)
{
    this->scriptName.AssignCStr(dwGuiOptions_aSubScreenNames[index]);
    this->scriptName.Append(".ifc", 4);
    this->screenIndex = index;

    // destroy the current controls (base Activate lazily rebuilds them from
    // the new script)
    dwListNode* pNode = this->controls.children.pSentinel->pNext;
    while (pNode != this->controls.children.pSentinel)
    {
        dwListNode* pNext = pNode->pNext;
        dwWidget* pWidget = (dwWidget*)pNode->pData;
        this->controls.children.UnlinkFreeNode(pNode);
        if (pWidget != NULL)
            delete pWidget; // binary: vtbl[0](1) virtual delete
        pNode = pNext;
    }
    this->Deactivate();
    this->Activate();
}

// vtbl +0x1c @424f50 (dwGuiOptions_OnMessage) — the menu command switch on
// (code - 6000). Commands (from the CreateControl-built widgets and the .ifc
// BUTTON ids): 0 main / 1 game / 2 new-game / 3 load-game / 4 credits /
// 5 help / 6 setup / 0xa cancel-quit / 0xb start-new-game / 0xc load
// selected profile / 0xd commit new-player name / 0x10 select profile /
// 0x11 toggle text / 0x13 brightness / 0x14 music vol / 0x15 sound vol /
// 0x18 view size / 0x19 delete profile / 0x1a replay sign-in intro /
// 0x1b-0x1d replay videos / 0x1e replay ending certificate.
int dwGuiOptions::OnMessage(dwWidgetMsg* pMsg)
{
    char bHandled = 0;

    switch (pMsg->code - 6000)
    {
    case 0:
        this->LoadSubScreen(0);
        break;
    case 1:
        this->selectedName.Free();
        this->LoadSubScreen(2);
        break;
    case 2:
        this->LoadSubScreen(3);
        break;
    case 3:
        this->LoadSubScreen(4);
        if (this->pScrollBox->items.pSentinel->pNext == this->pScrollBox->items.pSentinel)
        {
            // no profiles to load
            dwGuiDialog_RunModal("gmessage", "DLG_CANTLOAD");
            this->LoadSubScreen(3);
        }
        break;
    case 4:
    {
        dwGuiCredits* pCredits = new dwGuiCredits();
        dwSegment_InterruptWith(dwSegment_pActive, static_cast<dwSegment*>(pCredits));
        break;
    }
    case 5:
        this->LoadSubScreen(1);
        break;
    case 6:
        this->LoadSubScreen(5);
        break;
    case 0xa:
        // cancel a pending quit (binary: byte 0x53e8ac = 0)
        dwSegment_CancelQuit();
        break;
    case 0xb:
        if (dwPlayer_name.length == 0)
        {
            dwGuiDialog_RunModal("gmessage", "DLG_NONAME");
            this->LoadSubScreen(2);
        }
        else
        {
            dwSegment_RequestAdvance();
        }
        break;
    case 0xc: // load the selected profile and enter the workshop
        if (this->selectedName.length == 0)
            this->selectedName.AssignString(&this->pScrollBox->pSelectedItem->filename);
        this->controls.Disable();
        dwPlayer_SavePlr();
        dwGuiOptions_ResetGameState();
        dwPlayer_LoadPlr(this->selectedName.pBuffer);
        dwSound_SetMusic("ws-amb1.wav", 1);
        dwSegment_PushAndAdvance(dwMovie_OpenSeg("wstart.san", NULL));
        bHandled = 1;
        break;
    case 0xd: // commit the entered new-player name
    {
        this->controls.Disable();
        dwString trimmed(this->enteredName);
        // trim leading whitespace
        if (trimmed.pBuffer != NULL)
        {
            char* pStart = trimmed.pBuffer;
            while (*pStart != '\0' && isspace((unsigned char)*pStart))
                pStart++;
            this->enteredName.AssignCStr(pStart);
        }
        // trim trailing whitespace
        if (this->enteredName.length != 0)
        {
            trimmed.AssignString(&this->enteredName);
            char* pBase = this->enteredName.pBuffer;
            char* pEnd = pBase + this->enteredName.length - 1;
            while (isspace((unsigned char)*pEnd))
                pEnd--;
            this->enteredName.Assign(trimmed.pBuffer, (uint32_t)(pEnd - pBase) + 1);
        }
        if (this->enteredName.length == 0)
        {
            dwGuiDialog_RunModal("gmessage", "DLG_ENTERNAME");
            if (this->pNameEntry != NULL)
                this->pNameEntry->BeginEdit();
        }
        else
        {
            int bProceed = 1;
            if (dwGuiOptions_IsDuplicateName(&this->enteredName) != 0)
                bProceed = (dwGuiDialog_RunModal("gyesno", "DLG_DUPNAME") == 5000);
            if (bProceed)
            {
                dwPlayer_DeleteProfile(this->enteredName.pBuffer);
                dwPlayer_SavePlr();
                dwGuiOptions_ResetGameState();
                dwPlayer_CreateProfile(this->enteredName.pBuffer);
                dwPlayer_name.AssignString(&this->enteredName);
                if (this->bNoProfiles == 0)
                {
                    // profiles already existed: run the full new-player intro
                    dwSegment_PushAndAdvance(new dwGuiIntroSeg());
                }
                else
                {
                    // fresh install: the boot flow already staged the intro —
                    // straight into the workshop
                    dwSound_SetMusic("ws-amb1.wav", 1);
                    dwSegment_RequestAdvance();
                }
            }
            else
            {
                if (this->pNameEntry != NULL)
                    this->pNameEntry->BeginEdit();
            }
        }
        this->controls.Enable();
        break;
    }
    case 0x10:
        this->selectedName.AssignCStr((char*)pMsg->pSender);
        break;
    case 0x11:
        dw_settingShowText = (dw_settingShowText == 0);
        break;
    case 0x13:
        dw_settingBrightness = (uint32_t)(intptr_t)pMsg->pSender;
        dwColormap_SetDisplayPalette((void*)(intptr_t)dw_settingBrightness);
        break;
    case 0x14:
        dw_settingMusicVol = (uint32_t)(intptr_t)pMsg->pSender;
        sithSoundMixer_UpdateMusicVolume((float)dw_settingMusicVol * 0.01f);
        break;
    case 0x15:
        dw_settingSoundVol = (uint32_t)(intptr_t)pMsg->pSender;
        dwSound_SetMenuVolume((float)dw_settingSoundVol * 0.01f);
        break;
    case 0x18:
        dw_viewSizePct = (uint32_t)(intptr_t)pMsg->pSender;
        break;
    case 0x19: // delete the selected profile
    {
        this->controls.Disable();
        if (this->selectedName.length == 0)
            this->selectedName.AssignString(&this->pScrollBox->pSelectedItem->filename);
        if (dwString_Equals(this->selectedName.pBuffer, dwPlayer_name.pBuffer))
        {
            // deleting the CURRENT game
            if (dwGuiDialog_RunModal("gyesno", "DLG_DELETEGME") == 5000)
            {
                dwPlayer_DeleteProfile(this->selectedName.pBuffer);
                this->pScrollBox->RemoveSelected();
                dwGuiOptions_ResetGameState();
                dwPlayer_name.Free();
            }
        }
        else
        {
            if (dwGuiDialog_RunModal("gyesno", "DLG_DELETEOK") == 5000)
            {
                dwPlayer_DeleteProfile(this->selectedName.pBuffer);
                this->pScrollBox->RemoveSelected();
            }
        }
        // notify the sub-screen whether any profiles remain
        dwWidgetMsg msg;
        msg.code = (this->pScrollBox->items.pSentinel->pNext == this->pScrollBox->items.pSentinel)
                       ? 0x1772
                       : 0x1773;
        msg.pSender = NULL;
        msg.param = 0;
        msg.pTarget = NULL;
        dwWidget_DispatchMsg(&msg, NULL);
        this->controls.Enable();
        bHandled = 1;
        break;
    }
    case 0x1a: // replay the sign-in intro (longago -> crawl -> back here)
    {
        dwSound_SetMusic(NULL, 1);
        dwSegment_Push(static_cast<dwSegment*>(this));
        dwGuiOpening* pOpening = new dwGuiOpening();
        dwSegment_Push(pOpening);
        dwGuiLongAgo* pLongAgo = new dwGuiLongAgo();
        dwSegment_PushAndAdvance(static_cast<dwSegment*>(pLongAgo));
        break;
    }
    case 0x1b:
    {
        dwSegment* pSeg = dwMovie_OpenSeg("Congrats_A.san", NULL);
        dwSound_SetMusic(NULL, 1);
        dwSegment_InterruptWith(dwSegment_pActive, pSeg);
        break;
    }
    case 0x1c:
    {
        dwSegment* pSeg = dwMovie_OpenSeg("Congrats_B.san", NULL);
        dwSound_SetMusic(NULL, 1);
        dwSegment_InterruptWith(dwSegment_pActive, pSeg);
        break;
    }
    case 0x1d:
    {
        dwSegment* pSeg = dwMovie_OpenSeg("data.san", NULL);
        dwSound_SetMusic(NULL, 1);
        dwSegment_InterruptWith(dwSegment_pActive, pSeg);
        break;
    }
    case 0x1e: // replay the ending certificate
    {
        dwEnding* pEnding = new dwEnding();
        dwSound_SetMusic(NULL, 1);
        dwSegment_InterruptWith(dwSegment_pActive, static_cast<dwSegment*>(pEnding));
        break;
    }
    default:
        break;
    }

    if (bHandled == 0)
        bHandled = (char)dwGuiScreen::OnMessage(pMsg);
    return bHandled;
}

// vtbl +0x48 @425900 (dwGuiOptions_CreateControl)
dwWidget* dwGuiOptions::CreateControl(char* pKeyword, dwConfFile* pConf)
{
    dwRect rect = {0, 0, 0, 0};

    if (dwString_Equals(pKeyword, "SCROLLBOX"))
    {
        uint32_t scrollMsg = 0;
        int32_t textColor = 0;
        uint32_t highlightColor = 0;
        uint32_t selMsg = 0;
        dwConfFile_ParseRect(pConf, &rect);
        dwConfFile_ParseULong(pConf, &scrollMsg);
        char* pFontName = dwConfFile_NextToken(pConf);
        dwConfFile_ParseLong(pConf, &textColor);
        dwConfFile_ParseULong(pConf, &highlightColor);
        dwConfFile_ParseULong(pConf, &selMsg);
        this->pScrollBox = new dwGuiScrollBox(&rect, (int)scrollMsg, pFontName,
                                              (uint8_t)textColor, (uint8_t)highlightColor, (int)selMsg);
        // fill it with the existing profiles
        dwList profiles;
        dwPlayer_EnumProfiles(&profiles);
        for (dwListNode* pNode = profiles.pSentinel->pNext; pNode != profiles.pSentinel; pNode = pNode->pNext)
        {
            char* pPath = ((dwString*)pNode->pData)->pBuffer;
            this->pScrollBox->AddItem(pPath, pPath);
        }
        dwGuiOptions_FreeProfileList(&profiles);
        return this->pScrollBox;
    }
    if (dwString_Equals(pKeyword, "TEXT_TOGGLE"))
    {
        dwWidget* pCtl = dwGuiScreen::CreateControl((char*)"TOGGLE", pConf);
        if (pCtl != NULL && dw_settingShowText != 0)
        {
            // seed the toggle visual state with a synthetic click
            pCtl->OnMouseDown(pCtl->left + 1, pCtl->top);
        }
        return pCtl;
    }
    if (dwString_Equals(pKeyword, "BGT_SCROLLBAR"))
    {
        dwGuiScrollBar* pBar = (dwGuiScrollBar*)dwGuiScreen::CreateControl((char*)"SCROLLBAR", pConf);
        if (pBar != NULL)
            pBar->SetValue((int)dw_settingBrightness);
        return pBar;
    }
    if (dwString_Equals(pKeyword, "SZE_SCROLLBAR"))
    {
        dwGuiScrollBar* pBar = (dwGuiScrollBar*)dwGuiScreen::CreateControl((char*)"SCROLLBAR", pConf);
        if (pBar != NULL)
            pBar->SetValue((int)dw_viewSizePct);
        return pBar;
    }
    if (dwString_Equals(pKeyword, "MVOL_SCROLLBAR"))
    {
        dwGuiScrollBar* pBar = (dwGuiScrollBar*)dwGuiScreen::CreateControl((char*)"SCROLLBAR", pConf);
        if (pBar != NULL)
            pBar->SetValue((int)dw_settingMusicVol);
        return pBar;
    }
    if (dwString_Equals(pKeyword, "SVOL_SCROLLBAR"))
    {
        dwGuiScrollBar* pBar = (dwGuiScrollBar*)dwGuiScreen::CreateControl((char*)"SCROLLBAR", pConf);
        if (pBar != NULL)
            pBar->SetValue((int)dw_settingSoundVol);
        return pBar;
    }
    if (dwString_Equals(pKeyword, "PLAYERNAME"))
    {
        uint32_t textColor = 0;
        uint32_t cursorColor = 0;
        uint32_t msgCommit = 0;
        dwConfFile_ParseRect(pConf, &rect);
        char* pFontName = dwConfFile_NextToken(pConf);
        dwConfFile_ParseULong(pConf, &textColor);
        dwConfFile_ParseULong(pConf, &cursorColor);
        dwConfFile_ParseULong(pConf, &msgCommit);
        this->pNameEntry = new dwGuiTextEntry(&rect, pFontName, (uint8_t)textColor,
                                              (uint8_t)cursorColor, &this->enteredName,
                                              0, 0, (int32_t)msgCommit);
        return this->pNameEntry;
    }
    if (dwString_Equals(pKeyword, "SCROLLUPBUTTON"))
    {
        uint32_t cmdId = 0;
        dwConfFile_ParseRect(pConf, &rect);
        dwConfFile_ParseULong(pConf, &cmdId);
        char* pImgUp = dwConfFile_NextToken(pConf);
        char* pImgDown = dwConfFile_NextToken(pConf);
        this->pScrollUpBtn = new dwGuiScrollButton(&rect, pImgUp, pImgDown, (int)cmdId);
        // binary quirk kept: reads pScrollBox unconditionally (the .ifc
        // always defines SCROLLBOX before the scroll buttons/bar)
        if (this->pScrollBox->bNeedsScroll == 0)
            this->pScrollUpBtn->Disable();
        return this->pScrollUpBtn;
    }
    if (dwString_Equals(pKeyword, "SCROLLDOWNBUTTON"))
    {
        uint32_t cmdId = 0;
        dwConfFile_ParseRect(pConf, &rect);
        dwConfFile_ParseULong(pConf, &cmdId);
        char* pImgUp = dwConfFile_NextToken(pConf);
        char* pImgDown = dwConfFile_NextToken(pConf);
        this->pScrollDownBtn = new dwGuiScrollButton(&rect, pImgUp, pImgDown, (int)cmdId);
        if (this->pScrollBox->bNeedsScroll == 0)
            this->pScrollDownBtn->Disable();
        return this->pScrollDownBtn;
    }
    if (dwString_Equals(pKeyword, "NAMESCROLLBAR"))
    {
        uint32_t msgSetValue = 0;
        uint32_t msgLineUp = 0;
        uint32_t msgLineDown = 0;
        dwConfFile_ParseRect(pConf, &rect);
        dwConfFile_ParseULong(pConf, &msgSetValue);
        dwConfFile_ParseULong(pConf, &msgLineUp);
        dwConfFile_ParseULong(pConf, &msgLineDown);
        char* pThumbImg = dwConfFile_NextToken(pConf);
        if (pThumbImg != NULL && *pThumbImg == '\0')
            pThumbImg = NULL;
        int maxValue = 0;
        if (this->pScrollBox->itemCount != 0)
            maxValue = this->pScrollBox->itemCount - 1;
        this->pNameScrollBar = new dwGuiScrollBar(&rect, (int)msgSetValue, (int)msgLineUp,
                                                  (int)msgLineDown, 0, maxValue, NULL, pThumbImg);
        this->pNameScrollBar->SetValue(0);
        if (this->pScrollBox->bNeedsScroll == 0)
            this->pNameScrollBar->Disable();
        return this->pNameScrollBar;
    }
    if (dwString_Equals(pKeyword, "CUTSCENE"))
    {
        // replay-menu entry, shown only once its stats flag is earned
        uint32_t mask = 0;
        dwConfFile_ParseULong(pConf, &mask);
        if ((mask & dwPlayer_statsFlags) == 0)
            return NULL;
        char* pInner = dwConfFile_NextToken(pConf);
        return dwGuiScreen::CreateControl(pInner, pConf);
    }
    return dwGuiScreen::CreateControl(pKeyword, pConf);
}
