// dwGuiStatus — mission STATUS / debriefing screen (dwGuiScreen subclass) +
// the shared dwGuiPicture control. DroidWorks.exe 0x434d50-0x436d7f, vtbls
// 0x51fa80 (primary) / 0x51fa68 (segment); dwGuiPicture @0x4365d0 vtbl
// 0x51fad0. See Dw/dwGuiStatus.h for the class notes.

#include "Dw/dwGuiStatus.h"

#include "Dw/dwMission.h"      // dwMission / dwMissionObjective / dwMissionSequence / dwMission_ClearObjectives
#include "Dw/dwPart.h"         // dwPart / dwPart_FindBlueprint
#include "Dw/dwPlayer.h"       // dwPlayer_SavePlr
#include "Dw/dwGuiInGame.h"    // dwGuiInGame_New (replay) + dwGuiIndicator forward
#include "Dw/dwGuiOptions.h"   // dwMovie_OpenSeg (Ghidra: jkSmack_SmackPlay)
#include "Dw/dwGuiHypText.h"   // dwGuiHypText (rank/goal text)
#include "Dw/dwGuiTextMisc.h"  // dwGuiTypewriter + dwGuiTimer_New
#include "Dw/dwGuiButton.h"    // dwGuiClock
#include "Dw/dwGuiWidgetBar.h" // dwGuiWidgetBar
#include "Dw/dwGuiQuickView.h" // dwGuiDroidPreview_New
#include "Dw/dwSegment.h"      // dwSegment_Push/Pop/Release/GetElapsed
#include "Dw/dwSound.h"        // dwSound_Stop / dwSound_PlayRestart / dwSound_pManager
#include "Dw/dwColormap.h"     // dwColormap_Load
#include "Dw/dwImage.h"        // dwImage (rank icon blit)
#include "Dw/dwString.h"
#include "Dw/dwList.h"
#include "Dw/dwWidgetGroup.h"

#include "stdPlatform.h"

#include <stdlib.h> // rand

// ---- cross-unit symbols -----------------------------------------------------

// The global mission + workspace state (owned by the dw core unit, P7).
extern "C" dwListNode* dwCore_pMissionList;    // @0x53d95c (dwMission list sentinel)
extern "C" dwMission*  dwCore_pCurrentMission; // @0x53d... (selected mission)
extern "C" dwString    dwCore_workspaceName;   // @0x53d978 (droid name)

// The game-wide modal-dialog runner (dwGuiMission unit).
extern "C" int dwGuiDialog_RunModal(const char* pConfName, const char* pMsgKey);

// SPEED/DAMAGE/POWER gauges (dwGuiIndicator) — provided by dwHelp (P6 wave 2b).
// dwGuiIndicator_* are extern "C" shims, so include the real header (a local
// C++-linkage decl mismatches dwHelp.cpp's extern "C" definitions at link time).
#include "Dw/dwHelp.h"

// ---- module statics ---------------------------------------------------------

// The one-shot achievement bitmask (binary DAT_0053d9f8): tracks which
// congratulation cutscene/unlock has already fired. Persists across debriefs
// during a session; reset by dwGuiStatus_Startup for the soft-reset loop.
static uint32_t dwGuiStatus_achieveFlags = 0;

// Rank-icon RLE filenames indexed by rankImageIdx (binary table @0x51fa28,
// dwGuiImage_vtbl[idx + 0x12]). Index 0 = unranked (no image; the binary's
// entry is a zero-initialized .data slot, i.e. an empty string).
static const char* const dwGuiStatus_rankImages[6] = {
    "",
    "YRscavenger.RLE",
    "YRapprentice.RLE",
    "YRmaster.RLE",
    "YRCrystal.RLE",
    "YRDataDisk.RLE",
};

// Rank-name localization KEYS indexed by rank tier (binary table @0x51fa40,
// dwGuiImage_vtbl[tier + 0x18]).
static const char* const dwGuiStatus_rankNames[4] = {
    "UNRANKED",
    "APPRENTICE",
    "DESIGNER",
    "MASTER",
};

// ============================================================================
//  dwGuiPicture — shared id-keyed picture box (dwWidgetGroup subclass)
// ============================================================================

// @4365d0 (dwGuiPicture_Ctor) — pRect (Ghidra mislabeled the arg "pParent";
// every caller passes a rect).
dwGuiPicture::dwGuiPicture(dwRect* pRect, const char* pImageName, int32_t posPair)
    : dwWidgetGroup(pRect)
{
    // items' dwList ctor allocated + self-linked its sentinel.
    this->pImage = NULL;
    this->posX = (int16_t)posPair;
    this->posY = (int16_t)(posPair >> 16);
    this->imageName.AssignCStr(pImageName);
    this->EnsureImages();
}

// Added: C++-linkage factory (dwRef builds picture boxes through this).
dwWidget* dwGuiPicture_New(dwRect* pRect, const char* pImgName, int posPair)
{
    return new dwGuiPicture(pRect, pImgName, posPair);
}

// @436690 (dwGuiPicture_Dtor)
dwGuiPicture::~dwGuiPicture()
{
    this->FreeImages(); // deletes pImage

    // delete every id->image entry, then free the list nodes + sentinel
    dwListNode* pSent = this->items.pSentinel;
    dwListNode* pNode = pSent->pNext;
    while (pNode != pSent)
    {
        dwListNode* pNext = pNode->pNext;
        dwGuiPictureItem* pItem = (dwGuiPictureItem*)pNode->pData;
        if (pItem != NULL)
            delete pItem;
        pNode = pNext;
    }
    this->items.Free();
    // (imageName auto-freed; base ~dwWidgetGroup deletes the caption children)
}

// vtbl +0x18 @436b60 (dwGuiPicture_OnHover)
int dwGuiPicture::OnHover(int16_t x, int16_t y)
{
    (void)x; (void)y;
    // Note: the binary calls dwWidget_DispatchMsg with a stack message the
    // decompiler could not recover; the observable result is a consumed hover.
    return 1;
}

// vtbl +0x1c @4368c0 (dwGuiPicture_OnMessage)
int dwGuiPicture::OnMessage(dwWidgetMsg* pMsg)
{
    dwListNode* pSent = this->items.pSentinel;
    for (dwListNode* pNode = pSent->pNext; pNode != pSent; pNode = pNode->pNext)
    {
        dwGuiPictureItem* pItem = (dwGuiPictureItem*)pNode->pData;
        if (pItem->id == pMsg->code)
        {
            if (this->pImage != NULL)
            {
                delete this->pImage;
                this->pImage = NULL;
                this->Invalidate();
            }
            this->imageName.AssignString(&pItem->imageName);
            this->pImage = dwImage_LoadFile(this->imageName.pBuffer);
            this->Invalidate();
            break;
        }
    }
    return dwWidgetGroup::OnMessage(pMsg);
}

// vtbl +0x3c @436bd0 (dwGuiPicture_EnsureLoaded)
void dwGuiPicture::EnsureImages()
{
    if (this->pImage == NULL && this->imageName.length != 0)
        this->pImage = dwImage_LoadFile(this->imageName.pBuffer);
    dwWidgetGroup::EnsureImages();
}

// vtbl +0x40 @436c00 (dwGuiPicture_FreeImage)
void dwGuiPicture::FreeImages()
{
    if (this->pImage != NULL)
    {
        delete this->pImage;
        this->pImage = NULL;
    }
    dwWidgetGroup::FreeImages();
}

// vtbl +0x44 @436b90 (dwGuiPicture_Draw)
void dwGuiPicture::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    if (this->bEnabled != 0)
    {
        this->EnsureImages();
        if (this->pImage != NULL)
            this->pImage->Blit(pDestBits, this->left, this->top, pClipRect);
        dwWidgetGroup::Draw(pDestBits, pClipRect);
    }
}

// @436960 (dwGuiPicture_AddImage)
void dwGuiPicture::AddImage(char* pImageName, uint32_t id)
{
    dwGuiPictureItem* pItem = new dwGuiPictureItem(pImageName, (int)id);
    // push front (insert after the sentinel, before the current head)
    this->items.InsertAfter(this->items.pSentinel, pItem);
}

// @436a00 (dwGuiPicture_AddText) — spawn a positioned dwGuiHypText caption.
// The binary packs the position/size as two short pairs; reproduced here.
void dwGuiPicture::AddText(char* pText, int x, int y, int color, char* pFont)
{
    int16_t rl = (int16_t)x + this->left;
    int16_t rt = (int16_t)(x >> 16) + this->top;
    dwRect rect;
    rect.left = rl;
    rect.top = rt;
    rect.right = (int16_t)(rl + (int16_t)y);
    rect.bottom = (int16_t)(rt + (int16_t)(y >> 16));

    dwGuiHypText* pHyp = new dwGuiHypText(&rect, NULL, pFont, (uint8_t)color, (char*)"BLN");
    if (pHyp != NULL)
    {
        pHyp->text.Free();
        pHyp->SetText(pText);
    }
    // push front onto the caption children
    this->children.InsertAfter(this->children.pSentinel, pHyp);
}

// @436ae0 (dwGuiPicture_SelectById)
void dwGuiPicture::SelectById(int id)
{
    dwListNode* pSent = this->items.pSentinel;
    for (dwListNode* pNode = pSent->pNext; pNode != pSent; pNode = pNode->pNext)
    {
        dwGuiPictureItem* pItem = (dwGuiPictureItem*)pNode->pData;
        if (pItem->id == id)
        {
            if (this->pImage != NULL)
            {
                delete this->pImage;
                this->pImage = NULL;
                this->Invalidate();
            }
            this->imageName.AssignString(&pItem->imageName);
            this->pImage = dwImage_LoadFile(this->imageName.pBuffer);
            this->Invalidate();
            return;
        }
    }
}

// ============================================================================
//  dwGuiStatus — mission debrief screen
// ============================================================================

// @434d50 (dwGuiStatus_Ctor)
dwGuiStatus::dwGuiStatus(dwMission* pContextArg, float itemPctArg, float healthPctArg, int chargeMaxArg)
    : dwGuiScreen("Status", NULL)
{
    this->pContext = pContextArg;
    this->bChildBuilt = 0;
    // sound / speech dwString ctors ran (default empty)
    this->bStatsBuilt = 0;
    this->savedRank = (uint8_t)pContextArg->rank;
    this->altRank = (uint8_t)pContextArg->rank;
    this->rankIconRect0.left = this->rankIconRect0.top = this->rankIconRect0.right = this->rankIconRect0.bottom = 0;
    this->rankImageIdx = 0;
    this->rankRect.left = this->rankRect.top = this->rankRect.right = this->rankRect.bottom = 0;
    this->pRankImage = NULL;
    this->rankIconRect1.left = this->rankIconRect1.top = this->rankIconRect1.right = this->rankIconRect1.bottom = 0;
    this->rankIconRect3.left = this->rankIconRect3.top = this->rankIconRect3.right = this->rankIconRect3.bottom = 0;
    this->rankIconRect2.left = this->rankIconRect2.top = this->rankIconRect2.right = this->rankIconRect2.bottom = 0;
    this->bBlinkOn = 0;
    this->blinkTimer = 0.0f;
    this->pGoalsText = NULL;
    this->pGroup = NULL;
    this->itemPct = itemPctArg;
    this->healthPct = healthPctArg;
    this->chargeMax = chargeMaxArg;
}

// @434ee0 (dwGuiStatus_Dtor)
dwGuiStatus::~dwGuiStatus()
{
    this->FreeImages();
    if (this->pGroup != NULL)
        delete this->pGroup; // ~dwWidgetGroup deletes its header children
    // (sound/speech auto-freed; base ~dwGuiScreen tears the rest down)
}

// primary vtbl +0x14 @436400 (dwGuiStatus_Update)
void dwGuiStatus::Update(float dt)
{
    // tick the controls group first (the binary forwards through the embedded
    // group's Update slot), then run the caret/blink timer (0.7s period).
    this->controls.Update(dt);

    this->blinkTimer += dt;
    if (0.7f <= this->blinkTimer)
    {
        int whole = (int)(this->blinkTimer / 0.7f);
        this->bBlinkOn = (this->bBlinkOn == 0);
        this->blinkTimer = this->blinkTimer - (float)whole * 0.7f;
        this->Invalidate();
    }
}

// primary vtbl +0x1c @435180 (dwGuiStatus_OnMessage)
int dwGuiStatus::OnMessage(dwWidgetMsg* pMsg)
{
    if (pMsg->code == 30000 && this->speech.length != 0)
    {
        dwSound_Stop(this->speech.pBuffer);
        this->speech.Free();
    }
    else if (pMsg->code == 0x96)
    {
        dwMission_ClearObjectives(this->pContext);
        if (this->sound.length != 0)
        {
            // A congratulation movie is queued: retire this screen + the
            // mission sequence, play the movie, and return to the workshop.
            // Note: the popped-segment identities were EH-frame-corrupted in
            // the decompile; reconstructed as pop-this / pop-sequence /
            // reset+re-push sequence / push movie.
            dwSegment* pThis = dwSegment_Pop();
            dwSegment_Release(pThis);
            dwSegment* pSeq = dwSegment_Pop();
            ((dwMissionSequence*)pSeq)->Reset();
            dwSegment_Push(pSeq);
            dwSegment_Push(dwMovie_OpenSeg(this->sound.pBuffer, NULL));
            dwColormap_Load((char*)"workshop2.cmp");
        }
        else
        {
            // Offer to replay the mission.
            if (this->bStatsBuilt == 0 && dwGuiDialog_RunModal("gyesno", "DLG_REPLAY") == 5000)
            {
                dwSegment* pGame = dwGuiInGame_New(this->pContext);
                if (pGame != NULL)
                    dwSegment_Push(pGame);
            }
        }
    }
    return dwGuiScreen::OnMessage(pMsg);
}

// primary vtbl +0x3c @436520 (dwGuiStatus_EnsureLoaded)
void dwGuiStatus::EnsureImages()
{
    dwGuiScreen::EnsureImages();
    if (this->pRankImage == NULL)
        this->pRankImage = dwImage_LoadFile((char*)dwGuiStatus_rankImages[this->rankImageIdx]);
    if (this->pGoalsText != NULL)
        this->pGoalsText->EnsureImages();
    if (this->pGroup != NULL)
        this->pGroup->EnsureImages();
}

// primary vtbl +0x40 @436570 (dwGuiStatus_FreeImages)
void dwGuiStatus::FreeImages()
{
    dwGuiScreen::FreeImages();
    if (this->pRankImage != NULL)
    {
        delete this->pRankImage;
        this->pRankImage = NULL;
    }
    if (this->pGoalsText != NULL)
        this->pGoalsText->FreeImages();
    if (this->pGroup != NULL)
        this->pGroup->FreeImages();
}

// primary vtbl +0x44 @436480 (dwGuiStatus_Draw)
void dwGuiStatus::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    dwGuiScreen::Draw(pDestBits, pClipRect);
    if (this->pRankImage != NULL)
    {
        int w = (int)this->pRankImage->desc.width;
        int h = (int)this->pRankImage->desc.height;
        int x = (int)((int16_t)(this->rankRect.right - this->rankRect.left) - w) / 2 + this->rankRect.left;
        int y = (int)((int16_t)(this->rankRect.bottom - this->rankRect.top) - h) / 2 + this->rankRect.top;
        this->pRankImage->Blit(pDestBits, x, y, pClipRect);
    }
}

// primary vtbl +0x48 @4352e0 (dwGuiStatus_CreateControl)
dwWidget* dwGuiStatus::CreateControl(char* pKeyword, dwConfFile* pConf)
{
    if (dwString_Equals(pKeyword, "NAMETEXT"))
    {
        dwWidget* pW = dwGuiScreen::CreateControl((char*)"TEXT", pConf);
        dwGuiHypText* pHyp = (dwGuiHypText*)pW;
        pHyp->text.Free();
        pHyp->SetText(dwCore_workspaceName.pBuffer);
        return pW;
    }
    if (dwString_Equals(pKeyword, "LEVELTEXT"))
    {
        dwWidget* pW = dwGuiScreen::CreateControl((char*)"TEXT", pConf);
        dwGuiHypText* pHyp = (dwGuiHypText*)pW;
        pHyp->text.Free();
        pHyp->SetText(this->pContext->displayName.pBuffer);
        this->Invalidate();
        return pW;
    }
    if (dwString_Equals(pKeyword, "RANKRECT"))
    {
        dwConfFile_ParseRect(pConf, &this->rankRect);
        return NULL;
    }
    if (dwString_Equals(pKeyword, "SPEED"))
    {
        char* pTok = dwConfFile_NextToken(pConf);
        dwWidget* pW = dwGuiScreen::CreateControl(pTok, pConf);
        if (pW != NULL)
            dwGuiIndicator_SetProgress((dwGuiIndicator*)pW, 0.0f);
        return pW;
    }
    if (dwString_Equals(pKeyword, "DAMAGE"))
    {
        char* pTok = dwConfFile_NextToken(pConf);
        dwWidget* pW = dwGuiScreen::CreateControl(pTok, pConf);
        if (pW != NULL)
            dwGuiIndicator_SetProgress((dwGuiIndicator*)pW, this->healthPct);
        return pW;
    }
    if (dwString_Equals(pKeyword, "POWER"))
    {
        char* pTok = dwConfFile_NextToken(pConf);
        dwWidget* pW = dwGuiScreen::CreateControl(pTok, pConf);
        if (pW != NULL)
            dwGuiIndicator_SetProgress((dwGuiIndicator*)pW, this->itemPct);
        return pW;
    }
    if (dwString_Equals(pKeyword, "CLOCK"))
    {
        dwRect rect = { 0, 0, 0, 0 };
        uint32_t color = 0;
        dwConfFile_ParseRect(pConf, &rect);
        char* pFontName = dwConfFile_NextToken(pConf);
        dwConfFile_ParseULong(pConf, &color);
        return new dwGuiClock(rect, pFontName, (uint8_t)color, 0, this->chargeMax);
    }
    if (dwString_Equals(pKeyword, "WIDGETBAR"))
    {
        dwWidget* pW = dwGuiScreen::CreateControl((char*)"WIDGETBAR", pConf);
        ((dwGuiWidgetBar*)pW)->SelectIndex(0);
        pW->Update(5.0f);
        return pW;
    }
    if (dwString_Equals(pKeyword, "HELP"))
    {
        // TODO(dw-decomp): dwHelp (P6 wave 2b agent 3). Binary: new(0x5c)
        // dwHelp_Ctor(&rect, /*pParent*/0, /*speaker*/0x6c). Loud stub.
        stdPlatform_Printf("TODO(dw-decomp): dwGuiStatus control 'HELP' -> dwHelp(speaker 0x6c) not translated yet\n");
        return NULL;
    }
    if (dwString_Equals(pKeyword, "TYPEWRITER"))
    {
        dwRect rect;
        rect.left   = (int16_t)atoi(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), this->pStringTable));
        rect.top    = (int16_t)atoi(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), this->pStringTable));
        rect.right  = (int16_t)atoi(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), this->pStringTable));
        rect.bottom = (int16_t)atoi(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), this->pStringTable));
        char* pFontName = dwConfFile_NextToken(pConf);
        uint32_t color = 0;
        float duration = 0.0f;
        dwConfFile_ParseULong(pConf, &color);
        dwConfFile_ParseFloat(pConf, &duration);
        char* pText = dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), this->pStringTable);
        char* pTickSound = pConf->pCursor; // rest of the line
        return new dwGuiTypewriter(&rect, pFontName, (uint8_t)color, duration, pTickSound, 0, 0, pText);
    }
    return dwGuiScreen::CreateControl(pKeyword, pConf);
}

// segment vtbl +0x00 @434ff0 (dwGuiStatus_OnActivate)
int dwGuiStatus::Activate()
{
    int ret = dwGuiScreen::Activate();

    // Fixed rank-progression icon slots (binary literal coordinates).
    this->rankIconRect0.left = 0x1b3; this->rankIconRect0.top = 0x3c;
    this->rankIconRect0.right = 0x249; this->rankIconRect0.bottom = 0x7d;
    this->rankIconRect1.left = 0xe1;  this->rankIconRect1.top = 0x6e;
    this->rankIconRect1.right = 0x1a4; this->rankIconRect1.bottom = 0x8c;
    this->rankIconRect2.left = 0x1e;  this->rankIconRect2.top = 0xd2;
    this->rankIconRect2.right = 0xe1;  this->rankIconRect2.bottom = 0xff;
    this->rankIconRect3.left = 0x1a9; this->rankIconRect3.top = 0x6e;
    this->rankIconRect3.right = 0x267; this->rankIconRect3.bottom = 0xa0;

    this->pGroup = new dwWidgetGroup();

    if (this->bChildBuilt == '\0')
    {
        this->BuildControls();
        this->bChildBuilt = 1;
    }
    // display the pre-mission rank (the earned rank is committed on hide)
    this->pContext->rank = this->savedRank;
    return ret;
}

// segment vtbl +0x04 @435120 (dwGuiStatus_OnDeactivate)
void dwGuiStatus::Deactivate()
{
    if (this->speech.length != 0)
        dwSound_Stop(this->speech.pBuffer);
    dwGuiScreen::Deactivate();

    // commit the earned rank and persist the profile
    this->savedRank = (uint8_t)this->pContext->rank;
    this->pContext->rank = this->altRank;
    dwPlayer_SavePlr();
}

// @4356f0 (dwGuiStatus_BuildControls)
void dwGuiStatus::BuildControls()
{
    dwMission* m = this->pContext;

    // The current rank tier used to group displayed goals (clamped to 2).
    uint8_t tier = (uint8_t)m->rank;
    if (tier > 2)
        tier = 2;

    // Working layout rects derived from the goals anchor (rankIconRect2).
    // Note: these per-line coordinates are a faithful reconstruction of the
    // binary's short-packing arithmetic; verify against the .exe if a goal
    // line looks mis-placed.
    int16_t aL = this->rankIconRect2.left;   // anchor left
    int16_t aT = this->rankIconRect2.top;    // anchor top
    int16_t aB = this->rankIconRect2.bottom; // anchor bottom

    dwRect twA  = { (int16_t)(aL + 0x19), (int16_t)(aT + 4), (int16_t)(aL + 0xc8), (int16_t)(aB + 4) };
    dwRect picA = { aL,                    aT,                (int16_t)(aL + 0x14),  aB };
    dwRect twB  = { (int16_t)(aL + 0xeb), (int16_t)(aT + 4), (int16_t)(aL + 0x19a), (int16_t)(aB + 4) };
    dwRect picB = { (int16_t)(aL + 0xd2),  aT,                (int16_t)(aL + 0xe6),  aB };

    float picTime = 1.0f; // local_40 (checkmark timer seed)
    float twTime  = 1.8f; // local_3c (goal-text timer seed)

    int nShown = 0;     // local_45: total goals displayed
    int nComplete = 0;  // local_46: complete goals displayed

    for (dwListNode* pNode = m->pObjectives->pNext; pNode != m->pObjectives; pNode = pNode->pNext)
    {
        dwMissionObjective* pObj = (dwMissionObjective*)pNode->pData;
        if (pObj->code != tier)
            continue;

        dwRect* pTw  = (pObj->bRequirement == 0) ? &twA  : &twB;
        dwRect* pPic = (pObj->bRequirement == 0) ? &picA : &picB;

        // goal text (typewriter), wrapped in a reveal timer
        dwGuiTypewriter* pTypeW = new dwGuiTypewriter(
            pTw, (char*)"Arial10", 0x14, 0.25f, (char*)"WTextAppear.WAV", 0, 0, pObj->label.pBuffer);
        if (pTypeW != NULL)
        {
            dwWidget* pTimer = dwGuiTimer_New(pTypeW, twTime, 0.0f);
            this->controls.children.InsertAfter(this->controls.children.pSentinel->pPrev, pTimer);
        }

        // completion checkmark box
        dwGuiPicture* pBox;
        if (pObj->bFlag == 0)
        {
            pBox = new dwGuiPicture(pPic, "YBox_NC.rle", 0);
        }
        else
        {
            pBox = new dwGuiPicture(pPic, "YBox_C.rle", 0);
            nComplete++;
        }
        dwWidget* pBoxTimer = dwGuiTimer_New(pBox, picTime, 0.0f);
        this->controls.children.InsertAfter(this->controls.children.pSentinel->pPrev, pBoxTimer);

        pTw->top    = (int16_t)(pTw->top + 0x1e);
        pTw->bottom = (int16_t)(pTw->bottom + 0x1e);
        pPic->top    = (int16_t)(pPic->top + 0x1e);
        pPic->bottom = (int16_t)(pPic->bottom + 0x1e);

        picTime += 0.5f;
        twTime  += 0.5f;
        nShown++;
    }

    this->bStatsBuilt = 0;

    uint8_t rankTier; // local_44: rank tier for the name text lookup

    if (nComplete == nShown)
    {
        // ---- all displayed goals complete ----
        dwRect hdrRect = { (int16_t)(this->left + 0x16a), (int16_t)(this->top + 0x95),
                           this->right, this->bottom };
        dwGuiHypText* pHdr = new dwGuiHypText(&hdrRect, NULL, (char*)"Times_New_Roman18BA", 0x14, (char*)"DLO");
        if (pHdr != NULL)
        {
            char* s = dwGuiScreen_LocalizeString((char*)"GOALS_COMPLETE", this->pStringTable);
            pHdr->text.Free();
            pHdr->SetText(s);
            this->pGroup->children.InsertAfter(this->pGroup->children.pSentinel->pPrev, pHdr);
        }

        // unlock + preview the mission's reward blueprint
        dwPart* pBp = dwPart_FindBlueprint(m->aRewards[tier].pBuffer);
        if (pBp != NULL && pBp->bAvailable == 0)
        {
            pBp->bAvailable = 1;
            dwWidget* pPreview = dwGuiDroidPreview_New(&this->rankIconRect0, pBp);
            if (pPreview != NULL)
                this->controls.children.InsertAfter(this->controls.children.pSentinel->pPrev, pPreview);

            this->rankIconRect3.right = (int16_t)(this->rankIconRect3.right - 0xf);
            dwGuiHypText* pRewardText = new dwGuiHypText(
                &this->rankIconRect3, NULL, (char*)"Times_New_Roman12A", 0x14, (char*)"BCO");
            if (pRewardText != NULL)
            {
                pRewardText->text.Free();
                pRewardText->SetText(pBp->displayName.pBuffer);
                this->controls.children.InsertAfter(this->controls.children.pSentinel->pPrev, pRewardText);
            }
        }
        this->bStatsBuilt = 1;

        if (m->missionType == 0)
        {
            if (tier < 3)
                rankTier = (uint8_t)(tier + 1);
            else
                rankTier = 3;
        }
        else
        {
            rankTier = 3;
        }
    }
    else
    {
        // ---- some displayed goals still incomplete ----
        dwRect hdrRect = { (int16_t)(this->left + 0x168), (int16_t)(this->top + 0x95),
                           this->right, this->bottom };
        this->pGoalsText = new dwGuiHypText(&hdrRect, NULL, (char*)"Times_New_Roman18BA", 0x14, (char*)"DLO");
        if (this->pGoalsText != NULL)
        {
            char* s = dwGuiScreen_LocalizeString((char*)"GOALS_INCOMPLETE", this->pStringTable);
            ((dwGuiHypText*)this->pGoalsText)->text.Free();
            ((dwGuiHypText*)this->pGoalsText)->SetText(s);
            this->pGroup->children.InsertAfter(this->pGroup->children.pSentinel->pPrev, this->pGoalsText);
        }
        rankTier = (uint8_t)m->rank;
        if (rankTier >= 4)
            rankTier = 3;
    }

    // ---- rank name text + rank image index ----
    this->rankImageIdx = rankTier;
    dwGuiHypText* pName = new dwGuiHypText(&this->rankIconRect1, NULL, (char*)"Arial24BA", 0x14, (char*)"DCO");
    if (pName != NULL)
    {
        char* s = dwGuiScreen_LocalizeString((char*)dwGuiStatus_rankNames[rankTier], this->pStringTable);
        pName->text.Free();
        pName->SetText(s);
        this->controls.children.InsertAfter(this->controls.children.pSentinel->pPrev, pName);
    }

    // ---- mission-progression achievement state machine ----
    if (this->bStatsBuilt != 0)
    {
        if (m->missionType == 0)
        {
            if (this->altRank < 3)
                this->altRank++;
        }
        else
        {
            this->altRank = 3;
        }
        if ((uint8_t)m->rank != this->altRank && m->missionType == 0)
            m->bDone = 0;

        const char* pVoice = NULL;
        m->rank = this->altRank; // temporarily reflect the earned rank

        if (m->missionType == 0)
        {
            if (m->rank < 3)
            {
                int r = rand() % 3;
                if (r == 0 || r == 1 || r == 2)
                    pVoice = "HMCA006L.wav";
            }
            else if (this->savedRank != 3)
            {
                int r = rand() % 3;
                if (r == 0 || r == 1 || r == 2)
                    pVoice = "HMCA012L.wav";
            }
        }
        if (m->voiceover.length != 0)
            pVoice = m->voiceover.pBuffer;

        uint8_t sr = this->savedRank;
        if (sr == 0 && m->missionType == 0 && (dwGuiStatus_achieveFlags & 1) == 0)
        {
            bool allDone = true;
            for (dwListNode* p = dwCore_pMissionList->pNext; p != dwCore_pMissionList; p = p->pNext)
            {
                dwMission* mm = (dwMission*)p->pData;
                if (mm->missionType == 0 && mm->rank == 0) { allDone = false; break; }
            }
            if (allDone)
            {
                dwGuiStatus_achieveFlags |= 1;
                this->sound.AssignCStr("Congrats_A.san");
                pVoice = "HMCA014L.wav";
                for (dwListNode* p = dwCore_pMissionList->pNext; p != dwCore_pMissionList; p = p->pNext)
                {
                    dwMission* mm = (dwMission*)p->pData;
                    if (mm->missionType == 1) { mm->bUnlocked = 1; mm->bDone = 0; }
                    if (mm->missionType == 3) { mm->bUnlocked = 1; mm->bDone = 0; }
                }
            }
        }
        else if (sr == 2 && m->missionType == 0 && (dwGuiStatus_achieveFlags & 2) == 0)
        {
            bool allDone = true;
            for (dwListNode* p = dwCore_pMissionList->pNext; p != dwCore_pMissionList; p = p->pNext)
            {
                dwMission* mm = (dwMission*)p->pData;
                if (mm->missionType == 0 && mm->rank != 3) { allDone = false; break; }
            }
            if (allDone)
            {
                dwGuiStatus_achieveFlags |= 2;
                this->sound.AssignCStr("Congrats_B.san");
                pVoice = "HMCA017.wav";
            }
        }
        else if (sr == 0)
        {
            if (m->missionType == 1 && (dwGuiStatus_achieveFlags & 4) == 0)
            {
                this->rankImageIdx = 4;
                bool allDone = true;
                for (dwListNode* p = dwCore_pMissionList->pNext; p != dwCore_pMissionList; p = p->pNext)
                {
                    dwMission* mm = (dwMission*)p->pData;
                    if (mm->missionType == 1 && mm->rank == 0) { allDone = false; break; }
                }
                if (allDone)
                {
                    dwGuiStatus_achieveFlags |= 4;
                    pVoice = "HMCA022L.wav";
                    for (dwListNode* p = dwCore_pMissionList->pNext; p != dwCore_pMissionList; p = p->pNext)
                    {
                        dwMission* mm = (dwMission*)p->pData;
                        if (mm->missionType == 3) { mm->bUnlocked = 1; mm->bDone = 0; dwCore_pCurrentMission = mm; }
                    }
                }
            }
            else if (m->missionType == 3 && (dwGuiStatus_achieveFlags & 8) == 0)
            {
                this->rankImageIdx = 5;
                dwGuiStatus_achieveFlags |= 8;
                this->sound.AssignCStr("data.san");
                pVoice = "HMCA024.wav";
                for (dwListNode* p = dwCore_pMissionList->pNext; p != dwCore_pMissionList; p = p->pNext)
                {
                    dwMission* mm = (dwMission*)p->pData;
                    if (mm->missionType == 2) { mm->bUnlocked = 1; mm->bDone = 0; dwCore_pCurrentMission = mm; }
                }
            }
        }

        this->speech.AssignCStr(pVoice);
        if (pVoice != NULL)
            dwSound_PlayRestart(pVoice);

        m->rank = this->savedRank; // restore for display
    }

    if (this->rankImageIdx != 0)
        this->pRankImage = dwImage_LoadFile((char*)dwGuiStatus_rankImages[this->rankImageIdx]);
}

// Note: no binary counterpart — resets the achievement bitmask for the
// soft-reset loop.
extern "C" void dwGuiStatus_Startup(void)
{
    dwGuiStatus_achieveFlags = 0;
}

// Added: C-callable factory (see dwGuiStatus.h). Upcasts through the MI
// hierarchy to the dwSegment subobject. OWNS the former dwMain.c placeholder.
extern "C" dwSegment* dwGuiStatus_New(dwMission* pMission, float itemPct, float healthPct, int chargeMax)
{
    return static_cast<dwSegment*>(new dwGuiStatus(pMission, itemPct, healthPct, chargeMax));
}
