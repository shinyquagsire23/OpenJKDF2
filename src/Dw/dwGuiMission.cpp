// dwGuiMission — mission-select MAP/briefing screen cluster: dwGuiDialog (+
// the game-wide modal runner dwGuiDialog_RunModal), dwGuiBriefText,
// dwGuiObjectiveBtn, dwGuiBriefTextElem, dwGuiBriefLine, dwGuiMissionMap and
// the dwMissionTransIn/Out panel slides — plus the dwGuiRefRadioGroup/
// dwGuiRefRadioButton pair (owner dwGuiReference P6; landed here early, see
// the ownership note in Dw/dwGuiMission.h).
//
// Decompiled from DroidWorks.exe unit range 0x41c0f0-0x41f16f (the unit's
// dwMission_* record functions and dwMissionSequence live in dwMission.cpp;
// the radio pair is 0x42a540-0x42a87f). Per-function @addresses below.
//
// Translation notes:
//  - The screens' dwSegment-slot bodies (Activate/Deactivate) take the
//    SUBOBJECT this (obj+0x10) in the binary; field offsets there are
//    obj-relative minus 0x10 (e.g. OnActivate's radio group at seg+0xc0 =
//    obj+0xd0). All offsets in the comments below are OBJECT-relative.
//  - dwSound calls go through the C shims (manager NULL-guarded) or the
//    guarded manager methods where no shim exists (GetOrLoadSample /
//    FreeAllSamples) — the manager doesn't exist until the P7 boot flow.
//  - dwSoundSample::pFinishMsg carries the finish message CODE (the binary
//    stores the int 0xC1D in the pointer slot and dwSound_Update builds
//    { code, pSample, 0, NULL } from it — see the report note; dwSound.cpp's
//    current dispatch-as-pointer translation predates this discovery).
//  - The binary's __ftol truncates; the reveal radii are computed as
//    value + 0.5 (FSUB of a -0.5 double) before truncation = round-half-up.
//    Mirrored with double math + C casts (dwGuiHypText.cpp precedent).
//
// Module statics: none owned here (dwCore_pCurrentMission is dw-core P7
// state; the icon/wobble tables are const) — dwGuiMission_Startup is empty.

#include "Dw/dwGuiMission.h"

#include "Dw/dwGuiButton.h"    // dwGuiZoomBox
#include "Dw/dwControlPanel.h" // dwControlPanelHelpRect (MAP keyword)
#include "Dw/dwPart.h"         // dwPart_FindBlueprint (PARTTEXT keyword)
#include "Dw/dwGuiHypText.h"   // dwGuiPartText + stock format callbacks
#include "Dw/dwImage.h"        // dwImage_LoadFile
#include "Dw/dwImageDraw.h"    // dwImageDraw_ShadeRect
#include "Dw/dwDisplay.h"      // dwDisplay_pScreenImage/AddDirtyRect
#include "Dw/dwCursor.h"       // dwCursor_SetCursor/dwCursor_curIdx
#include "Dw/dwSound.h"        // dwSound_* C shims + dwSound_pManager methods
#include "Dw/dwColormap.h"     // dwColormap_transparentIdx/whiteIdx
#include "Dw/dwConfFile.h"     // conf parsing
#include "Dw/dwSegment.h"      // segment manager (overlay/push/advance)
#include "Dw/dwStringTable.h"  // dwStringTable (localize)

#include "jk.h"
#include "stdPlatform.h" // stdPlatform_Printf

#include <math.h>   // sqrt (binary: FSQRT)
#include <string.h> // memcpy (desktop-only unit; the reveal row copy)

// These engine headers have no extern "C" guards of their own — wrap at include site.
extern "C" {
#include "Win95/stdDisplay.h" // stdDisplay_pCurVideoMode (binary 0x6478f8)
}

// ---- cross-unit externs (TODO(dw-decomp): provided by other units) ----------

// The mission dwGuiInGame factory + droid validation.
// TODO(dw-decomp): provided by dwGuiInGame (P6 wave 2). Binary: BeginDeploy
// news the 0x284 screen via dwGuiInGame_Ctor@41f2a0(pMission) and pushes its
// dwSegment subobject (obj+0x10) — the factory returns that segment;
// dwGuiInGame_CheckDroidValid @41f6f0. Until that unit lands the orchestrator
// keeps `return NULL;` / `return 0;` placeholders in dwMain.c.
extern "C" dwSegment* dwGuiInGame_New(dwMission* pMission);
extern "C" int dwGuiInGame_CheckDroidValid(void);

// 8bpp screen-sized image copy (the dialog's shaded-snapshot background).
// Currently a loud P8 stub returning NULL, defined in dwAnim.cpp.
// TODO(dw-decomp): provided by the stdBitmapRle2 engine-side unit (P8).
extern "C" dwImage* stdBitmapRle2_InstantiateCopy(dwImage* pSrc, int16_t width, int16_t height); // @442ec0

// ---- const tables ------------------------------------------------------------

// dwGuiObjectiveBtn NORMAL-mission marker icon by earned rank (binary string
// table @0x51ef88, indexed by dwMission::rank 0-3: unranked / Scavenger /
// Apprentice / Master).
static const char* dwGuiObjectiveBtn_aRankIcons[4] = {
    "mbmission.rle",       // 0x5284cc
    "MScavenger_Icon.rle", // 0x5284b8
    "MApprentice_Icon.rle",// 0x5284a0
    "MMaster_Icon.rle",    // 0x52848c
};

// dwGuiBriefText reveal-circle edge wobble (binary int16 table @0x51ef20,
// cycled per scanline: radius - {0, 4, 8, 4}).
static const int16_t dwGuiBriefText_aWobble[4] = { 0, 4, 8, 4 };

// ---- module init ---------------------------------------------------------------

// Note: no binary counterpart — the unit owns no module statics; kept for the
// soft-reset convention. @-
extern "C" void dwGuiMission_Startup(void)
{
}

// ---- local helpers -------------------------------------------------------------

// Find pWidget's node in pList and unlink+free it (widget kept). Mirrors the
// binary's inline sentinel walks (same helper pattern as dwGuiScreen.cpp).
static void dwGuiMission_UnlinkWidgetNode(dwList* pList, void* pWidget)
{
    dwListNode* pNode;

    for (pNode = pList->pSentinel->pNext; pNode != pList->pSentinel; pNode = pNode->pNext)
    {
        if (pNode->pData == pWidget)
        {
            pList->UnlinkFreeNode(pNode);
            return;
        }
    }
}

// Capture the current screen into a new image and darken it to 60% — the
// dialog's dimmed backdrop. The binary inlines this in dwGuiDialog_Ctor
// (@41c260-41c315); it is byte-for-byte the dwGuiScreen 0x66/0x68 snapshot
// (see dwGuiScreen_CaptureShadedScreen — static there, replicated verbatim).
// The screen-image NULL guard is added (the binary assumes an open display).
static dwImage* dwGuiMission_CaptureShadedScreen()
{
    dwImage* pSnap;
    dwRect rect;
    dwImageBits bits;
    void* pPixels;
    int stride;

    if (!stdDisplay_pCurVideoMode || !dwDisplay_pScreenImage) // Note: guard added
        return NULL;

    rect.left = 0;
    rect.top = 0;
    rect.right = (int16_t)stdDisplay_pCurVideoMode->format.width;
    rect.bottom = (int16_t)stdDisplay_pCurVideoMode->format.height;

    // Note: binary @0x442ec0 ctor takes (pSrcImage, pRect) with rect always
    // {0,0,w,h}; the P8 placeholder signature takes width/height directly.
    pSnap = stdBitmapRle2_InstantiateCopy((dwImage*)dwDisplay_pScreenImage, rect.right, rect.bottom);
    if (pSnap)
    {
        pPixels = NULL;
        stride = 0;
        pSnap->Lock(&pPixels, &stride); // vtbl +0x0c
        bits.pDesc = &pSnap->desc;      // binary: obj-as-desc alias
        bits.pPixels = pPixels;
        bits.stride = stride;
        dwImageDraw_ShadeRect(&bits, &rect, 0x3c); // 60%
        pSnap->Unlock(); // vtbl +0x10
    }
    return pSnap;
}

// Shared stub reporter for not-yet-translated control classes (dwGuiScreen.cpp
// pattern).
static dwWidget* dwGuiMission_StubControl(const char* pKeyword, const char* pClass, const char* pUnit)
{
    stdPlatform_Printf("TODO(dw-decomp): dwGuiMissionMap control '%s' -> %s (unit %s) not translated yet\n",
                       pKeyword, pClass, pUnit);
    return NULL;
}

// ===========================================================================
// dwGuiRefRadioGroup / dwGuiRefRadioButton (owner dwGuiReference P6)
// ===========================================================================

// @42a540 (dwGuiRefRadioGroup_Ctor)
dwGuiRefRadioGroup::dwGuiRefRadioGroup(dwRect* pRect)
    : dwWidgetGroup(pRect)
    , pSelected(NULL)
{
}

// @42a580 (dwGuiRefRadioGroup_Dtor; scalar-deleting wrapper @42a560) — the
// binary body is the re-inlined dwWidgetGroup dtor (FreeChildImages + delete
// children + free list); all of that runs in the base dtor here.
dwGuiRefRadioGroup::~dwGuiRefRadioGroup()
{
}

// @42a6a0 (dwGuiRefRadioGroup_AddButton) — quirk preserved: the FIRST button
// is Select()ed BEFORE it is inserted.
void dwGuiRefRadioGroup::AddButton(dwGuiRefRadioButton* pBtn)
{
    if (pBtn == NULL)
        return;
    if (this->children.pSentinel == this->children.pSentinel->pNext) // empty
        pBtn->Select();
    this->children.InsertAfter(this->children.pSentinel->pPrev, pBtn);
}

// @42a770 (dwGuiRefRadioGroup_SetSelected)
void dwGuiRefRadioGroup::SetSelected(dwGuiRefRadioButton* pBtn)
{
    if (pBtn != NULL && this->pSelected != pBtn && this->pSelected != NULL)
        this->pSelected->Deselect();
    this->pSelected = pBtn;
}

// @42a7a0 (dwGuiRefRadioButton_Ctor)
dwGuiRefRadioButton::dwGuiRefRadioButton(dwGuiRefRadioGroup* pGroup, dwRect* pRect,
                                         char* pImgNormal, char* pSndOff, char* pImgPressed,
                                         char* pSndClick, int cmdId)
    : dwWorkshopCtrl(pRect, pImgNormal, pSndOff, pImgPressed, pSndClick, cmdId, /*bToggle*/1)
    , pGroup(pGroup)
{
}

// @42a800 (dwGuiRefRadioButton_Dtor; scalar-deleting wrapper @42a7e0)
dwGuiRefRadioButton::~dwGuiRefRadioButton()
{
}

// vtbl +0x08 @42a810
int dwGuiRefRadioButton::OnMouseDown(int16_t x, int16_t y)
{
    int ret;

    if (this->bHot != 0) // already the selection — ignore
        return 0;
    ret = dwWorkshopCtrl::OnMouseDown(x, y);
    if (this->bHot != 0)
        this->pGroup->SetSelected(this);
    return ret;
}

// @42a860 (dwGuiRefRadioButton_Select)
void dwGuiRefRadioButton::Select()
{
    if (this->bHot == 0)
    {
        this->bPressed = 0;
        this->bHot = 1;
        this->pGroup->SetSelected(this);
        this->Invalidate(); // vtbl +0x34
    }
}

// @42a850 (dwGuiRefRadioButton_Deselect)
void dwGuiRefRadioButton::Deselect()
{
    this->bPressed = 0;
    this->bHot = 0;
    this->Invalidate(); // vtbl +0x34
}

// ===========================================================================
// dwGuiDialog + dwGuiDialog_RunModal
// ===========================================================================

// @41c200 (dwGuiDialog_Ctor)
dwGuiDialog::dwGuiDialog(const char* pConfName, const char* pMsgKey, int* pResult)
    : dwGuiScreen(pConfName, NULL)
    , msgKey(pMsgKey, 0)
    , pResult(pResult)
{
    // Background = 60%-shaded copy of the live screen (binary inlines the
    // capture; dialog stores it straight into the base pBgImage @0x48).
    this->pBgImage = dwGuiMission_CaptureShadedScreen();
}

// @41c350 (dwGuiDialog_Dtor; scalar-deleting wrapper @41c330) — msgKey free
// (member dtor) + base dtor.
dwGuiDialog::~dwGuiDialog()
{
}

// vtbl +0x1c @41c4d0 (dwGuiDialog_OnMessage)
int dwGuiDialog::OnMessage(dwWidgetMsg* pMsg)
{
    if (pMsg->code != 5000 && pMsg->code != 0x1389) // 5000 YES / 5001 NO
        return dwGuiScreen::OnMessage(pMsg);
    *this->pResult = pMsg->code;
    return 1;
}

// vtbl +0x48 @41c3a0 (dwGuiDialog_CreateControl)
dwWidget* dwGuiDialog::CreateControl(char* pKeyword, dwConfFile* pConf)
{
    dwRect rect;
    char* pFontName;
    uint32_t color;
    char* pText;
    dwGuiHypText* pTextCtrl;

    if (dwString_Equals(pKeyword, "DLG_TEXT"))
    {
        rect.left = 0;
        rect.top = 0;
        rect.right = 0;
        rect.bottom = 0;
        dwConfFile_ParseRect(pConf, &rect);
        pFontName = dwConfFile_NextToken(pConf);
        color = 0;
        dwConfFile_ParseULong(pConf, &color);
        pText = dwGuiScreen_LocalizeString(this->msgKey.pBuffer, this->pStringTable);
        pTextCtrl = new dwGuiHypText(&rect, NULL, pFontName, (uint8_t)color,
                                     dwGuiHypText_HAlignLeft, dwGuiHypText_VAlignTop,
                                     dwGuiHypText_WrapWords, dwGuiHypText_DrawGlyphsNormal,
                                     NULL); // @438540 (dwGuiHypText_CtorEx)
        pTextCtrl->text.Free();
        pTextCtrl->SetText(pText); // vtbl +0x48 (SetText APPENDS — hence the Free)
        return pTextCtrl;
    }
    return dwGuiScreen::CreateControl(pKeyword, pConf); // @430a10
}

// @41c0f0 (dwGuiDialog_RunModal) — THE modal message-box runner.
extern "C" int dwGuiDialog_RunModal(const char* pConfName, const char* pMsgKey)
{
    int result;
    int savedCursor;
    dwGuiDialog* pDlg;
    dwWidget* pPrevTarget;
    dwWidgetMsg msg;

    result = 0;
    msg.code = 0x7532; // "screen switching" broadcast
    msg.pSender = NULL;
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);

    savedCursor = dwCursor_curIdx;
    pDlg = new dwGuiDialog(pConfName, pMsgKey, &result);
    pPrevTarget = dwWidget_pMouseTarget;
    if (pDlg != NULL)
    {
        dwWidget_pMouseTarget = pDlg;
        dwCursor_SetCursor(1);
        dwSound_PlayRestart("CError.wav");
        dwSegment_BeginOverlay(static_cast<dwSegment*>(pDlg));

        // Binary: `while (result == 0 && dwSegment_bRunning) Window_sub_507090();`
        // where 507090 drains the Win32 message queue or, when idle, runs
        // dwMain_MainLoopTick() (= dwSegment_Tick + window teardown). Here one
        // dwSegment_Tick per iteration mirrors that idle path — it updates
        // the overlay (this dialog) and returns the same app-running flag
        // (armed by StartOpeningCutscenes, P7; pre-P7 it is 0 so the loop
        // exits immediately with result 0 — callers treat != 5000 as NO).
        // TODO(dw-decomp): P7 dwMain owner — route one host event-pump
        // iteration through here so input reaches the dialog.
        while (result == 0 && dwSegment_Tick())
        {
        }

        dwSegment_EndOverlay();
        delete pDlg; // virtual scalar-deleting dtor (vtbl +0x00)
        dwWidget_pMouseTarget = pPrevTarget;
    }
    dwCursor_SetCursor(savedCursor);
    return result;
}

// ===========================================================================
// dwGuiBriefText
// ===========================================================================

// @41c9e0 (dwGuiBriefText_Ctor)
dwGuiBriefText::dwGuiBriefText(dwRect* pRect, dwPoint* pAnchor, const char* pConfName, int msgCode)
    : dwAnimBase(pRect, msgCode, /*bLoop*/0)
{
    dwConfFile conf;
    char* pTok;
    float timeSec;
    dwGuiBriefTextLine* pLine;
    int16_t dx, dy, tmp;

    this->state = 0;
    this->anchorX = pAnchor->x; // binary: one 4-byte copy of both shorts
    this->anchorY = pAnchor->y;
    // Note: the binary leaves revealPos/revealMax/revealElapsedSec/lineTimeSec
    // uninitialized until the parse/Play below; zero-initialized here.
    this->revealPos = 0;
    this->revealMax = 0;
    this->revealElapsedSec = 0.0f;
    this->lineTimeSec = 0.0f;
    this->bSoundPending = 1;
    // soundName default-ctor'd; `lines` ctor allocates the sentinel (the
    // binary inlines the same 0xc alloc + self-link)
    this->pCurLineNode = NULL;
    this->pCurImage = NULL;

    dwConfFile_Open(&conf, pConfName);

    // Line 1: the VO wav name (precached).
    dwConfFile_ReadLine(&conf);
    pTok = dwConfFile_NextToken(&conf);
    if (pTok != NULL && *pTok != '\0')
    {
        this->soundName.AssignCStr(pTok);
        if (dwSound_pManager) // Note: guard added (manager exists from P7)
            dwSound_pManager->GetOrLoadSample(pTok);
    }

    // Every further line: "<float time> <image.rle>".
    dwConfFile_ReadLine(&conf);
    while (!conf.bEof)
    {
        timeSec = 0.0f;
        dwConfFile_ParseFloat(&conf, &timeSec);
        pTok = dwConfFile_NextToken(&conf);
        if (pTok != NULL && *pTok != '\0')
        {
            pLine = new dwGuiBriefTextLine(timeSec, pTok);
            this->lines.InsertAfter(this->lines.pSentinel->pPrev, pLine); // append
        }
        dwConfFile_ReadLine(&conf);
    }
    this->pCurLineNode = this->lines.pSentinel;

    // revealMax = round(distance from the anchor to the farthest widget corner).
    dx = (int16_t)(this->right - this->anchorX);
    tmp = (int16_t)(this->anchorX - this->left);
    if (tmp < dx)
        tmp = dx;
    dx = tmp;
    dy = (int16_t)(this->bottom - this->anchorY);
    tmp = (int16_t)(this->anchorY - this->top);
    if (tmp < dy)
        tmp = dy;
    dy = tmp;
    this->revealMax = (int16_t)(sqrt((double)(dx * dx + dy * dy)) + 0.5); // round-half-up (binary FSUB -0.5 + __ftol)

    dwConfFile_Close(&conf);
}

// @41cc20 (dwGuiBriefText_Dtor; scalar-deleting wrapper @41cc00)
dwGuiBriefText::~dwGuiBriefText()
{
    dwListNode* pNode;
    dwListNode* pNext;
    dwGuiBriefTextLine* pLine;

    if (this->state == 1)
        this->state = 2;
    this->Stop();          // @41d000, called directly (not through the vtable)
    dwAnimBase::Play();    // faithful binary quirk: bPlaying = 1 + Invalidate
    if (this->soundName.pBuffer != NULL) // Note: guard added (empty conf -> NULL name)
        dwSound_Stop(this->soundName.pBuffer);
    if (this->pCurImage != NULL)
    {
        delete this->pCurImage; // virtual DtorDelete (vtbl +0x00)
        this->pCurImage = NULL;
    }
    // Free every line record + its node, then the sentinel (binary: inline
    // unlink/free loop + a second node sweep + sentinel free — dwList::Free).
    for (pNode = this->lines.pSentinel->pNext; pNode != this->lines.pSentinel; pNode = pNext)
    {
        pNext = pNode->pNext;
        pLine = (dwGuiBriefTextLine*)pNode->pData;
        this->lines.UnlinkFreeNode(pNode);
        if (pLine != NULL)
            delete pLine; // dwString member dtor frees the name
    }
    this->lines.Free();
    // soundName freed by the member dtor; dwAnimBase/dwWidget dtors implicit.
}

// vtbl +0x10 @41d050 (dwGuiBriefText_OnKey)
int dwGuiBriefText::OnKey(int key, int repeat)
{
    (void)repeat;
    if (key == 0x1b) // ESC
        this->Stop(); // binary: virtual +0x4c
    return 0;
}

// vtbl +0x1c @41d070 (dwGuiBriefText_OnMessage)
int dwGuiBriefText::OnMessage(dwWidgetMsg* pMsg)
{
    if (pMsg->code == 0xC1D) // VO sample finished
        this->Stop(); // binary: virtual +0x4c
    return dwAnimBase::OnMessage(pMsg); // msgCode toggle (Play/Stop)
}

// vtbl +0x14 @41cd80 (dwGuiBriefText_Update)
void dwGuiBriefText::Update(float dt)
{
    dwSoundSample* pSample;
    dwGuiBriefTextLine* pLine;
    dwRect r;

    // Kick the VO off on the first playing tick; its end broadcasts 0xC1D.
    if (this->bSoundPending != 0 && this->state == 1)
    {
        pSample = dwSound_PlayRestart(this->soundName.pBuffer);
        if (pSample != NULL)
        {
            // Finish message CODE stored in the pointer slot (binary
            // semantics; see the pFinishMsg note in the file header).
            pSample->pFinishMsg = (void*)(intptr_t)0xC1D;
        }
        this->bSoundPending = 0;
        dt = 0.0f;
    }

    if (this->state == 1) // circle growing
    {
        this->revealElapsedSec += dt;
        if (this->revealElapsedSec < 1.0f)
        {
            this->revealPos = (int16_t)((double)this->revealMax * this->revealElapsedSec + 0.5);
            r.left = (int16_t)(this->anchorX - this->revealPos);
            r.top = (int16_t)(this->anchorY - this->revealPos);
            r.right = (int16_t)(this->anchorX + this->revealPos);
            r.bottom = (int16_t)(this->anchorY + this->revealPos);
            dwDisplay_AddDirtyRect(&r);
        }
        else
        {
            this->state = 2; // fully revealed
            this->Invalidate(); // vtbl +0x34
        }
    }
    else if (this->state == 3) // collapsing
    {
        this->revealElapsedSec += dt;
        if (this->revealElapsedSec >= 1.0f || this->revealPos == 0)
        {
            this->state = 0;
            dwAnimBase::Stop(); // base: bPlaying = 0 + { 0x2328, msgCode } broadcast
            if (this->pCurImage != NULL)
                delete this->pCurImage;
            this->pCurImage = NULL;
        }
        else
        {
            r.left = (int16_t)(this->anchorX - this->revealPos);
            r.top = (int16_t)(this->anchorY - this->revealPos);
            r.right = (int16_t)(this->anchorX + this->revealPos);
            r.bottom = (int16_t)(this->anchorY + this->revealPos);
            dwDisplay_AddDirtyRect(&r);
            this->revealPos = (int16_t)(this->revealMax
                            - (int16_t)((double)this->revealMax * this->revealElapsedSec + 0.5));
        }
    }

    // Timed caption-line image switching (runs in every state).
    this->lineTimeSec += dt;
    if (this->pCurLineNode != this->lines.pSentinel)
    {
        pLine = (dwGuiBriefTextLine*)this->pCurLineNode->pData;
        if (pLine->timeSec <= this->lineTimeSec)
        {
            if (this->pCurImage != NULL)
                delete this->pCurImage;
            this->pCurImage = dwImage_LoadFile(pLine->imageName.pBuffer);
            this->pCurLineNode = this->pCurLineNode->pNext;
            this->Invalidate(); // vtbl +0x34
        }
    }
}

// vtbl +0x48 @41cf80 (dwGuiBriefText_Play)
void dwGuiBriefText::Play()
{
    dwGuiBriefTextLine* pLine;

    this->revealPos = 0;
    this->revealElapsedSec = 0.0f;
    this->state = 1;
    this->lineTimeSec = 0.0f;
    this->pCurLineNode = this->lines.pSentinel->pNext;
    if (this->lines.pSentinel != this->lines.pSentinel->pNext) // any lines?
    {
        if (this->pCurImage != NULL)
            delete this->pCurImage;
        pLine = (dwGuiBriefTextLine*)this->pCurLineNode->pData;
        this->pCurImage = dwImage_LoadFile(pLine->imageName.pBuffer);
        this->pCurLineNode = this->pCurLineNode->pNext;
        this->Invalidate(); // vtbl +0x34
    }
    if (dwSound_pManager && this->soundName.pBuffer) // Note: guards added
        dwSound_pManager->GetOrLoadSample(this->soundName.pBuffer);
    this->bSoundPending = 1;
    dwAnimBase::Play();
}

// vtbl +0x4c @41d000 (dwGuiBriefText_Stop)
void dwGuiBriefText::Stop()
{
    if (this->state != 3)
    {
        this->revealElapsedSec = 1.0f - this->revealElapsedSec; // mirror the clock
        this->state = 3;
        if (this->soundName.pBuffer != NULL) // Note: guard added
        {
            // Fade the VO to silence over the mirrored remainder.
            dwSound_SetSampleVolume(this->soundName.pBuffer, 0.0f, 1.0f - this->revealElapsedSec);
        }
    }
}

// vtbl +0x44 @41d0a0 (dwGuiBriefText_Draw)
void dwGuiBriefText::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    dwImage* pImg;
    dwRect rect;
    void* pPixels;
    int srcStride;
    uint8_t* pDstRow;
    uint8_t* pSrcRow;
    int radiusSq;
    int wobble;
    int16_t y, dy, halfW, x0, x1, len;

    pImg = this->pCurImage;
    if (pImg == NULL || this->state == 0)
        return;

    if (this->state == 2) // fully revealed: plain blit at the widget origin
    {
        pImg->Blit(pDestBits, this->left, this->top, pClipRect); // vtbl +0x04
        return;
    }

    // States 1/3: copy the caption rows through the wobbled reveal circle.
    pPixels = NULL;
    srcStride = 0;
    pImg->Lock(&pPixels, &srcStride); // vtbl +0x0c

    rect.left = (int16_t)(this->anchorX - this->revealPos);
    rect.top = (int16_t)(this->anchorY - this->revealPos);
    rect.right = (int16_t)(this->anchorX + this->revealPos);
    rect.bottom = (int16_t)(this->anchorY + this->revealPos);
    dwRect_Clip(&rect, pClipRect);

    pDstRow = (uint8_t*)pDestBits->pPixels + rect.top * pDestBits->stride;
    pSrcRow = (uint8_t*)pPixels + (rect.top - this->top) * srcStride;
    radiusSq = (int)this->revealPos * (int)this->revealPos;
    wobble = 0;

    for (y = rect.top; y < rect.bottom; y++)
    {
        dy = (int16_t)(this->anchorY - y);
        if (dy < 0)
            dy = (int16_t)-dy;
        // Ragged edge: round-half-up chord half-width minus the wobble cycle.
        halfW = (int16_t)(sqrt((double)(radiusSq - (int)dy * (int)dy)) + 0.5);
        halfW = (int16_t)(halfW - dwGuiBriefText_aWobble[wobble & 3]);
        wobble++;

        x0 = (int16_t)(this->anchorX - halfW);
        x1 = (int16_t)(this->anchorX + halfW);
        if (x0 < rect.left)
            x0 = rect.left;
        if (x1 >= rect.right)
            x1 = (int16_t)(rect.right - 1);
        len = (int16_t)(x1 - x0);
        if (len > 0)
            memcpy(pDstRow + x0, pSrcRow + (x0 - this->left), (size_t)len);

        pDstRow += pDestBits->stride;
        pSrcRow += srcStride;
    }

    pImg->Unlock(); // vtbl +0x10
}

// ===========================================================================
// dwGuiObjectiveBtn
// ===========================================================================

// @41d390 (dwGuiObjectiveBtn_Ctor)
dwGuiObjectiveBtn::dwGuiObjectiveBtn(dwGuiRefRadioGroup* pGroup, dwRect* pRect, dwMission* pMission)
    : dwGuiRefRadioButton(pGroup, pRect, NULL, NULL, NULL, NULL, /*cmdId*/0x791f)
    , pMission(pMission)
    , pFont(NULL)
{
    dwGuiObjectiveBtn::EnsureImages(); // binary calls LoadImage directly
    this->pFont = new dwFont;
    dwFont_Load(this->pFont, "Arial14BA");
    this->sndClick.Assign("WMissionLocate.wav", 0x12);
}

// @41d460 (dwGuiObjectiveBtn_Dtor; scalar-deleting wrapper @41d440)
dwGuiObjectiveBtn::~dwGuiObjectiveBtn()
{
    dwGuiObjectiveBtn::FreeImages(); // binary calls FreeImage directly
    if (this->pFont != NULL)
    {
        // (binary: an ICF'd empty COMDAT call, then the heap free — the
        // font's cached block belongs to dwFont_pCache, only the handle dies)
        delete this->pFont;
        this->pFont = NULL;
    }
}

// vtbl +0x04 @41d650 (undetected fn, recovered from the vtable @0x51ef98)
int dwGuiObjectiveBtn::OnMouseMove(int16_t x, int16_t y)
{
    dwWidgetMsg msg;

    if (!this->HitTest(x, y)) // virtual +0x48 (dwWorkshopCtrl rect test)
        return 0;
    msg.code = 0xBBB; // mission hover
    msg.pSender = this->pMission;
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);
    return 1;
}

// vtbl +0x08 @41d6a0 (undetected fn, recovered from the vtable @0x51ef98)
int dwGuiObjectiveBtn::OnMouseDown(int16_t x, int16_t y)
{
    dwWidgetMsg msg;
    int ret;

    ret = dwGuiRefRadioButton::OnMouseDown(x, y);
    if (ret != 0)
    {
        msg.code = 0xBBC; // mission selected
        msg.pSender = this->pMission;
        msg.param = 0;
        msg.pTarget = NULL;
        dwWidget_DispatchMsg(&msg, NULL);
    }
    return ret;
}

// vtbl +0x3c @41d6f0 (Ghidra: dwGuiObjectiveBtn_LoadImage — the EnsureImages slot)
void dwGuiObjectiveBtn::EnsureImages()
{
    dwImage* pImg;

    if (this->pImageNormal != NULL)
        return;
    pImg = NULL;
    switch (this->pMission->missionType)
    {
    case DW_MISSION_NORMAL:
        // Rank-indexed marker (binary indexes the 4-entry table UNCLAMPED —
        // rank is 0-3 by construction).
        pImg = dwImage_LoadFile((char*)dwGuiObjectiveBtn_aRankIcons[this->pMission->rank]);
        break;
    case DW_MISSION_SECRET:
        pImg = dwImage_LoadFile((char*)(this->pMission->rank != 0 ? "MCrystal_Icon.rle"
                                                                  : "MSecretIcon.rle"));
        break;
    case DW_MISSION_FINAL:
        pImg = dwImage_LoadFile((char*)"MScroll_Icon.rle");
        break;
    case DW_MISSION_CRYSTAL:
        pImg = dwImage_LoadFile((char*)(this->pMission->rank != 0 ? "MDataDiskIcon.rle"
                                                                  : "MSecretIcon.rle"));
        break;
    default: // TGROUND/DEPLOYMENT: no marker image
        pImg = this->pImageNormal; // (= NULL; matches the binary's default path)
        break;
    }
    // ONE image aliased into both base slots (FreeImages deletes it once).
    this->pImageNormal = pImg;
    this->pImagePressed = pImg;
}

// vtbl +0x40 @41d7c0 (Ghidra: dwGuiObjectiveBtn_FreeImage — the FreeImages slot)
void dwGuiObjectiveBtn::FreeImages()
{
    if (this->pImagePressed != NULL)
    {
        delete this->pImagePressed; // single delete of the aliased image
        this->pImagePressed = NULL;
        this->pImageNormal = NULL;
    }
}

// vtbl +0x44 @41d4d0 (dwGuiObjectiveBtn_Draw)
void dwGuiObjectiveBtn::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    char* pText;
    dwPoint pos, pos2;
    char ch;
    int w;
    uint32_t i;

    dwWorkshopCtrl::Draw(pDestBits, pClipRect); // @407580 (marker image)

    if (this->pFont == NULL || this->pFont->pHeader == NULL) // Note: pHeader guard added (font load can fail)
        return;
    pText = this->pMission->displayName.pBuffer;
    if (pText == NULL) // Note: guard added (mission without a NAME line)
        return;

    pos.x = this->left;
    pos.y = this->top;
    if (pText[0] == '#')
    {
        // "#X": draw only glyph X, centered in the marker — and only until
        // the mission has an earned rank.
        if (this->pMission->rank != 0)
            return;
        ch = pText[1];
        w = dwFont_GetCharWidth(this->pFont, ch);
        pos.x = (int16_t)(this->left + ((this->right - this->left) / 2 - w / 2));
        pos.y = (int16_t)(pos.y + ((this->bottom - this->top) / 2
                                   - (int)this->pFont->pHeader->lineHeight / 2)
                                + (int)this->pFont->pHeader->bpp);
        dwFont_DrawGlyph(this->pFont, pDestBits, &pos, ch, (uint8_t)dwColormap_transparentIdx);
    }
    else
    {
        // Shadowed mission name along the marker's bottom edge.
        pos.y = (int16_t)(this->bottom - (int16_t)this->pFont->pHeader->lineHeight
                          + 6 + (int16_t)this->pFont->pHeader->bpp);
        pos2.x = (int16_t)(pos.x + 2);
        pos2.y = (int16_t)(pos.y + 2);
        for (i = 0; i < this->pMission->displayName.length; i++, pText++)
        {
            dwFont_DrawGlyph(this->pFont, pDestBits, &pos2, *pText, (uint8_t)dwColormap_transparentIdx);
            dwFont_DrawGlyph(this->pFont, pDestBits, &pos, *pText, (uint8_t)dwColormap_whiteIdx);
        }
    }
}

// ===========================================================================
// dwGuiBriefTextElem
// ===========================================================================

// @41d7e0 (dwGuiBriefTextElem_Ctor)
dwGuiBriefTextElem::dwGuiBriefTextElem(float revealDuration)
    : dwGuiHypText_ElemT(revealDuration)
{
}

// @41d820 (dwGuiBriefTextElem_Dtor; scalar-deleting wrapper @41d800; the
// base-dtor COMDATs @41d880/@41db00 are the compiler's dwGuiHypTextElem
// base-dtor pair) — silence the typewriter tick instantly.
dwGuiBriefTextElem::~dwGuiBriefTextElem()
{
    dwSound_SetSampleVolume("WTextAppear.wav", 0.0f, 0.0f);
}

// vtbl +0x04 @41d890 (undetected fn, recovered from the vtable @0x51efe8) —
// base typewriter reveal + loop "WTextAppear.wav" while it runs.
void dwGuiBriefTextElem::Update(dwGuiHypText* pOwner, float dt, dwGuiHypTextRun** ppRuns)
{
    dwGuiHypText_ElemT::Update(pOwner, dt, ppRuns);
    if (this->curReveal == (uint32_t)this->totalLen)
    {
        if (dwSound_IsPlaying("WTextAppear.wav"))
            dwSound_Stop("WTextAppear.wav");
    }
    else if (this->curReveal < (uint32_t)this->totalLen)
    {
        if (!dwSound_IsPlaying("WTextAppear.wav"))
            dwSound_PlayLooping("WTextAppear.wav");
    }
}

// ===========================================================================
// dwGuiBriefLine
// ===========================================================================

// @41d910 (dwGuiBriefLine_Ctor)
dwGuiBriefLine::dwGuiBriefLine(dwRect* pRect, void* pNotify, char* pFontName, uint8_t color,
                               char* pFormat, char* pModeText, dwMission* pMission)
    : dwGuiHypText(pRect, pNotify, pFontName, color, pFormat)
    , modeText(pModeText, 0)
{
    dwGuiBriefTextElem* pElem;
    char mode;

    if (pMission != NULL)
    {
        mode = (this->modeText.pBuffer != NULL) ? this->modeText.pBuffer[0] : 0; // Note: NULL guard added
        if (mode == 'N')
        {
            this->text.Free();
            this->SetText(pMission->displayName.pBuffer); // vtbl +0x48
        }
        else if (mode == 'B')
        {
            this->text.Free();
            this->SetText(pMission->briefing.pBuffer); // vtbl +0x48
            pElem = new dwGuiBriefTextElem(5.0f); // binary const @0x40a00000
            this->elements.InsertAfter(this->elements.pSentinel->pPrev, pElem); // append
        }
    }
}

// @41da40 (dwGuiBriefLine_Dtor; scalar-deleting wrapper @41da20)
dwGuiBriefLine::~dwGuiBriefLine()
{
    // modeText freed by the member dtor; base dtor implicit.
}

// vtbl +0x1c @41da90 (undetected fn, recovered from the vtable @0x51f008)
int dwGuiBriefLine::OnMessage(dwWidgetMsg* pMsg)
{
    dwMission* pMission;
    char mode;

    if (pMsg->code == 0xBBC && pMsg->pSender != NULL)
    {
        pMission = (dwMission*)pMsg->pSender;
        mode = (this->modeText.pBuffer != NULL) ? this->modeText.pBuffer[0] : 0; // Note: NULL guard added
        if (mode == 'N')
        {
            this->text.Free();
            this->SetText(pMission->displayName.pBuffer); // vtbl +0x48
        }
        else if (mode == 'B')
        {
            this->text.Free();
            this->SetText(pMission->briefing.pBuffer); // vtbl +0x48
        }
    }
    return 0;
}

// ===========================================================================
// dwGuiMissionMap
// ===========================================================================

// @41db20 (dwGuiMissionMap_Ctor)
dwGuiMissionMap::dwGuiMissionMap(dwImage* pBgImage)
    : dwGuiScreen("map", pBgImage) // binary string @0x528558
{
    this->mapRect.left = 0;
    this->mapRect.top = 0;
    this->mapRect.right = 0;
    this->mapRect.bottom = 0;
    this->pRadioGroup = NULL;
    this->pZoomBox = NULL;
    this->pMissionText = NULL;
    this->reserved_0xdc[0] = 0;
    this->reserved_0xdc[1] = 0;
    this->reserved_0xdc[2] = 0;
    this->reserved_0xdc[3] = 0;
    this->briefMode = 0xBEA;
    this->pBriefText = NULL;
    this->pJawaAnim = NULL;
    this->pBriefingBlink = NULL;
}

// @41dbd0 (dwGuiMissionMap_Dtor; scalar-deleting wrapper @41dbb0)
dwGuiMissionMap::~dwGuiMissionMap()
{
    dwGuiMissionMap::FreeImages(); // binary calls its own slot body directly
    // (the controls — radio group, zoom box, brief text, jawa anim, blink
    // button — are children of the base screen's `controls` group and die in
    // its dtor)
}

// scn vtbl +0x00 @41ddb0 (dwGuiMissionMap_OnActivate; binary this = obj+0x10)
int dwGuiMissionMap::Activate()
{
    dwListNode* pNode;
    dwMission* pMission;
    dwGuiObjectiveBtn* pBtn;
    dwRect r;
    dwWidgetMsg msg;
    int ret;

    ret = dwGuiScreen::Activate(); // @431b90 (lazy LoadControls etc.)
    if (ret)
    {
        // Rebuild the objective radio group from scratch.
        if (this->pRadioGroup != NULL)
        {
            dwGuiMission_UnlinkWidgetNode(&this->controls.children, this->pRadioGroup);
            delete this->pRadioGroup; // virtual DtorDelete (children buttons die too)
        }
        this->pRadioGroup = new dwGuiRefRadioGroup(&this->mapRect);
        this->controls.children.InsertAfter(this->controls.children.pSentinel->pPrev,
                                            this->pRadioGroup); // append

        // One marker per unlocked mission (40x40 box centered on mapPos).
        if (dwCore_pMissionList != NULL) // Note: guard added (list is a P7 placeholder)
        {
            for (pNode = dwCore_pMissionList->pNext; pNode != dwCore_pMissionList; pNode = pNode->pNext)
            {
                pMission = (dwMission*)pNode->pData;
                if (pMission->bUnlocked == 0)
                    continue;
                r.left = (int16_t)(pMission->mapPos.x - 0x14);
                r.top = (int16_t)(pMission->mapPos.y - 0x14);
                r.right = (int16_t)(pMission->mapPos.x + 0x14);
                r.bottom = (int16_t)(pMission->mapPos.y + 0x14);
                pBtn = new dwGuiObjectiveBtn(this->pRadioGroup, &r, pMission);
                this->pRadioGroup->AddButton(pBtn);
                dwMission_ClearObjectives(pMission);
                if (pMission == dwCore_pCurrentMission)
                    pBtn->Select();
            }
        }
    }

    // Broadcast the current selection (handlers all NULL-check the sender).
    msg.code = 0xBBC;
    msg.pSender = dwCore_pCurrentMission;
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);
    return ret;
}

// scn vtbl +0x04 @41dfd0 (dwGuiMissionMap_OnDeactivate; binary this = obj+0x10)
void dwGuiMissionMap::Deactivate()
{
    dwWidgetMsg msg;

    msg.code = 0x7532; // "screen switching"
    msg.pSender = NULL;
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);

    if (this->pBriefText != NULL)
    {
        this->pBriefText->Stop(); // virtual +0x4c
        dwGuiMission_UnlinkWidgetNode(&this->controls.children, this->pBriefText);
        delete this->pBriefText;
        this->pBriefText = NULL;
    }
    if (this->pJawaAnim != NULL)
        this->pJawaAnim->Stop(); // virtual +0x4c
    dwSound_Stop("WTextAppear.wav");
    dwGuiScreen::Deactivate(); // @431c30
}

// @41dc30 (dwGuiMissionMap_SelectObjective)
void dwGuiMissionMap::SelectObjective(dwMission* pMission)
{
    dwCore_pCurrentMission = pMission;

    // ⚠ pMissionText is never assigned anywhere in the binary — this block
    // is dead code there too; kept faithful.
    if (pMission != NULL && this->pMissionText != NULL)
    {
        this->pMissionText->text.Free();
        this->pMissionText->SetText(pMission->briefing.pBuffer); // vtbl +0x48
    }

    // Blink the BRIEFING button until this mission's briefing was viewed.
    // (binary quirk: pMission is dereferenced UNGUARDED here — the only call
    // site, OnMessage 0xBBC, guarantees a non-NULL sender)
    if (this->pBriefingBlink != NULL)
    {
        if (pMission->bDone == 0)
            this->pBriefingBlink->StartBlink(); // @405d90
        else
            this->pBriefingBlink->StopBlink(); // @405db0
    }

    if (this->pZoomBox == NULL)
        this->pZoomBox = new dwGuiZoomBox(&this->mapRect, 500.0f, 0x53); // @4081d0
    if (this->pZoomBox != NULL)
    {
        // Re-append the zoom box at the children tail (drawn on top).
        dwGuiMission_UnlinkWidgetNode(&this->controls.children, this->pZoomBox);
        this->controls.children.InsertAfter(this->controls.children.pSentinel->pPrev,
                                            this->pZoomBox);
        this->pZoomBox->Enable(); // virtual +0x20
        this->pZoomBox->SetTarget(&pMission->mapPos); // @408240
    }
}

// @41e0b0 (dwGuiMissionMap_BeginDeploy)
void dwGuiMissionMap::BeginDeploy()
{
    dwWidgetMsg msg;
    dwSegment* pMissionSeg;
    dwSegment* pDeploySeg;
    dwListNode* pNode;

    // Tear the briefing caption down first.
    if (this->pBriefText != NULL)
    {
        this->pBriefText->Stop(); // virtual +0x4c
        dwGuiMission_UnlinkWidgetNode(&this->controls.children, this->pBriefText);
        delete this->pBriefText;
        this->pBriefText = NULL;
    }

    // "briefing caption finished" broadcast (restores the radio/zoom controls).
    msg.code = 0x2328; // 9000
    msg.pSender = (void*)(intptr_t)0xC1C;
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);

    // Refuse to deploy until the briefing was viewed: hover-notify 0x7921
    // ("view the briefing first" help text).
    if (dwCore_pCurrentMission == NULL // Note: guard added (binary derefs unguarded)
        || dwCore_pCurrentMission->bDone == 0)
    {
        msg.code = 0x7531;
        msg.pSender = (void*)(intptr_t)0x7921;
        msg.param = 0;
        msg.pTarget = NULL;
        dwWidget_DispatchMsg(&msg, NULL);
        return;
    }

    if (!dwGuiInGame_CheckDroidValid()) // @41f6f0 (dwGuiInGame P6w2)
        return;

    pMissionSeg = dwGuiInGame_New(dwCore_pCurrentMission); // new(0x284) @41f2a0
    // A DEPLOYMENT-type mission (missionType 5) plays before the real one.
    pDeploySeg = NULL;
    if (dwCore_pMissionList != NULL) // Note: guard added
    {
        for (pNode = dwCore_pMissionList->pNext; pNode != dwCore_pMissionList; pNode = pNode->pNext)
        {
            if (((dwMission*)pNode->pData)->missionType == DW_MISSION_DEPLOYMENT)
            {
                pDeploySeg = dwGuiInGame_New((dwMission*)pNode->pData);
                break;
            }
        }
    }

    if (pMissionSeg != NULL)
    {
        // Return here after the mission flow retires.
        dwSegment_Push(static_cast<dwSegment*>(this));
        if (pDeploySeg == NULL)
        {
            dwSegment_PushAndAdvance(pMissionSeg);
        }
        else
        {
            dwSegment_Push(pMissionSeg);
            dwSegment_PushAndAdvance(pDeploySeg); // deployment runs first
        }
    }
    else if (pDeploySeg != NULL)
    {
        delete pDeploySeg; // virtual dtor (binary: vtbl slot 0 with flag 1)
    }
}

// vtbl +0x1c @41e320 (dwGuiMissionMap_OnMessage)
int dwGuiMissionMap::OnMessage(dwWidgetMsg* pMsg)
{
    uint32_t code;
    dwWidgetMsg msg;
    char* pBrfName;
    uint8_t rank;
    int handled;

    code = (uint32_t)pMsg->code;
    handled = 0;

    switch (code)
    {
    case 0xBB8: // 3000: deploy
        this->BeginDeploy();
        break;

    case 0xBB9: // 3001: close the map (back to the sequencer)
        dwSegment_RequestAdvance();
        break;

    case 0xBBA: // 3002: show the selected mission's briefing
    {
        msg.code = 0x7532;
        msg.pSender = NULL;
        msg.param = 0;
        msg.pTarget = NULL;
        dwWidget_DispatchMsg(&msg, NULL);

        // Replace any live caption.
        if (this->pBriefText != NULL)
        {
            dwGuiMission_UnlinkWidgetNode(&this->controls.children, this->pBriefText);
            delete this->pBriefText;
            this->pBriefText = NULL;
        }

        if (dwCore_pCurrentMission == NULL) // Note: guard added (binary derefs unguarded)
            break;

        // rank 0-2 -> the rank's VIDEO entry; rank 3 -> the master briefing.
        rank = dwCore_pCurrentMission->rank;
        if (rank < 3)
            pBrfName = dwCore_pCurrentMission->aVideoNames[rank].pBuffer;
        else
            pBrfName = (char*)"Master.brf"; // binary string @0x52855c

        if (pBrfName != NULL && *pBrfName != '\0')
        {
            this->pBriefText = new dwGuiBriefText(&this->mapRect,
                                                  &dwCore_pCurrentMission->mapPos,
                                                  pBrfName, /*msgCode*/0xC1C);
            if (this->pBriefText != NULL)
            {
                if (this->pRadioGroup != NULL)
                    this->pRadioGroup->Disable(); // virtual +0x24
                if (this->pZoomBox != NULL)
                    this->pZoomBox->Disable(); // virtual +0x24
                dwCore_pCurrentMission->bDone = 1; // briefing viewed (gates deploy)
                this->controls.children.InsertAfter(this->controls.children.pSentinel->pPrev,
                                                    this->pBriefText); // append
                this->pBriefText->Play(); // virtual +0x48
            }
        }
        if (this->pJawaAnim != NULL)
            this->pJawaAnim->Play(1); // @401190 (non-virtual overload, skip-next-update)
        break;
    }

    case 0xBBC: // 3004: mission selected (from an objective button)
        dwGuiScreen::OnMessage(pMsg); // base FIRST — the broadcast reaches the children
        handled = 1;
        if (pMsg->pSender != NULL)
            this->SelectObjective((dwMission*)pMsg->pSender);
        break;

    case 0xBEA: // store the briefing-mode toggles
    case 0xBEB:
        this->briefMode = (int32_t)code;
        break;

    case 0xC1D: // briefing VO finished
        if (this->pJawaAnim != NULL)
            this->pJawaAnim->Stop(); // virtual +0x4c
        break;

    case 0x2328: // 9000: an anim finished; 0xC1C = the briefing caption
        if (pMsg->pSender == (void*)(intptr_t)0xC1C)
        {
            if (this->pBriefText != NULL)
                this->pBriefText->Disable(); // virtual +0x24
            if (this->pJawaAnim != NULL)
                this->pJawaAnim->Stop(); // virtual +0x4c
            if (this->pRadioGroup != NULL)
                this->pRadioGroup->Enable(); // virtual +0x20
            if (this->pZoomBox != NULL)
                this->pZoomBox->Enable(); // virtual +0x20
        }
        break;

    case 0x7530: // pick mode / hover notify: silence the briefing
    case 0x7531:
        if (this->pBriefText != NULL)
            this->pBriefText->Stop(); // virtual +0x4c
        if (this->pJawaAnim != NULL)
            this->pJawaAnim->Stop(); // virtual +0x4c
        break;

    default:
        break;
    }

    if (!handled)
        return dwGuiScreen::OnMessage(pMsg); // @4312d0
    return handled;
}

// vtbl +0x48 @41e630 (dwGuiMissionMap_CreateControl)
dwWidget* dwGuiMissionMap::CreateControl(char* pKeyword, dwConfFile* pConf)
{
    dwRect rect;
    char* pTok1;
    char* pTok2;
    uint32_t color;
    uint8_t slot;
    dwPart* pBlueprint;
    dwWidget* pCtrl;

    rect.left = 0;
    rect.top = 0;
    rect.right = 0;
    rect.bottom = 0;

    if (dwString_Equals(pKeyword, "HELP"))
    {
        // "HELP <rect> <anim>": the animated help-droid speech control,
        // speaker code 0x66 (MMCP).
        dwConfFile_ParseRect(pConf, &rect);
        pTok1 = dwConfFile_NextToken(pConf);
        (void)pTok1;
        // TODO(dw-decomp): HELP -> dwHelp (unit dwHelp, P6) — binary:
        // new(0x5c) dwHelp_Ctor@418b40(&rect, pTok1, 0x66).
        return dwGuiMission_StubControl("HELP", "dwHelp", "dwHelp");
    }
    if (dwString_Equals(pKeyword, "JOB_DESCRIPTION") || dwString_Equals(pKeyword, "JOB_NAME"))
    {
        // "<keyword> <format> <rect> <font> <color> <mode...>" — the two
        // keyword branches are byte-identical in the binary (the mode text at
        // the line tail selects the shown field).
        pTok1 = dwConfFile_NextToken(pConf); // format
        dwConfFile_ParseRect(pConf, &rect);
        pTok2 = dwConfFile_NextToken(pConf); // font
        color = 0;
        dwConfFile_ParseULong(pConf, &color);
        return new dwGuiBriefLine(&rect, /*pNotify*/(void*)(intptr_t)0x791e, pTok2,
                                  (uint8_t)color, pTok1, pConf->pCursor,
                                  dwCore_pCurrentMission); // @41d910
    }
    if (dwString_Equals(pKeyword, "JAWA_ANIM"))
    {
        // "JAWA_ANIM <keyword...>": the nested keyword builds the control
        // (ANIMATION -> dwAnim in practice); remembered for Play/Stop cues.
        pTok1 = dwConfFile_NextToken(pConf);
        pCtrl = dwGuiScreen::CreateControl(pTok1, pConf);
        this->pJawaAnim = (dwAnim*)pCtrl; // binary type-puns identically
        return pCtrl;
    }
    if (dwString_Equals(pKeyword, "MAP")) // binary string @0x52846c
    {
        // "MAP <rect>": latches the galaxy-map rect and covers it with a
        // help-code hotspot (inlined dwControlPanelHelpRect ctor, code 0x791f).
        dwConfFile_ParseRect(pConf, &this->mapRect);
        return new dwControlPanelHelpRect(&this->mapRect, 0x791f);
    }
    if (dwString_Equals(pKeyword, "PART_BOUNDS"))
    {
        // "PART_BOUNDS <rect>": 3D preview of the selected mission's reward part.
        dwConfFile_ParseRect(pConf, &rect);
        // TODO(dw-decomp): PART_BOUNDS -> dwGuiDroidPreview (unit
        // dwGuiQuickView, P6) — binary: new(0x574) dwGuiDroidPreview_Ctor
        // @429a80(&rect, NULL).
        return dwGuiMission_StubControl("PART_BOUNDS", "dwGuiDroidPreview", "dwGuiQuickView");
    }
    if (dwString_Equals(pKeyword, "PARTTEXT"))
    {
        // "PARTTEXT <format> <rect> <font> <color>": the reward part's name;
        // reward slot = min(rank, 2) into aRewards.
        pTok1 = dwConfFile_NextToken(pConf); // format
        dwConfFile_ParseRect(pConf, &rect);
        pTok2 = dwConfFile_NextToken(pConf); // font
        color = 0;
        dwConfFile_ParseULong(pConf, &color);
        if (dwCore_pCurrentMission == NULL) // Note: guard added (binary derefs unguarded)
            return NULL;
        slot = dwCore_pCurrentMission->rank;
        if (slot > 2)
            slot = 2;
        pBlueprint = dwPart_FindBlueprint(dwCore_pCurrentMission->aRewards[slot].pBuffer);
        if (pBlueprint == NULL)
            return NULL;
        return new dwGuiPartText(&rect, NULL, pTok2, (uint8_t)color, pTok1, pBlueprint); // @439050
    }
    if (dwString_Equals(pKeyword, "BRIEFING_BUTTON"))
    {
        // Built through the base BUTTON_BLINK branch; remembered for the
        // un-briefed blink in SelectObjective.
        pCtrl = dwGuiScreen::CreateControl((char*)"BUTTON_BLINK", pConf);
        this->pBriefingBlink = (dwWcButtonBlink*)pCtrl; // binary type-puns identically
        return pCtrl;
    }
    return dwGuiScreen::CreateControl(pKeyword, pConf); // @430a10
}

// vtbl +0x3c @41e9f0 (dwGuiMissionMap_EnsureImages)
void dwGuiMissionMap::EnsureImages()
{
    dwGuiScreen::EnsureImages(); // @432150
    if (this->pBriefText != NULL)
        this->pBriefText->EnsureImages(); // virtual +0x3c
    if (this->pJawaAnim != NULL)
        this->pJawaAnim->EnsureImages(); // virtual +0x3c
}

// vtbl +0x40 @41ea20 (dwGuiMissionMap_FreeImages)
void dwGuiMissionMap::FreeImages()
{
    dwGuiScreen::FreeImages(); // @432170
    if (this->pBriefText != NULL)
        this->pBriefText->FreeImages(); // virtual +0x40
    if (this->pJawaAnim != NULL)
        this->pJawaAnim->FreeImages(); // virtual +0x40
}

// ===========================================================================
// dwMissionTransIn / dwMissionTransOut
// ===========================================================================

// @41eb90 (dwMissionTransIn_Ctor)
dwMissionTransIn::dwMissionTransIn(dwImage* pBgImage)
    : dwFlicSeg("TransToM.flc", pBgImage)
    , cueState(0)
{
}

// shared @41ee90 (dwMissionTrans_Dtor — vptr repoint + dwFlicSeg dtor)
dwMissionTransIn::~dwMissionTransIn()
{
}

// scn vtbl +0x00 @41ebc0 (Ghidra: dwMissionTransIn_PreloadSounds)
int dwMissionTransIn::Activate()
{
    if (dwSound_pManager) // Note: guard added (manager exists from P7)
    {
        dwSound_pManager->GetOrLoadSample("MPanelBegin.wav");
        dwSound_pManager->GetOrLoadSample("MPanelMove1.wav");
        dwSound_pManager->GetOrLoadSample("MPanelMiddle.wav");
        dwSound_pManager->GetOrLoadSample("MPanelMove2.wav");
        dwSound_pManager->GetOrLoadSample("MPanelEnd.wav");
        dwSound_pManager->GetOrLoadSample("MScreenAppear.wav");
    }
    return dwFlicSeg::Activate(); // @401470
}

// scn vtbl +0x04 @41ec30 (Ghidra: dwMissionTransIn_StopSounds)
void dwMissionTransIn::Deactivate()
{
    dwSound_SetSampleVolume("MPanelBegin.wav", 0.0f, 0.1f);
    dwSound_SetSampleVolume("MPanelMove1.wav", 0.0f, 0.1f);
    dwSound_SetSampleVolume("MPanelMiddle.wav", 0.0f, 0.1f);
    dwSound_SetSampleVolume("MPanelMove2.wav", 0.0f, 0.1f);
    dwSound_SetSampleVolume("MPanelEnd.wav", 0.0f, 0.1f);
    if (dwSound_pManager) // Note: guard added
        dwSound_pManager->FreeAllSamples();
    dwFlicSeg::Deactivate(); // @401620
}

// scn vtbl +0x10 @41ecc0 (dwMissionTransIn_Update) — frame-cued sounds over
// the base FLC playback.
void dwMissionTransIn::Update()
{
    dwFlicSeg::Update(); // @401640
    if (this->cueState == 0)
    {
        dwSound_Play("MPanelBegin.wav");
        this->cueState = 1;
    }
    if (this->cueState == 1 && this->curFrame != 0)
    {
        dwSound_PlayLooping("MPanelMove1.wav");
        dwSound_SetSampleVolume("MPanelMove1.wav", 0.1f, 0.0f);
        dwSound_SetSampleVolume("MPanelMove1.wav", 1.0f, 0.1f);
        this->cueState = 2;
    }
    if (this->cueState == 2 && this->curFrame > 8)
    {
        dwSound_SetSampleVolume("MPanelMove1.wav", 0.0f, 0.1f);
        dwSound_Play("MPanelMiddle.wav");
        this->cueState = 3;
    }
    if (this->cueState == 3 && this->curFrame > 9)
    {
        dwSound_PlayLooping("MPanelMove2.wav");
        dwSound_SetSampleVolume("MPanelMove2.wav", 0.1f, 0.0f);
        dwSound_SetSampleVolume("MPanelMove2.wav", 1.0f, 0.1f);
        this->cueState = 4;
    }
    if (this->cueState == 4 && this->curFrame > 0x11)
    {
        dwSound_SetSampleVolume("MPanelMove2.wav", 0.0f, 0.1f);
        dwSound_Play("MPanelEnd.wav");
        this->cueState = 5;
    }
    if (this->cueState == 5 && this->curFrame > 0x15)
    {
        dwSound_Play("MScreenAppear.wav");
        this->cueState = 6;
    }
}

// @41ee60 (dwMissionTransOut_Ctor)
dwMissionTransOut::dwMissionTransOut(dwImage* pBgImage)
    : dwFlicSeg("TransFromM.flc", pBgImage)
    , cueState(0)
{
}

// shared @41ee90 (dwMissionTrans_Dtor)
dwMissionTransOut::~dwMissionTransOut()
{
}

// scn vtbl +0x00 @41eec0 (Ghidra: dwMissionTransOut_PreloadSounds)
int dwMissionTransOut::Activate()
{
    if (dwSound_pManager) // Note: guard added
    {
        dwSound_pManager->GetOrLoadSample("MPanelBegin.wav");
        dwSound_pManager->GetOrLoadSample("MPanelMove1.wav");
        dwSound_pManager->GetOrLoadSample("MPanelMiddle.wav");
        dwSound_pManager->GetOrLoadSample("MPanelMove2.wav");
        dwSound_pManager->GetOrLoadSample("MPanelEnd.wav");
        dwSound_pManager->GetOrLoadSample("MScreenVanish.wav");
    }
    return dwFlicSeg::Activate(); // @401470
}

// scn vtbl +0x04 @41ef30 (Ghidra: dwMissionTransOut_StopSounds)
void dwMissionTransOut::Deactivate()
{
    dwSound_SetSampleVolume("MPanelMove1.wav", 0.0f, 0.1f);
    dwSound_SetSampleVolume("MPanelMiddle.wav", 0.0f, 0.1f);
    dwSound_SetSampleVolume("MPanelMove2.wav", 0.0f, 0.1f);
    dwSound_SetSampleVolume("MPanelEnd.wav", 0.0f, 0.1f);
    dwSound_SetSampleVolume("MScreenVanish.wav", 0.0f, 0.1f);
    if (dwSound_pManager) // Note: guard added
        dwSound_pManager->FreeAllSamples();
    dwFlicSeg::Deactivate(); // @401620
}

// scn vtbl +0x10 @41efc0 (dwMissionTransOut_Update) — the TransIn cue machine
// mirrored (the panel slides back, so the states run 6 -> 1).
void dwMissionTransOut::Update()
{
    dwFlicSeg::Update(); // @401640
    if (this->cueState == 0)
    {
        dwSound_Play("MScreenVanish.wav");
        this->cueState = 6;
    }
    if (this->cueState == 6 && this->curFrame > 8)
    {
        dwSound_Play("MPanelEnd.wav");
        this->cueState = 5;
    }
    if (this->cueState == 5 && this->curFrame > 0xb)
    {
        dwSound_PlayLooping("MPanelMove2.wav");
        dwSound_SetSampleVolume("MPanelMove2.wav", 0.1f, 0.0f);
        dwSound_SetSampleVolume("MPanelMove2.wav", 1.0f, 0.1f);
        this->cueState = 4;
    }
    if (this->cueState == 4 && this->curFrame > 0x14)
    {
        dwSound_SetSampleVolume("MPanelMove2.wav", 0.0f, 0.1f);
        dwSound_Play("MPanelMiddle.wav");
        this->cueState = 3;
    }
    if (this->cueState == 3 && this->curFrame > 0x15)
    {
        dwSound_PlayLooping("MPanelMove1.wav");
        dwSound_SetSampleVolume("MPanelMove1.wav", 0.1f, 0.0f);
        dwSound_SetSampleVolume("MPanelMove1.wav", 1.0f, 0.1f);
        this->cueState = 2;
    }
    if (this->cueState == 2 && this->curFrame > 0x1c)
    {
        dwSound_SetSampleVolume("MPanelMove1.wav", 0.0f, 0.1f);
        dwSound_Play("MPanelBegin.wav");
        this->cueState = 1;
    }
}

// ===========================================================================
// dwMissionSequence phase factories (Dw/dwMission.h contract)
// ===========================================================================

// Bundles dwMissionSequence::Activate's `new(0x3d0) + Ctor@41eb90` pair.
extern "C" dwSegment* dwMissionTransIn_New(dwImage* pBgImage)
{
    return new dwMissionTransIn(pBgImage);
}

// Bundles the sequencer's `new(0xf4) + Ctor@41db20` pair; returns the
// screen's dwSegment subobject (binary: obj+0x10).
extern "C" dwSegment* dwGuiMissionMap_New(dwImage* pBgImage)
{
    return static_cast<dwSegment*>(new dwGuiMissionMap(pBgImage));
}

// Bundles the sequencer's `new(0x3d0) + Ctor@41ee60` pair.
extern "C" dwSegment* dwMissionTransOut_New(dwImage* pBgImage)
{
    return new dwMissionTransOut(pBgImage);
}
