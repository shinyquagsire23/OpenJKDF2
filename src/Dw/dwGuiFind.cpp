// dwGuiFind — reference-room TOPIC SEARCH screen ("Find") + its two nested
// scroll subclasses. DroidWorks.exe 0x412380-0x413c1f, primary vtbl 0x51eb90 /
// segment vtbl 0x51eb78 (dwGuiFind), 0x51ebe0 (dwGuiFindScrollBar), 0x51ec28
// (dwGuiFindScrollBox). See Dw/dwGuiFind.h.

#include "Dw/dwGuiFind.h"

#include "Dw/dwSegment.h"   // dwSegment_RequestAdvance
#include "Dw/dwSound.h"     // dwSound_Play / _SetSampleVolume
#include "Dw/dwConfFile.h"  // topic-file parsing
#include "Dw/dwInits.h"     // inits_EnumFilesByExt
#include "Dw/dwString.h"
#include "Dw/dwImage.h"
#include "Dw/dwList.h"
#include "Dw/dwWidget.h"    // dwWidget_DispatchMsg

#include "stdPlatform.h"

#include <new>      // placement new (C factory)
#include <stdlib.h> // atoi

// ---- cross-unit externs ------------------------------------------------------

// The current reference-room topic file (dwString @0x53d968) — owned by
// dwInits.cpp (parked there until dwGuiReference/dw core claims it). The
// QUERY factory seeds the box with this file's TOPIC_NAME; the confirm-selection
// messages write the picked result here.
extern dwString dwCore_currentRefFile;

// The empty-query sentinel string (binary DAT_00527d4c = a single space).
static const char dwGuiFind_emptyQueryMark[] = " ";

// =====================================================================
// dwGuiFindScrollBar
// =====================================================================

// @4136b0 (dwGuiFindScrollBar_Ctor)
dwGuiFindScrollBar::dwGuiFindScrollBar(dwRect* pRect, int msgSetValue, int msgLineUp,
                                       int msgLineDown, int minValue, int maxValue,
                                       char* pTrackImgName, char* pThumbImgName, int msgCode)
    : dwGuiScrollBar(pRect, msgSetValue, msgLineUp, msgLineDown, minValue, maxValue,
                     pTrackImgName, pThumbImgName)
{
    this->msgCode = msgCode;
}

// @413720 (dwGuiFindScrollBar_Dtor; scalar-deleting wrapper @413700)
dwGuiFindScrollBar::~dwGuiFindScrollBar()
{
}

// vtbl +0x1c @413730 (dwGuiFindScrollBar_OnMessage)
int dwGuiFindScrollBar::OnMessage(dwWidgetMsg* pMsg)
{
    if (pMsg->code == this->msgCode)
    {
        int v = this->value;
        int delta = (int)(intptr_t)pMsg->pSender;
        if (v > 1)
        {
            if (delta != 0)
            {
                this->SetValueClamp(delta + v);
                return 1;
            }
            if (v > 1 && delta < 0) // (dead per the guard above; faithful)
            {
                this->SetValueClamp(delta + v);
                return 1;
            }
        }
        this->SetValueClamp(delta);
    }
    return this->dwGuiScrollBar::OnMessage(pMsg);
}

// @4137a0 (dwGuiFindScrollBar_SetValue) — clamp-no-notify.
void dwGuiFindScrollBar::SetValueClamp(int newValue)
{
    int mn = this->minValue;
    int mx = this->maxValue;
    if (mn < mx)
    {
        if (newValue < mn) newValue = mn;
        if (mx < newValue) newValue = mx;
    }
    else
    {
        if (newValue < mx) newValue = mx;
        if (mn < newValue) newValue = mn;
    }
    if (this->value != newValue)
    {
        this->value = newValue;
        this->Invalidate();
    }
}

// =====================================================================
// dwGuiFindScrollBox
// =====================================================================

// @4137e0 (dwGuiFindScrollBox_Ctor)
dwGuiFindScrollBox::dwGuiFindScrollBox(dwRect* pRect, int scrollMsgCode, char* pFontName,
                                       uint8_t textColorIdx, uint8_t highlightColorIdx,
                                       int msgSelChanged, int msgNotify)
    : dwGuiScrollBox(pRect, scrollMsgCode, pFontName, textColorIdx, highlightColorIdx, msgSelChanged)
{
    this->msgNotify = msgNotify;
    this->searchStep = 0;
    this->reserved = 0;
}

// @413850 (dwGuiFindScrollBox_Dtor; scalar-deleting wrapper @413830)
dwGuiFindScrollBox::~dwGuiFindScrollBox()
{
}

// vtbl +0x08 @413860 (dwGuiFindScrollBox_OnMouseDown)
int dwGuiFindScrollBox::OnMouseDown(int16_t x, int16_t y)
{
    (void)x;
    int row = (y - this->top) / (int)this->pFont->pHeader->lineHeight;
    dwListNode* pNode = this->pFirstVisible;
    for (; row != 0; row--)
    {
        if (pNode == this->items.pSentinel)
            break;
        pNode = pNode->pNext;
    }
    if (pNode != this->items.pSentinel)
    {
        dwGuiScrollBoxItem* pItem = (dwGuiScrollBoxItem*)pNode->pData;
        this->bHasSelection = 1;
        this->pSelectedItem = pItem;
        // Note: binary dispatches a widget message whose payload Ghidra lost in
        // the __thiscall ECX; reconstructed as the box's selection-changed
        // notification (matches the base OnMouseDown behavior).
        dwWidgetMsg msg;
        msg.code = this->msgSelChanged;
        msg.pSender = pItem->filename.pBuffer;
        msg.param = 0;
        msg.pTarget = NULL;
        dwWidget_DispatchMsg(&msg, NULL);
        this->Invalidate();
    }
    return 0;
}

// vtbl +0x10 @413910 (dwGuiFindScrollBox_OnKey)
int dwGuiFindScrollBox::OnKey(int key, int repeat)
{
    (void)key; (void)repeat;
    return 0;
}

// vtbl +0x1c @413920 (dwGuiFindScrollBox_OnMessage) — the type-ahead matcher.
int dwGuiFindScrollBox::OnMessage(dwWidgetMsg* pMsg)
{
    uint8_t ret = 0;
    int delta = 0;

    this->searchStep = 0;
    if (pMsg->code == this->msgNotify)
    {
        dwString query;
        query.Assign((const char*)pMsg->pSender, 0);
        dwString cand;
        dwString tmp;

        dwListNode* pNode = this->pFirstVisible;
        bool bEmpty = dwString_Equals(query.pBuffer, dwGuiFind_emptyQueryMark);
        if ((!bEmpty || query.length > 1) && pNode != this->items.pSentinel)
        {
            do
            {
                dwGuiScrollBoxItem* pItem = (dwGuiScrollBoxItem*)pNode->pData;
                cand.Assign(pItem->displayName.pBuffer, query.length);
                if (dwString_CompareI(query.pBuffer, cand.pBuffer) == 0)
                {
                    // exact prefix match: select + scroll to it
                    this->pFirstVisible = pNode;
                    this->pSelectedItem = pItem;
                    this->bHasSelection = 1;
                    if (delta != 0)
                    {
                        dwWidgetMsg m;
                        m.code = 0x1b7b;
                        m.pSender = (void*)(intptr_t)delta;
                        m.param = 0;
                        m.pTarget = NULL;
                        dwWidget_DispatchMsg(&m, NULL);
                        if (delta < 0 && this->scrollPos > 0)
                            this->scrollPos += delta;
                        else if (this->scrollPos == 0 && delta > 0)
                            this->scrollPos = delta;
                        else
                            this->scrollPos += delta;
                    }
                    break;
                }
                if (dwString_CompareI(query.pBuffer, cand.pBuffer) < 0 && this->searchStep < 0x5f)
                {
                    // query sorts before the candidate: walk backward
                    delta--;
                    if (pNode == this->items.pSentinel->pNext)
                    {
                        dwSound_Play("RFindError.WAV");
                        break;
                    }
                    pNode = pNode->pPrev;
                    dwGuiScrollBoxItem* pPrev = (dwGuiScrollBoxItem*)pNode->pData;
                    tmp.Assign(pPrev->displayName.pBuffer, 1);
                    if (!dwString_Equals(cand.pBuffer, tmp.pBuffer)
                        || !dwString_Equals(query.pBuffer, tmp.pBuffer))
                        this->searchStep++;
                }
                else
                {
                    if (dwString_CompareI(query.pBuffer, cand.pBuffer) < 1 || this->searchStep > 0x5e)
                    {
                        dwSound_Play("RFindError.WAV");
                        break;
                    }
                    // query sorts after the candidate: walk forward
                    dwString tmp2;
                    delta++;
                    if (pNode == this->items.pSentinel->pPrev)
                    {
                        dwSound_Play("RFindError.WAV");
                        tmp2.Free();
                        break;
                    }
                    pNode = pNode->pNext;
                    dwGuiScrollBoxItem* pNext = (dwGuiScrollBoxItem*)pNode->pData;
                    tmp2.Assign(pNext->displayName.pBuffer, 1);
                    if (!dwString_Equals(cand.pBuffer, tmp2.pBuffer)
                        || !dwString_Equals(query.pBuffer, tmp2.pBuffer))
                        this->searchStep++;
                    tmp2.Free();
                }
            } while (pNode != this->items.pSentinel);
        }
        ret = 1;
        // query/cand/tmp freed by their dtors here
    }

    this->Invalidate();
    this->dwGuiScrollBox::OnMessage(pMsg);
    return ret;
}

// =====================================================================
// dwGuiFind  (screen)
// =====================================================================

// Scan every *.<ext> topic file and add the searchable ones (TOPIC_CATEGORY 0)
// to the result box. Binary: the two SCROLLBOX-population loops @412e40/412f90
// (one for "TPC", one for "SUB"). Cleanup here inlines what the binary did via
// dwGuiLoadSave_StringItemDtorDelete/_ClearList (avoids a cross-unit dependency).
static void dwGuiFind_ScanTopics(dwGuiFindScrollBox* pBox, const char* pExt)
{
    dwList files;
    inits_EnumFilesByExt(pExt, &files);

    dwString topicName;
    dwListNode* pNode = files.pSentinel->pNext;
    while (pNode != files.pSentinel)
    {
        dwString* pFilename = (dwString*)pNode->pData;
        dwConfFile conf;
        dwConfFile_Open(&conf, pFilename->pBuffer);
        for (;;)
        {
            char* pTok;
            do
            {
                if (conf.bEof)
                    goto nextFile;
                dwConfFile_ReadLine(&conf);
                pTok = dwConfFile_NextToken(&conf);
            } while (!dwString_Equals(pTok, "TOPIC_NAME"));
            topicName.Assign(conf.pCursor, 0);
            dwConfFile_ReadLine(&conf);
            pTok = dwConfFile_NextToken(&conf);
            if (dwString_Equals(pTok, "TOPIC_CATEGORY"))
                break;
        }
        dwConfFile_NextToken(&conf);
        if (atoi(conf.pCursor) == 0)
            pBox->AddItem(pFilename->pBuffer, topicName.pBuffer);
    nextFile:
        dwConfFile_Close(&conf);
        pNode = pNode->pNext;
    }

    // free the enumerated filename strings, then the list nodes + sentinel
    for (pNode = files.pSentinel->pNext; pNode != files.pSentinel;)
    {
        dwListNode* pNext = pNode->pNext;
        delete (dwString*)pNode->pData;
        pNode = pNext;
    }
    files.Free();
}

// The dwGuiFind_OnActivate reopen body (composite the parent snapshot into the
// background, seed the slide-in, set the ambient volume). Called by Activate()
// and by the OnMessage reopen commands. Binary @4128e0 (does NOT re-run base
// Activate; base is chained from Activate() to lazy-load the controls).
static void dwGuiFind_DoReopen(dwGuiFind* pThis)
{
    if (pThis->pBgImage != NULL && pThis->pParent != NULL)
    {
        void* pPixels = NULL;
        int stride = 0;
        dwImageBits bits;
        pThis->pBgImage->Lock(&pPixels, &stride);
        bits.pDesc = &pThis->pBgImage->desc;
        bits.pPixels = pPixels;
        bits.stride = stride;
        pThis->pParent->Blit(&bits, 0, 0, NULL); // this = SOURCE (the snapshot)
        pThis->pBgImage->Unlock();
    }
    pThis->slidePos = 0.0f;
    pThis->slideDir = 320.0f;
    dwSound_SetSampleVolume("WLSPanelAmb.WAV", 0.0f, (float)pThis->bottom / 320.0f);
}

// @412380 (dwGuiFind_Ctor)
dwGuiFind::dwGuiFind(dwImage* pBgSnapshot)
    : dwGuiScreen("Find", pBgSnapshot)
{
    this->pParent = pBgSnapshot;
    this->bAutoEditQuery = 0;
    this->pBgImageControl = NULL;
    this->pQueryEntry = NULL;
    this->pScrollBar = NULL;
    this->pResultBox = NULL;
    this->pScrollUp = NULL;
    this->pScrollDown = NULL;
    this->slidePos = 0.0f;
    this->slideDir = 0.0f;
}

// @412410 (dwGuiFind_Dtor)
dwGuiFind::~dwGuiFind()
{
    // The tracked controls (FINDBOX/QUERY/SCROLLBOX/FILESCROLLBAR/scroll
    // buttons) are children of the base screen's `controls` group and die in
    // its dtor. (The binary manually unlinked+deleted each before the base
    // dtor; letting the group own them is the project convention — see
    // dwGuiMissionMap — and avoids the binary's duplicate-node hazard.)
}

// vtbl(scn) +0x00 @4128e0 (dwGuiFind_OnActivate)
int dwGuiFind::Activate()
{
    // Note: the binary's OnActivate does NOT chain the base; base Activate is
    // chained here (guarded lazy LoadControls) so the FINDBOX/QUERY/SCROLLBOX
    // controls actually get built. The Find-specific reopen work follows.
    int ret = dwGuiScreen::Activate();
    dwGuiFind_DoReopen(this);
    return ret;
}

// vtbl(scn) +0x04 @40bea0 (shared body; Ghidra: dwGuiLoadSave_OnDeactivate) —
// reproduced here so dwGuiFind stays independent of the dwGuiLoadSave unit.
void dwGuiFind::Deactivate()
{
    if (dwSound_pManager)
        dwSound_pManager->FreeAllSamples();
}

// vtbl +0x10 @412be0 (dwGuiFind_OnKey)
int dwGuiFind::OnKey(int key, int repeat)
{
    if ((char)key == '\x1b' && repeat != 0 && this->slideDir != 0.0f)
        this->slidePos = 10.0f; // binary: &DAT_41200000
    this->dwGuiScreen::OnKey(key, repeat);
    return 0;
}

// vtbl +0x14 @412730 (dwGuiFind_Update) — drive the slide.
// Note: the binary's per-frame block is heavily EH-mangled in the decompile;
// the recoverable behavior (slide accumulation, completion -> RequestAdvance /
// BeginEdit, group Move + Invalidate, then the group tick) is reproduced here.
// The exact mid-slide pixel position is an approximation.
void dwGuiFind::Update(float dt)
{
    if (this->slideDir != 0.0f)
    {
        this->slidePos += dt;
        int16_t pos = (int16_t)this->slidePos;

        if (this->slideDir >= 0.0f)
        {
            // sliding out: complete when the panel reaches the screen bottom
            if (this->bottom <= pos)
            {
                this->slideDir = 0.0f;
                dwSegment_RequestAdvance();
                pos = this->bottom;
            }
        }
        else
        {
            // sliding in: complete when it reaches the start
            if ((int16_t)(pos + this->bottom) < 1)
            {
                this->slideDir = 0.0f;
                if (this->bAutoEditQuery && this->pQueryEntry != NULL)
                    this->pQueryEntry->BeginEdit();
                pos = 0;
            }
        }

        this->controls.Move((int16_t)(-this->controls.left), (int16_t)(pos - this->controls.top));
        this->Invalidate();
    }
    this->controls.Update(dt);
}

// vtbl +0x1c @412c30 (dwGuiFind_OnMessage)
int dwGuiFind::OnMessage(dwWidgetMsg* pMsg)
{
    switch (pMsg->code)
    {
    case 0x1b76:
        this->RefreshScrollWidgets();
        this->dwGuiScreen::OnMessage(pMsg);
        return 0;
    case 0x1b78:
        this->controls.Disable();
        this->RefreshScrollWidgets();
        dwGuiFind_DoReopen(this);
        this->dwGuiScreen::OnMessage(pMsg);
        return 0;
    case 0x1b79:
        this->controls.Disable();
        if (this->pResultBox != NULL && this->pResultBox->pSelectedItem != NULL)
            dwCore_currentRefFile.Assign(this->pResultBox->pSelectedItem->filename.pBuffer, 0);
        this->RefreshScrollWidgets();
        dwGuiFind_DoReopen(this);
        this->dwGuiScreen::OnMessage(pMsg);
        return 0;
    case 0x1b7a:
        dwSound_PlayRestart("WSelectDroid1.WAV");
        if (this->pResultBox != NULL && this->pResultBox->pSelectedItem != NULL)
            dwCore_currentRefFile.Assign(this->pResultBox->pSelectedItem->filename.pBuffer, 0);
        break;
    default:
        break;
    }
    this->dwGuiScreen::OnMessage(pMsg);
    return 0;
}

// @412b00 (dwGuiFind_RefreshScrollWidgets)
void dwGuiFind::RefreshScrollWidgets()
{
    this->pQueryEntry->Enable();

    if (this->bAutoEditQuery == 0)
    {
        // no forced edit: the box has a selection only when it has items
        this->pResultBox->bHasSelection = (this->pResultBox->itemCount != 0);
        this->pResultBox->Invalidate();
    }
    else
    {
        this->pResultBox->bHasSelection = 1;
        this->pResultBox->Invalidate();
        // Note: binary dispatches a widget message Ghidra lost here.
    }

    if (this->pResultBox->bNeedsScroll != 0)
    {
        this->pScrollBar->Enable();
        this->pScrollUp->Enable();
        this->pScrollDown->Enable();
        this->Invalidate();
    }
    else
    {
        this->pScrollBar->Disable();
        this->pScrollUp->Disable();
        this->pScrollDown->Disable();
        this->Invalidate();
    }
}

// vtbl +0x48 @412d10 (dwGuiFind_CreateControl)
dwWidget* dwGuiFind::CreateControl(char* pKeyword, dwConfFile* pConf)
{
    dwRect rect = {0, 0, 0, 0};

    if (dwString_Equals(pKeyword, "SCROLLBOX"))
    {
        uint32_t scrollMsgCode = 0, highlightColor = 0, msgSelChanged = 0, msgNotify = 0;
        int32_t textColor = 0;
        dwConfFile_ParseRect(pConf, &rect);
        dwConfFile_ParseULong(pConf, &scrollMsgCode);
        char* pFont = dwConfFile_NextToken(pConf);
        dwConfFile_ParseLong(pConf, &textColor);
        dwConfFile_ParseULong(pConf, &highlightColor);
        dwConfFile_ParseULong(pConf, &msgSelChanged);
        dwConfFile_ParseULong(pConf, &msgNotify);

        dwGuiFindScrollBox* pBox = new dwGuiFindScrollBox(
            &rect, (int)scrollMsgCode, pFont, (uint8_t)textColor,
            (uint8_t)highlightColor, (int)msgSelChanged, (int)msgNotify);
        this->pResultBox = pBox;

        // populate from every searchable TPC + SUB topic file
        dwGuiFind_ScanTopics(pBox, "TPC");
        dwGuiFind_ScanTopics(pBox, "SUB");
        return pBox;
    }
    if (dwString_Equals(pKeyword, "SCROLLUPBUTTON"))
    {
        uint32_t cmdId = 0;
        dwConfFile_ParseRect(pConf, &rect);
        dwConfFile_ParseULong(pConf, &cmdId);
        char* pImgUp = dwConfFile_NextToken(pConf);
        char* pImgDown = dwConfFile_NextToken(pConf);
        dwGuiScrollButton* pBtn = new dwGuiScrollButton(&rect, pImgUp, pImgDown, (int)cmdId);
        this->pScrollUp = pBtn;
        if (this->pResultBox->bNeedsScroll == 0)
            pBtn->Disable();
        return pBtn;
    }
    if (dwString_Equals(pKeyword, "SCROLLDOWNBUTTON"))
    {
        uint32_t cmdId = 0;
        dwConfFile_ParseRect(pConf, &rect);
        dwConfFile_ParseULong(pConf, &cmdId);
        char* pImgUp = dwConfFile_NextToken(pConf);
        char* pImgDown = dwConfFile_NextToken(pConf);
        dwGuiScrollButton* pBtn = new dwGuiScrollButton(&rect, pImgUp, pImgDown, (int)cmdId);
        this->pScrollDown = pBtn;
        if (this->pResultBox->bNeedsScroll == 0)
            pBtn->Disable();
        return pBtn;
    }
    if (dwString_Equals(pKeyword, "FILESCROLLBAR"))
    {
        uint32_t msgSetValue = 0, msgLineUp = 0, msgLineDown = 0, msgCode = 0;
        dwConfFile_ParseRect(pConf, &rect);
        dwConfFile_ParseULong(pConf, &msgSetValue);
        dwConfFile_ParseULong(pConf, &msgLineUp);
        dwConfFile_ParseULong(pConf, &msgLineDown);
        char* pThumb = dwConfFile_NextToken(pConf);
        if (pThumb != NULL && *pThumb == '\0')
            pThumb = NULL;
        dwConfFile_ParseULong(pConf, &msgCode);

        int maxValue = (this->pResultBox->itemCount == 0) ? 0 : (this->pResultBox->itemCount - 1);
        dwGuiFindScrollBar* pBar = new dwGuiFindScrollBar(
            &rect, (int)msgSetValue, (int)msgLineUp, (int)msgLineDown,
            /*minValue*/0, maxValue, /*track*/NULL, pThumb, (int)msgCode);
        this->pScrollBar = pBar;
        pBar->dwGuiScrollBar::SetValue(0); // base (notify) SetValue
        if (this->pResultBox->bNeedsScroll == 0)
            pBar->Disable();
        return pBar;
    }
    if (dwString_Equals(pKeyword, "QUERY"))
    {
        uint32_t textColor = 0, cursorColor = 0, msgEditNotify = 0, msgChanged = 0,
                 msgCommit = 0, messageCode = 0;
        dwConfFile_ParseRect(pConf, &rect);
        char* pFont = dwConfFile_NextToken(pConf);
        dwConfFile_ParseULong(pConf, &textColor);
        dwConfFile_ParseULong(pConf, &cursorColor);
        dwConfFile_ParseULong(pConf, &msgEditNotify);
        dwConfFile_ParseULong(pConf, &msgChanged);
        dwConfFile_ParseULong(pConf, &msgCommit);
        dwConfFile_ParseULong(pConf, &messageCode);

        // The editable buffer the query box points at (heap-owned, external to
        // the entry — faithful: the binary allocates it and never frees it).
        // Seed it with the current reference topic's TOPIC_NAME.
        dwString* pText = new dwString();
        dwConfFile conf;
        dwConfFile_Open(&conf, dwCore_currentRefFile.pBuffer);
        for (;;)
        {
            if (conf.bEof)
                break;
            dwConfFile_ReadLine(&conf);
            char* pTok = dwConfFile_NextToken(&conf);
            if (dwString_Equals(pTok, "TOPIC_NAME"))
            {
                pText->Assign(conf.pCursor, 0);
                break;
            }
        }
        dwConfFile_Close(&conf);

        dwGuiFindEntry* pEntry = new dwGuiFindEntry(
            &rect, pFont, (uint8_t)textColor, (uint8_t)cursorColor, pText,
            (int)msgEditNotify, (int)msgChanged, (int)msgCommit, (int)messageCode);
        this->pQueryEntry = pEntry;
        return pEntry;
    }
    if (dwString_Equals(pKeyword, "FINDBOX"))
    {
        dwWidget* pImg = this->dwGuiScreen::CreateControl((char*)"IMAGE", pConf);
        this->pBgImageControl = pImg;
        return pImg;
    }
    return this->dwGuiScreen::CreateControl(pKeyword, pConf);
}

// Added: C-callable factory (see dwGuiFind.h). Upcasts through the MI hierarchy
// to the dwSegment subobject that dwSegment_Push/_Tick drive.
extern "C" dwSegment* dwGuiFind_New(dwImage* pBgSnapshot)
{
    return static_cast<dwSegment*>(new dwGuiFind(pBgSnapshot));
}
