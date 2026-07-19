// dwGuiWidgets — the scroll-control cluster (dwGuiScrollBar / dwGuiScrollBox
// / dwGuiScrollButton / dwGuiTextRollover) + the .drd droid-file
// serialization free functions. See Dw/dwGuiWidgets.h for the class notes.
//
// Decompiled from DroidWorks.exe, unit range 0x432150-0x433d8f.
// NOT re-implemented here (already owned elsewhere): 0x432150/0x432170 =
// dwGuiScreen_EnsureImages/FreeImages (dwGuiScreen.cpp); 0x432280 =
// dw_CoreStubCtor (a dwSegment-vptr-reset COMDAT used only by the dw core
// unit's EH cleanup — C++ base-dtor semantics cover it); the four MI
// this-adjustor thunks @0x433db0-0x433de0 (compiler-generated now).
//
// No module statics — no dwGuiWidgets_Startup needed (soft-reset rule).

#include "Dw/dwGuiWidgets.h"
#include "Dw/dwImageDraw.h"
#include "Dw/dwColormap.h"
#include "Dw/dwSound.h"
#include "Dw/dwPart.h" // dwPart/dwPartNode — the .drd payloads (P5)

#include "stdPlatform.h"

extern "C" HostServices* dwMain_pHS; // the DW host-services pointer (dwMain.c); binary global dwHS @0x6b6258

#include <stdlib.h>

// ---------------------------------------------------------------------------
// dwGuiScrollBar (vtbl 0x51f7f0)
// ---------------------------------------------------------------------------

// @432980 (dwGuiScrollBar_Ctor)
dwGuiScrollBar::dwGuiScrollBar(dwRect* pRect, int msgSetValue, int msgLineUp, int msgLineDown,
                               int minValue, int maxValue, char* pTrackImgName, char* pThumbImgName)
    : dwWidget(pRect)
    , msgSetValue(msgSetValue)
    , msgLineUp(msgLineUp)
    , msgLineDown(msgLineDown)
    , minValue(minValue)
    , maxValue(maxValue)
    , value(minValue)
    , pTrackImage(NULL)
    , pThumbImage(NULL)
    , trackImageName()
    , thumbImageName()
    , bDragging(0)
    , bVertical(pRect->right - pRect->left < pRect->bottom - pRect->top)
    , dragMode(0)
    , repeatAccum(0.0f) // Note: NOT initialized by the binary ctor (written on arm)
{
    this->thumbImageName.AssignCStr(pThumbImgName);
    this->trackImageName.AssignCStr(pTrackImgName);
    dwGuiScrollBar::EnsureImages(); // binary: direct call @433000
}

// @432a80 (dwGuiScrollBar_Dtor; scalar-deleting wrapper @432a60)
dwGuiScrollBar::~dwGuiScrollBar()
{
    dwGuiScrollBar::FreeImages(); // binary: direct call @433050
    // thumbImageName/trackImageName freed by the member dtors (that order).
}

// vtbl +0x04 @432b20
int dwGuiScrollBar::OnMouseMove(int16_t x, int16_t y)
{
    if (this->bDragging != 0)
        this->SetValue(this->PointToValue(x, y));
    return this->bDragging;
}

// vtbl +0x08 @432b50
int dwGuiScrollBar::OnMouseDown(int16_t x, int16_t y)
{
    this->bDragging = 1;
    dwWidget_pMouseTarget = this;
    return this->OnMouseMove(x, y); // binary: virtual tail call (vtbl +0x04)
}

// vtbl +0x0c @432b70
int dwGuiScrollBar::OnMouseUp(int16_t x, int16_t y)
{
    (void)x; (void)y;
    this->bDragging = 0;
    if (dwWidget_pMouseTarget == this)
        dwWidget_pMouseTarget = NULL;
    return 1;
}

// vtbl +0x14 @432c00 — auto-repeat tick (constants 0.1f @0x51f838 / 10.0f
// @0x51f83c in the binary).
void dwGuiScrollBar::Update(float dt)
{
    int steps;

    if (this->dragMode == 0)
        return;
    this->repeatAccum = this->repeatAccum + dt;
    if (this->repeatAccum < 0.1f)
        return;
    steps = (int)(this->repeatAccum * 10.0f);
    this->repeatAccum = this->repeatAccum - (float)steps * 0.1f;
    if (this->dragMode == 1)
    {
        if (this->minValue < this->maxValue)
            this->SetValue(this->value + steps);
        else
            this->SetValue(this->value - steps);
    }
    else if (this->dragMode == 2)
    {
        if (this->minValue < this->maxValue)
            this->SetValue(this->value - steps);
        else
            this->SetValue(this->value + steps);
    }
    else
    {
        this->SetValue(this->value); // binary: unreachable-in-practice fallthrough
    }
}

// vtbl +0x18 @419780 (the shared dwWidget_OnHoverNotify COMDAT reading the
// derived +0x10 field — see the dwWidget.h note on the 64-bit adaptation)
int dwGuiScrollBar::OnHover(int16_t x, int16_t y)
{
    (void)x; (void)y;
    return this->OnHoverNotify((void*)(intptr_t)this->msgSetValue);
}

// vtbl +0x1c @432b90
int dwGuiScrollBar::OnMessage(dwWidgetMsg* pMsg)
{
    if (pMsg->code == this->msgSetValue)
    {
        this->SetValue((int)(intptr_t)pMsg->pSender);
        return 0;
    }
    if (pMsg->code == this->msgLineUp)
    {
        if (this->dragMode == 0)
        {
            this->repeatAccum = 0.0f;
            this->dragMode = 2;
            return 0;
        }
        this->dragMode = 0; // second message (button release) stops the repeat
        return 0;
    }
    if (pMsg->code == this->msgLineDown)
    {
        if (this->dragMode == 0)
        {
            this->repeatAccum = 0.0f;
            this->dragMode = 1;
            return 0;
        }
        this->dragMode = 0;
        return 0;
    }
    return 0;
}

// vtbl +0x20 @432af0 (Ghidra: dwGuiScrollBar_EnableInput) — Enable override
void dwGuiScrollBar::Enable()
{
    dwWidgetMsg msg;

    this->bEnabled = 1;
    msg.code = this->msgSetValue;
    msg.pSender = (void*)(intptr_t)this->value;
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);
}

// vtbl +0x3c @433000 (thumb first, then track — binary order)
void dwGuiScrollBar::EnsureImages()
{
    if (this->pThumbImage == NULL && this->thumbImageName.length != 0)
        this->pThumbImage = dwImage_LoadFile(this->thumbImageName.pBuffer); // NULL-tolerant (P8 stub)
    if (this->pTrackImage == NULL && this->trackImageName.length != 0)
        this->pTrackImage = dwImage_LoadFile(this->trackImageName.pBuffer);
}

// vtbl +0x40 @433050
void dwGuiScrollBar::FreeImages()
{
    if (this->pThumbImage != NULL)
    {
        delete this->pThumbImage; // binary: vtbl slot 0 (scalar-deleting dtor, flag 1)
        this->pThumbImage = NULL;
    }
    if (this->pTrackImage != NULL)
    {
        delete this->pTrackImage;
        this->pTrackImage = NULL;
    }
}

// vtbl +0x44 @432f60
void dwGuiScrollBar::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    dwRect thumbRect;

    thumbRect.left = 0;
    thumbRect.top = 0;
    thumbRect.right = 0;
    thumbRect.bottom = 0;
    this->GetThumbRect(&thumbRect); // binary quirk: computed even when disabled
    if (this->bEnabled == 0)
        return;
    this->EnsureImages(); // binary: virtual call (vtbl +0x3c)
    if (this->pTrackImage != NULL)
        this->pTrackImage->Blit(pDestBits, this->left, this->top, pClipRect);
    if (this->pThumbImage != NULL)
        this->pThumbImage->Blit(pDestBits, thumbRect.left, thumbRect.top, pClipRect);
    else
        dwImageDraw_FillRect(pDestBits, &thumbRect, dwColormap_transparentIdx, NULL);
}

// @432cc0 (dwGuiScrollBar_SetValue)
void dwGuiScrollBar::SetValue(int newValue)
{
    dwWidgetMsg msg;

    if (this->minValue < this->maxValue)
    {
        if (newValue < this->minValue)
            newValue = this->minValue;
        if (newValue > this->maxValue)
            newValue = this->maxValue;
    }
    else // inverted range
    {
        if (newValue < this->maxValue)
            newValue = this->maxValue;
        if (newValue > this->minValue)
            newValue = this->minValue;
    }
    if (this->value != newValue)
    {
        this->value = newValue;
        this->Invalidate(); // vtbl +0x34
        msg.code = this->msgSetValue;
        msg.pSender = (void*)(intptr_t)this->value;
        msg.param = 0;
        msg.pTarget = NULL;
        dwWidget_DispatchMsg(&msg, NULL);
    }
}

// @432d30 (dwGuiScrollBar_PointToValue)
int dwGuiScrollBar::PointToValue(int16_t x, int16_t y)
{
    int16_t thumbLen;
    int16_t trackLen;
    int16_t start;
    int16_t pos;

    this->EnsureImages(); // binary: virtual call (vtbl +0x3c)
    thumbLen = 5;
    if (this->bVertical == 0)
    {
        if (this->pThumbImage != NULL)
            thumbLen = (int16_t)this->pThumbImage->desc.width;
        trackLen = (int16_t)((this->right - this->left) - thumbLen);
        start = (int16_t)(thumbLen / 2 + this->left);
        pos = x;
    }
    else
    {
        if (this->pThumbImage != NULL)
            thumbLen = (int16_t)this->pThumbImage->desc.height;
        trackLen = (int16_t)((this->bottom - this->top) - thumbLen);
        start = (int16_t)(thumbLen / 2 + this->top);
        pos = y;
    }
    if (pos < start)
        return this->minValue;
    if (pos < (int16_t)(start + trackLen))
        return ((this->maxValue - this->minValue) * (pos - start)) / trackLen + this->minValue;
    return this->maxValue;
}

// @432e20 (dwGuiScrollBar_GetThumbRect)
void dwGuiScrollBar::GetThumbRect(dwRect* pRectOut)
{
    int16_t thumbLen;
    int16_t half;
    int16_t center;

    this->EnsureImages(); // binary: virtual call (vtbl +0x3c)
    pRectOut->left = this->left;
    pRectOut->top = this->top;
    pRectOut->right = this->right;
    pRectOut->bottom = this->bottom;
    thumbLen = 5;
    if (this->bVertical == 0)
    {
        if (this->pThumbImage != NULL)
            thumbLen = (int16_t)this->pThumbImage->desc.width;
        half = (int16_t)(thumbLen / 2);
        center = (int16_t)(half + this->left);
        if (this->maxValue != this->minValue)
        {
            center = (int16_t)(((this->value - this->minValue)
                                * (int16_t)((this->right - thumbLen) - this->left))
                               / (int16_t)((int16_t)this->maxValue - (int16_t)this->minValue)
                     + half + this->left);
        }
        if (this->value == this->minValue)
            center = (int16_t)(half + this->left);
        else if (this->value == this->maxValue)
            center = (int16_t)(this->right - half);
        pRectOut->left = (int16_t)(center - half);
        pRectOut->right = (int16_t)(thumbLen + (center - half));
    }
    else
    {
        if (this->pThumbImage != NULL)
            thumbLen = (int16_t)this->pThumbImage->desc.height;
        half = (int16_t)(thumbLen / 2);
        center = (int16_t)(this->top + half);
        if (this->maxValue != this->minValue)
        {
            center = (int16_t)(((this->value - this->minValue)
                                * (int16_t)((this->bottom - this->top) - thumbLen))
                               / (int16_t)((int16_t)this->maxValue - (int16_t)this->minValue)
                     + this->top + half);
        }
        if (this->value == this->minValue)
            center = (int16_t)(this->top + half);
        else if (this->value == this->maxValue)
            center = (int16_t)(this->bottom - half);
        pRectOut->top = (int16_t)(center - half);
        pRectOut->bottom = (int16_t)(thumbLen + (center - half));
    }
}

// ---------------------------------------------------------------------------
// dwGuiScrollBox (vtbl 0x51f840)
// ---------------------------------------------------------------------------

// @433080 (dwGuiScrollBox_Ctor)
dwGuiScrollBox::dwGuiScrollBox(dwRect* pRect, int scrollMsgCode, char* pFontName,
                               uint8_t textColorIdx, uint8_t highlightColorIdx, int msgSelChanged)
    : dwWidget(pRect)
    , textColorIdx(textColorIdx)
    , bHasSelection(1) // binary quirk: starts "selected" with pSelectedItem == NULL
    , highlightColorIdx(highlightColorIdx)
    , bNeedsScroll(0)
    , scrollMsgCode(scrollMsgCode)
    , itemCount(0)
    , scrollPos(0)
    , pFirstVisible(NULL)
    , items()
    , pSelectedItem(NULL)
    , pFont(NULL)
    , msgSelChanged(msgSelChanged)
    , bDrawBorder(0)
{
    if (pFontName != NULL)
    {
        this->pFont = new dwFont;
        if (this->pFont != NULL)
            dwFont_Load(this->pFont, pFontName);
    }
    this->pFirstVisible = this->items.pSentinel->pNext; // == sentinel (empty)
}

// @433180 (dwGuiScrollBox_Dtor; scalar-deleting wrapper @433160)
dwGuiScrollBox::~dwGuiScrollBox()
{
    dwListNode* pNode;
    dwListNode* pNext;
    dwGuiScrollBoxItem* pItem;

    if (this->pFont != NULL)
        delete this->pFont; // binary: no-op font "dtor" @504190 + free

    // unlink + free every node, deleting its item (strings then the block)
    pNode = this->items.pSentinel->pNext;
    while (pNode != this->items.pSentinel)
    {
        pNext = pNode->pNext;
        pItem = (dwGuiScrollBoxItem*)pNode->pData;
        this->items.UnlinkFreeNode(pNode);
        if (pItem != NULL)
            delete pItem;
        pNode = pNext;
    }
    // (the binary follows with a second payload-deleting sweep + a node-range
    // free — both no-ops on the now-empty ring — then frees the sentinel:)
    this->items.Free();
}

// vtbl +0x08 @433310
int dwGuiScrollBox::OnMouseDown(int16_t x, int16_t y)
{
    dwPoint pt;
    int row;
    dwListNode* pNode;
    dwGuiScrollBoxItem* pItem;
    dwWidgetMsg msg;

    pt.x = x;
    pt.y = y;
    if (x >= this->left && x < this->right && y >= this->top && y < this->bottom)
    {
        row = (y - this->top) / (int)this->pFont->pHeader->lineHeight;
        pNode = this->pFirstVisible;
        for (; row != 0; row--)
        {
            if (pNode == this->items.pSentinel)
                break;
            pNode = pNode->pNext;
        }
        if (pNode != this->items.pSentinel)
        {
            pItem = (dwGuiScrollBoxItem*)pNode->pData;
            this->bHasSelection = 1;
            this->pSelectedItem = pItem;
            msg.code = this->msgSelChanged;
            msg.pSender = pItem->filename.pBuffer;
            msg.param = 0;
            msg.pTarget = NULL;
            dwWidget_DispatchMsg(&msg, NULL);
            this->Invalidate();
        }
        this->bDrawBorder = 1;
        this->Invalidate();
        return 0;
    }
    this->bDrawBorder = 0;
    this->Invalidate();
    return 0;
}

// vtbl +0x18 @4337f0
int dwGuiScrollBox::OnHover(int16_t x, int16_t y)
{
    (void)x; (void)y;
    return this->OnHoverNotify((void*)(intptr_t)this->msgSelChanged);
}

// vtbl +0x1c @433750
int dwGuiScrollBox::OnMessage(dwWidgetMsg* pMsg)
{
    int newPos;
    int delta;
    dwListNode* pNode;

    if (pMsg->code != this->scrollMsgCode)
        return 0;
    newPos = (int)(intptr_t)pMsg->pSender;
    pNode = this->pFirstVisible;
    delta = newPos - this->scrollPos;
    if (delta < 1)
    {
        if (this->bNeedsScroll != 0)
        {
            for (delta = -delta; delta != 0; delta--)
            {
                if (pNode == this->items.pSentinel->pNext) // backward stop: the FIRST node
                    break;
                pNode = pNode->pPrev;
            }
        }
    }
    else if (this->bNeedsScroll != 0)
    {
        for (; delta != 0; delta--)
        {
            if (pNode == this->items.pSentinel)
                break;
            pNode = pNode->pNext;
        }
    }
    if (pNode != this->items.pSentinel)
    {
        this->pFirstVisible = pNode;
        this->scrollPos = newPos;
        this->Invalidate();
    }
    return 0;
}

// vtbl +0x44 @433820
void dwGuiScrollBox::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    dwListNode* pNode;
    dwGuiScrollBoxItem* pItem;
    dwRect rowRect;
    dwRect hlRect;
    dwPoint pos;
    int16_t lineHeight;

    if (this->items.pSentinel != this->items.pSentinel->pNext)
    {
        lineHeight = (int16_t)this->pFont->pHeader->lineHeight;
        rowRect.left = this->left;
        rowRect.top = this->top;
        rowRect.right = this->right;
        rowRect.bottom = (int16_t)(this->top + lineHeight);
        pNode = this->pFirstVisible;
        if (pNode != this->items.pSentinel)
        {
            while (rowRect.top < pClipRect->bottom)
            {
                pItem = (dwGuiScrollBoxItem*)pNode->pData;
                if (this->bHasSelection != 0 && this->pSelectedItem == pItem)
                {
                    hlRect = rowRect;
                    dwRect_Clip(&hlRect, pClipRect);
                    dwImageDraw_FillRect(pDestBits, &hlRect, this->highlightColorIdx, NULL);
                }
                pos.x = rowRect.left;
                pos.y = (int16_t)(rowRect.top + (int16_t)this->pFont->pHeader->bpp); // bpp low byte = first-line y-inset
                dwFont_DrawStringClipped(pDestBits, this->pFont, &pos,
                                         pItem->displayName.pBuffer, this->textColorIdx, pClipRect);
                pNode = pNode->pNext;
                rowRect.top = (int16_t)(rowRect.top + lineHeight);
                rowRect.bottom = (int16_t)(rowRect.bottom + lineHeight);
                if (pNode == this->items.pSentinel)
                    break;
            }
        }
    }
    if (this->bDrawBorder != 0)
        dwImageDraw_FrameRect(pDestBits, this->GetRectPtr(), 7, pClipRect);
}

// @433410 (dwGuiScrollBox_ContainsFile)
int dwGuiScrollBox::ContainsFile(dwString* pFilename)
{
    dwListNode* pNode;
    char* pBasename;

    pNode = this->items.pSentinel->pNext;
    if (pNode == this->items.pSentinel)
        return 0;
    do
    {
        pBasename = ((dwGuiScrollBoxItem*)pNode->pData)->filename.pBuffer;
        dwString_FindFilename(&pBasename);
        if (dwString_Equals(pFilename->pBuffer, pBasename))
            return 1;
        pNode = pNode->pNext;
    } while (pNode != this->items.pSentinel);
    return 0;
}

// @433490 (dwGuiScrollBox_AddItem) — sorted insert by display name
void dwGuiScrollBox::AddItem(char* pFilename, char* pDisplayName)
{
    dwGuiScrollBoxItem* pItem;
    dwListNode* pNode;

    pItem = new dwGuiScrollBoxItem(pFilename, pDisplayName);
    // (binary: an idk_alloc NULL-check skipped everything below; new throws)
    pNode = this->items.pSentinel->pNext;
    while (pNode != this->items.pSentinel)
    {
        if (pItem->displayName.pBuffer == NULL
            || ((dwGuiScrollBoxItem*)pNode->pData)->displayName.pBuffer == NULL)
            break;
        if (dwString_CompareI(pItem->displayName.pBuffer,
                              ((dwGuiScrollBoxItem*)pNode->pData)->displayName.pBuffer) < 1)
            break;
        pNode = pNode->pNext;
    }
    this->items.InsertAfter(pNode->pPrev, pItem); // insert BEFORE pNode
    this->itemCount = this->itemCount + 1;
    this->scrollPos = 0;
    this->pFirstVisible = this->items.pSentinel->pNext;
    this->pSelectedItem = (dwGuiScrollBoxItem*)this->pFirstVisible->pData;
    this->UpdateScrollFlag();
    this->Invalidate();
}

// @4335c0 (dwGuiScrollBox_RemoveSelected)
void dwGuiScrollBox::RemoveSelected()
{
    dwListNode* pNode;
    dwListNode* pNext;
    dwWidgetMsg msg;

    if (this->pSelectedItem == NULL)
        return;
    for (pNode = this->items.pSentinel->pNext; pNode != this->items.pSentinel; pNode = pNode->pNext)
    {
        if ((dwGuiScrollBoxItem*)pNode->pData == this->pSelectedItem)
            break;
    }
    if (pNode == this->items.pSentinel)
        return;
    // the selection moves to the previous node — or the next when the
    // removed node was the first
    if (pNode == this->items.pSentinel->pNext)
        pNext = pNode->pNext;
    else
        pNext = pNode->pPrev;
    this->items.UnlinkFreeNode(pNode);
    this->itemCount = this->itemCount - 1;
    if (this->pSelectedItem != NULL)
        delete this->pSelectedItem; // dwGuiScrollBox_ItemFree @433700 + free
    if (pNext != this->items.pSentinel)
    {
        this->pSelectedItem = (dwGuiScrollBoxItem*)pNext->pData;
        msg.code = this->msgSelChanged;
        msg.pSender = this->pSelectedItem->filename.pBuffer;
        msg.param = 0;
        msg.pTarget = NULL;
    }
    else
    {
        this->pSelectedItem = NULL;
        msg.code = this->msgSelChanged;
        msg.pSender = NULL;
        msg.param = 0;
        msg.pTarget = NULL;
    }
    dwWidget_DispatchMsg(&msg, NULL);
    this->UpdateScrollFlag();
    this->Invalidate();
}

// @433960 (dwGuiScrollBox_UpdateScrollFlag)
void dwGuiScrollBox::UpdateScrollFlag()
{
    if ((uint32_t)((int)(int16_t)(this->bottom - this->top) / (int)this->pFont->pHeader->lineHeight)
        < (uint32_t)this->itemCount)
    {
        this->bNeedsScroll = 1;
        return;
    }
    this->bNeedsScroll = 0;
    this->pFirstVisible = this->items.pSentinel->pNext;
}

// ---------------------------------------------------------------------------
// dwGuiScrollButton (vtbl 0x51f888)
// ---------------------------------------------------------------------------

// @433aa0 (dwGuiScrollButton_Ctor)
dwGuiScrollButton::dwGuiScrollButton(dwRect* pRect, char* pImgUpName, char* pImgDownName, int cmdId)
    : dwWorkshopCtrl(pRect, pImgUpName, NULL, pImgDownName, NULL, cmdId, 0)
{
}

// @433af0 (dwGuiScrollButton_Dtor; scalar-deleting wrapper @433ad0)
dwGuiScrollButton::~dwGuiScrollButton()
{
}

// vtbl +0x08 @433b00
int dwGuiScrollButton::OnMouseDown(int16_t x, int16_t y)
{
    int result;
    dwWidgetMsg msg;

    result = dwWorkshopCtrl::OnMouseDown(x, y); // binary: direct call @4073d0
    if (this->bHot != 0)
    {
        msg.code = this->cmdId;
        msg.pSender = NULL;
        msg.param = 0;
        msg.pTarget = NULL;
        dwWidget_DispatchMsg(&msg, NULL);
    }
    return result;
}

// vtbl +0x0c @433b50
int dwGuiScrollButton::OnMouseUp(int16_t x, int16_t y)
{
    dwWidgetMsg msg;

    (void)x; (void)y;
    if (dwWidget_pMouseTarget == this)
        dwWidget_pMouseTarget = NULL;
    if (this->bPressed != 0)
    {
        this->bPressed = 0;
        this->bHot = 0;
        this->Invalidate(); // vtbl +0x34
        msg.code = this->cmdId;
        msg.pSender = NULL;
        msg.param = 0;
        msg.pTarget = NULL;
        dwWidget_DispatchMsg(&msg, NULL);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// dwGuiTextRollover (vtbls 0x51f928 primary / 0x51f8d8 hyptext subobject)
// ---------------------------------------------------------------------------

// @433bb0 (dwGuiTextRollover_Ctor)
dwGuiTextRollover::dwGuiTextRollover(dwRect* pRect, char* pText, char* pFontName, char* pLinkTarget,
                                     uint8_t color, char* pSndOff, uint8_t colorHot,
                                     char* pSndClick, char* pHoverSnd, int cmdId)
    : dwGuiTextButton(pRect, pText, pFontName, color, pSndOff, colorHot,
                      pSndClick, pHoverSnd, cmdId, /*bAltDraw*/ 0)
    , dwGuiHypText(pRect, NULL, pFontName, color, (char*)"BCO") // binary format string @5294a4
    , linkTarget(pLinkTarget, 0)
{
    this->text.Free();      // dwGuiHypText::text — SetText APPENDS, so Free first
    this->SetText(pText);   // binary: virtual call (hyptext vtbl +0x48)
    this->labelText.Assign(this->text.pBuffer, 0); // button label = the hyptext text
}

// @433cb0 (dwGuiTextRollover_Dtor; scalar-deleting wrapper @433c90;
// hyptext-subobject thunk @433db0) — linkTarget + base dtors, all implicit.
dwGuiTextRollover::~dwGuiTextRollover()
{
}

// vtbl +0x0c @433d50 (hyptext-subobject thunk @433dc0 — Ghidra named it
// dwGuiTextRollover_OnHover2_Thunk, but the slot is OnMouseUp)
int dwGuiTextRollover::OnMouseUp(int16_t x, int16_t y)
{
    dwWidgetMsg msg;

    (void)x; (void)y;
    msg.code = this->cmdId; // dwWorkshopCtrl base (via dwGuiTextButton)
    msg.pSender = this->linkTarget.pBuffer;
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);
    return 1;
}

// vtbl +0x18 @433d30 (hyptext-subobject thunk @433dd0) — forwards to the
// shared { 0x7531, (void*)cmdId } body @439ad0 (= dwWorkshopCtrl::OnHover).
int dwGuiTextRollover::OnHover(int16_t x, int16_t y)
{
    return dwWorkshopCtrl::OnHover(x, y);
}

// vtbl +0x44 @433d80 (hyptext-subobject thunk @433de0)
void dwGuiTextRollover::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    // binary reads the PRIMARY (dwGuiTextButton) subobject's bEnabled
    if (this->dwGuiTextButton::bEnabled != 0)
    {
        dwGuiHypText::Draw(pDestBits, pClipRect);    // binary: direct call @438e20
        dwGuiTextButton::Draw(pDestBits, pClipRect); // binary: direct call @408150
    }
}

// ---------------------------------------------------------------------------
// .drd droid-file serialization (free functions)
// ---------------------------------------------------------------------------

// @432540 (dwGuiWidgets_NodeIndexOf)
extern "C" int dwGuiWidgets_NodeIndexOf(dwList* pList, void* pPayload)
{
    dwListNode* pNode;
    int index;

    index = 0;
    for (pNode = pList->pSentinel->pNext; pNode != pList->pSentinel; pNode = pNode->pNext)
    {
        if (pNode->pData == pPayload)
            break;
        index = index + 1;
    }
    return index; // quirk: == list size when not found
}

// @4328a0 (dwGuiWidgets_NodeAtIndex)
extern "C" void* dwGuiWidgets_NodeAtIndex(dwList* pList, int index)
{
    dwListNode* pNode;

    for (pNode = pList->pSentinel->pNext; pNode != pList->pSentinel; pNode = pNode->pNext)
    {
        if (index == 0)
            return pNode->pData;
        index = index - 1;
    }
    if (index == 0)
        return pNode->pData; // quirk (faithful): index == size reads the
                             // sentinel's uninitialized pData slot
    return NULL;
}

// @4322a0 (dwGuiWidgets_WriteDroidFile) — all prints via dwHS->filePrintf
// (dwHS @0x6b6258 = dwMain_pHS). Sections: VERSION / NAME / PARTS (blueprint
// name + slotIdx16 + position per node) / COLORS (the 9 recorded paint pairs
// per node) / PARENTS (1-based parent node index + attach-slot ordinal).
extern "C" int dwGuiWidgets_WriteDroidFile(stdFile_t file, dwString* pName, dwList* pNodeList)
{
    dwListNode* pNode;
    dwPartNode* pPartNode;
    dwPartNode* pParent;
    unsigned long count;
    rdVector3 pos;
    int parentIdx;
    int slotIdx;
    int i;

    count = 0;
    for (pNode = pNodeList->pSentinel->pNext; pNode != pNodeList->pSentinel; pNode = pNode->pNext)
        count++;

    dwMain_pHS->filePrintf(file, "VERSION 1\n");
    dwMain_pHS->filePrintf(file, "\n");
    if (pName->length == 0)
        dwMain_pHS->filePrintf(file, "NAME Untitled\n");
    else
        dwMain_pHS->filePrintf(file, "NAME %s\n", pName->pBuffer);
    dwMain_pHS->filePrintf(file, "\n");

    dwMain_pHS->filePrintf(file, "PARTS %lu\n", count);
    for (pNode = pNodeList->pSentinel->pNext; pNode != pNodeList->pSentinel; pNode = pNode->pNext)
    {
        pPartNode = (dwPartNode*)pNode->pData;
        pPartNode->GetPosition(&pos);
        dwMain_pHS->filePrintf(file, "%s %lu %f %f %f\n",
                               pPartNode->pPart->name.pBuffer,
                               (unsigned long)(uint16_t)pPartNode->slotIdx16,
                               pos.x, pos.y, pos.z);
    }

    dwMain_pHS->filePrintf(file, "\n");
    dwMain_pHS->filePrintf(file, "COLORS\n");
    for (pNode = pNodeList->pSentinel->pNext; pNode != pNodeList->pSentinel; pNode = pNode->pNext)
    {
        pPartNode = (dwPartNode*)pNode->pData;
        for (i = 0; i < 9; i++)
        {
            dwMain_pHS->filePrintf(file, "  %lu %lu",
                                   (unsigned long)pPartNode->aContacts[i][0],
                                   (unsigned long)pPartNode->aContacts[i][1]);
        }
        dwMain_pHS->filePrintf(file, "\n");
    }

    dwMain_pHS->filePrintf(file, "\n");
    dwMain_pHS->filePrintf(file, "PARENTS\n");
    // Faithful register quirk: the binary only sets the slot ordinal inside
    // the attached-node branch, so a detached/root node re-prints the
    // PREVIOUS node's value (+1). Carried across iterations here too.
    slotIdx = -1;
    for (pNode = pNodeList->pSentinel->pNext; pNode != pNodeList->pSentinel; pNode = pNode->pNext)
    {
        pPartNode = (dwPartNode*)pNode->pData;
        parentIdx = -1;
        if (pPartNode->partType != DW_PARTTYPE_NONE && pPartNode->pAttachData != NULL)
        {
            pParent = pPartNode->pAttachData;
            parentIdx = dwGuiWidgets_NodeIndexOf(pNodeList, pParent);
            // Find the node's attach slot by ADDRESS (== slotCount when the
            // address never matches — faithful).
            for (slotIdx = 0; slotIdx < pParent->slotCount; slotIdx++)
            {
                if (&pParent->aSlots[slotIdx] == pPartNode->pAttachSlot)
                    break;
            }
        }
        dwMain_pHS->filePrintf(file, "%lu %lu\n",
                               (unsigned long)(parentIdx + 1), (unsigned long)(slotIdx + 1));
    }

    dwMain_pHS->filePrintf(file, "\n");
    return 1;
}

// @4325d0 (dwGuiWidgets_ReadDroidFile) — rebuild the part tree from an open
// .drd dwConfFile. Returns 0 when any referenced blueprint is missing or
// locked (the parse still consumes the remaining PARTS lines, as in the
// binary, and the outer keyword loop then stops).
extern "C" int dwGuiWidgets_ReadDroidFile(dwConfFile* pConf, dwString* pNameOut, dwList* pNodeList)
{
    dwListNode* pNode;
    dwPartNode* pPartNode;
    dwPartNode* pNewNode;
    dwPartNode* pParent;
    dwPart* pBp;
    dwPartSlot* pSlot;
    char* pTok;
    uint32_t count;
    uint32_t slotVal;
    uint32_t a, b;
    uint32_t p, s;
    rdVector3 pos;
    int bOk;
    int i;

    bOk = 1;
    while (!pConf->bEof && bOk)
    {
        dwConfFile_ReadLine(pConf);
        pTok = dwConfFile_NextToken(pConf);
        if (dwString_Equals(pTok, "END")) // @528470
            break;
        if (dwString_Equals(pTok, "VERSION"))
        {
            // ignored
        }
        else if (dwString_Equals(pTok, "NAME"))
        {
            if (pNameOut != NULL)
                pNameOut->AssignCStr(pConf->pCursor); // REST of the line
        }
        else if (dwString_Equals(pTok, "PARTS"))
        {
            count = 0;
            dwConfFile_ParseULong(pConf, &count);
            for (; count != 0; count--)
            {
                dwConfFile_ReadLine(pConf);
                pTok = dwConfFile_NextToken(pConf);
                slotVal = 0;
                dwConfFile_ParseULong(pConf, &slotVal);
                pos.x = pos.y = pos.z = 0.0f;
                dwConfFile_ParseFloat(pConf, &pos.x);
                dwConfFile_ParseFloat(pConf, &pos.y);
                dwConfFile_ParseFloat(pConf, &pos.z);
                pBp = dwPart_FindBlueprint(pTok);
                if (pBp == NULL || pBp->bAvailable == 0)
                {
                    bOk = 0; // missing/locked blueprint (keep consuming lines)
                    continue;
                }
                pNewNode = pBp->CreateNode();
                if (pNewNode != NULL)
                {
                    pNewNode->slotIdx16 = (int16_t)(pNewNode->slotIdx16 + (int16_t)slotVal);
                    pNewNode->Translate(&pos);
                    pNodeList->InsertAfter(pNodeList->pSentinel->pPrev, pNewNode); // push-back
                }
            }
        }
        else if (dwString_Equals(pTok, "COLORS"))
        {
            for (pNode = pNodeList->pSentinel->pNext; pNode != pNodeList->pSentinel; pNode = pNode->pNext)
            {
                dwConfFile_ReadLine(pConf);
                pPartNode = (dwPartNode*)pNode->pData;
                for (i = 0; i < 9; i++)
                {
                    a = 0;
                    b = 0;
                    dwConfFile_ParseULong(pConf, &a);
                    dwConfFile_ParseULong(pConf, &b);
                    if (a != b)
                        pPartNode->CollectContacts((int)a, (int)b); // "paint material a -> color b"
                }
            }
        }
        else if (dwString_Equals(pTok, "PARENTS"))
        {
            for (pNode = pNodeList->pSentinel->pNext; pNode != pNodeList->pSentinel; pNode = pNode->pNext)
            {
                dwConfFile_ReadLine(pConf);
                p = 0;
                s = 0;
                dwConfFile_ParseULong(pConf, &p);
                dwConfFile_ParseULong(pConf, &s);
                if (p != 0)
                {
                    p--;
                    s--;
                    pParent = (dwPartNode*)dwGuiWidgets_NodeAtIndex(pNodeList, (int)p);
                    // Note: the binary computes the slot address before the
                    // NULL check; ordered NULL-check-first here (same result).
                    if (pParent != NULL)
                    {
                        pSlot = pParent->aSlots + (int32_t)s;
                        ((dwPartNode*)pNode->pData)->AttachToSlot(pParent, pSlot);
                    }
                }
            }
        }
    }
    return bOk;
}

// @432580 (dwGuiWidgets_SaveDroidToFile)
extern "C" int dwGuiWidgets_SaveDroidToFile(const char* pPath, dwString* pName, dwList* pNodeList)
{
    int result;
    stdFile_t file;

    result = 0;
    file = dwMain_pHS->fileOpen(pPath, "wt");
    if (file != 0)
    {
        result = dwGuiWidgets_WriteDroidFile(file, pName, pNodeList);
        dwMain_pHS->fileClose(file);
    }
    return result;
}

// @4328f0 (dwGuiWidgets_LoadDroidFromFile) — note: no open-failure check in
// the binary; a missing file simply parses as immediate EOF.
extern "C" int dwGuiWidgets_LoadDroidFromFile(const char* pPath, dwString* pNameOut, dwList* pNodeList)
{
    int result;
    dwConfFile conf;

    dwConfFile_Open(&conf, pPath);
    result = dwGuiWidgets_ReadDroidFile(&conf, pNameOut, pNodeList);
    dwConfFile_Close(&conf);
    return result;
}
