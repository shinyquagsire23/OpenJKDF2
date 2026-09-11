// dwGuiWidgetBar — the WIDGETBAR sliding icon+label toolbar (dwGuiWidgetBar
// + dwGuiBarItem). See Dw/dwGuiWidgetBar.h for the class/selection notes.
//
// Decompiled from DroidWorks.exe, unit range 0x43b4c0-0x43bfff (the
// 0x43c040/0x43c170 COMDATs past the end belong to dwWidgetGroup/dwList).
//
// No module statics — no dwGuiWidgetBar_Startup needed (soft-reset rule).

#include "Dw/dwGuiWidgetBar.h"
#include "Dw/dwSound.h"

#include <stdlib.h>

// ---------------------------------------------------------------------------
// dwGuiBarItem (vtbl 0x51ff48)
// ---------------------------------------------------------------------------

// @43b4c0 (dwGuiWidgetBar_ItemCtor)
dwGuiBarItem::dwGuiBarItem(dwWidget* pChildWidget, dwImage* pImage, char* pText,
                           char* pFontName, uint8_t color, int padTop, int padSide)
    : dwWcChildDecorator(pChildWidget) // dwWidget(child's rect) + pChild
    , pFont(NULL)
    , color(color)
    , label(pText, 0)
    , pImage(pImage)
    , padTop(padTop)
    , padSide(padSide)
    , scrollPos(0.0f) // Note: not written by the binary ctor (anim fields below are)
    , animCurX(0)
    , animCurY(0)
    , animTgtX(0)
    , animTgtY(0)
{
    if (pFontName != NULL && *pFontName != '\0')
    {
        this->pFont = new dwFont;
        if (this->pFont != NULL)
            dwFont_Load(this->pFont, pFontName);
    }
    // the icon sizes the item
    if (this->pImage != NULL)
    {
        this->left = 0;
        this->top = 0;
        this->right = (int16_t)this->pImage->desc.width;
        this->bottom = (int16_t)this->pImage->desc.height;
    }
    // inset the child: label band on top, side/bottom margins (the binary
    // writes the child's rect fields directly, no Move)
    pChildWidget->left = (int16_t)(this->left + (int16_t)this->padSide);
    pChildWidget->top = (int16_t)(this->top + (int16_t)this->padTop);
    pChildWidget->right = (int16_t)(this->right - (int16_t)this->padSide);
    pChildWidget->bottom = (int16_t)(this->bottom - (int16_t)this->padSide);
}

// @43b620 (dwGuiWidgetBar_ItemDtor; scalar-deleting wrapper @43b600)
dwGuiBarItem::~dwGuiBarItem()
{
    if (this->pFont != NULL)
    {
        delete this->pFont; // binary: no-op font "dtor" @504190 + free
        this->pFont = NULL;
    }
    if (this->pImage != NULL)
    {
        delete this->pImage; // binary: vtbl slot 0 (scalar-deleting dtor, flag 1)
        this->pImage = NULL;
    }
    // label freed by the member dtor; the dwWcChildDecorator base dtor then
    // FreeImages()es and deletes pChild (binary order preserved).
}

// vtbl +0x14 @43b6e0 (dwGuiWidgetBar_ItemUpdate) — 1000.0f px/s @0x51ff40
void dwGuiBarItem::Update(float dt)
{
    int16_t step;
    int16_t dx;
    int16_t dy;

    if (this->animTgtY != this->top || this->animTgtX != this->left)
    {
        this->scrollPos = this->scrollPos + dt;
        step = (int16_t)(int32_t)(this->scrollPos * 1000.0f);
        dx = (int16_t)(this->animTgtX - this->animCurX);
        dy = (int16_t)(this->animTgtY - this->animCurY);
        if (dx < 0 && step < -dx)
            dx = (int16_t)-step;
        else if (dx > 0 && step < dx)
            dx = step;
        if (dy < 0 && step < -dy)
            dy = (int16_t)-step;
        else if (dy > 0 && step < dy)
            dy = step;
        this->Invalidate(); // vtbl +0x34
        // virtual Move (vtbl +0x28) — the decorator override moves the child too
        this->Move((int16_t)((dx - this->left) + this->animCurX),
                   (int16_t)((dy - this->top) + this->animCurY));
        this->Invalidate();
    }
    this->pChild->Update(dt);
}

// vtbl +0x44 @43b7a0 (dwGuiWidgetBar_ItemDraw)
void dwGuiBarItem::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    dwPoint pos;

    this->EnsureImages(); // vtbl +0x3c (decorator: forwards to the child)
    if (this->pImage != NULL)
        this->pImage->Blit(pDestBits, this->left, this->top, pClipRect);
    if (this->label.length != 0 && this->pFont != NULL)
    {
        pos.x = (int16_t)(this->left + 3);
        pos.y = (int16_t)(this->top + (int16_t)this->pFont->pHeader->bpp // low byte = first-line y-inset
                          + (int16_t)((int16_t)(this->padTop - (int16_t)this->pFont->pHeader->lineHeight) / 2)
                          - 1);
        dwFont_DrawStringClipped(pDestBits, this->pFont, &pos,
                                 this->label.pBuffer, this->color, pClipRect);
    }
    this->pChild->DrawChild(pDestBits, pClipRect);
}

// @43b6c0 (dwGuiWidgetBar_ItemSetScrollTarget)
void dwGuiBarItem::SetScrollTarget(dwPoint* pPos)
{
    this->scrollPos = 0.0f;
    this->animCurX = this->left;
    this->animCurY = this->top;
    this->animTgtX = pPos->x;
    this->animTgtY = pPos->y;
}

// ---------------------------------------------------------------------------
// dwGuiWidgetBar (vtbl 0x51ff90)
// ---------------------------------------------------------------------------

// @43b840 (dwGuiWidgetBar_Ctor)
dwGuiWidgetBar::dwGuiWidgetBar(dwRect* pRect)
    : dwWidget(pRect)
    , items()
    , pSelectedItem(NULL)
{
}

// @43b8d0 (dwGuiWidgetBar_Dtor; scalar-deleting wrapper @43b8b0)
dwGuiWidgetBar::~dwGuiWidgetBar()
{
    dwListNode* pNode;
    dwListNode* pNext;
    dwGuiBarItem* pItem;

    dwGuiWidgetBar::FreeImages(); // binary: direct call to the @43c040 broadcast

    pNode = this->items.pSentinel->pNext;
    while (pNode != this->items.pSentinel)
    {
        pNext = pNode->pNext;
        pItem = (dwGuiBarItem*)pNode->pData;
        this->items.UnlinkFreeNode(pNode);
        if (pItem != NULL)
            delete pItem; // binary: vtbl slot 0 (scalar-deleting dtor, flag 1)
        pNode = pNext;
    }
    // (the binary follows with a second node sweep — a no-op on the empty
    // ring — then frees the sentinel:)
    this->items.Free();
}

// vtbl +0x04 @43be80
int dwGuiWidgetBar::OnMouseMove(int16_t x, int16_t y)
{
    dwPoint pt;

    pt.x = x;
    pt.y = y;
    if (this->pSelectedItem->bEnabled != 0) // unguarded deref — binary behavior
    {
        if (this->pSelectedItem->ContainsPoint(&pt)) // vtbl +0x2c
            return this->pSelectedItem->OnMouseMove(x, y);
    }
    return 0;
}

// vtbl +0x08 @43bd70
int dwGuiWidgetBar::OnMouseDown(int16_t x, int16_t y)
{
    dwPoint pt;
    dwListNode* pNode;
    dwGuiBarItem* pItem;
    dwGuiBarItem* pSel;

    pt.x = x;
    pt.y = y;
    // find the enabled item whose LABEL BAND contains the point
    pNode = this->items.pSentinel->pNext;
    while (pNode != this->items.pSentinel)
    {
        pItem = (dwGuiBarItem*)pNode->pData;
        if (pItem->bEnabled != 0)
        {
            if (pItem->ContainsPoint(&pt) && (y - pItem->top) < (int16_t)pItem->padTop)
                break;
        }
        pNode = pNode->pNext;
    }
    pSel = this->pSelectedItem;
    // clicking the selected item's own band selects the PREVIOUS item
    // (quirk kept: the sentinel's pData slot is read when nothing was hit)
    if ((dwGuiBarItem*)pNode->pData == pSel && pNode != this->items.pSentinel->pNext)
        pNode = pNode->pPrev;
    if (pNode != this->items.pSentinel)
    {
        this->ScrollToItem((dwGuiBarItem*)pNode->pData);
        dwSound_PlayRestart("WInfoCard.wav");
        return 0;
    }
    if (pSel->bEnabled != 0) // unguarded deref — binary behavior
    {
        if (pSel->ContainsPoint(&pt))
            return this->pSelectedItem->OnMouseDown(x, y);
    }
    return 0;
}

// vtbl +0x0c @43bed0
int dwGuiWidgetBar::OnMouseUp(int16_t x, int16_t y)
{
    dwPoint pt;

    pt.x = x;
    pt.y = y;
    if (this->pSelectedItem->bEnabled != 0) // unguarded deref — binary behavior
    {
        if (this->pSelectedItem->ContainsPoint(&pt))
            return this->pSelectedItem->OnMouseUp(x, y);
    }
    return 0;
}

// vtbl +0x10 @43bf20
int dwGuiWidgetBar::OnKey(int key, int repeat)
{
    if (this->pSelectedItem->bEnabled != 0) // unguarded deref — binary behavior
        return this->pSelectedItem->OnKey(key, repeat);
    return 0;
}

// vtbl +0x14 @43bd20
void dwGuiWidgetBar::Update(float dt)
{
    dwListNode* pNode;

    for (pNode = this->items.pSentinel->pNext; pNode != this->items.pSentinel; pNode = pNode->pNext)
    {
        if (((dwGuiBarItem*)pNode->pData)->bEnabled != 0)
            ((dwGuiBarItem*)pNode->pData)->Update(dt);
    }
}

// vtbl +0x18 @43bf80
int dwGuiWidgetBar::OnHover(int16_t x, int16_t y)
{
    dwPoint pt;
    dwListNode* pNode;
    dwGuiBarItem* pItem;

    pt.x = x;
    pt.y = y;
    pNode = this->items.pSentinel->pNext;
    while (pNode != this->items.pSentinel)
    {
        pItem = (dwGuiBarItem*)pNode->pData;
        if (pItem->bEnabled != 0)
        {
            if (pItem->ContainsPoint(&pt) && (y - pItem->top) < (int16_t)pItem->padTop)
                break;
        }
        pNode = pNode->pNext;
    }
    if (pNode != this->items.pSentinel)
        return ((dwGuiBarItem*)pNode->pData)->OnHover(x, y);
    return this->pSelectedItem->OnHover(x, y); // unguarded deref — binary behavior
}

// vtbl +0x1c @43bf40
int dwGuiWidgetBar::OnMessage(dwWidgetMsg* pMsg)
{
    dwListNode* pNode;
    int result;

    result = 0;
    for (pNode = this->items.pSentinel->pNext; pNode != this->items.pSentinel; pNode = pNode->pNext)
    {
        if (((dwGuiBarItem*)pNode->pData)->bEnabled != 0)
            result = ((dwGuiBarItem*)pNode->pData)->OnMessage(pMsg);
        if (result != 0)
            break;
    }
    return result;
}

// vtbl +0x3c @4447e0 (the shared dwWidgetGroup_EnsureImages broadcast body,
// reused by this vtable over the +0x10 list)
void dwGuiWidgetBar::EnsureImages()
{
    dwListNode* pNode;

    for (pNode = this->items.pSentinel->pNext; pNode != this->items.pSentinel; pNode = pNode->pNext)
        ((dwGuiBarItem*)pNode->pData)->EnsureImages();
}

// vtbl +0x40 @43c040 (the shared dwWidgetGroup_FreeChildImages broadcast body)
void dwGuiWidgetBar::FreeImages()
{
    dwListNode* pNode;

    for (pNode = this->items.pSentinel->pNext; pNode != this->items.pSentinel; pNode = pNode->pNext)
        ((dwGuiBarItem*)pNode->pData)->FreeImages();
}

// vtbl +0x44 @43bc70
void dwGuiWidgetBar::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    dwRect band;
    dwRect clipped;
    dwListNode* pNode;
    int16_t bandBottom;

    band.left = this->left;
    band.top = this->top;
    band.right = this->right;
    band.bottom = this->bottom;
    pNode = this->items.pSentinel->pNext;
    while (pNode != this->items.pSentinel)
    {
        if (pNode->pNext == this->items.pSentinel)
            bandBottom = this->bottom;
        else
            bandBottom = ((dwGuiBarItem*)pNode->pNext->pData)->top;
        band.bottom = bandBottom;
        clipped = band;
        dwRect_Clip(&clipped, pClipRect);
        ((dwGuiBarItem*)pNode->pData)->DrawChild(pDestBits, &clipped);
        pNode = pNode->pNext;
        band.top = bandBottom;
    }
}

// @43b9f0 (dwGuiWidgetBar_AddItem)
dwGuiBarItem* dwGuiWidgetBar::AddItem(dwWidget* pInner, char* pImageFile, char* pText,
                                      char* pFontName, uint8_t color, int padTop, int padSide)
{
    dwImage* pImage;
    dwGuiBarItem* pItem;
    dwListNode* pNode;
    int16_t y;

    pImage = NULL;
    if (pImageFile != NULL && *pImageFile != '\0')
        pImage = dwImage_LoadFile(pImageFile); // NULL-tolerant (P8 stub)
    pItem = new dwGuiBarItem(pInner, pImage, pText, pFontName, color, padTop, padSide);
    // (binary: on idk_alloc failure it deleted pImage + pInner and returned
    // NULL; new throws, so that path is unreachable here)
    this->items.InsertAfter(this->items.pSentinel->pPrev, pItem); // push-back

    // re-stack every item at the bar left, y advancing by each padTop
    y = this->top;
    pNode = this->items.pSentinel->pNext;
    while (pNode != this->items.pSentinel)
    {
        dwGuiBarItem* pCur = (dwGuiBarItem*)pNode->pData;
        pCur->Move((int16_t)(this->left - pCur->left), (int16_t)(y - pCur->top)); // virtual +0x28
        y = (int16_t)(y + (int16_t)pCur->padTop);
        pNode = pNode->pNext;
    }
    this->ScrollToItem(pItem);
    return pItem;
}

// @43bb40 (dwGuiWidgetBar_SelectIndex)
void dwGuiWidgetBar::SelectIndex(int index)
{
    dwListNode* pNode;

    for (pNode = this->items.pSentinel->pNext; pNode != this->items.pSentinel; pNode = pNode->pNext)
    {
        if (index == 0)
            break;
        index = index - 1;
    }
    if (index == 0 && pNode != this->items.pSentinel)
        this->ScrollToItem((dwGuiBarItem*)pNode->pData);
}

// @43bba0 (dwGuiWidgetBar_ScrollToItem)
void dwGuiWidgetBar::ScrollToItem(dwGuiBarItem* pItem)
{
    dwPoint pos;
    dwListNode* pNode;
    dwGuiBarItem* pCur;

    if (pItem == this->pSelectedItem)
        return;
    if (this->pSelectedItem != NULL)
        this->pSelectedItem->Invalidate();

    // items ABOVE the target stack from the bar top downward
    pos.x = this->left;
    pos.y = this->top;
    pNode = this->items.pSentinel->pNext;
    while (pNode != this->items.pSentinel)
    {
        pCur = (dwGuiBarItem*)pNode->pData;
        if (pCur == pItem)
            break;
        pCur->SetScrollTarget(&pos);
        pos.y = (int16_t)(pos.y + (int16_t)pCur->padTop);
        pNode = pNode->pNext;
    }
    if (pNode == this->items.pSentinel)
        return; // pItem not in the list — selection unchanged (binary quirk:
                // the above-items were still retargeted)

    this->pSelectedItem = pItem;
    pItem->SetScrollTarget(&pos);

    // items BELOW the target stack from the bar bottom upward
    pos.y = this->bottom;
    pNode = this->items.pSentinel->pPrev;
    while ((dwGuiBarItem*)pNode->pData != this->pSelectedItem)
    {
        pCur = (dwGuiBarItem*)pNode->pData;
        pos.y = (int16_t)(pos.y - (int16_t)pCur->padTop);
        pCur->SetScrollTarget(&pos);
        pNode = pNode->pPrev;
    }
}
