// dwGuiList / dwGuiSpeech / dwGuiDroidDance — DroidWorks in-game GUI controls.
// Decompiled from DroidWorks.exe, unit range 0x409fc0-0x40adbf. See dwGuiList.h
// for the class map. Verifiably C++ (vtables, ctor/dtor pairs, MSVC EH frames).

#include "Dw/dwGuiList.h"

#include "Dw/dwImageDraw.h"   // ShadeRect / FrameRect / FillTriBlend
#include "Dw/dwCursor.h"      // dwCursor_pos
#include "Dw/dwSound.h"       // dwSound_Stop + dwSound_pManager->FreeAllSamples()
#include "Dw/dwWidget.h"      // dwWidget_DispatchMsg / dwWidget_pMouseTarget
#include "Dw/dwPart.h"        // dwPartNode anim methods
#include "Dw/dwDroidStats.h"  // dwDroidStats_AutoBuildRandom

#include "jk.h"
#include "stdPlatform.h"
#include "globals.h"          // sithTime_g_msecGameTime (binary sithTime_curMs @0x541d48)

#include <new>       // placement new (raw-allocated list items / factory objects)
#include <stdlib.h>  // malloc / free / rand

// =============================================================================
// dwGuiList
// =============================================================================

// True-vs-signature note: the binary's dwGuiList_Ctor takes (pRect, fontName,
// baseColor, colorHi, colorFlag2, pStyle). The dwMain.c placeholder + its
// dwGuiInGame caller reversed the first two into (pRect, a=baseColor as float,
// fontName, colorHi, colorFlag2, pStyle) — we keep that signature so the caller
// links unchanged, mapping `a` -> base color and `pFontName` -> font name. The
// runtime effect is identical to the binary.
// @409fc0
dwGuiList::dwGuiList(dwRect* pRect, float a, char* pFontName, uint8_t colorHi,
                     uint8_t colorFlagParam, void* pStyle)
    : dwGuiHypText(pRect, /*pNotify*/NULL, pFontName, (uint8_t)a,
                   dwGuiHypText_HAlignLeft, dwGuiHypText_VAlignTop,
                   dwGuiHypText_WrapWords, dwGuiHypText_DrawGlyphsNormal, NULL)
{
    // Self-linked heap sentinel (binary idk_alloc(0xc)).
    this->pItems = (dwListNode*)malloc(sizeof(dwListNode));
    this->pItems->pNext = this->pItems;
    this->pItems->pPrev = this->pItems;

    this->colorHighlight = colorHi;
    this->colorFlag2 = colorFlagParam;
    this->bLayoutInvalid = 0;
    this->drawStyle = *(uint32_t*)pStyle;
    this->pHoverItem = NULL;
    this->pPressedItem = NULL;

    // vtable is dwGuiList's automatically (C++). Inset the text area by 2px.
    this->layoutRect.left   = (int16_t)(pRect->left + 2);
    this->layoutRect.top    = (int16_t)(pRect->top + 2);
    this->layoutRect.right  = (int16_t)(pRect->right - 2);
    this->layoutRect.bottom = (int16_t)(pRect->bottom - 2);
}

// @40a500 (dwGuiList_ItemFree) — free an item's two dwStrings (textB then
// textA, matching the binary order).
static void dwGuiList_ItemFree(dwGuiListItem* pItem)
{
    pItem->textB.Free();
    pItem->textA.Free();
}

// @40a0c0 (scalar-deleting wrapper @40a0a0)
dwGuiList::~dwGuiList()
{
    dwListNode* pSentinel = this->pItems;
    dwListNode* n = pSentinel->pNext;
    while (n != pSentinel)
    {
        dwGuiListItem* pItem = (dwGuiListItem*)n->pData;
        dwListNode* pNext = n->pNext;
        n->pPrev->pNext = n->pNext;
        n->pNext->pPrev = n->pPrev;
        n->pNext = NULL;
        n->pPrev = NULL;
        free(n);
        if (pItem)
        {
            dwGuiList_ItemFree(pItem);
            free(pItem);
        }
        n = pNext;
    }
    free(this->pItems);
    // base ~dwGuiHypText runs automatically.
}

// @40a200
void dwGuiList::Relayout()
{
    const int16_t x0 = this->layoutRect.left;
    const int16_t x1 = this->layoutRect.right;
    const int width = (int)(int16_t)(this->layoutRect.right - this->layoutRect.left);
    int16_t y = this->layoutRect.top;

    // Free every existing line run (keep the sentinel).
    ((dwList*)&this->pRuns)->FreeNodeRange((dwListNode*)this->pRuns->pNext,
                                           (dwListNode*)this->pRuns);

    // Position each item, wrapping its textA into the shared run ring.
    for (dwListNode* it = this->pItems->pNext; it != this->pItems; it = it->pNext)
    {
        dwGuiListItem* pItem = (dwGuiListItem*)it->pData;
        dwGuiHypTextRun* pTail = this->pRuns->pPrev; // tail before wrap
        this->pfnWrap(&pItem->textA, this->pFont, width, &this->pRuns);

        int16_t yBot = y;
        for (dwGuiHypTextRun* r = pTail->pNext; r != this->pRuns; r = r->pNext)
            yBot = (int16_t)(yBot + (int16_t)this->pFont->pHeader->lineHeight);

        pItem->left   = x0;
        pItem->top    = y;
        pItem->right  = x1;
        pItem->bottom = yBot;
        y = yBot;
    }

    // H-align each run, then reset its live draw fields.
    for (dwGuiHypTextRun* r = this->pRuns->pNext; r != this->pRuns; r = r->pNext)
    {
        this->pfnHAlign(r, width);
        r->startChar = 0;
        r->drawLen = r->len;
        r->drawX = (int16_t)r->xOffset;
    }

    // Let the inline elements re-layout against the fresh runs.
    for (dwListNode* e = this->elements.pSentinel->pNext;
         e != this->elements.pSentinel; e = e->pNext)
    {
        dwGuiHypTextElem* pElem = (dwGuiHypTextElem*)e->pData;
        pElem->Layout(this, &this->pRuns, this->pFont);
    }

    this->Invalidate();
    this->pHoverItem = NULL;
    this->UpdateHoverItem(dwCursor_pos.x, dwCursor_pos.y);
}

// @40a3b0
void dwGuiList::Clear()
{
    dwListNode* pSentinel = this->pItems;
    dwListNode* n = pSentinel->pNext;
    while (n != pSentinel)
    {
        dwGuiListItem* pItem = (dwGuiListItem*)n->pData;
        dwListNode* pNext = n->pNext;
        n->pPrev->pNext = n->pNext;
        n->pNext->pPrev = n->pPrev;
        n->pNext = NULL;
        n->pPrev = NULL;
        free(n);
        if (pItem)
        {
            dwGuiList_ItemFree(pItem);
            free(pItem);
        }
        n = pNext;
    }
    this->Relayout();
    this->bLayoutInvalid = 0;
}

// @40a430
void dwGuiList::AddItem(void* pData, int val, char* pTextA, char* pTextB)
{
    dwGuiListItem* pItem = (dwGuiListItem*)malloc(sizeof(dwGuiListItem));
    if (pItem)
    {
        pItem->data = pData;
        pItem->val = val;
        new (&pItem->textA) dwString(pTextA, 0);
        new (&pItem->textB) dwString(pTextB, 0);
        pItem->left = 0;
        pItem->top = 0;
        pItem->right = 0;
        pItem->bottom = 0;

        ((dwList*)&this->pItems)->InsertAfter(this->pItems->pPrev, pItem); // push-back
        this->Relayout();
    }
}

// @40a550
void dwGuiList::UpdateHoverItem(int16_t x, int16_t y)
{
    dwListNode* pSentinel = this->pItems;
    this->pHoverItem = NULL;
    for (dwListNode* n = pSentinel->pNext; n != pSentinel; n = n->pNext)
    {
        dwGuiListItem* pItem = (dwGuiListItem*)n->pData;
        if (x >= pItem->left && x < pItem->right && y >= pItem->top && y < pItem->bottom)
        {
            this->pHoverItem = pItem;
            this->Invalidate();
            return;
        }
    }
}

// @40a5e0
int dwGuiList::OnMouseMove(int16_t x, int16_t y)
{
    if (!this->bLayoutInvalid)
    {
        dwGuiListItem* pHover = this->pHoverItem;
        if (pHover && x >= pHover->left && x < pHover->right &&
            y >= pHover->top && y < pHover->bottom)
            return 0; // still over the current item — nothing to do
        this->UpdateHoverItem(x, y);
    }
    return 0;
}

// @40a630
int dwGuiList::OnMouseDown(int16_t x, int16_t y)
{
    if (this->bLayoutInvalid)
        return 0;
    dwGuiListItem* pHover = this->pHoverItem;
    if (!(pHover && x >= pHover->left && x < pHover->right &&
          y >= pHover->top && y < pHover->bottom))
        this->UpdateHoverItem(x, y);
    this->pPressedItem = this->pHoverItem;
    dwWidget_pMouseTarget = this;
    return 1;
}

// @40a690
int dwGuiList::OnMouseUp(int16_t x, int16_t y)
{
    if (dwWidget_pMouseTarget == this)
        dwWidget_pMouseTarget = NULL;

    if (this->pPressedItem != NULL && this->bLayoutInvalid == 0)
    {
        this->UpdateHoverItem(x, y);
        if (this->pHoverItem == this->pPressedItem)
        {
            this->bLayoutInvalid = 1;
            dwWidgetMsg msg;
            msg.code = 0x1f40;
            msg.pSender = this->pHoverItem;
            msg.param = 0;
            msg.pTarget = NULL;
            dwWidget_DispatchMsg(&msg, NULL);
        }
    }
    return 0;
}

// @40a710
void dwGuiList::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    if (this->pItems == this->pItems->pNext) // empty list
        return;

    dwRect* pWidgetRect = this->GetRectPtr();
    dwImageDraw_ShadeRect(pDestBits, pWidgetRect, 0x28);
    dwImageDraw_FrameRect(pDestBits, pWidgetRect, 0x46, pClipRect);
    dwRect fullScreen; fullScreen.left = 0; fullScreen.top = 0;
    fullScreen.right = 0x280; fullScreen.bottom = 0x1e0;
    dwImageDraw_FillTriBlend(pDestBits, 0x46, (dwPoint*)&this->drawStyle,
                             (dwPoint*)pWidgetRect, &fullScreen);

    dwRect clip = *pClipRect;
    dwRect_Clip(&clip, &this->layoutRect);
    if ((int16_t)(clip.right - clip.left) == 0 || (int16_t)(clip.bottom - clip.top) == 0)
        return;

    int16_t y = (int16_t)(this->layoutRect.top + (int16_t)this->pFont->pHeader->bpp);
    for (dwGuiHypTextRun* r = this->pRuns->pNext; r != this->pRuns; r = r->pNext)
    {
        dwGuiListItem* pHover = this->pHoverItem;
        int16_t px = (int16_t)(r->drawX + this->layoutRect.left);
        dwPoint pos; pos.x = px; pos.y = y;

        uint8_t color;
        if (pHover && px >= pHover->left && px < pHover->right &&
            y >= pHover->top && y < pHover->bottom)
            color = this->colorHighlight;
        else
            color = this->color;

        this->pfnDrawGlyphs(pDestBits, &pos, this->pFont, color, r, &clip);
        y = (int16_t)(pos.y + (int16_t)this->pFont->pHeader->lineHeight);
    }
}

// =============================================================================
// dwGuiSpeech
// =============================================================================

// @40a8a0
dwGuiSpeech::dwGuiSpeech(dwRect* pRect, int notify, char* pFontName, uint32_t color, void* pStyle)
    : dwGuiHypText(pRect, (void*)(intptr_t)notify, pFontName, (uint8_t)color,
                   dwGuiHypText_HAlignLeft, dwGuiHypText_VAlignTop,
                   dwGuiHypText_WrapWords, dwGuiHypText_DrawGlyphsNormal, NULL)
{
    this->drawStyle = *(uint32_t*)pStyle;
    this->pTimedItem = NULL;
    // soundName default-constructs (member). vtable is dwGuiSpeech's.
    this->layoutRect.left   = (int16_t)(pRect->left + 2);
    this->layoutRect.top    = (int16_t)(pRect->top + 2);
    this->layoutRect.right  = (int16_t)(pRect->right - 2);
    this->layoutRect.bottom = (int16_t)(pRect->bottom - 2);
}

// @40a990 (scalar-deleting wrapper @40a970) — soundName freed by its member
// dtor; base ~dwGuiHypText runs after.
dwGuiSpeech::~dwGuiSpeech()
{
}

// @40a9e0 (dwGuiSpeech_SetText)
void dwGuiSpeech::SetText(char* pText, void* pTimedItemArg, char* pSoundName)
{
    this->text.Free();
    // vtbl +0x48 (not overridden by dwGuiSpeech -> dwGuiHypText::SetText).
    this->dwGuiHypText::SetText(pText);
    this->pTimedItem = pTimedItemArg;
    if (pSoundName)
        this->soundName.AssignCStr(pSoundName);
    else
        this->soundName.AssignCStr("");
}

// @40aa30
void dwGuiSpeech::Clear()
{
    if (this->soundName.length != 0)
    {
        dwSound_Stop(this->soundName.pBuffer);
        this->soundName.AssignCStr("");
        dwSound_pManager->FreeAllSamples();
    }
    if (this->pTimedItem != NULL)
    {
        *(uint32_t*)((char*)this->pTimedItem + 0x14) = sithTime_g_msecGameTime;
        this->pTimedItem = NULL;
    }
}

// @40aa90
void dwGuiSpeech::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    char* pBuf = this->text.pBuffer;
    if (pBuf && *pBuf)
    {
        dwRect* pWidgetRect = this->GetRectPtr();
        dwImageDraw_ShadeRect(pDestBits, pWidgetRect, 0x28);
        dwImageDraw_FrameRect(pDestBits, pWidgetRect, 0x46, pClipRect);
        dwRect fullScreen; fullScreen.left = 0; fullScreen.top = 0;
        fullScreen.right = 0x280; fullScreen.bottom = 0x1e0;
        dwImageDraw_FillTriBlend(pDestBits, 0x46, (dwPoint*)&this->drawStyle,
                                 (dwPoint*)pWidgetRect, &fullScreen);
    }
    this->dwGuiHypText::Draw(pDestBits, pClipRect);
}

// =============================================================================
// dwGuiDroidDance
// =============================================================================

// @40ab70
dwGuiDroidDance::dwGuiDroidDance(dwRect* pRect)
    : dwGuiQuickView(pRect) // base ctor: allocs pNodes, LayoutNodes, sets QuickView vtbl
{
    // aGroups[7] default-constructed (each dwList() allocs its sentinel).
    this->danceTimer = 0.0f;
    this->groupIdx = 0;
    // vtable is dwGuiDroidDance's automatically.

    // Build 7 random droids (bodyType 1 ~70% of the time, else 2).
    for (int i = 0; i < 7; i++)
    {
        int bodyType = ((float)rand() * 3.051851e-05f < 0.7f) ? 1 : 2;
        dwDroidStats_AutoBuildRandom(bodyType, (dwListNode**)&this->aGroups[i]);
    }

    // Pick a random starting group and make its nodes the active dancers.
    unsigned int idx = (unsigned int)rand() % 7;
    this->groupIdx = (int32_t)idx;
    dwList* pGroup = &this->aGroups[idx];
    for (dwListNode* n = pGroup->pSentinel->pNext; n != pGroup->pSentinel; n = n->pNext)
    {
        dwPartNode* pNode = (dwPartNode*)n->pData;
        pNode->PlayActiveAnim();
        ((dwList*)&this->pNodes)->InsertAfter(this->pNodes->pPrev, pNode); // push-back
    }
    this->danceTimer = 12.0f;
    this->LayoutNodes();
}

// @40acf0 (scalar-deleting wrapper @40acd0)
dwGuiDroidDance::~dwGuiDroidDance()
{
    // Empty the active list WITHOUT deleting its payloads (they belong to
    // aGroups) so the base dwGuiQuickView dtor finds it empty and does not
    // double-free the part nodes.
    dwListNode* pSentinel = this->pNodes;
    dwListNode* n = pSentinel->pNext;
    while (n != pSentinel)
    {
        dwListNode* pNext = n->pNext;
        n->pPrev->pNext = n->pNext;
        n->pNext->pPrev = n->pPrev;
        n->pNext = NULL;
        n->pPrev = NULL;
        free(n);
        n = pNext;
    }

    // Destruct the 7 owned groups: delete each part-node payload, then free the
    // nodes + sentinel.
    for (int i = 0; i < 7; i++)
    {
        dwList* pGroup = &this->aGroups[i];
        for (dwListNode* gn = pGroup->pSentinel->pNext; gn != pGroup->pSentinel; gn = gn->pNext)
            delete (dwPartNode*)gn->pData;
        pGroup->Free();
    }
    // base ~dwGuiQuickView runs automatically (pNodes now empty).
}

// @40adb0 — vtbl +0x14
void dwGuiDroidDance::Update(float dt)
{
    dwGuiQuickView::Update(dt);

    for (dwListNode* n = this->pNodes->pNext; n != this->pNodes; n = n->pNext)
        ((dwPartNode*)n->pData)->FadeAnim(dt);

    if (this->danceTimer < dt)
    {
        dt -= this->danceTimer;
        this->groupIdx = (int32_t)((unsigned int)rand() % 7);

        for (dwListNode* n = this->pNodes->pNext; n != this->pNodes; n = n->pNext)
            ((dwPartNode*)n->pData)->StopAnim();

        // Clear the active list (nodes only; payloads owned by aGroups).
        ((dwList*)&this->pNodes)->FreeNodeRange(this->pNodes->pNext, this->pNodes);

        dwList* pGroup = &this->aGroups[this->groupIdx];
        for (dwListNode* n = pGroup->pSentinel->pNext; n != pGroup->pSentinel; n = n->pNext)
        {
            dwPartNode* pNode = (dwPartNode*)n->pData;
            pNode->PlayActiveAnim();
            ((dwList*)&this->pNodes)->InsertAfter(this->pNodes->pPrev, pNode);
        }
        this->danceTimer = 12.0f;
        this->LayoutNodes();
    }
    this->danceTimer -= dt;
}

// =============================================================================
// C FFI (implements the dwMain.c placeholders of the same name — delete those)
// =============================================================================

extern "C" dwGuiList* dwGuiList_Ctor(dwGuiList* pThis, dwRect* pRect, float a, char* pFont,
                                     uint8_t c, uint8_t d, void* pPoint)
{
    return new (pThis) dwGuiList(pRect, a, pFont, c, d, pPoint);
}

extern "C" void dwGuiList_Clear(dwGuiList* pList)
{
    pList->Clear();
}

extern "C" dwGuiSpeech* dwGuiSpeech_Ctor(dwGuiSpeech* pThis, dwRect* pRect, int a, char* pFont,
                                         uint32_t c, void* pPoint)
{
    return new (pThis) dwGuiSpeech(pRect, a, pFont, c, pPoint);
}

extern "C" void dwGuiSpeech_Clear(dwGuiSpeech* pSpeech)
{
    pSpeech->Clear();
}

extern "C" dwWidget* dwGuiDroidDance_New(dwRect* pRect)
{
    return (dwWidget*)new dwGuiDroidDance(pRect);
}
