// dwWorkshopCtrl — the droid-workshop control cluster: the dwWorkshopCtrl
// two-state button base + dwWcButtonBlink/dwWcEntryPanel/dwWcMaterials/
// dwWcBlueprints/dwWcChildDecorator/dwWcPalette, PLUS the unit's five
// dwGuiButton subclasses (dwWcArrows/dwWcBuildButton/dwWcPaintButton/
// dwWcBuildPaintButton/dwWcCargoNormalButton — declared in Dw/dwGuiButton.h,
// implemented here because their code lives in this compile unit).
//
// Decompiled from DroidWorks.exe (see the
// per-function `// @address` tags; several vtable-slot bodies were
// undetected functions recovered from the vtables — tagged "recovered fn").
// The dwWcBuildPaintButton/dwWcCargoNormalButton ctors were INLINED into
// dwWorkshop_CreateControl  in the binary; they are real
// ctors here so the P6 workshop screen can `new` them.
//
// GUI message codes used by this unit (dispatched to dwWidget_pDefault):
//   0x7531 hover-notify        0x7d0 blueprint hovered   0x7d1 blueprint clicked
//   0x7d3 paint color selected 0x7d5 clear droid         0x7db position reset
//   0x7dc/0x7dd randomize-latch control                  0x7de-0x7e1 rotate arrows
//   0x7e4 body type (1 biped/2 cargo)  0x7e5 part-type bits  0x7e6 close fly-out
//   0x7e7 build mode  0x7e8 paint mode  0x7e9/0x7ea palette FLC finished
//   0x7eb randomize   0x1bc8/0x1bc9 material row cycle   0x1b62/0x1b63 anim play/stop
//   0x2328 anim finished (from dwAnimBase::Stop)
//
// No module statics — no dwWorkshopCtrl_Startup needed (soft-reset rule).

#include "Dw/dwWorkshopCtrl.h"
#include "Dw/dwGuiButton.h"
#include "Dw/dwGuiHypText.h"
#include "Dw/dwStringTable.h"
#include "Dw/dwSound.h"
#include "Dw/dwDisplay.h"
#include "Dw/dwImageDraw.h"

#include "stdPlatform.h"

#include <stdlib.h>

// ---------------------------------------------------------------------------
// Cross-unit externs (not yet translated — declare + report, do not implement)
// ---------------------------------------------------------------------------

// dw-core global string table dwCore_pGlobalStrings (owner: dwMain, P7; also declared by
// dwGuiScreen.cpp). TODO(dw-decomp): provided by dwMain.
extern "C" dwStringTable* dwCore_pGlobalStrings;

// dw-core blueprint list sentinel dwCore_pBlueprintList (owner: dwMain, P7; payloads are
// dwPart blueprint records, P5). TODO(dw-decomp): provided by dwMain.
extern "C" dwListNode* dwCore_pBlueprintList;

// dw-core workspace part-node list sentinel dwCore_pWorkspaceNodes (owner: dwMain, P7).
// TODO(dw-decomp): provided by dwMain.
extern "C" dwListNode* dwCore_pWorkspaceNodes;

// Modal yes/no dialog runner dwGuiDialog_RunModal (owner: dwGuiMission, P6). Returns
// 0x1388 (5000) for YES, 0x1389 (5001) for NO.
// TODO(dw-decomp): provided by dwGuiMission.
extern "C" int dwGuiDialog_RunModal(const char* pConfName, const char* pMsgKey);

// Random-droid generator dwDroidStats_AutoBuildRandom (owner: dwDroidStats, P5).
// TODO(dw-decomp): provided by dwDroidStats.
extern "C" void dwDroidStats_AutoBuildRandom(int bodyType, dwListNode** ppWorkspaceList);

// dwGuiTimer factory (owner: dwGuiTimer in the dwGuiTextMisc unit, P4
// batch 2). The binary news a 0x20-byte dwGuiTimer(pTarget, startTime,
// duration) — a dwWcChildDecorator-style wrapper that shows/hides its target
// on a timer and DELETES it in its dtor. Until that class lands we go
// through this C-linkage factory returning the timer as a dwWidget*.
// TODO(dw-decomp): provided by dwGuiTextMisc (or replace the call sites with
// `new dwGuiTimer(...)` when it lands).
extern "C" dwWidget* dwGuiTimer_New(dwWidget* pTarget, float startTime, float duration);

// The blueprint records on dwCore_pBlueprintList are dwPart objects (P5,
// Dw/dwPart.h) — the grid cell image is the blueprint's ICON (pIcon @0x44).
#include "Dw/dwPart.h"

// ---------------------------------------------------------------------------
// dwWorkshopCtrl (dwWorkshopCtrl_vtbl)
// ---------------------------------------------------------------------------

// dwWorkshopCtrl_Ctor
dwWorkshopCtrl::dwWorkshopCtrl(dwRect* pRect, char* pImgNormal, char* pSndOff,
                               char* pImgPressed, char* pSndClick, int cmdId, uint8_t bToggle)
    : dwWidget(pRect)
    , pImageNormal(NULL)
    , imageNameNormal()
    , sndOff(pSndOff, 0)
    , pImagePressed(NULL)
    , imageNamePressed()
    , sndClick(pSndClick, 0)
    , cmdId(cmdId)
    , bToggle(bToggle)
    , bPressed(0)
    , bHot(0)
{
    this->imageNameNormal.AssignCStr(pImgNormal);
    this->imageNamePressed.AssignCStr(pImgPressed);
    dwWorkshopCtrl::EnsureImages(); // binary: direct call dwWorkshopCtrl_EnsureImagesLoaded
    if (this->sndClick.length == 0)
        this->sndClick.AssignCStr("CGenButton.wav");
}

// dwWorkshopCtrl_Dtor (scalar-deleting wrapper dwWorkshopCtrl_DtorDelete) — the four
// string frees are the member dtors (binary order matches reverse
// declaration order).
dwWorkshopCtrl::~dwWorkshopCtrl()
{
    dwWorkshopCtrl::FreeImages(); // binary: direct call
}

// vtbl +0x48 (Ghidra: dwWorkshopCtrl_HitTest) — the NEW overridable
// point-on-control test (left/top inclusive, right/bottom exclusive).
int dwWorkshopCtrl::HitTest(int16_t x, int16_t y)
{
    if (this->left <= x && x < this->right && this->top <= y && y < this->bottom)
        return 1;
    return 0;
}

// vtbl +0x04 dwWorkshopCtrl_OnMouseMove
int dwWorkshopCtrl::OnMouseMove(int16_t x, int16_t y)
{
    if (this->bPressed == 0)
        return 0;
    if (this->HitTest(x, y)) // vtbl +0x48
    {
        if (this->bHot == 0)
        {
            this->bHot = 1;
            this->Invalidate(); // vtbl +0x34
        }
    }
    else
    {
        if (this->bHot != 0)
        {
            this->bHot = 0;
            this->Invalidate();
        }
    }
    return 1;
}

// vtbl +0x08 dwWorkshopCtrl_OnMouseDown
int dwWorkshopCtrl::OnMouseDown(int16_t x, int16_t y)
{
    dwWidgetMsg msg;

    if (!this->HitTest(x, y)) // vtbl +0x48
        return 0;

    if (this->bToggle != 0)
    {
        if (this->bHot != 0)
        {
            // Toggle OFF: sndOff + Invalidate + dispatch { cmdId }.
            this->bHot = 0;
            if (this->sndOff.length != 0)
                dwSound_PlayRestart(this->sndOff.pBuffer);
            this->Invalidate();
        }
        else
        {
            // Toggle ON: sndClick + Invalidate + dispatch { cmdId }.
            this->bHot = 1;
            if (this->sndClick.length != 0)
                dwSound_PlayRestart(this->sndClick.pBuffer);
            this->Invalidate();
        }
        msg.code = this->cmdId;
        msg.pSender = NULL;
        msg.param = 0;
        msg.pTarget = NULL;
        dwWidget_DispatchMsg(&msg, NULL);
        return 1;
    }

    // Momentary: latch + capture; the command fires on mouse-up.
    this->bPressed = 1;
    this->bHot = 1;
    dwWidget_pMouseTarget = this;
    if (this->sndClick.length != 0)
        dwSound_PlayRestart(this->sndClick.pBuffer);
    this->Invalidate();
    return 1;
}

// vtbl +0x0c dwWorkshopCtrl_OnMouseUp
int dwWorkshopCtrl::OnMouseUp(int16_t x, int16_t y)
{
    dwWidgetMsg msg;

    (void)x; (void)y;
    if (this->bToggle != 0 || this->bPressed == 0)
        return 0;

    if (dwWidget_pMouseTarget == this)
        dwWidget_pMouseTarget = NULL;
    this->bPressed = 0;
    if (this->bHot != 0)
    {
        this->bHot = 0;
        if (this->sndOff.length != 0)
            dwSound_PlayRestart(this->sndOff.pBuffer);
        this->Invalidate();
        msg.code = this->cmdId;
        msg.pSender = NULL;
        msg.param = 0;
        msg.pTarget = NULL;
        dwWidget_DispatchMsg(&msg, NULL);
    }
    return 1;
}

// vtbl +0x18 (shared COMDAT; Ghidra: dwGuiTextPopup_OnHover — the
// linker kept the dwGuiTextPopup unit's copy)
int dwWorkshopCtrl::OnHover(int16_t x, int16_t y)
{
    dwWidgetMsg msg;

    (void)x; (void)y;
    msg.code = 0x7531;
    msg.pSender = (void*)(intptr_t)this->cmdId;
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);
    return 1;
}

// vtbl +0x3c (Ghidra: dwWorkshopCtrl_EnsureImagesLoaded)
void dwWorkshopCtrl::EnsureImages()
{
    if (this->pImageNormal == NULL && this->imageNameNormal.length != 0)
        this->pImageNormal = dwImage_LoadFile(this->imageNameNormal.pBuffer);
    if (this->pImagePressed == NULL && this->imageNamePressed.length != 0)
        this->pImagePressed = dwImage_LoadFile(this->imageNamePressed.pBuffer);
}

// vtbl +0x40 dwWorkshopCtrl_FreeImages
void dwWorkshopCtrl::FreeImages()
{
    if (this->pImageNormal != NULL)
    {
        delete this->pImageNormal; // binary: vtbl slot 0 (scalar-deleting dtor, flag 1)
        this->pImageNormal = NULL;
    }
    if (this->pImagePressed != NULL)
    {
        delete this->pImagePressed;
        this->pImagePressed = NULL;
    }
}

// vtbl +0x44 dwWorkshopCtrl_Draw
void dwWorkshopCtrl::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    dwImage* pImg;

    if (this->bEnabled == 0)
        return;
    this->EnsureImages(); // vtbl +0x3c
    pImg = this->pImageNormal;
    if (this->bHot != 0)
        pImg = this->pImagePressed;
    if (pImg != NULL)
        pImg->Blit(pDestBits, this->left, this->top, pClipRect); // vtbl +0x04
}

// ---------------------------------------------------------------------------
// dwWcButtonBlink (dwWcButtonBlink_vtbl)
// ---------------------------------------------------------------------------

// Blink timing constants (binary rdata).
#define DWWCBUTTONBLINK_PERIOD    0.5f
#define DWWCBUTTONBLINK_THRESHOLD 0.0f

// dwWcButtonBlink_Ctor
dwWcButtonBlink::dwWcButtonBlink(dwRect* pRect, char* pImgNormal, char* pSndOff,
                                 char* pImgPressed, char* pSndClick, char* pBlinkImg,
                                 char* pBlinkSnd, int cmdId)
    : dwWorkshopCtrl(pRect, pImgNormal, pSndOff, pImgPressed, pSndClick, cmdId, /*bToggle*/0)
    , pBlinkImage(NULL)
    , blinkImageName()
    , blinkSound()
    , bBlinking(0)
    , bBlinkState(0)
    , blinkTimer(0.0f)
{
    this->blinkImageName.AssignCStr(pBlinkImg);
    dwWcButtonBlink::EnsureImages(); // binary: direct call dwWcButtonBlink_EnsureImagesLoaded
    if (pBlinkSnd != NULL)
        this->blinkSound.AssignCStr(pBlinkSnd);
}

// dwWcButtonBlink_Dtor (scalar-deleting wrapper dwWcButtonBlink_DtorDelete)
dwWcButtonBlink::~dwWcButtonBlink()
{
    dwWcButtonBlink::FreeImages(); // binary: direct call
}

// dwWcButtonBlink_StartBlink
void dwWcButtonBlink::StartBlink()
{
    this->bBlinking = 1;
    this->bBlinkState = 1;
    this->blinkTimer = DWWCBUTTONBLINK_PERIOD;
    this->Invalidate(); // binary: tail-jump vtbl +0x34
}

// dwWcButtonBlink_StopBlink
void dwWcButtonBlink::StopBlink()
{
    this->bBlinking = 0;
    this->bBlinkState = 0;
    this->Invalidate();
}

// vtbl +0x0c dwWcButtonBlink_OnMouseUp (recovered fn — vtable-only body, no Ghidra name)
int dwWcButtonBlink::OnMouseUp(int16_t x, int16_t y)
{
    uint8_t bWasHot;
    int result;

    bWasHot = this->bHot;
    result = dwWorkshopCtrl::OnMouseUp(x, y);
    if (bWasHot != 0 && this->bHot == 0)
    {
        // The click completed — stop blinking.
        this->bBlinking = 0;
        this->bBlinkState = 0;
    }
    return result;
}

// vtbl +0x18 dwWcButtonBlink_OnHover (recovered fn)
int dwWcButtonBlink::OnHover(int16_t x, int16_t y)
{
    dwWidgetMsg msg;

    (void)x; (void)y;
    msg.code = 0x7531;
    msg.pSender = (void*)(intptr_t)this->cmdId;
    msg.param = (this->bBlinking != 0) ? 1 : 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);
    return 1;
}

// vtbl +0x14 dwWcButtonBlink_Update
void dwWcButtonBlink::Update(float dt)
{
    uint8_t bOldState;

    if (this->bBlinking == 0)
        return;
    bOldState = this->bBlinkState;
    this->blinkTimer = this->blinkTimer - dt;
    if (this->blinkTimer <= DWWCBUTTONBLINK_THRESHOLD)
    {
        do
        {
            this->bBlinkState = (this->bBlinkState == 0) ? 1 : 0;
            this->blinkTimer = this->blinkTimer + DWWCBUTTONBLINK_PERIOD;
        } while (this->blinkTimer <= DWWCBUTTONBLINK_THRESHOLD);
    }
    if (this->bBlinkState != bOldState)
    {
        this->Invalidate();
        if (this->blinkSound.length != 0)
            dwSound_PlayRestart(this->blinkSound.pBuffer);
    }
}

// vtbl +0x44 dwWcButtonBlink_Draw
void dwWcButtonBlink::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    dwImage* pImg;

    if (this->bEnabled == 0)
        return;
    this->EnsureImages(); // vtbl +0x3c
    pImg = this->pImageNormal;
    if (this->bHot != 0)
        pImg = this->pImagePressed;
    else if (this->bBlinkState != 0 && this->pBlinkImage != NULL)
        pImg = this->pBlinkImage;
    if (pImg != NULL)
        pImg->Blit(pDestBits, this->left, this->top, pClipRect);
}

// vtbl +0x3c (Ghidra: dwWcButtonBlink_EnsureImagesLoaded)
void dwWcButtonBlink::EnsureImages()
{
    dwWorkshopCtrl::EnsureImages(); // binary: direct call dwWorkshopCtrl_EnsureImagesLoaded
    if (this->pBlinkImage == NULL && this->blinkImageName.length != 0)
        this->pBlinkImage = dwImage_LoadFile(this->blinkImageName.pBuffer);
}

// vtbl +0x40 dwWcButtonBlink_FreeImages
void dwWcButtonBlink::FreeImages()
{
    if (this->pBlinkImage != NULL)
    {
        delete this->pBlinkImage;
        this->pBlinkImage = NULL;
    }
    dwWorkshopCtrl::FreeImages(); // binary: direct call
}

// ---------------------------------------------------------------------------
// dwWcEntry / dwWcEntryPanel (dwWcEntryPanel_vtbl)
// ---------------------------------------------------------------------------

// Entry ctor (binary: inlined into dwWcEntryPanel_AddEntry).
dwWcEntry::dwWcEntry(dwRect rect, char* pText, char* pFontName, uint8_t color,
                     int id, int16_t kind, char* pMarkup, float showTime, float hideTime)
    : rect(rect)
    , text(pText, 0)
    , fontName(pFontName, 0)
    , color(color)
    , id(id)
    , kind(kind)
    , pMarkup(pMarkup)
    , showTime(showTime)
    , hideTime(hideTime)
{
}

// dwWcEntry_Dtor (scalar-deleting wrapper dwWcEntry_DtorDelete) — frees fontName
// then text (member dtors; pMarkup is borrowed, not freed).
dwWcEntry::~dwWcEntry()
{
}

// dwWcEntryPanel_Ctor
dwWcEntryPanel::dwWcEntryPanel(dwRect* pRect, char* pName, void* pContext)
    : dwWidget(pRect)
    , pTimer0(NULL)
    , pTimer1(NULL)
    , pTimer2(NULL)
    , entries()
    , pHypText0(NULL)
    , pHypText1(NULL)
    , pHypText2(NULL)
    , pImage(NULL)
    , name()
    , pContext(pContext)
{
    this->name.AssignCStr(pName);
    dwWcEntryPanel::EnsureImages(); // binary: direct call dwWcEntryPanel_EnsureImagesLoaded
}

// dwWcEntryPanel_Dtor (scalar-deleting wrapper dwWcEntryPanel_DtorDelete)
dwWcEntryPanel::~dwWcEntryPanel()
{
    dwListNode* pSent;
    dwListNode* pNode;
    dwListNode* pNext;
    dwWcEntry* pEntry;

    dwWcEntryPanel::FreeImages(); // binary: direct call

    // Delete the timers — each dwGuiTimer deletes its wrapped caption.
    if (this->pTimer0 != NULL)
        delete this->pTimer0;
    if (this->pTimer1 != NULL)
        delete this->pTimer1;
    if (this->pTimer2 != NULL)
        delete this->pTimer2;

    // Free every entry + its node, then the sentinel (binary: two inlined
    // list-teardown loops over the same list; single pass here, identical
    // result).
    pSent = this->entries.pSentinel;
    pNode = pSent->pNext;
    while (pNode != pSent)
    {
        pEntry = (dwWcEntry*)pNode->pData;
        pNext = pNode->pNext;
        pNode->pPrev->pNext = pNode->pNext;
        pNode->pNext->pPrev = pNode->pPrev;
        free(pNode);
        if (pEntry != NULL)
            delete pEntry; // binary: dwWcEntry_DtorDelete(1)
        pNode = pNext;
    }
    this->entries.Free();
}

// Added: shared show body (the binary duplicates this inline in OnMessage
// dwWcEntryPanel_OnMessage and ShowById dwWcEntryPanel_ShowById — one helper here, same behavior/order).
void dwWcEntryPanel::ShowEntry(dwWcEntry* pEntry)
{
    dwWidget** ppTimerSlot;
    dwGuiHypText** ppHypSlot;
    dwGuiHypText* pHyp;
    dwString markup;

    // Slot crosswiring is the binary's: kind 1 -> caption 0 + timer 0,
    // kind 2 -> caption 2 + timer 1, anything else -> caption 1 + timer 2.
    if (pEntry->kind == 1)
    {
        ppTimerSlot = &this->pTimer0;
        ppHypSlot = &this->pHypText0;
    }
    else if (pEntry->kind == 2)
    {
        ppTimerSlot = &this->pTimer1;
        ppHypSlot = &this->pHypText2;
    }
    else
    {
        ppTimerSlot = &this->pTimer2;
        ppHypSlot = &this->pHypText1;
    }

    // Delete the slot's old timer (deletes the old caption with it).
    if (*ppTimerSlot != NULL)
        delete *ppTimerSlot;

    // Format = "DCO" + pMarkup + "T": draw-shadowed(O)/center(C)/no-wrap(D),
    // then pMarkup's decimal value consumed by the T (typewriter) element.
    markup.AssignCStr("DCO");
    markup.Append(pEntry->pMarkup, 0);
    markup.Append("T", 0);

    pHyp = new dwGuiHypText(&pEntry->rect, NULL, pEntry->fontName.pBuffer,
                            pEntry->color, markup.pBuffer);
    *ppHypSlot = pHyp;

    // Replace the ctor-parsed text with the entry text (free-then-SetText is
    // the documented replace idiom — SetText appends).
    pHyp->text.Free();
    pHyp->SetText(pEntry->text.pBuffer); // vtbl +0x48

    *ppTimerSlot = dwGuiTimer_New(pHyp, pEntry->showTime, pEntry->hideTime);
}

// vtbl +0x1c dwWcEntryPanel_OnMessage — shows EVERY entry whose id
// matches (no early exit). Returns 0.
int dwWcEntryPanel::OnMessage(dwWidgetMsg* pMsg)
{
    dwListNode* pSent;
    dwListNode* pNode;
    dwWcEntry* pEntry;

    pSent = this->entries.pSentinel;
    for (pNode = pSent->pNext; pNode != pSent; pNode = pNode->pNext)
    {
        pEntry = (dwWcEntry*)pNode->pData;
        if (pEntry->id == pMsg->code)
            this->ShowEntry(pEntry);
    }
    return 0;
}

// dwWcEntryPanel_ShowById
void dwWcEntryPanel::ShowById(int id)
{
    dwListNode* pSent;
    dwListNode* pNode;
    dwWcEntry* pEntry;

    pSent = this->entries.pSentinel;
    for (pNode = pSent->pNext; pNode != pSent; pNode = pNode->pNext)
    {
        pEntry = (dwWcEntry*)pNode->pData;
        if (pEntry->id == id)
            this->ShowEntry(pEntry);
    }
}

// dwWcEntryPanel_AddEntry — rect BY VALUE, push-back.
void dwWcEntryPanel::AddEntry(dwRect rect, char* pText, char* pFontName, uint8_t color,
                              int id, int16_t kind, char* pMarkup, float showTime, float hideTime)
{
    dwWcEntry* pEntry;

    pEntry = new dwWcEntry(rect, pText, pFontName, color, id, kind, pMarkup, showTime, hideTime);
    this->entries.InsertAfter(this->entries.pSentinel->pPrev, pEntry);
}

// vtbl +0x14 dwWcEntryPanel_Update
void dwWcEntryPanel::Update(float dt)
{
    if (this->bEnabled == 0)
        return;
    if (this->pTimer0 != NULL)
        this->pTimer0->Update(dt); // vtbl +0x14
    if (this->pTimer1 != NULL)
        this->pTimer1->Update(dt);
    if (this->pTimer2 != NULL)
        this->pTimer2->Update(dt);
}

// vtbl +0x18 (shared COMDAT; Ghidra: dwGuiIndicator_OnHover — the
// linker kept the dwHelp unit's copy; here the +0x3c field is pContext)
int dwWcEntryPanel::OnHover(int16_t x, int16_t y)
{
    dwWidgetMsg msg;

    (void)x; (void)y;
    msg.code = 0x7531;
    msg.pSender = this->pContext;
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);
    return 1;
}

// vtbl +0x44 dwWcEntryPanel_Draw
void dwWcEntryPanel::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    dwRect clip0, clip2, clip1;

    if (this->bEnabled == 0)
        return;
    this->EnsureImages(); // vtbl +0x3c
    if (this->pImage != NULL)
        this->pImage->Blit(pDestBits, this->left, this->top, pClipRect);

    // Quirk preserved: the captions only draw when ALL THREE exist; draw
    // order is slot 0, 2, 1, each clipped to its own widget rect.
    if (this->pHypText0 != NULL && this->pHypText2 != NULL && this->pHypText1 != NULL)
    {
        clip0 = *pClipRect;
        dwRect_Clip(&clip0, ((dwWidget*)this->pHypText0)->GetRectPtr());
        clip2 = *pClipRect;
        dwRect_Clip(&clip2, ((dwWidget*)this->pHypText2)->GetRectPtr());
        clip1 = *pClipRect;
        dwRect_Clip(&clip1, ((dwWidget*)this->pHypText1)->GetRectPtr());
        ((dwWidget*)this->pHypText0)->DrawChild(pDestBits, &clip0);
        ((dwWidget*)this->pHypText2)->DrawChild(pDestBits, &clip2);
        ((dwWidget*)this->pHypText1)->DrawChild(pDestBits, &clip1);
    }
}

// vtbl +0x3c (Ghidra: dwWcEntryPanel_EnsureImagesLoaded)
void dwWcEntryPanel::EnsureImages()
{
    if (this->pImage == NULL && this->name.length != 0)
        this->pImage = dwImage_LoadFile(this->name.pBuffer);
}

// vtbl +0x40 dwWcEntryPanel_FreeImages
void dwWcEntryPanel::FreeImages()
{
    if (this->pImage != NULL)
    {
        delete this->pImage;
        this->pImage = NULL;
    }
}

// ---------------------------------------------------------------------------
// dwWcMaterialsEntry / dwWcMaterials (MI dwWcMaterials_vtbl / dwWcMaterials_group_vtbl)
// ---------------------------------------------------------------------------

// Entry ctor (binary: inlined into dwWcMaterials_AddEntry).
dwWcMaterialsEntry::dwWcMaterialsEntry(char* pAnimFile, int code, uint8_t flag,
                                       char* pImageFile, char* pExtraFile)
    : animFile(pAnimFile, 0)
    , code(code)
    , flag(flag)
    , imageFile(pImageFile, 0)
    , extraFile(pExtraFile, 0)
{
}

// dwWcMaterialsEntry_Dtor (scalar-deleting wrapper dwWcMaterialsEntry_DtorDelete)
dwWcMaterialsEntry::~dwWcMaterialsEntry()
{
}

// dwWcMaterials_Ctor
dwWcMaterials::dwWcMaterials(dwRect* pRect, char* pImageName, void* pContext)
    : dwAnimBase(pRect, 0, 1)
    , dwWidgetGroup(pRect)
    , items()
    , msgSwatchA(0x1bc8)
    , msgSwatchB(0x1bc9)
    , curCode(0x1bbc)
    , pAnim(NULL)
    , matIdxA(7)
    , matIdxB(7)
    , pSwatchA(NULL)
    , pSwatchB(NULL)
    , pImage(NULL)
    , pContext(pContext)
    , imageName()
{
    this->imageName.AssignCStr(pImageName);
    dwWcMaterials::EnsureImages(); // binary: direct call dwWcMaterials_EnsureImagesLoaded
    this->matIdxA = 7;
    this->matIdxB = 7;
}

// dwWcMaterials_Dtor (scalar-deleting wrapper dwWcMaterials_DtorDelete, group thunk
// dwWcMaterials_DtorDelete_Thunk). Binary order: FreeImages, delete pAnim, free items, delete the
// group children, free imageName, base dtors — the child deletion is left
// to ~dwWidgetGroup here (single delete either way).
dwWcMaterials::~dwWcMaterials()
{
    dwListNode* pSent;
    dwListNode* pNode;
    dwListNode* pNext;
    dwWcMaterialsEntry* pEntry;

    dwWcMaterials::FreeImages(); // binary: direct call

    if (this->pAnim != NULL)
    {
        delete this->pAnim;
        this->pAnim = NULL;
    }

    pSent = this->items.pSentinel;
    pNode = pSent->pNext;
    while (pNode != pSent)
    {
        pEntry = (dwWcMaterialsEntry*)pNode->pData;
        pNext = pNode->pNext;
        pNode->pPrev->pNext = pNode->pNext;
        pNode->pNext->pPrev = pNode->pPrev;
        free(pNode);
        if (pEntry != NULL)
            delete pEntry; // binary: dwWcMaterialsEntry_DtorDelete(1)
        pNode = pNext;
    }
    this->items.Free();
}

// vtbl +0x1c dwWcMaterials_OnMessage (group thunk dwWcMaterials_OnMessage_Thunk) — the material panel logic.
int dwWcMaterials::OnMessage(dwWidgetMsg* pMsg)
{
    dwListNode* pSent;
    dwListNode* pNode;
    dwWcMaterialsEntry* pEntry;
    int combined;

    // Row A cycle (msg 0x1bc8): WOOD(7) -> RUBBER(8) -> GLASS(9) -> WOOD.
    if (pMsg->code == this->msgSwatchA)
    {
        if (this->matIdxA == 7)
        {
            this->matIdxA = 8;
            this->HighlightSwatchA((char*)"RUBBER");
        }
        else if (this->matIdxA == 8)
        {
            this->matIdxA = 9;
            this->HighlightSwatchA((char*)"GLASS");
        }
        else
        {
            this->matIdxA = 7;
            this->curCode = 0x1bbc; // wrap resets the scratch code (binary quirk)
            this->HighlightSwatchA((char*)"WOOD");
        }
    }
    // Row B cycle (msg 0x1bc9).
    else if (pMsg->code == this->msgSwatchB)
    {
        if (this->matIdxB == 7)
        {
            this->matIdxB = 8;
            this->HighlightSwatchB((char*)"RUBBER");
        }
        else if (this->matIdxB == 8)
        {
            this->matIdxB = 9;
            this->HighlightSwatchB((char*)"GLASS");
        }
        else
        {
            this->matIdxB = 7;
            this->HighlightSwatchB((char*)"WOOD");
        }
    }

    // Combination code: curCode (0x1bbc) + A + B, +2 when A==RUBBER / +4
    // when A==GLASS (curCode is reset to 0x1bbc at the end of every call).
    combined = this->curCode + this->matIdxA + this->matIdxB;
    this->curCode = combined;
    if (this->matIdxA == 8)
        this->curCode = combined + 2;
    else if (this->matIdxA == 9)
        this->curCode = combined + 4;

    // Swap in the matching combination's still image (first match; skips
    // entries without one). The pSender check keeps a sender that already
    // carries the code from retriggering itself.
    pSent = this->items.pSentinel;
    for (pNode = pSent->pNext; pNode != pSent; pNode = pNode->pNext)
    {
        pEntry = (dwWcMaterialsEntry*)pNode->pData;
        if (pEntry->code == this->curCode && pMsg->pSender != (void*)(intptr_t)pEntry->code)
        {
            if (this->bPlaying != 0)
            {
                this->pAnim->Stop(); // vtbl +0x4c (virtual dwAnimBase::Stop)
                this->bPlaying = 0;
            }
            if (pEntry->imageFile.length == 0)
                break; // binary: jumps straight to the play/stop handling
            if (this->pImage != NULL)
                delete this->pImage;
            this->imageName.AssignString(&pEntry->imageFile);
            this->pImage = dwImage_LoadFile(this->imageName.pBuffer);
            static_cast<dwAnimBase*>(this)->Invalidate(); // binary: primary-subobject Invalidate dwWidget_Invalidate
            break;
        }
    }

    if (pMsg->code == 0x1b62)
    {
        // Play: (re)open the matching combination's anim.
        for (pNode = pSent->pNext; pNode != pSent; pNode = pNode->pNext)
        {
            pEntry = (dwWcMaterialsEntry*)pNode->pData;
            if (pEntry->code == this->curCode)
            {
                if (this->pAnim != NULL)
                {
                    delete this->pAnim;
                    this->pAnim = NULL;
                }
                this->msgCode = pEntry->code; // dwAnimBase msg trigger
                this->pAnim = dwAnim_Open(static_cast<dwAnimBase*>(this)->GetRectPtr(),
                                          pEntry->animFile.pBuffer, pEntry->code, 0);
            }
        }
        if (this->pAnim != NULL)
        {
            this->pAnim->Play((uint8_t)1); // non-virtual dwAnim::Play
            this->bPlaying = 1;
            static_cast<dwAnimBase*>(this)->Invalidate();
        }
    }
    else if (pMsg->code == 0x1b63)
    {
        // Stop.
        if (this->pAnim != NULL)
        {
            this->pAnim->Stop(); // vtbl +0x4c
            this->bPlaying = 0;
            static_cast<dwAnimBase*>(this)->Invalidate();
        }
    }

    this->curCode = 0x1bbc;
    return this->dwAnimBase::OnMessage(pMsg);
}

// dwWcMaterials_HighlightSwatchA — row A sits at group-top + 5.
void dwWcMaterials::HighlightSwatchA(char* pMatName)
{
    dwString* pLocalized;
    dwListNode* pSent;
    dwListNode* pNode;
    dwGuiHypText* pLabel;

    pLocalized = dwCore_pGlobalStrings->Find(pMatName);
    if (pLocalized->length != 0)
        pMatName = pLocalized->pBuffer;

    pSent = this->children.pSentinel;
    for (pNode = pSent->pNext; pNode != pSent; pNode = pNode->pNext)
    {
        pLabel = (dwGuiHypText*)pNode->pData; // AddLabel children only
        if (dwString_Equals(pLabel->text.pBuffer, pMatName)
            && pLabel->top == (int16_t)(this->dwAnimBase::top + 5))
        {
            if (this->pSwatchA != NULL)
                this->pSwatchA->Disable(); // vtbl +0x24
            pLabel->Enable();              // vtbl +0x20
            this->pSwatchA = pLabel;
            static_cast<dwWidgetGroup*>(this)->Invalidate(); // binary: dwWidget_Invalidate(group)
            return;
        }
    }
}

// dwWcMaterials_HighlightSwatchB — row B sits at group-top + 0xa0.
void dwWcMaterials::HighlightSwatchB(char* pMatName)
{
    dwString* pLocalized;
    dwListNode* pSent;
    dwListNode* pNode;
    dwGuiHypText* pLabel;

    pLocalized = dwCore_pGlobalStrings->Find(pMatName);
    if (pLocalized->length != 0)
        pMatName = pLocalized->pBuffer;

    pSent = this->children.pSentinel;
    for (pNode = pSent->pNext; pNode != pSent; pNode = pNode->pNext)
    {
        pLabel = (dwGuiHypText*)pNode->pData;
        if (dwString_Equals(pLabel->text.pBuffer, pMatName)
            && pLabel->top == (int16_t)(this->dwAnimBase::top + 0xa0))
        {
            if (this->pSwatchB != NULL)
                this->pSwatchB->Disable();
            pLabel->Enable();
            this->pSwatchB = pLabel;
            static_cast<dwWidgetGroup*>(this)->Invalidate();
            return;
        }
    }
}

// dwWcMaterials_AddEntry — push-back onto items.
void dwWcMaterials::AddEntry(char* pAnimFile, int code, uint8_t flag,
                             char* pImageFile, char* pExtraFile)
{
    dwWcMaterialsEntry* pEntry;

    pEntry = new dwWcMaterialsEntry(pAnimFile, code, flag, pImageFile, pExtraFile);
    this->items.InsertAfter(this->items.pSentinel->pPrev, pEntry);
}

// dwWcMaterials_AddLabel — push-FRONT a disabled label child.
void dwWcMaterials::AddLabel(char* pText, dwPoint pos, dwPoint size, uint8_t color, char* pFontName)
{
    dwRect rect;
    dwGuiHypText* pLabel;

    rect.left = (int16_t)(pos.x + this->dwAnimBase::left);
    rect.top = (int16_t)(pos.y + this->dwAnimBase::top);
    rect.right = (int16_t)(size.x + rect.left);
    rect.bottom = (int16_t)(size.y + rect.top);

    pLabel = new dwGuiHypText(&rect, NULL, pFontName, color, (char*)"BLN");
    // Replace the parsed format text with the label text (free-then-SetText
    // replace idiom).
    pLabel->text.Free();
    pLabel->SetText(pText); // vtbl +0x48
    pLabel->Disable();      // vtbl +0x24 — only the selected label is enabled
    static_cast<dwWidgetGroup*>(this)->Invalidate();
    this->children.InsertAfter(this->children.pSentinel, pLabel); // push-front
}

// dwWcMaterials_RefreshSelection
void dwWcMaterials::RefreshSelection()
{
    dwListNode* pFirst;
    dwWcMaterialsEntry* pEntry;

    pFirst = this->items.pSentinel->pNext;
    // Note: added empty-list guard — the binary read the sentinel's
    // uninitialized pData when no entries were added yet.
    if (pFirst != this->items.pSentinel)
    {
        pEntry = (dwWcMaterialsEntry*)pFirst->pData;
        if (pEntry != NULL && pEntry->imageFile.pBuffer != NULL)
        {
            if (this->pImage != NULL)
                delete this->pImage;
            this->imageName.AssignString(&pEntry->imageFile);
            this->pImage = dwImage_LoadFile(this->imageName.pBuffer);
            static_cast<dwWidgetGroup*>(this)->Invalidate();
        }
    }
    this->HighlightSwatchA((char*)"WOOD");
    this->HighlightSwatchB((char*)"WOOD");
}

// vtbl +0x14 dwWcMaterials_Update (group thunk dwWcMaterials_Update_Thunk)
void dwWcMaterials::Update(float dt)
{
    if (this->dwAnimBase::bEnabled != 0 && this->pAnim != NULL)
        this->pAnim->Update(dt); // vtbl +0x14
    this->dwWidgetGroup::Update(dt); // binary: direct call
}

// vtbl +0x18 dwWcMaterials_OnHover (group thunk dwWcMaterials_OnHover_Thunk)
int dwWcMaterials::OnHover(int16_t x, int16_t y)
{
    dwWidgetMsg msg;

    (void)x; (void)y;
    msg.code = 0x7531;
    msg.pSender = this->pContext;
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);
    return 1;
}

// vtbl +0x44 dwWcMaterials_Draw (group thunk dwWcMaterials_Draw_Thunk — the binary re-emitted the whole
// body for the group vtable; the compiler generates the thunk here)
void dwWcMaterials::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    dwRect clip;

    if (this->dwAnimBase::bEnabled != 0)
    {
        this->EnsureImages(); // vtbl +0x3c
        if (this->pImage != NULL)
        {
            // Still image at the GROUP rect origin.
            this->pImage->Blit(pDestBits, this->dwWidgetGroup::left,
                               this->dwWidgetGroup::top, pClipRect);
        }
        if (this->pAnim != NULL)
        {
            clip = *pClipRect;
            dwRect_Clip(&clip, this->pAnim->GetRectPtr());
            this->pAnim->DrawChild(pDestBits, &clip);
        }
    }
    // The two enabled swatch labels draw even when the panel is disabled
    // (binary quirk — these checks sit outside the bEnabled block).
    if (this->pSwatchA != NULL && this->pSwatchA->bEnabled != 0)
        ((dwWidget*)this->pSwatchA)->DrawChild(pDestBits, pClipRect);
    if (this->pSwatchB != NULL && this->pSwatchB->bEnabled != 0)
        ((dwWidget*)this->pSwatchB)->DrawChild(pDestBits, pClipRect);
}

// vtbl +0x3c (group thunk dwWcMaterials_EnsureLoaded_Thunk; Ghidra: dwWcMaterials_EnsureImagesLoaded)
void dwWcMaterials::EnsureImages()
{
    if (this->pImage == NULL && this->imageName.length != 0)
        this->pImage = dwImage_LoadFile(this->imageName.pBuffer);
    this->dwWidgetGroup::EnsureImages(); // binary: direct call
}

// vtbl +0x40 dwWcMaterials_FreeImages (group thunk dwWcMaterials_FreeImages_Thunk)
void dwWcMaterials::FreeImages()
{
    if (this->pImage != NULL)
    {
        delete this->pImage;
        this->pImage = NULL;
    }
    this->dwWidgetGroup::FreeImages(); // binary: direct call dwWidgetGroup_FreeChildImages
}

// ---------------------------------------------------------------------------
// dwWcBlueprints (dwWcBlueprints_vtbl)
// ---------------------------------------------------------------------------

// dwWcBlueprints_Ctor
dwWcBlueprints::dwWcBlueprints(dwRect* pRect, int16_t xIndent)
    : dwWidget(pRect)
    , xIndent(xIndent)
    , gridX(0)
    , gridTop(0)
    , gridRight(0)
    , gridBottom(0)
    , bShown(0)
    , backdropColor(0x46)
    , slotMask(1)
    , typeBits(0)
    , pHover(NULL)
    , cellW(0)   // Note: cellW/cellH/cols left uninitialized by the binary
    , cellH(0)   // ctor (first set in BuildGrid); zero-initialized here.
    , cols(0)
{
    this->hoverRect.left = 0;
    this->hoverRect.top = 0;
    this->hoverRect.right = 0;
    this->hoverRect.bottom = 0;
}

// dwWcBlueprints_Dtor (scalar-deleting wrapper dwWcBlueprints_DtorDelete)
dwWcBlueprints::~dwWcBlueprints()
{
    if (this->bShown != 0)
        this->Hide();
}

// Shared filter: is this blueprint shown by the current slot/type filters?
static int dwWcBlueprints_IsEligible(dwWcBlueprints* pThis, dwPart* pBp)
{
    if (pBp->bAvailable == 0)
        return 0;
    // Note: not in the binary — dwImage_LoadFile is a P8 stub returning NULL,
    // and the grid measures/blits pIcon unguarded; treat icon-less blueprints
    // as ineligible until stdBitmapRle2 lands (same guard style as dwCursor).
    if (pBp->pIcon == NULL)
        return 0;
    if ((pBp->slotMask & pThis->slotMask) == 0)
        return 0;
    if ((pThis->typeBits & (1u << (pBp->type & 0x1f))) == 0)
        return 0;
    return 1;
}

// dwWcBlueprints_BuildGrid
void dwWcBlueprints::BuildGrid()
{
    dwListNode* pNode;
    dwPart* pBp;
    uint16_t count;
    int16_t maxCols;
    int16_t rows;

    this->cellW = 0;
    this->cellH = 0;
    count = 0;
    for (pNode = dwCore_pBlueprintList->pNext; pNode != dwCore_pBlueprintList; pNode = pNode->pNext)
    {
        pBp = (dwPart*)pNode->pData;
        if (!dwWcBlueprints_IsEligible(this, pBp))
            continue;
        if ((uint16_t)this->cellW < pBp->pIcon->desc.width)
            this->cellW = (int16_t)pBp->pIcon->desc.width;
        if ((uint16_t)this->cellH < pBp->pIcon->desc.height)
            this->cellH = (int16_t)pBp->pIcon->desc.height;
        count++;
    }

    if (count != 0)
    {
        maxCols = (int16_t)(((this->right - this->left) - this->xIndent) / this->cellW);
        this->cols = maxCols;
        if (count < (uint16_t)maxCols)
            this->cols = (int16_t)count;
        rows = (int16_t)(((count - 1) + this->cols) / this->cols);
        if (rows == 1 && count > 3)
            rows = 2;
        this->gridX = (int16_t)(this->xIndent + this->left);
        this->cols = (int16_t)((count + rows - 1) / rows);
        this->gridTop = (int16_t)((this->bottom + this->top) / 2 - (rows * this->cellH) / 2);
        this->gridRight = (int16_t)(this->cols * this->cellW + this->gridX);
        this->gridBottom = (int16_t)(rows * this->cellH + this->gridTop);
        this->pHover = NULL;
        this->bShown = 1;
        this->Invalidate(); // vtbl +0x34
    }
    // Capture the mouse even when nothing was eligible (binary quirk).
    dwWidget_pMouseTarget = this;
}

// dwWcBlueprints_Hide
void dwWcBlueprints::Hide()
{
    if (dwWidget_pMouseTarget == this)
        dwWidget_pMouseTarget = NULL;
    this->bShown = 0;
    this->Invalidate(); // binary: tail-jump vtbl +0x34
}

// vtbl +0x44 dwWcBlueprints_Draw
void dwWcBlueprints::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    dwPoint apex;
    dwPoint aEnds[2];
    dwListNode* pNode;
    dwPart* pBp;
    int16_t x, y;
    int16_t col;

    if (this->bShown == 0)
        return;

    // Translucent cone from the widget's left mid-height to the grid's left
    // edge. The binary passed &gridX (fields 0x12-0x18) as the two edge
    // points — i.e. paEnds[0] = (gridX, gridTop), paEnds[1] = (gridRight,
    // gridBottom); FillTriBlend walks columns using paEnds[0].x.
    apex.x = this->left;
    apex.y = (int16_t)(this->gridTop + (this->gridBottom - this->gridTop) / 2);
    aEnds[0].x = this->gridX;
    aEnds[0].y = this->gridTop;
    aEnds[1].x = this->gridRight;
    aEnds[1].y = this->gridBottom;
    dwImageDraw_FillTriBlend(pDestBits, this->backdropColor, &apex, aEnds, pClipRect);

    // Blueprint cells: hovered one full-color (Blit), the rest through the
    // colormap (BlitColorMap — the dimmed look).
    x = (int16_t)(this->left + this->xIndent);
    y = this->gridTop;
    col = 0;
    for (pNode = dwCore_pBlueprintList->pNext; pNode != dwCore_pBlueprintList; pNode = pNode->pNext)
    {
        pBp = (dwPart*)pNode->pData;
        if (!dwWcBlueprints_IsEligible(this, pBp))
            continue;
        if (pBp == this->pHover)
            pBp->pIcon->Blit(pDestBits, x, y, pClipRect);         // vtbl +0x04
        else
            pBp->pIcon->BlitColorMap(pDestBits, x, y, pClipRect); // vtbl +0x08
        col++;
        if (col == this->cols)
        {
            x = (int16_t)(this->left + this->xIndent);
            y = (int16_t)(y + this->cellH);
            col = 0;
        }
        else
        {
            x = (int16_t)(x + this->cellW);
        }
    }
}

// vtbl +0x04 dwWcBlueprints_OnMouseMove — hover tracking. Always
// returns 0.
int dwWcBlueprints::OnMouseMove(int16_t x, int16_t y)
{
    dwPart* pNewHover;
    dwListNode* pNode;
    dwPart* pBp;
    dwWidgetMsg msg;
    int16_t colIdx, rowIdx;
    int16_t target;

    pNewHover = NULL;
    if (this->bShown != 0 && dwRect_ContainsPoint(this->GetRectPtr(), x, y))
    {
        if (this->pHover != NULL && dwRect_ContainsPoint(&this->hoverRect, x, y))
        {
            pNewHover = this->pHover; // still over the same cell
        }
        else
        {
            colIdx = (int16_t)((x - this->gridX) / this->cellW);
            rowIdx = (int16_t)((y - this->gridTop) / this->cellH);
            target = (int16_t)(rowIdx * this->cols + colIdx + 1);

            pNode = dwCore_pBlueprintList->pNext;
            pBp = NULL;
            // Walk to the target'th eligible blueprint (binary loop shape:
            // decrement per eligible record, stop at zero or list end).
            while (pNode != dwCore_pBlueprintList)
            {
                pBp = (dwPart*)pNode->pData;
                if (dwWcBlueprints_IsEligible(this, pBp))
                    target--;
                if (target == 0)
                    break;
                pNode = pNode->pNext;
            }
            if (target == 0 && pNode != dwCore_pBlueprintList)
            {
                pNewHover = pBp;
                msg.code = 0x7d0;
                msg.pSender = pBp;
                msg.param = 0;
                msg.pTarget = NULL;
                dwWidget_DispatchMsg(&msg, NULL);
                dwDisplay_AddDirtyRect(&this->hoverRect); // repaint the old cell
                this->hoverRect.left = (int16_t)(colIdx * this->cellW + this->gridX);
                this->hoverRect.top = (int16_t)(rowIdx * this->cellH + this->gridTop);
                this->hoverRect.right = (int16_t)(this->hoverRect.left + this->cellW);
                this->hoverRect.bottom = (int16_t)(this->hoverRect.top + this->cellH);
            }
        }
    }
    if (this->pHover != pNewHover)
    {
        dwDisplay_AddDirtyRect(&this->hoverRect);
        this->pHover = pNewHover;
    }
    return 0;
}

// vtbl +0x08 dwWcBlueprints_OnMouseDown
int dwWcBlueprints::OnMouseDown(int16_t x, int16_t y)
{
    dwWidgetMsg msg;
    dwWidget* pTarget;
    int bInHoverCell;

    if (this->bShown == 0)
        return 0;

    bInHoverCell = 0;
    if (this->pHover != NULL)
    {
        if (x >= this->hoverRect.left && x < this->hoverRect.right
            && y >= this->hoverRect.top && y < this->hoverRect.bottom)
        {
            bInHoverCell = 1;
        }
    }

    if (bInHoverCell)
    {
        // Select the hovered blueprint.
        dwSound_PlayRestart("WSelectModel.wav");
        msg.code = 0x7d1;
        msg.pSender = this->pHover;
        msg.param = 0;
        msg.pTarget = NULL;
        dwWidget_DispatchMsg(&msg, NULL);
        msg.code = 0x7e6; // close (pSender still the blueprint — binary reuse)
        dwWidget_DispatchMsg(&msg, NULL);
        return 0;
    }

    // Clicked outside: broadcast the close, hide, and re-forward the click
    // to whoever should have received it.
    msg.code = 0x7e6;
    msg.pSender = NULL;
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);
    this->Hide();
    pTarget = dwWidget_pMouseTarget;
    if (pTarget == NULL)
        pTarget = dwWidget_pDefault;
    if (pTarget != NULL && pTarget->bEnabled != 0)
        return pTarget->OnMouseDown(x, y); // vtbl +0x08
    return 0;
}

// vtbl +0x1c dwWcBlueprints_OnMessage
int dwWcBlueprints::OnMessage(dwWidgetMsg* pMsg)
{
    if (pMsg->code == 0x7e4)
    {
        // Body type changed: 1 = biped, 2 = cargo -> the slot-mask filter.
        this->slotMask = (uint32_t)(uintptr_t)pMsg->pSender;
    }
    else if (pMsg->code == 0x7e5)
    {
        // Part-type bits from the category button: refresh or open.
        this->typeBits = (uint32_t)(uintptr_t)pMsg->pSender;
        if (this->bShown != 0)
            this->Invalidate();
        else
            this->BuildGrid();
    }
    else if (pMsg->code == 0x7e6)
    {
        if (this->bShown != 0)
            this->Hide();
    }
    return 0;
}

// ---------------------------------------------------------------------------
// dwWcChildDecorator (dwWcChildDecorator_vtbl)
// ---------------------------------------------------------------------------

// No standalone binary ctor — subclasses inline this sequence (the widget
// rect is COPIED FROM the child; see dwWcPalette_Ctor).
dwWcChildDecorator::dwWcChildDecorator(dwWidget* pChildWidget)
    : dwWidget(pChildWidget->GetRectPtr())
    , pChild(pChildWidget)
{
}

// dwWcChildDecorator_Dtor (scalar-deleting wrapper dwWcChildDecorator_DtorDelete)
dwWcChildDecorator::~dwWcChildDecorator()
{
    this->pChild->FreeImages(); // vtbl +0x40
    if (this->pChild != NULL)
        delete this->pChild;
}

int dwWcChildDecorator::OnMouseMove(int16_t x, int16_t y)
{
    return this->pChild->OnMouseMove(x, y);
}

int dwWcChildDecorator::OnMouseDown(int16_t x, int16_t y)
{
    return this->pChild->OnMouseDown(x, y);
}

int dwWcChildDecorator::OnMouseUp(int16_t x, int16_t y)
{
    return this->pChild->OnMouseUp(x, y);
}

int dwWcChildDecorator::OnKey(int key, int repeat)
{
    return this->pChild->OnKey(key, repeat);
}

void dwWcChildDecorator::Update(float dt)
{
    this->pChild->Update(dt);
}

int dwWcChildDecorator::OnHover(int16_t x, int16_t y)
{
    return this->pChild->OnHover(x, y);
}

int dwWcChildDecorator::OnMessage(dwWidgetMsg* pMsg)
{
    return this->pChild->OnMessage(pMsg);
}

void dwWcChildDecorator::Enable()
{
    this->bEnabled = 1;
    this->pChild->Enable();
}

void dwWcChildDecorator::Disable()
{
    this->bEnabled = 0;
    this->pChild->Disable();
}

void dwWcChildDecorator::Move(int16_t dx, int16_t dy)
{
    this->left = (int16_t)(this->left + dx);
    this->top = (int16_t)(this->top + dy);
    this->right = (int16_t)(this->right + dx);
    this->bottom = (int16_t)(this->bottom + dy);
    this->pChild->Move(dx, dy);
}

// (Ghidra: dwWcChildDecorator_EnsureLoaded)
void dwWcChildDecorator::EnsureImages()
{
    this->pChild->EnsureImages();
}

void dwWcChildDecorator::FreeImages()
{
    this->pChild->FreeImages();
}

void dwWcChildDecorator::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    this->pChild->DrawChild(pDestBits, pClipRect);
}

// ---------------------------------------------------------------------------
// dwWcPalette (dwWcPalette_vtbl)
// ---------------------------------------------------------------------------

// dwWcPalette_Ctor
dwWcPalette::dwWcPalette(dwRect* pRect)
    : dwWcChildDecorator(new dwWcBuildButton((char*)"wcbuildn", pRect))
    , mode(0)
    , variant(1)
    , bRandomConfirmed(0)
{
}

// dwWcPalette_Dtor (scalar-deleting wrapper dwWcPalette_DtorDelete) — the binary
// body is byte-identical to the decorator dtor (no own resources).
dwWcPalette::~dwWcPalette()
{
}

// dwWcPalette_SetMode
void dwWcPalette::SetMode(int newMode)
{
    dwAnim* pAnim;

    this->mode = newMode;
    if (this->pChild != NULL)
    {
        delete this->pChild;
        this->pChild = NULL;
    }

    if (this->mode == 1)
    {
        this->pChild = new dwWcPaintButton(this->GetRectPtr());
    }
    else if (this->mode == 2 || this->mode == 3)
    {
        // Transition FLCs; their finish messages (0x7e9/0x7ea via the
        // dwAnimBase 0x2328 broadcast) advance to the settled mode.
        if (this->mode == 2)
            pAnim = dwAnim_Open(this->GetRectPtr(), (char*)"WBuildPaint.flc", 0x7e9, 0);
        else
            pAnim = dwAnim_Open(this->GetRectPtr(), (char*)"WPaintBuild.flc", 0x7ea, 0);
        if (pAnim != NULL)
        {
            pAnim->Play((uint8_t)1); // non-virtual dwAnim::Play
            dwSound_PlayRestart("WModeSwitch.wav");
        }
        this->pChild = pAnim;
    }
    else if (this->mode == 0)
    {
        if (this->variant == 1)
            this->pChild = new dwWcBuildButton((char*)"wcbuildn", this->GetRectPtr());
        else
            this->pChild = new dwWcBuildButton((char*)"wcbuildc", this->GetRectPtr());
    }
    this->Invalidate(); // vtbl +0x34
}

// vtbl +0x1c dwWcPalette_OnMessage — every path forwards the
// message to the child afterwards.
int dwWcPalette::OnMessage(dwWidgetMsg* pMsg)
{
    dwWidgetMsg msg;
    int confirmed;

    if (pMsg->code == 0x7e4)
    {
        // Body type changed: close the fly-out, relabel the build button.
        if ((int)(intptr_t)pMsg->pSender != this->variant)
        {
            msg.code = 0x7e6;
            msg.pSender = NULL;
            msg.param = 0;
            msg.pTarget = NULL;
            dwWidget_DispatchMsg(&msg, NULL);
            dwSound_PlayRestart("WLocMode.wav");
            this->variant = (int)(intptr_t)pMsg->pSender;
        }
    }
    else if (pMsg->code == 0x7dd)
    {
        this->bRandomConfirmed = 0;
    }
    else if (pMsg->code == 0x2328)
    {
        // A palette transition FLC finished: re-dispatch its code as the
        // settled-mode message (0x7e9 -> paint button, 0x7ea -> build).
        if ((int)(intptr_t)pMsg->pSender == 0x7e9 || (int)(intptr_t)pMsg->pSender == 0x7ea)
        {
            msg.code = (int)(intptr_t)pMsg->pSender;
            msg.pSender = NULL;
            msg.param = 0;
            msg.pTarget = NULL;
            dwWidget_DispatchMsg(&msg, NULL);
        }
    }
    else if (pMsg->code == 0x7e7)
    {
        if (this->mode != 1)
            this->SetMode(2);
    }
    else if (pMsg->code == 0x7e8)
    {
        if (this->mode != 0)
            this->SetMode(3);
    }
    else if (pMsg->code == 0x7e9)
    {
        this->SetMode(1);
    }
    else if (pMsg->code == 0x7ea)
    {
        this->SetMode(0);
    }
    else if (pMsg->code == 0x7eb)
    {
        // RANDOMIZE: confirm once (when the workspace has parts), then
        // rebuild a random droid.
        if (this->bRandomConfirmed == 0 && dwCore_pWorkspaceNodes != dwCore_pWorkspaceNodes->pNext)
        {
            confirmed = dwGuiDialog_RunModal("gyesno", "DLG_RANDOMIZE");
            this->bRandomConfirmed = (confirmed == 5000) ? 1 : 0;
        }
        else
        {
            this->bRandomConfirmed = 1;
        }
        if (this->bRandomConfirmed != 0)
        {
            dwSound_PlayLooping("WRandom2.wav");
            dwDroidStats_AutoBuildRandom(this->variant, &dwCore_pWorkspaceNodes);
            dwSound_Stop("WRandom2.wav");
            dwSound_PlayRestart("WRandom3.wav");
        }
    }
    // (0x7dc falls through with no palette action — binary quirk.)

    return this->pChild->OnMessage(pMsg); // vtbl +0x1c
}

// ---------------------------------------------------------------------------
// dwWcArrows (dwWcArrows_vtbl) — dwGuiButton subclass, declared in dwGuiButton.h
// ---------------------------------------------------------------------------

// Rotate command table (binary rdata dwWcArrows_aCmdIds, indexed by button id 1..5).
static const int dwWcArrows_aCmdIds[6] = { 0, 0x7de, 0x7df, 0x7e0, 0x7e1, 0x7db };

// dwWcArrows_Ctor
dwWcArrows::dwWcArrows(dwRect* pRect)
    : dwGuiButton((char*)"wcarrows", pRect)
{
}

// dwWcArrows_Dtor (scalar-deleting wrapper dwWcArrows_DtorDelete) — vptr re-point
// + base dtor only.
dwWcArrows::~dwWcArrows()
{
}

// vtbl +0x04 dwWcArrows_OnMouseMove (recovered fn) — after the base tracking, press/release
// the arrow the cursor moved onto/off of (hold-to-rotate repeat).
int dwWcArrows::OnMouseMove(int16_t x, int16_t y)
{
    uint32_t oldShown;
    uint32_t newShown;
    int result;

    oldShown = (uint32_t)this->shownButtonId;
    result = dwGuiButton::OnMouseMove(x, y);
    newShown = (uint32_t)this->shownButtonId;
    if (oldShown != newShown)
    {
        if (newShown == 0 && oldShown < 5)
            this->OnButtonReleased((int)oldShown); // vtbl +0x4c
        else if (newShown < 5)
            this->OnButtonPressed((int)newShown);  // vtbl +0x48
    }
    return result;
}

// vtbl +0x08 dwWcArrows_OnMouseDown (recovered fn) — arrows fire on PRESS (ids 1-4), not
// just on the completed click.
int dwWcArrows::OnMouseDown(int16_t x, int16_t y)
{
    uint32_t shown;
    int result;

    result = dwGuiButton::OnMouseDown(x, y);
    shown = (uint32_t)this->shownButtonId;
    if (shown != 0 && shown < 5)
        this->OnButtonPressed((int)shown); // vtbl +0x48
    return result;
}

// vtbl +0x48 (Ghidra: dwWcArrows_HitTest — misnamed; this is the
// press-action hook)
void dwWcArrows::OnButtonPressed(int buttonId)
{
    dwWidgetMsg msg;
    const char* pSnd;
    int cmd;

    if (buttonId == 0)
        return;
    cmd = dwWcArrows_aCmdIds[buttonId];
    if (cmd == 0x7db)
    {
        pSnd = "WPosReset.wav";
    }
    else
    {
        // Quirk preserved: on a completed click the base already cleared
        // shownButtonId, so the release path plays the "off" sound here.
        pSnd = (this->shownButtonId != 0) ? "WRotButtnOn.wav" : "WRotButtnOff.wav";
    }
    dwSound_PlayRestart(pSnd);
    msg.code = cmd;
    msg.pSender = NULL;
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);
    this->Invalidate(); // vtbl +0x34
}

// vtbl +0x4c (Ghidra: dwWcArrows_OnAction)
void dwWcArrows::OnButtonReleased(int buttonId)
{
    dwWidgetMsg msg;
    int cmd;

    cmd = dwWcArrows_aCmdIds[buttonId];
    msg.code = cmd;
    msg.pSender = NULL;
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);
    this->Invalidate();
    if (cmd != 0x7db)
    {
        dwSound_Stop("WRotButtnOn.wav");
        dwSound_PlayRestart("WRotButtnOff.wav");
    }
}

// vtbl +0x18 dwWcArrows_OnHover (recovered fn)
int dwWcArrows::OnHover(int16_t x, int16_t y)
{
    dwWidgetMsg msg;

    (void)x; (void)y;
    msg.code = 0x7531;
    msg.pSender = (void*)(intptr_t)0x7de;
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);
    return 1;
}

// ---------------------------------------------------------------------------
// dwWcBuildButton (dwWcBuildButton_vtbl)
// ---------------------------------------------------------------------------

// Part-type bit sets by button id 1..6 (binary switch switchD).
static const int dwWcBuildButton_aTypeBits[7] = { 0, 0x18a, 0x20, 0x14, 0x200, 0x1, 0x40 };

// dwWcBuildButton_Ctor
dwWcBuildButton::dwWcBuildButton(char* pName, dwRect* pRect)
    : dwGuiButton(pName, pRect)
{
}

// (scalar-deleting dtor = shared COMDAT dwWcButton_DtorDelete)
dwWcBuildButton::~dwWcBuildButton()
{
}

// vtbl +0x48 dwWcBuildButton_OnButtonPressed (recovered fn)
void dwWcBuildButton::OnButtonPressed(int buttonId)
{
    dwWidgetMsg msg;
    int bits;

    if (buttonId >= 1 && buttonId <= 6)
        bits = dwWcBuildButton_aTypeBits[buttonId];
    else
        bits = buttonId; // binary default case: the raw id
    dwSound_PlayRestart("WPartButton.wav");
    msg.code = 0x7e5;
    msg.pSender = (void*)(intptr_t)bits;
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);
    this->Invalidate();
}

// vtbl +0x4c dwWcBuildButton_OnButtonReleased (recovered fn)
void dwWcBuildButton::OnButtonReleased(int buttonId)
{
    dwWidgetMsg msg;

    (void)buttonId;
    msg.code = 0x7e6;
    msg.pSender = NULL;
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);
    this->Invalidate();
}

// vtbl +0x1c dwWcBuildButton_OnMessage (recovered fn) — the fly-out closed: unlatch.
int dwWcBuildButton::OnMessage(dwWidgetMsg* pMsg)
{
    if (pMsg->code == 0x7e6)
        this->ClearPressed();
    return 0;
}

// vtbl +0x18 dwWcBuildButton_OnHover (recovered fn)
int dwWcBuildButton::OnHover(int16_t x, int16_t y)
{
    dwWidgetMsg msg;
    int hitId;

    hitId = this->HitTest(x, y);
    if (hitId != 0)
    {
        msg.code = 0x7531;
        msg.pSender = (void*)(intptr_t)0x7e5;
        msg.param = hitId;
        msg.pTarget = NULL;
        dwWidget_DispatchMsg(&msg, NULL);
    }
    return 1;
}

// ---------------------------------------------------------------------------
// dwWcPaintButton (dwWcPaintButton_vtbl)
// ---------------------------------------------------------------------------

// dwWcPaintButton_Ctor
dwWcPaintButton::dwWcPaintButton(dwRect* pRect)
    : dwGuiButton((char*)"wcpaint", pRect)
{
}

// (scalar-deleting dtor = shared COMDAT dwWcButton_DtorDelete)
dwWcPaintButton::~dwWcPaintButton()
{
}

// vtbl +0x48 dwWcPaintButton_OnButtonPressed (recovered fn)
void dwWcPaintButton::OnButtonPressed(int buttonId)
{
    dwWidgetMsg msg;

    dwSound_PlayRestart("WPaintSelect.wav");
    msg.code = 0x7d3;
    msg.pSender = (void*)(intptr_t)buttonId;
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);
    this->Invalidate();
}

// vtbl +0x4c dwWcPaintButton_OnButtonReleased (recovered fn)
void dwWcPaintButton::OnButtonReleased(int buttonId)
{
    dwWidgetMsg msg;

    (void)buttonId;
    msg.code = 0x7d3;
    msg.pSender = NULL;
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);
    this->Invalidate();
}

// vtbl +0x1c dwWcPaintButton_OnMessage (recovered fn) — a { 0x7d3, 0 } deselect while a color
// is latched unlatches it.
int dwWcPaintButton::OnMessage(dwWidgetMsg* pMsg)
{
    if (pMsg->code == 0x7d3 && pMsg->pSender == NULL && this->shownButtonId != 0)
        this->ClearPressed();
    return 0;
}

// vtbl +0x18 dwWcPaintButton_OnHover (recovered fn)
int dwWcPaintButton::OnHover(int16_t x, int16_t y)
{
    dwWidgetMsg msg;
    int hitId;

    hitId = this->HitTest(x, y);
    if (hitId != 0)
    {
        msg.code = 0x7531;
        msg.pSender = (void*)(intptr_t)0x7d3;
        msg.param = hitId;
        msg.pTarget = NULL;
        dwWidget_DispatchMsg(&msg, NULL);
    }
    return 1;
}

// ---------------------------------------------------------------------------
// dwWcBuildPaintButton (dwWcBuildPaintButton_vtbl; ctor inlined)
// ---------------------------------------------------------------------------

// Binary: inline ctor in dwWorkshop_CreateControl (keyword "BUILD/PAINT",
// alloc 0x38): dwGuiButton("wcbuildpaint", &rect); vptr; SetPressed(2).
dwWcBuildPaintButton::dwWcBuildPaintButton(dwRect* pRect)
    : dwGuiButton((char*)"wcbuildpaint", pRect)
{
    this->SetPressed(2);
}

dwWcBuildPaintButton::~dwWcBuildPaintButton()
{
}

// vtbl +0x48 dwWcBuildPaintButton_OnButtonPressed (recovered fn) — button 1 = build (0x7e7), 2 = paint (0x7e8).
void dwWcBuildPaintButton::OnButtonPressed(int buttonId)
{
    dwWidgetMsg msg;

    msg.code = (buttonId == 1) ? 0x7e7 : 0x7e8;
    msg.pSender = NULL;
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);
    this->Invalidate();
}

// vtbl +0x4c dwWcCargoNormalButton_OnButtonReleased (shared tiny body emitted in the dwWorkshop unit)
void dwWcBuildPaintButton::OnButtonReleased(int buttonId)
{
    (void)buttonId;
    this->Invalidate();
}

// vtbl +0x18 dwWcBuildPaintButton_OnHover (recovered fn)
int dwWcBuildPaintButton::OnHover(int16_t x, int16_t y)
{
    dwWidgetMsg msg;
    int hitId;

    hitId = this->HitTest(x, y);
    if (hitId == 0)
        return 0;
    msg.code = 0x7531;
    msg.pSender = (void*)(intptr_t)((hitId == 1) ? 0x7e7 : 0x7e8);
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);
    return 1;
}

// ---------------------------------------------------------------------------
// dwWcCargoNormalButton (dwWcCargoNormalButton_vtbl; ctor inlined)
// ---------------------------------------------------------------------------

// Binary: inline ctor in dwWorkshop_CreateControl (keyword "CARGO/NORMAL",
// alloc 0x3c): dwGuiButton("wccargonorm", &rect); vptr; bSuppressConfirm = 1;
// SetPressed(2); bSuppressConfirm = 0.
dwWcCargoNormalButton::dwWcCargoNormalButton(dwRect* pRect)
    : dwGuiButton((char*)"wccargonorm", pRect)
    , bSuppressConfirm(0)
{
    this->bSuppressConfirm = 1;
    this->SetPressed(2);
    this->bSuppressConfirm = 0;
}

dwWcCargoNormalButton::~dwWcCargoNormalButton()
{
}

// vtbl +0x48 dwWcCargoNormalButton_OnButtonPressed (recovered fn) — the body-type switch, with a yes/no
// confirmation when the workspace still has parts.
void dwWcCargoNormalButton::OnButtonPressed(int buttonId)
{
    dwWidgetMsg msg;
    int confirmed;

    confirmed = 1;
    if (dwCore_pWorkspaceNodes != (dwListNode*)dwCore_pWorkspaceNodes->pNext
        && this->bSuppressConfirm == 0)
    {
        confirmed = (dwGuiDialog_RunModal("gyesno",
                        (buttonId == 1) ? "DLG_BUILDBIPED" : "DLG_BUILDCARGO") == 5000);
        if (confirmed)
        {
            // Clear the droid before switching body type.
            msg.code = 0x7d5;
            msg.pSender = NULL;
            msg.param = 0;
            msg.pTarget = NULL;
            dwWidget_DispatchMsg(&msg, NULL);
        }
    }
    if (confirmed)
    {
        msg.code = 0x7e4;
        // Binary: the button requests the OTHER body type (button 1
        // asks for 2=cargo, matching its DLG_BUILDBIPED "switch to treads"
        // text) — the inverted 1:1 mapping here made the toggle ask for the
        // type already active, so the switch never happened (BUG 22).
        msg.pSender = (void*)(intptr_t)((buttonId == 1) ? 2 : 1);
        msg.param = 0;
        msg.pTarget = NULL;
        dwWidget_DispatchMsg(&msg, NULL);
        this->Invalidate();
    }
    else
    {
        // Declined: snap the shown frame back to the previous body type.
        this->shownButtonId = (buttonId == 1) ? 2 : 1;
        this->Invalidate();
    }
}

// vtbl +0x4c dwWcCargoNormalButton_OnButtonReleased (shared tiny body)
void dwWcCargoNormalButton::OnButtonReleased(int buttonId)
{
    (void)buttonId;
    this->Invalidate();
}

// vtbl +0x1c dwWcCargoNormalButton_OnMessage (recovered fn) — mirror an external body-type change
// into the shown frame (mode 2 shows frame 1 and vice versa — the frames
// display the button that SWITCHES AWAY from the current type).
int dwWcCargoNormalButton::OnMessage(dwWidgetMsg* pMsg)
{
    if (pMsg->code == 0x7e4)
    {
        if ((int)(intptr_t)pMsg->pSender == 2)
            this->shownButtonId = 1;
        else
            this->shownButtonId = 2;
        this->Invalidate();
    }
    return 0;
}

// vtbl +0x18 dwWcCargoNormalButton_OnHover (recovered fn)
int dwWcCargoNormalButton::OnHover(int16_t x, int16_t y)
{
    dwWidgetMsg msg;

    if (this->HitTest(x, y) == 0)
        return 0;
    msg.code = 0x7531;
    msg.pSender = (void*)(intptr_t)0x7e4;
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);
    return 1;
}
