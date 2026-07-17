// dwAnim — the DroidWorks animation WIDGET family: dwAnimBase (message-
// toggled anim base, +0x48 Play / +0x4c Stop new virtuals), dwAnim (FLC
// widget player) and dwGuiAnimView (MI reference-room anim viewer), plus the
// dwAnim_Open factory.
//
// Decompiled from DroidWorks.exe, unit range 0x401000-0x404010 (widget half;
// the segment half is dwMovie.cpp, the rdKeyframe helpers dwKeyframe.c).
// vtables: dwAnimBase 0x51e1d0 · dwAnim 0x51e000 · dwGuiAnimView 0x51e180
// (primary) + 0x51e138 (dwWidgetGroup secondary; the compiler regenerates
// the binary's this-adjustor thunks @403780-4037e0).
//
// Adaptations (all marked // Note: below):
//  - jk_logtofile -> stdPlatform_Printf (the binary's jk_logtofile is a
//    compiled-out no-op stub, same as the other translated units).
//  - stdBitmapRle2 frame images: the RLE bitmap class is NOT translated yet
//    (P8). dwAnim::EnsureImages calls two placeholder factories at the
//    bottom of this file that currently return NULL (frames stay empty,
//    draw is skipped) — see the TODO(dw-decomp) block.
//
// No module statics — no Startup hook needed here (soft-reset rule).

#include "Dw/dwAnim.h"

#include "Dw/dwFlic.h"
#include "Dw/dwGuiHypText.h"
#include "Dw/dwImage.h"

#include "jk.h"
#include "stdPlatform.h"

extern "C" HostServices* dwMain_pHS; // the DW host-services pointer (dwMain.c); binary global dwHS @0x6b6258

// Provided by the stdBitmapRle2 engine-side unit (P8, stdBitmapRle2.cpp). The
// binary split each call into `operator new(0x18)` + a __thiscall ctor
// (@442df0 / @442ec0); these 64-bit factories fold that pair.
extern "C" dwImage* stdBitmapRle2_Instantiate(int16_t width, int16_t height, int bpp);         // @442df0
extern "C" dwImage* stdBitmapRle2_InstantiateCopy(dwImage* pSrc, int16_t width, int16_t height); // @442ec0

// ---- dwAnimBase -------------------------------------------------------------

// @4038f0 (dwAnimBase_Ctor)
dwAnimBase::dwAnimBase(dwRect* pRect, int msgCode, uint8_t bLoop)
    : dwWidget(pRect)
{
    this->bPlaying = 0;
    this->msgCode = msgCode;
    this->bLoop = bLoop;
}

// @403940 (dwAnimBase_Dtor; scalar-deleting wrapper @403920) — vptr re-point
// + dwWidget base dtor only, both implicit here.
dwAnimBase::~dwAnimBase()
{
}

// vtbl +0x1c @403950 (dwAnimBase_OnMessage) — toggle on our message code.
// Always returns 0 (the binary returns with AL's surroundings masked off).
int dwAnimBase::OnMessage(dwWidgetMsg* pMsg)
{
    if (pMsg->code == this->msgCode)
    {
        if (this->bPlaying != 0)
            this->Stop(); // virtual +0x4c
        else
            this->Play(); // virtual +0x48
    }
    return 0;
}

// vtbl +0x48 @403980 (dwAnimBase_Play)
void dwAnimBase::Play()
{
    this->bPlaying = 1;
    this->Invalidate(); // binary: tail-jump through vtbl +0x34
}

// vtbl +0x4c @403990 (dwAnimBase_Stop) — stop + broadcast "anim finished".
void dwAnimBase::Stop()
{
    dwWidgetMsg msg;

    if (this->bPlaying == 0)
        return;
    this->bPlaying = 0;
    this->Invalidate(); // vtbl +0x34

    msg.code = 0x2328; // 9000: anim-finished notification
    msg.pSender = (void*)(intptr_t)this->msgCode;
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL); // -> dwWidget_pDefault
}

// ---- dwAnim -------------------------------------------------------------------

// @401000 (dwAnim_Ctor)
dwAnim::dwAnim(dwRect* pRect, const char* pFilename, int msgCode, uint8_t bLoop, float fps)
    : dwAnimBase(pRect, msgCode, bLoop)
    , fps(fps)
    , accumTimeSec(0.0f) // Note: uninitialized in the binary until Play()
    , frameCount(0)
    , curFrame(0)        // Note: uninitialized in the binary until EnsureImages()
    , paFrames(NULL)
    , filename()
    , bUpdatedThisFrame(0) // Note: uninitialized in the binary until Play()
{
    if (pFilename != NULL)
    {
        this->filename.AssignCStr(pFilename);
        dwAnim::EnsureImages(); // binary: direct call @401200 (frames loaded in the ctor)
    }
}

// @4010c0 (dwAnim_Dtor; scalar-deleting wrapper @4010a0)
dwAnim::~dwAnim()
{
    dwAnim::FreeImages(); // binary: direct call @4013c0
    // filename ~dwString + base dtors run implicitly.
}

// vtbl +0x14 @401120 (dwAnim_Update)
void dwAnim::Update(float dt)
{
    uint32_t frame;

    if (this->bPlaying != 0 && this->bUpdatedThisFrame == 0)
    {
        this->accumTimeSec = dt + this->accumTimeSec;
        frame = (uint32_t)(int32_t)(this->fps * this->accumTimeSec); // binary: __ftol
        if (frame >= this->frameCount)
        {
            if (this->bLoop == 0)
            {
                this->Stop(); // virtual +0x4c (play-once reached the end)
                frame = this->curFrame;
            }
            else
            {
                frame = frame % this->frameCount;
            }
        }
        if (frame != this->curFrame)
        {
            this->curFrame = frame;
            this->Invalidate(); // vtbl +0x34
        }
    }
    this->bUpdatedThisFrame = 0; // cleared unconditionally (faithful)
}

// vtbl +0x3c @401200 (Ghidra: dwAnim_EnsureLoaded — the EnsureImages slot).
// Decodes the whole FLC up front. Frame 0 gets a fresh WxH 8bpp RLE image;
// every later frame is constructed as a COPY of the previous frame's image
// so the FLC delta chunks accumulate correctly.
void dwAnim::EnsureImages()
{
    dwFlic flic;
    dwImage* pImg;
    dwFlicBits bits;
    void* pPixels;
    int stride;
    uint32_t i;

    if (this->paFrames != NULL || this->filename.length == 0)
        return;

    // Note: dwFlic_Open always returns 0, even on open failure (see
    // dwFlic.h) — the check is faithful but vestigial; a missing file yields
    // numFrames == 0 from the zeroed header read below in practice.
    if (dwFlic_Open(&flic, this->filename.pBuffer) != 0)
        return;

    this->frameCount = (uint32_t)(int16_t)flic.numFrames;
    this->curFrame = 0;
    this->paFrames = (dwImage**)dwMain_pHS->alloc((int16_t)flic.numFrames * sizeof(dwImage*));
    pImg = NULL;
    for (i = 0; i < (uint32_t)(int16_t)flic.numFrames; i++)
    {
        if (pImg == NULL)
            pImg = stdBitmapRle2_Instantiate((int16_t)flic.width, (int16_t)flic.height, 8);
        else
            pImg = stdBitmapRle2_InstantiateCopy(pImg, (int16_t)flic.width, (int16_t)flic.height);

        // Note: added guard — the binary only guarded the operator-new
        // result and would crash on a NULL image; with the P8 placeholder
        // factories returning NULL this skips decoding instead (the frame
        // slot stays NULL and Draw skips it).
        if (pImg != NULL)
        {
            pPixels = NULL;
            stride = 0;
            pImg->Lock(&pPixels, &stride); // vtbl +0x0c
            bits.pPixels = (uint8_t*)pPixels;
            bits.width = (int16_t)pImg->desc.width;  // binary: read from the image object (+0x4/+0x6)
            bits.height = (int16_t)pImg->desc.height;
            bits.rowStride = stride;
            dwFlic_DecodeFrame(&flic, &bits, NULL);
            this->paFrames[i] = pImg;
            pImg->Unlock(); // vtbl +0x10
        }
        else
        {
            this->paFrames[i] = NULL;
        }
    }
    dwFlic_Close(&flic);
}

// vtbl +0x40 @4013c0 (Ghidra: dwAnim_FreeFrames — the FreeImages slot)
void dwAnim::FreeImages()
{
    uint32_t i;
    dwImage* pImg;

    if (this->paFrames == NULL)
        return;
    for (i = 0; i < this->frameCount; i++)
    {
        pImg = this->paFrames[i];
        if (pImg != NULL)
            delete pImg; // binary: vtbl slot 0 (scalar-deleting dtor, flag 1)
    }
    dwMain_pHS->free(this->paFrames);
    this->paFrames = NULL;
}

// vtbl +0x44 @4011c0 (dwAnim_Draw)
void dwAnim::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    dwImage* pImg;

    if (this->bPlaying == 0)
        return;
    this->EnsureImages(); // vtbl +0x3c
    if (this->paFrames == NULL) // Note: added guard — the binary dereferenced
        return;                 // paFrames unguarded (crash if loading failed)
    pImg = this->paFrames[this->curFrame];
    if (pImg != NULL)
        pImg->Blit(pDestBits, this->left, this->top, pClipRect); // vtbl +0x04
}

// @401190 (dwAnim_Play — non-virtual overload; the +0x48 virtual slot keeps
// dwAnimBase_Play). bSkipUpdate lands in bUpdatedThisFrame, making the next
// Update tick a no-op (callers pass 1 right after selecting a new anim).
void dwAnim::Play(uint8_t bSkipUpdate)
{
    this->EnsureImages(); // vtbl +0x3c
    this->bUpdatedThisFrame = bSkipUpdate;
    if (this->paFrames != NULL)
    {
        this->curFrame = 0;
        this->accumTimeSec = 0.0f;
        this->dwAnimBase::Play(); // binary: direct (non-virtual) call @403980
    }
}

// @4037f0 (dwAnim_Open) — extension-dispatch factory.
dwAnim* dwAnim_Open(dwRect* pRect, char* pFilename, int msgCode, uint8_t bLoop)
{
    dwAnim* pAnim;
    char* pExt;

    pAnim = NULL;
    pExt = pFilename;
    dwString_FindExtension(&pExt);
    if (*pExt == 0)
    {
        stdPlatform_Printf("Animation file has no extension: %s\n", pFilename); // binary: jk_logtofile (compiled-out stub)
    }
    else
    {
        pExt = pExt + 1;
        if (dwString_Equals(pExt, "FLI") || dwString_Equals(pExt, "FLC"))
        {
            pAnim = new dwAnim(pRect, pFilename, msgCode, bLoop, 15.0f);
        }
        else
        {
            dwString_Equals(pExt, "SAN"); // faithful quirk: result DISCARDED —
                                          // .san widget anims fall through to failure
        }
    }
    if (pAnim == NULL)
        stdPlatform_Printf("Error opening animation: %s\n", pFilename); // binary: jk_logtofile
    return pAnim;
}

// ---- dwGuiAnimView ---------------------------------------------------------------

// Item ctor (inlined in @4031f0 dwGuiAnimView_AddItem; freed by @4036b0
// dwGuiAnimView_ItemDtor / @403690 dwGuiAnimView_ItemDtorDelete).
dwGuiAnimViewItem::dwGuiAnimViewItem(const char* pAnimFile, int code, uint8_t flag,
                                     const char* pImageFile, const char* pExtraFile)
    : animFile(pAnimFile, 0)
    , code(code)
    , flag(flag)
    , imageFile(pImageFile, 0)
    , extraFile(pExtraFile, 0)
{
}

// @402cf0 (dwGuiAnimView_Ctor)
dwGuiAnimView::dwGuiAnimView(dwRect* pRect, const char* pImageFilename, int itemCode)
    : dwAnimBase(pRect, 0, 1)
    , dwWidgetGroup(pRect)
    , items()
    , pImage(NULL)
    , itemCode(itemCode)
    , filename()
    , itemCount(0)
    , bAnimStarted(0)
    , pAnimPlayer(NULL)
{
    this->filename.AssignCStr(pImageFilename);
    dwGuiAnimView::EnsureImages(); // binary: direct call @403500
}

// @402dd0 (dwGuiAnimView_Dtor; primary DtorDelete @402db0, group-vtbl thunk
// @403780)
dwGuiAnimView::~dwGuiAnimView()
{
    dwListNode* pSent;
    dwListNode* pNode;
    dwListNode* pNext;
    dwGuiAnimViewItem* pItem;

    dwGuiAnimView::FreeImages(); // binary: direct call

    if (this->pAnimPlayer != NULL)
        delete this->pAnimPlayer; // vtbl slot 0, flag 1
    if (this->pImage != NULL)
        delete this->pImage;

    // Free every item + its list node (binary: inline unlink/free-node then
    // dwGuiAnimView_ItemDtorDelete on the payload), then the sentinel.
    pSent = this->items.pSentinel;
    pNode = pSent->pNext;
    while (pNode != pSent)
    {
        pItem = (dwGuiAnimViewItem*)pNode->pData;
        pNext = pNode->pNext;
        this->items.UnlinkFreeNode(pNode);
        if (pItem != NULL)
            delete pItem; // @403690 (dwGuiAnimView_ItemDtorDelete)
        pNode = pNext;
    }
    this->items.Free();

    // filename ~dwString, the dwWidgetGroup base dtor (FreeChildImages +
    // delete children + node teardown) and the dwAnimBase base dtor all run
    // implicitly, matching the binary's tail sequence.
}

// vtbl +0x14 @403450 (dwGuiAnimView_Update; group-vtbl thunk @403790)
void dwGuiAnimView::Update(float dt)
{
    if (this->dwAnimBase::bEnabled != 0 && this->pAnimPlayer != NULL)
        this->pAnimPlayer->Update(dt); // virtual +0x14
    this->dwWidgetGroup::Update(dt);   // binary: direct (non-virtual) call @444620
}

// vtbl +0x18 @4032c0 (dwGuiAnimView_OnHover; group-vtbl thunk @4037a0) —
// same body shape as the shared dwWidget_OnHoverNotify COMDAT, with this
// view's itemCode as the payload.
int dwGuiAnimView::OnHover(int16_t x, int16_t y)
{
    (void)x;
    (void)y;
    return this->dwAnimBase::OnHoverNotify((void*)(intptr_t)this->itemCode);
}

// vtbl +0x1c @403050 (dwGuiAnimView_OnMessage; group-vtbl thunk @4037b0)
int dwGuiAnimView::OnMessage(dwWidgetMsg* pMsg)
{
    dwListNode* pSent;
    dwListNode* pNode;
    dwGuiAnimViewItem* pItem;
    dwGuiAnimViewItem* pFirst;

    // Select the item whose code matches this message.
    pSent = this->items.pSentinel;
    for (pNode = pSent->pNext; pNode != pSent; pNode = pNode->pNext)
    {
        pItem = (dwGuiAnimViewItem*)pNode->pData;
        if (pItem->code != pMsg->code)
            continue;

        if (this->pAnimPlayer != NULL && this->bPlaying != 0)
        {
            this->pAnimPlayer->Stop(); // virtual +0x4c
            this->bPlaying = 0;
            if (this->pAnimPlayer != NULL)
                delete this->pAnimPlayer;
            this->pAnimPlayer = NULL;
        }
        if (pItem->imageFile.length != 0)
        {
            if (this->pImage != NULL)
            {
                delete this->pImage;
                this->pImage = NULL;
            }
            this->filename.AssignString(&pItem->imageFile);
            this->pImage = dwImage_LoadFile(this->filename.pBuffer);
            this->dwAnimBase::Invalidate();
            this->dwWidgetGroup::Invalidate();
        }
        this->msgCode = pItem->code;
        this->pAnimPlayer = dwAnim_Open(this->dwWidgetGroup::GetRectPtr(),
                                        pItem->animFile.pBuffer, pItem->code, 0);
        this->bAnimStarted = 1;
        break;
    }

    if (pMsg->code == 0x1b62) // play
    {
        if (this->pAnimPlayer != NULL && this->bPlaying != 0)
        {
            this->pAnimPlayer->Stop();
            this->bPlaying = 0;
            this->dwAnimBase::Invalidate();
            this->dwWidgetGroup::Invalidate();
        }
        if (this->bAnimStarted == 0 && this->itemCount > 1)
        {
            // Nothing explicitly selected yet: fall back to the FIRST item.
            if (this->pAnimPlayer != NULL)
                delete this->pAnimPlayer;
            pFirst = (dwGuiAnimViewItem*)this->items.pSentinel->pNext->pData;
            this->msgCode = pFirst->code;
            this->pAnimPlayer = dwAnim_Open(this->dwWidgetGroup::GetRectPtr(),
                                            pFirst->animFile.pBuffer, pFirst->code, 0);
        }
        if (this->pAnimPlayer != NULL)
        {
            this->pAnimPlayer->Play((uint8_t)1); // the @401190 overload (skip next Update)
            this->bPlaying = 1;
            this->dwAnimBase::Invalidate();
            this->dwWidgetGroup::Invalidate();
        }
    }
    else if (pMsg->code == 0x1b63 && this->pAnimPlayer != NULL) // stop
    {
        this->pAnimPlayer->Stop();
        this->bPlaying = 0;
        this->dwAnimBase::Invalidate();
        this->dwWidgetGroup::Invalidate();
    }

    return dwAnimBase::OnMessage(pMsg); // binary: direct call @403950
}

// vtbl +0x3c @403500 (dwGuiAnimView_EnsureImages; group-vtbl thunk @4037c0)
void dwGuiAnimView::EnsureImages()
{
    if (this->pImage == NULL && this->filename.length != 0)
        this->pImage = dwImage_LoadFile(this->filename.pBuffer);
    if (this->pAnimPlayer != NULL)
        this->pAnimPlayer->EnsureImages(); // virtual +0x3c
    this->dwWidgetGroup::EnsureImages();   // binary: direct call @4447e0
}

// vtbl +0x40 @403540 (dwGuiAnimView_FreeImages; group-vtbl thunk @4037d0)
void dwGuiAnimView::FreeImages()
{
    if (this->pImage != NULL)
    {
        delete this->pImage;
        this->pImage = NULL;
    }
    if (this->pAnimPlayer != NULL)
        this->pAnimPlayer->FreeImages(); // virtual +0x40
    this->dwWidgetGroup::FreeImages();   // binary: direct call @43c040
}

// vtbl +0x44 @403480 (dwGuiAnimView_Draw; group-vtbl thunk @4037e0)
void dwGuiAnimView::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    dwRect clip;

    if (this->dwAnimBase::bEnabled != 0)
    {
        this->EnsureImages(); // vtbl +0x3c
        if (this->pImage != NULL)
        {
            // Still image at the GROUP rect origin.
            this->pImage->Blit(pDestBits, this->dwWidgetGroup::left,
                               this->dwWidgetGroup::top, pClipRect); // vtbl +0x04
        }
        if (this->pAnimPlayer != NULL)
        {
            clip = *pClipRect;
            dwRect_Clip(&clip, this->pAnimPlayer->GetRectPtr());
            this->pAnimPlayer->DrawChild(pDestBits, &clip); // @4424b0
        }
    }
    this->dwWidgetGroup::Draw(pDestBits, pClipRect); // binary: direct call @444730
}

// @4031f0 (dwGuiAnimView_AddItem) — push-back onto the item list.
void dwGuiAnimView::AddItem(const char* pAnimFile, int code, uint8_t flag,
                            const char* pImageFile, const char* pExtraFile)
{
    dwGuiAnimViewItem* pItem;

    pItem = new dwGuiAnimViewItem(pAnimFile, code, flag, pImageFile, pExtraFile);
    this->items.InsertAfter(this->items.pSentinel->pPrev, pItem);
    this->itemCount = this->itemCount + 1;
}

// @4032f0 (dwGuiAnimView_AddHypTextChild) — build a "BLN"-format (word-wrap,
// left, normal glyphs) dwGuiHypText caption child and push-FRONT it onto the
// group. param_4 is the glyph color index and param_5 the font name — kept
// as ints to match the original decompiled signature (TODO(dw-decomp):
// retype to (uint8_t color, char* pFontName) when the caller,
// dwGuiReference_BuildAnimViewer, lands).
void dwGuiAnimView::AddHypTextChild(char* pText, dwPoint pos, dwPoint size, int param_4, int param_5)
{
    dwGuiHypText* pChild;
    dwRect rect;

    // Child rect: (pos, size) relative to the GROUP rect origin.
    rect.left = (int16_t)(pos.x + this->dwWidgetGroup::left);
    rect.top = (int16_t)(pos.y + this->dwWidgetGroup::top);
    rect.right = (int16_t)(size.x + rect.left);
    rect.bottom = (int16_t)(size.y + rect.top);

    // Note: the binary null-checked the 0x48 allocation and still inserted
    // the NULL payload on failure; unreachable with new.
    pChild = new dwGuiHypText(&rect, NULL, (char*)(uintptr_t)param_5, (uint8_t)param_4, (char*)"BLN"); // @438690
    pChild->text.Free();     // drop any current text so SetText replaces (it appends)
    pChild->SetText(pText);  // virtual +0x48
    this->children.InsertAfter(this->children.pSentinel, pChild); // push-FRONT
}

// @4033d0 (dwGuiAnimView_InitFirstFrame)
void dwGuiAnimView::InitFirstFrame()
{
    dwListNode* pFirst;
    dwGuiAnimViewItem* pItem;

    pFirst = this->items.pSentinel->pNext;
    if (pFirst == this->items.pSentinel) // Note: added guard — the binary read the
        return;                          // sentinel's uninitialized payload when empty
    pItem = (dwGuiAnimViewItem*)pFirst->pData;

    if (pItem != NULL && pItem->imageFile.pBuffer != NULL)
    {
        if (this->pImage != NULL)
            delete this->pImage;
        this->filename.AssignString(&pItem->imageFile);
        this->pImage = dwImage_LoadFile(this->filename.pBuffer);
        this->dwAnimBase::Invalidate();
        this->dwWidgetGroup::Invalidate();
    }
    if (this->itemCount == 1)
    {
        this->pAnimPlayer = dwAnim_Open(this->dwWidgetGroup::GetRectPtr(),
                                        pItem->animFile.pBuffer, pItem->code, 0);
    }
}
