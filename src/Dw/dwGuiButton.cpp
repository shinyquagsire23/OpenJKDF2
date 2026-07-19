// dwGuiButton — the .bbl "button blob" control family: dwGuiButton (image
// multi-button), dwGuiTextButton (text push button, dwWorkshopCtrl subclass),
// dwGuiZoomBox (animated targeting reticle) and dwGuiClock (HH:MM:SS
// display).
//
// Decompiled from DroidWorks.exe, unit range 0x407640-0x40877x. The unit's
// dwGuiButton SUBCLASSES owned by the dwWorkshopCtrl compile unit
// (dwWcArrows/dwWcBuildButton/dwWcPaintButton/dwWcBuildPaintButton/
// dwWcCargoNormalButton) are implemented in dwWorkshopCtrl.cpp.
//
// dwGui_NullVirtual @407ee0 (the shared no-op vtable default) is part of this
// unit's range in the binary but was already translated with dwWidget — not
// re-implemented here.
//
// No module statics — no dwGuiButton_Startup needed (soft-reset rule).

#include "Dw/dwGuiButton.h"
#include "Dw/dwConfFile.h"
#include "Dw/dwSound.h"
#include "Dw/dwImageDraw.h"

#include "jk.h" // _sscanf/_sprintf
#include "stdPlatform.h"

extern "C" HostServices* dwMain_pHS; // the DW host-services pointer (dwMain.c); binary global dwHS @0x6b6258

// Engine headers/globals without extern "C" guards of their own — wrap at
// include site. globals.h provides rdColormap_pCurMap (the palette-cycle
// ramp) and sithTime_g_msecGameTime (the binary's sithTime_curMs @0x541d48).
extern "C" {
#include "globals.h"
}

#include <stdlib.h>
#include <stdio.h>
#include <math.h>

// ---------------------------------------------------------------------------
// Cross-unit externs (not yet translated — declare + report, do not implement)
// ---------------------------------------------------------------------------

// The 16bpp RLE image loader @444c50 (Ghidra: stdBitmapRle_FUN_00444c50) —
// dwGuiButton loads its hit-test MASK image through it unconditionally
// (unlike dwImage_LoadFile's bpp dispatch). Provided by the stdBitmapRle2
// engine-side unit (P8, stdBitmapRle2.cpp).
extern "C" dwImage* stdBitmapRle2_LoadFile16(char* pFilePath); // @444c50

// ---------------------------------------------------------------------------
// dwGuiButton (vtbl 0x51e598)
// ---------------------------------------------------------------------------

// @407640 (dwGuiButton_Ctor)
dwGuiButton::dwGuiButton(char* pName, dwRect* pRect)
    : dwWidget(pRect)
    , bSticky(0)
    , bRadio(0)
    , activeButtonId(0)
    , shownButtonId(0)
    , numButtons(0)
    , hAllUpImage(NULL)
    , paButtonImages(NULL)
    , hMaskImage(NULL)
    , pAllUpName(NULL)
    , paButtonNames(NULL)
    , pMaskName(NULL)
{
    dwString filename(pName, 0);
    filename.Append(".bbl", 4);
    dwGuiButton::ParseBlob(filename.pBuffer); // binary: direct call @407810
    dwGuiButton::EnsureImages();              // binary: direct call @407da0
}

// @407710 (dwGuiButton_Dtor; scalar-deleting wrapper @4076f0; COMDAT copy
// dwWcButton_DtorDelete @406870 shared by the wc-button vtables)
dwGuiButton::~dwGuiButton()
{
    dwGuiButton::FreeImages();     // binary: direct call @407e70
    dwGuiButton::FreeResources();  // binary: direct call @407770
}

// @407770 (dwGuiButton_FreeResources)
void dwGuiButton::FreeResources()
{
    uint32_t i;

    this->FreeImages(); // binary: VIRTUAL call (vtbl +0x40)

    if (this->pAllUpName != NULL)
    {
        delete this->pAllUpName; // binary: dwString_Free + free
        this->pAllUpName = NULL;
    }
    if (this->paButtonNames != NULL)
    {
        for (i = 0; i < (uint32_t)this->numButtons; i++)
        {
            if (this->paButtonNames[i] != NULL)
            {
                delete this->paButtonNames[i];
                this->paButtonNames[i] = NULL;
            }
        }
        dwMain_pHS->free(this->paButtonNames);
        this->paButtonNames = NULL;
    }
    if (this->pMaskName != NULL)
    {
        delete this->pMaskName;
        this->pMaskName = NULL;
    }
}

// @407810 (dwGuiButton_ParseBlob) — (re)parse the .bbl conf file.
// Note: the binary's syntax-error log fn (Ghidra: jk_logtofile @402cc0) is a
// retail NO-OP; printing here is a diagnostic adaptation.
void dwGuiButton::ParseBlob(char* pFilePath)
{
    dwConfFile conf;
    char* pTok;
    char* pCursor;
    char buttonName[64];
    unsigned long buttonId; // Note: scanned via "%lu" — must be a real long on 64-bit hosts
    uint32_t i;
    const char* pErrFmt;

    dwGuiButton::FreeResources();
    dwConfFile_Open(&conf, pFilePath);
    while (conf.bEof == 0)
    {
        dwConfFile_ReadLine(&conf);
        pTok = dwConfFile_NextToken(&conf);
        pCursor = conf.pCursor;
        if (dwString_Equals(pTok, "STICKY"))
        {
            this->bSticky = 1;
            continue;
        }
        if (dwString_Equals(pTok, "RADIO"))
        {
            this->bSticky = 1;
            this->bRadio = 1;
            continue;
        }
        if (dwString_Equals(pTok, "COUNT"))
        {
            // Note: original scans "%lu" straight into the 32-bit field (long ==
            // 32-bit on x86); temp + narrow so 64-bit hosts don't write 8 bytes
            // (see dwConfFile_ParseULong).
            unsigned long count = 0;
            _sscanf(pCursor, "%lu", &count);
            this->numButtons = (int32_t)count;
            if (this->numButtons != 0)
            {
                this->paButtonNames = (dwString**)dwMain_pHS->alloc(this->numButtons * sizeof(dwString*));
                for (i = 0; i < (uint32_t)this->numButtons; i++)
                    this->paButtonNames[i] = NULL;
            }
            continue;
        }
        if (dwString_Equals(pTok, "ALLUP"))
        {
            pTok = dwConfFile_NextToken(&conf);
            if (pTok != NULL && *pTok != 0)
                this->pAllUpName = new dwString(pTok, 0);
            continue;
        }
        if (dwString_Equals(pTok, "MASK"))
        {
            pTok = dwConfFile_NextToken(&conf);
            if (pTok != NULL && *pTok != 0)
                this->pMaskName = new dwString(pTok, 0);
            continue;
        }
        if (dwString_Equals(pTok, "BUTTON"))
        {
            if (_sscanf(pCursor, "%lu %63s", &buttonId, buttonName) == 2) // Note: width added (64-byte stack buf)
            {
                if (buttonId != 0 && buttonId <= (uint32_t)this->numButtons)
                {
                    if (this->paButtonNames[buttonId - 1] != NULL)
                    {
                        pErrFmt = "Button Blob %s: Button already defined -- BUTTON %s\n";
                        goto logError;
                    }
                    this->paButtonNames[buttonId - 1] = new dwString(buttonName, 0);
                    continue;
                }
                pErrFmt = "Button Blob %s: invalid button ID -- BUTTON %s\n";
            }
            else
            {
                pErrFmt = "Button Blob %s: syntax error -- BUTTON %s\n";
                pTok = pCursor; // binary: reports the raw line tail
            }
            goto logError;
        }
        if (pTok == NULL || *pTok == 0)
            continue;
        pErrFmt = "Button Blob %s: syntax error -- %s\n";
logError:
        stdPlatform_Printf(pErrFmt, pFilePath, pTok); // binary: @402cc0 (retail no-op)
    }
    dwConfFile_Close(&conf);
}

// @407b20 (dwGuiButton_SetPressed)
void dwGuiButton::SetPressed(int buttonId)
{
    int oldShown;

    oldShown = this->shownButtonId;
    if (buttonId == oldShown)
    {
        // Re-press of the shown button toggles it OFF — unless RADIO.
        if (this->bRadio == 0)
        {
            this->shownButtonId = 0;
            this->activeButtonId = 0;
            this->OnButtonReleased(oldShown); // vtbl +0x4c
        }
    }
    else if (buttonId != 0)
    {
        if (oldShown != 0)
            this->OnButtonReleased(oldShown); // vtbl +0x4c
        this->activeButtonId = buttonId;
        this->shownButtonId = buttonId;
        if (this->bSticky != 0)
            this->OnButtonPressed(buttonId); // vtbl +0x48
    }
}

// @407b80 (dwGuiButton_ClearPressed)
void dwGuiButton::ClearPressed()
{
    int oldShown;

    oldShown = this->shownButtonId;
    this->activeButtonId = 0;
    this->shownButtonId = 0;
    if (oldShown != 0)
        this->OnButtonReleased(oldShown); // vtbl +0x4c
}

// @407ba0 (dwGuiButton_HitTest) — button id under (x, y) from the mask
// image's pixel value. QUIRK preserved: both bounds pre-checks compare
// against the mask WIDTH (the y check should use the height).
int dwGuiButton::HitTest(int16_t x, int16_t y)
{
    void* pPixels;
    int stride;
    int id;

    if (!dwRect_ContainsPoint(this->GetRectPtr(), x, y))
        return 0;
    if (this->hMaskImage == NULL)
        return 0;
    if ((int)(x - this->left) >= (int)this->hMaskImage->desc.width)
        return 0;
    if ((int)(y - this->top) >= (int)this->hMaskImage->desc.width) // binary: width, not height
        return 0;

    pPixels = NULL;
    stride = 0;
    this->hMaskImage->Lock(&pPixels, &stride); // vtbl +0x0c
    id = ((uint8_t*)pPixels)[(y - this->top) * stride + (x - this->left)];
    this->hMaskImage->Unlock();                // vtbl +0x10
    return id;
}

// vtbl +0x04 @407c50 (dwGuiButton_OnMouseMove) — while a non-sticky press is
// active, track whether the cursor is still over the pressed button.
// Returns 0.
int dwGuiButton::OnMouseMove(int16_t x, int16_t y)
{
    int hitId;

    if (this->bSticky != 0 || this->activeButtonId == 0)
        return 0;
    hitId = this->HitTest(x, y);
    if (hitId == this->activeButtonId)
    {
        if (this->shownButtonId != this->activeButtonId)
        {
            this->shownButtonId = this->activeButtonId;
            this->Invalidate(); // vtbl +0x34
        }
        return 0;
    }
    if (this->shownButtonId == this->activeButtonId)
    {
        this->shownButtonId = 0;
        this->Invalidate();
    }
    return 0;
}

// vtbl +0x08 @407cb0 (dwGuiButton_OnMouseDown)
int dwGuiButton::OnMouseDown(int16_t x, int16_t y)
{
    int hitId;

    hitId = this->HitTest(x, y);
    if (hitId == 0)
        return 0;
    this->SetPressed(hitId);
    if (this->bSticky == 0)
    {
        dwWidget_pMouseTarget = this;
        this->Invalidate();
    }
    return 1;
}

// vtbl +0x0c @407cf0 (dwGuiButton_OnMouseUp)
int dwGuiButton::OnMouseUp(int16_t x, int16_t y)
{
    int hitId;

    if (this->bSticky != 0 || this->activeButtonId == 0)
        return 0;
    if (dwWidget_pMouseTarget == this)
        dwWidget_pMouseTarget = NULL;
    this->shownButtonId = 0; // cleared BEFORE the action hook (see dwWcArrows)
    hitId = this->HitTest(x, y);
    if (hitId == this->activeButtonId)
        this->OnButtonPressed(hitId); // vtbl +0x48
    this->activeButtonId = 0;
    return 1;
}

// vtbl +0x48 default @407ee0 (dwGui_NullVirtual)
void dwGuiButton::OnButtonPressed(int buttonId)
{
    (void)buttonId;
}

// vtbl +0x4c default @407ee0 (dwGui_NullVirtual)
void dwGuiButton::OnButtonReleased(int buttonId)
{
    (void)buttonId;
}

// vtbl +0x44 @407d50 (dwGuiButton_Draw)
void dwGuiButton::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    dwImage* pImg;

    if (this->bEnabled == 0)
        return;
    this->EnsureImages(); // vtbl +0x3c
    pImg = this->hAllUpImage;
    if (this->shownButtonId != 0 && this->shownButtonId <= this->numButtons)
        pImg = this->paButtonImages[this->shownButtonId - 1];
    if (pImg != NULL)
        pImg->Blit(pDestBits, this->left, this->top, pClipRect); // vtbl +0x04
}

// vtbl +0x3c @407da0 (Ghidra: dwGuiButton_EnsureImagesLoaded)
void dwGuiButton::EnsureImages()
{
    uint32_t i;

    if (this->pAllUpName != NULL && this->pAllUpName->length != 0 && this->hAllUpImage == NULL)
        this->hAllUpImage = dwImage_LoadFile(this->pAllUpName->pBuffer);

    if (this->numButtons != 0 && this->paButtonImages == NULL)
    {
        this->paButtonImages = (dwImage**)dwMain_pHS->alloc(this->numButtons * sizeof(dwImage*));
        for (i = 0; i < (uint32_t)this->numButtons; i++)
            this->paButtonImages[i] = NULL;
        for (i = 0; i < (uint32_t)this->numButtons; i++)
        {
            if (this->paButtonNames[i] != NULL)
                this->paButtonImages[i] = dwImage_LoadFile(this->paButtonNames[i]->pBuffer);
        }
    }

    if (this->pMaskName != NULL && this->pMaskName->length != 0 && this->hMaskImage == NULL)
        this->hMaskImage = stdBitmapRle2_LoadFile16(this->pMaskName->pBuffer); // @444c50
}

// vtbl +0x40 @407e70 (dwGuiButton_FreeImages)
void dwGuiButton::FreeImages()
{
    uint32_t i;

    if (this->hAllUpImage != NULL)
        delete this->hAllUpImage; // binary: vtbl slot 0 (scalar-deleting dtor, flag 1)
    this->hAllUpImage = NULL;

    if (this->paButtonImages != NULL)
    {
        for (i = 0; i < (uint32_t)this->numButtons; i++)
        {
            if (this->paButtonImages[i] != NULL)
                delete this->paButtonImages[i];
        }
        dwMain_pHS->free(this->paButtonImages);
        this->paButtonImages = NULL;
    }

    if (this->hMaskImage != NULL)
        delete this->hMaskImage;
    this->hMaskImage = NULL;
}

// ---------------------------------------------------------------------------
// dwGuiTextButton (vtbl 0x51e5e8)
// ---------------------------------------------------------------------------

// @407ef0 (dwGuiTextButton_Ctor)
dwGuiTextButton::dwGuiTextButton(dwRect* pRect, char* pLabel, char* pFontName,
                                 uint8_t colorNormal, char* pSndOff, uint8_t colorHot,
                                 char* pSndClick, char* pHoverSnd, int cmdId, uint8_t bAltDraw)
    : dwWorkshopCtrl(pRect, NULL, pSndOff, NULL, pSndClick, cmdId, /*bToggle*/0)
    , bChecked(0)
    , labelText(pLabel, 0)
    , bAltDraw(bAltDraw)
    , hFont(NULL)
    , colorNormal(colorNormal)
    , colorHot(colorHot)
    , secondaryText(pHoverSnd, 0)
{
    if (pFontName != NULL)
    {
        this->hFont = new dwFont;
        dwFont_Load(this->hFont, pFontName);
    }
}

// @407ff0 (dwGuiTextButton_Dtor; scalar-deleting wrapper @407fd0) — the font
// handle "dtor" @504190 is a lone RET in the binary (the glyph block belongs
// to the dwFont cache); only the handle allocation is released.
dwGuiTextButton::~dwGuiTextButton()
{
    if (this->hFont != NULL)
        delete this->hFont;
}

// vtbl +0x04 @408070 (dwGuiTextButton_OnMouseMove) — hover tracking through
// bChecked (with mouse capture), plus the optional hover sound.
int dwGuiTextButton::OnMouseMove(int16_t x, int16_t y)
{
    if (this->bPressed == 0 && this->bHot == 0)
    {
        if (this->bChecked != 0)
        {
            if (!this->HitTest(x, y)) // vtbl +0x48
            {
                // Hover leave.
                this->bChecked = 0;
                if (dwWidget_pMouseTarget == this)
                    dwWidget_pMouseTarget = NULL;
                this->Invalidate(); // vtbl +0x34
                return 0;
            }
        }
        if (this->bChecked == 0)
        {
            if (this->HitTest(x, y))
            {
                // Hover enter.
                this->bChecked = 1;
                dwWidget_pMouseTarget = this;
                this->Invalidate();
                if (this->secondaryText.length != 0)
                    dwSound_PlayRestart(this->secondaryText.pBuffer);
            }
        }
        return 0;
    }
    this->bChecked = 0;
    return dwWorkshopCtrl::OnMouseMove(x, y);
}

// vtbl +0x0c @408130 (dwGuiTextButton_OnMouseUp)
int dwGuiTextButton::OnMouseUp(int16_t x, int16_t y)
{
    this->bChecked = 0;
    return dwWorkshopCtrl::OnMouseUp(x, y);
}

// vtbl +0x44 @408150 (dwGuiTextButton_Draw)
void dwGuiTextButton::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    uint8_t color;

    if (this->bEnabled == 0 || this->hFont == NULL || this->labelText.length == 0)
        return;
    color = this->colorNormal;
    if (this->bChecked != 0 || this->bHot != 0)
        color = this->colorHot;
    if (this->bAltDraw != 0)
        dwFont_DrawTextCentered(pDestBits, this->hFont, this->GetRectPtr(),
                                this->labelText.pBuffer, color, pClipRect); // @448d30
    else
        dwFont_DrawText(pDestBits, this->hFont, this->GetRectPtr(),
                        this->labelText.pBuffer, color, pClipRect);         // @448d00
}

// ---------------------------------------------------------------------------
// dwGuiZoomBox (vtbl 0x51e638)
// ---------------------------------------------------------------------------

// @4081d0 (dwGuiZoomBox_Ctor)
dwGuiZoomBox::dwGuiZoomBox(dwRect* pRect, float speed, uint8_t color)
    : dwWidget(pRect)
    , accumTime(0.0f) // Note: left uninitialized by the binary ctor (first
                      // set in SetTarget); zero-initialized here.
    , color(color)
    , speed(speed)
    , startRadius(0.0f)
    , targetRadius(0.0f)
    , curRadius(0.0f)
    , curSpeed(0.0f)
    , state(0)
{
    this->pt.x = 0;
    this->pt.y = 0;
}

// @408230 (dwGuiZoomBox_Dtor; scalar-deleting wrapper @408210) — vptr
// re-point + base dtor only.
dwGuiZoomBox::~dwGuiZoomBox()
{
}

// @408240 (dwGuiZoomBox_SetTarget)
void dwGuiZoomBox::SetTarget(dwPoint* pPt)
{
    int dx, dy;
    int d;
    float radius;

    dy = pPt->y - this->top;
    d = this->bottom - pPt->y;
    if (dy < d)
        dy = d;
    dx = pPt->x - this->left;
    d = this->right - pPt->x;
    if (dx < d)
        dx = d;

    this->state = 1;
    radius = sqrtf((float)dy * (float)dy + (float)dx * (float)dx);
    this->startRadius = radius;
    this->curRadius = radius;
    this->accumTime = 0.0f;
    this->pt = *pPt;
    this->targetRadius = 5.0f;
    this->curSpeed = this->speed;
}

// vtbl +0x14 @4082d0 (dwGuiZoomBox_Update) — ease curRadius toward
// targetRadius; on arrival advance the state and RECURSE with the overshoot
// time (keeps the animation continuous across state changes).
void dwGuiZoomBox::Update(float dt)
{
    int oldState;
    float traveled;
    float overshoot;
    float swap;
    int bArrived;

    oldState = this->state;
    this->accumTime = this->accumTime + dt;
    if (oldState != 5)
    {
        traveled = this->accumTime * this->curSpeed;
        bArrived = 0;
        overshoot = 0.0f;
        if (this->startRadius <= this->targetRadius)
        {
            this->curRadius = this->startRadius + traveled;
            if (this->curRadius >= this->targetRadius)
            {
                overshoot = (this->curRadius - this->targetRadius) / this->curSpeed;
                bArrived = 1;
            }
        }
        else
        {
            this->curRadius = this->startRadius - traveled;
            if (this->curRadius <= this->targetRadius)
            {
                overshoot = (this->targetRadius - this->curRadius) / this->curSpeed;
                bArrived = 1;
            }
        }
        if (bArrived)
        {
            // Generic swap, then the per-state overrides.
            swap = this->targetRadius;
            this->targetRadius = this->startRadius;
            this->startRadius = swap;
            this->accumTime = 0.0f;
            if (oldState == 1)
            {
                this->state = 2;
                this->targetRadius = 20.0f;
                this->curSpeed = this->speed * 0.25f;
            }
            else if (oldState == 2)
            {
                this->state = 3;
            }
            else if (oldState == 3)
            {
                this->state = 4;
                this->targetRadius = 25.0f;
            }
            else
            {
                this->state = 5;
                this->curRadius = this->startRadius;
            }
            this->Update(overshoot); // vtbl +0x14 (binary: virtual recursion)
            this->Invalidate();      // vtbl +0x34
            return;
        }
    }
    this->Invalidate();
}

// vtbl +0x44 @408420 (dwGuiZoomBox_Draw)
void dwGuiZoomBox::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    dwRect rect;
    int16_t radius;
    int16_t thick;
    int color;
    uint32_t cycle;
    int i;

    radius = (int16_t)(this->curRadius + 0.5f); // binary: __ftol(cur - (-0.5))

    if (this->state == 2 || this->state == 3)
    {
        // Converging crosshair: a vertical and a horizontal bar through the
        // target point, length = radius, thickness by radius (1/2/3 px).
        thick = 1;
        if (radius >= 0xd)
            thick = 3;
        else if (radius > 6)
            thick = 2;

        rect.left = (int16_t)(this->pt.x - thick / 2);
        rect.top = (int16_t)(this->pt.y - radius);
        rect.right = (int16_t)(this->pt.x + (thick - thick / 2));
        rect.bottom = (int16_t)(this->pt.y + radius + 1);
        dwImageDraw_FillRect(pDestBits, &rect, this->color, pClipRect);

        rect.left = (int16_t)(this->pt.x - radius);
        rect.top = (int16_t)(this->pt.y - thick / 2);
        rect.right = (int16_t)(this->pt.x + radius + 1);
        rect.bottom = (int16_t)(this->pt.y + (thick - thick / 2));
        dwImageDraw_FillRect(pDestBits, &rect, this->color, pClipRect);
    }
    else if (this->state != 0)
    {
        color = this->color;
        if (this->state == 5)
        {
            // Palette-cycled flash: triangle-wave 0x20..0x3f through the
            // colormap brightness ramp at 64 steps/sec.
            cycle = (uint32_t)(int)(this->accumTime * 64.0f + 0.5f) & 0x3f;
            if (cycle < 0x20)
                cycle = 0x3f - cycle;
            color = ((uint8_t*)rdColormap_pCurMap->lightlevel)[cycle * 0x100 + this->color];
        }
        // Triple circle (radius, radius-1, radius-2).
        for (i = 0; i < 3; i++)
        {
            dwImageDraw_Circle(pDestBits, &this->pt, radius, color, pClipRect);
            radius = (int16_t)(radius - 1);
        }
    }
}

// ---------------------------------------------------------------------------
// dwGuiClock (vtbl 0x51e698)
// ---------------------------------------------------------------------------

// @4085a0 (dwGuiClock_Ctor) — NOTE: rect passed BY VALUE in the binary.
dwGuiClock::dwGuiClock(dwRect rect, char* pFontName, uint8_t color, int bRunning, int elapsedSec)
    : dwWidget(&rect)
    , pFont(NULL)
    , color(color)
    , elapsedSec(elapsedSec)
    , bRunning(bRunning)
{
    this->pFont = new dwFont;
    if (this->pFont != NULL)
        dwFont_Load(this->pFont, pFontName);
}

// @408650 (dwGuiClock_Dtor; scalar-deleting wrapper @408630) — see the
// dwGuiTextButton dtor note on the @504190 font-handle "dtor".
dwGuiClock::~dwGuiClock()
{
    if (this->pFont != NULL)
        delete this->pFont;
}

// vtbl +0x44 @4086c0 (dwGuiClock_Draw) — the clock advances HERE (there is
// no Update override — binary quirk). Binary time source: sithTime_curMs
// @0x541d48 (= sithTime_g_msecGameTime in OpenJKDF2 naming), scaled by
// 0.001f and rounded.
void dwGuiClock::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    char aBuf[16];
    uint32_t elapsed;
    uint32_t rem;

    if (this->pFont == NULL)
        return;
    if (this->bRunning != 0)
        this->elapsedSec = (int32_t)((float)sithTime_g_msecGameTime * 0.001f + 0.5f);

    elapsed = (uint32_t)this->elapsedSec;
    rem = elapsed % 3600u;
    _sprintf(aBuf, "%02lu:%02lu:%02lu",
             (unsigned long)((elapsed / 3600u) % 60u), // hours wrap at 60 (binary quirk)
             (unsigned long)(rem / 60u),
             (unsigned long)(rem % 60u));
    dwFont_DrawTextCentered(pDestBits, this->pFont, this->GetRectPtr(), aBuf, this->color, pClipRect);
}
