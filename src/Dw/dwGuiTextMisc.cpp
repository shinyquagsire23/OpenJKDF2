// dwGuiTextMisc — six small DroidWorks text/decorator controls:
// dwGuiTextPopup + dwGuiTextSlider (unit 0x4399b0-0x439f1x), dwGuiTextSpitter
// + dwGuiTextStrip + dwGuiTimer (unit 0x439f20-0x43aa2x), dwGuiTypewriter
// (unit 0x43aa30-0x43ae3x). See Dw/dwGuiTextMisc.h for the class map and the
// per-class quirk notes.
//
// Decompiled from DroidWorks.exe 0x4399b0-0x43ae3f. vtables:
// dwGuiTextPopup_vtbl @0x51fce8, dwGuiTextSlider_vtbl @0x51fd38,
// dwGuiTextSpitter_vtbl @0x51fd88, dwGuiTextStrip_vtbl @0x51fdd8,
// dwGuiTimer_vtbl @0x51fe28, dwGuiTypewriter_vtbl @0x51fe78.
//
// Translation notes:
//  - The binary's __ftol truncates toward zero; where the binary biases by
//    +0.5 first (FSUB of the -0.5 double @0x51fed0, dwGuiTypewriter::Update)
//    that is round-half-up. Mirrored with double math + C casts (same
//    approach as dwGuiHypText.cpp).
//  - The slider/strip/spitter fly math accumulates its timer WITHOUT reset,
//    so the motion accelerates over time — faithful to the binary.
//  - Font handles follow the dwGuiTextButton precedent: `new dwFont` +
//    dwFont_Load; the binary's handle "dtor" @504190 is a lone RET (the
//    glyph block belongs to the dwFont cache), so the dtors just delete the
//    handle.
//
// No module statics — no dwGuiTextMisc_Startup needed (soft-reset rule).

#include "Dw/dwGuiTextMisc.h"

#include "Dw/dwColormap.h"
#include "Dw/dwImageDraw.h"
#include "Dw/dwSound.h"

// ---------------------------------------------------------------------------
// dwGuiTextPopup (vtbl 0x51fce8)
// ---------------------------------------------------------------------------

// @4399b0 (dwGuiTextPopup_Ctor)
dwGuiTextPopup::dwGuiTextPopup(dwRect* pRect, char* pLabel, char* pFontName,
                               uint8_t colorNormal, uint8_t colorHot, int cmdId,
                               char* pDisplayText, char* pSndOff, char* pAltText,
                               char* pSndClick, uint8_t bAltDraw)
    : dwGuiTextButton(pRect, pLabel, pFontName, colorNormal, pSndOff, colorHot,
                      pSndClick, (char*)"CTextRollover.WAV", cmdId, bAltDraw)
{
    // FIELD REUSE (binary quirk): the base image-name dwStrings hold the two
    // toggle strings — imageNameNormal = display text, imageNamePressed =
    // alt text.
    this->imageNameNormal.AssignCStr(pDisplayText);
    this->imageNamePressed.AssignCStr(pAltText);
    if (this->imageNameNormal.length != 0 && this->imageNamePressed.length != 0)
    {
        if (!dwString_Equals(this->imageNameNormal.pBuffer, "RmicroscopeGR.rle"))
        {
            // Text mode: both strings present and not the reference-screen
            // microscope image -> shown "hot" with the label visible.
            this->bHot = 1;
            this->bChecked = 1;
        }
    }
    // Redundant re-assign (the base ctor already set labelText = pLabel) —
    // binary quirk, preserved.
    this->labelText.Assign(pLabel, 0);
    this->dwWorkshopCtrl::EnsureImages(); // direct @4075c0 call in the binary
}

// @439ac0 (dwGuiTextPopup_Dtor; scalar-deleting wrapper @439aa0) — vptr
// re-point + base dtor only.
dwGuiTextPopup::~dwGuiTextPopup()
{
}

// vtbl +0x44 @439b00 (dwGuiTextPopup_Draw)
void dwGuiTextPopup::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    dwImage* pImg;
    dwRect textRect;
    int dy;
    uint8_t color;

    if (this->bEnabled == 0)
        return;
    this->EnsureImages(); // vtbl +0x3c (virtual here, unlike the ctor)

    pImg = this->pImageNormal;
    if (this->bHot != 0)
        pImg = this->pImagePressed;
    if (pImg != NULL)
        pImg->Blit(pDestBits, this->left, this->top, pClipRect); // vtbl +0x04

    if (this->bChecked == 0 && this->bHot == 0)
        return;
    if (this->hFont == NULL || this->labelText.length == 0)
        return;

    // Text rect = widget rect shifted down to vertically center one font
    // line (both top AND bottom get the offset — binary math).
    textRect.left = this->left;
    textRect.top = this->top;
    textRect.right = this->right;
    textRect.bottom = this->bottom;
    dy = ((int)(int16_t)(textRect.bottom - textRect.top)
          - (int)this->hFont->pHeader->lineHeight) / 2;
    textRect.top = (int16_t)(textRect.top + dy);
    textRect.bottom = (int16_t)(textRect.bottom + dy);

    // NOTE: keys on bHot only (dwGuiTextButton::Draw uses bChecked || bHot).
    color = this->colorNormal;
    if (this->bHot != 0)
        color = this->colorHot;

    if (this->bAltDraw != 0)
        dwFont_DrawTextCentered(pDestBits, this->hFont, &textRect,
                                this->labelText.pBuffer, color, pClipRect); // @448d30
    else
        dwFont_DrawText(pDestBits, this->hFont, &textRect,
                        this->labelText.pBuffer, color, pClipRect);         // @448d00
}

// ---------------------------------------------------------------------------
// dwGuiTextSlider (vtbl 0x51fd38)
// ---------------------------------------------------------------------------

// @439c10 (dwGuiTextSlider_Ctor)
dwGuiTextSlider::dwGuiTextSlider(dwRect* pRect, char* pFontName, uint8_t textColor,
                                 float scrollSpeed, uint8_t shadowColor, char* pText)
    : dwWidget(pRect)
    , label(pText, 0)
    , textColor(textColor)
    , shadowColor(shadowColor)
    , pFont(NULL)
    , scrollSpeed(scrollSpeed)
{
    int16_t d;

    if (pFontName != NULL)
    {
        this->pFont = new dwFont;
        dwFont_Load(this->pFont, pFontName);
    }
    // Scroll rect: start one rect-width to the LEFT of the widget — left
    // edge at left+50 minus the widget width, right edge at the widget's
    // left (rect width = widget width - 50).
    this->scrollRect.left = (int16_t)(this->left + 50);
    this->scrollRect.top = this->top;
    this->scrollRect.right = this->right;
    this->scrollRect.bottom = this->bottom;
    this->scrollTimer = 0.0f;
    d = (int16_t)((this->scrollRect.left - this->scrollRect.right) - 50);
    this->scrollRect.left = (int16_t)(this->scrollRect.left + d);
    this->scrollRect.right = (int16_t)(this->scrollRect.right + d);
}

// @439d10 (dwGuiTextSlider_Dtor; scalar-deleting wrapper @439cf0)
dwGuiTextSlider::~dwGuiTextSlider()
{
    if (this->pFont != NULL)
        delete this->pFont;
}

// vtbl +0x48 @439d80 (dwGuiTextSlider_SetText; COMDAT shared with
// dwGuiTypewriter's +0x48 — both keep the timer at binary 0x24 and the text
// at 0x10)
void dwGuiTextSlider::SetText(char* pText)
{
    this->scrollTimer = 0.0f;
    this->label.Assign(pText, 0);
    this->Invalidate(); // vtbl +0x34
}

// vtbl +0x14 @439db0 (dwGuiTextSlider_Update) — advance = widget width *
// (total elapsed / scrollSpeed) px, added CUMULATIVELY each tick (the timer
// never resets -> the slide accelerates; binary quirk). Once the rect's
// right edge reaches the widget's right edge the `>=` gate stops all
// further motion (single slide).
void dwGuiTextSlider::Update(float dt)
{
    int width;
    uint16_t adv;
    int16_t d;

    if (this->bEnabled == 0)
        return;
    this->scrollTimer += dt;
    if (this->scrollRect.right >= this->right)
        return;

    width = (int16_t)(this->right - this->left);
    adv = (uint16_t)(int)((float)width * (this->scrollTimer / this->scrollSpeed));
    if ((int)(uint32_t)adv > width)
        adv = (uint16_t)width;
    this->scrollRect.left = (int16_t)(this->scrollRect.left + adv);
    this->scrollRect.right = (int16_t)(this->scrollRect.right + adv);
    if (this->scrollRect.right > this->right)
    {
        // Overshot: snap back to left+50 (right edge lands exactly at the
        // widget's right, which then satisfies the gate above).
        d = (int16_t)((this->left - this->scrollRect.left) + 50);
        this->scrollRect.left = (int16_t)(this->scrollRect.left + d);
        this->scrollRect.right = (int16_t)(this->scrollRect.right + d);
    }
    this->Invalidate(); // vtbl +0x34
}

// vtbl +0x44 @439e60 (dwGuiTextSlider_Draw) — label at scrollRect with a
// (+1,+1) shadow pass in dwColormap_transparentIdx first (the stored
// shadowColor is NOT used — binary quirk), both clipped to
// pClipRect ∩ scrollRect. Nothing draws while scrollSpeed == 0.
void dwGuiTextSlider::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    dwRect clip;
    dwRect shadowRect;

    if (this->bEnabled == 0)
        return;
    clip = *pClipRect;
    dwRect_Clip(&clip, &this->scrollRect);
    if (this->label.length == 0 || this->scrollSpeed == 0.0f)
        return;

    shadowRect.left = (int16_t)(this->scrollRect.left + 1);
    shadowRect.top = (int16_t)(this->scrollRect.top + 1);
    shadowRect.right = (int16_t)(this->scrollRect.right + 1);
    shadowRect.bottom = (int16_t)(this->scrollRect.bottom + 1);
    dwFont_DrawText(pDestBits, this->pFont, &shadowRect, this->label.pBuffer,
                    (uint8_t)dwColormap_transparentIdx, &clip);
    dwFont_DrawText(pDestBits, this->pFont, &this->scrollRect, this->label.pBuffer,
                    this->textColor, &clip);
}

// ---------------------------------------------------------------------------
// dwGuiTextSpitter (vtbl 0x51fd88)
// ---------------------------------------------------------------------------

// Fly-in speed factor (binary float @0x51fdd4 = 0x3f7d7721 ≈ 1/1.01, applied
// TWICE: once to the timer, once to the fly range).
#define DWGUITEXTMISC_SPIT_FLY_K 0.99009901

// @439f20 (dwGuiTextSpitter_Ctor)
dwGuiTextSpitter::dwGuiTextSpitter(dwRect* pRect, char* pFontName, uint8_t color1,
                                   int mode, char* pSpitSound, uint8_t color2,
                                   char* pText)
    : dwWidget(pRect)
    , text(pText, 0)
    , color1(color1)
    , color2(color2)
    , pFont(NULL)
    , revealed(NULL, 0)
    , revealTimer(0.0f)
    , pFwdChar(NULL)
    , pEndChar(NULL)
    , accumWidth(0)
    , bDone(0)
    , mode(mode)
    , spitSound(pSpitSound, 0)
{
    char* pCh;

    this->charRect.left = 0;
    this->charRect.top = 0;
    this->charRect.right = 0;
    this->charRect.bottom = 0;
    this->landRect.left = 0;
    this->landRect.top = 0;
    this->landRect.right = 0;
    this->landRect.bottom = 0;
    this->extentFwd.x = 0;
    this->extentFwd.y = 0;
    this->extentEnd.x = 0;
    this->extentEnd.y = 0;

    if (pFontName != NULL)
    {
        this->pFont = new dwFont;
        dwFont_Load(this->pFont, pFontName);
    }

    this->pFwdChar = this->text.pBuffer;
    this->pEndChar = this->text.pBuffer + (this->text.length - 1);
    this->landRect.left = this->left;
    this->landRect.top = this->top;
    this->landRect.right = this->right;
    this->landRect.bottom = this->bottom;
    // maxChars = cursor offset - 1 (the fwd one is (uint)-1 here — "no
    // limit" by unsigned wraparound; binary math preserved).
    dwFont_MeasureWrappedExtent(&this->extentFwd, this->pFont, this->GetRectPtr(),
                                this->text.pBuffer,
                                (uint32_t)((this->pFwdChar - this->text.pBuffer) - 1));
    dwFont_MeasureWrappedExtent(&this->extentEnd, this->pFont, this->GetRectPtr(),
                                this->text.pBuffer,
                                (uint32_t)((this->pEndChar - this->text.pBuffer) - 1));
    if (this->mode == 0)
    {
        // Forward reveal: the landed-text rect starts collapsed at the LEFT.
        this->landRect.right = this->landRect.left;
        pCh = this->pFwdChar;
    }
    else
    {
        // Reverse reveal: collapsed at the RIGHT; accumWidth counts DOWN
        // from the full text width.
        this->accumWidth = dwFont_MeasureString(this->pFont, this->text.pBuffer,
                                                this->text.length);
        this->landRect.left = this->landRect.right;
        pCh = this->pEndChar;
    }
    this->UpdateCharExtent(pCh);
}

// @43a0f0 (dwGuiTextSpitter_Dtor; scalar-deleting wrapper @43a0d0)
dwGuiTextSpitter::~dwGuiTextSpitter()
{
    if (this->pFont != NULL)
        delete this->pFont;
    if (dwSound_IsPlaying(this->spitSound.pBuffer))
        dwSound_Stop(this->spitSound.pBuffer);
}

// vtbl +0x48 @43a1a0 (dwGuiTextSpitter_SetText) — QUIRK: no reveal-state
// reset (cursors/rects/bDone keep their values).
void dwGuiTextSpitter::SetText(char* pText)
{
    this->text.Assign(pText, 0);
    this->Invalidate(); // vtbl +0x34
}

// @43a1c0 (dwGuiTextSpitter_UpdateCharExtent)
void dwGuiTextSpitter::UpdateCharExtent(char* pCh)
{
    int16_t x;

    this->charWidth = dwFont_GetCharWidth(this->pFont, *pCh);
    if (this->mode == 0)
    {
        // Fly-in start: just past the widget's RIGHT edge.
        this->charRect.top = this->top;
        this->charRect.bottom = this->bottom;
        this->charRect.left = this->right;
        this->charRect.right = (int16_t)(this->right + this->charWidth);
    }
    else
    {
        // Fly-in start: one char width beyond the widget's LEFT edge.
        this->charRect.top = this->top;
        this->charRect.bottom = this->bottom;
        x = (int16_t)(this->left - this->charWidth);
        this->charRect.left = x;
        this->charRect.right = (int16_t)(x + this->charWidth);
    }
}

// vtbl +0x14 @43a230 (dwGuiTextSpitter_Update)
void dwGuiTextSpitter::Update(float dt)
{
    int width;
    int pixels;
    int16_t adv;
    int16_t d;

    if (this->bEnabled == 0)
        return;
    if (this->bDone != 0)
        return;

    this->revealTimer += dt;
    // pixels = ((width - charWidth) * K) * (totalTime * K); the timer never
    // resets, so the fly accelerates (binary quirk). The binary FILDs
    // {width - charWidth, 0} as an UNSIGNED qword — a negative difference
    // becomes huge; preserved via the uint32_t cast.
    width = (int16_t)(this->right - this->left);
    pixels = (int)(((double)(uint32_t)(width - this->charWidth) * DWGUITEXTMISC_SPIT_FLY_K)
                   * ((double)this->revealTimer * DWGUITEXTMISC_SPIT_FLY_K));
    if (pixels > width)
    {
        if (this->charWidth != 0)
            pixels = (int)((uint32_t)width / (uint32_t)this->charWidth);
        else
            pixels = width;
    }
    adv = (int16_t)pixels; // the binary adds the low 16 bits only

    if (this->mode == 0)
    {
        // Forward: the char flies LEFT from the right edge.
        this->charRect.left = (int16_t)(this->charRect.left - adv);
        this->charRect.right = (int16_t)(this->charRect.right - adv);
        if (this->charRect.left <= this->landRect.right)
        {
            // Landed: snap onto the end of the landed text, grow the landed
            // rect, tick, and advance the front cursor.
            d = (int16_t)(this->landRect.right - this->charRect.left);
            this->charRect.left = (int16_t)(this->charRect.left + d);
            this->charRect.right = (int16_t)(this->charRect.right + d);
            this->landRect.right = (int16_t)(this->landRect.right + this->charWidth);
            if (!dwSound_IsPlaying(this->spitSound.pBuffer))
                dwSound_Play(this->spitSound.pBuffer);
            this->accumWidth += this->charWidth;
            // QUIRK: appends the whole remaining tail (the landRect clip in
            // Draw bounds what is visible).
            this->revealed.Append(this->pFwdChar,
                                  (uint32_t)(this->pEndChar - this->pFwdChar) + 1);
            this->pFwdChar += 1;
            this->UpdateCharExtent(this->pFwdChar);
            dwFont_MeasureWrappedExtent(&this->extentFwd, this->pFont, this->GetRectPtr(),
                                        this->text.pBuffer,
                                        (uint32_t)((this->pFwdChar - this->text.pBuffer) - 1));
            // Done when both cursors sit on the same CHAR VALUE at the same
            // wrapped x-extent (binary's completion test).
            if (*this->pEndChar == *this->pFwdChar && this->extentEnd.x == this->extentFwd.x)
            {
                d = (int16_t)(this->landRect.right - this->charRect.left);
                this->charRect.left = (int16_t)(this->charRect.left + d);
                this->charRect.right = (int16_t)(this->charRect.right + d);
                this->landRect.right = (int16_t)(this->landRect.right + this->charWidth);
                this->revealed.Append(this->pFwdChar,
                                      (uint32_t)(this->pEndChar - this->pFwdChar) + 1);
                this->bDone = 1;
                if (dwSound_IsPlaying(this->spitSound.pBuffer))
                    dwSound_Stop(this->spitSound.pBuffer);
            }
        }
    }
    else
    {
        // Reverse: the char flies RIGHT from beyond the left edge; the
        // landed text is the SUFFIX from pEndChar (re-Assigned per landing).
        this->charRect.left = (int16_t)(this->charRect.left + adv);
        this->charRect.right = (int16_t)(this->charRect.right + adv);
        if (this->charRect.right >= this->landRect.left)
        {
            this->landRect.left = (int16_t)(this->landRect.left - this->charWidth);
            d = (int16_t)(this->landRect.left - this->charRect.left);
            this->charRect.left = (int16_t)(this->charRect.left + d);
            this->charRect.right = (int16_t)(this->charRect.right + d);
            if (!dwSound_IsPlaying(this->spitSound.pBuffer))
                dwSound_Play(this->spitSound.pBuffer);
            this->accumWidth -= this->charWidth;
            this->revealed.Assign(this->pEndChar, 0);
            this->pEndChar -= 1;
            this->UpdateCharExtent(this->pEndChar);
            dwFont_MeasureWrappedExtent(&this->extentEnd, this->pFont, this->GetRectPtr(),
                                        this->text.pBuffer,
                                        (uint32_t)((this->pEndChar - this->text.pBuffer) - 1));
            if (*this->pEndChar == *this->pFwdChar && this->extentEnd.x == this->extentFwd.x)
            {
                this->landRect.left = (int16_t)(this->landRect.left - this->charWidth);
                d = (int16_t)(this->landRect.left - this->charRect.left);
                this->charRect.left = (int16_t)(this->charRect.left + d);
                this->charRect.right = (int16_t)(this->charRect.right + d);
                this->revealed.Assign(this->pEndChar, 0);
                this->bDone = 1;
                if (dwSound_IsPlaying(this->spitSound.pBuffer))
                    dwSound_Stop(this->spitSound.pBuffer);
            }
        }
    }
    this->Invalidate(); // vtbl +0x34 (every non-early-return path)
}

// vtbl +0x44 @43a4e0 (dwGuiTextSpitter_Draw)
void dwGuiTextSpitter::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    dwRect clipChar;
    dwRect clipLand;
    dwRect shadowRect;
    dwPoint pos;
    int yInset;
    char* pFly;

    if (this->bEnabled == 0 || this->pFont == NULL || this->text.length == 0)
        return;

    if (this->color2 != 0)
    {
        // Static mode: centered shadowed draw of the not-yet-landed tail
        // (from the FRONT cursor even in reverse mode — binary quirk).
        shadowRect.left = (int16_t)(this->left + 1);
        shadowRect.top = (int16_t)(this->top + 1);
        shadowRect.right = (int16_t)(this->right + 1);
        shadowRect.bottom = (int16_t)(this->bottom + 1);
        dwFont_DrawTextCentered(pDestBits, this->pFont, &shadowRect, this->pFwdChar,
                                (uint8_t)dwColormap_transparentIdx, pClipRect);
        dwFont_DrawTextCentered(pDestBits, this->pFont, this->GetRectPtr(), this->pFwdChar,
                                this->color1, pClipRect);
        return;
    }

    clipChar = *pClipRect;
    dwRect_Clip(&clipChar, &this->charRect);
    clipLand = *pClipRect;
    dwRect_Clip(&clipLand, &this->landRect);
    if (this->revealed.length == 0)
        return;

    // Header +0x08 (bpp) doubles as the first-line top y-inset (see
    // dwFont.h).
    yInset = (int)this->pFont->pHeader->bpp;

    // Landed text: full `revealed` string clipped to the landed rect —
    // (+1,+1) shadow pass in the transparent index first.
    pos.x = (int16_t)(this->landRect.left + 1);
    pos.y = (int16_t)(this->landRect.top + yInset + 1);
    dwFont_DrawStringClipped(pDestBits, this->pFont, &pos, this->revealed.pBuffer,
                             (uint8_t)dwColormap_transparentIdx, &clipLand);
    pos.x = this->landRect.left;
    pos.y = (int16_t)(this->landRect.top + yInset);
    dwFont_DrawStringClipped(pDestBits, this->pFont, &pos, this->revealed.pBuffer,
                             this->color1, &clipLand);

    // Flying char: the whole remaining string clipped to the char rect.
    pFly = this->pFwdChar;
    if (this->mode != 0)
        pFly = this->pEndChar;
    pos.x = this->charRect.left;
    pos.y = (int16_t)(this->charRect.top + yInset);
    dwFont_DrawStringClipped(pDestBits, this->pFont, &pos, pFly, this->color1, &clipChar);
}

// ---------------------------------------------------------------------------
// dwGuiTextStrip (vtbl 0x51fdd8)
// ---------------------------------------------------------------------------

// @43a6a0 (dwGuiTextStrip_Ctor)
dwGuiTextStrip::dwGuiTextStrip(dwRect* pRect, uint8_t color, float scrollSpeed)
    : dwWidget(pRect)
    , color(color)
    , scrollSpeed(scrollSpeed)
    , label() // dead field (default-ctor'd, never used) — binary quirk
{
    int16_t d;

    // Same scroll-rect start as dwGuiTextSlider: one rect-width left of the
    // widget, right edge at the widget's left.
    this->scrollRect.left = (int16_t)(this->left + 50);
    this->scrollRect.top = this->top;
    this->scrollRect.right = this->right;
    this->scrollRect.bottom = this->bottom;
    this->scrollTimer = 0.0f;
    d = (int16_t)((this->scrollRect.left - this->scrollRect.right) - 50);
    this->scrollRect.left = (int16_t)(this->scrollRect.left + d);
    this->scrollRect.right = (int16_t)(this->scrollRect.right + d);
}

// @43a760 (dwGuiTextStrip_Dtor; scalar-deleting wrapper @43a740) — label
// free + base only (member dtors here).
dwGuiTextStrip::~dwGuiTextStrip()
{
}

// vtbl +0x14 @43a7b0 (dwGuiTextStrip_Update) — identical math to
// dwGuiTextSlider::Update (see its notes; single accelerating slide).
void dwGuiTextStrip::Update(float dt)
{
    int width;
    uint16_t adv;
    int16_t d;

    if (this->bEnabled == 0)
        return;
    this->scrollTimer += dt;
    if (this->scrollRect.right >= this->right)
        return;

    width = (int16_t)(this->right - this->left);
    adv = (uint16_t)(int)((float)width * (this->scrollTimer / this->scrollSpeed));
    if ((int)(uint32_t)adv > width)
        adv = (uint16_t)width;
    this->scrollRect.left = (int16_t)(this->scrollRect.left + adv);
    this->scrollRect.right = (int16_t)(this->scrollRect.right + adv);
    if (this->scrollRect.right > this->right)
    {
        d = (int16_t)((this->left - this->scrollRect.left) + 50);
        this->scrollRect.left = (int16_t)(this->scrollRect.left + d);
        this->scrollRect.right = (int16_t)(this->scrollRect.right + d);
    }
    this->Invalidate(); // vtbl +0x34
}

// vtbl +0x44 @43a860 (dwGuiTextStrip_Draw) — blend-fill the scroll rect.
void dwGuiTextStrip::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    dwRect clip;

    if (this->bEnabled == 0)
        return;
    // The binary computes pClipRect ∩ scrollRect into a local and then
    // NEVER uses it (BlendRect gets the raw pClipRect) — dead code,
    // preserved for fidelity.
    clip = *pClipRect;
    dwRect_Clip(&clip, &this->scrollRect);
    (void)clip;
    if (this->scrollSpeed == 0.0f)
        return;
    dwImageDraw_BlendRect(pDestBits, &this->scrollRect, this->color, pClipRect); // @446970
}

// ---------------------------------------------------------------------------
// dwGuiTimer (vtbl 0x51fe28)
// ---------------------------------------------------------------------------

// @43a8c0 (dwGuiTimer_Ctor) — the binary inlines the decorator ctor (widget
// rect copied from the child via &child->left); the base ctor here is that
// exact sequence. The child starts hidden.
dwGuiTimer::dwGuiTimer(dwWidget* pTarget, float startTime, float duration)
    : dwWcChildDecorator(pTarget)
    , startTime(startTime)
    , duration(duration)
{
    if (this->pChild->bEnabled != 0)
        this->pChild->Disable(); // vtbl +0x24
    this->elapsed = 0.0f;
}

// (dwGuiTimer dtor @43a9d0 / DtorDelete @43a9b0: re-points the vptr to
// dwWcChildDecorator_vtbl and repeats the decorator dtor body — FreeImages +
// delete child. That IS ~dwWcChildDecorator; no override needed here.)

// vtbl +0x14 @43a940 (dwGuiTimer_Update) — NOTE: does not gate on
// this->bEnabled (containers gate it); the child's Update is forwarded
// every tick, shown or not.
void dwGuiTimer::Update(float dt)
{
    this->elapsed += dt;
    if (this->elapsed > this->startTime && this->pChild->bEnabled == 0)
        this->pChild->Enable(); // vtbl +0x20
    if (this->duration != 0.0f && this->elapsed > this->duration
        && this->pChild->bEnabled != 0)
    {
        this->pChild->Disable(); // vtbl +0x24
        this->Invalidate();      // vtbl +0x34
    }
    this->pChild->Update(dt); // vtbl +0x14
}

// Invented C shim (no binary counterpart; declared in dwGuiTextMisc.h) —
// consumed by dwWorkshopCtrl.cpp's dwWcEntryPanel::ShowEntry, which passes
// (pHypText, entry->showTime, entry->hideTime) = (pTarget, startTime,
// duration), matching the ctor 1:1. Replaces the dwMain.c placeholder stub.
extern "C" dwWidget* dwGuiTimer_New(dwWidget* pTarget, float startTime, float duration)
{
    return new dwGuiTimer(pTarget, startTime, duration);
}

// ---------------------------------------------------------------------------
// dwGuiTypewriter (vtbl 0x51fe78)
// ---------------------------------------------------------------------------

// @43aa30 (dwGuiTypewriter_Ctor)
dwGuiTypewriter::dwGuiTypewriter(dwRect* pRect, char* pFontName, uint8_t textColor,
                                 float revealDuration, char* pTickSound,
                                 uint8_t color2, uint8_t bRightAlign, char* pText)
    : dwWidget(pRect)
    , text(pText, 0)
    , textColor(textColor)
    , color2(color2)
    , pFont(NULL)
    , revealDuration(revealDuration)
    , revealed(NULL, 0)
    , tickSound(pTickSound, 0)
    , bRightAlign(bRightAlign)
{
    if (pFontName != NULL)
    {
        this->pFont = new dwFont;
        dwFont_Load(this->pFont, pFontName);
    }
    this->revealTimer = 0.0f;
}

// @43ab30 (dwGuiTypewriter_Dtor; scalar-deleting wrapper @43ab10)
dwGuiTypewriter::~dwGuiTypewriter()
{
    if (this->pFont != NULL)
        delete this->pFont;
    if (dwSound_IsPlaying(this->tickSound.pBuffer))
        dwSound_Stop(this->tickSound.pBuffer);
}

// vtbl +0x48 @439d80 — the binary reuses dwGuiTextSlider_SetText as a COMDAT
// (identical layout: timer @0x24, text dwString @0x10); same body here.
void dwGuiTypewriter::SetText(char* pText)
{
    this->revealTimer = 0.0f;
    this->text.Assign(pText, 0);
    this->Invalidate(); // vtbl +0x34
}

// vtbl +0x14 @43abe0 (dwGuiTypewriter_Update)
void dwGuiTypewriter::Update(float dt)
{
    float frac;
    uint32_t len;

    if (this->bEnabled == 0)
        return;
    this->revealTimer += dt;
    frac = this->revealTimer / this->revealDuration;
    if (frac > 1.0f)
        frac = 1.0f;
    // round-half-up: the binary FSUBs the -0.5 double @0x51fed0 before the
    // truncating __ftol.
    len = (uint32_t)((double)this->text.length * (double)frac + 0.5);
    if (this->revealed.length != len)
    {
        this->revealed.Assign(this->text.pBuffer, len);
        this->Invalidate(); // vtbl +0x34
        if (!dwSound_IsPlaying(this->tickSound.pBuffer))
            dwSound_Play(this->tickSound.pBuffer);
    }
    if ((this->revealed.length == this->text.length
         || dwString_Equals(this->revealed.pBuffer, this->text.pBuffer))
        && dwSound_IsPlaying(this->tickSound.pBuffer))
    {
        dwSound_Stop(this->tickSound.pBuffer);
    }
}

// vtbl +0x44 @43acd0 (dwGuiTypewriter_Draw) — revealed prefix with a (+1,+1)
// shadow pass in dwColormap_transparentIdx; bRightAlign shifts the draw rect
// so the FULL text would end at the widget's right edge.
void dwGuiTypewriter::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    dwRect drawRect;
    dwRect shadowRect;
    int16_t fullWidth;

    if (this->bEnabled == 0 || this->text.length == 0 || this->revealDuration == 0.0f)
        return;
    if (this->pFont == NULL || this->revealed.length == 0)
        return;

    if (this->bRightAlign != 0)
    {
        drawRect.left = this->left;
        drawRect.top = this->top;
        drawRect.right = this->right;
        drawRect.bottom = this->bottom;
        fullWidth = (int16_t)dwFont_MeasureString(this->pFont, this->text.pBuffer,
                                                  this->text.length);
        drawRect.left = (int16_t)(drawRect.left
                                  + ((int16_t)(this->right - this->left) - fullWidth));
        shadowRect.left = (int16_t)(drawRect.left + 1);
        shadowRect.top = (int16_t)(drawRect.top + 1);
        shadowRect.right = (int16_t)(drawRect.right + 1);
        shadowRect.bottom = (int16_t)(drawRect.bottom + 1);
        dwFont_DrawText(pDestBits, this->pFont, &shadowRect, this->revealed.pBuffer,
                        (uint8_t)dwColormap_transparentIdx, pClipRect);
        dwFont_DrawText(pDestBits, this->pFont, &drawRect, this->revealed.pBuffer,
                        this->textColor, pClipRect);
        return;
    }

    shadowRect.left = (int16_t)(this->left + 1);
    shadowRect.top = (int16_t)(this->top + 1);
    shadowRect.right = (int16_t)(this->right + 1);
    shadowRect.bottom = (int16_t)(this->bottom + 1);
    dwFont_DrawText(pDestBits, this->pFont, &shadowRect, this->revealed.pBuffer,
                    (uint8_t)dwColormap_transparentIdx, pClipRect);
    dwFont_DrawText(pDestBits, this->pFont, this->GetRectPtr(), this->revealed.pBuffer,
                    this->textColor, pClipRect);
}
