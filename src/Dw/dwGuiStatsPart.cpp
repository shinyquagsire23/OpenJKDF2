// dwGuiStatsPart / dwGuiPartImage — droid-part display widgets.
//
// Decompiled from DroidWorks.exe:
//   dwGuiStatsPart 0x428740-0x428a0f (STATS_PART; vtbl @0x51f498)
//   dwGuiPartImage 0x428d10-0x4291ff (PART_IMAGE; vtbl @0x51f4e0)
// See dwGuiStatsPart.h for the layout / slot maps.
//
// No module statics — no dwGuiStatsPart_Startup needed (soft-reset rule).

#include "Dw/dwGuiStatsPart.h"

#include "Dw/dwPart.h"      // dwPart fields (displayName/desc/materials/mass/...)
#include "Dw/dwImageDraw.h" // dwImageDraw_Line
#include "Dw/dwGuiScreen.h" // dwGuiScreen_LocalizeString
#include "Dw/dwSound.h"     // dwSound_PlayRestart
#include "Dw/dwAnim.h"      // dwAnim (spinning preview)
#include "Dw/dwList.h"      // dwListNode iteration

#include "jk.h" // _sprintf

// Durability index (dwPart::durability, 0..5) -> localized-string key.
// Binary: the PTR_s_NONE table at dwDroidView_vtbl+0x18 (0x51f478).
static const char* const dwGuiStatsPart_aDurability[6] = {
    "NONE", "LOW", "MEDIUM_LOW", "MEDIUM", "MEDIUM_HIGH", "HIGH"
};

// =============================== dwGuiStatsPart ================================

// @428740
dwGuiStatsPart::dwGuiStatsPart(dwRect* pRect, char* pLabelFontName, uint8_t colorLabel,
                               char* pValueFontName, uint8_t colorValue)
    : dwWidget(pRect)
{
    this->pPart = NULL;
    this->pLabelFont = NULL;
    this->colorLabel = colorLabel;
    this->pValueFont = NULL;
    this->colorValue = colorValue;
    if (pLabelFontName != NULL)
        this->pLabelFont = dwFont_Load(new dwFont, pLabelFontName);
    if (pValueFontName != NULL)
        this->pValueFont = dwFont_Load(new dwFont, pValueFontName);
    this->pLabelMaterials = dwGuiScreen_LocalizeString((char*)"MATERIALS:", NULL);
    this->pLabelMass = dwGuiScreen_LocalizeString((char*)"MASS:", NULL);
    this->massValue[0] = '\0';
    this->pLabelMagnetic = dwGuiScreen_LocalizeString((char*)"MAGNETIC:", NULL);
    this->pValueMagnetic = NULL;
    this->pLabelDurability = dwGuiScreen_LocalizeString((char*)"DURABILITY:", NULL);
    this->pValueDurability = NULL;
}

// @428880 (DtorDelete @428860) — free the two font handles (binary:
// sithRender_Open() is a mislabeled empty COMDAT; the handle "dtor" is a lone
// RET, so a plain delete of the handle allocation is faithful).
dwGuiStatsPart::~dwGuiStatsPart()
{
    if (this->pLabelFont != NULL)
        delete this->pLabelFont;
    if (this->pValueFont != NULL)
        delete this->pValueFont;
}

// @428900 — hover-help notification.
int dwGuiStatsPart::OnHover(int16_t x, int16_t y)
{
    (void)x; (void)y;
    dwWidgetMsg msg = { 0x7531, (void*)0x7919, 0, NULL };
    dwWidget_DispatchMsg(&msg, NULL);
    return 1;
}

// @428930
int dwGuiStatsPart::OnMessage(dwWidgetMsg* pMsg)
{
    if (pMsg->code == 2000)
    {
        dwPart* pSender = (dwPart*)pMsg->pSender;
        if (pSender != this->pPart)
        {
            this->pPart = pSender;
            if (pSender == NULL)
            {
                // Binary fallback: pMsg->param holds a dwPart** (a 32-bit
                // pointer in the original). Note: only reached when the sender
                // passes a null pSender; senders normally set pSender directly.
                this->pPart = *(dwPart**)(intptr_t)pMsg->param;
            }

            char* pFmt = dwGuiScreen_LocalizeString((char*)"MASS_FMT", NULL);
            float mass = this->pPart->mass;
            _sprintf(this->massValue, pFmt, (int)(mass < 1000.0f), (double)mass);

            char* pMagKey = (this->pPart->capFlags & 0x10) ? (char*)"YES" : (char*)"NO";
            this->pValueMagnetic = dwGuiScreen_LocalizeString(pMagKey, NULL);

            this->pValueDurability = dwGuiScreen_LocalizeString(
                (char*)dwGuiStatsPart_aDurability[this->pPart->durability], NULL);

            this->Invalidate();
        }
    }
    return 0;
}

// @428a10 — draw the info-card: display name (2 label-lines), a separator,
// the description (4 value-lines), DURABILITY label+value, a separator, the
// materials list, then the MASS / MAGNETIC bottom row (left / right half).
void dwGuiStatsPart::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    dwFont* pLF = this->pLabelFont;
    if (pLF == NULL || this->pValueFont == NULL || this->pPart == NULL)
        return;

    dwPart* pPart = this->pPart;
    int16_t L = this->left, T = this->top, R = this->right;
    int lhLabel = (int)pLF->pHeader->lineHeight;

    // Part display name.
    dwRect row;
    row.left = (int16_t)(L + 2);
    row.top = (int16_t)(T + 2);
    row.right = (int16_t)(R - 2);
    row.bottom = (int16_t)((T + 2) + lhLabel * 2);
    dwFont_DrawText(pDestBits, pLF, &row, pPart->displayName.pBuffer, this->colorLabel, pClipRect);

    {
        dwPoint p0 = { (int16_t)(L + 2), row.bottom };
        dwPoint p1 = { (int16_t)(R - 2), row.bottom };
        dwImageDraw_Line(pDestBits, &p0, &p1, this->colorLabel, pClipRect);
    }

    // Description.
    int16_t descTop = (int16_t)(row.bottom + 2);
    row.left = (int16_t)(L + 7);
    row.top = descTop;
    row.bottom = (int16_t)(descTop + (int)this->pValueFont->pHeader->lineHeight * 4);
    dwFont_DrawText(pDestBits, this->pValueFont, &row, pPart->desc.pBuffer, this->colorValue, pClipRect);

    // DURABILITY label + value.
    row.left = (int16_t)(L + 2);
    row.top = row.bottom;
    row.bottom = (int16_t)(row.bottom + lhLabel);
    dwFont_DrawText(pDestBits, pLF, &row, this->pLabelDurability, this->colorLabel, pClipRect);
    dwFont_DrawTextAligned(pDestBits, this->pValueFont, &row, this->pValueDurability,
                           this->colorValue, pClipRect, 2);

    {
        dwPoint p0 = { (int16_t)(L + 2), row.bottom };
        dwPoint p1 = { (int16_t)(R - 2), row.bottom };
        dwImageDraw_Line(pDestBits, &p0, &p1, this->colorLabel, pClipRect);
    }

    // Materials list (indented, right edge = the FULL right, not R-2).
    {
        dwRect mrow;
        mrow.left = (int16_t)(L + 5);
        mrow.right = this->right;
        mrow.top = (int16_t)(row.bottom + 2);
        mrow.bottom = (int16_t)(mrow.top + (int)this->pValueFont->pHeader->lineHeight * 3);
        for (dwListNode* pNode = pPart->materials.pSentinel->pNext;
             pNode != pPart->materials.pSentinel; pNode = pNode->pNext)
        {
            dwString* pMat = (dwString*)pNode->pData;
            dwFont_DrawText(pDestBits, this->pValueFont, &mrow, pMat->pBuffer,
                            this->colorValue, pClipRect);
            mrow.top = (int16_t)(mrow.top + (int)this->pValueFont->pHeader->lineHeight);
        }
    }

    // MASS (left half) + MAGNETIC (right half) bottom row.
    int16_t half = (int16_t)((int16_t)((this->right - this->left) / 2) + 3 + (L + 2));
    dwRect brow;
    brow.left = (int16_t)(L + 2);
    brow.right = half;
    brow.bottom = (int16_t)(this->bottom - 2);
    brow.top = (int16_t)((this->bottom - 2) - lhLabel);
    dwFont_DrawText(pDestBits, pLF, &brow, this->pLabelMass, this->colorLabel, pClipRect);
    dwFont_DrawTextAligned(pDestBits, this->pValueFont, &brow, this->massValue,
                           this->colorValue, pClipRect, 2);

    brow.left = (int16_t)(half + 2);
    brow.right = (int16_t)(this->right - 2);
    dwFont_DrawText(pDestBits, pLF, &brow, this->pLabelMagnetic, this->colorLabel, pClipRect);
    dwFont_DrawTextAligned(pDestBits, this->pValueFont, &brow, this->pValueMagnetic,
                           this->colorValue, pClipRect, 2);
}

// =============================== dwGuiPartImage ================================

// @428d10
dwGuiPartImage::dwGuiPartImage(dwRect* pRect, char* pFontName, uint8_t color)
    : dwWidget(pRect)
{
    this->pPart = NULL;
    // partName default-constructed by the dwString member ctor.
    this->pFont = NULL;
    this->color = color;
    this->pAnim = NULL;
    this->bHighlight = 0;
    if (pFontName != NULL)
        this->pFont = dwFont_Load(new dwFont, pFontName);
}

// @428dd0 (DtorDelete @428db0)
dwGuiPartImage::~dwGuiPartImage()
{
    this->FreeImages();          // release the child anim's images (Ghidra: FreeAnim)
    if (this->pAnim != NULL)
        delete this->pAnim;      // pAnim->vtable[0](1): scalar-deleting dtor
    if (this->pFont != NULL)
        delete this->pFont;
    this->partName.Free();
}

// @428e90 — advance the reveal / spawn the preview anim.
void dwGuiPartImage::Update(float dt)
{
    dwPart* pPart = this->pPart;
    if (pPart != NULL && this->pAnim == NULL)
    {
        float t = dt + this->revealTimer;
        this->revealTimer = t;

        if (t < 0.5f || pPart->spinFlcName.length == 0)
        {
            // Reveal a growing prefix of the display name.
            float frac = t * 2.0f;
            if (frac > 1.0f)
                frac = 1.0f;
            // Binary: __ftol(displayName.length * frac - (-0.5)) — round-half-up.
            int charCount = (int)((float)(int)pPart->displayName.length * frac + 0.5f);
            if ((uint32_t)charCount != this->partName.length)
            {
                this->partName.Assign(pPart->displayName.pBuffer, (uint32_t)(charCount + 1));
                this->Invalidate();
            }
        }
        else
        {
            // Reveal complete + the part has a spin flc: show the full name and
            // spawn a spinning-preview child anim.
            this->partName.AssignString(&pPart->displayName);
            this->pAnim = new dwAnim(this->GetRectPtr(), pPart->spinFlcName.pBuffer, 2000, 1, 8.0f);
            if (this->pAnim != NULL)
            {
                dt = this->revealTimer - 0.5f;
                this->pAnim->Play((uint8_t)1);
            }
        }
    }

    if (this->pAnim != NULL)
        this->pAnim->Update(dt);
}

// @428e60 — hover-help notification.
int dwGuiPartImage::OnHover(int16_t x, int16_t y)
{
    (void)x; (void)y;
    dwWidgetMsg msg = { 0x7531, (void*)0x7918, 0, NULL };
    dwWidget_DispatchMsg(&msg, NULL);
    return 1;
}

// @428fe0
int dwGuiPartImage::OnMessage(dwWidgetMsg* pMsg)
{
    if (pMsg->code == 0x7e6)
    {
        this->bHighlight = 0;
        return 0x700;
    }
    if (pMsg->code == 0x7e5)
    {
        this->bHighlight = 1;
        return 0x700;
    }
    if (pMsg->code == 0x7d0) // 2000 — part selected
    {
        dwPart* pSender = (dwPart*)pMsg->pSender;
        if (pSender != this->pPart)
        {
            this->pPart = pSender;
            this->Invalidate();
            if (this->pAnim != NULL)
                delete this->pAnim; // pAnim->vtable[0](1)
            this->pAnim = NULL;
            this->revealTimer = 0.0f;
            if (this->bHighlight != 0)
                dwSound_PlayRestart("WModelType.WAV");
        }
    }
    return 0;
}

// @429060 — translate the rect and forward to the child anim.
void dwGuiPartImage::Move(int16_t dx, int16_t dy)
{
    this->left = (int16_t)(this->left + dx);
    this->top = (int16_t)(this->top + dy);
    this->right = (int16_t)(this->right + dx);
    this->bottom = (int16_t)(this->bottom + dy);
    if (this->pAnim != NULL)
        this->pAnim->Move(dx, dy);
}

// @429160 (Ghidra: dwGuiPartImage_Precache) — vtbl +0x3c EnsureImages override.
void dwGuiPartImage::EnsureImages()
{
    if (this->pAnim != NULL)
        this->pAnim->EnsureImages();
}

// @429170 (Ghidra: dwGuiPartImage_FreeAnim) — vtbl +0x40 FreeImages override.
void dwGuiPartImage::FreeImages()
{
    if (this->pAnim != NULL)
        this->pAnim->FreeImages();
}

// @429090 — draw the part image (or the child anim), then the name text.
void dwGuiPartImage::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    this->EnsureImages(); // vtbl +0x3c (Precache)

    if (this->pAnim == NULL)
    {
        if (this->pPart != NULL && this->pPart->pImage != NULL)
            this->pPart->pImage->Blit(pDestBits, this->left, this->top, pClipRect); // vtbl +0x04
    }
    else
    {
        this->pAnim->DrawChild(pDestBits, pClipRect);
    }

    if (this->pFont != NULL && this->partName.length != 0)
    {
        int16_t L = this->left, T = this->top, R = this->right, B = this->bottom;
        dwRect r;
        r.left = (int16_t)(L + 2);
        r.right = (int16_t)(R - 2);
        r.bottom = (int16_t)(B - 2);
        int span = (int)(int16_t)(r.bottom - (T + 2)) * 3;
        r.top = (int16_t)((T + 2) + (int16_t)(span / 4)); // binary: (span + (span>>31 & 3)) >> 2
        dwFont_DrawTextAligned(pDestBits, this->pFont, &r, this->partName.pBuffer,
                               this->color, pClipRect, 3);
    }
}
