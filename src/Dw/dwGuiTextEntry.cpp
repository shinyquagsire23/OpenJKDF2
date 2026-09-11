// dwGuiTextEntry — single-line editable name box (TEXTENTRY-family control)
// + the dwGuiFindEntry (topic-search query box) subclass.
//
// Decompiled from DroidWorks.exe range 0x439160-0x4399ax (dwGuiTextEntry,
// vtbl @0x51fca0) and 0x413c20-0x413ccx (dwGuiFindEntry, vtbl @0x51ec70 —
// reclassified out of the dwFlic address span). See Dw/dwGuiTextEntry.h for
// the field map and notification-code semantics.
//
// Translation notes:
//  - The three notification fields (0x20/0x24/0x28) are int message CODES
//    (proven by dwGuiFindEntry forcing 0x28 = 0x1b79); OnHover additionally
//    reuses field 0x20 as the 0x7531 hover message's pSender payload, cast
//    through intptr_t here.
//  - The binary's key classifier calls are MSVC CRT ctype lookups with masks
//    0x103/0x004/0x117 == isalpha/isdigit/isgraph; mapped to <ctype.h> with
//    the (unsigned char) cast per the dwGuiHypText.cpp precedent.
//  - __ftol truncates toward zero -> plain C casts.
//  - dwSound_PlayRestart is the repo dwSound C API (binary: thiscall on
//    dwSound_pManager @0x53d960).
//
// No module statics — no dwGuiTextEntry_Startup needed (soft-reset rule).

#include "Dw/dwGuiTextEntry.h"

#include "Dw/dwImage.h"     // dwImageBits (plain-C struct)
#include "Dw/dwImageDraw.h" // FillRect/FrameRect
#include "Dw/dwSound.h"     // dwSound_PlayRestart

#include "jk.h"
#include "stdPlatform.h"

#include <ctype.h>

// ---- dwGuiTextEntry ---------------------------------------------------------

// @439160 (dwGuiTextEntry_Ctor)
// Quirks preserved:
//  - selEnd starts at pText->length + 1 (one past the length).
//  - the dwFont handle is heap-owned; the binary stored NULL when the 0x10
//    allocation failed — unreachable with new (same note as dwGuiHypText).
//    Unlike dwGuiTextBlock's ctor there is NO NULL check on pFontName here
//    (a NULL name would crash in dwFont_Load — same as the binary).
dwGuiTextEntry::dwGuiTextEntry(dwRect* pRect, char* pFontName, uint8_t textColor,
                               uint8_t cursorColor, dwString* pText, int32_t msgEditNotify,
                               int32_t msgChanged, int32_t msgCommit)
    : dwWidget(pRect)
{
    this->textColor = textColor;
    this->cursorColor = cursorColor;
    this->pText = pText;
    this->bEditable = 0;
    this->bDragging = 0;
    this->pFont = NULL;
    this->msgEditNotify = msgEditNotify;
    this->msgChanged = msgChanged;
    this->msgCommit = msgCommit;
    this->maxLen = 0x400;
    this->selAnchor = 0;
    this->selEnd = 0;
    this->bCursorBlinkOn = 0;
    this->blinkTimer = 0.0f;

    this->pFont = dwFont_Load(new dwFont, pFontName);

    this->selAnchor = 0;
    this->selEnd = this->pText->length + 1; // quirk: one PAST the length
}

// @439250 (dwGuiTextEntry_Dtor; scalar-deleting wrapper @439230)
dwGuiTextEntry::~dwGuiTextEntry()
{
    if (this->pFont != NULL)
    {
        // @504190: the binary's dwFont handle "dtor" is a lone RET (the
        // glyph block is owned by the dwFont cache) — only the handle
        // allocation is released.
        delete this->pFont;
    }
    // (pText is the caller's; dwWidget base dtor implicit)
}

// @439310 (dwGuiTextEntry_BeginEdit)
void dwGuiTextEntry::BeginEdit()
{
    dwWidgetMsg msg;

    if (this->bEditable != 0)
        return;

    dwWidget_pMouseTarget = this;
    this->bEditable = 1;
    this->bCursorBlinkOn = 1;
    this->blinkTimer = 0.0f;
    this->Invalidate();
    this->selAnchor = 0;
    this->selEnd = this->pText->length; // select all
    if (this->msgEditNotify != 0)
    {
        msg.code = this->msgEditNotify;
        msg.pSender = this->pText->pBuffer;
        msg.param = 0;
        msg.pTarget = NULL;
        dwWidget_DispatchMsg(&msg, NULL);
    }
}

// @439370 (dwGuiTextEntry_EndEdit)
void dwGuiTextEntry::EndEdit()
{
    dwWidgetMsg msg;

    if (this->bEditable == 0)
        return;

    if (dwWidget_pMouseTarget == this)
        dwWidget_pMouseTarget = NULL;
    this->bEditable = 0;
    this->Invalidate();
    if (this->msgEditNotify != 0)
    {
        msg.code = this->msgEditNotify;
        msg.pSender = this->pText->pBuffer;
        msg.param = 0;
        msg.pTarget = NULL;
        dwWidget_DispatchMsg(&msg, NULL);
    }
}

// @4393d0 (dwGuiTextEntry_DeleteSelection)
void dwGuiTextEntry::DeleteSelection()
{
    uint32_t tmp;

    if (this->selEnd < this->selAnchor)
    {
        tmp = this->selEnd;
        this->selEnd = this->selAnchor;
        this->selAnchor = tmp;
    }
    this->pText->Erase(this->selAnchor, this->selEnd);
    this->selEnd = this->selAnchor;
    this->Invalidate();
}

// @439410 (dwGuiTextEntry_HitTestCaret) — x -> char index. Faithful shape:
// the first char's width is consumed before the loop; each further step
// consumes the width of the char AFTER the new index (reads the NUL when the
// caret passes the last char — dwFont_GetCharWidth handles it).
uint32_t dwGuiTextEntry::HitTestCaret(int16_t x)
{
    char* pCh;
    int remaining;
    uint32_t idx;

    idx = 0;
    pCh = this->pText->pBuffer;
    if (pCh != NULL)
    {
        remaining = ((int)x - (int)this->left) - dwFont_GetCharWidth(this->pFont, *pCh);
        while (remaining > 0 && idx < this->pText->length)
        {
            pCh++;
            remaining -= dwFont_GetCharWidth(this->pFont, *pCh);
            idx++;
        }
    }
    return idx;
}

// vtbl +0x08 @439470 (dwGuiTextEntry_OnMouseDown)
int dwGuiTextEntry::OnMouseDown(int16_t x, int16_t y)
{
    int result;
    uint32_t caret;

    result = 1;
    if (this->bEditable != 0
        && (x < this->left || x >= this->right || y < this->top || y >= this->bottom))
    {
        // Click outside while editing: commit-out and hand the click to the
        // active screen behind us.
        this->EndEdit();
        result = dwWidget_pDefault->OnMouseDown(x, y);
    }
    else
    {
        this->BeginEdit();
    }

    if (this->bEditable != 0)
    {
        this->bDragging = 1;
        caret = this->HitTestCaret(x);
        this->selAnchor = caret;
        this->selEnd = caret;
    }
    return result;
}

// vtbl +0x0c @4394f0 (dwGuiTextEntry_OnMouseUp)
int dwGuiTextEntry::OnMouseUp(int16_t x, int16_t y)
{
    (void)x;
    (void)y;
    if (this->bEditable != 0)
        this->bDragging = 0;
    return 0;
}

// vtbl +0x04 @439500 (dwGuiTextEntry_OnMouseMove)
int dwGuiTextEntry::OnMouseMove(int16_t x, int16_t y)
{
    (void)y;
    if (this->bDragging != 0)
    {
        this->selEnd = this->HitTestCaret(x);
        this->Invalidate();
    }
    return 0;
}

// vtbl +0x10 @439530 (dwGuiTextEntry_OnKey)
int dwGuiTextEntry::OnKey(int key, int repeat)
{
    dwWidgetMsg msg;
    char c;
    int width;
    uint8_t bPlaySound;

    if (this->bEditable == 0 || repeat == 0)
        return this->bEditable;

    this->bDragging = 0;
    bPlaySound = 1;
    c = (char)key;
    switch (c)
    {
    case 0x03:
    case 0x0d: // Enter: commit
        this->EndEdit();
        if (this->msgCommit != 0)
        {
            msg.code = this->msgCommit;
            msg.pSender = this->pText->pBuffer;
            msg.param = 0;
            msg.pTarget = NULL;
            dwWidget_DispatchMsg(&msg, NULL);
        }
        break;

    case 0x08: // backspace
        if (this->selAnchor == this->selEnd && this->selAnchor != 0)
            this->selAnchor--;
        this->DeleteSelection();
        break;

    case 0x1c: // caret left
        if (this->selAnchor != 0)
        {
            this->selAnchor--;
            this->selEnd = this->selAnchor;
            this->Invalidate();
        }
        break;

    case 0x1d: // caret right
        if (this->selAnchor < this->pText->length)
        {
            this->selAnchor++;
            this->selEnd = this->selAnchor;
            this->Invalidate();
        }
        break;

    default:
        bPlaySound = 0;
        // Binary: MSVC CRT ctype masks 0x103 (isalpha) / 0x004 (isdigit) /
        // 0x117 (isgraph), then the filename-special filter.
        if (!isalpha((unsigned char)c) && !isdigit((unsigned char)c)
            && !isgraph((unsigned char)c) && c != ' ')
        {
            break;
        }
        if (c == '\\' || c == '/' || c == ':' || c == '*' || c == '?' || c == '<'
            || c == '>' || c == '|' || c == '"' || c == '.')
        {
            break;
        }
        if (this->selAnchor != this->selEnd)
            this->DeleteSelection();
        width = dwFont_GetCharWidth(this->pFont, c);
        if (this->pText->length != 0)
            width += dwFont_MeasureString(this->pFont, this->pText->pBuffer, this->pText->length);
        if (width < (int)(int16_t)(this->right - this->left) - 1
            && this->pText->length < (uint32_t)this->maxLen)
        {
            this->pText->Insert(this->selAnchor, &c, 1);
            bPlaySound = 1;
            this->selAnchor++;
            this->selEnd = this->selAnchor;
        }
        this->Invalidate();
        break;
    }

    if (bPlaySound != 0)
    {
        dwSound_PlayRestart("WTextEntry.wav");
        if (this->msgChanged != 0)
        {
            msg.code = this->msgChanged;
            msg.pSender = this->pText->pBuffer;
            msg.param = 0;
            msg.pTarget = NULL;
            dwWidget_DispatchMsg(&msg, NULL);
        }
    }
    return this->bEditable;
}

// vtbl +0x14 @4397a0 (dwGuiTextEntry_Update) — 0.7s caret blink. The timer
// accumulates even while not editing (faithful).
void dwGuiTextEntry::Update(float dt)
{
    float t;
    int phases;

    t = dt + this->blinkTimer;
    this->blinkTimer = t;
    if (this->bEditable != 0 && t >= 0.7f)
    {
        phases = (int)(t / 0.7f); // __ftol: truncate
        this->bCursorBlinkOn = (this->bCursorBlinkOn == 0);
        this->blinkTimer = t - (float)phases * 0.7f;
        this->Invalidate();
    }
}

// vtbl +0x18 @4392c0 (dwGuiTextEntry_OnHover) — hover notify carrying the
// msgEditNotify code as the payload (see the header note).
int dwGuiTextEntry::OnHover(int16_t x, int16_t y)
{
    dwWidgetMsg msg;

    (void)x;
    (void)y;
    if (this->msgEditNotify == 0)
        return 0;
    msg.code = 0x7531;
    msg.pSender = (void*)(intptr_t)this->msgEditNotify;
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);
    return 1;
}

// vtbl +0x44 @439810 (dwGuiTextEntry_Draw)
void dwGuiTextEntry::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    dwPoint pos;
    dwRect rect;
    uint32_t lo;
    uint32_t hi;
    uint32_t tmp;
    int16_t xLeft;
    int centerAdj;

    // Text origin: 2px in from the left, vertically centered on the font
    // line height (pHeader->bpp's low bits double as the top y-inset).
    // 32-bit centering math, 16-bit final add — exactly the binary's.
    centerAdj = ((int)(int16_t)(this->bottom - this->top)
                 - (int)this->pFont->pHeader->lineHeight) / 2;
    pos.x = this->left + 2;
    pos.y = (int16_t)(this->top + (int16_t)(this->pFont->pHeader->bpp + centerAdj));

    if (this->bEditable != 0)
    {
        // Selection band (cursorColor), full widget height.
        lo = this->selAnchor;
        hi = this->selEnd;
        if (hi < lo)
        {
            tmp = lo;
            lo = hi;
            hi = tmp;
        }
        if (lo < hi && this->pText->length != 0)
        {
            rect = *this->GetRectPtr();
            if (lo != 0)
                rect.left = this->left
                    + (int16_t)dwFont_MeasureString(this->pFont, this->pText->pBuffer, lo);
            rect.right = this->left
                + (int16_t)dwFont_MeasureString(this->pFont, this->pText->pBuffer, hi);
            dwRect_Clip(&rect, pClipRect);
            dwImageDraw_FillRect(pDestBits, &rect, this->cursorColor, NULL);
        }

        // Blinking 2px caret (textColor) when there is no selection.
        if (this->bCursorBlinkOn != 0 && this->selAnchor == this->selEnd)
        {
            rect = *this->GetRectPtr();
            if (this->pText->length != 0)
            {
                xLeft = this->left + 1;
                if (this->selEnd != 0)
                    xLeft += (int16_t)dwFont_MeasureString(this->pFont, this->pText->pBuffer,
                                                           this->selEnd);
                rect.left = xLeft;
            }
            rect.right = rect.left + 2;
            dwRect_Clip(&rect, pClipRect);
            dwImageDraw_FillRect(pDestBits, &rect, this->textColor, NULL);
        }

        dwImageDraw_FrameRect(pDestBits, this->GetRectPtr(), 7, pClipRect);
    }

    if (this->pText->length != 0)
    {
        dwFont_DrawStringClipped(pDestBits, this->pFont, &pos, this->pText->pBuffer,
                                 this->textColor, pClipRect);
    }
}

// ---- dwGuiFindEntry ---------------------------------------------------------

// @413c20 (dwGuiFindEntry_Ctor) — base ctor with msgCommit forced to 0x1b79;
// the caller's msgCommitIgnored is never read (faithful).
dwGuiFindEntry::dwGuiFindEntry(dwRect* pRect, char* pFontName, uint8_t textColor,
                               uint8_t cursorColor, dwString* pText, int32_t msgEditNotify,
                               int32_t msgChanged, int32_t msgCommitIgnored, int32_t messageCode)
    : dwGuiTextEntry(pRect, pFontName, textColor, cursorColor, pText, msgEditNotify, msgChanged,
                     0x1b79)
{
    (void)msgCommitIgnored;
    this->messageCode = messageCode;
}

// @413c90 (dwGuiFindEntry_Dtor; scalar-deleting wrapper @413c70)
dwGuiFindEntry::~dwGuiFindEntry()
{
    // vptr re-point + base dtor only (implicit).
}

// vtbl +0x1c @413ca0 (dwGuiFindEntry_OnMessage) — mirror the payload string
// into the edited text.
int dwGuiFindEntry::OnMessage(dwWidgetMsg* pMsg)
{
    if (pMsg->code == this->messageCode)
    {
        this->pText->Assign((const char*)pMsg->pSender, 0);
        this->Invalidate();
    }
    return 0;
}
