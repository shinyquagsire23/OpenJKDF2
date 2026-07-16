// dwGuiCredits — 'credits' end-credits scroll screen (dwGuiScreen subclass).
// DroidWorks.exe 0x40af10-0x40b93f, vtbls @0x51e8c0 (primary) / 0x51e8a8
// (segment). See Dw/dwGuiCredits.h for the class notes.

#include "Dw/dwGuiCredits.h"

#include "Dw/dwSegment.h"   // dwSegment_RequestAdvance
#include "Dw/dwSound.h"     // dwSound_SetMusic / dwSound_FadeMusic
#include "Dw/dwCursor.h"    // dwCursor_SetCursor
#include "Dw/dwConfFile.h"  // CREDITS parsing
#include "Dw/dwString.h"    // dwString (line storage) + dwString_Equals
#include "Dw/dwFont.h"      // dwFont_Load / dwFont_DrawText* / free convention
#include "Dw/dwWidgetGroup.h"

#include "stdPlatform.h"

// @40af10 (dwGuiCredits_Ctor)
dwGuiCredits::dwGuiCredits()
    : dwGuiScreen("credits", NULL)
{
    this->scrollAccum = 0.0f;
    this->scrollSpeed = 0.0f;
    this->pSectionFont = NULL;
    this->pNameFont = NULL;
    this->pTitleFont = NULL;
    this->colorIdx = 0;
    this->creditsRect.left = 0;
    this->creditsRect.top = 0;
    this->creditsRect.right = 0;
    this->creditsRect.bottom = 0;
    this->bSoundTriggered = 0;
    // creditLines' dwList ctor allocated the sentinel (binary: inline
    // idk_alloc(0xc) + self-link)
    this->pCurrentLine = NULL;
    this->scrollY = 0;
    this->scrollBaseline = 0;
}

// @40b000 (dwGuiCredits_Dtor; scalar-deleting wrapper @40afe0; secondary
// dtor thunk @40ba60)
dwGuiCredits::~dwGuiCredits()
{
    // The dwFont handle "dtor" in the binary (@504190) is a no-op; freeing
    // the handle allocation is all that happens.
    if (this->pSectionFont != NULL)
        delete this->pSectionFont;
    if (this->pNameFont != NULL)
        delete this->pNameFont;
    if (this->pTitleFont != NULL)
        delete this->pTitleFont;

    // Free every credit line string, then the nodes + sentinel.
    dwListNode* pNode = this->creditLines.pSentinel->pNext;
    while (pNode != this->creditLines.pSentinel)
    {
        dwListNode* pNext = pNode->pNext;
        dwString* pStr = (dwString*)pNode->pData;
        if (pStr != NULL)
            delete pStr; // dwString dtor frees the buffer
        pNode = pNext;
    }
    this->creditLines.Free();
    // (base dwGuiScreen dtor tears the rest down)
}

// vtbl(scn) +0x00 @40b170 (dwGuiCredits_OnActivate)
int dwGuiCredits::Activate()
{
    int ret = dwGuiScreen::Activate();
    if (ret != 0)
        dwCursor_SetCursor(0);
    this->ResetClock();
    dwSound_SetMusic("DiscoBaby.wav", 0);
    return ret;
}

// vtbl +0x10 @40b1b0 (dwGuiCredits_OnKey)
int dwGuiCredits::OnKey(int key, int repeat)
{
    (void)repeat;
    if ((char)key == '\x1b')
        dwSegment_RequestAdvance();
    return 0;
}

// @40b300 (dwGuiCredits_GetLineFont)
dwFont* dwGuiCredits::GetLineFont(char* pLineText)
{
    dwFont* pFont = this->pTitleFont;
    if (pLineText != NULL && *pLineText != '\0')
    {
        char c = *pLineText;
        if (c == 'S')
            pFont = this->pSectionFont;
        if (c == 'N')
            pFont = this->pNameFont;
        if (c == 'T')
            pFont = this->pTitleFont;
    }
    return pFont;
}

// vtbl +0x14 @40b1d0 (dwGuiCredits_Update)
void dwGuiCredits::Update(float dt)
{
    this->scrollAccum += dt;
    // (int)(speed * accum - (-0.5)) — round-to-nearest of the scroll offset
    int16_t newBaseline = this->creditsRect.bottom
                        - (int16_t)(this->scrollSpeed * this->scrollAccum + 0.5f);
    int16_t oldBaseline = this->scrollBaseline;
    this->scrollBaseline = newBaseline;
    this->scrollY += newBaseline - oldBaseline;

    // Retire lines whose full height scrolled above the window top.
    // Note: the binary fetches the first line's font BEFORE testing for the
    // sentinel (reading the sentinel's uninitialized pData when the list is
    // empty); reordered here — same behavior for every non-empty list.
    if (this->pCurrentLine != NULL && this->pCurrentLine != this->creditLines.pSentinel)
    {
        dwFont* pFont = this->GetLineFont(((dwString*)this->pCurrentLine->pData)->pBuffer);
        while (this->pCurrentLine != this->creditLines.pSentinel)
        {
            int16_t lineH = (int16_t)pFont->pHeader->lineHeight;
            if ((int)lineH + (int)this->scrollY >= 0)
                break;
            this->scrollY += lineH;
            this->pCurrentLine = this->pCurrentLine->pNext;
            if (this->pCurrentLine != this->creditLines.pSentinel)
                pFont = this->GetLineFont(((dwString*)this->pCurrentLine->pData)->pBuffer);
        }
    }
    if (this->pCurrentLine == this->creditLines.pSentinel && this->scrollY < 0)
        dwSegment_RequestAdvance();

    this->Invalidate();
    this->controls.Update(dt); // tick the droid-dance child
}

// vtbl +0x44 @40b340 (dwGuiCredits_Draw)
void dwGuiCredits::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    dwGuiScreen::Draw(pDestBits, pClipRect);

    // Binary quirk kept: a clip copy is intersected with creditsRect, then
    // immediately overwritten with the widget rect — the text draws below
    // are clipped to the WIDGET rect, not to creditsRect.
    dwRect drawClip = *pClipRect;
    dwRect_Clip(&drawClip, &this->creditsRect); // (dead — see note)
    drawClip.left = this->left;
    drawClip.top = this->top;
    drawClip.right = this->right;
    drawClip.bottom = this->bottom;

    dwRect lineRect = this->creditsRect;
    int16_t y = this->scrollY;
    dwListNode* pNode = this->pCurrentLine;
    while (y < drawClip.bottom)
    {
        if (pNode == this->creditLines.pSentinel || pNode == NULL)
            break;
        char* pLine = ((dwString*)pNode->pData)->pBuffer;
        dwFont* pFont = this->GetLineFont(pLine);
        int16_t lineH = (int16_t)pFont->pHeader->lineHeight;
        lineRect.top = y;
        lineRect.bottom = y + lineH;
        char* pText = pLine + 2;
        if (pLine[1] == '!')
        {
            dwFont_DrawTextCentered(pDestBits, pFont, &lineRect, pText, this->colorIdx, &drawClip);
        }
        else if (pLine[1] == '/')
        {
            int16_t mid = (int16_t)(((int)this->creditsRect.right + (int)this->creditsRect.left) / 2);
            // split the line at the '/' marker (temporarily NUL-terminated)
            char* pSplit = pText;
            while (*pSplit != '\0' && *pSplit != '/')
                pSplit++;
            // Note: the binary restores '/' unconditionally (corrupting the
            // terminator when a '/'-layout line has no second '/'); restoring
            // the saved char is identical for well-formed data.
            char saved = *pSplit;
            *pSplit = '\0';
            dwRect half = lineRect;
            half.right = mid - 10;
            dwFont_DrawTextAligned(pDestBits, pFont, &half, pText, this->colorIdx, &drawClip, 2);
            *pSplit = saved;
            half.left = mid + 10;
            half.right = this->creditsRect.right;
            dwFont_DrawText(pDestBits, pFont, &half, saved != '\0' ? pSplit + 1 : pSplit, this->colorIdx, &drawClip);
            lineRect.left = this->creditsRect.left;
            lineRect.right = this->creditsRect.right;
        }
        // (any other byte1 draws nothing — blank spacing line)
        y += lineH;
        pNode = pNode->pNext;
    }

    // One-shot: when the credits tail is above the window's vertical middle,
    // fade the music out timed to the remaining scroll.
    if (this->bSoundTriggered == 0
        && (int)y < (int)this->creditsRect.top
                    + ((int)this->creditsRect.bottom - (int)this->creditsRect.top) / 2)
    {
        dwSound_FadeMusic(0.0f, (float)y / this->scrollSpeed - 0.3f);
        this->bSoundTriggered = 1;
    }
}

// vtbl +0x48 @40b580 (dwGuiCredits_CreateControl)
dwWidget* dwGuiCredits::CreateControl(char* pKeyword, dwConfFile* pConf)
{
    dwRect rect = {0, 0, 0, 0};

    if (dwString_Equals(pKeyword, "DROID_DANCE"))
    {
        dwConfFile_ParseRect(pConf, &rect);
        // TODO(dw-decomp): dwGuiDroidDance (disco droid viewer, unit
        // dwGuiList @40ab70 — P6 wave 2). Binary: new(0x598)
        // dwGuiDroidDance_Ctor(&rect). Loud stub until it lands.
        stdPlatform_Printf("TODO(dw-decomp): dwGuiCredits control 'DROID_DANCE' -> dwGuiDroidDance (unit dwGuiList) not translated yet\n");
        return NULL;
    }
    if (dwString_Equals(pKeyword, "SECTION_FONT"))
    {
        char* pName = dwConfFile_NextToken(pConf);
        this->pSectionFont = dwFont_Load(new dwFont, pName);
        return NULL;
    }
    if (dwString_Equals(pKeyword, "NAME_FONT"))
    {
        char* pName = dwConfFile_NextToken(pConf);
        this->pNameFont = dwFont_Load(new dwFont, pName);
        return NULL;
    }
    if (dwString_Equals(pKeyword, "TITLE_FONT"))
    {
        char* pName = dwConfFile_NextToken(pConf);
        this->pTitleFont = dwFont_Load(new dwFont, pName);
        return NULL;
    }
    if (dwString_Equals(pKeyword, "CREDITS"))
    {
        uint32_t color = 0;
        dwConfFile_ParseRect(pConf, &this->creditsRect);
        dwConfFile_ParseULong(pConf, &color);
        this->colorIdx = (uint8_t)color;
        dwConfFile_ParseFloat(pConf, &this->scrollSpeed);
        // every following non-empty line is one credits entry
        dwConfFile_ReadLine(pConf);
        while (pConf->bEof == 0)
        {
            char* pLine = pConf->pCursor;
            if (pLine != NULL && *pLine != '\0')
            {
                dwString* pStr = new dwString(pLine, 0);
                this->creditLines.InsertAfter(this->creditLines.pSentinel->pPrev, pStr);
            }
            dwConfFile_ReadLine(pConf);
        }
        this->scrollY = this->creditsRect.bottom;
        this->scrollBaseline = this->creditsRect.bottom;
        this->pCurrentLine = this->creditLines.pSentinel->pNext;
        return NULL;
    }
    return dwGuiScreen::CreateControl(pKeyword, pConf);
}

// Note: no binary counterpart — the unit owns no module statics; soft-reset
// convention seam.
extern "C" void dwGuiCredits_Startup(void)
{
}

// Added: C-callable factory (see dwGuiCredits.h). Upcasts through the MI
// hierarchy (dwGuiScreen -> dwWidget,dwSegment) to the dwSegment subobject.
extern "C" dwSegment* dwGuiCredits_New(void)
{
    return static_cast<dwSegment*>(new dwGuiCredits());
}
