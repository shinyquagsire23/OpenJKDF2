// dwGuiTextBlock — the TEXTBLOCK control: multi-line rich-text block with
// <...> hyperlink markup that spawns clickable rollover children on top of a
// timed text-reveal animation.
//
// Decompiled from DroidWorks.exe range 0x436d90-0x437d5x. MSVC MULTIPLE
// INHERITANCE (dwWidgetGroup primary @0x00 + dwGuiHypText secondary @0x14):
// binary vtables dwGuiTextBlock_vtbl @0x51fb68 (primary) and
// dwGuiTextBlock_HypText_vtbl @0x51fb18 (secondary; this-adjustor thunks
// @437d00-437d50 for dtor/OnMouseMove/OnMouseDown/Update/OnHover/Draw — the
// exact override set below, so plain C++ MI regenerates them). See
// Dw/dwGuiTextBlock.h for the field map.
//
// Translation notes:
//  - ParseMarkup/BuildLinkWidgets are LITERAL translations of the binary's
//    pointer walk (they were hand-verified against the disassembly; Ghidra's
//    decompile drops several argument loads). The walk relies on
//    dwString::Erase shifting the tail IN PLACE (no realloc) so the cursors
//    stay valid across erases — true for both the binary's and this repo's
//    dwString.
//  - Both bases embed a dwWidget: every rect/bEnabled/Invalidate access is
//    base-qualified to match the exact subobject the binary touched
//    (group rect for markup metrics, hyptext rect + bEnabled in Update).
//  - dwSound_* is the repo's name-keyed C API (binary: thiscall on
//    dwSound_pManager @0x53d960).
//  - dwGuiTextRollover children are constructed for real (Dw/dwGuiWidgets.h);
//    the binary call sites push a dead 11th ctor arg the ctor never reads —
//    see the notes in CreateLinkWidget.
//
// No module statics — no dwGuiTextBlock_Startup needed (soft-reset rule).

#include "Dw/dwGuiTextBlock.h"

#include "Dw/dwImage.h" // dwImageBits (plain-C struct)
#include "Dw/dwSound.h" // IsPlaying/PlayLooping/Stop
#include "Dw/dwGuiWidgets.h" // dwGuiTextRollover (link children)

#include "jk.h"
#include "stdPlatform.h"

// @436d90 (dwGuiTextBlock_Ctor)
// Base ctors exactly as the binary: dwWidgetGroup(pRect), then the hyptext
// FORMAT ctor dwGuiHypText(pRect, NULL, pFontName, color, pFormat) — pFormat
// may attach the visible wipe/typewriter elements to the base.
dwGuiTextBlock::dwGuiTextBlock(dwRect* pRect, char* pFontName, uint8_t color, uint8_t hAlign,
                               uint8_t vAlign, char* pFormat, char* pRevealSoundName,
                               void* pNotify, char* pMarkup)
    : dwWidgetGroup(pRect)
    , dwGuiHypText(pRect, NULL, pFontName, color, pFormat)
    , displayText(pMarkup, 0)
    , sourceMarkup(pMarkup, 0)
    , revealSound(pRevealSoundName, 0)
{
    char* pDisplay;

    this->hAlign = hAlign;
    this->vAlign = vAlign;
    this->pFont = NULL;
    this->revealL = 0;
    this->revealT = 0;
    this->revealR = 0;
    this->revealB = 0;
    this->linkPos.x = 0;
    this->linkPos.y = 0;
    this->pHoverNotify = pNotify;
    this->bRevealWDone = 0;
    this->bRevealHDone = 0;

    if (pFontName != NULL)
    {
        // Own heap-owned handle, independent of the hyptext base's (the
        // binary stored NULL when the 0x10 allocation failed — unreachable
        // with new, same note as dwGuiHypText).
        this->pFont = dwFont_Load(new dwFont, pFontName);
    }
    this->fontName.Assign(pFontName, 0);

    // Reveal progress rect starts collapsed at the widget's top-left (the
    // binary first dead-stores the full right/bottom, then overwrites them
    // with left/top — final values kept).
    this->revealL = this->dwWidgetGroup::left;
    this->revealT = this->dwWidgetGroup::top;
    this->revealR = this->dwWidgetGroup::left;
    this->revealB = this->dwWidgetGroup::top;
    this->revealTime = 0.0f;

    // " " is the placeholder for an empty block (filled in later via
    // messages); anything else is parsed and shown immediately.
    if (!dwString_Equals(this->displayText.pBuffer, " "))
    {
        this->ParseMarkup();
        this->Clear(); // dwGuiHypText::Clear (frees text + runs)
        pDisplay = this->displayText.pBuffer;
        this->text.Free(); // SetText APPENDS — free first (stock caller pattern)
        this->SetText(pDisplay); // virtual +0x48 (not overridden here -> base)
    }
}

// @436fa0 (dwGuiTextBlock_Dtor; scalar-deleting wrapper @436f80)
dwGuiTextBlock::~dwGuiTextBlock()
{
    if (this->pFont != NULL)
    {
        // @504190: the binary's dwFont handle "dtor" is a lone RET (the
        // glyph block is owned by the dwFont cache) — only the handle
        // allocation is released.
        delete this->pFont;
    }
    // The rest unwinds implicitly in exactly the binary's order: string
    // members in reverse declaration order (revealSound, sourceMarkup,
    // fontName, tagName, linkAnchor, linkTarget, displayText), then
    // ~dwGuiHypText (text/runs/elements + its font handle), then
    // ~dwWidgetGroup (FreeImages + DELETE of the link children + list),
    // then ~dwWidget.
}

// @437190 (dwGuiTextBlock_ParseMarkup) — ctor-time markup strip. LITERAL
// translation of the binary's pointer walk (see the file-top note).
//
// Grammar handled per "<...>" tag (two forms, all cursors kept live across
// the in-place Erase calls):
//   "<target anchor...>"      — a space inside the tag: linkTarget = text up
//                               to the space; the whole tag is erased.
//   "<...=tag>anchor<close>"  — '=' found walking BACK from '>' (the walk
//                               stops early — extent check — when it reaches
//                               the tag start): tagName = text after '=',
//                               tag erased, anchor = text up to the next
//                               '<', closing tag erased.
//   plain "<target>anchor<close>" (no '=', no space): linkTarget = the tag
//                               body, then anchor/closing tag as above.
// Quirks preserved: bFoundTarget is NEVER reset between tags; a tag whose
// '=' abuts '>' Assigns with len 0 == strlen (tagName gets the whole tail);
// only the LAST link's target/anchor/tagName survive (the ctor only strips —
// BuildLinkWidgets re-walks per link).
void dwGuiTextBlock::ParseMarkup()
{
    char* p;     // EDI: current tag cursor / second-half link-target cursor
    char* pScan; // ESI: forward scan cursor
    char* pWalk; // EBX: backward '='-walk cursor
    char* pInner; // first char after the opening '<'
    char* pTmp;
    char* pBuf;
    dwPoint extentStart; // wrapped extent at the tag start
    dwPoint extentCur;   // wrapped extent at the walk cursor
    int bFoundTarget;
    dwRect* pGroupRect;

    pGroupRect = ((dwWidgetGroup*)this)->GetRectPtr(); // binary: EBP+0x06
    extentStart.x = 0;
    extentStart.y = 0;
    extentCur.x = 0;
    extentCur.y = 0;
    bFoundTarget = 0; // quirk: never reset between tags

    p = this->displayText.pBuffer;
    while (*p != '\0' && *p != '<')
        p++;

    for (;;)
    {
        pScan = p;
        if (*p == '<')
        {
            pInner = p + 1;
            dwFont_MeasureWrappedExtent(&extentStart, this->pFont, pGroupRect,
                                        this->displayText.pBuffer,
                                        (unsigned int)(pInner - this->displayText.pBuffer) - 1);
            while (*pScan != '\0' && *pScan != '>')
                pScan++;
            if (*pScan == '>')
            {
                dwFont_MeasureWrappedExtent(&extentCur, this->pFont, pGroupRect,
                                            this->displayText.pBuffer,
                                            (unsigned int)(pScan - this->displayText.pBuffer) - 1);

                // Walk back from '>' looking for '='; bail to the plain-
                // target path when the measured extent reaches the start's.
                pWalk = pScan - 1;
                if (*pWalk != '=')
                {
                    for (;;)
                    {
                        if (extentCur.x == extentStart.x)
                        {
                            p = pInner; // join: plain "<target>" form
                            goto second_half;
                        }
                        dwFont_MeasureWrappedExtent(
                            &extentCur, this->pFont, pGroupRect, this->displayText.pBuffer,
                            (unsigned int)(pWalk - this->displayText.pBuffer) - 1);
                        pWalk--;
                        if (*pWalk == '=')
                            break;
                    }
                }
                pWalk++; // first char after '='

                // "<... =tag>" form (len 0 -> strlen quirk when '=' abuts '>')
                this->tagName.Assign(pWalk, (uint32_t)(pScan - pWalk));

                // Space form: linkTarget = "<target ..." up to the space.
                pTmp = pInner;
                while (*pTmp != '\0' && *pTmp != ' ')
                    pTmp++;
                if (*pTmp == ' ')
                {
                    this->linkTarget.Assign(pInner, (uint32_t)(pTmp - pInner));
                    bFoundTarget = 1;
                }

                // Erase the whole opening tag "[<...>]"; the tail shifts
                // left in place, the cursors now address the shifted text.
                pBuf = this->displayText.pBuffer;
                this->displayText.Erase((uint32_t)(pInner - pBuf) - 1,
                                        (uint32_t)(pScan - pBuf) + 1);

                // Anchor text runs to the next '<' (the closing tag).
                pScan = pInner;
                while (*pScan != '\0' && *pScan != '<')
                    pScan++;
                if (*pScan == '<')
                {
                    this->linkAnchor.Assign(pInner - 1, (uint32_t)(pScan - pInner) + 1);
                    p = pScan; // closing tag's '<'
                    while (*pScan != '\0' && *pScan != '>')
                        pScan++;
                    pBuf = this->displayText.pBuffer;
                    this->displayText.Erase((uint32_t)(p - pBuf), (uint32_t)(pScan - pBuf) + 1);
                    pScan = p - 1; // last anchor char
                    p = p + 1 - (intptr_t)this->linkAnchor.length; // one past the anchor start
                }
                else
                {
                    p = pInner; // no closing tag; pScan is at the string end
                }

            second_half:
                // No explicit space-target yet: the pending [p, pScan) text
                // (the plain tag body, or the '='-form's anchor region) IS
                // the target — erase it and pick up its own anchor/closing
                // tag pair.
                if (p != NULL && !bFoundTarget)
                {
                    this->linkTarget.Assign(p, (uint32_t)(pScan - p));
                    pBuf = this->displayText.pBuffer;
                    this->displayText.Erase((uint32_t)(p - pBuf) - 1,
                                            (uint32_t)(pScan - pBuf) + 1);
                    while (*pScan != '\0' && *pScan != '<')
                        pScan++;
                    if (*pScan == '<')
                    {
                        this->linkAnchor.Assign(p - 1, (uint32_t)(pScan - p) + 1);
                        pTmp = pScan; // closing tag's '<'
                        while (*pScan != '\0' && *pScan != '>')
                            pScan++;
                        pBuf = this->displayText.pBuffer;
                        this->displayText.Erase((uint32_t)(pTmp - pBuf),
                                                (uint32_t)(pScan - pBuf) + 1);
                        p = pTmp + 1 - (intptr_t)this->linkAnchor.length;
                        // (ParseMarkup leaves pScan at the erased '>' spot;
                        // only BuildLinkWidgets rewinds it — faithful)
                    }
                }
            }
        }

        // Advance to the next tag.
        while (*p != '\0' && *p != '<')
            p++;
        if (*p != '<')
            return;
    }
}

// @4373f0 (dwGuiTextBlock_BuildLinkWidgets) — reveal-completion pass: reset
// displayText from the pristine sourceMarkup, then re-walk the markup with
// the SAME literal pointer walk as ParseMarkup, additionally measuring each
// link's wrapped-text position and spawning its rollover child. Kept as a
// separate body (the binary duplicates the walk; only the deltas are
// commented).
void dwGuiTextBlock::BuildLinkWidgets()
{
    char* p;
    char* pScan;
    char* pWalk;
    char* pInner;
    char* pTmp;
    char* pBuf;
    dwPoint extentStart;
    dwPoint extentCur;
    int bFoundTarget;
    dwRect* pGroupRect;

    pGroupRect = ((dwWidgetGroup*)this)->GetRectPtr();
    extentStart.x = 0;
    extentStart.y = 0;
    extentCur.x = 0;
    extentCur.y = 0;
    bFoundTarget = 0; // quirk: never reset between links

    // Delta vs ParseMarkup: restart from the pristine markup.
    this->displayText.Free();
    this->displayText.Assign(this->sourceMarkup.pBuffer, 0);

    p = this->displayText.pBuffer;
    while (*p != '\0' && *p != '<')
        p++;

    for (;;)
    {
        pScan = p;
        if (*p == '<')
        {
            pInner = p + 1;
            dwFont_MeasureWrappedExtent(&extentStart, this->pFont, pGroupRect,
                                        this->displayText.pBuffer,
                                        (unsigned int)(pInner - this->displayText.pBuffer) - 1);
            while (*pScan != '\0' && *pScan != '>')
                pScan++;
            if (*pScan == '>')
            {
                dwFont_MeasureWrappedExtent(&extentCur, this->pFont, pGroupRect,
                                            this->displayText.pBuffer,
                                            (unsigned int)(pScan - this->displayText.pBuffer) - 1);

                pWalk = pScan - 1;
                if (*pWalk != '=')
                {
                    for (;;)
                    {
                        if (extentCur.x == extentStart.x)
                        {
                            p = pInner;
                            goto second_half;
                        }
                        dwFont_MeasureWrappedExtent(
                            &extentCur, this->pFont, pGroupRect, this->displayText.pBuffer,
                            (unsigned int)(pWalk - this->displayText.pBuffer) - 1);
                        pWalk--;
                        if (*pWalk == '=')
                            break;
                    }
                }
                pWalk++;

                this->tagName.Assign(pWalk, (uint32_t)(pScan - pWalk));

                pTmp = pInner;
                while (*pTmp != '\0' && *pTmp != ' ')
                    pTmp++;
                if (*pTmp == ' ')
                {
                    this->linkTarget.Assign(pInner, (uint32_t)(pTmp - pInner));
                    bFoundTarget = 1;
                }

                pBuf = this->displayText.pBuffer;
                this->displayText.Erase((uint32_t)(pInner - pBuf) - 1,
                                        (uint32_t)(pScan - pBuf) + 1);

                pScan = pInner;
                while (*pScan != '\0' && *pScan != '<')
                    pScan++;
                if (*pScan == '<')
                {
                    this->linkAnchor.Assign(pInner - 1, (uint32_t)(pScan - pInner) + 1);
                    p = pScan;
                    while (*pScan != '\0' && *pScan != '>')
                        pScan++;
                    pBuf = this->displayText.pBuffer;
                    this->displayText.Erase((uint32_t)(p - pBuf), (uint32_t)(pScan - pBuf) + 1);
                    pScan = p - 1;
                    p = p + 1 - (intptr_t)this->linkAnchor.length;
                }
                else
                {
                    p = pInner;
                }

            second_half:
                if (p != NULL && !bFoundTarget)
                {
                    this->linkTarget.Assign(p, (uint32_t)(pScan - p));
                    pBuf = this->displayText.pBuffer;
                    this->displayText.Erase((uint32_t)(p - pBuf) - 1,
                                            (uint32_t)(pScan - pBuf) + 1);
                    while (*pScan != '\0' && *pScan != '<')
                        pScan++;
                    if (*pScan == '<')
                    {
                        this->linkAnchor.Assign(p - 1, (uint32_t)(pScan - p) + 1);
                        pTmp = pScan;
                        while (*pScan != '\0' && *pScan != '>')
                            pScan++;
                        pBuf = this->displayText.pBuffer;
                        this->displayText.Erase((uint32_t)(pTmp - pBuf),
                                                (uint32_t)(pScan - pBuf) + 1);
                        // Delta vs ParseMarkup: this arm DOES rewind the scan
                        // cursor for the Equals guards below.
                        pScan = pTmp - 1;
                        p = pTmp + 1 - (intptr_t)this->linkAnchor.length;
                    }
                }
            }
        }

        // Delta vs ParseMarkup: spawn the link's rollover child (runs every
        // iteration; the empty-string guards skip degenerate cursors, e.g.
        // when the walk ended at the terminator).
        if (!dwString_Equals(p, "") && !dwString_Equals(pScan, ""))
        {
            dwFont_MeasureWrappedExtent(&this->linkPos, this->pFont, pGroupRect,
                                        this->displayText.pBuffer,
                                        (unsigned int)(p - this->displayText.pBuffer) - 1);
            // By-value copies, exactly like the binary's stack temporaries.
            this->CreateLinkWidget(this->linkAnchor, this->linkTarget, this->linkPos);
        }

        while (*p != '\0' && *p != '<')
            p++;
        if (*p != '<')
            return;
    }
}

// vtbl +0x04 @437710 — unify both bases' vtables on the GROUP's handler
// (the compiler emits the secondary-vtable thunk).
int dwGuiTextBlock::OnMouseMove(int16_t x, int16_t y)
{
    return this->dwWidgetGroup::OnMouseMove(x, y);
}

// vtbl +0x08 @437730
int dwGuiTextBlock::OnMouseDown(int16_t x, int16_t y)
{
    return this->dwWidgetGroup::OnMouseDown(x, y);
}

// vtbl +0x18 @437750 (dwGuiTextBlock_OnHover) — route the cursor to the
// link child under (x,y) (containment only, NO enabled check); else the
// stock hover notify. Returns 1 (or the child's result).
int dwGuiTextBlock::OnHover(int16_t x, int16_t y)
{
    dwListNode* pNode;
    dwWidget* pChild;
    dwWidgetMsg msg;

    for (pNode = this->children.pSentinel->pNext; pNode != this->children.pSentinel;
         pNode = pNode->pNext)
    {
        pChild = (dwWidget*)pNode->pData;
        if (x >= pChild->left && x < pChild->right && y >= pChild->top && y < pChild->bottom)
            return pChild->OnHover(x, y);
    }
    if (this->pHoverNotify != NULL)
    {
        msg.code = 0x7531;
        msg.pSender = this->pHoverNotify;
        msg.param = 0;
        msg.pTarget = NULL;
        dwWidget_DispatchMsg(&msg, NULL);
    }
    return 1;
}

// @437800 (dwGuiTextBlock_CreateLinkWidget) — build one rollover hotspot
// child for a link. The dwStrings arrive BY VALUE (the binary copy-
// constructs stack temporaries and frees them in the callee; C++ value
// parameters reproduce that).
void dwGuiTextBlock::CreateLinkWidget(dwString anchor, dwString target, dwPoint pos)
{
    dwRect rect;
    dwWidget* pWidget;

    if (dwString_Equals(target.pBuffer, "HL"))
    {
        // Hotspot rect: anchor text's wrapped position, one line high.
        rect.left = pos.x;
        rect.top = pos.y;
        rect.right = 0;
        rect.bottom = 0;
        rect.right = rect.left
            + (int16_t)dwFont_MeasureString(this->pFont, anchor.pBuffer, (int)anchor.length);
        rect.bottom = rect.top + (int16_t)this->pFont->pHeader->lineHeight;

        // Binary @437880-437914: new(0xcc) dwGuiTextRollover_Ctor(&rect,
        // anchor, fontName, tagName, hAlign, 0, vAlign, 0,
        // "CTextRollover.WAV", 0x1b58, 1) — the trailing literal 1 is an 11th
        // arg the ctor never reads (RET 0x2c; dead param, dropped from the
        // 10-param translation). Child insert is push-FRONT.
        // (both bases embed a dwWidget; the binary stores the PRIMARY
        // subobject pointer, i.e. the dwGuiTextButton path — cast through it)
        pWidget = static_cast<dwGuiTextButton*>(
            new dwGuiTextRollover(&rect, anchor.pBuffer, this->fontName.pBuffer,
                                  this->tagName.pBuffer, this->hAlign, NULL,
                                  this->vAlign, NULL, (char*)"CTextRollover.WAV",
                                  0x1b58));
        this->children.InsertAfter(this->children.pSentinel, pWidget);
    }
    else if (dwString_Equals(target.pBuffer, "URL"))
    {
        rect.left = pos.x;
        rect.top = pos.y;
        rect.right = 0;
        rect.bottom = 0;
        rect.right = rect.left
            + (int16_t)dwFont_MeasureString(this->pFont, anchor.pBuffer, (int)anchor.length);
        rect.bottom = rect.top + (int16_t)this->pFont->pHeader->lineHeight;

        // Binary @437976-437a1e: identical to the HL branch except the
        // command id 0x1b61 (URL launch); same dead 11th arg, same push-front.
        pWidget = static_cast<dwGuiTextButton*>(
            new dwGuiTextRollover(&rect, anchor.pBuffer, this->fontName.pBuffer,
                                  this->tagName.pBuffer, this->hAlign, NULL,
                                  this->vAlign, NULL, (char*)"CTextRollover.WAV",
                                  0x1b61));
        this->children.InsertAfter(this->children.pSentinel, pWidget);
    }
    else
    {
        // Binary: clears the two BY-VALUE temporaries before freeing them —
        // a no-op side effect on locals, kept for fidelity.
        anchor.Assign(NULL, 0);
        target.Assign(NULL, 0);
    }
    // (binary: explicit dwString_Free on both value params; the dtors do it)
}

// vtbl +0x14 @437a70 (dwGuiTextBlock_Update) — the reveal animation, gated
// on the HYPTEXT base's bEnabled (its own subobject flag; the group's copy
// is what parents tick against).
void dwGuiTextBlock::Update(float dt)
{
    dwListNode* pNode;
    dwWidget* pChild;
    int16_t width;
    int16_t height;
    int w;
    int h;

    if (this->dwGuiHypText::bEnabled == 0)
    {
        // Reveal gated off: force-disable any still-enabled link children
        // (only when the FIRST child is enabled — faithful gate).
        pNode = this->children.pSentinel->pNext;
        if (pNode != this->children.pSentinel && ((dwWidget*)pNode->pData)->bEnabled != 0)
        {
            while (pNode != this->children.pSentinel)
            {
                pChild = (dwWidget*)pNode->pData;
                if (pChild->bEnabled != 0)
                {
                    pChild->Disable();
                    ((dwGuiHypText*)this)->dwWidget::Invalidate();
                    ((dwWidgetGroup*)this)->dwWidget::Invalidate();
                }
                pNode = pNode->pNext;
            }
        }
    }
    else
    {
        this->revealTime = dt + this->revealTime;
        if (this->revealR != this->dwGuiHypText::right
            || this->revealB != this->dwGuiHypText::bottom)
        {
            // Reveal spans 1 second: revealed size = full size * elapsed.
            // The binary __ftol-truncates and keeps only the low 16 bits
            // (unsigned) before the clamp — mirrored exactly.
            width = this->dwGuiHypText::right - this->dwGuiHypText::left;
            height = this->dwGuiHypText::bottom - this->dwGuiHypText::top;
            w = (int)(uint16_t)(int32_t)((float)width * this->revealTime);
            h = (int)(uint16_t)(int32_t)((float)height * this->revealTime);
            if (w > (int)width)
                w = width;
            this->bRevealWDone = 1; // Note: unconditional in the binary
            if (h > (int)height)
                h = height;
            this->bRevealHDone = 1; // Note: unconditional in the binary
            this->revealR = this->revealL + (int16_t)w;
            this->revealB = this->revealT + (int16_t)h;

            // Faithful quirk: with both flags forced above, this alternates
            // Stop/PlayLooping while the sound reports playing — the bursty
            // typewriter loop heard during reveals.
            if (this->bRevealWDone != 0 && this->bRevealHDone != 0
                && dwSound_IsPlaying(this->revealSound.pBuffer))
            {
                dwSound_Stop(this->revealSound.pBuffer);
            }
            else
            {
                dwSound_PlayLooping(this->revealSound.pBuffer);
            }

            if (this->revealR == this->dwGuiHypText::right
                && this->revealB == this->dwGuiHypText::bottom)
            {
                // Reveal just completed: silence the loop, spawn the link
                // children, enable them.
                if (dwSound_IsPlaying(this->revealSound.pBuffer))
                    dwSound_Stop(this->revealSound.pBuffer);
                this->BuildLinkWidgets();
                for (pNode = this->children.pSentinel->pNext; pNode != this->children.pSentinel;
                     pNode = pNode->pNext)
                {
                    pChild = (dwWidget*)pNode->pData;
                    if (pChild->bEnabled == 0)
                        pChild->Enable();
                }
            }
            ((dwGuiHypText*)this)->dwWidget::Invalidate();
            ((dwWidgetGroup*)this)->dwWidget::Invalidate();
        }
    }

    this->dwGuiHypText::Update(dt);   // element tick (typewriter/wipe)
    this->dwWidgetGroup::Update(dt);  // child tick broadcast
}

// vtbl +0x44 @437cd0 (dwGuiTextBlock_Draw) — text first, children on top.
// dwGuiHypText::Draw clips *pClipRect to its layout rect IN PLACE, so the
// children inherit that clip (faithful — the binary passes the same pointer).
void dwGuiTextBlock::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    this->dwGuiHypText::Draw(pDestBits, pClipRect);
    this->dwWidgetGroup::Draw(pDestBits, pClipRect);
}
