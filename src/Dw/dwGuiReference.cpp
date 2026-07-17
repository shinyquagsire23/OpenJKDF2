// dwGuiReference — the "reference" room screen + the dwGuiRefTile decoration
// widget + the dwGuiRefRadioGroup_AddCategory factory helper. See
// Dw/dwGuiReference.h for the class roster, design notes and the translation
// status caveat.
//
// Decompiled from DroidWorks.exe, unit range 0x42a240-0x42f92f.

#include "Dw/dwGuiReference.h"

#include "Dw/dwControlPanel.h" // BUTTONHELPRECT / CONTROLPANEL factory targets
#include "Dw/dwRef.h"          // GRAPH -> dwRefGraph, PULLDOWN_MENU -> dwRefPulldown
#include "Dw/dwAnim.h"         // ICON_ANIM_PLAY -> dwAnim_Open
#include "Dw/dwGuiHypText.h"   // DENSITY_LABEL / TENSILE_LABEL -> dwGuiHypText
#include "Dw/dwStringTable.h"
#include "Dw/dwConfFile.h"
#include "Dw/dwString.h"
#include "Dw/dwList.h"
#include "Dw/dwWidgetGroup.h"
#include "Dw/dwImageDraw.h"    // dwGuiRefTile_Draw -> FrameRect

#include "jk.h"
#include "stdPlatform.h" // stdPlatform_Printf (LOUD-stub reporter)

#include <stdlib.h> // atoi, atof

// ---- module init ----------------------------------------------------------------

extern "C" void dwGuiReference_Startup(void)
{
    // No module statics.
}

// Shared LOUD-stub reporter for the entangled screen methods still blocked on
// the dwGuiScreen base-internal overlay + not-yet-landed screens.
static void dwGuiReference_StubReport(const char* pWhat)
{
    stdPlatform_Printf("TODO(dw-decomp): dwGuiReference::%s not translated yet "
                       "(base-overlay ambiguity / unlanded deps)\n", pWhat);
}

// =================================================================================
//  dwGuiRefTile
// =================================================================================

// @42a890 (dwGuiRefTile_Ctor)
dwGuiRefTile::dwGuiRefTile(dwRect* pRect, uint8_t color, uint8_t count)
    : dwWidget(pRect)
    , color(color)
    , count(count)
{
}

// @42a8e0 (dwGuiRefTile_Dtor; scalar-deleting wrapper @42a8c0) — plain dwWidget
// dtor (no owned members).
dwGuiRefTile::~dwGuiRefTile()
{
}

// @42a8f0 (dwGuiRefTile_Draw) — one frame when count == 1; otherwise `count`
// nested frames, each shrunk 1px on every side.
void dwGuiRefTile::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    if (this->count == 1)
    {
        dwImageDraw_FrameRect(pDestBits, this->GetRectPtr(), this->color, pClipRect);
        return;
    }
    if (this->count != 0)
    {
        dwRect r = *this->GetRectPtr();
        for (int i = 0; i < (int)this->count; i++)
        {
            dwImageDraw_FrameRect(pDestBits, &r, this->color, pClipRect);
            r.left = (int16_t)(r.left + 1);
            r.top = (int16_t)(r.top + 1);
            r.right = (int16_t)(r.right - 1);
            r.bottom = (int16_t)(r.bottom - 1);
        }
    }
}

// =================================================================================
//  dwGuiRefRadioGroup_AddCategory (owner of this unit; see the header note)
// =================================================================================

// @42a6f0 — new(0x54) dwGuiRefRadioButton(pGroup, pRect, imgNormal, sndOff,
// imgPressed, sndClick, cmdId), then pGroup->AddButton(it).
void dwGuiRefRadioGroup_AddCategory(dwGuiRefRadioGroup* pGroup, dwRect* pRect, char* pImgNormal,
                                    char* pSndOff, char* pImgPressed, char* pSndClick, int cmdId)
{
    dwGuiRefRadioButton* pBtn =
        new dwGuiRefRadioButton(pGroup, pRect, pImgNormal, pSndOff, pImgPressed, pSndClick, cmdId);
    pGroup->AddButton(pBtn);
}

// =================================================================================
//  dwGuiReference
// =================================================================================

// @42a990 (dwGuiReference_Ctor) — dwGuiScreen("reference", NULL); pSubPath seeds
// `path`. (pTopicList + the dwString members are constructed by their member
// initializers, matching the binary's per-field ctors.)
dwGuiReference::dwGuiReference(char* pSubPath)
    : dwGuiScreen("reference", NULL)
    , pTopicList()
    , currentFile()
    , bReloadPending(0)
    , bIntroPending(1)
    , pContentGroup(NULL)
    , path(pSubPath, 0)
    , pChildEc(NULL)
    , pChildF0(NULL)
    , pChildF4(NULL)
    , pChildF8(NULL)
    , scratchFC()
    , bReloadMaterials(0)
    , bSuppressStill(0)
    , menuMode(0)
    , field_110(0)
    , scratch114()
    , byte120(0)
    , bInternetOk(0)
{
}

// Unlink pGroup from the base `controls` child list (if present), then delete
// it — the binary's per-group teardown in the dtor (avoids the base group dtor
// double-freeing the content sub-groups).
static void dwGuiReference_RemoveGroup(dwGuiScreen* pScreen, dwWidgetGroup* pGroup)
{
    if (pGroup == NULL)
        return;
    dwList* pChildren = &pScreen->controls.children;
    dwListNode* pSent = pChildren->pSentinel;
    for (dwListNode* pNode = pSent->pNext; pNode != pSent; pNode = pNode->pNext)
    {
        if (pNode->pData == pGroup)
        {
            pChildren->UnlinkFreeNode(pNode);
            break;
        }
    }
    delete pGroup;
}

// @42aac0 (dwGuiReference_Dtor) — FreeImages, detach + delete the 5 content
// sub-groups, free the topic list, then the strings (member dtors) + base.
dwGuiReference::~dwGuiReference()
{
    this->FreeImages();

    dwGuiReference_RemoveGroup(this, this->pContentGroup); this->pContentGroup = NULL;
    dwGuiReference_RemoveGroup(this, this->pChildEc);      this->pChildEc = NULL;
    dwGuiReference_RemoveGroup(this, this->pChildF0);      this->pChildF0 = NULL;
    dwGuiReference_RemoveGroup(this, this->pChildF4);      this->pChildF4 = NULL;
    dwGuiReference_RemoveGroup(this, this->pChildF8);      this->pChildF8 = NULL;

    // Topic-list nodes: freed here (payloads are string-item records, deleted
    // via their scalar-deleting dtor in the binary). The list is only populated
    // by the still-stubbed page-navigation paths, so it is empty at runtime;
    // free the nodes + sentinel. TODO(dw-decomp): free string-item payloads
    // once the topic-navigation OnMessage paths land.
    this->pTopicList.Free();
}

// @42f740 (dwGuiReference_EnsureLoaded, vtbl +0x3c) — base EnsureImages, then
// each present content sub-group.
void dwGuiReference::EnsureImages()
{
    dwGuiScreen::EnsureImages();
    if (this->pContentGroup) this->pContentGroup->EnsureImages();
    if (this->pChildEc)      this->pChildEc->EnsureImages();
    if (this->pChildF0)      this->pChildF0->EnsureImages();
    if (this->pChildF4)      this->pChildF4->EnsureImages();
    if (this->pChildF8)      this->pChildF8->EnsureImages();
}

// @42f7a0 (dwGuiReference_FreeImages, vtbl +0x40)
void dwGuiReference::FreeImages()
{
    dwGuiScreen::FreeImages();
    if (this->pContentGroup) this->pContentGroup->FreeImages();
    if (this->pChildEc)      this->pChildEc->FreeImages();
    if (this->pChildF0)      this->pChildF0->FreeImages();
    if (this->pChildF4)      this->pChildF4->FreeImages();
    if (this->pChildF8)      this->pChildF8->FreeImages();
}

// @42d740 (dwGuiReference_CreateControl, vtbl +0x48) — the reference keyword
// factory. The GRAPH/PULLDOWN_MENU/CONTROLPANEL/CAT_RADIOGROUP/BUTTONHELPRECT/
// ICON_ANIM_PLAY/DENSITY_LABEL/TENSILE_LABEL branches are wired; the anim-viewer
// (ANIM_VIEWER/BACKDROP/BILEVEL/STILL_FRAME) and remaining text-control branches
// (SEEALSO/TEXTBLOCK/TEXTPOPUP/TEXTSLIDER/TEXTSPITTER/TEXTSTRIP/TYPEWRITER/
// SPITTIMER/STRIPTIMER) + HELP fall through to the base factory pending their
// dependencies (dwGuiPicture/dwWcMaterials/dwGuiAnimView/dwHelp + arg-verified
// ctors). See the binary @42d740 for those branches' exact recipes.
dwWidget* dwGuiReference::CreateControl(char* pKeyword, dwConfFile* pConf)
{
    dwStringTable* pTable = this->pStringTable;
    dwRect rect;
    rect.left = 0; rect.top = 0; rect.right = 0; rect.bottom = 0;

    if (dwString_Equals(pKeyword, "BUTTONHELPRECT"))
    {
        dwConfFile_ParseRect(pConf, &rect);
        uint32_t code = 0;
        dwConfFile_ParseULong(pConf, &code);
        return new dwControlPanelHelpRect(&rect, (int32_t)code);
    }

    if (dwString_Equals(pKeyword, "CAT_RADIOGROUP"))
    {
        rect.left   = (int16_t)atoi(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), pTable));
        rect.top    = (int16_t)atoi(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), pTable));
        rect.right  = (int16_t)atoi(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), pTable));
        rect.bottom = (int16_t)atoi(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), pTable));
        uint32_t nItems = 0;
        dwConfFile_ParseULong(pConf, &nItems);
        dwGuiRefRadioGroup* pGroup = new dwGuiRefRadioGroup(&rect);
        while (nItems != 0)
        {
            nItems--;
            if (pConf->bEof) break;
            dwConfFile_ReadLine(pConf);
            dwRect itemRect;
            itemRect.left   = (int16_t)atoi(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), pTable));
            itemRect.top    = (int16_t)atoi(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), pTable));
            itemRect.right  = (int16_t)atoi(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), pTable));
            itemRect.bottom = (int16_t)atoi(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), pTable));
            uint32_t id = 0;
            dwConfFile_ParseULong(pConf, &id);
            char* pImgNormal  = dwConfFile_NextToken(pConf);
            char* pSndOff     = dwConfFile_NextToken(pConf);
            char* pImgPressed = dwConfFile_NextToken(pConf);
            char* pSndClick   = dwConfFile_NextToken(pConf);
            dwGuiRefRadioGroup_AddCategory(pGroup, &itemRect, pImgNormal, pSndOff, pImgPressed,
                                           pSndClick, (int)id);
        }
        return pGroup;
    }

    if (dwString_Equals(pKeyword, "CONTROLPANEL"))
    {
        dwConfFile_ParseRect(pConf, &rect);
        uint32_t code = 0;
        dwConfFile_ParseULong(pConf, &code);
        char* pFilename = dwGuiScreen_LocalizeString(pConf->pCursor, pTable);
        // Sentinel filename (binary DAT_00529208) -> skip. Not localized here;
        // the base factory's own sentinel check is unavailable, so accept it.
        return new dwControlPanel(&rect, code, pFilename, pTable);
    }

    if (dwString_Equals(pKeyword, "GRAPH"))
    {
        dwConfFile_ParseRect(pConf, &rect);
        char* pName = dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), pTable);
        float f1 = (float)atof(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), pTable));
        float f2 = (float)atof(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), pTable));
        char* pSound = pConf->pCursor;
        return new dwRefGraph(&rect, pName, f1, f2, pSound);
    }

    if (dwString_Equals(pKeyword, "ICON_ANIM_PLAY"))
    {
        dwConfFile_ParseRect(pConf, &rect);
        uint32_t msgCode = 0;
        dwConfFile_ParseULong(pConf, &msgCode);
        char* pFile = dwConfFile_NextToken(pConf);
        dwAnim* pAnim = dwAnim_Open(&rect, pFile, (int)msgCode, 1);
        if (pAnim == NULL)
            return NULL;
        pAnim->Play();
        return pAnim;
    }

    if (dwString_Equals(pKeyword, "PULLDOWN_MENU"))
    {
        dwConfFile_ParseRect(pConf, &rect);
        char* pFont = dwConfFile_NextToken(pConf);
        int32_t colorParam = 0;    dwConfFile_ParseLong(pConf, &colorParam);
        uint32_t hotColorParam = 0;dwConfFile_ParseULong(pConf, &hotColorParam);
        uint32_t labelColor = 0;   dwConfFile_ParseULong(pConf, &labelColor);
        char* pImgNormal = dwConfFile_NextToken(pConf);
        char* pImgHot    = dwConfFile_NextToken(pConf);
        char* pOpenWav   = dwConfFile_NextToken(pConf);
        char* pSelectWav = dwConfFile_NextToken(pConf);
        char* pCloseWav  = dwConfFile_NextToken(pConf);
        char* pHoverWav  = dwConfFile_NextToken(pConf);
        char* pLabel     = dwConfFile_NextToken(pConf);
        uint32_t textColor = 0;    dwConfFile_ParseULong(pConf, &textColor);
        char* pFontHot   = pConf->pCursor;
        return new dwRefPulldown(&rect, pFont, (uint8_t)colorParam, (uint8_t)hotColorParam,
                                 labelColor, pImgNormal, pImgHot, pOpenWav, pSelectWav, pCloseWav,
                                 pHoverWav, pLabel, (uint8_t)textColor, pFontHot, 0);
    }

    if (dwString_Equals(pKeyword, "DENSITY_LABEL") || dwString_Equals(pKeyword, "TENSILE_LABEL"))
    {
        char* pFormat = dwConfFile_NextToken(pConf);
        rect.left   = (int16_t)atoi(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), pTable));
        rect.top    = (int16_t)atoi(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), pTable));
        rect.right  = (int16_t)atoi(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), pTable));
        rect.bottom = (int16_t)atoi(dwGuiScreen_LocalizeString(dwConfFile_NextToken(pConf), pTable));
        char* pFont = dwConfFile_NextToken(pConf);
        uint32_t color = 0;
        dwConfFile_ParseULong(pConf, &color);
        char* pText = dwGuiScreen_LocalizeString(pConf->pCursor, pTable);
        dwGuiHypText* pLabelW = new dwGuiHypText(&rect, NULL, pFont, (uint8_t)color, pFormat);
        pLabelW->text.Free();
        pLabelW->SetText(pText);
        return pLabelW;
    }

    // ANIM_VIEWER / BACKDROP / BILEVEL / STILL_FRAME / SEEALSO / TEXTBLOCK /
    // TEXTPOPUP / TEXTSLIDER / TEXTSPITTER / TEXTSTRIP / TYPEWRITER / SPITTIMER /
    // STRIPTIMER / HELP / HYP_TEXT / unknown -> base factory. TODO(dw-decomp):
    // wire the anim-viewer + text-control branches (recipes at binary @42d740).
    return dwGuiScreen::CreateControl(pKeyword, pConf);
}

// @42ba30 (dwGuiReference_OnMessage, vtbl +0x1c) — LOUD-stub. Handles the topic-
// navigation command codes (0x1b5a-0x1b61: category select, spawn dwGuiFind,
// build the info-card page via BuildDynamicControls, LAUNCH_URL flow), 7000
// (set current file) and 0x96 (advance). Blocked on the dwGuiScreen embedded-
// group overlay ambiguity + unlanded dwGuiFind; full recipe at binary @42ba30.
int dwGuiReference::OnMessage(dwWidgetMsg* pMsg)
{
    dwGuiReference_StubReport("OnMessage");
    return dwGuiScreen::OnMessage(pMsg);
}

// @42ed50 (dwGuiReference_Update, vtbl +0x14) — LOUD-stub. Rebuilds the current
// page's dynamic controls when bReloadPending/bReloadMaterials is set (opens the
// topic .ifc, clears the 5 content groups, re-runs BuildDynamicControls), then
// forwards the tick. Blocked on the same overlay ambiguity; recipe at @42ed50.
void dwGuiReference::Update(float dt)
{
    if (this->bReloadPending || this->bReloadMaterials)
        dwGuiReference_StubReport("Update(page reload)");
    // Forward the tick to the base (embedded controls group).
    dwGuiScreen::Update(dt);
}

// @42b300 (dwGuiReference_OnActivate, scn Activate) — LOUD-stub. Base Activate,
// then (first time) allocate the 5 content widget-groups + append them to the
// controls list, load the initial topic page (TPC enumeration + string table +
// BuildDynamicControls). Blocked on the overlay ambiguity; recipe at @42b300.
int dwGuiReference::Activate()
{
    int r = dwGuiScreen::Activate();
    dwGuiReference_StubReport("Activate(build content groups + first page)");
    return r;
}

// @42ae40 (dwGuiReference_BuildDynamicControls) — LOUD-stub. Parses a topic sub-
// section (DYNAMIC_CONTROL/NUMERATED_CONTROLS/NUMERATED_HEADER_CONTROLS/
// STRIPTIMER/ICON_ANIM_PLAY/BUTTONHELPRECT/TEXTPOPUP), building each control via
// the virtual CreateControl and prepending it into the target group. Recipe at
// binary @42ae40. Returns 1 (the binary's success path).
char dwGuiReference::BuildDynamicControls(dwConfFile* pConf, dwWidgetGroup* pGroupA,
                                          dwWidgetGroup* pGroupB, dwWidgetGroup* pGroupC,
                                          dwWidgetGroup* pGroupD)
{
    (void)pConf; (void)pGroupA; (void)pGroupB; (void)pGroupC; (void)pGroupD;
    dwGuiReference_StubReport("BuildDynamicControls");
    return 1;
}

// @42f800 (dwGuiReference_PlayIntroVideo) — LOUD-stub. The intro-video state
// machine: plays RefIntro.san (first visit) / RefRoom.san (returning) / RStart
// .san, gated by the reference tutorial prompt, via jkSmack + the segment stack.
// Blocked on jkSmack + the base video-state field; recipe at binary @42f800.
int dwGuiReference::PlayIntroVideo()
{
    dwGuiReference_StubReport("PlayIntroVideo");
    return 1;
}

// ---- internet-launch gates (Win32 in the binary; portable here) -----------------

// @42b7e0 (dwGuiReference_HasBrowser) — the binary probes the registry for the
// configured BROWSER_PATH key (RegOpenKeyExA under HKEY_CLASSES_ROOT).
// Note: no portable registry; report "browser available" so the LAUNCH_URL flow
// is not falsely blocked. TODO(dw-decomp): route through a portable URL opener.
int dwGuiReference::HasBrowser()
{
    return 1;
}

// @42b830 (dwGuiReference_CheckInternet) — the binary opens a Winsock socket to
// probe connectivity (Ordinal_* = WS2_32 by-ordinal imports).
// Note: no portable connectivity probe; report "connected".
int dwGuiReference::CheckInternet()
{
    this->bInternetOk = 1;
    return 1;
}

// @42b920 (dwGuiReference_ReadBrowserRegistry) — the binary reads the parental
// "INTERNET=ENABLED" lockout value from the registry (RegQueryValueExA under
// HKEY_LOCAL_MACHINE\<REG_PATH>).
// Note: no portable registry; report "not locked out".
int dwGuiReference::ReadBrowserRegistry()
{
    return 1;
}
