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
#include "Dw/dwGuiScreen.h"    // dwGuiScreen_CaptureShadedScreen
#include "Dw/dwGuiFind.h"      // dwGuiFind_New (topic-search spawn)
#include "Dw/dwSound.h"        // dwSound_SetMusic/StopAll/PauseAll/ResumeAll
#include "Dw/dwCursor.h"       // dwCursor_SetCursor/Redraw
#include "Dw/dwSegment.h"      // dwSegment_RequestAdvance/InterruptWith/pActive
#include "Dw/dwWidget.h"       // dwWidget_DispatchMsg, dwWidgetMsg
#include "Dw/dwGuiOptions.h"   // dwMovie_OpenSeg (.san intro-video segments)
#include "Dw/dwInits.h"        // inits_EnumFilesByExt
#include "Dw/dwPlayer.h"       // dwPlayer_statsFlags

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

// @0x53d968 — the reference-room "current topic" .plr TOPIC file (a dwString).
// In the Ghidra decompile its pBuffer@0x53d970 appears as DAT_0053d970.
extern dwString dwCore_currentRefFile;

// --- content-group list helpers ---------------------------------------------
// The binary rebuilds reference pages by (a) deleting every widget in a content
// group and (b) re-appending freshly-built controls. Both the inlined clear
// loops and the shared dwWcMaterials_ClearItems COMDAT do: unlink+free each
// node (dwList_UnlinkFreeNode) then `delete` the child (vtbl +0x00, flag 1).

static void dwGuiReference_ClearGroup(dwWidgetGroup* pGroup)
{
    if (pGroup == NULL)
        return;
    dwList* pChildren = &pGroup->children;
    dwListNode* pSent = pChildren->pSentinel;
    dwListNode* pNode = pSent->pNext;
    while (pNode != pSent)
    {
        dwWidget* pChild = (dwWidget*)pNode->pData;
        dwListNode* pNext = pNode->pNext;
        pChildren->UnlinkFreeNode(pNode);
        if (pChild)
            delete pChild;
        pNode = pNext;
    }
}

// Append a built control to a group. The binary appends at the tail for most
// keywords (InsertAfter(pSentinel->pPrev)) and at the head only for
// BUTTONHELPRECT / the OnActivate content sub-groups.
static void dwGuiReference_AppendBack(dwWidgetGroup* pGroup, dwWidget* pChild)
{
    pGroup->children.InsertAfter(pGroup->children.pSentinel->pPrev, pChild);
}
static void dwGuiReference_AppendFront(dwWidgetGroup* pGroup, dwWidget* pChild)
{
    pGroup->children.InsertAfter(pGroup->children.pSentinel, pChild);
}

// Post a widget message to the active screen (dwWidget_DispatchMsg with a
// stack {code, pSender, param, pTarget} record and no override target).
static void dwGuiReference_PostMsg(uint32_t code, void* pSender)
{
    dwWidgetMsg msg;
    msg.code = (int32_t)code;
    msg.pSender = pSender;
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);
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
// Clear a set of content groups (helper for the page-navigation cases).
static void dwGuiReference_ClearGroups(dwWidgetGroup* a, dwWidgetGroup* b, dwWidgetGroup* c,
                                       dwWidgetGroup* d, dwWidgetGroup* e)
{
    dwGuiReference_ClearGroup(a);
    dwGuiReference_ClearGroup(b);
    dwGuiReference_ClearGroup(c);
    dwGuiReference_ClearGroup(d);
    dwGuiReference_ClearGroup(e);
}

// @42ba30 (dwGuiReference_OnMessage, vtbl +0x1c). Topic navigation + the
// reference-room command handlers. Field mapping was pinned from the
// disassembly (direct this-relative offsets): the 5 content groups
// (pContentGroup/pChildEc/pChildF0/pChildF4/pChildF8), menuMode (@0x10c),
// bReloadPending (@0xd8), bReloadMaterials (@0x108), byte120 (@0x120), the
// currentFile/scratch114 dwStrings, and the pStringTable base member. DAT_0053d970
// is dwCore_currentRefFile.pBuffer.
int dwGuiReference::OnMessage(dwWidgetMsg* pMsg)
{
    uint32_t code = (uint32_t)pMsg->code;
    dwSegment* pSpawned = NULL;

    if (code < 0x1b59)
    {
        if (code == 7000)
        {
            // Select a new (non-materials) topic; Update rebuilds the page.
            char* pFile = (char*)pMsg->pSender;
            if (this->pContentGroup != NULL &&
                !dwString_Equals(this->scratch114.pBuffer, dwCore_currentRefFile.pBuffer) &&
                this->byte120 == 0)
            {
                this->scratch114.Assign(dwCore_currentRefFile.pBuffer, 0);
            }
            this->currentFile.Assign(pFile, 0);
            char* pName = pFile;
            dwString_FindFilename(&pName);
            dwCore_currentRefFile.Assign(pName, 0);
            this->bReloadPending = 1;
            if (this->byte120)
                this->byte120 = 0;
        }
        else if (code == 0x96)
        {
            dwSegment_RequestAdvance();
        }
    }
    else
    {
        switch (code)
        {
        case 0x1b5a:
        {
            // Refresh the current cached topic (re-post 0x1b5c/0x1b60).
            if (this->pContentGroup != NULL)
            {
                dwStringTable* pTable = new dwStringTable(this->scratch114.pBuffer);
                uint32_t next = (pTable && pTable->Find("FREQUENCY")) ? 0x1b60 : 0x1b5c;
                dwGuiReference_PostMsg(next, this->scratch114.pBuffer);
                if (pTable)
                    delete pTable;
            }
            break;
        }
        case 0x1b5b:
            // Spawn the topic-search ("Find") screen over a shaded snapshot.
            this->pSnapshotImage = dwGuiScreen_CaptureShadedScreen();
            this->byte120 = 1;
            this->scratch114.Assign(dwCore_currentRefFile.pBuffer, 0);
            dwSound_StopAll();
            pSpawned = dwGuiFind_New(this->pSnapshotImage);
            break;
        case 0x1b5c:
        {
            // Show a topic: build ObsMenuSelect, falling back to InqMenuSelect.
            dwCursor_SetCursor(4);
            dwCursor_Redraw();
            char* pTopic = (char*)pMsg->pSender;
            char localName[128];
            localName[0] = '\0';
            if (pTopic)
            {
                _strncpy(localName, pTopic, sizeof(localName) - 1);
                localName[sizeof(localName) - 1] = '\0';
            }
            if (this->pStringTable)
                delete this->pStringTable;
            this->pStringTable = new dwStringTable(pTopic);
            if (!dwString_Equals(this->scratch114.pBuffer, dwCore_currentRefFile.pBuffer) &&
                dwCore_currentRefFile.length != 0 &&
                !dwString_Equals(dwCore_currentRefFile.pBuffer, localName) &&
                this->byte120 == 0)
            {
                this->scratch114.Assign(dwCore_currentRefFile.pBuffer, 0);
            }
            dwCore_currentRefFile.Assign(localName, 0);
            dwGuiReference_ClearGroups(this->pContentGroup, this->pChildEc, this->pChildF0,
                                       this->pChildF4, this->pChildF8);
            this->menuMode = 4;
            char ok = this->BuildDynamicControls("ObsMenuSelect.ifc", this->pContentGroup,
                                                 this->pChildEc, this->pChildF0,
                                                 this->pChildF4, this->pChildF8);
            if (ok == 0)
            {
                dwGuiReference_ClearGroups(this->pContentGroup, this->pChildEc, this->pChildF0,
                                           this->pChildF4, this->pChildF8);
                this->menuMode = 3;
                this->BuildDynamicControls("InqMenuSelect.ifc", this->pContentGroup,
                                           this->pChildEc, this->pChildF0,
                                           this->pChildF4, this->pChildF8);
            }
            dwCursor_SetCursor(1);
            dwCursor_Redraw();
            if (this->byte120)
                this->byte120 = 0;
            break;
        }
        case 0x1b5d:
            // Observation sub-page.
            if (this->menuMode != 1 && this->menuMode != 4)
            {
                dwCursor_SetCursor(4);
                dwCursor_Redraw();
                this->menuMode = 1;
                dwGuiReference_ClearGroup(this->pContentGroup);
                dwGuiReference_ClearGroup(this->pChildF4);
                dwGuiReference_ClearGroup(this->pChildF0);
                dwGuiReference_ClearGroup(this->pChildF8);
                this->BuildDynamicControls("Observation.ifc", this->pContentGroup,
                                           this->pChildEc, this->pChildF0, NULL, this->pChildF8);
                dwCursor_SetCursor(1);
                dwCursor_Redraw();
            }
            break;
        case 0x1b5e:
            // Earthquest sub-page (single content group).
            if (this->menuMode != 2)
            {
                dwCursor_SetCursor(4);
                this->menuMode = 2;
                dwGuiReference_ClearGroup(this->pContentGroup);
                dwGuiReference_ClearGroup(this->pChildF0);
                dwGuiReference_ClearGroup(this->pChildF4);
                dwGuiReference_ClearGroup(this->pChildF8);
                this->BuildDynamicControls("Earthquest.ifc", this->pContentGroup,
                                           NULL, NULL, NULL, NULL);
                dwCursor_SetCursor(1);
            }
            break;
        case 0x1b5f:
            // Definition sub-page.
            if (this->menuMode != 0 && this->menuMode != 3)
            {
                dwCursor_SetCursor(4);
                dwCursor_Redraw();
                this->menuMode = 0;
                dwGuiReference_ClearGroup(this->pContentGroup);
                dwGuiReference_ClearGroup(this->pChildF4);
                dwGuiReference_ClearGroup(this->pChildF0);
                dwGuiReference_ClearGroup(this->pChildF8);
                this->BuildDynamicControls("Definition.ifc", this->pContentGroup,
                                           this->pChildEc, this->pChildF0, NULL, this->pChildF8);
                dwCursor_SetCursor(1);
                dwCursor_Redraw();
            }
            break;
        case 0x1b60:
        {
            // Select a materials topic; Update rebuilds the Materials page.
            char* pTopic = (char*)pMsg->pSender;
            char localName[128];
            localName[0] = '\0';
            if (pTopic)
            {
                _strncpy(localName, pTopic, sizeof(localName) - 1);
                localName[sizeof(localName) - 1] = '\0';
            }
            if (this->pStringTable)
                delete this->pStringTable;
            this->pStringTable = new dwStringTable(pTopic);
            if (dwString_Equals(this->scratch114.pBuffer, dwCore_currentRefFile.pBuffer) ||
                dwCore_currentRefFile.length == 0)
            {
                if (this->byte120)
                    this->byte120 = 0;
            }
            else if (this->byte120 == 0)
            {
                this->scratch114.Assign(dwCore_currentRefFile.pBuffer, 0);
            }
            else
            {
                this->byte120 = 0;
            }
            dwCore_currentRefFile.Assign(localName, 0);
            this->bReloadMaterials = 1;
            break;
        }
        case 0x1b61:
            // LAUNCH_URL: the parental-lockout / browser gates + a confirm dialog.
            // The binary then WinExec()s the localized URL; there is no portable
            // browser launcher here (mirrors HasBrowser/CheckInternet stubs), so
            // the launch itself is a no-op with a note.
            if (this->ReadBrowserRegistry() == 0)
            {
                dwGuiDialog_RunModal("gmessage", "DLG_INETLOCKOUT");
            }
            else if (this->HasBrowser() == 0)
            {
                dwGuiDialog_RunModal("gmessage", "DLG_NOBROWSER");
            }
            else if (dwGuiDialog_RunModal("gyesno", "DLG_INETCONNECT") == 5000)
            {
                dwSound_PauseAll();
                dwSound_SetMusic(0, 1);
                char okNet = (char)this->CheckInternet();
                dwSound_ResumeAll();
                dwSound_SetMusic(this->musicName.pBuffer, 1);
                if (okNet)
                {
                    stdPlatform_Printf("TODO(dw-decomp): dwGuiReference LAUNCH_URL '%s' "
                                       "(no portable browser launcher)\n",
                                       dwGuiScreen_LocalizeString((char*)"LAUNCH_URL", NULL));
                }
                else
                {
                    dwGuiDialog_RunModal("gmessage", "DLG_NODIALUP");
                }
            }
            break;
        default:
            break;
        }
    }

    // If a sub-screen was spawned (0x1b5b), broadcast the screen-switch and
    // interrupt into it.
    if (pSpawned)
    {
        dwGuiReference_PostMsg(0x7532, NULL);
        dwSegment_InterruptWith(dwSegment_pActive, pSpawned);
    }
    return dwGuiScreen::OnMessage(pMsg);
}

// @42ed50 (dwGuiReference_Update, vtbl +0x14) — LOUD-stub. Rebuilds the current
// page's dynamic controls when bReloadPending/bReloadMaterials is set (opens the
// topic .ifc, clears the 5 content groups, re-runs BuildDynamicControls), then
// forwards the tick. Blocked on the same overlay ambiguity; recipe at @42ed50.
void dwGuiReference::Update(float dt)
{
    if (this->bReloadPending == 0)
    {
        if (this->bReloadMaterials != 0)
        {
            // A material property changed: rebuild only the Materials page.
            dwCursor_SetCursor(4);
            dwCursor_Redraw();
            dwGuiReference_ClearGroup(this->pChildEc);
            dwGuiReference_ClearGroup(this->pChildF0);
            dwGuiReference_ClearGroup(this->pChildF4);
            dwGuiReference_ClearGroup(this->pContentGroup);
            dwGuiReference_ClearGroup(this->pChildF8);
            this->menuMode = 5;
            this->BuildDynamicControls("Materials.ifc", this->pContentGroup,
                                       this->pChildEc, this->pChildF0, NULL, NULL);
            this->bReloadMaterials = 0;
            dwCursor_SetCursor(1);
            dwCursor_Redraw();
        }
    }
    else
    {
        // A new topic was selected (7000): rebuild the whole page from its file.
        dwCursor_SetCursor(4);
        dwCursor_Redraw();
        if (this->pStringTable)
            delete this->pStringTable;
        this->pStringTable = new dwStringTable(this->currentFile.pBuffer);

        dwGuiReference_ClearGroup(this->pContentGroup);
        dwGuiReference_ClearGroup(this->pChildEc);
        dwGuiReference_ClearGroup(this->pChildF0);
        dwGuiReference_ClearGroup(this->pChildF4);
        dwGuiReference_ClearGroup(this->pChildF8);

        // Read the topic's TOPIC_CATEGORY to pick the layout.
        dwConfFile conf;
        dwConfFile_Open(&conf, this->currentFile.pBuffer);
        char* pCategory = NULL;
        while (conf.bEof == 0)
        {
            dwConfFile_ReadLine(&conf);
            char* pTok = dwConfFile_NextToken(&conf);
            if (dwString_Equals(pTok, "TOPIC_CATEGORY"))
            {
                pCategory = dwConfFile_NextToken(&conf);
                break;
            }
        }

        // (The binary also forces Materials when the file's extension matches a
        //  sentinel; the TOPIC_CATEGORY test covers the normal case.)
        if (dwString_Equals(pCategory, "Materials"))
        {
            this->menuMode = 5;
            this->BuildDynamicControls("Materials.ifc", this->pContentGroup,
                                       this->pChildEc, this->pChildF0, NULL, NULL);
        }
        else
        {
            this->menuMode = 4;
            char ok = this->BuildDynamicControls("ObsMenuSelect.ifc", this->pContentGroup,
                                                 this->pChildEc, this->pChildF0,
                                                 this->pChildF8, NULL);
            if (ok == 0)
            {
                // ObsMenuSelect hit its STILL_FRAME early-out: use the inquiry menu.
                dwGuiReference_ClearGroup(this->pContentGroup);
                dwGuiReference_ClearGroup(this->pChildEc);
                dwGuiReference_ClearGroup(this->pChildF0);
                dwGuiReference_ClearGroup(this->pChildF4);
                dwGuiReference_ClearGroup(this->pChildF8);
                this->menuMode = 3;
                this->BuildDynamicControls("InqMenuSelect.ifc", this->pContentGroup,
                                           this->pChildEc, this->pChildF0,
                                           this->pChildF4, this->pChildF8);
            }
        }

        this->bReloadPending = 0;
        dwCursor_SetCursor(1);
        dwCursor_Redraw();
        dwConfFile_Close(&conf);
    }

    // Tick the base controls group (which owns the content sub-groups).
    dwGuiScreen::Update(dt);
}

// @42b300 (dwGuiReference_OnActivate, scn Activate) — LOUD-stub. Base Activate,
// then (first time) allocate the 5 content widget-groups + append them to the
// controls list, load the initial topic page (TPC enumeration + string table +
// BuildDynamicControls). Blocked on the overlay ambiguity; recipe at @42b300.
int dwGuiReference::Activate()
{
    int r = dwGuiScreen::Activate();
    dwPlayer_statsFlags |= 0x40000000;

    // First activation: build the 5 content sub-groups and link them into the
    // embedded `controls` list (head-inserted, matching the binary's
    // dwRefGraph_ListAppend). They then tick/draw via the base controls group.
    if (r != 0 && this->pContentGroup == NULL)
    {
        this->pContentGroup = new dwWidgetGroup();
        dwGuiReference_AppendFront(&this->controls, this->pContentGroup);
        this->pChildEc = new dwWidgetGroup();
        dwGuiReference_AppendFront(&this->controls, this->pChildEc);
        this->pChildF0 = new dwWidgetGroup();
        dwGuiReference_AppendFront(&this->controls, this->pChildF0);
        this->pChildF4 = new dwWidgetGroup();
        dwGuiReference_AppendFront(&this->controls, this->pChildF4);
        this->pChildF8 = new dwWidgetGroup();
        dwGuiReference_AppendFront(&this->controls, this->pChildF8);
    }

    // Load the initial topic page. Post 0x1b5c (normal topic) or 0x1b60
    // (materials topic, has a FREQUENCY entry) to ourselves; Update/OnMessage
    // do the actual page build.
    dwStringTable* pTable = NULL;
    uint32_t msgCode = 0x1b5c;
    char* pTopicName = NULL;

    if (this->path.length == 0)
    {
        // No ctor sub-path: use the player's current topic, else enumerate the
        // TPC topic files and open the first one.
        // (The binary also treats a sentinel-valued current file as "none";
        //  the empty-string check below covers the common case.)
        if (dwCore_currentRefFile.length == 0 || dwCore_currentRefFile.pBuffer == NULL)
        {
            inits_EnumFilesByExt("TPC", &this->pTopicList);
            dwListNode* pFirst = this->pTopicList.pSentinel->pNext;
            if (this->scratch114.length == 0 || this->byte120 == 0)
                this->scratch114.Assign(dwCore_currentRefFile.pBuffer, 0);
            pTopicName = (pFirst != this->pTopicList.pSentinel && pFirst->pData)
                             ? ((dwString*)pFirst->pData)->pBuffer
                             : NULL;
            pTable = new dwStringTable(pTopicName);
            msgCode = (pTable && pTable->Find("FREQUENCY")) ? 0x1b60 : 0x1b5c;
        }
        else
        {
            pTopicName = dwCore_currentRefFile.pBuffer;
            if (this->scratch114.length == 0 || this->byte120 == 0)
                this->scratch114.Assign(dwCore_currentRefFile.pBuffer, 0);
            pTable = new dwStringTable(pTopicName);
            if (pTable && pTable->Find("FREQUENCY")) { this->byte120 = 1; msgCode = 0x1b60; }
            else msgCode = 0x1b5c;
        }
    }
    else
    {
        // A ctor sub-path was supplied: open it directly.
        pTopicName = this->path.pBuffer;
        if (!dwString_Equals(this->scratch114.pBuffer, this->path.pBuffer))
        {
            this->scratch114.Free();
            this->scratch114.Assign(this->path.pBuffer, 0);
        }
        pTable = new dwStringTable(pTopicName);
        msgCode = (pTable && pTable->Find("FREQUENCY")) ? 0x1b60 : 0x1b5c;
    }

    dwGuiReference_PostMsg(msgCode, pTopicName);
    if (pTable)
        delete pTable;

    // Enter the reference tutorial the first time (statsFlags bit 0x08000000).
    if (r != 0 && (dwPlayer_statsFlags & 0x08000000))
    {
        dwPlayer_statsFlags = (dwPlayer_statsFlags & ~0x08000000u) | 0x40000000;
        dwGuiReference_PostMsg(0x792a, NULL);
    }
    return r;
}

// @42ae40 (dwGuiReference_BuildDynamicControls) — LOUD-stub. Parses a topic sub-
// section (DYNAMIC_CONTROL/NUMERATED_CONTROLS/NUMERATED_HEADER_CONTROLS/
// STRIPTIMER/ICON_ANIM_PLAY/BUTTONHELPRECT/TEXTPOPUP), building each control via
// the virtual CreateControl and prepending it into the target group. Recipe at
// binary @42ae40. Returns 1 (the binary's success path).
char dwGuiReference::BuildDynamicControls(const char* pConfName, dwWidgetGroup* pGroupDefault,
                                          dwWidgetGroup* pGroupHeader, dwWidgetGroup* pGroupDynamic,
                                          dwWidgetGroup* pGroupUnused4, dwWidgetGroup* pGroupUnused5)
{
    (void)pGroupUnused4;
    (void)pGroupUnused5;
    if (pGroupDefault == NULL)
        pGroupDefault = &this->controls; // param_2 defaults to the controls group
    if (pConfName == NULL)
        return 1;

    dwConfFile conf;
    dwConfFile_Open(&conf, pConfName);
    while (conf.bEof == 0)
    {
        dwConfFile_ReadLine(&conf);
        char* pKeyword = dwConfFile_NextToken(&conf);

        // Each keyword's guard is ANDed with the match: a keyword whose target
        // group is NULL falls through to the default handler (append to
        // pGroupDefault), exactly as the binary's nested if/else chain does.
        if (dwString_Equals(pKeyword, "DYNAMIC_CONTROL") && pGroupDynamic != NULL)
        {
            char* pSub = dwGuiScreen_LocalizeString(dwConfFile_NextToken(&conf), this->pStringTable);
            if (dwString_Equals(pSub, "STILL_FRAME") && this->bSuppressStill && this->menuMode == 4)
            {
                this->bSuppressStill = 0;
                this->Invalidate();
                dwConfFile_Close(&conf);
                return 0; // early-out drives the InqMenuSelect fallback
            }
            dwWidget* pCtl = this->CreateControl(pSub, &conf);
            if (pCtl)
                dwGuiReference_AppendBack(pGroupDynamic, pCtl);
        }
        else if (dwString_Equals(pKeyword, "NUMERATED_HEADER_CONTROLS") && pGroupHeader != NULL)
        {
            int n = atoi(dwGuiScreen_LocalizeString(conf.pCursor, this->pStringTable));
            int pad = 2 - n;
            while (n != 0 && conf.bEof == 0)
            {
                n--;
                dwConfFile_ReadLine(&conf);
                dwWidget* pCtl = this->CreateControl(dwConfFile_NextToken(&conf), &conf);
                if (pCtl)
                    dwGuiReference_AppendBack(pGroupHeader, pCtl);
            }
            for (; pad > 0; pad--)
                dwConfFile_ReadLine(&conf);
        }
        else if (dwString_Equals(pKeyword, "NUMERATED_CONTROLS") && this->pChildF8 != NULL)
        {
            int n = atoi(dwGuiScreen_LocalizeString(conf.pCursor, this->pStringTable));
            int pad = 5 - n;
            while (n != 0 && conf.bEof == 0)
            {
                n--;
                dwConfFile_ReadLine(&conf);
                dwWidget* pCtl = this->CreateControl(dwConfFile_NextToken(&conf), &conf);
                if (pCtl)
                    dwGuiReference_AppendBack(this->pChildF8, pCtl);
            }
            for (; pad > 0; pad--)
                dwConfFile_ReadLine(&conf);
        }
        else if ((dwString_Equals(pKeyword, "STRIPTIMER") || dwString_Equals(pKeyword, "ICON_ANIM_PLAY"))
                 && pGroupHeader != NULL)
        {
            dwWidget* pCtl = this->CreateControl(pKeyword, &conf);
            if (pCtl)
                dwGuiReference_AppendBack(pGroupHeader, pCtl);
        }
        else if (dwString_Equals(pKeyword, "BUTTONHELPRECT") && pGroupHeader != NULL)
        {
            dwWidget* pCtl = this->CreateControl(pKeyword, &conf);
            if (pCtl)
                dwGuiReference_AppendFront(pGroupHeader, pCtl); // head insert
        }
        else if (dwString_Equals(pKeyword, "TEXTPOPUP"))
        {
            dwWidget* pCtl = this->CreateControl(pKeyword, &conf);
            if (pCtl)
                dwGuiReference_AppendBack(this->pContentGroup, pCtl);
        }
        else
        {
            dwWidget* pCtl = this->CreateControl(pKeyword, &conf);
            if (pCtl)
                dwGuiReference_AppendBack(pGroupDefault, pCtl);
        }
    }
    this->Invalidate();
    dwConfFile_Close(&conf);
    return 1;
}

// @42f800 (dwGuiReference_PlayIntroVideo) — the intro-video state machine.
// NOTE: in the binary this is the Activate of a SEPARATE tiny dwSegment
// subclass (new(0x18){ dwSegment_Ctor; state@0x14=0; vptr=0x51f238 }), spawned
// by dwGuiScreen msg 0x6a — NOT a dwGuiReference method; its `state` lives on
// that segment. Full state machine (decoded, kept here for the recipe):
//   state 0: statsFlags&0x40000000 ? OpenSeg("RefRoom.san")/state=1
//                                   : OpenSeg("RefIntro.san")/state=3;  InterruptWith
//   state 1: OpenSeg("RStart.san")/state=2;  InterruptWith
//   state 3: RunModal("tutoryn_ref","DLG_ASKINDEXTUT")==5000 -> statsFlags|=0x48000000;
//            OpenSeg("RStart.san")/state=2;  InterruptWith
//   state 2: PushAndAdvance(new dwGuiReference(0))
// TODO(dw-decomp): add a dwGuiRefIntroSeg (dwSegment subclass) whose Activate is
// this body, and wire dwGuiScreen msg 0x6a to spawn it. Reached only via 0x6a.
int dwGuiReference::PlayIntroVideo()
{
    dwGuiReference_StubReport("PlayIntroVideo (needs dwGuiRefIntroSeg wrapper; msg 0x6a)");
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
