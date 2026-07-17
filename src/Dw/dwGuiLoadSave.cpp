// dwGuiLoadSave — 'lsdroid' droid save/load screen (dwGuiScreen subclass).
// DroidWorks.exe 0x40ba90-0x40ce9f, vtbls @0x51e930 (primary) / 0x51e918
// (segment). See Dw/dwGuiLoadSave.h for the class notes.

#include "Dw/dwGuiLoadSave.h"

#include "Dw/dwSegment.h"    // dwSegment_RequestAdvance
#include "Dw/dwSound.h"      // dwSound_* (name-keyed C API)
#include "Dw/dwString.h"     // dwString + dwString_* free functions
#include "Dw/dwList.h"
#include "Dw/dwWidgetGroup.h"
#include "Dw/dwInits.h"      // inits_EnumFilesByExt / ResolveAndOpen / DeleteFile
#include "Dw/dwPart.h"       // dwPartNode (workspace node dtor)

#include "stdPlatform.h"     // HostServices

#include <ctype.h>

// The DW host-services pointer (dwMain.c; binary global dwHS @0x6b6258).
extern "C" HostServices* dwMain_pHS;

// ---- cross-unit symbols -----------------------------------------------------

// The global assembled-droid workspace (owned by the dw core unit, P7).
extern "C" dwListNode* dwCore_pWorkspaceNodes; // @0x53d984 (dwPartNode list sentinel)
extern "C" dwString dwCore_workspaceName;      // @0x53d978 (edited droid name)

// The game-wide modal-dialog runner (dwGuiMission unit).
extern "C" int dwGuiDialog_RunModal(const char* pConfName, const char* pMsgKey);

// TODO(dw-decomp): provided by dwHelp (P6 wave 2b agent 3). HELP builds an
// animated help-droid speech control; for dwGuiLoadSave the speaker code is
// 0x68 (LSCP). Binary: new(0x5c) dwHelp_Ctor(&rect, /*pParent*/0, 0x68).
// Loud-stubbed until dwHelp lands.

// ---- dwGuiLoadSave ----------------------------------------------------------

// @40ba90 (dwGuiLoadSave_Ctor)
dwGuiLoadSave::dwGuiLoadSave(dwImage* pBgSnapshot)
    : dwGuiScreen("lsdroid", pBgSnapshot)
{
    this->pSnapshot = pBgSnapshot;
    this->bEditNameMode = 0;
    this->pDroidBoxImage = NULL;
    this->pNameEntry = NULL;
    this->pFileScrollBar = NULL;
    this->pFileScrollBox = NULL;
    this->pScrollUpButton = NULL;
    this->pScrollDownButton = NULL;
    this->pButtonLoad = NULL;
    this->pButtonSave = NULL;
    this->pButtonRecycle = NULL;
    this->slideTimer = 0.0f;
    this->slideDir = 0.0f;
}

// @40bb30 (dwGuiLoadSave_Dtor)
dwGuiLoadSave::~dwGuiLoadSave()
{
    this->FreeImages();

    // The DROIDBOX image is added to `controls` by LoadControls and
    // dynamically detached/re-attached during the slide, so it may or may not
    // currently be in the child list. Detach it (so the group dtor won't
    // touch it) and delete it here.
    if (this->pDroidBoxImage != NULL)
    {
        dwListNode* pSent = this->controls.children.pSentinel;
        for (dwListNode* pNode = pSent->pNext; pNode != pSent; pNode = pNode->pNext)
        {
            if (pNode->pData == this->pDroidBoxImage)
            {
                this->controls.children.UnlinkFreeNode(pNode);
                break;
            }
        }
        delete this->pDroidBoxImage; // scalar-deleting dtor
    }
    // (base ~dwGuiScreen tears the rest down: the `controls` group dtor
    //  deletes the remaining child controls)
}

// vtbl(scn) +0x00 @40beb0 (dwGuiLoadSave_OnActivate)
int dwGuiLoadSave::Activate()
{
    // Empty the controls group so the base Activate rebuilds it (re-listing
    // *.drd, so a freshly-saved droid shows up). dwGuiScreen::Activate only
    // (re-)runs LoadControls when controls.children is empty, so this delete
    // is what forces the refresh. Each per-screen control pointer below
    // dangles until CreateControl reassigns it during the rebuild.
    {
        dwListNode* pSent = this->controls.children.pSentinel;
        dwListNode* pNode = pSent->pNext;
        while (pNode != pSent)
        {
            dwWidget* pChild = (dwWidget*)pNode->pData;
            dwListNode* pNext = pNode->pNext;
            this->controls.children.UnlinkFreeNode(pNode);
            if (pChild != NULL)
                delete pChild; // scalar-deleting dtor
            pNode = pNext;
        }
    }

    int ret = dwGuiScreen::Activate();
    if (ret != 0)
    {
        dwSound_PlayLooping("WLSPanelAmb.WAV");
        dwSound_SetSampleVolume("WLSPanelAmb.WAV", 0.05f, 0.0f);
        dwSound_SetSampleVolume("WLSPanelAmb.WAV", 1.0f, (float)(int)this->bottom / 320.0f);

        // Move the controls group off the bottom, then arm the slide-in.
        this->controls.Move(0, this->bottom);
        this->slideTimer = 0.0f;
        this->slideDir = -320.0f;
        this->bEditNameMode = 1;
        this->RefreshWidgets();

        // Load mode (name field disabled) with a live selection: draw the
        // list focus border. (The binary also dispatches a hover message and
        // snapshots the segment clock here; both were EH-frame-corrupted in
        // the decompile and are omitted — they don't affect the slide.)
        if (this->bEditNameMode == 0 && this->pFileScrollBox != NULL
            && this->pFileScrollBox->pSelectedItem != NULL)
        {
            this->pFileScrollBox->bDrawBorder = 1;
        }
    }
    return ret;
}

// vtbl(scn) +0x04 @40bea0 (dwGuiLoadSave_OnDeactivate)
void dwGuiLoadSave::Deactivate()
{
    if (dwSound_pManager)
        dwSound_pManager->FreeAllSamples();
}

// vtbl +0x10 @40c110 (dwGuiLoadSave_OnKey)
int dwGuiLoadSave::OnKey(int code, int repeat)
{
    if ((char)code == '\x1b' && repeat != 0
        && (this->slideDir < 0.0f || this->slideDir > 0.0f))
    {
        // fast-forward the current slide to completion
        this->slideTimer = 10.0f;
    }
    dwGuiScreen::OnKey(code, repeat);
    return 0;
}

// vtbl +0x08 @40c160 (dwGuiLoadSave_OnMouseDown)
int dwGuiLoadSave::OnMouseDown(int16_t x, int16_t y)
{
    // Swallow clicks while the panel is sliding.
    if (this->slideDir == 0.0f)
        return dwGuiScreen::OnMouseDown(x, y);
    return 0;
}

// vtbl +0x14 @40bc10 (dwGuiLoadSave_Update)
void dwGuiLoadSave::Update(float dt)
{
    if (this->slideDir != 0.0f)
    {
        this->slideTimer += dt;
        int pos = (int)(this->slideDir * this->slideTimer);
        int16_t screenH = this->bottom;

        if (this->slideDir >= 0.0f)
        {
            // slide out: descend until fully off the bottom, then advance
            if (screenH <= (int16_t)pos)
            {
                this->slideDir = 0.0f;
                dwSegment_RequestAdvance();
                pos = screenH;
            }
        }
        else
        {
            // slide in: rise from the bottom to the top
            pos = pos + screenH;
            if ((int16_t)pos < 1)
            {
                this->slideDir = 0.0f;
                if (this->bEditNameMode != 0)
                    this->pNameEntry->BeginEdit();

                // Detach the DROIDBOX snapshot from `controls` (it was only
                // shown during the transition).
                if (this->pDroidBoxImage != NULL)
                {
                    dwListNode* pSent = this->controls.children.pSentinel;
                    for (dwListNode* pNode = pSent->pNext; pNode != pSent; pNode = pNode->pNext)
                    {
                        if (pNode->pData == this->pDroidBoxImage)
                        {
                            this->controls.children.UnlinkFreeNode(pNode);
                            break;
                        }
                    }
                }
                pos = 0;
                this->Invalidate();
            }
        }

        this->controls.Move((int16_t)(-this->controls.left), (int16_t)((int16_t)pos - this->controls.top));
        this->Invalidate();
    }
    this->controls.Update(dt);
}

// vtbl +0x1c @40c190 (dwGuiLoadSave_OnMessage)
int dwGuiLoadSave::OnMessage(dwWidgetMsg* pMsg)
{
    switch (pMsg->code)
    {
    case 0xfa3: // file selected
        this->bEditNameMode = (pMsg->param == 0);
        this->RefreshWidgets();
        if (this->slideDir == 0.0f)
        {
            dwSound_PlayRestart("WSelectDroid1.WAV");
            if (this->bEditNameMode == 0)
                dwSound_PlayLooping("WSelectDroid2.WAV");
        }
        break;

    case 0xfa4: // RECYCLE
        if (dwGuiDialog_RunModal("gyesno", "DLG_RECYCLE") == 5000)
        {
            dwString resolved;
            stdFile_t file = inits_ResolveAndOpen(
                this->pFileScrollBox->pSelectedItem->filename.pBuffer, "rb", &resolved);
            if (file != 0)
            {
                dwMain_pHS->fileClose(file);
                inits_DeleteFile(resolved.pBuffer);
                this->pFileScrollBox->RemoveSelected();
                this->RefreshWidgets();
            }
            resolved.Free();
        }
        break;

    case 0xfa5: // SAVE
        if (dwCore_pWorkspaceNodes != dwCore_pWorkspaceNodes->pNext)
        {
            bool bProceed = true;
            dwString path;

            // trim leading whitespace off the droid name
            dwString tmp;
            tmp.AssignString(&dwCore_workspaceName);
            if (tmp.pBuffer != NULL)
            {
                char* p = tmp.pBuffer;
                while (*p != '\0' && isspace((unsigned char)*p))
                    p++;
                dwCore_workspaceName.AssignCStr(p);
            }
            // trim trailing whitespace
            if (dwCore_workspaceName.length != 0)
            {
                tmp.AssignString(&dwCore_workspaceName);
                char* pBase = dwCore_workspaceName.pBuffer;
                char* pEnd = dwCore_workspaceName.pBuffer + (dwCore_workspaceName.length - 1);
                while (isspace((unsigned char)*pEnd))
                    pEnd--;
                dwCore_workspaceName.Assign(tmp.pBuffer, (uint32_t)(pEnd + 1 - pBase));
            }

            path.AssignString(&dwCore_workspaceName);
            if (path.length == 0)
            {
                dwGuiDialog_RunModal("gmessage", "DLG_MUSTNAME");
                this->pNameEntry->BeginEdit();
            }
            else
            {
                path.Append(".drd", 4);
                if (this->pFileScrollBox->ContainsFile(&path))
                    bProceed = (dwGuiDialog_RunModal("gyesno", "DLG_REPLACE") == 5000);
                if (bProceed)
                {
                    dwGuiWidgets_SaveDroidToFile(
                        path.pBuffer, &dwCore_workspaceName, (dwList*)&dwCore_pWorkspaceNodes);
                    this->StartSlideOut();
                }
            }
            path.Free();
            tmp.Free();
        }
        break;

    case 0xfa6: // LOAD
    {
        // destroy the current workspace droid (part nodes + list nodes)
        for (dwListNode* pNode = dwCore_pWorkspaceNodes->pNext;
             pNode != dwCore_pWorkspaceNodes; pNode = pNode->pNext)
        {
            dwPartNode* pPart = (dwPartNode*)pNode->pData;
            if (pPart != NULL)
                delete pPart;
        }
        ((dwList*)&dwCore_pWorkspaceNodes)->FreeNodeRange(
            dwCore_pWorkspaceNodes->pNext, dwCore_pWorkspaceNodes);

        dwGuiWidgets_LoadDroidFromFile(
            this->pFileScrollBox->pSelectedItem->filename.pBuffer,
            &dwCore_workspaceName, (dwList*)&dwCore_pWorkspaceNodes);
    }
    // fallthrough
    case 0xfa7: // slide out
        this->StartSlideOut();
        break;

    case 0xfa8: // name entry activated
    {
        dwWidgetMsg refresh = { 0xfa3, NULL, 0, NULL };
        dwWidget_DispatchMsg(&refresh, NULL);
        break;
    }

    default:
        break;
    }

    int ret = dwGuiScreen::OnMessage(pMsg);
    if (pMsg->code == 0xfa3 && this->slideDir == 0.0f && this->bEditNameMode == 0)
    {
        dwSound_Stop("WSelectDroid2.WAV");
        dwSound_PlayRestart("WSelectDroid3.WAV");
    }
    return ret;
}

// vtbl +0x48 @40c5a0 (dwGuiLoadSave_CreateControl)
dwWidget* dwGuiLoadSave::CreateControl(char* pKeyword, dwConfFile* pConf)
{
    dwRect rect = { 0, 0, 0, 0 };

    if (dwString_Equals(pKeyword, "HELP"))
    {
        // TODO(dw-decomp): dwHelp (P6 wave 2b agent 3). Binary: new(0x5c)
        // dwHelp_Ctor(&rect, /*pParent*/0, /*speaker*/0x68). Loud stub.
        stdPlatform_Printf("TODO(dw-decomp): dwGuiLoadSave control 'HELP' -> dwHelp(speaker 0x68) not translated yet\n");
        return NULL;
    }
    if (dwString_Equals(pKeyword, "SCROLLBOX"))
    {
        uint32_t scrollMsg = 0;
        int32_t textColor = 0;
        uint32_t highlight = 0;
        uint32_t msgSel = 0;
        dwConfFile_ParseRect(pConf, &rect);
        dwConfFile_ParseULong(pConf, &scrollMsg);
        char* pFontName = dwConfFile_NextToken(pConf);
        dwConfFile_ParseLong(pConf, &textColor);
        dwConfFile_ParseULong(pConf, &highlight);
        dwConfFile_ParseULong(pConf, &msgSel);
        this->pFileScrollBox = new dwGuiScrollBox(
            &rect, (int)scrollMsg, pFontName, (uint8_t)textColor, (uint8_t)highlight, (int)msgSel);

        // Populate from every *.drd file's NAME field.
        dwList files;
        inits_EnumFilesByExt("drd", &files);
        for (dwListNode* pNode = files.pSentinel->pNext; pNode != files.pSentinel; pNode = pNode->pNext)
        {
            char* pFileName = ((dwString*)pNode->pData)->pBuffer;
            dwConfFile conf;
            dwConfFile_Open(&conf, pFileName);
            while (conf.bEof == 0)
            {
                dwConfFile_ReadLine(&conf);
                char* pTok = dwConfFile_NextToken(&conf);
                if (dwString_Equals(pTok, "NAME"))
                {
                    this->pFileScrollBox->AddItem(pFileName, conf.pCursor);
                    break;
                }
            }
            dwConfFile_Close(&conf);
        }
        // free the temp filename list (payloads are dwString*, owned)
        for (dwListNode* pNode = files.pSentinel->pNext; pNode != files.pSentinel; )
        {
            dwListNode* pNext = pNode->pNext;
            dwString* pStr = (dwString*)pNode->pData;
            if (pStr != NULL)
                delete pStr;
            pNode = pNext;
        }
        // @40ce30 dwGuiLoadSave_ClearList + free-sentinel == dwList::Free
        files.Free();
        return this->pFileScrollBox;
    }
    if (dwString_Equals(pKeyword, "SCROLLUPBUTTON") || dwString_Equals(pKeyword, "SCROLLDOWNBUTTON"))
    {
        uint32_t cmdId = 0;
        dwConfFile_ParseRect(pConf, &rect);
        dwConfFile_ParseULong(pConf, &cmdId);
        char* pImgUp = dwConfFile_NextToken(pConf);
        char* pImgDown = dwConfFile_NextToken(pConf);
        dwGuiScrollButton* pBtn = new dwGuiScrollButton(&rect, pImgUp, pImgDown, (int)cmdId);
        if (dwString_Equals(pKeyword, "SCROLLUPBUTTON"))
            this->pScrollUpButton = pBtn;
        else
            this->pScrollDownButton = pBtn;
        if (this->pFileScrollBox->bNeedsScroll == '\0')
            pBtn->Disable();
        return pBtn;
    }
    if (dwString_Equals(pKeyword, "FILESCROLLBAR"))
    {
        uint32_t msgSetValue = 0, msgLineUp = 0, msgLineDown = 0;
        dwConfFile_ParseRect(pConf, &rect);
        dwConfFile_ParseULong(pConf, &msgSetValue);
        dwConfFile_ParseULong(pConf, &msgLineUp);
        dwConfFile_ParseULong(pConf, &msgLineDown);
        char* pThumbImg = dwConfFile_NextToken(pConf);
        if (pThumbImg != NULL && *pThumbImg == '\0')
            pThumbImg = NULL;
        int maxValue = (this->pFileScrollBox->itemCount == 0)
                     ? 0 : (this->pFileScrollBox->itemCount - 1);
        this->pFileScrollBar = new dwGuiScrollBar(
            &rect, (int)msgSetValue, (int)msgLineUp, (int)msgLineDown, 0, maxValue, NULL, pThumbImg);
        this->pFileScrollBar->SetValue(0);
        if (this->pFileScrollBox->bNeedsScroll == '\0')
            this->pFileScrollBar->Disable();
        return this->pFileScrollBar;
    }
    if (dwString_Equals(pKeyword, "LOADSAVENAME"))
    {
        uint32_t color1 = 0, color2 = 0;
        dwConfFile_ParseRect(pConf, &rect);
        char* pFontName = dwConfFile_NextToken(pConf);
        dwConfFile_ParseULong(pConf, &color1);
        dwConfFile_ParseULong(pConf, &color2);
        // commit code: LOAD (0xfa6) when the Load button is enabled, else SAVE (0xfa5)
        int msgCommit = 0xfa5 + (this->pButtonLoad->bEnabled ? 1 : 0);
        this->pNameEntry = new dwGuiTextEntry(
            &rect, pFontName, (uint8_t)color1, (uint8_t)color2, &dwCore_workspaceName,
            0xfa8, 0, msgCommit);
        return this->pNameEntry;
    }
    if (dwString_Equals(pKeyword, "BUTTON_LOAD"))
    {
        this->pButtonLoad = dwGuiScreen::CreateControl((char*)"BUTTON", pConf);
        if (dwCore_pWorkspaceNodes == dwCore_pWorkspaceNodes->pNext)
            this->pButtonLoad->Enable();
        else
            this->pButtonLoad->Disable();
        return this->pButtonLoad;
    }
    if (dwString_Equals(pKeyword, "BUTTON_SAVE"))
    {
        this->pButtonSave = dwGuiScreen::CreateControl((char*)"BUTTON", pConf);
        if (dwCore_pWorkspaceNodes != dwCore_pWorkspaceNodes->pNext)
            this->pButtonSave->Enable();
        else
            this->pButtonSave->Disable();
        return this->pButtonSave;
    }
    if (dwString_Equals(pKeyword, "BUTTON_REC"))
    {
        this->pButtonRecycle = dwGuiScreen::CreateControl((char*)"BUTTON", pConf);
        if (dwCore_pWorkspaceNodes == dwCore_pWorkspaceNodes->pNext)
            this->pButtonRecycle->Enable();
        else
            this->pButtonRecycle->Disable();
        return this->pButtonRecycle;
    }
    if (dwString_Equals(pKeyword, "DROIDBOX"))
    {
        this->pDroidBoxImage = dwGuiScreen::CreateControl((char*)"IMAGE", pConf);
        return this->pDroidBoxImage;
    }
    return dwGuiScreen::CreateControl(pKeyword, pConf);
}

// vtbl +0x3c @40ccd0 (dwGuiLoadSave_EnsureImages)
void dwGuiLoadSave::EnsureImages()
{
    dwGuiScreen::EnsureImages();
    if (this->pDroidBoxImage != NULL)   this->pDroidBoxImage->EnsureImages();
    if (this->pNameEntry != NULL)       this->pNameEntry->EnsureImages();
    if (this->pFileScrollBar != NULL)   this->pFileScrollBar->EnsureImages();
    if (this->pFileScrollBox != NULL)   this->pFileScrollBox->EnsureImages();
    if (this->pScrollUpButton != NULL)  this->pScrollUpButton->EnsureImages();
    if (this->pScrollDownButton != NULL)this->pScrollDownButton->EnsureImages();
    if (this->pButtonLoad != NULL)      this->pButtonLoad->EnsureImages();
    if (this->pButtonSave != NULL)      this->pButtonSave->EnsureImages();
    if (this->pButtonRecycle != NULL)   this->pButtonRecycle->EnsureImages();
}

// vtbl +0x40 @40cd70 (dwGuiLoadSave_FreeImages)
void dwGuiLoadSave::FreeImages()
{
    dwGuiScreen::FreeImages();
    if (this->pDroidBoxImage != NULL)   this->pDroidBoxImage->FreeImages();
    if (this->pNameEntry != NULL)       this->pNameEntry->FreeImages();
    if (this->pFileScrollBar != NULL)   this->pFileScrollBar->FreeImages();
    if (this->pFileScrollBox != NULL)   this->pFileScrollBox->FreeImages();
    if (this->pScrollUpButton != NULL)  this->pScrollUpButton->FreeImages();
    if (this->pScrollDownButton != NULL)this->pScrollDownButton->FreeImages();
    if (this->pButtonLoad != NULL)      this->pButtonLoad->FreeImages();
    if (this->pButtonSave != NULL)      this->pButtonSave->FreeImages();
    if (this->pButtonRecycle != NULL)   this->pButtonRecycle->FreeImages();
}

// @40bff0 (dwGuiLoadSave_RefreshWidgets)
void dwGuiLoadSave::RefreshWidgets()
{
    if (dwCore_pWorkspaceNodes == dwCore_pWorkspaceNodes->pNext)
    {
        this->bEditNameMode = 0;
        this->pNameEntry->Disable();
    }
    else
    {
        this->pNameEntry->Enable();
    }

    if (this->bEditNameMode == 0)
    {
        if (this->pFileScrollBox->itemCount != 0)
        {
            this->pButtonLoad->Enable();
            this->pButtonSave->Disable();
            this->pButtonRecycle->Enable();
            this->pFileScrollBox->bHasSelection = 1;
            this->pFileScrollBox->Invalidate();
        }
        else
        {
            this->pButtonLoad->Disable();
            this->pButtonSave->Disable();
            this->pButtonRecycle->Disable();
            this->pFileScrollBox->bHasSelection = 0;
            this->pFileScrollBox->Invalidate();
        }
    }
    else
    {
        this->pButtonLoad->Disable();
        this->pButtonSave->Enable();
        this->pButtonRecycle->Disable();
        this->pFileScrollBox->bHasSelection = 0;
        this->pFileScrollBox->Invalidate();
    }

    if (this->pFileScrollBox->bNeedsScroll != '\0')
    {
        this->pFileScrollBar->Enable();
        this->pScrollUpButton->Enable();
        this->pScrollDownButton->Enable();
    }
    else
    {
        this->pFileScrollBar->Disable();
        this->pScrollUpButton->Disable();
        this->pScrollDownButton->Disable();
    }
    this->Invalidate();
}

// @40bdc0 (dwGuiLoadSave_StartSlideOut)
void dwGuiLoadSave::StartSlideOut()
{
    // Re-attach the DROIDBOX snapshot to `controls` so it is drawn while the
    // panel slides away. (The binary also prepares a snapshot rect via two
    // GetRect/blit-style calls before this; those were EH-frame-corrupted in
    // the decompile and are omitted — the observable effect is the re-attach
    // plus the slide-out arm below.)
    if (this->pDroidBoxImage != NULL)
        this->controls.children.InsertAfter(
            this->controls.children.pSentinel->pPrev, this->pDroidBoxImage);

    this->slideTimer = 0.0f;
    this->slideDir = 320.0f;
    dwSound_SetSampleVolume("WLSPanelAmb.WAV", 0.0f, (float)(int)this->bottom / 320.0f);
    this->Invalidate();
}

// Note: no binary counterpart — soft-reset convention seam (no module statics).
extern "C" void dwGuiLoadSave_Startup(void)
{
}

// Added: C-callable factory (see dwGuiLoadSave.h). Upcasts through the MI
// hierarchy (dwGuiScreen -> dwWidget, dwSegment) to the dwSegment subobject.
extern "C" dwSegment* dwGuiLoadSave_New(dwImage* pBgSnapshot)
{
    return static_cast<dwSegment*>(new dwGuiLoadSave(pBgSnapshot));
}
