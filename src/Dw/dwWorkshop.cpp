// dwWorkshop — the 'workshop' droid-editor SCREEN singleton. See dwWorkshop.h.
//
// Decompiled from DroidWorks.exe, unit range 0x43c1b0-0x43cf4f (primary
// vtable @0x51fff0, secondary scn vtable @0x51ffd8; the compiler regenerates
// the MI thunks, incl. dwWorkshop_ScnDtorThunk @43cf20).
//
// Engine/API mapping (DW-binary label -> repo):
//   stdBitmapRle_FUN_00444d00 -> dwWidget_DispatchMsg (known mislabel; the
//     stack dwWidgetMsg payloads below were recovered from the disassembly —
//     the Ghidra decompile hides the thiscall msg pointer)
//   DAT_0053d9f8 -> dwPlayer_statsFlags · DAT_0053d984 -> dwCore_pWorkspaceNodes
//   DAT_0053d954 -> dwCore_pCurrentMission (dw-core global, P7)
//   dwSegment_pCueList emptiness (@0x53e858) -> dwSegment_IsPlaylistEmpty()
//   rand() @507f30 -> _rand() (jk.h; dwDroidStats precedent)
//   constants: 3.051851e-05f (~1/32768) * 120.0f + 180.0f dance reseed;
//   float -180.0 @0x51e998 / double -0.5 @0x51e9a0 (editor unit; not used here)
//
// Module statics: dwWorkshop_pSingleton (reset in dwWorkshop_Startup).

#include "Dw/dwWorkshop.h"

#include "Dw/dwWorkshopDroidEditor.h"
#include "Dw/dwWorkshopCtrl.h" // dwWcBlueprints / dwWcPalette
#include "Dw/dwGuiButton.h"    // dwWcArrows / dwWcBuildPaintButton / dwWcCargoNormalButton
#include "Dw/dwHelp.h"         // dwHelp (HELP keyword)
#include "Dw/dwGuiTextEntry.h" // DROID_NAME
#include "Dw/dwPart.h"         // dwPartNode anim control + blueprint slotMask
#include "Dw/dwDroidView.h"    // dwDroidView (PANCONTROL)
#include "Dw/dwGuiStatsPart.h" // dwGuiPartImage (PART_IMAGE)
#include "Dw/dwList.h"
#include "Dw/dwConfFile.h"
#include "Dw/dwSound.h"
#include "Dw/dwCursor.h"
#include "Dw/dwSegment.h"
#include "Dw/dwPlayer.h" // dwPlayer_statsFlags

#include "jk.h" // _rand
#include "stdPlatform.h"

// dw-core workspace part-node list sentinel @0x53d984 (owner: dwMain, P7).
// TODO(dw-decomp): provided by dwMain.
extern "C" dwListNode* dwCore_pWorkspaceNodes;
// Modal yes/no dialog runner @41c0f0 (owner: dwGuiMission, P6). Returns
// 0x1388 (5000) for YES, 0x1389 (5001) for NO.
// TODO(dw-decomp): provided by dwGuiMission.
extern "C" int dwGuiDialog_RunModal(const char* pConfName, const char* pMsgKey);
// The workspace droid's display name @0x53d978 (currently dwInits.cpp,
// P7-owned) — the DROID_NAME entry edits it in place.
extern dwString dwCore_workspaceName;
// The currently-selected mission record @0x53d954 (dwMissionInfo*; owner:
// dw core, P7) — broadcast as the 0xbbc "show reward part" sender.
// TODO(dw-decomp): provided by dwMain/dwGuiMission (dwMain.c placeholder).
extern "C" void* dwCore_pCurrentMission;

// ---- module statics -----------------------------------------------------------

extern "C" dwWorkshop* dwWorkshop_pSingleton = NULL; // @0x53e8c0

// Reseed the idle dance poke: now + rand()*120/32768 + 180 seconds (the
// exact binary constants; shared by Activate/Update/msg 0x7932).
static void dwWorkshop_ReseedDanceTime(dwWorkshop* pThis)
{
    pThis->nextDanceTime = (float)_rand() * 3.051851e-05f * 120.0f
                         + pThis->dwSegment::GetElapsed() + 180.0f;
}

// ---- singleton -----------------------------------------------------------------

// @43c1b0 (dwWorkshop_CreateSingleton)
extern "C" void dwWorkshop_CreateSingleton(void)
{
    if (dwWorkshop_pSingleton == NULL)
        dwWorkshop_pSingleton = new dwWorkshop();
}

// Note: no binary counterpart — soft-reset rule (the object itself is torn
// down through the segment stack, not here).
extern "C" void dwWorkshop_Startup(void)
{
    dwWorkshop_pSingleton = NULL;
}

// ---- ctor/dtor -----------------------------------------------------------------

// @43c220 (dwWorkshop_Ctor)
dwWorkshop::dwWorkshop()
    : dwGuiScreen("workshop", NULL)
    , danceSound("dance.wav", 0)
{
    this->bPaintMode = 0;
    this->paintColorIdx = 0;
    dwRect_Set(&this->paintRect, 0, 0, 0, 0);
    dwRect_Set(&this->viewRect, 0, 0, 0, 0);
    this->bIdleAnims = 0;
    this->bActiveAnims = 0;
    this->bRotateCalcSound = 0;
    this->nextDanceTime = 0.0f;
}

// @43c300 (dwWorkshop_Dtor; scalar-deleting wrapper @43c2e0; secondary-vtbl
// dtor thunk dwWorkshop_ScnDtorThunk @43cf20 = compiler-generated here)
dwWorkshop::~dwWorkshop()
{
    dwWorkshop_pSingleton = NULL;
    // danceSound freed by its member dtor; dwGuiScreen base dtor follows.
}

// ---- segment lifecycle -----------------------------------------------------------

// @43c3e0 (dwWorkshop_OnActivate — secondary vtbl +0x00)
int dwWorkshop::Activate()
{
    dwListNode* pIter;
    dwPartNode* pNode;
    dwWidgetMsg msg;
    uint32_t slotMask;
    int ok;

    ok = this->dwGuiScreen::Activate();
    if (ok)
    {
        if (this->bIdleAnims != 0)
        {
            for (pIter = dwCore_pWorkspaceNodes->pNext; pIter != dwCore_pWorkspaceNodes; pIter = pIter->pNext)
            {
                pNode = (dwPartNode*)pIter->pData;
                pNode->StopAnim();
                if (this->bActiveAnims == 0)
                    pNode->PlayIdleAnim();
                else
                    pNode->PlayActiveAnim();
            }
            if (this->bActiveAnims != 0 && this->bModal == 0)
                dwSound_SetMusic(this->danceSound.pBuffer, 0);
        }

        // Show the current mission's reward part in the part viewers.
        msg.code = 0xbbc;
        msg.pSender = dwCore_pCurrentMission;
        msg.param = 0;
        msg.pTarget = NULL;
        dwWidget_DispatchMsg(&msg, NULL);

        // Re-announce the workspace body type from the first torso/chassis
        // blueprint (slotMask 1 = NORMAL / 2 = CARGO).
        for (pIter = dwCore_pWorkspaceNodes->pNext; pIter != dwCore_pWorkspaceNodes; pIter = pIter->pNext)
        {
            slotMask = ((dwPartNode*)pIter->pData)->pPart->slotMask;
            if (slotMask == 2 || slotMask == 1)
            {
                msg.code = 0x7e4;
                msg.pSender = (void*)(intptr_t)slotMask;
                msg.param = 0;
                msg.pTarget = NULL;
                dwWidget_DispatchMsg(&msg, NULL);
                break;
            }
        }

        msg.code = 0x7dc;
        msg.pSender = NULL;
        msg.param = 0;
        msg.pTarget = NULL;
        dwWidget_DispatchMsg(&msg, NULL);

        // A pending workshop-tutorial request (statsFlags bit 0x10000000,
        // set by the player-profile layer) starts the tutorial once.
        if (dwPlayer_statsFlags & 0x10000000)
        {
            dwPlayer_statsFlags = (dwPlayer_statsFlags & ~0x10000000u) | 0x80000000u;
            msg.code = 0x792a;
            msg.pSender = NULL;
            msg.param = 0;
            msg.pTarget = NULL;
            dwWidget_DispatchMsg(&msg, NULL);
        }
    }
    dwWorkshop_ReseedDanceTime(this);
    return ok;
}

// @43c360 (dwWorkshop_OnDeactivate — secondary vtbl +0x04)
void dwWorkshop::Deactivate()
{
    dwListNode* pIter;

    if (this->bIdleAnims != 0)
    {
        if (this->bActiveAnims != 0 && this->bModal == 0)
            dwSound_SetMusic(this->musicName.pBuffer, 0);
        for (pIter = dwCore_pWorkspaceNodes->pNext; pIter != dwCore_pWorkspaceNodes; pIter = pIter->pNext)
            ((dwPartNode*)pIter->pData)->StopAnim();
    }
    this->dwGuiScreen::Deactivate();
}

// ---- widget overrides -----------------------------------------------------------

// @43c5b0 (dwWorkshop_OnMouseMove — primary vtbl +0x04)
int dwWorkshop::OnMouseMove(int16_t x, int16_t y)
{
    int cursorIdx;

    if (this->bActive != 0) // base pick-a-control mode: wait cursor
    {
        cursorIdx = 3;
    }
    else if (dwRect_ContainsPoint(&this->viewRect, x, y))
    {
        cursorIdx = 2; // grab cursor over the droid viewer (PANCONTROL rect)
    }
    else if (this->bPaintMode != 0 && this->paintColorIdx != 0
             && dwRect_ContainsPoint(&this->paintRect, x, y))
    {
        cursorIdx = (int)this->paintColorIdx + 4; // per-color paint cursor
    }
    else
    {
        cursorIdx = 1; // arrow
    }
    dwCursor_SetCursor(cursorIdx);
    return this->dwGuiScreen::OnMouseMove(x, y);
}

// @43c990 (dwWorkshop_Update — primary vtbl +0x14).
// NOTE: replaces (does not chain) the base Update — it forwards to the
// embedded `controls` group itself, exactly like the base body.
void dwWorkshop::Update(float dt)
{
    dwWidgetMsg msg;

    // Tutorial-driven advance: once the recorded-input playlist drains,
    // retire the screen (statsFlags bit 0x4000000 armed the advance).
    if ((dwPlayer_statsFlags & 0x4000000) && dwSegment_IsPlaylistEmpty())
    {
        dwPlayer_statsFlags &= ~0x4000000u;
        dwSegment_RequestAdvance();
    }

    // Idle dance poke: every 180..300s with a droid present (not during a
    // tutorial) nudge the help layer with a hover-notify.
    if (this->dwSegment::GetElapsed() >= this->nextDanceTime
        && dwCore_pWorkspaceNodes != dwCore_pWorkspaceNodes->pNext
        && this->bModal == 0)
    {
        dwWorkshop_ReseedDanceTime(this);
        msg.code = 0x7531;
        msg.pSender = (void*)(intptr_t)0x7929;
        msg.param = 0;
        msg.pTarget = NULL;
        dwWidget_DispatchMsg(&msg, NULL);
    }

    this->controls.Update(dt); // binary: controls vtbl +0x14
}

// @43c670 (dwWorkshop_OnMessage — primary vtbl +0x1c)
int dwWorkshop::OnMessage(dwWidgetMsg* pMsg)
{
    dwListNode* pIter;
    dwPartNode* pNode;
    dwWidgetMsg msg;
    uint8_t bNewState;
    int handled;

    handled = 0;
    switch (pMsg->code)
    {
    case 0x7d3: // arm a paint color slot (cursor selection; the editor maps the color)
        this->paintColorIdx = (uint8_t)(uintptr_t)pMsg->pSender;
        break;

    case 0x7d4: // toggle idle anims (music follows: dance only when BOTH anims run)
        bNewState = (this->bIdleAnims == 0) ? 1 : 0;
        this->bIdleAnims = bNewState;
        if (this->bModal == 0)
        {
            if (bNewState != 0 && this->bActiveAnims != 0)
                dwSound_SetMusic(this->danceSound.pBuffer, 0);
            else
                dwSound_SetMusic(this->musicName.pBuffer, 0);
        }
        break;

    case 0x7de: // rotate-spin commands: toggle the WRotateCalc.wav loop
    case 0x7df:
    case 0x7e0:
    case 0x7e1:
        bNewState = (this->bRotateCalcSound == 0) ? 1 : 0;
        this->bRotateCalcSound = bNewState;
        if (bNewState != 0)
            dwSound_PlayLooping("WRotateCalc.wav");
        else
            dwSound_Stop("WRotateCalc.wav");
        break;

    case 0x7e3: // toggle dance anims (same music rule as 0x7d4)
        bNewState = (this->bActiveAnims == 0) ? 1 : 0;
        this->bActiveAnims = bNewState;
        if (this->bModal == 0)
        {
            if (this->bIdleAnims != 0 && bNewState != 0)
                dwSound_SetMusic(this->danceSound.pBuffer, 0);
            else
                dwSound_SetMusic(this->musicName.pBuffer, 0);
        }
        break;

    case 0x7e9: // paint tool selected
        this->bPaintMode = 1;
        this->paintColorIdx = 0;
        break;
    case 0x7ea: // build tool selected
        this->bPaintMode = 0;
        break;

    case 0x792a: // tutorial enter: offer to clear the current droid first
        if (dwCore_pWorkspaceNodes != dwCore_pWorkspaceNodes->pNext)
        {
            if (dwGuiDialog_RunModal("gyesno", "DLG_TUTCLEAROK") == 0x1388) // YES
            {
                for (pIter = dwCore_pWorkspaceNodes->pNext; pIter != dwCore_pWorkspaceNodes; pIter = pIter->pNext)
                {
                    pNode = (dwPartNode*)pIter->pData;
                    if (pNode != NULL)
                        delete pNode;
                }
                ((dwList*)&dwCore_pWorkspaceNodes)->FreeNodeRange(dwCore_pWorkspaceNodes->pNext, dwCore_pWorkspaceNodes);
                msg.code = 0x7dd;
                msg.pSender = NULL;
                msg.param = 0;
                msg.pTarget = NULL;
                dwWidget_DispatchMsg(&msg, NULL);
            }
            else
            {
                return 1; // NO: swallow the message (no tutorial, anims untouched)
            }
        }
        // Reset the anim toggles by clicking their toolbar buttons (the
        // binary literally synthesizes clicks at the buttons' coordinates).
        if (this->bIdleAnims != 0)
        {
            this->controls.OnMouseDown(0x140, 0x19a);
            this->controls.OnMouseUp(0x140, 0x19a);
        }
        if (this->bActiveAnims != 0)
        {
            this->controls.OnMouseDown(0x140, 0x1d6);
            this->controls.OnMouseUp(0x140, 0x1d6);
        }
        break;

    case 0x7932: // tutorial exit: push the next dance poke out again
        dwWorkshop_ReseedDanceTime(this);
        break;

    default:
        break;
    }

    handled = this->dwGuiScreen::OnMessage(pMsg);

    // RANDOMIZE (0x7eb) rebuilt the droid — restart the anims on the new parts.
    if (pMsg->code == 0x7eb && this->bIdleAnims != 0)
    {
        for (pIter = dwCore_pWorkspaceNodes->pNext; pIter != dwCore_pWorkspaceNodes; pIter = pIter->pNext)
        {
            pNode = (dwPartNode*)pIter->pData;
            pNode->StopAnim();
            if (this->bActiveAnims == 0)
                pNode->PlayIdleAnim();
            else
                pNode->PlayActiveAnim();
        }
    }
    return handled;
}

// ---- control factory -----------------------------------------------------------

// @43ca70 (dwWorkshop_CreateControl — primary vtbl +0x48)
dwWidget* dwWorkshop::CreateControl(char* pKeyword, dwConfFile* pConf)
{
    dwRect rect;
    dwRect rect2;
    char* pTok;
    uint32_t param;
    uint32_t param2;

    dwRect_Set(&rect, 0, 0, 0, 0);

    if (dwString_Equals(pKeyword, "ARROWBALL"))
    {
        dwConfFile_ParseRect(pConf, &rect);
        // binary: new(0x38) dwWcArrows_Ctor(&rect)
        return new dwWcArrows(&rect);
    }
    if (dwString_Equals(pKeyword, "BLUEPRINTS"))
    {
        param = 0;
        dwConfFile_ParseRect(pConf, &rect);
        dwConfFile_ParseULong(pConf, &param);
        // binary: new(0x38) dwWcBlueprints_Ctor(&rect, (short)xIndent)
        return new dwWcBlueprints(&rect, (int16_t)param);
    }
    if (dwString_Equals(pKeyword, "BUILD/PAINT"))
    {
        dwConfFile_ParseRect(pConf, &rect);
        // binary: new(0x38) dwGuiButton_Ctor("wcbuildpaint", &rect) + vtbl
        // 0x5200a0 + SetPressed(2) — the dwWcBuildPaintButton ctor is that
        // exact inlined sequence (Dw/dwGuiButton.h).
        return new dwWcBuildPaintButton(&rect);
    }
    if (dwString_Equals(pKeyword, "CARGO/NORMAL"))
    {
        dwConfFile_ParseRect(pConf, &rect);
        // binary: new(0x3c) dwGuiButton_Ctor("wccargonorm", &rect) + vtbl
        // 0x520050 + bSuppressConfirm-wrapped SetPressed(2) — inlined
        // dwWcCargoNormalButton ctor (Dw/dwGuiButton.h).
        return new dwWcCargoNormalButton(&rect);
    }
    if (dwString_Equals(pKeyword, "DANCE"))
    {
        // No control — just the dance-music wav name.
        pTok = dwConfFile_NextToken(pConf);
        this->danceSound.AssignCStr(pTok);
        return NULL;
    }
    if (dwString_Equals(pKeyword, "DROID_EDITOR"))
    {
        // The editor rect doubles as the screen's paint-cursor zone.
        dwConfFile_ParseRect(pConf, &this->paintRect);
        dwRect_Set(&rect2, 0, 0, 0, 0);
        pTok = dwConfFile_NextToken(pConf); // trash overlay image
        dwConfFile_ParseRect(pConf, &rect2); // trash drop rect
        // binary: new(0x5b4) dwWorkshopDroidEditor_Ctor(&paintRect, &trashRect, tok)
        return new dwWorkshopDroidEditor(&this->paintRect, &rect2, pTok);
    }
    if (dwString_Equals(pKeyword, "DROID_NAME"))
    {
        param = 0;
        param2 = 0;
        dwConfFile_ParseRect(pConf, &rect);
        pTok = dwConfFile_NextToken(pConf); // font
        dwConfFile_ParseULong(pConf, &param);  // text color
        dwConfFile_ParseULong(pConf, &param2); // cursor color
        // binary: new(0x40) dwGuiTextEntry_Ctor(&rect, font, colors,
        // &dwCore_workspaceName, 0xfa8, 0x7ec, 0)
        return new dwGuiTextEntry(&rect, pTok, (uint8_t)param, (uint8_t)param2,
                                  &dwCore_workspaceName, 0xfa8, 0x7ec, 0);
    }
    if (dwString_Equals(pKeyword, "HELP"))
    {
        dwConfFile_ParseRect(pConf, &rect);
        pTok = dwConfFile_NextToken(pConf);
        // dwHelp (unit dwHelp, landed P6w2b): binary new(0x5c)
        // dwHelp_Ctor(&rect, tok, /*speakerCode*/100) @418af0
        return new dwHelp(&rect, pTok, 100);
    }
    if (dwString_Equals(pKeyword, "PALETTE"))
    {
        dwConfFile_ParseRect(pConf, &rect);
        // binary: new(0x20) dwWcPalette_Ctor(&rect)
        return new dwWcPalette(&rect);
    }
    if (dwString_Equals(pKeyword, "PANCONTROL"))
    {
        param = 0;
        param2 = 0;
        // The view rect doubles as the screen's grab-cursor zone.
        dwConfFile_ParseRect(pConf, &this->viewRect);
        dwConfFile_ParseULong(pConf, &param);
        dwConfFile_ParseULong(pConf, &param2);
        // binary: new(0x57c) dwDroidView_Ctor(&this->viewRect, param, param2) @426080
        // param = dead middle arg, param2 = FOV%.
        return new dwDroidView(&this->viewRect, (int)param, (int)param2);
    }
    if (dwString_Equals(pKeyword, "PART_IMAGE"))
    {
        param = 0;
        dwConfFile_ParseRect(pConf, &rect);
        pTok = dwConfFile_NextToken(pConf); // font
        dwConfFile_ParseULong(pConf, &param); // color
        // binary: new(0x34) dwGuiPartImage_Ctor(&rect, font, (u8)color) @428d10
        return new dwGuiPartImage(&rect, pTok, (uint8_t)param);
    }

    return this->dwGuiScreen::CreateControl(pKeyword, pConf); // @430a10 base factory
}
