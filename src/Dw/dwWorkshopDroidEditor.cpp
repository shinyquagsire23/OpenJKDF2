// dwWorkshopDroidEditor — the workshop DROID_EDITOR control (3D droid
// assembly view: drag/attach/detach/paint parts). See dwWorkshopDroidEditor.h.
//
// Decompiled from DroidWorks.exe, unit range 0x40cea0-0x40eb5f
// (vtable @0x51e9b8). ⚠ EnsureImages/FreeImages/ContainsPoint
// @40eab0/40eaf0/40eb10 belong here (old dwDroidStats Ghidra labels wrong).
//
// Engine mapping (DW-binary label -> repo):
//   rd_FUN_0047ebd0 / rd_FUN_0047ebf0 -> rdAdvanceFrame / rdFinishFrame
//     (the DW fork's rdAdvanceFrame ALSO clears the pick buffer when render
//     option 0x100 is set — rdRaycast_ClearPickBuffer@47f560, untranslated;
//     the manual stdDisplay_VBufferFill(canvas->d3d_vbuf) calls below are the
//     binary's own "option not set" fallback and fully cover this widget's
//     use, since it never sets option 0x100)
//   stdDisplay_FUN_004fe010 -> stdDisplay_VBufferFill
//   DAT_005542cc            -> rdCamera_g_pCurCamera
//   dwHS->getTimerTick (@0x6b6258 +0x2c) -> dwMain_pHS->getTimerTick
//   DAT_7f7fc99e (immediate) -> 3.4e38f hit-record init (dwDroidStats precedent)
//
// No module statics — dwWorkshopDroidEditor_Startup is a documented no-op.

#include "Dw/dwWorkshopDroidEditor.h"

#include "Dw/dwPart.h"
#include "Dw/dwList.h"
#include "Dw/dwSound.h"
#include "Dw/dwCursor.h"   // dwCursor_pos (fresh-spawn drag warm-up)
#include "Dw/dwImage.h"
#include "Dw/dwImageVBuf.h" // dwDisplay_pScreenImage's concrete class (Lock/Unlock)
#include "Dw/dwDisplay.h"  // dwDisplay_pScreenImage (paint pick sample)
#include "Dw/dwControlPanel.h" // dw_aPartSlotColors[10]

#include <math.h> // sqrtf

#include "jk.h"
#include "stdPlatform.h"
#include "Engine/rdCamera.h"
#include "Primitives/rdVector.h"  // has extern "C" guards
#include "Primitives/rdRaycast.h" // has extern "C" guards
// These engine headers have no extern "C" guards of their own — wrap at the
// include site.
extern "C" {
#include "Engine/rdroid.h"
#include "Win95/stdDisplay.h"
#ifdef RDRASTER_SW_ZBUFFER
#include "Raster/rdZRaster.h" // SW z-buffer per-frame clear for the 3D view
#endif
}

// dw-core workspace part-node list sentinel @0x53d984 (owner: dwMain, P7).
// TODO(dw-decomp): provided by dwMain.
extern "C" dwListNode* dwCore_pWorkspaceNodes;
// The DW host-services pointer (dwMain.c).
extern "C" HostServices* dwMain_pHS;

// PALETTE paint-color slot -> DW palette color index (binary byte table
// @0x51e987, indexed by the msg-0x7d3 payload; slot 0 = none).
static const uint8_t dwWorkshopDroidEditor_aPaintColors[10] = {
    0, 18, 83, 5, 44, 96, 70, 31, 57, 105
};

// Part-type attach compatibility: equal, or one of the mirror pairs
// 1<->3 (arm), 7<->8 (cargo arm), 2<->4 (affector). Shared by
// DropDraggedPart (both passes) and Draw's marker blink.
static int dwWorkshopDroidEditor_TypesCompatible(int typeA, int typeB)
{
    if (typeA == typeB)
        return 1;
    if ((typeA == 1 && typeB == 3) || (typeA == 3 && typeB == 1))
        return 1;
    if ((typeA == 7 && typeB == 8) || (typeA == 8 && typeB == 7))
        return 1;
    if ((typeA == 2 && typeB == 4) || (typeA == 4 && typeB == 2))
        return 1;
    return 0;
}

// A node's own MOUNT point viewed as a dwPartSlot: the binary passes
// (dwPartSlot*)&node->partType — the {partType, pMountNode} pair tiles
// exactly like {dwPartSlot.type, dwPartSlot.pNode}, and GetSlotPosition only
// reads pSlot->pNode. A local copy is layout-independent on 64-bit.
static void dwWorkshopDroidEditor_GetMountPosition(dwPartNode* pNode, rdVector3* pOut)
{
    dwPartSlot mountSlot;
    mountSlot.type = pNode->partType;
    mountSlot.pNode = pNode->pMountNode;
    mountSlot.pChildTypePtr = NULL;
    mountSlot.pChild = NULL;
    pNode->GetSlotPosition(&mountSlot, pOut);
}

// @40e180 (dwWorkshopDroidEditor_DestroyPartSubtree) — recursively delete
// pNode and its attached children, unlinking each from the workspace list;
// ends with a { 0x7dd, pNode } broadcast (pSender = the just-deleted node,
// exactly as the binary — receivers only match the code).
static void dwWorkshopDroidEditor_DestroyPartSubtree(dwPartNode* pNode)
{
    dwListNode* pIter;
    dwWidgetMsg msg;
    uint32_t i;

    for (i = 0; i < (uint32_t)pNode->slotCount; i++)
    {
        if (pNode->aSlots[i].pChild != NULL)
            dwWorkshopDroidEditor_DestroyPartSubtree(pNode->aSlots[i].pChild);
    }

    for (pIter = dwCore_pWorkspaceNodes->pNext;
         pIter != dwCore_pWorkspaceNodes && pIter->pData != pNode;
         pIter = pIter->pNext)
    {
    }
    if (pIter != dwCore_pWorkspaceNodes)
        ((dwList*)&dwCore_pWorkspaceNodes)->UnlinkFreeNode(pIter);

    if (pNode != NULL)
        delete pNode;

    msg.code = 0x7dd;
    msg.pSender = pNode; // Note: dangling by design (binary passes the freed node)
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);
}

// @40df00 (dwWorkshopDroidEditor_FindBatteryTarget) — recursive: find a node
// in pNode's assembly whose blueprint has battery capacity. Batteries
// themselves never match; the walk climbs to the parent (unless this is a
// NORMAL-mode torso or an unattached root) and descends into the torso
// children of a NORMAL-mode locomotion.
static dwPartNode* dwWorkshopDroidEditor_FindBatteryTarget(dwPartNode* pNode)
{
    dwPartNode* pFound = NULL;
    dwPartNode* pChild;
    int i;

    if (pNode == NULL)
        return NULL;
    if (pNode->pPart->type == DW_PARTTYPE_BATTERY)
        return NULL;
    if (pNode->pPart->battery != 0)
        return pNode;

    if (!(pNode->pPart->type == DW_PARTTYPE_TORSO && pNode->pPart->slotMask == 1)
        && pNode->partType != DW_PARTTYPE_NONE)
    {
        pFound = dwWorkshopDroidEditor_FindBatteryTarget(pNode->pAttachData);
    }
    if (pNode->pPart->type == DW_PARTTYPE_LOCOMOTION && pNode->pPart->slotMask == 1)
    {
        for (i = 0; i < pNode->slotCount; i++)
        {
            pChild = pNode->aSlots[i].pChild;
            if (pChild != NULL && pChild->pPart->type == DW_PARTTYPE_TORSO)
                pFound = dwWorkshopDroidEditor_FindBatteryTarget(pChild);
        }
    }
    return pFound;
}

// ---- ctor/dtor -----------------------------------------------------------------

// @40cea0 (dwWorkshopDroidEditor_Ctor)
dwWorkshopDroidEditor::dwWorkshopDroidEditor(dwRect* pRect, dwRect* pTrashRect, char* pTrashImageName)
    : dwGuiViewBox(pRect, 1)
{
    this->bIdleAnims = 0;
    this->bActiveAnims = 0;
    this->yawSpinDelta = 0.0f;
    this->yawSpinAccum = 0.0f;  // Note: binary leaves accum/start unset until a spin arms
    this->yawSpinStart = 0.0f;
    this->pitchSpinDelta = 0.0f;
    this->pitchSpinAccum = 0.0f;
    this->pitchSpinStart = 0.0f;
    this->bCursorActive = 0;
    this->paintColorIdx = 0;
    this->dragGrab.x = 0.0f;
    this->dragGrab.y = 0.0f;
    this->dragGrab.z = 0.0f;
    this->pDraggedNode = NULL;
    this->bDragStarted = 0;
    this->dragTimerTick = 0;
    this->bBlinkPhase = 0;
    this->bInTrashZone = 0;
    this->trashRect = *pTrashRect;
    this->pTrashImage = NULL;
    this->trashImageName.AssignCStr(pTrashImageName);
    this->EnsureImages();
}

// @40cf90 (dwWorkshopDroidEditor_Dtor; scalar-deleting wrapper @40cf70)
dwWorkshopDroidEditor::~dwWorkshopDroidEditor()
{
    this->FreeImages();
    // trashImageName freed by its member dtor; dwGuiViewBox base dtor follows.
}

// ---- input ---------------------------------------------------------------------

// @40e370 (dwWorkshopDroidEditor_OnMouseMove)
int dwWorkshopDroidEditor::OnMouseMove(int16_t x, int16_t y)
{
    dwPoint pt;
    rdVector3 world;
    rdVector3 dir;
    rdVector3 planeNormal;
    rdVector3 delta;
    rdRaycastHit hit;
    uint8_t bInTrash;

    if (this->pDraggedNode == NULL)
    {
        this->bInTrashZone = 0;
        return 0;
    }

    bInTrash = dwRect_ContainsPoint(&this->trashRect, x, y) ? 1 : 0;
    if (bInTrash != this->bInTrashZone)
    {
        dwSound_PlayRestart("WOpenTrash.wav");
        this->bInTrashZone = bInTrash;
    }

    // Drag the part along the camera-facing plane through the grab point.
    pt.x = x;
    pt.y = y;
    this->ScreenToWorld(&pt, &world);
    dir.x = world.x - this->viewMat.scale.x;
    dir.y = world.y - this->viewMat.scale.y;
    dir.z = world.z - this->viewMat.scale.z;
    rdVector_Normalize3Acc(&dir);
    planeNormal.x = -this->viewMat.lvec.x;
    planeNormal.y = -this->viewMat.lvec.y;
    planeNormal.z = -this->viewMat.lvec.z;
    hit.pMesh = NULL;
    hit.pFace = NULL;
    hit.distance = 3.4e38f;
    if (rdRaycast_RayPlane(&this->viewMat.scale, &dir, &this->dragGrab, &planeNormal, &hit))
    {
        delta.x = hit.worldHitPos.x - this->dragGrab.x;
        delta.y = hit.worldHitPos.y - this->dragGrab.y;
        delta.z = hit.worldHitPos.z - this->dragGrab.z;
        this->pDraggedNode->Translate(&delta);
        this->dragGrab = hit.worldHitPos;
        this->Invalidate();
        return 1;
    }
    return 1;
}

// @40e260 (dwWorkshopDroidEditor_OnMouseDown)
int dwWorkshopDroidEditor::OnMouseDown(int16_t x, int16_t y)
{
    dwPoint pt;
    int bInRect;

    pt.x = x;
    pt.y = y;
    bInRect = dwRect_ContainsPoint(this->GetRectPtr(), x, y);

    if (this->pDraggedNode != NULL)
    {
        this->DropDraggedPart(&pt);
        if ((dwWorkshopDroidEditor*)dwWidget_pMouseTarget == this)
            dwWidget_pMouseTarget = NULL;
        return bInRect;
    }
    if (bInRect)
    {
        if (this->bCursorActive != 0 && this->paintColorIdx != 0)
            return this->PaintPickedPart(&pt);
        if (this->BeginDragOrDetach(&pt))
            dwWidget_pMouseTarget = this;
    }
    return bInRect;
}

// @40e310 (dwWorkshopDroidEditor_OnMouseUp)
int dwWorkshopDroidEditor::OnMouseUp(int16_t x, int16_t y)
{
    dwPoint pt;

    if (this->pDraggedNode == NULL || this->bDragStarted != 0)
        return 0;

    pt.x = x;
    pt.y = y;
    this->DropDraggedPart(&pt);
    if ((dwWorkshopDroidEditor*)dwWidget_pMouseTarget == this)
        dwWidget_pMouseTarget = NULL;
    return 1;
}

// @40e510 (dwWorkshopDroidEditor_OnHover)
int dwWorkshopDroidEditor::OnHover(int16_t x, int16_t y)
{
    dwListNode* pIter;
    dwPartNode* pNode;
    rdVector3 pos;
    rdVector3 screen;
    rdRaycastHit hit;
    dwWidgetMsg msg;
    dwPoint pt;
    float fx, fy, dx, dy;
    int code;
    uint32_t i;

    code = 0;
    if (dwRect_ContainsPoint(&this->trashRect, x, y))
        code = 0x7d5;

    if (code == 0)
    {
        fx = (float)x;
        fy = (float)y;
        for (pIter = dwCore_pWorkspaceNodes->pNext;
             pIter != dwCore_pWorkspaceNodes && code == 0;
             pIter = pIter->pNext)
        {
            pNode = (dwPartNode*)pIter->pData;
            if (pNode->partType != DW_PARTTYPE_NONE && pNode->pAttachSlot == NULL)
            {
                dwWorkshopDroidEditor_GetMountPosition(pNode, &pos);
                this->ProjectPoint(&screen, &pos);
                dx = screen.x - fx;
                dy = screen.y - fy;
                if (sqrtf(dx * dx + dy * dy) <= 6.0f)
                    code = 0x791d;
            }
            for (i = 0; i < (uint32_t)pNode->slotCount && code == 0; i++)
            {
                if (pNode->aSlots[i].pChildTypePtr == NULL)
                {
                    pNode->GetSlotPosition(&pNode->aSlots[i], &pos);
                    this->ProjectPoint(&screen, &pos);
                    dx = screen.x - fx;
                    dy = screen.y - fy;
                    if (sqrtf(dx * dx + dy * dy) < 6.0f)
                        code = 0x791d;
                }
            }
        }
    }

    if (code == 0)
    {
        pt.x = x;
        pt.y = y;
        hit.pMesh = NULL;
        hit.pFace = NULL;
        hit.distance = 3.4e38f;
        if (this->RaycastPickNode(&pt, &hit) != NULL)
            code = 0x7920;
        if (code == 0)
            code = 0x791c;
    }

    msg.code = 0x7531;
    msg.pSender = (void*)(intptr_t)code;
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);
    return 1;
}

// ---- tick / messages -------------------------------------------------------------

// @40cff0 (dwWorkshopDroidEditor_Update)
void dwWorkshopDroidEditor::Update(float dt)
{
    dwListNode* pIter;
    dwWidgetMsg msg;
    uint32_t nowTick;
    int angle;

    if (this->yawSpinDelta != 0.0f)
    {
        this->yawSpinAccum = this->yawSpinAccum + dt;
        // Binary: __ftol truncation of (start + delta*accum + 180.0 + 0.5),
        // then %360 - 180 (recentered to -180..179).
        angle = (int)((double)this->yawSpinStart + (double)this->yawSpinDelta * (double)this->yawSpinAccum + 180.0 + 0.5);
        msg.code = 0x3e9; // set yaw (dwGuiViewBox)
        msg.pSender = (void*)(intptr_t)(angle % 360 - 180);
        msg.param = 0;
        msg.pTarget = NULL;
        dwWidget_DispatchMsg(&msg, NULL);
    }
    if (this->pitchSpinDelta != 0.0f)
    {
        this->pitchSpinAccum = this->pitchSpinAccum + dt;
        angle = (int)((double)this->pitchSpinStart + (double)this->pitchSpinDelta * (double)this->pitchSpinAccum + 0.5);
        msg.code = 0x3e8; // set pitch (dwGuiViewBox)
        msg.pSender = (void*)(intptr_t)(angle % 360);
        msg.param = 0;
        msg.pTarget = NULL;
        dwWidget_DispatchMsg(&msg, NULL);
    }
    if (this->bIdleAnims != 0)
    {
        for (pIter = dwCore_pWorkspaceNodes->pNext; pIter != dwCore_pWorkspaceNodes; pIter = pIter->pNext)
            ((dwPartNode*)pIter->pData)->FadeAnim(dt);
        msg.code = 0x7d6; // repaint broadcast
        msg.pSender = NULL;
        msg.param = 0;
        msg.pTarget = NULL;
        dwWidget_DispatchMsg(&msg, NULL);
    }
    if (this->pDraggedNode != NULL)
    {
        nowTick = dwMain_pHS->getTimerTick();
        if (nowTick - this->dragTimerTick > 500)
        {
            this->dragTimerTick = nowTick;
            this->bBlinkPhase = (this->bBlinkPhase == 0) ? 1 : 0;
            this->Invalidate();
        }
    }
}

// @40d1e0 (dwWorkshopDroidEditor_OnMessage)
int dwWorkshopDroidEditor::OnMessage(dwWidgetMsg* pMsg)
{
    dwListNode* pIter;
    dwPartNode* pNode;
    dwPart* pBlueprint;
    dwWidgetMsg msg;
    uint8_t colorSlot;

    switch (pMsg->code)
    {
    case 0x7d1: // blueprint clicked in the fly-out: spawn a fresh part + drag it
        if (this->pDraggedNode != NULL)
        {
            dwWorkshopDroidEditor_DestroyPartSubtree(this->pDraggedNode);
            this->pDraggedNode = NULL;
        }
        pBlueprint = (dwPart*)pMsg->pSender;
        if (pBlueprint != NULL && (pNode = pBlueprint->CreateNode()) != NULL)
        {
            this->bDragStarted = 1;
            ((dwList*)&dwCore_pWorkspaceNodes)->InsertAfter(dwCore_pWorkspaceNodes->pPrev, pNode); // push-back
            this->pDraggedNode = pNode;
            pNode->SetDrawFlag2Rec(); // wireframe while dragging
            this->pDraggedNode->GetPosition(&this->dragGrab);
            this->OnMouseMove(dwCursor_pos.x, dwCursor_pos.y); // warm up the drag plane (binary: virtual +0x04)
            this->dragTimerTick = dwMain_pHS->getTimerTick();
            this->bBlinkPhase = 1;
            if (this->bIdleAnims != 0)
            {
                if (this->bActiveAnims == 0)
                    pNode->PlayIdleAnim();
                else
                    pNode->PlayActiveAnim();
            }
            dwWidget_pMouseTarget = this;
            msg.code = 0x7d0; // selection changed: {blueprint, node}
            msg.pSender = pBlueprint;
            msg.param = (int32_t)(intptr_t)pNode; // Note: consumers read pSender; low bits only on 64-bit
            msg.pTarget = NULL;
            dwWidget_DispatchMsg(&msg, NULL);
        }
        return 0;

    case 0x7d3: // arm the paint cursor with a palette color slot
        colorSlot = (uint8_t)(uintptr_t)pMsg->pSender;
        this->paintColorIdx = colorSlot;
        if (colorSlot != 0)
        {
            this->paintColorIdx = dwWorkshopDroidEditor_aPaintColors[colorSlot];
            this->bCursorActive = 1;
            this->Invalidate();
            return 0;
        }
        // fall through (slot 0 = clear, same as 0x7ea)
    case 0x7ea: // paint mode off
        this->bCursorActive = 0;
        this->Invalidate();
        return 0;

    case 0x7d4: // toggle idle anims
        if (this->bIdleAnims != 0)
        {
            this->bIdleAnims = 0;
            for (pIter = dwCore_pWorkspaceNodes->pNext; pIter != dwCore_pWorkspaceNodes; pIter = pIter->pNext)
                ((dwPartNode*)pIter->pData)->StopAnim();
            msg.code = 0x7d6;
            msg.pSender = NULL;
            msg.param = 0;
            msg.pTarget = NULL;
            dwWidget_DispatchMsg(&msg, NULL);
        }
        else
        {
            this->RefreshPartAnims();
        }
        return 0;

    case 0x7d5: // dump every part (trash-all)
        if (dwCore_pWorkspaceNodes != dwCore_pWorkspaceNodes->pNext)
        {
            dwSound_PlayRestart("WDumpParts.wav");
            for (pIter = dwCore_pWorkspaceNodes->pNext; pIter != dwCore_pWorkspaceNodes; pIter = pIter->pNext)
            {
                if (pIter->pData != NULL)
                    delete (dwPartNode*)pIter->pData;
            }
            ((dwList*)&dwCore_pWorkspaceNodes)->FreeNodeRange(dwCore_pWorkspaceNodes->pNext, dwCore_pWorkspaceNodes);
            msg.code = 0x7dd;
            msg.pSender = NULL;
            msg.param = 0;
            msg.pTarget = NULL;
            dwWidget_DispatchMsg(&msg, NULL);
            msg.code = 0x7db;
            dwWidget_DispatchMsg(&msg, NULL);
        }
        return 0;

    case 0x7d6: // repaint requests
    case 0x7dc:
    case 0x7dd:
        this->Invalidate();
        return 0;

    case 0x7db: // reset the view (zoom/yaw/pitch home)
    case 0x7e4:
        msg.code = 0x3ea; // FOV/zoom percent (dwGui3DView)
        msg.pSender = (void*)(intptr_t)0x1004;
        msg.param = 0;
        msg.pTarget = NULL;
        dwWidget_DispatchMsg(&msg, NULL);
        msg.code = 0x3e9; // yaw 340
        msg.pSender = (void*)(intptr_t)0x154;
        dwWidget_DispatchMsg(&msg, NULL);
        msg.code = 0x3e8; // pitch 135
        msg.pSender = (void*)(intptr_t)0x87;
        dwWidget_DispatchMsg(&msg, NULL);
        return 0;

    case 0x7de: // yaw spin right (toggles off when already spinning)
        if (this->yawSpinDelta == 0.0f)
        {
            this->yawSpinAccum = 0.0f;
            this->yawSpinStart = this->yaw;
            this->yawSpinDelta = 90.0f;
        }
        else
        {
            this->yawSpinDelta = 0.0f;
        }
        return 0;
    case 0x7df: // yaw spin left
        if (this->yawSpinDelta == 0.0f)
        {
            this->yawSpinAccum = 0.0f;
            this->yawSpinStart = this->yaw;
            this->yawSpinDelta = -90.0f;
        }
        else
        {
            this->yawSpinDelta = 0.0f;
        }
        return 0;
    case 0x7e0: // pitch spin up
        if (this->pitchSpinDelta == 0.0f)
        {
            this->pitchSpinAccum = 0.0f;
            this->pitchSpinStart = this->pitch;
            this->pitchSpinDelta = 90.0f;
        }
        else
        {
            this->pitchSpinDelta = 0.0f;
        }
        return 0;
    case 0x7e1: // pitch spin down
        if (this->pitchSpinDelta == 0.0f)
        {
            this->pitchSpinAccum = 0.0f;
            this->pitchSpinStart = this->pitch;
            this->pitchSpinDelta = -90.0f;
        }
        else
        {
            this->pitchSpinDelta = 0.0f;
        }
        return 0;

    case 0x7e3: // toggle active ("dance") anims
        this->bActiveAnims = (this->bActiveAnims == 0) ? 1 : 0;
        if (this->bIdleAnims != 0)
            this->RefreshPartAnims();
        return 0;

    default:
        return this->dwGuiViewBox::OnMessage(pMsg);
    }
}

// ---- picking / drag ---------------------------------------------------------------

// @40d180 (dwWorkshopDroidEditor_RefreshPartAnims)
void dwWorkshopDroidEditor::RefreshPartAnims()
{
    dwListNode* pIter;
    dwPartNode* pNode;

    this->bIdleAnims = 1;
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

// @40d740 (dwWorkshopDroidEditor_RaycastPickNode)
dwPartNode* dwWorkshopDroidEditor::RaycastPickNode(dwPoint* pPt, rdRaycastHit* pHit)
{
    dwListNode* pIter;
    dwPartNode* pHitNode;
    rdVector3 world;
    rdVector3 dir;

    pHitNode = NULL;
    this->ScreenToWorld(pPt, &world);
    dir.x = world.x - this->viewMat.scale.x;
    dir.y = world.y - this->viewMat.scale.y;
    dir.z = world.z - this->viewMat.scale.z;
    rdVector_Normalize3Acc(&dir);
    for (pIter = dwCore_pWorkspaceNodes->pNext; pIter != dwCore_pWorkspaceNodes; pIter = pIter->pNext)
    {
        // The hit record keeps improving across parts — the last hit is the nearest.
        if (((dwPartNode*)pIter->pData)->RaycastHit(&this->viewMat.scale, &dir, pHit))
            pHitNode = (dwPartNode*)pIter->pData;
    }
    return pHitNode;
}

// @40d7f0 (dwWorkshopDroidEditor_BeginDragOrDetach)
int dwWorkshopDroidEditor::BeginDragOrDetach(dwPoint* pPt)
{
    dwPartNode* pNode;
    dwPartNode* pChild;
    rdRaycastHit hit;
    dwWidgetMsg msg;
    int i;

    hit.pMesh = NULL;
    hit.pFace = NULL;
    hit.distance = 3.4e38f;
    this->pDraggedNode = this->RaycastPickNode(pPt, &hit);
    if (this->pDraggedNode != NULL)
    {
        this->bDragStarted = 0;
        msg.code = 0x7d0; // selection changed
        msg.pSender = this->pDraggedNode->pPart;
        msg.param = (int32_t)(intptr_t)this->pDraggedNode;
        msg.pTarget = NULL;
        dwWidget_DispatchMsg(&msg, NULL);

        pNode = this->pDraggedNode;
        if (pNode->pPart->type == DW_PARTTYPE_TORSO)
        {
            // A torso drags its parent assembly instead.
            if (pNode->pAttachData != NULL)
                this->pDraggedNode = pNode->pAttachData;
        }
        else if (pNode->pPart->type == DW_PARTTYPE_LOCOMOTION)
        {
            // A chassis leaves its torso children in place.
            for (i = 0; i < pNode->slotCount; i++)
            {
                pChild = pNode->aSlots[i].pChild;
                if (pChild != NULL && pChild->pPart->type == DW_PARTTYPE_TORSO)
                {
                    pChild->DetachFromSlot();
                    dwSound_PlayRestart("WPartDetach.wav");
                }
            }
        }
        else
        {
            // Note: the binary's DetachFromSlot leaks its "was attached" flag
            // in AL and this caller tests it; the repo method is void, so the
            // same condition is evaluated up front.
            int bWasAttached = (pNode->partType != DW_PARTTYPE_NONE && pNode->pAttachSlot != NULL);
            pNode->DetachFromSlot();
            if (bWasAttached)
                dwSound_PlayRestart("WPartDetach.wav");
        }

        this->dragGrab = hit.worldHitPos;
        this->pDraggedNode->SetDrawFlag2Rec();
        this->dragTimerTick = dwMain_pHS->getTimerTick();
        this->bBlinkPhase = 1;
        msg.code = 0x7d6;
        msg.pSender = NULL;
        msg.param = 0;
        msg.pTarget = NULL;
        dwWidget_DispatchMsg(&msg, NULL);
    }
    return this->pDraggedNode != NULL;
}

// @40d950 (dwWorkshopDroidEditor_DropDraggedPart)
void dwWorkshopDroidEditor::DropDraggedPart(dwPoint* pPt)
{
    dwListNode* pIter;
    dwPartNode* pDragged;
    dwPartNode* pOther;
    dwPartNode* pPicked;
    dwPartNode* pTarget;
    dwPartNode* pBestNode;
    dwPartSlot* pBestSlot;
    rdVector3 pos;
    rdVector3 mountScreen;
    rdVector3 slotScreen;
    rdRaycastHit hit;
    dwWidgetMsg msg;
    const char* pSound;
    float bestDist, dist, dx, dy;
    uint16_t capacity;
    int i, bAttached, bNearMiss;

    // Refresh the dragged part's pose (joint matrices) before slot math.
    rdAdvanceFrame();
    this->pDraggedNode->Draw();
    rdFinishFrame();

    pSound = "WDropPart.wav";
    if (!dwRect_ContainsPoint(this->GetRectPtr(), pPt->x, pPt->y)
        || dwRect_ContainsPoint(&this->trashRect, pPt->x, pPt->y))
    {
        // Outside the view or in the trash: destroy the subtree.
        dwWorkshopDroidEditor_DestroyPartSubtree(this->pDraggedNode);
        this->pDraggedNode = NULL;
        pSound = "WDumpParts.wav";
        msg.code = 0x7dd;
        msg.pSender = NULL;
        msg.param = 0;
        msg.pTarget = NULL;
        dwWidget_DispatchMsg(&msg, NULL);
        if (dwCore_pWorkspaceNodes == dwCore_pWorkspaceNodes->pNext)
        {
            msg.code = 0x7db; // workspace emptied
            dwWidget_DispatchMsg(&msg, NULL);
        }
    }
    else if (this->pDraggedNode->pPart->type == DW_PARTTYPE_BATTERY)
    {
        // Batteries are consumed: charge the assembly under the drop point.
        capacity = this->pDraggedNode->pPart->battery;
        dwWorkshopDroidEditor_DestroyPartSubtree(this->pDraggedNode);
        this->pDraggedNode = NULL;
        hit.pMesh = NULL;
        hit.pFace = NULL;
        hit.distance = 3.4e38f;
        pPicked = this->RaycastPickNode(pPt, &hit);
        pTarget = dwWorkshopDroidEditor_FindBatteryTarget(pPicked);
        if (pTarget != NULL
            && (int)capacity <= (int)pTarget->pPart->battery - (int)(uint16_t)pTarget->slotIdx16)
        {
            msg.code = 0x7d0;
            msg.pSender = pPicked->pPart;
            msg.param = (int32_t)(intptr_t)pPicked;
            msg.pTarget = NULL;
            dwWidget_DispatchMsg(&msg, NULL);
            pTarget->slotIdx16 = (int16_t)(pTarget->slotIdx16 + capacity); // battery charge (see dwPart.h)
            pSound = "WAttachBattery.WAV";
        }
        msg.code = 0x7dc;
        msg.pSender = NULL;
        msg.param = 0;
        msg.pTarget = NULL;
        dwWidget_DispatchMsg(&msg, NULL);
    }
    else
    {
        pDragged = this->pDraggedNode;
        bNearMiss = 0;
        bAttached = 0;

        // Pass 1: attach the dragged part's MOUNT into the nearest compatible
        // free slot of another node (within 10 screen px).
        if (pDragged->partType != DW_PARTTYPE_NONE)
        {
            pBestNode = NULL;
            pBestSlot = NULL;
            bestDist = 3.4e38f;
            dwWorkshopDroidEditor_GetMountPosition(pDragged, &pos);
            this->ProjectPoint(&mountScreen, &pos);
            for (pIter = dwCore_pWorkspaceNodes->pNext; pIter != dwCore_pWorkspaceNodes; pIter = pIter->pNext)
            {
                pOther = (dwPartNode*)pIter->pData;
                if (pOther == this->pDraggedNode)
                    continue;
                for (i = 0; i < pOther->slotCount; i++)
                {
                    pOther->GetSlotPosition(&pOther->aSlots[i], &pos);
                    this->ProjectPoint(&slotScreen, &pos);
                    dx = slotScreen.x - mountScreen.x;
                    dy = slotScreen.y - mountScreen.y;
                    dist = sqrtf(dx * dx + dy * dy);
                    if (dist < bestDist)
                    {
                        bNearMiss = 1; // binary latches this before the free/compat tests
                        if (pOther->aSlots[i].pChildTypePtr == NULL
                            && dwWorkshopDroidEditor_TypesCompatible(pDragged->partType, pOther->aSlots[i].type))
                        {
                            pBestNode = pOther;
                            pBestSlot = &pOther->aSlots[i];
                            bestDist = dist;
                        }
                    }
                }
            }
            if (pBestNode != NULL && pBestSlot != NULL && bestDist < 10.0f)
            {
                this->pDraggedNode->AttachToSlot(pBestNode, pBestSlot);
                bAttached = 1;
            }
        }

        // Pass 2: pull nearby unattached parts into the dragged part's own
        // free slots (nearest compatible mount within 10 screen px per slot).
        for (i = 0; i < this->pDraggedNode->slotCount; i++)
        {
            if (this->pDraggedNode->aSlots[i].pChildTypePtr != NULL)
                continue;
            this->pDraggedNode->GetSlotPosition(&this->pDraggedNode->aSlots[i], &pos);
            this->ProjectPoint(&mountScreen, &pos);
            pBestNode = NULL;
            bestDist = 3.4e38f;
            for (pIter = dwCore_pWorkspaceNodes->pNext; pIter != dwCore_pWorkspaceNodes; pIter = pIter->pNext)
            {
                pOther = (dwPartNode*)pIter->pData;
                if (pOther == this->pDraggedNode)
                    continue;
                if (pOther->partType == DW_PARTTYPE_NONE || pOther->pAttachSlot != NULL)
                    continue;
                bNearMiss = 1; // binary latches per candidate examined
                if (!dwWorkshopDroidEditor_TypesCompatible(pOther->partType, this->pDraggedNode->aSlots[i].type))
                    continue;
                dwWorkshopDroidEditor_GetMountPosition(pOther, &pos);
                this->ProjectPoint(&slotScreen, &pos);
                dx = slotScreen.x - mountScreen.x;
                dy = slotScreen.y - mountScreen.y;
                dist = sqrtf(dx * dx + dy * dy);
                if (dist < bestDist)
                {
                    pBestNode = pOther;
                    bestDist = dist;
                }
            }
            if (pBestNode != NULL && bestDist < 10.0f)
            {
                pBestNode->AttachToSlot(this->pDraggedNode, &this->pDraggedNode->aSlots[i]);
                bAttached = 1;
            }
        }

        if (bAttached)
            pSound = "WPartAttach.wav";
        else if (bNearMiss)
            pSound = "WBadAttach.wav";

        this->pDraggedNode->SetDrawFlag4Rec(); // back to full draw
        this->pDraggedNode = NULL;
        if (this->bIdleAnims != 0)
            this->RefreshPartAnims();
        msg.code = 0x7dc;
        msg.pSender = NULL;
        msg.param = 0;
        msg.pTarget = NULL;
        dwWidget_DispatchMsg(&msg, NULL);
    }

    if (pSound != NULL)
        dwSound_PlayRestart(pSound);
}

// @40dfc0 (dwWorkshopDroidEditor_PaintPickedPart)
int dwWorkshopDroidEditor::PaintPickedPart(dwPoint* pPt)
{
    dwPartNode* pPicked;
    rdRaycastHit hit;
    dwWidgetMsg msg;
    void* pPixels;
    int stride;
    uint8_t color;

    hit.pMesh = NULL;
    hit.pFace = NULL;
    hit.distance = 3.4e38f;
    pPicked = this->RaycastPickNode(pPt, &hit);
    if (pPicked == NULL || this->paintColorIdx == 0)
        return 0;

    msg.code = 0x7d0; // selection changed
    msg.pSender = pPicked->pPart;
    msg.param = (int32_t)(intptr_t)pPicked;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);

    // Render the picked part UNLIT into the pick buffer and sample the pixel.
    if (!(rdGetRenterOptions() & 0x100))
        stdDisplay_VBufferFill(rdCamera_g_pCurCamera->pCanvas->d3d_vbuf, 0, NULL);
    rdCamera_SetCurrent(&this->camera);
    rdCamera_Update(&this->viewMat);
    rdSetGeometryMode(4);
    rdSetLightingMode(0);
    rdAdvanceFrame();
    pPicked->UpdateTransform();
    rdFinishFrame();

    color = 0;
    pPixels = NULL;
    stride = 0;
    // Note: the binary locks unconditionally; NULL guards added (the screen
    // image is a display-lifetime object and Lock can fail).
    if (dwDisplay_pScreenImage != NULL
        && dwDisplay_pScreenImage->Lock(&pPixels, &stride) && pPixels != NULL)
    {
        color = ((uint8_t*)pPixels)[(int)pPt->x + (int)pPt->y * stride];
        dwDisplay_pScreenImage->Unlock();
    }

    // Restore: redraw the part normally (Gouraud).
    if (!(rdGetRenterOptions() & 0x100))
        stdDisplay_VBufferFill(rdCamera_g_pCurCamera->pCanvas->d3d_vbuf, 0, NULL);
    rdSetGeometryMode(4);
    rdSetLightingMode(3);
    rdAdvanceFrame();
    pPicked->Draw();
    rdFinishFrame();

    // Colors 0..4 are reserved (background/markers); anything else paints.
    if (color != 0 && color > 4)
    {
        pPicked->CollectContacts(color, this->paintColorIdx);
        dwSound_PlayRestart("WPaintApply.wav");
    }

    msg.code = 0x7d6;
    msg.pSender = NULL;
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);
    return 1;
}

// ---- paint/draw -----------------------------------------------------------------

// @40e770 (dwWorkshopDroidEditor_Draw)
void dwWorkshopDroidEditor::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    dwListNode* pIter;
    dwPartNode* pNode;
    rdVector3 pos;
    uint8_t color;
    int mountCompatType; // dragged part type a free MOUNT must match to blink
    int slotCompatType;  // dragged part type a free SLOT must match to blink
    int slotType, halfSize, bCompat;
    int i;

    this->EnsureImages(); // virtual +0x3c
    this->dwGui3DView::Draw(pDestBits, pClipRect); // camera bring-up (binary: direct call @43b2b0)

    // Added: software-renderer bracket (shared — dwGui3DView_BeginSwRender/
    // EndSwRender; the original inline version documented here is in dwGui3DView.cpp).
    int swSavedAccel = 0;
    rdCanvas* pSwCanvas = dwGui3DView_BeginSwRender(&swSavedAccel);
    rdSetGeometryMode(4);

    if (this->bInTrashZone != 0 && this->pDraggedNode != NULL && this->pTrashImage != NULL)
        this->pTrashImage->Blit(pDestBits, this->trashRect.left, this->trashRect.top, pClipRect);

    for (pIter = dwCore_pWorkspaceNodes->pNext; pIter != dwCore_pWorkspaceNodes; pIter = pIter->pNext)
    {
        pNode = (dwPartNode*)pIter->pData;
        if (pNode->partType == DW_PARTTYPE_NONE || pNode->pAttachSlot == NULL)
            pNode->Draw(); // roots/detached only — Draw recurses attached children
    }
    dwGui3DView_EndSwRender(pSwCanvas, swSavedAccel);

    // Which markers blink for the dragged part (0xb never matches anything real).
    mountCompatType = DW_PARTTYPE_NONE;
    slotCompatType = DW_PARTTYPE_NONE;
    if (this->pDraggedNode != NULL)
    {
        slotCompatType = this->pDraggedNode->pPart->type;
        if (slotCompatType == DW_PARTTYPE_LOCOMOTION)
        {
            mountCompatType = DW_PARTTYPE_TORSO; // dragging a chassis: torso MOUNTS blink
            slotCompatType = DW_PARTTYPE_NONE;
        }
        else if (slotCompatType == DW_PARTTYPE_TORSO)
        {
            slotCompatType = DW_PARTTYPE_NONE; // faithful: nothing blinks for a torso
        }
    }

    for (pIter = dwCore_pWorkspaceNodes->pNext; pIter != dwCore_pWorkspaceNodes; pIter = pIter->pNext)
    {
        pNode = (dwPartNode*)pIter->pData;

        // Free attach-slot markers (size 6).
        for (i = 0; i < pNode->slotCount; i++)
        {
            if (pNode->aSlots[i].pChildTypePtr != NULL)
                continue;
            slotType = pNode->aSlots[i].type;
            color = dw_aPartSlotColors[slotType];
            if (slotType == DW_PARTTYPE_TORSO)
                color = dw_aPartSlotColors[5];
            bCompat = dwWorkshopDroidEditor_TypesCompatible(slotCompatType, slotType);
            if (bCompat && this->bBlinkPhase == 0)
                continue; // blink-off phase
            pNode->GetSlotPosition(&pNode->aSlots[i], &pos);
            this->DrawMarker(pDestBits, &pos, 6, color, pClipRect);
        }

        // Unattached MOUNT marker (size 5; 7 for the dragged part itself).
        if (pNode->partType != DW_PARTTYPE_NONE && pNode->pAttachSlot == NULL)
        {
            bCompat = dwWorkshopDroidEditor_TypesCompatible(mountCompatType, pNode->pPart->type);
            if (!bCompat || this->bBlinkPhase != 0)
            {
                dwWorkshopDroidEditor_GetMountPosition(pNode, &pos);
                halfSize = (pNode == this->pDraggedNode) ? 7 : 5;
                color = dw_aPartSlotColors[pNode->partType];
                if (pNode->partType == DW_PARTTYPE_TORSO)
                    color = dw_aPartSlotColors[5];
                this->DrawMarker(pDestBits, &pos, (int16_t)halfSize, color, pClipRect);
            }
        }
    }
}

// @40eab0 (dwWorkshopDroidEditor_EnsureImages — was mislabeled dwDroidStats)
void dwWorkshopDroidEditor::EnsureImages()
{
    if (this->pTrashImage == NULL && this->trashImageName.length != 0)
        this->pTrashImage = dwImage_LoadFile(this->trashImageName.pBuffer); // NULL until stdBitmapRle2 (P8)
}

// @40eaf0 (dwWorkshopDroidEditor_FreeImages — was mislabeled dwDroidStats)
void dwWorkshopDroidEditor::FreeImages()
{
    if (this->pTrashImage != NULL)
    {
        delete this->pTrashImage; // virtual dtor (binary: vtbl slot 0, flags=1)
        this->pTrashImage = NULL;
    }
}

// @40eb10 (dwWorkshopDroidEditor_ContainsPoint — was mislabeled dwDroidStats)
int dwWorkshopDroidEditor::ContainsPoint(dwPoint* pPt)
{
    if (this->pDraggedNode == NULL)
        return dwRect_ContainsPoint(this->GetRectPtr(), pPt->x, pPt->y);
    return 1; // while dragging, the whole screen is ours (mouse capture)
}

// ---- module reset -----------------------------------------------------------------

// Note: no binary counterpart — the unit owns no module statics; kept for the
// project-wide soft-reset convention.
extern "C" void dwWorkshopDroidEditor_Startup(void)
{
}
