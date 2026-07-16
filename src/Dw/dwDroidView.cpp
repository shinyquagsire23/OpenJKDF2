// dwDroidView — the DroidWorks 3D droid-viewer widget (orbit dwGuiViewBox +
// mouse-capture ray-pick). See dwDroidView.h for the layout / slot map.
//
// Decompiled from DroidWorks.exe, unit range 0x426080-0x426d6f (the
// dwDroidView class only; the dwPartNode functions that share this binary
// range landed in dwPart.cpp — P5).
//
// Engine-call mapping (DW-binary label -> repo):
//   stdBitmapRle_FUN_00444d00 -> dwWidget_DispatchMsg
//   DAT_005542cc              -> rdCamera_g_pCurCamera
//   stdDisplay_FUN_004fe010   -> stdDisplay_VBufferFill (canvas->d3d_vbuf)
//   rd_FUN_0047ebd0/0047ebf0  -> rdAdvanceFrame / rdFinishFrame
//   rdGetRenterOptions bit 0x100 = pick-buffer render pass (skip the fill)
//
// No module statics — no dwDroidView_Startup needed (soft-reset rule).

#include "Dw/dwDroidView.h"

#include "Dw/dwPart.h"       // dwPartNode, DW_PARTTYPE_NONE
#include "Dw/dwList.h"       // dwListNode
#include "Dw/dwImageDraw.h"  // dwImageDraw_FrameRect
#include "Dw/dwColormap.h"   // dwColormap_greenIdx
#include "Dw/dwRect.h"       // dwRect_Clip

#include "jk.h"
#include "stdPlatform.h"
#include "Engine/rdCamera.h"
#include "Primitives/rdVector.h"  // has extern "C" guards
#include "Primitives/rdRaycast.h" // has extern "C" guards
// These engine headers have no extern "C" guards of their own — wrap here.
extern "C" {
#include "Engine/rdroid.h"
#include "Win95/stdDisplay.h"
#include "General/stdMath.h"
}

// dw-core workspace part-node list sentinel @0x53d984 (owner: dwMain, P7).
// TODO(dw-decomp): provided by dwMain.
extern "C" dwListNode* dwCore_pWorkspaceNodes;

// ================================ dwDroidView ===================================

// @426080 (Ghidra: dwDroidView_Ctor). Binary ctor arg order: (pRect, dwUnused,
// fovPct); the middle argument is dead (kept only so the PANCONTROL factory
// call reads literally).
dwDroidView::dwDroidView(dwRect* pRect, int /*dwUnused*/, int fovPct)
    : dwGuiViewBox(pRect, 0)
{
    this->bMouseCaptured = 0;
    this->lastPickX = 0;
    this->lastPickY = 0;
    // (the compiler installs dwDroidView's vtable here)

    // Apply the FOV to THIS view's camera (base handles 0x3ea) AND broadcast
    // it to the active screen — the binary does both.
    dwWidgetMsg msg;
    msg.code = 0x3ea;
    msg.pSender = (void*)(intptr_t)fovPct;
    msg.param = 0;
    msg.pTarget = NULL;
    this->dwGuiViewBox::OnMessage(&msg); // direct base call (binary CALL 0x434920)
    dwWidget_DispatchMsg(&msg, NULL);    // broadcast to dwWidget_pDefault

    this->tanFovX = (float)fovPct * 0.01f;
    this->tanFovY = (float)fovPct * 0.01f;
    this->lastPickX = (int16_t)(((int)pRect->left + (int)pRect->right) / 2);
    this->lastPickY = (int16_t)(((int)pRect->top + (int)pRect->bottom) / 2);
    this->pickResult.x = 0.0f;
    this->pickResult.y = 0.0f;
    this->pickResult.z = 0.0f;
}

// @426190 (Ghidra: dwDroidView_Dtor; DtorDelete @426170) — base dtor only.
dwDroidView::~dwDroidView()
{
}

// @4261d0 (Ghidra: dwDroidView_OnMouseMove) — vtbl +0x04.
int dwDroidView::OnMouseMove(int16_t x, int16_t y)
{
    if (this->bMouseCaptured != 0)
    {
        dwPoint pt;
        pt.x = x;
        pt.y = y;
        this->PickPart(&pt, 1);
    }
    return this->bMouseCaptured;
}

// @426210 (Ghidra: dwDroidView_OnMouseDown) — vtbl +0x08.
int dwDroidView::OnMouseDown(int16_t x, int16_t y)
{
    bool bWasFree = (this->bMouseCaptured == 0);
    if (bWasFree)
    {
        this->bMouseCaptured = 1;
        dwWidget_pMouseTarget = this;
        this->OnMouseMove(x, y); // virtual (binary CALL vtable+0x04)
    }
    return bWasFree ? 1 : 0;
}

// @426240 (Ghidra: dwDroidView_OnMouseUp) — vtbl +0x0c. Binary leaves EAX
// undefined; return 0 (the message pump ignores the result).
int dwDroidView::OnMouseUp(int16_t /*x*/, int16_t /*y*/)
{
    if (this->bMouseCaptured != 0)
    {
        this->bMouseCaptured = 0;
        if (dwWidget_pMouseTarget == this)
            dwWidget_pMouseTarget = NULL;
    }
    return 0;
}

// @4261a0 (Ghidra: dwDroidView_OnHover) — vtbl +0x18. Dispatch the shared
// { 0x7531, id } hover notification (id 0x3eb) to pDefault.
int dwDroidView::OnHover(int16_t /*x*/, int16_t /*y*/)
{
    return this->OnHoverNotify((void*)0x3eb);
}

// @426270 (Ghidra: dwDroidView_OnMessage) — vtbl +0x1c.
int dwDroidView::OnMessage(dwWidgetMsg* pMsg)
{
    uint32_t code = (uint32_t)pMsg->code;

    if (code == 0x3ea) // FOV change: update the pick-FOV and re-pick
    {
        int fovVal = (int)(intptr_t)pMsg->pSender;
        this->tanFovY = (float)fovVal * 0.01f;

        // Re-project the current pick point to the screen (using the camera's
        // existing FOV — 0x3ea is deliberately NOT forwarded to the base here)
        // and re-pick there.
        rdVector3 screen;
        this->ProjectPoint(&screen, &this->pickResult);
        dwPoint pt;
        pt.x = (int16_t)(int)(screen.x + 0.5f); // binary: FSUB -0.5, then __ftol
        pt.y = (int16_t)(int)(screen.y + 0.5f);
        this->PickPart(&pt, 0);

        this->Invalidate(); // vtbl +0x34
        return 0;
    }
    if (code == 0x3eb) // pivot-recenter (our own broadcast) — swallowed here
        return 0;
    if (code == 0x7d6 || code == 0x7dc || code == 0x7dd)
    {
        this->Invalidate(); // vtbl +0x34
        return 0;
    }
    return this->dwGuiViewBox::OnMessage(pMsg);
}

// @426370 (Ghidra: dwDroidView_ClampRectToView).
bool dwDroidView::ClampRectToView(dwRect* pRect)
{
    int16_t dRight = this->right - pRect->right;
    if (dRight < 0)
    {
        pRect->left = (int16_t)(pRect->left + dRight);
        pRect->right = (int16_t)(pRect->right + dRight);
    }
    int16_t dBottom = this->bottom - pRect->bottom;
    if (dBottom < 0)
    {
        pRect->top = (int16_t)(pRect->top + dBottom);
        pRect->bottom = (int16_t)(pRect->bottom + dBottom);
    }
    int16_t dLeft = this->left - pRect->left;
    if (0 < dLeft)
    {
        pRect->left = (int16_t)(pRect->left + dLeft);
        pRect->right = (int16_t)(pRect->right + dLeft);
    }
    int16_t dTop = this->top - pRect->top;
    if (0 < dTop)
    {
        pRect->top = (int16_t)(pRect->top + dTop);
        pRect->bottom = (int16_t)(pRect->bottom + dTop);
    }
    return (0 < dTop) || (0 < dLeft) || (dBottom < 0) || (dRight < 0);
}

// @4263f0 (Ghidra: dwDroidView_PickPart).
void dwDroidView::PickPart(dwPoint* pPoint, uint8_t bForce)
{
    dwRect rect;
    rect.left = 0;
    rect.top = 0;
    rect.right = 0;
    rect.bottom = 0;
    this->ComputeViewExtents(pPoint, &rect);
    bool bClamped = this->ClampRectToView(&rect);
    if (!bClamped && bForce == 0)
        return;

    int16_t cx = (int16_t)(((int)rect.left + (int)rect.right) / 2);
    int16_t cy = (int16_t)(((int)rect.top + (int)rect.bottom) / 2);
    if (cx == this->lastPickX && cy == this->lastPickY)
        return;

    dwPoint center;
    center.x = cx;
    center.y = cy;
    rdVector3 world;
    this->ScreenToWorld(&center, &world);

    rdVector3 dir;
    dir.x = world.x - this->viewMat.scale.x;
    dir.y = world.y - this->viewMat.scale.y;
    dir.z = world.z - this->viewMat.scale.z;
    rdVector_Normalize3Acc(&dir);

    rdVector3 planePoint;
    planePoint.x = 0.0f;
    planePoint.y = 0.0f;
    planePoint.z = 0.0f;
    rdVector3 planeNormal;
    planeNormal.x = -this->viewMat.lvec.x;
    planeNormal.y = -this->viewMat.lvec.y;
    planeNormal.z = -this->viewMat.lvec.z;

    rdRaycastHit hit;
    hit.pMesh = NULL;
    hit.pFace = NULL;
    hit.distance = 3.4e38f;
    rdRaycast_RayPlane(&this->viewMat.scale, &dir, &planePoint, &planeNormal, &hit);

    // Broadcast a pivot-recenter to the picked world point (targets pDefault).
    dwWidgetMsg msg;
    msg.code = 0x3eb;
    msg.pSender = &hit.worldHitPos;
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);

    this->pickResult = hit.worldHitPos;
    this->lastPickX = cx;
    this->lastPickY = cy;
    this->Invalidate(); // vtbl +0x34
}

// @426590 (Ghidra: dwDroidView_ComputeViewExtents). Screen-space pick rect =
// the widget rect (minus a 2px inset) scaled by tan(tanFovY/2)/tan(tanFovX/2),
// centered on *pPoint.
void dwDroidView::ComputeViewExtents(dwPoint* pPoint, dwRect* pOut)
{
    float tanX = (float)stdMath_Tan(this->tanFovX * 0.5f);
    float tanY = (float)stdMath_Tan(this->tanFovY * 0.5f);
    float ratio = tanY / tanX;
    int w = (int)(int16_t)(this->right - this->left);
    int h = (int)(int16_t)(this->bottom - this->top);
    float halfW = (float)(w - 2) * 0.5f * ratio;
    float halfH = (float)(h - 2) * 0.5f * ratio;
    float px = (float)pPoint->x;
    float py = (float)pPoint->y;
    pOut->left   = (int16_t)(int)(px - halfW);
    pOut->right  = (int16_t)(int)(px + halfW);
    pOut->top    = (int16_t)(int)(py - halfH);
    pOut->bottom = (int16_t)(int)(py + halfH);
}

// @426690 (Ghidra: dwDroidView_Draw) — vtbl +0x44.
void dwDroidView::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    this->dwGui3DView::Draw(pDestBits, pClipRect); // camera bring-up (binary CALL 0x43b2b0)

    if (!(rdGetRenterOptions() & 0x100))
        stdDisplay_VBufferFill(rdCamera_g_pCurCamera->pCanvas->d3d_vbuf, 0, NULL);
    rdAdvanceFrame();
    rdSetLightingMode(0);
    rdSetGeometryMode(3);

    for (dwListNode* pIter = dwCore_pWorkspaceNodes->pNext;
         pIter != dwCore_pWorkspaceNodes; pIter = pIter->pNext)
    {
        dwPartNode* pNode = (dwPartNode*)pIter->pData;
        if (pNode->partType == DW_PARTTYPE_NONE || pNode->pAttachSlot == NULL)
            pNode->DrawHighlighted();
    }
    rdFinishFrame();

    // Green pick-selection frame around the last picked point.
    dwRect pickRect;
    pickRect.left = 0;
    pickRect.top = 0;
    pickRect.right = 0;
    pickRect.bottom = 0;
    this->ComputeViewExtents((dwPoint*)&this->lastPickX, &pickRect);
    dwRect_Clip(&pickRect, this->GetRectPtr());
    dwImageDraw_FrameRect(pDestBits, &pickRect, dwColormap_greenIdx, this->GetRectPtr());
}

// ---- C FFI factory ----------------------------------------------------------

// Added: see dwDroidView.h.
extern "C" dwWidget* dwDroidView_New(dwRect* pRect, int dwUnused, int fovPct)
{
    return new dwDroidView(pRect, dwUnused, fovPct);
}
