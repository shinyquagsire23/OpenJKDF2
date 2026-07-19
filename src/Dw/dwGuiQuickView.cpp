// dwGuiQuickView — the DroidWorks 3D droid-model preview widget, plus its
// dwGuiDroidPreview subclass. See dwGuiQuickView.h for the layout / slot map.
//
// Decompiled from DroidWorks.exe, unit range 0x429a80-0x42a5xx.
//
// Engine-call mapping (DW-binary label -> repo):
//   stdBitmapRle_FUN_00444d00 -> dwWidget_DispatchMsg
//   DAT_005542cc              -> rdCamera_g_pCurCamera
//   stdDisplay_FUN_004fe010   -> stdDisplay_VBufferFill (canvas->d3d_vbuf)
//   rd_FUN_0047ebd0/0047ebf0  -> rdAdvanceFrame / rdFinishFrame
//   idk_alloc(0xc)            -> malloc(sizeof(dwListNode))  (list sentinel/node)
//   stdPlatform_FreeHandle    -> free / delete (per the freed object)
//
// No module statics — no dwGuiQuickView_Startup needed (soft-reset rule).

#include "Dw/dwGuiQuickView.h"

#include "Dw/dwPart.h"          // dwPart / dwPartNode, dwPart_FindBlueprint
#include "Dw/dwList.h"          // dwList / dwListNode
#include "Dw/dwImage.h"         // dwImageBits
#include "Dw/dwImageVBuf.h"     // dwDisplay_pScreenImage's concrete class (Lock/Unlock/desc)
#include "Dw/dwDisplay.h"       // dwDisplay_pScreenImage
#include "Dw/dwRect.h"          // dwRect_Set
#include "Dw/dwGuiWidgets.h"    // dwGuiWidgets_LoadDroidFromFile
#include "Dw/dwGuiMission.h"    // dwGuiDialog_RunModal
#include "Dw/dwString.h"        // dwString_Equals

#include "jk.h"
#include "stdPlatform.h"
#include "Engine/rdCamera.h"
#include "Primitives/rdVector.h"  // has extern "C" guards
// These engine headers have no extern "C" guards of their own — wrap here.
extern "C" {
#include "Engine/rdroid.h"
#include "Win95/stdDisplay.h"
#include "General/stdMath.h"
}

#include <stdlib.h> // malloc/free

// dw-core workspace part-node list sentinel @0x53d984 (owner: dwMain, P7).
// TODO(dw-decomp): provided by dwMain.
extern "C" dwListNode* dwCore_pWorkspaceNodes;

// Clear a QuickView node list: unlink+free every node AND delete its owned
// dwPartNode payload (the binary inlines this loop in the dtor / OnMessage).
static void dwGuiQuickView_ClearNodes(dwListNode* pSentinel)
{
    for (dwListNode* pIter = pSentinel->pNext; pIter != pSentinel; )
    {
        dwListNode* pNext = pIter->pNext;
        dwPartNode* pPayload = (dwPartNode*)pIter->pData;
        ((dwList*)&pSentinel)->UnlinkFreeNode(pIter); // unlink + free the node
        if (pPayload != NULL)
            delete pPayload; // binary: dwPartNode_Dtor + free
        pIter = pNext;
    }
}

// ================================ dwGuiQuickView ================================

// @429c90 (Ghidra: dwGuiQuickView_Ctor). Lights follow the view.
dwGuiQuickView::dwGuiQuickView(dwRect* pRect)
    : dwGuiViewBox(pRect, 1), name(), rotTimer(0.0f), pNodes(NULL)
{
    // Own droid list: a self-linked heap sentinel (binary idk_alloc(0xc)).
    this->pNodes = (dwListNode*)malloc(sizeof(dwListNode));
    this->pNodes->pNext = this->pNodes;
    this->pNodes->pPrev = this->pNodes;
    this->LayoutNodes();
}

// @429d50 (Ghidra: dwGuiQuickView_Dtor; DtorDelete @429d30).
dwGuiQuickView::~dwGuiQuickView()
{
    dwGuiQuickView_ClearNodes(this->pNodes);
    free(this->pNodes);
    this->name.Free();
    // (base dtor runs automatically)
}

// @429e80 (Ghidra: dwGuiQuickView_Update) — vtbl +0x14. Auto-rotate: broadcast
// a set-pitch message with the accumulated angle to the active screen.
void dwGuiQuickView::Update(float dt)
{
    this->rotTimer += dt;
    int angle = ((int)((float)this->rotTimer * 45.0f + 0.5f) + 180) % 360;

    dwWidgetMsg msg;
    msg.code = 0x3e8; // set pitch/elevation angle (handled by dwGuiViewBox)
    msg.pSender = (void*)(intptr_t)angle;
    msg.param = 0;
    msg.pTarget = NULL;
    dwWidget_DispatchMsg(&msg, NULL);
}

// @42a510 (Ghidra: dwGuiQuickView_OnHover) — vtbl +0x18.
int dwGuiQuickView::OnHover(int16_t /*x*/, int16_t /*y*/)
{
    return this->OnHoverNotify((void*)0x7922);
}

// @429ee0 (Ghidra: dwGuiQuickView_OnMessage) — vtbl +0x1c.
int dwGuiQuickView::OnMessage(dwWidgetMsg* pMsg)
{
    uint32_t code = (uint32_t)pMsg->code;

    if (code == 0xfa3) // load a droid from a .drd file (pSender = path or NULL)
    {
        const char* pFile = (const char*)pMsg->pSender;
        if (pFile == NULL)
        {
            dwGuiQuickView_ClearNodes(this->pNodes);
            this->name.AssignCStr(""); // binary DAT_0053d6c4 = ""
        }
        else if (!dwString_Equals(this->name.pBuffer, pFile))
        {
            this->name.AssignCStr(pFile);
            dwGuiQuickView_ClearNodes(this->pNodes);
            if (!dwGuiWidgets_LoadDroidFromFile(pFile, NULL, (dwList*)&this->pNodes))
                dwGuiDialog_RunModal("gmessage", "DLG_MISSINGPART");
        }
        // (same-name path falls straight through to the relayout + repaint)

        this->LayoutNodes();

        // Eager repaint straight to the screen surface (the binary Locks the
        // screen image, virtual-Draws the whole view, and Unlocks).
        dwImageVBuf* pImg = dwDisplay_pScreenImage;
        if (pImg != NULL) // Note: guard added (binary assumes an open display)
        {
            dwImageBits bits;
            bits.pDesc = &pImg->desc; // binary: obj-as-desc alias
            bits.pPixels = NULL;
            bits.stride = 0;
            pImg->Lock(&bits.pPixels, &bits.stride); // vtbl +0x0c
            dwRect rect;
            int16_t w = 0, h = 0;
            if (stdDisplay_pCurVideoMode)
            {
                w = (int16_t)stdDisplay_pCurVideoMode->format.width;
                h = (int16_t)stdDisplay_pCurVideoMode->format.height;
            }
            dwRect_Set(&rect, 0, 0, w, h);
            this->Draw(&bits, &rect); // vtbl +0x44 (virtual)
            pImg->Unlock();           // vtbl +0x10
        }

        this->LayoutNodes();
        this->Invalidate(); // vtbl +0x34
    }
    else if (code >= 0x7d5 && code <= 0x7d6 && this->name.length == 0)
    {
        // Reflect a workspace change (only while showing the live workspace).
        this->LayoutNodes();
        this->Invalidate(); // vtbl +0x34
    }
    else if (code == 0xfa9) // commit our preview droid into the global workspace
    {
        // Delete the old workspace part nodes, then free their list nodes.
        for (dwListNode* pIter = dwCore_pWorkspaceNodes->pNext;
             pIter != dwCore_pWorkspaceNodes; pIter = pIter->pNext)
        {
            dwPartNode* p = (dwPartNode*)pIter->pData;
            if (p != NULL)
                delete p; // binary: dwPartNode_Dtor + free
        }
        ((dwList*)&dwCore_pWorkspaceNodes)->FreeNodeRange(
            dwCore_pWorkspaceNodes->pNext, dwCore_pWorkspaceNodes);

        // Move our nodes' payloads into the workspace (push-back; payloads shared).
        for (dwListNode* pIter = this->pNodes->pNext; pIter != this->pNodes;
             pIter = pIter->pNext)
        {
            ((dwList*)&dwCore_pWorkspaceNodes)->InsertAfter(
                dwCore_pWorkspaceNodes->pPrev, pIter->pData);
        }

        // Clear our list (nodes only — payloads were moved, not deleted).
        for (dwListNode* pIter = this->pNodes->pNext; pIter != this->pNodes; )
        {
            dwListNode* pNext = pIter->pNext;
            ((dwList*)&this->pNodes)->UnlinkFreeNode(pIter);
            pIter = pNext;
        }
    }

    return this->dwGuiViewBox::OnMessage(pMsg);
}

// @42a260 (Ghidra: dwGuiQuickView_Draw) — vtbl +0x44.
void dwGuiQuickView::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    this->dwGui3DView::Draw(pDestBits, pClipRect); // camera bring-up (binary CALL 0x43b2b0)

    // Added: software-renderer bracket (shared — without it the geometry takes
    // the GL path and the preview renders nothing).
    int swSavedAccel = 0;
    rdCanvas* pSwCanvas = dwGui3DView_BeginSwRender(&swSavedAccel);
    rdSetGeometryMode(4);

    // Own droid list, or the live workspace when ours is empty.
    dwListNode* pSentinel = this->pNodes;
    if (this->pNodes == this->pNodes->pNext)
        pSentinel = dwCore_pWorkspaceNodes;
    for (dwListNode* pIter = pSentinel->pNext; pIter != pSentinel; pIter = pIter->pNext)
    {
        dwPartNode* pNode = (dwPartNode*)pIter->pData;
        if (pNode->partType == DW_PARTTYPE_NONE || pNode->pAttachSlot == NULL)
            pNode->Draw();
    }
    dwGui3DView_EndSwRender(pSwCanvas, swSavedAccel);
}

// @42a320 (Ghidra: dwGuiQuickView_LayoutNodes).
void dwGuiQuickView::LayoutNodes()
{
    dwListNode* pSentinel = this->pNodes;
    if (this->pNodes == this->pNodes->pNext)
        pSentinel = dwCore_pWorkspaceNodes;

    rdVector3 vMin, vMax;
    rdVector_Set3(&vMin, 3.4e38f, 3.4e38f, 3.4e38f);
    rdVector_Set3(&vMax, -3.4e38f, -3.4e38f, -3.4e38f);
    for (dwListNode* pIter = pSentinel->pNext; pIter != pSentinel; pIter = pIter->pNext)
        ((dwPartNode*)pIter->pData)->DrawAt(&vMin, &vMax); // bbox accumulate (no pixels)

    // Largest axis extent of the droid's world-space bounding box.
    float extent = vMax.x - vMin.x;
    if (extent < vMax.y - vMin.y) extent = vMax.y - vMin.y;
    if (extent < vMax.z - vMin.z) extent = vMax.z - vMin.z;

    int height = (int)(int16_t)(this->bottom - this->top);
    int width  = (int)(int16_t)(this->right - this->left);
    int maxDim, minDim;
    if (height < width) { maxDim = width; minDim = height; }
    else                { maxDim = height; minDim = width; }

    float tanHalfFov = (float)stdMath_Tan(this->camera.fov * 0.5f);

    this->orbitDistance =
        (((float)maxDim / (float)minDim) * extent * 0.5f * 1.05f) / tanHalfFov;
    this->pivotX = (vMax.x + vMin.x) * 0.5f;
    this->pivotY = (vMax.y + vMin.y) * 0.5f;
    this->pivotZ = (vMax.z + vMin.z) * 0.5f;
    this->Refresh(); // vtbl +0x4c (the orbit rebuild)
}

// =============================== dwGuiDroidPreview ==============================

// @429a80 (Ghidra: dwGuiDroidPreview_Ctor).
dwGuiDroidPreview::dwGuiDroidPreview(dwRect* pRect, dwPart* pBlueprint)
    : dwGuiQuickView(pRect)
{
    // (compiler installs dwGuiDroidPreview's vtable here)
    if (pBlueprint != NULL)
    {
        dwPartNode* pNode = pBlueprint->CreateNode();
        ((dwList*)&this->pNodes)->InsertAfter(this->pNodes->pPrev, pNode); // push-back
        this->LayoutNodes();
    }
}

// @429b30 (Ghidra: dwGuiDroidPreview_Dtor; DtorDelete @429b10) — base dtor only.
dwGuiDroidPreview::~dwGuiDroidPreview()
{
}

// @429c60 (Ghidra: dwGuiDroidPreview_OnHover) — vtbl +0x18.
int dwGuiDroidPreview::OnHover(int16_t /*x*/, int16_t /*y*/)
{
    return this->OnHoverNotify((void*)0x7920);
}

// @429b40 (Ghidra: dwGuiDroidPreview_OnMessage) — vtbl +0x1c.
int dwGuiDroidPreview::OnMessage(dwWidgetMsg* pMsg)
{
    if (pMsg->code == 0xbbc && pMsg->pSender != NULL)
    {
        // The sender is the selected PART (dwPart*): its part type picks one of
        // its first three blueprint-name strings, which we look up + display.
        // NOTE: this couples to the sender's layout — the sender is produced by
        // dwGuiMissionMap (JAWA_ANIM) / dwGuiStatus (P6). Binary read is
        // byte @+8 (part type) and a char* @ +0x70 + variant*0xc (== dwPart::
        // type and dwPart::aAnimNames[variant].pBuffer); expressed here with
        // named dwPart members so it stays 64-bit-safe IF the sender is a dwPart.
        dwPart* pSender = (dwPart*)pMsg->pSender;

        dwGuiQuickView_ClearNodes(this->pNodes);

        uint32_t variant = (uint8_t)pSender->type;
        if (variant > 2)
            variant = 2;
        dwPart* pBp = dwPart_FindBlueprint(pSender->aAnimNames[variant].pBuffer);
        if (pBp != NULL)
        {
            dwPartNode* pNode = pBp->CreateNode();
            ((dwList*)&this->pNodes)->InsertAfter(this->pNodes->pPrev, pNode); // push-back
            this->LayoutNodes();
        }
    }
    return this->dwGuiQuickView::OnMessage(pMsg);
}

// ---- C FFI factories --------------------------------------------------------

// Added: see dwGuiQuickView.h.
extern "C" dwWidget* dwGuiQuickView_New(dwRect* pRect)
{
    return new dwGuiQuickView(pRect);
}

extern "C" dwWidget* dwGuiDroidPreview_New(dwRect* pRect, dwPart* pBlueprint)
{
    return new dwGuiDroidPreview(pRect, pBlueprint);
}
