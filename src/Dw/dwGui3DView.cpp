// dwGui3DView — the DroidWorks base 3D-view widget (embedded rdCanvas +
// rdCamera + two rdLights rendering into the DW back buffer).
//
// Decompiled from DroidWorks.exe, unit range 0x43ae40-0x43b4bf.
// vtable @0x51fef0. See dwGui3DView.h for the field/slot map.
//
// Engine mapping notes:
//  - The binary's `rdCanvas_New` label at the ctor call site is the engine's
//    rdCanvas_NewEntry (in-place init of the EMBEDDED canvas); the repo's
//    9th parameter (a9 -> field_14) is not visible in the 8-arg binary call,
//    so 0 is passed.
//  - rd_FUN_0047eb60(2) resolves to rdSetZBufferMethod (the DW rdroid setter
//    cluster @0x47eb00 mirrors src/Engine/rdroid.c's function order).
//  - The dtor's `sithRender_Open()` call is a mislabel: 0x504190 is an empty
//    ICF-folded COMDAT == rdCanvas_FreeEntry (a no-op in the engine too).
//  - rdMatrix_FUN_00486af0 == rdMatrix_TransformPoint34Acc (verified from its
//    body: in-place point transform incl. translation).
//  - DAT_006b5a40 (the canvas target tVBuffer) is the DW back buffer ==
//    dwDisplay_pBackVBuf; the d3d/scratch buffer slot gets dwDisplay_pSwBuffer.
//
// No module statics — no dwGui3DView_Startup needed (soft-reset rule).

#include "Dw/dwGui3DView.h"

#include "Dw/dwDisplay.h"
#include "Dw/dwImageDraw.h"

#include "jk.h"
#include "Engine/rdCamera.h"
#include "Engine/rdCanvas.h"
#include "Primitives/rdMatrix.h"
// This engine header has no extern "C" guards of its own — wrap at include site.
extern "C" {
#include "Engine/rdroid.h"
}

// ---- ctor/dtor -----------------------------------------------------------------

// @43ae40 (Ghidra: dwGui3DView_Ctor)
dwGui3DView::dwGui3DView(dwRect* pRect)
    : dwWidget(pRect)
{
    rdSetRenderOptions(rdGetRenterOptions() | 3);
    rdSetZBufferMethod(RD_ZBUFFER_READ_WRITE); // binary: rd_FUN_0047eb60(2)

    // In-place canvas over the DW back buffer, covering the widget rect
    // (binary: rdCanvas_NewEntry-equivalent call; a9/field_14 not present in
    // the 8-arg binary call — pass 0).
    rdCanvas_NewEntry(&this->canvas, 3, dwDisplay_pBackVBuf, dwDisplay_pSwBuffer,
                      pRect->left, pRect->top, pRect->right - 1, pRect->bottom - 1, 0);
    this->canvas.half_screen_width = (flex_t)(pRect->left + pRect->right) * 0.5;
    this->canvas.half_screen_height = (flex_t)(pRect->top + pRect->bottom) * 0.5;

    // Binary zeroes exactly the embedded camera before rdCamera_NewEntry
    // (0x119 dwords @+0x68).
    _memset(&this->camera, 0, sizeof(this->camera));
    rdCamera_NewEntry(&this->camera, 20.0, 0, 0.008, 50.0, 1.0);
    rdCamera_SetCanvas(&this->camera, &this->canvas);
    rdCamera_SetAmbientLight(&this->camera, 0.3);
    rdCamera_SetAttenuation(&this->camera, 1e-5, 1e-5);

    // Note: the binary leaves the two rdLights (and position vectors)
    // uninitialized heap garbage until SetLight0/1 fill pos/intensity/type
    // (id/radii are filled by rdCamera_AddLight). Zeroing here keeps the
    // untouched fields (bEnabled/direction/color) deterministic on 64-bit.
    _memset(&this->light0Pos, 0, sizeof(this->light0Pos));
    _memset(&this->light1Pos, 0, sizeof(this->light1Pos));
    _memset(&this->light0, 0, sizeof(this->light0));
    _memset(&this->light1, 0, sizeof(this->light1));
    // Note: viewMat is NOT initialized here (faithful) — dwGuiViewBox builds
    // it in its ctor; a bare dwGui3DView must not be drawn before someone
    // sets it.

    this->SetLight0(0.0f, -1.0f, -0.4f, 1.0f, 2);
    this->SetLight1(0.0f, -0.2f, 1.0f, 0.75f, 2);
    dwGui3DView::RebuildLights(); // binary: direct call (vtable is this class's here anyway)
    dwGui3DView::Refresh();       // binary: direct call
}

// @43afd0 (Ghidra: dwGui3DView_Dtor; DtorDelete @43afb0)
dwGui3DView::~dwGui3DView()
{
    rdCanvas_FreeEntry(&this->canvas); // binary: ICF-folded empty fn @0x504190 (mislabeled sithRender_Open)
    rdCamera_FreeEntry(&this->camera);
    // dwWidget base dtor runs automatically.
}

// ---- virtuals ------------------------------------------------------------------

// @43b000 (Ghidra: dwGui3DView_OnMessage) — vtbl +0x1c.
// Msg 0x3ea = set FOV/zoom; the numeric payload rides in the pSender slot
// (percent: fov = payload * 0.01).
int dwGui3DView::OnMessage(dwWidgetMsg* pMsg)
{
    if (pMsg->code == 0x3ea)
    {
        float newFov = (float)(uint32_t)(uintptr_t)pMsg->pSender * 0.01f;
        if (newFov != this->camera.fov)
        {
            // Re-sync the frustum to the WIDGET rect when the canvas cache
            // is stale (the canvas x/y/w/h fields double as a "last frustum
            // rect" cache in this class).
            rdCanvas* pCanvas = this->camera.pCanvas;
            if (pCanvas->xStart != this->left || pCanvas->yStart != this->top
                || pCanvas->widthMinusOne != this->right || pCanvas->heightMinusOne != this->bottom)
            {
                rdCamera_SetFrustrum(&this->camera, this->camera.pClipFrustum,
                                     this->left, this->top, this->right, this->bottom);
                pCanvas->xStart = this->left;
                pCanvas->yStart = this->top;
                pCanvas->widthMinusOne = this->right;
                pCanvas->heightMinusOne = this->bottom;
            }
            this->camera.fov = newFov;
            rdCamera_BuildFOV(&this->camera);
            this->Refresh(); // vtbl +0x4c
        }
    }
    return 0;
}

// @43b0f0 (Ghidra: dwGui3DView_Move; recovered fn) — vtbl +0x28
void dwGui3DView::Move(int16_t dx, int16_t dy)
{
    this->left = this->left + dx;
    this->top = this->top + dy;
    this->right = this->right + dx;
    this->bottom = this->bottom + dy;
    this->camera.pCanvas->half_screen_width = (flex_t)(this->right + this->left) * 0.5;
    this->camera.pCanvas->half_screen_height = (flex_t)(this->top + this->bottom) * 0.5;
}

// @43b2b0 (Ghidra: dwGui3DView_Draw) — vtbl +0x44. Camera bring-up only;
// draws no pixels (derived classes render content after calling this).
// pDestBits is unused (faithful).
void dwGui3DView::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    rdCamera_SetCurrent(&this->camera);
    rdCamera_Update(&this->viewMat);

    rdCanvas* pCanvas = this->camera.pCanvas;
    int x1 = (int16_t)(pClipRect->left + 1);
    int y1 = (int16_t)(pClipRect->top + 1);
    int x2 = pClipRect->right;
    int y2 = pClipRect->bottom;
    if (pCanvas->xStart != x1 || pCanvas->yStart != y1
        || pCanvas->widthMinusOne != x2 || pCanvas->heightMinusOne != y2)
    {
        rdCamera_SetFrustrum(&this->camera, this->camera.pClipFrustum, x1, y1, x2, y2);
        pCanvas->xStart = x1;
        pCanvas->yStart = y1;
        pCanvas->widthMinusOne = x2;
        pCanvas->heightMinusOne = y2;
    }
    rdSetLightingMode(3); // RD_LIGHTMODE_GOURAUD
}

// @43b370 (Ghidra: dwGui3DView_RebuildLights) — vtbl +0x48 (NEW virtual).
// Re-adds each light whose |intensity| > 1e-5 (quirk preserved: a NEGATIVE
// intensity beyond the epsilon is added too).
void dwGui3DView::RebuildLights()
{
    rdCamera_ClearLights(&this->camera);

    float intensity0 = this->light0.intensity;
    if (intensity0 < 0.0f)
        intensity0 = -intensity0;
    if (intensity0 <= 1e-5f)
        intensity0 = 0.0f;
    else
        intensity0 = this->light0.intensity;
    if (intensity0 != 0.0f)
        rdCamera_AddLight(&this->camera, &this->light0, &this->light0Pos);

    float intensity1 = this->light1.intensity;
    if (intensity1 < 0.0f)
        intensity1 = -intensity1;
    if (intensity1 <= 1e-5f)
        intensity1 = 0.0f;
    else
        intensity1 = this->light1.intensity;
    if (intensity1 != 0.0f)
        rdCamera_AddLight(&this->camera, &this->light1, &this->light1Pos);
}

// @43b150 (Ghidra: dwGui3DView_Refresh) — vtbl +0x4c (NEW virtual):
// forwards to virtual Invalidate (+0x34).
void dwGui3DView::Refresh()
{
    this->Invalidate();
}

// ---- non-virtual helpers -------------------------------------------------------

// @43b160 (Ghidra: dwGui3DView_ScreenToWorld)
void dwGui3DView::ScreenToWorld(dwPoint* pPt, rdVector3* pOut)
{
    pOut->x = (flex_t)pPt->x;
    pOut->z = -(flex_t)pPt->y;
    pOut->y = this->camera.focalLength; // Ghidra: "groundPlaneY"@0xa4 — the projection distance
    pOut->x = pOut->x - this->canvas.half_screen_width;
    pOut->z = this->canvas.half_screen_height + pOut->z;
    rdMatrix_TransformPoint34Acc(pOut, &this->viewMat); // binary: rdMatrix_FUN_00486af0
}

// @43b1b0 (Ghidra: dwGui3DView_ProjectPoint)
void dwGui3DView::ProjectPoint(rdVector3* pOut, rdVector3* pWorldPos)
{
    if (rdCamera_g_pCurCamera != &this->camera) // binary: DAT_005542cc
    {
        rdCamera_SetCurrent(&this->camera);
        rdCamera_Update(&this->viewMat);
    }
    rdVector3 world;
    world.x = pWorldPos->x;
    world.y = pWorldPos->y;
    world.z = pWorldPos->z;
    rdVector3 camSpace;
    rdMatrix_TransformPoint34(&camSpace, &world, &this->camera.orient);
    this->camera.pfProject(pOut, &camSpace); // Ghidra: "pProjCallback"@0xb4
}

// @43b220 (Ghidra: dwGui3DView_DrawMarker)
void dwGui3DView::DrawMarker(dwImageBits* pDestBits, rdVector3* pWorldPos, int16_t halfSize, int color, dwRect* pClipRect)
{
    rdVector3 screen;
    this->ProjectPoint(&screen, pWorldPos);
    int16_t x = (int16_t)(int32_t)screen.x; // binary: __ftol (truncate)
    int16_t y = (int16_t)(int32_t)screen.y;

    dwRect rect;
    rect.left = x - halfSize;
    rect.top = y - halfSize;
    rect.right = halfSize + x;
    rect.bottom = halfSize + y;
    if (pClipRect)
        dwRect_Clip(&rect, pClipRect);
    dwImageDraw_FillRect(pDestBits, &rect, color, NULL);
}

// @43b440 (Ghidra: dwGui3DView_SetLight0)
void dwGui3DView::SetLight0(float x, float y, float z, float intensity, int type)
{
    this->light0Pos.x = x;
    this->light0Pos.y = y;
    this->light0Pos.z = z;
    this->light0.intensity = intensity;
    this->light0.type = type;
    this->RebuildLights(); // vtbl +0x48 (virtual)
}

// @43b480 (Ghidra: dwGui3DView_SetLight1)
void dwGui3DView::SetLight1(float x, float y, float z, float intensity, int type)
{
    this->light1Pos.x = x;
    this->light1Pos.y = y;
    this->light1Pos.z = z;
    this->light1.intensity = intensity;
    this->light1.type = type;
    this->RebuildLights(); // vtbl +0x48 (virtual)
}
