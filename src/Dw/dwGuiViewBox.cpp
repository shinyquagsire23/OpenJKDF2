// dwGuiViewBox — the DroidWorks orbit/turntable 3D-view widget, plus the
// dwGuiImage static-image widget that shares its compile unit.
//
// Decompiled from DroidWorks.exe, unit range 0x434840-0x434cff.
// vtables: dwGuiViewBox_vtbl @0x51f988, dwGuiImage_vtbl @0x51f9e0.
// See dwGuiViewBox.h for the layout/slot maps.
//
// No module statics — no dwGuiViewBox_Startup needed (soft-reset rule).

#include "Dw/dwGuiViewBox.h"

#include "Engine/rdCamera.h"
#include "Primitives/rdMatrix.h"
// This engine header has no extern "C" guards of its own — wrap at include site.
extern "C" {
#include "General/stdMath.h"
}

// =============================== dwGuiViewBox ===================================

// @434840 (Ghidra: dwGuiViewBox_Ctor)
dwGuiViewBox::dwGuiViewBox(dwRect* pRect, uint8_t bLightsFollowView)
    : dwGui3DView(pRect)
{
    float fov = this->camera.fov; // read right after the base ctor (Ghidra: currentFOV; == 20.0)
    this->bLightsFollowView = bLightsFollowView;
    this->pivotX = 0.0f;
    this->pivotY = 0.0f;
    this->pivotZ = 0.0f;
    this->yaw = 0.0f;
    this->pitch = 180.0f;
    this->orbitDistance = 0.08f / stdMath_Tan(fov * 0.5f);
    dwGuiViewBox::RebuildLights(); // binary: direct calls (vtable already this class's)
    dwGuiViewBox::Refresh();       // (Ghidra: dwGuiViewBox_RebuildView)
}

// @434910 (Ghidra: dwGuiViewBox_Dtor; DtorDelete @4348f0) — base dtor only.
dwGuiViewBox::~dwGuiViewBox()
{
}

// @434920 (Ghidra: dwGuiViewBox_OnMessage) — vtbl +0x1c. The numeric/pointer
// payload rides in the message's pSender slot (see dwWidgetMsg).
int dwGuiViewBox::OnMessage(dwWidgetMsg* pMsg)
{
    if (pMsg->code == 0x3e8) // set pitch/elevation (integer degrees)
    {
        this->SetAngles(this->yaw, (float)(int32_t)(intptr_t)pMsg->pSender); // vtbl +0x50
        return 0;
    }
    if (pMsg->code == 0x3e9) // set yaw/azimuth (integer degrees)
    {
        this->SetAngles((float)(int32_t)(intptr_t)pMsg->pSender, this->pitch); // vtbl +0x50
        return 0;
    }
    if (pMsg->code == 0x3eb) // recenter the pivot from a float[3] payload
    {
        float* pVec = (float*)pMsg->pSender;
        this->pivotX = pVec[0];
        this->pivotY = pVec[1];
        this->pivotZ = pVec[2];
        this->Refresh(); // vtbl +0x4c (the orbit rebuild)
        return 0;
    }
    return dwGui3DView::OnMessage(pMsg); // 0x3ea set-FOV lives in the base
}

// @434b20 (Ghidra: dwGuiViewBox_RebuildLights) — vtbl +0x48
void dwGuiViewBox::RebuildLights()
{
    if (this->bLightsFollowView != 0)
    {
        this->SetAngles(this->yaw, this->pitch); // vtbl +0x50 — rebuilds view + following lights
        return;
    }
    dwGui3DView::RebuildLights(); // static base lights
}

// @4349c0 (Ghidra: dwGuiViewBox_RebuildView — this class's override of the
// +0x4c Refresh slot). Rebuilds viewMat from yaw/pitch orbiting the pivot at
// orbitDistance; when bLightsFollowView, re-adds the two base lights with
// positions rotated by the new view matrix (so they rotate WITH the camera).
void dwGuiViewBox::Refresh()
{
    rdVector3 rot;
    rot.z = 0.0f;
    rot.x = this->yaw;   // Ghidra field names kept — see dwGuiViewBox.h note
    rot.y = this->pitch;
    rdMatrix_BuildRotate34(&this->viewMat, &rot);

    rdVector3 offset;
    offset.y = -this->orbitDistance;
    offset.x = 0.0f;
    offset.z = 0.0f;
    rdMatrix_TransformVector34Acc(&offset, &this->viewMat);
    offset.x = this->pivotX + offset.x;
    offset.y = this->pivotY + offset.y;
    offset.z = this->pivotZ + offset.z;
    rdMatrix_Build34(&this->viewMat, &rot, &offset);

    if (this->bLightsFollowView != 0)
    {
        rdVector3 pos;
        rdCamera_ClearLights(&this->camera);
        // Quirk preserved: plain != 0 intensity tests here (the base
        // RebuildLights uses a 1e-5 epsilon).
        if (this->light0.intensity != 0.0f)
        {
            rdMatrix_TransformVector34(&pos, &this->light0Pos, &this->viewMat);
            rdCamera_AddLight(&this->camera, &this->light0, &pos);
        }
        if (this->light1.intensity != 0.0f)
        {
            rdMatrix_TransformVector34(&pos, &this->light1Pos, &this->viewMat);
            rdCamera_AddLight(&this->camera, &this->light1, &pos);
        }
    }
    this->Invalidate(); // vtbl +0x34
}

// @4349a0 (Ghidra: dwGuiViewBox_SetAngles; recovered fn) — NEW vtbl +0x50.
// Binary stores pitch first, then yaw, then virtual-Refreshes.
void dwGuiViewBox::SetAngles(float yaw, float pitch)
{
    this->pitch = pitch;
    this->yaw = yaw;
    this->Refresh(); // vtbl +0x4c
}

// ================================ dwGuiImage ====================================

// @434b50 (Ghidra: dwGuiImage_Ctor)
dwGuiImage::dwGuiImage(dwRect* pRect, char* pFilename)
    : dwWidget(pRect), filename(), pImage(NULL)
{
    this->filename.AssignCStr(pFilename);
    dwGuiImage::EnsureImages(); // binary: direct call (Ghidra: dwGuiImage_EnsureLoaded)
}

// @434bf0 (Ghidra: dwGuiImage_Dtor; DtorDelete @434bd0) — FreeImage, then the
// filename release (the dwString member dtor here) and the base dtor.
dwGuiImage::~dwGuiImage()
{
    dwGuiImage::FreeImages(); // binary: direct call (Ghidra: dwGuiImage_FreeImage)
}

// @434c80 (Ghidra: dwGuiImage_EnsureLoaded) — vtbl +0x3c.
// dwImage_LoadFile is the P8 stdBitmapRle2 stub (returns NULL) for now —
// pImage simply stays NULL and Draw's guard skips (dwCursor precedent).
void dwGuiImage::EnsureImages()
{
    if (this->pImage == NULL && this->filename.length != 0)
    {
        this->pImage = dwImage_LoadFile(this->filename.pBuffer);
    }
}

// @434cb0 (Ghidra: dwGuiImage_FreeImage) — vtbl +0x40. Binary: scalar-deleting
// dtor via the image's vtbl slot 0 == C++ delete.
void dwGuiImage::FreeImages()
{
    if (this->pImage != NULL)
    {
        delete this->pImage;
        this->pImage = NULL;
    }
}

// @434c50 (Ghidra: dwGuiImage_Draw) — vtbl +0x44. Blit `this` is the SOURCE
// image (see dwImage.h).
void dwGuiImage::Draw(dwImageBits* pDestBits, dwRect* pClipRect)
{
    this->EnsureImages(); // vtbl +0x3c (virtual in the binary)
    if (this->pImage != NULL)
    {
        this->pImage->Blit(pDestBits, this->left, this->top, pClipRect);
    }
}
