// Stub std3D backend for the Sega Dreamcast (KallistiOS).
//
// This implements the non-SDL2 std3D contract (see the `#else` branch in
// src/Platform/std3D.h, reached because the Dreamcast build does not define
// SDL2_RENDER) with no-op bodies so the engine links and runs. Nothing is drawn
// yet.
//
// The plan is to borrow the GL 1.1 fixed-function renderer (src/Platform/GL11)
// on top of KOS's GLdc once the scaffolding is up; for now this keeps the Dreamcast
// target self-contained and buildable, mirroring how the DSi backend started out.

#include "Platform/std3D.h"

#include "Main/Main.h"
#include "Win95/Video.h"
#include "Win95/stdDisplay.h"
#include "jk.h"

#include <kos.h>
#include <dc/video.h>
#include <dc/flashrom.h>

int std3D_bReinitHudElements = 0;

static int std3D_bHasInitted = 0;

// --- Lifecycle ---------------------------------------------------------------
int  std3D_Startup()        { std3D_bHasInitted = 1; return 1; }
void std3D_Shutdown()       { std3D_bHasInitted = 0; }
int  std3D_StartScene()     { return 0; }
int  std3D_EndScene()       { return 0; }
int  std3D_IsReady()        { return std3D_bHasInitted; }
void std3D_FreeResources()  {}
void std3D_UpdateSettings() {}

// --- Render list -------------------------------------------------------------
void std3D_ResetRenderList()            {}
int  std3D_RenderListVerticesFinish()   { return 0; }
void std3D_DrawRenderList()             {}
int  std3D_AddRenderListVertices(D3DVERTEX* vertices, int count) { return 1; }
void std3D_AddRenderListTris(rdTri* tris, unsigned int num_tris) {}
void std3D_AddRenderListLines(rdLine* lines, uint32_t num_lines) {}

// --- Palette / dimensions ----------------------------------------------------
int  std3D_SetCurrentPalette(rdColor24* a1, int a2) { return 1; }
void std3D_GetValidDimension(unsigned int inW, unsigned int inH, unsigned int* outW, unsigned int* outH)
{
    if (outW) *outW = inW;
    if (outH) *outH = inH;
}
int  std3D_GetValidDimensions(int a1, int a2, int a3, int a4) { return 1; }

// --- Texture cache -----------------------------------------------------------
int  std3D_AddToTextureCache(stdVBuffer* vbuf, rdDDrawSurface* texture, int is_alpha_tex, int no_alpha) { return 1; }
void std3D_UnloadAllTextures()                              {}
void std3D_PurgeEntireTextureCache()                       {}
int  std3D_PurgeTextureCache(size_t size)                  { return 1; }
void std3D_RemoveTextureFromCacheList(rdDDrawSurface* pCacheTexture) {}
void std3D_AddTextureToCacheList(rdDDrawSurface* pTexture)  {}
void std3D_UpdateFrameCount(rdDDrawSurface* pTexture)       {}
void std3D_PurgeUIEntry(int i, int idx)                    {}
void std3D_PurgeTextureEntry(int i)                        {}
void std3D_PurgeBitmapRefs(stdBitmap* pBitmap)             {}
void std3D_PurgeSurfaceRefs(rdDDrawSurface* texture)       {}

// --- Z buffer / viewport / device --------------------------------------------
int  std3D_ClearZBuffer()                 { return 1; }
void std3D_InitializeViewport(rdRect* viewRect) {}
int  std3D_DrawOverlay()                  { return 1; }
int  std3D_FindClosestDevice(uint32_t index, int a2) { return 0; }
int  std3D_SetRenderList(intptr_t a1)     { return 0; }
intptr_t std3D_GetRenderList()            { return 0; }
int  std3D_CreateExecuteBuffer()          { return 1; }
void std3D_DrawSceneFbo()                 {}
void std3D_Screenshot(const char* pFpath) {}

// --- Capabilities ------------------------------------------------------------
int std3D_HasAlpha()             { return 0; }
int std3D_HasModulateAlpha()     { return 0; }
int std3D_HasAlphaFlatStippled() { return 0; }

// --- Menu / UI (handled separately later, like the DSi backend) --------------
void std3D_DrawMenu()        {}
void std3D_ResetUIRenderList() {}
int  std3D_AddBitmapToTextureCache(stdBitmap* texture, int mipIdx, int is_alpha_tex, int no_alpha) { return 0; }
void std3D_DrawUIBitmapRGBA(stdBitmap* pBmp, int mipIdx, flex_t dstX, flex_t dstY, rdRect* srcRect, flex_t scaleX, flex_t scaleY, int bAlphaOverwrite, uint8_t color_r, uint8_t color_g, uint8_t color_b, uint8_t color_a) {}
void std3D_DrawUIBitmap(stdBitmap* pBmp, int mipIdx, flex_t dstX, flex_t dstY, rdRect* srcRect, flex_t scale, int bAlphaOverwrite) {}
void std3D_DrawUIClearedRect(uint8_t palIdx, rdRect* dstRect) {}
void std3D_DrawUIClearedRectRGBA(uint8_t color_r, uint8_t color_g, uint8_t color_b, uint8_t color_a, rdRect* dstRect) {}
