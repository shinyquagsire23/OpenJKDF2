// std3D backend for the Sega Dreamcast (KallistiOS).
//
// This implements the non-SDL2 std3D contract (see the `#else` branch in
// src/Platform/std3D.h, reached because the Dreamcast build does not define
// SDL2_RENDER). The engine software-renders the menu/cutscene/HUD (and, with
// b3DAccel off, the 3D scene) into the 8-bit paletted Video_menuBuffer; here we
// present that to a 640x480 RGB565 framebuffer in VRAM, expanding through the
// current display palette. (Hardware-accelerated 3D via PVR/GLdc comes later.)

#include "Platform/std3D.h"

#include "Main/Main.h"
#include "Win95/Video.h"
#include "Win95/stdDisplay.h"
#include "jk.h"

#include <kos.h>
#include <dc/video.h>
#include <dc/flashrom.h>
#include <dc/sq.h>

int std3D_bReinitHudElements = 0;

static int std3D_bHasInitted = 0;

// --- Lifecycle ---------------------------------------------------------------
int std3D_Startup()
{
    if (Main_bHeadless) { std3D_bHasInitted = 1; return 1; }

    // Pick a 640x480 RGB565 mode. VGA is always 60Hz progressive; otherwise use
    // the console region to choose 50Hz (PAL/Europe) vs 60Hz (NTSC), defaulting
    // to 60Hz when region is unknown.
    int cable  = vid_check_cable();
    int region = flashrom_get_region();
    int mode;
    if (cable == CT_VGA)
        mode = DM_640x480_VGA;            // 60Hz progressive
    else if (region == FLASHROM_REGION_EUROPE)
        mode = DM_640x480_PAL_IL;         // 50Hz
    else
        mode = DM_640x480_NTSC_IL;        // 60Hz

    vid_set_mode(mode, PM_RGB565);

    std3D_bHasInitted = 1;
    return 1;
}
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

// --- Framebuffer present -----------------------------------------------------
// The engine composites everything into the 8-bit paletted Video_menuBuffer.
// Present it by expanding each index through the display palette into the
// 640x480 RGB565 VRAM framebuffer. std3D_DrawMenu is the present hook reached
// every frame (menu/cutscene via Window_SdlUpdate; HUD/scene similarly).
//
// The expansion is fed directly through the SH4 store queues (32-byte bursts to
// VRAM) instead of individual uncached 16-bit stores, which is dramatically
// faster for a full-screen blit.
void std3D_DrawMenu()
{
    if (Main_bHeadless) return;
    if (!Video_menuBuffer.surface_lock_alloc) return;

    const int srcW = Video_menuBuffer.format.width;
    const int srcH = Video_menuBuffer.format.height;
    const uint32_t pitch = Video_menuBuffer.format.width_in_bytes;
    if (srcW <= 0 || srcH <= 0) return;

    // 8-bit index -> RGB565 lookup, rebuilt from the current display palette.
    static uint16_t pal565[256];
    for (int i = 0; i < 256; i++)
    {
        const rdColor24* c = &stdDisplay_masterPalette[i];
        pal565[i] = (uint16_t)(((c->r >> 3) << 11) | ((c->g >> 2) << 5) | (c->b >> 3));
    }

    const uint8_t* src = (const uint8_t*)Video_menuBuffer.surface_lock_alloc;

    // Fast path: a full 640x480 source maps 1:1 to the framebuffer, 16 pixels
    // (32 bytes) per store-queue burst.
    if (srcW >= 640 && srcH >= 480 && pitch >= 640)
    {
        uint32_t* sq = sq_lock(vram_s);
        for (int y = 0; y < 480; y++)
        {
            const uint8_t* s = src + (size_t)y * pitch;
            for (int bx = 0; bx < 640 / 16; bx++)
            {
                sq[0] = pal565[s[0]]  | (pal565[s[1]]  << 16);
                sq[1] = pal565[s[2]]  | (pal565[s[3]]  << 16);
                sq[2] = pal565[s[4]]  | (pal565[s[5]]  << 16);
                sq[3] = pal565[s[6]]  | (pal565[s[7]]  << 16);
                sq[4] = pal565[s[8]]  | (pal565[s[9]]  << 16);
                sq[5] = pal565[s[10]] | (pal565[s[11]] << 16);
                sq[6] = pal565[s[12]] | (pal565[s[13]] << 16);
                sq[7] = pal565[s[14]] | (pal565[s[15]] << 16);
                sq_flush(sq);
                sq += 8;
                s += 16;
            }
        }
        sq_unlock();
        return;
    }

    // Fallback for non-standard dimensions: direct (uncached) expansion.
    int w = (srcW < 640) ? srcW : 640;
    int h = (srcH < 480) ? srcH : 480;
    uint16_t* dst = vram_s;
    for (int y = 0; y < h; y++)
    {
        const uint8_t* srow = src + (size_t)y * pitch;
        uint16_t* drow = dst + (size_t)y * 640;
        for (int x = 0; x < w; x++)
            drow[x] = pal565[srow[x]];
    }
}
void std3D_ResetUIRenderList() {}
int  std3D_AddBitmapToTextureCache(stdBitmap* texture, int mipIdx, int is_alpha_tex, int no_alpha) { return 0; }
void std3D_DrawUIBitmapRGBA(stdBitmap* pBmp, int mipIdx, flex_t dstX, flex_t dstY, rdRect* srcRect, flex_t scaleX, flex_t scaleY, int bAlphaOverwrite, uint8_t color_r, uint8_t color_g, uint8_t color_b, uint8_t color_a) {}
void std3D_DrawUIBitmap(stdBitmap* pBmp, int mipIdx, flex_t dstX, flex_t dstY, rdRect* srcRect, flex_t scale, int bAlphaOverwrite) {}
void std3D_DrawUIClearedRect(uint8_t palIdx, rdRect* dstRect) {}
void std3D_DrawUIClearedRectRGBA(uint8_t color_r, uint8_t color_g, uint8_t color_b, uint8_t color_a, rdRect* dstRect) {}
