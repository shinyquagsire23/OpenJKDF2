// std3D backend for the Sega Dreamcast (KallistiOS), PowerVR hardware path.
//
// Implements the non-SDL2 std3D contract (the `#else` branch of std3D.h). The
// engine accumulates a screen-space triangle render list (RDCACHE_RENDER_NGONS is
// TWL-only, so Dreamcast uses the Tris path -- same as src/Platform/GL11). We
// replicate that GL11 accumulation and submit the geometry to the PVR's opaque
// list, then composite the 8-bit menu/HUD buffer as a punch-through overlay quad.
//
// First-pass scope:
//  - All geometry goes to the opaque list (rdCache pre-sorts; translucency TBD).
//  - Textures are assumed power-of-two; UVs arrive normalized (PVR wants floats).
//  - Non-twiddled 16-bit textures (RGB565 / ARGB1555) for simple linear uploads.

#include "Platform/std3D.h"

#include "Main/Main.h"
#include "Win95/Video.h"
#include "Win95/stdDisplay.h"
#include "Engine/rdColormap.h"
#include "Engine/rdCamera.h"
#include "World/sithWorld.h"
#include "jk.h"

#include <kos.h>
#include <dc/pvr.h>
#include <dc/video.h>
#include <dc/flashrom.h>

#include <stdlib.h>
#include <string.h>

#define COMP_B(c) ((c) & 0xFF)
#define COMP_G(c) (((c) >> 8) & 0xFF)
#define COMP_R(c) (((c) >> 16) & 0xFF)
#define COMP_A(c) (((c) >> 24) & 0xFF)

// Tri flag bits (shared with the modern renderer's state machine).
#define STD3D_TRI_DEPTHTEST  0x800
#define STD3D_TRI_BLEND      0x600
#define STD3D_TRI_DEPTHWRITE 0x1000
#define STD3D_TRI_CULLBACK   0x10000

int std3D_bReinitHudElements = 0;
static int std3D_bHasInitted = 0;
static int std3D_bPvrReady   = 0;  // pvr_init done once; never torn down (the PVR
                                   // is a persistent context across GUI transitions)

// --- Scene lifecycle state ---------------------------------------------------
static int std3D_bInScene   = 0;
static int std3D_bOpListOpen = 0;
static int std3D_bMenuPending = 0;

// --- Render list accumulators (mirrors GL11) ---------------------------------
static D3DVERTEX GL_tmpVertices[STD3D_MAX_VERTICES] = {0};
static size_t    GL_tmpVerticesAmt = 0;
static rdTri     GL_tmpTris[STD3D_MAX_TRIS] = {0};
static size_t    GL_tmpTrisAmt = 0;

// --- Texture cache -----------------------------------------------------------
typedef struct dcTexEntry {
    rdDDrawSurface* surf;
    pvr_ptr_t       ptr;
    int             w, h;
    int             fmt;   // PVR_TXRFMT_* (incl. NONTWIDDLED)
} dcTexEntry;
static dcTexEntry std3D_aTex[STD3D_MAX_TEXTURES] = {0};
static size_t     std3D_numTex = 0;

static rdColor24 std3D_currentPalette[256];

// --- Menu/HUD overlay texture ------------------------------------------------
// PVR textures must be power-of-two; the 640x480 menu buffer lives in the
// top-left of a 1024x512 ARGB1555 texture (index 0 -> transparent for the HUD).
#define MENU_TEX_W 1024
#define MENU_TEX_H 512
static pvr_ptr_t std3D_menuTex = NULL;
static uint16_t* std3D_pMenuStaging = NULL; // 1024x512 ARGB1555 staging in main RAM

// ----------------------------------------------------------------------------

int std3D_Startup()
{
    if (Main_bHeadless) { std3D_bHasInitted = 1; return 1; }

    // pvr_init must run exactly once for the whole session -- it sets up the TA,
    // VRAM and display. The engine calls std3D_Startup/Shutdown around GUI/menu
    // transitions (Video_SwitchToGDI etc.), so we keep the PVR alive and only flip
    // the soft "initted" flag.
    if (!std3D_bPvrReady)
    {
        // Opaque + punch-through lists (translucent comes later). The PVR picks the
        // video mode from the detected cable/region (50Hz PAL, else 60Hz / VGA).
        pvr_init_params_t params = {
            { PVR_BINSIZE_32, PVR_BINSIZE_0, PVR_BINSIZE_0, PVR_BINSIZE_0, PVR_BINSIZE_32 },
            512 * 1024, // vertex buffer size
            0,          // dma
            0,          // fsaa
            0,          // autosort NOT disabled (let the PVR sort translucents later)
            3           // extra OPBs for heavy geometry
        };
        pvr_init(&params);
        pvr_set_bg_color(0.0f, 0.0f, 0.0f);

        // Menu overlay texture + its main-RAM staging buffer (kept for the session).
        std3D_menuTex = pvr_mem_malloc(MENU_TEX_W * MENU_TEX_H * 2);
        std3D_pMenuStaging = (uint16_t*)memalign(32, MENU_TEX_W * MENU_TEX_H * 2);
        if (std3D_pMenuStaging)
            memset(std3D_pMenuStaging, 0, MENU_TEX_W * MENU_TEX_H * 2);

        std3D_bPvrReady = 1;
    }

    std3D_bHasInitted = 1;
    return 1;
}

void std3D_Shutdown()
{
    // Soft shutdown only: the engine calls this on GUI transitions, so we keep the
    // PVR context and its textures alive (tearing down/reinitializing the PVR
    // mid-run would freeze the display). Real teardown only matters at exit.
    std3D_bHasInitted = 0;
}

int std3D_IsReady()        { return std3D_bHasInitted; }
void std3D_FreeResources() {}
void std3D_UpdateSettings() {}

int std3D_StartScene()
{
    if (Main_bHeadless) return 0;

    // Advance the global frame counter every frame. The material LRU
    // (rdMaterial_EnsureData/EnsureMetadata) gates its per-frame load budget and
    // its "load once per frame" check on this; it starts at 1 and the guard
    // `std3D_frameCount != 1` means materials never load until it moves past 1.
    ++std3D_frameCount;

    // Lazily re-establish after a soft Shutdown (GUI transitions clear bHasInitted).
    if (!std3D_bHasInitted) std3D_Startup();
    if (!std3D_bPvrReady) return 0;

    // If a previous scene was never finished (an early-out somewhere skipped
    // EndScene), close it out so we never deadlock on pvr_wait_ready.
    if (std3D_bInScene) std3D_EndScene();

    pvr_wait_ready();
    pvr_scene_begin();
    pvr_list_begin(PVR_LIST_OP_POLY);
    std3D_bInScene = 1;
    std3D_bOpListOpen = 1;
    return 0;
}

// Draw the menu/HUD overlay quad (punch-through). Called from EndScene after the
// opaque list is closed.
static void std3D_SubmitMenuOverlay()
{
    if (!std3D_menuTex) return;

    pvr_poly_cxt_t cxt;
    pvr_poly_hdr_t hdr;
    pvr_poly_cxt_txr(&cxt, PVR_LIST_PT_POLY,
                     PVR_TXRFMT_ARGB1555 | PVR_TXRFMT_NONTWIDDLED,
                     MENU_TEX_W, MENU_TEX_H, std3D_menuTex, PVR_FILTER_NEAREST);
    cxt.gen.culling = PVR_CULLING_NONE;
    // The HUD/menu overlay is always on top of the 3D scene. Without this it depth-
    // tests against the world (which writes nearer 1/w values) and gets occluded.
    cxt.depth.comparison = PVR_DEPTHCMP_ALWAYS;
    cxt.depth.write = 0;
    pvr_poly_compile(&hdr, &cxt);
    pvr_prim(&hdr, sizeof(hdr));

    const float u1 = 640.0f / MENU_TEX_W;
    const float v1 = 480.0f / MENU_TEX_H;
    // The punch-through list still depth-tests (GREATER) against the opaque world
    // even with DEPTHCMP_ALWAYS set -- the PVR ignores ALWAYS for PT. World vertices
    // carry z = 1/w (1/z_camera), which gets large for geometry near the camera (the
    // first-person weapon especially), so z=10 still loses to it. Park the overlay at
    // a huge uniform z so it wins GREATER against everything. Uniform z across all 4
    // verts => no perspective/UV distortion.
    const float z  = 1.0e6f;

    pvr_vertex_t v;
    v.oargb = 0;
    v.argb  = 0xFFFFFFFF;
    v.flags = PVR_CMD_VERTEX;

    v.x = 0.0f;   v.y = 0.0f;   v.z = z; v.u = 0.0f; v.v = 0.0f; pvr_prim(&v, sizeof(v));
    v.x = 640.0f; v.y = 0.0f;   v.z = z; v.u = u1;   v.v = 0.0f; pvr_prim(&v, sizeof(v));
    v.x = 0.0f;   v.y = 480.0f; v.z = z; v.u = 0.0f; v.v = v1;   pvr_prim(&v, sizeof(v));
    v.flags = PVR_CMD_VERTEX_EOL;
    v.x = 640.0f; v.y = 480.0f; v.z = z; v.u = u1;   v.v = v1;   pvr_prim(&v, sizeof(v));
}

// TEMP DEBUG: draw a small filled square at the platform mouse position so we can
// see where Window_mouseX/Y actually is relative to the on-screen cursor.
static void std3D_SubmitCursorSquare()
{
    extern int Window_mouseX, Window_mouseY;
    const float x = (float)Window_mouseX;
    const float y = (float)Window_mouseY;
    const float s = 4.0f;
    const float z = 10.0f; // in front of the menu overlay (z=1)

    pvr_poly_cxt_t cxt;
    pvr_poly_hdr_t hdr;
    pvr_poly_cxt_col(&cxt, PVR_LIST_PT_POLY);
    cxt.gen.culling = PVR_CULLING_NONE;
    cxt.depth.comparison = PVR_DEPTHCMP_ALWAYS;
    cxt.depth.write = 0;
    pvr_poly_compile(&hdr, &cxt);
    pvr_prim(&hdr, sizeof(hdr));

    pvr_vertex_t v;
    v.oargb = 0;
    v.argb  = 0xFFFF0000; // opaque red
    v.u = 0.0f; v.v = 0.0f;
    v.flags = PVR_CMD_VERTEX;
    v.x = x;     v.y = y;     v.z = z; pvr_prim(&v, sizeof(v));
    v.x = x + s; v.y = y;     v.z = z; pvr_prim(&v, sizeof(v));
    v.x = x;     v.y = y + s; v.z = z; pvr_prim(&v, sizeof(v));
    v.flags = PVR_CMD_VERTEX_EOL;
    v.x = x + s; v.y = y + s; v.z = z; pvr_prim(&v, sizeof(v));
}

int std3D_dbgTrisSeen   = 0;
int std3D_dbgTrisSubmit = 0;
int std3D_dbgEarlyOut   = 0;

int std3D_EndScene()
{
    if (Main_bHeadless || !std3D_bInScene) return 0;

    if (std3D_bOpListOpen) { pvr_list_finish(); std3D_bOpListOpen = 0; }

    if (std3D_bMenuPending) {
        pvr_list_begin(PVR_LIST_PT_POLY);
        std3D_SubmitMenuOverlay();
        if (!jkGame_isDDraw) {
            std3D_SubmitCursorSquare(); // mouse position marker
        }
        pvr_list_finish();
        std3D_bMenuPending = 0;
    }

    pvr_scene_finish();
    std3D_bInScene = 0;

    // TEMP DIAGNOSTIC: seen vs submitted vs dropped (scene inactive), once per ~2s.
    {
        static int s_frame = 0;
        if ((s_frame++ % 120) == 0)
            stdPlatform_Printf("[DC std3D] f=%d seen=%d submit=%d earlyOut=%d numTex=%d ddraw=%d\n",
                               s_frame, std3D_dbgTrisSeen, std3D_dbgTrisSubmit,
                               std3D_dbgEarlyOut, (int)std3D_numTex, jkGame_isDDraw);
    }
    std3D_dbgTrisSeen = std3D_dbgTrisSubmit = std3D_dbgEarlyOut = 0;
    return 0;
}

// --- Render list -------------------------------------------------------------
void std3D_ResetRenderList()
{
    GL_tmpVerticesAmt = 0;
    GL_tmpTrisAmt = 0;
}

int std3D_RenderListVerticesFinish() { return 0; }

int std3D_AddRenderListVertices(D3DVERTEX* vertices, int count)
{
    if (Main_bHeadless) return 1;
    if (GL_tmpVerticesAmt + count >= STD3D_MAX_VERTICES) return 0;
    memcpy(&GL_tmpVertices[GL_tmpVerticesAmt], vertices, sizeof(D3DVERTEX) * count);
    GL_tmpVerticesAmt += count;
    return 1;
}

void std3D_AddRenderListTris(rdTri* tris, unsigned int num_tris)
{
    if (Main_bHeadless) return;
    if (GL_tmpTrisAmt + num_tris > STD3D_MAX_TRIS) return;
    memcpy(&GL_tmpTris[GL_tmpTrisAmt], tris, sizeof(rdTri) * num_tris);
    GL_tmpTrisAmt += num_tris;
}

void std3D_AddRenderListLines(rdLine* lines, uint32_t num_lines) {}

static inline void std3D_EmitVertex(const D3DVERTEX* vtx, int textured, uint32_t cmd)
{
    pvr_vertex_t v;
    v.flags = cmd;
    v.x = vtx->x;
    v.y = vtx->y;

    // The PVR's vertex z is 1/w: it is interpolated linearly in screen space for
    // both depth (GEQUAL, nearer = larger) and perspective-correct texturing.
    // rdCache stores the engine's true 1/w (== 1/z_camera) in nx, scaled by 1/32
    // (rdCache.c:744). Using the depth-buffer value 1/(1-z) instead is ~w (the
    // reciprocal), which only approximates perspective and skews the texture on
    // triangles that span a large depth range — most visible at the screen edges.
    v.z = vtx->nx * 32.0f;

    if (textured) { v.u = vtx->tu; v.v = vtx->tv; }
    else          { v.u = 0.0f;    v.v = 0.0f;    }

    // Vertex color carries baked lighting (ARGB); force opaque for the OP list.
    v.argb  = 0xFF000000u | (vtx->color & 0x00FFFFFFu);
    v.oargb = 0;
    pvr_prim(&v, sizeof(v));
}

extern int std3D_dbgTrisSeen;     // tris handed to DrawRenderList this frame
extern int std3D_dbgTrisSubmit;   // tris actually submitted to the PVR
extern int std3D_dbgEarlyOut;     // DrawRenderList calls dropped (scene inactive)

void std3D_DrawRenderList()
{
    // Diagnostic: record what the engine handed us *before* any early-out.
    std3D_dbgTrisSeen += (int)GL_tmpTrisAmt;

    if (Main_bHeadless || !std3D_bInScene || !std3D_bOpListOpen || !GL_tmpTrisAmt) {
        if (GL_tmpTrisAmt && (!std3D_bInScene || !std3D_bOpListOpen))
            std3D_dbgEarlyOut += (int)GL_tmpTrisAmt;
        std3D_ResetRenderList();
        return;
    }

    rdTri*     tris  = GL_tmpTris;
    D3DVERTEX* verts = GL_tmpVertices;

    std3D_dbgTrisSubmit += (int)GL_tmpTrisAmt;

    rdDDrawSurface* lastTex = (rdDDrawSurface*)~0;
    int textured = 0;

    for (size_t j = 0; j < GL_tmpTrisAmt; j++)
    {
        rdDDrawSurface* tex = tris[j].texture;

        // Re-emit the poly header whenever the bound texture changes.
        if (tex != lastTex)
        {
            pvr_poly_cxt_t cxt;
            pvr_poly_hdr_t hdr;
            if (tex && tex->texture_loaded && (size_t)tex->texture_id < std3D_numTex)
            {
                dcTexEntry* e = &std3D_aTex[tex->texture_id];
                pvr_poly_cxt_txr(&cxt, PVR_LIST_OP_POLY, e->fmt, e->w, e->h,
                                 e->ptr, PVR_FILTER_NEAREST);
                textured = 1;
            }
            else
            {
                pvr_poly_cxt_col(&cxt, PVR_LIST_OP_POLY);
                textured = 0;
            }
            cxt.gen.culling = PVR_CULLING_NONE;
            pvr_poly_compile(&hdr, &cxt);
            pvr_prim(&hdr, sizeof(hdr));
            lastTex = tex;
        }

        std3D_EmitVertex(&verts[tris[j].v1], textured, PVR_CMD_VERTEX);
        std3D_EmitVertex(&verts[tris[j].v2], textured, PVR_CMD_VERTEX);
        std3D_EmitVertex(&verts[tris[j].v3], textured, PVR_CMD_VERTEX_EOL);
    }

    std3D_ResetRenderList();
}

// --- Palette / dimensions ----------------------------------------------------
int std3D_SetCurrentPalette(rdColor24* a1, int a2)
{
    if (a1) memcpy(std3D_currentPalette, a1, sizeof(std3D_currentPalette));
    return 1;
}

void std3D_GetValidDimension(unsigned int inW, unsigned int inH, unsigned int* outW, unsigned int* outH)
{
    if (outW) *outW = inW;
    if (outH) *outH = inH;
}
int std3D_GetValidDimensions(int a1, int a2, int a3, int a4) { return 1; }

// --- Texture cache -----------------------------------------------------------
static inline uint8_t std3D_Expand5(uint8_t v5) { return (uint8_t)((v5 * 527 + 23) >> 6); }
static inline uint8_t std3D_Expand6(uint8_t v6) { return (uint8_t)((v6 * 259 + 33) >> 6); }

int std3D_AddToTextureCache(stdVBuffer* vbuf, rdDDrawSurface* texture, int is_alpha_tex, int no_alpha)
{
    if (Main_bHeadless) return 1;
    if (!vbuf || !texture) return 1;
    if (texture->texture_loaded) return 1;
    if (std3D_numTex >= STD3D_MAX_TEXTURES) return 1;

    uint32_t width  = vbuf->format.width;
    uint32_t height = vbuf->format.height;
    if (!width || !height) return 1;

    uint16_t* staging = (uint16_t*)memalign(32, width * height * 2);
    if (!staging) return 1;

    int fmt;
    uint8_t*  src8  = (uint8_t*)vbuf->surface_lock_alloc;
    uint16_t* src16 = (uint16_t*)vbuf->surface_lock_alloc;

    if (vbuf->format.format.is16bit)
    {
        // Engine 565 / ARGB1555 share the PVR bit layout: straight copy.
        uint32_t rowpx = vbuf->format.width_in_bytes / 2;
        for (uint32_t y = 0; y < height; y++)
            for (uint32_t x = 0; x < width; x++)
                staging[y * width + x] = src16[y * rowpx + x];
        fmt = (is_alpha_tex ? PVR_TXRFMT_ARGB1555 : PVR_TXRFMT_RGB565) | PVR_TXRFMT_NONTWIDDLED;
    }
    else
    {
        // 8-bit paletted -> expand through the texture palette (or world colormap).
        uint8_t* pal = (uint8_t*)vbuf->palette;
        uint32_t rowpx = vbuf->format.width_in_bytes;
        for (uint32_t y = 0; y < height; y++)
        {
            for (uint32_t x = 0; x < width; x++)
            {
                uint8_t idx = src8[y * rowpx + x];
                uint8_t r, g, b;
                if (pal) { r = pal[idx*3+0]; g = pal[idx*3+1]; b = pal[idx*3+2]; }
                else if (sithWorld_pCurrentWorld && sithWorld_pCurrentWorld->colormaps)
                { rdColor24* c = &sithWorld_pCurrentWorld->colormaps->colors[idx]; r=c->r; g=c->g; b=c->b; }
                else { rdColor24* c = &std3D_currentPalette[idx]; r=c->r; g=c->g; b=c->b; }

                if (is_alpha_tex)
                {
                    uint16_t a = (idx == 0 && !no_alpha) ? 0x0000 : 0x8000;
                    staging[y*width+x] = a | ((r>>3)<<10) | ((g>>3)<<5) | (b>>3);
                }
                else
                {
                    staging[y*width+x] = ((r>>3)<<11) | ((g>>2)<<5) | (b>>3);
                }
            }
        }
        fmt = (is_alpha_tex ? PVR_TXRFMT_ARGB1555 : PVR_TXRFMT_RGB565) | PVR_TXRFMT_NONTWIDDLED;
    }

    pvr_ptr_t ptr = pvr_mem_malloc(width * height * 2);
    if (!ptr) { free(staging); return 1; }
    pvr_txr_load(staging, ptr, width * height * 2);
    free(staging);

    size_t idx = std3D_numTex++;
    std3D_aTex[idx].surf = texture;
    std3D_aTex[idx].ptr  = ptr;
    std3D_aTex[idx].w    = width;
    std3D_aTex[idx].h    = height;
    std3D_aTex[idx].fmt  = fmt;

    texture->texture_id     = (int)idx;
    texture->texture_loaded = 1;
    texture->is_16bit       = vbuf->format.format.is16bit ? 1 : 0;
    return 1;
}

void std3D_UnloadAllTextures()
{
    for (size_t i = 0; i < std3D_numTex; i++)
    {
        if (std3D_aTex[i].ptr) pvr_mem_free(std3D_aTex[i].ptr);
        if (std3D_aTex[i].surf) std3D_aTex[i].surf->texture_loaded = 0;
        std3D_aTex[i].ptr = NULL;
        std3D_aTex[i].surf = NULL;
    }
    std3D_numTex = 0;
}

void std3D_PurgeEntireTextureCache()       { std3D_UnloadAllTextures(); }
int  std3D_PurgeTextureCache(size_t size)  { std3D_UnloadAllTextures(); return 1; }
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

// --- Menu / HUD overlay ------------------------------------------------------
// Expand the 8-bit Video_menuBuffer into the ARGB1555 overlay texture (index 0
// transparent so the world shows through the HUD), upload it, and flag it for
// compositing in EndScene. Replaces the old direct-framebuffer present now that
// the PVR owns the display.
void std3D_DrawMenu()
{
    if (Main_bHeadless || !std3D_pMenuStaging) return;
    if (!Video_menuBuffer.surface_lock_alloc) return;

    const int srcW = Video_menuBuffer.format.width;
    const int srcH = Video_menuBuffer.format.height;
    const uint32_t pitch = Video_menuBuffer.format.width_in_bytes;
    if (srcW <= 0 || srcH <= 0) return;

    static uint16_t pal1555[256];
    for (int i = 0; i < 256; i++)
    {
        const rdColor24* c = &stdDisplay_masterPalette[i];
        pal1555[i] = (uint16_t)(0x8000 | ((c->r >> 3) << 10) | ((c->g >> 3) << 5) | (c->b >> 3));
    }

    int w = (srcW < 640) ? srcW : 640;
    int h = (srcH < 480) ? srcH : 480;
    const uint8_t* src = (const uint8_t*)Video_menuBuffer.surface_lock_alloc;

    for (int y = 0; y < h; y++)
    {
        const uint8_t* srow = src + (size_t)y * pitch;
        uint16_t* drow = std3D_pMenuStaging + (size_t)y * MENU_TEX_W;
        for (int x = 0; x < w; x++)
        {
            uint8_t idx = srow[x];
            drow[x] = idx ? pal1555[idx] : 0x0000; // index 0 -> transparent
        }
    }

    pvr_txr_load(std3D_pMenuStaging, std3D_menuTex, MENU_TEX_W * MENU_TEX_H * 2);
    std3D_bMenuPending = 1;
}

void std3D_ResetUIRenderList() {}
int  std3D_AddBitmapToTextureCache(stdBitmap* texture, int mipIdx, int is_alpha_tex, int no_alpha) { return 0; }
void std3D_DrawUIBitmapRGBA(stdBitmap* pBmp, int mipIdx, flex_t dstX, flex_t dstY, rdRect* srcRect, flex_t scaleX, flex_t scaleY, int bAlphaOverwrite, uint8_t color_r, uint8_t color_g, uint8_t color_b, uint8_t color_a) {}
void std3D_DrawUIBitmap(stdBitmap* pBmp, int mipIdx, flex_t dstX, flex_t dstY, rdRect* srcRect, flex_t scale, int bAlphaOverwrite) {}
void std3D_DrawUIClearedRect(uint8_t palIdx, rdRect* dstRect) {}
void std3D_DrawUIClearedRectRGBA(uint8_t color_r, uint8_t color_g, uint8_t color_b, uint8_t color_a, rdRect* dstRect) {}
