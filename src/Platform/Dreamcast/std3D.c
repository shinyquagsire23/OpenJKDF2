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
#include <dc/biosfont.h>
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

// --- Deferred translucent triangles ------------------------------------------
// PVR lists must be submitted in order (OP -> PT -> TR), but DrawRenderList runs
// many times per frame straight into the already-open OP list. So translucent
// tris (flags & 0x600) are pre-converted and stashed here, then flushed in the TR
// pass at EndScene.
//
// This stays small because the engine already renders alpha *surfaces* in their own
// pass (sithRender_RenderAlphaSurfaces); only the transparent *things* (sprites,
// blaster impacts, effects) interleaved into RenderThings actually need buffering.
// Overflow silently drops tris -- bump this if heavy particle scenes flicker.
// #2 test: set to 1 to bypass the whole TR/defer path -- translucent tris go
// straight to the OP list as opaque. If maps stop hanging with this, the culprit is
// the TR list / autosort / deferral machinery; if they still hang, it's the base
// opaque pipeline. (Visual: translucent surfaces render opaque.)
#define STD3D_DISABLE_TR 0

#define STD3D_MAX_DEFER_TRIS 512
typedef struct dcDeferTri {
    pvr_vertex_t    v[3];
    rdDDrawSurface* tex;
    int             textured;
} dcDeferTri;
static dcDeferTri std3D_deferTR[STD3D_MAX_DEFER_TRIS];
static size_t     std3D_numDeferTR = 0;

// --- Border-color loop tracer ------------------------------------------------
// Paints the TV overscan border a color at each phase of the frame, so a hardware
// hang (no serial console) shows *where* the loop froze by what color it's stuck on.
// Enable at compile time with -DSTD3D_BORDER_TRACE, or sneakily at runtime by
// plugging a controller into port 4 (checked once in std3D_Startup).
#ifdef STD3D_BORDER_TRACE
static int std3D_bBorderTrace = 1;
#else
static int std3D_bBorderTrace = 0;
#endif
void std3D_BorderTrace(uint8_t r, uint8_t g, uint8_t b)
{
    if (std3D_bBorderTrace) vid_border_color(r, g, b);
}

// One blink "unit" as a busy-loop count (~1/3 s at 200 MHz -- filmable; exact timing
// doesn't matter, only the color sequence does). Interrupts are off in the handler so
// timers aren't available.
#define EXC_UNIT 10000000u
static void std3D_ExcSpin(uint32_t loops) { for (volatile uint32_t i = 0; i < loops; i++) { } }

// Blink a 32-bit value on the TV border, MSB first, as 8 hex nibbles. Each nibble is a
// GREEN start marker, then its 4 bits MSB-first as RED=1 / BLUE=0 (both lit, so there's
// no "black == 0" ambiguity), each bit followed by a short black gap. To decode: after
// the intro color, read 8 groups; each group is GREEN then 4 colored pulses => 1 hex
// digit; concatenate the 8 digits.
static void std3D_BlinkWord(uint32_t val)
{
    for (int nib = 7; nib >= 0; nib--) {
        uint32_t n = (val >> (nib * 4)) & 0xF;
        vid_border_color(0, 255, 0); std3D_ExcSpin(EXC_UNIT);       // GREEN: nibble start
        vid_border_color(0, 0, 0);   std3D_ExcSpin(EXC_UNIT / 2);
        for (int bit = 3; bit >= 0; bit--) {
            if (n & (1u << bit)) vid_border_color(255, 0, 0);       // RED  = 1
            else                 vid_border_color(0, 0, 255);       // BLUE = 0
            std3D_ExcSpin(EXC_UNIT);
            vid_border_color(0, 0, 0); std3D_ExcSpin(EXC_UNIT / 2); // gap between bits
        }
    }
}

// Catch SH4 CPU faults and blink the fault registers out on the border (the framebuffer
// is unreachable from an exception context; the border register always works). Maps
// back to source with sh-elf-addr2line -e openjkdf2.elf <PC>. Never returns -- the game
// is wedged anyway. Registered in std3D_Startup only when the tracer is enabled.
static void std3D_ExcHandler(irq_t code, irq_context_t* ctx, void* data)
{
    (void)data; (void)code;
    uint32_t tea = *(volatile uint32_t*)0xFF00000C; // SH4 TEA: faulting data address

    // Blink the fault registers out on the border in binary (the framebuffer is
    // unreachable from an exception; the border register always works). Film it and
    // decode per std3D_BlinkWord's scheme. Loops forever over PC, then PR, then the
    // faulting address, each introduced by a long identifying color.
    for (;;) {
        vid_border_color(255, 255, 255); std3D_ExcSpin(EXC_UNIT * 5); // WHITE = PC next
        std3D_BlinkWord(ctx->pc);
        vid_border_color(255, 255, 0);   std3D_ExcSpin(EXC_UNIT * 5); // YELLOW = PR next
        std3D_BlinkWord(ctx->pr);
        vid_border_color(255, 0, 255);   std3D_ExcSpin(EXC_UNIT * 5); // MAGENTA = addr next
        std3D_BlinkWord(tea);
    }
}

// --- Texture cache -----------------------------------------------------------
typedef struct dcTexEntry {
    rdDDrawSurface* surf;
    pvr_ptr_t       ptr;
    int             w, h;
    int             fmt;   // PVR_TXRFMT_* (incl. NONTWIDDLED)
} dcTexEntry;
static dcTexEntry std3D_aTex[STD3D_MAX_TEXTURES] = {0};
static size_t     std3D_numTex = 0;

// Texture-cache LRU (ported from the TWL/original path). Cached textures are kept
// in a doubly-linked list on the surface (pFirst/pLastTexCache + the surface's
// pNext/pPrevCachedTexture links); frameNum records last use. Lets
// std3D_PurgeTextureCache evict the oldest textures to satisfy an allocation
// instead of nuking the whole cache. (These globals live in generated/globals.h.)

static rdColor24 std3D_currentPalette[256];

// --- Menu/HUD overlay texture ------------------------------------------------
// PVR textures must be power-of-two; the 640x480 menu buffer lives in the
// top-left of a 1024x512 texture (index 0 -> transparent for the HUD).
//
// Two implementations, selected by STD3D_MENU_PALETTED:
//   0 (default): expand the 8-bit menu buffer to a non-twiddled ARGB1555 texture
//                on the CPU each frame and upload it (pvr_txr_load, no twiddle).
//   1: upload the raw 8-bit indices as a *paletted* PAL8BPP texture and let the
//      PVR do the lookup through a hardware palette bank (bank 0 = current
//      palette). Half the VRAM/upload, but paletted textures must be twiddled and
//      pvr_txr_load_ex's per-frame twiddle of the full 1024x512 has shown up as
//      lag -- kept here for the game-texture (static, twiddle-once) work.
#define STD3D_MENU_PALETTED 0
#define MENU_TEX_W 1024
#define MENU_TEX_H 512
#define MENU_PAL_BANK 0
#define MENU_PAL_BASE (MENU_PAL_BANK * 256)
static pvr_ptr_t std3D_menuTex = NULL;
#if STD3D_MENU_PALETTED
static uint8_t*  std3D_pMenuStaging = NULL; // 1024x512 8-bit index staging in main RAM
#else
static uint16_t* std3D_pMenuStaging = NULL; // 1024x512 ARGB1555 staging in main RAM
#endif

static void std3D_UpdateWorldPaletteBanks(void); // defined in the texture cache section
static void std3D_EmitDeferredTR(void);          // defined in the render list section

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
        // opb sizes: [OP_POLY, OP_MOD, TR_POLY, TR_MOD, PT_POLY]. TR enabled for
        // alpha-blended (translucent) world geometry; OP_MOD/TR_MOD stay off.
        pvr_init_params_t params = {
            { PVR_BINSIZE_32, PVR_BINSIZE_0, PVR_BINSIZE_32, PVR_BINSIZE_0, PVR_BINSIZE_32 },
            512 * 1024, // vertex buffer size (known-VRAM-safe)
            0,          // dma
            0,          // fsaa
            // #1 test: autosort DISABLED. Autosort is the OPB-hungriest PVR mode;
            // the engine already depth-sorts (rdCache_ProcFaceCompare) so TR should
            // still look right. Set back to 0 to re-enable if it doesn't help.
            1,          // autosort_disabled
            // Extra object-pointer-buffer blocks the TA grabs when a screen tile
            // overflows its bin. 3 is far too small for full 3D maps: on hardware the
            // TA stalls waiting for OPB space and hangs the next pvr_wait_ready
            // (Flycast treats the OPB as unlimited). 16 is still VRAM-cheap next to
            // the vertex buffer -- dial down if pvr_mem complains at startup.
            16          // extra OPBs for heavy geometry
        };
        pvr_init(&params);
        pvr_set_bg_color(0.0f, 0.0f, 0.0f);

        // 16-bit ARGB1555 palette entries, globally, for all paletted textures
        // (world 8bpp textures and the optional paletted menu). 1-bit alpha matches
        // the engine's index-0 colorkey transparency.
        pvr_set_pal_format(PVR_PAL_ARGB1555);

#if STD3D_MENU_PALETTED
        // Menu overlay texture + its main-RAM staging buffer (kept for the session).
        // 8bpp paletted: half the VRAM and upload bandwidth of the old ARGB1555 path.
        std3D_menuTex = pvr_mem_malloc(MENU_TEX_W * MENU_TEX_H * 1);
        std3D_pMenuStaging = (uint8_t*)memalign(32, MENU_TEX_W * MENU_TEX_H * 1);
        if (std3D_pMenuStaging)
            memset(std3D_pMenuStaging, 0, MENU_TEX_W * MENU_TEX_H * 1);
#else
        // Menu overlay texture + its main-RAM staging buffer (kept for the session).
        std3D_menuTex = pvr_mem_malloc(MENU_TEX_W * MENU_TEX_H * 2);
        std3D_pMenuStaging = (uint16_t*)memalign(32, MENU_TEX_W * MENU_TEX_H * 2);
        if (std3D_pMenuStaging)
            memset(std3D_pMenuStaging, 0, MENU_TEX_W * MENU_TEX_H * 2);
#endif

        std3D_bPvrReady = 1;
    }

#ifndef STD3D_BORDER_TRACE
    // Sneaky enable: a controller plugged into port 4 (0-indexed port 3) turns on
    // the border loop tracer for this run, no rebuild needed.
    if (maple_enum_dev(3, 0) != NULL) std3D_bBorderTrace = 1;
#endif

    // When the tracer is on, also catch CPU faults and flash the border (see
    // std3D_ExcHandler). Registered once.
    if (std3D_bBorderTrace) {
        static int excHooked = 0;
        if (!excHooked) {
            excHooked = 1;
            arch_irq_set_handler(EXC_DATA_ADDRESS_READ,  std3D_ExcHandler, NULL);
            arch_irq_set_handler(EXC_DATA_ADDRESS_WRITE, std3D_ExcHandler, NULL);
            arch_irq_set_handler(EXC_ILLEGAL_INSTR,      std3D_ExcHandler, NULL);
        }
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

    // Refresh the world palette banks if the level colormap changed (cheap: gated
    // on a pointer compare). Must run before scene_finish reads the palette.
    std3D_UpdateWorldPaletteBanks();

    std3D_numDeferTR = 0; // fresh translucent buffer for the frame

    // If a previous scene was never finished (an early-out somewhere skipped
    // EndScene), close it out so we never deadlock on pvr_wait_ready.
    if (std3D_bInScene) std3D_EndScene();

    // TEMP HW DIAGNOSTIC (border/overscan color = where the loop is stuck; visible
    // with no console). RED just before pvr_wait_ready, GREEN once it returns. If the
    // screen freezes with a RED border, pvr_wait_ready is blocking on a render-done
    // IRQ that never fired; BLUE (set in EndScene) means we're stuck in the game sim,
    // not the PVR at all.
    std3D_BorderTrace(255, 0, 0);  // RED: about to wait for the previous render
    pvr_wait_ready();
    std3D_BorderTrace(0, 255, 0);  // GREEN: wait returned, registering this scene
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
#if STD3D_MENU_PALETTED
                     PVR_TXRFMT_PAL8BPP | PVR_TXRFMT_8BPP_PAL(MENU_PAL_BANK),
#else
                     PVR_TXRFMT_ARGB1555 | PVR_TXRFMT_NONTWIDDLED,
#endif
                     MENU_TEX_W, MENU_TEX_H, std3D_menuTex, PVR_FILTER_NEAREST);
    cxt.gen.culling = PVR_CULLING_NONE;
    // The HUD/menu overlay is always on top of the 3D scene. Without this it depth-
    // tests against the world (which writes nearer 1/w values) and gets occluded.
    // Depth WRITE is on so the overlay stamps its huge z into the depth buffer; the
    // translucent (TR) pass renders after PT, and this makes those tris fail the
    // GREATER test against the HUD and stay behind it.
    cxt.depth.comparison = PVR_DEPTHCMP_ALWAYS;
    cxt.depth.write = 1;
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
    const float z = 1.0e6f; // in front of the menu overlay (z=1)

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

    // Translucent world geometry deferred during the frame, flushed last (the PVR
    // renders TR after OP/PT). Autosort orders them back-to-front for us.
    if (std3D_numDeferTR) {
        pvr_list_begin(PVR_LIST_TR_POLY);
        std3D_EmitDeferredTR();
        pvr_list_finish();
    }

    pvr_scene_finish();
    std3D_bInScene = 0;
    std3D_BorderTrace(0, 0, 255);  // BLUE: scene submitted; loop now back in the game
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

static inline void std3D_ConvertVertex(pvr_vertex_t* v, const D3DVERTEX* vtx,
                                       int textured, uint32_t cmd, int keepAlpha)
{
    v->flags = cmd;
    v->x = vtx->x;
    v->y = vtx->y;

    // The PVR's vertex z is 1/w: it is interpolated linearly in screen space for
    // both depth (GEQUAL, nearer = larger) and perspective-correct texturing.
    // rdCache stores the engine's true 1/w (== 1/z_camera) in nx, scaled by 1/32
    // (rdCache.c:744). Using the depth-buffer value 1/(1-z) instead is ~w (the
    // reciprocal), which only approximates perspective and skews the texture on
    // triangles that span a large depth range — most visible at the screen edges.
    v->z = vtx->nx * 32.0f;

    if (textured) { v->u = vtx->tu; v->v = vtx->tv; }
    else          { v->u = 0.0f;    v->v = 0.0f;    }

    // Vertex color carries baked lighting (0xAARRGGBB). The OP list forces opaque;
    // the TR list keeps the engine's alpha so MODULATEALPHA blends by it.
    v->argb  = keepAlpha ? vtx->color : (0xFF000000u | (vtx->color & 0x00FFFFFFu));
    v->oargb = 0;
}

static inline void std3D_EmitVertex(const D3DVERTEX* vtx, int textured, uint32_t cmd)
{
    pvr_vertex_t v;
    std3D_ConvertVertex(&v, vtx, textured, cmd, 0);
    pvr_prim(&v, sizeof(v));
}

// Flush the deferred translucent triangles into the (already-open) TR list.
static void std3D_EmitDeferredTR(void)
{
    rdDDrawSurface* lastTex = (rdDDrawSurface*)~0;
    for (size_t i = 0; i < std3D_numDeferTR; i++)
    {
        dcDeferTri* d = &std3D_deferTR[i];
        if (d->tex != lastTex)
        {
            pvr_poly_cxt_t cxt;
            pvr_poly_hdr_t hdr;
            if (d->textured && d->tex && d->tex->texture_loaded
                && (size_t)d->tex->texture_id < std3D_numTex)
            {
                dcTexEntry* e = &std3D_aTex[d->tex->texture_id];
                pvr_poly_cxt_txr(&cxt, PVR_LIST_TR_POLY, e->fmt, e->w, e->h,
                                 e->ptr, PVR_FILTER_NEAREST);
            }
            else
            {
                pvr_poly_cxt_col(&cxt, PVR_LIST_TR_POLY);
            }
            cxt.gen.culling = PVR_CULLING_NONE;
            cxt.depth.write = 0; // translucent geometry must not occlude
            pvr_poly_compile(&hdr, &cxt);
            pvr_prim(&hdr, sizeof(hdr));
            lastTex = d->tex;
        }
        pvr_prim(&d->v[0], sizeof(pvr_vertex_t));
        pvr_prim(&d->v[1], sizeof(pvr_vertex_t));
        pvr_prim(&d->v[2], sizeof(pvr_vertex_t));
    }
}

void std3D_DrawRenderList()
{
    if (Main_bHeadless || !std3D_bInScene || !std3D_bOpListOpen || !GL_tmpTrisAmt) {
        std3D_ResetRenderList();
        return;
    }

    rdTri*     tris  = GL_tmpTris;
    D3DVERTEX* verts = GL_tmpVertices;

    rdDDrawSurface* lastTex = (rdDDrawSurface*)~0;
    int textured = 0;

    for (size_t j = 0; j < GL_tmpTrisAmt; j++)
    {
        rdDDrawSurface* tex = tris[j].texture;
        int isTex = tex && tex->texture_loaded && (size_t)tex->texture_id < std3D_numTex;

        // Translucent (flags & 0x600): defer to the TR pass, keeping the vertex
        // alpha so the PVR blends it. Everything else goes straight to the OP list.
        if (!STD3D_DISABLE_TR && (tris[j].flags & 0x600))
        {
            if (std3D_numDeferTR < STD3D_MAX_DEFER_TRIS)
            {
                dcDeferTri* d = &std3D_deferTR[std3D_numDeferTR++];
                d->tex = isTex ? tex : NULL;
                d->textured = isTex;
                std3D_ConvertVertex(&d->v[0], &verts[tris[j].v1], isTex, PVR_CMD_VERTEX,     1);
                std3D_ConvertVertex(&d->v[1], &verts[tris[j].v2], isTex, PVR_CMD_VERTEX,     1);
                std3D_ConvertVertex(&d->v[2], &verts[tris[j].v3], isTex, PVR_CMD_VERTEX_EOL, 1);
            }
            continue;
        }

        // Re-emit the poly header whenever the bound texture changes.
        if (tex != lastTex)
        {
            pvr_poly_cxt_t cxt;
            pvr_poly_hdr_t hdr;
            if (isTex)
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

// --- World texture palette banks ---------------------------------------------
// 8-bit world/model textures are indices into the level colormap. We upload that
// colormap once into hardware palette banks (ARGB1555) and reference them from
// PAL8BPP textures, so those textures upload at 1 byte/pixel instead of being
// expanded to 16-bit -- the swizzle/twiddle is paid once at load, not per frame.
// The two banks differ only in index 0: colorkey (transparent) for alpha textures
// and opaque for the rest, mirroring the engine's index-0 colorkey. Lighting comes
// from the modulated vertex color, so a single (unlit) colormap suffices; banks 2-3
// are left for the emissive/full-bright variants later.
#define WORLD_PAL_BANK_CK      0   // index 0 transparent (is_alpha_tex colorkey)
#define WORLD_PAL_BANK_OPAQUE  1   // index 0 opaque
static void* std3D_loadedColormap = NULL;

static inline int std3D_IsPow2(uint32_t n) { return n && !(n & (n - 1)); }

// Populate the world palette banks from the current level colormap. Gated on the
// colormap pointer changing (level load), like the TWL update_from_world_palette.
static void std3D_UpdateWorldPaletteBanks()
{
    if (!sithWorld_pCurrentWorld || !sithWorld_pCurrentWorld->colormaps) return;
    rdColormap* pCmp = sithWorld_pCurrentWorld->colormaps;
    if ((void*)pCmp == std3D_loadedColormap) return; // unchanged since last upload
    std3D_loadedColormap = (void*)pCmp;

    for (int i = 0; i < 256; i++)
    {
        rdColor24* c = &pCmp->colors[i];
        uint16_t rgb = ((c->r >> 3) << 10) | ((c->g >> 3) << 5) | (c->b >> 3);
        pvr_set_pal_entry(WORLD_PAL_BANK_CK     * 256 + i, (i == 0) ? 0x0000u : (0x8000u | rgb));
        pvr_set_pal_entry(WORLD_PAL_BANK_OPAQUE * 256 + i, 0x8000u | rgb);
    }
}

// Allocate VRAM for a texture; if the heap is full, evict LRU cache entries to make
// room and retry once (the original OOM strategy).
static pvr_ptr_t std3D_pvrAllocOrPurge(size_t bytes)
{
    pvr_ptr_t p = pvr_mem_malloc(bytes);
    if (!p) {
        std3D_PurgeTextureCache(bytes);
        p = pvr_mem_malloc(bytes);
    }
    return p;
}

int std3D_AddToTextureCache(stdVBuffer* vbuf, rdDDrawSurface* texture, int is_alpha_tex, int no_alpha)
{
    if (Main_bHeadless) return 1;
    if (!vbuf || !texture) return 1;
    if (texture->texture_loaded) return 1;
    if (std3D_numTex >= STD3D_MAX_TEXTURES) return 1;

    uint32_t width  = vbuf->format.width;
    uint32_t height = vbuf->format.height;
    if (!width || !height) return 1;

    std3D_UpdateWorldPaletteBanks();

    int fmt;
    pvr_ptr_t ptr;
    uint32_t  texBytes = 0; // VRAM bytes (tracked for the LRU purge accounting)
    uint8_t*  src8  = (uint8_t*)vbuf->surface_lock_alloc;
    uint16_t* src16 = (uint16_t*)vbuf->surface_lock_alloc;

    // Fast path: 8-bit textures that index the world colormap upload as raw PAL8BPP
    // (1 byte/pixel, half the bandwidth). Paletted textures must be twiddled, which
    // requires power-of-two dims; anything else falls through to 16-bit expansion.
    int usePaletted = !vbuf->format.format.is16bit
                   && std3D_IsPow2(width) && std3D_IsPow2(height)
                   && sithWorld_pCurrentWorld && sithWorld_pCurrentWorld->colormaps;

    if (usePaletted)
    {
        uint8_t* staging8 = (uint8_t*)memalign(32, width * height);
        if (!staging8) return 1;
        uint32_t rowpx = vbuf->format.width_in_bytes;
        for (uint32_t y = 0; y < height; y++)
            memcpy(staging8 + (size_t)y * width, src8 + (size_t)y * rowpx, width);

        texBytes = width * height;
        ptr = std3D_pvrAllocOrPurge(texBytes);
        if (!ptr) { free(staging8); return 1; }
        // pvr_txr_load_ex twiddles during upload (required for paletted textures).
        pvr_txr_load_ex(staging8, ptr, width, height, PVR_TXRLOAD_8BPP);
        free(staging8);

        int bank = is_alpha_tex ? WORLD_PAL_BANK_CK : WORLD_PAL_BANK_OPAQUE;
        fmt = PVR_TXRFMT_PAL8BPP | PVR_TXRFMT_8BPP_PAL(bank);
    }
    else
    {
        uint16_t* staging = (uint16_t*)memalign(32, width * height * 2);
        if (!staging) return 1;

        if (vbuf->format.format.is16bit)
        {
            // Engine 565 / ARGB1555 share the PVR bit layout: straight copy.
            uint32_t rowpx = vbuf->format.width_in_bytes / 2;
            for (uint32_t y = 0; y < height; y++)
                for (uint32_t x = 0; x < width; x++)
                    staging[y * width + x] = src16[y * rowpx + x];
        }
        else
        {
            // 8-bit (non-POT or no colormap) -> expand through the texture palette.
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
        }
        fmt = (is_alpha_tex ? PVR_TXRFMT_ARGB1555 : PVR_TXRFMT_RGB565) | PVR_TXRFMT_NONTWIDDLED;

        texBytes = width * height * 2;
        ptr = std3D_pvrAllocOrPurge(texBytes);
        if (!ptr) { free(staging); return 1; }
        pvr_txr_load(staging, ptr, width * height * 2);
        free(staging);
    }

    // Reuse a slot freed by std3D_PurgeSurfaceRefs before growing the high-water
    // mark, so streaming maps don't march the cache to STD3D_MAX_TEXTURES.
    size_t idx = std3D_numTex;
    for (size_t i = 0; i < std3D_numTex; i++) {
        if (!std3D_aTex[i].surf && !std3D_aTex[i].ptr) { idx = i; break; }
    }
    if (idx == std3D_numTex) {
        if (std3D_numTex >= STD3D_MAX_TEXTURES) { pvr_mem_free(ptr); return 1; }
        std3D_numTex++;
    }
    std3D_aTex[idx].surf = texture;
    std3D_aTex[idx].ptr  = ptr;
    std3D_aTex[idx].w    = width;
    std3D_aTex[idx].h    = height;
    std3D_aTex[idx].fmt  = fmt;

    texture->texture_id     = (int)idx;
    texture->texture_loaded = 1;
    texture->is_16bit       = vbuf->format.format.is16bit ? 1 : 0;
    texture->textureSize    = texBytes;         // for LRU purge accounting
    std3D_AddTextureToCacheList(texture);       // newest -> MRU end of the list
    texture->frameNum       = std3D_frameCount;
    return 1;
}

void std3D_UnloadAllTextures()
{
    for (size_t i = 0; i < std3D_numTex; i++)
    {
        if (std3D_aTex[i].ptr) pvr_mem_free(std3D_aTex[i].ptr);
        if (std3D_aTex[i].surf) {
            std3D_aTex[i].surf->texture_loaded = 0;
            std3D_aTex[i].surf->pNextCachedTexture = NULL;
            std3D_aTex[i].surf->pPrevCachedTexture = NULL;
        }
        std3D_aTex[i].ptr = NULL;
        std3D_aTex[i].surf = NULL;
    }
    std3D_numTex = 0;
    std3D_pFirstTexCache = NULL;
    std3D_pLastTexCache  = NULL;
    std3D_numCachedTextures = 0;
}

void std3D_PurgeEntireTextureCache() { std3D_UnloadAllTextures(); }

// --- LRU cache list (from OpenJones3D / the original std3D) -------------------
void std3D_RemoveTextureFromCacheList(rdDDrawSurface* pCacheTexture)
{
    if (!pCacheTexture) return;

    if (pCacheTexture == std3D_pFirstTexCache)
    {
        std3D_pFirstTexCache = pCacheTexture->pNextCachedTexture;
        if (std3D_pFirstTexCache)
        {
            std3D_pFirstTexCache->pPrevCachedTexture = NULL;
            if (!std3D_pFirstTexCache->pNextCachedTexture)
                std3D_pLastTexCache = std3D_pFirstTexCache;
        }
        else
            std3D_pLastTexCache = NULL;
    }
    else if (pCacheTexture == std3D_pLastTexCache)
    {
        std3D_pLastTexCache = pCacheTexture->pPrevCachedTexture;
        if (pCacheTexture->pPrevCachedTexture)
            pCacheTexture->pPrevCachedTexture->pNextCachedTexture = NULL;
        else
            std3D_pLastTexCache = std3D_pFirstTexCache;
    }
    else
    {
        if (pCacheTexture->pPrevCachedTexture)
            pCacheTexture->pPrevCachedTexture->pNextCachedTexture = pCacheTexture->pNextCachedTexture;
        if (pCacheTexture->pNextCachedTexture)
            pCacheTexture->pNextCachedTexture->pPrevCachedTexture = pCacheTexture->pPrevCachedTexture;
    }

    pCacheTexture->pNextCachedTexture = NULL;
    pCacheTexture->pPrevCachedTexture = NULL;
    pCacheTexture->frameNum = 0;
    --std3D_numCachedTextures;
}

void std3D_AddTextureToCacheList(rdDDrawSurface* pTexture)
{
    if (!pTexture) return;

    if (std3D_pFirstTexCache)
    {
        std3D_pLastTexCache->pNextCachedTexture = pTexture;
        pTexture->pPrevCachedTexture            = std3D_pLastTexCache;
        pTexture->pNextCachedTexture            = NULL;
        std3D_pLastTexCache                     = pTexture;
    }
    else
    {
        std3D_pLastTexCache          = pTexture;
        std3D_pFirstTexCache         = pTexture;
        pTexture->pPrevCachedTexture = NULL;
        pTexture->pNextCachedTexture = NULL;
    }
    ++std3D_numCachedTextures;
}

// Bump a texture to most-recently-used and stamp the current frame (called when a
// texture is bound for rendering).
void std3D_UpdateFrameCount(rdDDrawSurface* pTexture)
{
    if (!pTexture) return;
    std3D_RemoveTextureFromCacheList(pTexture);
    std3D_AddTextureToCacheList(pTexture);
    pTexture->frameNum = std3D_frameCount;
}

// Free the VRAM texture backing a surface, release its cache slot, and unlink it
// from the LRU list. Called by rdMaterial's unload path (rdMaterial.c) -- without
// this the PVR texture heap leaks as maps stream materials and eventually corrupts.
void std3D_PurgeSurfaceRefs(rdDDrawSurface* texture)
{
    if (!texture) return;
    for (size_t i = 0; i < std3D_numTex; i++) {
        if (std3D_aTex[i].surf != texture) continue;
        if (std3D_aTex[i].ptr) pvr_mem_free(std3D_aTex[i].ptr);
        std3D_aTex[i].ptr  = NULL;
        std3D_aTex[i].surf = NULL; // slot reusable by std3D_AddToTextureCache
    }
    std3D_RemoveTextureFromCacheList(texture);
    texture->texture_loaded = 0;
}

void std3D_PurgeTextureEntry(int i)
{
    if (i < 0 || (size_t)i >= std3D_numTex) return;
    if (std3D_aTex[i].surf) std3D_PurgeSurfaceRefs(std3D_aTex[i].surf);
}

// Evict cached textures to free at least `size` bytes of VRAM. Mirrors the original
// std3D_PurgeTextureCache: first try to reuse an exact-size victim, otherwise evict
// oldest-first. Never touch the current or previous frame's textures -- the PVR is
// still rasterizing the previous scene from them.
int std3D_PurgeTextureCache(size_t size)
{
    size_t purgedBytes = 0;

    for (rdDDrawSurface* pTex = std3D_pFirstTexCache;
         pTex && !(pTex->frameNum == std3D_frameCount || pTex->frameNum == std3D_frameCount - 1);
         pTex = pTex->pNextCachedTexture)
    {
        if (pTex->textureSize == size) {
            std3D_PurgeSurfaceRefs(pTex);
            return 1;
        }
    }

    rdDDrawSurface* pNext = NULL;
    for (rdDDrawSurface* pTex = std3D_pFirstTexCache; pTex && purgedBytes < size; pTex = pNext)
    {
        pNext = pTex->pNextCachedTexture;
        if (pTex->frameNum == std3D_frameCount || pTex->frameNum == std3D_frameCount - 1)
            continue;
        purgedBytes += pTex->textureSize;
        std3D_PurgeSurfaceRefs(pTex);
    }
    return purgedBytes != 0;
}

void std3D_PurgeUIEntry(int i, int idx)      {}
void std3D_PurgeBitmapRefs(stdBitmap* pBitmap) {}

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
// Report colorkey/alpha-texture support so rdCache selects the alpha material
// variant and tags those tris with flag 0x400 (rdCache.c:538/558 -- "blaster
// shots, etc"). is_alpha_tex already loads them into the colorkey palette bank
// (index 0 transparent); the 0x400 flag routes them to the TR pass, where
// MODULATEALPHA + the transparent index-0 gives a proper cutout.
int std3D_HasAlpha()             { return 1; }
// Report modulated-alpha support so rdCache keeps translucent materials' vertex
// alpha (~90/255) instead of forcing them opaque (rdCache.c:391). Those tris get
// flag 0x600 and are routed to the PVR TR list with alpha blending.
int std3D_HasModulateAlpha()     { return 1; }
int std3D_HasAlphaFlatStippled() { return 1; }

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

    int w = (srcW < 640) ? srcW : 640;
    int h = (srcH < 480) ? srcH : 480;
    const uint8_t* src = (const uint8_t*)Video_menuBuffer.surface_lock_alloc;

#if STD3D_MENU_PALETTED
    // Push the current palette into hardware bank 0 (ARGB1555). Index 0 stays
    // transparent (alpha bit clear) so the punch-through overlay shows the world
    // through the HUD's empty areas; everything else is opaque.
    //
    // The 256 register writes are only needed when the palette actually changes
    // (menu<->world transitions, palette effects), so gate them on a memcmp of the
    // master palette -- same trick as the GL3 renderer's displaypal_data cache.
    static rdColor24 menuPalCache[256];
    static int menuPalCacheValid = 0;
    if (!menuPalCacheValid || memcmp(menuPalCache, stdDisplay_masterPalette, 0x300))
    {
        memcpy(menuPalCache, stdDisplay_masterPalette, 0x300);
        menuPalCacheValid = 1;
        pvr_set_pal_entry(MENU_PAL_BASE + 0, 0x0000);
        for (int i = 1; i < 256; i++)
        {
            const rdColor24* c = &stdDisplay_masterPalette[i];
            pvr_set_pal_entry(MENU_PAL_BASE + i,
                              0x8000u | ((c->r >> 3) << 10) | ((c->g >> 3) << 5) | (c->b >> 3));
        }
    }

    // Copy the raw 8-bit indices straight into the staging buffer -- no per-pixel
    // palette expansion; the PVR does the lookup. (The unused padding columns/rows
    // are never sampled by the overlay quad, so they don't need clearing.)
    for (int y = 0; y < h; y++)
    {
        const uint8_t* srow = src + (size_t)y * pitch;
        uint8_t* drow = std3D_pMenuStaging + (size_t)y * MENU_TEX_W;
        memcpy(drow, srow, w);
    }

    // pvr_txr_load_ex twiddles (required for paletted textures) during upload.
    pvr_txr_load_ex(std3D_pMenuStaging, std3D_menuTex, MENU_TEX_W, MENU_TEX_H, PVR_TXRLOAD_8BPP);
#else
    // Expand the 8-bit menu buffer to ARGB1555 on the CPU and upload it untwiddled.
    static uint16_t pal1555[256];
    for (int i = 0; i < 256; i++)
    {
        const rdColor24* c = &stdDisplay_masterPalette[i];
        pal1555[i] = (uint16_t)(0x8000 | ((c->r >> 3) << 10) | ((c->g >> 3) << 5) | (c->b >> 3));
    }

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
#endif
    std3D_bMenuPending = 1;
}

void std3D_ResetUIRenderList() {}
int  std3D_AddBitmapToTextureCache(stdBitmap* texture, int mipIdx, int is_alpha_tex, int no_alpha) { return 0; }
void std3D_DrawUIBitmapRGBA(stdBitmap* pBmp, int mipIdx, flex_t dstX, flex_t dstY, rdRect* srcRect, flex_t scaleX, flex_t scaleY, int bAlphaOverwrite, uint8_t color_r, uint8_t color_g, uint8_t color_b, uint8_t color_a) {}
void std3D_DrawUIBitmap(stdBitmap* pBmp, int mipIdx, flex_t dstX, flex_t dstY, rdRect* srcRect, flex_t scale, int bAlphaOverwrite) {}
void std3D_DrawUIClearedRect(uint8_t palIdx, rdRect* dstRect) {}
void std3D_DrawUIClearedRectRGBA(uint8_t color_r, uint8_t color_g, uint8_t color_b, uint8_t color_a, rdRect* dstRect) {}
