// OpenGL 1.1 fixed-function renderer for legacy targets (e.g. Windows XP).
//
// This is a desktop SDL2 backend (it defines SDL2_RENDER and implements the same
// std3D contract as src/Platform/GL/std3D.c), but it draws with the GL 1.1
// fixed-function pipeline in immediate mode -- no shaders, no VBOs, no FBOs --
// structurally similar to the DSi backend in src/Platform/TWL/std3D.c.
//
// Per-vertex math is replicated from resource/shaders/default_v.glsl on the CPU
// so that geometry and perspective-correct texturing match the modern renderer:
//   pos = mvp * (x,y,z,1);  w = 1/(1-z);  gl_Position = vec4(pos.xyz*w, w)
// We emit that via glVertex4f() with identity GL matrices.
//
// UI/HUD entry points are intentionally stubbed (like TWL): menus are expected to
// be presented through a separate SDL software-paletted path, and the HW-text dev
// console is compiled out for this target.
//
// Intentional simplifications (the engine already bakes scene lighting into the
// vertex colors, so plain modulation looks correct without these):
//  - The DSi emissive/dynamic-light path (D3DVERTEX_ext.lightLevel / shader
//    f_light) is deliberately not ported -- it relies on hardware palette tricks
//    that aren't available/guaranteed under GL 1.1. We modulate texture * vertex
//    color only.
//  - Fog is not wired up (the desktop std3D contract has no SetFog* entry point,
//    and it was a DSi-specific draw-distance feature).
//
// Possible on-hardware tuning (deferred):
//  - Blended polys use standard glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
//    the modern shader pre-multiplies alpha, so additive/window blends may differ.

#include "Platform/std3D.h"

#include <stdlib.h>
#include <string.h>

#include "SDL2_helper.h"

#include <SDL_opengl.h>
#include <SDL_video.h>

#include "Win95/stdDisplay.h"
#include "Win95/Window.h"
#include "World/sithWorld.h"
#include "Engine/rdColormap.h"
#include "Engine/rdCamera.h"
#include "Main/jkGame.h"
#include "Main/Main.h"
#include "World/jkPlayer.h"
#include "General/stdBitmap.h"
#include "stdPlatform.h"
#include "jk.h"

#define COMP_B(c) ((c) & 0xFF)
#define COMP_G(c) (((c) >> 8) & 0xFF)
#define COMP_R(c) (((c) >> 16) & 0xFF)
#define COMP_A(c) (((c) >> 24) & 0xFF)

// Tri flag bits (shared with the modern renderer's DrawRenderList state machine)
#define STD3D_TRI_DEPTHTEST  0x800
#define STD3D_TRI_BLEND      0x600
#define STD3D_TRI_BLEND_INV  0x200
#define STD3D_TRI_DEPTHWRITE 0x1000
#define STD3D_TRI_CULLBACK   0x10000

// --- GL_EXT_paletted_texture (optional 8-bit hardware palette path) ----------
#ifndef APIENTRY
#define APIENTRY
#endif
#ifndef GL_COLOR_INDEX8_EXT
#define GL_COLOR_INDEX8_EXT 0x80E5
#endif
#ifndef GL_COLOR_INDEX
#define GL_COLOR_INDEX 0x1900
#endif
typedef void (APIENTRY *std3D_PFNGLCOLORTABLEEXTPROC)(GLenum target, GLenum internalFormat, GLsizei width, GLenum format, GLenum type, const void* table);
static std3D_PFNGLCOLORTABLEEXTPROC std3D_glColorTableEXT = NULL;
static int std3D_bHasPalettedTex = 0;

int std3D_bReinitHudElements = 0;
static int std3D_bHasInitted = 0;

// --- Render list accumulators -----------------------------------------------
// rdCache flushes accumulation at STD3D_MAX_VERTICES (0x400), but it submits a
// single dense procEntry as one batch that can exceed that (up to its own array
// capacity, RDCACHE_MAX_VERTICES). The modern backend reads an undersized VBO on
// overflow (benign, collapsed geometry); our immediate-mode path would instead
// read *stale* entries straight out of these static arrays, smearing last frame's
// geometry across the screen (a location-dependent "rotated" flicker). Size the
// buffers to the full batch capacity so a big batch is never partially dropped.
#define GL11_RL_MAX_VERTICES (RDCACHE_MAX_VERTICES)
#define GL11_RL_MAX_TRIS     (RDCACHE_MAX_VERTICES)
static D3DVERTEX GL_tmpVertices[GL11_RL_MAX_VERTICES] = {0};
static size_t    GL_tmpVerticesAmt = 0;
static rdTri     GL_tmpTris[GL11_RL_MAX_TRIS] = {0};
static size_t    GL_tmpTrisAmt = 0;

// --- Texture cache ----------------------------------------------------------
static rdDDrawSurface* std3D_aLoadedSurfaces[STD3D_MAX_TEXTURES] = {0};
static GLuint          std3D_aLoadedTextures[STD3D_MAX_TEXTURES] = {0};
static size_t          std3D_loadedTexturesAmt = 0;

static rdColor24 std3D_currentPalette[256];

// ----------------------------------------------------------------------------

// Software-paletted menu state: the engine renders the GUI/cutscene layers into
// the 8-bit Video_menuBuffer; we expand it to an RGB GL texture each frame and
// draw it as a fullscreen quad in the GL context (see std3D_DrawMenu).
static GLuint   std3D_menuTexId = 0;
static uint8_t* std3D_pMenuRGB = NULL;
static int      std3D_menuTexW = 0;
static int      std3D_menuTexH = 0;
static int      std3D_menuWinW = 0;  // drawable size captured for the subrect helper
static int      std3D_menuWinH = 0;

// UI / HUD overlay render list (ported from the modern backend). HUD status
// bitmaps (health/shield/force/items) and GPU-path font glyphs accumulate
// textured quads here during the frame; std3D_DrawUIRenderList flushes them on
// top of the menu/scene at the end of std3D_DrawMenu.
static GLuint    std3D_uiWhiteTex = 0;
static D3DVERTEX std3D_aUIVertices[STD3D_MAX_UI_VERTICES] = {0};
static size_t    std3D_uiVerticesAmt = 0;
static rdUITri   std3D_aUITris[STD3D_MAX_UI_TRIS] = {0};
static size_t    std3D_uiTrisAmt = 0;

static void std3D_DrawUIRenderList(void);

// Resolve the real GL drawable size (HiDPI-safe), falling back to Window_xSize.
// Used by both the menu and UI passes so their coordinate spaces stay in sync.
static void std3D_GetDrawableSize(int* pW, int* pH)
{
    int dw = Window_xSize, dh = Window_ySize;
    SDL_Window* pWin = SDL_GL_GetCurrentWindow();
    if (pWin) SDL_GL_GetDrawableSize(pWin, &dw, &dh);
    if (dw < 1) dw = 640;
    if (dh < 1) dh = 480;
    *pW = dw;
    *pH = dh;
}

int std3D_Startup()
{
    if (Main_bHeadless) return 1;

    const char* exts = (const char*)glGetString(GL_EXTENSIONS);
    if (exts && strstr(exts, "GL_EXT_paletted_texture"))
    {
        std3D_glColorTableEXT = (std3D_PFNGLCOLORTABLEEXTPROC)SDL_GL_GetProcAddress("glColorTableEXT");
        std3D_bHasPalettedTex = (std3D_glColorTableEXT != NULL);
    }

    glDisable(GL_LIGHTING);
    glEnable(GL_DEPTH_TEST);
    glDepthFunc(GL_LESS);
    glEnable(GL_BLEND);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
    glEnable(GL_CULL_FACE);
    glCullFace(GL_FRONT);
    glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_MODULATE);
    glClearColor(0.0f, 0.0f, 0.0f, 1.0f);
    glClearDepth(1.0);

    // 1x1 white texture for solid-color UI rects (std3D_DrawUIClearedRect*).
    // Guard so re-entry (see std3D_StartScene lazy re-init) doesn't leak it.
    if (!std3D_uiWhiteTex)
    glGenTextures(1, &std3D_uiWhiteTex);
    glBindTexture(GL_TEXTURE_2D, std3D_uiWhiteTex);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    {
        const uint8_t white[4] = { 255, 255, 255, 255 };
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, 1, 1, 0, GL_RGBA, GL_UNSIGNED_BYTE, white);
    }

    std3D_bHasInitted = 1;
    return 1;
}

void std3D_Shutdown()
{
    std3D_UnloadAllTextures();

    if (std3D_menuTexId)
    {
        glDeleteTextures(1, &std3D_menuTexId);
        std3D_menuTexId = 0;
    }
    if (std3D_pMenuRGB)
    {
        free(std3D_pMenuRGB);
        std3D_pMenuRGB = NULL;
    }
    std3D_menuTexW = 0;
    std3D_menuTexH = 0;

    if (std3D_uiWhiteTex)
    {
        glDeleteTextures(1, &std3D_uiWhiteTex);
        std3D_uiWhiteTex = 0;
    }

    std3D_bHasInitted = 0;
}

int std3D_StartScene()
{
    if (Main_bHeadless) return 0;

    // The engine tears the renderer down on GUI/menu transitions (Video_SwitchToGDI
    // -> std3D_Shutdown) but the GDI->game restore path (Video_SetVideoDesc) can
    // skip std3D_Startup. GL 1.1 keeps a single persistent context, so just
    // re-initialize on demand whenever we find ourselves shut down.
    if (!std3D_bHasInitted)
        std3D_Startup();

    glMatrixMode(GL_PROJECTION);
    glLoadIdentity();
    glMatrixMode(GL_MODELVIEW);
    glLoadIdentity();

    glDepthMask(GL_TRUE);
    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
    return 0;
}

int std3D_EndScene()
{
    // Buffer swap is performed by Window.c (SDL_GL_SwapWindow).
    return 0;
}

void std3D_ResetRenderList()
{
    GL_tmpVerticesAmt = 0;
    GL_tmpTrisAmt = 0;
}

int std3D_RenderListVerticesFinish()
{
    return 0;
}

int std3D_AddRenderListVertices(D3DVERTEX* vertices, int count)
{
    if (Main_bHeadless) return 1;
    if (GL_tmpVerticesAmt + count >= GL11_RL_MAX_VERTICES)
        return 0;

    memcpy(&GL_tmpVertices[GL_tmpVerticesAmt], vertices, sizeof(D3DVERTEX) * count);
    GL_tmpVerticesAmt += count;
    return 1;
}

void std3D_AddRenderListTris(rdTri* tris, unsigned int num_tris)
{
    if (Main_bHeadless) return;
    if (GL_tmpTrisAmt + num_tris > GL11_RL_MAX_TRIS)
        return;

    memcpy(&GL_tmpTris[GL_tmpTrisAmt], tris, sizeof(rdTri) * num_tris);
    GL_tmpTrisAmt += num_tris;
}

void std3D_AddRenderListLines(rdLine* lines, uint32_t num_lines)
{
    // Debug lines are not drawn by the GL 1.1 backend.
}

// Replicates default_v.glsl: maps a screen-space vertex through `mvp` and applies
// the 1/(1-z) perspective-correct w, then emits a clip-space glVertex4f.
static void std3D_EmitVertex(const D3DVERTEX* v, const float* m, int textured)
{
    float x = v->x, y = v->y, z = v->z;

    float px = m[0]  * x + m[12];
    float py = m[5]  * y + m[13];
    float pz = m[10] * z + m[14];

    float denom = 1.0f - z;
    // Avoid a divide-by-zero, but preserve the sign: a small *negative* denom means
    // the vertex is past the camera plane (w should stay negative so GL clips it).
    // Clamping it to +1e-6 would flip w positive and fling the vertex far in front,
    // smearing a huge triangle across the screen for a frame as geometry crosses
    // the camera plane (the modern shader has no guard and clips correctly).
    if (denom < 1e-6f && denom > -1e-6f)
        denom = (denom < 0.0f) ? -1e-6f : 1e-6f;
    float w = 1.0f / denom;

    glColor4ub(COMP_R(v->color), COMP_G(v->color), COMP_B(v->color), COMP_A(v->color));
    if (textured)
        glTexCoord2f(v->tu, v->tv);
    glVertex4f(px * w, py * w, pz * w, w);
}

void std3D_DrawRenderList()
{
    if (Main_bHeadless || !GL_tmpTrisAmt)
    {
        std3D_ResetRenderList();
        return;
    }

    float internalWidth  = (float)Video_menuBuffer.format.width;
    float internalHeight = (float)Video_menuBuffer.format.height;
    if (internalWidth < 1.0f)  internalWidth  = 640.0f;
    if (internalHeight < 1.0f) internalHeight = 480.0f;

    float scaleX = 1.0f / (internalWidth  / 2.0f);
    float scaleY = 1.0f / (internalHeight / 2.0f);
    int   bPerspective = (!rdCamera_pCurCamera ||
                          rdCamera_pCurCamera->projectType == rdCameraProjectType_Perspective);

    // mvp, column-major, matching the world matrix in src/Platform/GL/std3D.c
    float mvp[16] = {0};
    mvp[0]  = scaleX;
    mvp[5]  = -scaleY;
    mvp[10] = 1.0f;
    mvp[12] = -(internalWidth  / 2.0f) * scaleX;   // -> -1
    mvp[13] =  (internalHeight / 2.0f) * scaleY;   // -> +1
    mvp[14] = bPerspective ? -1.0f : 1.0f;
    mvp[15] = 1.0f;

    glMatrixMode(GL_PROJECTION);
    glLoadIdentity();
    glMatrixMode(GL_MODELVIEW);
    glLoadIdentity();
    glViewport(0, 0, Window_xSize, Window_ySize);

    glEnable(GL_DEPTH_TEST);
    glEnable(GL_BLEND);
    glEnable(GL_ALPHA_TEST);
    glAlphaFunc(GL_GREATER, 0.0f); // drop fully-transparent (color-keyed) texels
    glEnable(GL_CULL_FACE);
    glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_MODULATE);

    rdTri*      tris  = GL_tmpTris;
    D3DVERTEX*  verts = GL_tmpVertices;

    rdDDrawSurface* lastTex   = (rdDDrawSurface*)~0;
    uint32_t        lastFlags = ~0u;
    int             textured  = 0;

    for (size_t j = 0; j < GL_tmpTrisAmt; j++)
    {
        // Safety net: never index past the vertices actually submitted this batch
        // (reading the stale tail of the static array shows last frame's geometry).
        if ((size_t)tris[j].v1 >= GL_tmpVerticesAmt ||
            (size_t)tris[j].v2 >= GL_tmpVerticesAmt ||
            (size_t)tris[j].v3 >= GL_tmpVerticesAmt)
            continue;

        rdDDrawSurface* tex   = tris[j].texture;
        uint32_t        flags = tris[j].flags;

        if (tex != lastTex)
        {
            if (tex && tex->texture_loaded)
            {
                glEnable(GL_TEXTURE_2D);
                glBindTexture(GL_TEXTURE_2D, tex->texture_id);
                textured = 1;
            }
            else
            {
                glDisable(GL_TEXTURE_2D);
                textured = 0;
            }
            lastTex = tex;
        }

        if (flags != lastFlags)
        {
            glDepthFunc((flags & STD3D_TRI_DEPTHTEST) ? GL_LESS : GL_ALWAYS);

            if (flags & STD3D_TRI_BLEND)
                glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
            else
                glBlendFunc(GL_ONE, GL_ZERO);

            glDepthMask((flags & STD3D_TRI_DEPTHWRITE) ? GL_TRUE : GL_FALSE);
            glCullFace((flags & STD3D_TRI_CULLBACK) ? GL_BACK : GL_FRONT);
            lastFlags = flags;
        }

        glBegin(GL_TRIANGLES);
        std3D_EmitVertex(&verts[tris[j].v1], mvp, textured);
        std3D_EmitVertex(&verts[tris[j].v2], mvp, textured);
        std3D_EmitVertex(&verts[tris[j].v3], mvp, textured);
        glEnd();
    }

    glDisable(GL_TEXTURE_2D);
    glDepthMask(GL_TRUE);

    std3D_ResetRenderList();
}

int std3D_ClearZBuffer()
{
    glDepthMask(GL_TRUE);
    glClear(GL_DEPTH_BUFFER_BIT);
    return 1;
}

// 5-bit -> 8-bit and 6-bit -> 8-bit channel expansion (matches the modern renderer).
static inline uint8_t std3D_Expand5(uint8_t v5) { return (uint8_t)((v5 * 527 + 23) >> 6); }
static inline uint8_t std3D_Expand6(uint8_t v6) { return (uint8_t)((v6 * 259 + 33) >> 6); }

int std3D_AddToTextureCache(stdVBuffer* vbuf, rdDDrawSurface* texture, int is_alpha_tex, int no_alpha)
{
    if (Main_bHeadless) return 1;
    if (!vbuf || !texture) return 1;
    if (texture->texture_loaded) return 1;

    if (std3D_loadedTexturesAmt >= STD3D_MAX_TEXTURES)
    {
        stdPlatform_Printf("ERROR: GL11 texture cache exhausted!\n");
        return 1;
    }

    uint32_t width  = vbuf->format.width;
    uint32_t height = vbuf->format.height;
    uint8_t*  src8  = (uint8_t*)vbuf->sdlSurface->pixels;
    uint16_t* src16 = (uint16_t*)vbuf->sdlSurface->pixels;

    GLuint image_texture;
    glGenTextures(1, &image_texture);
    glBindTexture(GL_TEXTURE_2D, image_texture);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_REPEAT);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT);

    if (jkPlayer_enableTextureFilter && vbuf->format.format.is16bit)
    {
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    }
    else
    {
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    }

    if (vbuf->format.format.is16bit)
    {
        // GL 1.1 has no packed-pixel upload formats, so expand 565/1555 to RGBA8
        // on the CPU and request a 16-bit internal format to keep VRAM small.
        texture->is_16bit = 1;
        uint32_t* image_data = (uint32_t*)malloc((size_t)width * height * 4);
        for (uint32_t i = 0; i < width * height; i++)
        {
            uint16_t val = src16[i];
            uint8_t r8, g8, b8, a8;
            if (!is_alpha_tex) // RGB565
            {
                r8 = std3D_Expand5((val >> 11) & 0x1F);
                g8 = std3D_Expand6((val >> 5)  & 0x3F);
                b8 = std3D_Expand5((val >> 0)  & 0x1F);
                a8 = 0xFF;
            }
            else // RGB1555
            {
                a8 = (val >> 15) ? 0xFF : 0x00;
                r8 = std3D_Expand5((val >> 10) & 0x1F);
                g8 = std3D_Expand5((val >> 5)  & 0x1F);
                b8 = std3D_Expand5((val >> 0)  & 0x1F);
            }
            image_data[i] = (uint32_t)r8 | ((uint32_t)g8 << 8) | ((uint32_t)b8 << 16) | ((uint32_t)a8 << 24);
        }
        glTexImage2D(GL_TEXTURE_2D, 0, is_alpha_tex ? GL_RGB5_A1 : GL_RGB5,
                     width, height, 0, GL_RGBA, GL_UNSIGNED_BYTE, image_data);
        free(image_data);
    }
    else
    {
        texture->is_16bit = 0;
        uint8_t* pal = (uint8_t*)vbuf->palette; // 3 bytes/entry when present

        if (std3D_bHasPalettedTex)
        {
            // Hardware 8-bit path: upload indices + an RGBA color table. Index 0 is
            // the color key, so it gets alpha 0.
            uint8_t table[256 * 4];
            for (int k = 0; k < 256; k++)
            {
                uint8_t r, g, b;
                if (pal) { r = pal[k*3+0]; g = pal[k*3+1]; b = pal[k*3+2]; }
                else if (sithWorld_pCurrentWorld && sithWorld_pCurrentWorld->colormaps)
                {
                    rdColor24* c = &sithWorld_pCurrentWorld->colormaps->colors[k];
                    r = c->r; g = c->g; b = c->b;
                }
                else { r = std3D_currentPalette[k].r; g = std3D_currentPalette[k].g; b = std3D_currentPalette[k].b; }
                table[k*4+0] = r;
                table[k*4+1] = g;
                table[k*4+2] = b;
                table[k*4+3] = (k == 0 && !no_alpha) ? 0x00 : 0xFF;
            }
            std3D_glColorTableEXT(GL_TEXTURE_2D, GL_RGBA8, 256, GL_RGBA, GL_UNSIGNED_BYTE, table);
            glTexImage2D(GL_TEXTURE_2D, 0, GL_COLOR_INDEX8_EXT, width, height, 0,
                         GL_COLOR_INDEX, GL_UNSIGNED_BYTE, src8);
        }
        else
        {
            // Software fallback: expand 8-bit indices through the palette to RGBA8.
            uint32_t* image_data = (uint32_t*)malloc((size_t)width * height * 4);
            for (uint32_t i = 0; i < width * height; i++)
            {
                uint8_t idx = src8[i];
                uint8_t r, g, b;
                if (pal) { r = pal[idx*3+0]; g = pal[idx*3+1]; b = pal[idx*3+2]; }
                else if (sithWorld_pCurrentWorld && sithWorld_pCurrentWorld->colormaps)
                {
                    rdColor24* c = &sithWorld_pCurrentWorld->colormaps->colors[idx];
                    r = c->r; g = c->g; b = c->b;
                }
                else { r = std3D_currentPalette[idx].r; g = std3D_currentPalette[idx].g; b = std3D_currentPalette[idx].b; }
                uint8_t a = (idx == 0 && !no_alpha) ? 0x00 : 0xFF;
                image_data[i] = (uint32_t)r | ((uint32_t)g << 8) | ((uint32_t)b << 16) | ((uint32_t)a << 24);
            }
            glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, width, height, 0, GL_RGBA, GL_UNSIGNED_BYTE, image_data);
            free(image_data);
        }
    }

    std3D_aLoadedSurfaces[std3D_loadedTexturesAmt] = texture;
    std3D_aLoadedTextures[std3D_loadedTexturesAmt++] = image_texture;

    texture->texture_id = image_texture;
    texture->texture_loaded = 1;
    texture->pDataDepthConverted = NULL;

    glBindTexture(GL_TEXTURE_2D, 0);
    return 1;
}

int std3D_SetCurrentPalette(rdColor24* a1, int a2)
{
    if (a1)
        memcpy(std3D_currentPalette, a1, sizeof(std3D_currentPalette));
    return 1;
}

void std3D_GetValidDimension(unsigned int inW, unsigned int inH, unsigned int* outW, unsigned int* outH)
{
    if (outW) *outW = inW;
    if (outH) *outH = inH;
}

// --- Texture cache eviction --------------------------------------------------

static void std3D_RemoveLoadedIndex(size_t i)
{
    if (i >= std3D_loadedTexturesAmt) return;
    glDeleteTextures(1, &std3D_aLoadedTextures[i]);
    if (std3D_aLoadedSurfaces[i])
        std3D_aLoadedSurfaces[i]->texture_loaded = 0;

    std3D_loadedTexturesAmt--;
    std3D_aLoadedSurfaces[i] = std3D_aLoadedSurfaces[std3D_loadedTexturesAmt];
    std3D_aLoadedTextures[i] = std3D_aLoadedTextures[std3D_loadedTexturesAmt];
    std3D_aLoadedSurfaces[std3D_loadedTexturesAmt] = NULL;
    std3D_aLoadedTextures[std3D_loadedTexturesAmt] = 0;
}

void std3D_UnloadAllTextures()
{
    for (size_t i = 0; i < std3D_loadedTexturesAmt; i++)
    {
        glDeleteTextures(1, &std3D_aLoadedTextures[i]);
        if (std3D_aLoadedSurfaces[i])
            std3D_aLoadedSurfaces[i]->texture_loaded = 0;
        std3D_aLoadedSurfaces[i] = NULL;
        std3D_aLoadedTextures[i] = 0;
    }
    std3D_loadedTexturesAmt = 0;
}

void std3D_PurgeEntireTextureCache()
{
    std3D_UnloadAllTextures();
}

int std3D_PurgeTextureCache(size_t size)
{
    std3D_UnloadAllTextures();
    return 1;
}

void std3D_RemoveTextureFromCacheList(rdDDrawSurface* pCacheTexture)
{
    for (size_t i = 0; i < std3D_loadedTexturesAmt; i++)
    {
        if (std3D_aLoadedSurfaces[i] == pCacheTexture)
        {
            std3D_RemoveLoadedIndex(i);
            return;
        }
    }
}

void std3D_AddTextureToCacheList(rdDDrawSurface* pTexture)
{
    // Textures are registered on upload in std3D_AddToTextureCache.
}

void std3D_PurgeSurfaceRefs(rdDDrawSurface* texture)
{
    std3D_RemoveTextureFromCacheList(texture);
}

void std3D_PurgeBitmapRefs(stdBitmap* pBitmap)
{
    // Release any GL textures this bitmap uploaded for the UI render list.
    if (!pBitmap || !pBitmap->abLoadedToGPU || !pBitmap->aTextureIds) return;
    for (int i = 0; i < pBitmap->numMips; i++)
    {
        if (pBitmap->abLoadedToGPU[i])
        {
            GLuint tex = pBitmap->aTextureIds[i];
            if (tex) glDeleteTextures(1, &tex);
            pBitmap->aTextureIds[i] = 0;
            pBitmap->abLoadedToGPU[i] = 0;
        }
    }
}

void std3D_UpdateFrameCount(rdDDrawSurface* pTexture)
{
    // No LRU tracking in the GL 1.1 backend.
}

// --- Contract stubs ----------------------------------------------------------
// UI/HUD, FBO and overlay paths are intentionally not implemented (see header).

// Emits one textured quad of the menu texture, mirroring the modern backend's
// std3D_DrawMenuSubrect: (x,y,w,h) is the source rect in menu-buffer texels,
// (dstX,dstY) is the top-left destination in screen pixels, and `scale` multiplies
// the destination size. scale==0 is the "proportional" mode used for full-buffer
// fills (source maps 1:1 to the drawable). (cr,cg,cb) modulates the texels --
// white for normal draws, black for the subtitle drop-shadow outline.
static void std3D_DrawMenuSubrect(float x, float y, float w, float h,
                                  float dstX, float dstY, float scale,
                                  uint8_t cr, uint8_t cg, uint8_t cb)
{
    float tex_w = (float)std3D_menuTexW;
    float tex_h = (float)std3D_menuTexH;
    if (tex_w < 1.0f) tex_w = 1.0f;
    if (tex_h < 1.0f) tex_h = 1.0f;

    float w_dst = w, h_dst = h;
    if (scale == 0.0f)
    {
        w_dst = (w / tex_w) * (float)std3D_menuWinW;
        h_dst = (h / tex_h) * (float)std3D_menuWinH;
        dstX  = (dstX / tex_w) * (float)std3D_menuWinW;
        dstY  = (dstY / tex_h) * (float)std3D_menuWinH;
        scale = 1.0f;
    }

    float u1 = x / tex_w, u2 = (x + w) / tex_w;
    float v1 = y / tex_h, v2 = (y + h) / tex_h;
    float x0 = dstX, y0 = dstY;
    float x1 = dstX + scale * w_dst, y1 = dstY + scale * h_dst;

    glColor4ub(cr, cg, cb, 255);
    glBegin(GL_TRIANGLES);
        glTexCoord2f(u1, v1); glVertex2f(x0, y0);
        glTexCoord2f(u1, v2); glVertex2f(x0, y1);
        glTexCoord2f(u2, v2); glVertex2f(x1, y1);

        glTexCoord2f(u1, v1); glVertex2f(x0, y0);
        glTexCoord2f(u2, v2); glVertex2f(x1, y1);
        glTexCoord2f(u2, v1); glVertex2f(x1, y0);
    glEnd();
}

// Software-paletted menu presentation.
//
// The GUI/menu and 2D cutscene layers are software-rendered by the engine into
// the 8-bit paletted Video_menuBuffer. GL 1.1 has no shader to do the palette
// lookup the modern backend uses, so we expand the indices to RGBA8888 on the CPU
// through stdDisplay_masterPalette (matching the modern renderer's displaypal),
// upload to a GL texture, and draw it in the existing GL context. Geometry/layout
// (menu pillarbox, cutscene letterbox + subtitles, in-game HUD compositing) mirror
// std3D_DrawMenu in src/Platform/GL/std3D.c.
void std3D_DrawMenu()
{
    if (Main_bHeadless) return;

    // Read the SDL surface pixels directly (like the modern backend): the engine
    // leaves the menu buffer unlocked when it's not actively drawing, which nulls
    // surface_lock_alloc -- but sdlSurface->pixels is always valid for a software
    // surface.
    if (!Video_menuBuffer.sdlSurface) return;

    const int srcW = Video_menuBuffer.format.width;
    const int srcH = Video_menuBuffer.format.height;
    const uint8_t* pSrc = (const uint8_t*)Video_menuBuffer.sdlSurface->pixels;
    if (srcW <= 0 || srcH <= 0 || !pSrc) return;

    const uint32_t srcPitch = Video_menuBuffer.sdlSurface->pitch;

    // (Re)allocate the CPU scratch buffer and GL texture when dimensions change.
    // RGBA: palette index 0 is the color-key (transparent) entry -> alpha 0, so
    // the 3D scene shows through where the HUD/menu buffer is empty (this pass is
    // also the in-game 2D/HUD compositing step, called every frame from
    // jkGame_Render -- it must NOT clear or opaquely overpaint the 3D scene).
    if (std3D_menuTexW != srcW || std3D_menuTexH != srcH || !std3D_menuTexId)
    {
        if (std3D_pMenuRGB) free(std3D_pMenuRGB);
        std3D_pMenuRGB = (uint8_t*)malloc((size_t)srcW * srcH * 4);
        std3D_menuTexW = srcW;
        std3D_menuTexH = srcH;

        if (!std3D_menuTexId)
            glGenTextures(1, &std3D_menuTexId);
        glBindTexture(GL_TEXTURE_2D, std3D_menuTexId);
        // Nearest keeps the color-key edges crisp (no alpha fringing at the
        // transparent border, matching the modern shader's per-texel discard).
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, srcW, srcH, 0, GL_RGBA, GL_UNSIGNED_BYTE, NULL);
    }
    if (!std3D_pMenuRGB) return;

    // Expand the 8-bit indices through the display palette into RGBA8888;
    // index 0 -> fully transparent (matches menu_f.glsl's `if (index == 0) discard`).
    for (int y = 0; y < srcH; ++y)
    {
        const uint8_t* pRow = pSrc + (size_t)y * srcPitch;
        uint8_t* pDst = std3D_pMenuRGB + (size_t)y * srcW * 4;
        for (int x = 0; x < srcW; ++x)
        {
            uint8_t idx = pRow[x];
            if (idx == 0)
            {
                *pDst++ = 0; *pDst++ = 0; *pDst++ = 0; *pDst++ = 0;
            }
            else
            {
                const rdColor24* pCol = &stdDisplay_masterPalette[idx];
                *pDst++ = pCol->r;
                *pDst++ = pCol->g;
                *pDst++ = pCol->b;
                *pDst++ = 255;
            }
        }
    }

    glBindTexture(GL_TEXTURE_2D, std3D_menuTexId);
    glPixelStorei(GL_UNPACK_ALIGNMENT, 4);
    glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, srcW, srcH, GL_RGBA, GL_UNSIGNED_BYTE, std3D_pMenuRGB);

    // Query the real drawable size (HiDPI-safe) rather than Window_xSize, which
    // may not be updated until the first resize event.
    int dw, dh;
    std3D_GetDrawableSize(&dw, &dh);
    std3D_menuWinW = dw;
    std3D_menuWinH = dh;
    glViewport(0, 0, dw, dh);

    // Screen-space projection: (0,0) top-left -> (dw,dh) bottom-right, so the
    // ported subrect destinations are in screen pixels just like the modern path.
    glMatrixMode(GL_PROJECTION);
    glLoadIdentity();
    glOrtho(0.0, (double)dw, (double)dh, 0.0, -1.0, 1.0);
    glMatrixMode(GL_MODELVIEW);
    glLoadIdentity();

    glDisable(GL_DEPTH_TEST);
    glDepthMask(GL_FALSE);
    glDisable(GL_CULL_FACE);
    glDisable(GL_BLEND);
    glEnable(GL_ALPHA_TEST);
    glAlphaFunc(GL_GREATER, 0.5f); // discard transparent (index-0) texels
    glEnable(GL_TEXTURE_2D);

    extern int jkGuiBuildMulti_bRendering;

    if (jkCutscene_isRendering)
    {
        // Letterboxed cutscene: video band (centered, width-fit), optional
        // subtitles with a black drop-shadow outline, and the pause text band.
        // Source bands live in the top-left 640-wide column of the menu buffer.
        float fake_windowW = (float)dw;
        float fake_windowH = (float)dh;

        int video_height = Main_bMotsCompat ? 350 : 300;
        int subs_y = Main_bMotsCompat ? 400 : 350;
        int subs_h = Main_bMotsCompat ? 80  : 130;

        // For ultrawide screens, limit the video width to 16:9.
        if (dw > dh && ((float)dw / (float)dh) > (Main_bMotsCompat ? (16.0f / 9.0f) : (21.0f / 9.0f)))
            fake_windowW = fake_windowH * (16.0f / 9.0f);

        float upscale  = fake_windowW / 640.0f;
        float upscale2 = (fake_windowH - (50.0f + video_height * upscale)) / (float)subs_h;
        float upscale3 = 1.0f;

        if (upscale2 < 1.0f)
        {
            upscale2 = 1.0f;
            if (fake_windowH > 480.0f)
                upscale2 = 2.0f;
        }
        if (upscale2 > upscale)
            upscale2 = upscale;

        float shift_y = ((float)dh - fake_windowH) / 2.0f;
        float shift_x = ((float)dw - fake_windowW) / 2.0f;

        float sub_width = 640.0f * upscale2;
        float sub_x = (fake_windowW - sub_width) / 2.0f;

        float pause_width = 640.0f * upscale3;
        float pause_x = (fake_windowW - pause_width) / 2.0f;

        // Main video view
        std3D_DrawMenuSubrect(0, 50, 640, video_height, shift_x, shift_y + 50, upscale, 255, 255, 255);

        // Subtitles (drop-shadow outline drawn black, then the text in white)
        if (jkCutscene_dword_55B750)
        {
            float sub_dstX = shift_x + sub_x;
            float sub_dstY = shift_y + fake_windowH - (subs_h * upscale2);
            std3D_DrawMenuSubrect(0, subs_y, 640, subs_h, sub_dstX - 2, sub_dstY,     upscale2, 0, 0, 0);
            std3D_DrawMenuSubrect(0, subs_y, 640, subs_h, sub_dstX + 2, sub_dstY,     upscale2, 0, 0, 0);
            std3D_DrawMenuSubrect(0, subs_y, 640, subs_h, sub_dstX,     sub_dstY - 2, upscale2, 0, 0, 0);
            std3D_DrawMenuSubrect(0, subs_y, 640, subs_h, sub_dstX,     sub_dstY + 2, upscale2, 0, 0, 0);
            std3D_DrawMenuSubrect(0, subs_y, 640, subs_h, sub_dstX,     sub_dstY,     upscale2, 255, 255, 255);
        }

        // Pause text
        std3D_DrawMenuSubrect(0, 10, 640, 40, shift_x + pause_x, shift_y, upscale3, 255, 255, 255);
    }
    else if (!jkGame_isDDraw || jkGuiBuildMulti_bRendering)
    {
        // Full-screen GUI menus render at a fixed 640x480 in the top-left of the
        // menu buffer; sample that sub-rect and pillarbox to a 4:3 aspect.
        float menu_h = (float)dh;
        float menu_w = menu_h * (640.0f / 480.0f);
        float menu_x = ((float)dw - menu_w) / 2.0f;
        std3D_DrawMenuSubrect(0, 0, 640, 480, menu_x, 0, menu_w / 640.0f, 255, 255, 255);
    }
    else
    {
        // In-game HUD overlay: the buffer is full-resolution; stretch it 1:1 over
        // the already-rendered 3D scene (index-0 texels are discarded above).
        std3D_DrawMenuSubrect(0, 0, (float)srcW, (float)srcH, 0, 0, 0.0f, 255, 255, 255);
    }

    // Composite the accumulated HUD/UI overlay on top of the menu/scene.
    std3D_DrawUIRenderList();

    // Restore the baseline state set up in std3D_Startup for the 3D path.
    glDisable(GL_ALPHA_TEST);
    glEnable(GL_DEPTH_TEST);
    glEnable(GL_CULL_FACE);
    glEnable(GL_BLEND);
    glDepthMask(GL_TRUE);
}
void std3D_DrawSceneFbo() {}
void std3D_FreeResources() {}
int  std3D_DrawOverlay() { return 1; }
void std3D_InitializeViewport(rdRect* viewRect) {}
int  std3D_GetValidDimensions(int a1, int a2, int a3, int a4) { return 1; }
int  std3D_FindClosestDevice(uint32_t index, int a2) { return 0; }
int  std3D_SetRenderList(intptr_t a1) { return 0; }
intptr_t std3D_GetRenderList() { return 0; }
int  std3D_CreateExecuteBuffer() { return 1; }

void std3D_PurgeUIEntry(int i, int idx) {}
void std3D_PurgeTextureEntry(int i) {}
void std3D_UpdateSettings() {}
void std3D_Screenshot(const char* pFpath) {}
void std3D_ResetUIRenderList()
{
    std3D_uiVerticesAmt = 0;
    std3D_uiTrisAmt = 0;
}
int  std3D_IsReady() { return std3D_bHasInitted; }

int std3D_HasAlpha() { return 0; }
int std3D_HasModulateAlpha() { return 0; }
int std3D_HasAlphaFlatStippled() { return 0; }

// Convert a stdBitmap mip (8-bit paletted or 16-bit) to an RGBA8 GL texture and
// cache the id in the bitmap. Index 0 / the color key becomes transparent so the
// UI shader's discard behavior can be replicated with alpha test. Mirrors the
// modern std3D_AddBitmapToTextureCache.
int std3D_AddBitmapToTextureCache(stdBitmap* texture, int mipIdx, int is_alpha_tex, int no_alpha)
{
    if (Main_bHeadless) return 1;
    if (!std3D_bHasInitted) return 0;
    if (!texture) return 1;
    if (mipIdx >= texture->numMips) return 1;
    if (!texture->abLoadedToGPU || texture->abLoadedToGPU[mipIdx]) return 1;

    stdVBuffer* vbuf = texture->mipSurfaces[mipIdx];
    if (!vbuf || !vbuf->sdlSurface) return 1;

    uint32_t width  = vbuf->format.width;
    uint32_t height = vbuf->format.height;
    if (!width || !height) return 1;

    uint8_t*  src8  = (uint8_t*)vbuf->sdlSurface->pixels;
    uint16_t* src16 = (uint16_t*)vbuf->sdlSurface->pixels;

    GLuint image_texture;
    glGenTextures(1, &image_texture);
    glBindTexture(GL_TEXTURE_2D, image_texture);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);

    uint32_t* image_data = (uint32_t*)malloc((size_t)width * height * 4);
    if (!image_data) return 1;

    if (vbuf->format.format.is16bit || texture->format.bpp == 16)
    {
        texture->is_16bit = 1;
        uint32_t row_stride = vbuf->format.width_in_bytes / 2;
        int is565 = (vbuf->format.format.r_bits == 5 &&
                     vbuf->format.format.g_bits == 6 &&
                     vbuf->format.format.b_bits == 5);

        for (uint32_t j = 0; j < height; j++)
        {
            for (uint32_t i = 0; i < width; i++)
            {
                uint16_t val = src16[j * row_stride + i];
                uint8_t r8, g8, b8, a8;
                if (is565)
                {
                    r8 = std3D_Expand5((val >> 11) & 0x1F);
                    g8 = std3D_Expand6((val >> 5)  & 0x3F);
                    b8 = std3D_Expand5((val >> 0)  & 0x1F);
                    a8 = 0xFF;
                    if (vbuf->transparent_color &&
                        ((val >> 11) & 0x1F) == ((vbuf->transparent_color >> 11) & 0x1F) &&
                        ((val >> 5)  & 0x3F) == ((vbuf->transparent_color >> 5)  & 0x3F) &&
                        ((val >> 0)  & 0x1F) == ((vbuf->transparent_color >> 0)  & 0x1F))
                    {
                        a8 = 0x00;
                    }
                }
                else // ARGB1555
                {
                    a8 = (val >> 15) ? 0xFF : 0x00;
                    r8 = std3D_Expand5((val >> 10) & 0x1F);
                    g8 = std3D_Expand5((val >> 5)  & 0x1F);
                    b8 = std3D_Expand5((val >> 0)  & 0x1F);
                }
                image_data[j * width + i] = (uint32_t)r8 | ((uint32_t)g8 << 8) |
                                            ((uint32_t)b8 << 16) | ((uint32_t)a8 << 24);
            }
        }
    }
    else
    {
        texture->is_16bit = 0;
        uint8_t* pal = (uint8_t*)texture->palette; // 3 bytes/entry when present
        uint32_t row_stride = vbuf->format.width_in_bytes;

        for (uint32_t j = 0; j < height; j++)
        {
            for (uint32_t i = 0; i < width; i++)
            {
                uint8_t idx = src8[j * row_stride + i];
                uint8_t r, g, b;
                if (pal) { r = pal[idx*3+0]; g = pal[idx*3+1]; b = pal[idx*3+2]; }
                else { rdColor24* c = &stdDisplay_masterPalette[idx]; r = c->r; g = c->g; b = c->b; }
                uint8_t a = idx ? 0xFF : 0x00; // index 0 is the color key
                image_data[j * width + i] = (uint32_t)r | ((uint32_t)g << 8) |
                                            ((uint32_t)b << 16) | ((uint32_t)a << 24);
            }
        }
    }

    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, width, height, 0, GL_RGBA, GL_UNSIGNED_BYTE, image_data);
    free(image_data);

    texture->aTextureIds[mipIdx] = image_texture;
    texture->abLoadedToGPU[mipIdx] = 1;
    return 1;
}

// Accumulate a textured bitmap quad into the UI render list. Destination coords
// are in menu-buffer space and get scaled to the drawable here, matching the
// modern std3D_DrawUIBitmapRGBA.
void std3D_DrawUIBitmapRGBA(stdBitmap* pBmp, int mipIdx, flex_t dstX, flex_t dstY, rdRect* srcRect, flex_t scaleX, flex_t scaleY, int bAlphaOverwrite, uint8_t color_r, uint8_t color_g, uint8_t color_b, uint8_t color_a)
{
    if (Main_bHeadless || !pBmp) return;
    if (!pBmp->abLoadedToGPU || !pBmp->abLoadedToGPU[mipIdx])
        std3D_AddBitmapToTextureCache(pBmp, mipIdx, !(pBmp->palFmt & 1), 0);
    if (!pBmp->abLoadedToGPU[mipIdx]) return;

    extern int jkGuiBuildMulti_bRendering;
    int winW, winH;
    std3D_GetDrawableSize(&winW, &winH);

    float internalWidth  = (float)Video_menuBuffer.format.width;
    float internalHeight = (float)Video_menuBuffer.format.height;
    if (jkGuiBuildMulti_bRendering) { internalWidth = 640.0f; internalHeight = 480.0f; }
    if (internalWidth < 1.0f || internalHeight < 1.0f) return;

    float scaleX_ = (float)winW / internalWidth;
    float scaleY_ = (float)winH / internalHeight;
    dstX *= scaleX_;
    dstY *= scaleY_;

    float tex_w = (float)pBmp->mipSurfaces[0]->format.width;
    float tex_h = (float)pBmp->mipSurfaces[0]->format.height;
    if (tex_w < 1.0f || tex_h < 1.0f) return;

    float w = tex_w, h = tex_h, x = 0.0f, y = 0.0f;
    if (srcRect) { x = srcRect->x; y = srcRect->y; w = srcRect->width; h = srcRect->height; }

    float w_dst = w, h_dst = h;
    if (scaleX == 0.0f && scaleY == 0.0f)
    {
        w_dst = (w / tex_w) * (float)winW;
        h_dst = (h / tex_h) * (float)winH;
        dstX  = (dstX / tex_w) * (float)winW;
        dstY  = (dstY / tex_h) * (float)winH;
        scaleX = 1.0f;
        scaleY = 1.0f;
    }

    float dstScaleX = scaleX * scaleX_;
    float dstScaleY = scaleY * scaleY_;

    float u1 = x / tex_w, u2 = (x + w) / tex_w;
    float v1 = y / tex_h, v2 = (y + h) / tex_h;

    float x0 = dstX, y0 = dstY;
    float x1 = dstX + dstScaleX * w_dst, y1 = dstY + dstScaleY * h_dst;

    if (y1 < 0.0f || x1 < 0.0f) return;
    if (dstY > (float)winH || dstX > (float)winW) return;

    if (std3D_uiVerticesAmt + 4 > STD3D_MAX_UI_VERTICES) return;
    if (std3D_uiTrisAmt + 2 > STD3D_MAX_UI_TRIS) return;

    // Pack ARGB so the COMP_R/G/B/A macros (R at bits 16-23) read it back correctly.
    uint32_t color = ((uint32_t)color_r << 16) | ((uint32_t)color_g << 8) |
                     (uint32_t)color_b | ((uint32_t)color_a << 24);

    size_t v = std3D_uiVerticesAmt;
    std3D_aUIVertices[v+0].x = x0; std3D_aUIVertices[v+0].y = y0; std3D_aUIVertices[v+0].z = 0.0f; std3D_aUIVertices[v+0].tu = u1; std3D_aUIVertices[v+0].tv = v1; std3D_aUIVertices[v+0].color = color;
    std3D_aUIVertices[v+1].x = x0; std3D_aUIVertices[v+1].y = y1; std3D_aUIVertices[v+1].z = 0.0f; std3D_aUIVertices[v+1].tu = u1; std3D_aUIVertices[v+1].tv = v2; std3D_aUIVertices[v+1].color = color;
    std3D_aUIVertices[v+2].x = x1; std3D_aUIVertices[v+2].y = y1; std3D_aUIVertices[v+2].z = 0.0f; std3D_aUIVertices[v+2].tu = u2; std3D_aUIVertices[v+2].tv = v2; std3D_aUIVertices[v+2].color = color;
    std3D_aUIVertices[v+3].x = x1; std3D_aUIVertices[v+3].y = y0; std3D_aUIVertices[v+3].z = 0.0f; std3D_aUIVertices[v+3].tu = u2; std3D_aUIVertices[v+3].tv = v1; std3D_aUIVertices[v+3].color = color;

    size_t t = std3D_uiTrisAmt;
    std3D_aUITris[t+0].v1 = v+1; std3D_aUITris[t+0].v2 = v+0; std3D_aUITris[t+0].v3 = v+2; std3D_aUITris[t+0].flags = bAlphaOverwrite; std3D_aUITris[t+0].texture = pBmp->aTextureIds[mipIdx];
    std3D_aUITris[t+1].v1 = v+0; std3D_aUITris[t+1].v2 = v+3; std3D_aUITris[t+1].v3 = v+2; std3D_aUITris[t+1].flags = bAlphaOverwrite; std3D_aUITris[t+1].texture = pBmp->aTextureIds[mipIdx];

    std3D_uiVerticesAmt += 4;
    std3D_uiTrisAmt += 2;
}

void std3D_DrawUIBitmap(stdBitmap* pBmp, int mipIdx, flex_t dstX, flex_t dstY, rdRect* srcRect, flex_t scale, int bAlphaOverwrite)
{
    std3D_DrawUIBitmapRGBA(pBmp, mipIdx, dstX, dstY, srcRect, scale, scale, bAlphaOverwrite, 0xFF, 0xFF, 0xFF, 0xFF);
}

void std3D_DrawUIClearedRect(uint8_t palIdx, rdRect* dstRect)
{
    rdColor24* c = &stdDisplay_masterPalette[palIdx];
    std3D_DrawUIClearedRectRGBA(c->r, c->g, c->b, 0xFF, dstRect);
}

// Accumulate a solid-color rect (using the 1x1 white texture) into the UI list.
void std3D_DrawUIClearedRectRGBA(uint8_t color_r, uint8_t color_g, uint8_t color_b, uint8_t color_a, rdRect* dstRect)
{
    if (Main_bHeadless || !std3D_bHasInitted || !dstRect) return;

    extern int jkGuiBuildMulti_bRendering;
    int winW, winH;
    std3D_GetDrawableSize(&winW, &winH);

    float internalWidth  = (float)Video_menuBuffer.format.width;
    float internalHeight = (float)Video_menuBuffer.format.height;
    if (jkGuiBuildMulti_bRendering) { internalWidth = 640.0f; internalHeight = 480.0f; }
    if (internalWidth < 1.0f || internalHeight < 1.0f) return;
    if (!dstRect->width || !dstRect->height) return;

    float scaleX = (float)winW / internalWidth;
    float scaleY = (float)winH / internalHeight;

    float x0 = dstRect->x * scaleX;
    float y0 = dstRect->y * scaleY;
    float x1 = x0 + dstRect->width  * scaleX;
    float y1 = y0 + dstRect->height * scaleY;

    if (std3D_uiVerticesAmt + 4 > STD3D_MAX_UI_VERTICES) return;
    if (std3D_uiTrisAmt + 2 > STD3D_MAX_UI_TRIS) return;

    // Pack ARGB so the COMP_R/G/B/A macros (R at bits 16-23) read it back correctly.
    uint32_t color = ((uint32_t)color_r << 16) | ((uint32_t)color_g << 8) |
                     (uint32_t)color_b | ((uint32_t)color_a << 24);

    size_t v = std3D_uiVerticesAmt;
    std3D_aUIVertices[v+0].x = x0; std3D_aUIVertices[v+0].y = y0; std3D_aUIVertices[v+0].z = 0.0f; std3D_aUIVertices[v+0].tu = 0.0f; std3D_aUIVertices[v+0].tv = 0.0f; std3D_aUIVertices[v+0].color = color;
    std3D_aUIVertices[v+1].x = x0; std3D_aUIVertices[v+1].y = y1; std3D_aUIVertices[v+1].z = 0.0f; std3D_aUIVertices[v+1].tu = 0.0f; std3D_aUIVertices[v+1].tv = 1.0f; std3D_aUIVertices[v+1].color = color;
    std3D_aUIVertices[v+2].x = x1; std3D_aUIVertices[v+2].y = y1; std3D_aUIVertices[v+2].z = 0.0f; std3D_aUIVertices[v+2].tu = 1.0f; std3D_aUIVertices[v+2].tv = 1.0f; std3D_aUIVertices[v+2].color = color;
    std3D_aUIVertices[v+3].x = x1; std3D_aUIVertices[v+3].y = y0; std3D_aUIVertices[v+3].z = 0.0f; std3D_aUIVertices[v+3].tu = 1.0f; std3D_aUIVertices[v+3].tv = 0.0f; std3D_aUIVertices[v+3].color = color;

    size_t t = std3D_uiTrisAmt;
    std3D_aUITris[t+0].v1 = v+1; std3D_aUITris[t+0].v2 = v+0; std3D_aUITris[t+0].v3 = v+2; std3D_aUITris[t+0].flags = 0; std3D_aUITris[t+0].texture = std3D_uiWhiteTex;
    std3D_aUITris[t+1].v1 = v+0; std3D_aUITris[t+1].v2 = v+3; std3D_aUITris[t+1].v3 = v+2; std3D_aUITris[t+1].flags = 0; std3D_aUITris[t+1].texture = std3D_uiWhiteTex;

    std3D_uiVerticesAmt += 4;
    std3D_uiTrisAmt += 2;
}

// Flush the accumulated UI/HUD quads. Drawn in screen-pixel space with the same
// top-left ortho as the menu. flags (bAlphaOverwrite) selects the modern UI
// shader's two transparency modes: set -> discard color-keyed texels (blended);
// clear -> color-keyed texels become opaque black (no blend), matching ui_f.glsl.
static void std3D_DrawUIRenderList(void)
{
    if (Main_bHeadless || !std3D_uiTrisAmt)
    {
        std3D_ResetUIRenderList();
        return;
    }

    int winW, winH;
    std3D_GetDrawableSize(&winW, &winH);

    glViewport(0, 0, winW, winH);
    glMatrixMode(GL_PROJECTION);
    glLoadIdentity();
    glOrtho(0.0, (double)winW, (double)winH, 0.0, -1.0, 1.0);
    glMatrixMode(GL_MODELVIEW);
    glLoadIdentity();

    glDisable(GL_DEPTH_TEST);
    glDepthMask(GL_FALSE);
    glDisable(GL_CULL_FACE);
    glEnable(GL_TEXTURE_2D);
    glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_MODULATE);

    GLuint lastTex   = (GLuint)~0u;
    int    lastFlags = -1;

    for (size_t j = 0; j < std3D_uiTrisAmt; j++)
    {
        rdUITri* tri = &std3D_aUITris[j];

        if (tri->texture != lastTex)
        {
            glBindTexture(GL_TEXTURE_2D, tri->texture ? tri->texture : std3D_uiWhiteTex);
            lastTex = tri->texture;
        }
        if (tri->flags != lastFlags)
        {
            if (tri->flags)
            {
                // Color-keyed texels are discarded; the rest blends normally.
                glEnable(GL_BLEND);
                glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
                glEnable(GL_ALPHA_TEST);
                glAlphaFunc(GL_GREATER, 0.5f);
            }
            else
            {
                // Color-keyed texels become opaque black; opaque rect/text fills.
                glDisable(GL_BLEND);
                glDisable(GL_ALPHA_TEST);
            }
            lastFlags = tri->flags;
        }

        const D3DVERTEX* a = &std3D_aUIVertices[tri->v1];
        const D3DVERTEX* b = &std3D_aUIVertices[tri->v2];
        const D3DVERTEX* c = &std3D_aUIVertices[tri->v3];

        glBegin(GL_TRIANGLES);
            glColor4ub(COMP_R(a->color), COMP_G(a->color), COMP_B(a->color), COMP_A(a->color));
            glTexCoord2f(a->tu, a->tv); glVertex2f(a->x, a->y);
            glColor4ub(COMP_R(b->color), COMP_G(b->color), COMP_B(b->color), COMP_A(b->color));
            glTexCoord2f(b->tu, b->tv); glVertex2f(b->x, b->y);
            glColor4ub(COMP_R(c->color), COMP_G(c->color), COMP_B(c->color), COMP_A(c->color));
            glTexCoord2f(c->tu, c->tv); glVertex2f(c->x, c->y);
        glEnd();
    }

    glDisable(GL_ALPHA_TEST);
    std3D_ResetUIRenderList();
}
