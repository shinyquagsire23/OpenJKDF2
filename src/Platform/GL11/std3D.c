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
static D3DVERTEX GL_tmpVertices[STD3D_MAX_VERTICES] = {0};
static size_t    GL_tmpVerticesAmt = 0;
static rdTri     GL_tmpTris[STD3D_MAX_TRIS] = {0};
static size_t    GL_tmpTrisAmt = 0;

// --- Texture cache ----------------------------------------------------------
static rdDDrawSurface* std3D_aLoadedSurfaces[STD3D_MAX_TEXTURES] = {0};
static GLuint          std3D_aLoadedTextures[STD3D_MAX_TEXTURES] = {0};
static size_t          std3D_loadedTexturesAmt = 0;

static rdColor24 std3D_currentPalette[256];

// ----------------------------------------------------------------------------

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

    std3D_bHasInitted = 1;
    return 1;
}

void std3D_Shutdown()
{
    std3D_UnloadAllTextures();
    std3D_bHasInitted = 0;
}

int std3D_StartScene()
{
    if (Main_bHeadless) return 0;

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
    if (GL_tmpVerticesAmt + count >= STD3D_MAX_VERTICES)
        return 0;

    memcpy(&GL_tmpVertices[GL_tmpVerticesAmt], vertices, sizeof(D3DVERTEX) * count);
    GL_tmpVerticesAmt += count;
    return 1;
}

void std3D_AddRenderListTris(rdTri* tris, unsigned int num_tris)
{
    if (Main_bHeadless) return;
    if (GL_tmpTrisAmt + num_tris > STD3D_MAX_TRIS)
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
    if (denom < 1e-6f && denom > -1e-6f)
        denom = 1e-6f;
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
    // UI bitmaps are not cached by the GL 1.1 backend (no UI render path).
}

void std3D_UpdateFrameCount(rdDDrawSurface* pTexture)
{
    // No LRU tracking in the GL 1.1 backend.
}

// --- Contract stubs ----------------------------------------------------------
// UI/HUD, FBO and overlay paths are intentionally not implemented (see header).

void std3D_DrawMenu() {}
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
void std3D_ResetUIRenderList() {}
int  std3D_IsReady() { return std3D_bHasInitted; }

int std3D_HasAlpha() { return 0; }
int std3D_HasModulateAlpha() { return 0; }
int std3D_HasAlphaFlatStippled() { return 0; }

int std3D_AddBitmapToTextureCache(stdBitmap* texture, int mipIdx, int is_alpha_tex, int no_alpha) { return 0; }
void std3D_DrawUIBitmapRGBA(stdBitmap* pBmp, int mipIdx, flex_t dstX, flex_t dstY, rdRect* srcRect, flex_t scaleX, flex_t scaleY, int bAlphaOverwrite, uint8_t color_r, uint8_t color_g, uint8_t color_b, uint8_t color_a) {}
void std3D_DrawUIBitmap(stdBitmap* pBmp, int mipIdx, flex_t dstX, flex_t dstY, rdRect* srcRect, flex_t scale, int bAlphaOverwrite) {}
void std3D_DrawUIClearedRect(uint8_t palIdx, rdRect* dstRect) {}
void std3D_DrawUIClearedRectRGBA(uint8_t color_r, uint8_t color_g, uint8_t color_b, uint8_t color_a, rdRect* dstRect) {}
