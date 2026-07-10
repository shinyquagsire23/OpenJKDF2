// Standalone functional test for the perspective, NON-z-buffered software rasterizer
// (rdNRaster). rdNRaster is not wired into OpenJKDF2's live render path (only rdZRaster is), so
// this direct-call test is its validation: it drives rdNRaster_DrawFace() with proc faces built
// by hand into a plain 8bpp framebuffer and checks the pixels.
//
// The key discriminating check: the SAME depth-varying triangle is drawn once perspective-correct
// (IT, textureMode 1 -> per-pixel 1/w divide) and once affine (AT, textureMode 0 -> linear u,v).
// With per-vertex depth variation the two sampling schemes MUST disagree, which proves the
// perspective divide actually runs (not silently collapsing to affine).
//
// Build: TARGET_BUILD_TESTS=1 on macOS with RDRASTER_SOFTWARE_RENDERER enabled.

#include "types.h"
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "Main/Main.h"
#include "stdPlatform.h"
#include "Win95/std.h"
#include "Raster/rdRaster.h"
#include "Raster/rdNRaster.h"

#if defined(PLATFORM_POSIX)
#include <locale.h>
#endif

static HostServices hs;

#ifdef RDRASTER_SOFTWARE_RENDERER

#define FB_W 64
#define FB_H 48

static uint8_t g_framebuffer[FB_W * FB_H];

// Depth-varying triangle (screen x,y; per-vertex eye depth z used as w). The wide depth spread is
// what makes the perspective (IT) and affine (AT) results diverge.
static rdVector3 g_verts[3];
static rdVector2 g_uvs[3];

static void print_fb(void)
{
    for (int y = 0; y < FB_H; y++)
    {
        for (int x = 0; x < FB_W; x++)
        {
            uint8_t p = g_framebuffer[y * FB_W + x];
            putchar(p == 0x20 ? '+' : p == 0x40 ? '#' : p ? 'o' : '.');
        }
        putchar('\n');
    }
}

// Fill g_framebuffer by drawing the triangle once through rdNRaster in the given texture mode.
// Returns fill/colour counts via out-params.
static void draw_case(rdProcEntry* pProc, int textureMode, int* pFill, int* pC20, int* pC40)
{
    pProc->textureMode = textureMode;
    memset(g_framebuffer, 0, sizeof(g_framebuffer));
    rdNRaster_DrawFace(pProc);

    int fill = 0, c20 = 0, c40 = 0;
    for (int i = 0; i < FB_W * FB_H; i++)
    {
        if (g_framebuffer[i]) fill++;
        if (g_framebuffer[i] == 0x20) c20++;
        if (g_framebuffer[i] == 0x40) c40++;
    }
    *pFill = fill; *pC20 = c20; *pC40 = c40;
}

int main(int argc, char** argv)
{
#if defined(PLATFORM_POSIX)
    setlocale(LC_ALL, "C");
#endif
    stdInitServices(&hs);
    hs.debugPrint = stdConsolePrintf;
    hs.messagePrint = stdConsolePrintf;
    hs.errorPrint = stdConsolePrintf;
    pHS = &hs;
    std_g_pHS = &hs;
    rdroid_g_pHS = &hs;
    stdStartup(&hs);
    rdRaster_Startup();

    printf("rdNRaster (perspective, non-Z) software-rasterizer test (%dx%d)\n", FB_W, FB_H);

    // --- Minimal render target: a plain 8bpp framebuffer behind a canvas/camera. ---
    tVBuffer vbuf;
    memset(&vbuf, 0, sizeof(vbuf));
    vbuf.surface_lock_alloc = g_framebuffer;
    vbuf.format.width = FB_W;
    vbuf.format.height = FB_H;
    vbuf.format.rowSize = FB_W;
    vbuf.format.rowWidth = FB_W;

    rdCanvas canvas;
    memset(&canvas, 0, sizeof(canvas));
    canvas.pVBuffer = &vbuf;
    canvas.xStart = 0;
    canvas.yStart = 0;
    canvas.widthMinusOne = FB_W - 1;
    canvas.heightMinusOne = FB_H - 1;

    rdCamera camera;
    memset(&camera, 0, sizeof(camera));
    camera.pCanvas = &canvas;
    rdCamera_g_pCurCamera = &camera;

    rdroid_g_curGeometryMode = RD_GEOMETRY_FULL;
    rdroid_g_curLightingMode = 4;
    rdroid_curTextureMode = 1;         // allow perspective (faces cap up to this)
    rdroid_g_curRenderOptions = 0;

    rdroid_aMipDistances.x = 100.0f;
    rdroid_aMipDistances.y = 200.0f;
    rdroid_aMipDistances.z = 400.0f;
    rdroid_aMipDistances.w = 800.0f;

    // Depth-varying triangle: wide z spread across the three verts.
    g_verts[0].x = 10.0f; g_verts[0].y = 6.0f;  g_verts[0].z = 4.0f;    // apex, near
    g_verts[1].x = 24.0f; g_verts[1].y = 42.0f; g_verts[1].z = 24.0f;   // bottom-left, far
    g_verts[2].x = 56.0f; g_verts[2].y = 22.0f; g_verts[2].z = 8.0f;    // right, mid
    g_uvs[0].x = 0.0f;          g_uvs[0].y = 0.0f;
    g_uvs[1].x = 0.0f;          g_uvs[1].y = 8.0f;
    g_uvs[2].x = 8.0f;          g_uvs[2].y = 4.0f;

    // --- 8x8 checker texture. ---
    #define TEX_W 8
    #define TEX_H 8
    static uint8_t texels[TEX_W * TEX_H];
    for (int ty = 0; ty < TEX_H; ty++)
        for (int tx = 0; tx < TEX_W; tx++)
            texels[ty * TEX_W + tx] = ((tx ^ ty) & 1) ? 0x20 : 0x40;

    tVBuffer mip;
    memset(&mip, 0, sizeof(mip));
    mip.surface_lock_alloc = texels;
    mip.format.width = TEX_W;
    mip.format.height = TEX_H;
    mip.format.rowSize = TEX_W;
    mip.format.rowWidth = TEX_W;

    rdTexture texture;
    memset(&texture, 0, sizeof(texture));
    texture.alpha_en = 0;
    texture.width_bitcnt = 3;
    texture.width_minus_1 = TEX_W - 1;
    texture.height_minus_1 = TEX_H - 1;
    texture.num_mipmaps = 1;
    texture.texture_struct[0] = &mip;

    rdTexinfo texinfoTex;
    memset(&texinfoTex, 0, sizeof(texinfoTex));
    texinfoTex.header.texture_type = 8;   // "full" -> textured
    texinfoTex.texture_ptr = &texture;

    rdMaterial matTex;
    memset(&matTex, 0, sizeof(matTex));
    matTex.num_texinfo = 1;
    matTex.curCelNum = 0;
    matTex.texinfos[0] = &texinfoTex;

    rdProcEntry proc;
    memset(&proc, 0, sizeof(proc));
    proc.geometryMode = RD_GEOMETRY_FULL;
    proc.lightingMode = RD_LIGHTMODE_FULLYLIT;
    proc.numVertices = 3;
    proc.aVertices = g_verts;
    proc.aTexVerticies = g_uvs;
    proc.material = &matTex;
    proc.wallCel = 0;
    proc.extraData = 0;
    proc.z_min = 5.0f;   // < mipDist.x -> mip 0

    // --- Perspective (IT) vs affine (AT): must both fill with both colours, and DIFFER. ---
    printf("\n--- IT (perspective) vs AT (affine) textured triangle ---\n");

    uint8_t fbAffine[FB_W * FB_H];
    int fillA, c20A, c40A;
    draw_case(&proc, 0, &fillA, &c20A, &c40A);        // textureMode 0 -> affine
    memcpy(fbAffine, g_framebuffer, sizeof(fbAffine));
    printf("AT (affine):      fill=%d (0x20:%d 0x40:%d)\n", fillA, c20A, c40A);
    print_fb();

    int fillP, c20P, c40P;
    draw_case(&proc, 1, &fillP, &c20P, &c40P);        // textureMode 1 -> perspective
    printf("\nIT (perspective): fill=%d (0x20:%d 0x40:%d)\n", fillP, c20P, c40P);
    print_fb();

    int diff = 0;
    for (int i = 0; i < FB_W * FB_H; i++)
        if (fbAffine[i] != g_framebuffer[i])
            diff++;
    printf("\nIT vs AT differing pixels: %d\n", diff);

    if (fillA < 200 || c20A < 20 || c40A < 20)
    {
        printf("\nFAIL: affine (AT) did not fill the textured triangle with both colours.\n");
        return 1;
    }
    if (fillP < 200 || c20P < 20 || c40P < 20)
    {
        printf("\nFAIL: perspective (IT) did not fill the textured triangle with both colours.\n");
        return 1;
    }
    if (diff < 10)
    {
        printf("\nFAIL: IT and AT produced (nearly) identical output — the per-pixel 1/w divide\n"
               "      is not running (perspective collapsed to affine).\n");
        return 1;
    }
    printf("\nOK: rdNRaster drew perspective- and affine-textured triangles that correctly differ.\n");

    // --- Solid (untextured) fill: non-"full" texture -> flat solidColor fill. ---
    printf("\n--- Solid (untextured) fill ---\n");
    rdTexinfo texinfoSolid;
    memset(&texinfoSolid, 0, sizeof(texinfoSolid));
    texinfoSolid.header.texture_type = 0;      // not "full" -> solid
    texinfoSolid.header.solidColor = 0x55;
    texinfoSolid.texture_ptr = NULL;

    rdMaterial matSolid;
    memset(&matSolid, 0, sizeof(matSolid));
    matSolid.num_texinfo = 1;
    matSolid.curCelNum = 0;
    matSolid.texinfos[0] = &texinfoSolid;

    proc.material = &matSolid;
    proc.aTexVerticies = NULL;                 // unused for solid faces

    proc.textureMode = 0;
    memset(g_framebuffer, 0, sizeof(g_framebuffer));
    rdNRaster_DrawFace(&proc);

    int fillS = 0, c55 = 0;
    for (int i = 0; i < FB_W * FB_H; i++)
    {
        if (g_framebuffer[i]) fillS++;
        if (g_framebuffer[i] == 0x55) c55++;
    }
    printf("Solid: fill=%d (0x55:%d)\n", fillS, c55);
    if (fillS < 200 || c55 != fillS)
    {
        printf("\nFAIL: solid fill did not paint the interior with the flat colour.\n");
        return 1;
    }
    printf("\nOK: rdNRaster drew a flat solid-colour triangle.\n");

    printf("\nAll rdNRaster tests passed.\n");
    return 0;
}

#else // RDRASTER_SOFTWARE_RENDERER

int main(int argc, char** argv)
{
    printf("rdNRaster_test: RDRASTER_SOFTWARE_RENDERER is disabled; nothing to test.\n");
    return 0;
}

#endif
