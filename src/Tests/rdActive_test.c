// Standalone integration test for the software (CPU) rasterizer wireframe path.
// Feeds one triangle proc face through rdActive (BuildEdges -> AddActiveFace ->
// BuildSpans -> DrawScene -> rdAFRaster wireframe draw) into a plain 8bpp framebuffer,
// then prints the framebuffer as ASCII art so the polygon outline can be eyeballed.
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
#include "Engine/rdActive.h"
#include "Raster/rdRaster.h"

#if defined(PLATFORM_POSIX)
#include <locale.h>
#endif

static HostServices hs;

#ifdef RDRASTER_SOFTWARE_RENDERER

#define FB_W 64
#define FB_H 48

static uint8_t g_framebuffer[FB_W * FB_H];

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
    rdRaster_Startup();   // build the reciprocal LUTs the textured span math reads

    printf("rdActive software-rasterizer wireframe test (%dx%d)\n", FB_W, FB_H);

    // --- Minimal render target: a plain 8bpp framebuffer behind a canvas/camera. ---
    tVBuffer vbuf;
    memset(&vbuf, 0, sizeof(vbuf));
    vbuf.surface_lock_alloc = g_framebuffer;
    vbuf.format.width = FB_W;
    vbuf.format.height = FB_H;
    vbuf.format.rowSize = FB_W;   // 8bpp -> 1 byte/pixel, so byte stride == width
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

    // --- Renderer mode caps: wireframe, painter's (non-Z) path. ---
    rdroid_g_curGeometryMode = RD_GEOMETRY_WIREFRAME;
    rdroid_g_curLightingMode = 4;
    rdroid_curTextureMode = 0;
    rdroid_curZBufferMethod = 1;
    rdroid_g_curRenderOptions = 0;

    // --- One triangle proc face (screen-space verts, constant depth). ---
    // Wound so that downward (left-chain) edges sort to smaller X, as the rasterizer
    // expects from back-face-culled faces: apex -> bottom-left -> right.
    rdVector3 verts[3];
    verts[0].x = 10.0f; verts[0].y = 6.0f;  verts[0].z = 10.0f;   // apex
    verts[1].x = 24.0f; verts[1].y = 42.0f; verts[1].z = 10.0f;   // bottom-left
    verts[2].x = 56.0f; verts[2].y = 22.0f; verts[2].z = 10.0f;   // right

    // Material/texinfo just to carry the wireframe color (index 0xFF).
    rdTexinfo texinfo;
    memset(&texinfo, 0, sizeof(texinfo));
    texinfo.header.solidColor = 0xFF;
    texinfo.header.texture_type = 0;

    rdMaterial mat;
    memset(&mat, 0, sizeof(mat));
    mat.num_texinfo = 1;
    mat.curCelNum = 0;
    mat.texinfos[0] = &texinfo;

    rdProcEntry* pProc = &rdCache_aProcFaces[0];
    memset(pProc, 0, sizeof(*pProc));
    pProc->geometryMode = RD_GEOMETRY_WIREFRAME;
    pProc->lightingMode = 0;
    pProc->textureMode = 0;
    pProc->numVertices = 3;
    pProc->aVertices = verts;
    pProc->material = &mat;
    pProc->wallCel = 0;
    pProc->light_flags = 0;
    pProc->extraData = 0;
    rdCache_numProcFaces = 1;

    // --- Run the pipeline. ---
    memset(g_framebuffer, 0, sizeof(g_framebuffer));
    rdActive_Startup();
    rdActive_AdvanceFrame();
    rdActive_DrawScene();
    printf("Pipeline: numActiveFaces=%d numActiveEdges=%d yMin=%d yMax=%d drawnFaces=%d\n",
           numActiveFaces, numActiveEdges, yMinEdge, yMaxEdge, rdActive_drawnFaces);

    // --- Report. ---
    int litPixels = 0;
    for (int i = 0; i < FB_W * FB_H; i++)
        if (g_framebuffer[i])
            litPixels++;

    printf("Lit pixels: %d (expected: the triangle's edge outline)\n\n", litPixels);
    for (int y = 0; y < FB_H; y++)
    {
        for (int x = 0; x < FB_W; x++)
            putchar(g_framebuffer[y * FB_W + x] ? '#' : '.');
        putchar('\n');
    }

    // The wireframe draws two endpoint pixels per covered scanline (~2 * triangle
    // height), so expect a few dozen lit pixels tracing the outline.
    if (numActiveFaces != 1 || numActiveEdges != 3 || litPixels < 20)
    {
        printf("\nFAIL: expected 1 face / 3 edges / >=20 lit pixels.\n");
        return 1;
    }
    printf("\nOK: software rasterizer drew the wireframe outline.\n");

    // ============================================================================
    // Flat affine textured (FAT) triangle: same geometry, filled with an 8x8
    // checkerboard texture. Verifies the FAT setup/edge/span-sampler path fills the
    // interior with real texel values (two distinct colors), not just an outline.
    // ============================================================================
    printf("\n--- FAT (flat affine textured) test ---\n");

    #define TEX_W 8
    #define TEX_H 8
    static uint8_t texels[TEX_W * TEX_H];
    for (int ty = 0; ty < TEX_H; ty++)
        for (int tx = 0; tx < TEX_W; tx++)
            texels[ty * TEX_W + tx] = ((tx ^ ty) & 1) ? 0x20 : 0x40;   // 2-color checker

    tVBuffer mip;
    memset(&mip, 0, sizeof(mip));
    mip.surface_lock_alloc = texels;
    mip.format.width = TEX_W;
    mip.format.height = TEX_H;
    mip.format.rowSize = TEX_W;
    mip.format.rowWidth = TEX_W;

    rdTexture texture;
    memset(&texture, 0, sizeof(texture));
    texture.alpha_en = 0;              // opaque (masked path gate)
    texture.width_bitcnt = 3;          // log2(8)
    texture.width_minus_1 = TEX_W - 1;
    texture.height_minus_1 = TEX_H - 1;
    texture.num_mipmaps = 1;
    texture.texture_struct[0] = &mip;

    rdTexinfo texinfoFAT;
    memset(&texinfoFAT, 0, sizeof(texinfoFAT));
    texinfoFAT.header.texture_type = 8;   // "full" flag set -> stays RD_GEOMETRY_FULL
    texinfoFAT.texture_ptr = &texture;

    rdMaterial matFAT;
    memset(&matFAT, 0, sizeof(matFAT));
    matFAT.num_texinfo = 1;
    matFAT.curCelNum = 0;
    matFAT.texinfos[0] = &texinfoFAT;

    rdVector2 uvs[3];
    uvs[0].x = 0.0f;             uvs[0].y = 0.0f;             // apex
    uvs[1].x = 0.0f;             uvs[1].y = (flex_t)TEX_H;    // bottom-left
    uvs[2].x = (flex_t)TEX_W;    uvs[2].y = (flex_t)TEX_H/2;  // right

    rdroid_aMipDistances.x = 10.0f;
    rdroid_aMipDistances.y = 20.0f;
    rdroid_aMipDistances.z = 40.0f;
    rdroid_aMipDistances.w = 80.0f;

    rdroid_g_curGeometryMode = RD_GEOMETRY_FULL;
    rdroid_g_curLightingMode = 4;
    rdroid_curTextureMode = 0;
    rdroid_curZBufferMethod = 1;

    pProc = &rdCache_aProcFaces[0];
    memset(pProc, 0, sizeof(*pProc));
    pProc->geometryMode = RD_GEOMETRY_FULL;
    pProc->lightingMode = RD_LIGHTMODE_FULLYLIT;
    pProc->textureMode = 0;
    pProc->numVertices = 3;
    pProc->aVertices = verts;
    pProc->aTexVerticies = uvs;
    pProc->material = &matFAT;
    pProc->wallCel = 0;
    pProc->light_flags = 0;
    pProc->extraData = 0;
    pProc->z_min = 5.0f;    // < mipDist.x=10 -> mip 0
    rdCache_numProcFaces = 1;

    memset(g_framebuffer, 0, sizeof(g_framebuffer));
    rdActive_AdvanceFrame();
    rdActive_DrawScene();

    int fillPixels = 0, c20 = 0, c40 = 0;
    for (int i = 0; i < FB_W * FB_H; i++)
    {
        if (g_framebuffer[i]) fillPixels++;
        if (g_framebuffer[i] == 0x20) c20++;
        if (g_framebuffer[i] == 0x40) c40++;
    }
    printf("FAT: numActiveFaces=%d numActiveEdges=%d fillPixels=%d (0x20:%d 0x40:%d)\n",
           numActiveFaces, numActiveEdges, fillPixels, c20, c40);
    for (int y = 0; y < FB_H; y++)
    {
        for (int x = 0; x < FB_W; x++)
        {
            uint8_t p = g_framebuffer[y * FB_W + x];
            putchar(p == 0x20 ? '+' : p == 0x40 ? '#' : '.');
        }
        putchar('\n');
    }

    // A filled triangle covers hundreds of pixels; the checker must produce BOTH colors.
    if (numActiveFaces != 1 || fillPixels < 200 || c20 < 20 || c40 < 20)
    {
        printf("\nFAIL: expected a filled textured triangle with both checker colors.\n");
        return 1;
    }
    printf("\nOK: FAT drew a texture-mapped filled triangle.\n");

    // ============================================================================
    // LAT (lit) and GAT (gouraud): same textured triangle, now modulated through a
    // colormap light table. The table is set up so light level 63 (full bright) is an
    // identity map, so a fully-lit face reproduces the FAT checker exactly.
    // ============================================================================
    printf("\n--- LAT / GAT (lit + gouraud affine textured) test ---\n");

    static uint8_t lightlevel[64 * 256];
    for (int lvl = 0; lvl < 64; lvl++)
        for (int c = 0; c < 256; c++)
            lightlevel[lvl * 256 + c] = (uint8_t)((c * (lvl + 1)) / 64);   // brighter with lvl; lvl 63 == identity

    rdColormap colormap;
    memset(&colormap, 0, sizeof(colormap));
    colormap.lightlevel = lightlevel;
    pProc->colormap = &colormap;
    rdroid_g_curRenderOptions = 0;

    struct { const char* name; int lightingMode; int gouraud; } lit_cases[2] = {
        { "LAT", RD_LIGHTMODE_NOTLIT,  0 },
        { "GAT", RD_LIGHTMODE_GOURAUD, 1 },
    };
    flex_t vertIntens[3];
    for (int ci = 0; ci < 2; ci++)
    {
        pProc->lightingMode = lit_cases[ci].lightingMode;
        pProc->extralight = 1.0f;              // full bright -> light level 63 -> identity row
        pProc->ambientLight = 0.0f;
        pProc->light_level_static = 0.0f;
        if (lit_cases[ci].gouraud)
        {
            vertIntens[0] = vertIntens[1] = vertIntens[2] = 1.0f;   // (AddActiveFace rescales in place)
            pProc->vertexIntensities = vertIntens;
        }

        memset(g_framebuffer, 0, sizeof(g_framebuffer));
        rdActive_AdvanceFrame();
        rdActive_DrawScene();

        int fill = 0, k20 = 0, k40 = 0;
        for (int i = 0; i < FB_W * FB_H; i++)
        {
            if (g_framebuffer[i]) fill++;
            if (g_framebuffer[i] == 0x20) k20++;
            if (g_framebuffer[i] == 0x40) k40++;
        }
        printf("%s: numActiveFaces=%d fill=%d (0x20:%d 0x40:%d)\n",
               lit_cases[ci].name, numActiveFaces, fill, k20, k40);
        if (numActiveFaces != 1 || fill < 200 || k20 < 20 || k40 < 20)
        {
            printf("\nFAIL: %s did not reproduce the lit texture (expected both checker colors).\n",
                   lit_cases[ci].name);
            return 1;
        }
    }
    printf("\nOK: LAT and GAT drew light-modulated texture-mapped triangles.\n");

    // ============================================================================
    // Perspective (FIT) vs affine (FAT): a depth-varying triangle textured both
    // ways. The affine active-edge path is textureMode 0 (FAT); textureMode 1 is
    // the perspective (IT) family (per-pixel 1/z divide). With per-vertex depth
    // variation they MUST differ, proving the perspective span pipeline runs.
    // ============================================================================
    printf("\n--- FIT (perspective) vs FAT (affine) test ---\n");

    rdVector3 pverts[3];
    pverts[0].x = 10.0f; pverts[0].y = 6.0f;  pverts[0].z = 4.0f;    // apex, near
    pverts[1].x = 24.0f; pverts[1].y = 42.0f; pverts[1].z = 24.0f;   // bottom-left, far
    pverts[2].x = 56.0f; pverts[2].y = 22.0f; pverts[2].z = 8.0f;    // right, mid

    pProc = &rdCache_aProcFaces[0];
    memset(pProc, 0, sizeof(*pProc));
    pProc->geometryMode = RD_GEOMETRY_FULL;
    pProc->lightingMode = RD_LIGHTMODE_FULLYLIT;
    pProc->numVertices = 3;
    pProc->aVertices = pverts;
    pProc->aTexVerticies = uvs;
    pProc->material = &matFAT;
    pProc->wallCel = 0;
    pProc->z_min = 5.0f;
    rdCache_numProcFaces = 1;

    rdroid_curTextureMode = 1;   // allow perspective

    uint8_t fbAffine[FB_W * FB_H];
    pProc->textureMode = 0;      // affine (FAT)
    memset(g_framebuffer, 0, sizeof(g_framebuffer));
    rdActive_AdvanceFrame();
    rdActive_DrawScene();
    memcpy(fbAffine, g_framebuffer, sizeof(fbAffine));
    int fillAff = 0, cAff20 = 0, cAff40 = 0;
    for (int i = 0; i < FB_W * FB_H; i++)
    {
        if (g_framebuffer[i]) fillAff++;
        if (g_framebuffer[i] == 0x20) cAff20++;
        if (g_framebuffer[i] == 0x40) cAff40++;
    }
    printf("FAT (affine):      fill=%d (0x20:%d 0x40:%d)\n", fillAff, cAff20, cAff40);

    pProc->textureMode = 1;      // perspective (FIT)
    memset(g_framebuffer, 0, sizeof(g_framebuffer));
    rdActive_AdvanceFrame();
    rdActive_DrawScene();
    int fillPer = 0, cPer20 = 0, cPer40 = 0, diff = 0;
    for (int i = 0; i < FB_W * FB_H; i++)
    {
        if (g_framebuffer[i]) fillPer++;
        if (g_framebuffer[i] == 0x20) cPer20++;
        if (g_framebuffer[i] == 0x40) cPer40++;
        if (g_framebuffer[i] != fbAffine[i]) diff++;
    }
    printf("FIT (perspective): fill=%d (0x20:%d 0x40:%d), diff vs affine=%d\n",
           fillPer, cPer20, cPer40, diff);
    for (int y = 0; y < FB_H; y++)
    {
        for (int x = 0; x < FB_W; x++)
        {
            uint8_t p = g_framebuffer[y * FB_W + x];
            putchar(p == 0x20 ? '+' : p == 0x40 ? '#' : '.');
        }
        putchar('\n');
    }
    if (fillPer < 200 || cPer20 < 20 || cPer40 < 20 || diff < 10)
    {
        printf("\nFAIL: FIT did not fill with both colors OR did not differ from affine.\n");
        return 1;
    }
    printf("\nOK: FIT (perspective) filled and differs from FAT (affine).\n");

    // ============================================================================
    // Solid (FS): a texinfo without the "full" texture flag falls back to a flat
    // solid-color fill. Expect the whole triangle painted with one color.
    // ============================================================================
    printf("\n--- FS (solid) test ---\n");
    rdTexinfo texinfoSolid;
    memset(&texinfoSolid, 0, sizeof(texinfoSolid));
    texinfoSolid.header.texture_type = 0;    // not "full" -> solid fallback
    texinfoSolid.header.solidColor = 0x55;
    texinfoSolid.texture_ptr = NULL;
    rdMaterial matSolid;
    memset(&matSolid, 0, sizeof(matSolid));
    matSolid.num_texinfo = 1;
    matSolid.curCelNum = 0;
    matSolid.texinfos[0] = &texinfoSolid;

    pProc->geometryMode = RD_GEOMETRY_FULL;   // reclassified to SOLID by AddActiveFace
    pProc->lightingMode = RD_LIGHTMODE_FULLYLIT;
    pProc->textureMode = 0;
    pProc->aVertices = verts;                 // flat-depth triangle
    pProc->aTexVerticies = NULL;
    pProc->material = &matSolid;
    memset(g_framebuffer, 0, sizeof(g_framebuffer));
    rdActive_AdvanceFrame();
    rdActive_DrawScene();
    int fillSolid = 0, c55 = 0;
    for (int i = 0; i < FB_W * FB_H; i++)
    {
        if (g_framebuffer[i]) fillSolid++;
        if (g_framebuffer[i] == 0x55) c55++;
    }
    printf("FS: fill=%d (0x55:%d)\n", fillSolid, c55);
    if (fillSolid < 200 || c55 != fillSolid)
    {
        printf("\nFAIL: FS did not paint a flat solid triangle.\n");
        return 1;
    }
    printf("\nOK: FS drew a flat solid triangle.\n");

    // ============================================================================
    // Masked (MFAT): a transparent texture (alpha_en&1) whose index-0 texels are
    // skipped. Half the checker is index 0, so the fill count must drop well below
    // the opaque FAT triangle while the opaque color still appears.
    // ============================================================================
    printf("\n--- MFAT (masked) test ---\n");
    static uint8_t mtexels[TEX_W * TEX_H];
    for (int ty = 0; ty < TEX_H; ty++)
        for (int tx = 0; tx < TEX_W; tx++)
            mtexels[ty * TEX_W + tx] = ((tx ^ ty) & 1) ? 0x00 : 0x40;   // half transparent
    tVBuffer mmip;
    memset(&mmip, 0, sizeof(mmip));
    mmip.surface_lock_alloc = mtexels;
    mmip.format.width = TEX_W; mmip.format.height = TEX_H;
    mmip.format.rowSize = TEX_W; mmip.format.rowWidth = TEX_W;
    rdTexture mtexture;
    memset(&mtexture, 0, sizeof(mtexture));
    mtexture.alpha_en = 1;                    // transparent -> masked path
    mtexture.width_bitcnt = 3;
    mtexture.width_minus_1 = TEX_W - 1;
    mtexture.height_minus_1 = TEX_H - 1;
    mtexture.num_mipmaps = 1;
    mtexture.texture_struct[0] = &mmip;
    rdTexinfo texinfoM;
    memset(&texinfoM, 0, sizeof(texinfoM));
    texinfoM.header.texture_type = 8;
    texinfoM.texture_ptr = &mtexture;
    rdMaterial matM;
    memset(&matM, 0, sizeof(matM));
    matM.num_texinfo = 1; matM.curCelNum = 0; matM.texinfos[0] = &texinfoM;

    pProc->geometryMode = RD_GEOMETRY_FULL;
    pProc->lightingMode = RD_LIGHTMODE_FULLYLIT;
    pProc->textureMode = 0;
    pProc->aVertices = verts;
    pProc->aTexVerticies = uvs;
    pProc->material = &matM;
    memset(g_framebuffer, 0, sizeof(g_framebuffer));
    rdActive_AdvanceFrame();
    rdActive_DrawScene();
    int fillM = 0, cM40 = 0, cM00nonzero = 0;
    for (int i = 0; i < FB_W * FB_H; i++)
    {
        if (g_framebuffer[i]) fillM++;
        if (g_framebuffer[i] == 0x40) cM40++;
    }
    printf("MFAT: fill=%d (0x40:%d) — expect ~half of the opaque 714\n", fillM, cM40);
    if (fillM < 100 || fillM > 600 || cM40 < 100)
    {
        printf("\nFAIL: MFAT did not skip the transparent texels (masked fill wrong).\n");
        return 1;
    }
    printf("\nOK: MFAT skipped transparent texels (masked).\n");

    printf("\nAll rdActive/rdAFRaster family tests passed.\n");
    return 0;
}

#else // RDRASTER_SOFTWARE_RENDERER

int main(int argc, char** argv)
{
    printf("rdActive_test: RDRASTER_SOFTWARE_RENDERER is disabled; nothing to test.\n");
    return 0;
}

#endif
