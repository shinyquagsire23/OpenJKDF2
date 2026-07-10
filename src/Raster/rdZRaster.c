#include "rdZRaster.h"

#include "Engine/rdCamera.h"
#include "Win95/stdDisplay.h"
#include "jk.h"

#ifdef RDRASTER_SOFTWARE_RENDERER

#include <math.h>

// Depth buffer holding 1/w (nearer = larger); sized to the canvas, cleared each frame.
static float* rdZRaster_pZBuffer;
static int    rdZRaster_zbWidth;
static int    rdZRaster_zbHeight;

// Shading axes for the DrawNGon template (RDZ_SHADE).
#define RDZ_FLAT    0   // no light table (full bright)
#define RDZ_LIT     1   // one constant light level through the light table
#define RDZ_GOURAUD 2   // per-pixel interpolated light level through the light table

// Per-vertex screen-space attributes for the face currently being rasterized.
typedef struct rdZVertex
{
    flex_t sx, sy;      // screen position
    flex_t oneOverW;    // 1/z (depth key, and the perspective divisor for IT texturing)
    flex_t uOverW;      // texel-u / z   (perspective / IT)
    flex_t vOverW;      // texel-v / z   (perspective / IT)
    flex_t u, v;        // texel-u, texel-v (affine / AT — interpolated linearly in screen space)
    flex_t intensity;   // light level 0..63
} rdZVertex;

void rdZRaster_Startup(void)
{
    // Keep any existing allocation across a soft reset; just forget the contents.
    rdZRaster_zbWidth = 0;
    rdZRaster_zbHeight = 0;
}

// Alloc/resize the depth buffer to a target vbuffer and clear it to "infinitely far" (0 == 1/w=0).
static void rdZRaster_SizeAndClear(tVBuffer* pVBuffer)
{
    if (pVBuffer == NULL)
        return;
    int w = pVBuffer->format.width;
    int h = pVBuffer->format.height;
    if (rdZRaster_pZBuffer == NULL || w * h > rdZRaster_zbWidth * rdZRaster_zbHeight)
    {
        if (rdZRaster_pZBuffer != NULL)
            _free(rdZRaster_pZBuffer);
        rdZRaster_pZBuffer = (float*)_malloc(w * h * sizeof(float));
    }
    rdZRaster_zbWidth = w;
    rdZRaster_zbHeight = h;
    if (rdZRaster_pZBuffer != NULL)
        _memset(rdZRaster_pZBuffer, 0, w * h * sizeof(float));
}

// Scene-start depth clear for a known target vbuffer. Called once per frame from the software
// render bracket (jkGame_Update), BEFORE the world is drawn — this is the reliable per-frame clear.
// (rdCamera_AdvanceFrame clears JK's software z-buffer by filling canvas->d3d_vbuf on the accel<=0
// path, not via std3D_ClearZBuffer, so that hook alone never fires here.)
void rdZRaster_BeginFrame(tVBuffer* pVBuffer)
{
    rdZRaster_SizeAndClear(pVBuffer);
}

// Depth clear against the current camera's canvas. Hooked into std3D_ClearZBuffer() so JK's own
// mid-frame clear — jkPlayer_DrawPov's, which puts the first-person weapon in front — also clears
// the software buffer.
void rdZRaster_ClearZBuffer(void)
{
    if (rdCamera_g_pCurCamera == NULL || rdCamera_g_pCurCamera->pCanvas == NULL)
        return;
    rdZRaster_SizeAndClear(rdCamera_g_pCurCamera->pCanvas->pVBuffer);
}

static flex_t rdZRaster_Clamp01(flex_t f)
{
    if (f < 0.0f) return 0.0f;
    if (f > 1.0f) return 1.0f;
    return f;
}

// Resolve the 256x256 palette transparency LUT for a translucent face. A colormap only allocates
// its `transparency` table when it declares a transparency section (flags & 1); without the flag
// the pointer is uninitialized garbage, so a plain non-NULL test is unsafe. Prefer the face's own
// colormap, then the identity map; return NULL (opaque) if neither has a valid table.
static const uint8_t* rdZRaster_ResolveTransTable(rdColormap* pColormap)
{
    if (pColormap != NULL && (pColormap->flags & 1) && pColormap->transparency != NULL)
        return (const uint8_t*)pColormap->transparency;
    if (rdColormap_pIdentityMap != NULL && (rdColormap_pIdentityMap->flags & 1)
        && rdColormap_pIdentityMap->transparency != NULL)
        return (const uint8_t*)rdColormap_pIdentityMap->transparency;
    return NULL;
}

// State shared by every generated DrawNGon variant. The mode axes (solid / masked / translucent)
// are NOT here — they are compile-time, baked into each variant by rdZRaster_ngon.h.
typedef struct rdZRasterState
{
    const uint8_t* pTexels;      // selected mip texels (textured variants)
    const uint8_t* pLightBase;   // colormap light table, or NULL for raw texels
    const uint8_t* pTransTable;  // colormap transparency LUT (translucent variants)
    int mip, mipW, mipH, mipStride;
    int solidColor;              // flat fill color (solid variants)
} rdZRasterState;

// --- Generate the full GrimFandango rdZRaster DrawNGon family from one scanline body
// (rdZRaster_ngon.h). Each #include emits one real, separately-named function; the template
// trailer #undefs the mode macros. Naming: [M][T]<F|L|G><S|AT|IT> — M masked, T translucent,
// F/L/G flat/lit/gouraud shading, S solid, AT affine-textured, IT perspective(interpolated)-textured.
// (Masking does not apply to untextured solids, so those variants are absent, as in JK.) ---

#define RDZ_NAME rdZRaster_DrawNGonFS
#define RDZ_SOLID 1
#define RDZ_AFFINE 0
#define RDZ_MASKED 0
#define RDZ_TRANSLUCENT 0
#define RDZ_SHADE RDZ_FLAT
#include "rdZRaster_ngon.h"

#define RDZ_NAME rdZRaster_DrawNGonLS
#define RDZ_SOLID 1
#define RDZ_AFFINE 0
#define RDZ_MASKED 0
#define RDZ_TRANSLUCENT 0
#define RDZ_SHADE RDZ_LIT
#include "rdZRaster_ngon.h"

#define RDZ_NAME rdZRaster_DrawNGonGS
#define RDZ_SOLID 1
#define RDZ_AFFINE 0
#define RDZ_MASKED 0
#define RDZ_TRANSLUCENT 0
#define RDZ_SHADE RDZ_GOURAUD
#include "rdZRaster_ngon.h"

#define RDZ_NAME rdZRaster_DrawNGonTFS
#define RDZ_SOLID 1
#define RDZ_AFFINE 0
#define RDZ_MASKED 0
#define RDZ_TRANSLUCENT 1
#define RDZ_SHADE RDZ_FLAT
#include "rdZRaster_ngon.h"

#define RDZ_NAME rdZRaster_DrawNGonTLS
#define RDZ_SOLID 1
#define RDZ_AFFINE 0
#define RDZ_MASKED 0
#define RDZ_TRANSLUCENT 1
#define RDZ_SHADE RDZ_LIT
#include "rdZRaster_ngon.h"

#define RDZ_NAME rdZRaster_DrawNGonTGS
#define RDZ_SOLID 1
#define RDZ_AFFINE 0
#define RDZ_MASKED 0
#define RDZ_TRANSLUCENT 1
#define RDZ_SHADE RDZ_GOURAUD
#include "rdZRaster_ngon.h"

#define RDZ_NAME rdZRaster_DrawNGonFAT
#define RDZ_SOLID 0
#define RDZ_AFFINE 1
#define RDZ_MASKED 0
#define RDZ_TRANSLUCENT 0
#define RDZ_SHADE RDZ_FLAT
#include "rdZRaster_ngon.h"

#define RDZ_NAME rdZRaster_DrawNGonLAT
#define RDZ_SOLID 0
#define RDZ_AFFINE 1
#define RDZ_MASKED 0
#define RDZ_TRANSLUCENT 0
#define RDZ_SHADE RDZ_LIT
#include "rdZRaster_ngon.h"

#define RDZ_NAME rdZRaster_DrawNGonGAT
#define RDZ_SOLID 0
#define RDZ_AFFINE 1
#define RDZ_MASKED 0
#define RDZ_TRANSLUCENT 0
#define RDZ_SHADE RDZ_GOURAUD
#include "rdZRaster_ngon.h"

#define RDZ_NAME rdZRaster_DrawNGonTFAT
#define RDZ_SOLID 0
#define RDZ_AFFINE 1
#define RDZ_MASKED 0
#define RDZ_TRANSLUCENT 1
#define RDZ_SHADE RDZ_FLAT
#include "rdZRaster_ngon.h"

#define RDZ_NAME rdZRaster_DrawNGonTLAT
#define RDZ_SOLID 0
#define RDZ_AFFINE 1
#define RDZ_MASKED 0
#define RDZ_TRANSLUCENT 1
#define RDZ_SHADE RDZ_LIT
#include "rdZRaster_ngon.h"

#define RDZ_NAME rdZRaster_DrawNGonTGAT
#define RDZ_SOLID 0
#define RDZ_AFFINE 1
#define RDZ_MASKED 0
#define RDZ_TRANSLUCENT 1
#define RDZ_SHADE RDZ_GOURAUD
#include "rdZRaster_ngon.h"

#define RDZ_NAME rdZRaster_DrawNGonMFAT
#define RDZ_SOLID 0
#define RDZ_AFFINE 1
#define RDZ_MASKED 1
#define RDZ_TRANSLUCENT 0
#define RDZ_SHADE RDZ_FLAT
#include "rdZRaster_ngon.h"

#define RDZ_NAME rdZRaster_DrawNGonMLAT
#define RDZ_SOLID 0
#define RDZ_AFFINE 1
#define RDZ_MASKED 1
#define RDZ_TRANSLUCENT 0
#define RDZ_SHADE RDZ_LIT
#include "rdZRaster_ngon.h"

#define RDZ_NAME rdZRaster_DrawNGonMGAT
#define RDZ_SOLID 0
#define RDZ_AFFINE 1
#define RDZ_MASKED 1
#define RDZ_TRANSLUCENT 0
#define RDZ_SHADE RDZ_GOURAUD
#include "rdZRaster_ngon.h"

#define RDZ_NAME rdZRaster_DrawNGonMTFAT
#define RDZ_SOLID 0
#define RDZ_AFFINE 1
#define RDZ_MASKED 1
#define RDZ_TRANSLUCENT 1
#define RDZ_SHADE RDZ_FLAT
#include "rdZRaster_ngon.h"

#define RDZ_NAME rdZRaster_DrawNGonMTLAT
#define RDZ_SOLID 0
#define RDZ_AFFINE 1
#define RDZ_MASKED 1
#define RDZ_TRANSLUCENT 1
#define RDZ_SHADE RDZ_LIT
#include "rdZRaster_ngon.h"

#define RDZ_NAME rdZRaster_DrawNGonMTGAT
#define RDZ_SOLID 0
#define RDZ_AFFINE 1
#define RDZ_MASKED 1
#define RDZ_TRANSLUCENT 1
#define RDZ_SHADE RDZ_GOURAUD
#include "rdZRaster_ngon.h"

#define RDZ_NAME rdZRaster_DrawNGonFIT
#define RDZ_SOLID 0
#define RDZ_AFFINE 0
#define RDZ_MASKED 0
#define RDZ_TRANSLUCENT 0
#define RDZ_SHADE RDZ_FLAT
#include "rdZRaster_ngon.h"

#define RDZ_NAME rdZRaster_DrawNGonLIT
#define RDZ_SOLID 0
#define RDZ_AFFINE 0
#define RDZ_MASKED 0
#define RDZ_TRANSLUCENT 0
#define RDZ_SHADE RDZ_LIT
#include "rdZRaster_ngon.h"

#define RDZ_NAME rdZRaster_DrawNGonGIT
#define RDZ_SOLID 0
#define RDZ_AFFINE 0
#define RDZ_MASKED 0
#define RDZ_TRANSLUCENT 0
#define RDZ_SHADE RDZ_GOURAUD
#include "rdZRaster_ngon.h"

#define RDZ_NAME rdZRaster_DrawNGonTFIT
#define RDZ_SOLID 0
#define RDZ_AFFINE 0
#define RDZ_MASKED 0
#define RDZ_TRANSLUCENT 1
#define RDZ_SHADE RDZ_FLAT
#include "rdZRaster_ngon.h"

#define RDZ_NAME rdZRaster_DrawNGonTLIT
#define RDZ_SOLID 0
#define RDZ_AFFINE 0
#define RDZ_MASKED 0
#define RDZ_TRANSLUCENT 1
#define RDZ_SHADE RDZ_LIT
#include "rdZRaster_ngon.h"

#define RDZ_NAME rdZRaster_DrawNGonTGIT
#define RDZ_SOLID 0
#define RDZ_AFFINE 0
#define RDZ_MASKED 0
#define RDZ_TRANSLUCENT 1
#define RDZ_SHADE RDZ_GOURAUD
#include "rdZRaster_ngon.h"

#define RDZ_NAME rdZRaster_DrawNGonMFIT
#define RDZ_SOLID 0
#define RDZ_AFFINE 0
#define RDZ_MASKED 1
#define RDZ_TRANSLUCENT 0
#define RDZ_SHADE RDZ_FLAT
#include "rdZRaster_ngon.h"

#define RDZ_NAME rdZRaster_DrawNGonMLIT
#define RDZ_SOLID 0
#define RDZ_AFFINE 0
#define RDZ_MASKED 1
#define RDZ_TRANSLUCENT 0
#define RDZ_SHADE RDZ_LIT
#include "rdZRaster_ngon.h"

#define RDZ_NAME rdZRaster_DrawNGonMGIT
#define RDZ_SOLID 0
#define RDZ_AFFINE 0
#define RDZ_MASKED 1
#define RDZ_TRANSLUCENT 0
#define RDZ_SHADE RDZ_GOURAUD
#include "rdZRaster_ngon.h"

#define RDZ_NAME rdZRaster_DrawNGonMTFIT
#define RDZ_SOLID 0
#define RDZ_AFFINE 0
#define RDZ_MASKED 1
#define RDZ_TRANSLUCENT 1
#define RDZ_SHADE RDZ_FLAT
#include "rdZRaster_ngon.h"

#define RDZ_NAME rdZRaster_DrawNGonMTLIT
#define RDZ_SOLID 0
#define RDZ_AFFINE 0
#define RDZ_MASKED 1
#define RDZ_TRANSLUCENT 1
#define RDZ_SHADE RDZ_LIT
#include "rdZRaster_ngon.h"

#define RDZ_NAME rdZRaster_DrawNGonMTGIT
#define RDZ_SOLID 0
#define RDZ_AFFINE 0
#define RDZ_MASKED 1
#define RDZ_TRANSLUCENT 1
#define RDZ_SHADE RDZ_GOURAUD
#include "rdZRaster_ngon.h"


// Route a face's state + verts to the DrawNGon symbol matching its surface/shading/modifiers
// (the per-face equivalent of JK's rdCache_DrawFaceZ picking one DrawNGon function).
static void rdZRaster_DispatchNGon(const rdZVertex* pVerts, int numVerts, const rdZRasterState* st,
                                   int solid, int affine, int masked, int translucent, int shade)
{
    switch (shade) {
    case RDZ_FLAT:
        if (solid) {
            if (translucent) rdZRaster_DrawNGonTFS(pVerts, numVerts, st); else rdZRaster_DrawNGonFS(pVerts, numVerts, st);
        } else if (affine) {
            if (masked && translucent) rdZRaster_DrawNGonMTFAT(pVerts, numVerts, st);
            else if (masked && !translucent) rdZRaster_DrawNGonMFAT(pVerts, numVerts, st);
            else if (!masked && translucent) rdZRaster_DrawNGonTFAT(pVerts, numVerts, st);
            else if (!masked && !translucent) rdZRaster_DrawNGonFAT(pVerts, numVerts, st);
        } else {
            if (masked && translucent) rdZRaster_DrawNGonMTFIT(pVerts, numVerts, st);
            else if (masked && !translucent) rdZRaster_DrawNGonMFIT(pVerts, numVerts, st);
            else if (!masked && translucent) rdZRaster_DrawNGonTFIT(pVerts, numVerts, st);
            else if (!masked && !translucent) rdZRaster_DrawNGonFIT(pVerts, numVerts, st);
        }
        break;
    case RDZ_LIT:
        if (solid) {
            if (translucent) rdZRaster_DrawNGonTLS(pVerts, numVerts, st); else rdZRaster_DrawNGonLS(pVerts, numVerts, st);
        } else if (affine) {
            if (masked && translucent) rdZRaster_DrawNGonMTLAT(pVerts, numVerts, st);
            else if (masked && !translucent) rdZRaster_DrawNGonMLAT(pVerts, numVerts, st);
            else if (!masked && translucent) rdZRaster_DrawNGonTLAT(pVerts, numVerts, st);
            else if (!masked && !translucent) rdZRaster_DrawNGonLAT(pVerts, numVerts, st);
        } else {
            if (masked && translucent) rdZRaster_DrawNGonMTLIT(pVerts, numVerts, st);
            else if (masked && !translucent) rdZRaster_DrawNGonMLIT(pVerts, numVerts, st);
            else if (!masked && translucent) rdZRaster_DrawNGonTLIT(pVerts, numVerts, st);
            else if (!masked && !translucent) rdZRaster_DrawNGonLIT(pVerts, numVerts, st);
        }
        break;
    case RDZ_GOURAUD:
        if (solid) {
            if (translucent) rdZRaster_DrawNGonTGS(pVerts, numVerts, st); else rdZRaster_DrawNGonGS(pVerts, numVerts, st);
        } else if (affine) {
            if (masked && translucent) rdZRaster_DrawNGonMTGAT(pVerts, numVerts, st);
            else if (masked && !translucent) rdZRaster_DrawNGonMGAT(pVerts, numVerts, st);
            else if (!masked && translucent) rdZRaster_DrawNGonTGAT(pVerts, numVerts, st);
            else if (!masked && !translucent) rdZRaster_DrawNGonGAT(pVerts, numVerts, st);
        } else {
            if (masked && translucent) rdZRaster_DrawNGonMTGIT(pVerts, numVerts, st);
            else if (masked && !translucent) rdZRaster_DrawNGonMGIT(pVerts, numVerts, st);
            else if (!masked && translucent) rdZRaster_DrawNGonTGIT(pVerts, numVerts, st);
            else if (!masked && !translucent) rdZRaster_DrawNGonGIT(pVerts, numVerts, st);
        }
        break;
    }
}

void rdZRaster_DrawFace(rdProcEntry* pProcEntry)
{
    if (rdZRaster_pZBuffer == NULL)
        return;

    // Handles the two filled geometry modes JK's DrawFaceZ rasterizes: RD_GEOMETRY_FULL (textured)
    // and RD_GEOMETRY_SOLID (flat solid fill). Wireframe (mode 2) / points (mode 1) are left to the
    // affine path; the target must be the 8bpp canvas (16bpp is unreachable via the menu buffer).
    tVBuffer* pVBuffer = rdCamera_g_pCurCamera->pCanvas->pVBuffer;
    if (pVBuffer->surface_lock_alloc == NULL || pVBuffer->format.format.is16bit)
        return;

    int geometryMode = pProcEntry->geometryMode;
    if (geometryMode > rdroid_g_curGeometryMode)
        geometryMode = rdroid_g_curGeometryMode;
    int lightingMode = pProcEntry->lightingMode;
    if (lightingMode > rdroid_g_curLightingMode)
        lightingMode = rdroid_g_curLightingMode;
    if ((geometryMode != RD_GEOMETRY_FULL && geometryMode != RD_GEOMETRY_SOLID)
        || (pProcEntry->extraData & 1) != 0)
        return;
    if (lightingMode < 0 || lightingMode >= 5)
        return;

    // Resolve the material cel -> texinfo -> a resident mip surface.
    rdMaterial* pMaterial = pProcEntry->material;
    if (pMaterial == NULL)
        return;
    int cel = pProcEntry->wallCel;
    if (cel == -1)
        cel = pMaterial->curCelNum;
    if (cel < 0)
        cel = 0;
    else if (cel > (int)pMaterial->num_texinfo - 1)
        cel = pMaterial->num_texinfo - 1;
    rdTexinfo* pTexinfo = pMaterial->texinfos[cel];
    if (pTexinfo == NULL)
        return;

    // Decide solid vs textured. A non-"full" texture (texture_type & 8 clear) or a texinfo with no
    // texture renders as a flat solid color (the texinfo's solidColor); a full texture is sampled.
    rdTexture* pTexture = pTexinfo->texture_ptr;
    int solidColor = -1;
    int masked = 0;
    const uint8_t* pTexels = NULL;
    tVBuffer* pMip = NULL;
    int lockedMip = 0;
    int mip = 0, mipW = 0, mipH = 0, mipStride = 0;

    if (geometryMode == RD_GEOMETRY_SOLID || (pTexinfo->header.texture_type & 8) == 0 || pTexture == NULL)
    {
        solidColor = (int)(pTexinfo->header.solidColor & 0xFF);
    }
    else
    {
        masked = (pTexture->alpha_en & 1) != 0;      // transparent texture: skip index-0 texels

        // Mip level from face distance (matches CalcAffineGradients thresholds), clamped to a
        // resident mip surface.
        int numMipsMinus1 = (int)pTexture->num_mipmaps - 1;
        flex_t dist = pProcEntry->z_min;
        if (numMipsMinus1 == 1)
        {
            if (rdroid_aMipDistances.y < dist) mip = 1;
        }
        else if (numMipsMinus1 == 2)
        {
            if (rdroid_aMipDistances.x < dist) mip = (rdroid_aMipDistances.y < dist) ? 2 : 1;
        }
        else if (numMipsMinus1 >= 3)
        {
            if (rdroid_aMipDistances.x < dist)
            {
                mip = 1;
                if (rdroid_aMipDistances.y < dist)
                {
                    mip = 2;
                    if (rdroid_aMipDistances.z < dist) mip = 3;
                }
            }
        }
        while (mip > 0 && pTexture->texture_struct[mip] == NULL)
            mip--;
        pMip = pTexture->texture_struct[mip];
        if (pMip == NULL)
            return;

        // Lock the mip on desktop to expose its 8bpp texels (persistent on TWL/DC).
        pTexels = (const uint8_t*)pMip->surface_lock_alloc;
        if (pTexels == NULL)
        {
            stdDisplay_VBufferLock(pMip);
            pTexels = (const uint8_t*)pMip->surface_lock_alloc;
            lockedMip = 1;
        }
        if (pTexels == NULL)
            return;
        mipW = (int)pMip->format.width;
        mipH = (int)pMip->format.height;
        mipStride = (int)pMip->format.rowSize;
    }

    // Colormap light table (per-vertex intensity indexes it). Absent -> raw texels.
    const uint8_t* pLightBase = NULL;
    if (pProcEntry->colormap != NULL && pProcEntry->colormap->lightlevel != NULL)
        pLightBase = pProcEntry->colormap->lightlevel;

    // Translucent faces (type & 2) blend the lit source over the destination through a 256x256
    // palette transparency LUT (matches JK's TGAT/translucent scanlines). Only a colormap with a
    // transparency section (flags & 1) allocates the table — the `transparency` pointer is
    // UNINITIALIZED otherwise, so gate on the flag, not just non-NULL (a NULL check alone crashed
    // on translucent faces whose colormap has no table). Prefer the proc's own colormap; fall back
    // to the identity map.
    const uint8_t* pTransTable = NULL;
    if (pProcEntry->type & 2)
        pTransTable = rdZRaster_ResolveTransTable(pProcEntry->colormap);

    // Per-vertex light level (0..63), by shading mode (mirrors rdCache_DrawFaceZ).
    flex_t ambient = (rdroid_g_curRenderOptions & 2) ? pProcEntry->ambientLight : 0.0f;
    flex_t flatLevel = 0.0f;
    int perVertex = 0;
    if (lightingMode == RD_LIGHTMODE_FULLYLIT || pLightBase == NULL)
    {
        flatLevel = 63.0f;   // no darkening
    }
    else if (lightingMode == RD_LIGHTMODE_GOURAUD)
    {
        perVertex = 1;
    }
    else   // NOTLIT / DIFFUSE
    {
        flex_t level = (lightingMode == RD_LIGHTMODE_NOTLIT)
                     ? rdZRaster_Clamp01(pProcEntry->extralight)
                     : rdZRaster_Clamp01(pProcEntry->extralight + pProcEntry->light_level_static);
        if (level < ambient) level = ambient;
        flatLevel = level * 63.0f;
    }

    // Shading variant for the dispatch: flat = full bright (no light table), lit = one constant
    // level, gouraud = per-pixel. Textured faces are affine (AT) when textureMode selects it, else
    // perspective-correct (IT) — the same axis JK's rdCache_DrawFaceZ dispatches on.
    int shade;
    if (lightingMode == RD_LIGHTMODE_FULLYLIT || pLightBase == NULL)
        shade = RDZ_FLAT;
    else if (lightingMode == RD_LIGHTMODE_GOURAUD)
        shade = RDZ_GOURAUD;
    else
        shade = RDZ_LIT;

    int textureMode = pProcEntry->textureMode;
    if (textureMode > rdroid_curTextureMode)
        textureMode = rdroid_curTextureMode;
    // JK's rdCache_DrawFaceZ selects affine (AT, textureMode 0, sub_45F040 — pure linear u/v, no
    // per-pixel divide) vs perspective (IT, textureMode 1). Dispatch faithfully; whether a face is
    // affine or perspective is decided upstream by whatever sets its textureMode.
    int affine = (textureMode == 0);

    // Build the per-vertex attribute array.
    int numVerts = (int)pProcEntry->numVertices;
    if (numVerts < 3 || numVerts > 32)
    {
        if (lockedMip) stdDisplay_VBufferUnlock(pMip);
        return;
    }
    rdZVertex verts[32];
    rdVector3* pV = pProcEntry->aVertices;
    rdVector2* pUV = pProcEntry->aTexVerticies;   // unused (and possibly NULL) for solid faces
    for (int i = 0; i < numVerts; i++)
    {
        flex_t z = pV[i].z;
        flex_t oow = (z != 0.0f) ? (1.0f / z) : 0.0f;
        verts[i].sx = pV[i].x;
        verts[i].sy = pV[i].y;
        verts[i].oneOverW = oow;
        verts[i].uOverW = (solidColor < 0) ? pUV[i].x * oow : 0.0f;
        verts[i].vOverW = (solidColor < 0) ? pUV[i].y * oow : 0.0f;
        verts[i].u = (solidColor < 0) ? pUV[i].x : 0.0f;   // affine (AT) texel coords
        verts[i].v = (solidColor < 0) ? pUV[i].y : 0.0f;
        if (perVertex)
        {
            flex_t vl = rdZRaster_Clamp01(pProcEntry->vertexIntensities[i] + pProcEntry->extralight);
            if (vl < ambient) vl = ambient;
            verts[i].intensity = vl * 63.0f;
        }
        else
        {
            verts[i].intensity = flatLevel;
        }
    }

    rdZRasterState st;
    st.pTexels = pTexels;
    st.pLightBase = pLightBase;
    st.pTransTable = pTransTable;
    st.mip = mip;
    st.mipW = mipW;
    st.mipH = mipH;
    st.mipStride = mipStride;
    st.solidColor = solidColor;
    rdZRaster_DispatchNGon(verts, numVerts, &st,
                           solidColor >= 0,          // solid (untextured) fill
                           affine,                    // AT (affine) vs IT (perspective)
                           masked,                    // skip index-0 texels
                           pTransTable != NULL,       // translucent blend
                           shade);                    // flat / lit / gouraud
    if (lockedMip)
        stdDisplay_VBufferUnlock(pMip);
}

#endif // RDRASTER_SOFTWARE_RENDERER
