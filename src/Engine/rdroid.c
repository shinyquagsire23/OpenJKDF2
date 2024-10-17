#include "rdroid.h"

#include "Raster/rdRaster.h"
#include "Engine/rdActive.h"
#include "Raster/rdCache.h"
#include "Primitives/rdModel3.h"
#include "General/stdPalEffects.h"
#include "Engine/rdCamera.h"
#include "Win95/stdDisplay.h"
#include "Primitives/rdPrimit3.h"

#ifdef FOG
int rdroid_curFogEnabled;
rdVector4 rdroid_curFogColor;
float rdroid_curFogStartDepth;
float rdroid_curFogEndDepth;
#endif


#ifdef RENDER_DROID2

#include "General/stdMath.h"
#include "Primitives/rdQuat.h"

void rdMatrixChanged();

static rdCaps_t rdroid_caps = RD_LIGHTING | RD_SHADOWS | RD_DECALS;

static std3D_RasterState       rdroid_rasterState;
static std3D_BlendState        rdroid_blendState;
static std3D_DepthStencilState rdroid_depthStencilState;
static std3D_TextureState      rdroid_textureState;
static std3D_LightingState     rdroid_lightingState;

static rdMatrixMode_t rdroid_curMatrixMode = RD_MATRIX_MODEL;
static rdMatrix44     rdroid_matrices[3];
static rdMatrix44     rdroid_curCamMatrix;
static rdMatrix44     rdroid_curModelView;
static rdMatrix44     rdroid_curViewProj;
static rdMatrix44     rdroid_curProjInv;
static rdMatrix44     rdroid_curViewProjInv;

static int rdroid_sortPriority = 0;
static float rdroid_sortDistance = 0;
static int rdroid_renderPass = 0;

static uint32_t  rdroid_vertexColorState = 0xFFFFFFFF;
static rdVector4 rdroid_vertexTexCoordState = { 0.0f, 0.0f, 0.0f, 1.0f };
static rdVector3 rdroid_vertexNormalState = { 0.0f, 0.0f, 0.0f };

static int               rdroid_vertexCacheNum = 0;
static D3DVERTEX         rdroid_vertexCache[64];
static rdPrimitiveType_t rdroid_curPrimitiveType = RD_PRIMITIVE_NONE;

void rdResetRasterState()
{
	rdroid_rasterState.geoMode = RD_GEOMODE_TEXTURED;
	rdroid_rasterState.colorMode = RD_VERTEX_COLOR_MODE_COLORED;
	rdroid_rasterState.cullMode = RD_CULL_MODE_CCW_ONLY;

	rdroid_rasterState.scissorMode = RD_SCISSOR_DISABLED;
	rdroid_rasterState.scissor.x = rdroid_rasterState.scissor.y = 0;
	rdroid_rasterState.scissor.width = 640;
	rdroid_rasterState.scissor.height = 480;

	rdroid_rasterState.viewport.x = rdroid_rasterState.viewport.y = 0;
	rdroid_rasterState.viewport.width = 640;
	rdroid_rasterState.viewport.height = 480;
	rdroid_rasterState.viewport.minDepth = 0;
	rdroid_rasterState.viewport.maxDepth = 1;
}

void rdResetBlendState()
{
	rdroid_blendState.blendMode = RD_BLEND_MODE_NONE;
}

void rdResetDepthStencilState()
{
	rdroid_depthStencilState.zmethod = RD_ZBUFFER_READ_WRITE;
	rdroid_depthStencilState.zcompare = RD_COMPARE_LESS_EQUAL;
}

void rdResetTextureState()
{
	rdroid_textureState.alphaTest = 0;
	rdroid_textureState.alphaRef = 0;
	rdroid_textureState.chromaKeyMode = RD_CHROMA_KEY_DISABLED;
	rdroid_textureState.chromaKeyColor = 0;
	rdroid_textureState.pTexture = NULL;
	rdroid_textureState.texMode = RD_TEXTUREMODE_PERSPECTIVE;
	rdroid_textureState.texGen = RD_TEXGEN_NONE;
	rdroid_textureState.texGenParams.x = rdroid_textureState.texGenParams.y = rdroid_textureState.texGenParams.z = rdroid_textureState.texGenParams.w = 0;
	rdroid_textureState.texOffset.x = rdroid_textureState.texOffset.y = 0;
}

void rdResetLightingState()
{
	rdVector_Zero3(&rdroid_lightingState.ambientColor);
	rdAmbient_Zero(&rdroid_lightingState.ambientStateSH);
}
#endif

int rdStartup(HostServices *p_hs)
{
    if (bRDroidStartup)
        return 1;

    rdroid_pHS = p_hs;
    rdCache_Startup();
    rdActive_Startup();
    rdRaster_Startup();

#ifdef RENDER_DROID2
	rdResetMatrices();
	rdResetRasterState();
	rdResetBlendState();
	rdResetDepthStencilState();
	rdResetTextureState();
	rdResetLightingState();
	rdroid_sortPriority = 0;
	rdroid_sortDistance = 0;
#endif

    bRDroidStartup = 1;
    return 1;
}

void rdShutdown()
{
    if (bRDroidStartup)
        bRDroidStartup = 0;
}

int rdOpen(int a1)
{
    if (bRDroidOpen)
        return 1;

    rdroid_curGeometryMode = 5;
    rdroid_curLightingMode = 5;
    rdroid_curRenderOptions = 1;
    rdroid_curTextureMode = 3;
    rdroid_curSortingMethod = 0;
    rdroid_curOcclusionMethod = 0;
    rdroid_curCullFlags = 3;
    rdroid_curProcFaceUserData = 0;
 
#ifdef FOG
	rdroid_curFogEnabled = 0;
	rdVector_Zero3(&rdroid_curFogColor);
	rdroid_curFogStartDepth = 0.0f;
	rdroid_curFogEndDepth = 10000.0f;
#endif

    stdPalEffects_ResetEffect(&rdroid_curColorEffects);

    // MOTS added
    rdroid_curVertexColorMode = 0;
    
    rdroid_frameTrue = 0;
    rdCache_ClearFrameCounters();
    rdActive_ClearFrameCounters();
    rdModel3_ClearFrameCounters();
    rdroid_curAcceleration = a1;

    bRDroidOpen = 1;
    return 1;
}

void rdClose()
{
    if (bRDroidOpen)
        bRDroidOpen = 0;
}

void rdSetRenderOptions(int a1)
{
    rdroid_curRenderOptions = a1;
}

void rdSetGeometryMode(int a1)
{
    rdroid_curGeometryMode = a1;
}

void rdSetLightingMode(int a1)
{
    rdroid_curLightingMode = a1;
}

void rdSetTextureMode(int a1)
{
    rdroid_curTextureMode = a1;
}

void rdSetSortingMethod(int a1)
{
    rdroid_curSortingMethod = a1;
}

void rdSetOcclusionMethod(int a1)
{
    rdroid_curOcclusionMethod = a1;
}

void rdSetZBufferMethod(rdZBufferMethod_t val)
{
    rdroid_curZBufferMethod = val;
}

void rdSetCullFlags(int a1)
{
    rdroid_curCullFlags = a1;
}

void rdSetProcFaceUserData(int a1)
{
    rdroid_curProcFaceUserData = a1;
}

// MOTS added
void rdSetVertexColorMode(int a1)
{
#ifdef RGB_THING_LIGHTS
	rdroid_curVertexColorMode = 1;
#else
    rdroid_curVertexColorMode = a1;
#endif
}

#ifdef FOG
void rdSetFog(int active, const rdVector4* color, float startDepth, float endDepth)
{
#ifdef RENDER_DROID2
	if(active)
		rdEnable(RD_FOG);
	else
		rdDisable(RD_FOG);
	rdFogColorf(color->x, color->y, color->z, color->w);
	rdFogRange(startDepth, endDepth);
#else
	rdroid_curFogEnabled = active;
	rdVector_Copy4(&rdroid_curFogColor, color);
	rdroid_curFogStartDepth = startDepth;
	rdroid_curFogEndDepth = endDepth;
#endif
}
#endif

int rdGetRenderOptions(void)
{
    return rdroid_curRenderOptions;
}

int rdGetGeometryMode(void)
{
    return rdroid_curGeometryMode;
}

int rdGetLightingMode(void)
{
    return rdroid_curLightingMode;
}

int rdGetTextureMode(void)
{
    return rdroid_curTextureMode;
}

int rdGetSortingMethod(void)
{
    return rdroid_curSortingMethod;
}

int rdGetOcclusionMethod(void)
{
    return rdroid_curOcclusionMethod;
}

int rdGetZBufferMethod(void)
{
    return rdroid_curZBufferMethod;
}

int rdGetCullFlags(void)
{
    return rdroid_curCullFlags;
}

int rdGetProcFaceUserData(void)
{
    return rdroid_curProcFaceUserData;
}

// MOTS added
int rdGetVertexColorMode(void)
{
#ifdef RGB_THING_LIGHTS
	return 1;
#else
    return rdroid_curVertexColorMode;
#endif
}

int rdSetMipDistances(rdVector4 *dists)
{
    rdVector_Copy4(&rdroid_aMipDistances, dists);

#ifdef QOL_IMPROVEMENTS
    static rdVector4 origLod;
    static int once = 0;
    if (!once) {
        origLod = sithWorld_pCurrentWorld->lodDistance;
        once = 1;
    }

    float scale_factor = (Video_format.width / 640.0) * 2.0;
    rdroid_aMipDistances.x *= scale_factor;
    rdroid_aMipDistances.y *= scale_factor;
    rdroid_aMipDistances.z *= scale_factor;
    rdroid_aMipDistances.w *= scale_factor;

    sithWorld_pCurrentWorld->lodDistance.x = origLod.x * scale_factor;
    sithWorld_pCurrentWorld->lodDistance.y = origLod.y * scale_factor;
    sithWorld_pCurrentWorld->lodDistance.z = origLod.z * scale_factor;
    sithWorld_pCurrentWorld->lodDistance.w = origLod.w * scale_factor;
#endif

    return 1;
}

int rdSetColorEffects(stdPalEffect *effects)
{
    _memcpy(&rdroid_curColorEffects, effects, sizeof(rdroid_curColorEffects));
    return 1;
}

void rdAdvanceFrame()
{
  rdCache_ClearFrameCounters();
  rdActive_ClearFrameCounters();
  rdModel3_ClearFrameCounters();
  
  ++rdroid_frameTrue;
  
  rdCamera_AdvanceFrame();
  rdCache_AdvanceFrame();
}

void rdFinishFrame()
{
  rdCache_Flush();
  rdCache_FinishFrame();
  // rdPrimit3_ClearFrameCounters(); // MOTS added
  stdDisplay_ddraw_waitforvblank(); // MOTS removed
  rdCache_ClearFrameCounters(); // MOTS removed
  rdActive_ClearFrameCounters(); // MOTS removed
  rdModel3_ClearFrameCounters(); // MOTS removed

#ifdef RENDER_DROID2
  rdResetMatrices();
  rdResetRasterState();
  rdResetBlendState();
  rdResetDepthStencilState();
  rdResetTextureState();
  rdResetLightingState();
#endif
}

void rdClearPostStatistics()
{
    rdPrimit3_ClearFrameCounters();
}


#ifdef RENDER_DROID2

void rdEnable(rdCaps_t cap)
{
	rdroid_caps |= cap;
}

void rdDisable(rdCaps_t cap)
{
	rdroid_caps &= ~cap;
}

// Matrix state

void rdMatrixChanged()
{
	rdMatrix_Multiply44(&rdroid_curModelView, &rdroid_matrices[RD_MATRIX_VIEW], &rdroid_matrices[RD_MATRIX_MODEL]);
	rdMatrix_Invert44(&rdroid_curCamMatrix, &rdroid_matrices[RD_MATRIX_VIEW]);
	rdMatrix_Multiply44(&rdroid_curViewProj, &rdroid_matrices[RD_MATRIX_PROJECTION], &rdroid_matrices[RD_MATRIX_VIEW]);
	rdMatrix_Invert44(&rdroid_curProjInv, &rdroid_matrices[RD_MATRIX_PROJECTION]);
	rdMatrix_Invert44(&rdroid_curViewProjInv, &rdroid_curViewProj);
}

void rdMatrixMode(rdMatrixMode_t mode)
{
	rdroid_curMatrixMode = mode;
}

void rdPerspective(float fov, float aspect, float nearPlane, float farPlane)
{
	rdMatrix44 persp;
	rdMatrix_BuildPerspective44(&persp, fov, aspect, nearPlane, farPlane);
	rdMatrix_PreMultiply44(&rdroid_matrices[rdroid_curMatrixMode], &persp);
	rdMatrixChanged();
}

void rdOrthographic(float width, float height, float near_plane, float far_plane)
{
	rdMatrix44 ortho;
	rdMatrix_BuildOrthographic44(&ortho, -width / 2.0f, width / 2.0f, -height / 2.0f, height / 2.0f, near_plane, far_plane);
	rdMatrix_PreMultiply44(&rdroid_matrices[rdroid_curMatrixMode], &ortho);
	rdMatrixChanged();
}

void rdLookat(const rdVector3* pViewer, const rdVector3* pTarget, const rdVector3* pUp)
{
	rdMatrix34 lookat;
	rdMatrix_BuildLookAt34(&lookat, pViewer, pTarget, pUp);
	rdMatrix44 lookat44;
	rdMatrix_Copy34to44(&lookat44, &lookat);

	rdMatrix_PreMultiply44(&rdroid_matrices[rdroid_curMatrixMode], &lookat44);
	rdMatrixChanged();
}

void rdTranslate(const rdVector3* pTranslation)
{
	rdMatrix_PreTranslate44(&rdroid_matrices[rdroid_curMatrixMode], pTranslation);
	rdMatrixChanged();
}

void rdRotate(const rdVector3* pRotation)
{
	rdMatrix_PreRotate44(&rdroid_matrices[rdroid_curMatrixMode], pRotation);
	rdMatrixChanged();
}

void rdScale(const rdVector4* pScaling)
{
	rdMatrix_PreScale44(&rdroid_matrices[rdroid_curMatrixMode], pScaling);
	rdMatrixChanged();
}

void rdIdentity()
{
	rdMatrix_Identity44(&rdroid_matrices[rdroid_curMatrixMode]);
	rdMatrixChanged();
}

void rdTranspose()
{
	rdMatrix44 tmp;
	rdMatrix_Copy44(&tmp, &rdroid_matrices[rdroid_curMatrixMode]);
	rdMatrix_Transpose44(&rdroid_matrices[rdroid_curMatrixMode], &tmp);
	rdMatrixChanged();
}

void rdLoadMatrix34(const rdMatrix34* pMatrix)
{
	rdMatrix_Copy34to44(&rdroid_matrices[rdroid_curMatrixMode], pMatrix);
	rdMatrixChanged();
}

void rdLoadMatrix(const rdMatrix44* pMatrix)
{
	rdMatrix_Copy44(&rdroid_matrices[rdroid_curMatrixMode], pMatrix);
	rdMatrixChanged();
}

void rdPreMultiplyMatrix(const rdMatrix44* pMatrix)
{
	rdMatrix_PreMultiply44(&rdroid_matrices[rdroid_curMatrixMode], pMatrix);
	rdMatrixChanged();
}

void rdPostMultiplyMatrix(const rdMatrix44* pMatrix)
{
	rdMatrix_PostMultiply44(&rdroid_matrices[rdroid_curMatrixMode], pMatrix);
	rdMatrixChanged();
}

void rdGetMatrix(rdMatrix44* out, rdMatrixMode_t mode)
{
	rdMatrix_Copy44(out, &rdroid_matrices[mode]);
}

void rdResetMatrices()
{
	rdMatrix_Identity44(&rdroid_matrices[RD_MATRIX_MODEL]);
	rdMatrix_Identity44(&rdroid_matrices[RD_MATRIX_PROJECTION]);
	rdMatrix_Identity44(&rdroid_matrices[RD_MATRIX_VIEW]);
}

// Viewport
void rdViewport(float x, float y, float width, float height, float minDepth, float maxDepth)
{
	rdroid_rasterState.viewport.x = x - 0.5f;
	rdroid_rasterState.viewport.y = y - 0.5f;
	rdroid_rasterState.viewport.width = width;
	rdroid_rasterState.viewport.height = height;
	rdroid_rasterState.viewport.minDepth = minDepth;
	rdroid_rasterState.viewport.maxDepth = maxDepth;
	rdMatrixChanged();
}

void rdGetViewport(rdViewportRect* pOut)
{
	memcpy(pOut, &rdroid_rasterState.viewport, sizeof(rdViewportRect));
}

void rdFogRange(float startDepth, float endDepth)
{
	rdroid_rasterState.fogStart = startDepth;
	rdroid_rasterState.fogEnd = endDepth;
}

void rdFogColor(uint8_t r, uint8_t g, uint8_t b, uint8_t a)
{
	rdroid_rasterState.fogColor = b | (g << 8) | (r << 16) | (a << 24);
}

void rdFogColorf(float r, float g, float b, float a)
{
	uint32_t ir = stdMath_ClampInt(r * 255, 0, 255);
	uint32_t ig = stdMath_ClampInt(g * 255, 0, 255);
	uint32_t ib = stdMath_ClampInt(b * 255, 0, 255);
	uint32_t ia = stdMath_ClampInt(a * 255, 0, 255);
	rdFogColor(ir, ig, ib, ia);
}

// Primitive
int rdBeginPrimitive(rdPrimitiveType_t type)
{
	// fail if we're already building a primitive
	if (rdroid_curPrimitiveType != RD_PRIMITIVE_NONE)
		return 0;

	rdroid_vertexCacheNum = 0;
	rdroid_curPrimitiveType = type;
	return 1;
}

extern void std3D_AddDrawCall(rdPrimitiveType_t type, std3D_DrawCallState* pDrawCallState, D3DVERTEX* paVertices, int numVertices);

void rdEndPrimitive()
{
	if(rdroid_vertexCacheNum == 0)
		return;

	std3D_DrawCallState state;
	rdMatrix_Copy44(&state.modelView, &rdroid_curModelView);
	rdMatrix_Copy44(&state.proj, &rdroid_matrices[RD_MATRIX_PROJECTION]);
	state.sortPriority = rdroid_sortPriority;
	state.sortDistance = rdroid_sortDistance;
	state.renderPass = rdroid_renderPass;
	state.renderCaps = rdroid_caps;

	memcpy(&state.raster, &rdroid_rasterState, sizeof(std3D_RasterState));
	memcpy(&state.blend, &rdroid_blendState, sizeof(std3D_BlendState));
	memcpy(&state.depthStencil, &rdroid_depthStencilState, sizeof(std3D_DepthStencilState));
	memcpy(&state.texture, &rdroid_textureState, sizeof(std3D_TextureState));
	memcpy(&state.lighting, &rdroid_lightingState, sizeof(std3D_LightingState));

	state.raster.fog = rdroid_caps & RD_FOG;

	// fixme
	state.depthStencil.zmethod = rdGetZBufferMethod();

	// clamp to global states
	//if (state.raster.geoMode > rdroid_curGeometryMode)
	//	state.raster.geoMode = rdroid_curGeometryMode;
	//
	//if(state.texture.texMode > rdroid_curTextureMode)
	//	state.texture.texMode = rdroid_curTextureMode;
	//
	//if (state.lighting.lightMode > rdroid_curLightingMode)
	//	state.lighting.lightMode = rdroid_curLightingMode;

	std3D_AddDrawCall(rdroid_curPrimitiveType, &state, rdroid_vertexCache, rdroid_vertexCacheNum);

	rdroid_vertexCacheNum = 0;
	rdroid_vertexColorState = 0xFFFFFFFF;
	rdVector_Set4(&rdroid_vertexTexCoordState, 0.0f, 0.0f, 0.0f, 1.0f);
	rdVector_Set3(&rdroid_vertexNormalState, 0.0f, 0.0f, 1.0f);
	rdroid_curPrimitiveType = RD_PRIMITIVE_NONE;
}

void rdVertex3f(float x, float y, float z)
{
	if(rdroid_vertexCacheNum >= 24)
	{
		// todo: real error callback hooks
		printf("too many vertices for primitive\n");
		return;
	}

	D3DVERTEX* pVert = &rdroid_vertexCache[rdroid_vertexCacheNum++];
	pVert->x = x;
	pVert->y = y;
	pVert->z = z;
	pVert->tu = rdroid_vertexTexCoordState.x;
	pVert->tv = rdroid_vertexTexCoordState.y;
	pVert->tr = rdroid_vertexTexCoordState.z;
	pVert->tq = rdroid_vertexTexCoordState.w;
	pVert->nx = rdroid_vertexNormalState.x;
	pVert->ny = rdroid_vertexNormalState.y;
	pVert->nz = rdroid_vertexNormalState.z;
	pVert->color = rdroid_vertexColorState;
	pVert->lightLevel = 0.0f;
}

void rdVertex(const rdVector3* pPos)
{
	rdVertex3f(pPos->x, pPos->y, pPos->z);
}

void rdColor4f(float r, float g, float b, float a)
{
	uint32_t ir = stdMath_ClampInt(r * 255, 0, 255);
	uint32_t ig = stdMath_ClampInt(g * 255, 0, 255);
	uint32_t ib = stdMath_ClampInt(b * 255, 0, 255);
	uint32_t ia = stdMath_ClampInt(a * 255, 0, 255);
	rdroid_vertexColorState = ib | (ig << 8) | (ir << 16) | (ia << 24);
}

void rdColor(const rdVector4* pCol)
{
	rdColor4f(pCol->x, pCol->y, pCol->z, pCol->w);
}

void rdTexCoord2f(float u, float v)
{
	rdroid_vertexTexCoordState.x = u;
	rdroid_vertexTexCoordState.y = v;
	rdroid_vertexTexCoordState.z = 0;
	rdroid_vertexTexCoordState.w = 1;
}

void rdTexCoord2i(float u, float v)
{
	if(rdroid_textureState.pTexture)
	{
		rdroid_vertexTexCoordState.x = (float)u / rdroid_textureState.texSize.x;
		rdroid_vertexTexCoordState.y = (float)v / rdroid_textureState.texSize.y;
	}
	else
	{
		rdroid_vertexTexCoordState.x = (float)u / 32.0f;
		rdroid_vertexTexCoordState.y = (float)v / 32.0f;
	}
	rdroid_vertexTexCoordState.z = 0;
	rdroid_vertexTexCoordState.w = 1;
}

void rdTexCoord(const rdVector2* pUV)
{
	rdTexCoord2f(pUV->x, pUV->y);
}

void rdTexCoord4i(float u, float v, float r, float q)
{
	rdTexCoord2i(u, v);
	rdroid_vertexTexCoordState.z = r;
	rdroid_vertexTexCoordState.w = q;
}

void rdNormal3f(float x, float y, float z)
{
	rdroid_vertexNormalState.x = x;
	rdroid_vertexNormalState.y = y;
	rdroid_vertexNormalState.z = z;
}

void rdNormal(const rdVector3* pNormal)
{
	rdNormal3f(pNormal->x, pNormal->y, pNormal->z);
}

// Texture
// todo: mips? how to do that in hw with current material cache?
void std3D_GetValidDimension(unsigned int inW, unsigned int inH, unsigned int* outW, unsigned int* outH);
int rdBindTexture(rdTexture* pTexture)
{
	if (!pTexture)
		return 0;

	// todo: texture cache here
	rdroid_textureState.pTexture = &pTexture->alphaMats[0];
	// todo: move me
	rdroid_textureState.alphaTest = (pTexture->alpha_en & 1) != 0;

	uint32_t out_width, out_height;
	std3D_GetValidDimension(
		pTexture->texture_struct[0]->format.width,
		pTexture->texture_struct[0]->format.height,
		&out_width,
		&out_height);
	rdroid_textureState.texSize.x = (float)(out_width << 0);
	rdroid_textureState.texSize.y = (float)(out_height << 0);
	rdroid_textureState.numMips = pTexture->num_mipmaps;

	return 1;
}

int rdBindMaterial(rdMaterial* pMaterial, int cel)
{
	if(!pMaterial)
		return 0;

	int alpha_is_opaque = 0;

	if(cel < 0)
		cel = pMaterial->celIdx;

	cel = stdMath_ClampInt(cel, 0, pMaterial->num_texinfo - 1);

	// set the material fill color
	rdVector3 fillColor;
	rdMaterial_GetFillColor(&fillColor, pMaterial, rdColormap_pCurMap, cel, -1);
	rdSetConstantColorf(fillColor.x, fillColor.y, fillColor.z, 1.f);

	rdTexinfo* texinfo = pMaterial->texinfos[cel];
	if (!texinfo || (texinfo->header.texture_type & 8) == 0)
	{
		rdroid_textureState.pTexture = NULL;
	}
	else
	{
		rdTexture* sith_tex_sel = texinfo->texture_ptr;
		if (!rdMaterial_AddToTextureCache(pMaterial, sith_tex_sel, 0, alpha_is_opaque, cel))
			return 0;

		rdroid_textureState.pTexture = &sith_tex_sel->alphaMats[0];
		if (alpha_is_opaque)
			rdroid_textureState.pTexture = &sith_tex_sel->opaqueMats[0];
		
		// todo: move me
		rdroid_textureState.alphaTest = (sith_tex_sel->alpha_en & 1) != 0;

		uint32_t out_width, out_height;
		std3D_GetValidDimension(
			sith_tex_sel->texture_struct[0]->format.width,
			sith_tex_sel->texture_struct[0]->format.height,
			&out_width,
			&out_height);
		rdroid_textureState.texSize.x = (float)(out_width << 0);
		rdroid_textureState.texSize.y = (float)(out_height << 0);
		rdroid_textureState.numMips = sith_tex_sel->num_mipmaps;
	}

	return 1;
}

void rdTexGen(rdTexGen_t texGen)
{
	rdroid_textureState.texGen = texGen;
}

void rdTexGenParams(float p0, float p1, float p2, float p3)
{
	rdroid_textureState.texGenParams.x = p0;
	rdroid_textureState.texGenParams.y = p1;
	rdroid_textureState.texGenParams.z = p2;
	rdroid_textureState.texGenParams.w = p3;
}

void rdTexOffset(float u, float v)
{
	rdroid_textureState.texOffset.x = u;
	rdroid_textureState.texOffset.y = v;
}

void rdTexOffseti(float u, float v)
{
	if (rdroid_textureState.pTexture)
	{
		rdroid_textureState.texOffset.x = (float)u / rdroid_textureState.texSize.x;
		rdroid_textureState.texOffset.y = (float)v / rdroid_textureState.texSize.y;
	}
	else
	{
		rdroid_textureState.texOffset.x = (float)u / 32.0f;
		rdroid_textureState.texOffset.y = (float)v / 32.0f;
	}
}

// Framebuffer
extern void std3D_SetRenderPassFlags(int8_t, rdRenderPassFlags_t);
void rdRenderPass(int8_t renderPass, rdRenderPassFlags_t renderPassFlags)
{
	std3D_SetRenderPassFlags(renderPass, renderPassFlags);
	rdroid_renderPass = renderPass;
}

extern void std3D_SetDepthRange(int8_t renderPass, float znearNorm, float zfarNorm);
void rdDepthRange(float znearNorm, float zfarNorm)
{
	std3D_SetDepthRange(rdroid_renderPass, znearNorm, zfarNorm);
}

// States
void rdSetZBufferCompare(rdCompare_t compare)
{
	rdroid_depthStencilState.zcompare = compare;
}

void rdSetBlendMode(rdBlendMode_t state)
{
	rdroid_blendState.blendMode = state;
}

void rdSetCullMode(rdCullMode_t mode)
{
	rdroid_rasterState.cullMode = mode;
}

void rdSetScissor(int x, int y, int width, int height)
{
	rdroid_rasterState.scissor.x = x;
	rdroid_rasterState.scissor.y = y;
	rdroid_rasterState.scissor.width = width;
	rdroid_rasterState.scissor.height = height;
}

void rdSetAlphaThreshold(uint8_t threshold)
{
	rdroid_textureState.alphaRef = threshold;
}

void rdSetConstantColor(uint8_t r, uint8_t g, uint8_t b, uint8_t a)
{
	rdroid_textureState.fillColor = b | (g << 8) | (r << 16) | (a << 24);
}

void rdSetConstantColorf(float r, float g, float b, float a)
{
	uint32_t ir = stdMath_ClampInt(r * 255, 0, 255);
	uint32_t ig = stdMath_ClampInt(g * 255, 0, 255);
	uint32_t ib = stdMath_ClampInt(b * 255, 0, 255);
	uint32_t ia = stdMath_ClampInt(a * 255, 0, 255);
	rdSetConstantColor(ir, ig, ib, ia);
}

void rdSetChromaKey(rdChromaKeyMode_t mode)
{
	rdroid_textureState.chromaKeyMode = mode;
}

void rdSetChromaKeyValue(uint8_t r, uint8_t g, uint8_t b)
{
	rdroid_textureState.chromaKeyColor = b | (g << 8) | (r << 16);
}

void rdSortPriority(int sortPriority)
{
	rdroid_sortPriority = sortPriority;
}

void rdSortDistance(float distance)
{
	rdroid_sortDistance = distance;
}

void rdSetGeoMode(int a1)
{
	rdroid_rasterState.geoMode = a1;
}

void rdSetLightMode(int a1)
{
	rdroid_lightingState.lightMode = a1;
}

void rdSetTexMode(int a1)
{
	rdroid_textureState.texMode = a1;
}

void rdDitherMode(rdDitherMode_t mode)
{
	rdroid_rasterState.ditherMode = mode;
}

// Lighting
int std3D_AddLight(rdLight* light, rdVector3* viewPosition);
int rdAddLight(rdLight* pLight, rdVector3* pPosition)
{
	rdVector4 pos4;
	rdVector_Copy3(&pos4, pPosition);
	pos4.w = 1.0f;

	rdVector4 viewPos;
	rdMatrix_TransformPoint44(&viewPos, &pos4, &rdroid_matrices[RD_MATRIX_VIEW]);
	return std3D_AddLight(pLight, (rdVector3*)&viewPos);
}

void std3D_ClearLights();
void std3D_ClearOccluders();
void std3D_ClearDecals();
void rdClearLights()
{
	std3D_ClearLights();
}

void rdClearOccluders()
{
	std3D_ClearOccluders();
}

void rdClearDecals()
{
	std3D_ClearDecals();
}

extern int jkPlayer_enableShadows;
void std3D_DrawOccluder(rdVector3* position, float radius, rdVector3* verts);
void rdAddOccluder(rdVector3* position, float radius)
{
	if (!jkPlayer_enableShadows )
		return;
	
	rdVector4 pos4;
	rdVector_Copy3(&pos4, position);
	pos4.w = 1.0f;
	
	rdVector4 viewPos;
	rdMatrix_TransformPoint44(&viewPos, &pos4, &rdroid_matrices[RD_MATRIX_VIEW]);
	std3D_DrawOccluder((rdVector3*)&viewPos, radius, NULL);
}

extern int jkPlayer_enableDecals;
void std3D_DrawDecal(stdVBuffer* vbuf, rdDDrawSurface* texture, rdVector3* verts, rdMatrix44* decalMatrix, rdVector3* color, uint32_t flags, float angleFade);
void rdAddDecal(rdDecal* decal, rdMatrix34* modelMat, rdVector3* color, rdVector3* scale, float angleFade)
{
	if(!jkPlayer_enableDecals)
		return;

	if (!decal->material)
		return;

	rdTexture* sith_tex_sel = decal->material->texinfos[0]->texture_ptr;
	if (!rdMaterial_AddToTextureCache(decal->material, sith_tex_sel, 0, 0, 0))
		return 0;

	rdDDrawSurface* tex2_arr_sel = &sith_tex_sel->alphaMats[0];
	if (!tex2_arr_sel)
		return;

//	rdMatrix34 decalMatrix;
//	rdMatrix_Multiply34(&decalMatrix, &rdroid_matrices[RD_MATRIX_VIEW], modelMat);
//	rdMatrix_Copy34(&decalMatrix, modelMat);

	rdMatrix44 decalMatrix;
	rdMatrix_Multiply44(&decalMatrix, &rdroid_matrices[RD_MATRIX_VIEW], &rdroid_matrices[RD_MATRIX_MODEL]);

	std3D_DrawDecal(sith_tex_sel->texture_struct[0], tex2_arr_sel, scale, &decalMatrix, color, decal->flags, angleFade);
}

void rdAmbientLight(float r, float g, float b)
{
	rdVector_Set3(&rdroid_lightingState.ambientColor, r, g, b);
}

// todo: completely remove this in favor of a light type
rdVector4 rdroid_sgBasis[8];

void rdAmbientLightSH(rdAmbient* amb)
{
	if (!amb)
	{
		rdAmbient_Zero(&rdroid_lightingState.ambientStateSH);
		return;
	}

	rdMatrix34 viewMat;
	rdMatrix_Copy44to34(&viewMat, &rdroid_matrices[RD_MATRIX_VIEW]);

#ifndef RENDER_DROID2
	// rotate the ambient SH to view space
	rdroid_lightingState.ambientStateSH.r.x = amb->r.x;
	rdroid_lightingState.ambientStateSH.g.x = amb->g.x;
	rdroid_lightingState.ambientStateSH.b.x = amb->b.x;
	rdMatrix_TransformVector34((rdVector3*)&rdroid_lightingState.ambientStateSH.r.y, &amb->r.y, &viewMat);
	rdMatrix_TransformVector34((rdVector3*)&rdroid_lightingState.ambientStateSH.g.y, &amb->g.y, &viewMat);
	rdMatrix_TransformVector34((rdVector3*)&rdroid_lightingState.ambientStateSH.b.y, &amb->b.y, &viewMat);
	rdMatrix_TransformVector34(&rdroid_lightingState.ambientStateSH.dominantDir, &amb->dominantDir, &viewMat);
	//rdAmbient_Copy(&rdroid_lightingState.ambientStateSH, amb);
#else
	for(int i = 0; i < 8; ++i)
	{
		rdVector_Copy3(&rdroid_lightingState.ambientStateSH.sgs[i], &amb->sgs[i]);

		rdMatrix_TransformVector34((rdVector3*)&rdroid_sgBasis[i].x, &rdLight_sgBasis[i].x, &viewMat);
		rdroid_sgBasis[i].w = rdLight_sgBasis[i].w;
	}
#endif
}

#endif