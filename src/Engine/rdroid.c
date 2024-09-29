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

static RD_CULL_MODE rdroid_curCullMode = RD_CULL_MODE_CCW_ONLY;

static RD_MATRIX_MODE rdroid_curMatrixMode = RD_MATRIX_MODEL;
static rdViewportRect rdroid_curViewport;
static rdMatrix44     rdroid_matrices[3];

static rdMaterial* rdroid_curMaterial = NULL;
static rdDDrawSurface* rdroid_curTexture = NULL;
static float rdroid_texWidth = 1;
static float rdroid_texHeight = 1;

static uint32_t rdroid_vertexColorState = 0xFFFFFFFF;
static rdVector2 rdroid_vertexTexCoordState = { 0.0f, 0.0f };
static rdVector3 rdroid_vertexNormalState = { 0.0f, 0.0f, 0.0f };

static int rdroid_vertexCacheNum = 0;
static D3DVERTEX rdroid_vertexCache[32];
static RD_PRIMITIVE_TYPE rdroid_curPrimitiveType = RD_PRIMITIVE_NONE;

static float rdroid_curFov = 90.0f;
static rdMatrix44 rdroid_curCamMatrix;
static rdMatrix44 rdroid_curViewProj;
static rdMatrix44 rdroid_curProjInv;
static rdMatrix44 rdroid_curViewProjInv;
static rdVector3 rdroid_curRotationPYR;

static int rdroid_lightType = 0;
static rdVector3 rdroid_lightPosState = { 0.0f, 0.0f, 0.0f };
static float rdroid_lightRadiusState = 0.0f;
static rdVector3 rdroid_lightColorState = { 0.0f, 0.0f, 0.0f };

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
	rdroid_curFogEnabled = active;
	rdVector_Copy4(&rdroid_curFogColor, color);
	rdroid_curFogStartDepth = startDepth;
	rdroid_curFogEndDepth = endDepth;
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
}

void rdClearPostStatistics()
{
    rdPrimit3_ClearFrameCounters();
}


#ifdef RENDER_DROID2

// Matrix state

void rdMatrixChanged()
{
	// todo: can do this once instead of on every change
	rdroid_curFov = (2.0 * atanf(1.0f / rdroid_matrices[RD_MATRIX_PROJECTION].vB.y));
	rdMatrix_Invert44(&rdroid_curCamMatrix, &rdroid_matrices[RD_MATRIX_VIEW]);
	rdMatrix_Multiply44(&rdroid_curViewProj, &rdroid_matrices[RD_MATRIX_PROJECTION], &rdroid_matrices[RD_MATRIX_VIEW]);
	rdMatrix_Invert44(&rdroid_curProjInv, &rdroid_matrices[RD_MATRIX_PROJECTION]);
	rdMatrix_Invert44(&rdroid_curViewProjInv, &rdroid_curViewProj);

	// extract angles doesn't seem to be working here?
	rdroid_curRotationPYR.y = atan2(rdroid_curCamMatrix.vA.y, rdroid_curCamMatrix.vA.x);
	rdroid_curRotationPYR.z = atan2(-rdroid_curCamMatrix.vA.z, stdMath_Sqrt(rdroid_curCamMatrix.vB.z * rdroid_curCamMatrix.vB.z + rdroid_curCamMatrix.vC.z * rdroid_curCamMatrix.vC.z));
	rdroid_curRotationPYR.x = atan2(rdroid_curCamMatrix.vB.z, rdroid_curCamMatrix.vC.z);
}

void rdMatrixMode(RD_MATRIX_MODE mode)
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
	rdMatrix_PostTranslate44(&rdroid_matrices[rdroid_curMatrixMode], pTranslation);
	rdMatrixChanged();
}

void rdRotate(const rdVector3* pRotation)
{
	rdMatrix_PostRotate44(&rdroid_matrices[rdroid_curMatrixMode], pRotation);
	rdMatrixChanged();
}

void rdScale(const rdVector4* pScaling)
{
	rdMatrix_PostScale44(&rdroid_matrices[rdroid_curMatrixMode], pScaling);
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

void rdGetMatrix(rdMatrix44* out, RD_MATRIX_MODE mode)
{
	rdMatrix_Copy44(out, &rdroid_matrices[rdroid_curMatrixMode]);
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
	rdroid_curViewport.x = x - 0.5f;
	rdroid_curViewport.y = y - 0.5f;
	rdroid_curViewport.width = width;
	rdroid_curViewport.height = height;
	rdroid_curViewport.minDepth = minDepth;
	rdroid_curViewport.maxDepth = maxDepth;
	rdMatrixChanged();
}

void rdGetViewport(rdViewportRect* pOut)
{
	memcpy(pOut, &rdroid_curViewport, sizeof(rdViewportRect));
}

// Primitive
int rdBeginPrimitive(RD_PRIMITIVE_TYPE type)
{
	// fail if we're already building a primitive
	if (rdroid_curPrimitiveType != RD_PRIMITIVE_NONE)
		return 0;

	rdroid_vertexCacheNum = 0;
	rdroid_curPrimitiveType = type;
	return 1;
}

void std3D_AddRenderListPrimitive(rdPrimitive* pPrimitive);

void rdEndPrimitive()
{
	rdPrimitive prim;
	rdMatrix_Multiply44(&prim.modelViewProj, &rdroid_matrices[RD_MATRIX_MODEL], &rdroid_curViewProj);
	prim.pTexture = rdroid_curTexture;
	memcpy(prim.aVertices, rdroid_vertexCache, sizeof(D3DVERTEX) * rdroid_vertexCacheNum);
	prim.numVertices = rdroid_vertexCacheNum;
	std3D_AddRenderListPrimitive(&prim);

	rdroid_vertexCacheNum = 0;
	rdroid_vertexColorState = 0xFFFFFFFF;
	rdVector_Set2(&rdroid_vertexTexCoordState, 0.0f, 0.0f);
	rdVector_Set3(&rdroid_vertexNormalState, 0.0f, 0.0f, 1.0f);
	rdroid_curPrimitiveType = RD_PRIMITIVE_NONE;
}

void rdVertex3f(float x, float y, float z)
{
	if(rdroid_vertexCacheNum >= 32)
		return;

	D3DVERTEX* pVert = &rdroid_vertexCache[rdroid_vertexCacheNum++];
	pVert->x = x;
	pVert->y = y;
	pVert->z = z;
	pVert->tu = rdroid_vertexTexCoordState.x;
	pVert->tv = rdroid_vertexTexCoordState.y;
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
}

void rdTexCoord2i(float u, float v)
{
	if(rdroid_curTexture)
	{
		rdroid_vertexTexCoordState.x = (float)u / rdroid_texWidth;
		rdroid_vertexTexCoordState.y = (float)v / rdroid_texHeight;
	}
	else
	{
		rdroid_vertexTexCoordState.x = (float)u / 32.0f;
		rdroid_vertexTexCoordState.y = (float)v / 32.0f;
	}
}

void rdTexCoord(const rdVector2* pUV)
{
	rdTexCoord2f(pUV->x, pUV->y);
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
// todo: mips? maybe do that in hw?
int rdBindTexture(rdMaterial* pMaterial, int cel)
{
	if(!pMaterial)
		return 0;

	int alpha_is_opaque = 0;

	cel = stdMath_ClampInt(cel, 0, pMaterial->num_texinfo - 1);

	rdTexinfo* texinfo = pMaterial->texinfos[cel];

	rdTexture* sith_tex_sel = NULL;
	if (!texinfo || (texinfo->header.texture_type & 8) == 0)
	{
		rdroid_curTexture = NULL;
	}
	else
	{
		sith_tex_sel = texinfo->texture_ptr;
		if (!rdMaterial_AddToTextureCache(pMaterial, sith_tex_sel, 0, alpha_is_opaque, cel))
			return 0;

		rdroid_curTexture = &sith_tex_sel->alphaMats[0];
		if (alpha_is_opaque)
			rdroid_curTexture = &sith_tex_sel->opaqueMats[0];
		
		uint32_t out_width, out_height;
		std3D_GetValidDimension(
			sith_tex_sel->texture_struct[0]->format.width,
			sith_tex_sel->texture_struct[0]->format.height,
			&out_width,
			&out_height);
		rdroid_texWidth = (float)(out_width << 0);
		rdroid_texHeight = (float)(out_height << 0);	
	}
	rdroid_curMaterial = pMaterial;

	return 1;
}

// Framebuffer
void rdClearDepth(uint32_t z)
{
	// todo
}

void rdClearColor(uint32_t rgba)
{
	// todo
}

// States
void rdSetZBufferCompare(RD_COMPARE mode)
{
	// todo
}

void rdSetBlendMode(RD_BLEND_MODE state)
{
	// todo
}

void rdSetCullMode(RD_CULL_MODE mode)
{
	// todo
}

void rdSetScissor(int x, int y, int width, int height)
{
	// todo
}

void rdSetAlphaThreshold(uint8_t threshold)
{
	// todo
}
void rdSetConstantColor(uint8_t r, uint8_t g, uint8_t b, uint8_t a)
{
	// todo
}

void rdSetChromaKey(RD_CHROMA_KEY_MODE mode)
{
	// todo
}

void rdSetChromaKeyValue(uint8_t r, uint8_t g, uint8_t b)
{
	// todo
}

void rdSetGeoMode(int a1)
{
	// todo
}

void rdSetLightMode(int a1)
{
	// todo
}

void rdSetTexMode(int a1)
{
	// todo
}

// Lighting
int rdBeginLight()
{
	if (rdroid_lightType != 0)
		return 0;
	// todo
	rdroid_lightType = 1;
	return 1;
}

void rdLightPosition(const rdVector3* pPos)
{
	rdVector_Copy3(&rdroid_lightPosState, pPos);
}

void rdLightRadius(float radius)
{
	rdroid_lightRadiusState = radius;
}

void rdLightColor(const rdVector3* pColor)
{
	rdVector_Copy3(&rdroid_lightColorState, pColor);
}

void rdEndLight()
{
	if (rdroid_lightType == 0)
		return;
	// todo
	rdroid_lightType = 0;
}

#endif