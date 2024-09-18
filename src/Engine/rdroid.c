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

#ifdef STENCIL_BUFFER
int rdroid_curStencilMethod = 0;
#endif

int rdStartup(HostServices *p_hs)
{
    if (bRDroidStartup)
        return 1;

    rdroid_pHS = p_hs;
    rdCache_Startup();
    rdActive_Startup();
    rdRaster_Startup();

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

#ifdef STENCIL_BUFFER
void rdSetStencilBufferMethod(int val)
{
	rdroid_curStencilMethod = val;
}
#endif

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

#ifdef STENCIL_BUFFER
int rdGetStencilBufferMethod()
{
	return rdroid_curStencilMethod;
}
#endif

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
