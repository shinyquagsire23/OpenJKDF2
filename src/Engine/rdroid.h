#ifndef _RDROID_H
#define _RDROID_H

#include "jk.h"
#include "types.h"
#include "globals.h"

#define rdStartup_ADDR (0x0043A950)
#define rdShutdown_ADDR (0x0043A990)
#define rdOpen_ADDR (0x0043A9B0)
#define rdClose_ADDR (0x0043AA40)
#define rdSetRenderOptions_ADDR (0x0043AA60)
#define rdSetGeometryMode_ADDR (0x0043AA70)
#define rdSetLightingMode_ADDR (0x0043AA80)
#define rdSetTextureMode_ADDR (0x0043AA90)
#define rdSetSortingMethod_ADDR (0x0043AAA0)
#define rdSetOcclusionMethod_ADDR (0x0043AAB0)
#define rdSetZBufferMethod_ADDR (0x0043AAC0)
#define rdSetCullFlags_ADDR (0x0043AAD0)
#define rdSetProcFaceUserData_ADDR (0x0043AAE0)
#define rdGetRenderOptions_ADDR (0x0043AAF0)
#define rdGetGeometryMode_ADDR (0x0043AB00)
#define rdGetLightingMode_ADDR (0x0043AB10)
#define rdGetTextureMode_ADDR (0x0043AB20)
#define rdGetSortingMethod_ADDR (0x0043AB30)
#define rdGetOcclusionMethod_ADDR (0x0043AB40)
#define rdGetZBufferMethod_ADDR (0x0043AB50)
#define rdGetCullFlags_ADDR (0x0043AB60)
#define rdGetProcFaceUserData_ADDR (0x0043AB70)
#define rdSetMipDistances_ADDR (0x0043AB80)
#define rdSetColorEffects_ADDR (0x0043ABB0)
#define rdAdvanceFrame_ADDR (0x0043ABD0)
#define rdFinishFrame_ADDR (0x0043ABF0)
#define rdClearPostStatistics_ADDR (0x0043AC10)

extern int rdroid_curVertexColorMode;
#ifdef FOG
extern int rdroid_curFogEnabled;
extern rdVector4 rdroid_curFogColor;
extern float rdroid_curFogStartDepth;
extern float rdroid_curFogEndDepth;
#endif

int rdStartup(HostServices *p_hs);
void rdShutdown();
int rdOpen(int a1);
void rdClose();

void rdSetRenderOptions(int a1);
void rdSetGeometryMode(int a1);
void rdSetLightingMode(int a1);
void rdSetTextureMode(int a1);
void rdSetSortingMethod(int a1);
void rdSetOcclusionMethod(int a1);
void rdSetZBufferMethod(rdZBufferMethod_t val);
void rdSetCullFlags(int a1);
void rdSetProcFaceUserData(int a1);
void rdSetVertexColorMode(int a1);

#ifdef FOG
void rdSetFog(int active, const rdVector4* color, float startDepth, float endDepth);
#endif

int rdGetRenderOptions(void);
int rdGetGeometryMode(void);
int rdGetLightingMode(void);
int rdGetTextureMode(void);
int rdGetSortingMethod(void);
int rdGetOcclusionMethod(void);
int rdGetZBufferMethod(void);
int rdGetCullFlags(void);
int rdGetProcFaceUserData(void);
int rdGetVertexColorMode(void);

int rdSetMipDistances(rdVector4 *dists);
int rdSetColorEffects(stdPalEffect *effects);

void rdAdvanceFrame();
void rdFinishFrame();
void rdClearPostStatistics();

//#define  (*(int*)0x)

#ifdef RENDER_DROID2
// todo: the original rdProcEntry stuff was somewhat stateless, try to move away from stateful api

// todo: rdPushMatrix/rdPopMatrix?
void rdMatrixMode(rdMatrixMode_t mode);
void rdPerspective(float fov, float aspect, float nearPlane, float farPlane);
void rdOrthographic(float width, float height, float nearPlane, float farPlane);
void rdLookat(const rdVector3* pViewer, const rdVector3* pTarget, const rdVector3* pUp);
void rdTranslate(const rdVector3* pTranslation);
void rdRotate(const rdVector3* pRotation);
void rdScale(const rdVector4* pScaling);
void rdIdentity();
void rdTranspose();
void rdLoadMatrix34(const rdMatrix34* pMatrix);
void rdLoadMatrix(const rdMatrix44* pMatrix);
void rdPostMultiplyMatrix(const rdMatrix44* pMatrix);
void rdPreMultiplyMatrix(const rdMatrix44* pMatrix);
void rdGetMatrix(rdMatrix44* pOut, rdMatrixMode_t mode);
void rdResetMatrices();

void rdViewport(float x, float y, float width, float height, float minDepth, float maxDepth);
void rdGetViewport(rdViewportRect* pOut);

int rdBeginPrimitive(rdPrimitiveType_t type);
void rdEndPrimitive();
void rdVertex3f(float x, float y, float z);
void rdColor4f(float r, float g, float b, float a);
void rdTexCoord2f(float u, float v); // normalized
void rdTexCoord2i(float u, float v); // unnormalized
void rdTexCoord4i(float u, float v, float r, float q); // unnormalized
void rdNormal3f(float x, float y, float z);
void rdVertex(const rdVector3* pPos);
void rdColor(const rdVector4* pCol);
void rdTexCoord(const rdVector2* pUV);
void rdNormal(const rdVector3* pNormal);

// render state
void rdSetZBufferCompare(rdCompare_t compare);
void rdSetBlendMode(rdBlendMode_t state);
void rdSetCullMode(rdCullMode_t mode);
void rdSetScissor(int x, int y, int width, int height);
void rdSetAlphaThreshold(uint8_t threshold);
void rdSetConstantColorf(float r, float g, float b, float a);
void rdSetConstantColor(uint8_t r, uint8_t g, uint8_t b, uint8_t a);
void rdSetChromaKey(rdChromaKeyMode_t mode);
void rdSetChromaKeyValue(uint8_t r, uint8_t g, uint8_t b);

void rdSortPriority(int sortPriority);
void rdSortDistance(float distance);

// these names kinda suck, come up with better for per-primitive modes
void rdSetGeoMode(int a1);
void rdSetLightMode(int a1);
void rdSetTexMode(int a1);

// todo:
// rdDitherMode

void rdDrawLayer(uint8_t layer);

int rdBindTexture(rdTexture* pTexture);
int rdBindMaterial(rdMaterial* pMaterial, int cel);

void rdTexGen(rdTexGen_t texGen);
void rdTexGenParams(float p0, float p1, float p2, float p3);
void rdTexOffset(float u, float v);
void rdTexOffseti(float u, float v);

int rdAddLight(rdLight* pLight, rdVector3* pPosition);
void rdAddOccluder(rdVector3* position, float radius);
void rdAddDecal(rdDecal* decal, rdMatrix34* matrix, rdVector3* color, rdVector3* scale, float angleFade);

void rdClearLights();
void rdClearOccluders();
void rdClearDecals();

void rdSetAmbientMode(rdAmbientMode_t type);
void rdAmbientLight(float r, float g, float b);
void rdAmbientLightSH(rdAmbient* amb);

#endif

#endif // _RDROID_H
