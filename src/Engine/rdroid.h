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
void rdSetZBufferMethod(int a1);
void rdSetCullFlags(int a1);
void rdSetProcFaceUserData(int a1);
void rdSetVertexColorMode(int a1);

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

#endif // _RDROID_H
