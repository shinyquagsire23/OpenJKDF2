#ifndef _RDROID_H
#define _RDROID_H

#include "jk.h"
#include "types.h"
#include "General/stdPalEffects.h"

#define rdStartup_ADDR (0x0043A950)
#define rdShutdown_ADDR (0x0043A990)
#define rdOpen_ADDR (0x0043A9B0)
#define rdClose_ADDR (0x0043AA40)
#define rdSetGeometryMode_ADDR (0x0043AA60)
#define rdSetLightingMode_ADDR (0x0043AA70)
#define rdSetTextureMode_ADDR (0x0043AA80)
#define rdSetSortingMethod_ADDR (0x0043AA90)
#define rdSetOcclusionMethod_ADDR (0x0043AAA0)
#define rdSetZBufferMethod_ADDR (0x0043AAB0)
#define rdSetCullFlags_ADDR (0x0043AAC0)
#define rdSetProcFaceUserdata_ADDR (0x0043AAD0)
#define rdSetVertexColorMode_ADDR (0x0043AAE0)
#define rdGetGeometryMode_ADDR (0x0043AAF0)
#define rdGetLightingMode_ADDR (0x0043AB00)
#define rdGetTextureMode_ADDR (0x0043AB10)
#define rdGetSortingMethod_ADDR (0x0043AB20)
#define rdGetOcclusionMethod_ADDR (0x0043AB30)
#define rdGetZBufferMethod_ADDR (0x0043AB40)
#define rdGetCullFlags_ADDR (0x0043AB50)
#define rdGetProcFaceUserdata_ADDR (0x0043AB60)
#define rdGetVertexColorMode_ADDR (0x0043AB70)
#define rdSetMipDistances_ADDR (0x0043AB80)
#define rdSetColorEffects_ADDR (0x0043ABB0)
#define rdAdvanceFrame_ADDR (0x0043ABD0)
#define rdFinishFrame_ADDR (0x0043ABF0)
#define rdClearPostStatistics_ADDR (0x0043AC10)

#define rdroid_aMipDistances (*(rdVector4*)0x548250)

#define rdroid_frameTrue (*(int*)0x570390)
#define bRDroidStartup (*(int*)0x570394)
#define bRDroidOpen (*(int*)0x570398)

#define rdroid_curTextureMode (*(int*)0x889EA0)
#define rdroid_pHS (*(struct common_functions**)0x889EA4)
#define rdroid_curLightingMode (*(int*)0x889EA8)

#define rdroid_curColorEffects  (*(stdPalEffect*)0x889EC0)
#define rdroid_curZBufferMethod (*(int*)0x00889EE8)
#define rdroid_curCullFlags (*(int*)0x00889EEC)
#define rdroid_curVertexColorMode (*(int*)0x00889EF0)
#define rdroid_curOcclusionMethod (*(int*)0x00889EF4)
#define rdroid_curAcceleration (*(int*)0x00889EF8)
#define rdroid_curSortingMethod (*(int*)0x00889EFC)
#define rdroid_curGeometryMode (*(int*)0x00889F00)
#define rdroid_curProcFaceUserData (*(int*)0x00889F04)

int rdStartup(struct common_functions *p_hs);
void rdShutdown();
int rdOpen(int a1);
void rdClose();

void rdSetGeometryMode(int a1);
void rdSetLightingMode(int a1);
void rdSetTextureMode(int a1);
void rdSetSortingMethod(int a1);
void rdSetOcclusionMethod(int a1);
void rdSetZBufferMethod(int a1);
void rdSetCullFlags(int a1);
void rdSetProcFaceUserdata(int a1);
void rdSetVertexColorMode(int a1);

int rdGetGeometryMode(void);
int rdGetLightingMode(void);
int rdGetTextureMode(void);
int rdGetSortingMethod(void);
int rdGetOcclusionMethod(void);
int rdGetZBufferMethod(void);
int rdGetCullFlags(void);
int rdGetProcFaceUserdata(void);
int rdGetVertexColorMode(void);

int rdSetMipDistances(rdVector4 *dists);
int rdSetColorEffects(stdPalEffect *effects);

void rdAdvanceFrame();
void rdFinishFrame();
void rdClearPostStatistics();

//#define  (*(int*)0x)

#endif // _RDROID_H
