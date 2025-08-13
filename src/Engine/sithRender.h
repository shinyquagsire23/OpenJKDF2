#ifndef _SITHRENDER_H
#define _SITHRENDER_H

#include "types.h"
#include "globals.h"

#define sithRender_Startup_ADDR (0x004C6180)
#define sithRender_Open_ADDR (0x004C61C0)
#define sithRender_Close_ADDR (0x004C6250)
#define sithRender_Shutdown_ADDR (0x004C6260)
#define sithRender_SetSomeRenderflag_ADDR (0x004C6270)
#define sithRender_GetSomeRenderFlag_ADDR (0x004C6280)
#define sithRender_EnableIRMode_ADDR (0x004C6290)
#define sithRender_DisableIRMode_ADDR (0x004C6320)
#define sithRender_SetGeoMode_ADDR (0x004C6330)
#define sithRender_SetLightMode_ADDR (0x004C6340)
#define sithRender_SetTexMode_ADDR (0x004C6350)
#define sithRender_SetPalette_ADDR (0x004C6360)
#define sithRender_Draw_ADDR (0x004C63B0)
#define sithRender_Clip_ADDR (0x004C6650)
#define sithRender_RenderLevelGeometry_ADDR (0x004C6C40)
#define sithRender_UpdateAllLights_ADDR (0x004C76B0)
#define sithRender_UpdateLights_ADDR (0x004C7720)
#define sithRender_RenderDynamicLights_ADDR (0x004C79A0)
#define sithRender_RenderThings_ADDR (0x004C7BE0)
#define sithRender_RenderThing_ADDR (0x004C8070)
#define sithRender_RenderAlphaSurfaces_ADDR (0x004C8220)
#define sithRender_SetRenderWeaponHandle_ADDR (0x004C8600)

int sithRender_Startup();
int sithRender_Open();
void sithRender_Close();
void sithRender_Shutdown();
void sithRender_SetSomeRenderflag(int flag);
int sithRender_GetSomeRenderFlag();
void sithRender_EnableIRMode(flex_t a, flex_t b);
void sithRender_DisableIRMode();
void sithRender_SetGeoMode(rdGeoMode_t val);
void sithRender_SetLightMode(rdLightMode_t a1);
void sithRender_SetTexMode(rdTexMode_t a1);
void sithRender_SetPalette(const void *palette);
MATH_FUNC void sithRender_Draw();
MATH_FUNC void sithRender_Clip(sithSector *sector, rdClipFrustum *frustumArg, flex_t a3, int depth); // Added: depth safety
MATH_FUNC void sithRender_NoClip(sithSector *sector, rdClipFrustum *frustumArg, flex_t a3, int depth);
MATH_FUNC void sithRender_KindaClipAssignFrustum(sithSector *sector, rdClipFrustum *frustumArg, int depth, int parentSector);
MATH_FUNC void sithRender_KindaClip(sithSector *sector, rdClipFrustum *frustumArg, flex_t prevAdjoinDistAdd, int depth);
MATH_FUNC void sithRender_RenderLevelGeometry();
MATH_FUNC void sithRender_UpdateAllLights();
MATH_FUNC void sithRender_UpdateLights(sithSector *sector, flex_t prev, flex_t dist, int depth);
MATH_FUNC void sithRender_RenderDynamicLights();
MATH_FUNC void sithRender_RenderThings();
MATH_FUNC int sithRender_RenderThing(sithThing *povThing);
MATH_FUNC void sithRender_RenderAlphaSurfaces();
int sithRender_SetRenderWeaponHandle(sithRender_weapRendFunc_t a1);
void sithRender_WorldFlash(flex_t arg1,flex_t arg2);

// Added
void sithRender_RenderDebugLight(flex_t intensity, rdVector3* pos);

#define SITHREND_NUM_LIGHTS (32)

//static void (*sithRender_Clip_)(sithSector *sector, rdClipFrustum *frustumArg, flex_t a3) = (void*)sithRender_Clip_ADDR;
//static void (*sithRender_UpdateLights_)(sithSector *sector, flex_t a2, flex_t dist) = (void*)sithRender_UpdateLights_ADDR;
//static void (*sithRender_RenderDynamicLights_)() = (void*)sithRender_RenderDynamicLights_ADDR;
//static void (*sithRender_RenderLevelGeometry_)() = (void*)sithRender_RenderLevelGeometry_ADDR;
//static void (*sithRender_RenderThings)() = (void*)sithRender_RenderThings_ADDR;
//static void (*sithRender_RenderAlphaSurfaces_)() = (void*)sithRender_RenderAlphaSurfaces_ADDR;
//static int (*sithRender_RenderThing)(sithThing *a2) = (void*)sithRender_RenderThing_ADDR;

#endif // _SITHRENDER_H
