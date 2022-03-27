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
void sithRender_EnableIRMode(float a, float b);
void sithRender_DisableIRMode();
void sithRender_SetGeoMode(int val);
void sithRender_SetLightMode(int a1);
void sithRender_SetTexMode(int a1);
void sithRender_SetPalette(const void *palette);
void sithRender_Draw();
void sithRender_Clip(sithSector *sector, rdClipFrustum *frustumArg, float a3);
void sithRender_RenderLevelGeometry();
void sithRender_UpdateAllLights();
void sithRender_UpdateLights(sithSector *sector, float prev, float dist);
void sithRender_RenderDynamicLights();
void sithRender_RenderThings();
int sithRender_RenderThing(sithThing *povThing);
void sithRender_RenderAlphaSurfaces();
int sithRender_SetRenderWeaponHandle(void *a1);

// Added
void sithRender_RenderDebugLight(float intensity, rdVector3* pos);

#define SITHREND_NUM_LIGHTS (32)

static void (*sithRender_Clip_)(sithSector *sector, rdClipFrustum *frustumArg, float a3) = (void*)sithRender_Clip_ADDR;
static void (*sithRender_UpdateLights_)(sithSector *sector, float a2, float dist) = (void*)sithRender_UpdateLights_ADDR;
static void (*sithRender_RenderDynamicLights_)() = (void*)sithRender_RenderDynamicLights_ADDR;
static void (*sithRender_RenderLevelGeometry_)() = (void*)sithRender_RenderLevelGeometry_ADDR;
//static void (*sithRender_RenderThings)() = (void*)sithRender_RenderThings_ADDR;
static void (*sithRender_RenderAlphaSurfaces_)() = (void*)sithRender_RenderAlphaSurfaces_ADDR;
//static int (*sithRender_RenderThing)(sithThing *a2) = (void*)sithRender_RenderThing_ADDR;

#endif // _SITHRENDER_H
