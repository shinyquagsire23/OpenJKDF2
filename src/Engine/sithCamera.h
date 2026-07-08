#ifndef _SITHCAMERA_H
#define _SITHCAMERA_H

#include "types.h"
#include "globals.h"
#include "Engine/rdCamera.h"

#ifdef __cplusplus
extern "C" {
#endif

#define sithCamera_Startup_ADDR (0x004C4DE0)
#define sithCamera_Shutdown_ADDR (0x004C4EF0)
#define sithCamera_Open_ADDR (0x004C4F20)
#define sithCamera_Close_ADDR (0x004C5130)
#define sithCamera_ResetAllCameras_ADDR (0x004C5150)
#define sithCamera_New_ADDR (0x004C5260)
#define sithCamera_NewEntry_ADDR (0x004C52B0)
#define sithCamera_FreeEntry_ADDR (0x004C5370)
#define sithCamera_Free_ADDR (0x004C53A0)
#define sithCamera_SetCanvas_ADDR (0x004C53C0)
#define sithCamera_SetCurrentCamera_ADDR (0x004C5420)
#define sithCamera_CycleCamera_ADDR (0x004C54D0)
#define sithCamera_SetCurrentToCycleCamera_ADDR (0x004C5590)
#define sithCamera_IdkChecksDword4_ADDR (0x004C5640)
#define sithCamera_SetCameraFocus_ADDR (0x004C5670)
#define sithCamera_GetPrimaryFocus_ADDR (0x004C5690)
#define sithCamera_GetSecondaryFocus_ADDR (0x004C56A0)
#define sithCamera_Update_ADDR (0x004C56B0)
#define sithCamera_RenderScene_ADDR (0x004C5FD0)
#define sithCamera_SetPOVShake_ADDR (0x004C6000)
#define sithCamera_SearchSectorInRadius_ADDR (0x004C6050)
#define sithCamera_SetCameraStateFlags_ADDR (0x004C6160)
#define sithCamera_GetCameraStateFlags_ADDR (0x004C6170)

int sithCamera_Startup();
void sithCamera_Shutdown();
int sithCamera_Open(rdCanvas *pCanvas, flex_t aspect);
void sithCamera_Close();
void sithCamera_ResetAllCameras();
int sithCamera_NewEntry(SithCamera *camera, uint32_t a2, uint32_t a3, flex_t fov, flex_t aspectRatio, rdCanvas *pCanvas, SithThing *focus_far, SithThing *focus_near);

MATH_FUNC void sithCamera_Update(SithCamera *cam);
void sithCamera_RenderScene();
void sithCamera_SetCurrentToCycleCamera();
int sithCamera_SetCurrentCamera(SithCamera *camera);
void sithCamera_SetCameraFocus(SithCamera *camera, SithThing *primary, SithThing *secondary);
SithSector* sithCamera_SearchSectorInRadius(SithThing* a3, SithSector* a2, rdVector3* a4, rdVector3* a6, flex_t a7, int flags);
void sithCamera_SetPOVShake(rdVector3 *a1, rdVector3 *a2, flex_t a3, flex_t a4);
SithThing* sithCamera_GetPrimaryFocus(SithCamera *pCamera);
SithThing* sithCamera_GetSecondaryFocus(SithCamera *pCamera);
int sithCamera_SetCameraStateFlags(int a1);
int sithCamera_GetCameraStateFlags();
void sithCamera_CycleCamera();
MATH_FUNC void sithCamera_SetZoom(SithCamera *pCamera, flex_t zoomScale, flex_t zoom_2); // MOTS added
MATH_FUNC void sithCamera_UpdateZoom(SithCamera *pCamera);

#ifndef __cplusplus
//static void (*sithCamera_Shutdown)() = (void*)sithCamera_Shutdown_ADDR;
static int (*sithCamera_NewEntry_)(SithCamera *camera, int a2, int a3, flex_t fov, flex_t a5, rdCanvas* a6, SithThing *focus_far, SithThing *focus_near) = (void*)sithCamera_NewEntry_ADDR;
//static void (*sithCamera_SetCameraFocus)(SithCamera *a1, SithThing *primary, SithThing *secondary) = (void*)sithCamera_SetCameraFocus_ADDR;
//static SithThing* (*sithCamera_GetPrimaryFocus)(SithCamera *cam) = (void*)sithCamera_GetPrimaryFocus_ADDR;
//static SithThing* (*sithCamera_GetSecondaryFocus)(SithCamera *cam) = (void*)sithCamera_GetSecondaryFocus_ADDR;
//static void (*sithCamera_CycleCamera)(void) = (void*)sithCamera_CycleCamera_ADDR;
//static void (*sithCamera_SetPOVShake)(rdVector3 *a1, rdVector3 *a2, flex_t a3, flex_t a4) = (void*)sithCamera_SetPOVShake_ADDR;
//static int (*sithCamera_SetCurrentCamera)(SithCamera *a1) = (void*)sithCamera_SetCurrentCamera_ADDR;
//static int (*sithCamera_GetCameraStateFlags)(void) = (void*)sithCamera_GetCameraStateFlags_ADDR;
//static void (*sithCamera_SetCameraStateFlags)(int) = (void*)sithCamera_SetCameraStateFlags_ADDR;
//static void (*sithCamera_Close)() = (void*)sithCamera_Close_ADDR;
//static void (*sithCamera_Update)(SithCamera *cam) = (void*)sithCamera_Update_ADDR;
//static void (*sithCamera_RenderScene)() = (void*)sithCamera_RenderScene_ADDR;
//static SithSector* (*sithCamera_SearchSectorInRadius)(SithThing *a3, SithSector *a2, rdVector3 *a4, rdVector3 *a6, flex_t a7, int arg14) = (void*)sithCamera_SearchSectorInRadius_ADDR;
//static void (*sithCamera_ResetAllCameras)() = (void*)sithCamera_ResetAllCameras_ADDR;
#endif

#ifdef __cplusplus
}
#endif

#endif // _SITHCAMERA_H
