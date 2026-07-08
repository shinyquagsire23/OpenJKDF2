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
int sithCamera_Open(rdCanvas *canvas, flex_t aspect);
void sithCamera_Close();
void sithCamera_ResetAllCameras();
int sithCamera_NewEntry(sithCamera *camera, uint32_t a2, uint32_t a3, flex_t fov, flex_t aspectRatio, rdCanvas *canvas, sithThing *focus_far, sithThing *focus_near);

MATH_FUNC void sithCamera_Update(sithCamera *cam);
void sithCamera_RenderScene();
void sithCamera_SetCurrentToCycleCamera();
int sithCamera_SetCurrentCamera(sithCamera *camera);
void sithCamera_SetCameraFocus(sithCamera *camera, sithThing *primary, sithThing *secondary);
sithSector* sithCamera_SearchSectorInRadius(sithThing* a3, sithSector* a2, rdVector3* a4, rdVector3* a6, flex_t a7, int flags);
void sithCamera_SetPOVShake(rdVector3 *a1, rdVector3 *a2, flex_t a3, flex_t a4);
sithThing* sithCamera_GetPrimaryFocus(sithCamera *pCamera);
sithThing* sithCamera_GetSecondaryFocus(sithCamera *pCamera);
int sithCamera_SetCameraStateFlags(int a1);
int sithCamera_GetCameraStateFlags();
void sithCamera_CycleCamera();
MATH_FUNC void sithCamera_SetZoom(sithCamera *pCamera, flex_t zoomScale, flex_t zoom_2); // MOTS added
MATH_FUNC void sithCamera_UpdateZoom(sithCamera *pCamera);

#ifndef __cplusplus
//static void (*sithCamera_Shutdown)() = (void*)sithCamera_Shutdown_ADDR;
static int (*sithCamera_NewEntry_)(sithCamera *camera, int a2, int a3, flex_t fov, flex_t a5, rdCanvas* a6, sithThing *focus_far, sithThing *focus_near) = (void*)sithCamera_NewEntry_ADDR;
//static void (*sithCamera_SetCameraFocus)(sithCamera *a1, sithThing *primary, sithThing *secondary) = (void*)sithCamera_SetCameraFocus_ADDR;
//static sithThing* (*sithCamera_GetPrimaryFocus)(sithCamera *cam) = (void*)sithCamera_GetPrimaryFocus_ADDR;
//static sithThing* (*sithCamera_GetSecondaryFocus)(sithCamera *cam) = (void*)sithCamera_GetSecondaryFocus_ADDR;
//static void (*sithCamera_CycleCamera)(void) = (void*)sithCamera_CycleCamera_ADDR;
//static void (*sithCamera_SetPOVShake)(rdVector3 *a1, rdVector3 *a2, flex_t a3, flex_t a4) = (void*)sithCamera_SetPOVShake_ADDR;
//static int (*sithCamera_SetCurrentCamera)(sithCamera *a1) = (void*)sithCamera_SetCurrentCamera_ADDR;
//static int (*sithCamera_GetCameraStateFlags)(void) = (void*)sithCamera_GetCameraStateFlags_ADDR;
//static void (*sithCamera_SetCameraStateFlags)(int) = (void*)sithCamera_SetCameraStateFlags_ADDR;
//static void (*sithCamera_Close)() = (void*)sithCamera_Close_ADDR;
//static void (*sithCamera_Update)(sithCamera *cam) = (void*)sithCamera_Update_ADDR;
//static void (*sithCamera_RenderScene)() = (void*)sithCamera_RenderScene_ADDR;
//static sithSector* (*sithCamera_SearchSectorInRadius)(sithThing *a3, sithSector *a2, rdVector3 *a4, rdVector3 *a6, flex_t a7, int arg14) = (void*)sithCamera_SearchSectorInRadius_ADDR;
//static void (*sithCamera_ResetAllCameras)() = (void*)sithCamera_ResetAllCameras_ADDR;
#endif

#ifdef __cplusplus
}
#endif

#endif // _SITHCAMERA_H
