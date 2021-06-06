#ifndef _SITHCAMERA_H
#define _SITHCAMERA_H

#include "Primitives/rdVector.h"
#include "Primitives/rdMatrix.h"
#include "Engine/rdCamera.h"

#define sithCamera_Startup_ADDR (0x004C4DE0)
#define sithCamera_Shutdown_ADDR (0x004C4EF0)
#define sithCamera_Open_ADDR (0x004C4F20)
#define sithCamera_Close_ADDR (0x004C5130)
#define sithCamera_SetsFocus_ADDR (0x004C5150)
#define sithCamera_New_ADDR (0x004C5260)
#define sithCamera_NewEntry_ADDR (0x004C52B0)
#define sithCamera_FreeEntry_ADDR (0x004C5370)
#define sithCamera_Free_ADDR (0x004C53A0)
#define sithCamera_SetCanvas_ADDR (0x004C53C0)
#define sithCamera_SetCurrentCamera_ADDR (0x004C5420)
#define sithCamera_CycleCamera_ADDR (0x004C54D0)
#define sithCamera_idkdebug_ADDR (0x004C5590)
#define sithCamera_IdkChecksDword4_ADDR (0x004C5640)
#define sithCamera_SetCameraFocus_ADDR (0x004C5670)
#define sithCamera_GetPrimaryFocus_ADDR (0x004C5690)
#define sithCamera_GetSecondaryFocus_ADDR (0x004C56A0)
#define sithCamera_FollowFocus_ADDR (0x004C56B0)
#define sithCamera_SetRdCameraAndRenderidk_ADDR (0x004C5FD0)
#define sithCamera_SetPovShake_ADDR (0x004C6000)
#define sithCamera_create_unk_struct_ADDR (0x004C6050)
#define sithCamera_SetState_ADDR (0x004C6160)
#define sithCamera_GetState_ADDR (0x004C6170)

typedef struct rdColormap rdColormap;
typedef struct sithThing sithThing;
typedef struct sithSector sithSector;

typedef struct sithCameraRenderInfo
{
    uint32_t field_0;
    float field_4;
    float field_8;
    rdColormap* colormap;
} sithCameraRenderInfo;

#pragma pack(push, 4)
typedef struct sithCamera
{
    uint32_t cameraPerspective;
    uint32_t dword4;
    float fov;
    float aspectRatio;
    sithThing* primaryFocus;
    sithThing* secondaryFocus;
    sithSector* sector;
    rdVector3 vec3_3;
    rdVector3 vec3_4;
    rdMatrix34 viewMat;
    rdVector3 vec3_1;
    rdVector3 vec3_2;
    rdCamera rdCam;
} sithCamera;
#pragma pack(pop)

int sithCamera_Startup();
int sithCamera_Open(rdCanvas *canvas, float aspect);
void sithCamera_SetsFocus();
int sithCamera_NewEntry(sithCamera *camera, uint32_t a2, uint32_t a3, float fov, float aspectRatio, rdCanvas *canvas, sithThing *focus_far, sithThing *focus_near);

void sithCamera_FollowFocus(sithCamera *cam);
void sithCamera_SetRdCameraAndRenderidk();

static int (*sithCamera_NewEntry_)(sithCamera *camera, int a2, int a3, float fov, float a5, rdCanvas* a6, sithThing *focus_far, sithThing *focus_near) = (void*)sithCamera_NewEntry_ADDR;
static void (*sithCamera_SetCameraFocus)(sithCamera *a1, sithThing *primary, sithThing *secondary) = (void*)sithCamera_SetCameraFocus_ADDR;
static sithThing* (*sithCamera_GetPrimaryFocus)(sithCamera *cam) = (void*)sithCamera_GetPrimaryFocus_ADDR;
static sithThing* (*sithCamera_GetSecondaryFocus)(sithCamera *cam) = (void*)sithCamera_GetSecondaryFocus_ADDR;
static void (*sithCamera_CycleCamera)(void) = (void*)sithCamera_CycleCamera_ADDR;
static void (*sithCamera_SetPovShake)(rdVector3 *a1, rdVector3 *a2, float a3, float a4) = (void*)sithCamera_SetPovShake_ADDR;
static int (*sithCamera_SetCurrentCamera)(sithCamera *a1) = (void*)sithCamera_SetCurrentCamera_ADDR;
static int (*sithCamera_GetState)(void) = (void*)sithCamera_GetState_ADDR;
static void (*sithCamera_SetState)(int) = (void*)sithCamera_SetState_ADDR;
//static void (*sithCamera_FollowFocus)(sithCamera *cam) = (void*)sithCamera_FollowFocus_ADDR;
//static void (*sithCamera_SetRdCameraAndRenderidk)() = (void*)sithCamera_SetRdCameraAndRenderidk_ADDR;
static sithSector* (*sithCamera_create_unk_struct)(sithThing *a3, sithSector *a2, rdVector3 *a4, rdVector3 *a6, float a7, int arg14) = (void*)sithCamera_create_unk_struct_ADDR;
//static void (*sithCamera_SetsFocus)() = (void*)sithCamera_SetsFocus_ADDR;

#define sithCamera_cameras ((sithCamera*)0x8EC380)
#define sithCamera_dword_8EE5A0 (*(int*)0x8EE5A0)
#define sithCamera_state (*(int*)0x8EE5A4)
#define sithCamera_curCameraIdx (*(int*)0x8EE5A8)
#define sithCamera_povShakeVector1 (*(rdVector3*)0x008EE5AC)
#define sithCamera_povShakeVector2 (*(rdVector3*)0x008EE5B8)
#define sithCamera_povShakeF1 (*(float*)0x008EE5C4)
#define sithCamera_povShakeF2 (*(float*)0x008EE5C8)
#define sithCamera_currentCamera (*(sithCamera**)0x82F104)
#define sithCamera_bInitted (*(int*)0x0082F108)
#define sithCamera_viewMat (*(rdMatrix34*)0x8EE5E0)
#define sithCamera_focusMat (*(rdMatrix34*)0x0082F0B8)
#define sithCamera_bOpen (*(int*)0x0082F10C)

#endif // _SITHCAMERA_H
