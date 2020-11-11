#ifndef _SITHCAMERA_H
#define _SITHCAMERA_H

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
#define sithCamera_updateidk_ADDR (0x004C56B0)
#define sithCamera_SetRdCameraAndRenderidk_ADDR (0x004C5FD0)
#define sithCamera_SetPovShake_ADDR (0x004C6000)
#define sithCamera_create_unk_struct_ADDR (0x004C6050)
#define sithCamera_SetState_ADDR (0x004C6160)
#define sithCamera_GetState_ADDR (0x004C6170)

typedef struct sithCamera
{
    uint32_t cameraPerspective;
    uint32_t dword4;
    float float8;
    float floatC;
    sithThing* primaryFocus;
    sithThing* secondaryFocus;
    float* unk_struct;
    rdVector3 vec3_3;
    rdVector3 vec3_4;
    rdMatrix34 matrix_4_3_idk;
    rdVector3 vec3_1;
    rdVector3 vec3_2;
    rdCamera rdCam;
} sithCamera;

static void (*sithCamera_SetCameraFocus)(sithCamera *a1, sithThing *primary, sithThing *secondary) = (void*)sithCamera_SetCameraFocus_ADDR;
static sithThing* (*sithCamera_GetPrimaryFocus)(sithCamera *cam) = (void*)sithCamera_GetPrimaryFocus_ADDR;
static sithThing* (*sithCamera_GetSecondaryFocus)(sithCamera *cam) = (void*)sithCamera_GetSecondaryFocus_ADDR;
static void (*sithCamera_CycleCamera)(void) = (void*)sithCamera_CycleCamera_ADDR;
static void (*sithCamera_SetPovShake)(rdVector3 *a1, rdVector3 *a2, float a3, float a4) = (void*)sithCamera_SetPovShake_ADDR;
static int (*sithCamera_SetCurrentCamera)(sithCamera *a1) = (void*)sithCamera_SetCurrentCamera_ADDR;
static int (*sithCamera_GetState)(void) = (void*)sithCamera_GetState_ADDR;
static void (*sithCamera_SetState)(int) = (void*)sithCamera_SetState_ADDR;

#define sithCamera_cameras ((sithCamera*)0x8EC380)
#define sithCamera_dword_8EE5A0 (*(int*)0x8EE5A0)
#define sithCamera_state (*(int*)0x8EE5A4)
#define sithCamera_curCameraIdx (*(int*)0x8EE5A8)
#define sithCamera_povShakeVector1 (*(rdVector3*)0x008EE5AC)
#define sithCamera_povShakeVector2 (*(rdVector3*)0x008EE5B8)
#define sithCamera_povShakeF1 (*(float*)0x008EE5C4)
#define sithCamera_povShakeF2 (*(float*)0x008EE5C8)
#define sithCamera_currentCamera (*(sithCamera**)0x82F104)

#endif // _SITHCAMERA_H
