#ifndef _RDCAMERA_H
#define _RDCAMERA_H

#include "Primitives/rdVector.h"
#include "Primitives/rdMatrix.h"
#include "Engine/rdCanvas.h"

#define rdCamera_New_ADDR (0x00443260)
#define rdCamera_NewEntry_ADDR (0x00443360)
#define rdCamera_Free_ADDR (0x00443440)
#define rdCamera_FreeEntry_ADDR (0x00443470)
#define rdCamera_SetCanvas_ADDR (0x00443490)
#define rdCamera_SetCurrent_ADDR (0x004434B0)
#define rdCamera_SetFOV_ADDR (0x004434D0)
#define rdCamera_SetProjectType_ADDR (0x00443520)
#define rdCamera_SetOrthoScale_ADDR (0x004435A0)
#define rdCamera_SetAspectRatio_ADDR (0x004435C0)
#define rdCamera_BuildFOV_ADDR (0x00443670)
#define rdCamera_BuildClipFrustum_ADDR (0x00443830)
#define rdCamera_Update_ADDR (0x00443900)
#define rdCamera_PerspProject_ADDR (0x00443940)
#define rdCamera_PerspProjectLst_ADDR (0x00443980)
#define rdCamera_PerspProjectSquare_ADDR (0x00443A00)
#define rdCamera_PerspProjectSquareLst_ADDR (0x00443A40)
#define rdCamera_OrthoProject_ADDR (0x00443AB0)
#define rdCamera_OrthoProjectLst_ADDR (0x00443B00)
#define rdCamera_OrthoProjectSquare_ADDR (0x00443B80)
#define rdCamera_OrthoProjectSquareLst_ADDR (0x00443BC0)
#define rdCamera_SetAmbientLight_ADDR (0x00443C30)
#define rdCamera_SetAttenuation_ADDR (0x00443C40)
#define rdCamera_AddLight_ADDR (0x00443C80)
#define rdCamera_ClearLights_ADDR (0x00443CF0)
#define rdCamera_AdvanceFrame_ADDR (0x00443D10)

#define rdCameraProjectType_Perspective (0)
#define rdCameraProjectType_Ortho       (1)

typedef struct rdCanvas rdCanvas;
typedef struct rdLight rdLight;

typedef struct rdClipFrustum
{
  rdVector3 field_0;
  float field_C;
  float field_10;
  float field_14;
  float field_18;
  float field_1C;
  float field_20;
  float field_24;
  float field_28;
  float field_2C;
  float field_30;
} rdClipFrustum;

typedef struct rdCamera
{
    int projectType;
    rdCanvas* canvas;
    rdMatrix34 view_matrix;
    float fov;
    float fov_y;
    float screenAspectRatio;
    float orthoScale;
    rdClipFrustum *cameraClipFrustum;
    void (__cdecl *project)(rdVector3 *, rdVector3 *);
    void (__cdecl *projectLst)(rdVector3 *, rdVector3 *, unsigned int);
    float ambientLight;
    int numLights;
    rdLight* lights[64];
    rdVector3 lightPositions[64];
    float attenuationMin;
    float attenuationMax;
} rdCamera;

rdCamera* rdCamera_New(float fov, float x, float y, float z, float aspectRatio);
int rdCamera_NewEntry(rdCamera *camera, float fov, float a3, float a4, float a5, float aspectRatio);
void rdCamera_Free(rdCamera *camera);
void rdCamera_FreeEntry(rdCamera *camera);
int rdCamera_SetCanvas(rdCamera *camera, rdCanvas *canvas);
int rdCamera_SetCurrent(rdCamera *camera);
int rdCamera_SetFOV(rdCamera *camera, float fovVal);
int rdCamera_SetProjectType(rdCamera *camera, int type);
int rdCamera_SetOrthoScale(rdCamera *camera, float scale);
int rdCamera_SetAspectRatio(rdCamera *camera, float ratio);
int rdCamera_BuildFOV(rdCamera *camera);
int rdCamera_BuildClipFrustum(rdCamera *camera, rdClipFrustum *outClip, signed int height, signed int width, signed int height2, signed int width2);
void rdCamera_Update(rdMatrix34 *orthoProj);

void rdCamera_SetAmbientLight(rdCamera *camera, float amt);
void rdCamera_SetAttenuation(rdCamera *camera, float minVal, float maxVal);
int rdCamera_AddLight(rdCamera *camera, rdLight *light, rdVector3 *lightPos);
int rdCamera_ClearLights(rdCamera *camera);

//static int (*rdCamera_NewEntry)(rdCamera *camera, float fov, float a3, float a4, float a5, float a6) = (void*)rdCamera_NewEntry_ADDR;
//static void (*rdCamera_SetAttenuation)(rdCamera *a1, float a2, float a3) = (void*)rdCamera_SetAttenuation_ADDR;
//static int (*rdCamera_BuildFOV)(rdCamera *camera) = (void*)rdCamera_BuildFOV_ADDR;
//static int (*rdCamera_SetCanvas)(rdCamera *camera, rdCanvas *canvas) = (void*)rdCamera_SetCanvas_ADDR;
//static void (*rdCamera_SetAmbientLight)(rdCamera *camera, float amt) = (void*)rdCamera_SetAmbientLight_ADDR;
static void (*rdCamera_AdvanceFrame)(void) = (void*)rdCamera_AdvanceFrame_ADDR;

static void (*rdCamera_PerspProjectSquare)(rdVector3 *a1, rdVector3 *a2) = (void*)rdCamera_PerspProjectSquare_ADDR;
static void (*rdCamera_PerspProjectSquareLst)(rdVector3 *a1, rdVector3 *a2) = (void*)rdCamera_PerspProjectSquareLst_ADDR;
static void (*rdCamera_PerspProject)(rdVector3 *a1, rdVector3 *a2) = (void*)rdCamera_PerspProject_ADDR;
static void (*rdCamera_PerspProjectLst)(rdVector3 *a1, rdVector3 *a2) = (void*)rdCamera_PerspProjectLst_ADDR;

static void (*rdCamera_OrthoProjectSquare)(rdVector3 *a1, rdVector3 *a2) = (void*)rdCamera_OrthoProjectSquare_ADDR;
static void (*rdCamera_OrthoProjectSquareLst)(rdVector3 *a1, rdVector3 *a2) = (void*)rdCamera_OrthoProjectSquareLst_ADDR;
static void (*rdCamera_OrthoProject)(rdVector3 *a1, rdVector3 *a2) = (void*)rdCamera_OrthoProject_ADDR;
static void (*rdCamera_OrthoProjectLst)(rdVector3 *a1, rdVector3 *a2) = (void*)rdCamera_OrthoProjectLst_ADDR;

#define rdCamera_pCurCamera (*(rdCamera**)0x73A3D0)
#define rdCamera_camRotation (*(rdVector3*)0x86EE20)
#define rdCamera_camMatrix  (*(rdMatrix34*)0x86EE40)

#endif // _RDCAMERA_H
