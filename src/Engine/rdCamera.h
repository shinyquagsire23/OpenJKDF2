#ifndef _RDCAMERA_H
#define _RDCAMERA_H

#include "types.h"
#include "Engine/rdCanvas.h"
#include "globals.h"

#ifdef __cplusplus
extern "C" {
#endif

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
#define rdCamera_OrthoProject_ADDR (0x00443940)
#define rdCamera_OrthoProjectLst_ADDR (0x00443980)
#define rdCamera_OrthoProjectSquare_ADDR (0x00443A00)
#define rdCamera_OrthoProjectSquareLst_ADDR (0x00443A40)
#define rdCamera_PerspProject_ADDR (0x00443AB0)
#define rdCamera_PerspProjectLst_ADDR (0x00443B00)
#define rdCamera_PerspProjectSquare_ADDR (0x00443B80)
#define rdCamera_PerspProjectSquareLst_ADDR (0x00443BC0)
#define rdCamera_SetAmbientLight_ADDR (0x00443C30)
#define rdCamera_SetAttenuation_ADDR (0x00443C40)
#define rdCamera_AddLight_ADDR (0x00443C80)
#define rdCamera_ClearLights_ADDR (0x00443CF0)
#define rdCamera_AdvanceFrame_ADDR (0x00443D10)

rdCamera* rdCamera_New(flex_t fov, flex_t x, flex_t y, flex_t z, flex_t aspectRatio);
int rdCamera_NewEntry(rdCamera *camera, flex_t fov, flex_t a3, flex_t zNear, flex_t zFar, flex_t aspectRatio);
void rdCamera_Free(rdCamera *camera);
void rdCamera_FreeEntry(rdCamera *camera);
int rdCamera_SetCanvas(rdCamera *camera, rdCanvas *canvas);
int rdCamera_SetCurrent(rdCamera *camera);
int rdCamera_SetFOV(rdCamera *camera, flex_t fovVal);
int rdCamera_SetProjectType(rdCamera *camera, int type);
int rdCamera_SetOrthoScale(rdCamera *camera, flex_t scale);
int rdCamera_SetAspectRatio(rdCamera *camera, flex_t ratio);
int rdCamera_BuildFOV(rdCamera *camera);
int rdCamera_BuildClipFrustum(rdCamera *camera, rdClipFrustum *outClip, signed int height, signed int width, signed int height2, signed int width2);
void rdCamera_Update(rdMatrix34 *orthoProj);
void rdCamera_OrthoProject(rdVector3* out, rdVector3* v);
void rdCamera_OrthoProjectLst(rdVector3 *vertices_out, rdVector3 *vertices_in, unsigned int num_vertices);
void rdCamera_OrthoProjectSquare(rdVector3 *out, rdVector3 *v);
void rdCamera_OrthoProjectSquareLst(rdVector3 *vertices_out, rdVector3 *vertices_in, unsigned int num_vertices);
void rdCamera_PerspProject(rdVector3 *out, rdVector3 *v);
void rdCamera_PerspProjectLst(rdVector3 *vertices_out, rdVector3 *vertices_in, unsigned int num_vertices);
void rdCamera_PerspProjectSquare(rdVector3 *out, rdVector3 *v);
void rdCamera_PerspProjectSquareLst(rdVector3 *vertices_out, rdVector3 *vertices_in, unsigned int num_vertices);
void rdCamera_SetAmbientLight(rdCamera *camera, flex_t amt);
void rdCamera_SetAttenuation(rdCamera *camera, flex_t minVal, flex_t maxVal);
int rdCamera_AddLight(rdCamera *camera, rdLight *light, rdVector3 *lightPos);
int rdCamera_ClearLights(rdCamera *camera);
void rdCamera_AdvanceFrame();
flex_t rdCamera_GetMipmapScalar(); // MOTS added
void rdCamera_SetMipmapScalar(flex_t val); // MOTS added

#ifdef __cplusplus
}
#endif

#endif // _RDCAMERA_H
