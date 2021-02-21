#include "rdCamera.h"

#include "Engine/rdLight.h"
#include "jk.h"
#include "Engine/rdroid.h"
#include "General/stdMath.h"
#include "Win95/stdDisplay.h"
#include "Win95/std3D.h"

static rdVector3 rdCamera_camRotation;

rdCamera* rdCamera_New(float fov, float x, float y, float z, float aspectRatio)
{
    rdCamera* out = (rdCamera *)rdroid_pHS->alloc(sizeof(rdCamera));
    if ( !out )
        return 0;
    
    rdCamera_NewEntry(out, fov, x, y, z, aspectRatio);    
    
    return out;
}

int rdCamera_NewEntry(rdCamera *camera, float fov, float a3, float a4, float a5, float aspectRatio)
{
    if (!camera)
        return 0;

    camera->cameraClipFrustum = (rdClipFrustum *)rdroid_pHS->alloc(sizeof(rdClipFrustum));
    if ( camera->cameraClipFrustum )
    {
        camera->canvas = 0;
        rdCamera_SetFOV(camera, fov);
        rdCamera_SetOrthoScale(camera, 1.0);

        camera->cameraClipFrustum->field_0.x = a3;
        camera->cameraClipFrustum->field_0.y = a4;
        camera->cameraClipFrustum->field_0.z = a5;
        camera->screenAspectRatio = aspectRatio;
        camera->ambientLight = 0.0;
        camera->numLights = 0;
        camera->attenuationMin = 0.2;
        camera->attenuationMax = 0.1;
        
        rdCamera_SetProjectType(camera, rdCameraProjectType_Ortho);

        return 1;
    }
    return 0;
}

void rdCamera_Free(rdCamera *camera)
{
    if (camera)
    {
        rdCamera_FreeEntry(camera);
        rdroid_pHS->free(camera);
    }
}

void rdCamera_FreeEntry(rdCamera *camera)
{
    if ( camera->cameraClipFrustum )
        rdroid_pHS->free(camera->cameraClipFrustum);
}

int rdCamera_SetCanvas(rdCamera *camera, rdCanvas *canvas)
{
    camera->canvas = canvas;
    rdCamera_BuildFOV(camera);
    return 1;
}

int rdCamera_SetCurrent(rdCamera *camera)
{
    if ( rdCamera_pCurCamera != camera )
        rdCamera_pCurCamera = camera;
    return 1;
}

int rdCamera_SetFOV(rdCamera *camera, float fovVal)
{
    if ( fovVal < 5.0 )
    {
        fovVal = 5.0;
    }
    else if ( fovVal > 179.0 )
    {
        fovVal = 179.0;
    }

    camera->fov = fovVal;
    rdCamera_BuildFOV(camera);
    return 1;
}

int rdCamera_SetProjectType(rdCamera *camera, int type)
{
    camera->projectType = type;
    
    switch (type)
    {
        case rdCameraProjectType_Perspective:
        {
            if (camera->screenAspectRatio == 1.0 )
            {
                camera->project = rdCamera_PerspProjectSquare;
                camera->projectLst = rdCamera_PerspProjectSquareLst;
            }
            else
            {
                camera->project = rdCamera_PerspProject;
                camera->projectLst = rdCamera_PerspProjectLst;
            }
            break;
        }
        case rdCameraProjectType_Ortho:
        {
            if (camera->screenAspectRatio == 1.0)
            {
                camera->project = rdCamera_OrthoProjectSquare;
                camera->projectLst = rdCamera_OrthoProjectSquareLst;
            }
            else
            {
                camera->project = rdCamera_OrthoProject;
                camera->projectLst = rdCamera_OrthoProjectLst;
            }
            break;
        }
        
    }

    if ( camera->canvas )
        rdCamera_BuildFOV(camera);

    return 1;
}

int rdCamera_SetOrthoScale(rdCamera *camera, float scale)
{
    camera->orthoScale = scale;
    rdCamera_BuildFOV(camera);
    return 1;
}

int rdCamera_SetAspectRatio(rdCamera *camera, float ratio)
{
    camera->screenAspectRatio = ratio;
    rdCamera_SetProjectType(camera, camera->projectType);
}

int rdCamera_BuildFOV(rdCamera *camera)
{
    double v5; // st6
    double v6; // st5
    double v7; // st7
    double v8; // rtt
    double v9; // st5
    double v10; // st3
    double v14; // st7
    double v15; // st4
    double v16; // st5
    float v17; // [esp+0h] [ebp-18h]
    float v18; // [esp+10h] [ebp-8h]
    float v20; // [esp+14h] [ebp-4h]
    float cameraa; // [esp+1Ch] [ebp+4h]
    float camerab; // [esp+1Ch] [ebp+4h]
    float camerac; // [esp+1Ch] [ebp+4h]
    float camerad; // [esp+1Ch] [ebp+4h]

    rdClipFrustum* clipFrustum = camera->cameraClipFrustum;
    rdCanvas* canvas = camera->canvas;
    if ( !canvas )
        return 0;

    switch (camera->projectType)
    {
        case rdCameraProjectType_Perspective:
        {
            camera->fov_y = 0.0;
            camerac = ((double)(canvas->heightMinusOne - canvas->yStart) * 0.5) / camera->orthoScale;
            v14 = -camerac / camera->screenAspectRatio;
            v15 = ((double)(canvas->widthMinusOne - canvas->xStart) * 0.5) / camera->orthoScale;
            v16 = camerac / camera->screenAspectRatio;
            camerad = v15;
            clipFrustum->field_C = -v15;
            clipFrustum->field_10 = v16;
            clipFrustum->field_14 = camerad;
            clipFrustum->field_18 = v14;
            clipFrustum->field_1C = 0.0;
            clipFrustum->field_20 = 0.0;
            clipFrustum->field_24 = 0.0;
            clipFrustum->field_28 = 0.0;
            return 1;
        }
        
        case rdCameraProjectType_Ortho:
        {
            v18 = (double)(canvas->widthMinusOne - canvas->xStart) * 0.5;
            cameraa = (double)(canvas->heightMinusOne - canvas->yStart) * 0.5;
            v17 = camera->fov * 0.5;
            v20 = stdMath_Tan(v17);
            v5 = cameraa;
            v6 = cameraa;
            v7 = cameraa - -1.0;
            camerab = v18 / v20;
            v8 = v6 / camerab;
            camera->fov_y = camerab;
            v9 = -v5 / camerab / camera->screenAspectRatio;
            clipFrustum->field_1C = v8 / camera->screenAspectRatio;
            v10 = camera->screenAspectRatio;
            clipFrustum->field_24 = -v18 / camerab;
            clipFrustum->field_20 = v9;
            clipFrustum->field_28 = v18 / camerab;
            clipFrustum->field_2C = v7 / camerab / v10;
            clipFrustum->field_30 = -(v18 - -1.0) / camerab;
            return 1;
        }
    }

    return 1;
}

int rdCamera_BuildClipFrustum(rdCamera *camera, rdClipFrustum *outClip, signed int height, signed int width, signed int height2, signed int width2)
{
    double v8; // st7
    double v9; // st4
    double v11; // rt0
    
    jk_printf("%u %u %u %u\n", height, width, height2, width2);

    rdClipFrustum* cameraClip = camera->cameraClipFrustum;
    rdCanvas* canvas = camera->canvas;
    if ( !canvas )
        return 0;

    v8 = canvas->screen_width_half - ((double)width - 0.5);
    v9 = -((double)width2 - 0.5 - canvas->screen_width_half) / camera->fov_y;
    v11 = canvas->screen_height_half - ((double)height - 0.5);

    outClip->field_1C = v8 / camera->fov_y / camera->screenAspectRatio;
    outClip->field_24 = -v11 / camera->fov_y;
    outClip->field_20 = v9 / camera->screenAspectRatio;

    outClip->field_0.x = cameraClip->field_0.x;
    outClip->field_0.y = cameraClip->field_0.y;
    outClip->field_0.z = cameraClip->field_0.z;
    outClip->field_28 = ((double)height2 - 0.5 - canvas->screen_height_half) / camera->fov_y;
    outClip->field_2C = ((v8 - -1.0) / camera->fov_y) / camera->screenAspectRatio;
    outClip->field_30 = -(v11 - -1.0) / camera->fov_y;

    return 1;
}

void rdCamera_Update(rdMatrix34 *orthoProj)
{
    rdMatrix_InvertOrtho34(&rdCamera_pCurCamera->view_matrix, orthoProj);
    rdMatrix_Copy34(&rdCamera_camMatrix, orthoProj);
    rdMatrix_ExtractAngles34(&rdCamera_camMatrix, &rdCamera_camRotation);
}

void rdCamera_PerspProject(rdVector3* out, rdVector3* v)
{
    out->x = rdCamera_pCurCamera->orthoScale * v->x + rdCamera_pCurCamera->canvas->screen_height_half;
    out->y = -(v->z * rdCamera_pCurCamera->orthoScale) * rdCamera_pCurCamera->screenAspectRatio + rdCamera_pCurCamera->canvas->screen_width_half;
    out->z = v->y;
}

void rdCamera_PerspProjectLst(rdVector3 *vertices_out, rdVector3 *vertices_in, unsigned int num_vertices)
{
    for (int i = 0; i < num_vertices; i++)
    {
        rdCamera_PerspProject(vertices_out, vertices_in);
        ++vertices_in;
        ++vertices_out;
    }
}

void rdCamera_PerspProjectSquare(rdVector3 *out, rdVector3 *v)
{
    out->x = rdCamera_pCurCamera->orthoScale * v->x + rdCamera_pCurCamera->canvas->screen_height_half;
    out->y = rdCamera_pCurCamera->canvas->screen_width_half - v->z * rdCamera_pCurCamera->orthoScale;
    out->z = v->y;
}

void rdCamera_PerspProjectSquareLst(rdVector3 *vertices_out, rdVector3 *vertices_in, unsigned int num_vertices)
{
    for (int i = 0; i < num_vertices; i++)
    {
        rdCamera_PerspProjectSquare(vertices_out, vertices_in);
        ++vertices_in;
        ++vertices_out;
    }
}

void rdCamera_OrthoProject(rdVector3 *out, rdVector3 *v)
{
    out->x = (rdCamera_pCurCamera->fov_y / v->y) * v->x + rdCamera_pCurCamera->canvas->screen_height_half;
    out->y = rdCamera_pCurCamera->canvas->screen_width_half - rdCamera_pCurCamera->screenAspectRatio * (rdCamera_pCurCamera->fov_y / v->y) * v->z;
    out->z = v->y;
}

void rdCamera_OrthoProjectLst(rdVector3 *vertices_out, rdVector3 *vertices_in, unsigned int num_vertices)
{
    for (int i = 0; i < num_vertices; i++)
    {
        rdCamera_OrthoProject(vertices_out, vertices_in);
        ++vertices_in;
        ++vertices_out;
    }
}

void rdCamera_OrthoProjectSquare(rdVector3 *out, rdVector3 *v)
{
    out->x = (rdCamera_pCurCamera->fov_y / v->y) * v->x + rdCamera_pCurCamera->canvas->screen_height_half;
    out->y = rdCamera_pCurCamera->canvas->screen_width_half - v->z * (rdCamera_pCurCamera->fov_y / v->y);
    out->z = v->y;
}

void rdCamera_OrthoProjectSquareLst(rdVector3 *vertices_out, rdVector3 *vertices_in, unsigned int num_vertices)
{
    for (int i = 0; i < num_vertices; i++)
    {
        rdCamera_OrthoProjectSquare(vertices_out, vertices_in);
        ++vertices_in;
        ++vertices_out;
    }
}

void rdCamera_SetAmbientLight(rdCamera *camera, float amt)
{
    camera->ambientLight = amt;
}

void rdCamera_SetAttenuation(rdCamera *camera, float minVal, float maxVal)
{
    int numLights; // edx
    rdLight **v4; // ecx
    rdLight *v5; // eax

    numLights = camera->numLights;
    camera->attenuationMax = maxVal;
    camera->attenuationMin = minVal;
    if ( numLights )
    {
        v4 = camera->lights;
        do
        {
            v5 = *v4++;
            --numLights;
            v5->falloffMin = v5->intensity / minVal;
            v5->falloffMax = v5->intensity / maxVal;
        }
        while ( numLights );
    }
}

int rdCamera_AddLight(rdCamera *camera, rdLight *light, rdVector3 *lightPos)
{
    if ( camera->numLights > 0x40 )
        return 0;

    camera->lights[camera->numLights] = light;

    light->id = camera->numLights;
    rdVector_Copy3(&camera->lightPositions[camera->numLights], lightPos);
    light->falloffMin = light->intensity / camera->attenuationMin;
    light->falloffMax = light->intensity / camera->attenuationMax;

    ++camera->numLights;
    return 1;
}

int rdCamera_ClearLights(rdCamera *camera)
{
    camera->numLights = 0;
    return 1;
}

void rdCamera_AdvanceFrame()
{
    rdCanvas *v0; // eax
    rdRect a4; // [esp+0h] [ebp-10h] BYREF

    v0 = rdCamera_pCurCamera->canvas;
    if ( (rdroid_curRenderOptions & 0x100) != 0 && (v0->bIdk & 2) != 0 )
    {
        if ( rdroid_curAcceleration <= 0 )
        {
            if ( (v0->bIdk & 1) != 0 )
            {
                a4.x = v0->xStart;
                a4.y = v0->yStart;
                a4.width = v0->widthMinusOne - v0->xStart + 1;
                a4.height = v0->heightMinusOne - v0->yStart + 1;
                stdDisplay_VBufferFill(v0->d3d_vbuf, 0, &a4);
            }
            else
            {
                stdDisplay_VBufferFill(v0->d3d_vbuf, 0, 0);
            }
        }
        else
        {
            std3D_ClearZBuffer();
        }
    }
}
