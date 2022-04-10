#include "rdCamera.h"

#include "Engine/rdLight.h"
#include "jk.h"
#include "Engine/rdroid.h"
#include "General/stdMath.h"
#include "Win95/stdDisplay.h"
#include "Platform/std3D.h"
#include "Engine/sithRender.h"
#include "World/jkPlayer.h"

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
        
        rdCamera_SetProjectType(camera, rdCameraProjectType_Perspective);

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
        case rdCameraProjectType_Ortho:
        {
            if (camera->screenAspectRatio == 1.0 )
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
        case rdCameraProjectType_Perspective:
        {
            if (camera->screenAspectRatio == 1.0)
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
    return rdCamera_SetProjectType(camera, camera->projectType);
}

int rdCamera_BuildFOV(rdCamera *camera)
{
    double v10; // st3
    double v15; // st4
    float camerac; // [esp+1Ch] [ebp+4h]

    rdClipFrustum* clipFrustum = camera->cameraClipFrustum;
    rdCanvas* canvas = camera->canvas;
    if ( !canvas )
        return 0;

    switch (camera->projectType)
    {
        case rdCameraProjectType_Ortho:
        {
            camera->fov_y = 0.0;
            camerac = ((double)(canvas->heightMinusOne - canvas->yStart) * 0.5) / camera->orthoScale;
            v15 = ((double)(canvas->widthMinusOne - canvas->xStart) * 0.5) / camera->orthoScale;
            clipFrustum->orthoLeft = -v15;
            clipFrustum->orthoTop = camerac / camera->screenAspectRatio;
            clipFrustum->orthoRight = v15;
            clipFrustum->orthoBottom = -camerac / camera->screenAspectRatio;
            clipFrustum->farTop = 0.0;
            clipFrustum->bottom = 0.0;
            clipFrustum->farLeft = 0.0;
            clipFrustum->right = 0.0;
            return 1;
        }
        
        case rdCameraProjectType_Perspective:
        {
            float width = canvas->xStart;
            float height = canvas->yStart;
            float project_width_half = (canvas->widthMinusOne - (double)width) * 0.5;
            float project_height_half = (canvas->heightMinusOne - (double)height) * 0.5;
            
            float project_width_half_2 = project_width_half;
            float project_height_half_2 = project_height_half;
            
#ifdef QOL_IMPROVEMENTS
            if (jkPlayer_fovIsVertical) {
                camera->fov_y = project_width_half / ((1.0/camera->screenAspectRatio) * stdMath_Tan(camera->fov * 0.5));
            }
            else
            {
                camera->fov_y = project_width_half / stdMath_Tan(camera->fov * 0.5);
            }
            
#else
            camera->fov_y = project_width_half / stdMath_Tan(camera->fov * 0.5);
#endif

            float fov_calc = camera->fov_y;
            float fov_calc_height = camera->fov_y * camera->screenAspectRatio;

#ifdef QOL_IMPROVEMENTS
            if (jkPlayer_enableOrigAspect)
                fov_calc_height = camera->fov_y;
#endif

            clipFrustum->farTop = project_height_half / fov_calc_height; // far top
            clipFrustum->farLeft = -project_width_half / fov_calc; // far left
            clipFrustum->bottom = -project_height_half_2 / fov_calc_height; // bottom
            clipFrustum->right = project_width_half_2 / fov_calc; // right
            clipFrustum->nearTop = (project_height_half - -1.0) / fov_calc_height; // near top
            clipFrustum->nearLeft = -(project_width_half - -1.0) / fov_calc; // near left
            return 1;
        }
    }

    return 1;
}

int rdCamera_BuildClipFrustum(rdCamera *camera, rdClipFrustum *outClip, signed int height, signed int width, signed int height2, signed int width2)
{   
    //jk_printf("%u %u %u %u\n", height, width, height2, width2);

    rdClipFrustum* cameraClip = camera->cameraClipFrustum;
    rdCanvas* canvas = camera->canvas;
    if ( !canvas )
        return 0;

    float project_width_half = canvas->screen_width_half - ((double)width - 0.5);
    float project_height_half = canvas->screen_height_half - ((double)height - 0.5);
    
    float project_width_half_2 = -canvas->screen_width_half + ((double)width2 - 0.5);
    float project_height_half_2 = -canvas->screen_height_half + ((double)height2 - 0.5);

    rdVector_Copy3(&outClip->field_0, &cameraClip->field_0);
    
    float fov_calc = camera->fov_y;
    float fov_calc_height = camera->fov_y * camera->screenAspectRatio;

#ifdef QOL_IMPROVEMENTS
    if (jkPlayer_enableOrigAspect)
        fov_calc_height = camera->fov_y;
#endif

    outClip->farTop = project_width_half / fov_calc_height;
    outClip->farLeft = -project_height_half / fov_calc;
    outClip->bottom = -project_width_half_2 / fov_calc_height;
    outClip->right = project_height_half_2 / fov_calc;
    outClip->nearTop = (project_width_half - -1.0) / fov_calc_height;
    outClip->nearLeft = -(project_height_half - -1.0) / fov_calc;

    return 1;
}

void rdCamera_Update(rdMatrix34 *orthoProj)
{
    rdMatrix_InvertOrtho34(&rdCamera_pCurCamera->view_matrix, orthoProj);
    rdMatrix_Copy34(&rdCamera_camMatrix, orthoProj);
    rdMatrix_ExtractAngles34(&rdCamera_camMatrix, &rdCamera_camRotation);
}

void rdCamera_OrthoProject(rdVector3* out, rdVector3* v)
{
    //rdCamera_pCurCamera->orthoScale = 200.0;

    out->x = rdCamera_pCurCamera->orthoScale * v->x + rdCamera_pCurCamera->canvas->screen_height_half;
    out->y = -(v->z * rdCamera_pCurCamera->orthoScale) * rdCamera_pCurCamera->screenAspectRatio + rdCamera_pCurCamera->canvas->screen_width_half;
    out->z = v->y * rdCamera_pCurCamera->orthoScale;

    //printf("%f %f %f -> %f %f %f\n", v->x, v->y, v->z, out->x, out->y, out->z);
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
    out->x = rdCamera_pCurCamera->orthoScale * v->x + rdCamera_pCurCamera->canvas->screen_height_half;
    out->y = rdCamera_pCurCamera->canvas->screen_width_half - v->z * rdCamera_pCurCamera->orthoScale;
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

void rdCamera_PerspProject(rdVector3 *out, rdVector3 *v)
{
    out->x = (rdCamera_pCurCamera->fov_y / v->y) * v->x + rdCamera_pCurCamera->canvas->screen_height_half;
    out->y = rdCamera_pCurCamera->canvas->screen_width_half - (jkPlayer_enableOrigAspect ? 1.0 : rdCamera_pCurCamera->screenAspectRatio) * (rdCamera_pCurCamera->fov_y / v->y) * v->z;
    out->z = v->y;

    //printf("%f %f %f -> %f %f %f\n", v->x, v->y, v->z, out->x, out->y, out->z);
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
    out->x = (rdCamera_pCurCamera->fov_y / v->y) * v->x + rdCamera_pCurCamera->canvas->screen_height_half;
    out->y = rdCamera_pCurCamera->canvas->screen_width_half - v->z * (rdCamera_pCurCamera->fov_y / v->y);
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
    //sithRender_RenderDebugLight(light->intensity * 10.0, lightPos);
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
