#include "rdCamera.h"

#include "stdPlatform.h" // Added: *_ALLOC/*_FREE macros

#include "Engine/rdLight.h"
#include "jk.h"
#include "Engine/rdroid.h"
#include "General/stdMath.h"
#include "Win95/stdDisplay.h"
#include "Platform/std3D.h"
#include "Engine/sithRender.h"
#include "World/jkPlayer.h"

static rdVector3 rdCamera_camRotation;
static flex_t rdCamera_mipmapScalar = 1.0; // MOTS added

#ifdef TARGET_TWL
int rdCamera_bForceRealProj = 0;
#endif

rdCamera* rdCamera_New(flex_t fov, BOOL bFarClip, flex_t nearPlane, flex_t farPlane, flex_t aspectRatio)
{
    rdCamera* out = (rdCamera *)RDROID_ALLOC(sizeof(rdCamera));
    if ( !out ) {
        return 0;
    }
    
    // Added: zero out alloc
    memset(out, 0, sizeof(*out));

    rdCamera_NewEntry(out, fov, bFarClip, nearPlane, farPlane, aspectRatio);    
    
    return out;
}

int rdCamera_NewEntry(rdCamera *pCamera, flex_t fov, BOOL bClipFar, flex_t nearPlane, flex_t farPlane, flex_t aspectRatio)
{
    if (!pCamera)
        return 0;

#ifdef TARGET_TWL
    bClipFar = 1;
#endif

    // Added: Don't double-alloc
    if (!pCamera->pClipFrustum)
    {
        pCamera->pClipFrustum = (rdClipFrustum *)RDROID_ALLOC(sizeof(rdClipFrustum));
    }

    if ( pCamera->pClipFrustum )
    {
        pCamera->pCanvas = 0;
        rdCamera_SetFOV(pCamera, fov);
        rdCamera_SetOrthoScale(pCamera, 1.0);

        pCamera->pClipFrustum->bClipFar = bClipFar;
        pCamera->pClipFrustum->nearPlane = nearPlane;
        pCamera->pClipFrustum->farPlane = farPlane;
        pCamera->aspectRatio = aspectRatio;
        pCamera->ambientLight = 0.0;
        pCamera->numLights = 0;
        pCamera->attenuationMin = 0.2;
        pCamera->attenuationMax = 0.1;
        
        rdCamera_SetProjectType(pCamera, rdCameraProjectType_Perspective);

        return 1;
    }
    return 0;
}

void rdCamera_Free(rdCamera *pCamera)
{
    if (pCamera)
    {
        rdCamera_FreeEntry(pCamera);
        RDROID_FREE(pCamera);
    }
}

void rdCamera_FreeEntry(rdCamera *pCamera)
{
    if ( pCamera->pClipFrustum ) {
        RDROID_FREE(pCamera->pClipFrustum);
        pCamera->pClipFrustum = NULL; // Added: no UAF
    }
}

int rdCamera_SetCanvas(rdCamera *pCamera, rdCanvas *pCanvas)
{
    pCamera->pCanvas = pCanvas;
    rdCamera_BuildFOV(pCamera);
    return 1;
}

int rdCamera_SetCurrent(rdCamera *pCamera)
{
    if ( rdCamera_g_pCurCamera != pCamera )
        rdCamera_g_pCurCamera = pCamera;
    return 1;
}

extern int jkGuiBuildMulti_bRendering;
int rdCamera_SetFOV(rdCamera *pCamera, flex_t fov)
{
    if ( fov < 5.0 )
    {
        fov = 5.0;
    }
    else if ( fov > 179.0 )
    {
        fov = 179.0;
    }

#ifdef QOL_IMPROVEMENTS
    if (!jkGuiBuildMulti_bRendering && jkPlayer_fovIsVertical && pCamera->aspectRatio != 0.0) {
        pCamera->fov = stdMath_ArcTan3(1.0, stdMath_Tan(fov * 0.5) / pCamera->aspectRatio) * -2.0;

        if ( pCamera->fov < 5.0 )
        {
            pCamera->fov = 5.0;
        }
        else if ( pCamera->fov > 179.0 )
        {
            pCamera->fov = 179.0;
        }
    }
    else
#endif
    {
        pCamera->fov = fov;
    }     
    
    rdCamera_BuildFOV(pCamera);
    return 1;
}

int rdCamera_SetProjectType(rdCamera *pCamera, int type)
{
    pCamera->projectType = type;
    
    switch (type)
    {
        case rdCameraProjectType_Ortho:
        {
            if (pCamera->aspectRatio == 1.0 )
            {
                pCamera->pfProject = rdCamera_OrthoProjectSquare;
                pCamera->pfProjectList = rdCamera_OrthoProjectSquareLst;
#ifdef TARGET_TWL
                pCamera->fnProjectLstClip = rdCamera_OrthoProjectSquareLst;
#endif
            }
            else
            {
                pCamera->pfProject = rdCamera_OrthoProject;
                pCamera->pfProjectList = rdCamera_OrthoProjectLst;
#ifdef TARGET_TWL
                pCamera->fnProjectLstClip = rdCamera_OrthoProjectLst;
#endif
            }
            break;
        }
        case rdCameraProjectType_Perspective:
        {
            if (pCamera->aspectRatio == 1.0)
            {
                pCamera->pfProject = rdCamera_PerspProjectSquare;
                pCamera->pfProjectList = rdCamera_PerspProjectSquareLst;
#ifdef TARGET_TWL
                pCamera->fnProjectLstClip = rdCamera_PerspProjectLstClip;
                if (rdCamera_bForceRealProj) {
                    pCamera->pfProject = rdCamera_PerspProjectClip;
                    pCamera->pfProjectList = rdCamera_PerspProjectLstClip;
                }
#endif
            }
            else
            {
                pCamera->pfProject = rdCamera_PerspProject;
                pCamera->pfProjectList = rdCamera_PerspProjectLst;
#ifdef TARGET_TWL
                pCamera->fnProjectLstClip = rdCamera_PerspProjectLstClip;
                if (rdCamera_bForceRealProj) {
                    pCamera->pfProject = rdCamera_PerspProjectClip;
                    pCamera->pfProjectList = rdCamera_PerspProjectLstClip;
                }
#endif
            }
            break;
        }
        
    }

    if ( pCamera->pCanvas )
        rdCamera_BuildFOV(pCamera);

    return 1;
}

int rdCamera_SetOrthoScale(rdCamera *pCamera, flex_t scale)
{
    pCamera->orthoScale = scale;
    rdCamera_BuildFOV(pCamera);
    return 1;
}

int rdCamera_SetAspectRatio(rdCamera *pCamera, flex_t ratio)
{
#ifdef QOL_IMPROVEMENTS
    if (jkPlayer_enableOrigAspect) ratio = 1.0;
#endif

    pCamera->aspectRatio = ratio;
    return rdCamera_SetProjectType(pCamera, pCamera->projectType);
}

int rdCamera_BuildFOV(rdCamera *pCamera)
{
    flex_d_t v10; // st3
    flex_d_t v15; // st4
    flex_t camerac; // [esp+1Ch] [ebp+4h]

    rdClipFrustum* pClipFrustum = pCamera->pClipFrustum;
    rdCanvas* pCanvas = pCamera->pCanvas;
    if ( !pCanvas )
        return 0;

    switch (pCamera->projectType)
    {
        case rdCameraProjectType_Ortho:
        {
            pCamera->focalLength = 0.0;
            camerac = ((flex_d_t)(pCanvas->heightMinusOne - pCanvas->yStart) * 0.5) / pCamera->orthoScale;
            v15 = ((flex_d_t)(pCanvas->widthMinusOne - pCanvas->xStart) * 0.5) / pCamera->orthoScale;
            pClipFrustum->orthoLeftPlane = -v15;
            pClipFrustum->orthoTopPlane = camerac / pCamera->aspectRatio;
            pClipFrustum->orthoRightPlane = v15;
            pClipFrustum->orthoBottomPlane = -camerac / pCamera->aspectRatio;
            pClipFrustum->farTop = 0.0;
            pClipFrustum->bottom = 0.0;
            pClipFrustum->farLeft = 0.0;
            pClipFrustum->right = 0.0;
            return 1;
        }
        
        case rdCameraProjectType_Perspective:
        {
#if defined(QOL_IMPROVEMENTS)
            flex_t overdraw = 1.0; // Added: HACK for 1px off on the bottom of the screen
#else
            flex_t overdraw = 0.0;
#endif
            flex_t width = pCanvas->xStart;
            flex_t height = pCanvas->yStart;
            flex_t project_width_half = overdraw + (pCanvas->widthMinusOne - (flex_d_t)width) * 0.5;
            flex_t project_height_half = overdraw + (pCanvas->heightMinusOne - (flex_d_t)height) * 0.5;
            
            flex_t project_width_half_2 = project_width_half;
            flex_t project_height_half_2 = project_height_half;
            
            flex_t tangent = stdMath_Tan(pCamera->fov * 0.5);
            pCamera->focalLength = project_width_half / tangent;

            flex_t focalLength = pCamera->focalLength;
            flex_t fovDy = pCamera->focalLength;

            // UBSAN fixes
            if (fovDy == 0) {
                fovDy = 0.000001;
            }
            if (focalLength == 0) {
                focalLength = 0.000001;
            }

            // This area is very susceptible to fixed-point error 
#ifdef EXPERIMENTAL_FIXED_POINT
            pClipFrustum->bClipFar = 1;
            flex_t aspect = project_height_half_2/project_width_half;
            pClipFrustum->farTop = tangent * aspect; // far top
            pClipFrustum->farLeft = -tangent; // far left
            pClipFrustum->bottom = -pClipFrustum->farTop;
            pClipFrustum->right = tangent; // right
            pClipFrustum->nearTop = ((project_height_half - -1.0) / project_width_half) * tangent; // near top
            pClipFrustum->nearLeft = (-(project_width_half - -1.0) / project_width_half) * tangent; // near left
#else
            pClipFrustum->farTop = project_height_half / fovDy; // far top
            pClipFrustum->farLeft = -project_width_half / focalLength; // far left
            pClipFrustum->bottom = -project_height_half_2 / fovDy; // bottom
            pClipFrustum->right = project_width_half_2 / focalLength; // right
            pClipFrustum->nearTop = (project_height_half - -1.0) / fovDy; // near top
            pClipFrustum->nearLeft = -(project_width_half - -1.0) / focalLength; // near left
#endif
            return 1;
        }
    }

    return 1;
}

int rdCamera_SetFrustrum(rdCamera *pCamera, rdClipFrustum *pFrustrum, signed int left, signed int top, signed int right, signed int bottom)
{   
    //jk_printf("%u %u %u %u\n", height, width, height2, width2);

    rdClipFrustum* cameraClip = pCamera->pClipFrustum;
    rdCanvas* pCanvas = pCamera->pCanvas;
    if ( !pCanvas )
        return 0;

#if defined(QOL_IMPROVEMENTS)
    flex_t overdraw = 1.0; // Added: HACK for 1px off on the bottom of the screen
#else
    flex_t overdraw = 0.0;
#endif
    flex_t project_width_half = overdraw + pCanvas->half_screen_height - ((flex_d_t)top - 0.5);
    flex_t project_height_half = overdraw + pCanvas->half_screen_width - ((flex_d_t)left - 0.5);
    
    flex_t project_width_half_2 = -pCanvas->half_screen_height + ((flex_d_t)bottom - 0.5);
    flex_t project_height_half_2 = -pCanvas->half_screen_width + ((flex_d_t)right - 0.5);

    pFrustrum->bClipFar = cameraClip->bClipFar;
    pFrustrum->nearPlane = cameraClip->nearPlane;
    pFrustrum->farPlane = cameraClip->farPlane;
    
    flex_t focalLength = pCamera->focalLength;
    flex_t fovDy = pCamera->focalLength;

    // UBSAN fixes
    if (fovDy == 0) {
        fovDy = 0.000001;
    }
    if (focalLength == 0) {
        focalLength = 0.000001;
    }

#if 0 //def EXPERIMENTAL_FIXED_POINT
    flex_t tangent = stdMath_Tan(pCamera->fov * 0.5);
    flex_t aspect = project_height_half_2/project_width_half;
    pClipFrustum->farTop = tangent * aspect; // far top
    pClipFrustum->farLeft = -tangent; // far left
    pClipFrustum->bottom = -pClipFrustum->farTop;
    pClipFrustum->right = tangent; // right
    pClipFrustum->nearTop = ((project_height_half - -1.0) / project_width_half) * tangent; // near top
    pClipFrustum->nearLeft = (-(project_width_half - -1.0) / project_width_half) * tangent; // near left
#else
    pFrustrum->farTop = project_width_half / fovDy;
    pFrustrum->farLeft = -project_height_half / focalLength;
    pFrustrum->bottom = -project_width_half_2 / fovDy;
    pFrustrum->right = project_height_half_2 / focalLength;
    pFrustrum->nearTop = (project_width_half - -1.0) / fovDy;
    pFrustrum->nearLeft = -(project_height_half - -1.0) / focalLength;
#endif

    return 1;
}

void rdCamera_Update(rdMatrix34 *orient)
{
    rdMatrix_InvertOrtho34(&rdCamera_g_pCurCamera->orient, orient);
    rdMatrix_Copy34(&rdCamera_g_camMatrix, orient);
    rdMatrix_ExtractAngles34(&rdCamera_g_camMatrix, &rdCamera_camRotation);
}

void rdCamera_OrthoProject(rdVector3* pDestVertex, const rdVector3* pSrcVertex)
{
    //rdCamera_g_pCurCamera->orthoScale = 200.0;

    pDestVertex->x = rdCamera_g_pCurCamera->orthoScale * pSrcVertex->x + rdCamera_g_pCurCamera->pCanvas->half_screen_width;
    pDestVertex->y = -(pSrcVertex->z * rdCamera_g_pCurCamera->orthoScale) * rdCamera_g_pCurCamera->aspectRatio + rdCamera_g_pCurCamera->pCanvas->half_screen_height;
    pDestVertex->z = pSrcVertex->y * rdCamera_g_pCurCamera->orthoScale;

    //printf("%f %f %f -> %f %f %f\n", v->x, v->y, v->z, out->x, out->y, out->z);
}

void rdCamera_OrthoProjectLst(rdVector3 *pDestVerts, const rdVector3 *pSrcVerts, unsigned int numVerts)
{
    for (int i = 0; i < numVerts; i++)
    {
        rdCamera_OrthoProject(pDestVerts, pSrcVerts);
        ++pSrcVerts;
        ++pDestVerts;
    }
}

void rdCamera_OrthoProjectSquare(rdVector3 *pDestVertex, const rdVector3 *pSrcVertex)
{
    pDestVertex->x = rdCamera_g_pCurCamera->orthoScale * pSrcVertex->x + rdCamera_g_pCurCamera->pCanvas->half_screen_width;
    pDestVertex->y = rdCamera_g_pCurCamera->pCanvas->half_screen_height - pSrcVertex->z * rdCamera_g_pCurCamera->orthoScale;
    pDestVertex->z = pSrcVertex->y;
}

void rdCamera_OrthoProjectSquareLst(rdVector3 *pDestVerts, const rdVector3 *pSrcVerts, unsigned int numVerts)
{
    for (int i = 0; i < numVerts; i++)
    {
        rdCamera_OrthoProjectSquare(pDestVerts, pSrcVerts);
        ++pSrcVerts;
        ++pDestVerts;
    }
}

// TODO: The original game had an aspect ratio multiply here, 
// DSi needs an aspect divide, OpenGL wants nothing??
void rdCamera_PerspProject(rdVector3 *pDestVertex, const rdVector3 *pSrcVertex)
{
#ifdef TARGET_TWL
    // DSi does HW projection
    pDestVertex->x = pSrcVertex->x;
    pDestVertex->y = pSrcVertex->y;
    pDestVertex->z = pSrcVertex->z;
#else
    flex_t fov_y_calc = (rdCamera_g_pCurCamera->focalLength / pSrcVertex->y);
    flex_t fov_x_calc = fov_y_calc; // This is the same because the clipping is what actually handles the aspect change
    pDestVertex->x = rdCamera_g_pCurCamera->pCanvas->half_screen_width + (pSrcVertex->x * fov_x_calc);
    pDestVertex->y = rdCamera_g_pCurCamera->pCanvas->half_screen_height - (pSrcVertex->z * fov_y_calc);
    pDestVertex->z = pSrcVertex->y;
#endif
    //printf("%f %f %f -> %f %f %f\n", v->x, v->y, v->z, out->x, out->y, out->z);
}

void rdCamera_PerspProjectLst(rdVector3 *pDestVerts, const rdVector3 *pSrcVerts, unsigned int numVerts)
{
#ifdef TARGET_TWL
    // DSi does HW projection
    memcpy(pDestVerts, pSrcVerts, numVerts * sizeof(rdVector3));
    return;
#endif

    for (unsigned int i = 0; i < numVerts; i++)
    {
        rdCamera_PerspProject(pDestVerts, pSrcVerts);
        ++pSrcVerts;
        ++pDestVerts;
    }
}

#ifdef TARGET_TWL
void rdCamera_PerspProjectClip(rdVector3 *out, const rdVector3 *v)
{
    flex_t fov_y_calc = (rdCamera_g_pCurCamera->focalLength / v->y);
    flex_t fov_x_calc = fov_y_calc; // This is the same because the clipping is what actually handles the aspect change
    
    out->x = rdCamera_g_pCurCamera->pCanvas->half_screen_width + (v->x * fov_x_calc);
    out->y = rdCamera_g_pCurCamera->pCanvas->half_screen_height - (v->z * fov_y_calc);
    out->z = v->y;
}

void rdCamera_PerspProjectLstClip(rdVector3 *pVerticesOut, const rdVector3 *pVerticesIn, unsigned int numVertices)
{
    for (unsigned int i = 0; i < numVertices; i++)
    {
        rdCamera_PerspProjectClip(pVerticesOut, pVerticesIn);
        ++pVerticesIn;
        ++pVerticesOut;
    }
}
#endif

void rdCamera_PerspProjectSquare(rdVector3 *pDestVertex, const rdVector3 *pSrcVertex)
{
#ifdef TARGET_TWL
    // DSi does HW projection
    pDestVertex->x = pSrcVertex->x;
    pDestVertex->y = pSrcVertex->y;
    pDestVertex->z = pSrcVertex->z;
#else
    flex_t fov_y_calc = (rdCamera_g_pCurCamera->focalLength / pSrcVertex->y);
    pDestVertex->x = rdCamera_g_pCurCamera->pCanvas->half_screen_width + (pSrcVertex->x * fov_y_calc);
    pDestVertex->y = rdCamera_g_pCurCamera->pCanvas->half_screen_height - (pSrcVertex->z * fov_y_calc);
    pDestVertex->z = pSrcVertex->y;
#endif
}

void rdCamera_PerspProjectSquareLst(rdVector3 *pDestVerts, const rdVector3 *pSrcVerts, unsigned int numVerts)
{
#ifdef TARGET_TWL
    memcpy(pDestVerts, pSrcVerts, numVerts * sizeof(rdVector3));
    return;
#endif
    for (unsigned int i = 0; i < numVerts; i++)
    {
        rdCamera_PerspProjectSquare(pDestVerts, pSrcVerts);
        ++pSrcVerts;
        ++pDestVerts;
    }
}

void rdCamera_SetAmbientLight(rdCamera *pCamera, flex_t amt)
{
    pCamera->ambientLight = amt;
}

void rdCamera_SetAttenuation(rdCamera *pCamera, flex_t min, flex_t max)
{
    int numLights; // edx
    rdLight **v4; // ecx
    rdLight *v5; // eax

    numLights = pCamera->numLights;
    pCamera->attenuationMax = max;
    pCamera->attenuationMin = min;
    if ( numLights )
    {
        v4 = pCamera->aLights;
        do
        {
            v5 = *v4++;
            --numLights;
            v5->minRadius = v5->intensity / min;
            v5->maxRadius = v5->intensity / max;
        }
        while ( numLights );
    }
}

int rdCamera_AddLight(rdCamera *pCamera, rdLight *pLight, rdVector3 *pPos)
{
    //sithRender_RenderDebugLight(light->intensity * 10.0, lightPos);
    if ( pCamera->numLights >= RDCAMERA_MAX_LIGHTS ) // Added: > to >=
        return 0;

    pCamera->aLights[pCamera->numLights] = pLight;

    pLight->id = pCamera->numLights;
    rdVector_Copy3(&pCamera->aLightPositions[pCamera->numLights], pPos);
    pLight->minRadius = pLight->intensity / pCamera->attenuationMin;
    pLight->maxRadius = pLight->intensity / pCamera->attenuationMax;

    ++pCamera->numLights;
    return 1;
}

int rdCamera_ClearLights(rdCamera *pCamera)
{
    pCamera->numLights = 0;
    return 1;
}

void rdCamera_AdvanceFrame()
{
    rdCanvas *v0; // eax
    rdRect a4; // [esp+0h] [ebp-10h] BYREF

    v0 = rdCamera_g_pCurCamera->pCanvas;
    if ( (rdroid_g_curRenderOptions & 0x100) != 0 && (v0->bIdk & 2) != 0 )
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

// MOTS added
flex_t rdCamera_GetMipmapScalar()
{
    return rdCamera_mipmapScalar;
}

// MOTS added
void rdCamera_SetMipmapScalar(flex_t val)
{
    rdCamera_mipmapScalar = val;
}
