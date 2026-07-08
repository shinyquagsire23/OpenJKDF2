#include "sithCamera.h"

#include "World/sithSector.h"
#include "World/sithThing.h"
#include "World/sithWorld.h"
#include "World/jkPlayer.h"
#include "Engine/sithCollision.h"
#include "Primitives/rdMath.h"
#include "Primitives/rdVector.h"
#include "Primitives/rdMatrix.h"
#include "Gameplay/sithTime.h"
#include "Engine/rdCamera.h"
#include "Engine/sithRender.h"
#include "General/stdMath.h"
#include "jk.h"

static rdVector3 sithCamera_trans = {0.0, 0.3, 0.0};
static rdVector3 sithCamera_trans2 = {0.0, 0.2, 0.0};
static rdVector3 sithCamera_trans3 = {0.0, 1.0, 1.0};
static int sithCamera_camIdxToGlobalIdx[2] = {0,1};

int sithCamera_Startup()
{
    sithCamera_NewEntry(&sithCamera_g_aCameras[0], 0, 0x1, SITHCAMERA_FOV, SITHCAMERA_ASPECT, NULL, NULL, NULL);
    sithCamera_NewEntry(&sithCamera_g_aCameras[1], 0, 0x4, SITHCAMERA_FOV, SITHCAMERA_ASPECT, NULL, NULL, NULL);
    sithCamera_g_aCameras[1].offset.x = 0.0;
    sithCamera_g_aCameras[1].offset.y = -0.2;
    sithCamera_g_aCameras[1].offset.z = 0.06;
    sithCamera_NewEntry(&sithCamera_g_aCameras[2], 0, 0x8, SITHCAMERA_FOV, SITHCAMERA_ASPECT, NULL, NULL, NULL);
    sithCamera_NewEntry(&sithCamera_g_aCameras[4], 0, 0x20, SITHCAMERA_FOV, SITHCAMERA_ASPECT, NULL, NULL, NULL);
    sithCamera_NewEntry(&sithCamera_g_aCameras[5], 0, 0x40, SITHCAMERA_FOV, SITHCAMERA_ASPECT, NULL, NULL, NULL);
    sithCamera_NewEntry(&sithCamera_g_aCameras[6], 0, 0x80, SITHCAMERA_FOV, SITHCAMERA_ASPECT, NULL, NULL, NULL);
#ifdef DW_CAMERA
    if (Main_bDwCompat) {
        sithCamera_NewEntry(&sithCamera_g_aCameras[7], 0, 0x100, SITHCAMERA_FOV, SITHCAMERA_ASPECT, NULL, NULL, NULL);
    }
#endif
    sithCamera_g_curCycleCamNum = 0;
    sithCamera_bStartup = 1;

    return 1;
}

void sithCamera_Shutdown()
{
    sithCamera_Close(); // Added--moved the rdCamera_FreeEntries where they belong

    // Added: Clean reset
#ifdef DW_CAMERA
    memset(sithCamera_g_aCameras, 0, sizeof(SithCamera) * 8);
#else
    memset(sithCamera_g_aCameras, 0, sizeof(SithCamera) * 7);
#endif

    sithCamera_bStartup = 0;
}

int sithCamera_Open(rdCanvas *pCanvas, flex_t aspect)
{
    if ( sithCamera_bOpen )
        return 0;

    sithCamera_g_aCameras[0].aspectRatio = aspect;
    rdCamera_NewEntry(&sithCamera_g_aCameras[0].rdCamera, sithCamera_g_aCameras[0].rdCamera.fov, 0, SITHCAMERA_ZNEAR_FIRSTPERSON, SITHCAMERA_ZFAR, aspect);
    rdCamera_SetAttenuation(&sithCamera_g_aCameras[0].rdCamera, SITHCAMERA_ATTENUATION_MIN, SITHCAMERA_ATTENUATION_MAX);
    rdCamera_SetCanvas(&sithCamera_g_aCameras[0].rdCamera, pCanvas);
    sithCamera_g_aCameras[1].aspectRatio = aspect;
    rdCamera_NewEntry(&sithCamera_g_aCameras[1].rdCamera, sithCamera_g_aCameras[1].rdCamera.fov, 0, SITHCAMERA_ZNEAR, SITHCAMERA_ZFAR, aspect);
    rdCamera_SetAttenuation(&sithCamera_g_aCameras[1].rdCamera, SITHCAMERA_ATTENUATION_MIN, SITHCAMERA_ATTENUATION_MAX);
    rdCamera_SetCanvas(&sithCamera_g_aCameras[1].rdCamera, pCanvas);
    sithCamera_g_aCameras[2].aspectRatio = aspect;
    rdCamera_NewEntry(&sithCamera_g_aCameras[2].rdCamera, sithCamera_g_aCameras[2].rdCamera.fov, 0, SITHCAMERA_ZNEAR, SITHCAMERA_ZFAR, aspect);
    rdCamera_SetAttenuation(&sithCamera_g_aCameras[2].rdCamera, SITHCAMERA_ATTENUATION_MIN, SITHCAMERA_ATTENUATION_MAX);
    rdCamera_SetCanvas(&sithCamera_g_aCameras[2].rdCamera, pCanvas);
    sithCamera_g_aCameras[4].aspectRatio = aspect;
    rdCamera_NewEntry(&sithCamera_g_aCameras[4].rdCamera, sithCamera_g_aCameras[4].rdCamera.fov, 0, SITHCAMERA_ZNEAR, SITHCAMERA_ZFAR, aspect);
    rdCamera_SetAttenuation(&sithCamera_g_aCameras[4].rdCamera, SITHCAMERA_ATTENUATION_MIN, SITHCAMERA_ATTENUATION_MAX);
    rdCamera_SetCanvas(&sithCamera_g_aCameras[4].rdCamera, pCanvas);
    sithCamera_g_aCameras[5].aspectRatio = aspect;
    rdCamera_NewEntry(&sithCamera_g_aCameras[5].rdCamera, sithCamera_g_aCameras[5].rdCamera.fov, 0, SITHCAMERA_ZNEAR, SITHCAMERA_ZFAR, aspect);
    rdCamera_SetAttenuation(&sithCamera_g_aCameras[5].rdCamera, SITHCAMERA_ATTENUATION_MIN, SITHCAMERA_ATTENUATION_MAX);
    rdCamera_SetCanvas(&sithCamera_g_aCameras[5].rdCamera, pCanvas);
    sithCamera_g_aCameras[6].aspectRatio = aspect;
    rdCamera_NewEntry(&sithCamera_g_aCameras[6].rdCamera, sithCamera_g_aCameras[6].rdCamera.fov, 0, SITHCAMERA_ZNEAR, SITHCAMERA_ZFAR, aspect);
    rdCamera_SetAttenuation(&sithCamera_g_aCameras[6].rdCamera, SITHCAMERA_ATTENUATION_MIN, SITHCAMERA_ATTENUATION_MAX);
    rdCamera_SetCanvas(&sithCamera_g_aCameras[6].rdCamera, pCanvas);
#ifdef DW_CAMERA
    if (Main_bDwCompat) {
        sithCamera_g_aCameras[7].aspectRatio = aspect;
        rdCamera_NewEntry(&sithCamera_g_aCameras[7].rdCamera, sithCamera_g_aCameras[7].rdCamera.fov, 0.0, SITHCAMERA_ZNEAR, SITHCAMERA_ZFAR, aspect);
        rdCamera_SetAttenuation(&sithCamera_g_aCameras[7].rdCamera, SITHCAMERA_ATTENUATION_MIN, SITHCAMERA_ATTENUATION_MAX);
        rdCamera_SetCanvas(&sithCamera_g_aCameras[7].rdCamera, pCanvas);
    }
#endif // DW_CAMERA
    sithCamera_Update(sithCamera_g_pCurCamera);
    sithCamera_bOpen = 1;
    return 1;
}

void sithCamera_Close()
{
    if ( sithCamera_bOpen ) {
        sithCamera_bOpen = 0;

        // Added: Prevent UAF
        rdCamera_SetCanvas(&sithCamera_g_aCameras[0].rdCamera, NULL);
        rdCamera_SetCanvas(&sithCamera_g_aCameras[1].rdCamera, NULL);
        rdCamera_SetCanvas(&sithCamera_g_aCameras[2].rdCamera, NULL);
        rdCamera_SetCanvas(&sithCamera_g_aCameras[4].rdCamera, NULL);
        rdCamera_SetCanvas(&sithCamera_g_aCameras[5].rdCamera, NULL);
        rdCamera_SetCanvas(&sithCamera_g_aCameras[6].rdCamera, NULL);
#ifdef DW_CAMERA
        rdCamera_SetCanvas(&sithCamera_g_aCameras[7].rdCamera, NULL);
#endif

        // Added: Prevent memleak
        for (int i = 0; i < 7; i++)
        {
            rdCamera_FreeEntry(&sithCamera_g_aCameras[i].rdCamera);
        }
#ifdef DW_CAMERA
        if (Main_bDwCompat) {
            rdCamera_FreeEntry(&sithCamera_g_aCameras[7].rdCamera);
        }
#endif
    }
}

void sithCamera_ResetAllCameras()
{
    SithThing *v0; // eax
    rdVector3 rot; // [esp+Ch] [ebp-Ch] BYREF

    v0 = sithWorld_g_pCurrentWorld->pCameraFocusThing;
    sithCamera_g_stateFlags &= ~1u;
    sithCamera_g_aCameras[0].pPrimaryFocusThing = v0;
    sithCamera_g_aCameras[1].pPrimaryFocusThing = v0;
    sithCamera_g_aCameras[2].pPrimaryFocusThing = v0;
    sithCamera_g_aCameras[2].pSecondaryFocusThing = v0;
    sithCamera_g_aCameras[4].pPrimaryFocusThing = v0;
    sithCamera_g_aCameras[4].pSecondaryFocusThing = v0;
    sithCamera_g_aCameras[5].pPrimaryFocusThing = v0;
    sithCamera_g_aCameras[5].pSecondaryFocusThing = v0;
    sithCamera_g_aCameras[6].pPrimaryFocusThing = v0;
    sithCamera_g_aCameras[6].pSecondaryFocusThing = v0;
    sithCamera_g_bCurCameraSet = 0;
    sithCamera_g_aCameras[0].pSecondaryFocusThing = 0;
    sithCamera_g_aCameras[1].pSecondaryFocusThing = 0;
    if ( !sithCamera_g_pCurCamera || sithCamera_g_aCameras[0].dword4 >= sithCamera_g_pCurCamera->dword4 )
    {
        sithCamera_g_pCurCamera = sithCamera_g_aCameras;
        sithCamera_g_bCurCameraSet = 1;
        rdCamera_SetCurrent(&sithCamera_g_aCameras[0].rdCamera);
        if ( sithCamera_g_aCameras[0].type == 32 )
        {
            rdMatrix_Copy34(&sithCamera_idleCamOrient, &sithCamera_g_pCurCamera->pPrimaryFocusThing->orient);
            rot.x = 0.0;
            rot.z = 0.0;
            rot.y = -45.0;
            rdMatrix_PostRotate34(&sithCamera_idleCamOrient, &rot);
        }
        sithCamera_Update(sithCamera_g_pCurCamera);
    }
    sithCamera_g_curCycleCamNum = 0;
}

// MOTS altered
int sithCamera_NewEntry(SithCamera *camera, uint32_t a2, uint32_t a3, flex_t fov, flex_t aspectRatio, rdCanvas *pCanvas, SithThing *focus_far, SithThing *focus_near)
{
    camera->type = a3;
    camera->dword4 = a2;
    camera->pPrimaryFocusThing = focus_far;
    camera->fov = fov;
    camera->aspectRatio = aspectRatio;
    camera->pSecondaryFocusThing = focus_near;
    rdCamera_NewEntry(&camera->rdCamera, fov, 0, SITHCAMERA_ZNEAR, SITHCAMERA_ZFAR, aspectRatio);
    rdCamera_SetAttenuation(&camera->rdCamera, SITHCAMERA_ATTENUATION_MIN, SITHCAMERA_ATTENUATION_MAX);

    if (pCanvas) {
        rdCamera_SetCanvas(&camera->rdCamera, pCanvas);
    }

    rdVector_Zero3(&camera->lookPos);
    rdVector_Zero3(&camera->lookPYR);
    rdVector_Zero3(&camera->offset);
#ifndef OPTIMIZE_AWAY_UNUSED_FIELDS
    rdVector_Zero3(&camera->vecUnknown1);
#endif
    rdMatrix_Identity34(&camera->orient);

#ifdef JKM_CAMERA
    camera->bZoomed = 0;
    camera->zoomScale = 1.0;
    camera->invZoomScale = 1.0;
    camera->zoomFov = camera->fov;
    camera->zoomSpeed = 0.0;
#ifdef QOL_IMPROVEMENTS
    camera->zoomScaleOrig = 1.0;
    camera->zoomFov = 1.0;
#endif
#endif

    return 1;
}

// MOTS altered
void sithCamera_Update(SithCamera *cam)
{
    rdVector3 mode64Tmp;
    rdVector3 v76;
    rdVector3 v2; // [esp+2Ch] [ebp-60h] BYREF
    rdVector3 a1; // [esp+38h] [ebp-54h] BYREF
    rdVector3 v84; // [esp+44h] [ebp-48h] BYREF
    rdVector3 rot; // [esp+50h] [ebp-3Ch] BYREF
    rdMatrix34 out; // [esp+5Ch] [ebp-30h] BYREF

    SithThing* focusThing = cam->pPrimaryFocusThing;
    flex_t v77 = sithCamera_g_cameraAngleDelta * sithTime_g_frameTimeFlex;
    flex_t v78 = sithCamera_g_cameraPosDelta * sithTime_g_frameTimeFlex;
    switch ( cam->type )
    {
        case 1:
            // MOTS added: scope zoom
#ifdef JKM_CAMERA
#ifndef QOL_IMPROVEMENTS
            // Redundant
            if (cam->bZoomed) 
#endif
            {
                sithCamera_UpdateZoom(cam);
            }
            rdCamera_SetMipmapScalar(cam->invZoomScale);
#endif

            rdMatrix_Copy34(&cam->orient, &focusThing->orient);
            if ( focusThing->moveType == SITH_MT_PATH && focusThing->renderData.paJointMatrices)
            {
                rdMatrix_Copy34(&cam->orient, focusThing->renderData.paJointMatrices);
            }
            else
            {
                if ( focusThing->type == SITH_THING_ACTOR || focusThing->type == SITH_THING_PLAYER )
                {
                    rdVector_Copy3(&v76, &focusThing->actorParams.headPYR);
                }
                else
                {
                    rdVector_Zero3(&v76);
                }

                if ( focusThing->moveType == SITH_MT_PHYSICS )
                {
                    v76.z = rdMath_clampf(5.0 * rdVector_Dot3(&focusThing->orient.rvec, &focusThing->physicsParams.vel), -8.0, 8.0); 
                }

                // MOTS added: hmm??
                if (Main_bMotsCompat || focusThing == sithPlayer_g_pLocalPlayerThing )
                {
                    rdVector_Add3Acc(&v76, &sithCamera_g_vecCameraAngleOffset);
                }

                rdMatrix_PreRotate34(&cam->orient, &v76);
                rdMatrix_PostTranslate34(&cam->orient, &focusThing->position);
                if ( focusThing->type == SITH_THING_ACTOR || focusThing->type == SITH_THING_PLAYER )
                {
                    rdMatrix_PreTranslate34(&cam->orient, &focusThing->actorParams.eyeOffset);
                    
                    // MOTS added: hmm??
                    if (Main_bMotsCompat || focusThing == sithPlayer_g_pLocalPlayerThing )
                        rdMatrix_PreTranslate34(&cam->orient, &sithCamera_g_vecCameraPosOffset);
                }
                rdMatrix_Normalize34(&cam->orient);
            }
            // Added: nullptr check
            if (focusThing->sector)
                cam->sector = sithCollision_FindSectorInRadius(focusThing->sector, &focusThing->position, &cam->orient.scale, 0.02);
            break;
        case 4:
            if ( focusThing->type == SITH_THING_ACTOR || focusThing->type == SITH_THING_PLAYER )
            {
                rdVector_Copy3(&v76, &focusThing->actorParams.headPYR);
            }
            else
            {
                rdVector_Zero3(&v76);
            }

            // MOTS added: hmm??
            if (Main_bMotsCompat)
            {
                rdVector_Add3Acc(&v76, &sithCamera_g_vecCameraAngleOffset);
            }

            rdMatrix_Copy34(&out, &focusThing->orient);
            rdMatrix_PreRotate34(&out, &v76);
            rdMatrix_PostTranslate34(&out, &focusThing->position);
            if ( focusThing->type == SITH_THING_ACTOR || focusThing->type == SITH_THING_PLAYER )
                rdMatrix_PostTranslate34(&out, &focusThing->actorParams.eyeOffset);
            cam->sector = sithCamera_SearchSectorInRadius(0, focusThing->sector, &focusThing->position, &out.scale, 0.02, RAYCAST_2000 | RAYCAST_200);
            rdVector_Copy3(&v84, &out.scale);
            rdMatrix_Copy34(&cam->orient, &out);

            // MOTS added: hmm?
            if (Main_bMotsCompat) {
                rdMatrix_PreTranslate34(&cam->orient,&sithCamera_g_vecCameraPosOffset);
            }

            rdMatrix_PreTranslate34(&out, &sithCamera_trans);
            rdMatrix_PreTranslate34(&cam->orient, &cam->offset);
            rdMatrix_LookAt(&cam->orient, &cam->orient.scale, &out.scale, 0.0);
            cam->sector = sithCamera_SearchSectorInRadius(0, cam->sector, &v84, &cam->orient.scale, 0.02, RAYCAST_2000 | RAYCAST_200);
            break;
        case 32:
            rdMatrix_TransformVector34(&a1, &sithCamera_trans2, &sithCamera_idleCamOrient);
            v2 = (rdVector3){0.0, 0.0, 0.05};
            rdVector_Sub3(&v2, &focusThing->position, &v2);
            rdVector_Add3Acc(&a1, &v2);
            rdMatrix_LookAt(&cam->orient, &a1, &v2, 0.0);
            cam->sector = sithCamera_SearchSectorInRadius(0, focusThing->sector, &focusThing->position, &cam->orient.scale, 0.02, RAYCAST_2000 | RAYCAST_200);
            rot.x = 0.0;
            rot.y = sithTime_g_frameTimeFlex * 8.0;
            rot.z = 0.0;
            rdMatrix_PostRotate34(&sithCamera_idleCamOrient, &rot);
            rdMatrix_Normalize34(&sithCamera_idleCamOrient);
            break;
        case 64:
            rdVector_Normalize3Acc(&sithCamera_trans3);
            rdVector_Neg3(&mode64Tmp, &sithCamera_trans3);
            
            // rdMatrix_BuildFromLook34 ish?
            cam->orient.lvec.x = mode64Tmp.x;
            cam->orient.lvec.y = mode64Tmp.y;
            cam->orient.lvec.z = mode64Tmp.z;
            cam->orient.rvec.x = (1.0 * mode64Tmp.y) - (0.0 * mode64Tmp.z);
            cam->orient.rvec.y = (0.0 * mode64Tmp.z) - (1.0 * mode64Tmp.x);
            cam->orient.rvec.z = (0.0 * mode64Tmp.x) - (0.0 * mode64Tmp.y);
            cam->orient.uvec.x = (cam->orient.rvec.y * mode64Tmp.z) - (cam->orient.rvec.z * mode64Tmp.y);
            cam->orient.uvec.y = (cam->orient.rvec.z * mode64Tmp.x) - (cam->orient.rvec.x * mode64Tmp.z);
            cam->orient.uvec.z = (cam->orient.rvec.x * mode64Tmp.y) - (cam->orient.rvec.y * mode64Tmp.x);

            rdMatrix_Normalize34(&cam->orient);
            rdVector_Scale3(&cam->orient.scale, &sithCamera_trans3, 0.2);

            rdMatrix_PostTranslate34(&cam->orient, &focusThing->position);
            cam->sector = sithCamera_SearchSectorInRadius(0, focusThing->sector, &focusThing->position, &cam->orient.scale, 0.02, RAYCAST_2000 | RAYCAST_200);
            break;
        case 128:
            rdMatrix_Copy34(&cam->orient, &sithCamera_g_orbCamOrient);
            rdMatrix_PostTranslate34(&cam->orient, &focusThing->position);
            cam->sector = sithCollision_FindSectorInRadius(focusThing->sector, &focusThing->position, &cam->orient.scale, 0.02);
            break;
        default:
            break;
    }
    cam->lookPos = cam->orient.scale;
    rdMatrix_ExtractAngles34(&cam->orient, &cam->lookPYR);

    // TODO what inlined func is this
    if ( sithCamera_g_vecCameraPosOffset.x <= 0.0 )
    {
        if ( sithCamera_g_vecCameraPosOffset.x < 0.0 )
        {
            flex_t v42 = v78 + sithCamera_g_vecCameraPosOffset.x;
            if ( v42 < 0.0 )
            {
                sithCamera_g_vecCameraPosOffset.x = v42;
            }
            else {
                sithCamera_g_vecCameraPosOffset.x = 0.0;
            }
        }
        
    }
    else
    {
        flex_t v41 = sithCamera_g_vecCameraPosOffset.x - v78;
        if ( v41 > 0.0 )
        {
            sithCamera_g_vecCameraPosOffset.x = v41;
        }
        else {
            sithCamera_g_vecCameraPosOffset.x = 0.0;
        }
    }

    if ( sithCamera_g_vecCameraPosOffset.y <= 0.0 )
    {
        if ( sithCamera_g_vecCameraPosOffset.y < 0.0 )
        {
            flex_t v48 = v78 + sithCamera_g_vecCameraPosOffset.y;
            if ( v48 < 0.0 )
            {
                sithCamera_g_vecCameraPosOffset.y = v48;
            }
            else {
                sithCamera_g_vecCameraPosOffset.y = 0.0;
            }
        }
    }
    else
    {
        flex_t v47 = sithCamera_g_vecCameraPosOffset.y - v78;
        if ( v47 > 0.0 )
        {
            sithCamera_g_vecCameraPosOffset.y = v47;
        }
        else {
            sithCamera_g_vecCameraPosOffset.y = 0.0;
        }
    }

    if ( sithCamera_g_vecCameraPosOffset.z <= 0.0 )
    {
        if ( sithCamera_g_vecCameraPosOffset.z < 0.0 )
        {
            flex_t v54 = v78 + sithCamera_g_vecCameraPosOffset.z;
            if ( v54 < 0.0 )
            {
                sithCamera_g_vecCameraPosOffset.z = v54;
            }
            else {
                sithCamera_g_vecCameraPosOffset.z = 0.0;
            }
        }
    }
    else
    {
        flex_t v53 = sithCamera_g_vecCameraPosOffset.z - v78;
        if ( v53 > 0.0 )
        {
            sithCamera_g_vecCameraPosOffset.z = v53;
        }
        else {
            sithCamera_g_vecCameraPosOffset.z = 0.0;
        }
    }
    
    if ( sithCamera_g_vecCameraAngleOffset.x <= 0.0 )
    {
        if ( sithCamera_g_vecCameraAngleOffset.x < 0.0 )
        {
            flex_t v60 = v77 + sithCamera_g_vecCameraAngleOffset.x;
            if ( v60 < 0.0 )
            {
                sithCamera_g_vecCameraAngleOffset.x = v60;
            }
            else {
                sithCamera_g_vecCameraAngleOffset.x = 0.0;
            }
        }
    }
    else
    {
        flex_t v59 = sithCamera_g_vecCameraAngleOffset.x - v77;
        if ( v59 > 0.0 )
        {
            sithCamera_g_vecCameraAngleOffset.x = v59;
        }
        else {
            sithCamera_g_vecCameraAngleOffset.x = 0.0;
        }
    }

    if ( sithCamera_g_vecCameraAngleOffset.y <= 0.0 )
    {
        if ( sithCamera_g_vecCameraAngleOffset.y < 0.0 )
        {
            flex_t v66 = v77 + sithCamera_g_vecCameraAngleOffset.y;
            if ( v66 < 0.0 )
            {
                sithCamera_g_vecCameraAngleOffset.y = v66;
            }
            else {
                sithCamera_g_vecCameraAngleOffset.y = 0.0;
            }
        }
        
    }
    else
    {
        flex_t v65 = sithCamera_g_vecCameraAngleOffset.y - v77;
        if ( v65 > 0.0 )
        {
            sithCamera_g_vecCameraAngleOffset.y = v65;
        }
        else {
            sithCamera_g_vecCameraAngleOffset.y = 0.0;
        }
    }
    
    if ( sithCamera_g_vecCameraAngleOffset.z <= 0.0 )
    {
        if ( sithCamera_g_vecCameraAngleOffset.z < 0.0 )
        {
            flex_t v72 = v77 + sithCamera_g_vecCameraAngleOffset.z;
            if ( v72 < 0.0 )
            {
                sithCamera_g_vecCameraAngleOffset.z = v72;
            }
            else {
                sithCamera_g_vecCameraAngleOffset.z = 0.0;
            }
        }
        
    }
    else
    {
        flex_t v71 = sithCamera_g_vecCameraAngleOffset.z - v77;
        if ( v71 > 0.0 )
        {
            sithCamera_g_vecCameraAngleOffset.z = v71;
        }
        else {
            sithCamera_g_vecCameraAngleOffset.z = 0.0;
        }
    }
    
}

void sithCamera_RenderScene()
{
    if ( sithCamera_g_pCurCamera )
    {
        rdCamera_SetCurrent(&sithCamera_g_pCurCamera->rdCamera);
        rdCamera_Update(&sithCamera_g_pCurCamera->orient);
        sithRender_Draw();
    }
}

void sithCamera_SetCurrentToCycleCamera()
{
    SithCamera *v0; // esi

    v0 = &sithCamera_g_aCameras[sithCamera_camIdxToGlobalIdx[sithCamera_g_curCycleCamNum]];
    sithCamera_SetCurrentCamera(v0);
}

int sithCamera_SetCurrentCamera(SithCamera *camera)
{
    rdVector3 rot; // [esp+8h] [ebp-Ch] BYREF

    if ( sithCamera_g_pCurCamera && camera->dword4 < sithCamera_g_pCurCamera->dword4 )
        return 0;
    sithCamera_g_pCurCamera = camera;
    sithCamera_g_bCurCameraSet = 1;
    rdCamera_SetCurrent(&camera->rdCamera);
    if ( camera->type == 32 )
    {
        rdMatrix_Copy34(&sithCamera_idleCamOrient, &sithCamera_g_pCurCamera->pPrimaryFocusThing->orient);
        rot.x = 0.0;
        rot.y = -45.0;
        rot.z = 0.0;
        rdMatrix_PostRotate34(&sithCamera_idleCamOrient, &rot);
    }
    sithCamera_Update(sithCamera_g_pCurCamera);
    return 1;
}

void sithCamera_SetCameraFocus(SithCamera *camera, SithThing *primary, SithThing *secondary)
{
    camera->pPrimaryFocusThing = primary;
    camera->pSecondaryFocusThing = secondary;
}

SithSector* sithCamera_SearchSectorInRadius(SithThing *a3, SithSector *a2, rdVector3 *a4, rdVector3 *a6, flex_t a7, int flags)
{
    flex_d_t v7; // st7
    SithSector *v9; // ebx
    SithCollision *i; // ecx
    rdVector3 a5; // [esp+Ch] [ebp-Ch] BYREF
    flex_t a6a; // [esp+28h] [ebp+10h]

    rdVector_Sub3(&a5, a6, a4);
    v7 = rdVector_Normalize3Acc(&a5);
    a6a = v7;
    v9 = a2;
    sithCollision_SearchForCollisions(a2, a3, a4, &a5, a6a, a7, flags | RAYCAST_800);
    for ( i = sithCollision_PopStack(); i; i = sithCollision_PopStack() )
    {
        if ( (i->type & SITHCOLLISION_ADJOINCROSS) != 0 )
        {
            v9 = i->surface->pAdjoin->sector;
        }
        else if ( (i->type & SITHCOLLISION_THING) == 0 || (i->pThingCollided->type != SITH_THING_ITEM) && i->distance != 0.0 && i->pThingCollided->type != SITH_THING_WEAPON )
        {
            rdVector_Copy3(a6, a4);
            rdVector_ScaleAdd3Acc(a6, &a5, i->distance);
            break;
        }
    }
    sithCollision_DecreaseStackLevel();
    return v9;
}

void sithCamera_SetPOVShake(rdVector3 *a1, rdVector3 *a2, flex_t a3, flex_t a4)
{
    rdVector_Copy3(&sithCamera_g_vecCameraPosOffset, a1);
    rdVector_Copy3(&sithCamera_g_vecCameraAngleOffset, a2);
    sithCamera_g_cameraPosDelta = a3;
    sithCamera_g_cameraAngleDelta = a4;
}

SithThing* sithCamera_GetPrimaryFocus(SithCamera *pCamera)
{
    return pCamera->pPrimaryFocusThing;
}

SithThing* sithCamera_GetSecondaryFocus(SithCamera *pCamera)
{
    return pCamera->pSecondaryFocusThing;
}

int sithCamera_SetCameraStateFlags(int a1)
{
    int result; // eax

    result = a1;
    sithCamera_g_stateFlags = a1;
    return result;
}

int sithCamera_GetCameraStateFlags()
{
    return sithCamera_g_stateFlags;
}

void sithCamera_CycleCamera()
{
    int cam_id; // eax
    SithCamera *v1; // esi
    rdVector3 rot; // [esp+8h] [ebp-Ch] BYREF

    cam_id = ++sithCamera_g_curCycleCamNum;
    if ( (unsigned int)sithCamera_g_curCycleCamNum >= 2 )
    {
        cam_id = 0;
        sithCamera_g_curCycleCamNum = 0;
    }

    v1 = &sithCamera_g_aCameras[sithCamera_camIdxToGlobalIdx[cam_id]];
    sithCamera_SetCurrentCamera(v1);
}

// MOTS added
void sithCamera_SetZoom(SithCamera *pCamera, flex_t zoomScale, flex_t zoomSpeed)
{
    if (!pCamera) return;
    if (!pCamera->rdCamera.pCanvas) return;

#ifdef JKM_CAMERA
#ifdef QOL_IMPROVEMENTS
    flex_t zoomScaleNew = zoomScale;
    if (jkPlayer_fovIsVertical && pCamera->rdCamera.aspectRatio != 0.0) {
        flex_t horFov = (stdMath_ArcTan3(1.0, stdMath_Tan(jkPlayer_fov * 0.5) / pCamera->rdCamera.aspectRatio) *
 -2.0);
        flex_t zoomFov = zoomScale * horFov;
        zoomScaleNew = zoomFov / horFov;
    }

    if (zoomSpeed != 0.0) 
    {
        pCamera->bZoomed = 1;
        pCamera->zoomScaleOrig = zoomScale;
        pCamera->zoomScale = zoomScaleNew;
        pCamera->zoomSpeed = zoomSpeed / 5.0; // TODO find a more exact scalar than just guessing
        pCamera->invZoomScale = 1.0 / zoomScale;
        return;
    }

    rdCamera_SetFOV(&pCamera->rdCamera, jkPlayer_fov / zoomScale);
    pCamera->zoomSpeed = 0.0;
    pCamera->bZoomed = 0;
    pCamera->zoomFov = zoomScale;
#else
    // I have no idea what's going on here
    flex_t zoomFov = stdMath_ArcTan4(zoomScale * 0.5, 0.0);
    zoomFov = -zoomFov * 2.0;

    if (zoomFov != pCamera->rdCamera.fov) 
    {
        if (zoomSpeed != 0.0) 
        {
            pCamera->bZoomed = 1;
            pCamera->zoomScale = zoomScale;
            pCamera->zoomFov = zoomFov;
            pCamera->zoomSpeed = zoomSpeed;
            pCamera->invZoomScale = 1.0 / zoomScale;
            return;
        }

        rdCamera_SetFOV(&pCamera->rdCamera, zoomFov);
        pCamera->zoomSpeed = 0.0;
        pCamera->bZoomed = 0;
    }
#endif
#endif
}

#ifdef QOL_IMPROVEMENTS
// MOTS added (overhauled, zoomFov is now used as a stored scale value)
void sithCamera_UpdateZoom(SithCamera *pCamera)
{
    flex_t currentScale;
    flex_t fVar2;
    int iVar3;
    int iVar4;
    int zoomDirection;

    if (!pCamera->rdCamera.pCanvas) return;

    // Fix zoomscale if screen size changed mid-zoom
    if (jkPlayer_fovIsVertical && pCamera->rdCamera.aspectRatio != 0.0) {
        flex_t horFov = (stdMath_ArcTan3(1.0, stdMath_Tan(jkPlayer_fov * 0.5) / pCamera->rdCamera.aspectRatio) *
 -2.0);
        flex_t zoomFov = pCamera->zoomScaleOrig * horFov;
        pCamera->zoomScale = zoomFov / horFov;
    }

    if (!pCamera->bZoomed) {
        if (Main_bMotsCompat) {
            rdCamera_SetFOV(&sithCamera_g_pCurCamera->rdCamera, jkPlayer_fov / pCamera->zoomScale); 
        }
        //printf("Zoom: en=%x scale=%f, fov=%f, speed=%f, invScale=%f; %x %x %f\n", pCamera->bZoomed, pCamera->zoomScale, pCamera->zoomFov, pCamera->zoomSpeed, pCamera->invZoomScale, 999, 999, jkPlayer_fov / pCamera->zoomScale);
        return;
    }

    currentScale = pCamera->zoomFov;
    fVar2 = pCamera->zoomScale - currentScale;
    if (0.0 <= fVar2) {
        zoomDirection = 1;
        if (fVar2 < 0.0) {
            zoomDirection = 0;
        }
    }
    else {
        zoomDirection = -1;
    }
    fVar2 = currentScale - pCamera->zoomScale;

    flex_t newScale = ((flex_t)zoomDirection * pCamera->zoomSpeed * sithTime_g_frameTimeFlex + currentScale);
    if (fVar2 >= 0.0) {
        if (fVar2 < 0.0) {
            iVar4 = 0;
        }
        else {
            iVar4 = 1;
        }
    }
    else {
        iVar4 = -1;
    }

    fVar2 = newScale - pCamera->zoomScale;
    if (fVar2 >= 0.0) {
        if (fVar2 > 0.0) {
            iVar3 = 1;
        }
        else {
            iVar3 = 0;
        }
    }
    else {
        iVar3 = -1;
    }

    //printf("Zoom: en=%x scale=%f, fov=%f, speed=%f, invScale=%f; %x %x %f %f %f\n", pCamera->bZoomed, pCamera->zoomScale, pCamera->zoomFov, pCamera->zoomSpeed, pCamera->invZoomScale, iVar4, iVar3, newScale, currentScale - pCamera->zoomFov, newScale - pCamera->zoomFov);

    if (iVar4 != iVar3) {
        newScale = pCamera->zoomScale;
    }
    
    // Added: prevent overshoot
    if (zoomDirection < 0) {
        if (newScale < pCamera->zoomScale) {
            newScale = pCamera->zoomScale;
        }
    }
    else if (zoomDirection > 0) {
        if (newScale > pCamera->zoomScale) {
            newScale = pCamera->zoomScale;
        }
    }

    pCamera->zoomFov = newScale;
    rdCamera_SetFOV(&pCamera->rdCamera, jkPlayer_fov / newScale);
    if ((pCamera->zoomFov == currentScale) || (iVar4 != iVar3)) {
        pCamera->zoomSpeed = 0.0;
        pCamera->bZoomed = 0;
    }
}
#else

// MOTS added (original)
void sithCamera_UpdateZoom(SithCamera *pCamera)
{
    flex_t currentFov;
    flex_t fVar2;
    int iVar3;
    int iVar4;
    int zoomDirection;

    if (!pCamera->rdCamera.pCanvas) return;
    if (!pCamera->bZoomed) {

        // Added
        if (Main_bMotsCompat) {
            rdCamera_SetFOV(&sithCamera_g_pCurCamera->rdCamera, jkPlayer_fov / pCamera->zoomScale); 
        }
        return;
    }

    currentFov = pCamera->rdCamera.fov;
    fVar2 = pCamera->zoomFov - currentFov;
    if (0.0 <= fVar2) {
        zoomDirection = 1;
        if (fVar2 < 0.0) {
            zoomDirection = 0;
        }
    }
    else {
        zoomDirection = -1;
    }
    fVar2 = currentFov - pCamera->zoomFov;

    flex_t newFov = ((flex_t)zoomDirection * pCamera->zoomSpeed * sithTime_g_frameTimeFlex + currentFov);
    if (fVar2 >= 0.0) {
        if (fVar2 < 0.0) {
            iVar4 = 0;
        }
        else {
            iVar4 = 1;
        }
    }
    else {
        iVar4 = -1;
    }

    fVar2 = newFov - pCamera->zoomFov;
    if (fVar2 >= 0.0) {
        if (fVar2 > 0.0) {
            iVar3 = 1;
        }
        else {
            iVar3 = 0;
        }
    }
    else {
        iVar3 = -1;
    }

    if (iVar4 != iVar3) {
        newFov = pCamera->zoomFov;
    }
    
    rdCamera_SetFOV(&pCamera->rdCamera, newFov);
    if ((pCamera->rdCamera.fov == currentFov) || (iVar4 != iVar3)) {
        pCamera->zoomSpeed = 0.0;
        pCamera->bZoomed = 0;
    }
}
#endif

