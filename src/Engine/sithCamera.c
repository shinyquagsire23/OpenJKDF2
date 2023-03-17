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
    sithCamera_NewEntry(&sithCamera_cameras[0], 0, 0x1, SITHCAMERA_FOV, SITHCAMERA_ASPECT, NULL, NULL, NULL);
    sithCamera_NewEntry(&sithCamera_cameras[1], 0, 0x4, SITHCAMERA_FOV, SITHCAMERA_ASPECT, NULL, NULL, NULL);
    sithCamera_cameras[1].collisionOffset.x = 0.0;
    sithCamera_cameras[1].collisionOffset.y = -0.2;
    sithCamera_cameras[1].collisionOffset.z = 0.06;
    sithCamera_NewEntry(&sithCamera_cameras[2], 0, 0x8, SITHCAMERA_FOV, SITHCAMERA_ASPECT, NULL, NULL, NULL);
    sithCamera_NewEntry(&sithCamera_cameras[4], 0, 0x20, SITHCAMERA_FOV, SITHCAMERA_ASPECT, NULL, NULL, NULL);
    sithCamera_NewEntry(&sithCamera_cameras[5], 0, 0x40, SITHCAMERA_FOV, SITHCAMERA_ASPECT, NULL, NULL, NULL);
    sithCamera_NewEntry(&sithCamera_cameras[6], 0, 0x80, SITHCAMERA_FOV, SITHCAMERA_ASPECT, NULL, NULL, NULL);
#ifdef DW_CAMERA
    if (Main_bDwCompat) {
        sithCamera_NewEntry(&sithCamera_cameras[7], 0, 0x100, SITHCAMERA_FOV, SITHCAMERA_ASPECT, NULL, NULL, NULL);
    }
#endif
    sithCamera_curCameraIdx = 0;
    sithCamera_bInitted = 1;

    return 1;
}

void sithCamera_Shutdown()
{
    sithCamera_Close(); // Added--moved the rdCamera_FreeEntries where they belong

    // Added: Clean reset
#ifdef DW_CAMERA
    memset(sithCamera_cameras, 0, sizeof(sithCamera) * 8);
#else
    memset(sithCamera_cameras, 0, sizeof(sithCamera) * 7);
#endif

    sithCamera_bInitted = 0;
}

int sithCamera_Open(rdCanvas *canvas, float aspect)
{
    if ( sithCamera_bOpen )
        return 0;

    sithCamera_cameras[0].aspectRatio = aspect;
    rdCamera_NewEntry(&sithCamera_cameras[0].rdCam, sithCamera_cameras[0].rdCam.fov, 0.0, SITHCAMERA_ZNEAR_FIRSTPERSON, SITHCAMERA_ZFAR, aspect);
    rdCamera_SetAttenuation(&sithCamera_cameras[0].rdCam, SITHCAMERA_ATTENUATION_MIN, SITHCAMERA_ATTENUATION_MAX);
    rdCamera_SetCanvas(&sithCamera_cameras[0].rdCam, canvas);
    sithCamera_cameras[1].aspectRatio = aspect;
    rdCamera_NewEntry(&sithCamera_cameras[1].rdCam, sithCamera_cameras[1].rdCam.fov, 0.0, SITHCAMERA_ZNEAR, SITHCAMERA_ZFAR, aspect);
    rdCamera_SetAttenuation(&sithCamera_cameras[1].rdCam, SITHCAMERA_ATTENUATION_MIN, SITHCAMERA_ATTENUATION_MAX);
    rdCamera_SetCanvas(&sithCamera_cameras[1].rdCam, canvas);
    sithCamera_cameras[2].aspectRatio = aspect;
    rdCamera_NewEntry(&sithCamera_cameras[2].rdCam, sithCamera_cameras[2].rdCam.fov, 0.0, SITHCAMERA_ZNEAR, SITHCAMERA_ZFAR, aspect);
    rdCamera_SetAttenuation(&sithCamera_cameras[2].rdCam, SITHCAMERA_ATTENUATION_MIN, SITHCAMERA_ATTENUATION_MAX);
    rdCamera_SetCanvas(&sithCamera_cameras[2].rdCam, canvas);
    sithCamera_cameras[4].aspectRatio = aspect;
    rdCamera_NewEntry(&sithCamera_cameras[4].rdCam, sithCamera_cameras[4].rdCam.fov, 0.0, SITHCAMERA_ZNEAR, SITHCAMERA_ZFAR, aspect);
    rdCamera_SetAttenuation(&sithCamera_cameras[4].rdCam, SITHCAMERA_ATTENUATION_MIN, SITHCAMERA_ATTENUATION_MAX);
    rdCamera_SetCanvas(&sithCamera_cameras[4].rdCam, canvas);
    sithCamera_cameras[5].aspectRatio = aspect;
    rdCamera_NewEntry(&sithCamera_cameras[5].rdCam, sithCamera_cameras[5].rdCam.fov, 0.0, SITHCAMERA_ZNEAR, SITHCAMERA_ZFAR, aspect);
    rdCamera_SetAttenuation(&sithCamera_cameras[5].rdCam, SITHCAMERA_ATTENUATION_MIN, SITHCAMERA_ATTENUATION_MAX);
    rdCamera_SetCanvas(&sithCamera_cameras[5].rdCam, canvas);
    sithCamera_cameras[6].aspectRatio = aspect;
    rdCamera_NewEntry(&sithCamera_cameras[6].rdCam, sithCamera_cameras[6].rdCam.fov, 0.0, SITHCAMERA_ZNEAR, SITHCAMERA_ZFAR, aspect);
    rdCamera_SetAttenuation(&sithCamera_cameras[6].rdCam, SITHCAMERA_ATTENUATION_MIN, SITHCAMERA_ATTENUATION_MAX);
    rdCamera_SetCanvas(&sithCamera_cameras[6].rdCam, canvas);
#ifdef DW_CAMERA
    if (Main_bDwCompat) {
        sithCamera_cameras[7].aspectRatio = aspect;
        rdCamera_NewEntry(&sithCamera_cameras[7].rdCam, sithCamera_cameras[7].rdCam.fov, 0.0, SITHCAMERA_ZNEAR, SITHCAMERA_ZFAR, aspect);
        rdCamera_SetAttenuation(&sithCamera_cameras[7].rdCam, SITHCAMERA_ATTENUATION_MIN, SITHCAMERA_ATTENUATION_MAX);
        rdCamera_SetCanvas(&sithCamera_cameras[7].rdCam, canvas);
    }
#endif // DW_CAMERA
    sithCamera_FollowFocus(sithCamera_currentCamera);
    sithCamera_bOpen = 1;
    return 1;
}

void sithCamera_Close()
{
    if ( sithCamera_bOpen ) {
        sithCamera_bOpen = 0;

        // Added: Prevent UAF
        rdCamera_SetCanvas(&sithCamera_cameras[0].rdCam, NULL);
        rdCamera_SetCanvas(&sithCamera_cameras[1].rdCam, NULL);
        rdCamera_SetCanvas(&sithCamera_cameras[2].rdCam, NULL);
        rdCamera_SetCanvas(&sithCamera_cameras[4].rdCam, NULL);
        rdCamera_SetCanvas(&sithCamera_cameras[5].rdCam, NULL);
        rdCamera_SetCanvas(&sithCamera_cameras[6].rdCam, NULL);
#ifdef DW_CAMERA
        rdCamera_SetCanvas(&sithCamera_cameras[7].rdCam, NULL);
#endif

        // Added: Prevent memleak
        for (int i = 0; i < 7; i++)
        {
            rdCamera_FreeEntry(&sithCamera_cameras[i].rdCam);
        }
#ifdef DW_CAMERA
        if (Main_bDwCompat) {
            rdCamera_FreeEntry(&sithCamera_cameras[7].rdCam);
        }
#endif
    }
}

void sithCamera_SetsFocus()
{
    sithThing *v0; // eax
    rdVector3 rot; // [esp+Ch] [ebp-Ch] BYREF

    v0 = sithWorld_pCurrentWorld->cameraFocus;
    sithCamera_state &= ~1u;
    sithCamera_cameras[0].primaryFocus = v0;
    sithCamera_cameras[1].primaryFocus = v0;
    sithCamera_cameras[2].primaryFocus = v0;
    sithCamera_cameras[2].secondaryFocus = v0;
    sithCamera_cameras[4].primaryFocus = v0;
    sithCamera_cameras[4].secondaryFocus = v0;
    sithCamera_cameras[5].primaryFocus = v0;
    sithCamera_cameras[5].secondaryFocus = v0;
    sithCamera_cameras[6].primaryFocus = v0;
    sithCamera_cameras[6].secondaryFocus = v0;
    sithCamera_dword_8EE5A0 = 0;
    sithCamera_cameras[0].secondaryFocus = 0;
    sithCamera_cameras[1].secondaryFocus = 0;
    if ( !sithCamera_currentCamera || sithCamera_cameras[0].dword4 >= sithCamera_currentCamera->dword4 )
    {
        sithCamera_currentCamera = sithCamera_cameras;
        sithCamera_dword_8EE5A0 = 1;
        rdCamera_SetCurrent(&sithCamera_cameras[0].rdCam);
        if ( sithCamera_cameras[0].cameraPerspective == 32 )
        {
            rdMatrix_Copy34(&sithCamera_focusMat, &sithCamera_currentCamera->primaryFocus->lookOrientation);
            rot.x = 0.0;
            rot.z = 0.0;
            rot.y = -45.0;
            rdMatrix_PostRotate34(&sithCamera_focusMat, &rot);
        }
        sithCamera_FollowFocus(sithCamera_currentCamera);
    }
    sithCamera_curCameraIdx = 0;
}

// MOTS altered
int sithCamera_NewEntry(sithCamera *camera, uint32_t a2, uint32_t a3, float fov, float aspectRatio, rdCanvas *canvas, sithThing *focus_far, sithThing *focus_near)
{
    camera->cameraPerspective = a3;
    camera->dword4 = a2;
    camera->primaryFocus = focus_far;
    camera->fov = fov;
    camera->aspectRatio = aspectRatio;
    camera->secondaryFocus = focus_near;
    rdCamera_NewEntry(&camera->rdCam, fov, 0.0, SITHCAMERA_ZNEAR, SITHCAMERA_ZFAR, aspectRatio);
    rdCamera_SetAttenuation(&camera->rdCam, SITHCAMERA_ATTENUATION_MIN, SITHCAMERA_ATTENUATION_MAX);

    if (canvas) {
        rdCamera_SetCanvas(&camera->rdCam, canvas);
    }

    rdVector_Zero3(&camera->vec3_1);
    rdVector_Zero3(&camera->viewPYR);
    rdVector_Zero3(&camera->collisionOffset);
    rdVector_Zero3(&camera->unused1);
    rdMatrix_Identity34(&camera->viewMat);

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
void sithCamera_FollowFocus(sithCamera *cam)
{
    rdVector3 mode64Tmp;
    rdVector3 v76;
    rdVector3 v2; // [esp+2Ch] [ebp-60h] BYREF
    rdVector3 a1; // [esp+38h] [ebp-54h] BYREF
    rdVector3 v84; // [esp+44h] [ebp-48h] BYREF
    rdVector3 rot; // [esp+50h] [ebp-3Ch] BYREF
    rdMatrix34 out; // [esp+5Ch] [ebp-30h] BYREF

    sithThing* focusThing = cam->primaryFocus;
    float v77 = sithCamera_povShakeF2 * sithTime_deltaSeconds;
    float v78 = sithCamera_povShakeF1 * sithTime_deltaSeconds;
    switch ( cam->cameraPerspective )
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

            rdMatrix_Copy34(&cam->viewMat, &focusThing->lookOrientation);
            if ( focusThing->moveType == SITH_MT_PATH && focusThing->rdthing.hierarchyNodeMatrices)
            {
                rdMatrix_Copy34(&cam->viewMat, focusThing->rdthing.hierarchyNodeMatrices);
            }
            else
            {
                if ( focusThing->type == SITH_THING_ACTOR || focusThing->type == SITH_THING_PLAYER )
                {
                    rdVector_Copy3(&v76, &focusThing->actorParams.eyePYR);
                }
                else
                {
                    rdVector_Zero3(&v76);
                }

                if ( focusThing->moveType == SITH_MT_PHYSICS )
                {
                    v76.z = rdMath_clampf(5.0 * rdVector_Dot3(&focusThing->lookOrientation.rvec, &focusThing->physicsParams.vel), -8.0, 8.0); 
                }

                // MOTS added: hmm??
                if (Main_bMotsCompat || focusThing == sithPlayer_pLocalPlayerThing )
                {
                    rdVector_Add3Acc(&v76, &sithCamera_povShakeVector2);
                }

                rdMatrix_PreRotate34(&cam->viewMat, &v76);
                rdMatrix_PostTranslate34(&cam->viewMat, &focusThing->position);
                if ( focusThing->type == SITH_THING_ACTOR || focusThing->type == SITH_THING_PLAYER )
                {
                    rdMatrix_PreTranslate34(&cam->viewMat, &focusThing->actorParams.eyeOffset);
                    
                    // MOTS added: hmm??
                    if (Main_bMotsCompat || focusThing == sithPlayer_pLocalPlayerThing )
                        rdMatrix_PreTranslate34(&cam->viewMat, &sithCamera_povShakeVector1);
                }
                rdMatrix_Normalize34(&cam->viewMat);
            }
            // Added: nullptr check
            if (focusThing->sector)
                cam->sector = sithCollision_GetSectorLookAt(focusThing->sector, &focusThing->position, &cam->viewMat.scale, 0.02);
            break;
        case 4:
            if ( focusThing->type == SITH_THING_ACTOR || focusThing->type == SITH_THING_PLAYER )
            {
                rdVector_Copy3(&v76, &focusThing->actorParams.eyePYR);
            }
            else
            {
                rdVector_Zero3(&v76);
            }

            // MOTS added: hmm??
            if (Main_bMotsCompat)
            {
                rdVector_Add3Acc(&v76, &sithCamera_povShakeVector2);
            }

            rdMatrix_Copy34(&out, &focusThing->lookOrientation);
            rdMatrix_PreRotate34(&out, &v76);
            rdMatrix_PostTranslate34(&out, &focusThing->position);
            if ( focusThing->type == SITH_THING_ACTOR || focusThing->type == SITH_THING_PLAYER )
                rdMatrix_PostTranslate34(&out, &focusThing->actorParams.eyeOffset);
            cam->sector = sithCamera_create_unk_struct(0, focusThing->sector, &focusThing->position, &out.scale, 0.02, 8704);
            rdVector_Copy3(&v84, &out.scale);
            rdMatrix_Copy34(&cam->viewMat, &out);

            // MOTS added: hmm?
            if (Main_bMotsCompat) {
                rdMatrix_PreTranslate34(&cam->viewMat,&sithCamera_povShakeVector1);
            }

            rdMatrix_PreTranslate34(&out, &sithCamera_trans);
            rdMatrix_PreTranslate34(&cam->viewMat, &cam->collisionOffset);
            rdMatrix_LookAt(&cam->viewMat, &cam->viewMat.scale, &out.scale, 0.0);
            cam->sector = sithCamera_create_unk_struct(0, cam->sector, &v84, &cam->viewMat.scale, 0.02, 8704);
            break;
        case 32:
            rdMatrix_TransformVector34(&a1, &sithCamera_trans2, &sithCamera_focusMat);
            v2 = (rdVector3){0.0, 0.0, 0.05};
            rdVector_Sub3(&v2, &focusThing->position, &v2);
            rdVector_Add3Acc(&a1, &v2);
            rdMatrix_LookAt(&cam->viewMat, &a1, &v2, 0.0);
            cam->sector = sithCamera_create_unk_struct(0, focusThing->sector, &focusThing->position, &cam->viewMat.scale, 0.02, 8704);
            rot.x = 0.0;
            rot.y = sithTime_deltaSeconds * 8.0;
            rot.z = 0.0;
            rdMatrix_PostRotate34(&sithCamera_focusMat, &rot);
            rdMatrix_Normalize34(&sithCamera_focusMat);
            break;
        case 64:
            rdVector_Normalize3Acc(&sithCamera_trans3);
            rdVector_Neg3(&mode64Tmp, &sithCamera_trans3);
            
            // rdMatrix_BuildFromLook34 ish?
            cam->viewMat.lvec.x = mode64Tmp.x;
            cam->viewMat.lvec.y = mode64Tmp.y;
            cam->viewMat.lvec.z = mode64Tmp.z;
            cam->viewMat.rvec.x = (1.0 * mode64Tmp.y) - (0.0 * mode64Tmp.z);
            cam->viewMat.rvec.y = (0.0 * mode64Tmp.z) - (1.0 * mode64Tmp.x);
            cam->viewMat.rvec.z = (0.0 * mode64Tmp.x) - (0.0 * mode64Tmp.y);
            cam->viewMat.uvec.x = (cam->viewMat.rvec.y * mode64Tmp.z) - (cam->viewMat.rvec.z * mode64Tmp.y);
            cam->viewMat.uvec.y = (cam->viewMat.rvec.z * mode64Tmp.x) - (cam->viewMat.rvec.x * mode64Tmp.z);
            cam->viewMat.uvec.z = (cam->viewMat.rvec.x * mode64Tmp.y) - (cam->viewMat.rvec.y * mode64Tmp.x);

            rdMatrix_Normalize34(&cam->viewMat);
            rdVector_Scale3(&cam->viewMat.scale, &sithCamera_trans3, 0.2);

            rdMatrix_PostTranslate34(&cam->viewMat, &focusThing->position);
            cam->sector = sithCamera_create_unk_struct(0, focusThing->sector, &focusThing->position, &cam->viewMat.scale, 0.02, 8704);
            break;
        case 128:
            rdMatrix_Copy34(&cam->viewMat, &sithCamera_viewMat);
            rdMatrix_PostTranslate34(&cam->viewMat, &focusThing->position);
            cam->sector = sithCollision_GetSectorLookAt(focusThing->sector, &focusThing->position, &cam->viewMat.scale, 0.02);
            break;
        default:
            break;
    }
    cam->vec3_1 = cam->viewMat.scale;
    rdMatrix_ExtractAngles34(&cam->viewMat, &cam->viewPYR);

    // TODO what inlined func is this
    if ( sithCamera_povShakeVector1.x <= 0.0 )
    {
        if ( sithCamera_povShakeVector1.x < 0.0 )
        {
            float v42 = v78 + sithCamera_povShakeVector1.x;
            if ( v42 < 0.0 )
            {
                sithCamera_povShakeVector1.x = v42;
            }
            else {
                sithCamera_povShakeVector1.x = 0.0;
            }
        }
        
    }
    else
    {
        float v41 = sithCamera_povShakeVector1.x - v78;
        if ( v41 > 0.0 )
        {
            sithCamera_povShakeVector1.x = v41;
        }
        else {
            sithCamera_povShakeVector1.x = 0.0;
        }
    }

    if ( sithCamera_povShakeVector1.y <= 0.0 )
    {
        if ( sithCamera_povShakeVector1.y < 0.0 )
        {
            float v48 = v78 + sithCamera_povShakeVector1.y;
            if ( v48 < 0.0 )
            {
                sithCamera_povShakeVector1.y = v48;
            }
            else {
                sithCamera_povShakeVector1.y = 0.0;
            }
        }
    }
    else
    {
        float v47 = sithCamera_povShakeVector1.y - v78;
        if ( v47 > 0.0 )
        {
            sithCamera_povShakeVector1.y = v47;
        }
        else {
            sithCamera_povShakeVector1.y = 0.0;
        }
    }

    if ( sithCamera_povShakeVector1.z <= 0.0 )
    {
        if ( sithCamera_povShakeVector1.z < 0.0 )
        {
            float v54 = v78 + sithCamera_povShakeVector1.z;
            if ( v54 < 0.0 )
            {
                sithCamera_povShakeVector1.z = v54;
            }
            else {
                sithCamera_povShakeVector1.z = 0.0;
            }
        }
    }
    else
    {
        float v53 = sithCamera_povShakeVector1.z - v78;
        if ( v53 > 0.0 )
        {
            sithCamera_povShakeVector1.z = v53;
        }
        else {
            sithCamera_povShakeVector1.z = 0.0;
        }
    }
    
    if ( sithCamera_povShakeVector2.x <= 0.0 )
    {
        if ( sithCamera_povShakeVector2.x < 0.0 )
        {
            float v60 = v77 + sithCamera_povShakeVector2.x;
            if ( v60 < 0.0 )
            {
                sithCamera_povShakeVector2.x = v60;
            }
            else {
                sithCamera_povShakeVector2.x = 0.0;
            }
        }
    }
    else
    {
        float v59 = sithCamera_povShakeVector2.x - v77;
        if ( v59 > 0.0 )
        {
            sithCamera_povShakeVector2.x = v59;
        }
        else {
            sithCamera_povShakeVector2.x = 0.0;
        }
    }

    if ( sithCamera_povShakeVector2.y <= 0.0 )
    {
        if ( sithCamera_povShakeVector2.y < 0.0 )
        {
            float v66 = v77 + sithCamera_povShakeVector2.y;
            if ( v66 < 0.0 )
            {
                sithCamera_povShakeVector2.y = v66;
            }
            else {
                sithCamera_povShakeVector2.y = 0.0;
            }
        }
        
    }
    else
    {
        float v65 = sithCamera_povShakeVector2.y - v77;
        if ( v65 > 0.0 )
        {
            sithCamera_povShakeVector2.y = v65;
        }
        else {
            sithCamera_povShakeVector2.y = 0.0;
        }
    }
    
    if ( sithCamera_povShakeVector2.z <= 0.0 )
    {
        if ( sithCamera_povShakeVector2.z < 0.0 )
        {
            float v72 = v77 + sithCamera_povShakeVector2.z;
            if ( v72 < 0.0 )
            {
                sithCamera_povShakeVector2.z = v72;
            }
            else {
                sithCamera_povShakeVector2.z = 0.0;
            }
        }
        
    }
    else
    {
        float v71 = sithCamera_povShakeVector2.z - v77;
        if ( v71 > 0.0 )
        {
            sithCamera_povShakeVector2.z = v71;
        }
        else {
            sithCamera_povShakeVector2.z = 0.0;
        }
    }
    
}

void sithCamera_SetRdCameraAndRenderidk()
{
    if ( sithCamera_currentCamera )
    {
        rdCamera_SetCurrent(&sithCamera_currentCamera->rdCam);
        rdCamera_Update(&sithCamera_currentCamera->viewMat);
        sithRender_Draw();
    }
}

void sithCamera_DoIdleAnimation()
{
    sithCamera *v0; // esi

    v0 = &sithCamera_cameras[sithCamera_camIdxToGlobalIdx[sithCamera_curCameraIdx]];
    sithCamera_SetCurrentCamera(v0);
}

int sithCamera_SetCurrentCamera(sithCamera *camera)
{
    rdVector3 rot; // [esp+8h] [ebp-Ch] BYREF

    if ( sithCamera_currentCamera && camera->dword4 < sithCamera_currentCamera->dword4 )
        return 0;
    sithCamera_currentCamera = camera;
    sithCamera_dword_8EE5A0 = 1;
    rdCamera_SetCurrent(&camera->rdCam);
    if ( camera->cameraPerspective == 32 )
    {
        
        rdMatrix_Copy34(&sithCamera_focusMat, &sithCamera_currentCamera->primaryFocus->lookOrientation);
        rot.x = 0.0;
        rot.y = -45.0;
        rot.z = 0.0;
        rdMatrix_PostRotate34(&sithCamera_focusMat, &rot);
    }
    sithCamera_FollowFocus(sithCamera_currentCamera);
    return 1;
}

void sithCamera_SetCameraFocus(sithCamera *camera, sithThing *primary, sithThing *secondary)
{
    camera->primaryFocus = primary;
    camera->secondaryFocus = secondary;
}

sithSector* sithCamera_create_unk_struct(sithThing *a3, sithSector *a2, rdVector3 *a4, rdVector3 *a6, float a7, int arg14)
{
    double v7; // st7
    sithSector *v9; // ebx
    sithCollisionSearchEntry *i; // ecx
    rdVector3 a5; // [esp+Ch] [ebp-Ch] BYREF
    float a6a; // [esp+28h] [ebp+10h]

    rdVector_Sub3(&a5, a6, a4);
    v7 = rdVector_Normalize3Acc(&a5);
    a6a = v7;
    v9 = a2;
    sithCollision_SearchRadiusForThings(a2, a3, a4, &a5, a6a, a7, arg14 | 0x800);
    for ( i = sithCollision_NextSearchResult(); i; i = sithCollision_NextSearchResult() )
    {
        if ( (i->hitType & SITHCOLLISION_ADJOINCROSS) != 0 )
        {
            v9 = i->surface->adjoin->sector;
        }
        else if ( (i->hitType & SITHCOLLISION_THING) == 0 || (i->receiver->type != SITH_THING_ITEM) && i->distance != 0.0 && i->receiver->type != SITH_THING_WEAPON )
        {
            rdVector_Copy3(a6, a4);
            rdVector_MultAcc3(a6, &a5, i->distance);
            break;
        }
    }
    sithCollision_SearchClose();
    return v9;
}

void sithCamera_SetPovShake(rdVector3 *a1, rdVector3 *a2, float a3, float a4)
{
    rdVector_Copy3(&sithCamera_povShakeVector1, a1);
    rdVector_Copy3(&sithCamera_povShakeVector2, a2);
    sithCamera_povShakeF1 = a3;
    sithCamera_povShakeF2 = a4;
}

sithThing* sithCamera_GetPrimaryFocus(sithCamera *pCamera)
{
    return pCamera->primaryFocus;
}

sithThing* sithCamera_GetSecondaryFocus(sithCamera *pCamera)
{
    return pCamera->secondaryFocus;
}

int sithCamera_SetState(int a1)
{
    int result; // eax

    result = a1;
    sithCamera_state = a1;
    return result;
}

int sithCamera_GetState()
{
    return sithCamera_state;
}

void sithCamera_CycleCamera()
{
    int cam_id; // eax
    sithCamera *v1; // esi
    rdVector3 rot; // [esp+8h] [ebp-Ch] BYREF

    cam_id = ++sithCamera_curCameraIdx;
    if ( (unsigned int)sithCamera_curCameraIdx >= 2 )
    {
        cam_id = 0;
        sithCamera_curCameraIdx = 0;
    }

    v1 = &sithCamera_cameras[sithCamera_camIdxToGlobalIdx[cam_id]];
    sithCamera_SetCurrentCamera(v1);
}

// MOTS added
void sithCamera_SetZoom(sithCamera *pCamera, float zoomScale, float zoomSpeed)
{
    if (!pCamera) return;
    if (!pCamera->rdCam.canvas) return;

#ifdef JKM_CAMERA
#ifdef QOL_IMPROVEMENTS
    float zoomScaleNew = zoomScale;
    if (jkPlayer_fovIsVertical && pCamera->rdCam.screenAspectRatio != 0.0) {
        float horFov = (stdMath_ArcTan3(1.0, stdMath_Tan(jkPlayer_fov * 0.5) / pCamera->rdCam.screenAspectRatio) *
 -2.0);
        float zoomFov = zoomScale * horFov;
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

    rdCamera_SetFOV(&pCamera->rdCam, jkPlayer_fov / zoomScale);
    pCamera->zoomSpeed = 0.0;
    pCamera->bZoomed = 0;
    pCamera->zoomFov = zoomScale;
#else
    // I have no idea what's going on here
    float zoomFov = stdMath_ArcTan4(zoomScale * 0.5, 0.0);
    zoomFov = -zoomFov * 2.0;

    if (zoomFov != pCamera->rdCam.fov) 
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

        rdCamera_SetFOV(&pCamera->rdCam, zoomFov);
        pCamera->zoomSpeed = 0.0;
        pCamera->bZoomed = 0;
    }
#endif
#endif
}

#ifdef QOL_IMPROVEMENTS
// MOTS added (overhauled, zoomFov is now used as a stored scale value)
void sithCamera_UpdateZoom(sithCamera *pCamera)
{
    float currentScale;
    float fVar2;
    int iVar3;
    int iVar4;
    int zoomDirection;

    if (!pCamera->rdCam.canvas) return;

    // Fix zoomscale if screen size changed mid-zoom
    if (jkPlayer_fovIsVertical && pCamera->rdCam.screenAspectRatio != 0.0) {
        float horFov = (stdMath_ArcTan3(1.0, stdMath_Tan(jkPlayer_fov * 0.5) / pCamera->rdCam.screenAspectRatio) *
 -2.0);
        float zoomFov = pCamera->zoomScaleOrig * horFov;
        pCamera->zoomScale = zoomFov / horFov;
    }

    if (!pCamera->bZoomed) {
        if (Main_bMotsCompat) {
            rdCamera_SetFOV(&sithCamera_currentCamera->rdCam, jkPlayer_fov / pCamera->zoomScale); 
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

    float newScale = ((float)zoomDirection * pCamera->zoomSpeed * sithTime_deltaSeconds + currentScale);
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
    rdCamera_SetFOV(&pCamera->rdCam, jkPlayer_fov / newScale);
    if ((pCamera->zoomFov == currentScale) || (iVar4 != iVar3)) {
        pCamera->zoomSpeed = 0.0;
        pCamera->bZoomed = 0;
    }
}
#else

// MOTS added (original)
void sithCamera_UpdateZoom(sithCamera *pCamera)
{
    float currentFov;
    float fVar2;
    int iVar3;
    int iVar4;
    int zoomDirection;

    if (!pCamera->rdCam.canvas) return;
    if (!pCamera->bZoomed) {

        // Added
        if (Main_bMotsCompat) {
            rdCamera_SetFOV(&sithCamera_currentCamera->rdCam, jkPlayer_fov / pCamera->zoomScale); 
        }
        return;
    }

    currentFov = pCamera->rdCam.fov;
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

    float newFov = ((float)zoomDirection * pCamera->zoomSpeed * sithTime_deltaSeconds + currentFov);
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
    
    rdCamera_SetFOV(&pCamera->rdCam, newFov);
    if ((pCamera->rdCam.fov == currentFov) || (iVar4 != iVar3)) {
        pCamera->zoomSpeed = 0.0;
        pCamera->bZoomed = 0;
    }
}
#endif

