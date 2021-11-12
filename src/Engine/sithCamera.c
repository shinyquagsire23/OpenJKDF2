#include "sithCamera.h"

#include "World/sithSector.h"
#include "World/sithThing.h"
#include "World/sithWorld.h"
#include "World/jkPlayer.h"
#include "World/sithUnk3.h"
#include "Primitives/rdMath.h"
#include "Primitives/rdVector.h"
#include "Primitives/rdMatrix.h"
#include "Engine/sithTime.h"
#include "Engine/rdCamera.h"
#include "Engine/sithRender.h"
#include "Engine/sithAdjoin.h"
#include "jk.h"

static rdVector3 sithCamera_trans = {0.0, 0.3, 0.0};
static rdVector3 sithCamera_trans2 = {0.0, 0.2, 0.0};
static rdVector3 sithCamera_trans3 = {0.0, 1.0, 1.0};
static int sithCamera_camIdxToGlobalIdx[2] = {0,1};

#define SITHCAMERA_FOV (90.0)
#define SITHCAMERA_ASPECT (1.0)

int sithCamera_Startup()
{
    sithCamera_NewEntry(&sithCamera_cameras[0], 0, 1, SITHCAMERA_FOV, SITHCAMERA_ASPECT, NULL, NULL, NULL);
    sithCamera_NewEntry(&sithCamera_cameras[1], 0, 4, SITHCAMERA_FOV, SITHCAMERA_ASPECT, NULL, NULL, NULL);
    sithCamera_cameras[1].vec3_3.x = 0.0;
    sithCamera_cameras[1].vec3_3.y = -0.2;
    sithCamera_cameras[1].vec3_3.z = 0.059999999;
    sithCamera_NewEntry(&sithCamera_cameras[2], 0, 8, SITHCAMERA_FOV, SITHCAMERA_ASPECT, NULL, NULL, NULL);
    sithCamera_NewEntry(&sithCamera_cameras[4], 0, 32, SITHCAMERA_FOV, SITHCAMERA_ASPECT, NULL, NULL, NULL);
    sithCamera_NewEntry(&sithCamera_cameras[5], 0, 64, SITHCAMERA_FOV, SITHCAMERA_ASPECT, NULL, NULL, NULL);
    sithCamera_NewEntry(&sithCamera_cameras[6], 0, 128, SITHCAMERA_FOV, SITHCAMERA_ASPECT, NULL, NULL, NULL);
    sithCamera_curCameraIdx = 0;
    sithCamera_bInitted = 1;

    return 1;
}

int sithCamera_Open(rdCanvas *canvas, float aspect)
{
    if ( sithCamera_bOpen )
        return 0;

    sithCamera_cameras[0].aspectRatio = aspect;
    rdCamera_NewEntry(&sithCamera_cameras[0].rdCam, sithCamera_cameras[0].rdCam.fov, 0.0, 1.0/64.0, 64.0, aspect);
    rdCamera_SetAttenuation(&sithCamera_cameras[0].rdCam, 0.40000001, 0.80000001);
    rdCamera_SetCanvas(&sithCamera_cameras[0].rdCam, canvas);
    sithCamera_cameras[1].aspectRatio = aspect;
    rdCamera_NewEntry(&sithCamera_cameras[1].rdCam, sithCamera_cameras[1].rdCam.fov, 0.0, 1.0/64.0, 64.0, aspect);
    rdCamera_SetAttenuation(&sithCamera_cameras[1].rdCam, 0.40000001, 0.80000001);
    rdCamera_SetCanvas(&sithCamera_cameras[1].rdCam, canvas);
    sithCamera_cameras[2].aspectRatio = aspect;
    rdCamera_NewEntry(&sithCamera_cameras[2].rdCam, sithCamera_cameras[2].rdCam.fov, 0.0, 1.0/64.0, 64.0, aspect);
    rdCamera_SetAttenuation(&sithCamera_cameras[2].rdCam, 0.40000001, 0.80000001);
    rdCamera_SetCanvas(&sithCamera_cameras[2].rdCam, canvas);
    sithCamera_cameras[4].aspectRatio = aspect;
    rdCamera_NewEntry(&sithCamera_cameras[4].rdCam, sithCamera_cameras[4].rdCam.fov, 0.0, 1.0/64.0, 64.0, aspect);
    rdCamera_SetAttenuation(&sithCamera_cameras[4].rdCam, 0.40000001, 0.80000001);
    rdCamera_SetCanvas(&sithCamera_cameras[4].rdCam, canvas);
    sithCamera_cameras[5].aspectRatio = aspect;
    rdCamera_NewEntry(&sithCamera_cameras[5].rdCam, sithCamera_cameras[5].rdCam.fov, 0.0, 1.0/64.0, 64.0, aspect);
    rdCamera_SetAttenuation(&sithCamera_cameras[5].rdCam, 0.40000001, 0.80000001);
    rdCamera_SetCanvas(&sithCamera_cameras[5].rdCam, canvas);
    sithCamera_cameras[6].aspectRatio = aspect;
    rdCamera_NewEntry(&sithCamera_cameras[6].rdCam, sithCamera_cameras[6].rdCam.fov, 0.0, 1.0/64.0, 64.0, aspect);
    rdCamera_SetAttenuation(&sithCamera_cameras[6].rdCam, 0.40000001, 0.80000001);
    rdCamera_SetCanvas(&sithCamera_cameras[6].rdCam, canvas);
    sithCamera_FollowFocus(sithCamera_currentCamera);
    sithCamera_bOpen = 1;
    return 1;
}

void sithCamera_Close()
{
    if ( sithCamera_bOpen )
        sithCamera_bOpen = 0;
}

void sithCamera_SetsFocus()
{
    sithThing *v0; // eax
    rdVector3 rot; // [esp+Ch] [ebp-Ch] BYREF

    v0 = sithWorld_pCurWorld->cameraFocus;
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

int sithCamera_NewEntry(sithCamera *camera, uint32_t a2, uint32_t a3, float fov, float aspectRatio, rdCanvas *canvas, sithThing *focus_far, sithThing *focus_near)
{
    camera->cameraPerspective = a3;
    camera->dword4 = a2;
    camera->primaryFocus = focus_far;
    camera->fov = fov;
    camera->aspectRatio = aspectRatio;
    camera->secondaryFocus = focus_near;
    rdCamera_NewEntry(&camera->rdCam, fov, 0.0, 1.0/64.0, 64.0, aspectRatio);
    rdCamera_SetAttenuation(&camera->rdCam, 0.40000001, 0.80000001);

    if (canvas)
        rdCamera_SetCanvas(&camera->rdCam, canvas);

    rdVector_Zero3(&camera->vec3_1);
    rdVector_Zero3(&camera->vec3_2);
    rdVector_Zero3(&camera->vec3_3);
    rdVector_Zero3(&camera->vec3_4);
    rdMatrix_Identity34(&camera->viewMat);

    return 1;
}

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
            rdMatrix_Copy34(&cam->viewMat, &focusThing->lookOrientation);
            if ( focusThing->move_type == SITH_MT_PATH && focusThing->rdthing.hierarchyNodeMatrices)
            {
                rdMatrix_Copy34(&cam->viewMat, focusThing->rdthing.hierarchyNodeMatrices);
            }
            else
            {
                if ( focusThing->thingType == THINGTYPE_ACTOR || focusThing->thingType == THINGTYPE_PLAYER )
                {
                    rdVector_Copy3(&v76, &focusThing->actorParams.eyePYR);
                }
                else
                {
                    rdVector_Zero3(&v76);
                }

                if ( focusThing->move_type == SITH_MT_PHYSICS )
                {
                    v76.z = rdMath_clampf(5.0 * rdVector_Dot3(&focusThing->lookOrientation.rvec, &focusThing->physicsParams.vel), -8.0, 8.0); 
                }
                if ( focusThing == g_localPlayerThing )
                {
                    rdVector_Add3Acc(&v76, &sithCamera_povShakeVector2);
                }
                rdMatrix_PreRotate34(&cam->viewMat, &v76);
                rdMatrix_PostTranslate34(&cam->viewMat, &focusThing->position);
                if ( focusThing->thingType == THINGTYPE_ACTOR || focusThing->thingType == THINGTYPE_PLAYER )
                {
                    rdMatrix_PreTranslate34(&cam->viewMat, &focusThing->actorParams.eyeOffset);
                    if ( focusThing == g_localPlayerThing )
                        rdMatrix_PreTranslate34(&cam->viewMat, &sithCamera_povShakeVector1);
                }
                rdMatrix_Normalize34(&cam->viewMat);
            }
            // Added: nullptr check
            if (focusThing->sector)
                cam->sector = sithUnk3_GetSectorLookAt(focusThing->sector, &focusThing->position, &cam->viewMat.scale, 0.02);
            break;
        case 4:
            if ( focusThing->thingType == THINGTYPE_ACTOR || focusThing->thingType == THINGTYPE_PLAYER )
            {
                rdVector_Copy3(&v76, &focusThing->actorParams.eyePYR);
            }
            else
            {
                rdVector_Zero3(&v76);
            }
            rdMatrix_Copy34(&out, &focusThing->lookOrientation);
            rdMatrix_PreRotate34(&out, &v76);
            rdMatrix_PostTranslate34(&out, &focusThing->position);
            if ( focusThing->thingType == THINGTYPE_ACTOR || focusThing->thingType == THINGTYPE_PLAYER )
                rdMatrix_PostTranslate34(&out, &focusThing->actorParams.eyeOffset);
            cam->sector = sithCamera_create_unk_struct(0, focusThing->sector, &focusThing->position, &out.scale, 0.02, 8704);
            rdVector_Copy3(&v84, &out.scale);
            rdMatrix_Copy34(&cam->viewMat, &out);
            rdMatrix_PreTranslate34(&out, &sithCamera_trans);
            rdMatrix_PreTranslate34(&cam->viewMat, &cam->vec3_3);
            rdMatrix_LookAt(&cam->viewMat, &cam->viewMat.scale, &out.scale, 0.0);
            cam->sector = sithCamera_create_unk_struct(0, cam->sector, &v84, &cam->viewMat.scale, 0.02, 8704);
            break;
        case 32:
            rdMatrix_TransformVector34(&a1, &sithCamera_trans2, &sithCamera_focusMat);
            v2 = (rdVector3){0.0, 0.0, 0.050000001};
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
            
            cam->viewMat.lvec.x = mode64Tmp.x;
            cam->viewMat.lvec.y = mode64Tmp.y;
            cam->viewMat.lvec.z = mode64Tmp.z;
            cam->viewMat.rvec.x = (1.0 * mode64Tmp.y) - (0.0 * mode64Tmp.z);
            cam->viewMat.rvec.y = (0.0 * mode64Tmp.z) - (1.0 * mode64Tmp.x);
            cam->viewMat.rvec.z = (0.0 * mode64Tmp.x) - (0.0 * mode64Tmp.y);
            cam->viewMat.uvec.x = (((0.0 * mode64Tmp.z) - (1.0 * mode64Tmp.x)) * mode64Tmp.z) - (((0.0 * mode64Tmp.x) - (0.0 * mode64Tmp.y)) * mode64Tmp.y);
            cam->viewMat.uvec.y = (((0.0 * mode64Tmp.x) - (0.0 * mode64Tmp.y)) * mode64Tmp.x) - ((1.0 * mode64Tmp.y) - (0.0 * mode64Tmp.z)) * mode64Tmp.z;
            cam->viewMat.uvec.z = (((1.0 * mode64Tmp.y) - (0.0 * mode64Tmp.z)) * mode64Tmp.y) - (((0.0 * mode64Tmp.z) - (1.0 * mode64Tmp.x)) * mode64Tmp.x);

            rdMatrix_Normalize34(&cam->viewMat);
            rdVector_Scale3(&cam->viewMat.scale, &sithCamera_trans3, 0.2);

            rdMatrix_PostTranslate34(&cam->viewMat, &focusThing->position);
            cam->sector = sithCamera_create_unk_struct(0, focusThing->sector, &focusThing->position, &cam->viewMat.scale, 0.02, 8704);
            break;
        case 128:
            rdMatrix_Copy34(&cam->viewMat, &sithCamera_viewMat);
            rdMatrix_PostTranslate34(&cam->viewMat, &focusThing->position);
            cam->sector = sithUnk3_GetSectorLookAt(focusThing->sector, &focusThing->position, &cam->viewMat.scale, 0.02);
            break;
        default:
            break;
    }
    cam->vec3_1 = cam->viewMat.scale;
    rdMatrix_ExtractAngles34(&cam->viewMat, &cam->vec3_2);

    // TODO what inlined func is this
    if ( sithCamera_povShakeVector1.x < 0.0 )
    {
        if ( sithCamera_povShakeVector1.x >= 0.0 )
            goto LABEL_42;
        float v42 = v78 + sithCamera_povShakeVector1.x;
        if ( v42 < 0.0 )
        {
            sithCamera_povShakeVector1.x = v42;
            goto LABEL_42;
        }
    }
    else
    {
        float v41 = sithCamera_povShakeVector1.x - v78;
        if ( v41 > 0.0 )
        {
            sithCamera_povShakeVector1.x = v41;
            goto LABEL_42;
        }
    }
    sithCamera_povShakeVector1.x = 0.0;
LABEL_42:

    if ( sithCamera_povShakeVector1.y < 0.0 )
    {
        if ( sithCamera_povShakeVector1.y >= 0.0 )
            goto LABEL_49;
        float v48 = v78 + sithCamera_povShakeVector1.y;
        if ( v48 < 0.0 )
        {
            sithCamera_povShakeVector1.y = v48;
            goto LABEL_49;
        }
    }
    else
    {
        float v47 = sithCamera_povShakeVector1.y - v78;
        if ( v47 > 0.0 )
        {
            sithCamera_povShakeVector1.y = v47;
            goto LABEL_49;
        }
    }
    sithCamera_povShakeVector1.y = 0.0;
LABEL_49:
    if ( sithCamera_povShakeVector1.z < 0.0 )
    {
        if ( sithCamera_povShakeVector1.z >= 0.0 )
            goto LABEL_56;
        float v54 = v78 + sithCamera_povShakeVector1.z;
        if ( v54 < 0.0 )
        {
            sithCamera_povShakeVector1.z = v54;
            goto LABEL_56;
        }
    }
    else
    {
        float v53 = sithCamera_povShakeVector1.z - v78;
        if ( v53 > 0.0 )
        {
            sithCamera_povShakeVector1.z = v53;
            goto LABEL_56;
        }
    }
    sithCamera_povShakeVector1.z = 0.0;
LABEL_56:
    if ( sithCamera_povShakeVector2.x < 0.0 )
    {
        if ( sithCamera_povShakeVector2.x >= 0.0 )
            goto LABEL_63;
        float v60 = v77 + sithCamera_povShakeVector2.x;
        if ( v60 < 0.0 )
        {
            sithCamera_povShakeVector2.x = v60;
            goto LABEL_63;
        }
    }
    else
    {
        float v59 = sithCamera_povShakeVector2.x - v77;
        if ( v59 > 0.0 )
        {
            sithCamera_povShakeVector2.x = v59;
            goto LABEL_63;
        }
    }
    sithCamera_povShakeVector2.x = 0.0;
LABEL_63:
    if ( sithCamera_povShakeVector2.y < 0.0 )
    {
        if ( sithCamera_povShakeVector2.y >= 0.0 )
            goto LABEL_70;
        float v66 = v77 + sithCamera_povShakeVector2.y;
        if ( v66 < 0.0 )
        {
            sithCamera_povShakeVector2.y = v66;
            goto LABEL_70;
        }
    }
    else
    {
        float v65 = sithCamera_povShakeVector2.y - v77;
        if ( v65 > 0.0 )
        {
            sithCamera_povShakeVector2.y = v65;
            goto LABEL_70;
        }
    }
    sithCamera_povShakeVector2.y = 0.0;
LABEL_70:
    if ( sithCamera_povShakeVector2.z < 0.0 )
    {
        if ( sithCamera_povShakeVector2.z >= 0.0 )
            return;
        float v72 = v77 + sithCamera_povShakeVector2.z;
        if ( v72 < 0.0 )
        {
            sithCamera_povShakeVector2.z = v72;
            return;
        }
    }
    else
    {
        float v71 = sithCamera_povShakeVector2.z - v77;
        if ( v71 > 0.0 )
        {
            sithCamera_povShakeVector2.z = v71;
            return;
        }
    }
    sithCamera_povShakeVector2.z = 0.0;
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
    int v8; // ecx
    sithSector *v9; // ebx
    sithUnk3SearchEntry *i; // ecx
    double v12; // st6
    double v13; // st7
    rdVector3 a5; // [esp+Ch] [ebp-Ch] BYREF
    float a6a; // [esp+28h] [ebp+10h]

    a5.x = a6->x - a4->x;
    a5.y = a6->y - a4->y;
    a5.z = a6->z - a4->z;
    v7 = rdVector_Normalize3Acc(&a5);
    v8 = arg14;
    a6a = v7;
    v8 |= 0x800;
    v9 = a2;
    sithUnk3_SearchRadiusForThings(a2, a3, a4, &a5, a6a, a7, v8);
    for ( i = sithUnk3_NextSearchResult(); i; i = sithUnk3_NextSearchResult() )
    {
        if ( (i->collideType & 0x20) != 0 )
        {
            v9 = i->surface->adjoin->sector;
        }
        else if ( (i->collideType & 1) == 0 || (i->receiver->thingType != THINGTYPE_ITEM) && i->distance != 0.0 && i->receiver->thingType != THINGTYPE_WEAPON )
        {
            v12 = i->distance * a5.y + a4->y;
            v13 = i->distance * a5.z + a4->z;
            a6->x = i->distance * a5.x + a4->x;
            a6->y = v12;
            a6->z = v13;
            break;
        }
    }
    sithUnk3_SearchClose();
    return v9;
}

void sithCamera_SetPovShake(rdVector3 *a1, rdVector3 *a2, float a3, float a4)
{
    float v4; // eax
    float v5; // eax
    float v6; // ecx

    sithCamera_povShakeVector1.x = a1->x;
    sithCamera_povShakeVector1.y = a1->y;
    v4 = a1->z;
    sithCamera_povShakeVector2.x = a2->x;
    sithCamera_povShakeVector1.z = v4;
    v5 = a2->y;
    sithCamera_povShakeF1 = a3;
    sithCamera_povShakeVector2.y = v5;
    v6 = a2->z;
    sithCamera_povShakeF2 = a4;
    sithCamera_povShakeVector2.z = v6;
}

sithThing* sithCamera_GetPrimaryFocus(sithCamera *cam)
{
    return cam->primaryFocus;
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
    if ( !sithCamera_currentCamera || v1->dword4 >= sithCamera_currentCamera->dword4 )
    {
        sithCamera_currentCamera = &sithCamera_cameras[sithCamera_camIdxToGlobalIdx[cam_id]];
        sithCamera_dword_8EE5A0 = 1;
        rdCamera_SetCurrent(&v1->rdCam);
        if ( v1->cameraPerspective == 32 )
        {
            rdMatrix_Copy34(&sithCamera_focusMat, &sithCamera_currentCamera->primaryFocus->lookOrientation);
            rot.x = 0.0;
            rot.y = -45.0;
            rot.z = 0.0;
            rdMatrix_PostRotate34(&sithCamera_focusMat, &rot);
        }
        sithCamera_FollowFocus(sithCamera_currentCamera);
    }
}
