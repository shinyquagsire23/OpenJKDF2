// dwCamera — DroidWorks collision-aware follow camera (see dwCamera.h).
//
// Ghidra (DroidWorks.exe): dwCamera_Reset@0x4655e0, dwCamera_Update@0x4656c0,
// dwCamera_TryPosition@0x465a00. Driven by the engine's camera slot 7
// (SithCamera type 0x100): sithCamera_Update case 0x100 -> dwCamera_Update,
// sithCamera_SetCurrentCamera type-0x100 branch -> dwCamera_Reset.

#include "Dw/dwCamera.h"

#include "Engine/sithCamera.h"
#include "Engine/sithCollision.h"
#include "Primitives/rdMatrix.h"
#include "Primitives/rdVector.h"

// Candidate rings, degrees (binary: .data 0x52d608 / 0x52d630; never written).
flex_t dwCamera_aYawOffsets[9] = { 0.0, 10.0, 20.0, 40.0, 60.0, 90.0, 110.0, 140.0, 180.0 };
flex_t dwCamera_aPitchOffsets[8] = { -20.0, -10.0, 0.0, -40.0, -50.0, -60.0, 20.0, 40.0 };

flex_t dwCamera_curYaw = 0.0;   // binary: .bss 0x5470b8
flex_t dwCamera_curPitch = 0.0; // binary: .bss 0x5470b4

// Note: no binary counterpart — statics reset for the soft-reset loop only.
void dwCamera_Startup()
{
    dwCamera_curYaw = 0.0;
    dwCamera_curPitch = 0.0;
}

// @0x4655e0
void dwCamera_Reset(SithCamera* pPrevCamera, SithCamera* pCamera)
{
    SithThing* pFocus;
    flex_t savedDelta;

    // Skip when re-selecting the camera that is already current.
    if (pPrevCamera && pPrevCamera == sithCamera_g_pCurCamera)
        return;

    pFocus = pCamera->pPrimaryFocusThing;
    pCamera->lookPos = pFocus->position;
    rdVector_Zero3(&pCamera->lookPYR);
    rdMatrix_Copy34(&pCamera->orient, &pFocus->orient);
    pCamera->sector = pFocus->sector;

    // Settle: run one update with the frame delta inflated by +1s so the
    // ease-in covers the whole move in a single step.
    savedDelta = sithTime_g_frameTimeFlex;
    sithTime_g_frameTimeFlex = savedDelta + 1.0;
    dwCamera_curYaw = dwCamera_aYawOffsets[0];
    dwCamera_curPitch = dwCamera_aPitchOffsets[0];
    dwCamera_Update(pCamera);
    sithTime_g_frameTimeFlex = savedDelta;

    pCamera->lookPos = pCamera->orient.scale;
    rdMatrix_ExtractAngles34(&pCamera->orient, &pCamera->lookPYR);
}

// @0x4656c0
void dwCamera_Update(SithCamera* pCamera)
{
    SithThing* pFocus;
    SithSector* pNewSector;
    rdMatrix34 target; // focus placement (head/eye adjusted); scale = look-at point
    rdVector3 newPos;
    rdVector3 moveDir;
    flex_t wantDist, minDist, maxDist;
    flex_t sign;
    flex_t moveDist, clampedDist;
    flex_t yawSigned, pitch;
    uint32_t numYaw, i;
    int bFound, bTriedOtherSign;

    pFocus = pCamera->pPrimaryFocusThing;
    pNewSector = NULL;
    wantDist = pFocus->renderData.model3->radius;
    wantDist = wantDist + wantDist;
    rdMatrix_Copy34(&target, &pFocus->orient);
    minDist = wantDist * 0.75;
    maxDist = wantDist * 2.5;

    if (pFocus->type == SITH_THING_ACTOR || pFocus->type == SITH_THING_PLAYER)
        rdMatrix_PreRotate34(&target, &pFocus->actorParams.headPYR);
    rdMatrix_PostTranslate34(&target, &pFocus->position);
    if (pFocus->type == SITH_THING_ACTOR || pFocus->type == SITH_THING_PLAYER)
        rdMatrix_PostTranslate34(&target, &pFocus->actorParams.eyeOffset);
    rdMatrix_Normalize34(&target);

    bFound = 0;
    // Mirror the yaw ring to the other side first when the last chosen pitch
    // was positive (quirk kept from the binary).
    sign = 1.0;
    if (dwCamera_curPitch > 0.0)
        sign = -1.0;

    bTriedOtherSign = 0;
    numYaw = 6;
    for (;;)
    {
        for (i = 0; i < numYaw && !bFound; i++)
        {
            flex_t yawBase = dwCamera_aYawOffsets[i];
            uint32_t j;
            yawSigned = yawBase * sign;
            for (j = 0; j < 8; j++)
            {
                pitch = dwCamera_aPitchOffsets[j];
                if (dwCamera_TryPosition(pCamera, pitch, yawBase * sign, pFocus, &target,
                                         wantDist, minDist, maxDist,
                                         &newPos, &clampedDist, &moveDir, &moveDist))
                {
                    // Ease toward the accepted candidate at 3 x distance/sec.
                    flex_t step = moveDist * 3.0 * sithTime_g_frameTimeFlex;
                    if (moveDist < step)
                        step = moveDist;
                    newPos.x = step * moveDir.x + pCamera->lookPos.x;
                    newPos.y = step * moveDir.y + pCamera->lookPos.y;
                    newPos.z = step * moveDir.z + pCamera->lookPos.z;
                    pNewSector = sithCamera_SearchSectorInRadius(NULL, pCamera->sector, &pCamera->lookPos, &newPos, 0.02, 0);
                    dwCamera_curYaw = yawSigned;
                    dwCamera_curPitch = pitch;
                    bFound = 1;
                    break;
                }
            }
        }

        if (!bFound)
        {
            if (bTriedOtherSign)
            {
                if (numYaw == 6)
                {
                    // Both signs failed on the narrow ring: widen to all 9 yaws.
                    sign = -sign;
                    numYaw = 9;
                    bTriedOtherSign = 0;
                }
                else
                {
                    // Every candidate failed: force the last chosen angles at
                    // wantDist, whatever they collide with.
                    rdVector3 rot;
                    rot.x = dwCamera_curPitch;
                    rot.y = dwCamera_curYaw;
                    rot.z = 0.0;
                    newPos.x = 0.0;
                    newPos.y = -wantDist;
                    newPos.z = 0.0;
                    rdMatrix_PreRotate34(&target, &rot);
                    rdMatrix_TransformPoint34Acc(&newPos, &target);
                    pNewSector = sithCamera_SearchSectorInRadius(NULL, pFocus->sector, &pFocus->position, &newPos, 0.02, RAYCAST_100 | RAYCAST_200);
                    bFound = 1;
                }
            }
            else
            {
                // Retry the same ring mirrored to the other yaw sign.
                sign = -sign;
                bTriedOtherSign = 1;
            }
        }

        if (bFound)
        {
            pCamera->sector = pNewSector;
            rdMatrix_LookAt(&pCamera->orient, &newPos, &target.scale, 0.0);
            return;
        }
    }
}

// @0x465a00
int dwCamera_TryPosition(SithCamera* pCamera, flex_t pitch, flex_t yaw, SithThing* pFocusThing, const rdMatrix34* pBaseOrient, flex_t wantDist, flex_t minDist, flex_t maxDist, rdVector3* pOutPos, flex_t* pOutClampedDist, rdVector3* pOutMoveDir, flex_t* pOutMoveDist)
{
    rdMatrix34 mat;
    rdVector3 pyr;
    rdVector3 back;
    rdVector3 moveDir;
    rdVector3 candidate;
    SithCollision* pCol;
    flex_t moveDist;
    int bOk = 0;

    pyr.x = pitch;
    pyr.y = yaw;
    pyr.z = 0.0;
    rdMatrix_Copy34(&mat, pBaseOrient);
    rdMatrix_PreRotate34(&mat, &pyr);
    rdVector_Neg3(&back, &mat.lvec);

    // Clamp the backward distance to the nearest obstacle behind the target.
    *pOutClampedDist = wantDist;
    sithCollision_SearchForCollisions(pFocusThing->sector, NULL, &pFocusThing->position, &back, wantDist, 0.02, RAYCAST_100 | RAYCAST_200);
    for (pCol = sithCollision_PopStack(); pCol; pCol = sithCollision_PopStack())
    {
        if (((pCol->type & SITHCOLLISION_THING) && pCol->pThingCollided != pFocusThing)
            || (pCol->type & (SITHCOLLISION_WORLD | SITHCOLLISION_THINGADJOINCROSS)))
        {
            *pOutClampedDist = pCol->distance;
            break;
        }
    }
    sithCollision_DecreaseStackLevel();

    candidate.x = back.x * *pOutClampedDist + pFocusThing->position.x;
    candidate.y = back.y * *pOutClampedDist + pFocusThing->position.y;
    candidate.z = back.z * *pOutClampedDist + pFocusThing->position.z;
    if (*pOutClampedDist < minDist)
        return 0;
    if (maxDist < *pOutClampedDist)
        return 0;

    // Reject when the path from the current camera position to the candidate
    // is blocked short of it.
    rdVector_Sub3(&moveDir, &candidate, &pCamera->lookPos);
    moveDist = rdVector_Normalize3Acc(&moveDir);
    *pOutMoveDist = moveDist;
    sithCollision_SearchForCollisions(pCamera->sector, NULL, &pCamera->lookPos, &moveDir, moveDist, 0.02, RAYCAST_2 | RAYCAST_20 | RAYCAST_200);
    pCol = sithCollision_PopStack();
    if (pCol)
    {
        while (!(pCol->type & SITHCOLLISION_THING) || pCol->pThingCollided == pFocusThing)
        {
            if (pCol->type & (SITHCOLLISION_WORLD | SITHCOLLISION_THINGADJOINCROSS))
                break;
            pCol = sithCollision_PopStack();
            if (!pCol)
                break;
        }
        if (pCol)
        {
            flex_t over = *pOutMoveDist - pCol->distance;
            if (over < 0.0 ? (-over <= 0.00001) : (over <= 0.00001))
                over = 0.0;
            if (over > 0.0)
                goto done; // blocked before reaching the candidate
        }
    }

    bOk = 1;
    *pOutPos = candidate;
    *pOutMoveDir = moveDir;
done:
    sithCollision_DecreaseStackLevel();
    return bOk;
}
