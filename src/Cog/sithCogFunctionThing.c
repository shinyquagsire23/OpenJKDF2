#include "sithCogFunctionThing.h"

#include <stdint.h>
#include "World/sithSector.h"
#include "World/sithThing.h"
#include "World/sithTrackThing.h"
#include "Gameplay/sithInventory.h"
#include "World/jkPlayer.h"
#include "World/sithItem.h"
#include "Engine/sithCollision.h"
#include "Engine/sithCamera.h"
#include "Engine/rdThing.h"
#include "World/sithSurface.h"
#include "Engine/sithPuppet.h"
#include "Gameplay/sithTime.h"
#include "Engine/sithAnimClass.h"
#include "Engine/sithPhysics.h"
//#include "Engine/rdSurface.h"
#include "Dss/sithDSSThing.h"
#include "Dss/sithDSSCog.h"
#include "General/stdConffile.h"
#include "stdPlatform.h"
#include "Devices/sithConsole.h"
#include "Main/Main.h"
#include "jk.h"

void sithCogFunctionThing_createThingAtPos_nr_Mots(sithCog *ctx, int idk, SithThing* pThingIn);
void sithCogFunctionThing_createThingAtPos_nr(sithCog *ctx, int idk);

void sithCogFunctionThing_GetThingType(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing)
        sithCogExec_PushInt(pCog, pThing->type);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionThing_CreateThing(sithCog *pCog)
{
    SithThing *v1; // esi
    SithThing *v2; // ebx
    SithThing *v3; // edi

    v1 = sithCogExec_PopThing(pCog);
    v2 = sithCogExec_PopTemplate(pCog);
    if ( v1 && v1->type && v1->sector && v2 && (v3 = sithThing_CreateThing(v2, v1)) != 0 )
    {
        if ( COG_SHOULD_SYNC(pCog) )
        {
            sithDSSThing_CreateThing(v2, v3, v1, 0, 0, 0, 255, 1);
        }
        sithCogExec_PushInt(pCog, v3->idx);
    }
    else
    {
        sithCogExec_PushInt(pCog, -1);
    }
}


void sithCogFunctionThing_CreateThingNr(sithCog *pCog)
{
    SithThing *v1; // esi
    SithThing *v2; // ebx
    SithThing *v3; // edi

    v1 = sithCogExec_PopThing(pCog);
    v2 = sithCogExec_PopTemplate(pCog);
    if ( v1 && v1->type && v1->sector && v2 && (v3 = sithThing_CreateThing(v2, v1)) != 0 )
    {
        if ( COG_SHOULD_SYNC(pCog) )
        {
            sithDSSThing_CreateThing(v2, v3, v1, 0, 0, 0, 255, 1);
        }
        sithCogExec_PushInt(pCog, v3->idx);
    }
    else
    {
        sithCogExec_PushInt(pCog, -1);
    }
}

void sithCogFunctionThing_createThingUnused(sithCog *pCog)
{
    SithThing *v1; // esi
    SithThing *v2; // ebx
    SithThing *v3; // edi
    int v6; // [esp+18h] [ebp+8h]

    v6 = 0; // aaaaaa original is undefined

    v1 = sithCogExec_PopThing(pCog);
    v2 = sithCogExec_PopTemplate(pCog);
    if ( v1 && v1->type && v1->sector && v2 && (v3 = sithThing_CreateThing(v2, v1)) != 0 )
    {
        if ( COG_SHOULD_SYNC(pCog) )
        {
            sithDSSThing_CreateThing(v2, v3, v1, 0, 0, 0, 255, v6);
        }
        sithCogExec_PushInt(pCog, v3->idx);
    }
    else
    {
        sithCogExec_PushInt(pCog, -1);
    }
}

// MOTS added
void sithCogFunctionThing_CreateThingLocal(sithCog *pCog)
{
    SithThing *v1; // esi
    SithThing *v2; // ebx
    SithThing *v3; // edi

    v1 = sithCogExec_PopThing(pCog);
    v2 = sithCogExec_PopTemplate(pCog);
    if ( v1 && v1->type && v1->sector && v2 && (v3 = sithThing_CreateThing(v2, v1)) != 0 )
    {
        sithCogExec_PushInt(pCog, v3->idx);
    }
    else
    {
        sithCogExec_PushInt(pCog, -1);
    }
}

// MOTS added
void sithCogFunctionThing_CreateThingAtPosMots(sithCog *pCog)
{
    sithCogFunctionThing_createThingAtPos_nr_Mots(pCog, 0, NULL);
}

// MOTS added
void sithCogFunctionThing_CreateThingAtPosOwner(sithCog *pCog)
{
    SithThing* pThingIn = sithCogExec_PopThing(pCog);
    sithCogFunctionThing_createThingAtPos_nr_Mots(pCog, 0, pThingIn);
}

void sithCogFunctionThing_CreateThingAtPosNrMots(sithCog *pCog)
{
    sithCogFunctionThing_createThingAtPos_nr_Mots(pCog, 0, NULL);
}

// MOTS added
void sithCogFunctionThing_createThingAtPos_nr_Mots(sithCog *pCog, int idk, SithThing* pThingIn)
{
    SithSector *popSector; // ebp
    SithThing *popTemplate; // eax
    rdVector3 *v5; // eax
    rdVector3 *v6; // ecx
    SithThing *v7; // ebx
    rdVector3 a1; // [esp+10h] [ebp-54h]
    rdVector3 pos; // [esp+1Ch] [ebp-48h]
    rdVector3 rot; // [esp+28h] [ebp-3Ch]
    rdMatrix34 a3; // [esp+34h] [ebp-30h]

    sithCogExec_PopVector(pCog, &rot);
    sithCogExec_PopVector(pCog, &pos);
    popSector = sithCogExec_PopSector(pCog);
    popTemplate = sithCogExec_PopTemplate(pCog);
    if ( !popTemplate || !popSector )
    {
        sithCogExec_PushInt(pCog, -1);
        return;
    }
    if (popTemplate->renderData.type == RD_THING_MODEL3)
    {
        a1 = popTemplate->renderData.model3->insertOffset;
    }
    else if (popTemplate->renderData.type == RD_THING_SPRITE3)
    {
        a1 = popTemplate->renderData.sprite3->offset;
    }
    else
    {
        rdVector_Zero3(&a1);
    }
    
    rdVector3 rot_2;
    rdVector_Zero3(&rot_2);
    rdMatrix_BuildRotate34(&a3, &rot_2);
    rdMatrix_TransformVector34Acc(&a1, &a3);
    rdVector_Add3Acc(&pos, &a1);

    v7 = sithThing_CreateThingAtPos(popTemplate, &pos, &a3, popSector, pThingIn);
    if ( v7 )
    {
        if (!rdVector_IsZero3(&rot)) {
            rdVector_Normalize3Acc(&rot);
            rdMatrix_BuildFromLook34(&v7->orient,&rot);
        }

        if ( COG_SHOULD_SYNC(pCog) )
        {
            if (pThingIn) {
                sithDSSThing_SendMOTSNew1(popTemplate, v7, NULL, popSector, &pos, &rot, 0xff, idk); // MOTS added
                sithCogExec_PushInt(pCog, v7->idx);
                return;
            }
            sithDSSThing_CreateThing(popTemplate, v7, 0, popSector, &pos, &rot, 255, idk);
        }
        sithCogExec_PushInt(pCog, v7->idx);
    }
    else
    {
        sithCogExec_PushInt(pCog, -1);
    }
}

void sithCogFunctionThing_CreateThingAtPos(sithCog *pCog)
{
    sithCogFunctionThing_createThingAtPos_nr(pCog, 1);
}

void sithCogFunctionThing_CreateThingAtPosNr(sithCog *pCog)
{
    sithCogFunctionThing_createThingAtPos_nr(pCog, 0);
}

void sithCogFunctionThing_createThingAtPos_nr(sithCog *pCog, int idk)
{
    SithSector *popSector; // ebp
    SithThing *popTemplate; // eax
    rdVector3 *v5; // eax
    rdVector3 *v6; // ecx
    SithThing *v7; // ebx
    rdVector3 a1; // [esp+10h] [ebp-54h]
    rdVector3 pos; // [esp+1Ch] [ebp-48h]
    rdVector3 rot; // [esp+28h] [ebp-3Ch]
    rdMatrix34 a3; // [esp+34h] [ebp-30h]

    sithCogExec_PopVector(pCog, &rot);
    sithCogExec_PopVector(pCog, &pos);
    popSector = sithCogExec_PopSector(pCog);
    popTemplate = sithCogExec_PopTemplate(pCog);
    if ( !popTemplate || !popSector )
    {
        sithCogExec_PushInt(pCog, -1);
        return;
    }
    if (popTemplate->renderData.type == RD_THING_MODEL3)
    {
        a1 = popTemplate->renderData.model3->insertOffset;
    }
    else if (popTemplate->renderData.type == RD_THING_SPRITE3)
    {
        a1 = popTemplate->renderData.sprite3->offset;
    }
    else
    {
       rdVector_Zero3(&a1);
    }
    
    rdMatrix_BuildRotate34(&a3, &rot);
    rdMatrix_TransformVector34Acc(&a1, &a3);
    rdVector_Add3Acc(&pos, &a1);
    v7 = sithThing_CreateThingAtPos(popTemplate, &pos, &a3, popSector, 0);
    if ( v7 )
    {
        if ( COG_SHOULD_SYNC(pCog) )
        {
            sithDSSThing_CreateThing(popTemplate, v7, 0, popSector, &pos, &rot, 255, idk);
        }
        sithCogExec_PushInt(pCog, v7->idx);
    }
    else
    {
        sithCogExec_PushInt(pCog, -1);
    }
}

void sithCogFunctionThing_DamageThing(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);
    int a4 = sithCogExec_PopInt(pCog);
    cog_flex_t a5 = sithCogExec_PopFlex(pCog);
    SithThing* pThing2 = sithCogExec_PopThing(pCog);

    if ( a5 > 0.0 && pThing2 )
    {
        if ( !pThing )
            pThing = pThing2;
        if ( COG_SHOULD_SYNC(pCog) )
        {
            sithDSSThing_DamageThing(pThing2, pThing, a5, a4, -1, 1);
        }
        sithCogExec_PushFlex(pCog, sithThing_DamageThing(pThing2, pThing, a5, a4));
    }
    else
    {
        sithCogExec_PushInt(pCog, -1);
    }
}

void sithCogFunctionThing_HealThing(sithCog *pCog)
{
    cog_flex_t amt = sithCogExec_PopFlex(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (amt > 0.0 && pThing && (pThing->type == SITH_THING_ACTOR || pThing->type == SITH_THING_PLAYER))
    {
        pThing->actorParams.health += amt;
        if ( pThing->actorParams.health > pThing->actorParams.maxHealth)
            pThing->actorParams.health = pThing->actorParams.maxHealth;
    }
}

void sithCogFunctionThing_GetHealth(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if ( pThing && (pThing->type == SITH_THING_ACTOR || pThing->type == SITH_THING_PLAYER) )
        sithCogExec_PushFlex(pCog, pThing->actorParams.health);
    else
        sithCogExec_PushFlex(pCog, -1.0);
}

void sithCogFunctionThing_SetHealth(sithCog *pCog)
{
    cog_flex_t amt = sithCogExec_PopFlex(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing && (pThing->type == SITH_THING_ACTOR || pThing->type == SITH_THING_PLAYER))
        pThing->actorParams.health = amt;
}

void sithCogFunctionThing_DestroyThing(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (!pThing)
        return;

    //printf("destroy %x %s\n", pThing->guid, ctx->aName);

    if (COG_SHOULD_SYNC(pCog) )
        sithDSSThing_DestroyThing(pThing->guid, -1);

    sithThing_DestroyThing(pThing);
}

void sithCogFunctionThing_JumpToFrame(sithCog *pCog)
{
    SithSector* sector = sithCogExec_PopSector(pCog);
    uint32_t frame = sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if ( pThing && sector && pThing->moveType == SITH_MT_PATH && frame < pThing->trackParams.loadedFrames )
    {
        if ( pThing->sector && sector != pThing->sector )
            sithThing_ExitSector(pThing);

        if ( pThing->attach_flags )
            sithThing_DetachThing(pThing);

        rdMatrix_BuildRotate34(&pThing->orient, &pThing->trackParams.aFrames[frame].rot);
        rdVector_Copy3(&pThing->position, &pThing->trackParams.aFrames[frame].pos);

        if ( !pThing->sector )
            sithThing_EnterSector(pThing, sector, 1, 0);
    }
}

void sithCogFunctionThing_MoveToFrame(sithCog *pCog)
{
    cog_flex_t speed = sithCogExec_PopFlex(pCog) * 0.1;
    int frame = sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if ( pThing && pThing->moveType == SITH_MT_PATH && pThing->trackParams.loadedFrames > frame )
    {
        if ( speed == 0.0 )
            speed = 0.5;

        sithTrackThing_MoveToFrame(pThing, frame, speed);

        if (COG_SHOULD_SYNC(pCog))
            sithDSSThing_PathMove(pThing, frame, speed, 0, -1, 255);
    }
}

void sithCogFunctionThing_SkipToFrame(sithCog *pCog)
{
    cog_flex_t speed = sithCogExec_PopFlex(pCog) * 0.1;
    int frame = sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if ( pThing && pThing->moveType == SITH_MT_PATH && pThing->trackParams.loadedFrames > frame )
    {
        if ( speed == 0.0 )
            speed = 0.5;

        sithTrackThing_SkipToFrame(pThing, frame, speed);

        if (COG_SHOULD_SYNC(pCog))
            sithDSSThing_PathMove(pThing, frame, speed, 1, -1, 255);
    }
}

void sithCogFunctionThing_RotatePivot(sithCog *pCog)
{
    cog_flex_t speed = sithCogExec_PopFlex(pCog);
    uint32_t frame = sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if ( speed == 0.0 )
        speed = 1.0;

    if ( pThing && pThing->moveType == SITH_MT_PATH && pThing->trackParams.loadedFrames > frame )
    {
        rdVector3* pos = &pThing->trackParams.aFrames[frame].pos;
        rdVector3* rot = &pThing->trackParams.aFrames[frame].rot;
        if ( speed <= 0.0 )
        {
            rdVector3 negRot;

            rdVector_Neg3(&negRot, rot);
            cog_flex_t negSpeed = -speed;
            sithTrackThing_RotatePivot(pThing, pos, &negRot, negSpeed);
        }
        else
        {
            sithTrackThing_RotatePivot(pThing, pos, rot, speed);
        }
    }
}

void sithCogFunctionThing_Rotate(sithCog *pCog)
{
    rdVector3 rot;

    sithCogExec_PopVector(pCog, &rot);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing)
    {
        if ( pThing->moveType == SITH_MT_PATH )
            sithTrackThing_Rotate(pThing, &rot);
    }
}

void sithCogFunctionThing_GetThingLight(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing)
        sithCogExec_PushFlex(pCog, pThing->light);
    else
        sithCogExec_PushFlex(pCog, -1.0);
}

void sithCogFunctionThing_ThingLight(sithCog *pCog)
{
    cog_flex_t idk = sithCogExec_PopFlex(pCog);
    cog_flex_t light = sithCogExec_PopFlex(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if ( pThing && light >= 0.0 )
    {
        if ( idk == 0.0 )
        {
            pThing->light = light;
            if ( light != 0.0 )
            {
                pThing->flags |= SITH_TF_EMITLIGHT;
            }
        }
        else
        {
            sithSurface_SetThingLight(pThing, light, idk, 0);
        }
    }
}

void sithCogFunctionThing_ThingLightAnim(sithCog *pCog)
{
    cog_flex_t idk_; // ST08_4
    rdSurface *surface; // eax

    cog_flex_t idk = sithCogExec_PopFlex(pCog);
    cog_flex_t light2 = sithCogExec_PopFlex(pCog);
    cog_flex_t light = sithCogExec_PopFlex(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if ( pThing
      && light2 >= (flex_d_t)light
      && idk > 0.0
      && (idk_ = idk * 0.5, pThing->light = light, (surface = sithSurface_SetThingLight(pThing, light2, idk_, 1)) != 0) )
    {
        sithCogExec_PushInt(pCog, surface->index);
    }
    else
    {
        sithCogExec_PushInt(pCog, -1);
    }
}

void sithCogFunctionThing_WaitForStop(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if ( pThing && pThing->moveType == SITH_MT_PATH && pThing->trackParams.flags & 3 )
    {
        int idx = pThing->idx;
        pCog->script_running = 3;
        pCog->msecTimerTimeout = idx;

        if ( pCog->flags & SITH_COG_DEBUG)
        {
#ifdef SITH_DEBUG_STRUCT_NAMES
            _sprintf(std_g_genBuffer, "Cog %s: Waiting for stop on object %d.\n", pCog->aName, idx);
            sithConsole_PrintString(std_g_genBuffer);
#endif
        }
    }
}

void sithCogFunctionThing_GetThingSector(sithCog *pCog)
{
    SithSector *sector;

    SithThing* pThing = sithCogExec_PopThing(pCog);
    if ( pThing && (sector = pThing->sector) != 0 )
        sithCogExec_PushInt(pCog, sector->id);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionThing_GetCurFrame(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if ( pThing && pThing->moveType == SITH_MT_PATH )
        sithCogExec_PushInt(pCog, pThing->curframe);
    else
        sithCogExec_PushInt(pCog, 0);
}

void sithCogFunctionThing_GetGoalFrame(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if ( pThing && pThing->moveType == SITH_MT_PATH )
        sithCogExec_PushInt(pCog, pThing->goalframe);
    else
        sithCogExec_PushInt(pCog, 0);
}

void sithCogFunctionThing_StopThing(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (!pThing)
        return;

    if ( pThing->moveType == SITH_MT_PATH )
    {
        sithTrackThing_Stop(pThing);
        if (COG_SHOULD_SYNC(pCog))
            sithDSSThing_PathMove(pThing, 0, 0.0, 2, -1, 255);
    }
    else if (pThing->moveType == SITH_MT_PHYSICS)
    {
        sithPhysics_ResetThingMovement(pThing);
    }
}

void sithCogFunctionThing_IsThingMoving(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if ( !pThing || pThing->type == SITH_THING_FREE )
    {
        sithCogExec_PushInt(pCog, 0);
        return;
    }

    if ( pThing->moveType == SITH_MT_PHYSICS )
    {
        if (!rdVector_IsZero3(&pThing->physicsParams.vel))
        {
            sithCogExec_PushInt(pCog, 1);
            return;
        }
    }
    else if ( pThing->moveType == SITH_MT_PATH )
    {
        sithCogExec_PushInt(pCog, pThing->trackParams.flags & 3);
        return;
    }

    sithCogExec_PushInt(pCog, 0);
}

void sithCogFunctionThing_SetThingPulse(sithCog *pCog)
{
    cog_flex_t pulseSecs = sithCogExec_PopFlex(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (!pThing)
        return;

    if ( pulseSecs == 0.0 )
    {
        pThing->msecNextPulseTime = 0;
        pThing->flags &= ~SITH_TF_PULSESET;
        pThing->msecPulseInterval = 0;
    }
    else
    {
        pThing->flags |= SITH_TF_PULSESET;
        pThing->msecPulseInterval = (int)(pulseSecs * 1000.0);
        pThing->msecNextPulseTime = pThing->msecPulseInterval + sithTime_g_msecGameTime;
    }
}

void sithCogFunctionThing_SetThingTimer(sithCog *pCog)
{
    cog_flex_t timerSecs = sithCogExec_PopFlex(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (!pThing)
        return;

    if ( timerSecs == 0.0 )
    {
        pThing->timer = 0;
        pThing->flags &= ~SITH_TF_TIMERSET;
    }
    else
    {
        pThing->flags |= SITH_TF_TIMERSET;
        pThing->timer = sithTime_g_msecGameTime + (uint32_t)(timerSecs * 1000.0);
    }
}

void sithCogFunctionThing_CaptureThing(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing)
    {
        pThing->pCaptureCog = pCog;
        pThing->flags |= SITH_TF_CAPTURED;
    }
}

void sithCogFunctionThing_ReleaseThing(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
    {
        sithCog* pCog = pThing->pCog;
        pThing->pCaptureCog = NULL;
        if ( !pCog && !sithThing_Release(pThing) )
        {
            pThing->flags &= ~SITH_TF_CAPTURED;
        }
    }
}

void sithCogFunctionThing_GetThingParent(sithCog *pCog)
{
    SithThing* parent;

    SithThing* pThing = sithCogExec_PopThing(pCog);
    if ( pThing && (parent = sithThing_GetThingParent(pThing)) != 0 )
        sithCogExec_PushInt(pCog, parent->idx);
    else
        sithCogExec_PushInt(pCog, -1);
}

// MOTS added
void sithCogFunctionThing_SetThingParent(sithCog *pCog)
{
    int guid = sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing) 
    {
        SithThing* pThing2 = sithThing_GetGuidThing(guid);
        if (pThing2) 
        {
            pThing->pParent = pThing2;
            pThing->parentSignature = pThing2->signature;
        }
    }
}

void sithCogFunctionThing_GetThingPos(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing)
        sithCogExec_PushVector(pCog, &pThing->position);
    else
        sithCogExec_PushVector(pCog, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_SetThingPos(sithCog *pCog)
{
    rdVector3 poppedVec;

    sithCogExec_PopVector(pCog, &poppedVec);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing)
    {
        rdVector_Copy3(&pThing->position, &poppedVec);
        if (COG_SHOULD_SYNC(pCog))
        {
            sithDSSThing_Pos(pThing, -1, 1);
        }
        sithCogExec_PushInt(pCog, 1);
    }
    else
    {
        sithCogExec_PushInt(pCog, 0);
    }
}

// MOTS added
void sithCogFunctionThing_SetThingPosEx(sithCog *pCog)
{
    rdVector3 poppedVec;

    SithSector* pSector = sithCogExec_PopSector(pCog);
    sithCogExec_PopVector(pCog, &poppedVec);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pSector || (pSector == (SithSector *)-1)) {
        pSector = sithSector_FindSectorAtPos(sithWorld_g_pCurrentWorld, &poppedVec);
    }
    if (pThing)
    {
        rdVector_Copy3(&pThing->position, &poppedVec);
        sithThing_SetSector(pThing,pSector,0);
        if (pThing->moveType == SITH_MT_PHYSICS && pThing->physicsParams.flags & SITH_PF_FLOORSTICK)
            sithPhysics_FindFloor(pThing, 1);

        if ( pThing == sithPlayer_g_pLocalPlayerThing )
            sithCamera_Update(sithCamera_g_pCurCamera);

        if (COG_SHOULD_SYNC(pCog))
        {
            sithDSSThing_Pos(pThing, -1, 1);
        }
        sithCogExec_PushInt(pCog, 1);
    }
    else
    {
        sithCogExec_PushInt(pCog, 0);
    }
}

void sithCogFunctionThing_GetInventory(sithCog *pCog)
{
    unsigned int binIdx;
    SithThing *pLocalPlayer;

    binIdx = sithCogExec_PopInt(pCog);
    pLocalPlayer = sithCogExec_PopThing(pCog);

    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }

    if ( pLocalPlayer 
         && pLocalPlayer->type == SITH_THING_PLAYER 
         && pLocalPlayer->actorParams.pPlayer 
         && binIdx < SITHBIN_NUMBINS )
    {
        sithCogExec_PushFlex(pCog, sithInventory_GetInventory(pLocalPlayer, binIdx));
    }
    else
    {
        sithCogExec_PushFlex(pCog, 0.0);
    }
}

void sithCogFunctionThing_SetInventory(sithCog *pCog)
{
    cog_flex_t amt = sithCogExec_PopFlex(pCog);
    uint32_t binIdx = sithCogExec_PopInt(pCog);
    SithThing* pLocalPlayer = sithCogExec_PopThing(pCog);

    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }

    if ( pLocalPlayer 
         && pLocalPlayer->type == SITH_THING_PLAYER 
         && pLocalPlayer->actorParams.pPlayer 
         && binIdx < SITHBIN_NUMBINS )
        sithInventory_SetInventory(pLocalPlayer, binIdx, amt);
}

void sithCogFunctionThing_ChangeInventory(sithCog *pCog)
{
    cog_flex_t amt = sithCogExec_PopFlex(pCog);
    uint32_t binIdx = sithCogExec_PopInt(pCog);
    SithThing* pLocalPlayer = sithCogExec_PopThing(pCog);

    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }

    if ( pLocalPlayer 
         && pLocalPlayer->type == SITH_THING_PLAYER 
         && pLocalPlayer->actorParams.pPlayer 
         && binIdx < SITHBIN_NUMBINS )
    {
        sithCogExec_PushFlex(pCog, sithInventory_ChangeInventory(pLocalPlayer, binIdx, amt));
    }
    else
    {
        sithCogExec_PushFlex(pCog, 0.0);
    }
}

void sithCogFunctionThing_GetInventoryCog(sithCog *pCog)
{
    unsigned int binIdx;
    SithThing *pLocalPlayer;
    SithInventoryType *desc;
    sithCog *descCog;

    binIdx = sithCogExec_PopInt(pCog);
    pLocalPlayer = sithCogExec_PopThing(pCog);

    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }

    if ( pLocalPlayer
      && pLocalPlayer->type == SITH_THING_PLAYER
      && pLocalPlayer->actorParams.pPlayer
      && (desc = sithInventory_GetInventoryType(pLocalPlayer, binIdx), binIdx < SITHBIN_NUMBINS)
      && desc
      && (descCog = desc->cog) != 0 )
    {
        sithCogExec_PushInt(pCog, descCog->idx);
    }
    else
    {
        sithCogExec_PushInt(pCog, -1);
    }
}

void sithCogFunctionThing_GetThingVelocity(sithCog *pCog)
{
    rdVector3 retval;

    rdVector_Copy3(&retval, (rdVector3*)&rdroid_zeroVector3);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing)
    {
        if ( pThing->moveType == SITH_MT_PHYSICS)
        {
            rdVector_Copy3(&retval, &pThing->physicsParams.vel);
        }
        else if ( pThing->moveType == SITH_MT_PATH )
        {
            rdVector_Scale3(&retval, &pThing->trackParams.vel, pThing->trackParams.moveVel);
        }
        sithCogExec_PushVector(pCog, &retval);
    }
    else
    {
        sithCogExec_PushVector(pCog, (rdVector3*)&rdroid_zeroVector3);
    }
}

void sithCogFunctionThing_SetThingVel(sithCog *pCog)
{
    rdVector3 poppedVec;

    sithCogExec_PopVector(pCog, &poppedVec);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if ( pThing && pThing->moveType == SITH_MT_PHYSICS)
    {
        rdVector_Copy3(&pThing->physicsParams.vel, &poppedVec);
        if (COG_SHOULD_SYNC(pCog))
        {
            sithThing_SyncThing(pThing, SITHTHING_SYNC_POS);
        }
    }
}

void sithCogFunctionThing_ApplyForce(sithCog *pCog)
{
    rdVector3 poppedVec;

    sithCogExec_PopVector(pCog, &poppedVec);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if ( pThing && pThing->moveType == SITH_MT_PHYSICS)
    {
        sithPhysics_ApplyForce(pThing, &poppedVec);
        if (COG_SHOULD_SYNC(pCog))
        {
            sithThing_SyncThing(pThing, SITHTHING_SYNC_POS);
        }
    }
}

void sithCogFunctionThing_AddThingVel(sithCog *pCog)
{
    rdVector3 poppedVec;

    sithCogExec_PopVector(pCog, &poppedVec);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if ( pThing && pThing->moveType == SITH_MT_PHYSICS)
    {
        rdVector_Add3Acc(&pThing->physicsParams.vel, &poppedVec);
        if (COG_SHOULD_SYNC(pCog))
        {
            sithThing_SyncThing(pThing, SITHTHING_SYNC_POS);
        }
    }
}

void sithCogFunctionThing_GetThingLVec(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing)
        sithCogExec_PushVector(pCog, &pThing->orient.lvec);
    else
        sithCogExec_PushVector(pCog, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_GetThingLVecPYR(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (!pThing) {
        sithCogExec_PushVector(pCog, (rdVector3*)&rdroid_zeroVector3);
        return;
    }

    rdVector3 pyrOut;
    rdMatrix34 lookOrient;
    rdMatrix_Copy34(&lookOrient, &pThing->orient);
    rdMatrix_ExtractAngles34(&lookOrient, &pyrOut);
    sithCogExec_PushVector(pCog, &pyrOut);
}

void sithCogFunctionThing_GetThingUVec(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing)
        sithCogExec_PushVector(pCog, &pThing->orient.uvec);
    else
        sithCogExec_PushVector(pCog, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_GetThingRVec(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing)
        sithCogExec_PushVector(pCog, &pThing->orient.rvec);
    else
        sithCogExec_PushVector(pCog, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_GetEyePYR(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if ( pThing && (pThing->type == SITH_THING_ACTOR || pThing->type == SITH_THING_PLAYER))
        sithCogExec_PushVector(pCog, &pThing->actorParams.headPYR);
    else
        sithCogExec_PushVector(pCog, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_DetachThing(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing)
    {
        sithThing_DetachThing(pThing);
        if (COG_SHOULD_SYNC(pCog))
        {
            sithDSSThing_Attachment(pThing, -1, 255, 1);
        }
    }
}

void sithCogFunctionThing_GetThingAttachFlags(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing)
        sithCogExec_PushInt(pCog, pThing->attach_flags);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionThing_AttachThingToSurf(sithCog *pCog)
{
    SithSurface* surface = sithCogExec_PopSurface(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing && surface)
    {
        sithThing_AttachThingToSurface(pThing, surface, 1);
        if (COG_SHOULD_SYNC(pCog))
        {
            sithDSSThing_Attachment(pThing, -1, 255, 1);
        }
    }
}

void sithCogFunctionThing_AttachThingToThing(sithCog *pCog)
{
    SithThing* attached = sithCogExec_PopThing(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing && attached)
    {
        sithThing_AttachThingToThing(pThing, attached);
        if (COG_SHOULD_SYNC(pCog))
        {
            sithDSSThing_Attachment(pThing, -1, 255, 1);
        }
    }
}

void sithCogFunctionThing_AttachThingToThingEx(sithCog *pCog)
{
    int attachFlags = sithCogExec_PopInt(pCog);
    SithThing* attached = sithCogExec_PopThing(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing && attached)
    {
        sithThing_AttachThingToThing(pThing, attached);
        pThing->attach_flags |= attachFlags;

        if (COG_SHOULD_SYNC(pCog))
        {
            sithDSSThing_Attachment(pThing, -1, 255, 1);
        }
    }
}

void sithCogFunctionThing_PlayMode(sithCog *pCog)
{
    int mode = sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if ( mode < 43 && pThing && pThing->pPuppetClass && pThing->renderData.puppet)
    {
        int track = sithPuppet_PlayMode(pThing, mode, 0);
        if (track >= 0)
        {
            sithCogExec_PushInt(pCog, track);
            if (COG_SHOULD_SYNC(pCog))
            {
                sithDSSThing_PlayKeyMode(pThing, mode, pThing->renderData.puppet->aTracks[track].field_130, -1, 255);
            }
        }
    }
    else
    {
        sithCogExec_PushInt(pCog, -1);
    }
}

void sithCogFunctionThing_PlayKey(sithCog *pCog)
{
    int trackNum = sithCogExec_PopInt(pCog);
    int popInt = sithCogExec_PopInt(pCog);
    rdKeyframe* keyframe = sithCogExec_PopKeyframe(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    rdPuppet* puppet = NULL;
    int track = 0;

    if ( !pThing )
        goto fail;

    puppet = pThing->renderData.puppet;
    if ( !puppet ) {
        goto fail;
    }

    // MOTS added: bugfix?
    if ( Main_bMotsCompat && pThing == sithPlayer_g_pLocalPlayerThing && pThing->actorParams.health < 1.0) {
        goto fail;
    }

    // MOTS added: nullptr deref fix
    if (!keyframe) {
       goto fail;
    }
    
    track = sithPuppet_PlayKey(puppet, keyframe, popInt, popInt + 2, trackNum, 0);
    if ( track >= 0 )
    {
        sithCogExec_PushInt(pCog, track);
        if ( pThing->moveType == SITH_MT_PATH )
        {
            if ( pThing->trackParams.flags )
                sithTrackThing_Stop(pThing);
            rdVector_Copy3(&pThing->trackParams.curOrient.scale, &pThing->position);
        }
        if (COG_SHOULD_SYNC(pCog))
        {
            sithDSSThing_PlayKey(pThing, keyframe, trackNum, popInt, pThing->renderData.puppet->aTracks[track].field_130, -1, 255);
        }
        return;
    }

fail:
    sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionThing_StopKey(sithCog *pCog)
{
    cog_flex_t poppedFlex = sithCogExec_PopFlex(pCog);
    int track = sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (!pThing)
        return;

    rdPuppet* puppet = pThing->renderData.puppet;
    if (!puppet)
        return;

    if ( track >= 0 && track < 4 && poppedFlex >= 0.0 )
    {
        int v6 = puppet->aTracks[track].field_130;
        if ( sithPuppet_StopKey(puppet, track, poppedFlex) )
        {
            if (COG_SHOULD_SYNC(pCog))
            {
                sithDSSThing_StopKey(pThing, v6, poppedFlex, -1, 255);
            }
        }
    }
}

void sithCogFunctionThing_SetThingModel(sithCog *pCog)
{
    rdModel3* model = sithCogExec_PopModel3(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if ( pThing && model)
    {
        rdModel3* v4 = pThing->renderData.model3;
        int v5;
        if (!v4)
        {
            v5 = -1;
        }
        else
        {
            v5 = v4->id;
            sithThing_SetThingModel(pThing, model);
        }

        sithCogExec_PushInt(pCog, v5);

        if (COG_SHOULD_SYNC(pCog))
        {
            sithDSSThing_SetModel(pThing, -1);
        }
    }
    else
    {
        sithCogExec_PushInt(pCog, -1);
    }
}

void sithCogFunctionThing_GetThingModel(sithCog *pCog)
{
    rdModel3 *model;

    SithThing* pThing = sithCogExec_PopThing(pCog);
    if ( pThing && pThing->renderData.type == RD_THING_MODEL3 && (model = pThing->renderData.model3) != 0 )
        sithCogExec_PushInt(pCog, model->id);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionThing_SetArmedMode(sithCog *pCog)
{
    int poppedInt = sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if ( pThing && poppedInt >= 0 && poppedInt <= 2)
    {
        sithPuppet_SetArmedMode(pThing, poppedInt);

        if (COG_SHOULD_SYNC(pCog))
        {
            sithDSSThing_UpdateState(pThing, -1, 255);
        }
    }
}

void sithCogFunctionThing_GetThingFlags(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing)
        sithCogExec_PushInt(pCog, pThing->flags);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionThing_SetThingFlags(sithCog *pCog)
{
    int flags = sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if ( pThing && flags)
    {
        pThing->flags |= flags;

        if (COG_SHOULD_SYNC(pCog))
        {
            sithThing_SyncThing(pThing, SITHTHING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_ClearThingFlags(sithCog *pCog)
{
    int flags = sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if ( pThing && flags)
    {
        pThing->flags &= ~flags;

        if (COG_SHOULD_SYNC(pCog))
        {
            sithThing_SyncThing(pThing, SITHTHING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_TeleportThing(sithCog *pCog)
{
    SithThing* thingTo = sithCogExec_PopThing(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing && thingTo )
    {
        if ( pThing->attach_flags )
            sithThing_DetachThing(pThing);

        rdMatrix_Copy34(&pThing->orient, &thingTo->orient);
        rdVector_Copy3(&pThing->position, &thingTo->position);
        sithThing_SetSector(pThing, thingTo->sector, 0);
        if (pThing->moveType == SITH_MT_PHYSICS && pThing->physicsParams.flags & SITH_PF_FLOORSTICK)
            sithPhysics_FindFloor(pThing, 1);

        if ( pThing == sithPlayer_g_pLocalPlayerThing )
            sithCamera_Update(sithCamera_g_pCurCamera);

        if (COG_SHOULD_SYNC(pCog))
        {
            sithDSSThing_Pos(pThing, -1, 1);
        }
    }
}

void sithCogFunctionThing_SetThingType(sithCog *pCog)
{
    int type = sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if ( pThing && type >= 0 && type < 12 )
        pThing->type = type;
}

void sithCogFunctionThing_GetCollideType(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing)
        sithCogExec_PushInt(pCog, pThing->collide);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionThing_SetCollideType(sithCog *pCog)
{
    int collideType = sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if ( pThing && collideType < 4)
    {
        pThing->collide = collideType;

        if (COG_SHOULD_SYNC(pCog))
        {
            sithThing_SyncThing(pThing, SITHTHING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_FirstThingInSector(sithCog *pCog)
{
    SithSector* sector = sithCogExec_PopSector(pCog);
    if (sector)
    {
        SithThing* pThing = sector->pFirstThingInSector;

        if (pThing)
            sithCogExec_PushInt(pCog, pThing->idx);
        else
            sithCogExec_PushInt(pCog, -1);
    }
    else
    {
        sithCogExec_PushInt(pCog, -1);
        sithCogExec_PushInt(pCog, -1);
    }
}

void sithCogFunctionThing_NextThingInSector(sithCog *pCog)
{
    SithThing *pNextThingInSector;

    SithThing* pThing = sithCogExec_PopThing(pCog);
    if ( pThing && (pNextThingInSector = pThing->pNextThingInSector) != 0 )
    {
        sithCogExec_PushInt(pCog, pNextThingInSector->idx);
    }
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionThing_PrevThingInSector(sithCog *pCog)
{
    SithThing *pPrevThingInSector;

    SithThing* pThing = sithCogExec_PopThing(pCog);
    if ( pThing && (pPrevThingInSector = pThing->pPrevThingInSector) != 0 )
        sithCogExec_PushInt(pCog, pPrevThingInSector->idx);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionThing_GetInventoryMinimum(sithCog *pCog)
{
    int binIdx = sithCogExec_PopInt(pCog);
    SithThing* player = sithCogExec_PopThing(pCog);

    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }

    if ( player && player->type == SITH_THING_PLAYER && player->actorParams.pPlayer )
    {
        sithCogExec_PushFlex(pCog, sithInventory_GetInventoryMinimum(player, binIdx));
    }
    else
    {
        sithCogExec_PushFlex(pCog, -1.0);
    }
}

void sithCogFunctionThing_GetInventoryMaximum(sithCog *pCog)
{
    int binIdx = sithCogExec_PopInt(pCog);
    SithThing* player = sithCogExec_PopThing(pCog);

    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }

    if ( player && player->type == SITH_THING_PLAYER && player->actorParams.pPlayer )
    {
        sithCogExec_PushFlex(pCog, sithInventory_GetInventoryMaximum(player, binIdx));
    }
    else
    {
        sithCogExec_PushFlex(pCog, -1.0);
    }
}

// unused/unreferenced
void sithCogFunctionThing_GetLoadedFrames(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing && pThing->moveType == SITH_MT_PATH)
        sithCogExec_PushInt(pCog, pThing->trackParams.loadedFrames);
    else
        sithCogExec_PushInt(pCog, -1);
}

// unused/unreferenced
void sithCogFunctionThing_GetFramePos(sithCog *pCog)
{
    uint32_t frame = sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if ( pThing && pThing->moveType == SITH_MT_PATH && frame < pThing->trackParams.loadedFrames )
        sithCogExec_PushVector(pCog, &pThing->trackParams.aFrames[frame].pos);
    sithCogExec_PushVector(pCog, (rdVector3*)&rdroid_zeroVector3);
}

// unused/unreferenced
void sithCogFunctionThing_GetFrameRot(sithCog *pCog)
{
    uint32_t frame = sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing && pThing->moveType == SITH_MT_PATH && frame < pThing->trackParams.loadedFrames)
        sithCogExec_PushVector(pCog, &pThing->trackParams.aFrames[frame].rot);
    sithCogExec_PushVector(pCog, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_PathMovePause(sithCog *pCog)
{
    int ret = 0;
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if ( pThing && pThing->moveType == SITH_MT_PATH )
        ret = sithTrackThing_PathMovePause(pThing);

    if ( ret == 1 )
        sithCogExec_PushInt(pCog, pThing->idx);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionThing_SetHeadLightIntensity(sithCog *pCog)
{
    cog_flex_t intensity = sithCogExec_PopFlex(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing && (pThing->type == SITH_THING_ACTOR || pThing->type == SITH_THING_PLAYER))
    {
        pThing->actorParams.lightIntensity = intensity;
        sithCogExec_PushFlex(pCog, intensity);
    }
    else
    {
        sithCogExec_PushFlex(pCog, -1.0);
    }
}

void sithCogFunctionThing_GetHeadLightIntensity(sithCog *pCog)
{
    sithCogExec_PopFlex(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing && (pThing->type == SITH_THING_ACTOR || pThing->type == SITH_THING_PLAYER))
        sithCogExec_PushFlex(pCog, pThing->actorParams.lightIntensity);
    else
        sithCogExec_PushFlex(pCog, -1.0);
}

void sithCogFunctionThing_IsThingVisible(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing)
        sithCogExec_PushInt(pCog, pThing->renderFrame + 1 >= (unsigned int)jkPlayer_currentTickIdx);
    else
        sithCogExec_PushInt(pCog, 0);
}

void sithCogFunctionThing_PathMoveResume(sithCog *pCog)
{
    int ret = 0;
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if ( pThing && pThing->moveType == SITH_THING_ACTOR )
        ret = sithTrackThing_PathMoveResume(pThing);
    if ( ret == 1 )
        sithCogExec_PushInt(pCog, pThing->idx);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionThing_SetCurInvWeapon(sithCog *pCog)
{
    int binIdx = sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }
    if (pThing)
        sithInventory_SetCurrentWeapon(pThing, binIdx);
}

void sithCogFunctionThing_GetCurInvWeapon(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing)
    {
        int binIdx = sithInventory_GetCurrentWeapon(pThing);
        if (Main_bMotsCompat) {
            binIdx = sithInventory_SelectWeaponPrior(binIdx);
        }
        sithCogExec_PushInt(pCog, binIdx);
    }
    else
    {
        sithCogExec_PushInt(pCog, -1);
    }
}

// MOTS added
void sithCogFunctionThing_GetCurInvWeaponMots(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing)
    {
        int idx = sithInventory_GetCurrentWeapon(pThing);
        sithInventory_SelectWeaponPrior(idx);
        sithCogExec_PushInt(pCog, idx);
    }
    else
    {
        sithCogExec_PushInt(pCog, -1);
    }
}

void sithCogFunctionThing_SetThingGeoMode(sithCog *pCog)
{
    rdGeoMode_t mode = (rdGeoMode_t)sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing)
        pThing->renderData.desiredGeoMode = mode;
}

void sithCogFunctionThing_GetThingGeoMode(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing)
        sithCogExec_PushInt(pCog, (int)pThing->renderData.desiredGeoMode);
}

void sithCogFunctionThing_SetThingLightMode(sithCog *pCog)
{
    rdLightMode_t mode = (rdLightMode_t)sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing)
        pThing->renderData.desiredLightMode = mode;
}

void sithCogFunctionThing_GetThingLightMode(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing)
        sithCogExec_PushInt(pCog, (int)pThing->renderData.desiredLightMode);
}

void sithCogFunctionThing_SetThingTexMode(sithCog *pCog)
{
    int mode = sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing)
        pThing->renderData.desiredTexMode = mode;
}

void sithCogFunctionThing_GetThingTexMode(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing)
        sithCogExec_PushInt(pCog, pThing->renderData.desiredTexMode);
}

void sithCogFunctionThing_SetThingCurGeoMode(sithCog *pCog)
{
    rdGeoMode_t mode = (rdGeoMode_t)sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing)
    {
        pThing->renderData.curGeoMode = mode;
        if (COG_SHOULD_SYNC(pCog))
        {
                sithThing_SyncThing(pThing, SITHTHING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_GetThingCurGeoMode(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing)
        sithCogExec_PushInt(pCog, (int)pThing->renderData.curGeoMode);
}

void sithCogFunctionThing_SetThingCurLightMode(sithCog *pCog)
{
    rdLightMode_t mode = (rdLightMode_t)sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing)
        pThing->renderData.curLightMode = mode;
}

void sithCogFunctionThing_GetThingCurLightMode(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing)
        sithCogExec_PushInt(pCog, (int)pThing->renderData.curLightMode);
}

void sithCogFunctionThing_SetThingCurTexMode(sithCog *pCog)
{
    int mode = sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing)
        pThing->renderData.curTexMode = mode;
}

void sithCogFunctionThing_GetThingCurTexMode(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing)
        sithCogExec_PushInt(pCog, pThing->renderData.curTexMode);
}

void sithCogFunctionThing_SetActorExtraSpeed(sithCog *pCog)
{
    cog_flex_t extraSpeed = sithCogExec_PopFlex(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing)
        pThing->actorParams.extraSpeed = extraSpeed;
}

void sithCogFunctionThing_GetThingTemplate(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing && pThing->pTemplate)
        sithCogExec_PushInt(pCog, pThing->pTemplate->idx);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionThing_SetLifeleft(sithCog *pCog)
{
    cog_flex_t lifeLeftSecs = sithCogExec_PopFlex(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if ( pThing && lifeLeftSecs >= 0.0)
    {
        pThing->msecLifeLeft = (int)(lifeLeftSecs * 1000.0);
        if (COG_SHOULD_SYNC(pCog))
        {
            sithThing_SyncThing(pThing, SITHTHING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_GetLifeleft(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing)
    {
        sithCogExec_PushFlex(pCog, (flex_d_t)(unsigned int)pThing->msecLifeLeft * 0.001);
    }
}

void sithCogFunctionThing_SetThingThrust(sithCog *pCog)
{
    rdVector3 poppedVec;

    int couldPopVec = sithCogExec_PopVector(pCog, &poppedVec);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if ( pThing && pThing->moveType == SITH_MT_PHYSICS && couldPopVec)
    {
        sithCogExec_PushVector(pCog, &pThing->physicsParams.acceleration);
        rdVector_Copy3(&pThing->physicsParams.acceleration, &poppedVec);
    }
}

void sithCogFunctionThing_GetThingThrust(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if ( pThing )
    {
        if ( pThing->moveType == SITH_MT_PHYSICS )
            sithCogExec_PushVector(pCog, &pThing->physicsParams.acceleration);
    }
}

void sithCogFunctionThing_AmputateJoint(sithCog *pCog)
{
    uint32_t idx = sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing)
    {
        rdThing* renderData = &pThing->renderData;
        if ( pThing != (SithThing *)-196 )
        {
            SithPuppetClass* pPuppetClass = pThing->pPuppetClass;
            if (pPuppetClass && idx < 0xA)
            {
                int jointIdx = pPuppetClass->aJoints[idx];
                if ( jointIdx >= 0 ) {
                    // Added: prevent oob
                    if (renderData->model3 && jointIdx < renderData->model3->numHNodes)
                        renderData->paJointAmputationFlags[jointIdx] = 1;
                }
            }
        }
    }
}

void sithCogFunctionThing_SetActorWeapon(sithCog *pCog)
{
    SithThing* weapTemplate = sithCogExec_PopTemplate(pCog);
    int weap_idx = sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if ( pThing && (pThing->type == SITH_THING_ACTOR || pThing->type == SITH_THING_PLAYER))
    {
        if ( weap_idx == 1 )
        {
            pThing->actorParams.pWeaponTemplate = weapTemplate;
        }
        else if ( weap_idx == 2 )
        {
            pThing->actorParams.templateWeapon2 = weapTemplate;
        }
    }
}

// MOTS altered
void sithCogFunctionThing_GetActorWeapon(sithCog *pCog)
{
    int weap_idx = sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing && (pThing->type == SITH_THING_ACTOR || pThing->type == SITH_THING_PLAYER))
    {
        SithThing* weapTemplate;
        if ( weap_idx == 1 )
        {
            weapTemplate = pThing->actorParams.pWeaponTemplate;
        }
        else if ( weap_idx == 2 )
        {
            weapTemplate = pThing->actorParams.templateWeapon2;
        }
        else
        {
            sithCogExec_PushInt(pCog, -1);
            return;
        }

        if (weapTemplate)
        {
            sithCogExec_PushInt(pCog, weapTemplate->idx);
            return;
        }

        sithCogExec_PushInt(pCog, -1);
        return;
    }
}

// MOTS added
void sithCogFunctionThing_GetActorWeaponMots(sithCog *pCog)
{
    int weap_idx = sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing && (pThing->type == SITH_THING_ACTOR || pThing->type == SITH_THING_PLAYER))
    {
        SithThing* weapTemplate;
        if ( weap_idx == 1 )
        {
            weapTemplate = pThing->actorParams.pWeaponTemplate;
        }
        else if ( weap_idx == 2 )
        {
            weapTemplate = pThing->actorParams.templateWeapon2;
        }
        else
        {
            sithCogExec_PushInt(pCog, -1);
            return;
        }

        if (weapTemplate)
        {
            if (pThing->type != SITH_THING_PLAYER) {
                sithCogExec_PushInt(pCog, weapTemplate->idx);
                return;
            }
            int idx = sithInventory_SelectWeaponPrior(weapTemplate->idx);
            sithCogExec_PushInt(pCog, idx);
            return;
        }

        sithCogExec_PushInt(pCog, -1);
        return;
    }
}

void sithCogFunctionThing_GetPhysicsFlags(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if ( pThing && pThing->moveType == SITH_MT_PHYSICS )
        sithCogExec_PushInt(pCog, pThing->physicsParams.flags);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionThing_SetPhysicsFlags(sithCog *pCog)
{
    int flags = sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing && flags && pThing->moveType == SITH_MT_PHYSICS)
    {
        pThing->physicsParams.flags |= flags;
        if (COG_SHOULD_SYNC(pCog))
        {
            sithThing_SyncThing(pThing, SITHTHING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_ClearPhysicsFlags(sithCog *pCog)
{
    int flags = sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing && flags && pThing->moveType == SITH_MT_PHYSICS)
        pThing->physicsParams.flags &= ~flags;
}

void sithCogFunctionThing_SkillTarget(sithCog *pCog)
{
    sithCog *classCog;

    cog_flex_t param1 = sithCogExec_PopFlex(pCog);
    cog_flex_t param0 = sithCogExec_PopFlex(pCog);
    SithThing* otherThing = sithCogExec_PopThing(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if ( pThing && otherThing && (classCog = pThing->pCog) != 0 )
    {
        if ( sithNet_isMulti && pThing->type == SITH_THING_PLAYER )
        {
            sithDSSCog_SendMessage(
                classCog,
                SITH_MESSAGE_SKILL,
                SENDERTYPE_THING,
                pThing->idx,
                SENDERTYPE_THING,
                otherThing->idx,
                0,
                param0,
                param1,
                0.0,
                0.0,
                pThing->actorParams.pPlayer->playerNetId);
            sithCogExec_PushFlex(pCog, 0.0);
        }
        else
        {
            cog_flex_t ret = sithCog_SendMessageEx(
                          classCog,
                          SITH_MESSAGE_SKILL,
                          SENDERTYPE_THING,
                          pThing->idx,
                          SENDERTYPE_THING,
                          otherThing->idx,
                          0,
                          param0,
                          param1,
                          0.0,
                          0.0);
            sithCogExec_PushFlex(pCog, ret);
        }
    }
    else
    {
        sithCogExec_PushFlex(pCog, -1.0);
    }
}

void sithCogFunctionThing_ParseArg(sithCog *pCog)
{
    char* str = sithCogExec_PopString(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (str && pThing)
    {
        _strncpy(std_g_genBuffer, str, 0x3FFu);
        std_g_genBuffer[1023] = 0;

        stdConffile_ReadArgsFromStr(std_g_genBuffer);
        for (int i = 0 ; i < stdConffile_g_entry.numArgs; i++)
        {
            StdConffileArg* arg = &stdConffile_g_entry.aArgs[i];
            sithThing_ParseArg(arg, pThing);
        }
    }
}

void sithCogFunctionThing_SetThingRotVel(sithCog *pCog)
{
    rdVector3 popped_vector3;

    sithCogExec_PopVector(pCog, &popped_vector3);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if ( pThing && pThing->moveType == SITH_MT_PHYSICS)
    {
        rdVector_Copy3(&pThing->physicsParams.angularVelocity, &popped_vector3);
        if (COG_SHOULD_SYNC(pCog))
        {
            sithThing_SyncThing(pThing, SITHTHING_SYNC_POS);
        }
    }
}

void sithCogFunctionThing_GetThingRotVel(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if ( pThing && pThing->moveType == SITH_MT_PHYSICS )
        sithCogExec_PushVector(pCog, &pThing->physicsParams.angularVelocity);
    else
        sithCogExec_PushVector(pCog, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_SetThingLook(sithCog *pCog)
{
    rdVector3 popped_vector3;

    int pop_v3_retval = sithCogExec_PopVector(pCog, &popped_vector3);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if ( pThing && pop_v3_retval == 1)
    {
        rdVector_Normalize3Acc(&popped_vector3);
        rdMatrix_BuildFromLook34(&pThing->orient, &popped_vector3);

        if (COG_SHOULD_SYNC(pCog))
        {
            sithThing_SyncThing(pThing, SITHTHING_SYNC_POS);
        }
    }
}

void sithCogFunctionThing_IsThingCrouching(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if ( !pThing || pThing->moveType != SITH_MT_PHYSICS )
        sithCogExec_PushInt(pCog, -1);

    if (pThing->physicsParams.flags & SITH_PF_CROUCHING)
        sithCogExec_PushInt(pCog, 1);
    else
        sithCogExec_PushInt(pCog, 0);
}

void sithCogFunctionThing_GetThingClassCog(sithCog *pCog)
{
    sithCog *classCog; // eax

    SithThing* pThing = sithCogExec_PopThing(pCog);
    if ( pThing && (classCog = pThing->pCog) != 0 )
        sithCogExec_PushInt(pCog, classCog->idx);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionThing_SetThingClassCog(sithCog *pCog)
{
    sithCog* classCog = sithCogExec_PopCog(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if ( pThing )
    {
        if ( classCog )
            pThing->pCog = classCog;
    }
}

void sithCogFunctionThing_GetThingCaptureCog(sithCog *pCog)
{
    sithCog *captureCog; // eax

    SithThing* pThing = sithCogExec_PopThing(pCog);
    if ( pThing && (captureCog = pThing->pCaptureCog) != 0 )
        sithCogExec_PushInt(pCog, captureCog->idx);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionThing_SetThingCaptureCog(sithCog *pCog)
{
    sithCog *captureCog; // edi

    captureCog = sithCogExec_PopCog(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if ( pThing )
    {
        if ( captureCog )
            pThing->pCaptureCog = captureCog;
    }
}

void sithCogFunctionThing_GetThingRespawn(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing && pThing->type == SITH_THING_ITEM)
    {
        sithCogExec_PushFlex(pCog, pThing->itemParams.secRespawnInterval);
    }
}

void sithCogFunctionThing_GetThingSignature(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if ( pThing )
        sithCogExec_PushInt(pCog, pThing->signature);
    else
        sithCogExec_PushInt(pCog, -1);
}

// MOTS added
void sithCogFunctionThing_GetThingGuid(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing) {
        sithCogExec_PushInt(pCog, pThing->guid);
        return;
    }
    sithCogExec_PushInt(pCog, -1);
}

// MOTS added
void sithCogFunctionThing_GetGuidThing(sithCog *pCog)
{
    int guid = sithCogExec_PopInt(pCog);
    SithThing* pThing = sithThing_GetGuidThing(guid);
    if (pThing == (SithThing *)0x0) {
        sithCogExec_PushInt(pCog,-1);
        return;
    }
    sithCogExec_PushInt(pCog,pThing->idx);
    return;
}

void sithCogFunctionThing_SetThingAttachFlags(sithCog *pCog)
{
    int flags = sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if ( pThing && flags)
    {
        pThing->attach_flags |= flags;

        if (COG_SHOULD_SYNC(pCog))
        {
            sithDSSThing_Attachment(pThing, -1, 255, 1);
        }
    }
}

void sithCogFunctionThing_ClearThingAttachFlags(sithCog *pCog)
{
    int flags = sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if ( pThing && flags)
    {
        pThing->attach_flags &= ~flags;

        if (COG_SHOULD_SYNC(pCog))
        {
            sithDSSThing_Attachment(pThing, -1, 255, 1);
        }
    }
}

void sithCogFunctionThing_GetParticleSize(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing && pThing->type == SITH_THING_PARTICLE)
        sithCogExec_PushFlex(pCog, pThing->particleParams.size);
    else
        sithCogExec_PushFlex(pCog, -1.0);
}

void sithCogFunctionThing_SetParticleSize(sithCog *pCog)
{
    cog_flex_t size = sithCogExec_PopFlex(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing && pThing->type == SITH_THING_PARTICLE)
    {
        pThing->particleParams.size = size;
    }
}

void sithCogFunctionThing_GetParticleGrowthSpeed(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if ( pThing && pThing->type == SITH_THING_PARTICLE )
        sithCogExec_PushFlex(pCog, pThing->particleParams.growthSpeed);
    else
        sithCogExec_PushFlex(pCog, -1.0);
}

void sithCogFunctionThing_SetParticleGrowthSpeed(sithCog *pCog)
{
    cog_flex_t speed = sithCogExec_PopFlex(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing && pThing->type == SITH_THING_PARTICLE)
    {
        pThing->particleParams.growthSpeed = speed;
    }
}

void sithCogFunctionThing_GetParticleTimeoutRate(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if ( pThing && pThing->type == SITH_THING_PARTICLE )
        sithCogExec_PushFlex(pCog, pThing->particleParams.rate);
    else
        sithCogExec_PushFlex(pCog, -1.0);
}

void sithCogFunctionThing_SetParticleTimeoutRate(sithCog *pCog)
{
    cog_flex_t rate = sithCogExec_PopFlex(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing && pThing->type == SITH_THING_PARTICLE)
    {
        pThing->particleParams.rate = rate;
    }
}

void sithCogFunctionThing_GetTypeFlags(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing)
    {
        switch ( pThing->type )
        {
            case SITH_THING_ACTOR:
            case SITH_THING_ITEM:
            case SITH_THING_PLAYER:
                sithCogExec_PushInt(pCog, pThing->actorParams.flags);
                return;
            case SITH_THING_WEAPON:
            case SITH_THING_PARTICLE:
                sithCogExec_PushInt(pCog, pThing->weaponParams.flags);
                return;
            case SITH_THING_EXPLOSION:
                sithCogExec_PushInt(pCog, pThing->explosionParams.flags);
                return;
        }
    }

    sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionThing_SetTypeFlags(sithCog *pCog)
{
    int flags = sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if ( pThing && flags )
    {
        switch ( pThing->type )
        {
            case SITH_THING_ACTOR:
            case SITH_THING_WEAPON:
            case SITH_THING_ITEM:
            case SITH_THING_EXPLOSION:
            case SITH_THING_PLAYER:
            case SITH_THING_PARTICLE:
                pThing->actorParams.flags |= flags;
                break;
            default:
                break;
        }

        if (COG_SHOULD_SYNC(pCog))
        {
            sithThing_SyncThing(pThing, SITHTHING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_ClearTypeFlags(sithCog *pCog)
{
    int flags = sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if ( pThing && flags )
    {
        switch ( pThing->type )
        {
            case SITH_THING_ACTOR:
            case SITH_THING_WEAPON:
            case SITH_THING_ITEM:
            case SITH_THING_EXPLOSION:
            case SITH_THING_PLAYER:
            case SITH_THING_PARTICLE:
                pThing->actorParams.flags &= ~flags;
                break;
            default:
                break;
        }

        if (COG_SHOULD_SYNC(pCog))
        {
            sithThing_SyncThing(pThing, SITHTHING_SYNC_STATE);
        }
    }
}

// MOTS altered
void sithCogFunctionThing_TakeItem(sithCog *pCog)
{
    SithThing* player = sithCogExec_PopThing(pCog);
    SithThing* itemThing = sithCogExec_PopThing(pCog);
    if ( itemThing && (Main_bMotsCompat || player) && itemThing->type == SITH_THING_ITEM )
        sithItem_SetItemTaken(itemThing, player, 0);
}

void sithCogFunctionThing_HasLOS(sithCog *pCog)
{
    SithThing* pThingB = sithCogExec_PopThing(pCog);
    SithThing* pThingA = sithCogExec_PopThing(pCog);

    if ( pThingA && pThingB )
    {
        if (sithCollision_HasLOS(pThingA, pThingB, 0))
            sithCogExec_PushInt(pCog, 1);
        else
            sithCogExec_PushInt(pCog, 0);
    }
    else
    {
        sithCogExec_PushInt(pCog, -1);
    }
}

void sithCogFunctionThing_GetFireOffset(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing)
        sithCogExec_PushVector(pCog, &pThing->actorParams.fireOffset);
    else
        sithCogExec_PushVector(pCog, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_SetFireOffset(sithCog *pCog)
{
    rdVector3 poppedVec;

    sithCogExec_PopVector(pCog, &poppedVec);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing)
    {
        rdVector_Copy3(&pThing->actorParams.fireOffset, &poppedVec);
    }
}

void sithCogFunctionThing_GetThingUserData(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing)
        sithCogExec_PushFlex(pCog, pThing->userval);
    else
        sithCogExec_PushFlex(pCog, -1.0);
}

void sithCogFunctionThing_SetThingUserData(sithCog *pCog)
{
    cog_flex_t userval = sithCogExec_PopFlex(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing)
        pThing->userval = userval;
}

void sithCogFunctionThing_GetThingCollideSize(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing)
        sithCogExec_PushFlex(pCog, pThing->collideSize);
    else
        sithCogExec_PushFlex(pCog, -1.0);
}

void sithCogFunctionThing_SetThingCollideSize(sithCog *pCog)
{
    cog_flex_t size = sithCogExec_PopFlex(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing)
        pThing->collideSize = size;
}

void sithCogFunctionThing_GetThingMoveSize(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing)
        sithCogExec_PushFlex(pCog, pThing->moveSize);
    else
        sithCogExec_PushFlex(pCog, -1.0);
}

void sithCogFunctionThing_SetThingMoveSize(sithCog *pCog)
{
    cog_flex_t moveSize = sithCogExec_PopFlex(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing)
        pThing->moveSize = moveSize;
}

void sithCogFunctionThing_GetThingMass(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing)
    {
        if (pThing->moveType == SITH_MT_PHYSICS)
            sithCogExec_PushFlex(pCog, pThing->physicsParams.mass);
        else
            sithCogExec_PushFlex(pCog, 0.0);
    }
}

void sithCogFunctionThing_SetThingMass(sithCog *pCog)
{
    cog_flex_t mass = sithCogExec_PopFlex(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing && pThing->moveType == SITH_MT_PHYSICS)
    {
        pThing->physicsParams.mass = mass;
        if (COG_SHOULD_SYNC(pCog))
        {
            sithThing_SyncThing(pThing, SITHTHING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_SyncThingPos(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing)
        sithThing_SyncThing(pThing, SITHTHING_SYNC_POS);
}

void sithCogFunctionThing_SyncThingAttachment(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing)
        sithDSSThing_Attachment(pThing, -1, 255, 0);
}

void sithCogFunctionThing_SyncThingState(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing)
        sithThing_SyncThing(pThing, SITHTHING_SYNC_STATE);
}

void sithCogFunctionThing_GetMajorMode(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if (pThing && pThing->pPuppetClass && pThing->renderData.puppet)
        sithCogExec_PushInt(pCog, pThing->puppet->majorMode);
    else
        sithCogExec_PushInt(pCog, -1);
}

// MOTS added
void sithCogFunctionThing_GetThingMaxVelocity(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing && pThing->moveType == SITH_MT_PHYSICS) 
    {
        sithCogExec_PushFlex(pCog,pThing->physicsParams.maxVelocity);
    }
    else 
    {
        sithCogExec_PushFlex(pCog,0.0);
    }
}

// MOTS added
void sithCogFunctionThing_SetThingMaxVelocity(sithCog *pCog)
{
    cog_flex_t val = sithCogExec_PopFlex(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing && pThing->moveType == SITH_MT_PHYSICS) 
    {
        pThing->physicsParams.maxVelocity = val;
    }
}

// MOTS added
void sithCogFunctionThing_GetThingMaxAngularVelocity(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing && pThing->moveType == SITH_MT_PHYSICS) 
    {
        sithCogExec_PushFlex(pCog,pThing->physicsParams.maxRotationVelocity);
    }
    else 
    {
        sithCogExec_PushFlex(pCog,0.0);
    }
}

// MOTS added
void sithCogFunctionThing_SetThingMaxAngularVelocity(sithCog *pCog)
{
    cog_flex_t val = sithCogExec_PopFlex(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing && pThing->moveType == SITH_MT_PHYSICS) 
    {
        pThing->physicsParams.maxRotationVelocity = val;
    }
}

// MOTS added
void sithCogFunctionThing_GetActorHeadPYR(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing && (pThing->type == SITH_THING_ACTOR || pThing->type == SITH_THING_PLAYER))
    {
        sithCogExec_PushVector(pCog, &pThing->actorParams.headPYR);
        return;
    }
    sithCogExec_PushVector(pCog,&rdroid_zeroVector3);
}

// MOTS added
void sithCogFunctionThing_SetHeadPYR(sithCog *pCog)
{
    rdVector3 tmp;

    sithCogExec_PopVector(pCog, &tmp);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing && (pThing->type == SITH_THING_ACTOR || pThing->type == SITH_THING_PLAYER))
    {
        rdVector_Copy3(&pThing->actorParams.headPYR, &tmp);
    }
}

// MOTS added
void sithCogFunctionThing_SetMaxHeadPitch(sithCog *pCog)
{
    cog_flex_t val = sithCogExec_PopFlex(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing && pThing->moveType == SITH_MT_PHYSICS) 
    {
        sithCogExec_PushFlex(pCog, pThing->actorParams.maxHeadPitch);
        pThing->actorParams.maxHeadPitch = val;
    }
}

// MOTS added
void sithCogFunctionThing_SetMinHeadPitch(sithCog *pCog)
{
    cog_flex_t val = sithCogExec_PopFlex(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing && pThing->moveType == SITH_MT_PHYSICS) 
    {
        sithCogExec_PushFlex(pCog, pThing->actorParams.minHeadPitch);
        pThing->actorParams.minHeadPitch = val;
    }
}

// MOTS added
void sithCogFunctionThing_SetWeaponTarget(sithCog *pCog)
{
    cog_flex_t fVar1 = sithCogExec_PopFlex(pCog);
    SithThing* pTargetThing = sithCogExec_PopThing(pCog);
    SithThing* pWeaponThing = sithCogExec_PopThing(pCog);

    if (fVar1 > 0.0 && pWeaponThing && pWeaponThing->type == SITH_THING_WEAPON) 
    {
        pWeaponThing->weaponParams.pTargetThing = pTargetThing;
        pWeaponThing->weaponParams.field_38 = fVar1;
    }
}

// MOTS added
void sithCogFunctionThing_InterpolatePYR(sithCog *pCog)
{
    rdVector3 tmpOut;
    rdVector3 inVec2;
    rdVector3 tmpAngles;
    rdVector3 inVec1;
    rdVector3 inVec0;
    rdVector3 tmpAngles2;
    rdMatrix34 local_30;
    
    cog_flex_t fVar1 = sithCogExec_PopFlex(pCog);
    sithCogExec_PopVector(pCog,&inVec0);
    sithCogExec_PopVector(pCog,&inVec1);
    sithCogExec_PopVector(pCog,&inVec2);
    tmpOut.x = inVec1.x - inVec2.x;
    tmpOut.y = inVec1.y - inVec2.y;
    tmpOut.z = inVec1.z - inVec2.z;
    rdVector_Normalize3Acc(&tmpOut);
    rdMatrix_BuildFromLook34(&local_30,&tmpOut);
    rdMatrix_ExtractAngles34(&local_30,&tmpAngles);
    tmpOut.x = inVec0.x - inVec2.x;
    tmpOut.y = inVec0.y - inVec2.y;
    tmpOut.z = inVec0.z - inVec2.z;
    rdVector_Normalize3Acc(&tmpOut);
    rdMatrix_BuildFromLook34(&local_30,&tmpOut);
    rdMatrix_ExtractAngles34(&local_30,&tmpAngles2);
    tmpOut.x = (tmpAngles2.x - tmpAngles.x) * fVar1 + tmpAngles.x;
    tmpOut.y = (tmpAngles2.y - tmpAngles.y) * fVar1 + tmpAngles.y;
    tmpOut.z = (tmpAngles2.z - tmpAngles.z) * fVar1 + tmpAngles.z;
    sithCogExec_PushVector(pCog,&tmpOut);
    return;
}

// MOTS added
void sithCogFunctionThing_SetJointAngle(sithCog *pCog)
{
    rdVector3 *prVar1;
    int arg1;
    SithThing *pThing;

    cog_flex_t fVar2 = sithCogExec_PopFlex(pCog);
    arg1 = sithCogExec_PopInt(pCog);
    pThing = sithCogExec_PopThing(pCog);
    if (((pThing && pThing->pPuppetClass) 
      && (pThing->renderData.type == RD_THING_MODEL3)) 
      && ((prVar1 = pThing->renderData.hierarchyNodes2, prVar1 != NULL &&
      (arg1 = pThing->pPuppetClass->aJoints[arg1],
      arg1 > -1 && arg1 <= (int)(pThing->renderData.model3->numHNodes - 1))))) 
    {
        prVar1[arg1].x = fVar2;
    }
}

// MOTS added
void sithCogFunctionThing_GetJointAngle(sithCog *pCog)
{
    rdVector3 *prVar1;

    flex_t local_4 = -1.0;
    int arg1 = sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing)
    {
        if (((pThing->pPuppetClass && pThing->renderData.type == RD_THING_MODEL3) &&
            (prVar1 = (pThing->renderData).hierarchyNodes2, prVar1 != NULL)) &&
           (arg1 = pThing->pPuppetClass->aJoints[arg1],
           arg1 > -1 && arg1 <= (int)(pThing->renderData.model3->numHNodes - 1))) 
        {
          local_4 = prVar1[arg1].x;
        }
        sithCogExec_PushFlex(pCog,local_4);
    }
}

// MOTS added
void sithCogFunctionThing_SetThingLookPYR(sithCog *pCog)
{
    int iVar1;
    SithThing *pThing;
    rdVector3 pyr;
    rdMatrix34 tmp_mat;

    iVar1 = sithCogExec_PopVector(pCog, &pyr);
    pThing = sithCogExec_PopThing(pCog);
    if (pThing && iVar1 == 1) 
    {
        rdMatrix_BuildRotate34(&tmp_mat, &pyr);
        rdVector_Normalize3Acc(&tmp_mat.lvec);
        rdMatrix_BuildFromLook34(&pThing->orient, &tmp_mat.lvec);
        if (COG_SHOULD_SYNC(pCog)) {
            sithThing_SyncThing(pThing, 1);
        }
    }
    return;
}

// DW added
void sithCogFunctionThing_GetThingInsertOffset(sithCog *pCog)
{
    rdModel3 *prVar1;
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (((pThing != (SithThing *)0x0) 
        && ((pThing->renderData).type == RD_THING_MODEL3)) 
        && (prVar1 = (pThing->renderData).model3, prVar1 != (rdModel3 *)0x0))
    {
        sithCogExec_PushVector(pCog,&prVar1->insertOffset);
        return;
    }
    sithCogExec_PushVector(pCog,&rdroid_zeroVector3);
}



void sithCogFunctionThing_Startup(SithCogSymbolTable* pCog)
{
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_WaitForStop, "waitforstop");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_StopThing, "stopthing");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_DestroyThing, "destroything");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetHealth, "getthinghealth");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetHealth, "gethealth");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_HealThing, "healthing");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingLight, "getthinglight");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_ThingLight, "setthinglight");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_ThingLight, "thinglight");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_ThingLightAnim, "thinglightanim");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_Rotate, "rotate");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_CreateThing, "creatething");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_CreateThingLocal, "createthinglocal");
    }

    // DW added: ?
    if (Main_bDwCompat) {
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_CreateThing, "createthingnr");
    }
    else {
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_CreateThingNr, "createthingnr");
    }

    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_CreateThingAtPosMots, "createthingatpos");
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_CreateThingAtPosOwner, "createthingatposowner");
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_CreateThingAtPos, "createthingatposold");
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_CreateThingAtPosNrMots, "createthingatposnr");
    }
    else {
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_CreateThingAtPos, "createthingatpos");
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_CreateThingAtPosNr, "createthingatposnr");
    }
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_RotatePivot, "rotatepivot");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_CaptureThing, "capturething");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_ReleaseThing, "releasething");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetThingVel, "setthingvel");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_AddThingVel, "addthingvel");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_ApplyForce, "applyforce");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_DetachThing, "detachthing");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingAttachFlags, "getattachflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingAttachFlags, "getthingattachflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_AttachThingToSurf, "attachthingtosurf");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_AttachThingToThing, "attachthingtothing");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetArmedMode, "setarmedmode");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetThingFlags, "setthingflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_ClearThingFlags, "clearthingflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_TeleportThing, "teleportthing");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetThingType, "setthingtype");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetCollideType, "setcollidetype");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetHeadLightIntensity, "setheadlightintensity");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingGeoMode, "getthinggeomode");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetThingGeoMode, "setthinggeomode");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingLightMode, "getthinglightmode");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetThingLightMode, "setthinglightmode");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingTexMode, "getthingtexmode");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetThingTexMode, "setthingtexmode");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingCurGeoMode, "getthingcurgeomode");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetThingCurGeoMode, "setthingcurgeomode");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingCurLightMode, "getthingcurlightmode");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetThingCurLightMode, "setthingcurlightmode");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingCurTexMode, "getthingcurtexmode");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetThingCurTexMode, "setthingcurtexmode");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetActorExtraSpeed, "setactorextraspeed");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingType, "getthingtype");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_IsThingMoving, "isthingmoving");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_IsThingMoving, "ismoving");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetCurFrame, "getcurframe");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetGoalFrame, "getgoalframe");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingParent, "getthingparent");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetThingParent, "setthingparent");
    }
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingSector, "getthingsector");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingPos, "getthingpos");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetThingPos, "setthingpos");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetThingPosEx, "setthingposex");
    }
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingVelocity, "getthingvel");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingUVec, "getthinguvec");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingLVec, "getthinglvec");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingLVecPYR, "getthinglvecpyr");
    }
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingRVec, "getthingrvec");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingFlags, "getthingflags");
    if (Main_bDwCompat) {
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingInsertOffset, "getthinginsertoffset");
    }
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetCollideType, "getcollidetype");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetHeadLightIntensity, "getheadlightintensity");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_IsThingVisible, "isthingvisible");
    if (Main_bDwCompat) {
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingCollideSize, "getthingradius");
    }
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetThingPulse, "setthingpulse");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetThingTimer, "setthingtimer");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetInventory, "getinv");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetInventory, "setinv"); // DW added: g_debugModeFlags & DEBUGFLAG_100 check
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_ChangeInventory, "changeinv"); // DW added: g_debugModeFlags & DEBUGFLAG_100 check
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetInventoryCog, "getinvcog");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetInventoryMinimum, "getinvmin");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetInventoryMaximum, "getinvmax");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetCurInvWeapon, "getcurinvweapon2");
        //sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetCurInvWeaponMots, "getcurinvweapon");
    }
    else {
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetCurInvWeapon, "getcurinvweapon");
    }
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetCurInvWeapon, "setcurinvweapon");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_PlayKey, "playkey");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_StopKey, "stopkey");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetThingModel, "setthingmodel");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingModel, "getthingmodel");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_PlayMode, "playmode");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetMajorMode, "getmajormode");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_FirstThingInSector, "firstthinginsector");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_NextThingInSector, "nextthinginsector");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_PrevThingInSector, "prevthinginsector");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_MoveToFrame, "movetoframe");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SkipToFrame, "skiptoframe");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_JumpToFrame, "jumptoframe");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_PathMovePause, "pathmovepause");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_PathMoveResume, "pathmoveresume");
    if (Main_bDwCompat) {
        // TODO
        //sithCog_RegisterFunction(ctx, sithCogFunctionThing_AddLaser, "addlaser");
        //sithCog_RegisterFunction(ctx, sithCogFunctionThing_AddBeam, "addbeam");
        //sithCog_RegisterFunction(ctx, sithCogFunctionThing_RemoveLaser, "removelaser");
        //sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetLaserColor, "getlasercolor");
        //sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetLaserId, "getlaserid");
        //sithCog_RegisterFunction(ctx, sithCogFunctionThing_ComputeCatapultVelocity, "computecatapultvelocity");
    }
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingTemplate, "getthingtemplate");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_DamageThing, "damagething");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetLifeleft, "setlifeleft");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetLifeleft, "getlifeleft");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetThingThrust, "setthingthrust");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingThrust, "getthingthrust");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetHealth, "setthinghealth");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetHealth, "sethealth");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_AmputateJoint, "amputatejoint");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetActorWeapon, "setactorweapon");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetActorWeaponMots, "getactorweapon");
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetActorWeapon, "getactorweapon2");
    }
    else {
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetActorWeapon, "getactorweapon");
    }
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetPhysicsFlags, "getphysicsflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetPhysicsFlags, "setphysicsflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_ClearPhysicsFlags, "clearphysicsflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SkillTarget, "skilltarget");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_ParseArg, "parsearg");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingRotVel, "getthingrotvel");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetThingRotVel, "setthingrotvel");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetThingLook, "setthinglook");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetThingLookPYR, "setthinglookpyr");
    }
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_IsThingCrouching, "isthingcrouching"); // DW removed
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_IsThingCrouching, "iscrouching");  // DW removed
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingClassCog, "getthingclasscog");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetThingClassCog, "setthingclasscog");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingCaptureCog, "getthingcapturecog");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetThingCaptureCog, "setthingcapturecog");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingRespawn, "getthingrespawn");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingSignature, "getthingsignature");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(pCog,sithCogFunctionThing_GetThingGuid,"getthingguid");
        sithCog_RegisterFunction(pCog,sithCogFunctionThing_GetGuidThing,"getguidthing");
    }
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetThingAttachFlags, "setthingattachflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_ClearThingAttachFlags, "clearthingattachflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetParticleSize, "getparticlesize");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetParticleSize, "setparticlesize");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetParticleGrowthSpeed, "getparticlegrowthspeed");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetParticleGrowthSpeed, "setparticlegrowthspeed");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetParticleTimeoutRate, "getparticletimeoutrate");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetParticleTimeoutRate, "setparticletimeoutrate");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetTypeFlags, "gettypeflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetTypeFlags, "settypeflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_ClearTypeFlags, "cleartypeflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetTypeFlags, "getactorflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetTypeFlags, "setactorflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_ClearTypeFlags, "clearactorflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetTypeFlags, "getweaponflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetTypeFlags, "setweaponflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_ClearTypeFlags, "clearweaponflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetTypeFlags, "getexplosionflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetTypeFlags, "setexplosionflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_ClearTypeFlags, "clearexplosionflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetTypeFlags, "getitemflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetTypeFlags, "setitemflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_ClearTypeFlags, "clearitemflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetTypeFlags, "getparticleflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetTypeFlags, "setparticleflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_ClearTypeFlags, "clearparticleflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_TakeItem, "takeitem");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_HasLOS, "haslos");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetFireOffset, "getthingfireoffset");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetFireOffset, "setthingfireoffset");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingUserData, "getthinguserdata");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetThingUserData, "setthinguserdata");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingCollideSize, "getthingcollidesize");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetThingCollideSize, "setthingcollidesize");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingMoveSize, "getthingmovesize");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetThingMoveSize, "setthingmovesize");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingMass, "getthingmass");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetThingMass, "setthingmass");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SyncThingPos, "syncthingpos");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SyncThingAttachment, "syncthingattachment");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_SyncThingState, "syncthingstate");
    sithCog_RegisterFunction(pCog, sithCogFunctionThing_AttachThingToThingEx, "attachthingtothingex");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingMaxVelocity, "getthingmaxvelocity");
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetThingMaxVelocity, "setthingmaxvelocity");
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetThingMaxAngularVelocity, "getthingmaxangularvelocity");
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetThingMaxAngularVelocity, "setthingmaxangularvelocity");
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetActorHeadPYR, "getactorheadpyr");
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetHeadPYR, "setactorheadpyr");
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetJointAngle, "setthingjointangle");
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_GetJointAngle, "getthingjointangle");
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetMaxHeadPitch, "setthingmaxheadpitch");
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetMinHeadPitch, "setthingminheadpitch");
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_InterpolatePYR, "interpolatepyr");
        sithCog_RegisterFunction(pCog, sithCogFunctionThing_SetWeaponTarget, "setweapontarget");

        // TODO: weap_eweb_m.cog references a "SetThingCollide" verb? Superceded by "SetThingCollideSize"?
        // TODO: exp_hrail.cog references a "GetUserData" verb? Superceded by "GetThingUserData"?
    }
}
