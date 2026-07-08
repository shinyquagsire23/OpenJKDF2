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

void sithCogFunctionThing_GetThingType(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        sithCogExec_PushInt(ctx, pThing->type);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_CreateThing(sithCog *ctx)
{
    SithThing *v1; // esi
    SithThing *v2; // ebx
    SithThing *v3; // edi

    v1 = sithCogExec_PopThing(ctx);
    v2 = sithCogExec_PopTemplate(ctx);
    if ( v1 && v1->type && v1->sector && v2 && (v3 = sithThing_CreateThing(v2, v1)) != 0 )
    {
        if ( COG_SHOULD_SYNC(ctx) )
        {
            sithDSSThing_CreateThing(v2, v3, v1, 0, 0, 0, 255, 1);
        }
        sithCogExec_PushInt(ctx, v3->idx);
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}


void sithCogFunctionThing_CreateThingNr(sithCog *ctx)
{
    SithThing *v1; // esi
    SithThing *v2; // ebx
    SithThing *v3; // edi

    v1 = sithCogExec_PopThing(ctx);
    v2 = sithCogExec_PopTemplate(ctx);
    if ( v1 && v1->type && v1->sector && v2 && (v3 = sithThing_CreateThing(v2, v1)) != 0 )
    {
        if ( COG_SHOULD_SYNC(ctx) )
        {
            sithDSSThing_CreateThing(v2, v3, v1, 0, 0, 0, 255, 1);
        }
        sithCogExec_PushInt(ctx, v3->idx);
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunctionThing_createThingUnused(sithCog *ctx)
{
    SithThing *v1; // esi
    SithThing *v2; // ebx
    SithThing *v3; // edi
    int v6; // [esp+18h] [ebp+8h]

    v6 = 0; // aaaaaa original is undefined

    v1 = sithCogExec_PopThing(ctx);
    v2 = sithCogExec_PopTemplate(ctx);
    if ( v1 && v1->type && v1->sector && v2 && (v3 = sithThing_CreateThing(v2, v1)) != 0 )
    {
        if ( COG_SHOULD_SYNC(ctx) )
        {
            sithDSSThing_CreateThing(v2, v3, v1, 0, 0, 0, 255, v6);
        }
        sithCogExec_PushInt(ctx, v3->idx);
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}

// MOTS added
void sithCogFunctionThing_CreateThingLocal(sithCog *ctx)
{
    SithThing *v1; // esi
    SithThing *v2; // ebx
    SithThing *v3; // edi

    v1 = sithCogExec_PopThing(ctx);
    v2 = sithCogExec_PopTemplate(ctx);
    if ( v1 && v1->type && v1->sector && v2 && (v3 = sithThing_CreateThing(v2, v1)) != 0 )
    {
        sithCogExec_PushInt(ctx, v3->idx);
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}

// MOTS added
void sithCogFunctionThing_CreateThingAtPosMots(sithCog *ctx)
{
    sithCogFunctionThing_createThingAtPos_nr_Mots(ctx, 0, NULL);
}

// MOTS added
void sithCogFunctionThing_CreateThingAtPosOwner(sithCog *ctx)
{
    SithThing* pThingIn = sithCogExec_PopThing(ctx);
    sithCogFunctionThing_createThingAtPos_nr_Mots(ctx, 0, pThingIn);
}

void sithCogFunctionThing_CreateThingAtPosNrMots(sithCog *ctx)
{
    sithCogFunctionThing_createThingAtPos_nr_Mots(ctx, 0, NULL);
}

// MOTS added
void sithCogFunctionThing_createThingAtPos_nr_Mots(sithCog *ctx, int idk, SithThing* pThingIn)
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

    sithCogExec_PopVector(ctx, &rot);
    sithCogExec_PopVector(ctx, &pos);
    popSector = sithCogExec_PopSector(ctx);
    popTemplate = sithCogExec_PopTemplate(ctx);
    if ( !popTemplate || !popSector )
    {
        sithCogExec_PushInt(ctx, -1);
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

        if ( COG_SHOULD_SYNC(ctx) )
        {
            if (pThingIn) {
                sithDSSThing_SendMOTSNew1(popTemplate, v7, NULL, popSector, &pos, &rot, 0xff, idk); // MOTS added
                sithCogExec_PushInt(ctx, v7->idx);
                return;
            }
            sithDSSThing_CreateThing(popTemplate, v7, 0, popSector, &pos, &rot, 255, idk);
        }
        sithCogExec_PushInt(ctx, v7->idx);
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunctionThing_CreateThingAtPos(sithCog *ctx)
{
    sithCogFunctionThing_createThingAtPos_nr(ctx, 1);
}

void sithCogFunctionThing_CreateThingAtPosNr(sithCog *ctx)
{
    sithCogFunctionThing_createThingAtPos_nr(ctx, 0);
}

void sithCogFunctionThing_createThingAtPos_nr(sithCog *ctx, int idk)
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

    sithCogExec_PopVector(ctx, &rot);
    sithCogExec_PopVector(ctx, &pos);
    popSector = sithCogExec_PopSector(ctx);
    popTemplate = sithCogExec_PopTemplate(ctx);
    if ( !popTemplate || !popSector )
    {
        sithCogExec_PushInt(ctx, -1);
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
        if ( COG_SHOULD_SYNC(ctx) )
        {
            sithDSSThing_CreateThing(popTemplate, v7, 0, popSector, &pos, &rot, 255, idk);
        }
        sithCogExec_PushInt(ctx, v7->idx);
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunctionThing_DamageThing(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);
    int a4 = sithCogExec_PopInt(ctx);
    cog_flex_t a5 = sithCogExec_PopFlex(ctx);
    SithThing* pThing2 = sithCogExec_PopThing(ctx);

    if ( a5 > 0.0 && pThing2 )
    {
        if ( !pThing )
            pThing = pThing2;
        if ( COG_SHOULD_SYNC(ctx) )
        {
            sithDSSThing_DamageThing(pThing2, pThing, a5, a4, -1, 1);
        }
        sithCogExec_PushFlex(ctx, sithThing_DamageThing(pThing2, pThing, a5, a4));
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunctionThing_HealThing(sithCog *ctx)
{
    cog_flex_t amt = sithCogExec_PopFlex(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (amt > 0.0 && pThing && (pThing->type == SITH_THING_ACTOR || pThing->type == SITH_THING_PLAYER))
    {
        pThing->actorParams.health += amt;
        if ( pThing->actorParams.health > pThing->actorParams.maxHealth)
            pThing->actorParams.health = pThing->actorParams.maxHealth;
    }
}

void sithCogFunctionThing_GetHealth(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && (pThing->type == SITH_THING_ACTOR || pThing->type == SITH_THING_PLAYER) )
        sithCogExec_PushFlex(ctx, pThing->actorParams.health);
    else
        sithCogExec_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_SetHealth(sithCog *ctx)
{
    cog_flex_t amt = sithCogExec_PopFlex(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && (pThing->type == SITH_THING_ACTOR || pThing->type == SITH_THING_PLAYER))
        pThing->actorParams.health = amt;
}

void sithCogFunctionThing_DestroyThing(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (!pThing)
        return;

    //printf("destroy %x %s\n", pThing->guid, ctx->cogscript_fpath);

    if (COG_SHOULD_SYNC(ctx) )
        sithDSSThing_DestroyThing(pThing->guid, -1);

    sithThing_DestroyThing(pThing);
}

void sithCogFunctionThing_JumpToFrame(sithCog *ctx)
{
    SithSector* sector = sithCogExec_PopSector(ctx);
    uint32_t frame = sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

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

void sithCogFunctionThing_MoveToFrame(sithCog *ctx)
{
    cog_flex_t speed = sithCogExec_PopFlex(ctx) * 0.1;
    int frame = sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && pThing->moveType == SITH_MT_PATH && pThing->trackParams.loadedFrames > frame )
    {
        if ( speed == 0.0 )
            speed = 0.5;

        sithTrackThing_MoveToFrame(pThing, frame, speed);

        if (COG_SHOULD_SYNC(ctx))
            sithDSSThing_PathMove(pThing, frame, speed, 0, -1, 255);
    }
}

void sithCogFunctionThing_SkipToFrame(sithCog *ctx)
{
    cog_flex_t speed = sithCogExec_PopFlex(ctx) * 0.1;
    int frame = sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && pThing->moveType == SITH_MT_PATH && pThing->trackParams.loadedFrames > frame )
    {
        if ( speed == 0.0 )
            speed = 0.5;

        sithTrackThing_SkipToFrame(pThing, frame, speed);

        if (COG_SHOULD_SYNC(ctx))
            sithDSSThing_PathMove(pThing, frame, speed, 1, -1, 255);
    }
}

void sithCogFunctionThing_RotatePivot(sithCog *ctx)
{
    cog_flex_t speed = sithCogExec_PopFlex(ctx);
    uint32_t frame = sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

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

void sithCogFunctionThing_Rotate(sithCog *ctx)
{
    rdVector3 rot;

    sithCogExec_PopVector(ctx, &rot);
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
    {
        if ( pThing->moveType == SITH_MT_PATH )
            sithTrackThing_Rotate(pThing, &rot);
    }
}

void sithCogFunctionThing_GetThingLight(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        sithCogExec_PushFlex(ctx, pThing->light);
    else
        sithCogExec_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_ThingLight(sithCog *ctx)
{
    cog_flex_t idk = sithCogExec_PopFlex(ctx);
    cog_flex_t light = sithCogExec_PopFlex(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

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

void sithCogFunctionThing_ThingLightAnim(sithCog *ctx)
{
    cog_flex_t idk_; // ST08_4
    rdSurface *surface; // eax

    cog_flex_t idk = sithCogExec_PopFlex(ctx);
    cog_flex_t light2 = sithCogExec_PopFlex(ctx);
    cog_flex_t light = sithCogExec_PopFlex(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing
      && light2 >= (flex_d_t)light
      && idk > 0.0
      && (idk_ = idk * 0.5, pThing->light = light, (surface = sithSurface_SetThingLight(pThing, light2, idk_, 1)) != 0) )
    {
        sithCogExec_PushInt(ctx, surface->index);
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunctionThing_WaitForStop(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && pThing->moveType == SITH_MT_PATH && pThing->trackParams.flags & 3 )
    {
        int idx = pThing->idx;
        ctx->script_running = 3;
        ctx->wakeTimeMs = idx;

        if ( ctx->flags & SITH_COG_DEBUG)
        {
#ifdef SITH_DEBUG_STRUCT_NAMES
            _sprintf(std_g_genBuffer, "Cog %s: Waiting for stop on object %d.\n", ctx->cogscript_fpath, idx);
            sithConsole_PrintString(std_g_genBuffer);
#endif
        }
    }
}

void sithCogFunctionThing_GetThingSector(sithCog *ctx)
{
    SithSector *sector;

    SithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && (sector = pThing->sector) != 0 )
        sithCogExec_PushInt(ctx, sector->id);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_GetCurFrame(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && pThing->moveType == SITH_MT_PATH )
        sithCogExec_PushInt(ctx, pThing->curframe);
    else
        sithCogExec_PushInt(ctx, 0);
}

void sithCogFunctionThing_GetGoalFrame(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && pThing->moveType == SITH_MT_PATH )
        sithCogExec_PushInt(ctx, pThing->goalframe);
    else
        sithCogExec_PushInt(ctx, 0);
}

void sithCogFunctionThing_StopThing(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (!pThing)
        return;

    if ( pThing->moveType == SITH_MT_PATH )
    {
        sithTrackThing_Stop(pThing);
        if (COG_SHOULD_SYNC(ctx))
            sithDSSThing_PathMove(pThing, 0, 0.0, 2, -1, 255);
    }
    else if (pThing->moveType == SITH_MT_PHYSICS)
    {
        sithPhysics_ResetThingMovement(pThing);
    }
}

void sithCogFunctionThing_IsThingMoving(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if ( !pThing || pThing->type == SITH_THING_FREE )
    {
        sithCogExec_PushInt(ctx, 0);
        return;
    }

    if ( pThing->moveType == SITH_MT_PHYSICS )
    {
        if (!rdVector_IsZero3(&pThing->physicsParams.vel))
        {
            sithCogExec_PushInt(ctx, 1);
            return;
        }
    }
    else if ( pThing->moveType == SITH_MT_PATH )
    {
        sithCogExec_PushInt(ctx, pThing->trackParams.flags & 3);
        return;
    }

    sithCogExec_PushInt(ctx, 0);
}

void sithCogFunctionThing_SetThingPulse(sithCog *ctx)
{
    cog_flex_t pulseSecs = sithCogExec_PopFlex(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);
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

void sithCogFunctionThing_SetThingTimer(sithCog *ctx)
{
    cog_flex_t timerSecs = sithCogExec_PopFlex(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);
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

void sithCogFunctionThing_CaptureThing(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
    {
        pThing->pCaptureCog = ctx;
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

void sithCogFunctionThing_GetThingParent(sithCog *ctx)
{
    SithThing* parent;

    SithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && (parent = sithThing_GetThingParent(pThing)) != 0 )
        sithCogExec_PushInt(ctx, parent->idx);
    else
        sithCogExec_PushInt(ctx, -1);
}

// MOTS added
void sithCogFunctionThing_SetThingParent(sithCog *ctx)
{
    int guid = sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);
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

void sithCogFunctionThing_GetThingPos(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        sithCogExec_PushVector(ctx, &pThing->position);
    else
        sithCogExec_PushVector(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_SetThingPos(sithCog *ctx)
{
    rdVector3 poppedVec;

    sithCogExec_PopVector(ctx, &poppedVec);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
    {
        rdVector_Copy3(&pThing->position, &poppedVec);
        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_Pos(pThing, -1, 1);
        }
        sithCogExec_PushInt(ctx, 1);
    }
    else
    {
        sithCogExec_PushInt(ctx, 0);
    }
}

// MOTS added
void sithCogFunctionThing_SetThingPosEx(sithCog *ctx)
{
    rdVector3 poppedVec;

    SithSector* pSector = sithCogExec_PopSector(ctx);
    sithCogExec_PopVector(ctx, &poppedVec);
    SithThing* pThing = sithCogExec_PopThing(ctx);
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

        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_Pos(pThing, -1, 1);
        }
        sithCogExec_PushInt(ctx, 1);
    }
    else
    {
        sithCogExec_PushInt(ctx, 0);
    }
}

void sithCogFunctionThing_GetInventory(sithCog *ctx)
{
    unsigned int binIdx;
    SithThing *pLocalPlayer;

    binIdx = sithCogExec_PopInt(ctx);
    pLocalPlayer = sithCogExec_PopThing(ctx);

    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }

    if ( pLocalPlayer 
         && pLocalPlayer->type == SITH_THING_PLAYER 
         && pLocalPlayer->actorParams.pPlayer 
         && binIdx < SITHBIN_NUMBINS )
    {
        sithCogExec_PushFlex(ctx, sithInventory_GetInventory(pLocalPlayer, binIdx));
    }
    else
    {
        sithCogExec_PushFlex(ctx, 0.0);
    }
}

void sithCogFunctionThing_SetInventory(sithCog *ctx)
{
    cog_flex_t amt = sithCogExec_PopFlex(ctx);
    uint32_t binIdx = sithCogExec_PopInt(ctx);
    SithThing* pLocalPlayer = sithCogExec_PopThing(ctx);

    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }

    if ( pLocalPlayer 
         && pLocalPlayer->type == SITH_THING_PLAYER 
         && pLocalPlayer->actorParams.pPlayer 
         && binIdx < SITHBIN_NUMBINS )
        sithInventory_SetInventory(pLocalPlayer, binIdx, amt);
}

void sithCogFunctionThing_ChangeInventory(sithCog *ctx)
{
    cog_flex_t amt = sithCogExec_PopFlex(ctx);
    uint32_t binIdx = sithCogExec_PopInt(ctx);
    SithThing* pLocalPlayer = sithCogExec_PopThing(ctx);

    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }

    if ( pLocalPlayer 
         && pLocalPlayer->type == SITH_THING_PLAYER 
         && pLocalPlayer->actorParams.pPlayer 
         && binIdx < SITHBIN_NUMBINS )
    {
        sithCogExec_PushFlex(ctx, sithInventory_ChangeInventory(pLocalPlayer, binIdx, amt));
    }
    else
    {
        sithCogExec_PushFlex(ctx, 0.0);
    }
}

void sithCogFunctionThing_GetInventoryCog(sithCog *ctx)
{
    unsigned int binIdx;
    SithThing *pLocalPlayer;
    SithInventoryType *desc;
    sithCog *descCog;

    binIdx = sithCogExec_PopInt(ctx);
    pLocalPlayer = sithCogExec_PopThing(ctx);

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
        sithCogExec_PushInt(ctx, descCog->selfCog);
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunctionThing_GetThingVelocity(sithCog *ctx)
{
    rdVector3 retval;

    rdVector_Copy3(&retval, (rdVector3*)&rdroid_zeroVector3);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
    {
        if ( pThing->moveType == SITH_MT_PHYSICS)
        {
            rdVector_Copy3(&retval, &pThing->physicsParams.vel);
        }
        else if ( pThing->moveType == SITH_MT_PATH )
        {
            rdVector_Scale3(&retval, &pThing->trackParams.vel, pThing->trackParams.lerpSpeed);
        }
        sithCogExec_PushVector(ctx, &retval);
    }
    else
    {
        sithCogExec_PushVector(ctx, (rdVector3*)&rdroid_zeroVector3);
    }
}

void sithCogFunctionThing_SetThingVel(sithCog *ctx)
{
    rdVector3 poppedVec;

    sithCogExec_PopVector(ctx, &poppedVec);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && pThing->moveType == SITH_MT_PHYSICS)
    {
        rdVector_Copy3(&pThing->physicsParams.vel, &poppedVec);
        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SyncThing(pThing, SITHTHING_SYNC_POS);
        }
    }
}

void sithCogFunctionThing_ApplyForce(sithCog *ctx)
{
    rdVector3 poppedVec;

    sithCogExec_PopVector(ctx, &poppedVec);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && pThing->moveType == SITH_MT_PHYSICS)
    {
        sithPhysics_ApplyForce(pThing, &poppedVec);
        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SyncThing(pThing, SITHTHING_SYNC_POS);
        }
    }
}

void sithCogFunctionThing_AddThingVel(sithCog *ctx)
{
    rdVector3 poppedVec;

    sithCogExec_PopVector(ctx, &poppedVec);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && pThing->moveType == SITH_MT_PHYSICS)
    {
        rdVector_Add3Acc(&pThing->physicsParams.vel, &poppedVec);
        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SyncThing(pThing, SITHTHING_SYNC_POS);
        }
    }
}

void sithCogFunctionThing_GetThingLVec(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        sithCogExec_PushVector(ctx, &pThing->orient.lvec);
    else
        sithCogExec_PushVector(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_GetThingLVecPYR(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (!pThing) {
        sithCogExec_PushVector(ctx, (rdVector3*)&rdroid_zeroVector3);
        return;
    }

    rdVector3 pyrOut;
    rdMatrix34 lookOrient;
    rdMatrix_Copy34(&lookOrient, &pThing->orient);
    rdMatrix_ExtractAngles34(&lookOrient, &pyrOut);
    sithCogExec_PushVector(ctx, &pyrOut);
}

void sithCogFunctionThing_GetThingUVec(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        sithCogExec_PushVector(ctx, &pThing->orient.uvec);
    else
        sithCogExec_PushVector(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_GetThingRVec(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        sithCogExec_PushVector(ctx, &pThing->orient.rvec);
    else
        sithCogExec_PushVector(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_GetEyePYR(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && (pThing->type == SITH_THING_ACTOR || pThing->type == SITH_THING_PLAYER))
        sithCogExec_PushVector(ctx, &pThing->actorParams.headPYR);
    else
        sithCogExec_PushVector(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_DetachThing(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
    {
        sithThing_DetachThing(pThing);
        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_Attachment(pThing, -1, 255, 1);
        }
    }
}

void sithCogFunctionThing_GetThingAttachFlags(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        sithCogExec_PushInt(ctx, pThing->attach_flags);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_AttachThingToSurf(sithCog *ctx)
{
    SithSurface* surface = sithCogExec_PopSurface(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && surface)
    {
        sithThing_AttachThingToSurface(pThing, surface, 1);
        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_Attachment(pThing, -1, 255, 1);
        }
    }
}

void sithCogFunctionThing_AttachThingToThing(sithCog *ctx)
{
    SithThing* attached = sithCogExec_PopThing(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && attached)
    {
        sithThing_AttachThingToThing(pThing, attached);
        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_Attachment(pThing, -1, 255, 1);
        }
    }
}

void sithCogFunctionThing_AttachThingToThingEx(sithCog *ctx)
{
    int attachFlags = sithCogExec_PopInt(ctx);
    SithThing* attached = sithCogExec_PopThing(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && attached)
    {
        sithThing_AttachThingToThing(pThing, attached);
        pThing->attach_flags |= attachFlags;

        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_Attachment(pThing, -1, 255, 1);
        }
    }
}

void sithCogFunctionThing_PlayMode(sithCog *ctx)
{
    int mode = sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if ( mode < 43 && pThing && pThing->pPuppetClass && pThing->renderData.puppet)
    {
        int track = sithPuppet_PlayMode(pThing, mode, 0);
        if (track >= 0)
        {
            sithCogExec_PushInt(ctx, track);
            if (COG_SHOULD_SYNC(ctx))
            {
                sithDSSThing_PlayKeyMode(pThing, mode, pThing->renderData.puppet->tracks[track].field_130, -1, 255);
            }
        }
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunctionThing_PlayKey(sithCog *ctx)
{
    int trackNum = sithCogExec_PopInt(ctx);
    int popInt = sithCogExec_PopInt(ctx);
    rdKeyframe* keyframe = sithCogExec_PopKeyframe(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);
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
        sithCogExec_PushInt(ctx, track);
        if ( pThing->moveType == SITH_MT_PATH )
        {
            if ( pThing->trackParams.flags )
                sithTrackThing_Stop(pThing);
            rdVector_Copy3(&pThing->trackParams.moveFrameOrientation.scale, &pThing->position);
        }
        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_PlayKey(pThing, keyframe, trackNum, popInt, pThing->renderData.puppet->tracks[track].field_130, -1, 255);
        }
        return;
    }

fail:
    sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_StopKey(sithCog *ctx)
{
    cog_flex_t poppedFlex = sithCogExec_PopFlex(ctx);
    int track = sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (!pThing)
        return;

    rdPuppet* puppet = pThing->renderData.puppet;
    if (!puppet)
        return;

    if ( track >= 0 && track < 4 && poppedFlex >= 0.0 )
    {
        int v6 = puppet->tracks[track].field_130;
        if ( sithPuppet_StopKey(puppet, track, poppedFlex) )
        {
            if (COG_SHOULD_SYNC(ctx))
            {
                sithDSSThing_StopKey(pThing, v6, poppedFlex, -1, 255);
            }
        }
    }
}

void sithCogFunctionThing_SetThingModel(sithCog *ctx)
{
    rdModel3* model = sithCogExec_PopModel3(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);
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

        sithCogExec_PushInt(ctx, v5);

        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_SetModel(pThing, -1);
        }
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunctionThing_GetThingModel(sithCog *ctx)
{
    rdModel3 *model;

    SithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && pThing->renderData.type == RD_THING_MODEL3 && (model = pThing->renderData.model3) != 0 )
        sithCogExec_PushInt(ctx, model->id);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetArmedMode(sithCog *ctx)
{
    int poppedInt = sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && poppedInt >= 0 && poppedInt <= 2)
    {
        sithPuppet_SetArmedMode(pThing, poppedInt);

        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_UpdateState(pThing, -1, 255);
        }
    }
}

void sithCogFunctionThing_GetThingFlags(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        sithCogExec_PushInt(ctx, pThing->flags);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetThingFlags(sithCog *ctx)
{
    int flags = sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && flags)
    {
        pThing->flags |= flags;

        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SyncThing(pThing, SITHTHING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_ClearThingFlags(sithCog *ctx)
{
    int flags = sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && flags)
    {
        pThing->flags &= ~flags;

        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SyncThing(pThing, SITHTHING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_TeleportThing(sithCog *ctx)
{
    SithThing* thingTo = sithCogExec_PopThing(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

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

        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_Pos(pThing, -1, 1);
        }
    }
}

void sithCogFunctionThing_SetThingType(sithCog *ctx)
{
    int type = sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && type >= 0 && type < 12 )
        pThing->type = type;
}

void sithCogFunctionThing_GetCollideType(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        sithCogExec_PushInt(ctx, pThing->collide);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetCollideType(sithCog *ctx)
{
    int collideType = sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && collideType < 4)
    {
        pThing->collide = collideType;

        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SyncThing(pThing, SITHTHING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_FirstThingInSector(sithCog *ctx)
{
    SithSector* sector = sithCogExec_PopSector(ctx);
    if (sector)
    {
        SithThing* pThing = sector->pFirstThingInSector;

        if (pThing)
            sithCogExec_PushInt(ctx, pThing->idx);
        else
            sithCogExec_PushInt(ctx, -1);
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunctionThing_NextThingInSector(sithCog *ctx)
{
    SithThing *pNextThingInSector;

    SithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && (pNextThingInSector = pThing->pNextThingInSector) != 0 )
    {
        sithCogExec_PushInt(ctx, pNextThingInSector->idx);
    }
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_PrevThingInSector(sithCog *ctx)
{
    SithThing *pPrevThingInSector;

    SithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && (pPrevThingInSector = pThing->pPrevThingInSector) != 0 )
        sithCogExec_PushInt(ctx, pPrevThingInSector->idx);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_GetInventoryMinimum(sithCog *ctx)
{
    int binIdx = sithCogExec_PopInt(ctx);
    SithThing* player = sithCogExec_PopThing(ctx);

    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }

    if ( player && player->type == SITH_THING_PLAYER && player->actorParams.pPlayer )
    {
        sithCogExec_PushFlex(ctx, sithInventory_GetInventoryMinimum(player, binIdx));
    }
    else
    {
        sithCogExec_PushFlex(ctx, -1.0);
    }
}

void sithCogFunctionThing_GetInventoryMaximum(sithCog *ctx)
{
    int binIdx = sithCogExec_PopInt(ctx);
    SithThing* player = sithCogExec_PopThing(ctx);

    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }

    if ( player && player->type == SITH_THING_PLAYER && player->actorParams.pPlayer )
    {
        sithCogExec_PushFlex(ctx, sithInventory_GetInventoryMaximum(player, binIdx));
    }
    else
    {
        sithCogExec_PushFlex(ctx, -1.0);
    }
}

// unused/unreferenced
void sithCogFunctionThing_GetLoadedFrames(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && pThing->moveType == SITH_MT_PATH)
        sithCogExec_PushInt(ctx, pThing->trackParams.loadedFrames);
    else
        sithCogExec_PushInt(ctx, -1);
}

// unused/unreferenced
void sithCogFunctionThing_GetFramePos(sithCog *ctx)
{
    uint32_t frame = sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && pThing->moveType == SITH_MT_PATH && frame < pThing->trackParams.loadedFrames )
        sithCogExec_PushVector(ctx, &pThing->trackParams.aFrames[frame].pos);
    sithCogExec_PushVector(ctx, (rdVector3*)&rdroid_zeroVector3);
}

// unused/unreferenced
void sithCogFunctionThing_GetFrameRot(sithCog *ctx)
{
    uint32_t frame = sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && pThing->moveType == SITH_MT_PATH && frame < pThing->trackParams.loadedFrames)
        sithCogExec_PushVector(ctx, &pThing->trackParams.aFrames[frame].rot);
    sithCogExec_PushVector(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_PathMovePause(sithCog *ctx)
{
    int ret = 0;
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && pThing->moveType == SITH_MT_PATH )
        ret = sithTrackThing_PathMovePause(pThing);

    if ( ret == 1 )
        sithCogExec_PushInt(ctx, pThing->idx);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetHeadLightIntensity(sithCog *ctx)
{
    cog_flex_t intensity = sithCogExec_PopFlex(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && (pThing->type == SITH_THING_ACTOR || pThing->type == SITH_THING_PLAYER))
    {
        pThing->actorParams.lightIntensity = intensity;
        sithCogExec_PushFlex(ctx, intensity);
    }
    else
    {
        sithCogExec_PushFlex(ctx, -1.0);
    }
}

void sithCogFunctionThing_GetHeadLightIntensity(sithCog *ctx)
{
    sithCogExec_PopFlex(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && (pThing->type == SITH_THING_ACTOR || pThing->type == SITH_THING_PLAYER))
        sithCogExec_PushFlex(ctx, pThing->actorParams.lightIntensity);
    else
        sithCogExec_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_IsThingVisible(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        sithCogExec_PushInt(ctx, pThing->renderFrame + 1 >= (unsigned int)jkPlayer_currentTickIdx);
    else
        sithCogExec_PushInt(ctx, 0);
}

void sithCogFunctionThing_PathMoveResume(sithCog *ctx)
{
    int ret = 0;
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && pThing->moveType == SITH_THING_ACTOR )
        ret = sithTrackThing_PathMoveResume(pThing);
    if ( ret == 1 )
        sithCogExec_PushInt(ctx, pThing->idx);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetCurInvWeapon(sithCog *ctx)
{
    int binIdx = sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }
    if (pThing)
        sithInventory_SetCurrentWeapon(pThing, binIdx);
}

void sithCogFunctionThing_GetCurInvWeapon(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
    {
        int binIdx = sithInventory_GetCurrentWeapon(pThing);
        if (Main_bMotsCompat) {
            binIdx = sithInventory_SelectWeaponPrior(binIdx);
        }
        sithCogExec_PushInt(ctx, binIdx);
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}

// MOTS added
void sithCogFunctionThing_GetCurInvWeaponMots(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
    {
        int idx = sithInventory_GetCurrentWeapon(pThing);
        sithInventory_SelectWeaponPrior(idx);
        sithCogExec_PushInt(ctx, idx);
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunctionThing_SetThingGeoMode(sithCog *ctx)
{
    rdGeoMode_t mode = (rdGeoMode_t)sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        pThing->renderData.desiredGeoMode = mode;
}

void sithCogFunctionThing_GetThingGeoMode(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        sithCogExec_PushInt(ctx, (int)pThing->renderData.desiredGeoMode);
}

void sithCogFunctionThing_SetThingLightMode(sithCog *ctx)
{
    rdLightMode_t mode = (rdLightMode_t)sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        pThing->renderData.desiredLightMode = mode;
}

void sithCogFunctionThing_GetThingLightMode(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        sithCogExec_PushInt(ctx, (int)pThing->renderData.desiredLightMode);
}

void sithCogFunctionThing_SetThingTexMode(sithCog *ctx)
{
    int mode = sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        pThing->renderData.desiredTexMode = mode;
}

void sithCogFunctionThing_GetThingTexMode(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        sithCogExec_PushInt(ctx, pThing->renderData.desiredTexMode);
}

void sithCogFunctionThing_SetThingCurGeoMode(sithCog *ctx)
{
    rdGeoMode_t mode = (rdGeoMode_t)sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
    {
        pThing->renderData.curGeoMode = mode;
        if (COG_SHOULD_SYNC(ctx))
        {
                sithThing_SyncThing(pThing, SITHTHING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_GetThingCurGeoMode(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        sithCogExec_PushInt(ctx, (int)pThing->renderData.curGeoMode);
}

void sithCogFunctionThing_SetThingCurLightMode(sithCog *ctx)
{
    rdLightMode_t mode = (rdLightMode_t)sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        pThing->renderData.curLightMode = mode;
}

void sithCogFunctionThing_GetThingCurLightMode(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        sithCogExec_PushInt(ctx, (int)pThing->renderData.curLightMode);
}

void sithCogFunctionThing_SetThingCurTexMode(sithCog *ctx)
{
    int mode = sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        pThing->renderData.curTexMode = mode;
}

void sithCogFunctionThing_GetThingCurTexMode(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        sithCogExec_PushInt(ctx, pThing->renderData.curTexMode);
}

void sithCogFunctionThing_SetActorExtraSpeed(sithCog *ctx)
{
    cog_flex_t extraSpeed = sithCogExec_PopFlex(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        pThing->actorParams.extraSpeed = extraSpeed;
}

void sithCogFunctionThing_GetThingTemplate(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && pThing->pTemplate)
        sithCogExec_PushInt(ctx, pThing->pTemplate->idx);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetLifeleft(sithCog *ctx)
{
    cog_flex_t lifeLeftSecs = sithCogExec_PopFlex(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && lifeLeftSecs >= 0.0)
    {
        pThing->msecLifeLeft = (int)(lifeLeftSecs * 1000.0);
        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SyncThing(pThing, SITHTHING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_GetLifeleft(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
    {
        sithCogExec_PushFlex(ctx, (flex_d_t)(unsigned int)pThing->msecLifeLeft * 0.001);
    }
}

void sithCogFunctionThing_SetThingThrust(sithCog *ctx)
{
    rdVector3 poppedVec;

    int couldPopVec = sithCogExec_PopVector(ctx, &poppedVec);
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && pThing->moveType == SITH_MT_PHYSICS && couldPopVec)
    {
        sithCogExec_PushVector(ctx, &pThing->physicsParams.acceleration);
        rdVector_Copy3(&pThing->physicsParams.acceleration, &poppedVec);
    }
}

void sithCogFunctionThing_GetThingThrust(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing )
    {
        if ( pThing->moveType == SITH_MT_PHYSICS )
            sithCogExec_PushVector(ctx, &pThing->physicsParams.acceleration);
    }
}

void sithCogFunctionThing_AmputateJoint(sithCog *ctx)
{
    uint32_t idx = sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
    {
        rdThing* renderData = &pThing->renderData;
        if ( pThing != (SithThing *)-196 )
        {
            SithPuppetClass* pPuppetClass = pThing->pPuppetClass;
            if (pPuppetClass && idx < 0xA)
            {
                int jointIdx = pPuppetClass->bodypart_to_joint[idx];
                if ( jointIdx >= 0 ) {
                    // Added: prevent oob
                    if (renderData->model3 && jointIdx < renderData->model3->numHierarchyNodes)
                        renderData->amputatedJoints[jointIdx] = 1;
                }
            }
        }
    }
}

void sithCogFunctionThing_SetActorWeapon(sithCog *ctx)
{
    SithThing* weapTemplate = sithCogExec_PopTemplate(ctx);
    int weap_idx = sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

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
void sithCogFunctionThing_GetActorWeapon(sithCog *ctx)
{
    int weap_idx = sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

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
            sithCogExec_PushInt(ctx, -1);
            return;
        }

        if (weapTemplate)
        {
            sithCogExec_PushInt(ctx, weapTemplate->idx);
            return;
        }

        sithCogExec_PushInt(ctx, -1);
        return;
    }
}

// MOTS added
void sithCogFunctionThing_GetActorWeaponMots(sithCog *ctx)
{
    int weap_idx = sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

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
            sithCogExec_PushInt(ctx, -1);
            return;
        }

        if (weapTemplate)
        {
            if (pThing->type != SITH_THING_PLAYER) {
                sithCogExec_PushInt(ctx, weapTemplate->idx);
                return;
            }
            int idx = sithInventory_SelectWeaponPrior(weapTemplate->idx);
            sithCogExec_PushInt(ctx, idx);
            return;
        }

        sithCogExec_PushInt(ctx, -1);
        return;
    }
}

void sithCogFunctionThing_GetPhysicsFlags(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && pThing->moveType == SITH_MT_PHYSICS )
        sithCogExec_PushInt(ctx, pThing->physicsParams.flags);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetPhysicsFlags(sithCog *ctx)
{
    int flags = sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && flags && pThing->moveType == SITH_MT_PHYSICS)
    {
        pThing->physicsParams.flags |= flags;
        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SyncThing(pThing, SITHTHING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_ClearPhysicsFlags(sithCog *ctx)
{
    int flags = sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && flags && pThing->moveType == SITH_MT_PHYSICS)
        pThing->physicsParams.flags &= ~flags;
}

void sithCogFunctionThing_SkillTarget(sithCog *ctx)
{
    sithCog *classCog;

    cog_flex_t param1 = sithCogExec_PopFlex(ctx);
    cog_flex_t param0 = sithCogExec_PopFlex(ctx);
    SithThing* otherThing = sithCogExec_PopThing(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

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
                pThing->actorParams.pPlayer->net_id);
            sithCogExec_PushFlex(ctx, 0.0);
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
            sithCogExec_PushFlex(ctx, ret);
        }
    }
    else
    {
        sithCogExec_PushFlex(ctx, -1.0);
    }
}

void sithCogFunctionThing_ParseArg(sithCog *ctx)
{
    char* str = sithCogExec_PopString(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (str && pThing)
    {
        _strncpy(std_g_genBuffer, str, 0x3FFu);
        std_g_genBuffer[1023] = 0;

        stdConffile_ReadArgsFromStr(std_g_genBuffer);
        for (int i = 0 ; i < stdConffile_g_entry.numArgs; i++)
        {
            StdConffileArg* arg = &stdConffile_g_entry.args[i];
            sithThing_ParseArg(arg, pThing);
        }
    }
}

void sithCogFunctionThing_SetThingRotVel(sithCog *ctx)
{
    rdVector3 popped_vector3;

    sithCogExec_PopVector(ctx, &popped_vector3);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && pThing->moveType == SITH_MT_PHYSICS)
    {
        rdVector_Copy3(&pThing->physicsParams.angularVelocity, &popped_vector3);
        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SyncThing(pThing, SITHTHING_SYNC_POS);
        }
    }
}

void sithCogFunctionThing_GetThingRotVel(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && pThing->moveType == SITH_MT_PHYSICS )
        sithCogExec_PushVector(ctx, &pThing->physicsParams.angularVelocity);
    else
        sithCogExec_PushVector(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_SetThingLook(sithCog *ctx)
{
    rdVector3 popped_vector3;

    int pop_v3_retval = sithCogExec_PopVector(ctx, &popped_vector3);
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && pop_v3_retval == 1)
    {
        rdVector_Normalize3Acc(&popped_vector3);
        rdMatrix_BuildFromLook34(&pThing->orient, &popped_vector3);

        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SyncThing(pThing, SITHTHING_SYNC_POS);
        }
    }
}

void sithCogFunctionThing_IsThingCrouching(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if ( !pThing || pThing->moveType != SITH_MT_PHYSICS )
        sithCogExec_PushInt(ctx, -1);

    if (pThing->physicsParams.flags & SITH_PF_CROUCHING)
        sithCogExec_PushInt(ctx, 1);
    else
        sithCogExec_PushInt(ctx, 0);
}

void sithCogFunctionThing_GetThingClassCog(sithCog *ctx)
{
    sithCog *classCog; // eax

    SithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && (classCog = pThing->pCog) != 0 )
        sithCogExec_PushInt(ctx, classCog->selfCog);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetThingClassCog(sithCog *ctx)
{
    sithCog* classCog = sithCogExec_PopCog(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing )
    {
        if ( classCog )
            pThing->pCog = classCog;
    }
}

void sithCogFunctionThing_GetThingCaptureCog(sithCog *ctx)
{
    sithCog *captureCog; // eax

    SithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && (captureCog = pThing->pCaptureCog) != 0 )
        sithCogExec_PushInt(ctx, captureCog->selfCog);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetThingCaptureCog(sithCog *ctx)
{
    sithCog *captureCog; // edi

    captureCog = sithCogExec_PopCog(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing )
    {
        if ( captureCog )
            pThing->pCaptureCog = captureCog;
    }
}

void sithCogFunctionThing_GetThingRespawn(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing && pThing->type == SITH_THING_ITEM)
    {
        sithCogExec_PushFlex(ctx, pThing->itemParams.secRespawnInterval);
    }
}

void sithCogFunctionThing_GetThingSignature(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing )
        sithCogExec_PushInt(ctx, pThing->signature);
    else
        sithCogExec_PushInt(ctx, -1);
}

// MOTS added
void sithCogFunctionThing_GetThingGuid(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing) {
        sithCogExec_PushInt(ctx, pThing->guid);
        return;
    }
    sithCogExec_PushInt(ctx, -1);
}

// MOTS added
void sithCogFunctionThing_GetGuidThing(sithCog *ctx)
{
    int guid = sithCogExec_PopInt(ctx);
    SithThing* pThing = sithThing_GetGuidThing(guid);
    if (pThing == (SithThing *)0x0) {
        sithCogExec_PushInt(ctx,-1);
        return;
    }
    sithCogExec_PushInt(ctx,pThing->idx);
    return;
}

void sithCogFunctionThing_SetThingAttachFlags(sithCog *ctx)
{
    int flags = sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && flags)
    {
        pThing->attach_flags |= flags;

        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_Attachment(pThing, -1, 255, 1);
        }
    }
}

void sithCogFunctionThing_ClearThingAttachFlags(sithCog *ctx)
{
    int flags = sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && flags)
    {
        pThing->attach_flags &= ~flags;

        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_Attachment(pThing, -1, 255, 1);
        }
    }
}

void sithCogFunctionThing_GetParticleSize(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && pThing->type == SITH_THING_PARTICLE)
        sithCogExec_PushFlex(ctx, pThing->particleParams.size);
    else
        sithCogExec_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_SetParticleSize(sithCog *ctx)
{
    cog_flex_t size = sithCogExec_PopFlex(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && pThing->type == SITH_THING_PARTICLE)
    {
        pThing->particleParams.size = size;
    }
}

void sithCogFunctionThing_GetParticleGrowthSpeed(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && pThing->type == SITH_THING_PARTICLE )
        sithCogExec_PushFlex(ctx, pThing->particleParams.growthSpeed);
    else
        sithCogExec_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_SetParticleGrowthSpeed(sithCog *ctx)
{
    cog_flex_t speed = sithCogExec_PopFlex(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && pThing->type == SITH_THING_PARTICLE)
    {
        pThing->particleParams.growthSpeed = speed;
    }
}

void sithCogFunctionThing_GetParticleTimeoutRate(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && pThing->type == SITH_THING_PARTICLE )
        sithCogExec_PushFlex(ctx, pThing->particleParams.rate);
    else
        sithCogExec_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_SetParticleTimeoutRate(sithCog *ctx)
{
    cog_flex_t rate = sithCogExec_PopFlex(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && pThing->type == SITH_THING_PARTICLE)
    {
        pThing->particleParams.rate = rate;
    }
}

void sithCogFunctionThing_GetTypeFlags(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
    {
        switch ( pThing->type )
        {
            case SITH_THING_ACTOR:
            case SITH_THING_ITEM:
            case SITH_THING_PLAYER:
                sithCogExec_PushInt(ctx, pThing->actorParams.flags);
                return;
            case SITH_THING_WEAPON:
            case SITH_THING_PARTICLE:
                sithCogExec_PushInt(ctx, pThing->weaponParams.flags);
                return;
            case SITH_THING_EXPLOSION:
                sithCogExec_PushInt(ctx, pThing->explosionParams.flags);
                return;
        }
    }

    sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetTypeFlags(sithCog *ctx)
{
    int flags = sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

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

        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SyncThing(pThing, SITHTHING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_ClearTypeFlags(sithCog *ctx)
{
    int flags = sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

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

        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SyncThing(pThing, SITHTHING_SYNC_STATE);
        }
    }
}

// MOTS altered
void sithCogFunctionThing_TakeItem(sithCog *ctx)
{
    SithThing* player = sithCogExec_PopThing(ctx);
    SithThing* itemThing = sithCogExec_PopThing(ctx);
    if ( itemThing && (Main_bMotsCompat || player) && itemThing->type == SITH_THING_ITEM )
        sithItem_SetItemTaken(itemThing, player, 0);
}

void sithCogFunctionThing_HasLOS(sithCog *ctx)
{
    SithThing* pThingB = sithCogExec_PopThing(ctx);
    SithThing* pThingA = sithCogExec_PopThing(ctx);

    if ( pThingA && pThingB )
    {
        if (sithCollision_HasLOS(pThingA, pThingB, 0))
            sithCogExec_PushInt(ctx, 1);
        else
            sithCogExec_PushInt(ctx, 0);
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunctionThing_GetFireOffset(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        sithCogExec_PushVector(ctx, &pThing->actorParams.fireOffset);
    else
        sithCogExec_PushVector(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_SetFireOffset(sithCog *ctx)
{
    rdVector3 poppedVec;

    sithCogExec_PopVector(ctx, &poppedVec);
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
    {
        rdVector_Copy3(&pThing->actorParams.fireOffset, &poppedVec);
    }
}

void sithCogFunctionThing_GetThingUserData(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        sithCogExec_PushFlex(ctx, pThing->userval);
    else
        sithCogExec_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_SetThingUserData(sithCog *ctx)
{
    cog_flex_t userval = sithCogExec_PopFlex(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        pThing->userval = userval;
}

void sithCogFunctionThing_GetThingCollideSize(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        sithCogExec_PushFlex(ctx, pThing->collideSize);
    else
        sithCogExec_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_SetThingCollideSize(sithCog *ctx)
{
    cog_flex_t size = sithCogExec_PopFlex(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        pThing->collideSize = size;
}

void sithCogFunctionThing_GetThingMoveSize(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        sithCogExec_PushFlex(ctx, pThing->moveSize);
    else
        sithCogExec_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_SetThingMoveSize(sithCog *ctx)
{
    cog_flex_t moveSize = sithCogExec_PopFlex(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        pThing->moveSize = moveSize;
}

void sithCogFunctionThing_GetThingMass(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
    {
        if (pThing->moveType == SITH_MT_PHYSICS)
            sithCogExec_PushFlex(ctx, pThing->physicsParams.mass);
        else
            sithCogExec_PushFlex(ctx, 0.0);
    }
}

void sithCogFunctionThing_SetThingMass(sithCog *ctx)
{
    cog_flex_t mass = sithCogExec_PopFlex(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && pThing->moveType == SITH_MT_PHYSICS)
    {
        pThing->physicsParams.mass = mass;
        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SyncThing(pThing, SITHTHING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_SyncThingPos(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        sithThing_SyncThing(pThing, SITHTHING_SYNC_POS);
}

void sithCogFunctionThing_SyncThingAttachment(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        sithDSSThing_Attachment(pThing, -1, 255, 0);
}

void sithCogFunctionThing_SyncThingState(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        sithThing_SyncThing(pThing, SITHTHING_SYNC_STATE);
}

void sithCogFunctionThing_GetMajorMode(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && pThing->pPuppetClass && pThing->renderData.puppet)
        sithCogExec_PushInt(ctx, pThing->puppet->majorMode);
    else
        sithCogExec_PushInt(ctx, -1);
}

// MOTS added
void sithCogFunctionThing_GetThingMaxVelocity(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing && pThing->moveType == SITH_MT_PHYSICS) 
    {
        sithCogExec_PushFlex(ctx,pThing->physicsParams.maxVelocity);
    }
    else 
    {
        sithCogExec_PushFlex(ctx,0.0);
    }
}

// MOTS added
void sithCogFunctionThing_SetThingMaxVelocity(sithCog *ctx)
{
    cog_flex_t val = sithCogExec_PopFlex(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing && pThing->moveType == SITH_MT_PHYSICS) 
    {
        pThing->physicsParams.maxVelocity = val;
    }
}

// MOTS added
void sithCogFunctionThing_GetThingMaxAngularVelocity(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing && pThing->moveType == SITH_MT_PHYSICS) 
    {
        sithCogExec_PushFlex(ctx,pThing->physicsParams.maxRotationVelocity);
    }
    else 
    {
        sithCogExec_PushFlex(ctx,0.0);
    }
}

// MOTS added
void sithCogFunctionThing_SetThingMaxAngularVelocity(sithCog *ctx)
{
    cog_flex_t val = sithCogExec_PopFlex(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing && pThing->moveType == SITH_MT_PHYSICS) 
    {
        pThing->physicsParams.maxRotationVelocity = val;
    }
}

// MOTS added
void sithCogFunctionThing_GetActorHeadPYR(sithCog *ctx)
{
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing && (pThing->type == SITH_THING_ACTOR || pThing->type == SITH_THING_PLAYER))
    {
        sithCogExec_PushVector(ctx, &pThing->actorParams.headPYR);
        return;
    }
    sithCogExec_PushVector(ctx,&rdroid_zeroVector3);
}

// MOTS added
void sithCogFunctionThing_SetHeadPYR(sithCog *ctx)
{
    rdVector3 tmp;

    sithCogExec_PopVector(ctx, &tmp);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing && (pThing->type == SITH_THING_ACTOR || pThing->type == SITH_THING_PLAYER))
    {
        rdVector_Copy3(&pThing->actorParams.headPYR, &tmp);
    }
}

// MOTS added
void sithCogFunctionThing_SetMaxHeadPitch(sithCog *ctx)
{
    cog_flex_t val = sithCogExec_PopFlex(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing && pThing->moveType == SITH_MT_PHYSICS) 
    {
        sithCogExec_PushFlex(ctx, pThing->actorParams.maxHeadPitch);
        pThing->actorParams.maxHeadPitch = val;
    }
}

// MOTS added
void sithCogFunctionThing_SetMinHeadPitch(sithCog *ctx)
{
    cog_flex_t val = sithCogExec_PopFlex(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing && pThing->moveType == SITH_MT_PHYSICS) 
    {
        sithCogExec_PushFlex(ctx, pThing->actorParams.minHeadPitch);
        pThing->actorParams.minHeadPitch = val;
    }
}

// MOTS added
void sithCogFunctionThing_SetWeaponTarget(sithCog *ctx)
{
    cog_flex_t fVar1 = sithCogExec_PopFlex(ctx);
    SithThing* pTargetThing = sithCogExec_PopThing(ctx);
    SithThing* pWeaponThing = sithCogExec_PopThing(ctx);

    if (fVar1 > 0.0 && pWeaponThing && pWeaponThing->type == SITH_THING_WEAPON) 
    {
        pWeaponThing->weaponParams.pTargetThing = pTargetThing;
        pWeaponThing->weaponParams.field_38 = fVar1;
    }
}

// MOTS added
void sithCogFunctionThing_InterpolatePYR(sithCog *ctx)
{
    rdVector3 tmpOut;
    rdVector3 inVec2;
    rdVector3 tmpAngles;
    rdVector3 inVec1;
    rdVector3 inVec0;
    rdVector3 tmpAngles2;
    rdMatrix34 local_30;
    
    cog_flex_t fVar1 = sithCogExec_PopFlex(ctx);
    sithCogExec_PopVector(ctx,&inVec0);
    sithCogExec_PopVector(ctx,&inVec1);
    sithCogExec_PopVector(ctx,&inVec2);
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
    sithCogExec_PushVector(ctx,&tmpOut);
    return;
}

// MOTS added
void sithCogFunctionThing_SetJointAngle(sithCog *ctx)
{
    rdVector3 *prVar1;
    int arg1;
    SithThing *pThing;

    cog_flex_t fVar2 = sithCogExec_PopFlex(ctx);
    arg1 = sithCogExec_PopInt(ctx);
    pThing = sithCogExec_PopThing(ctx);
    if (((pThing && pThing->pPuppetClass) 
      && (pThing->renderData.type == RD_THING_MODEL3)) 
      && ((prVar1 = pThing->renderData.hierarchyNodes2, prVar1 != NULL &&
      (arg1 = pThing->pPuppetClass->bodypart_to_joint[arg1],
      arg1 > -1 && arg1 <= (int)(pThing->renderData.model3->numHierarchyNodes - 1))))) 
    {
        prVar1[arg1].x = fVar2;
    }
}

// MOTS added
void sithCogFunctionThing_GetJointAngle(sithCog *ctx)
{
    rdVector3 *prVar1;

    flex_t local_4 = -1.0;
    int arg1 = sithCogExec_PopInt(ctx);
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
    {
        if (((pThing->pPuppetClass && pThing->renderData.type == RD_THING_MODEL3) &&
            (prVar1 = (pThing->renderData).hierarchyNodes2, prVar1 != NULL)) &&
           (arg1 = pThing->pPuppetClass->bodypart_to_joint[arg1],
           arg1 > -1 && arg1 <= (int)(pThing->renderData.model3->numHierarchyNodes - 1))) 
        {
          local_4 = prVar1[arg1].x;
        }
        sithCogExec_PushFlex(ctx,local_4);
    }
}

// MOTS added
void sithCogFunctionThing_SetThingLookPYR(sithCog *ctx)
{
    int iVar1;
    SithThing *pThing;
    rdVector3 pyr;
    rdMatrix34 tmp_mat;

    iVar1 = sithCogExec_PopVector(ctx, &pyr);
    pThing = sithCogExec_PopThing(ctx);
    if (pThing && iVar1 == 1) 
    {
        rdMatrix_BuildRotate34(&tmp_mat, &pyr);
        rdVector_Normalize3Acc(&tmp_mat.lvec);
        rdMatrix_BuildFromLook34(&pThing->orient, &tmp_mat.lvec);
        if (COG_SHOULD_SYNC(ctx)) {
            sithThing_SyncThing(pThing, 1);
        }
    }
    return;
}

// DW added
void sithCogFunctionThing_GetThingInsertOffset(sithCog *ctx)
{
    rdModel3 *prVar1;
    SithThing* pThing = sithCogExec_PopThing(ctx);
    if (((pThing != (SithThing *)0x0) 
        && ((pThing->renderData).type == RD_THING_MODEL3)) 
        && (prVar1 = (pThing->renderData).model3, prVar1 != (rdModel3 *)0x0))
    {
        sithCogExec_PushVector(ctx,&prVar1->insertOffset);
        return;
    }
    sithCogExec_PushVector(ctx,&rdroid_zeroVector3);
}



void sithCogFunctionThing_Startup(SithCogSymbolTable* ctx)
{
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_WaitForStop, "waitforstop");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_StopThing, "stopthing");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_DestroyThing, "destroything");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetHealth, "getthinghealth");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetHealth, "gethealth");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_HealThing, "healthing");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingLight, "getthinglight");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_ThingLight, "setthinglight");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_ThingLight, "thinglight");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_ThingLightAnim, "thinglightanim");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_Rotate, "rotate");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_CreateThing, "creatething");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_CreateThingLocal, "createthinglocal");
    }

    // DW added: ?
    if (Main_bDwCompat) {
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_CreateThing, "createthingnr");
    }
    else {
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_CreateThingNr, "createthingnr");
    }

    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_CreateThingAtPosMots, "createthingatpos");
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_CreateThingAtPosOwner, "createthingatposowner");
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_CreateThingAtPos, "createthingatposold");
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_CreateThingAtPosNrMots, "createthingatposnr");
    }
    else {
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_CreateThingAtPos, "createthingatpos");
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_CreateThingAtPosNr, "createthingatposnr");
    }
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_RotatePivot, "rotatepivot");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_CaptureThing, "capturething");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_ReleaseThing, "releasething");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingVel, "setthingvel");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_AddThingVel, "addthingvel");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_ApplyForce, "applyforce");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_DetachThing, "detachthing");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingAttachFlags, "getattachflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingAttachFlags, "getthingattachflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_AttachThingToSurf, "attachthingtosurf");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_AttachThingToThing, "attachthingtothing");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetArmedMode, "setarmedmode");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingFlags, "setthingflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_ClearThingFlags, "clearthingflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_TeleportThing, "teleportthing");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingType, "setthingtype");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetCollideType, "setcollidetype");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetHeadLightIntensity, "setheadlightintensity");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingGeoMode, "getthinggeomode");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingGeoMode, "setthinggeomode");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingLightMode, "getthinglightmode");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingLightMode, "setthinglightmode");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingTexMode, "getthingtexmode");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingTexMode, "setthingtexmode");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingCurGeoMode, "getthingcurgeomode");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingCurGeoMode, "setthingcurgeomode");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingCurLightMode, "getthingcurlightmode");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingCurLightMode, "setthingcurlightmode");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingCurTexMode, "getthingcurtexmode");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingCurTexMode, "setthingcurtexmode");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetActorExtraSpeed, "setactorextraspeed");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingType, "getthingtype");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_IsThingMoving, "isthingmoving");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_IsThingMoving, "ismoving");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetCurFrame, "getcurframe");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetGoalFrame, "getgoalframe");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingParent, "getthingparent");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingParent, "setthingparent");
    }
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingSector, "getthingsector");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingPos, "getthingpos");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingPos, "setthingpos");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingPosEx, "setthingposex");
    }
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingVelocity, "getthingvel");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingUVec, "getthinguvec");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingLVec, "getthinglvec");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingLVecPYR, "getthinglvecpyr");
    }
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingRVec, "getthingrvec");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingFlags, "getthingflags");
    if (Main_bDwCompat) {
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingInsertOffset, "getthinginsertoffset");
    }
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetCollideType, "getcollidetype");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetHeadLightIntensity, "getheadlightintensity");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_IsThingVisible, "isthingvisible");
    if (Main_bDwCompat) {
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingCollideSize, "getthingradius");
    }
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingPulse, "setthingpulse");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingTimer, "setthingtimer");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetInventory, "getinv");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetInventory, "setinv"); // DW added: g_debugModeFlags & DEBUGFLAG_100 check
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_ChangeInventory, "changeinv"); // DW added: g_debugModeFlags & DEBUGFLAG_100 check
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetInventoryCog, "getinvcog");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetInventoryMinimum, "getinvmin");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetInventoryMaximum, "getinvmax");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetCurInvWeapon, "getcurinvweapon2");
        //sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetCurInvWeaponMots, "getcurinvweapon");
    }
    else {
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetCurInvWeapon, "getcurinvweapon");
    }
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetCurInvWeapon, "setcurinvweapon");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_PlayKey, "playkey");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_StopKey, "stopkey");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingModel, "setthingmodel");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingModel, "getthingmodel");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_PlayMode, "playmode");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetMajorMode, "getmajormode");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_FirstThingInSector, "firstthinginsector");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_NextThingInSector, "nextthinginsector");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_PrevThingInSector, "prevthinginsector");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_MoveToFrame, "movetoframe");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SkipToFrame, "skiptoframe");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_JumpToFrame, "jumptoframe");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_PathMovePause, "pathmovepause");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_PathMoveResume, "pathmoveresume");
    if (Main_bDwCompat) {
        // TODO
        //sithCog_RegisterFunction(ctx, sithCogFunctionThing_AddLaser, "addlaser");
        //sithCog_RegisterFunction(ctx, sithCogFunctionThing_AddBeam, "addbeam");
        //sithCog_RegisterFunction(ctx, sithCogFunctionThing_RemoveLaser, "removelaser");
        //sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetLaserColor, "getlasercolor");
        //sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetLaserId, "getlaserid");
        //sithCog_RegisterFunction(ctx, sithCogFunctionThing_ComputeCatapultVelocity, "computecatapultvelocity");
    }
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingTemplate, "getthingtemplate");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_DamageThing, "damagething");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetLifeleft, "setlifeleft");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetLifeleft, "getlifeleft");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingThrust, "setthingthrust");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingThrust, "getthingthrust");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetHealth, "setthinghealth");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetHealth, "sethealth");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_AmputateJoint, "amputatejoint");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetActorWeapon, "setactorweapon");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetActorWeaponMots, "getactorweapon");
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetActorWeapon, "getactorweapon2");
    }
    else {
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetActorWeapon, "getactorweapon");
    }
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetPhysicsFlags, "getphysicsflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetPhysicsFlags, "setphysicsflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_ClearPhysicsFlags, "clearphysicsflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SkillTarget, "skilltarget");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_ParseArg, "parsearg");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingRotVel, "getthingrotvel");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingRotVel, "setthingrotvel");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingLook, "setthinglook");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingLookPYR, "setthinglookpyr");
    }
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_IsThingCrouching, "isthingcrouching"); // DW removed
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_IsThingCrouching, "iscrouching");  // DW removed
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingClassCog, "getthingclasscog");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingClassCog, "setthingclasscog");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingCaptureCog, "getthingcapturecog");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingCaptureCog, "setthingcapturecog");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingRespawn, "getthingrespawn");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingSignature, "getthingsignature");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(ctx,sithCogFunctionThing_GetThingGuid,"getthingguid");
        sithCog_RegisterFunction(ctx,sithCogFunctionThing_GetGuidThing,"getguidthing");
    }
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingAttachFlags, "setthingattachflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_ClearThingAttachFlags, "clearthingattachflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetParticleSize, "getparticlesize");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetParticleSize, "setparticlesize");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetParticleGrowthSpeed, "getparticlegrowthspeed");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetParticleGrowthSpeed, "setparticlegrowthspeed");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetParticleTimeoutRate, "getparticletimeoutrate");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetParticleTimeoutRate, "setparticletimeoutrate");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetTypeFlags, "gettypeflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetTypeFlags, "settypeflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_ClearTypeFlags, "cleartypeflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetTypeFlags, "getactorflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetTypeFlags, "setactorflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_ClearTypeFlags, "clearactorflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetTypeFlags, "getweaponflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetTypeFlags, "setweaponflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_ClearTypeFlags, "clearweaponflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetTypeFlags, "getexplosionflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetTypeFlags, "setexplosionflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_ClearTypeFlags, "clearexplosionflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetTypeFlags, "getitemflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetTypeFlags, "setitemflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_ClearTypeFlags, "clearitemflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetTypeFlags, "getparticleflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetTypeFlags, "setparticleflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_ClearTypeFlags, "clearparticleflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_TakeItem, "takeitem");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_HasLOS, "haslos");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetFireOffset, "getthingfireoffset");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetFireOffset, "setthingfireoffset");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingUserData, "getthinguserdata");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingUserData, "setthinguserdata");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingCollideSize, "getthingcollidesize");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingCollideSize, "setthingcollidesize");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingMoveSize, "getthingmovesize");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingMoveSize, "setthingmovesize");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingMass, "getthingmass");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingMass, "setthingmass");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SyncThingPos, "syncthingpos");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SyncThingAttachment, "syncthingattachment");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_SyncThingState, "syncthingstate");
    sithCog_RegisterFunction(ctx, sithCogFunctionThing_AttachThingToThingEx, "attachthingtothingex");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingMaxVelocity, "getthingmaxvelocity");
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingMaxVelocity, "setthingmaxvelocity");
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingMaxAngularVelocity, "getthingmaxangularvelocity");
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingMaxAngularVelocity, "setthingmaxangularvelocity");
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetActorHeadPYR, "getactorheadpyr");
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetHeadPYR, "setactorheadpyr");
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetJointAngle, "setthingjointangle");
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetJointAngle, "getthingjointangle");
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetMaxHeadPitch, "setthingmaxheadpitch");
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetMinHeadPitch, "setthingminheadpitch");
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_InterpolatePYR, "interpolatepyr");
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetWeaponTarget, "setweapontarget");

        // TODO: weap_eweb_m.cog references a "SetThingCollide" verb? Superceded by "SetThingCollideSize"?
        // TODO: exp_hrail.cog references a "GetUserData" verb? Superceded by "GetThingUserData"?
    }
}
