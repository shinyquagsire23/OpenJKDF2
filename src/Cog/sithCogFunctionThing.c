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

void sithCogFunctionThing_createThingAtPos_nr_Mots(sithCog *ctx, int idk, sithThing* pThingIn);
void sithCogFunctionThing_createThingAtPos_nr(sithCog *ctx, int idk);

void sithCogFunctionThing_GetThingType(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        sithCogExec_PushInt(ctx, pThing->type);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_CreateThing(sithCog *ctx)
{
    sithThing *v1; // esi
    sithThing *v2; // ebx
    sithThing *v3; // edi

    v1 = sithCogExec_PopThing(ctx);
    v2 = sithCogExec_PopTemplate(ctx);
    if ( v1 && v1->type && v1->sector && v2 && (v3 = sithThing_SpawnTemplate(v2, v1)) != 0 )
    {
        if ( COG_SHOULD_SYNC(ctx) )
        {
            sithDSSThing_SendCreateThing(v2, v3, v1, 0, 0, 0, 255, 1);
        }
        sithCogExec_PushInt(ctx, v3->thingIdx);
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}


void sithCogFunctionThing_CreateThingNr(sithCog *ctx)
{
    sithThing *v1; // esi
    sithThing *v2; // ebx
    sithThing *v3; // edi

    v1 = sithCogExec_PopThing(ctx);
    v2 = sithCogExec_PopTemplate(ctx);
    if ( v1 && v1->type && v1->sector && v2 && (v3 = sithThing_SpawnTemplate(v2, v1)) != 0 )
    {
        if ( COG_SHOULD_SYNC(ctx) )
        {
            sithDSSThing_SendCreateThing(v2, v3, v1, 0, 0, 0, 255, 1);
        }
        sithCogExec_PushInt(ctx, v3->thingIdx);
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunctionThing_createThingUnused(sithCog *ctx)
{
    sithThing *v1; // esi
    sithThing *v2; // ebx
    sithThing *v3; // edi
    int v6; // [esp+18h] [ebp+8h]

    v6 = 0; // aaaaaa original is undefined

    v1 = sithCogExec_PopThing(ctx);
    v2 = sithCogExec_PopTemplate(ctx);
    if ( v1 && v1->type && v1->sector && v2 && (v3 = sithThing_SpawnTemplate(v2, v1)) != 0 )
    {
        if ( COG_SHOULD_SYNC(ctx) )
        {
            sithDSSThing_SendCreateThing(v2, v3, v1, 0, 0, 0, 255, v6);
        }
        sithCogExec_PushInt(ctx, v3->thingIdx);
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}

// MOTS added
void sithCogFunctionThing_CreateThingLocal(sithCog *ctx)
{
    sithThing *v1; // esi
    sithThing *v2; // ebx
    sithThing *v3; // edi

    v1 = sithCogExec_PopThing(ctx);
    v2 = sithCogExec_PopTemplate(ctx);
    if ( v1 && v1->type && v1->sector && v2 && (v3 = sithThing_SpawnTemplate(v2, v1)) != 0 )
    {
        sithCogExec_PushInt(ctx, v3->thingIdx);
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
    sithThing* pThingIn = sithCogExec_PopThing(ctx);
    sithCogFunctionThing_createThingAtPos_nr_Mots(ctx, 0, pThingIn);
}

void sithCogFunctionThing_CreateThingAtPosNrMots(sithCog *ctx)
{
    sithCogFunctionThing_createThingAtPos_nr_Mots(ctx, 0, NULL);
}

// MOTS added
void sithCogFunctionThing_createThingAtPos_nr_Mots(sithCog *ctx, int idk, sithThing* pThingIn)
{
    sithSector *popSector; // ebp
    sithThing *popTemplate; // eax
    rdVector3 *v5; // eax
    rdVector3 *v6; // ecx
    sithThing *v7; // ebx
    rdVector3 a1; // [esp+10h] [ebp-54h]
    rdVector3 pos; // [esp+1Ch] [ebp-48h]
    rdVector3 rot; // [esp+28h] [ebp-3Ch]
    rdMatrix34 a3; // [esp+34h] [ebp-30h]

    sithCogExec_PopVector3(ctx, &rot);
    sithCogExec_PopVector3(ctx, &pos);
    popSector = sithCogExec_PopSector(ctx);
    popTemplate = sithCogExec_PopTemplate(ctx);
    if ( !popTemplate || !popSector )
    {
        sithCogExec_PushInt(ctx, -1);
        return;
    }
    if (popTemplate->rdthing.type == RD_THINGTYPE_MODEL)
    {
        a1 = popTemplate->rdthing.model3->insertOffset;
    }
    else if (popTemplate->rdthing.type == RD_THINGTYPE_SPRITE3)
    {
        a1 = popTemplate->rdthing.sprite3->offset;
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

    v7 = sithThing_Create(popTemplate, &pos, &a3, popSector, pThingIn);
    if ( v7 )
    {
        if (!rdVector_IsZero3(&rot)) {
            rdVector_Normalize3Acc(&rot);
            rdMatrix_BuildFromLook34(&v7->lookOrientation,&rot);
        }

        if ( COG_SHOULD_SYNC(ctx) )
        {
            if (pThingIn) {
                sithDSSThing_SendMOTSNew1(popTemplate, v7, NULL, popSector, &pos, &rot, 0xff, idk); // MOTS added
                sithCogExec_PushInt(ctx, v7->thingIdx);
                return;
            }
            sithDSSThing_SendCreateThing(popTemplate, v7, 0, popSector, &pos, &rot, 255, idk);
        }
        sithCogExec_PushInt(ctx, v7->thingIdx);
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
    sithSector *popSector; // ebp
    sithThing *popTemplate; // eax
    rdVector3 *v5; // eax
    rdVector3 *v6; // ecx
    sithThing *v7; // ebx
    rdVector3 a1; // [esp+10h] [ebp-54h]
    rdVector3 pos; // [esp+1Ch] [ebp-48h]
    rdVector3 rot; // [esp+28h] [ebp-3Ch]
    rdMatrix34 a3; // [esp+34h] [ebp-30h]

    sithCogExec_PopVector3(ctx, &rot);
    sithCogExec_PopVector3(ctx, &pos);
    popSector = sithCogExec_PopSector(ctx);
    popTemplate = sithCogExec_PopTemplate(ctx);
    if ( !popTemplate || !popSector )
    {
        sithCogExec_PushInt(ctx, -1);
        return;
    }
    if (popTemplate->rdthing.type == RD_THINGTYPE_MODEL)
    {
        a1 = popTemplate->rdthing.model3->insertOffset;
    }
    else if (popTemplate->rdthing.type == RD_THINGTYPE_SPRITE3)
    {
        a1 = popTemplate->rdthing.sprite3->offset;
    }
    else
    {
       rdVector_Zero3(&a1);
    }
    
    rdMatrix_BuildRotate34(&a3, &rot);
    rdMatrix_TransformVector34Acc(&a1, &a3);
    rdVector_Add3Acc(&pos, &a1);
    v7 = sithThing_Create(popTemplate, &pos, &a3, popSector, 0);
    if ( v7 )
    {
        if ( COG_SHOULD_SYNC(ctx) )
        {
            sithDSSThing_SendCreateThing(popTemplate, v7, 0, popSector, &pos, &rot, 255, idk);
        }
        sithCogExec_PushInt(ctx, v7->thingIdx);
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunctionThing_DamageThing(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    int a4 = sithCogExec_PopInt(ctx);
    float a5 = sithCogExec_PopFlex(ctx);
    sithThing* pThing2 = sithCogExec_PopThing(ctx);

    if ( a5 > 0.0 && pThing2 )
    {
        if ( !pThing )
            pThing = pThing2;
        if ( COG_SHOULD_SYNC(ctx) )
        {
            sithDSSThing_SendDamage(pThing2, pThing, a5, a4, -1, 1);
        }
        sithCogExec_PushFlex(ctx, sithThing_Damage(pThing2, pThing, a5, a4));
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunctionThing_HealThing(sithCog *ctx)
{
    float amt = sithCogExec_PopFlex(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (amt > 0.0 && pThing && (pThing->type == SITH_THING_ACTOR || pThing->type == SITH_THING_PLAYER))
    {
        pThing->actorParams.health += amt;
        if ( pThing->actorParams.health > pThing->actorParams.maxHealth)
            pThing->actorParams.health = pThing->actorParams.maxHealth;
    }
}

void sithCogFunctionThing_GetThingHealth(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && (pThing->type == SITH_THING_ACTOR || pThing->type == SITH_THING_PLAYER) )
        sithCogExec_PushFlex(ctx, pThing->actorParams.health);
    else
        sithCogExec_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_SetHealth(sithCog *ctx)
{
    float amt = sithCogExec_PopFlex(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && (pThing->type == SITH_THING_ACTOR || pThing->type == SITH_THING_PLAYER))
        pThing->actorParams.health = amt;
}

void sithCogFunctionThing_DestroyThing(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (!pThing)
        return;

    //printf("destroy %x %s\n", pThing->thing_id, ctx->cogscript_fpath);

    if (COG_SHOULD_SYNC(ctx) )
        sithDSSThing_SendDestroyThing(pThing->thing_id, -1);

    sithThing_Destroy(pThing);
}

void sithCogFunctionThing_JumpToFrame(sithCog *ctx)
{
    sithSector* sector = sithCogExec_PopSector(ctx);
    uint32_t frame = sithCogExec_PopInt(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && sector && pThing->moveType == SITH_MT_PATH && frame < pThing->trackParams.loadedFrames )
    {
        if ( pThing->sector && sector != pThing->sector )
            sithThing_LeaveSector(pThing);

        if ( pThing->attach_flags )
            sithThing_DetachThing(pThing);

        rdMatrix_BuildRotate34(&pThing->lookOrientation, &pThing->trackParams.aFrames[frame].rot);
        rdVector_Copy3(&pThing->position, &pThing->trackParams.aFrames[frame].pos);

        if ( !pThing->sector )
            sithThing_EnterSector(pThing, sector, 1, 0);
    }
}

void sithCogFunctionThing_MoveToFrame(sithCog *ctx)
{
    float speed = sithCogExec_PopFlex(ctx) * 0.1;
    int frame = sithCogExec_PopInt(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && pThing->moveType == SITH_MT_PATH && pThing->trackParams.loadedFrames > frame )
    {
        if ( speed == 0.0 )
            speed = 0.5;

        sithTrackThing_MoveToFrame(pThing, frame, speed);

        if (COG_SHOULD_SYNC(ctx))
            sithDSSThing_SendPathMove(pThing, frame, speed, 0, -1, 255);
    }
}

void sithCogFunctionThing_SkipToFrame(sithCog *ctx)
{
    float speed = sithCogExec_PopFlex(ctx) * 0.1;
    int frame = sithCogExec_PopInt(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && pThing->moveType == SITH_MT_PATH && pThing->trackParams.loadedFrames > frame )
    {
        if ( speed == 0.0 )
            speed = 0.5;

        sithTrackThing_SkipToFrame(pThing, frame, speed);

        if (COG_SHOULD_SYNC(ctx))
            sithDSSThing_SendPathMove(pThing, frame, speed, 1, -1, 255);
    }
}

void sithCogFunctionThing_RotatePivot(sithCog *ctx)
{
    float speed = sithCogExec_PopFlex(ctx);
    uint32_t frame = sithCogExec_PopInt(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);

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
            float negSpeed = -speed;
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

    sithCogExec_PopVector3(ctx, &rot);
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
    {
        if ( pThing->moveType == SITH_MT_PATH )
            sithTrackThing_Rotate(pThing, &rot);
    }
}

void sithCogFunctionThing_GetThingLight(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        sithCogExec_PushFlex(ctx, pThing->light);
    else
        sithCogExec_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_SetThingLight(sithCog *ctx)
{
    float idk = sithCogExec_PopFlex(ctx);
    float light = sithCogExec_PopFlex(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && light >= 0.0 )
    {
        if ( idk == 0.0 )
        {
            pThing->light = light;
            if ( light != 0.0 )
            {
                pThing->thingflags |= SITH_TF_LIGHT;
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
    float idk_; // ST08_4
    rdSurface *surface; // eax

    float idk = sithCogExec_PopFlex(ctx);
    float light2 = sithCogExec_PopFlex(ctx);
    float light = sithCogExec_PopFlex(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing
      && light2 >= (double)light
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
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && pThing->moveType == SITH_MT_PATH && pThing->trackParams.flags & 3 )
    {
        int idx = pThing->thingIdx;
        ctx->script_running = 3;
        ctx->wakeTimeMs = idx;

        if ( ctx->flags & SITH_COG_DEBUG)
        {
            _sprintf(std_genBuffer, "Cog %s: Waiting for stop on object %d.\n", ctx->cogscript_fpath, idx);
            sithConsole_Print(std_genBuffer);
        }
    }
}

void sithCogFunctionThing_GetThingSector(sithCog *ctx)
{
    sithSector *sector;

    sithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && (sector = pThing->sector) != 0 )
        sithCogExec_PushInt(ctx, sector->id);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_GetCurFrame(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && pThing->moveType == SITH_MT_PATH )
        sithCogExec_PushInt(ctx, pThing->curframe);
    else
        sithCogExec_PushInt(ctx, 0);
}

void sithCogFunctionThing_GetGoalFrame(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && pThing->moveType == SITH_MT_PATH )
        sithCogExec_PushInt(ctx, pThing->goalframe);
    else
        sithCogExec_PushInt(ctx, 0);
}

void sithCogFunctionThing_StopThing(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (!pThing)
        return;

    if ( pThing->moveType == SITH_MT_PATH )
    {
        sithTrackThing_Stop(pThing);
        if (COG_SHOULD_SYNC(ctx))
            sithDSSThing_SendPathMove(pThing, 0, 0.0, 2, -1, 255);
    }
    else if (pThing->moveType == SITH_MT_PHYSICS)
    {
        sithPhysics_ThingStop(pThing);
    }
}

void sithCogFunctionThing_IsMoving(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
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
    float pulseSecs = sithCogExec_PopFlex(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (!pThing)
        return;

    if ( pulseSecs == 0.0 )
    {
        pThing->pulse_end_ms = 0;
        pThing->thingflags &= ~SITH_TF_PULSE;
        pThing->pulse_ms = 0;
    }
    else
    {
        pThing->thingflags |= SITH_TF_PULSE;
        pThing->pulse_ms = (int)(pulseSecs * 1000.0);
        pThing->pulse_end_ms = pThing->pulse_ms + sithTime_curMs;
    }
}

void sithCogFunctionThing_SetThingTimer(sithCog *ctx)
{
    float timerSecs = sithCogExec_PopFlex(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (!pThing)
        return;

    if ( timerSecs == 0.0 )
    {
        pThing->timer = 0;
        pThing->thingflags &= ~SITH_TF_TIMER;
    }
    else
    {
        pThing->thingflags |= SITH_TF_TIMER;
        pThing->timer = sithTime_curMs + (uint32_t)(timerSecs * 1000.0);
    }
}

void sithCogFunctionThing_CaptureThing(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
    {
        pThing->capture_cog = ctx;
        pThing->thingflags |= SITH_TF_CAPTURED;
    }
}

void sithCogFunctionThing_ReleaseThing(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
    {
        sithCog* class_cog = pThing->class_cog;
        pThing->capture_cog = NULL;
        if ( !class_cog && !sithThing_Release(pThing) )
        {
            pThing->thingflags &= ~SITH_TF_CAPTURED;
        }
    }
}

void sithCogFunctionThing_GetThingParent(sithCog *ctx)
{
    sithThing* parent;

    sithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && (parent = sithThing_GetParent(pThing)) != 0 )
        sithCogExec_PushInt(ctx, parent->thingIdx);
    else
        sithCogExec_PushInt(ctx, -1);
}

// MOTS added
void sithCogFunctionThing_SetThingParent(sithCog *ctx)
{
    int thing_id = sithCogExec_PopInt(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing) 
    {
        sithThing* pThing2 = sithThing_GetById(thing_id);
        if (pThing2) 
        {
            pThing->prev_thing = pThing2;
            pThing->child_signature = pThing2->signature;
        }
    }
}

void sithCogFunctionThing_GetThingPos(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        sithCogExec_PushVector3(ctx, &pThing->position);
    else
        sithCogExec_PushVector3(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_SetThingPos(sithCog *ctx)
{
    rdVector3 poppedVec;

    sithCogExec_PopVector3(ctx, &poppedVec);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
    {
        rdVector_Copy3(&pThing->position, &poppedVec);
        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_SendPos(pThing, -1, 1);
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

    sithSector* pSector = sithCogExec_PopSector(ctx);
    sithCogExec_PopVector3(ctx, &poppedVec);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pSector || (pSector == (sithSector *)-1)) {
        pSector = sithSector_sub_4F8D00(sithWorld_pCurrentWorld, &poppedVec);
    }
    if (pThing)
    {
        rdVector_Copy3(&pThing->position, &poppedVec);
        sithThing_MoveToSector(pThing,pSector,0);
        if (pThing->moveType == SITH_MT_PHYSICS && pThing->physicsParams.physflags & SITH_PF_FLOORSTICK)
            sithPhysics_FindFloor(pThing, 1);

        if ( pThing == sithPlayer_pLocalPlayerThing )
            sithCamera_FollowFocus(sithCamera_currentCamera);

        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_SendPos(pThing, -1, 1);
        }
        sithCogExec_PushInt(ctx, 1);
    }
    else
    {
        sithCogExec_PushInt(ctx, 0);
    }
}

void sithCogFunctionThing_GetInv(sithCog *ctx)
{
    unsigned int binIdx;
    sithThing *playerThing;

    binIdx = sithCogExec_PopInt(ctx);
    playerThing = sithCogExec_PopThing(ctx);

    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }

    if ( playerThing 
         && playerThing->type == SITH_THING_PLAYER 
         && playerThing->actorParams.playerinfo 
         && binIdx < SITHBIN_NUMBINS )
    {
        sithCogExec_PushFlex(ctx, sithInventory_GetBinAmount(playerThing, binIdx));
    }
    else
    {
        sithCogExec_PushFlex(ctx, 0.0);
    }
}

void sithCogFunctionThing_SetInv(sithCog *ctx)
{
    float amt = sithCogExec_PopFlex(ctx);
    uint32_t binIdx = sithCogExec_PopInt(ctx);
    sithThing* playerThing = sithCogExec_PopThing(ctx);

    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }

    if ( playerThing 
         && playerThing->type == SITH_THING_PLAYER 
         && playerThing->actorParams.playerinfo 
         && binIdx < SITHBIN_NUMBINS )
        sithInventory_SetBinAmount(playerThing, binIdx, amt);
}

void sithCogFunctionThing_ChangeInv(sithCog *ctx)
{
    float amt = sithCogExec_PopFlex(ctx);
    uint32_t binIdx = sithCogExec_PopInt(ctx);
    sithThing* playerThing = sithCogExec_PopThing(ctx);

    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }

    if ( playerThing 
         && playerThing->type == SITH_THING_PLAYER 
         && playerThing->actorParams.playerinfo 
         && binIdx < SITHBIN_NUMBINS )
    {
        sithCogExec_PushFlex(ctx, sithInventory_ChangeInv(playerThing, binIdx, amt));
    }
    else
    {
        sithCogExec_PushFlex(ctx, 0.0);
    }
}

void sithCogFunctionThing_GetInvCog(sithCog *ctx)
{
    unsigned int binIdx;
    sithThing *playerThing;
    sithItemDescriptor *desc;
    sithCog *descCog;

    binIdx = sithCogExec_PopInt(ctx);
    playerThing = sithCogExec_PopThing(ctx);

    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }

    if ( playerThing
      && playerThing->type == SITH_THING_PLAYER
      && playerThing->actorParams.playerinfo
      && (desc = sithInventory_GetItemDesc(playerThing, binIdx), binIdx < SITHBIN_NUMBINS)
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

void sithCogFunctionThing_GetThingVel(sithCog *ctx)
{
    rdVector3 retval;

    rdVector_Copy3(&retval, (rdVector3*)&rdroid_zeroVector3);
    sithThing* pThing = sithCogExec_PopThing(ctx);
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
        sithCogExec_PushVector3(ctx, &retval);
    }
    else
    {
        sithCogExec_PushVector3(ctx, (rdVector3*)&rdroid_zeroVector3);
    }
}

void sithCogFunctionThing_SetThingVel(sithCog *ctx)
{
    rdVector3 poppedVec;

    sithCogExec_PopVector3(ctx, &poppedVec);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && pThing->moveType == SITH_MT_PHYSICS)
    {
        rdVector_Copy3(&pThing->physicsParams.vel, &poppedVec);
        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SetSyncFlags(pThing, THING_SYNC_POS);
        }
    }
}

void sithCogFunctionThing_ApplyForce(sithCog *ctx)
{
    rdVector3 poppedVec;

    sithCogExec_PopVector3(ctx, &poppedVec);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && pThing->moveType == SITH_MT_PHYSICS)
    {
        sithPhysics_ThingApplyForce(pThing, &poppedVec);
        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SetSyncFlags(pThing, THING_SYNC_POS);
        }
    }
}

void sithCogFunctionThing_AddThingVel(sithCog *ctx)
{
    rdVector3 poppedVec;

    sithCogExec_PopVector3(ctx, &poppedVec);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && pThing->moveType == SITH_MT_PHYSICS)
    {
        rdVector_Add3Acc(&pThing->physicsParams.vel, &poppedVec);
        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SetSyncFlags(pThing, THING_SYNC_POS);
        }
    }
}

void sithCogFunctionThing_GetThingLvec(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        sithCogExec_PushVector3(ctx, &pThing->lookOrientation.lvec);
    else
        sithCogExec_PushVector3(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_GetThingLvecPYR(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (!pThing) {
        sithCogExec_PushVector3(ctx, (rdVector3*)&rdroid_zeroVector3);
        return;
    }

    rdVector3 pyrOut;
    rdMatrix34 lookOrient;
    rdMatrix_Copy34(&lookOrient, &pThing->lookOrientation);
    rdMatrix_ExtractAngles34(&lookOrient, &pyrOut);
    sithCogExec_PushVector3(ctx, &pyrOut);
}

void sithCogFunctionThing_GetThingUvec(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        sithCogExec_PushVector3(ctx, &pThing->lookOrientation.uvec);
    else
        sithCogExec_PushVector3(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_GetThingRvec(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        sithCogExec_PushVector3(ctx, &pThing->lookOrientation.rvec);
    else
        sithCogExec_PushVector3(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_GetEyePYR(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && (pThing->type == SITH_THING_ACTOR || pThing->type == SITH_THING_PLAYER))
        sithCogExec_PushVector3(ctx, &pThing->actorParams.eyePYR);
    else
        sithCogExec_PushVector3(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_DetachThing(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
    {
        sithThing_DetachThing(pThing);
        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_SendSyncThingAttachment(pThing, -1, 255, 1);
        }
    }
}

void sithCogFunctionThing_GetAttachFlags(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        sithCogExec_PushInt(ctx, pThing->attach_flags);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_AttachThingToSurf(sithCog *ctx)
{
    sithSurface* surface = sithCogExec_PopSurface(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && surface)
    {
        sithThing_AttachToSurface(pThing, surface, 1);
        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_SendSyncThingAttachment(pThing, -1, 255, 1);
        }
    }
}

void sithCogFunctionThing_AttachThingToThing(sithCog *ctx)
{
    sithThing* attached = sithCogExec_PopThing(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && attached)
    {
        sithThing_AttachThing(pThing, attached);
        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_SendSyncThingAttachment(pThing, -1, 255, 1);
        }
    }
}

void sithCogFunctionThing_AttachThingToThingEx(sithCog *ctx)
{
    int attachFlags = sithCogExec_PopInt(ctx);
    sithThing* attached = sithCogExec_PopThing(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && attached)
    {
        sithThing_AttachThing(pThing, attached);
        pThing->attach_flags |= attachFlags;

        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_SendSyncThingAttachment(pThing, -1, 255, 1);
        }
    }
}

void sithCogFunctionThing_PlayMode(sithCog *ctx)
{
    int mode = sithCogExec_PopInt(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if ( mode < 43 && pThing && pThing->animclass && pThing->rdthing.puppet)
    {
        int track = sithPuppet_PlayMode(pThing, mode, 0);
        if (track >= 0)
        {
            sithCogExec_PushInt(ctx, track);
            if (COG_SHOULD_SYNC(ctx))
            {
                sithDSSThing_SendPlayKeyMode(pThing, mode, pThing->rdthing.puppet->tracks[track].field_130, -1, 255);
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
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if ( !pThing )
        goto fail;

    rdPuppet* puppet = pThing->rdthing.puppet;
    if ( !puppet ) {
        goto fail;
    }

    // MOTS added: bugfix?
    if ( Main_bMotsCompat && pThing == sithPlayer_pLocalPlayerThing && pThing->actorParams.health < 1.0) {
        goto fail;
    }

    // MOTS added: nullptr deref fix
    if (!keyframe) {
       goto fail;
    }
    
    int track = sithPuppet_StartKey(puppet, keyframe, popInt, popInt + 2, trackNum, 0);
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
            sithDSSThing_SendPlayKey(pThing, keyframe, trackNum, popInt, pThing->rdthing.puppet->tracks[track].field_130, -1, 255);
        }
        return;
    }

fail:
    sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_StopKey(sithCog *ctx)
{
    float poppedFlex = sithCogExec_PopFlex(ctx);
    int track = sithCogExec_PopInt(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (!pThing)
        return;

    rdPuppet* puppet = pThing->rdthing.puppet;
    if (!puppet)
        return;

    if ( track >= 0 && track < 4 && poppedFlex >= 0.0 )
    {
        int v6 = puppet->tracks[track].field_130;
        if ( sithPuppet_StopKey(puppet, track, poppedFlex) )
        {
            if (COG_SHOULD_SYNC(ctx))
            {
                sithDSSThing_SendStopKey(pThing, v6, poppedFlex, -1, 255);
            }
        }
    }
}

void sithCogFunctionThing_SetThingModel(sithCog *ctx)
{
    rdModel3* model = sithCogExec_PopModel3(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && model)
    {
        rdModel3* v4 = pThing->rdthing.model3;
        int v5;
        if (!v4)
        {
            v5 = -1;
        }
        else
        {
            v5 = v4->id;
            sithThing_SetNewModel(pThing, model);
        }

        sithCogExec_PushInt(ctx, v5);

        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_SendSetThingModel(pThing, -1);
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

    sithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && pThing->rdthing.type == RD_THINGTYPE_MODEL && (model = pThing->rdthing.model3) != 0 )
        sithCogExec_PushInt(ctx, model->id);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetArmedMode(sithCog *ctx)
{
    int poppedInt = sithCogExec_PopInt(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && poppedInt >= 0 && poppedInt <= 2)
    {
        sithPuppet_SetArmedMode(pThing, poppedInt);

        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_SendSyncThing(pThing, -1, 255);
        }
    }
}

void sithCogFunctionThing_GetThingFlags(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        sithCogExec_PushInt(ctx, pThing->thingflags);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetThingFlags(sithCog *ctx)
{
    int flags = sithCogExec_PopInt(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && flags)
    {
        pThing->thingflags |= flags;

        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SetSyncFlags(pThing, THING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_ClearThingFlags(sithCog *ctx)
{
    int flags = sithCogExec_PopInt(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && flags)
    {
        pThing->thingflags &= ~flags;

        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SetSyncFlags(pThing, THING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_TeleportThing(sithCog *ctx)
{
    sithThing* thingTo = sithCogExec_PopThing(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && thingTo )
    {
        if ( pThing->attach_flags )
            sithThing_DetachThing(pThing);

        rdMatrix_Copy34(&pThing->lookOrientation, &thingTo->lookOrientation);
        rdVector_Copy3(&pThing->position, &thingTo->position);
        sithThing_MoveToSector(pThing, thingTo->sector, 0);
        if (pThing->moveType == SITH_MT_PHYSICS && pThing->physicsParams.physflags & SITH_PF_FLOORSTICK)
            sithPhysics_FindFloor(pThing, 1);

        if ( pThing == sithPlayer_pLocalPlayerThing )
            sithCamera_FollowFocus(sithCamera_currentCamera);

        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_SendPos(pThing, -1, 1);
        }
    }
}

void sithCogFunctionThing_SetThingType(sithCog *ctx)
{
    int type = sithCogExec_PopInt(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && type >= 0 && type < 12 )
        pThing->type = type;
}

void sithCogFunctionThing_GetCollideType(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        sithCogExec_PushInt(ctx, pThing->collide);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetCollideType(sithCog *ctx)
{
    int collideType = sithCogExec_PopInt(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && collideType < 4)
    {
        pThing->collide = collideType;

        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SetSyncFlags(pThing, THING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_FirstThingInSector(sithCog *ctx)
{
    sithSector* sector = sithCogExec_PopSector(ctx);
    if (sector)
    {
        sithThing* pThing = sector->thingsList;

        if (pThing)
            sithCogExec_PushInt(ctx, pThing->thingIdx);
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
    sithThing *nextThing;

    sithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && (nextThing = pThing->nextThing) != 0 )
    {
        sithCogExec_PushInt(ctx, nextThing->thingIdx);
    }
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_PrevThingInSector(sithCog *ctx)
{
    sithThing *prevThing;

    sithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && (prevThing = pThing->prevThing) != 0 )
        sithCogExec_PushInt(ctx, prevThing->thingIdx);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_GetInvMin(sithCog *ctx)
{
    int binIdx = sithCogExec_PopInt(ctx);
    sithThing* player = sithCogExec_PopThing(ctx);

    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }

    if ( player && player->type == SITH_THING_PLAYER && player->actorParams.playerinfo )
    {
        sithCogExec_PushFlex(ctx, sithInventory_GetMin(player, binIdx));
    }
    else
    {
        sithCogExec_PushFlex(ctx, -1.0);
    }
}

void sithCogFunctionThing_GetInvMax(sithCog *ctx)
{
    int binIdx = sithCogExec_PopInt(ctx);
    sithThing* player = sithCogExec_PopThing(ctx);

    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }

    if ( player && player->type == SITH_THING_PLAYER && player->actorParams.playerinfo )
    {
        sithCogExec_PushFlex(ctx, sithInventory_GetMax(player, binIdx));
    }
    else
    {
        sithCogExec_PushFlex(ctx, -1.0);
    }
}

// unused/unreferenced
void sithCogFunctionThing_GetLoadedFrames(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && pThing->moveType == SITH_MT_PATH)
        sithCogExec_PushInt(ctx, pThing->trackParams.loadedFrames);
    else
        sithCogExec_PushInt(ctx, -1);
}

// unused/unreferenced
void sithCogFunctionThing_GetFramePos(sithCog *ctx)
{
    uint32_t frame = sithCogExec_PopInt(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && pThing->moveType == SITH_MT_PATH && frame < pThing->trackParams.loadedFrames )
        sithCogExec_PushVector3(ctx, &pThing->trackParams.aFrames[frame].pos);
    sithCogExec_PushVector3(ctx, (rdVector3*)&rdroid_zeroVector3);
}

// unused/unreferenced
void sithCogFunctionThing_GetFrameRot(sithCog *ctx)
{
    uint32_t frame = sithCogExec_PopInt(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && pThing->moveType == SITH_MT_PATH && frame < pThing->trackParams.loadedFrames)
        sithCogExec_PushVector3(ctx, &pThing->trackParams.aFrames[frame].rot);
    sithCogExec_PushVector3(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_PathMovePause(sithCog *ctx)
{
    int ret = 0;
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && pThing->moveType == SITH_MT_PATH )
        ret = sithTrackThing_PathMovePause(pThing);

    if ( ret == 1 )
        sithCogExec_PushInt(ctx, pThing->thingIdx);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetHeadlightIntensity(sithCog *ctx)
{
    float intensity = sithCogExec_PopFlex(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);

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

void sithCogFunctionThing_GetHeadlightIntensity(sithCog *ctx)
{
    sithCogExec_PopFlex(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && (pThing->type == SITH_THING_ACTOR || pThing->type == SITH_THING_PLAYER))
        sithCogExec_PushFlex(ctx, pThing->actorParams.lightIntensity);
    else
        sithCogExec_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_IsThingVisible(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        sithCogExec_PushInt(ctx, pThing->isVisible + 1 >= (unsigned int)bShowInvisibleThings);
    else
        sithCogExec_PushInt(ctx, 0);
}

void sithCogFunctionThing_PathMoveResume(sithCog *ctx)
{
    int ret = 0;
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && pThing->moveType == SITH_THING_ACTOR )
        ret = sithTrackThing_PathMoveResume(pThing);
    if ( ret == 1 )
        sithCogExec_PushInt(ctx, pThing->thingIdx);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetCurInvWeapon(sithCog *ctx)
{
    int binIdx = sithCogExec_PopInt(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }
    if (pThing)
        sithInventory_SetCurWeapon(pThing, binIdx);
}

void sithCogFunctionThing_GetCurInvWeapon(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
    {
        int binIdx = sithInventory_GetCurWeapon(pThing);
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
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
    {
        int idx = sithInventory_GetCurWeapon(pThing);
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
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        pThing->rdthing.desiredGeoMode = mode;
}

void sithCogFunctionThing_GetThingGeoMode(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        sithCogExec_PushInt(ctx, (int)pThing->rdthing.desiredGeoMode);
}

void sithCogFunctionThing_SetThingLightMode(sithCog *ctx)
{
    rdLightMode_t mode = (rdLightMode_t)sithCogExec_PopInt(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        pThing->rdthing.desiredLightMode = mode;
}

void sithCogFunctionThing_GetThingLightMode(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        sithCogExec_PushInt(ctx, (int)pThing->rdthing.desiredLightMode);
}

void sithCogFunctionThing_SetThingTexMode(sithCog *ctx)
{
    int mode = sithCogExec_PopInt(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        pThing->rdthing.desiredTexMode = mode;
}

void sithCogFunctionThing_GetThingTexMode(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        sithCogExec_PushInt(ctx, pThing->rdthing.desiredTexMode);
}

void sithCogFunctionThing_SetThingCurGeoMode(sithCog *ctx)
{
    rdGeoMode_t mode = (rdGeoMode_t)sithCogExec_PopInt(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
    {
        pThing->rdthing.curGeoMode = mode;
        if (COG_SHOULD_SYNC(ctx))
        {
                sithThing_SetSyncFlags(pThing, THING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_GetThingCurGeoMode(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        sithCogExec_PushInt(ctx, (int)pThing->rdthing.curGeoMode);
}

void sithCogFunctionThing_SetThingCurLightMode(sithCog *ctx)
{
    rdLightMode_t mode = (rdLightMode_t)sithCogExec_PopInt(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        pThing->rdthing.curLightMode = mode;
}

void sithCogFunctionThing_GetThingCurLightMode(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        sithCogExec_PushInt(ctx, (int)pThing->rdthing.curLightMode);
}

void sithCogFunctionThing_SetThingCurTexMode(sithCog *ctx)
{
    int mode = sithCogExec_PopInt(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        pThing->rdthing.curTexMode = mode;
}

void sithCogFunctionThing_GetThingCurTexMode(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        sithCogExec_PushInt(ctx, pThing->rdthing.curTexMode);
}

void sithCogFunctionThing_SetActorExtraSpeed(sithCog *ctx)
{
    float extraSpeed = sithCogExec_PopFlex(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
        pThing->actorParams.extraSpeed = extraSpeed;
}

void sithCogFunctionThing_GetThingTemplate(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && pThing->templateBase)
        sithCogExec_PushInt(ctx, pThing->templateBase->thingIdx);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetLifeLeft(sithCog *ctx)
{
    float lifeLeftSecs = sithCogExec_PopFlex(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && lifeLeftSecs >= 0.0)
    {
        pThing->lifeLeftMs = (int)(lifeLeftSecs * 1000.0);
        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SetSyncFlags(pThing, THING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_GetLifeLeft(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
    {
        sithCogExec_PushFlex(ctx, (double)(unsigned int)pThing->lifeLeftMs * 0.001);
    }
}

void sithCogFunctionThing_SetThingThrust(sithCog *ctx)
{
    rdVector3 poppedVec;

    int couldPopVec = sithCogExec_PopVector3(ctx, &poppedVec);
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && pThing->moveType == SITH_MT_PHYSICS && couldPopVec)
    {
        sithCogExec_PushVector3(ctx, &pThing->physicsParams.acceleration);
        rdVector_Copy3(&pThing->physicsParams.acceleration, &poppedVec);
    }
}

void sithCogFunctionThing_GetThingThrust(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing )
    {
        if ( pThing->moveType == SITH_MT_PHYSICS )
            sithCogExec_PushVector3(ctx, &pThing->physicsParams.acceleration);
    }
}

void sithCogFunctionThing_AmputateJoint(sithCog *ctx)
{
    uint32_t idx = sithCogExec_PopInt(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
    {
        rdThing* rdthing = &pThing->rdthing;
        if ( pThing != (sithThing *)-196 )
        {
            sithAnimclass* animclass = pThing->animclass;
            if (animclass && idx < 0xA)
            {
                int jointIdx = animclass->bodypart_to_joint[idx];
                if ( jointIdx >= 0 ) {
                    // Added: prevent oob
                    if (rdthing->model3 && jointIdx < rdthing->model3->numHierarchyNodes)
                        rdthing->amputatedJoints[jointIdx] = 1;
                }
            }
        }
    }
}

void sithCogFunctionThing_SetActorWeapon(sithCog *ctx)
{
    sithThing* weapTemplate = sithCogExec_PopTemplate(ctx);
    int weap_idx = sithCogExec_PopInt(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && (pThing->type == SITH_THING_ACTOR || pThing->type == SITH_THING_PLAYER))
    {
        if ( weap_idx == 1 )
        {
            pThing->actorParams.templateWeapon = weapTemplate;
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
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && (pThing->type == SITH_THING_ACTOR || pThing->type == SITH_THING_PLAYER))
    {
        sithThing* weapTemplate;
        if ( weap_idx == 1 )
        {
            weapTemplate = pThing->actorParams.templateWeapon;
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
            sithCogExec_PushInt(ctx, weapTemplate->thingIdx);
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
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && (pThing->type == SITH_THING_ACTOR || pThing->type == SITH_THING_PLAYER))
    {
        sithThing* weapTemplate;
        if ( weap_idx == 1 )
        {
            weapTemplate = pThing->actorParams.templateWeapon;
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
                sithCogExec_PushInt(ctx, weapTemplate->thingIdx);
                return;
            }
            int idx = sithInventory_SelectWeaponPrior(weapTemplate->thingIdx);
            sithCogExec_PushInt(ctx, idx);
            return;
        }

        sithCogExec_PushInt(ctx, -1);
        return;
    }
}

void sithCogFunctionThing_GetPhysicsFlags(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && pThing->moveType == SITH_MT_PHYSICS )
        sithCogExec_PushInt(ctx, pThing->physicsParams.physflags);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetPhysicsFlags(sithCog *ctx)
{
    int flags = sithCogExec_PopInt(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && flags && pThing->moveType == SITH_MT_PHYSICS)
    {
        pThing->physicsParams.physflags |= flags;
        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SetSyncFlags(pThing, THING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_ClearPhysicsFlags(sithCog *ctx)
{
    int flags = sithCogExec_PopInt(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && flags && pThing->moveType == SITH_MT_PHYSICS)
        pThing->physicsParams.physflags &= ~flags;
}

void sithCogFunctionThing_SkillTarget(sithCog *ctx)
{
    sithCog *classCog;

    float param1 = sithCogExec_PopFlex(ctx);
    float param0 = sithCogExec_PopFlex(ctx);
    sithThing* otherThing = sithCogExec_PopThing(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && otherThing && (classCog = pThing->class_cog) != 0 )
    {
        if ( sithNet_isMulti && pThing->type == SITH_THING_PLAYER )
        {
            sithDSSCog_SendSendTrigger(
                classCog,
                SITH_MESSAGE_SKILL,
                SENDERTYPE_THING,
                pThing->thingIdx,
                SENDERTYPE_THING,
                otherThing->thingIdx,
                0,
                param0,
                param1,
                0.0,
                0.0,
                pThing->actorParams.playerinfo->net_id);
            sithCogExec_PushFlex(ctx, 0.0);
        }
        else
        {
            float ret = sithCog_SendMessageEx(
                          classCog,
                          SITH_MESSAGE_SKILL,
                          SENDERTYPE_THING,
                          pThing->thingIdx,
                          SENDERTYPE_THING,
                          otherThing->thingIdx,
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
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (str && pThing)
    {
        _strncpy(std_genBuffer, str, 0x3FFu);
        std_genBuffer[1023] = 0;

        stdConffile_ReadArgsFromStr(std_genBuffer);
        for (int i = 0 ; i < stdConffile_entry.numArgs; i++)
        {
            stdConffileArg* arg = &stdConffile_entry.args[i];
            sithThing_ParseArgs(arg, pThing);
        }
    }
}

void sithCogFunctionThing_SetThingRotVel(sithCog *ctx)
{
    rdVector3 popped_vector3;

    sithCogExec_PopVector3(ctx, &popped_vector3);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && pThing->moveType == SITH_MT_PHYSICS)
    {
        rdVector_Copy3(&pThing->physicsParams.angVel, &popped_vector3);
        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SetSyncFlags(pThing, THING_SYNC_POS);
        }
    }
}

void sithCogFunctionThing_GetThingRotVel(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && pThing->moveType == SITH_MT_PHYSICS )
        sithCogExec_PushVector3(ctx, &pThing->physicsParams.angVel);
    else
        sithCogExec_PushVector3(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_SetThingLook(sithCog *ctx)
{
    rdVector3 popped_vector3;

    int pop_v3_retval = sithCogExec_PopVector3(ctx, &popped_vector3);
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && pop_v3_retval == 1)
    {
        rdVector_Normalize3Acc(&popped_vector3);
        rdMatrix_BuildFromLook34(&pThing->lookOrientation, &popped_vector3);

        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SetSyncFlags(pThing, THING_SYNC_POS);
        }
    }
}

void sithCogFunctionThing_IsCrouching(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if ( !pThing || pThing->moveType != SITH_MT_PHYSICS )
        sithCogExec_PushInt(ctx, -1);

    if (pThing->physicsParams.physflags & SITH_PF_CROUCHING)
        sithCogExec_PushInt(ctx, 1);
    else
        sithCogExec_PushInt(ctx, 0);
}

void sithCogFunctionThing_GetThingClassCog(sithCog *ctx)
{
    sithCog *classCog; // eax

    sithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && (classCog = pThing->class_cog) != 0 )
        sithCogExec_PushInt(ctx, classCog->selfCog);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetThingClassCog(sithCog *ctx)
{
    sithCog* classCog = sithCogExec_PopCog(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing )
    {
        if ( classCog )
            pThing->class_cog = classCog;
    }
}

void sithCogFunctionThing_GetThingCaptureCog(sithCog *ctx)
{
    sithCog *captureCog; // eax

    sithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing && (captureCog = pThing->capture_cog) != 0 )
        sithCogExec_PushInt(ctx, captureCog->selfCog);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetThingCaptureCog(sithCog *ctx)
{
    sithCog *captureCog; // edi

    captureCog = sithCogExec_PopCog(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if ( pThing )
    {
        if ( captureCog )
            pThing->capture_cog = captureCog;
    }
}

void sithCogFunctionThing_GetThingRespawn(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing && pThing->type == SITH_THING_ITEM)
    {
        sithCogExec_PushFlex(ctx, pThing->itemParams.respawn);
    }
}

void sithCogFunctionThing_GetThingSignature(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing )
        sithCogExec_PushInt(ctx, pThing->signature);
    else
        sithCogExec_PushInt(ctx, -1);
}

// MOTS added
void sithCogFunctionThing_GetThingGUID(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing) {
        sithCogExec_PushInt(ctx, pThing->thing_id);
        return;
    }
    sithCogExec_PushInt(ctx, -1);
}

// MOTS added
void sithCogFunctionThing_GetGUIDThing(sithCog *ctx)
{
    int thing_id = sithCogExec_PopInt(ctx);
    sithThing* pThing = sithThing_GetById(thing_id);
    if (pThing == (sithThing *)0x0) {
        sithCogExec_PushInt(ctx,-1);
        return;
    }
    sithCogExec_PushInt(ctx,pThing->thingIdx);
    return;
}

void sithCogFunctionThing_SetThingAttachFlags(sithCog *ctx)
{
    int flags = sithCogExec_PopInt(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && flags)
    {
        pThing->attach_flags |= flags;

        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_SendSyncThingAttachment(pThing, -1, 255, 1);
        }
    }
}

void sithCogFunctionThing_ClearThingAttachFlags(sithCog *ctx)
{
    int flags = sithCogExec_PopInt(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && flags)
    {
        pThing->attach_flags &= ~flags;

        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_SendSyncThingAttachment(pThing, -1, 255, 1);
        }
    }
}

void sithCogFunctionThing_GetParticleSize(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && pThing->type == SITH_THING_PARTICLE)
        sithCogExec_PushFlex(ctx, pThing->particleParams.elementSize);
    else
        sithCogExec_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_SetParticleSize(sithCog *ctx)
{
    float size = sithCogExec_PopFlex(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && pThing->type == SITH_THING_PARTICLE)
    {
        pThing->particleParams.elementSize = size;
    }
}

void sithCogFunctionThing_GetParticleGrowthSpeed(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && pThing->type == SITH_THING_PARTICLE )
        sithCogExec_PushFlex(ctx, pThing->particleParams.growthSpeed);
    else
        sithCogExec_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_SetParticleGrowthSpeed(sithCog *ctx)
{
    float speed = sithCogExec_PopFlex(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && pThing->type == SITH_THING_PARTICLE)
    {
        pThing->particleParams.growthSpeed = speed;
    }
}

void sithCogFunctionThing_GetParticleTimeoutRate(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if ( pThing && pThing->type == SITH_THING_PARTICLE )
        sithCogExec_PushFlex(ctx, pThing->particleParams.rate);
    else
        sithCogExec_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_SetParticleTimeoutRate(sithCog *ctx)
{
    float rate = sithCogExec_PopFlex(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && pThing->type == SITH_THING_PARTICLE)
    {
        pThing->particleParams.rate = rate;
    }
}

void sithCogFunctionThing_GetXFlags(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
    {
        switch ( pThing->type )
        {
            case SITH_THING_ACTOR:
            case SITH_THING_ITEM:
            case SITH_THING_PLAYER:
                sithCogExec_PushInt(ctx, pThing->actorParams.typeflags);
                return;
            case SITH_THING_WEAPON:
            case SITH_THING_PARTICLE:
                sithCogExec_PushInt(ctx, pThing->weaponParams.typeflags);
                return;
            case SITH_THING_EXPLOSION:
                sithCogExec_PushInt(ctx, pThing->explosionParams.typeflags);
                return;
        }
    }

    sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetXFlags(sithCog *ctx)
{
    int flags = sithCogExec_PopInt(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);

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
                pThing->actorParams.typeflags |= flags;
                break;
            default:
                break;
        }

        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SetSyncFlags(pThing, THING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_ClearXFlags(sithCog *ctx)
{
    int flags = sithCogExec_PopInt(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);

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
                pThing->actorParams.typeflags &= ~flags;
                break;
            default:
                break;
        }

        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SetSyncFlags(pThing, THING_SYNC_STATE);
        }
    }
}

// MOTS altered
void sithCogFunctionThing_TakeItem(sithCog *ctx)
{
    sithThing* player = sithCogExec_PopThing(ctx);
    sithThing* itemThing = sithCogExec_PopThing(ctx);
    if ( itemThing && (Main_bMotsCompat || player) && itemThing->type == SITH_THING_ITEM )
        sithItem_Take(itemThing, player, 0);
}

void sithCogFunctionThing_HasLos(sithCog *ctx)
{
    sithThing* pThingB = sithCogExec_PopThing(ctx);
    sithThing* pThingA = sithCogExec_PopThing(ctx);

    if ( pThingA && pThingB )
    {
        if (sithCollision_HasLos(pThingA, pThingB, 0))
            sithCogExec_PushInt(ctx, 1);
        else
            sithCogExec_PushInt(ctx, 0);
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunctionThing_GetThingFireOffset(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        sithCogExec_PushVector3(ctx, &pThing->actorParams.fireOffset);
    else
        sithCogExec_PushVector3(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_SetThingFireOffset(sithCog *ctx)
{
    rdVector3 poppedVec;

    sithCogExec_PopVector3(ctx, &poppedVec);
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
    {
        rdVector_Copy3(&pThing->actorParams.fireOffset, &poppedVec);
    }
}

void sithCogFunctionThing_GetThingUserdata(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        sithCogExec_PushFlex(ctx, pThing->userdata);
    else
        sithCogExec_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_SetThingUserdata(sithCog *ctx)
{
    float userdata = sithCogExec_PopFlex(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        pThing->userdata = userdata;
}

void sithCogFunctionThing_GetThingCollideSize(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        sithCogExec_PushFlex(ctx, pThing->collideSize);
    else
        sithCogExec_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_SetThingCollideSize(sithCog *ctx)
{
    float size = sithCogExec_PopFlex(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        pThing->collideSize = size;
}

void sithCogFunctionThing_GetThingMoveSize(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        sithCogExec_PushFlex(ctx, pThing->moveSize);
    else
        sithCogExec_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_SetThingMoveSize(sithCog *ctx)
{
    float moveSize = sithCogExec_PopFlex(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        pThing->moveSize = moveSize;
}

void sithCogFunctionThing_GetThingMass(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
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
    float mass = sithCogExec_PopFlex(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && pThing->moveType == SITH_MT_PHYSICS)
    {
        pThing->physicsParams.mass = mass;
        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SetSyncFlags(pThing, THING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_SyncThingPos(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        sithThing_SetSyncFlags(pThing, THING_SYNC_POS);
}

void sithCogFunctionThing_SyncThingAttachment(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        sithDSSThing_SendSyncThingAttachment(pThing, -1, 255, 0);
}

void sithCogFunctionThing_SyncThingState(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing)
        sithThing_SetSyncFlags(pThing, THING_SYNC_STATE);
}

void sithCogFunctionThing_GetMajorMode(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && pThing->animclass && pThing->rdthing.puppet)
        sithCogExec_PushInt(ctx, pThing->puppet->majorMode);
    else
        sithCogExec_PushInt(ctx, -1);
}

// MOTS added
void sithCogFunctionThing_GetThingMaxVelocity(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing && pThing->moveType == SITH_MT_PHYSICS) 
    {
        sithCogExec_PushFlex(ctx,pThing->physicsParams.maxVel);
    }
    else 
    {
        sithCogExec_PushFlex(ctx,0.0);
    }
}

// MOTS added
void sithCogFunctionThing_SetThingMaxVelocity(sithCog *ctx)
{
    float val = sithCogExec_PopFlex(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing && pThing->moveType == SITH_MT_PHYSICS) 
    {
        pThing->physicsParams.maxVel = val;
    }
}

// MOTS added
void sithCogFunctionThing_GetThingMaxAngularVelocity(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing && pThing->moveType == SITH_MT_PHYSICS) 
    {
        sithCogExec_PushFlex(ctx,pThing->physicsParams.maxRotVel);
    }
    else 
    {
        sithCogExec_PushFlex(ctx,0.0);
    }
}

// MOTS added
void sithCogFunctionThing_SetThingMaxAngularVelocity(sithCog *ctx)
{
    float val = sithCogExec_PopFlex(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing && pThing->moveType == SITH_MT_PHYSICS) 
    {
        pThing->physicsParams.maxRotVel = val;
    }
}

// MOTS added
void sithCogFunctionThing_GetActorHeadPYR(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing && (pThing->type == SITH_THING_ACTOR || pThing->type == SITH_THING_PLAYER))
    {
        sithCogExec_PushVector3(ctx, &pThing->actorParams.eyePYR);
        return;
    }
    sithCogExec_PushVector3(ctx,&rdroid_zeroVector3);
}

// MOTS added
void sithCogFunctionThing_SetActorHeadPYR(sithCog *ctx)
{
    rdVector3 tmp;

    sithCogExec_PopVector3(ctx, &tmp);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing && (pThing->type == SITH_THING_ACTOR || pThing->type == SITH_THING_PLAYER))
    {
        rdVector_Copy3(&pThing->actorParams.eyePYR, &tmp);
    }
}

// MOTS added
void sithCogFunctionThing_SetThingMaxHeadPitch(sithCog *ctx)
{
    float val = sithCogExec_PopFlex(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing && pThing->moveType == SITH_MT_PHYSICS) 
    {
        sithCogExec_PushFlex(ctx, pThing->actorParams.maxHeadPitch);
        pThing->actorParams.maxHeadPitch = val;
    }
}

// MOTS added
void sithCogFunctionThing_SetThingMinHeadPitch(sithCog *ctx)
{
    float val = sithCogExec_PopFlex(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing && pThing->moveType == SITH_MT_PHYSICS) 
    {
        sithCogExec_PushFlex(ctx, pThing->actorParams.minHeadPitch);
        pThing->actorParams.minHeadPitch = val;
    }
}

// MOTS added
void sithCogFunctionThing_SetWeaponTarget(sithCog *ctx)
{
    float fVar1 = sithCogExec_PopFlex(ctx);
    sithThing* pTargetThing = sithCogExec_PopThing(ctx);
    sithThing* pWeaponThing = sithCogExec_PopThing(ctx);

    if (fVar1 > 0.0 && pWeaponThing && pWeaponThing->type == SITH_THING_WEAPON) 
    {
        pWeaponThing->weaponParams.pTargetThing = pTargetThing;
        pWeaponThing->weaponParams.field_38 = fVar1;
    }
}

// MOTS added
void sithCogFunctionThing_InterpolatePYR(sithCog *ctx)
{
    float fVar1;
    rdVector3 tmpOut;
    rdVector3 inVec2;
    rdVector3 tmpAngles;
    rdVector3 inVec1;
    rdVector3 inVec0;
    rdVector3 tmpAngles2;
    rdMatrix34 local_30;
    
    fVar1 = sithCogExec_PopFlex(ctx);
    sithCogExec_PopVector3(ctx,&inVec0);
    sithCogExec_PopVector3(ctx,&inVec1);
    sithCogExec_PopVector3(ctx,&inVec2);
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
    sithCogExec_PushVector3(ctx,&tmpOut);
    return;
}

// MOTS added
void sithCogFunctionThing_SetThingJointAngle(sithCog *ctx)
{
    rdVector3 *prVar1;
    int arg1;
    sithThing *pThing;
    float fVar2;

    fVar2 = sithCogExec_PopFlex(ctx);
    arg1 = sithCogExec_PopInt(ctx);
    pThing = sithCogExec_PopThing(ctx);
    if (((pThing && pThing->animclass) 
      && (pThing->rdthing.type == RD_THINGTYPE_MODEL)) 
      && ((prVar1 = pThing->rdthing.hierarchyNodes2, prVar1 != NULL &&
      (arg1 = pThing->animclass->bodypart_to_joint[arg1],
      arg1 > -1 && arg1 <= (int)(pThing->rdthing.model3->numHierarchyNodes - 1))))) 
    {
        prVar1[arg1].x = fVar2;
    }
}

// MOTS added
void sithCogFunctionThing_GetThingJointAngle(sithCog *ctx)
{
    rdVector3 *prVar1;

    float local_4 = -1.0;
    int arg1 = sithCogExec_PopInt(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
    {
        if (((pThing->animclass && pThing->rdthing.type == RD_THINGTYPE_MODEL) &&
            (prVar1 = (pThing->rdthing).hierarchyNodes2, prVar1 != NULL)) &&
           (arg1 = pThing->animclass->bodypart_to_joint[arg1],
           arg1 > -1 && arg1 <= (int)(pThing->rdthing.model3->numHierarchyNodes - 1))) 
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
    sithThing *pThing;
    rdVector3 pyr;
    rdMatrix34 tmp_mat;

    iVar1 = sithCogExec_PopVector3(ctx, &pyr);
    pThing = sithCogExec_PopThing(ctx);
    if (pThing && iVar1 == 1) 
    {
        rdMatrix_BuildRotate34(&tmp_mat, &pyr);
        rdVector_Normalize3Acc(&tmp_mat.lvec);
        rdMatrix_BuildFromLook34(&pThing->lookOrientation, &tmp_mat.lvec);
        if (COG_SHOULD_SYNC(ctx)) {
            sithThing_SetSyncFlags(pThing, 1);
        }
    }
    return;
}

// DW added
void sithCogFunctionThing_GetThingInsertOffset(sithCog *ctx)
{
    rdModel3 *prVar1;
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (((pThing != (sithThing *)0x0) 
        && ((pThing->rdthing).type == RD_THINGTYPE_MODEL)) 
        && (prVar1 = (pThing->rdthing).model3, prVar1 != (rdModel3 *)0x0))
    {
        sithCogExec_PushVector3(ctx,&prVar1->insertOffset);
        return;
    }
    sithCogExec_PushVector3(ctx,&rdroid_zeroVector3);
}



void sithCogFunctionThing_Startup(void* ctx)
{
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_WaitForStop, "waitforstop");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_StopThing, "stopthing");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_DestroyThing, "destroything");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingHealth, "getthinghealth");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingHealth, "gethealth");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_HealThing, "healthing");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingLight, "getthinglight");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingLight, "setthinglight");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingLight, "thinglight");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_ThingLightAnim, "thinglightanim");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_Rotate, "rotate");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_CreateThing, "creatething");
    if (Main_bMotsCompat) {
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_CreateThingLocal, "createthinglocal");
    }

    // DW added: ?
    if (Main_bDwCompat) {
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_CreateThing, "createthingnr");
    }
    else {
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_CreateThingNr, "createthingnr");
    }

    if (Main_bMotsCompat) {
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_CreateThingAtPosMots, "createthingatpos");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_CreateThingAtPosOwner, "createthingatposowner");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_CreateThingAtPos, "createthingatposold");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_CreateThingAtPosNrMots, "createthingatposnr");
    }
    else {
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_CreateThingAtPos, "createthingatpos");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_CreateThingAtPosNr, "createthingatposnr");
    }
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_RotatePivot, "rotatepivot");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_CaptureThing, "capturething");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_ReleaseThing, "releasething");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingVel, "setthingvel");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_AddThingVel, "addthingvel");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_ApplyForce, "applyforce");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_DetachThing, "detachthing");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetAttachFlags, "getattachflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetAttachFlags, "getthingattachflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_AttachThingToSurf, "attachthingtosurf");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_AttachThingToThing, "attachthingtothing");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetArmedMode, "setarmedmode");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingFlags, "setthingflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_ClearThingFlags, "clearthingflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_TeleportThing, "teleportthing");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingType, "setthingtype");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetCollideType, "setcollidetype");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetHeadlightIntensity, "setheadlightintensity");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingGeoMode, "getthinggeomode");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingGeoMode, "setthinggeomode");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingLightMode, "getthinglightmode");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingLightMode, "setthinglightmode");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingTexMode, "getthingtexmode");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingTexMode, "setthingtexmode");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingCurGeoMode, "getthingcurgeomode");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingCurGeoMode, "setthingcurgeomode");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingCurLightMode, "getthingcurlightmode");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingCurLightMode, "setthingcurlightmode");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingCurTexMode, "getthingcurtexmode");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingCurTexMode, "setthingcurtexmode");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetActorExtraSpeed, "setactorextraspeed");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingType, "getthingtype");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_IsMoving, "isthingmoving");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_IsMoving, "ismoving");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetCurFrame, "getcurframe");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetGoalFrame, "getgoalframe");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingParent, "getthingparent");
    if (Main_bMotsCompat) {
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingParent, "setthingparent");
    }
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingSector, "getthingsector");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingPos, "getthingpos");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingPos, "setthingpos");
    if (Main_bMotsCompat) {
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingPosEx, "setthingposex");
    }
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingVel, "getthingvel");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingUvec, "getthinguvec");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingLvec, "getthinglvec");
    if (Main_bMotsCompat) {
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingLvecPYR, "getthinglvecpyr");
    }
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingRvec, "getthingrvec");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingFlags, "getthingflags");
    if (Main_bDwCompat) {
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingInsertOffset, "getthinginsertoffset");
    }
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetCollideType, "getcollidetype");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetHeadlightIntensity, "getheadlightintensity");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_IsThingVisible, "isthingvisible");
    if (Main_bDwCompat) {
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingCollideSize, "getthingradius");
    }
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingPulse, "setthingpulse");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingTimer, "setthingtimer");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetInv, "getinv");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetInv, "setinv"); // DW added: g_debugModeFlags & DEBUGFLAG_100 check
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_ChangeInv, "changeinv"); // DW added: g_debugModeFlags & DEBUGFLAG_100 check
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetInvCog, "getinvcog");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetInvMin, "getinvmin");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetInvMax, "getinvmax");
    if (Main_bMotsCompat) {
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetCurInvWeapon, "getcurinvweapon2");
        //sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetCurInvWeaponMots, "getcurinvweapon");
    }
    else {
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetCurInvWeapon, "getcurinvweapon");
    }
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetCurInvWeapon, "setcurinvweapon");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_PlayKey, "playkey");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_StopKey, "stopkey");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingModel, "setthingmodel");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingModel, "getthingmodel");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_PlayMode, "playmode");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetMajorMode, "getmajormode");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_FirstThingInSector, "firstthinginsector");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_NextThingInSector, "nextthinginsector");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_PrevThingInSector, "prevthinginsector");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_MoveToFrame, "movetoframe");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SkipToFrame, "skiptoframe");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_JumpToFrame, "jumptoframe");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_PathMovePause, "pathmovepause");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_PathMoveResume, "pathmoveresume");
    if (Main_bDwCompat) {
        // TODO
        //sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_AddLaser, "addlaser");
        //sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_AddBeam, "addbeam");
        //sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_RemoveLaser, "removelaser");
        //sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetLaserColor, "getlasercolor");
        //sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetLaserId, "getlaserid");
        //sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_ComputeCatapultVelocity, "computecatapultvelocity");
    }
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingTemplate, "getthingtemplate");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_DamageThing, "damagething");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetLifeLeft, "setlifeleft");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetLifeLeft, "getlifeleft");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingThrust, "setthingthrust");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingThrust, "getthingthrust");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetHealth, "setthinghealth");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetHealth, "sethealth");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_AmputateJoint, "amputatejoint");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetActorWeapon, "setactorweapon");
    if (Main_bMotsCompat) {
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetActorWeaponMots, "getactorweapon");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetActorWeapon, "getactorweapon2");
    }
    else {
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetActorWeapon, "getactorweapon");
    }
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetPhysicsFlags, "getphysicsflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetPhysicsFlags, "setphysicsflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_ClearPhysicsFlags, "clearphysicsflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SkillTarget, "skilltarget");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_ParseArg, "parsearg");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingRotVel, "getthingrotvel");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingRotVel, "setthingrotvel");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingLook, "setthinglook");
    if (Main_bMotsCompat) {
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingLookPYR, "setthinglookpyr");
    }
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_IsCrouching, "isthingcrouching"); // DW removed
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_IsCrouching, "iscrouching");  // DW removed
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingClassCog, "getthingclasscog");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingClassCog, "setthingclasscog");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingCaptureCog, "getthingcapturecog");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingCaptureCog, "setthingcapturecog");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingRespawn, "getthingrespawn");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingSignature, "getthingsignature");
    if (Main_bMotsCompat) {
        sithCogScript_RegisterVerb(ctx,sithCogFunctionThing_GetThingGUID,"getthingguid");
        sithCogScript_RegisterVerb(ctx,sithCogFunctionThing_GetGUIDThing,"getguidthing");
    }
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingAttachFlags, "setthingattachflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_ClearThingAttachFlags, "clearthingattachflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetParticleSize, "getparticlesize");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetParticleSize, "setparticlesize");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetParticleGrowthSpeed, "getparticlegrowthspeed");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetParticleGrowthSpeed, "setparticlegrowthspeed");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetParticleTimeoutRate, "getparticletimeoutrate");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetParticleTimeoutRate, "setparticletimeoutrate");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetXFlags, "gettypeflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetXFlags, "settypeflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_ClearXFlags, "cleartypeflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetXFlags, "getactorflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetXFlags, "setactorflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_ClearXFlags, "clearactorflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetXFlags, "getweaponflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetXFlags, "setweaponflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_ClearXFlags, "clearweaponflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetXFlags, "getexplosionflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetXFlags, "setexplosionflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_ClearXFlags, "clearexplosionflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetXFlags, "getitemflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetXFlags, "setitemflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_ClearXFlags, "clearitemflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetXFlags, "getparticleflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetXFlags, "setparticleflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_ClearXFlags, "clearparticleflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_TakeItem, "takeitem");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_HasLos, "haslos");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingFireOffset, "getthingfireoffset");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingFireOffset, "setthingfireoffset");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingUserdata, "getthinguserdata");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingUserdata, "setthinguserdata");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingCollideSize, "getthingcollidesize");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingCollideSize, "setthingcollidesize");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingMoveSize, "getthingmovesize");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingMoveSize, "setthingmovesize");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingMass, "getthingmass");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingMass, "setthingmass");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SyncThingPos, "syncthingpos");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SyncThingAttachment, "syncthingattachment");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SyncThingState, "syncthingstate");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_AttachThingToThingEx, "attachthingtothingex");
    if (Main_bMotsCompat) {
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingMaxVelocity, "getthingmaxvelocity");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingMaxVelocity, "setthingmaxvelocity");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingMaxAngularVelocity, "getthingmaxangularvelocity");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingMaxAngularVelocity, "setthingmaxangularvelocity");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetActorHeadPYR, "getactorheadpyr");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetActorHeadPYR, "setactorheadpyr");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingJointAngle, "setthingjointangle");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingJointAngle, "getthingjointangle");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingMaxHeadPitch, "setthingmaxheadpitch");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingMinHeadPitch, "setthingminheadpitch");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_InterpolatePYR, "interpolatepyr");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetWeaponTarget, "setweapontarget");

        // TODO: weap_eweb_m.cog references a "SetThingCollide" verb? Superceded by "SetThingCollideSize"?
        // TODO: exp_hrail.cog references a "GetUserData" verb? Superceded by "GetThingUserData"?
    }
}
