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
#include "Engine/sithNet.h"
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
    sithThing *thing;

    thing = sithCogExec_PopThing(ctx);
    if (thing)
        sithCogExec_PushInt(ctx, thing->type);
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
                //sithDSSThing_SendMOTSNew1(); // MOTS added TODO TODO
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
    sithThing* thing = sithCogExec_PopThing(ctx);
    int a4 = sithCogExec_PopInt(ctx);
    float a5 = sithCogExec_PopFlex(ctx);
    sithThing* thing2 = sithCogExec_PopThing(ctx);

    if ( a5 > 0.0 && thing2 )
    {
        if ( !thing )
            thing = thing2;
        if ( COG_SHOULD_SYNC(ctx) )
        {
            sithDSSThing_SendDamage(thing2, thing, a5, a4, -1, 1);
        }
        sithCogExec_PushFlex(ctx, sithThing_Damage(thing2, thing, a5, a4));
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunctionThing_HealThing(sithCog *ctx)
{
    float amt = sithCogExec_PopFlex(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);
    if (amt > 0.0 && thing && (thing->type == SITH_THING_ACTOR || thing->type == SITH_THING_PLAYER))
    {
        thing->actorParams.health += amt;
        if ( thing->actorParams.health > thing->actorParams.maxHealth)
            thing->actorParams.health = thing->actorParams.maxHealth;
    }
}

void sithCogFunctionThing_GetThingHealth(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);

    if ( thing && (thing->type == SITH_THING_ACTOR || thing->type == SITH_THING_PLAYER) )
        sithCogExec_PushFlex(ctx, thing->actorParams.health);
    else
        sithCogExec_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_SetHealth(sithCog *ctx)
{
    float amt = sithCogExec_PopFlex(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing && (thing->type == SITH_THING_ACTOR || thing->type == SITH_THING_PLAYER))
        thing->actorParams.health = amt;
}

void sithCogFunctionThing_DestroyThing(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);
    if (!thing)
        return;

    //printf("destroy %x %s\n", thing->thing_id, ctx->cogscript_fpath);

    if (COG_SHOULD_SYNC(ctx) )
        sithDSSThing_SendDestroyThing(thing->thing_id, -1);

    sithThing_Destroy(thing);
}

void sithCogFunctionThing_JumpToFrame(sithCog *ctx)
{
    sithSector* sector = sithCogExec_PopSector(ctx);
    uint32_t frame = sithCogExec_PopInt(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if ( thing && sector && thing->moveType == SITH_MT_PATH && frame < thing->trackParams.loadedFrames )
    {
        if ( thing->sector && sector != thing->sector )
            sithThing_LeaveSector(thing);

        if ( thing->attach_flags )
            sithThing_DetachThing(thing);

        rdMatrix_BuildRotate34(&thing->lookOrientation, &thing->trackParams.aFrames[frame].rot);
        rdVector_Copy3(&thing->position, &thing->trackParams.aFrames[frame].pos);

        if ( !thing->sector )
            sithThing_EnterSector(thing, sector, 1, 0);
    }
}

void sithCogFunctionThing_MoveToFrame(sithCog *ctx)
{
    float speed = sithCogExec_PopFlex(ctx) * 0.1;
    int frame = sithCogExec_PopInt(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);
    if ( thing && thing->moveType == SITH_MT_PATH && thing->trackParams.loadedFrames > frame )
    {
        if ( speed == 0.0 )
            speed = 0.5;

        sithTrackThing_MoveToFrame(thing, frame, speed);

        if (COG_SHOULD_SYNC(ctx))
            sithDSSThing_SendPathMove(thing, frame, speed, 0, -1, 255);
    }
}

void sithCogFunctionThing_SkipToFrame(sithCog *ctx)
{
    float speed = sithCogExec_PopFlex(ctx) * 0.1;
    int frame = sithCogExec_PopInt(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);
    if ( thing && thing->moveType == SITH_MT_PATH && thing->trackParams.loadedFrames > frame )
    {
        if ( speed == 0.0 )
            speed = 0.5;

        sithTrackThing_SkipToFrame(thing, frame, speed);

        if (COG_SHOULD_SYNC(ctx))
            sithDSSThing_SendPathMove(thing, frame, speed, 1, -1, 255);
    }
}

void sithCogFunctionThing_RotatePivot(sithCog *ctx)
{
    float speed = sithCogExec_PopFlex(ctx);
    uint32_t frame = sithCogExec_PopInt(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if ( speed == 0.0 )
        speed = 1.0;

    if ( thing && thing->moveType == SITH_MT_PATH && thing->trackParams.loadedFrames > frame )
    {
        rdVector3* pos = &thing->trackParams.aFrames[frame].pos;
        rdVector3* rot = &thing->trackParams.aFrames[frame].rot;
        if ( speed <= 0.0 )
        {
            rdVector3 negRot;

            rdVector_Neg3(&negRot, rot);
            float negSpeed = -speed;
            sithTrackThing_RotatePivot(thing, pos, &negRot, negSpeed);
        }
        else
        {
            sithTrackThing_RotatePivot(thing, pos, rot, speed);
        }
    }
}

void sithCogFunctionThing_Rotate(sithCog *ctx)
{
    rdVector3 rot;

    sithCogExec_PopVector3(ctx, &rot);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing)
    {
        if ( thing->moveType == SITH_MT_PATH )
            sithTrackThing_Rotate(thing, &rot);
    }
}

void sithCogFunctionThing_GetThingLight(sithCog *ctx)
{
    sithThing *thing;

    thing = sithCogExec_PopThing(ctx);
    if (thing)
        sithCogExec_PushFlex(ctx, thing->light);
    else
        sithCogExec_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_SetThingLight(sithCog *ctx)
{
    float idk = sithCogExec_PopFlex(ctx);
    float light = sithCogExec_PopFlex(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if ( thing && light >= 0.0 )
    {
        if ( idk == 0.0 )
        {
            thing->light = light;
            if ( light != 0.0 )
            {
                thing->thingflags |= SITH_TF_LIGHT;
            }
        }
        else
        {
            sithSurface_SetThingLight(thing, light, idk, 0);
        }
    }
}

void sithCogFunctionThing_ThingLightAnim(sithCog *ctx)
{
    sithThing *thing; // ecx
    float idk_; // ST08_4
    rdSurface *surface; // eax
    float idk; // [esp+Ch] [ebp-8h]
    float light2; // [esp+10h] [ebp-4h]
    float light; // [esp+18h] [ebp+4h]

    idk = sithCogExec_PopFlex(ctx);
    light2 = sithCogExec_PopFlex(ctx);
    light = sithCogExec_PopFlex(ctx);
    thing = sithCogExec_PopThing(ctx);
    if ( thing
      && light2 >= (double)light
      && idk > 0.0
      && (idk_ = idk * 0.5, thing->light = light, (surface = sithSurface_SetThingLight(thing, light2, idk_, 1)) != 0) )
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
    sithThing* thing = sithCogExec_PopThing(ctx);

    if ( thing && thing->moveType == SITH_MT_PATH && thing->trackParams.field_C & 3 )
    {
        int idx = thing->thingIdx;
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
    sithThing *thing;
    sithSector *sector;

    thing = sithCogExec_PopThing(ctx);
    if ( thing && (sector = thing->sector) != 0 )
        sithCogExec_PushInt(ctx, sector->id);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_GetCurFrame(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);

    if ( thing && thing->moveType == SITH_MT_PATH )
        sithCogExec_PushInt(ctx, thing->curframe);
    else
        sithCogExec_PushInt(ctx, 0);
}

void sithCogFunctionThing_GetGoalFrame(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);

    if ( thing && thing->moveType == SITH_MT_PATH )
        sithCogExec_PushInt(ctx, thing->goalframe);
    else
        sithCogExec_PushInt(ctx, 0);
}

void sithCogFunctionThing_StopThing(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (!thing)
        return;

    if ( thing->moveType == SITH_MT_PATH )
    {
        sithTrackThing_Stop(thing);
        if (COG_SHOULD_SYNC(ctx))
            sithDSSThing_SendPathMove(thing, 0, 0.0, 2, -1, 255);
    }
    else if (thing->moveType == SITH_MT_PHYSICS)
    {
        sithPhysics_ThingStop(thing);
    }
}

void sithCogFunctionThing_IsMoving(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);
    if ( !thing || thing->type == SITH_THING_FREE )
    {
        sithCogExec_PushInt(ctx, 0);
        return;
    }

    if ( thing->moveType == SITH_MT_PHYSICS )
    {
        if ( thing->physicsParams.vel.x != 0.0 || thing->physicsParams.vel.y != 0.0 || thing->physicsParams.vel.z != 0.0 )
        {
            sithCogExec_PushInt(ctx, 1);
            return;
        }
    }
    else if ( thing->moveType == SITH_MT_PATH )
    {
        sithCogExec_PushInt(ctx, thing->trackParams.field_C & 3);
        return;
    }

    sithCogExec_PushInt(ctx, 0);
}

void sithCogFunctionThing_SetThingPulse(sithCog *ctx)
{
    float pulseSecs = sithCogExec_PopFlex(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);
    if (!thing)
        return;

    if ( pulseSecs == 0.0 )
    {
        thing->pulse_end_ms = 0;
        thing->thingflags &= ~SITH_TF_PULSE;
        thing->pulse_ms = 0;
    }
    else
    {
        thing->thingflags |= SITH_TF_PULSE;
        thing->pulse_ms = (int)(pulseSecs * 1000.0);
        thing->pulse_end_ms = thing->pulse_ms + sithTime_curMs;
    }
}

void sithCogFunctionThing_SetThingTimer(sithCog *ctx)
{
    float timerSecs = sithCogExec_PopFlex(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);
    if (!thing)
        return;

    if ( timerSecs == 0.0 )
    {
        thing->timer = 0;
        thing->thingflags &= ~SITH_TF_TIMER;
    }
    else
    {
        thing->thingflags |= SITH_TF_TIMER;
        thing->timer = sithTime_curMs + (uint32_t)(timerSecs * 1000.0);
    }
}

void sithCogFunctionThing_CaptureThing(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);
    if (thing)
    {
        thing->capture_cog = ctx;
        thing->thingflags |= SITH_TF_CAPTURED;
    }
}

void sithCogFunctionThing_ReleaseThing(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);
    if (thing)
    {
        sithCog* class_cog = thing->class_cog;
        thing->capture_cog = NULL;
        if ( !class_cog && !sithThing_Release(thing) )
        {
            thing->thingflags &= ~SITH_TF_CAPTURED;
        }
    }
}

void sithCogFunctionThing_GetThingParent(sithCog *ctx)
{
    sithThing* thing;
    sithThing* parent;

    thing = sithCogExec_PopThing(ctx);
    if ( thing && (parent = sithThing_GetParent(thing)) != 0 )
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
    sithThing* thing = sithCogExec_PopThing(ctx);
    if (thing)
        sithCogExec_PushVector3(ctx, &thing->position);
    else
        sithCogExec_PushVector3(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_SetThingPos(sithCog *ctx)
{
    rdVector3 poppedVec;

    sithCogExec_PopVector3(ctx, &poppedVec);
    sithThing* thing = sithCogExec_PopThing(ctx);
    if (thing)
    {
        rdVector_Copy3(&thing->position, &poppedVec);
        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_SendPos(thing, -1, 1);
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
    sithThing* thing = sithCogExec_PopThing(ctx);
    if (pSector || (pSector == (sithSector *)-1)) {
        pSector = sithSector_sub_4F8D00(sithWorld_pCurrentWorld, &poppedVec);
    }
    if (thing)
    {
        rdVector_Copy3(&thing->position, &poppedVec);
        sithThing_MoveToSector(thing,pSector,0);
        if (thing->moveType == SITH_MT_PHYSICS && thing->physicsParams.physflags & SITH_PF_FLOORSTICK)
            sithPhysics_FindFloor(thing, 1);

        if ( thing == sithPlayer_pLocalPlayerThing )
            sithCamera_FollowFocus(sithCamera_currentCamera);

        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_SendPos(thing, -1, 1);
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
    sithThing* thing = sithCogExec_PopThing(ctx);
    if (thing)
    {
        if ( thing->moveType == SITH_MT_PHYSICS)
        {
            rdVector_Copy3(&retval, &thing->physicsParams.vel);
        }
        else if ( thing->moveType == SITH_MT_PATH )
        {
            rdVector_Scale3(&retval, &thing->trackParams.vel, thing->trackParams.field_20);
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
    sithThing* thing = sithCogExec_PopThing(ctx);
    if ( thing && thing->moveType == SITH_MT_PHYSICS)
    {
        rdVector_Copy3(&thing->physicsParams.vel, &poppedVec);
        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SetSyncFlags(thing, THING_SYNC_POS);
        }
    }
}

void sithCogFunctionThing_ApplyForce(sithCog *ctx)
{
    rdVector3 poppedVec;

    sithCogExec_PopVector3(ctx, &poppedVec);
    sithThing* thing = sithCogExec_PopThing(ctx);
    if ( thing && thing->moveType == SITH_MT_PHYSICS)
    {
        sithPhysics_ThingApplyForce(thing, &poppedVec);
        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SetSyncFlags(thing, THING_SYNC_POS);
        }
    }
}

void sithCogFunctionThing_AddThingVel(sithCog *ctx)
{
    rdVector3 poppedVec;

    sithCogExec_PopVector3(ctx, &poppedVec);
    sithThing* thing = sithCogExec_PopThing(ctx);
    if ( thing && thing->moveType == SITH_MT_PHYSICS)
    {
        rdVector_Add3Acc(&thing->physicsParams.vel, &poppedVec);
        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SetSyncFlags(thing, THING_SYNC_POS);
        }
    }
}

void sithCogFunctionThing_GetThingLvec(sithCog *ctx)
{
    sithThing *thing; // eax

    thing = sithCogExec_PopThing(ctx);
    if (thing)
        sithCogExec_PushVector3(ctx, &thing->lookOrientation.lvec);
    else
        sithCogExec_PushVector3(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_GetThingLvecPYR(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (!pThing)
        sithCogExec_PushVector3(ctx, (rdVector3*)&rdroid_zeroVector3);

    rdVector3 pyrOut;
    rdMatrix34 lookOrient;
    rdMatrix_Copy34(&lookOrient, &pThing->lookOrientation);
    rdMatrix_ExtractAngles34(&lookOrient, &pyrOut);
    sithCogExec_PushVector3(ctx, &pyrOut);
}

void sithCogFunctionThing_GetThingUvec(sithCog *ctx)
{
    sithThing *thing; // eax

    thing = sithCogExec_PopThing(ctx);
    if (thing)
        sithCogExec_PushVector3(ctx, &thing->lookOrientation.uvec);
    else
        sithCogExec_PushVector3(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_GetThingRvec(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing)
        sithCogExec_PushVector3(ctx, &thing->lookOrientation.rvec);
    else
        sithCogExec_PushVector3(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_GetEyePYR(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);

    if ( thing && (thing->type == SITH_THING_ACTOR || thing->type == SITH_THING_PLAYER))
        sithCogExec_PushVector3(ctx, &thing->actorParams.eyePYR);
    else
        sithCogExec_PushVector3(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_DetachThing(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);
    if (thing)
    {
        sithThing_DetachThing(thing);
        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_SendSyncThingAttachment(thing, -1, 255, 1);
        }
    }
}

void sithCogFunctionThing_GetAttachFlags(sithCog *ctx)
{
    sithThing *thing; // eax

    thing = sithCogExec_PopThing(ctx);
    if (thing)
        sithCogExec_PushInt(ctx, thing->attach_flags);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_AttachThingToSurf(sithCog *ctx)
{
    sithSurface* surface = sithCogExec_PopSurface(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing && surface)
    {
        sithThing_AttachToSurface(thing, surface, 1);
        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_SendSyncThingAttachment(thing, -1, 255, 1);
        }
    }
}

void sithCogFunctionThing_AttachThingToThing(sithCog *ctx)
{
    sithThing* attached = sithCogExec_PopThing(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing && attached)
    {
        sithThing_AttachThing(thing, attached);
        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_SendSyncThingAttachment(thing, -1, 255, 1);
        }
    }
}

void sithCogFunctionThing_AttachThingToThingEx(sithCog *ctx)
{
    int attachFlags = sithCogExec_PopInt(ctx);
    sithThing* attached = sithCogExec_PopThing(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing && attached)
    {
        sithThing_AttachThing(thing, attached);
        thing->attach_flags |= attachFlags;

        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_SendSyncThingAttachment(thing, -1, 255, 1);
        }
    }
}

void sithCogFunctionThing_PlayMode(sithCog *ctx)
{
    int mode = sithCogExec_PopInt(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);
    if ( mode < 43 && thing && thing->animclass && thing->rdthing.puppet)
    {
        int track = sithPuppet_PlayMode(thing, mode, 0);
        if (track >= 0)
        {
            sithCogExec_PushInt(ctx, track);
            if (COG_SHOULD_SYNC(ctx))
            {
                sithDSSThing_SendPlayKeyMode(thing, mode, thing->rdthing.puppet->tracks[track].field_130, -1, 255);
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
    sithThing* thing = sithCogExec_PopThing(ctx);

    if ( !thing )
        goto fail;

    rdPuppet* puppet = thing->rdthing.puppet;
    if ( !puppet ) {
        goto fail;
    }

    // MOTS added: bugfix?
    if ( Main_bMotsCompat && thing == sithPlayer_pLocalPlayerThing && thing->actorParams.health < 1.0) {
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
        if ( thing->moveType == SITH_MT_PATH )
        {
            if ( thing->trackParams.field_C )
                sithTrackThing_Stop(thing);
            rdVector_Copy3(&thing->trackParams.field_24.scale, &thing->position);
        }
        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_SendPlayKey(thing, keyframe, trackNum, popInt, thing->rdthing.puppet->tracks[track].field_130, -1, 255);
        }
    }

    return;

fail:
    sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_StopKey(sithCog *ctx)
{
    float poppedFlex = sithCogExec_PopFlex(ctx);
    int track = sithCogExec_PopInt(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);
    if (!thing)
        return;

    rdPuppet* puppet = thing->rdthing.puppet;
    if (!puppet)
        return;

    if ( track >= 0 && track < 4 && poppedFlex >= 0.0 )
    {
        int v6 = puppet->tracks[track].field_130;
        if ( sithPuppet_StopKey(puppet, track, poppedFlex) )
        {
            if (COG_SHOULD_SYNC(ctx))
            {
                sithDSSThing_SendStopKey(thing, v6, poppedFlex, -1, 255);
            }
        }
    }
}

void sithCogFunctionThing_SetThingModel(sithCog *ctx)
{
    rdModel3* model = sithCogExec_PopModel3(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);
    if ( thing && model)
    {
        rdModel3* v4 = thing->rdthing.model3;
        int v5;
        if (v4)
        {
            v5 = -1;
        }
        else
        {
            v5 = v4->id;
            sithThing_SetNewModel(thing, model);
        }

        sithCogExec_PushInt(ctx, v5);

        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_SendSetThingModel(thing, -1);
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

    sithThing* thing = sithCogExec_PopThing(ctx);
    if ( thing && thing->rdthing.type == RD_THINGTYPE_MODEL && (model = thing->rdthing.model3) != 0 )
        sithCogExec_PushInt(ctx, model->id);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetArmedMode(sithCog *ctx)
{
    int poppedInt = sithCogExec_PopInt(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);
    if ( thing && poppedInt >= 0 && poppedInt <= 2)
    {
        sithPuppet_SetArmedMode(thing, poppedInt);

        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_SendSyncThing(thing, -1, 255);
        }
    }
}

void sithCogFunctionThing_GetThingFlags(sithCog *ctx)
{
    sithThing *thing; // eax

    thing = sithCogExec_PopThing(ctx);
    if (thing)
        sithCogExec_PushInt(ctx, thing->thingflags);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetThingFlags(sithCog *ctx)
{
    int flags = sithCogExec_PopInt(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);
    if ( thing && flags)
    {
        thing->thingflags |= flags;

        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SetSyncFlags(thing, THING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_ClearThingFlags(sithCog *ctx)
{
    int flags = sithCogExec_PopInt(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);
    if ( thing && flags)
    {
        thing->thingflags &= ~flags;

        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SetSyncFlags(thing, THING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_TeleportThing(sithCog *ctx)
{
    sithThing* thingTo = sithCogExec_PopThing(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if ( thing && thingTo )
    {
        if ( thing->attach_flags )
            sithThing_DetachThing(thing);

        rdMatrix_Copy34(&thing->lookOrientation, &thingTo->lookOrientation);
        rdVector_Copy3(&thing->position, &thingTo->position);
        sithThing_MoveToSector(thing, thingTo->sector, 0);
        if (thing->moveType == SITH_MT_PHYSICS && thing->physicsParams.physflags & SITH_PF_FLOORSTICK)
            sithPhysics_FindFloor(thing, 1);

        if ( thing == sithPlayer_pLocalPlayerThing )
            sithCamera_FollowFocus(sithCamera_currentCamera);

        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_SendPos(thing, -1, 1);
        }
    }
}

void sithCogFunctionThing_SetThingType(sithCog *ctx)
{
    int type = sithCogExec_PopInt(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if ( thing && type >= 0 && type < 12 )
        thing->type = type;
}

void sithCogFunctionThing_GetCollideType(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing)
        sithCogExec_PushInt(ctx, thing->collide);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetCollideType(sithCog *ctx)
{
    int collideType = sithCogExec_PopInt(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if ( thing && collideType < 4)
    {
        thing->collide = collideType;

        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SetSyncFlags(thing, THING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_FirstThingInSector(sithCog *ctx)
{
    sithSector* sector = sithCogExec_PopSector(ctx);
    if (sector)
    {
        sithThing* thing = sector->thingsList;

        if (thing)
            sithCogExec_PushInt(ctx, thing->thingIdx);
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
    sithThing *thing;
    sithThing *nextThing;

    thing = sithCogExec_PopThing(ctx);
    if ( thing && (nextThing = thing->nextThing) != 0 )
    {
        sithCogExec_PushInt(ctx, nextThing->thingIdx);
    }
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_PrevThingInSector(sithCog *ctx)
{
    sithThing *thing;
    sithThing *prevThing;

    thing = sithCogExec_PopThing(ctx);
    if ( thing && (prevThing = thing->prevThing) != 0 )
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
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing && thing->moveType == SITH_MT_PATH)
        sithCogExec_PushInt(ctx, thing->trackParams.loadedFrames);
    else
        sithCogExec_PushInt(ctx, -1);
}

// unused/unreferenced
void sithCogFunctionThing_GetFramePos(sithCog *ctx)
{
    uint32_t frame = sithCogExec_PopInt(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if ( thing && thing->moveType == SITH_MT_PATH && frame < thing->trackParams.loadedFrames )
        sithCogExec_PushVector3(ctx, &thing->trackParams.aFrames[frame].pos);
    sithCogExec_PushVector3(ctx, (rdVector3*)&rdroid_zeroVector3);
}

// unused/unreferenced
void sithCogFunctionThing_GetFrameRot(sithCog *ctx)
{
    uint32_t frame = sithCogExec_PopInt(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing && thing->moveType == SITH_MT_PATH && frame < thing->trackParams.loadedFrames)
        sithCogExec_PushVector3(ctx, &thing->trackParams.aFrames[frame].rot);
    sithCogExec_PushVector3(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_PathMovePause(sithCog *ctx)
{
    int ret = 0;
    sithThing* thing = sithCogExec_PopThing(ctx);

    if ( thing && thing->moveType == SITH_MT_PATH )
        ret = sithTrackThing_PathMovePause(thing);

    if ( ret == 1 )
        sithCogExec_PushInt(ctx, thing->thingIdx);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetHeadlightIntensity(sithCog *ctx)
{
    float intensity = sithCogExec_PopFlex(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing && (thing->type == SITH_THING_ACTOR || thing->type == SITH_THING_PLAYER))
    {
        thing->actorParams.lightIntensity = intensity;
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
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing && (thing->type == SITH_THING_ACTOR || thing->type == SITH_THING_PLAYER))
        sithCogExec_PushFlex(ctx, thing->actorParams.lightIntensity);
    else
        sithCogExec_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_IsThingVisible(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing)
        sithCogExec_PushInt(ctx, thing->isVisible + 1 >= (unsigned int)bShowInvisibleThings);
    else
        sithCogExec_PushInt(ctx, 0);
}

void sithCogFunctionThing_PathMoveResume(sithCog *ctx)
{
    int ret = 0;
    sithThing* thing = sithCogExec_PopThing(ctx);

    if ( thing && thing->moveType == SITH_THING_ACTOR )
        ret = sithTrackThing_PathMoveResume(thing);
    if ( ret == 1 )
        sithCogExec_PushInt(ctx, thing->thingIdx);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetCurInvWeapon(sithCog *ctx)
{
    int binIdx = sithCogExec_PopInt(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);
    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }
    if (thing)
        sithInventory_SetCurWeapon(thing, binIdx);
}

void sithCogFunctionThing_GetCurInvWeapon(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);
    if (thing)
    {
        int binIdx = sithInventory_GetCurWeapon(thing);
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
    sithThing* thing = sithCogExec_PopThing(ctx);
    if (thing)
    {
        int idx = sithInventory_GetCurWeapon(thing);
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
    sithThing* thing = sithCogExec_PopThing(ctx);
    if (thing)
        thing->rdthing.desiredGeoMode = mode;
}

void sithCogFunctionThing_GetThingGeoMode(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);
    if (thing)
        sithCogExec_PushInt(ctx, (int)thing->rdthing.desiredGeoMode);
}

void sithCogFunctionThing_SetThingLightMode(sithCog *ctx)
{
    rdLightMode_t mode = (rdLightMode_t)sithCogExec_PopInt(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);
    if (thing)
        thing->rdthing.desiredLightMode = mode;
}

void sithCogFunctionThing_GetThingLightMode(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);
    if (thing)
        sithCogExec_PushInt(ctx, (int)thing->rdthing.desiredLightMode);
}

void sithCogFunctionThing_SetThingTexMode(sithCog *ctx)
{
    int mode = sithCogExec_PopInt(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);
    if (thing)
        thing->rdthing.desiredTexMode = mode;
}

void sithCogFunctionThing_GetThingTexMode(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);
    if (thing)
        sithCogExec_PushInt(ctx, thing->rdthing.desiredTexMode);
}

void sithCogFunctionThing_SetThingCurGeoMode(sithCog *ctx)
{
    rdGeoMode_t mode = (rdGeoMode_t)sithCogExec_PopInt(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);
    if (thing)
    {
        thing->rdthing.curGeoMode = mode;
        if (COG_SHOULD_SYNC(ctx))
        {
                sithThing_SetSyncFlags(thing, THING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_GetThingCurGeoMode(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing)
        sithCogExec_PushInt(ctx, (int)thing->rdthing.curGeoMode);
}

void sithCogFunctionThing_SetThingCurLightMode(sithCog *ctx)
{
    rdLightMode_t mode = (rdLightMode_t)sithCogExec_PopInt(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);
    if (thing)
        thing->rdthing.curLightMode = mode;
}

void sithCogFunctionThing_GetThingCurLightMode(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing)
        sithCogExec_PushInt(ctx, (int)thing->rdthing.curLightMode);
}

void sithCogFunctionThing_SetThingCurTexMode(sithCog *ctx)
{
    int mode = sithCogExec_PopInt(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);
    if (thing)
        thing->rdthing.curTexMode = mode;
}

void sithCogFunctionThing_GetThingCurTexMode(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing)
        sithCogExec_PushInt(ctx, thing->rdthing.curTexMode);
}

void sithCogFunctionThing_SetActorExtraSpeed(sithCog *ctx)
{
    float extraSpeed = sithCogExec_PopFlex(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);
    if (thing)
        thing->actorParams.extraSpeed = extraSpeed;
}

void sithCogFunctionThing_GetThingTemplate(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing && thing->templateBase)
        sithCogExec_PushInt(ctx, thing->templateBase->thingIdx);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetLifeLeft(sithCog *ctx)
{
    float lifeLeftSecs = sithCogExec_PopFlex(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);
    if ( thing && lifeLeftSecs >= 0.0)
    {
        thing->lifeLeftMs = (int)(lifeLeftSecs * 1000.0);
        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SetSyncFlags(thing, THING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_GetLifeLeft(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);
    if (thing)
    {
        sithCogExec_PushFlex(ctx, (double)(unsigned int)thing->lifeLeftMs * 0.001);
    }
}

void sithCogFunctionThing_SetThingThrust(sithCog *ctx)
{
    rdVector3 poppedVec;

    int couldPopVec = sithCogExec_PopVector3(ctx, &poppedVec);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if ( thing && thing->moveType == SITH_MT_PHYSICS && couldPopVec)
    {
        sithCogExec_PushVector3(ctx, &thing->physicsParams.acceleration);
        rdVector_Copy3(&thing->physicsParams.acceleration, &poppedVec);
    }
}

void sithCogFunctionThing_GetThingThrust(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);

    if ( thing )
    {
        if ( thing->moveType == SITH_MT_PHYSICS )
            sithCogExec_PushVector3(ctx, &thing->physicsParams.acceleration);
    }
}

void sithCogFunctionThing_AmputateJoint(sithCog *ctx)
{
    uint32_t idx = sithCogExec_PopInt(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing)
    {
        rdThing* rdthing = &thing->rdthing;
        if ( thing != (sithThing *)-196 )
        {
            sithAnimclass* animclass = thing->animclass;
            if (animclass && idx < 0xA)
            {
                int jointIdx = animclass->bodypart_to_joint[idx];
                if ( jointIdx >= 0 )
                    rdthing->amputatedJoints[jointIdx] = 1;
            }
        }
    }
}

void sithCogFunctionThing_SetActorWeapon(sithCog *ctx)
{
    sithThing* weapTemplate = sithCogExec_PopTemplate(ctx);
    int weap_idx = sithCogExec_PopInt(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if ( thing && (thing->type == SITH_THING_ACTOR || thing->type == SITH_THING_PLAYER))
    {
        if ( weap_idx == 1 )
        {
            thing->actorParams.templateWeapon = weapTemplate;
        }
        else if ( weap_idx == 2 )
        {
            thing->actorParams.templateWeapon2 = weapTemplate;
        }
    }
}

// MOTS altered
void sithCogFunctionThing_GetActorWeapon(sithCog *ctx)
{
    int weap_idx = sithCogExec_PopInt(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing && (thing->type == SITH_THING_ACTOR || thing->type == SITH_THING_PLAYER))
    {
        sithThing* weapTemplate;
        if ( weap_idx == 1 )
        {
            weapTemplate = thing->actorParams.templateWeapon;
        }
        else if ( weap_idx == 2 )
        {
            weapTemplate = thing->actorParams.templateWeapon2;
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
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing && (thing->type == SITH_THING_ACTOR || thing->type == SITH_THING_PLAYER))
    {
        sithThing* weapTemplate;
        if ( weap_idx == 1 )
        {
            weapTemplate = thing->actorParams.templateWeapon;
        }
        else if ( weap_idx == 2 )
        {
            weapTemplate = thing->actorParams.templateWeapon2;
        }
        else
        {
            sithCogExec_PushInt(ctx, -1);
            return;
        }

        if (weapTemplate)
        {
            if (thing->type != SITH_THING_PLAYER) {
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
    sithThing* thing = sithCogExec_PopThing(ctx);
    if ( thing && thing->moveType == SITH_MT_PHYSICS )
        sithCogExec_PushInt(ctx, thing->physicsParams.physflags);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetPhysicsFlags(sithCog *ctx)
{
    int flags = sithCogExec_PopInt(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing && flags && thing->moveType == SITH_MT_PHYSICS)
    {
        thing->physicsParams.physflags |= flags;
        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SetSyncFlags(thing, THING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_ClearPhysicsFlags(sithCog *ctx)
{
    int flags = sithCogExec_PopInt(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing && flags && thing->moveType == SITH_MT_PHYSICS)
        thing->physicsParams.physflags &= ~flags;
}

void sithCogFunctionThing_SkillTarget(sithCog *ctx)
{
    sithCog *classCog;

    float param1 = sithCogExec_PopFlex(ctx);
    float param0 = sithCogExec_PopFlex(ctx);
    sithThing* otherThing = sithCogExec_PopThing(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if ( thing && otherThing && (classCog = thing->class_cog) != 0 )
    {
        if ( sithNet_isMulti && thing->type == SITH_THING_PLAYER )
        {
            sithDSSCog_SendSendTrigger(
                classCog,
                SITH_MESSAGE_SKILL,
                SENDERTYPE_THING,
                thing->thingIdx,
                SENDERTYPE_THING,
                otherThing->thingIdx,
                0,
                param0,
                param1,
                0.0,
                0.0,
                thing->actorParams.playerinfo->net_id);
            sithCogExec_PushFlex(ctx, 0.0);
        }
        else
        {
            float ret = sithCog_SendMessageEx(
                          classCog,
                          SITH_MESSAGE_SKILL,
                          SENDERTYPE_THING,
                          thing->thingIdx,
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
    sithThing* thing = sithCogExec_PopThing(ctx);

    if ( str && thing)
    {
        _strncpy(std_genBuffer, str, 0x3FFu);
        std_genBuffer[1023] = 0;

        stdConffile_ReadArgsFromStr(std_genBuffer);
        for (int i = 0 ; i < stdConffile_entry.numArgs; i++)
        {
            stdConffileArg* arg = &stdConffile_entry.args[i];
            sithThing_ParseArgs(arg, thing);
        }
    }
}

void sithCogFunctionThing_SetThingRotVel(sithCog *ctx)
{
    rdVector3 popped_vector3;

    sithCogExec_PopVector3(ctx, &popped_vector3);
    sithThing* thing = sithCogExec_PopThing(ctx);
    if ( thing && thing->moveType == SITH_MT_PHYSICS)
    {
        rdVector_Copy3(&thing->physicsParams.angVel, &popped_vector3);
        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SetSyncFlags(thing, THING_SYNC_POS);
        }
    }
}

void sithCogFunctionThing_GetThingRotVel(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);
    if ( thing && thing->moveType == SITH_MT_PHYSICS )
        sithCogExec_PushVector3(ctx, &thing->physicsParams.angVel);
    else
        sithCogExec_PushVector3(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_SetThingLook(sithCog *ctx)
{
    rdVector3 popped_vector3;

    int pop_v3_retval = sithCogExec_PopVector3(ctx, &popped_vector3);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if ( thing && pop_v3_retval == 1)
    {
        rdVector_Normalize3Acc(&popped_vector3);
        rdMatrix_BuildFromLook34(&thing->lookOrientation, &popped_vector3);

        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SetSyncFlags(thing, THING_SYNC_POS);
        }
    }
}

void sithCogFunctionThing_IsCrouching(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);
    if ( !thing || thing->moveType != SITH_MT_PHYSICS )
        sithCogExec_PushInt(ctx, -1);

    if (thing->physicsParams.physflags & SITH_PF_CROUCHING)
        sithCogExec_PushInt(ctx, 1);
    else
        sithCogExec_PushInt(ctx, 0);
}

void sithCogFunctionThing_GetThingClassCog(sithCog *ctx)
{
    sithThing *thing; // eax
    sithCog *classCog; // eax

    thing = sithCogExec_PopThing(ctx);
    if ( thing && (classCog = thing->class_cog) != 0 )
        sithCogExec_PushInt(ctx, classCog->selfCog);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetThingClassCog(sithCog *ctx)
{
    sithCog *classCog; // edi
    sithThing *thing; // eax

    classCog = sithCogExec_PopCog(ctx);
    thing = sithCogExec_PopThing(ctx);
    if ( thing )
    {
        if ( classCog )
            thing->class_cog = classCog;
    }
}

void sithCogFunctionThing_GetThingCaptureCog(sithCog *ctx)
{
    sithThing *thing; // eax
    sithCog *captureCog; // eax

    thing = sithCogExec_PopThing(ctx);
    if ( thing && (captureCog = thing->capture_cog) != 0 )
        sithCogExec_PushInt(ctx, captureCog->selfCog);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetThingCaptureCog(sithCog *ctx)
{
    sithCog *captureCog; // edi
    sithThing *thing; // eax

    captureCog = sithCogExec_PopCog(ctx);
    thing = sithCogExec_PopThing(ctx);
    if ( thing )
    {
        if ( captureCog )
            thing->capture_cog = captureCog;
    }
}

void sithCogFunctionThing_GetThingRespawn(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);
    if (thing && thing->type == SITH_THING_ITEM)
    {
        sithCogExec_PushFlex(ctx, thing->itemParams.respawn);
    }
}

void sithCogFunctionThing_GetThingSignature(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);

    if ( thing )
        sithCogExec_PushInt(ctx, thing->signature);
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
    sithThing* thing = sithCogExec_PopThing(ctx);

    if ( thing && flags)
    {
        thing->attach_flags |= flags;

        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_SendSyncThingAttachment(thing, -1, 255, 1);
        }
    }
}

void sithCogFunctionThing_ClearThingAttachFlags(sithCog *ctx)
{
    int flags = sithCogExec_PopInt(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if ( thing && flags)
    {
        thing->attach_flags &= ~flags;

        if (COG_SHOULD_SYNC(ctx))
        {
            sithDSSThing_SendSyncThingAttachment(thing, -1, 255, 1);
        }
    }
}

void sithCogFunctionThing_GetParticleSize(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing && thing->type == SITH_THING_PARTICLE)
        sithCogExec_PushFlex(ctx, thing->particleParams.elementSize);
    else
        sithCogExec_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_SetParticleSize(sithCog *ctx)
{
    float size = sithCogExec_PopFlex(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing && thing->type == SITH_THING_PARTICLE)
    {
        thing->particleParams.elementSize = size;
    }
}

void sithCogFunctionThing_GetParticleGrowthSpeed(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);

    if ( thing && thing->type == SITH_THING_PARTICLE )
        sithCogExec_PushFlex(ctx, thing->particleParams.growthSpeed);
    else
        sithCogExec_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_SetParticleGrowthSpeed(sithCog *ctx)
{
    float speed = sithCogExec_PopFlex(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing && thing->type == SITH_THING_PARTICLE)
    {
        thing->particleParams.growthSpeed = speed;
    }
}

void sithCogFunctionThing_GetParticleTimeoutRate(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);

    if ( thing && thing->type == SITH_THING_PARTICLE )
        sithCogExec_PushFlex(ctx, thing->particleParams.rate);
    else
        sithCogExec_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_SetParticleTimeoutRate(sithCog *ctx)
{
    float rate = sithCogExec_PopFlex(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing && thing->type == SITH_THING_PARTICLE)
    {
        thing->particleParams.rate = rate;
    }
}

void sithCogFunctionThing_GetXFlags(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);
    if (thing)
    {
        switch ( thing->type )
        {
            case SITH_THING_ACTOR:
            case SITH_THING_ITEM:
            case SITH_THING_PLAYER:
                sithCogExec_PushInt(ctx, thing->actorParams.typeflags);
                return;
            case SITH_THING_WEAPON:
            case SITH_THING_PARTICLE:
                sithCogExec_PushInt(ctx, thing->weaponParams.typeflags);
                return;
            case SITH_THING_EXPLOSION:
                sithCogExec_PushInt(ctx, thing->explosionParams.typeflags);
                return;
        }
    }

    sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetXFlags(sithCog *ctx)
{
    int flags = sithCogExec_PopInt(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if ( thing && flags )
    {
        switch ( thing->type )
        {
            case SITH_THING_ACTOR:
            case SITH_THING_WEAPON:
            case SITH_THING_ITEM:
            case SITH_THING_EXPLOSION:
            case SITH_THING_PLAYER:
            case SITH_THING_PARTICLE:
                thing->actorParams.typeflags |= flags;
                break;
            default:
                break;
        }

        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SetSyncFlags(thing, THING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_ClearXFlags(sithCog *ctx)
{
    int flags = sithCogExec_PopInt(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if ( thing && flags )
    {
        switch ( thing->type )
        {
            case SITH_THING_ACTOR:
            case SITH_THING_WEAPON:
            case SITH_THING_ITEM:
            case SITH_THING_EXPLOSION:
            case SITH_THING_PLAYER:
            case SITH_THING_PARTICLE:
                thing->actorParams.typeflags &= ~flags;
                break;
            default:
                break;
        }

        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SetSyncFlags(thing, THING_SYNC_STATE);
        }
    }
}

// MOTS altered
void sithCogFunctionThing_TakeItem(sithCog *ctx)
{
    sithThing* player = sithCogExec_PopThing(ctx);
    sithThing* itemThing = sithCogExec_PopThing(ctx);
    if ( itemThing && (Main_bMotsCompat ? 1 : player) && itemThing->type == SITH_THING_ITEM )
        sithItem_Take(itemThing, player, 0);
}

void sithCogFunctionThing_HasLos(sithCog *ctx)
{
    sithThing* thingB = sithCogExec_PopThing(ctx);
    sithThing* thingA = sithCogExec_PopThing(ctx);

    if ( thingA && thingB )
    {
        if (sithCollision_HasLos(thingA, thingB, 0))
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
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing)
        sithCogExec_PushVector3(ctx, &thing->actorParams.fireOffset);
    else
        sithCogExec_PushVector3(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_SetThingFireOffset(sithCog *ctx)
{
    rdVector3 poppedVec;

    sithCogExec_PopVector3(ctx, &poppedVec);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing)
    {
        rdVector_Copy3(&thing->actorParams.fireOffset, &poppedVec);
    }
}

void sithCogFunctionThing_GetThingUserdata(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing)
        sithCogExec_PushFlex(ctx, thing->userdata);
    else
        sithCogExec_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_SetThingUserdata(sithCog *ctx)
{
    float userdata = sithCogExec_PopFlex(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing)
        thing->userdata = userdata;
}

void sithCogFunctionThing_GetThingCollideSize(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing)
        sithCogExec_PushFlex(ctx, thing->collideSize);
    else
        sithCogExec_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_SetThingCollideSize(sithCog *ctx)
{
    float size = sithCogExec_PopFlex(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing)
        thing->collideSize = size;
}

void sithCogFunctionThing_GetThingMoveSize(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing)
        sithCogExec_PushFlex(ctx, thing->moveSize);
    else
        sithCogExec_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_SetThingMoveSize(sithCog *ctx)
{
    float moveSize = sithCogExec_PopFlex(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing)
        thing->moveSize = moveSize;
}

void sithCogFunctionThing_GetThingMass(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);
    if (thing)
    {
        if (thing->moveType == SITH_MT_PHYSICS)
            sithCogExec_PushFlex(ctx, thing->physicsParams.mass);
        else
            sithCogExec_PushFlex(ctx, 0.0);
    }
}

void sithCogFunctionThing_SetThingMass(sithCog *ctx)
{
    float mass = sithCogExec_PopFlex(ctx);
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing && thing->moveType == SITH_MT_PHYSICS)
    {
        thing->physicsParams.mass = mass;
        if (COG_SHOULD_SYNC(ctx))
        {
            sithThing_SetSyncFlags(thing, THING_SYNC_STATE);
        }
    }
}

void sithCogFunctionThing_SyncThingPos(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing)
        sithThing_SetSyncFlags(thing, THING_SYNC_POS);
}

void sithCogFunctionThing_SyncThingAttachment(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing)
        sithDSSThing_SendSyncThingAttachment(thing, -1, 255, 0);
}

void sithCogFunctionThing_SyncThingState(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing)
        sithThing_SetSyncFlags(thing, THING_SYNC_STATE);
}

void sithCogFunctionThing_GetMajorMode(sithCog *ctx)
{
    sithThing* thing = sithCogExec_PopThing(ctx);

    if (thing && thing->animclass && thing->rdthing.puppet)
        sithCogExec_PushInt(ctx, thing->puppet->majorMode);
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
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_CreateThingNr, "createthingnr");
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
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetCollideType, "getcollidetype");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetHeadlightIntensity, "getheadlightintensity");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_IsThingVisible, "isthingvisible");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingPulse, "setthingpulse");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingTimer, "setthingtimer");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetInv, "getinv");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetInv, "setinv");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_ChangeInv, "changeinv");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetInvCog, "getinvcog");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetInvMin, "getinvmin");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetInvMax, "getinvmax");
    if (Main_bMotsCompat) {
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetCurInvWeapon, "getcurinvweapon2");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetCurInvWeaponMots, "getcurinvweapon");
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
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_IsCrouching, "isthingcrouching");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_IsCrouching, "iscrouching");
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
        //sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingJointAngle, "setthingjointangle");
        //sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingJointAngle, "getthingjointangle");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingMaxHeadPitch, "setthingmaxheadpitch");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingMinHeadPitch, "setthingminheadpitch");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_InterpolatePYR, "interpolatepyr");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetWeaponTarget, "setweapontarget");
    }
}
