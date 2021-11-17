#include "sithCogFunctionThing.h"

#include <stdint.h>
#include "World/sithSector.h"
#include "World/sithThing.h"
#include "World/sithTrackThing.h"
#include "World/sithInventory.h"
#include "World/jkPlayer.h"
#include "World/sithItem.h"
#include "Engine/sithCollision.h"
#include "Engine/sithCamera.h"
#include "Engine/rdThing.h"
#include "Engine/sithNet.h"
#include "Engine/sithSurface.h"
#include "Engine/sithPuppet.h"
#include "Engine/sithTime.h"
#include "Engine/sithAnimClass.h"
#include "Engine/sithPhysics.h"
//#include "Engine/rdSurface.h"
#include "Dss/sithDSSThing.h"
#include "Dss/sithDSSCog.h"
#include "General/stdConffile.h"
#include "stdPlatform.h"
#include "Win95/DebugConsole.h"
#include "jk.h"

void sithCogFunctionThing_createThingAtPos_nr(sithCog *ctx);

void sithCogFunctionThing_GetThingType(sithCog *ctx)
{
    sithThing *thing;

    thing = sithCogVm_PopThing(ctx);
    if (thing)
        sithCogVm_PushInt(ctx, thing->type);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionThing_CreateThing(sithCog *ctx)
{
    sithThing *v1; // esi
    sithThing *v2; // ebx
    sithThing *v3; // edi

    v1 = sithCogVm_PopThing(ctx);
    v2 = sithCogVm_PopTemplate(ctx);
    if ( v1 && v1->type && v1->sector && v2 && (v3 = sithThing_SpawnTemplate(v2, v1)) != 0 )
    {
        if ( sithCogVm_multiplayerFlags )
        {
            if ( !(ctx->flags & 0x200) )
            {
                if ( ctx->trigId != SITH_MESSAGE_STARTUP && ctx->trigId != SITH_MESSAGE_SHUTDOWN )
                    sithDSSThing_SendCreateThing(v2, v3, v1, 0, 0, 0, 255, 1);
            }
        }
        sithCogVm_PushInt(ctx, v3->thingIdx);
    }
    else
    {
        sithCogVm_PushInt(ctx, -1);
    }
}


void sithCogFunctionThing_CreateThingNr(sithCog *ctx)
{
    sithThing *v1; // esi
    sithThing *v2; // ebx
    sithThing *v3; // edi

    v1 = sithCogVm_PopThing(ctx);
    v2 = sithCogVm_PopTemplate(ctx);
    if ( v1 && v1->type && v1->sector && v2 && (v3 = sithThing_SpawnTemplate(v2, v1)) != 0 )
    {
        if ( sithCogVm_multiplayerFlags )
        {
            if ( !(ctx->flags & 0x200) )
            {
                if ( ctx->trigId != SITH_MESSAGE_STARTUP && ctx->trigId != SITH_MESSAGE_SHUTDOWN )
                    sithDSSThing_SendCreateThing(v2, v3, v1, 0, 0, 0, 255, 1);
            }
        }
        sithCogVm_PushInt(ctx, v3->thingIdx);
    }
    else
    {
        sithCogVm_PushInt(ctx, -1);
    }
}

void sithCogFunctionThing_createThingUnused(sithCog *ctx)
{
    sithThing *v1; // esi
    sithThing *v2; // ebx
    sithThing *v3; // edi
    int v6; // [esp+18h] [ebp+8h]

    v6 = 0; // aaaaaa original is undefined

    v1 = sithCogVm_PopThing(ctx);
    v2 = sithCogVm_PopTemplate(ctx);
    if ( v1 && v1->type && v1->sector && v2 && (v3 = sithThing_SpawnTemplate(v2, v1)) != 0 )
    {
        if ( sithCogVm_multiplayerFlags )
        {
            if ( !(ctx->flags & 0x200) )
            {
                if ( ctx->trigId != SITH_MESSAGE_STARTUP && ctx->trigId != SITH_MESSAGE_SHUTDOWN )
                    sithDSSThing_SendCreateThing(v2, v3, v1, 0, 0, 0, 255, v6);
            }
        }
        sithCogVm_PushInt(ctx, v3->thingIdx);
    }
    else
    {
        sithCogVm_PushInt(ctx, -1);
    }
}

void sithCogFunctionThing_CreateThingAtPos(sithCog *ctx)
{
    sithCogFunctionThing_createThingAtPos_nr(ctx);
}

void sithCogFunctionThing_CreateThingAtPosNr(sithCog *ctx)
{
    sithCogFunctionThing_createThingAtPos_nr(ctx);
}

void sithCogFunctionThing_createThingAtPos_nr(sithCog *ctx)
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
    int a8; // [esp+6Ch] [ebp+8h]

    sithCogVm_PopVector3(ctx, &rot);
    sithCogVm_PopVector3(ctx, &pos);
    popSector = sithCogVm_PopSector(ctx);
    popTemplate = sithCogVm_PopTemplate(ctx);
    if ( !popTemplate || !popSector )
    {
        sithCogVm_PushInt(ctx, -1);
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
        a1.x = 0.0;
        a1.y = 0.0;
        a1.z = 0.0;
    }
    
    a8 = 0; // aaaaaa undefined in original

    rdMatrix_BuildRotate34(&a3, &rot);
    rdMatrix_TransformVector34Acc(&a1, &a3);
    rdVector_Add3Acc(&pos, &a1);
    v7 = sithThing_Create(popTemplate, &pos, &a3, popSector, 0);
    if ( v7 )
    {
        if ( sithCogVm_multiplayerFlags )
        {
            if ( !(ctx->flags & 0x200) )
            {
                if ( ctx->trigId != SITH_MESSAGE_STARTUP && ctx->trigId != SITH_MESSAGE_SHUTDOWN )
                    sithDSSThing_SendCreateThing(popTemplate, v7, 0, popSector, (int *)&pos, (int *)&rot, 255, a8);
            }
        }
        sithCogVm_PushInt(ctx, v7->thingIdx);
    }
    else
    {
        sithCogVm_PushInt(ctx, -1);
    }
}

void sithCogFunctionThing_DamageThing(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);
    int a4 = sithCogVm_PopInt(ctx);
    float a5 = sithCogVm_PopFlex(ctx);
    sithThing* thing2 = sithCogVm_PopThing(ctx);

    if ( a5 > 0.0 && thing2 )
    {
        if ( !thing )
            thing = thing2;
        if ( sithCogVm_multiplayerFlags )
        {
            if ( !(ctx->flags & 0x200) )
            {
                if ( ctx->trigId != SITH_MESSAGE_STARTUP && ctx->trigId != SITH_MESSAGE_SHUTDOWN )
                {
                    if ( sithNet_isServer )
                        sithDSSThing_SendDamage(thing2, thing, a5, a4, -1, 1);
                }
            }
        }
        sithCogVm_PushFlex(ctx, sithThing_Damage(thing2, thing, a5, a4));
    }
    else
    {
        sithCogVm_PushInt(ctx, -1);
    }
}

void sithCogFunctionThing_HealThing(sithCog *ctx)
{
    float amt = sithCogVm_PopFlex(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);
    if (amt > 0.0 && thing && (thing->type == SITH_THING_ACTOR || thing->type == SITH_THING_PLAYER))
    {
        thing->actorParams.health += amt;
        if ( thing->actorParams.health > thing->actorParams.maxHealth)
            thing->actorParams.health = thing->actorParams.maxHealth;
    }
}

void sithCogFunctionThing_GetThingHealth(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);

    if ( thing && (thing->type == SITH_THING_ACTOR || thing->type == SITH_THING_PLAYER) )
        sithCogVm_PushFlex(ctx, thing->actorParams.health);
    else
        sithCogVm_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_SetHealth(sithCog *ctx)
{
    float amt = sithCogVm_PopFlex(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing && (thing->type == SITH_THING_ACTOR || thing->type == SITH_THING_PLAYER))
        thing->actorParams.health = amt;
}

void sithCogFunctionThing_DestroyThing(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);
    if (!thing)
        return;

    //printf("destroy %x %s\n", thing->thing_id, ctx->cogscript_fpath);

    if (sithCogVm_multiplayerFlags 
        && !(ctx->flags & 0x200) 
        && ctx->trigId != SITH_MESSAGE_STARTUP 
        && ctx->trigId != SITH_MESSAGE_SHUTDOWN )
        sithDSSThing_SendDestroyThing(thing->thing_id, -1);

    sithThing_Destroy(thing);
}

void sithCogFunctionThing_JumpToFrame(sithCog *ctx)
{
    sithSector* sector = sithCogVm_PopSector(ctx);
    uint32_t frame = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

    if ( thing && sector && thing->moveType == SITH_MT_PATH && frame < thing->trackParams.loadedFrames )
    {
        if ( thing->sector && sector != thing->sector )
            sithThing_LeaveSector(thing);

        if ( thing->attach_flags )
            sithThing_DetachThing(thing);

        rdMatrix_BuildRotate34(&thing->lookOrientation, &thing->trackParams.frames[frame].rot);
        rdVector_Copy3(&thing->position, &thing->trackParams.frames[frame].pos);

        if ( !thing->sector )
            sithThing_EnterSector(thing, sector, 1, 0);
    }
}

void sithCogFunctionThing_MoveToFrame(sithCog *ctx)
{
    float speed = sithCogVm_PopFlex(ctx) * 0.1;
    int frame = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);
    if ( thing && thing->moveType == SITH_MT_PATH && thing->trackParams.loadedFrames > frame )
    {
        if ( speed == 0.0 )
            speed = 0.5;

        sithTrackThing_MoveToFrame(thing, frame, speed);

        if (sithCogVm_multiplayerFlags 
            && !(ctx->flags & 0x200) 
            && ctx->trigId != SITH_MESSAGE_STARTUP 
            && ctx->trigId != SITH_MESSAGE_SHUTDOWN )
            sithDSSThing_SendSyncThingFrame(thing, frame, speed, 0, -1, 255);
    }
}

void sithCogFunctionThing_SkipToFrame(sithCog *ctx)
{
    float speed = sithCogVm_PopFlex(ctx) * 0.1;
    int frame = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);
    if ( thing && thing->moveType == SITH_MT_PATH && thing->trackParams.loadedFrames > frame )
    {
        if ( speed == 0.0 )
            speed = 0.5;

        sithTrackThing_SkipToFrame(thing, frame, speed);

        if (sithCogVm_multiplayerFlags 
            && !(ctx->flags & 0x200) 
            && ctx->trigId != SITH_MESSAGE_STARTUP 
            && ctx->trigId != SITH_MESSAGE_SHUTDOWN )
            sithDSSThing_SendSyncThingFrame(thing, frame, speed, 1, -1, 255);
    }
}

void sithCogFunctionThing_RotatePivot(sithCog *ctx)
{
    float speed = sithCogVm_PopFlex(ctx);
    uint32_t frame = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

    if ( speed == 0.0 )
        speed = 1.0;

    if ( thing && thing->moveType == SITH_MT_PATH && thing->trackParams.loadedFrames > frame )
    {
        rdVector3* pos = &thing->trackParams.frames[frame].pos;
        rdVector3* rot = &thing->trackParams.frames[frame].rot;
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

    sithCogVm_PopVector3(ctx, &rot);
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing)
    {
        if ( thing->moveType == SITH_MT_PATH )
            sithTrackThing_Rotate(thing, &rot);
    }
}

void sithCogFunctionThing_GetThingLight(sithCog *ctx)
{
    sithThing *thing;

    thing = sithCogVm_PopThing(ctx);
    if (thing)
        sithCogVm_PushFlex(ctx, thing->light);
    else
        sithCogVm_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_SetThingLight(sithCog *ctx)
{
    float idk = sithCogVm_PopFlex(ctx);
    float light = sithCogVm_PopFlex(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

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

    idk = sithCogVm_PopFlex(ctx);
    light2 = sithCogVm_PopFlex(ctx);
    light = sithCogVm_PopFlex(ctx);
    thing = sithCogVm_PopThing(ctx);
    if ( thing
      && light2 >= (double)light
      && idk > 0.0
      && (idk_ = idk * 0.5, thing->light = light, (surface = sithSurface_SetThingLight(thing, light2, idk_, 1)) != 0) )
    {
        sithCogVm_PushInt(ctx, surface->index);
    }
    else
    {
        sithCogVm_PushInt(ctx, -1);
    }
}

void sithCogFunctionThing_WaitForStop(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);

    if ( thing && thing->moveType == SITH_MT_PATH && thing->trackParams.field_C & 3 )
    {
        int idx = thing->thingIdx;
        ctx->script_running = 3;
        ctx->wakeTimeMs = idx;

        if ( ctx->flags & 1 )
        {
            _sprintf(std_genBuffer, "Cog %s: Waiting for stop on object %d.\n", ctx->cogscript_fpath, idx);
            DebugConsole_Print(std_genBuffer);
        }
    }
}

void sithCogFunctionThing_GetThingSector(sithCog *ctx)
{
    sithThing *thing;
    sithSector *sector;

    thing = sithCogVm_PopThing(ctx);
    if ( thing && (sector = thing->sector) != 0 )
        sithCogVm_PushInt(ctx, sector->id);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionThing_GetCurFrame(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);

    if ( thing && thing->moveType == SITH_MT_PATH )
        sithCogVm_PushInt(ctx, thing->curframe);
    else
        sithCogVm_PushInt(ctx, 0);
}

void sithCogFunctionThing_GetGoalFrame(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);

    if ( thing && thing->moveType == SITH_MT_PATH )
        sithCogVm_PushInt(ctx, thing->goalframe);
    else
        sithCogVm_PushInt(ctx, 0);
}

void sithCogFunctionThing_StopThing(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (!thing)
        return;

    if ( thing->moveType == SITH_MT_PATH )
    {
        sithTrackThing_Stop(thing);
        if (sithCogVm_multiplayerFlags && !(ctx->flags & 0x200) && ctx->trigId != SITH_MESSAGE_STARTUP && ctx->trigId != SITH_MESSAGE_SHUTDOWN)
            sithDSSThing_SendSyncThingFrame(thing, 0, 0.0, 2, -1, 255);
    }
    else if (thing->moveType == SITH_MT_PHYSICS)
    {
        sithPhysics_ThingStop(thing);
    }
}

void sithCogFunctionThing_IsMoving(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);
    if ( !thing || thing->type == SITH_THING_FREE )
    {
        sithCogVm_PushInt(ctx, 0);
        return;
    }

    if ( thing->moveType == SITH_MT_PHYSICS )
    {
        if ( thing->physicsParams.vel.x != 0.0 || thing->physicsParams.vel.y != 0.0 || thing->physicsParams.vel.z != 0.0 )
        {
            sithCogVm_PushInt(ctx, 1);
            return;
        }
    }
    else if ( thing->moveType == SITH_MT_PATH )
    {
        sithCogVm_PushInt(ctx, thing->trackParams.field_C & 3);
        return;
    }

    sithCogVm_PushInt(ctx, 0);
}

void sithCogFunctionThing_SetThingPulse(sithCog *ctx)
{
    float pulseSecs = sithCogVm_PopFlex(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);
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
    float timerSecs = sithCogVm_PopFlex(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);
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
    sithThing* thing = sithCogVm_PopThing(ctx);
    if (thing)
    {
        thing->capture_cog = ctx;
        thing->thingflags |= SITH_TF_CAPTURED;
    }
}

void sithCogFunctionThing_ReleaseThing(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);
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

    thing = sithCogVm_PopThing(ctx);
    if ( thing && (parent = sithThing_GetParent(thing)) != 0 )
        sithCogVm_PushInt(ctx, parent->thingIdx);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionThing_GetThingPos(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);
    if (thing)
        sithCogVm_PushVector3(ctx, &thing->position);
    else
        sithCogVm_PushVector3(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_SetThingPos(sithCog *ctx)
{
    rdVector3 poppedVec;

    sithCogVm_PopVector3(ctx, &poppedVec);
    sithThing* thing = sithCogVm_PopThing(ctx);
    if (thing)
    {
        rdVector_Copy3(&thing->position, &poppedVec);
        if (sithCogVm_multiplayerFlags 
            && !(ctx->flags & 0x200)
            && ctx->trigId != SITH_MESSAGE_STARTUP 
            && ctx->trigId != SITH_MESSAGE_SHUTDOWN)
        {
            sithDSSThing_SendTeleportThing(thing, -1, 1);
        }
        sithCogVm_PushInt(ctx, 1);
    }
    else
    {
        sithCogVm_PushInt(ctx, 0);
    }
}

void sithCogFunctionThing_GetInv(sithCog *ctx)
{
    unsigned int binIdx;
    sithThing *playerThing;

    binIdx = sithCogVm_PopInt(ctx);
    playerThing = sithCogVm_PopThing(ctx);
    if ( playerThing 
         && playerThing->type == SITH_THING_PLAYER 
         && playerThing->actorParams.playerinfo 
         && binIdx < SITHBIN_NUMBINS )
    {
        sithCogVm_PushFlex(ctx, sithInventory_GetBinAmount(playerThing, binIdx));
    }
    else
    {
        sithCogVm_PushFlex(ctx, 0.0);
    }
}

void sithCogFunctionThing_SetInv(sithCog *ctx)
{
    float amt = sithCogVm_PopFlex(ctx);
    uint32_t binIdx = sithCogVm_PopInt(ctx);
    sithThing* playerThing = sithCogVm_PopThing(ctx);

    if ( playerThing 
         && playerThing->type == SITH_THING_PLAYER 
         && playerThing->actorParams.playerinfo 
         && binIdx < SITHBIN_NUMBINS )
        sithInventory_SetBinAmount(playerThing, binIdx, amt);
}

void sithCogFunctionThing_ChangeInv(sithCog *ctx)
{
    float amt = sithCogVm_PopFlex(ctx);
    uint32_t binIdx = sithCogVm_PopInt(ctx);
    sithThing* playerThing = sithCogVm_PopThing(ctx);

    if ( playerThing 
         && playerThing->type == SITH_THING_PLAYER 
         && playerThing->actorParams.playerinfo 
         && binIdx < SITHBIN_NUMBINS )
    {
        sithCogVm_PushFlex(ctx, sithInventory_ChangeInv(playerThing, binIdx, amt));
    }
    else
    {
        sithCogVm_PushFlex(ctx, 0.0);
    }
}

void sithCogFunctionThing_GetInvCog(sithCog *ctx)
{
    unsigned int binIdx;
    sithThing *playerThing;
    sithItemDescriptor *desc;
    sithCog *descCog;

    binIdx = sithCogVm_PopInt(ctx);
    playerThing = sithCogVm_PopThing(ctx);
    if ( playerThing
      && playerThing->type == SITH_THING_PLAYER
      && playerThing->actorParams.playerinfo
      && (desc = sithInventory_GetItemDesc(playerThing, binIdx), binIdx < SITHBIN_NUMBINS)
      && desc
      && (descCog = desc->cog) != 0 )
    {
        sithCogVm_PushInt(ctx, descCog->selfCog);
    }
    else
    {
        sithCogVm_PushInt(ctx, -1);
    }
}

void sithCogFunctionThing_GetThingVel(sithCog *ctx)
{
    rdVector3 retval;

    rdVector_Copy3(&retval, (rdVector3*)&rdroid_zeroVector3);
    sithThing* thing = sithCogVm_PopThing(ctx);
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
        sithCogVm_PushVector3(ctx, &retval);
    }
    else
    {
        sithCogVm_PushVector3(ctx, (rdVector3*)&rdroid_zeroVector3);
    }
}

void sithCogFunctionThing_SetThingVel(sithCog *ctx)
{
    rdVector3 poppedVec;

    sithCogVm_PopVector3(ctx, &poppedVec);
    sithThing* thing = sithCogVm_PopThing(ctx);
    if ( thing && thing->moveType == SITH_MT_PHYSICS)
    {
        rdVector_Copy3(&thing->physicsParams.vel, &poppedVec);
        if ( sithCogVm_multiplayerFlags 
             && !(ctx->flags & 0x200)
             && ctx->trigId != SITH_MESSAGE_STARTUP 
             && ctx->trigId != SITH_MESSAGE_SHUTDOWN)
        {
            sithThing_SyncThingPos(thing, 1);
        }
    }
}

void sithCogFunctionThing_ApplyForce(sithCog *ctx)
{
    rdVector3 poppedVec;

    sithCogVm_PopVector3(ctx, &poppedVec);
    sithThing* thing = sithCogVm_PopThing(ctx);
    if ( thing && thing->moveType == SITH_MT_PHYSICS)
    {
        sithPhysics_ThingApplyForce(thing, &poppedVec);
        if ( sithCogVm_multiplayerFlags 
             && !(ctx->flags & 0x200)
             && ctx->trigId != SITH_MESSAGE_STARTUP 
             && ctx->trigId != SITH_MESSAGE_SHUTDOWN)
        {
            sithThing_SyncThingPos(thing, 1);
        }
    }
}

void sithCogFunctionThing_AddThingVel(sithCog *ctx)
{
    rdVector3 poppedVec;

    sithCogVm_PopVector3(ctx, &poppedVec);
    sithThing* thing = sithCogVm_PopThing(ctx);
    if ( thing && thing->moveType == SITH_MT_PHYSICS)
    {
        rdVector_Add3Acc(&thing->physicsParams.vel, &poppedVec);
        if ( sithCogVm_multiplayerFlags 
             && !(ctx->flags & 0x200)
             && ctx->trigId != SITH_MESSAGE_STARTUP 
             && ctx->trigId != SITH_MESSAGE_SHUTDOWN)
        {
            sithThing_SyncThingPos(thing, 1);
        }
    }
}

void sithCogFunctionThing_GetThingLvec(sithCog *ctx)
{
    sithThing *thing; // eax

    thing = sithCogVm_PopThing(ctx);
    if (thing)
        sithCogVm_PushVector3(ctx, &thing->lookOrientation.lvec);
    else
        sithCogVm_PushVector3(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_GetThingUvec(sithCog *ctx)
{
    sithThing *thing; // eax

    thing = sithCogVm_PopThing(ctx);
    if (thing)
        sithCogVm_PushVector3(ctx, &thing->lookOrientation.uvec);
    else
        sithCogVm_PushVector3(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_GetThingRvec(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing)
        sithCogVm_PushVector3(ctx, &thing->lookOrientation.rvec);
    else
        sithCogVm_PushVector3(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_GetEyePYR(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);

    if ( thing && (thing->type == SITH_THING_ACTOR || thing->type == SITH_THING_PLAYER))
        sithCogVm_PushVector3(ctx, &thing->actorParams.eyePYR);
    else
        sithCogVm_PushVector3(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_DetachThing(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);
    if (thing)
    {
        sithThing_DetachThing(thing);
        if (sithCogVm_multiplayerFlags 
            && !(ctx->flags & 0x200)
            && ctx->trigId != SITH_MESSAGE_STARTUP 
            && ctx->trigId != SITH_MESSAGE_SHUTDOWN)
        {
            sithDSSThing_SendSyncThingAttachment(thing, -1, 255, 1);
        }
    }
}

void sithCogFunctionThing_GetAttachFlags(sithCog *ctx)
{
    sithThing *thing; // eax

    thing = sithCogVm_PopThing(ctx);
    if (thing)
        sithCogVm_PushInt(ctx, thing->attach_flags);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionThing_AttachThingToSurf(sithCog *ctx)
{
    sithSurface* surface = sithCogVm_PopSurface(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing && surface)
    {
        sithThing_AttachToSurface(thing, surface, 1);
        if (sithCogVm_multiplayerFlags 
            && !(ctx->flags & 0x200)
            && ctx->trigId != SITH_MESSAGE_STARTUP 
            && ctx->trigId != SITH_MESSAGE_SHUTDOWN)
        {
            sithDSSThing_SendSyncThingAttachment(thing, -1, 255, 1);
        }
    }
}

void sithCogFunctionThing_AttachThingToThing(sithCog *ctx)
{
    sithThing* attached = sithCogVm_PopThing(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing && attached)
    {
        sithThing_AttachThing(thing, attached);
        if (sithCogVm_multiplayerFlags 
            && !(ctx->flags & 0x200)
            && ctx->trigId != SITH_MESSAGE_STARTUP 
            && ctx->trigId != SITH_MESSAGE_SHUTDOWN)
        {
            sithDSSThing_SendSyncThingAttachment(thing, -1, 255, 1);
        }
    }
}

void sithCogFunctionThing_AttachThingToThingEx(sithCog *ctx)
{
    int attachFlags = sithCogVm_PopInt(ctx);
    sithThing* attached = sithCogVm_PopThing(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing && attached)
    {
        sithThing_AttachThing(thing, attached);
        thing->attach_flags |= attachFlags;

        if (sithCogVm_multiplayerFlags 
            && !(ctx->flags & 0x200)
            && ctx->trigId != SITH_MESSAGE_STARTUP 
            && ctx->trigId != SITH_MESSAGE_SHUTDOWN)
        {
            sithDSSThing_SendSyncThingAttachment(thing, -1, 255, 1);
        }
    }
}

void sithCogFunctionThing_PlayMode(sithCog *ctx)
{
    int mode = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);
    if ( mode < 43 && thing && thing->animclass && thing->rdthing.puppet)
    {
        int track = sithPuppet_PlayMode(thing, mode, 0);
        if (track >= 0)
        {
            sithCogVm_PushInt(ctx, track);
            if (sithCogVm_multiplayerFlags 
                && !(ctx->flags & 0x200)
                && ctx->trigId != SITH_MESSAGE_STARTUP 
                && ctx->trigId != SITH_MESSAGE_SHUTDOWN)
            {
                sithDSSThing_SendOpenDoor(thing, mode, thing->rdthing.puppet->tracks[track].field_130, -1, 255);
            }
        }
    }
    else
    {
        sithCogVm_PushInt(ctx, -1);
    }
}

void sithCogFunctionThing_PlayKey(sithCog *ctx)
{
    int trackNum = sithCogVm_PopInt(ctx);
    int popInt = sithCogVm_PopInt(ctx);
    rdKeyframe* keyframe = sithCogVm_PopKeyframe(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

    if ( !thing )
        goto fail;

    rdPuppet* puppet = thing->rdthing.puppet;
    if ( !puppet )
        goto fail;

    if ( !keyframe )
    {
        sithCogVm_PushInt(ctx, -1);
        return;
    }
    
    int track = sithPuppet_StartKey(puppet, keyframe, popInt, popInt + 2, trackNum, 0);
    if ( track >= 0 )
    {
        sithCogVm_PushInt(ctx, track);
        if ( thing->moveType == SITH_MT_PATH )
        {
            if ( thing->trackParams.field_C )
                sithTrackThing_Stop(thing);
            rdVector_Copy3(&thing->trackParams.field_24.scale, &thing->position);
        }
        if (sithCogVm_multiplayerFlags 
            && !(ctx->flags & 0x200)
            && ctx->trigId != SITH_MESSAGE_STARTUP 
            && ctx->trigId != SITH_MESSAGE_SHUTDOWN)
        {
            sithDSSThing_SendPlayKey(thing, keyframe, trackNum, popInt, thing->rdthing.puppet->tracks[track].field_130, -1, 255);
        }
    }

    return;

fail:
    sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionThing_StopKey(sithCog *ctx)
{
    float poppedFlex = sithCogVm_PopFlex(ctx);
    int track = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);
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
            if (sithCogVm_multiplayerFlags 
                && !(ctx->flags & 0x200)
                && ctx->trigId != SITH_MESSAGE_STARTUP 
                && ctx->trigId != SITH_MESSAGE_SHUTDOWN)
            {
                sithDSSThing_SendStopKey(thing, v6, poppedFlex, -1, 255);
            }
        }
    }
}

void sithCogFunctionThing_SetThingModel(sithCog *ctx)
{
    rdModel3* model = sithCogVm_PopModel3(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);
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

        sithCogVm_PushInt(ctx, v5);

        if (sithCogVm_multiplayerFlags 
            && !(ctx->flags & 0x200)
            && ctx->trigId != SITH_MESSAGE_STARTUP 
            && ctx->trigId != SITH_MESSAGE_SHUTDOWN)
        {
            sithDSSThing_SendSetThingModel(thing, -1);
        }
    }
    else
    {
        sithCogVm_PushInt(ctx, -1);
    }
}

void sithCogFunctionThing_GetThingModel(sithCog *ctx)
{
    rdModel3 *model;

    sithThing* thing = sithCogVm_PopThing(ctx);
    if ( thing && thing->rdthing.type == RD_THINGTYPE_MODEL && (model = thing->rdthing.model3) != 0 )
        sithCogVm_PushInt(ctx, model->id);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetArmedMode(sithCog *ctx)
{
    int poppedInt = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);
    if ( thing && poppedInt >= 0 && poppedInt <= 2)
    {
        sithPuppet_SetArmedMode(thing, poppedInt);

        if (sithCogVm_multiplayerFlags 
            && !(ctx->flags & 0x200)
            && ctx->trigId != SITH_MESSAGE_STARTUP 
            && ctx->trigId != SITH_MESSAGE_SHUTDOWN)
        {
            sithDSSThing_SendSyncThing(thing, -1, 255);
        }
    }
}

void sithCogFunctionThing_GetThingFlags(sithCog *ctx)
{
    sithThing *thing; // eax

    thing = sithCogVm_PopThing(ctx);
    if (thing)
        sithCogVm_PushInt(ctx, thing->thingflags);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetThingFlags(sithCog *ctx)
{
    int flags = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);
    if ( thing && flags)
    {
        thing->thingflags |= flags;

        if (sithCogVm_multiplayerFlags 
            && !(ctx->flags & 0x200)
            && ctx->trigId != SITH_MESSAGE_STARTUP 
            && ctx->trigId != SITH_MESSAGE_SHUTDOWN)
        {
            sithThing_SyncThingPos(thing, 2);
        }
    }
}

void sithCogFunctionThing_ClearThingFlags(sithCog *ctx)
{
    int flags = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);
    if ( thing && flags)
    {
        thing->thingflags &= ~flags;

        if (sithCogVm_multiplayerFlags 
            && !(ctx->flags & 0x200)
            && ctx->trigId != SITH_MESSAGE_STARTUP 
            && ctx->trigId != SITH_MESSAGE_SHUTDOWN)
        {
            sithThing_SyncThingPos(thing, 2);
        }
    }
}

void sithCogFunctionThing_TeleportThing(sithCog *ctx)
{
    sithThing* thingTo = sithCogVm_PopThing(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

    if ( thing && thingTo )
    {
        if ( thing->attach_flags )
            sithThing_DetachThing(thing);

        rdMatrix_Copy34(&thing->lookOrientation, &thingTo->lookOrientation);
        rdVector_Copy3(&thing->position, &thingTo->position);
        sithThing_MoveToSector(thing, thingTo->sector, 0);
        if (thing->moveType == SITH_MT_PHYSICS && thing->physicsParams.physflags & PHYSFLAGS_FLOORSTICK)
            sithPhysics_FindFloor(thing, 1);

        if ( thing == g_localPlayerThing )
            sithCamera_FollowFocus(sithCamera_currentCamera);

        if (sithCogVm_multiplayerFlags 
            && !(ctx->flags & 0x200)
            && ctx->trigId != SITH_MESSAGE_STARTUP 
            && ctx->trigId != SITH_MESSAGE_SHUTDOWN)
        {
            sithDSSThing_SendTeleportThing(thing, -1, 1);
        }
    }
}

void sithCogFunctionThing_SetThingType(sithCog *ctx)
{
    int type = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

    if ( thing && type >= 0 && type < 12 )
        thing->type = type;
}

void sithCogFunctionThing_GetCollideType(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing)
        sithCogVm_PushInt(ctx, thing->collide);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetCollideType(sithCog *ctx)
{
    int collideType = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

    if ( thing && collideType < 4)
    {
        thing->collide = collideType;

        if (sithCogVm_multiplayerFlags 
            && !(ctx->flags & 0x200)
            && ctx->trigId != SITH_MESSAGE_STARTUP 
            && ctx->trigId != SITH_MESSAGE_SHUTDOWN)
        {
            sithThing_SyncThingPos(thing, 2);
        }
    }
}

void sithCogFunctionThing_FirstThingInSector(sithCog *ctx)
{
    sithSector* sector = sithCogVm_PopSector(ctx);
    if (sector)
    {
        sithThing* thing = sector->thingsList;

        if (thing)
            sithCogVm_PushInt(ctx, thing->thingIdx);
        else
            sithCogVm_PushInt(ctx, -1);
    }
    else
    {
        sithCogVm_PushInt(ctx, -1);
        sithCogVm_PushInt(ctx, -1);
    }
}

void sithCogFunctionThing_NextThingInSector(sithCog *ctx)
{
    sithThing *thing;
    sithThing *nextThing;

    thing = sithCogVm_PopThing(ctx);
    if ( thing && (nextThing = thing->nextThing) != 0 )
    {
        sithCogVm_PushInt(ctx, nextThing->thingIdx);
    }
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionThing_PrevThingInSector(sithCog *ctx)
{
    sithThing *thing;
    sithThing *prevThing;

    thing = sithCogVm_PopThing(ctx);
    if ( thing && (prevThing = thing->prevThing) != 0 )
        sithCogVm_PushInt(ctx, prevThing->thingIdx);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionThing_GetInvMin(sithCog *ctx)
{
    int binIdx = sithCogVm_PopInt(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);
    if ( player && player->type == SITH_THING_PLAYER && player->actorParams.playerinfo )
    {
        sithCogVm_PushFlex(ctx, sithInventory_GetMin(player, binIdx));
    }
    else
    {
        sithCogVm_PushFlex(ctx, -1.0);
    }
}

void sithCogFunctionThing_GetInvMax(sithCog *ctx)
{
    int binIdx = sithCogVm_PopInt(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);
    if ( player && player->type == SITH_THING_PLAYER && player->actorParams.playerinfo )
    {
        sithCogVm_PushFlex(ctx, sithInventory_GetMax(player, binIdx));
    }
    else
    {
        sithCogVm_PushFlex(ctx, -1.0);
    }
}

// unused/unreferenced
void sithCogFunctionThing_GetLoadedFrames(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing && thing->moveType == SITH_MT_PATH)
        sithCogVm_PushInt(ctx, thing->trackParams.loadedFrames);
    else
        sithCogVm_PushInt(ctx, -1);
}

// unused/unreferenced
void sithCogFunctionThing_GetFramePos(sithCog *ctx)
{
    uint32_t frame = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

    if ( thing && thing->moveType == SITH_MT_PATH && frame < thing->trackParams.loadedFrames )
        sithCogVm_PushVector3(ctx, &thing->trackParams.frames[frame].pos);
    sithCogVm_PushVector3(ctx, (rdVector3*)&rdroid_zeroVector3);
}

// unused/unreferenced
void sithCogFunctionThing_GetFrameRot(sithCog *ctx)
{
    uint32_t frame = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing && thing->moveType == SITH_MT_PATH && frame < thing->trackParams.loadedFrames)
        sithCogVm_PushVector3(ctx, &thing->trackParams.frames[frame].rot);
    sithCogVm_PushVector3(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_PathMovePause(sithCog *ctx)
{
    int ret = 0;
    sithThing* thing = sithCogVm_PopThing(ctx);

    if ( thing && thing->moveType == SITH_MT_PATH )
        ret = sithTrackThing_PathMovePause(thing);

    if ( ret == 1 )
        sithCogVm_PushInt(ctx, thing->thingIdx);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetHeadlightIntensity(sithCog *ctx)
{
    float intensity = sithCogVm_PopFlex(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing && (thing->type == SITH_THING_ACTOR || thing->type == SITH_THING_PLAYER))
    {
        thing->actorParams.lightIntensity = intensity;
        sithCogVm_PushFlex(ctx, intensity);
    }
    else
    {
        sithCogVm_PushFlex(ctx, -1.0);
    }
}

void sithCogFunctionThing_GetHeadlightIntensity(sithCog *ctx)
{
    sithCogVm_PopFlex(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing && (thing->type == SITH_THING_ACTOR || thing->type == SITH_THING_PLAYER))
        sithCogVm_PushFlex(ctx, thing->actorParams.lightIntensity);
    else
        sithCogVm_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_IsThingVisible(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing)
        sithCogVm_PushInt(ctx, thing->isVisible + 1 >= (unsigned int)bShowInvisibleThings);
    else
        sithCogVm_PushInt(ctx, 0);
}

void sithCogFunctionThing_PathMoveResume(sithCog *ctx)
{
    int ret = 0;
    sithThing* thing = sithCogVm_PopThing(ctx);

    if ( thing && thing->moveType == SITH_THING_ACTOR )
        ret = sithTrackThing_PathMoveResume(thing);
    if ( ret == 1 )
        sithCogVm_PushInt(ctx, thing->thingIdx);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetCurInvWeapon(sithCog *ctx)
{
    int idx = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);
    if (thing)
        sithInventory_SetCurWeapon(thing, idx);
}

void sithCogFunctionThing_GetCurInvWeapon(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);
    if (thing)
    {
        sithCogVm_PushInt(ctx, sithInventory_GetCurWeapon(thing));
    }
    else
    {
        sithCogVm_PushInt(ctx, -1);
    }
}

void sithCogFunctionThing_SetThingGeoMode(sithCog *ctx)
{
    int mode = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);
    if (thing)
        thing->rdthing.geoMode = mode;
}

void sithCogFunctionThing_GetThingGeoMode(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);
    if (thing)
        sithCogVm_PushInt(ctx, thing->rdthing.geoMode);
}

void sithCogFunctionThing_SetThingLightMode(sithCog *ctx)
{
    int mode = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);
    if (thing)
        thing->rdthing.lightMode = mode;
}

void sithCogFunctionThing_GetThingLightMode(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);
    if (thing)
        sithCogVm_PushInt(ctx, thing->rdthing.lightMode);
}

void sithCogFunctionThing_SetThingTexMode(sithCog *ctx)
{
    int mode = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);
    if (thing)
        thing->rdthing.texMode = mode;
}

void sithCogFunctionThing_GetThingTexMode(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);
    if (thing)
        sithCogVm_PushInt(ctx, thing->rdthing.texMode);
}

void sithCogFunctionThing_SetThingCurGeoMode(sithCog *ctx)
{
    int mode = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);
    if (thing)
    {
        thing->rdthing.geometryMode = mode;
        if (sithCogVm_multiplayerFlags 
            && !(ctx->flags & 0x200)
            && ctx->trigId != SITH_MESSAGE_STARTUP 
            && ctx->trigId != SITH_MESSAGE_SHUTDOWN)
        {
                sithThing_SyncThingPos(thing, 2);
        }
    }
}

void sithCogFunctionThing_GetThingCurGeoMode(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing)
        sithCogVm_PushInt(ctx, thing->rdthing.geometryMode);
}

void sithCogFunctionThing_SetThingCurLightMode(sithCog *ctx)
{
    int mode = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);
    if (thing)
        thing->rdthing.lightingMode = mode;
}

void sithCogFunctionThing_GetThingCurLightMode(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing)
        sithCogVm_PushInt(ctx, thing->rdthing.lightingMode);
}

void sithCogFunctionThing_SetThingCurTexMode(sithCog *ctx)
{
    int mode = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);
    if (thing)
        thing->rdthing.textureMode = mode;
}

void sithCogFunctionThing_GetThingCurTexMode(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing)
        sithCogVm_PushInt(ctx, thing->rdthing.textureMode);
}

void sithCogFunctionThing_SetActorExtraSpeed(sithCog *ctx)
{
    float extraSpeed = sithCogVm_PopFlex(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);
    if (thing)
        thing->actorParams.extraSpeed = extraSpeed;
}

void sithCogFunctionThing_GetThingTemplate(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing && thing->templateBase)
        sithCogVm_PushInt(ctx, thing->templateBase->thingIdx);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetLifeLeft(sithCog *ctx)
{
    float lifeLeftSecs = sithCogVm_PopFlex(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);
    if ( thing && lifeLeftSecs >= 0.0)
    {
        thing->lifeLeftMs = (int)(lifeLeftSecs * 1000.0);
        if (sithCogVm_multiplayerFlags 
            && !(ctx->flags & 0x200)
            && ctx->trigId != SITH_MESSAGE_STARTUP 
            && ctx->trigId != SITH_MESSAGE_SHUTDOWN)
        {
            sithThing_SyncThingPos(thing, 2);
        }
    }
}

void sithCogFunctionThing_GetLifeLeft(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);
    if (thing)
    {
        sithCogVm_PushFlex(ctx, (double)(unsigned int)thing->lifeLeftMs * 0.001);
    }
}

void sithCogFunctionThing_SetThingThrust(sithCog *ctx)
{
    rdVector3 poppedVec;

    int couldPopVec = sithCogVm_PopVector3(ctx, &poppedVec);
    sithThing* thing = sithCogVm_PopThing(ctx);

    if ( thing && thing->moveType == SITH_MT_PHYSICS && couldPopVec)
    {
        sithCogVm_PushVector3(ctx, &thing->physicsParams.acceleration);
        rdVector_Copy3(&thing->physicsParams.acceleration, &poppedVec);
    }
}

void sithCogFunctionThing_GetThingThrust(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);

    if ( thing )
    {
        if ( thing->moveType == SITH_MT_PHYSICS )
            sithCogVm_PushVector3(ctx, &thing->physicsParams.acceleration);
    }
}

void sithCogFunctionThing_AmputateJoint(sithCog *ctx)
{
    uint32_t idx = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

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
    sithThing* weapTemplate = sithCogVm_PopTemplate(ctx);
    int weap_idx = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

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

void sithCogFunctionThing_GetActorWeapon(sithCog *ctx)
{
    int weap_idx = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

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
            sithCogVm_PushInt(ctx, -1);
            return;
        }

        if (weapTemplate)
        {
            sithCogVm_PushInt(ctx, weapTemplate->thingIdx);
            return;
        }

        sithCogVm_PushInt(ctx, -1);
        return;
    }
}

void sithCogFunctionThing_GetPhysicsFlags(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);
    if ( thing && thing->moveType == SITH_MT_PHYSICS )
        sithCogVm_PushInt(ctx, thing->physicsParams.physflags);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetPhysicsFlags(sithCog *ctx)
{
    int flags = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing && flags && thing->moveType == SITH_MT_PHYSICS)
    {
        thing->physicsParams.physflags |= flags;
        if (sithCogVm_multiplayerFlags 
            && !(ctx->flags & 0x200)
            && ctx->trigId != SITH_MESSAGE_STARTUP 
            && ctx->trigId != SITH_MESSAGE_SHUTDOWN)
        {
            sithThing_SyncThingPos(thing, 2);
        }
    }
}

void sithCogFunctionThing_ClearPhysicsFlags(sithCog *ctx)
{
    int flags = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing && flags && thing->moveType == SITH_MT_PHYSICS)
        thing->physicsParams.physflags &= ~flags;
}

void sithCogFunctionThing_SkillTarget(sithCog *ctx)
{
    sithCog *classCog;

    float param1 = sithCogVm_PopFlex(ctx);
    float param0 = sithCogVm_PopFlex(ctx);
    sithThing* otherThing = sithCogVm_PopThing(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

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
            sithCogVm_PushFlex(ctx, 0.0);
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
            sithCogVm_PushFlex(ctx, ret);
        }
    }
    else
    {
        sithCogVm_PushFlex(ctx, -1.0);
    }
}

void sithCogFunctionThing_ParseArg(sithCog *ctx)
{
    char* str = sithCogVm_PopString(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

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

    sithCogVm_PopVector3(ctx, &popped_vector3);
    sithThing* thing = sithCogVm_PopThing(ctx);
    if ( thing && thing->moveType == SITH_MT_PHYSICS)
    {
        rdVector_Copy3(&thing->physicsParams.angVel, &popped_vector3);
        if (sithCogVm_multiplayerFlags 
            && !(ctx->flags & 0x200)
            && ctx->trigId != SITH_MESSAGE_STARTUP 
            && ctx->trigId != SITH_MESSAGE_SHUTDOWN)
        {
            sithThing_SyncThingPos(thing, 1);
        }
    }
}

void sithCogFunctionThing_GetThingRotVel(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);
    if ( thing && thing->moveType == SITH_MT_PHYSICS )
        sithCogVm_PushVector3(ctx, &thing->physicsParams.angVel);
    else
        sithCogVm_PushVector3(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_SetThingLook(sithCog *ctx)
{
    rdVector3 popped_vector3;

    int pop_v3_retval = sithCogVm_PopVector3(ctx, &popped_vector3);
    sithThing* thing = sithCogVm_PopThing(ctx);

    if ( thing && pop_v3_retval == 1)
    {
        rdVector_Normalize3Acc(&popped_vector3);
        rdMatrix_BuildFromLook34(&thing->lookOrientation, &popped_vector3);

        if (sithCogVm_multiplayerFlags 
            && !(ctx->flags & 0x200)
            && ctx->trigId != SITH_MESSAGE_STARTUP 
            && ctx->trigId != SITH_MESSAGE_SHUTDOWN)
        {
            sithThing_SyncThingPos(thing, 1);
        }
    }
}

void sithCogFunctionThing_IsCrouching(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);
    if ( !thing || thing->moveType != SITH_MT_PHYSICS )
        sithCogVm_PushInt(ctx, -1);

    if (thing->physicsParams.physflags & PHYSFLAGS_CROUCHING)
        sithCogVm_PushInt(ctx, 1);
    else
        sithCogVm_PushInt(ctx, 0);
}

void sithCogFunctionThing_GetThingClassCog(sithCog *ctx)
{
    sithThing *thing; // eax
    sithCog *classCog; // eax

    thing = sithCogVm_PopThing(ctx);
    if ( thing && (classCog = thing->class_cog) != 0 )
        sithCogVm_PushInt(ctx, classCog->selfCog);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetThingClassCog(sithCog *ctx)
{
    sithCog *classCog; // edi
    sithThing *thing; // eax

    classCog = sithCogVm_PopCog(ctx);
    thing = sithCogVm_PopThing(ctx);
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

    thing = sithCogVm_PopThing(ctx);
    if ( thing && (captureCog = thing->capture_cog) != 0 )
        sithCogVm_PushInt(ctx, captureCog->selfCog);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetThingCaptureCog(sithCog *ctx)
{
    sithCog *captureCog; // edi
    sithThing *thing; // eax

    captureCog = sithCogVm_PopCog(ctx);
    thing = sithCogVm_PopThing(ctx);
    if ( thing )
    {
        if ( captureCog )
            thing->capture_cog = captureCog;
    }
}

void sithCogFunctionThing_GetThingRespawn(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);
    if (thing && thing->type == SITH_THING_ITEM)
    {
        sithCogVm_PushFlex(ctx, thing->itemParams.respawn);
    }
}

void sithCogFunctionThing_GetThingSignature(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);

    if ( thing )
        sithCogVm_PushInt(ctx, thing->signature);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetThingAttachFlags(sithCog *ctx)
{
    int flags = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

    if ( thing && flags)
    {
        thing->attach_flags |= flags;

        if (sithCogVm_multiplayerFlags 
            && !(ctx->flags & 0x200)
            && ctx->trigId != SITH_MESSAGE_STARTUP 
            && ctx->trigId != SITH_MESSAGE_SHUTDOWN)
        {
            sithDSSThing_SendSyncThingAttachment(thing, -1, 255, 1);
        }
    }
}

void sithCogFunctionThing_ClearThingAttachFlags(sithCog *ctx)
{
    int flags = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

    if ( thing && flags)
    {
        thing->attach_flags &= ~flags;

        if (sithCogVm_multiplayerFlags 
            && !(ctx->flags & 0x200)
            && ctx->trigId != SITH_MESSAGE_STARTUP 
            && ctx->trigId != SITH_MESSAGE_SHUTDOWN)
        {
            sithDSSThing_SendSyncThingAttachment(thing, -1, 255, 1);
        }
    }
}

void sithCogFunctionThing_GetParticleSize(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing && thing->type == SITH_THING_PARTICLE)
        sithCogVm_PushFlex(ctx, thing->particleParams.elementSize);
    else
        sithCogVm_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_SetParticleSize(sithCog *ctx)
{
    float size = sithCogVm_PopFlex(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing && thing->type == SITH_THING_PARTICLE)
    {
        thing->particleParams.elementSize = size;
    }
}

void sithCogFunctionThing_GetParticleGrowthSpeed(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);

    if ( thing && thing->type == SITH_THING_PARTICLE )
        sithCogVm_PushFlex(ctx, thing->particleParams.growthSpeed);
    else
        sithCogVm_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_SetParticleGrowthSpeed(sithCog *ctx)
{
    float speed = sithCogVm_PopFlex(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing && thing->type == SITH_THING_PARTICLE)
    {
        thing->particleParams.growthSpeed = speed;
    }
}

void sithCogFunctionThing_GetParticleTimeoutRate(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);

    if ( thing && thing->type == SITH_THING_PARTICLE )
        sithCogVm_PushFlex(ctx, thing->particleParams.rate);
    else
        sithCogVm_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_SetParticleTimeoutRate(sithCog *ctx)
{
    float rate = sithCogVm_PopFlex(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing && thing->type == SITH_THING_PARTICLE)
    {
        thing->particleParams.rate = rate;
    }
}

void sithCogFunctionThing_GetXFlags(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);
    if (thing)
    {
        switch ( thing->type )
        {
            case SITH_THING_ACTOR:
            case SITH_THING_ITEM:
            case SITH_THING_PLAYER:
                sithCogVm_PushInt(ctx, thing->actorParams.typeflags);
                return;
            case SITH_THING_WEAPON:
            case SITH_THING_PARTICLE:
                sithCogVm_PushInt(ctx, thing->weaponParams.typeflags);
                return;
            case SITH_THING_EXPLOSION:
                sithCogVm_PushInt(ctx, thing->explosionParams.typeflags);
                return;
        }
    }

    sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionThing_SetXFlags(sithCog *ctx)
{
    int flags = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

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

        if (sithCogVm_multiplayerFlags 
            && !(ctx->flags & 0x200)
            && ctx->trigId != SITH_MESSAGE_STARTUP 
            && ctx->trigId != SITH_MESSAGE_SHUTDOWN)
        {
            sithThing_SyncThingPos(thing, 2);
        }
    }
}

void sithCogFunctionThing_ClearXFlags(sithCog *ctx)
{
    int flags = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

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

        if (sithCogVm_multiplayerFlags 
            && !(ctx->flags & 0x200)
            && ctx->trigId != SITH_MESSAGE_STARTUP 
            && ctx->trigId != SITH_MESSAGE_SHUTDOWN)
        {
            sithThing_SyncThingPos(thing, 2);
        }
    }
}

void sithCogFunctionThing_TakeItem(sithCog *ctx)
{
    sithThing* player = sithCogVm_PopThing(ctx);
    sithThing* itemThing = sithCogVm_PopThing(ctx);
    if ( itemThing && player && itemThing->type == SITH_THING_ITEM )
        sithItem_Take(itemThing, player, 0);
}

void sithCogFunctionThing_HasLos(sithCog *ctx)
{
    sithThing* thingB = sithCogVm_PopThing(ctx);
    sithThing* thingA = sithCogVm_PopThing(ctx);

    if ( thingA && thingB )
    {
        if (sithCollision_HasLos(thingA, thingB, 0))
            sithCogVm_PushInt(ctx, 1);
        else
            sithCogVm_PushInt(ctx, 0);
    }
    else
    {
        sithCogVm_PushInt(ctx, -1);
    }
}

void sithCogFunctionThing_GetThingFireOffset(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing)
        sithCogVm_PushVector3(ctx, &thing->actorParams.fireOffset);
    else
        sithCogVm_PushVector3(ctx, (rdVector3*)&rdroid_zeroVector3);
}

void sithCogFunctionThing_SetThingFireOffset(sithCog *ctx)
{
    rdVector3 poppedVec;

    sithCogVm_PopVector3(ctx, &poppedVec);
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing)
    {
        rdVector_Copy3(&thing->actorParams.fireOffset, &poppedVec);
    }
}

void sithCogFunctionThing_GetThingUserdata(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing)
        sithCogVm_PushFlex(ctx, thing->userdata);
    else
        sithCogVm_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_SetThingUserdata(sithCog *ctx)
{
    float userdata = sithCogVm_PopFlex(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing)
        thing->userdata = userdata;
}

void sithCogFunctionThing_GetThingCollideSize(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing)
        sithCogVm_PushFlex(ctx, thing->collideSize);
    else
        sithCogVm_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_SetThingCollideSize(sithCog *ctx)
{
    float size = sithCogVm_PopFlex(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing)
        thing->collideSize = size;
}

void sithCogFunctionThing_GetThingMoveSize(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing)
        sithCogVm_PushFlex(ctx, thing->moveSize);
    else
        sithCogVm_PushFlex(ctx, -1.0);
}

void sithCogFunctionThing_SetThingMoveSize(sithCog *ctx)
{
    float moveSize = sithCogVm_PopFlex(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing)
        thing->moveSize = moveSize;
}

void sithCogFunctionThing_GetThingMass(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);
    if (thing)
    {
        if (thing->moveType == SITH_MT_PHYSICS)
            sithCogVm_PushFlex(ctx, thing->physicsParams.mass);
        else
            sithCogVm_PushFlex(ctx, 0.0);
    }
}

void sithCogFunctionThing_SetThingMass(sithCog *ctx)
{
    float mass = sithCogVm_PopFlex(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing && thing->moveType == SITH_MT_PHYSICS)
    {
        thing->physicsParams.mass = mass;
        if (sithCogVm_multiplayerFlags 
            && !(ctx->flags & 0x200)
            && ctx->trigId != SITH_MESSAGE_STARTUP 
            && ctx->trigId != SITH_MESSAGE_SHUTDOWN)
        {
            sithThing_SyncThingPos(thing, 2);
        }
    }
}

void sithCogFunctionThing_SyncThingPos(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing)
        sithThing_SyncThingPos(thing, 1);
}

void sithCogFunctionThing_SyncThingAttachment(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing)
        sithDSSThing_SendSyncThingAttachment(thing, -1, 255, 0);
}

void sithCogFunctionThing_SyncThingState(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing)
        sithThing_SyncThingPos(thing, 2);
}

void sithCogFunctionThing_GetMajorMode(sithCog *ctx)
{
    sithThing* thing = sithCogVm_PopThing(ctx);

    if (thing && thing->animclass && thing->rdthing.puppet)
        sithCogVm_PushInt(ctx, thing->puppet->majorMode);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionThing_Initialize(void* ctx)
{
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_WaitForStop, "waitforstop");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_StopThing, "stopthing");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_DestroyThing, "destroything");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetThingHealth, "getthinghealth");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetThingHealth, "gethealth");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_HealThing, "healthing");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetThingLight, "getthinglight");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetThingLight, "setthinglight");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetThingLight, "thinglight");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_ThingLightAnim, "thinglightanim");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_Rotate, "rotate");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_CreateThing, "creatething");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_CreateThingNr, "createthingnr");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_CreateThingAtPos, "createthingatpos");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_CreateThingAtPosNr, "createthingatposnr");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_RotatePivot, "rotatepivot");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_CaptureThing, "capturething");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_ReleaseThing, "releasething");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetThingVel, "setthingvel");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_AddThingVel, "addthingvel");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_ApplyForce, "applyforce");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_DetachThing, "detachthing");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetAttachFlags, "getattachflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetAttachFlags, "getthingattachflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_AttachThingToSurf, "attachthingtosurf");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_AttachThingToThing, "attachthingtothing");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetArmedMode, "setarmedmode");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetThingFlags, "setthingflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_ClearThingFlags, "clearthingflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_TeleportThing, "teleportthing");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetThingType, "setthingtype");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetCollideType, "setcollidetype");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetHeadlightIntensity, "setheadlightintensity");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetThingGeoMode, "getthinggeomode");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetThingGeoMode, "setthinggeomode");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetThingLightMode, "getthinglightmode");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetThingLightMode, "setthinglightmode");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetThingTexMode, "getthingtexmode");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetThingTexMode, "setthingtexmode");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetThingCurGeoMode, "getthingcurgeomode");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetThingCurGeoMode, "setthingcurgeomode");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetThingCurLightMode, "getthingcurlightmode");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetThingCurLightMode, "setthingcurlightmode");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetThingCurTexMode, "getthingcurtexmode");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetThingCurTexMode, "setthingcurtexmode");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetActorExtraSpeed, "setactorextraspeed");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetThingType, "getthingtype");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_IsMoving, "isthingmoving");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_IsMoving, "ismoving");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetCurFrame, "getcurframe");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetGoalFrame, "getgoalframe");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetThingParent, "getthingparent");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetThingSector, "getthingsector");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetThingPos, "getthingpos");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetThingPos, "setthingpos");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetThingVel, "getthingvel");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetThingUvec, "getthinguvec");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetThingLvec, "getthinglvec");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetThingRvec, "getthingrvec");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetThingFlags, "getthingflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetCollideType, "getcollidetype");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetHeadlightIntensity, "getheadlightintensity");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_IsThingVisible, "isthingvisible");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetThingPulse, "setthingpulse");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetThingTimer, "setthingtimer");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetInv, "getinv");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetInv, "setinv");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_ChangeInv, "changeinv");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetInvCog, "getinvcog");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetInvMin, "getinvmin");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetInvMax, "getinvmax");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetCurInvWeapon, "getcurinvweapon");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetCurInvWeapon, "setcurinvweapon");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_PlayKey, "playkey");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_StopKey, "stopkey");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetThingModel, "setthingmodel");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetThingModel, "getthingmodel");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_PlayMode, "playmode");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetMajorMode, "getmajormode");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_FirstThingInSector, "firstthinginsector");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_NextThingInSector, "nextthinginsector");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_PrevThingInSector, "prevthinginsector");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_MoveToFrame, "movetoframe");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SkipToFrame, "skiptoframe");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_JumpToFrame, "jumptoframe");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_PathMovePause, "pathmovepause");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_PathMoveResume, "pathmoveresume");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetThingTemplate, "getthingtemplate");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_DamageThing, "damagething");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetLifeLeft, "setlifeleft");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetLifeLeft, "getlifeleft");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetThingThrust, "setthingthrust");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetThingThrust, "getthingthrust");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetHealth, "setthinghealth");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetHealth, "sethealth");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_AmputateJoint, "amputatejoint");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetActorWeapon, "setactorweapon");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetActorWeapon, "getactorweapon");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetPhysicsFlags, "getphysicsflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetPhysicsFlags, "setphysicsflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_ClearPhysicsFlags, "clearphysicsflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SkillTarget, "skilltarget");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_ParseArg, "parsearg");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetThingRotVel, "getthingrotvel");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetThingRotVel, "setthingrotvel");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetThingLook, "setthinglook");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_IsCrouching, "isthingcrouching");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_IsCrouching, "iscrouching");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetThingClassCog, "getthingclasscog");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetThingClassCog, "setthingclasscog");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetThingCaptureCog, "getthingcapturecog");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetThingCaptureCog, "setthingcapturecog");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetThingRespawn, "getthingrespawn");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetThingSignature, "getthingsignature");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetThingAttachFlags, "setthingattachflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_ClearThingAttachFlags, "clearthingattachflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetParticleSize, "getparticlesize");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetParticleSize, "setparticlesize");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetParticleGrowthSpeed, "getparticlegrowthspeed");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetParticleGrowthSpeed, "setparticlegrowthspeed");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetParticleTimeoutRate, "getparticletimeoutrate");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetParticleTimeoutRate, "setparticletimeoutrate");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetXFlags, "gettypeflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetXFlags, "settypeflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_ClearXFlags, "cleartypeflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetXFlags, "getactorflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetXFlags, "setactorflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_ClearXFlags, "clearactorflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetXFlags, "getweaponflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetXFlags, "setweaponflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_ClearXFlags, "clearweaponflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetXFlags, "getexplosionflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetXFlags, "setexplosionflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_ClearXFlags, "clearexplosionflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetXFlags, "getitemflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetXFlags, "setitemflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_ClearXFlags, "clearitemflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetXFlags, "getparticleflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetXFlags, "setparticleflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_ClearXFlags, "clearparticleflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_TakeItem, "takeitem");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_HasLos, "haslos");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetThingFireOffset, "getthingfireoffset");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetThingFireOffset, "setthingfireoffset");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetThingUserdata, "getthinguserdata");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetThingUserdata, "setthinguserdata");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetThingCollideSize, "getthingcollidesize");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetThingCollideSize, "setthingcollidesize");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetThingMoveSize, "getthingmovesize");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetThingMoveSize, "setthingmovesize");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_GetThingMass, "getthingmass");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SetThingMass, "setthingmass");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SyncThingPos, "syncthingpos");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SyncThingAttachment, "syncthingattachment");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_SyncThingState, "syncthingstate");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogFunctionThing_AttachThingToThingEx, "attachthingtothingex");
}
