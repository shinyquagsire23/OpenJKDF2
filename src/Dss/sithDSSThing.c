#include "sithDSSThing.h"

#include "Cog/sithCog.h"
#include "Engine/sithSoundClass.h"
#include "Engine/sithSoundSys.h"
#include "Engine/sithSurface.h"
#include "Engine/sithSound.h"
#include "World/sithThing.h"
#include "World/sithSector.h"
#include "World/sithUnk4.h"

// Teleport

void sithDSSThing_SendTeleportThing(sithThing *pThing, int sendto_id, int bSync)
{
    rdVector3 lookOrientation; // [esp+4h] [ebp-Ch] BYREF

    NETMSG_START;

    if ( pThing && pThing->thingtype && pThing->sector)
    {
        sithSector* pSector = pThing->sector;
        NETMSG_PUSHS32(pThing->thing_id);
        NETMSG_PUSHU16(pThing->attach_flags);
        NETMSG_PUSHS16(pSector->id);
        NETMSG_PUSHVEC3(pThing->position);
        rdMatrix_ExtractAngles34(&pThing->lookOrientation, &lookOrientation);
        NETMSG_PUSHF32(lookOrientation.x);
        NETMSG_PUSHF32(lookOrientation.y);
        NETMSG_PUSHF32(lookOrientation.z);

        if ( pThing->moveType == SITH_MT_PHYSICS )
        {
            NETMSG_PUSHU32(pThing->physicsParams.physflags);
            NETMSG_PUSHVEC3(pThing->physicsParams.vel);
            if ( !pThing->attach_flags )
            {
                NETMSG_PUSHVEC3(pThing->physicsParams.angVel);
            }
        }
        if ( pThing->thingtype == SITH_THING_PLAYER )
            NETMSG_PUSHF32(pThing->actorParams.eyePYR.x);

        NETMSG_END(COGMSG_TELEPORTTHING);

        sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, 255, bSync);
    }
}

int sithDSSThing_HandleTeleportThing(sithCogMsg *msg)
{
    rdVector3 lookTmp; // [esp+10h] [ebp-18h] BYREF
    rdVector3 pos; // [esp+1Ch] [ebp-Ch] BYREF

    if ( !sithWorld_pCurrentWorld )
        return 0;

    NETMSG_IN_START(msg);

    int thing_id = NETMSG_POPS32();

    sithThing* pThing = sithThing_GetById(thing_id);
    if ( !pThing || pThing->thingtype == SITH_THING_FREE || !pThing->sector )
        return 0;
    uint16_t attach_flags = NETMSG_POPU16();
    if ( !attach_flags && pThing->attach_flags )
        sithThing_DetachThing(pThing);

    // TODO attach flags not set??

    int16_t sectorIdx = NETMSG_POPS16();
    sithSector* pSector = sithSector_GetPtrFromIdx(sectorIdx);
    if ( !pSector )
        return 0;

    pos = NETMSG_POPVEC3();
    lookTmp = NETMSG_POPVEC3();

    rdMatrix_BuildRotate34(&pThing->lookOrientation, &lookTmp);
    if ( pThing->moveType == SITH_MT_PHYSICS )
    {
        pThing->physicsParams.physflags = NETMSG_POPU32();

        pThing->physicsParams.vel = NETMSG_POPVEC3();
        if ( attach_flags )
        {
            rdVector_Zero3(&pThing->physicsParams.angVel);
        }
        else
        {
            pThing->physicsParams.angVel = NETMSG_POPVEC3();
        }
        sithDSSThing_TransitionMovingThing(pThing, &pos, pSector);
    }
    else
    {
        pThing->position = pos;
        sithThing_MoveToSector(pThing, pSector, 0);
    }
    if ( pThing->thingtype == SITH_THING_PLAYER )
    {
        rdVector_Zero3(&lookTmp);
        lookTmp.x = NETMSG_POPF32();
        sithUnk4_MoveJointsForEyePYR(pThing, &lookTmp);
    }
    return 1;
}

// SyncThing

void sithDSSThing_SendPlaySoundPos(sithThing *followThing, rdVector3 *pos, sithSound *sound, float volume, float a5, int flags, int refid, int sendto_id, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHU32(flags);
    NETMSG_PUSHF32(volume);
    NETMSG_PUSHF32(a5);
    NETMSG_PUSHU16(sound->id);
    if ( (flags & SITHSOUNDFLAG_FOLLOWSTHING) == 0 )
    {
        if ( (flags & SITHSOUNDFLAG_ABSOLUTE) != 0 )
        {
            NETMSG_PUSHVEC3(*pos);
        }
    }
    else
    {
        NETMSG_PUSHS32(followThing->thing_id);
    }
    NETMSG_PUSHU32(refid);
    
    NETMSG_END(COGMSG_PLAYSOUNDPOS);
    
    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, mpFlags, 0);
}

int sithDSSThing_HandlePlaySoundPos(sithCogMsg *msg)
{
    sithPlayingSound* out = NULL;

    NETMSG_IN_START(msg);

    int flags = NETMSG_POPU32();
    float volume = NETMSG_POPF32();
    float a5 = NETMSG_POPF32();
    int16_t soundIdx = NETMSG_POPS16();
    sithSound* sound = sithSound_GetFromIdx(soundIdx);

    if (!sound)
        return 0;

    if ( (flags & SITHSOUNDFLAG_FOLLOWSTHING) == 0 )
    {
        if ( (flags & SITHSOUNDFLAG_ABSOLUTE) != 0 )
        {
            rdVector3 pos = NETMSG_POPVEC3();
            out = sithSoundSys_PlaySoundPosAbsolute(sound, &pos, 0, 1.0, volume, a5, flags);
        }
        else
        {
            out = sithSoundSys_cog_playsound_internal(sound, volume, a5, flags);
        }
    }
    else
    {
        sithThing* thing = sithThing_GetById(NETMSG_POPS32());
        if ( !thing )
            return 0;
        out = sithSoundSys_PlaySoundPosThing(sound, thing, 1.0, volume, a5, flags);
    }

    if ( out )
        out->refid = NETMSG_POPU32();

    return 1;
}

void sithDSSThing_SendSyncThingFull(sithThing *thing, int sendto_id, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHS16(thing->thingIdx);
    NETMSG_PUSHS16(thing->type);
    if ( thing->type )
    {
        NETMSG_PUSHS16(thing->templateBase->thingIdx);
        NETMSG_PUSHS32(thing->signature);
        NETMSG_PUSHS32(thing->thing_id);
        NETMSG_PUSHVEC3(thing->position);
        NETMSG_PUSHVEC3(thing->lookOrientation.rvec);
        NETMSG_PUSHVEC3(thing->lookOrientation.lvec);
        NETMSG_PUSHVEC3(thing->lookOrientation.uvec);
        if ( thing->sector ) {
            NETMSG_PUSHS16(thing->sector->id);
        }
        else {
            NETMSG_PUSHS16(-1);
        }
        NETMSG_PUSHU32(thing->thingflags);
        NETMSG_PUSHS32(thing->lifeLeftMs);
        NETMSG_PUSHS32(thing->timer);
        NETMSG_PUSHS32(thing->pulse_end_ms);
        NETMSG_PUSHS32(thing->pulse_ms);
        NETMSG_PUSHF32(thing->userdata);
        NETMSG_PUSHU8(thing->rdthing.geometryMode);
        NETMSG_PUSHS16(thing->collide);
        NETMSG_PUSHF32(thing->collideSize);
        NETMSG_PUSHF32(thing->light);
        NETMSG_PUSHU32(thing->jkFlags);
        if ( (thing->thingflags & SITH_TF_CAPTURED) != 0 )
        {
            if ( thing->class_cog ) {
                NETMSG_PUSHS16(thing->class_cog->selfCog);
            }
            else {
                NETMSG_PUSHS16(-1);
            }
            if ( thing->capture_cog ) {
                NETMSG_PUSHS16(thing->capture_cog->selfCog);
            }
            else {
                NETMSG_PUSHS16(-1);
            }
        }
        switch ( thing->type )
        {
            case SITH_THING_ACTOR:
            case SITH_THING_CORPSE:
            case SITH_THING_PLAYER:
                NETMSG_PUSHU32(thing->actorParams.typeflags);
                NETMSG_PUSHF32(thing->actorParams.health);
                NETMSG_PUSHF32(thing->actorParams.extraSpeed);
                NETMSG_PUSHVEC3(thing->actorParams.eyePYR);
                
                NETMSG_PUSHF32(thing->actorParams.timeLeftLengthChange);
                NETMSG_PUSHF32(thing->actorParams.lightIntensity);
                NETMSG_PUSHS32(thing->actorParams.field_1BC);
                if ( thing->actorParams.playerinfo )
                {
                    NETMSG_PUSHS32(thing->actorParams.playerinfo - jkPlayer_playerInfos);
                    NETMSG_PUSHS32(thing->actorParams.playerinfo->palEffectsIdx1);
                    NETMSG_PUSHS32(thing->actorParams.playerinfo->palEffectsIdx2);
                }
                else
                {
                    NETMSG_PUSHS32(-1);
                }
                break;
            case SITH_THING_WEAPON:
                NETMSG_PUSHU32(thing->weaponParams.typeflags);
                NETMSG_PUSHF32(thing->weaponParams.unk8);
                NETMSG_PUSHS16(thing->weaponParams.field_18);
                break;
            case SITH_THING_EXPLOSION:
                NETMSG_PUSHU32(thing->explosionParams.typeflags);
                break;
            default:
                break;
        }
        if ( thing->moveType == SITH_MT_PHYSICS )
        {
            NETMSG_PUSHU32(thing->physicsParams.physflags);
            NETMSG_PUSHVEC3(thing->physicsParams.vel);
            NETMSG_PUSHVEC3(thing->physicsParams.angVel);
        }
        else if ( thing->moveType == SITH_MT_PATH )
        {
            NETMSG_PUSHS16(thing->trackParams.field_C);
            NETMSG_PUSHVEC3(thing->trackParams.vel);
            NETMSG_PUSHF32(thing->trackParams.field_1C);
            NETMSG_PUSHF32(thing->trackParams.field_20);
            NETMSG_PUSHF32(thing->trackParams.field_54);
            NETMSG_PUSHVEC3(thing->trackParams.field_58);
            NETMSG_PUSHVEC3(thing->trackParams.field_64);
            NETMSG_PUSHF32(thing->field_24C);
            NETMSG_PUSHS16(thing->field_250);
            NETMSG_PUSHS16(thing->curframe);
            NETMSG_PUSHS16(thing->field_258);
            NETMSG_PUSHS16(thing->goalframe);
            NETMSG_PUSHMAT34(thing->trackParams.field_24);
            NETMSG_PUSHVEC3(thing->trackParams.orientation);
            NETMSG_PUSHS16(thing->trackParams.loadedFrames);

            for (int i = 0; i < thing->trackParams.loadedFrames; i++)
            {
                NETMSG_PUSHVEC3(thing->trackParams.frames[i].pos);
                NETMSG_PUSHVEC3(thing->trackParams.frames[i].rot);
            }
        }
    }
    
    NETMSG_END(COGMSG_SYNCTHINGFULL);

    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, mpFlags, 1);
}

int sithDSSThing_HandleSyncThingFull(sithCogMsg *msg)
{
    int16_t thingIdx; // ebp
    int32_t v8; // ecx
    sithThing* thing;
    sithSector* v11;
    int type;


    NETMSG_IN_START(msg);

    if ( sithNet_isMulti && (g_submodeFlags & 8) == 0 )
        return 0;

    thingIdx = NETMSG_POPS16();
    if ( thingIdx >= sithWorld_pCurrentWorld->numThingsLoaded )
        return 0;

    if ( sithWorld_pCurrentWorld->things[thingIdx].type )
        sithThing_FreeEverythingNet(&sithWorld_pCurrentWorld->things[thingIdx]);

    if ( sithWorld_pCurrentWorld->numThings > thingIdx )
        thingIdx = sithWorld_pCurrentWorld->numThings;

    sithWorld_pCurrentWorld->numThings = thingIdx;

    type = NETMSG_POPS16();
    if ( !type )
        return 1;

    thing = &sithWorld_pCurrentWorld->things[thingIdx];
    sithThing_DoesRdThingInit(thing);
    v8 = NETMSG_POPS16();

    if ( v8 >= sithWorld_pCurrentWorld->numTemplatesLoaded )
        return 0;

    sithThing_sub_4CD8A0(thing, &sithWorld_pCurrentWorld->templates[v8]);

    thing->signature = NETMSG_POPS32();
    thing->thing_id = NETMSG_POPS32();
    thing->type = type;
    thing->thingtype = type; // Added: why is this needed?
    thing->position = NETMSG_POPVEC3();
    thing->lookOrientation.rvec = NETMSG_POPVEC3();
    thing->lookOrientation.lvec = NETMSG_POPVEC3();
    thing->lookOrientation.uvec = NETMSG_POPVEC3();
    int sectorIdx = NETMSG_POPS16();
    v11 = sithSector_GetPtrFromIdx(sectorIdx);
    if ( v11 )
        sithThing_MoveToSector(thing, v11, 1);

    thing->thingflags = NETMSG_POPU32();
    thing->lifeLeftMs = NETMSG_POPS32();
    thing->timer = NETMSG_POPS32();
    thing->pulse_end_ms = NETMSG_POPS32();
    thing->pulse_ms = NETMSG_POPS32();
    thing->userdata = NETMSG_POPF32();
    thing->rdthing.geometryMode = NETMSG_POPU8();
    thing->collide = NETMSG_POPS16();
    thing->collideSize = NETMSG_POPF32();
    thing->light = NETMSG_POPF32();
    thing->jkFlags = NETMSG_POPU32();

    if ( thing->thingflags & SITH_TF_CAPTURED )
    {
        thing->class_cog = sithCog_GetByIdx(NETMSG_POPS16());
        thing->capture_cog = sithCog_GetByIdx(NETMSG_POPS16());
    }
    switch ( thing->type )
    {
        case SITH_THING_ACTOR:
        case SITH_THING_CORPSE:
        case SITH_THING_PLAYER:
            thing->actorParams.typeflags = NETMSG_POPU32();
            thing->actorParams.health = NETMSG_POPF32();
            thing->actorParams.extraSpeed = NETMSG_POPF32();
            thing->actorParams.eyePYR = NETMSG_POPVEC3();
            
            thing->actorParams.timeLeftLengthChange = NETMSG_POPF32();
            thing->actorParams.lightIntensity = NETMSG_POPF32();
            thing->actorParams.field_1BC = NETMSG_POPS32();
            
            int playerInfo_idx = NETMSG_POPS32();
            
            if ( playerInfo_idx >= 0 && playerInfo_idx < 32 )
            {
                thing->actorParams.playerinfo = &jkPlayer_playerInfos[playerInfo_idx];
                thing->actorParams.playerinfo->palEffectsIdx1 = NETMSG_POPS32();
                thing->actorParams.playerinfo->palEffectsIdx2 = NETMSG_POPS32();
            }
            break;
        case SITH_THING_WEAPON:
            thing->weaponParams.typeflags = NETMSG_POPU32();
            thing->weaponParams.unk8 = NETMSG_POPF32();
            thing->weaponParams.field_18 = NETMSG_POPS16();
            break;
        case SITH_THING_EXPLOSION:
            thing->explosionParams.typeflags = NETMSG_POPU32();
            break;
        default:
            break;
    }
    if ( thing->moveType == SITH_MT_PHYSICS )
    {
        thing->physicsParams.physflags = NETMSG_POPU32();
        thing->physicsParams.vel = NETMSG_POPVEC3();
        thing->physicsParams.angVel = NETMSG_POPVEC3();
    }
    else if ( thing->moveType == SITH_MT_PATH )
    {
        thing->trackParams.field_C = NETMSG_POPS16();
        thing->trackParams.vel = NETMSG_POPVEC3();
        thing->trackParams.field_1C = NETMSG_POPF32();
        thing->trackParams.field_20 = NETMSG_POPF32();
        thing->trackParams.field_54 = NETMSG_POPF32();
        thing->trackParams.field_58 = NETMSG_POPVEC3();
        thing->trackParams.field_64 = NETMSG_POPVEC3();
        thing->field_24C = NETMSG_POPF32();
        thing->field_250 = NETMSG_POPS16();
        thing->curframe = NETMSG_POPS16();
        thing->field_258 = NETMSG_POPS16();
        thing->goalframe = NETMSG_POPS16();
        thing->trackParams.field_24 = NETMSG_POPMAT34();
        thing->trackParams.orientation = NETMSG_POPVEC3();
        thing->trackParams.loadedFrames = NETMSG_POPS16();

        if ( thing->trackParams.loadedFrames )
        {
            // TODO: verify this doesn't leak memory
            thing->trackParams.numFrames = thing->trackParams.loadedFrames;
            thing->trackParams.frames = pSithHS->alloc(sizeof(sithThingFrame) * thing->trackParams.numFrames);
        }

        for (int i = 0; i < thing->trackParams.loadedFrames; i++)
        {
            thing->trackParams.frames[i].pos = NETMSG_POPVEC3();
            thing->trackParams.frames[i].rot = NETMSG_POPVEC3();
        }
    }
    sithThing_sub_4CD100(thing);
    return 1;
}

void sithDSSThing_SendSyncThingAttachment(sithThing *thing, int sendto_id, int mpFlags, int a4)
{
    NETMSG_START;
    
    NETMSG_PUSHS32(thing->thing_id);
    NETMSG_PUSHU16(thing->attach_flags);

    if (thing->attach_flags & ATTACHFLAGS_WORLDSURFACE)
    {
        NETMSG_PUSHU16(thing->attachedSurface->field_0);
    }
    else if (thing->attach_flags & (ATTACHFLAGS_THING|ATTACHFLAGS_THINGSURFACE))
    {
        sithThing* v7 = (sithThing *)thing->attachedThing;
        NETMSG_PUSHS32(v7->thing_id)
        if ( (thing->attach_flags & ATTACHFLAGS_THINGSURFACE) != 0 )
        {
            NETMSG_PUSHS16(((intptr_t)thing->attachedSufaceInfo - (intptr_t)v7->rdthing.model3->geosets[0].meshes->faces) / sizeof(sithSurfaceInfo));
        }
        else
        {
           NETMSG_PUSHVEC3(thing->field_4C);
        }
    }
    
    NETMSG_END(COGMSG_SYNCTHINGATTACHMENT);
    
    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, mpFlags, a4);
}

int sithDSSThing_HandleSyncThingAttachment(sithCogMsg *msg)
{    
    NETMSG_IN_START(msg);

    sithThing* v1 = sithThing_GetById(NETMSG_POPS32());
    if ( !v1 )
        return 0;
    int v3 = NETMSG_POPS16();
    if (v3 & ATTACHFLAGS_WORLDSURFACE)
    {
        sithSurface* v5 = sithSurface_sub_4E63B0(NETMSG_POPS16());
        if ( v5 )
        {
            sithThing_AttachToSurface(v1, v5, 1);
            v1->attach_flags = v3;
            return 1;
        }
        return 0;
    }
    if (v3 & (ATTACHFLAGS_THING|ATTACHFLAGS_THINGSURFACE))
    {
        sithThing* v9 = sithThing_GetById(NETMSG_POPS32());
        if ( !v9 )
            return 0;
        if (v3 & ATTACHFLAGS_THINGSURFACE)
        {
            sithThing_LandThing(
                v1,
                v9,
                &v9->rdthing.model3->geosets[0].meshes->faces[NETMSG_POPS16()],
                v9->rdthing.model3->geosets[0].meshes->vertices,
                1);
            v1->attach_flags = v3;
            return 1;
        }
        else
        {
            sithThing_AttachThing(v1, v9);
            v1->attach_flags = v3;
            v1->field_4C = NETMSG_POPVEC3();
            return 1;
        }
    }
    else
    {
        if ( v1->attach_flags )
            sithThing_DetachThing(v1);
        return 1;
    }
    return 0;
}

void sithDSSThing_SendDeath(sithThing *sender, sithThing *receiver, char cause, int sendto_id, int mpFlags)
{
    NETMSG_START;
    
    NETMSG_PUSHS32(sender->thing_id);
    if ( receiver ) {
        NETMSG_PUSHS32(receiver->thing_id);
    }
    else {
        NETMSG_PUSHS32(-1);
    }
    NETMSG_PUSHU8(cause);
    
    NETMSG_END(COGMSG_DEATH);
    
    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, mpFlags, 1);
}

void sithDSSThing_TransitionMovingThing(sithThing *pThing, rdVector3 *pPos, sithSector *pSector)
{
    rdVector3 a1; // [esp+8h] [ebp-Ch] BYREF

    rdVector_Scale3(&a1, &pThing->physicsParams.vel, 0.25);
    rdVector_Add3Acc(&a1, pPos);
    rdVector_Sub3Acc(&a1, &pThing->position);
    float v5 = rdVector_Len3(&a1);
    if ( v5 == 0.0 || v5 >= 0.5 )
    {
        rdVector_Copy3(&pThing->position, pPos);
        sithThing_MoveToSector(pThing, pSector, 0);
    }
    else
    {
        rdVector_Scale3(&pThing->physicsParams.vel, &a1, 4.0);
    }
}