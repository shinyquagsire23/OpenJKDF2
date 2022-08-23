#include "sithDSSThing.h"

#include "Cog/sithCog.h"
#include "Engine/sithSoundClass.h"
#include "Engine/sithSoundSys.h"
#include "Engine/sithSurface.h"
#include "Engine/sithSound.h"
#include "Engine/sithKeyFrame.h"
#include "World/sithThing.h"
#include "World/sithSector.h"
#include "World/sithUnk4.h"
#include "Engine/sithPuppet.h"
#include "Engine/sithModel.h"
#include "Engine/sithTemplate.h"
#include "World/sithItem.h"
#include "World/sithWeapon.h"
#include "World/sithTrackThing.h"
#include "jk.h"

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

void sithDSSThing_SendSyncThing(sithThing *pThing, int sendto_id, int mpFlags)
{
    NETMSG_START;

    if (!pThing || !pThing->thingtype || !pThing->sector || !sithThing_GetIdxFromThing(pThing) )
        return;

    NETMSG_PUSHS32(pThing->thing_id);
    NETMSG_PUSHS32(pThing->jkFlags);
    NETMSG_PUSHS32(pThing->lifeLeftMs);
    NETMSG_PUSHS16(pThing->sector->id);
    NETMSG_PUSHS16(pThing->collide);
    NETMSG_PUSHVEC3(pThing->position);
    NETMSG_PUSHS32(pThing->thingflags);
    NETMSG_PUSHS32(pThing->rdthing.geometryMode);

    if ( pThing->animclass )
    {
        NETMSG_PUSHS16(pThing->puppet->field_0);
        NETMSG_PUSHS16(pThing->puppet->field_4);
    }
    NETMSG_PUSHS32(pThing->light);
    switch ( pThing->thingtype )
    {
        case SITH_THING_ACTOR:
        case SITH_THING_CORPSE:
        case SITH_THING_PLAYER:
            NETMSG_PUSHS32(pThing->actorParams.typeflags);
            break;
        case SITH_THING_WEAPON:
            NETMSG_PUSHS32(pThing->weaponParams.typeflags);
            break;
        case SITH_THING_ITEM:
            NETMSG_PUSHS32(pThing->itemParams.typeflags);
            if (pThing->itemParams.typeflags & ITEMSTATE_AVAILABLE)
            {
                NETMSG_PUSHS16(pThing->itemParams.numBins);
                for (int i = 0; i < pThing->itemParams.numBins; i++)
                {
                    NETMSG_PUSHS16(pThing->itemParams.contents[i].binIdx);
                    NETMSG_PUSHF32(pThing->itemParams.contents[i].value);
                }
            }
            break;
        default:
            break;
    }
    if ( pThing->moveType == SITH_MT_PHYSICS )
        NETMSG_PUSHS32(pThing->physicsParams.physflags);

    NETMSG_END(COGMSG_SYNCTHING);

    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, mpFlags, 1);
}

int sithDSSThing_HandleSyncThing(sithCogMsg *msg)
{
    NETMSG_IN_START(msg);

    sithThing* pThing = sithThing_GetById(msg->pktData[0]);
    if ( !pThing )
        return 0;
    if ( pThing->thingtype == SITH_THING_FREE )
        return 0;
    if ( !pThing->sector )
        return 0;
    pThing->jkFlags = NETMSG_POPS32();
    pThing->lifeLeftMs = NETMSG_POPS32();
    sithSector* pSector = sithSector_GetPtrFromIdx(NETMSG_POPS16());
    if ( !pSector )
        return 0;
    pThing->collide = NETMSG_POPS16();
    pThing->position = NETMSG_POPVEC3();
    sithThing_MoveToSector(pThing, pSector, 0);

    uint32_t thingflags = NETMSG_POPS32();
    if ( pThing->thingtype == SITH_THING_PLAYER && (pThing->thingflags & SITH_TF_DEAD) && !(thingflags & SITH_TF_DEAD))
        sithPlayer_debug_loadauto(pThing);
    
    // Lol, anticheat?
    if ( (pThing->thingflags & SITH_TF_INVULN) != 0 )
        thingflags |= SITH_TF_INVULN;
    else
        thingflags &= ~SITH_TF_INVULN;

    sithAnimclass* pAnimclass = pThing->animclass;
    pThing->thingflags = thingflags;
    pThing->rdthing.geometryMode = NETMSG_POPS32();
    if ( pAnimclass )
    {
        sithPuppet_SetArmedMode(pThing, NETMSG_POPS16());
        sithPuppet_sub_4E4760(pThing, NETMSG_POPS16());
    }

    pThing->light = NETMSG_POPF32();

    switch ( pThing->thingtype )
    {
        case SITH_THING_ACTOR:
        case SITH_THING_CORPSE:
        case SITH_THING_PLAYER:
            pThing->actorParams.typeflags = NETMSG_POPS32();
            break;
        case SITH_THING_WEAPON:
            pThing->weaponParams.typeflags = NETMSG_POPS32();
            break;
        case SITH_THING_ITEM:
            pThing->itemParams.typeflags = NETMSG_POPS32();
            if (pThing->itemParams.typeflags & ITEMSTATE_AVAILABLE)
            {
                pThing->itemParams.numBins = NETMSG_POPS16();
                for (int i = 0; i < pThing->itemParams.numBins; i++)
                {
                    pThing->itemParams.contents[i].binIdx = NETMSG_POPS16();
                    pThing->itemParams.contents[i].value = NETMSG_POPF32();
                }
            }
            break;
        default:
            break;
    }

    if ( pThing->moveType == SITH_MT_PHYSICS )
        pThing->physicsParams.physflags = NETMSG_POPS32();

    return 1;
}

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

void sithDSSThing_SoundClassPlay(sithThing *pThing, int16_t a2, int a3, float a4)
{
    NETMSG_START;

    NETMSG_PUSHS32(pThing->thing_id);
    NETMSG_PUSHS32(a3);
    NETMSG_PUSHF32(a4);
    NETMSG_PUSHS16(a2);

    NETMSG_END(COGMSG_SOUNDCLASSPLAY);

    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, -1, 255, 0);
}

int sithDSSThing_HandleSoundClassPlay(sithCogMsg *msg)
{
    sithSoundClass *v6; // eax

    NETMSG_IN_START(msg);

    sithThing* pThing = sithThing_GetById(NETMSG_POPS32());
    if (!pThing)
        return 0;
    
    int v4 = NETMSG_POPS32();
    float v3 = NETMSG_POPF32();
    int16_t idk = NETMSG_POPS16();

    if ( v3 >= 0.0 )
        v6 = sithSoundClass_ThingPlaySoundclass5(pThing, idk, v3);
    else
        v6 = sithSoundClass_ThingPlaySoundclass(pThing, idk);
    if ( v6 )
        v6->entries[14] = (sithSoundClassEntry*)v4; // TODO wat??
    return 1;
}

void sithDSSThing_SendPlayKey(sithThing *pThing, rdKeyframe *pRdKeyframe, int a3, int16_t a4, int a5, int a6, int a7)
{
    NETMSG_START;

    NETMSG_PUSHS32(pThing->thing_id);
    NETMSG_PUSHS32(pRdKeyframe->id);
    NETMSG_PUSHS16(a4);
    NETMSG_PUSHS32(a3);
    NETMSG_PUSHS32(a5);

    NETMSG_END(COGMSG_PLAYKEY);

    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, a6, a7, 0);
}

int sithDSSThing_HandlePlayKey(sithCogMsg *msg)
{
    NETMSG_IN_START(msg);

    sithThing* pThing = sithThing_GetById(NETMSG_POPS32());
    if ( pThing )
    {
        if ( pThing->rdthing.puppet )
        {
            rdKeyframe* pKeyframe = sithKeyFrame_GetByIdx(NETMSG_POPS32());
            if ( pKeyframe )
            {
                int arg1 = NETMSG_POPS16();
                int arg2 = NETMSG_POPS32();
                int arg3 = NETMSG_POPS32();
                int v4 = sithPuppet_StartKey(
                         pThing->rdthing.puppet,
                         pKeyframe,
                         arg1,
                         arg1 + 2,
                         arg2,
                         0);
                if ( v4 >= 0 )
                    pThing->rdthing.puppet->tracks[v4].field_130 = arg3;
                return 1;
            }
        }
        else
        {
            return 0;
        }
    }
    return 0;
}

void sithDSSThing_SendOpenDoor(sithThing *pThing, int16_t idx1, int idx2, int sendtoId, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHS32(pThing->thing_id);
    NETMSG_PUSHS32(idx2);
    NETMSG_PUSHS16(idx1);
    
    NETMSG_END(COGMSG_OPENDOOR);

    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendtoId, mpFlags, 0);
}

int sithDSSThing_HandleOpenDoor(sithCogMsg *msg)
{
    NETMSG_IN_START(msg);

    sithThing* pThing = sithThing_GetById(NETMSG_POPS32());

    if ( pThing )
    {
        if ( pThing->rdthing.puppet )
        {
            int arg1 = NETMSG_POPS32();
            int v4 = sithPuppet_PlayMode(pThing, NETMSG_POPS16(), 0);
            if ( v4 >= 0 )
                pThing->rdthing.puppet->tracks[v4].field_130 = arg1;
            return 1;
        }
        else
        {
            return 0;
        }
    }
    return 0;
}

void sithDSSThing_SendSetThingModel(sithThing *pThing, int sendtoId)
{
    if (!pThing || pThing->rdthing.type != RD_THINGTYPE_MODEL )
        return;

    const char *pFname = pThing->rdthing.model3->filename;
    if (!pFname)
        return;

    NETMSG_START;

    NETMSG_PUSHS32(pThing->thing_id);
    NETMSG_PUSHSTR(pFname, 0x20);

    NETMSG_END(COGMSG_SETTHINGMODEL);

    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendtoId, 255, 1);
}

int sithDSSThing_HandleSetThingModel(sithCogMsg *msg)
{
    char model_3do_fname[32];

    NETMSG_IN_START(msg);

    sithThing* pThing = sithThing_GetById(NETMSG_POPS32());
    if ( pThing )
    {
        NETMSG_POPSTR(model_3do_fname, 0x20);
        rdModel3* pModel = sithModel_LoadEntry(model_3do_fname, 1);
        if ( pModel )
        {
            sithThing_SetNewModel(pThing, pModel);
            return 1;
        }
    }
    return 0;
}

void sithDSSThing_SendStopKey(sithThing *pThing, int a2, float a3, int sendtoId, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHS32(pThing->thing_id);
    NETMSG_PUSHS32(a2);
    NETMSG_PUSHF32(a3);

    NETMSG_END(COGMSG_STOPKEY);

    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendtoId, mpFlags, 1);
}

int sithDSSThing_HandleStopKey(sithCogMsg *msg)
{
    NETMSG_IN_START(msg);

    sithThing* pThing = sithThing_GetById(NETMSG_POPS32());
    if ( !pThing )
        return 0;

    rdPuppet* pPuppet = pThing->rdthing.puppet;
    if ( !pPuppet )
        return 0;

    uint32_t v3 = 0;
    int arg1 = NETMSG_POPS32();
    rdPuppetTrack* v4 = &pPuppet->tracks[0];
    for (int i = 0; i < 4; i++)
    {
        if ( v4->field_130 == arg1 )
            break;
        ++v3;
        ++v4;
    }

    if ( v3 < 4 )
        sithPuppet_StopKey(pPuppet, v3, NETMSG_POPF32());

    return 1;
}

void sithDSSThing_SendStopSound(sithPlayingSound *pSound, float a2, int a3, int a4)
{
    NETMSG_START;

    NETMSG_PUSHS32(pSound->refid);
    NETMSG_PUSHF32(a2);

    NETMSG_END(COGMSG_STOPSOUND);

    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, a3, a4, 1);
}

int sithDSSThing_HandleStopSound(sithCogMsg *msg)
{
    NETMSG_IN_START(msg);

    int refid = NETMSG_POPS32();
    float fadeInTime = NETMSG_POPF32();
    sithPlayingSound* pSound = sithSoundSys_GetSoundFromRef(refid);
    if ( pSound )
    {
        if ( fadeInTime <= 0.0 )
        {
            sithSoundSys_StopSound(pSound);
            return 1;
        }
        sithSoundSys_FadeSound(pSound, 0.0, fadeInTime);
        pSound->flags |= SITHSOUNDFLAG_FADING;
    }
    return 1;
}

void sithDSSThing_SendFireProjectile(sithThing *pWeapon, sithThing *pProjectile, rdVector3 *pFireOffset, rdVector3 *pAimError, sithSound *pFireSound, int16_t anim, float scale, int16_t scaleFlags, float a9, int thingId, int sendtoId, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHS32(pWeapon->thing_id);
    NETMSG_PUSHS16(scaleFlags);
    
    int16_t v12 = -1;
    if ( pProjectile ) {
        NETMSG_PUSHS16(pProjectile->thingIdx);
    }
    else {
        NETMSG_PUSHS16(-1);
    }
    if ( pFireSound ) {
        v12 = pFireSound->id;
    }

    NETMSG_PUSHS16(v12);
    NETMSG_PUSHS16(anim);
    NETMSG_PUSHVEC3(*pAimError);
    NETMSG_PUSHVEC3(*pFireOffset);
    NETMSG_PUSHF32(scale);
    NETMSG_PUSHF32(a9);
    NETMSG_PUSHS32(thingId);

    NETMSG_END(COGMSG_FIREPROJECTILE);

    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendtoId, mpFlags, 0);
}

int sithDSSThing_HandleFireProjectile(sithCogMsg *msg)
{
    NETMSG_IN_START(msg);

    sithThing* pThing = sithThing_GetById(NETMSG_POPS32());
    if ( pThing )
    {
        int16_t scaleFlags = NETMSG_POPS16();
        sithThing* pTemplate = sithTemplate_GetEntryByIdx(NETMSG_POPS16());
        sithSound* pSound = sithSound_GetFromIdx(NETMSG_POPS16());
        int anim = NETMSG_POPS16();
        rdVector3 aimError = NETMSG_POPVEC3();
        rdVector3 fireOffset = NETMSG_POPVEC3();
        float scale = NETMSG_POPF32();
        float a9 = NETMSG_POPF32();
        int thingId = NETMSG_POPS32();
        sithThing* pThing2 = sithWeapon_FireProjectile_0(
                      pThing,
                      pTemplate,
                      &fireOffset,
                      &aimError,
                      pSound,
                      anim,
                      scale,
                      scaleFlags,
                      a9);
        if ( pThing2 )
        {
            pThing2->thing_id = thingId;
            pThing2->thingflags |= SITH_TF_INVULN;
        }
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

int sithDSSThing_HandleDeath(sithCogMsg *msg)
{
    NETMSG_IN_START(msg);

    sithThing* pSender = sithThing_GetById(NETMSG_POPS32());
    if ( pSender )
    {
        sithThing* pReceiver = sithThing_GetById(NETMSG_POPS32());
        int cause = NETMSG_POPU8();
        int senderType = pSender->thingtype;
        if ( senderType == SITH_THING_ACTOR)
        {
            sithThing_SpawnDeadBodyMaybe(pSender, pReceiver, 0);
        }
        else if (senderType == SITH_THING_PLAYER)
        {
            if ( cause == 1 )
            {
                sithPlayer_HandleSentDeathPkt(pSender);
                return 1;
            }
            sithThing_SpawnDeadBodyMaybe(pSender, pReceiver, 0);
        }
        return 1;
    }
    return 0;
}

void sithDSSThing_SendDamage(sithThing *pDamagedThing, sithThing *pDamagedBy, float amt, int16_t a4, int sendtoId, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHS32(pDamagedThing->thing_id);
    if ( pDamagedBy ) {
        NETMSG_PUSHS32(pDamagedBy->thing_id);
    }
    else{
        NETMSG_PUSHS32(-1);
    }
    NETMSG_PUSHF32(amt);
    NETMSG_PUSHS16(a4);

     NETMSG_END(COGMSG_DAMAGE);

    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendtoId, mpFlags, 1);
}

int sithDSSThing_HandleDamage(sithCogMsg *msg)
{
    if ( msg->netMsg.thingIdx != sithNet_dword_8C4BA4 )
        return 0;

    NETMSG_IN_START(msg);

    sithThing* pDamagedThing = sithThing_GetById(NETMSG_POPS32());
    if ( pDamagedThing )
    {
        sithThing* pDamagedBy = sithThing_GetById(NETMSG_POPS32());
        if ( !pDamagedBy )
            pDamagedBy = pDamagedThing;

        float arg2 = NETMSG_POPF32();
        int16_t arg3 = NETMSG_POPS16();
        sithThing_Damage(pDamagedThing, pDamagedBy, arg2, arg3);
        return 1;
    }
    return 0;
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
                NETMSG_PUSHVEC3(thing->trackParams.aFrames[i].pos);
                NETMSG_PUSHVEC3(thing->trackParams.aFrames[i].rot);
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
            thing->trackParams.sizeFrames = thing->trackParams.loadedFrames;
            thing->trackParams.aFrames = pSithHS->alloc(sizeof(sithThingFrame) * thing->trackParams.sizeFrames);
        }

        for (int i = 0; i < thing->trackParams.loadedFrames; i++)
        {
            thing->trackParams.aFrames[i].pos = NETMSG_POPVEC3();
            thing->trackParams.aFrames[i].rot = NETMSG_POPVEC3();
        }
    }
    sithThing_sub_4CD100(thing);
    return 1;
}

void sithDSSThing_SendSyncThingFrame(sithThing *pThing, int16_t a2, float a3, int a4, int sendtoId, int mpFlags)
{
    rdVector3 out;

    if (!pThing || pThing->moveType != SITH_MT_PATH || !pThing->thingtype )
        return;
    if (!pThing->sector)
        return;

    NETMSG_START;

    NETMSG_PUSHS32(a4);
    NETMSG_PUSHS32(pThing->thing_id);
    NETMSG_PUSHU32(bShowInvisibleThings);
    NETMSG_PUSHS16(pThing->sector->id);
    NETMSG_PUSHVEC3(pThing->position);
    rdMatrix_ExtractAngles34(&pThing->lookOrientation, &out);
    NETMSG_PUSHVEC3(out);
    NETMSG_PUSHS16(a2);
    NETMSG_PUSHF32(a3);

    NETMSG_END(COGMSG_SYNCTHINGFRAME);

    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendtoId, mpFlags, 1);
}

int sithDSSThing_HandleSyncThingFrame(sithCogMsg *msg)
{
    NETMSG_IN_START(msg);

    int arg0 = NETMSG_POPS32();
    sithThing* pThing = sithThing_GetById(NETMSG_POPS32());
    if ( !pThing || pThing->moveType != SITH_MT_PATH )
        return 0;

    uint32_t arg2 = NETMSG_POPU32();
    if ( pThing->field_260 <= arg2 )
    {
        pThing->field_260 = arg2;
        sithSector* pSector = sithSector_GetPtrFromIdx(NETMSG_POPS16());
        if ( !pSector )
            return 0;

        pThing->position = NETMSG_POPVEC3();
        sithThing_MoveToSector(pThing, pSector, 0);
        rdVector3 lookAngles = NETMSG_POPVEC3();
        
        rdMatrix_BuildRotate34(&pThing->lookOrientation, &lookAngles);
        int arg9 = NETMSG_POPS16();
        float arg10 = NETMSG_POPF32();

        if ( arg0 )
        {
            if ( arg0 == 1 )
            {
                sithTrackThing_SkipToFrame(pThing, arg9, arg10);
                return 1;
            }
            if ( arg0 == 2 )
            {
                sithTrackThing_Stop(pThing);
                return 1;
            }
        }
        else
        {
            sithTrackThing_MoveToFrame(pThing, arg9, arg10);
        }
    }
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

// TODO probably some weird inlining going on here
void sithDSSThing_SendTakeItem(sithThing *pItemThing, sithThing *pActor, int mpFlags)
{
    int itemThingId; // edi
    int actorId; // edx
    sithThing *pItemThing2; // esi
    sithThing *pActor2_; // eax
    sithThing *pActor2; // edi

    itemThingId = pItemThing->thing_id;
    actorId = pActor->thing_id;
    sithCogVm_netMsgTmp.pktData[0] = itemThingId;
    sithCogVm_netMsgTmp.pktData[1] = actorId;
    sithCogVm_netMsgTmp.netMsg.flag_maybe = 0;
    sithCogVm_netMsgTmp.netMsg.cogMsgId = COGMSG_TAKEITEM1;
    sithCogVm_netMsgTmp.netMsg.msg_size = 8;
    if ( !sithNet_isServer )
    {
        sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sithNet_dword_8C4BA4, mpFlags, 1);
        return;
    }
    pItemThing2 = sithThing_GetById(itemThingId);
    if ( !pItemThing2 && sithNet_isServer )
    {
        sithCogVm_netMsgTmp.pktData[0] = itemThingId;
        sithCogVm_netMsgTmp.netMsg.flag_maybe = 0;
        sithCogVm_netMsgTmp.netMsg.cogMsgId = COGMSG_DESTROYTHING;
        sithCogVm_netMsgTmp.netMsg.msg_size = 4;
        sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sithCogVm_netMsgTmp.netMsg.thingIdx, 255, 1);
        return;
    }
    pActor2_ = sithThing_GetById(sithCogVm_netMsgTmp.pktData[1]);
    pActor2 = pActor2_;
    if ( pItemThing2 && pActor2_ )
    {
        if ( sithCogVm_netMsgTmp.netMsg.cogMsgId != COGMSG_TAKEITEM1 )
        {
LABEL_12:
            sithItem_Take(pItemThing2, pActor2, 1);
            return;
        }
        if ( pItemThing2->thingtype == SITH_THING_ITEM && (pItemThing2->thingflags & (SITH_TF_DISABLED|SITH_TF_WILLBEREMOVED)) == 0 )
        {
            sithCogVm_netMsgTmp.netMsg.cogMsgId = COGMSG_TAKEITEM2;
            sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, -1, 1, 1);
            goto LABEL_12;
        }
    }
}

int sithDSSThing_HandleTakeItem(sithCogMsg *msg)
{
    int v1; // ebx
    sithThing *v2; // edi
    sithThing *v4; // eax
    sithThing *v5; // esi
    int v6; // [esp-Ch] [ebp-1Ch]

    v1 = msg->pktData[0];
    v2 = sithThing_GetById(v1);
    if ( !v2 && sithNet_isServer )
    {
        v6 = msg->netMsg.thingIdx;
        sithCogVm_netMsgTmp.pktData[0] = v1;
        sithCogVm_netMsgTmp.netMsg.flag_maybe = 0;
        sithCogVm_netMsgTmp.netMsg.cogMsgId = COGMSG_DESTROYTHING;
        sithCogVm_netMsgTmp.netMsg.msg_size = 4;
        sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp.netMsg, v6, 255, 1);
        return 0;
    }
    v4 = sithThing_GetById(msg->pktData[1]);
    v5 = v4;
    if ( v2 && v4 )
    {
        if ( msg->netMsg.cogMsgId == COGMSG_TAKEITEM1 )
        {
            if ( v2->thingtype != SITH_THING_ITEM || (v2->thingflags & (SITH_TF_DISABLED|SITH_TF_WILLBEREMOVED)) != 0 )
                return 1;
            msg->netMsg.cogMsgId = COGMSG_TAKEITEM2;
            sithCogVm_SendMsgToPlayer(&msg->netMsg, -1, 1, 1);
        }
        sithItem_Take(v2, v5, 1);
        return 1;
    }
    return 0;
}

void sithDSSThing_SendCreateThing(sithThing *pTemplate, sithThing *pThing, sithThing *pThing2, sithSector *pSector, rdVector3 *pPos, rdVector3 *pRot, int mpFlags, int bSync)
{
    NETMSG_START;

    NETMSG_PUSHS16(pTemplate->thingIdx);
    if ( pThing2 )
    {
        NETMSG_PUSHS32(pThing2->thing_id);
    }
    else
    {
        NETMSG_PUSHS32(-1);
        NETMSG_PUSHS32(pSector->id);
        NETMSG_PUSHVEC3(*pPos);
        NETMSG_PUSHVEC3(*pRot);
    }
    NETMSG_PUSHS32(pThing->thing_id);

    NETMSG_END(COGMSG_CREATETHING);
    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, -1, mpFlags, bSync);
}

int sithDSSThing_HandleCreateThing(sithCogMsg *msg)
{
    rdMatrix34 lookOrient;

    NETMSG_IN_START(msg);

    sithThing* pCreated = NULL;
    sithThing* pThing = sithTemplate_GetEntryByIdx(NETMSG_POPS16());
    if ( pThing )
    {
        int pThing2Id = NETMSG_POPS32();
        if ( pThing2Id < 0 )
        {
            sithSector* pSector = (sithThing *)sithSector_GetPtrFromIdx(NETMSG_POPS16());
            if ( !pSector )
                return 0;
            rdVector3 pos = NETMSG_POPVEC3();
            rdVector3 rot = NETMSG_POPVEC3();
            rdMatrix_BuildRotate34(&lookOrient, &rot);
            pCreated = sithThing_Create(pThing, &pos, &lookOrient, pSector, 0);
        }
        else
        {
            sithThing* pThing2 = sithThing_GetById(pThing2Id);
            if ( !pThing2 )
                return pThing2;
            pCreated = sithThing_SpawnTemplate(pThing, pThing2);
        }

        if ( pCreated )
        {
            pCreated->thing_id = NETMSG_POPS32();
            pCreated->thingflags |= SITH_TF_INVULN;
            return 1;
        }
    }
    return 0;
}

void sithDSSThing_SendDestroyThing(int idx, int sendtoId)
{
    NETMSG_START;

    NETMSG_PUSHS32(idx);
    NETMSG_END(COGMSG_DESTROYTHING);

    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendtoId, 255, 1);
}

int sithDSSThing_HandleDestroyThing(sithCogMsg *msg)
{
    NETMSG_IN_START(msg);

    sithThing* pThing = sithThing_GetById(NETMSG_POPS32());
    if ( pThing )
    {
        sithThing_Destroy(pThing);
        return 1;
    }
    return 0;
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