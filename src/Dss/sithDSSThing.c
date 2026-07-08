#include "sithDSSThing.h"

#include "Cog/sithCog.h"
#include "World/sithSoundClass.h"
#include "Devices/sithSoundMixer.h"
#include "World/sithSurface.h"
#include "Devices/sithSound.h"
#include "Engine/sithKeyFrame.h"
#include "Dss/sithMulti.h"
#include "World/sithThing.h"
#include "World/sithSector.h"
#include "World/sithActor.h"
#include "Engine/sithPuppet.h"
#include "World/sithModel.h"
#include "World/sithTemplate.h"
#include "World/sithItem.h"
#include "World/sithWeapon.h"
#include "World/sithTrackThing.h"
#include "Devices/sithComm.h"
#include "stdPlatform.h"
#include "jk.h"

void sithDSSThing_Pos(SithThing *pThing, int sendto_id, int bSync)
{
    rdVector3 orient; // [esp+4h] [ebp-Ch] BYREF

    NETMSG_START;

    if ( pThing && pThing->type && pThing->sector && MOTS_ONLY_COND(!(pThing->physicsParams.flags & SITH_PF_4000000)))
    {
        SithSector* pSector = pThing->sector;
        NETMSG_PUSHS32(pThing->guid);
        NETMSG_PUSHU16(pThing->attach_flags);
        NETMSG_PUSHS16(pSector->id);
        NETMSG_PUSHVEC3(pThing->position);
        rdMatrix_ExtractAngles34(&pThing->orient, &orient);
        NETMSG_PUSHF32(orient.x);
        NETMSG_PUSHF32(orient.y);
        NETMSG_PUSHF32(orient.z);

        if ( pThing->moveType == SITH_MT_PHYSICS )
        {
            NETMSG_PUSHU32(pThing->physicsParams.flags);
            NETMSG_PUSHVEC3(pThing->physicsParams.vel);
            if ( !pThing->attach_flags )
            {
                NETMSG_PUSHVEC3(pThing->physicsParams.angularVelocity);
            }
        }
        if ( pThing->type == SITH_THING_PLAYER )
            NETMSG_PUSHF32(pThing->actorParams.headPYR.x);

        NETMSG_END(DSS_THINGPOS);

        sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sendto_id, 255, bSync);
    }
}

int sithDSSThing_ProcessPos(SithMessage *msg)
{
    rdVector3 lookTmp; // [esp+10h] [ebp-18h] BYREF
    rdVector3 pos; // [esp+1Ch] [ebp-Ch] BYREF

    if ( !sithWorld_g_pCurrentWorld )
        return 0;

    NETMSG_IN_START(msg);

    int guid = NETMSG_POPS32();

    SithThing* pThing = sithThing_GetGuidThing(guid);
    //printf("sithDSSThing_ProcessPos %x %x\n", guid, pThing->controlType);
    if ( !pThing || pThing->type == SITH_THING_FREE || !pThing->sector )
        return 0;
    uint16_t attach_flags = NETMSG_POPU16();
    if ( !attach_flags && pThing->attach_flags )
        sithThing_DetachThing(pThing);

    // TODO attach flags not set??

    int16_t sectorIdx = NETMSG_POPS16();
    SithSector* pSector = sithSector_GetPtrFromIdx(sectorIdx);
    if ( !pSector )
        return 0;

    pos = NETMSG_POPVEC3();
    lookTmp = NETMSG_POPVEC3();

    rdMatrix_BuildRotate34(&pThing->orient, &lookTmp);
    if ( pThing->moveType == SITH_MT_PHYSICS )
    {
        pThing->physicsParams.flags = NETMSG_POPU32();

        pThing->physicsParams.vel = NETMSG_POPVEC3();
        if ( attach_flags )
        {
            rdVector_Zero3(&pThing->physicsParams.angularVelocity);
        }
        else
        {
            pThing->physicsParams.angularVelocity = NETMSG_POPVEC3();
        }
        sithDSSThing_MoveToPos(pThing, &pos, pSector);
    }
    else
    {
        pThing->position = pos;
        sithThing_SetSector(pThing, pSector, 0);
    }
    if ( pThing->type == SITH_THING_PLAYER )
    {
        rdVector_Zero3(&lookTmp);
        lookTmp.x = NETMSG_POPF32();
        sithActor_SetHeadPYR(pThing, &lookTmp);
    }

    return 1;
}

// MoTS altered
void sithDSSThing_UpdateState(SithThing *pThing, int sendto_id, int mpFlags)
{
    NETMSG_START;

#if 0
    if (!pThing) {
        jk_printf("OpenJKDF2 WARN: Thing NULL, not synced.\n");
        return;
    }
    if (!pThing->type) {
        jk_printf("OpenJKDF2 WARN: Thing type 0, not synced.\n");
    }
    if (!pThing->sector) {
        jk_printf("OpenJKDF2 WARN: Thing sector NULL, not synced.\n");
    }
    if (!sithThing_ValidateThingPointer(pThing)) {
        jk_printf("OpenJKDF2 WARN: Thing not syncable?\n");
    }
#endif

    if (!pThing || !pThing->type || !pThing->sector || !sithThing_ValidateThingPointer(pThing) || MOTS_ONLY_FLAG(pThing->physicsParams.flags & SITH_PF_4000000))
        return;

    NETMSG_PUSHS32(pThing->guid);
    NETMSG_PUSHS32(pThing->jkFlags);
    NETMSG_PUSHS32(pThing->msecLifeLeft);
    NETMSG_PUSHS16(pThing->sector->id);
    NETMSG_PUSHS16(pThing->collide);
    NETMSG_PUSHVEC3(pThing->position);
    NETMSG_PUSHS32(pThing->flags);
    NETMSG_PUSHS32(pThing->renderData.curGeoMode);

    if ( pThing->pPuppetClass )
    {
        NETMSG_PUSHS16(pThing->puppet->field_0);
        NETMSG_PUSHS16(pThing->puppet->field_4);
    }
    NETMSG_PUSHS32(pThing->light);
    switch ( pThing->type )
    {
        case SITH_THING_ACTOR:
        case SITH_THING_CORPSE:
        case SITH_THING_PLAYER:
            NETMSG_PUSHS32(pThing->actorParams.flags);
            break;
        case SITH_THING_WEAPON:
            NETMSG_PUSHS32(pThing->weaponParams.flags);
            break;
        case SITH_THING_ITEM:
            NETMSG_PUSHS32(pThing->itemParams.flags);
            if (pThing->itemParams.flags & SITH_ITEM_BACKPACK)
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
        NETMSG_PUSHS32(pThing->physicsParams.flags);

    NETMSG_END(DSS_SYNCTHING);

    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sendto_id, mpFlags, 1);
}

// MOTS altered
int sithDSSThing_ProcessStateUpdate(SithMessage *msg)
{
    NETMSG_IN_START(msg);

    int id = NETMSG_POPS32();
    SithThing* pThing = sithThing_GetGuidThing(id);
    if ( !pThing )
        return 0;

    // 1 for multiplayer hackfix:
#if 0
    // Added: why is this needed???
    if (!pThing->controlType && pThing->type) {
        jk_printf("OpenJKDF2 WARN: id %08x pThing->controlType 0, using pThing->type %u\n", id, pThing->type);
        pThing->controlType = pThing->type;
    }
    if (pThing->controlType && !pThing->type) {
        jk_printf("OpenJKDF2 WARN: id %08x pThing->type 0, using pThing->controlType %u\n", id, pThing->controlType);
        pThing->type = pThing->controlType;
    }
#endif

    if ( pThing->type == SITH_THING_FREE )
        return 0;
    if ( !pThing->sector )
        return 0;
    pThing->jkFlags = NETMSG_POPS32();
    pThing->msecLifeLeft = NETMSG_POPS32();
    SithSector* pSector = sithSector_GetPtrFromIdx(NETMSG_POPS16());
    if ( !pSector )
        return 0;
    pThing->collide = NETMSG_POPS16();
    pThing->position = NETMSG_POPVEC3();
    sithThing_SetSector(pThing, pSector, 0);

    uint32_t flags = NETMSG_POPS32();
    if ( pThing->type == SITH_THING_PLAYER && (pThing->flags & SITH_TF_DEAD) && !(flags & SITH_TF_DEAD) && MOTS_ONLY_COND(pThing != sithPlayer_g_pLocalPlayerThing))
        sithPlayer_debug_loadauto(pThing);
    
    // Lol, anticheat?
    if ( (pThing->flags & SITH_TF_INVULN) != 0 )
        flags |= SITH_TF_INVULN;
    else
        flags &= ~SITH_TF_INVULN;

    // MoTS added
    if (Main_bMotsCompat)
    {
        if ((pThing->flags & SITH_TF_DISABLED)
            && !(flags & SITH_TF_DISABLED) 
            && pThing->type == SITH_THING_ITEM 
            && sithNet_isMulti 
            && !sithNet_isServer
            && pThing->itemParams.respawnFactor != 0 
            && pThing->itemParams.flags & SITH_ITEM_RESPAWN_MP) {
            sithCog_ThingSendMessage(pThing, pThing, SITH_MESSAGE_RESPAWN);
        }
    }

    SithPuppetClass* pAnimclass = pThing->pPuppetClass;
    pThing->flags = flags;
    pThing->renderData.curGeoMode = (rdGeoMode_t)NETMSG_POPS32();
    if ( pAnimclass )
    {
        sithPuppet_SetArmedMode(pThing, NETMSG_POPS16());
        sithPuppet_SetMoveMode(pThing, NETMSG_POPS16());
    }

    pThing->light = NETMSG_POPF32();

    switch ( pThing->type )
    {
        case SITH_THING_ACTOR:
        case SITH_THING_CORPSE:
        case SITH_THING_PLAYER:
            pThing->actorParams.flags = NETMSG_POPS32();
            break;
        case SITH_THING_WEAPON:
            pThing->weaponParams.flags = NETMSG_POPS32();
            break;
        case SITH_THING_ITEM:
            pThing->itemParams.flags = NETMSG_POPS32();
            if (pThing->itemParams.flags & SITH_ITEM_BACKPACK)
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
        pThing->physicsParams.flags = NETMSG_POPS32();

    return 1;
}

void sithDSSThing_PlaySound(SithThing *followThing, rdVector3 *pos, sithSound *sound, flex32_t volume, flex32_t a5, int flags, int refid, int sendto_id, int mpFlags)
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
        NETMSG_PUSHS32(followThing->guid);
    }
    NETMSG_PUSHU32(refid);
    
    NETMSG_END(DSS_PLAYSOUND);
    
    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sendto_id, mpFlags, 0);
}

int sithDSSThing_ProcessPlaySound(SithMessage *msg)
{
    sithPlayingSound* out = NULL;

    NETMSG_IN_START(msg);

    int flags = NETMSG_POPU32();
    flex32_t volume = NETMSG_POPF32();
    flex32_t a5 = NETMSG_POPF32();
    int16_t soundIdx = NETMSG_POPS16();
    sithSound* sound = sithSound_GetFromIdx(soundIdx);

    if (!sound)
        return 0;

    if ( (flags & SITHSOUNDFLAG_FOLLOWSTHING) == 0 )
    {
        if ( (flags & SITHSOUNDFLAG_ABSOLUTE) != 0 )
        {
            rdVector3 pos = NETMSG_POPVEC3();
            out = sithSoundMixer_PlaySoundPos(sound, &pos, 0, 1.0, volume, a5, flags);
        }
        else
        {
            out = sithSoundMixer_PlaySound(sound, volume, a5, flags);
        }
    }
    else
    {
        SithThing* thing = sithThing_GetGuidThing(NETMSG_POPS32());
        if ( !thing )
            return 0;
        out = sithSoundMixer_PlaySoundThing(sound, thing, 1.0, volume, a5, flags);
    }

    if ( out )
        out->refid = NETMSG_POPU32();

    return 1;
}

void sithDSSThing_PlaySoundMode(SithThing *pThing, int16_t a2, int a3, flex32_t a4)
{
    NETMSG_START;

    NETMSG_PUSHS32(pThing->guid);
    NETMSG_PUSHS32(a3);
    NETMSG_PUSHF32(a4);
    NETMSG_PUSHS16(a2);

    NETMSG_END(DSS_PLAYSOUNDMODE);

    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, -1, 255, 0);
}

int sithDSSThing_ProcessPlaySoundMode(SithMessage *msg)
{
    sithPlayingSound *v6; // eax

    NETMSG_IN_START(msg);

    SithThing* pThing = sithThing_GetGuidThing(NETMSG_POPS32());
    if (!pThing)
        return 0;
    
    int v4 = NETMSG_POPS32();
    flex32_t v3 = NETMSG_POPF32();
    int16_t idk = NETMSG_POPS16();

    if ( v3 >= 0.0 )
        v6 = sithSoundClass_PlayMode(pThing, idk, v3);
    else
        v6 = sithSoundClass_PlayModeRandom(pThing, idk);
    if ( v6 )
        v6->refid = v4;
    return 1;
}

void sithDSSThing_PlayKey(SithThing *pThing, rdKeyframe *pRdKeyframe, int a3, int16_t a4, int a5, int a6, int a7)
{
    NETMSG_START;

    NETMSG_PUSHS32(pThing->guid);
    NETMSG_PUSHS32(pRdKeyframe->id);
    NETMSG_PUSHS16(a4);
    NETMSG_PUSHS32(a3);
    NETMSG_PUSHS32(a5);

    NETMSG_END(DSS_PLAYKEY);

    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, a6, a7, 0);
}

int sithDSSThing_ProcessPlayKey(SithMessage *msg)
{
    NETMSG_IN_START(msg);

    SithThing* pThing = sithThing_GetGuidThing(NETMSG_POPS32());
    if ( pThing )
    {
        if ( pThing->renderData.puppet )
        {
            rdKeyframe* pKeyframe = sithKeyFrame_GetByIdx(NETMSG_POPS32());
            if ( pKeyframe )
            {
                int arg1 = NETMSG_POPS16();
                int arg2 = NETMSG_POPS32();
                int arg3 = NETMSG_POPS32();
                int v4 = sithPuppet_PlayKey(
                         pThing->renderData.puppet,
                         pKeyframe,
                         arg1,
                         arg1 + 2,
                         arg2,
                         0);
                if ( v4 >= 0 )
                    pThing->renderData.puppet->tracks[v4].field_130 = arg3;
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

void sithDSSThing_PlayKeyMode(SithThing *pThing, int16_t idx1, int idx2, int sendtoId, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHS32(pThing->guid);
    NETMSG_PUSHS32(idx2);
    NETMSG_PUSHS16(idx1);
    
    NETMSG_END(DSS_PLAYKEYMODE);

    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sendtoId, mpFlags, 0);
}

int sithDSSThing_ProcessPlayKeyMode(SithMessage *msg)
{
    NETMSG_IN_START(msg);

    SithThing* pThing = sithThing_GetGuidThing(NETMSG_POPS32());

    if (!pThing )
        return 0;
    if (!pThing->renderData.puppet)
        return 0;

    int arg1 = NETMSG_POPS32();
    int v4 = sithPuppet_PlayMode(pThing, NETMSG_POPS16(), 0);
    if ( v4 >= 0 )
        pThing->renderData.puppet->tracks[v4].field_130 = arg1;
    return 1;
}

void sithDSSThing_SetModel(SithThing *pThing, int sendtoId)
{
    if (!pThing || pThing->renderData.type != RD_THING_MODEL3 )
        return;

    const char *pFname = pThing->renderData.model3->filename;
    if (!pFname)
        return;

    NETMSG_START;

    NETMSG_PUSHS32(pThing->guid);
    NETMSG_PUSHSTR(pFname, 0x20);

    NETMSG_END(DSS_SETTHINGMODEL);

    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sendtoId, 255, 1);
}

int sithDSSThing_ProcessSetModel(SithMessage *msg)
{
    char model_3do_fname[32];

    NETMSG_IN_START(msg);

    SithThing* pThing = sithThing_GetGuidThing(NETMSG_POPS32());
    if ( pThing )
    {
        NETMSG_POPSTR(model_3do_fname, 0x20);
        rdModel3* pModel = sithModel_Load(model_3do_fname, 1);
        if ( pModel )
        {
            sithThing_SetThingModel(pThing, pModel);
            return 1;
        }
    }
    return 0;
}

void sithDSSThing_StopKey(SithThing *pThing, int a2, flex32_t a3, int sendtoId, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHS32(pThing->guid);
    NETMSG_PUSHS32(a2);
    NETMSG_PUSHF32(a3);

    NETMSG_END(DSS_STOPKEY);

    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sendtoId, mpFlags, 1);
}

int sithDSSThing_ProcessStopKey(SithMessage *msg)
{
    NETMSG_IN_START(msg);

    SithThing* pThing = sithThing_GetGuidThing(NETMSG_POPS32());
    if ( !pThing )
        return 0;

    rdPuppet* pPuppet = pThing->renderData.puppet;
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

void sithDSSThing_StopSound(sithPlayingSound *pSound, flex32_t a2, int a3, int a4)
{
    NETMSG_START;

    NETMSG_PUSHS32(pSound->refid);
    NETMSG_PUSHF32(a2);

    NETMSG_END(DSS_STOPSOUND);

    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, a3, a4, 1);
}

int sithDSSThing_ProcessStopSound(SithMessage *msg)
{
    NETMSG_IN_START(msg);

    int refid = NETMSG_POPS32();
    flex32_t fadeInTime = NETMSG_POPF32();
    sithPlayingSound* pSound = sithSoundMixer_GetChannelHandle(refid);
    if ( pSound )
    {
        if ( fadeInTime <= 0.0 )
        {
            sithSoundMixer_StopSound(pSound);
            return 1;
        }
        sithSoundMixer_FadeVolume(pSound, 0.0, fadeInTime);
        pSound->flags |= SITHSOUNDFLAG_FADING;
    }
    return 1;
}

// MoTS altered
void sithDSSThing_Fire(SithThing *pWeapon, SithThing *pProjectile, rdVector3 *pFireOffset, rdVector3 *pAimError, sithSound *pFireSound, int16_t anim, flex32_t scale, int16_t scaleFlags, flex32_t a9, int thingId, int sendtoId, int mpFlags, int idk)
{
    NETMSG_START;

    //printf("sithDSSThing_Fire %x %x (%f %f %f) (%f %f %f) %x %f %x %f\n", pWeapon ? pWeapon->guid : -1, pProjectile->idx, pAimError->x, pAimError->y, pAimError->z, pFireOffset->x, pFireOffset->y, pFireOffset->z, anim, scale, scaleFlags, a9);

    NETMSG_PUSHS32(pWeapon->guid);
    NETMSG_PUSHS16(scaleFlags);
    
    int16_t v12 = -1;
    if ( pProjectile ) {
        NETMSG_PUSHS16(pProjectile->idx);
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

    if (idk == 0 || !Main_bMotsCompat) {
        NETMSG_END(DSS_FIREPROJECTILE);
    }
    else if (Main_bMotsCompat) {
        NETMSG_PUSHS32(idk);
        NETMSG_END(DSS_MOTS_NEW_2);
    }

    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sendtoId, mpFlags, 0);
}

// MOTS altered (Added argument to sithWeapon_WeaponFireProjectile)
int sithDSSThing_ProcessFire(SithMessage *msg)
{
    NETMSG_IN_START(msg);

    int idx = NETMSG_POPS32();

    // TODO: bug? if this fails, it might completely screw over save files?

    SithThing* pThing = sithThing_GetGuidThing(idx);
    if ( pThing )
    {
        int16_t scaleFlags = NETMSG_POPS16();
        int16_t templateIdx = NETMSG_POPS16();
        SithThing* pCreateThingTemplate = sithTemplate_GetTemplateByIndex(templateIdx);
        sithSound* pSound = sithSound_GetFromIdx(NETMSG_POPS16());
        int anim = NETMSG_POPS16();
        rdVector3 aimError = NETMSG_POPVEC3();
        rdVector3 fireOffset = NETMSG_POPVEC3();
        flex32_t scale = NETMSG_POPF32();
        flex32_t a9 = NETMSG_POPF32();
        int thingId = NETMSG_POPS32();
        //printf("sithDSSThing_ProcessFire %x %x (%f %f %f) (%f %f %f) %x %f %x %f\n", idx, templateIdx, aimError.x, aimError.y, aimError.z, fireOffset.x, fireOffset.y, fireOffset.z, anim, scale, scaleFlags, a9);
        SithThing* pThing2 = sithWeapon_WeaponFireProjectile(
                      pThing,
                      pCreateThingTemplate,
                      &fireOffset,
                      &aimError,
                      pSound,
                      anim,
                      scale,
                      scaleFlags,
                      a9,
                      0);
        if ( pThing2 )
        {
            pThing2->guid = thingId;
            pThing2->flags |= SITH_TF_INVULN;
        }
        return 1;
    }
    return 0;
}

int sithDSSThing_ProcessMOTSNew2(SithMessage *msg)
{
    NETMSG_IN_START(msg);

    SithThing* pThing = sithThing_GetGuidThing(NETMSG_POPS32());
    if ( pThing )
    {
        int16_t scaleFlags = NETMSG_POPS16();
        SithThing* pCreateThingTemplate = sithTemplate_GetTemplateByIndex(NETMSG_POPS16());
        sithSound* pSound = sithSound_GetFromIdx(NETMSG_POPS16());
        int anim = NETMSG_POPS16();
        rdVector3 aimError = NETMSG_POPVEC3();
        rdVector3 fireOffset = NETMSG_POPVEC3();
        flex32_t scale = NETMSG_POPF32();
        flex32_t a9 = NETMSG_POPF32();
        int thingId = NETMSG_POPS32();
        int idk = NETMSG_POPS32();
        SithThing* pThing2 = sithWeapon_WeaponFireProjectile(
                      pThing,
                      pCreateThingTemplate,
                      &fireOffset,
                      &aimError,
                      pSound,
                      anim,
                      scale,
                      scaleFlags,
                      a9,
                      idk);
        if ( pThing2 )
        {
            pThing2->guid = thingId;
            pThing2->flags |= SITH_TF_INVULN;
        }
        return 1;
    }
    return 0;
}

void sithDSSThing_Death(SithThing *sender, SithThing *receiver, char cause, int sendto_id, int mpFlags)
{
    NETMSG_START;
    
    NETMSG_PUSHS32(sender->guid);
    if ( receiver ) {
        NETMSG_PUSHS32(receiver->guid);
    }
    else {
        NETMSG_PUSHS32(-1);
    }
    NETMSG_PUSHU8(cause);
    
    NETMSG_END(DSS_DEATH);
    
    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sendto_id, mpFlags, 1);
}

int sithDSSThing_ProcessDeath(SithMessage *msg)
{
    NETMSG_IN_START(msg);

    SithThing* pSender = sithThing_GetGuidThing(NETMSG_POPS32());
    if ( pSender )
    {
        SithThing* pReceiver = sithThing_GetGuidThing(NETMSG_POPS32());
        int cause = NETMSG_POPU8();
        int senderType = pSender->type;
        if ( senderType == SITH_THING_ACTOR)
        {
            sithActor_KillActor(pSender, pReceiver, 0);
        }
        else if (senderType == SITH_THING_PLAYER)
        {
            if ( cause == 1 )
            {
                sithPlayer_KillPlayer(pSender);
                return 1;
            }
            sithActor_KillActor(pSender, pReceiver, 0);
        }
        return 1;
    }
    return 0;
}

void sithDSSThing_DamageThing(SithThing *pDamagedThing, SithThing *pDamagedBy, flex32_t amt, int16_t a4, int sendtoId, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHS32(pDamagedThing->guid);
    if ( pDamagedBy ) {
        NETMSG_PUSHS32(pDamagedBy->guid);
    }
    else{
        NETMSG_PUSHS32(-1);
    }
    NETMSG_PUSHF32(amt);
    NETMSG_PUSHS16(a4);

     NETMSG_END(DSS_DAMAGE);

    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sendtoId, mpFlags, 1);
}

int sithDSSThing_ProcessDamage(SithMessage *msg)
{
    if ( msg->netMsg.idx != sithNet_serverNetId )
        return 0;

    NETMSG_IN_START(msg);

    SithThing* pDamagedThing = sithThing_GetGuidThing(NETMSG_POPS32());
    if ( pDamagedThing )
    {
        SithThing* pDamagedBy = sithThing_GetGuidThing(NETMSG_POPS32());
        if ( !pDamagedBy )
            pDamagedBy = pDamagedThing;

        flex32_t arg2 = NETMSG_POPF32();
        int16_t arg3 = NETMSG_POPS16();
        sithThing_DamageThing(pDamagedThing, pDamagedBy, arg2, arg3);
        return 1;
    }
    return 0;
}

// MoTS altered
void sithDSSThing_FullDescription(SithThing *thing, int sendto_id, int mpFlags)
{
    NETMSG_START;

    NETMSG_PUSHS16(thing->idx);
    NETMSG_PUSHS16(thing->type);
    if ( thing->type )
    {
        NETMSG_PUSHS16(thing->pTemplate->idx);
        NETMSG_PUSHS32(thing->signature);
        NETMSG_PUSHS32(thing->guid);
        NETMSG_PUSHVEC3(thing->position);
        NETMSG_PUSHVEC3(thing->orient.rvec);
        NETMSG_PUSHVEC3(thing->orient.lvec);
        NETMSG_PUSHVEC3(thing->orient.uvec);
        if ( thing->sector ) {
            NETMSG_PUSHS16(thing->sector->id);
        }
        else {
            NETMSG_PUSHS16(-1);
        }
        NETMSG_PUSHU32(thing->flags);
        NETMSG_PUSHS32(thing->msecLifeLeft);
        NETMSG_PUSHS32(thing->timer);
        NETMSG_PUSHS32(thing->msecNextPulseTime);
        NETMSG_PUSHS32(thing->msecPulseInterval);
        NETMSG_PUSHF32(thing->userval);
        NETMSG_PUSHU8(thing->renderData.curGeoMode);
        NETMSG_PUSHS16(thing->collide);
        NETMSG_PUSHF32(thing->collideSize);
        NETMSG_PUSHF32(thing->light);
        NETMSG_PUSHU32(thing->jkFlags);
        if ( (thing->flags & SITH_TF_CAPTURED) != 0 )
        {
            if ( thing->pCog ) {
                NETMSG_PUSHS16(thing->pCog->idx);
            }
            else {
                NETMSG_PUSHS16(-1);
            }
            if ( thing->pCaptureCog ) {
                NETMSG_PUSHS16(thing->pCaptureCog->idx);
            }
            else {
                NETMSG_PUSHS16(-1);
            }
        }

        // MOTS added
        if (sithComm_version == 0x7D6 && thing->renderData.type == RD_THING_MODEL3) {
            rdModel3* model = thing->renderData.model3;
            if (thing->unk && model) 
            {
                NETMSG_PUSHS16(1);

                char tmp_model[32+1];
                NETMSG_PUSHSTR(model->filename, 0x20);
                NETMSG_PUSHS16(0);
            }
            else 
            {
                NETMSG_PUSHS16(0);
            }

            if (thing->renderData.amputatedJoints) {

                int numJoints = 0;
                for (int i = 0; i < model->numHierarchyNodes; i++) {
                    if (thing->renderData.amputatedJoints[i]) {
                        numJoints++;
                    }
                }
                NETMSG_PUSHS16(numJoints);
                for (int i = 0; i < model->numHierarchyNodes; i++) {
                    if (thing->renderData.amputatedJoints[i]) {
                        NETMSG_PUSHS16(i);
                    }
                }
            }
            else {
                NETMSG_PUSHS16(0);
            }
        }

        switch ( thing->type )
        {
            case SITH_THING_ACTOR:
            case SITH_THING_CORPSE:
            case SITH_THING_PLAYER:
                NETMSG_PUSHU32(thing->actorParams.flags);
                NETMSG_PUSHF32(thing->actorParams.health);
                NETMSG_PUSHF32(thing->actorParams.extraSpeed);
                NETMSG_PUSHVEC3(thing->actorParams.headPYR);
                
                NETMSG_PUSHF32(thing->actorParams.timeLeftLengthChange);
                NETMSG_PUSHF32(thing->actorParams.lightIntensity);
                NETMSG_PUSHS32(thing->actorParams.field_1BC);
                if ( thing->actorParams.pPlayer )
                {
                    NETMSG_PUSHS32(thing->actorParams.pPlayer - jkPlayer_playerInfos);
                    NETMSG_PUSHS32(thing->actorParams.pPlayer->palEffectsIdx1);
                    NETMSG_PUSHS32(thing->actorParams.pPlayer->palEffectsIdx2);
                }
                else
                {
                    NETMSG_PUSHS32(-1);
                }
                if (sithComm_version == 0x7D6) {
                    if (thing->actorParams.pWeaponTemplate) {
                        NETMSG_PUSHS16(1);
                    }
                    else {
                        NETMSG_PUSHS16(0);
                    }
                }
                break;
            case SITH_THING_WEAPON:
                NETMSG_PUSHU32(thing->weaponParams.flags);
                NETMSG_PUSHF32(thing->weaponParams.unk8);
                NETMSG_PUSHS16(thing->weaponParams.numRicochets);
                break;
            case SITH_THING_EXPLOSION:
                NETMSG_PUSHU32(thing->explosionParams.flags);
                break;
            default:
                break;
        }
        if ( thing->moveType == SITH_MT_PHYSICS )
        {
            NETMSG_PUSHU32(thing->physicsParams.flags);
            NETMSG_PUSHVEC3(thing->physicsParams.vel);
            NETMSG_PUSHVEC3(thing->physicsParams.angularVelocity);
        }
        else if ( thing->moveType == SITH_MT_PATH )
        {
            NETMSG_PUSHS16(thing->trackParams.flags);
            NETMSG_PUSHVEC3(thing->trackParams.vel);
            NETMSG_PUSHF32(thing->trackParams.field_1C);
            NETMSG_PUSHF32(thing->trackParams.moveVel);
            NETMSG_PUSHF32(thing->trackParams.field_54);
            NETMSG_PUSHVEC3(thing->trackParams.field_58);
            NETMSG_PUSHVEC3(thing->trackParams.moveFrameDeltaAngles);
            NETMSG_PUSHF32(thing->field_24C);
            NETMSG_PUSHS16(thing->field_250);
            NETMSG_PUSHS16(thing->curframe);
            NETMSG_PUSHS16(thing->field_258);
            NETMSG_PUSHS16(thing->goalframe);
            NETMSG_PUSHMAT34(thing->trackParams.curOrient);
            NETMSG_PUSHVEC3(thing->trackParams.orientation);
            NETMSG_PUSHS16(thing->trackParams.loadedFrames);

            for (int i = 0; i < thing->trackParams.loadedFrames; i++)
            {
                NETMSG_PUSHVEC3(thing->trackParams.aFrames[i].pos);
                NETMSG_PUSHVEC3(thing->trackParams.aFrames[i].rot);
            }
        }
    }
    
    NETMSG_END(DSS_THINGFULLDESC);

    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sendto_id, mpFlags, 1);
}

// MoTS altered
int sithDSSThing_ProcessFullDescription(SithMessage *msg)
{
    int16_t idx; // ebp
    int32_t v8; // ecx
    SithThing* thing;
    SithSector* v11;
    int type;


    NETMSG_IN_START(msg);

    if ( sithNet_isMulti && (g_submodeFlags & 8) == 0 )
        return 0;

    idx = NETMSG_POPS16();
    if ( idx >= sithWorld_g_pCurrentWorld->numThingsLoaded )
        return 0;

    if ( sithWorld_g_pCurrentWorld->aThings[idx].type )
        sithThing_RemoveThing(&sithWorld_g_pCurrentWorld->aThings[idx]);

    // Only bump the high-water mark; do NOT clobber the destination slot.
    // The original game (JK.EXE @ 0x004F46F0) keeps these as two separate locals:
    // the packet's idx is always the slot the thing is written to, while a
    // throwaway temporary is used to raise numThings = max(numThings, idx).
    // An earlier decompile merged the two into `idx`, so whenever
    // numThings > idx the received thing was written to aThings[numThings]
    // instead of aThings[idx]. A projectile spawned while a player is joining
    // inflates numThings, which misroutes the FullDesc of every static thing still
    // streaming through the join sync, corrupting the guid<->slot mapping and
    // causing remote aThings to teleport.
    if ( sithWorld_g_pCurrentWorld->numThings < idx )
        sithWorld_g_pCurrentWorld->numThings = idx;

    type = NETMSG_POPS16();
    if ( !type )
        return 1;

    thing = &sithWorld_g_pCurrentWorld->aThings[idx];
    sithThing_Reset(thing);
    v8 = NETMSG_POPS16();

    if ( v8 >= sithWorld_g_pCurrentWorld->numThingTemplates )
        return 0;

    sithThing_SetThingBasedOn(thing, &sithWorld_g_pCurrentWorld->aThingTemplates[v8]);

    thing->signature = NETMSG_POPS32();
    thing->guid = NETMSG_POPS32();
    thing->type = type;
    //thing->controlType = type; // Added: why is this needed?
    thing->position = NETMSG_POPVEC3();
    thing->orient.rvec = NETMSG_POPVEC3();
    thing->orient.lvec = NETMSG_POPVEC3();
    thing->orient.uvec = NETMSG_POPVEC3();
    int sectorIdx = NETMSG_POPS16();
    v11 = sithSector_GetPtrFromIdx(sectorIdx);
    if ( v11 )
        sithThing_SetSector(thing, v11, 1);

    thing->flags = NETMSG_POPU32();
    thing->msecLifeLeft = NETMSG_POPS32();
    thing->timer = NETMSG_POPS32();
    thing->msecNextPulseTime = NETMSG_POPS32();
    thing->msecPulseInterval = NETMSG_POPS32();
    thing->userval = NETMSG_POPF32();
    thing->renderData.curGeoMode = (rdGeoMode_t)NETMSG_POPU8();
    thing->collide = NETMSG_POPS16();
    thing->collideSize = NETMSG_POPF32();
    thing->light = NETMSG_POPF32();
    thing->jkFlags = NETMSG_POPU32();

    if ( thing->flags & SITH_TF_CAPTURED )
    {
        thing->pCog = sithCog_GetCogByIndex(NETMSG_POPS16());
        thing->pCaptureCog = sithCog_GetCogByIndex(NETMSG_POPS16());
    }

    // MOTS added
    if (sithComm_version == 0x7D6 && thing->renderData.type == RD_THING_MODEL3) {
        thing->unk = NETMSG_POPS16();

        rdModel3* model = thing->renderData.model3;
        if (thing->unk) {
            char tmp_model[32+1];
            NETMSG_POPSTR(tmp_model, 0x20);
            int unused = NETMSG_POPS16();
            rdModel3* pModel = sithModel_Load(tmp_model, 0);
            sithThing_SetThingModel(thing, pModel);

            model = pModel;
        }

        int numJoints = NETMSG_POPS16();
        if (model && numJoints > 0) {
            for (int i = 0; i < numJoints; i++)
            {
                int val = NETMSG_POPS16();
                if (thing->renderData.amputatedJoints && (uint32_t)val < model->numHierarchyNodes) {
                    thing->renderData.amputatedJoints[val] = 1;
                }
            }
        }
    }

    int playerInfo_idx = -1;
    switch ( thing->type )
    {
        case SITH_THING_ACTOR:
        case SITH_THING_CORPSE:
        case SITH_THING_PLAYER:
            thing->actorParams.flags = NETMSG_POPU32();
            thing->actorParams.health = NETMSG_POPF32();
            thing->actorParams.extraSpeed = NETMSG_POPF32();
            thing->actorParams.headPYR = NETMSG_POPVEC3();
            
            thing->actorParams.timeLeftLengthChange = NETMSG_POPF32();
            thing->actorParams.lightIntensity = NETMSG_POPF32();
            thing->actorParams.field_1BC = NETMSG_POPS32();
            
            playerInfo_idx = NETMSG_POPS32();
            
            if ( playerInfo_idx >= 0 && playerInfo_idx < 32 )
            {
                thing->actorParams.pPlayer = &jkPlayer_playerInfos[playerInfo_idx];
                thing->actorParams.pPlayer->palEffectsIdx1 = NETMSG_POPS32();
                thing->actorParams.pPlayer->palEffectsIdx2 = NETMSG_POPS32();
            }

            // MOTS added
            if (sithComm_version == 0x7D6) {
                if (!NETMSG_POPS16()) {
                    thing->actorParams.pWeaponTemplate = NULL;
                }
            }
            break;
        case SITH_THING_WEAPON:
            thing->weaponParams.flags = NETMSG_POPU32();
            thing->weaponParams.unk8 = NETMSG_POPF32();
            thing->weaponParams.numRicochets = NETMSG_POPS16();
            break;
        case SITH_THING_EXPLOSION:
            thing->explosionParams.flags = NETMSG_POPU32();
            break;
        default:
            break;
    }
    if ( thing->moveType == SITH_MT_PHYSICS )
    {
        thing->physicsParams.flags = NETMSG_POPU32();
        thing->physicsParams.vel = NETMSG_POPVEC3();
        thing->physicsParams.angularVelocity = NETMSG_POPVEC3();
    }
    else if ( thing->moveType == SITH_MT_PATH )
    {
        thing->trackParams.flags = NETMSG_POPS16();
        thing->trackParams.vel = NETMSG_POPVEC3();
        thing->trackParams.field_1C = NETMSG_POPF32();
        thing->trackParams.moveVel = NETMSG_POPF32();
        thing->trackParams.field_54 = NETMSG_POPF32();
        thing->trackParams.field_58 = NETMSG_POPVEC3();
        thing->trackParams.moveFrameDeltaAngles = NETMSG_POPVEC3();
        thing->field_24C = NETMSG_POPF32();
        thing->field_250 = NETMSG_POPS16();
        thing->curframe = NETMSG_POPS16();
        thing->field_258 = NETMSG_POPS16();
        thing->goalframe = NETMSG_POPS16();
        thing->trackParams.curOrient = NETMSG_POPMAT34();
        thing->trackParams.orientation = NETMSG_POPVEC3();
        thing->trackParams.loadedFrames = NETMSG_POPS16();

        if (thing->trackParams.sizeFrames && thing->trackParams.loadedFrames < 0) {
            stdPlatform_Printf("OpenJKDF2: Serialized thing has underflowed trackParams.loadedFrames 0x%x, size 0x%x\n", thing->trackParams.loadedFrames, thing->trackParams.sizeFrames);
            return 0;
        }
        else if (!thing->trackParams.sizeFrames && thing->trackParams.loadedFrames < 0) {
            stdPlatform_Printf("OpenJKDF2: Serialized thing has underflowed trackParams.loadedFrames 0x%x, size 0x%x, recovering?\n", thing->trackParams.loadedFrames, thing->trackParams.sizeFrames);
#ifdef SITH_DEBUG_STRUCT_NAMES
            stdPlatform_Printf("OpenJKDF2: Template ID %x, %s\n", v8, sithWorld_g_pCurrentWorld->aThingTemplates[v8].aName);
#endif
            thing->trackParams.loadedFrames = thing->trackParams.sizeFrames;
        }

        if ( thing->trackParams.loadedFrames )
        {
            // TODO: verify this doesn't leak memory
            thing->trackParams.sizeFrames = thing->trackParams.loadedFrames;

            // Prevent memleaks
            if (thing->trackParams.aFrames) {
                SITH_FREE(thing->trackParams.aFrames);
            }
            thing->trackParams.aFrames = (SithPathFrame*)SITH_ALLOC(sizeof(SithPathFrame) * thing->trackParams.sizeFrames);
        }

        for (int i = 0; i < thing->trackParams.loadedFrames; i++)
        {
            rdVector3 tmp1 = NETMSG_POPVEC3();
            rdVector3 tmp2 = NETMSG_POPVEC3();
            if (thing->trackParams.aFrames) {
                thing->trackParams.aFrames[i].pos = tmp1;
                thing->trackParams.aFrames[i].rot = tmp2;
            }
        }
    }
    sithThing_Initialize(thing);
    return 1;
}

void sithDSSThing_PathMove(SithThing *pThing, int16_t a2, flex32_t a3, int a4, int sendtoId, int mpFlags)
{
    rdVector3 out;

    if (!pThing || pThing->moveType != SITH_MT_PATH || !pThing->type )
        return;
    if (!pThing->sector)
        return;

    NETMSG_START;

    NETMSG_PUSHS32(a4);
    NETMSG_PUSHS32(pThing->guid);
    NETMSG_PUSHU32(jkPlayer_currentTickIdx);
    NETMSG_PUSHS16(pThing->sector->id);
    NETMSG_PUSHVEC3(pThing->position);
    rdMatrix_ExtractAngles34(&pThing->orient, &out);
    NETMSG_PUSHVEC3(out);
    NETMSG_PUSHS16(a2);
    NETMSG_PUSHF32(a3);

    NETMSG_END(DSS_PATHMOVE);

    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sendtoId, mpFlags, 1);
}

int sithDSSThing_ProcessPathMove(SithMessage *msg)
{
    NETMSG_IN_START(msg);

    int arg0 = NETMSG_POPS32();
    SithThing* pThing = sithThing_GetGuidThing(NETMSG_POPS32());
    if ( !pThing || pThing->moveType != SITH_MT_PATH )
        return 0;

    uint32_t arg2 = NETMSG_POPU32();
    if ( pThing->field_260 <= arg2 )
    {
        pThing->field_260 = arg2;
        SithSector* pSector = sithSector_GetPtrFromIdx(NETMSG_POPS16());
        if ( !pSector )
            return 0;

        pThing->position = NETMSG_POPVEC3();
        sithThing_SetSector(pThing, pSector, 0);
        rdVector3 lookAngles = NETMSG_POPVEC3();
        
        rdMatrix_BuildRotate34(&pThing->orient, &lookAngles);
        int arg9 = NETMSG_POPS16();
        flex32_t arg10 = NETMSG_POPF32();

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

void sithDSSThing_Attachment(SithThing *thing, int sendto_id, int mpFlags, int a4)
{
    NETMSG_START;
    
    NETMSG_PUSHS32(thing->guid);
    NETMSG_PUSHU16(thing->attach_flags);

    if (thing->attach_flags & SITH_ATTACH_SURFACE)
    {
        NETMSG_PUSHU16(thing->attachedSurface->index);
    }
    else if (thing->attach_flags & (SITH_ATTACH_THING|SITH_ATTACH_THINGFACE))
    {
        SithThing* v7 = (SithThing *)thing->attachedThing;
        NETMSG_PUSHS32(v7->guid)
        if ( (thing->attach_flags & SITH_ATTACH_THINGFACE) != 0 )
        {
            NETMSG_PUSHS16(((intptr_t)thing->attachedSufaceInfo - (intptr_t)v7->renderData.model3->geosets[0].meshes->faces) / sizeof(sithSurfaceInfo));
        }
        else
        {
           NETMSG_PUSHVEC3(thing->field_4C);
        }
    }
    
    NETMSG_END(DSS_SYNCTHINGATTACHMENT);
    
    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sendto_id, mpFlags, a4);
}

int sithDSSThing_ProcessAttachment(SithMessage *msg)
{    
    NETMSG_IN_START(msg);

    SithThing* v1 = sithThing_GetGuidThing(NETMSG_POPS32());
    if ( !v1 )
        return 0;
    int v3 = NETMSG_POPU16();
    if (v3 & SITH_ATTACH_SURFACE)
    {
        SithSurface* v5 = sithSurface_sub_4E63B0(NETMSG_POPS16());
        if ( v5 )
        {
            sithThing_AttachThingToSurface(v1, v5, 1);
            v1->attach_flags = v3;
            return 1;
        }
        return 0;
    }
    if (v3 & (SITH_ATTACH_THING|SITH_ATTACH_THINGFACE))
    {
        SithThing* v9 = sithThing_GetGuidThing(NETMSG_POPS32());
        if ( !v9 )
            return 0;
        if (v3 & SITH_ATTACH_THINGFACE)
        {
            sithThing_AttachThingToThingFace(
                v1,
                v9,
                &v9->renderData.model3->geosets[0].meshes->faces[NETMSG_POPS16()],
                v9->renderData.model3->geosets[0].meshes->aVertices,
                1);
            v1->attach_flags = v3;
            return 1;
        }
        else
        {
            sithThing_AttachThingToThing(v1, v9);
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
void sithDSSThing_Take(SithThing *pItemThing, SithThing *pActor, int mpFlags)
{
    int itemThingId; // edi
    int actorId; // edx
    SithThing *pItemThing2; // esi
    SithThing *pActor2; // edi

    itemThingId = pItemThing->guid;

    if (!pActor) // MOTS added
        actorId = -1;
    else
        actorId = pActor->guid;

    sithComm_netMsgTmp.pktData[0] = itemThingId;
    sithComm_netMsgTmp.pktData[1] = actorId;
    sithComm_netMsgTmp.netMsg.flag_maybe = 0;
    sithComm_netMsgTmp.netMsg.cogMsgId = DSS_TAKEITEM1;
    sithComm_netMsgTmp.netMsg.msg_size = 8;
    if ( !sithNet_isServer )
    {
        sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sithNet_serverNetId, mpFlags, 1);
        return;
    }
    pItemThing2 = sithThing_GetGuidThing(itemThingId);
    if ( !pItemThing2 && sithNet_isServer )
    {
        sithComm_netMsgTmp.pktData[0] = itemThingId;
        sithComm_netMsgTmp.netMsg.flag_maybe = 0;
        sithComm_netMsgTmp.netMsg.cogMsgId = DSS_DESTROYTHING;
        sithComm_netMsgTmp.netMsg.msg_size = 4;
        sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sithComm_netMsgTmp.netMsg.idx, 255, 1);
        return;
    }
    pActor2 = sithThing_GetGuidThing(sithComm_netMsgTmp.pktData[1]);
    if ( pItemThing2 && pActor2 )
    {
        if ( sithComm_netMsgTmp.netMsg.cogMsgId != DSS_TAKEITEM1 )
        {
            sithItem_SetItemTaken(pItemThing2, pActor2, 1);
            return;
        }
        if ( pItemThing2->type == SITH_THING_ITEM && (pItemThing2->flags & (SITH_TF_DISABLED|SITH_TF_DESTROYED)) == 0 )
        {
            sithComm_netMsgTmp.netMsg.cogMsgId = DSS_TAKEITEM2;
            sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, -1, 1, 1);
            sithItem_SetItemTaken(pItemThing2, pActor2, 1);
            return;
        }
    }
}

int sithDSSThing_ProcessTake(SithMessage *msg)
{
    int v1; // ebx
    SithThing *v2; // edi
    SithThing *v4; // eax
    int v6; // [esp-Ch] [ebp-1Ch]

    v1 = msg->pktData[0];
    v2 = sithThing_GetGuidThing(v1);
    if ( !v2 && sithNet_isServer )
    {
        v6 = msg->netMsg.idx;
        sithComm_netMsgTmp.pktData[0] = v1;
        sithComm_netMsgTmp.netMsg.flag_maybe = 0;
        sithComm_netMsgTmp.netMsg.cogMsgId = DSS_DESTROYTHING;
        sithComm_netMsgTmp.netMsg.msg_size = 4;
        sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, v6, 255, 1);
        return 0;
    }
    if (msg->pktData[1] == -1) // MOTS added
        v4 = NULL;
    else
        v4 = sithThing_GetGuidThing(msg->pktData[1]);
    if ( v2 /*&& v4*/ ) // MOTS removed nullptr check
    {
        if ( msg->netMsg.cogMsgId == DSS_TAKEITEM1 )
        {
            if ( v2->type != SITH_THING_ITEM || (v2->flags & (SITH_TF_DISABLED|SITH_TF_DESTROYED)) != 0 )
                return 1;
            msg->netMsg.cogMsgId = DSS_TAKEITEM2;
            sithComm_SendMsgToPlayer(msg, -1, 1, 1);
        }
        sithItem_SetItemTaken(v2, v4, 1);
        return 1;
    }
    return 0;
}

void sithDSSThing_CreateThing(SithThing *pCreateThingTemplate, SithThing *pThing, SithThing *pThing2, SithSector *pSector, rdVector3 *pPos, rdVector3 *pRot, int mpFlags, int bSync)
{
    NETMSG_START;

    NETMSG_PUSHS16(pCreateThingTemplate->idx);
    if ( pThing2 )
    {
        NETMSG_PUSHS32(pThing2->guid);
    }
    else
    {
        NETMSG_PUSHS32(-1);
        NETMSG_PUSHS32(pSector->id);
        NETMSG_PUSHVEC3(*pPos);
        NETMSG_PUSHVEC3(*pRot);
    }
    NETMSG_PUSHS32(pThing->guid);

    NETMSG_END(DSS_CREATETHING);
    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, -1, mpFlags, bSync);
}

int sithDSSThing_ProcessCreateThing(SithMessage *msg)
{
    rdMatrix34 lookOrient;

    NETMSG_IN_START(msg);

    SithThing* pCreated = NULL;
    SithThing* pThing = sithTemplate_GetTemplateByIndex(NETMSG_POPS16());
    if ( pThing )
    {
        int pThing2Id = NETMSG_POPS32();
        if ( pThing2Id < 0 )
        {
            SithSector* pSector = sithSector_GetPtrFromIdx(NETMSG_POPS16());
            if ( !pSector )
                return 0;
            rdVector3 pos = NETMSG_POPVEC3();
            rdVector3 rot = NETMSG_POPVEC3();
            rdMatrix_BuildRotate34(&lookOrient, &rot);
            pCreated = sithThing_CreateThingAtPos(pThing, &pos, &lookOrient, pSector, 0);
        }
        else
        {
            SithThing* pThing2 = sithThing_GetGuidThing(pThing2Id);
            if ( !pThing2 )
                return 0;
            pCreated = sithThing_CreateThing(pThing, pThing2);
        }

        if ( pCreated )
        {
            pCreated->guid = NETMSG_POPS32();
            pCreated->flags |= SITH_TF_INVULN;
            return 1;
        }
    }
    return 0;
}

void sithDSSThing_DestroyThing(int idx, int sendtoId)
{
    NETMSG_START;

    NETMSG_PUSHS32(idx);
    NETMSG_END(DSS_DESTROYTHING);

    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sendtoId, 255, 1);
}

int sithDSSThing_ProcessDestroyThing(SithMessage *msg)
{
    NETMSG_IN_START(msg);

    SithThing* pThing = sithThing_GetGuidThing(NETMSG_POPS32());
    if ( pThing )
    {
        sithThing_DestroyThing(pThing);
        return 1;
    }
    return 0;
}

void sithDSSThing_MoveToPos(SithThing *pThing, rdVector3 *pPos, SithSector *pSector)
{
    rdVector3 a1; // [esp+8h] [ebp-Ch] BYREF

#ifdef QOL_IMPROVEMENTS
    if ( pThing->moveType == SITH_MT_PHYSICS )
    {
        rdVector_Scale3(&a1, &pThing->physicsParams.vel, 0.25);
    }
    else if (pThing->moveType == SITH_MT_PATH) {
        stdPlatform_Printf("OpenJKDDF2: attempted sithDSSThing_MoveToPos on track thing! This would corrupt state in the original game.\n");
        //rdVector_Scale3(&a1, &pThing->trackParams.vel, 0.25); // TODO: idk if we want this?
    }
    else {
        stdPlatform_Printf("OpenJKDDF2: attempted sithDSSThing_MoveToPos on non-physics thing!\n");
    }
#else
    rdVector_Scale3(&a1, &pThing->physicsParams.vel, 0.25);
#endif

    rdVector_Add3Acc(&a1, pPos);
    rdVector_Sub3Acc(&a1, &pThing->position);
    flex_t v5 = rdVector_Len3(&a1);
    if ( v5 == 0.0 || v5 >= 0.5 )
    {
        rdVector_Copy3(&pThing->position, pPos);
        sithThing_SetSector(pThing, pSector, 0);
    }
    else
    {
#ifdef QOL_IMPROVEMENTS
    if ( pThing->moveType == SITH_MT_PHYSICS )
    {
        rdVector_Scale3(&pThing->physicsParams.vel, &a1, 4.0);
    }
    else if (pThing->moveType == SITH_MT_PATH) {
        stdPlatform_Printf("OpenJKDDF2: attempted sithDSSThing_MoveToPos on track thing! This would corrupt state in the original game.\n");
        //rdVector_Scale3(&a1, &pThing->trackParams.vel, 4.0); // TODO: idk if we want this?
    }
    else {
        stdPlatform_Printf("OpenJKDDF2: attempted sithDSSThing_MoveToPos on non-physics thing!\n");
    }
#else
        rdVector_Scale3(&pThing->physicsParams.vel, &a1, 4.0);
#endif
    }
}

// MOTS added
int sithDSSThing_ProcessMOTSNew1(SithMessage *msg)
{
    int guid;
    SithThing *psVar1;
    SithThing *psVar2;
    SithSector *sector;
    uint32_t uVar3;
    int puVar4;
    rdVector3 local_54;
    rdVector3 local_48;
    rdVector3 local_3c;
    rdMatrix34 local_30;

    if (!Main_bMotsCompat) return 0;

    NETMSG_IN_START(msg);

    psVar1 = sithTemplate_GetTemplateByIndex(NETMSG_POPS16());
    if (psVar1 == NULL) 
    {
        return 0;
    }
    guid = NETMSG_POPS32();
    puVar4 = NETMSG_POPS32();
    if (guid < 0)
    {
        sector = sithSector_GetPtrFromIdx(puVar4);
        if (sector == NULL)
        {
            return 0;
        }
        local_3c = NETMSG_POPVEC3();
        local_54 = NETMSG_POPVEC3();
        rdVector_Zero3(&local_48);

        rdMatrix_BuildRotate34(&local_30,&local_48);

        uVar3 = NETMSG_POPS32();
        psVar2 = sithThing_GetGuidThing(NETMSG_POPS32());
        psVar1 = sithThing_CreateThingAtPos(psVar1,&local_3c,&local_30,sector,psVar2);
        if (!rdVector_IsZero3(&local_54))
        {
            rdVector_Normalize3Acc(&local_54);
            rdMatrix_BuildFromLook34(&psVar1->orient,&local_54);
        }
    }
    else 
    {
        psVar2 = sithThing_GetGuidThing(guid);
        if (psVar2 == NULL)
        {
            return 0;
        }
        psVar1 = sithThing_CreateThing(psVar1,psVar2);
        uVar3 = puVar4;
    }

    if (psVar1 == NULL)
    {
        return 0;
    }
    psVar1->guid = uVar3;
    psVar1->flags |= SITH_TF_INVULN;
    return 1;
}

// MOTS added
void sithDSSThing_SendMOTSNew1(SithThing* pThing1, SithThing* pThing2, SithThing* pThing3, SithSector* pSector, 
    rdVector3* pVec1, rdVector3* pVec2, int mpFlags, int param_8)
{
    if (!Main_bMotsCompat) return;

    NETMSG_START;

    NETMSG_PUSHS16(pThing1->idx);

    if (pThing3 == NULL)
    {
        NETMSG_PUSHS32(-1);
        NETMSG_PUSHS32(pSector->id);
        NETMSG_PUSHVEC3(*pVec1);
        NETMSG_PUSHVEC3(*pVec2);
    }
    else 
    {
        NETMSG_PUSHS32(pThing3->guid);
    }

    SithThing* psVar1 = pThing2->pParent;
    NETMSG_PUSHS32(pThing2->guid);
    NETMSG_PUSHS32(psVar1->guid);

    NETMSG_END(DSS_MOTS_NEW_1);
    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, -1, mpFlags, param_8);
}

