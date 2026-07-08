#include "sithActor.h"

#include "Cog/sithCog.h"
#include "World/sithThing.h"
#include "Engine/sithAnimClass.h"
#include "World/sithSoundClass.h"
#include "Engine/sithPuppet.h"
#include "Engine/sithCollision.h"
#include "Engine/sithPhysics.h"
#include "World/jkPlayer.h"
#include "World/sithThing.h"
#include "World/sithSector.h"
#include "World/sithTemplate.h"
#include "AI/sithAI.h"
#include "AI/sithAIAwareness.h"
#include "AI/sithAIClass.h"
#include "Dss/sithMulti.h"
#include "Dss/sithDSSThing.h"
#include "jk.h"

void sithActor_SetDifficulty(SithThing *pActor)
{
    if ( jkPlayer_setDiff )
    {
        if ( jkPlayer_setDiff == 2 )
        {
            pActor->actorParams.maxHealth = pActor->actorParams.maxHealth * 1.2;
            pActor->actorParams.health = pActor->actorParams.health * 1.2;
        }
    }
    else
    {
        pActor->actorParams.maxHealth = pActor->actorParams.maxHealth * 0.8;
        pActor->actorParams.health = pActor->actorParams.health * 0.8;
    }
}

void sithActor_Update(SithThing *pThing, int msecDeltaTime)
{
    unsigned int v2; // eax
    unsigned int v3; // eax

    // Added
    if (!pThing) return;

    if ( (pThing->actorParams.flags & SITH_AF_BREATHEUNDERWATER) == 0 && (pThing->flags & (SITH_TF_DEAD|SITH_TF_DESTROYED)) == 0 )
    {
        if ( (pThing->physicsParams.flags & SITH_PF_ONWATERSURFACE) != 0 || (pThing->sector && pThing->sector->flags & SITH_SECTOR_UNDERWATER) == 0 ) // Added: Sector check
        {
            v3 = pThing->actorParams.endurance;
            if ( v3 )
            {
                if ( v3 <= 18000 )
                {
                    if ( v3 > 10000 )
                        sithSoundClass_PlayModeRandom(pThing, SITH_SC_BREATH);
                }
                else
                {
                    sithSoundClass_PlayModeRandom(pThing, SITH_SC_GASP);
                }
                pThing->actorParams.endurance = 0;
            }
        }
        else
        {
            v2 = msecDeltaTime + pThing->actorParams.endurance;
            pThing->actorParams.endurance = v2;
            if ( v2 > 20000 )
            {
                sithThing_DamageThing(pThing, pThing, 10.0, SITH_DAMAGE_DROWN);
                pThing->actorParams.endurance -= 2000;
            }
        }
    }
}

// MOTS altered
flex_t sithActor_DamageActor(SithThing *pActor, SithThing *pThing, flex_t damage, int damageType)
{
    SithThing *receiver_; // edi
    flex_d_t v6; // st7
    SithThing *v7; // eax
    flex_t fR; // [esp+0h] [ebp-1Ch]

    // Added: J3D asserts
    SITH_ASSERTREL(pActor && (damage > 0.0f));
    SITH_ASSERTREL(pActor->type == SITH_THING_ACTOR || pActor->type == SITH_THING_PLAYER);

    if ( sithNet_isMulti && (pActor->flags & SITH_TF_INVULN) != 0 )
    {
        receiver_ = pThing;
        goto LABEL_32;
    }
    if ( (pActor->actorParams.flags & SITH_AF_INVULNERABLE) != 0 && damageType != 0x40 )
        return 0.0;
    if ( pActor->actorParams.health <= 0.0 )
        return damage;
    receiver_ = pThing;
    if ( pActor->type == SITH_THING_PLAYER )
    {
        v6 = sithInventory_BroadcastMessage(
                 pActor,
                 SENDERTYPE_THING,
                 pThing->idx,
                 SITH_MESSAGE_DAMAGED,
                 0x10,
                 damage,
                 (flex_t)damageType, // FLEXTODO
                 0.0,
                 0.0);
        damage = v6;
        if ( v6 == 0.0 )
            return 0.0;
    }
    if ( pThing )
    {
        if ( pThing != pActor && pActor->controlType == SITH_CT_AI )
            sithAI_EmitEvent(pActor->actor, SITHAI_MODE_MOVING, (intptr_t)pThing);
        v7 = sithThing_GetThingParent(pThing);
        receiver_ = v7;

        flex_t damageMult = 1.0;
        if ( v7
          && damageType != 0x20
          && damageType != 0x40
          && v7->type == SITH_THING_ACTOR
          && (v7->actorParams.flags & SITH_AF_FULLDAMAGE) == 0
          && pActor->type == SITH_THING_ACTOR )
        {
            damageMult = 0.1;

            // MOTS added: alignment
            if (Main_bMotsCompat
                && pActor->controlType == SITH_CT_AI
                && pActor->actor
                && pActor->actor->pClass
                && v7->controlType == SITH_CT_AI
                && v7->actor
                && v7->actor->pClass) {

                if (v7->actor->pClass->alignment * pActor->actor->pClass->alignment <= -1.0) {
                    damageMult = 0.5;
                }
            }
        }
        damage *= damageMult;
        if ( sithNet_isMulti && (sithNet_MultiModeFlags & MULTIMODEFLAG_2) != 0 && sithPlayer_sub_4C9060(v7, pActor) )
            return 0.0;
    }

    pActor->actorParams.health -= damage;
    if ( pActor == sithPlayer_g_pLocalPlayerThing )
    {
        fR = damage * 0.04;
        sithPlayer_AddDynamicTint(fR, 0.0, 0.0);
    }
    if ( pActor->actorParams.health >= 1.0 )
    {
LABEL_32:
        if ( pActor->pPuppetClass && pActor != receiver_ && damage * 0.05 > _frand() )
            sithPuppet_PlayMode(pActor, SITH_ANIM_HIT, 0);
        sithActor_PlayDamageSoundFx(pActor, damage, damageType);
        return damage;
    }
    if ( sithMessage_g_outputstream )
        sithDSSThing_Death(pActor, receiver_, 0, -1, 255);
    sithActor_KillActor(pActor, receiver_, damageType);
    return damage - pActor->actorParams.health;
}

void sithActor_PlayDamageSoundFx(SithThing *pThing, flex_t amount, int hurtType)
{
    if ( pThing->actorParams.health <= 0.0 || amount < 3.0 ) return;


    flex_t hurt_vol = amount / pThing->actorParams.health * 1.5;
    if (hurt_vol >= 0.01)
    {
        if (hurt_vol < 0.0)
        {
            hurt_vol = 0.0;
        }
        else if (hurt_vol > 1.0)
        {
            hurt_vol = 1.0;
        }
        switch ( hurtType )
        {
            case SITH_DAMAGE_ENERGY:
                sithSoundClass_PlayMode(pThing, SITH_SC_HURTENERGY, hurt_vol);
                break;
            case SITH_DAMAGE_FIRE:
                sithSoundClass_PlayMode(pThing, SITH_SC_HURTFIRE, hurt_vol);
                break;
            case SITH_DAMAGE_FORCE:
                sithSoundClass_PlayMode(pThing, SITH_SC_HURTMAGIC, hurt_vol);
                break;
            case SITH_DAMAGE_SABER:
                sithSoundClass_PlayMode(pThing, SITH_SC_HURTSPECIAL, hurt_vol);
                break;
            case SITH_DAMAGE_DROWN:
                sithSoundClass_PlayMode(pThing, SITH_SC_DROWNING, hurt_vol);
                break;
            default:
                sithSoundClass_PlayMode(pThing, SITH_SC_HURTIMPACT, hurt_vol);
                break;
        }
    }
}

// MOTS altered
void sithActor_KillActor(SithThing *pThing, SithThing *pSrcThing, int damageType)
{
    SithThing *v8; // eax
    uint32_t v10; // edx

    if (pThing->flags & SITH_TF_DEAD) return;


    pThing->actorParams.health = 0.0;
    if ( (pThing->flags & SITH_TF_CAPTURED) == 0 || (sithCog_ThingSendMessage(pThing, pSrcThing, SITH_MESSAGE_KILLED), (pThing->flags & SITH_TF_DESTROYED) == 0) )
    {
        sithSoundClass_StopSound(pThing, 0);

        // MOTS added: quiet death (sithCogFunctionPlayer_KillPlayerQuietly)
        if (!Main_bMotsCompat || damageType != 12345678) {
            if ( damageType == 0x20 )
            {
                sithSoundClass_PlayModeRandom(pThing, SITH_SC_DROWNED);
            }
            else if ( damageType == 0x40 )
            {
                sithSoundClass_PlayModeRandom(pThing, SITH_SC_SPLATTERED);
            }
            else if ( (pThing->flags & SITH_TF_WATER) != 0 )
            {
                sithSoundClass_PlayModeRandom(pThing, SITH_SC_DEATHUNDER);
            }
            else if ( pThing->actorParams.health >= -10.0 )
            {
                sithSoundClass_PlayModeRandom(pThing, SITH_SC_DEATH1);
            }
            else
            {
                sithSoundClass_PlayModeRandom(pThing, SITH_SC_DEATH2);
            }
        }
        sithActor_SetHeadPYR(pThing, &rdroid_zeroVector3);

        // MOTS added: quiet death
        if (!Main_bMotsCompat || damageType != 12345678) {
            sithAIAwareness_CreateTransmittingEvent(pThing->sector, &pThing->position, 0, 5.0, pSrcThing);
        }
        if ( pThing->type == SITH_THING_PLAYER )
            sithPlayer_PlayerKilledAction(pThing, pSrcThing);

        // MOTS added: quiet death
        if (!Main_bMotsCompat || damageType != 12345678) {
            if ( pThing == sithWorld_g_pCurrentWorld->pCameraFocusThing )
                sithCamera_SetCurrentCamera(&sithCamera_g_aCameras[5]);

            // MOTS added: quiet death
            if (!Main_bMotsCompat || damageType != 12345678) {
                if ( pThing->pPuppetClass )
                {
                    sithPuppet_ResetTrack(pThing);
                    if ( pThing->actorParams.health >= -10.0 )
                        pThing->puppet->field_18 = sithPuppet_PlayMode(pThing, SITH_ANIM_DEATH, 0);
                    else
                        pThing->puppet->field_18 = sithPuppet_PlayMode(pThing, SITH_ANIM_DEATH2, 0);
                }
            }
        }

        pThing->physicsParams.flags &= ~SITH_PF_CROUCHING;
        if ( pThing->type != SITH_THING_PLAYER )
        {
            int old_typeflags = pThing->actorParams.flags;

            // MOTS added: quiet death
            if ((!Main_bMotsCompat || damageType != 12345678) && (old_typeflags & SITH_AF_EXPLODE_WHEN_KILLED) && pThing->actorParams.pExplodeTemplate)
            {
                sithThing_CreateThingAtPos(pThing->actorParams.pExplodeTemplate, &pThing->position, &pThing->orient, pThing->sector, 0);
                sithThing_DestroyThing(pThing);
            }
            else
            {
                if (old_typeflags & SITH_AF_BREATHEUNDERWATER) {
                    pThing->physicsParams.buoyancy = 0.3;
                }
                else if (Main_bMotsCompat) {
                    pThing->physicsParams.buoyancy = 0.01; // MOTS added
                }
                if (pThing->physicsParams.flags & SITH_PF_FLY)
                {
                    sithActor_DestroyActor(pThing);
                }
                else
                {
                    pThing->msecLifeLeft = 1000;
                }
            }
        }
    }
}

int sithActor_SurfaceCollisionHandler(SithThing *pThing, SithSurface *pSurface, SithCollision *pHitStack)
{
    int ret = sithCollision_HandleThingHitSurface(pThing, pSurface, pHitStack);
    if (ret && pThing->controlType == SITH_CT_AI) {
        sithAI_EmitEvent(pThing->actor, SITHAI_MODE_ACTIVE, 0);
    }
    return ret;
}

void sithActor_SetHeadPYR(SithThing *pThing, const rdVector3 *headAngles)
{
    SithPuppetClass *pAnimClass; // eax
    rdVector3 *v4; // ebx
    int torsoIdx; // esi
    int primaryWeapJointIdx; // ebp
    int v7; // edx
    int neckIdx; // ecx
    int v9; // eax
    int v10; // edx
    int v11; // edi
    int v12; // ecx
    int v13; // ecx
    int v14; // ecx

    // Added: J3D assert
    SITH_ASSERTREL(pThing && headAngles && ((pThing->type == SITH_THING_ACTOR) || (pThing->type == SITH_THING_PLAYER) || (pThing->type == SITH_THING_CORPSE)));

    pThing->actorParams.flags &= ~SITH_AF_VIEWCENTRED;
    pThing->actorParams.headPYR = *headAngles;
    pAnimClass = pThing->pPuppetClass;
    if (!pAnimClass || pThing->renderData.type != RD_THING_MODEL3) return;


    v4 = pThing->renderData.hierarchyNodes2;
    if (v4)
    {
        torsoIdx = pAnimClass->aJoints[JOINTTYPE_TORSO];
        primaryWeapJointIdx = pAnimClass->aJoints[JOINTTYPE_PRIMARYWEAPJOINT];
        v7 = pThing->renderData.model3->numHNodes;
        neckIdx = pAnimClass->aJoints[JOINTTYPE_NECK];
        v9 = pAnimClass->aJoints[JOINTTYPE_SECONDARYWEAPJOINT];
        v10 = v7 - 1;
        if ( neckIdx < 0 )
        {
            v11 = 0;
        }
        else
        {
            v11 = neckIdx <= v10;
        }
        if ( v11 ) {
            v4[neckIdx].x = headAngles->x * 0.5;
        }
        if ( torsoIdx < 0 ) {
            v12 = 0;
        }
        else {
            v12 = torsoIdx <= v10;
        }
        if ( v12 ) {
            v4[torsoIdx].x = headAngles->x * 0.5;
        }
        if ( primaryWeapJointIdx < 0 ) {
            v13 = 0;
        }
        else {
            v13 = primaryWeapJointIdx <= v10;
        }
        if ( v13 ) {
            v4[primaryWeapJointIdx].x = headAngles->x * 0.3;
        }
        if ( v9 < 0 ) {
            v14 = 0;
        }
        else {
            v14 = v9 <= v10;
        }
        if ( v14 ) {
            v4[v9].x = headAngles->x * 0.3;
        }
    }
}

int sithActor_ActorCollisionHandler(SithThing *pSrcThing, SithThing *pThing, SithCollision *pCollision, int a4)
{
    int ret = sithCollision_ThingCollisionHandler(pSrcThing, pThing, pCollision, a4);
    if (ret)
    {
        if (pSrcThing->controlType == SITH_CT_AI && pSrcThing->actor)
        {
            sithAI_EmitEvent(pSrcThing->actor, SITHAI_MODE_SEARCHING, (intptr_t)pThing);
        }
        if (pThing->controlType == SITH_CT_AI && pThing->actor)
        {
            sithAI_EmitEvent(pThing->actor, SITHAI_MODE_SEARCHING, (intptr_t)pSrcThing);
        }
    }
    return ret;
}

void sithActor_UpdateAimJoints(SithThing* pThing)
{
    // Added: J3D assert
    SITH_ASSERTREL(pThing && ((pThing->type == SITH_THING_ACTOR) || (pThing->type == SITH_THING_PLAYER) || (pThing->type == SITH_THING_CORPSE)));
    SithPuppetClass* pAnimClass = pThing->pPuppetClass;
    if (pAnimClass)
    {
        int pitch_idx = pAnimClass->aJoints[JOINTTYPE_TURRETPITCH];
        int yaw_idx = pAnimClass->aJoints[JOINTTYPE_TURRETYAW];
        if (pitch_idx >= 0)
            pThing->renderData.hierarchyNodes2[pitch_idx].x = pThing->actorParams.headPYR.x;
        if (yaw_idx >= 0)
            pThing->renderData.hierarchyNodes2[yaw_idx].y = pThing->actorParams.headPYR.y;
    }
}

// MOTS altered
int sithActor_thing_anim_blocked(SithThing *a1, SithThing *thing2, SithCollision *a3)
{
    rdVector3 a1a; // [esp+10h] [ebp-54h] BYREF
    rdVector3 v18; // [esp+1Ch] [ebp-48h] BYREF
    rdVector3 vAngs; // [esp+28h] [ebp-3Ch] BYREF
    rdMatrix34 out; // [esp+34h] [ebp-30h] BYREF

    if ( _frand() > thing2->actorParams.chance )
        return 0;

    rdVector_Sub3(&a1a, &a1->position, &thing2->position);
    rdVector_Copy3(&vAngs, &a1->physicsParams.vel);
    rdVector_Normalize3Acc(&a1a);
    rdMatrix_Copy34(&out, &thing2->orient);

    if ( thing2->type == SITH_THING_ACTOR || thing2->type == SITH_THING_PLAYER )
        rdMatrix_PreRotate34(&out, &thing2->actorParams.headPYR);

    rdVector_Copy3(&v18, &out.lvec);
    rdVector_Normalize3Acc(&v18);
    if ( rdVector_Dot3(&v18, &a1a) < thing2->actorParams.fov )
        return 0;
    if (!sithCollision_ThingCollisionHandler(a1, thing2, a3, 0))
        return 0;

    rdVector_Neg3(&a1->physicsParams.vel, &vAngs);
    if ( _frand() < thing2->actorParams.error )
    {
        rdVector_Zero3(&vAngs);
        vAngs.x = (_frand() - 0.5) * 90.0;
        vAngs.y = (_frand() - 0.5) * 90.0;
        rdVector_Rotate3Acc(&a1->physicsParams.vel, &vAngs);
    }
    rdVector_Normalize3(&a1->orient.lvec, &a1->physicsParams.vel);
    a1->orient.rvec.x = (a1->orient.lvec.y * 1.0) - (a1->orient.lvec.z * 0.0);
    a1->orient.rvec.y = (a1->orient.lvec.z * 0.0) - (a1->orient.lvec.x * 1.0);
    a1->orient.rvec.z = (a1->orient.lvec.x * 0.0) - (a1->orient.lvec.y * 0.0);
    rdVector_Normalize3Acc(&a1->orient.rvec);
    a1->orient.uvec.x = a1->orient.rvec.y * a1->orient.lvec.z - a1->orient.rvec.z * a1->orient.lvec.y;
    a1->orient.uvec.y = a1->orient.rvec.z * a1->orient.lvec.x - a1->orient.lvec.z * a1->orient.rvec.x;
    a1->orient.uvec.z = a1->orient.lvec.y * a1->orient.rvec.x - a1->orient.rvec.y * a1->orient.lvec.x;
    sithSoundClass_PlayModeRandom(a1, SITH_SC_DEFLECTED);
    if ( thing2->orient.uvec.x * a1a.x + thing2->orient.uvec.y * a1a.y + thing2->orient.uvec.z * a1a.z <= 0.0 )
        sithPuppet_PlayMode(thing2, SITH_ANIM_BLOCK2, 0);
    else
        sithPuppet_PlayMode(thing2, SITH_ANIM_BLOCK, 0);
    a1->actorParams.flags &= ~SITH_AF_CANROTATEHEAD;
    a1->pParent = thing2;
    a1->parentSignature = thing2->signature;
    sithCog_ThingSendMessage(thing2, 0, SITH_MESSAGE_BLOCKED);
    return 1;
}

void sithActor_DestroyActor(SithThing *pActor)
{
    pActor->flags |= SITH_TF_DEAD;
    sithThing_DetachAttachedThings(pActor);
    pActor->type = SITH_THING_CORPSE;
    pActor->physicsParams.flags &= ~(SITH_PF_FLY|SITH_PF_800|SITH_PF_100|SITH_PF_WALLSTICK);
    pActor->physicsParams.flags |= (SITH_PF_FLOORSTICK|SITH_PF_ALIGNSURFACE|SITH_PF_USEGRAVITY);
    pActor->msecLifeLeft = jkPlayer_bKeepCorpses ? -1 : 20000; // Added
    sithPhysics_FindFloor(pActor, 0);
}

void sithActor_DestroyCorpse(SithThing *pThing)
{
    // Added: retain corpses option
    if (jkPlayer_bKeepCorpses || pThing->renderFrame + 1 == jkPlayer_currentTickIdx ) {
        pThing->msecLifeLeft = 3000;
    }
    else {
        sithThing_DestroyThing(pThing);
    }
}

int sithActor_ParseArg(StdConffileArg *pArg, SithThing *pThing, unsigned int adjNum)
{
    int result; // eax
    flex_d_t v6; // st7
    flex_d_t v9; // st7
    flex_d_t v10; // st7
    flex_d_t v11; // st7
    flex_d_t v12; // st7
    int v13; // eax
    flex_d_t v19; // st7
    flex_d_t v20; // st7
    flex_d_t v21; // st7
    flex32_t tmp, vx, vy, vz;
    int tmpInt;

    switch (adjNum)
    {
        case THINGPARAM_TYPEFLAGS:
            if ( _sscanf(pArg->value, "%x", &tmpInt) != 1 )
                goto LABEL_38;
            pThing->actorParams.flags = tmpInt;
            return 1;
        case THINGPARAM_HEALTH:
            tmp = _atof(pArg->value);
            if ( tmp < 0.0 )
                goto LABEL_38;

            pThing->actorParams.health = tmp;
            if ( tmp < (flex_d_t)pThing->actorParams.maxHealth )
                pThing->actorParams.maxHealth = pThing->actorParams.maxHealth;
            else
                pThing->actorParams.maxHealth = tmp;
            return 1;
        case THINGPARAM_MAXTHRUST:
            v10 = _atof(pArg->value);
            if ( v10 < 0.0 )
                return 0;
            result = 1;
            pThing->actorParams.maxThrust = v10;
            return result;
        case THINGPARAM_MAXROTTHRUST:
            v11 = _atof(pArg->value);
            if ( v11 < 0.0 )
                return 0;
            result = 1;
            pThing->actorParams.maxRotVelocity = v11;
            return result;
        case THINGPARAM_JUMPSPEED:
            v12 = _atof(pArg->value);
            if ( v12 < 0.0 )
                return 0;
            result = 1;
            pThing->actorParams.jumpSpeed = v12;
            return result;
        case THINGPARAM_WEAPON:
            pThing->actorParams.pWeaponTemplate = sithTemplate_GetTemplate(pArg->value);
            return 1;
        case THINGPARAM_WEAPON2:
            pThing->actorParams.templateWeapon2 = sithTemplate_GetTemplate(pArg->value);
            return 1;
        case THINGPARAM_EXPLODE:
            pThing->actorParams.pExplodeTemplate = sithTemplate_GetTemplate(pArg->value);
            return 1;
        case THINGPARAM_MAXHEALTH:
            v9 = _atof(pArg->value);
            if ( v9 < 0.0 )
                return 0;
            result = 1;
            pThing->actorParams.maxHealth = v9;
            pThing->actorParams.health = v9;
            return result;
        case THINGPARAM_EYEOFFSET:
            v13 = _sscanf(
                      pArg->value,
                      "(%f/%f/%f)",
                      &vx, &vy, &vz);
            pThing->actorParams.eyeOffset.x = vx;
            pThing->actorParams.eyeOffset.y = vy;
            pThing->actorParams.eyeOffset.z = vz;
            if ( v13 != 3 )
                goto LABEL_38;
            result = 1;
            break;
        case THINGPARAM_MINHEADPITCH:
            result = _sscanf(pArg->value, "%f", &tmp);
            if ( result != 1 )
                goto LABEL_38;
            pThing->actorParams.minHeadPitch = tmp;
            break;
        case THINGPARAM_MAXHEADPITCH:
            result = _sscanf(pArg->value, "%f", &tmp);
            if ( result != 1 )
                goto LABEL_38;
            pThing->actorParams.maxHeadPitch = tmp;
            break;
        case THINGPARAM_FIREOFFSET:
            v13 = _sscanf(
                      pArg->value,
                      "(%f/%f/%f)",
                      &vx, &vy, &vz);
            if ( v13 != 3 )
                goto LABEL_38;
            pThing->actorParams.fireOffset.x = vx;
            pThing->actorParams.fireOffset.y = vy;
            pThing->actorParams.fireOffset.z = vz;
            result = 1;
            break;
        case THINGPARAM_LIGHTOFFSET:
            if ( _sscanf(
                     pArg->value,
                     "(%f/%f/%f)",
                     &vx, &vy, &vz) != 3 )
                goto LABEL_38;
            pThing->actorParams.lightOffset.x = vx;
            pThing->actorParams.lightOffset.y = vy;
            pThing->actorParams.lightOffset.z = vz;
            pThing->flags |= SITH_TF_EMITLIGHT;
            result = 1;
            break;
        case THINGPARAM_LIGHTINTENSITY:
            if ( _sscanf(pArg->value, "%f", &tmp) != 1 )
                return 0;
            pThing->actorParams.lightIntensity = tmp;
            pThing->flags |= SITH_TF_EMITLIGHT;
            return 1;
        case THINGPARAM_ERROR:
            v19 = _atof(pArg->value);
            pThing->actorParams.error = v19;
            return 1;
        case THINGPARAM_FOV:
            v20 = _atof(pArg->value);
            pThing->actorParams.fov = v20;
            return 1;
        case THINGPARAM_CHANCE:
            v21 = _atof(pArg->value);
            pThing->actorParams.chance = v21;
            return 1;
        default:
LABEL_38:
            result = 0;
            break;
    }
    return result;
}
