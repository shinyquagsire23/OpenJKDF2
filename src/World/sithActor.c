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

void sithActor_SetDifficulty(SithThing *thing)
{
    if ( jkPlayer_setDiff )
    {
        if ( jkPlayer_setDiff == 2 )
        {
            thing->actorParams.maxHealth = thing->actorParams.maxHealth * 1.2;
            thing->actorParams.health = thing->actorParams.health * 1.2;
        }
    }
    else
    {
        thing->actorParams.maxHealth = thing->actorParams.maxHealth * 0.8;
        thing->actorParams.health = thing->actorParams.health * 0.8;
    }
}

void sithActor_Update(SithThing *thing, int deltaMs)
{
    unsigned int v2; // eax
    unsigned int v3; // eax

    // Added
    if (!thing) return;

    if ( (thing->actorParams.flags & SITH_AF_BREATHEUNDERWATER) == 0 && (thing->flags & (SITH_TF_DEAD|SITH_TF_DESTROYED)) == 0 )
    {
        if ( (thing->physicsParams.flags & SITH_PF_ONWATERSURFACE) != 0 || (thing->sector && thing->sector->flags & SITH_SECTOR_UNDERWATER) == 0 ) // Added: Sector check
        {
            v3 = thing->actorParams.endurance;
            if ( v3 )
            {
                if ( v3 <= 18000 )
                {
                    if ( v3 > 10000 )
                        sithSoundClass_PlayModeRandom(thing, SITH_SC_BREATH);
                }
                else
                {
                    sithSoundClass_PlayModeRandom(thing, SITH_SC_GASP);
                }
                thing->actorParams.endurance = 0;
            }
        }
        else
        {
            v2 = deltaMs + thing->actorParams.endurance;
            thing->actorParams.endurance = v2;
            if ( v2 > 20000 )
            {
                sithThing_DamageThing(thing, thing, 10.0, SITH_DAMAGE_DROWN);
                thing->actorParams.endurance -= 2000;
            }
        }
    }
}

// MOTS altered
flex_t sithActor_DamageActor(SithThing *sender, SithThing *receiver, flex_t amount, int flags)
{
    SithThing *receiver_; // edi
    flex_d_t v6; // st7
    SithThing *v7; // eax
    flex_t fR; // [esp+0h] [ebp-1Ch]

    if ( sithNet_isMulti && (sender->flags & SITH_TF_INVULN) != 0 )
    {
        receiver_ = receiver;
        goto LABEL_32;
    }
    if ( (sender->actorParams.flags & SITH_AF_INVULNERABLE) != 0 && flags != 0x40 )
        return 0.0;
    if ( sender->actorParams.health <= 0.0 )
        return amount;
    receiver_ = receiver;
    if ( sender->type == SITH_THING_PLAYER )
    {
        v6 = sithInventory_BroadcastMessage(
                 sender,
                 SENDERTYPE_THING,
                 receiver->idx,
                 SITH_MESSAGE_DAMAGED,
                 0x10,
                 amount,
                 (flex_t)flags, // FLEXTODO
                 0.0,
                 0.0);
        amount = v6;
        if ( v6 == 0.0 )
            return 0.0;
    }
    if ( receiver )
    {
        if ( receiver != sender && sender->controlType == SITH_CT_AI )
            sithAI_EmitEvent(sender->actor, SITHAI_MODE_MOVING, (intptr_t)receiver);
        v7 = sithThing_GetThingParent(receiver);
        receiver_ = v7;

        flex_t damageMult = 1.0;
        if ( v7
          && flags != 0x20
          && flags != 0x40
          && v7->type == SITH_THING_ACTOR
          && (v7->actorParams.flags & SITH_AF_FULLDAMAGE) == 0
          && sender->type == SITH_THING_ACTOR )
        {
            damageMult = 0.1;

            // MOTS added: alignment
            if (Main_bMotsCompat
                && sender->controlType == SITH_CT_AI
                && sender->actor
                && sender->actor->pAIClass
                && v7->controlType == SITH_CT_AI
                && v7->actor
                && v7->actor->pAIClass) {

                if (v7->actor->pAIClass->alignment * sender->actor->pAIClass->alignment <= -1.0) {
                    damageMult = 0.5;
                }
            }
        }
        amount *= damageMult;
        if ( sithNet_isMulti && (sithNet_MultiModeFlags & MULTIMODEFLAG_2) != 0 && sithPlayer_sub_4C9060(v7, sender) )
            return 0.0;
    }

    sender->actorParams.health -= amount;
    if ( sender == sithPlayer_g_pLocalPlayerThing )
    {
        fR = amount * 0.04;
        sithPlayer_AddDynamicTint(fR, 0.0, 0.0);
    }
    if ( sender->actorParams.health >= 1.0 )
    {
LABEL_32:
        if ( sender->pPuppetClass && sender != receiver_ && amount * 0.05 > _frand() )
            sithPuppet_PlayMode(sender, SITH_ANIM_HIT, 0);
        sithActor_PlayDamageSoundFx(sender, amount, flags);
        return amount;
    }
    if ( sithMessage_g_outputstream )
        sithDSSThing_Death(sender, receiver_, 0, -1, 255);
    sithActor_KillActor(sender, receiver_, flags);
    return amount - sender->actorParams.health;
}

void sithActor_PlayDamageSoundFx(SithThing *thing, flex_t amount, int hurtType)
{
    if ( thing->actorParams.health <= 0.0 || amount < 3.0 ) return;


    flex_t hurt_vol = amount / thing->actorParams.health * 1.5;
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
                sithSoundClass_PlayMode(thing, SITH_SC_HURTENERGY, hurt_vol);
                break;
            case SITH_DAMAGE_FIRE:
                sithSoundClass_PlayMode(thing, SITH_SC_HURTFIRE, hurt_vol);
                break;
            case SITH_DAMAGE_FORCE:
                sithSoundClass_PlayMode(thing, SITH_SC_HURTMAGIC, hurt_vol);
                break;
            case SITH_DAMAGE_SABER:
                sithSoundClass_PlayMode(thing, SITH_SC_HURTSPECIAL, hurt_vol);
                break;
            case SITH_DAMAGE_DROWN:
                sithSoundClass_PlayMode(thing, SITH_SC_DROWNING, hurt_vol);
                break;
            default:
                sithSoundClass_PlayMode(thing, SITH_SC_HURTIMPACT, hurt_vol);
                break;
        }
    }
}

// MOTS altered
void sithActor_KillActor(SithThing *thing, SithThing *a3, int a4)
{
    SithThing *v8; // eax
    uint32_t v10; // edx

    if (thing->flags & SITH_TF_DEAD) return;


    thing->actorParams.health = 0.0;
    if ( (thing->flags & SITH_TF_CAPTURED) == 0 || (sithCog_ThingSendMessage(thing, a3, SITH_MESSAGE_KILLED), (thing->flags & SITH_TF_DESTROYED) == 0) )
    {
        sithSoundClass_StopSound(thing, 0);

        // MOTS added: quiet death (sithCogFunctionPlayer_KillPlayerQuietly)
        if (!Main_bMotsCompat || a4 != 12345678) {
            if ( a4 == 0x20 )
            {
                sithSoundClass_PlayModeRandom(thing, SITH_SC_DROWNED);
            }
            else if ( a4 == 0x40 )
            {
                sithSoundClass_PlayModeRandom(thing, SITH_SC_SPLATTERED);
            }
            else if ( (thing->flags & SITH_TF_WATER) != 0 )
            {
                sithSoundClass_PlayModeRandom(thing, SITH_SC_DEATHUNDER);
            }
            else if ( thing->actorParams.health >= -10.0 )
            {
                sithSoundClass_PlayModeRandom(thing, SITH_SC_DEATH1);
            }
            else
            {
                sithSoundClass_PlayModeRandom(thing, SITH_SC_DEATH2);
            }
        }
        sithActor_SetHeadPYR(thing, &rdroid_zeroVector3);

        // MOTS added: quiet death
        if (!Main_bMotsCompat || a4 != 12345678) {
            sithAIAwareness_CreateTransmittingEvent(thing->sector, &thing->position, 0, 5.0, a3);
        }
        if ( thing->type == SITH_THING_PLAYER )
            sithPlayer_PlayerKilledAction(thing, a3);

        // MOTS added: quiet death
        if (!Main_bMotsCompat || a4 != 12345678) {
            if ( thing == sithWorld_g_pCurrentWorld->pCameraFocusThing )
                sithCamera_SetCurrentCamera(&sithCamera_g_aCameras[5]);

            // MOTS added: quiet death
            if (!Main_bMotsCompat || a4 != 12345678) {
                if ( thing->pPuppetClass )
                {
                    sithPuppet_ResetTrack(thing);
                    if ( thing->actorParams.health >= -10.0 )
                        thing->puppet->field_18 = sithPuppet_PlayMode(thing, SITH_ANIM_DEATH, 0);
                    else
                        thing->puppet->field_18 = sithPuppet_PlayMode(thing, SITH_ANIM_DEATH2, 0);
                }
            }
        }

        thing->physicsParams.flags &= ~SITH_PF_CROUCHING;
        if ( thing->type != SITH_THING_PLAYER )
        {
            int old_typeflags = thing->actorParams.flags;

            // MOTS added: quiet death
            if ((!Main_bMotsCompat || a4 != 12345678) && (old_typeflags & SITH_AF_EXPLODE_WHEN_KILLED) && thing->actorParams.pExplodeTemplate)
            {
                sithThing_CreateThingAtPos(thing->actorParams.pExplodeTemplate, &thing->position, &thing->orient, thing->sector, 0);
                sithThing_DestroyThing(thing);
            }
            else
            {
                if (old_typeflags & SITH_AF_BREATHEUNDERWATER) {
                    thing->physicsParams.buoyancy = 0.3;
                }
                else if (Main_bMotsCompat) {
                    thing->physicsParams.buoyancy = 0.01; // MOTS added
                }
                if (thing->physicsParams.flags & SITH_PF_FLY)
                {
                    sithActor_DestroyActor(thing);
                }
                else
                {
                    thing->msecLifeLeft = 1000;
                }
            }
        }
    }
}

int sithActor_SurfaceCollisionHandler(SithThing *thing, SithSurface *surface, SithCollision *searchEnt)
{
    int ret = sithCollision_HandleThingHitSurface(thing, surface, searchEnt);
    if (ret && thing->controlType == SITH_CT_AI) {
        sithAI_EmitEvent(thing->actor, SITHAI_MODE_ACTIVE, 0);
    }
    return ret;
}

void sithActor_SetHeadPYR(SithThing *actor, const rdVector3 *headPYR)
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

    actor->actorParams.flags &= ~SITH_AF_VIEWCENTRED;
    actor->actorParams.headPYR = *headPYR;
    pAnimClass = actor->pPuppetClass;
    if (!pAnimClass || actor->renderData.type != RD_THING_MODEL3) return;


    v4 = actor->renderData.hierarchyNodes2;
    if (v4)
    {
        torsoIdx = pAnimClass->bodypart_to_joint[JOINTTYPE_TORSO];
        primaryWeapJointIdx = pAnimClass->bodypart_to_joint[JOINTTYPE_PRIMARYWEAPJOINT];
        v7 = actor->renderData.model3->numHierarchyNodes;
        neckIdx = pAnimClass->bodypart_to_joint[JOINTTYPE_NECK];
        v9 = pAnimClass->bodypart_to_joint[JOINTTYPE_SECONDARYWEAPJOINT];
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
            v4[neckIdx].x = headPYR->x * 0.5;
        }
        if ( torsoIdx < 0 ) {
            v12 = 0;
        }
        else {
            v12 = torsoIdx <= v10;
        }
        if ( v12 ) {
            v4[torsoIdx].x = headPYR->x * 0.5;
        }
        if ( primaryWeapJointIdx < 0 ) {
            v13 = 0;
        }
        else {
            v13 = primaryWeapJointIdx <= v10;
        }
        if ( v13 ) {
            v4[primaryWeapJointIdx].x = headPYR->x * 0.3;
        }
        if ( v9 < 0 ) {
            v14 = 0;
        }
        else {
            v14 = v9 <= v10;
        }
        if ( v14 ) {
            v4[v9].x = headPYR->x * 0.3;
        }
    }
}

int sithActor_ActorCollisionHandler(SithThing *thing, SithThing *thing2, SithCollision *a3, int a4)
{
    int ret = sithCollision_ThingCollisionHandler(thing, thing2, a3, a4);
    if (ret)
    {
        if (thing->controlType == SITH_CT_AI && thing->actor)
        {
            sithAI_EmitEvent(thing->actor, SITHAI_MODE_SEARCHING, (intptr_t)thing2);
        }
        if (thing2->controlType == SITH_CT_AI && thing2->actor)
        {
            sithAI_EmitEvent(thing2->actor, SITHAI_MODE_SEARCHING, (intptr_t)thing);
        }
    }
    return ret;
}

void sithActor_UpdateAimJoints(SithThing* pThing)
{
    SithPuppetClass* pAnimClass = pThing->pPuppetClass;
    if (pAnimClass)
    {
        int pitch_idx = pAnimClass->bodypart_to_joint[JOINTTYPE_TURRETPITCH];
        int yaw_idx = pAnimClass->bodypart_to_joint[JOINTTYPE_TURRETYAW];
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

void sithActor_DestroyActor(SithThing *thing)
{
    thing->flags |= SITH_TF_DEAD;
    sithThing_DetachAttachedThings(thing);
    thing->type = SITH_THING_CORPSE;
    thing->physicsParams.flags &= ~(SITH_PF_FLY|SITH_PF_800|SITH_PF_100|SITH_PF_WALLSTICK);
    thing->physicsParams.flags |= (SITH_PF_FLOORSTICK|SITH_PF_ALIGNSURFACE|SITH_PF_USEGRAVITY);
    thing->msecLifeLeft = jkPlayer_bKeepCorpses ? -1 : 20000; // Added
    sithPhysics_FindFloor(thing, 0);
}

void sithActor_DestroyCorpse(SithThing *corpse)
{
    // Added: retain corpses option
    if (jkPlayer_bKeepCorpses || corpse->renderFrame + 1 == jkPlayer_currentTickIdx ) {
        corpse->msecLifeLeft = 3000;
    }
    else {
        sithThing_DestroyThing(corpse);
    }
}

int sithActor_ParseArg(StdConffileArg *arg, SithThing *thing, unsigned int param)
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

    switch (param)
    {
        case THINGPARAM_TYPEFLAGS:
            if ( _sscanf(arg->value, "%x", &tmpInt) != 1 )
                goto LABEL_38;
            thing->actorParams.flags = tmpInt;
            return 1;
        case THINGPARAM_HEALTH:
            tmp = _atof(arg->value);
            if ( tmp < 0.0 )
                goto LABEL_38;

            thing->actorParams.health = tmp;
            if ( tmp < (flex_d_t)thing->actorParams.maxHealth )
                thing->actorParams.maxHealth = thing->actorParams.maxHealth;
            else
                thing->actorParams.maxHealth = tmp;
            return 1;
        case THINGPARAM_MAXTHRUST:
            v10 = _atof(arg->value);
            if ( v10 < 0.0 )
                return 0;
            result = 1;
            thing->actorParams.maxThrust = v10;
            return result;
        case THINGPARAM_MAXROTTHRUST:
            v11 = _atof(arg->value);
            if ( v11 < 0.0 )
                return 0;
            result = 1;
            thing->actorParams.maxRotVelocity = v11;
            return result;
        case THINGPARAM_JUMPSPEED:
            v12 = _atof(arg->value);
            if ( v12 < 0.0 )
                return 0;
            result = 1;
            thing->actorParams.jumpSpeed = v12;
            return result;
        case THINGPARAM_WEAPON:
            thing->actorParams.pWeaponTemplate = sithTemplate_GetTemplate(arg->value);
            return 1;
        case THINGPARAM_WEAPON2:
            thing->actorParams.templateWeapon2 = sithTemplate_GetTemplate(arg->value);
            return 1;
        case THINGPARAM_EXPLODE:
            thing->actorParams.pExplodeTemplate = sithTemplate_GetTemplate(arg->value);
            return 1;
        case THINGPARAM_MAXHEALTH:
            v9 = _atof(arg->value);
            if ( v9 < 0.0 )
                return 0;
            result = 1;
            thing->actorParams.maxHealth = v9;
            thing->actorParams.health = v9;
            return result;
        case THINGPARAM_EYEOFFSET:
            v13 = _sscanf(
                      arg->value,
                      "(%f/%f/%f)",
                      &vx, &vy, &vz);
            thing->actorParams.eyeOffset.x = vx;
            thing->actorParams.eyeOffset.y = vy;
            thing->actorParams.eyeOffset.z = vz;
            if ( v13 != 3 )
                goto LABEL_38;
            result = 1;
            break;
        case THINGPARAM_MINHEADPITCH:
            result = _sscanf(arg->value, "%f", &tmp);
            if ( result != 1 )
                goto LABEL_38;
            thing->actorParams.minHeadPitch = tmp;
            break;
        case THINGPARAM_MAXHEADPITCH:
            result = _sscanf(arg->value, "%f", &tmp);
            if ( result != 1 )
                goto LABEL_38;
            thing->actorParams.maxHeadPitch = tmp;
            break;
        case THINGPARAM_FIREOFFSET:
            v13 = _sscanf(
                      arg->value,
                      "(%f/%f/%f)",
                      &vx, &vy, &vz);
            if ( v13 != 3 )
                goto LABEL_38;
            thing->actorParams.fireOffset.x = vx;
            thing->actorParams.fireOffset.y = vy;
            thing->actorParams.fireOffset.z = vz;
            result = 1;
            break;
        case THINGPARAM_LIGHTOFFSET:
            if ( _sscanf(
                     arg->value,
                     "(%f/%f/%f)",
                     &vx, &vy, &vz) != 3 )
                goto LABEL_38;
            thing->actorParams.lightOffset.x = vx;
            thing->actorParams.lightOffset.y = vy;
            thing->actorParams.lightOffset.z = vz;
            thing->flags |= SITH_TF_EMITLIGHT;
            result = 1;
            break;
        case THINGPARAM_LIGHTINTENSITY:
            if ( _sscanf(arg->value, "%f", &tmp) != 1 )
                return 0;
            thing->actorParams.lightIntensity = tmp;
            thing->flags |= SITH_TF_EMITLIGHT;
            return 1;
        case THINGPARAM_ERROR:
            v19 = _atof(arg->value);
            thing->actorParams.error = v19;
            return 1;
        case THINGPARAM_FOV:
            v20 = _atof(arg->value);
            thing->actorParams.fov = v20;
            return 1;
        case THINGPARAM_CHANCE:
            v21 = _atof(arg->value);
            thing->actorParams.chance = v21;
            return 1;
        default:
LABEL_38:
            result = 0;
            break;
    }
    return result;
}
