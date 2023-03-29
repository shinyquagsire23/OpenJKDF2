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

void sithActor_SetMaxHeathForDifficulty(sithThing *thing)
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

void sithActor_Tick(sithThing *thing, int deltaMs)
{
    unsigned int v2; // eax
    unsigned int v3; // eax

    // Added
    if (!thing) return;

    if ( (thing->actorParams.typeflags & SITH_AF_BREATH_UNDER_WATER) == 0 && (thing->thingflags & (SITH_TF_DEAD|SITH_TF_WILLBEREMOVED)) == 0 )
    {
        if ( (thing->physicsParams.physflags & SITH_PF_MIDAIR) != 0 || (thing->sector && thing->sector->flags & SITH_SECTOR_UNDERWATER) == 0 ) // Added: Sector check
        {
            v3 = thing->actorParams.msUnderwater;
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
                thing->actorParams.msUnderwater = 0;
            }
        }
        else
        {
            v2 = deltaMs + thing->actorParams.msUnderwater;
            thing->actorParams.msUnderwater = v2;
            if ( v2 > 20000 )
            {
                sithThing_Damage(thing, thing, 10.0, SITH_DAMAGE_DROWN);
                thing->actorParams.msUnderwater -= 2000;
            }
        }
    }
}

// MOTS altered
float sithActor_Hit(sithThing *sender, sithThing *receiver, float amount, int flags)
{
    sithThing *receiver_; // edi
    double v6; // st7
    sithThing *v7; // eax
    float fR; // [esp+0h] [ebp-1Ch]

    if ( sithNet_isMulti && (sender->thingflags & SITH_TF_INVULN) != 0 )
    {
        receiver_ = receiver;
        goto LABEL_32;
    }
    if ( (sender->actorParams.typeflags & SITH_AF_INVULNERABLE) != 0 && flags != 0x40 )
        return 0.0;
    if ( sender->actorParams.health <= 0.0 )
        return amount;
    receiver_ = receiver;
    if ( sender->type == SITH_THING_PLAYER )
    {
        v6 = sithInventory_SendMessageToAllWithFlag(
                 sender,
                 SENDERTYPE_THING,
                 receiver->thingIdx,
                 SITH_MESSAGE_DAMAGED,
                 0x10,
                 amount,
                 (float)flags,
                 0.0,
                 0.0);
        amount = v6;
        if ( v6 == 0.0 )
            return 0.0;
    }
    if ( receiver )
    {
        if ( receiver != sender && sender->thingtype == SITH_THING_ACTOR )
            sithAI_SetActorFireTarget(sender->actor, SITHAI_MODE_MOVING, (intptr_t)receiver);
        v7 = sithThing_GetParent(receiver);
        receiver_ = v7;

        float damageMult = 1.0;
        if ( v7
          && flags != 0x20
          && flags != 0x40
          && v7->type == SITH_THING_ACTOR
          && (v7->actorParams.typeflags & SITH_AF_FULL_ACTOR_DAMAGE) == 0
          && sender->type == SITH_THING_ACTOR )
        {
            damageMult = 0.1;

            // MOTS added: alignment
            if (Main_bMotsCompat
                && sender->thingtype == SITH_THING_ACTOR
                && sender->actor
                && sender->actor->pAIClass
                && v7->thingtype == SITH_THING_ACTOR
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
    if ( sender == sithPlayer_pLocalPlayerThing )
    {
        fR = amount * 0.04;
        sithPlayer_AddDynamicTint(fR, 0.0, 0.0);
    }
    if ( sender->actorParams.health >= 1.0 )
    {
LABEL_32:
        if ( sender->animclass && sender != receiver_ && amount * 0.05 > _frand() )
            sithPuppet_PlayMode(sender, SITH_ANIM_HIT, 0);
        sithActor_HurtSound(sender, amount, flags);
        return amount;
    }
    if ( sithComm_multiplayerFlags )
        sithDSSThing_SendDeath(sender, receiver_, 0, -1, 255);
    sithActor_SpawnDeadBodyMaybe(sender, receiver_, flags);
    return amount - sender->actorParams.health;
}

void sithActor_HurtSound(sithThing *thing, float amount, int hurtType)
{
    double v3; // st7
    float v4; // [esp+8h] [ebp+8h]

    if ( thing->actorParams.health > 0.0 && amount >= 3.0 )
    {
        v3 = amount / thing->actorParams.health * 1.5;
        v4 = v3;
        if ( v3 >= 0.01 )
        {
            if ( v4 < 0.0 )
            {
                v4 = 0.0;
            }
            else if ( v4 > 1.0 )
            {
                v4 = 1.0;
            }
            switch ( hurtType )
            {
                case 2:
                    sithSoundClass_ThingPlaySoundclass5(thing, SITH_SC_HURTENERGY, v4);
                    break;
                case 4:
                    sithSoundClass_ThingPlaySoundclass5(thing, SITH_SC_HURTFIRE, v4);
                    break;
                case 8:
                    sithSoundClass_ThingPlaySoundclass5(thing, SITH_SC_HURTMAGIC, v4);
                    break;
                case 16:
                    sithSoundClass_ThingPlaySoundclass5(thing, SITH_SC_HURTSPECIAL, v4);
                    break;
                case 32:
                    sithSoundClass_ThingPlaySoundclass5(thing, SITH_SC_DROWNING, v4);
                    break;
                default:
                    sithSoundClass_ThingPlaySoundclass5(thing, SITH_SC_HURTIMPACT, v4);
                    break;
            }
        }
    }
}

// MOTS altered
void sithActor_SpawnDeadBodyMaybe(sithThing *thing, sithThing *a3, int a4)
{
    int v7; // ecx
    sithThing *v8; // eax
    uint32_t v10; // edx

    if ( (thing->thingflags & SITH_TF_DEAD) == 0 )
    {
        thing->actorParams.health = 0.0;
        if ( (thing->thingflags & SITH_TF_CAPTURED) == 0 || (sithCog_SendMessageFromThing(thing, a3, SITH_MESSAGE_KILLED), (thing->thingflags & SITH_TF_WILLBEREMOVED) == 0) )
        {
            sithSoundClass_StopSound(thing, 0);

            // MOTS added: quiet death
            if (!Main_bMotsCompat || a4 != 12345678) {
                if ( a4 == 0x20 )
                {
                    sithSoundClass_PlayModeRandom(thing, SITH_SC_DROWNED);
                }
                else if ( a4 == 0x40 )
                {
                    sithSoundClass_PlayModeRandom(thing, SITH_SC_SPLATTERED);
                }
                else if ( (thing->thingflags & SITH_TF_WATER) != 0 )
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
            sithActor_MoveJointsForEyePYR(thing, &rdroid_zeroVector3);

            // MOTS added: quiet death
            if (!Main_bMotsCompat || a4 != 12345678) {
                sithAIAwareness_AddEntry(thing->sector, &thing->position, 0, 5.0, a3);
            }
            if ( thing->type == SITH_THING_PLAYER )
                sithPlayer_sub_4C9150(thing, a3);

            // MOTS added: quiet death
            if (!Main_bMotsCompat || a4 != 12345678) {
                if ( thing == sithWorld_pCurrentWorld->cameraFocus )
                    sithCamera_SetCurrentCamera(&sithCamera_cameras[5]);

                // MOTS added: quiet death
                if (!Main_bMotsCompat || a4 != 12345678) {
                    if ( thing->animclass )
                    {
                        sithPuppet_ResetTrack(thing);
                        if ( thing->actorParams.health >= -10.0 )
                            thing->puppet->field_18 = sithPuppet_PlayMode(thing, SITH_ANIM_DEATH, 0);
                        else
                            thing->puppet->field_18 = sithPuppet_PlayMode(thing, SITH_ANIM_DEATH2, 0);
                    }
                }
            }

            thing->physicsParams.physflags &= ~SITH_PF_CROUCHING;
            if ( thing->type != SITH_THING_PLAYER )
            {
                v7 = thing->actorParams.typeflags;

                // MOTS added: quiet death
                if ((!Main_bMotsCompat || a4 != 12345678) && (v7 & SITH_AF_EXPLODE_WHEN_KILLED) != 0 && (v8 = thing->actorParams.templateExplode) != 0 )
                {
                    sithThing_Create(v8, &thing->position, &thing->lookOrientation, thing->sector, 0);
                    sithThing_Destroy(thing);
                }
                else
                {
                    if ( (v7 & SITH_AF_BREATH_UNDER_WATER) != 0 ) {
                        thing->physicsParams.buoyancy = 0.3;
                    }
                    else if (Main_bMotsCompat) {
                        thing->physicsParams.buoyancy = 0.01; // MOTS added
                    }
                    if ( (thing->physicsParams.physflags & SITH_PF_FLY) != 0 )
                    {
                        sithActor_Remove(thing);
                    }
                    else
                    {
                        thing->lifeLeftMs = 1000;
                    }
                }
            }
        }
    }
}

int sithActor_sub_4ED1D0(sithThing *thing, sithSurface *surface, sithCollisionSearchEntry *searchEnt)
{
    int v3; // edi

    v3 = sithCollision_DefaultHitHandler(thing, surface, searchEnt);
    if ( v3 && thing->thingtype == SITH_THING_ACTOR )
        sithAI_SetActorFireTarget(thing->actor, SITHAI_MODE_ACTIVE, 0);
    return v3;
}

void sithActor_MoveJointsForEyePYR(sithThing *actor, const rdVector3 *eyePYR)
{
    sithAnimclass *v3; // eax
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
    rdVector3 *actora; // [esp+14h] [ebp+4h]

    actor->actorParams.typeflags &= ~SITH_AF_HEAD_IS_CENTERED;
    actor->actorParams.eyePYR = *eyePYR;
    v3 = actor->animclass;
    if ( v3 )
    {
        if ( actor->rdthing.type == RD_THINGTYPE_MODEL )
        {
            actora = actor->rdthing.hierarchyNodes2;
            v4 = actora;
            if ( actora )
            {
                torsoIdx = v3->bodypart_to_joint[JOINTTYPE_TORSO];
                primaryWeapJointIdx = v3->bodypart_to_joint[JOINTTYPE_PRIMARYWEAPJOINT];
                v7 = actor->rdthing.model3->numHierarchyNodes;
                neckIdx = v3->bodypart_to_joint[JOINTTYPE_NECK];
                v9 = v3->bodypart_to_joint[JOINTTYPE_SECONDARYWEAPJOINT];
                v10 = v7 - 1;
                if ( neckIdx < 0 )
                {
                    v11 = 0;
                }
                else
                {
                    v11 = neckIdx <= v10;
                    v4 = actora;
                }
                if ( v11 )
                    v4[neckIdx].x = eyePYR->x * 0.5;
                if ( torsoIdx < 0 )
                    v12 = 0;
                else
                    v12 = torsoIdx <= v10;
                if ( v12 )
                    v4[torsoIdx].x = eyePYR->x * 0.5;
                if ( primaryWeapJointIdx < 0 )
                    v13 = 0;
                else
                    v13 = primaryWeapJointIdx <= v10;
                if ( v13 )
                    v4[primaryWeapJointIdx].x = eyePYR->x * 0.3;
                if ( v9 < 0 )
                    v14 = 0;
                else
                    v14 = v9 <= v10;
                if ( v14 )
                    v4[v9].x = eyePYR->x * 0.3;
            }
        }
    }
}

int sithActor_ActorActorCollide(sithThing *thing, sithThing *thing2, sithCollisionSearchEntry *a3, int a4)
{
    int result; // eax
    int v5; // ebx
    sithActor *v6; // eax
    sithActor *v7; // eax

    result = sithCollision_DebrisDebrisCollide(thing, thing2, a3, a4);
    v5 = result;
    if ( result )
    {
        if ( thing->thingtype == SITH_THING_ACTOR )
        {
            v6 = thing->actor;
            if ( v6 )
                sithAI_SetActorFireTarget(v6, SITHAI_MODE_SEARCHING, (intptr_t)thing2);
        }
        if ( thing2->thingtype == SITH_THING_ACTOR )
        {
            v7 = thing2->actor;
            if ( v7 )
                sithAI_SetActorFireTarget(v7, SITHAI_MODE_SEARCHING, (intptr_t)thing);
        }
        result = v5;
    }
    return result;
}

void sithActor_RotateTurretToEyePYR(sithThing *a1)
{
    sithAnimclass *v1; // eax
    int v2; // ecx
    int v3; // eax

    v1 = a1->animclass;
    if ( v1 )
    {
        v2 = v1->bodypart_to_joint[7];
        v3 = v1->bodypart_to_joint[8];
        if ( v2 >= 0 )
            a1->rdthing.hierarchyNodes2[v2].x = a1->actorParams.eyePYR.x;
        if ( v3 >= 0 )
            a1->rdthing.hierarchyNodes2[v3].y = a1->actorParams.eyePYR.y;
    }
}

// MOTS altered
int sithActor_thing_anim_blocked(sithThing *a1, sithThing *thing2, sithCollisionSearchEntry *a3)
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
    rdMatrix_Copy34(&out, &thing2->lookOrientation);

    if ( thing2->type == SITH_THING_ACTOR || thing2->type == SITH_THING_PLAYER )
        rdMatrix_PreRotate34(&out, &thing2->actorParams.eyePYR);

    rdVector_Copy3(&v18, &out.lvec);
    rdVector_Normalize3Acc(&v18);
    if ( rdVector_Dot3(&v18, &a1a) < thing2->actorParams.fov )
        return 0;
    if (!sithCollision_DebrisDebrisCollide(a1, thing2, a3, 0))
        return 0;

    rdVector_Neg3(&a1->physicsParams.vel, &vAngs);
    if ( _frand() < thing2->actorParams.error )
    {
        rdVector_Zero3(&vAngs);
        vAngs.x = (_frand() - 0.5) * 90.0;
        vAngs.y = (_frand() - 0.5) * 90.0;
        rdVector_Rotate3Acc(&a1->physicsParams.vel, &vAngs);
    }
    rdVector_Normalize3(&a1->lookOrientation.lvec, &a1->physicsParams.vel);
    a1->lookOrientation.rvec.x = (a1->lookOrientation.lvec.y * 1.0) - (a1->lookOrientation.lvec.z * 0.0);
    a1->lookOrientation.rvec.y = (a1->lookOrientation.lvec.z * 0.0) - (a1->lookOrientation.lvec.x * 1.0);
    a1->lookOrientation.rvec.z = (a1->lookOrientation.lvec.x * 0.0) - (a1->lookOrientation.lvec.y * 0.0);
    rdVector_Normalize3Acc(&a1->lookOrientation.rvec);
    a1->lookOrientation.uvec.x = a1->lookOrientation.rvec.y * a1->lookOrientation.lvec.z - a1->lookOrientation.rvec.z * a1->lookOrientation.lvec.y;
    a1->lookOrientation.uvec.y = a1->lookOrientation.rvec.z * a1->lookOrientation.lvec.x - a1->lookOrientation.lvec.z * a1->lookOrientation.rvec.x;
    a1->lookOrientation.uvec.z = a1->lookOrientation.lvec.y * a1->lookOrientation.rvec.x - a1->lookOrientation.rvec.y * a1->lookOrientation.lvec.x;
    sithSoundClass_PlayModeRandom(a1, SITH_SC_DEFLECTED);
    if ( thing2->lookOrientation.uvec.x * a1a.x + thing2->lookOrientation.uvec.y * a1a.y + thing2->lookOrientation.uvec.z * a1a.z <= 0.0 )
        sithPuppet_PlayMode(thing2, SITH_ANIM_BLOCK2, 0);
    else
        sithPuppet_PlayMode(thing2, SITH_ANIM_BLOCK, 0);
    a1->actorParams.typeflags &= ~SITH_AF_CAN_ROTATE_HEAD;
    a1->prev_thing = thing2;
    a1->child_signature = thing2->signature;
    sithCog_SendMessageFromThing(thing2, 0, SITH_MESSAGE_BLOCKED);
    return 1;
}

void sithActor_Remove(sithThing *thing)
{
    thing->thingflags |= SITH_TF_DEAD;
    sithThing_detachallchildren(thing);
    thing->type = SITH_THING_CORPSE;
    thing->physicsParams.physflags &= ~(SITH_PF_FLY|SITH_PF_800|SITH_PF_100|SITH_PF_WALLSTICK);
    thing->physicsParams.physflags |= (SITH_PF_FLOORSTICK|SITH_PF_SURFACEALIGN|SITH_PF_USEGRAVITY);
    thing->lifeLeftMs = jkPlayer_bKeepCorpses ? -1 : 20000; // Added
    sithPhysics_FindFloor(thing, 0);
}

void sithActor_RemoveCorpse(sithThing *corpse)
{
    if (jkPlayer_bKeepCorpses || corpse->isVisible + 1 == bShowInvisibleThings ) // Added
        corpse->lifeLeftMs = 3000;
    else
        sithThing_Destroy(corpse);
}

int sithActor_LoadParams(stdConffileArg *arg, sithThing *thing, unsigned int param)
{
    sithThing *v3; // eax
    int result; // eax
    sithThing *v5; // eax
    double v6; // st7
    double v9; // st7
    double v10; // st7
    double v11; // st7
    double v12; // st7
    int v13; // eax
    sithThing *v14; // esi
    sithThing *v16; // eax
    sithThing *v18; // eax
    double v19; // st7
    double v20; // st7
    double v21; // st7
    float tmp;
    int tmpInt;

    switch ( param )
    {
        case THINGPARAM_TYPEFLAGS:
            if ( _sscanf(arg->value, "%x", &tmpInt) != 1 )
                goto LABEL_38;
            thing->actorParams.typeflags = tmpInt;
            return 1;
        case THINGPARAM_HEALTH:
            tmp = _atof(arg->value);
            if ( tmp < 0.0 )
                goto LABEL_38;

            thing->actorParams.health = tmp;
            if ( tmp < (double)thing->actorParams.maxHealth )
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
            thing->actorParams.maxRotThrust = v11;
            return result;
        case THINGPARAM_JUMPSPEED:
            v12 = _atof(arg->value);
            if ( v12 < 0.0 )
                return 0;
            result = 1;
            thing->actorParams.jumpSpeed = v12;
            return result;
        case THINGPARAM_WEAPON:
            v3 = sithTemplate_GetEntryByName(arg->value);
            thing->actorParams.templateWeapon = v3;
            return 1;
        case THINGPARAM_WEAPON2:
            v5 = sithTemplate_GetEntryByName(arg->value);
            thing->actorParams.templateWeapon2 = v5;
            return 1;
        case THINGPARAM_EXPLODE:
            v18 = sithTemplate_GetEntryByName(arg->value);
            thing->actorParams.templateExplode = v18;
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
                      &thing->actorParams.eyeOffset.x,
                      &thing->actorParams.eyeOffset.y,
                      &thing->actorParams.eyeOffset.z);
            goto LABEL_25;
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
                      &thing->actorParams.fireOffset.x,
                      &thing->actorParams.fireOffset.y,
                      &thing->actorParams.fireOffset.z);
LABEL_25:
            if ( v13 != 3 )
                goto LABEL_38;
            result = 1;
            break;
        case THINGPARAM_LIGHTOFFSET:
            v14 = thing;
            if ( _sscanf(
                     arg->value,
                     "(%f/%f/%f)",
                     &thing->actorParams.lightOffset.x,
                     &thing->actorParams.lightOffset.y,
                     &thing->actorParams.lightOffset.z) != 3 )
                goto LABEL_38;
            v14->thingflags |= SITH_TF_LIGHT;
            result = 1;
            break;
        case THINGPARAM_LIGHTINTENSITY:
            if ( _sscanf(arg->value, "%f", &tmp) != 1 )
                return 0;
            v16 = thing;
            thing->actorParams.lightIntensity = tmp;
            v16->thingflags |= SITH_TF_LIGHT;
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
