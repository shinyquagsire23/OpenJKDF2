#include "sithAICmd.h"

#include "AI/sithAI.h"
#include "World/sithThing.h"
#include "World/sithActor.h"
#include "Cog/sithCog.h"
#include "Engine/sithTime.h"
#include "Engine/sithSoundClass.h"
#include "Engine/sithAnimClass.h"
#include "Engine/sithPuppet.h"
#include "AI/sithAIClass.h"
#include "Main/jkGame.h"
#include "World/sithWeapon.h"
#include "World/jkPlayer.h"
#include "World/sithSector.h"
#include "World/sithUnk4.h"
#include "World/sithUnk3.h"
#include "jk.h"

#define sithAICmd_Follow ((void*)sithAICmd_Follow_ADDR)
#define sithAICmd_TurretFire ((void*)sithAICmd_TurretFire_ADDR)
#define sithAICmd_Listen ((void*)sithAICmd_Listen_ADDR)
#define sithAICmd_SenseDanger ((void*)sithAICmd_SenseDanger_ADDR)
#define sithAICmd_HitAndRun ((void*)sithAICmd_HitAndRun_ADDR)
#define sithAICmd_Retreat ((void*)sithAICmd_Retreat_ADDR)
#define sithAICmd_ReturnHome ((void*)sithAICmd_ReturnHome_ADDR)
#define sithAICmd_Talk ((void*)sithAICmd_Talk_ADDR)

void sithAICmd_Startup()
{
    sithAI_RegisterCommand("listen", sithAICmd_Listen, 
        0, // allowed flags...?
        0, // disallowed flags
        SITHAIFLAGS_SEARCHING|SITHAIFLAGS_ATTACKING_TARGET|SITHAIFLAGS_MOVING_TO_DEST);
    sithAI_RegisterCommand("lookfortarget", sithAICmd_LookForTarget, 
        SITHAIFLAGS_AWAKE_AND_ACTIVE|SITHAIFLAGS_SEARCHING, // allowed flags
        0,                              // disallowed flags
        0);
    sithAI_RegisterCommand("primaryfire", sithAICmd_PrimaryFire, 
        SITHAIFLAGS_ATTACKING_TARGET,   // allowed flags
        0,                              // disallowed flags
        SITHAIFLAGS_UNK100);
    sithAI_RegisterCommand("follow", sithAICmd_Follow,
        SITHAIFLAGS_ATTACKING_TARGET,   // allowed flags
        SITHAIFLAGS_FLEEING,            // disallowed flags
        SITHAIFLAGS_FLEEING|SITHAIFLAGS_TARGET_SIGHTED_IN_RANGE|SITHAIFLAGS_AWAKE_AND_ACTIVE);
    sithAI_RegisterCommand("turretfire", sithAICmd_TurretFire, 
        SITHAIFLAGS_ATTACKING_TARGET,   // allowed flags
        SITHAIFLAGS_FLEEING,            // disallowed flags
        SITHAIFLAGS_UNK100);
    sithAI_RegisterCommand("opendoors", sithAICmd_OpenDoors, 
        SITHAIFLAGS_ATTACKING_TARGET,   // allowed flags
        0,                              // disallowed flags
        0);
    sithAI_RegisterCommand("jump", sithAICmd_Jump, 
        0,                      // allowed flags
        0,                      // disallowed flags
        SITHAIFLAGS_TARGET_SIGHTED_IN_RANGE|SITHAIFLAGS_AWAKE_AND_ACTIVE|SITHAIFLAGS_SEARCHING);
    sithAI_RegisterCommand("randomturn", sithAICmd_RandomTurn, 
        SITHAIFLAGS_SEARCHING,  // allowed flags
        0,                      // disallowed flags
        0);
    sithAI_RegisterCommand("roam", sithAICmd_Roam, 
        SITHAIFLAGS_SEARCHING,  // allowed flags
        0,                      // disallowed flags
        0);
    sithAI_RegisterCommand("flee", sithAICmd_Flee,
        SITHAIFLAGS_FLEEING,    // allowed flags
        0,                      // disallowed flags
        SITHAIFLAGS_FLEEING|SITHAIFLAGS_TARGET_SIGHTED_IN_RANGE|SITHAIFLAGS_AWAKE_AND_ACTIVE|SITHAIFLAGS_UNK100|SITHAIFLAGS_SEARCHING|SITHAIFLAGS_MOVING_TO_DEST);
    sithAI_RegisterCommand("sensedanger", sithAICmd_SenseDanger,
        SITHAIFLAGS_SEARCHING, // SenseDanger allowed flags
        SITHAIFLAGS_FLEEING,   // SenseDanger disallowed flags
        SITHAIFLAGS_SEARCHING|SITHAIFLAGS_ATTACKING_TARGET|SITHAIFLAGS_MOVING_TO_DEST); // SenseDanger idk?
    sithAI_RegisterCommand("hitandrun", sithAICmd_HitAndRun, 
        SITHAIFLAGS_FLEEING|SITHAIFLAGS_TARGET_SIGHTED_IN_RANGE, // HitAndRun allowed flags
        0,                            // HitAndRun disallowed flags
        0);                           // HitAndRun idk?
    sithAI_RegisterCommand("retreat", sithAICmd_Retreat, 
        SITHAIFLAGS_ATTACKING_TARGET, // allowed flags
        SITHAIFLAGS_FLEEING,          // disallowed flags
        0);
    sithAI_RegisterCommand("circlestrafe", sithAICmd_CircleStrafe, 
        SITHAIFLAGS_ATTACKING_TARGET, // allowed flags
        SITHAIFLAGS_FLEEING,          // disallowed flags
        0);
    sithAI_RegisterCommand("blindfire", sithAICmd_BlindFire, 
        SITHAIFLAGS_ATTACKING_TARGET, // allowed flags
        SITHAIFLAGS_FLEEING|SITHAIFLAGS_TARGET_SIGHTED_IN_RANGE, // disallowed flags
        0);
    sithAI_RegisterCommand("returnhome", sithAICmd_ReturnHome, 
        0, // allowed flags
        0, // disallowed flags
        SITHAIFLAGS_FLEEING|SITHAIFLAGS_UNK100);
    sithAI_RegisterCommand("lobfire", sithAICmd_LobFire, 
        SITHAIFLAGS_ATTACKING_TARGET,   // allowed flags
        0,                              // disallowed flags
        SITHAIFLAGS_UNK100);
    sithAI_RegisterCommand("talk", sithAICmd_Talk, 
        0xFFFF, // allowed flags (any)
        0,      // disallowed flags
        0);
    sithAI_RegisterCommand("crouch", sithAICmd_Crouch, 
        SITHAIFLAGS_ATTACKING_TARGET, // allowed flags
        0, // disallowed flags
        SITHAIFLAGS_UNK100);
    sithAI_RegisterCommand("withdraw", sithAICmd_Withdraw,
        SITHAIFLAGS_FLEEING, // allowed flags
        0, // disallowed flags
        SITHAIFLAGS_FLEEING|SITHAIFLAGS_TARGET_SIGHTED_IN_RANGE|SITHAIFLAGS_AWAKE_AND_ACTIVE|SITHAIFLAGS_UNK100|SITHAIFLAGS_SEARCHING|SITHAIFLAGS_MOVING_TO_DEST);
    sithAI_RegisterCommand("dodge", sithAICmd_Dodge, 
        0, // allowed flags
        0, // disallowed flags
        SITHAIFLAGS_AT_EASE|SITHAIFLAGS_ATTACKING_TARGET|SITHAIFLAGS_MOVING_TO_DEST);
}

// sithAICmd_Follow

int sithAICmd_CircleStrafe(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, int otherFlags)
{
    int v8; // edi
    double v13; // st7
    sithAIClass *v15; // edx
    rdVector3 movePos; // [esp+10h] [ebp-30h] BYREF
    rdVector3 a2a; // [esp+1Ch] [ebp-24h] BYREF
    rdVector3 a4; // [esp+28h] [ebp-18h] BYREF
    rdVector3 a5; // [esp+34h] [ebp-Ch] BYREF
    float unused;

    instinct->nextUpdate = sithTime_curMs + aiclass->argsAsInt[0];
    if ( actor->thingidk )
    {
        v8 = aiclass->argsAsInt[4];
        sithAI_sub_4EAF40(actor);
        if ( aiclass->argsAsFloat[2] >= (double)actor->field_234 && !actor->field_238 )
        {
            a2a.x = actor->field_228.x * -actor->field_234;
            a2a.y = actor->field_228.y * -actor->field_234;
            a2a.z = actor->field_228.z * -actor->field_234;
            if ( v8
              || actor->thingidk->lookOrientation.lvec.y * a2a.y + actor->thingidk->lookOrientation.lvec.z * a2a.z + actor->thingidk->lookOrientation.lvec.x * a2a.x >= 0.0 )
            {
                if ( instinct->param0 == 0.0 || v8 )
                {
                    if ( _frand() >= 0.5 )
                        instinct->param0 = 1.0;
                    else
                        instinct->param0 = -1.0;
                }
                rdVector_Zero3(&a4);
                if ( v8 )
                {
                    v13 = (_frand() - -0.5) * instinct->param0 * aiclass->argsAsFloat[1];
                }
                else
                {
                    v13 = aiclass->argsAsFloat[1] * instinct->param0;
                }
                a4.y = v13;
                rdVector_Rotate3(&movePos, &a2a, &a4);
                movePos.x = movePos.x + actor->thingidk->position.x;
                movePos.y = actor->thingidk->position.y + movePos.y;
                movePos.z = actor->thingidk->position.z + movePos.z;
                if ( !sithAI_sub_4EB300(actor->thingidk, &actor->thingidk->position, &movePos, -1.0, actor->aiclass->sightDist, 0.0, &a5, &unused) )
                {
                    sithAI_SetMoveThing(actor, &movePos, 0.5);
                    sithAI_SetLookFrame(actor, &actor->thingidk->position);
                    instinct->nextUpdate = sithTime_curMs + aiclass->argsAsInt[3];
                    return 0;
                }
                instinct->param0 = -instinct->param0;
            }
        }
    }
    return 0;
}

int sithAICmd_Crouch(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, int otherFlags)
{
    instinct->nextUpdate = sithTime_curMs + aiclass->argsAsInt[0];
    if (!(actor->flags & SITHAIFLAGS_MOVING_TO_DEST) 
        && (actor->flags & SITHAIFLAGS_ATTACKING_TARGET)
        && (actor->flags & SITHAIFLAGS_TARGET_SIGHTED_IN_RANGE))
    {
        actor->thing->physicsParams.physflags |= PHYSFLAGS_CROUCHING;
        return 0;
    }
    else
    {
        actor->thing->physicsParams.physflags &= ~PHYSFLAGS_CROUCHING;
        return 0;
    }
}

int sithAICmd_BlindFire(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, int otherFlags)
{
    sithThing *weapon; // esi
    unsigned int bWhichProjectile; // ebp
    sithThing *projectile; // ebx
    sithThing *v11; // eax
    int v13; // eax
    rdVector3 fireOffs; // [esp+2Ch] [ebp-Ch] BYREF
    float fOut;

    weapon = actor->thing;
    if ( aiclass->argsAsFloat[1] < _frand() || actor->field_288 > sithTime_curMs )
    {
        instinct->nextUpdate = sithTime_curMs + 1000;
    }
    else
    {
        bWhichProjectile = aiclass->argsAsInt[2];
        instinct->nextUpdate = sithTime_curMs + aiclass->argsAsInt[0];
        if ( bWhichProjectile > 1 )
            bWhichProjectile = 1;
        if ( bWhichProjectile == 1 )
            projectile = weapon->actorParams.templateWeapon2;
        else
            projectile = weapon->actorParams.templateWeapon;
        if ( !actor->field_1D0 || !projectile )
        {
            actor->flags &= ~SITHAIFLAGS_ATTACKING_TARGET;
            return 1;
        }
        if ( !sithAI_sub_4EB300(weapon, &weapon->position, &actor->field_1F8, aiclass->argsAsFloat[3], 10.0, projectile->moveSize, &fireOffs, &fOut)
          && fOut >= (double)aiclass->argsAsFloat[4] )
        {
            if ( actor->field_1F0 != 0.0 && aiclass->argsAsFloat[5] != 0.0 )
            {
                sithAI_RandomFireVector(&fireOffs, aiclass->argsAsFloat[5] / fOut);
            }
            if ( (g_debugmodeFlags & 0x80u) == 0 )
            {
                sithSoundClass_ThingPlaySoundclass4(weapon, bWhichProjectile + SITH_SC_FIRE1);
                v11 = sithWeapon_Fire(weapon, projectile, &fireOffs, &actor->blindAimError, 0, bWhichProjectile + SITH_ANIM_FIRE, 1.0, 0, 0.0);
                if ( v11 )
                {
                    sithCog_SendMessageFromThing(weapon, v11, SITH_MESSAGE_FIRE);
                    return 0;
                }
            }
        }
    }
    return 0;
}

int sithAICmd_LobFire(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, int otherFlags)
{
    int v5; // ebx
    sithThing *v6; // eax
    sithThing *v7; // ebp
    int v11; // eax

    v5 = 0;
    v6 = actor->thing;
    v7 = actor->field_1D0;
    if ( flags )
    {
        if ( flags == SITHAIFLAGS_UNK100 )
        {
            if ( (actor->flags & SITHAIFLAGS_AWAKE_AND_ACTIVE) != 0 )
                sithPuppet_SetArmedMode(v6, 1);
            else
                sithPuppet_SetArmedMode(v6, 0);
            instinct->nextUpdate = sithTime_curMs + 1000;
            return 0;
        }
        return 0;
    }
    if ( (v7->thingflags & (SITH_TF_DEAD|SITH_TF_WILLBEREMOVED)) == 0 )
    {
        if ( aiclass->argsAsFloat[5] > _frand() )
            v5 = 1;
        if ( sithAI_FireWeapon(actor, aiclass->argsAsFloat[2], aiclass->argsAsFloat[3], aiclass->argsAsFloat[1], aiclass->argsAsFloat[4], v5, 2) )
        {
            actor->flags |= SITHAIFLAGS_TARGET_SIGHTED_IN_RANGE;
            v11 = sithTime_curMs + aiclass->argsAsInt[0];
            instinct->nextUpdate = v11;
            actor->field_288 = v11;
            return 0;
        }
        sithAI_SetLookFrame(actor, &v7->position);
        actor->flags |= SITHAIFLAGS_TARGET_SIGHTED_IN_RANGE;
        instinct->nextUpdate = sithTime_curMs + 500;
        return 0;
    }
    if ( (actor->flags & SITHAIFLAGS_TARGET_SIGHTED_IN_RANGE) != 0 )
    {
        sithSoundClass_ThingPlaySoundclass(v6, SITH_SC_VICTORY);
        sithPuppet_PlayMode(actor->thing, SITH_ANIM_VICTORY, 0);
    }

    actor->flags &= ~(SITHAIFLAGS_TARGET_SIGHTED_IN_RANGE|SITHAIFLAGS_AWAKE_AND_ACTIVE|SITHAIFLAGS_HAS_TARGET|SITHAIFLAGS_ATTACKING_TARGET);
    actor->flags |= SITHAIFLAGS_SEARCHING;
    return 1;
}

int sithAICmd_PrimaryFire(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, int otherFlags)
{
    int v5; // ebp
    int v6; // ebx
    sithThing *v7; // eax
    int v9; // edx
    rdVector3 v18; // [esp+28h] [ebp-Ch] BYREF

    v5 = 0;
    v6 = 0;
    v7 = actor->thing;
    if ( flags )
    {
        if ( flags == SITHAIFLAGS_UNK100 )
        {
            if ( (actor->flags & SITHAIFLAGS_AWAKE_AND_ACTIVE) != 0 )
            {
                sithPuppet_SetArmedMode(v7, 1);
                v9 = sithTime_curMs + aiclass->argsAsInt[5];
                instinct->param0 = aiclass->argsAsFloat[8];
                instinct->nextUpdate = v9;
            }
            else
            {
                sithPuppet_SetArmedMode(v7, 0);
            }
            return 0;
        }
        return 0;
    }
    if ( !actor->field_1D0 )
        return 0;
    if ( (actor->field_1D0->thingflags & (SITH_TF_DEAD|SITH_TF_WILLBEREMOVED)) == 0 )
    {
        if ( aiclass->argsAsFloat[6] != 0.0 && aiclass->argsAsFloat[6] >= _frand() )
            v5 = 1;
        if ( aiclass->argsAsFloat[7] != 0.0 && aiclass->argsAsFloat[7] >= _frand() )
            v6 = 1;
        if ( sithAI_FireWeapon(actor, aiclass->argsAsFloat[4], aiclass->argsAsFloat[2], aiclass->argsAsFloat[1], aiclass->argsAsFloat[3], v6, v5) )
        {
            actor->flags |= SITHAIFLAGS_TARGET_SIGHTED_IN_RANGE;
            if ( instinct->param0 == 0.0 )
            {
                instinct->param0 = aiclass->argsAsFloat[8];
                instinct->nextUpdate = sithTime_curMs + (int64_t)((_frand() * 0.40000001 - 0.2 - -1.0) * aiclass->argsAsFloat[0]);
            }
            else
            {
                instinct->nextUpdate = sithTime_curMs + aiclass->argsAsInt[9];
                instinct->param0 = instinct->param0 - 1.0;
            }
            return 0;
        }
        instinct->param0 = aiclass->argsAsFloat[8];
        if ( actor->field_1F4 == 2 )
        {
            sithAI_SetLookFrame(actor, &actor->field_1D4);
        }
        else if ( !actor->field_1F4 )
        {
            if (actor->field_1D0 && actor->field_1D0->move_type == MOVETYPE_PHYSICS )
            {
                rdVector_Copy3(&v18, &actor->field_1D0->position);
                rdVector_MultAcc3(&v18, &actor->field_1D0->physicsParams.vel, 0.5);
                sithAI_SetLookFrame(actor, &v18);
            }
        }
        if ( actor->field_1F4 == 3 )
        {
            actor->flags &= ~SITHAIFLAGS_TARGET_SIGHTED_IN_RANGE;
        }
        instinct->nextUpdate = sithTime_curMs + 250;
        return 0;
    }
    if ( (actor->flags & SITHAIFLAGS_TARGET_SIGHTED_IN_RANGE) != 0 )
    {
        sithSoundClass_ThingPlaySoundclass(v7, SITH_SC_VICTORY);
        sithPuppet_PlayMode(actor->thing, SITH_ANIM_VICTORY, 0);
    }

    instinct->param0 = aiclass->argsAsFloat[8];
    actor->flags &= ~(SITHAIFLAGS_TARGET_SIGHTED_IN_RANGE|SITHAIFLAGS_AWAKE_AND_ACTIVE|SITHAIFLAGS_HAS_TARGET|SITHAIFLAGS_ATTACKING_TARGET);
    actor->flags |= SITHAIFLAGS_SEARCHING;
    return 1;
}

// sithAICmd_TurretFire
// sithAICmd_Listen

int sithAICmd_LookForTarget(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, void *extra)
{
    int v6; // ecx
    unsigned int v9; // edx
    sithThing *v10; // eax
    int v11; // ecx
    sithThing *v12; // [esp-8h] [ebp-10h]

    if ( !flags && (g_debugmodeFlags & 0x200) == 0 )
    {
        if ( (actor->flags & SITHAIFLAGS_AWAKE_AND_ACTIVE) != 0 )
        {
            v6 = aiclass->argsAsInt[1];
            if ( v6 && v6 + actor->field_204 < sithTime_curMs )
            {
                actor->flags &= ~(SITHAIFLAGS_TARGET_SIGHTED_IN_RANGE|SITHAIFLAGS_AWAKE_AND_ACTIVE|SITHAIFLAGS_HAS_TARGET|SITHAIFLAGS_ATTACKING_TARGET);
                actor->flags |= SITHAIFLAGS_SEARCHING;
                sithUnk4_MoveJointsForEyePYR(actor->thing, &rdroid_zeroVector3);
                return 1;
            }
        }
        else if ( (actor->flags & SITHAIFLAGS_SEARCHING) != 0 )
        {
            v9 = sithTime_curMs;
            v10 = g_localPlayerThing;
            v11 = aiclass->argsAsInt[0];
            actor->field_1D0 = g_localPlayerThing;
            instinct->nextUpdate = v9 + v11;
            if ( (v10->thingflags & (SITH_TF_DEAD|SITH_TF_WILLBEREMOVED)) == 0 )
            {
                sithAI_sub_4EAD60(actor);
                if ( !actor->field_1F4 )
                {
                    v12 = actor->thing;
                    actor->flags &= ~SITHAIFLAGS_SEARCHING;
                    actor->flags |= (SITHAIFLAGS_AWAKE_AND_ACTIVE|SITHAIFLAGS_HAS_TARGET|SITHAIFLAGS_HAS_DEST|SITHAIFLAGS_ATTACKING_TARGET);
                    sithSoundClass_ThingPlaySoundclass(v12, SITH_SC_ALERT);
                    sithSoundClass_ThingPlaySoundclass4(actor->thing, SITH_SC_ACTIVATE);
                    sithSector_AddEntry(actor->field_1D0->sector, &actor->thing->position, 0, 3.0, actor->field_1D0);
                    actor->thingidk = actor->field_1D0;
                    return 1;
                }
                if ( aiclass->argsAsFloat[0] == 0.0 )
                    aiclass->argsAsFloat[0] = 500.0;
            }
        }
    }
    return 0;
}

int sithAICmd_OpenDoors(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, void *extra)
{
    if ( (actor->flags & SITHAIFLAGS_MOVING_TO_DEST) != 0 )
    {
        sithActor_cogMsg_OpenDoor(actor->thing);
        instinct->nextUpdate = sithTime_curMs + 1000;
    }
    return 0;
}

int sithAICmd_Jump(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, void *extra)
{
    sithActor *v5; // edi
    sithThing *v6; // esi
    sithSector *v7; // ebx
    rdVector3 a2; // [esp+Ch] [ebp-18h] BYREF
    rdVector3 a3; // [esp+18h] [ebp-Ch] BYREF

    v5 = actor;
    v6 = actor->thing;
    v7 = actor->thing->sector;
    if ( !actor->thing->attach_flags )
        return 0;
    if (!(actor->flags & SITHAIFLAGS_MOVING_TO_DEST))
        return 0;
    if ( actor->field_228.x * v6->physicsParams.vel.x
       + actor->field_228.y * v6->physicsParams.vel.y
       + actor->field_228.z * v6->physicsParams.vel.z > 0.02 )
        return 0;
    //*(_QWORD *)&a2.x = sithTime_curMs;
    if ( (double)sithTime_curMs < instinct->param0 )
        return 0;

    instinct->param0 = aiclass->argsAsFloat[0] + (double)sithTime_curMs;
    if ( flags != SITHAIFLAGS_SEARCHING && flags != SITHAIFLAGS_AWAKE_AND_ACTIVE )
    {
        if ( flags != SITHAIFLAGS_TARGET_SIGHTED_IN_RANGE )
            return 0;

        a2.x = (aiclass->argsAsFloat[2] * v5->field_1AC.x) + v6->position.x;
        a2.y = (aiclass->argsAsFloat[2] * v5->field_1AC.y) + v6->position.y;
        a2.z = (aiclass->argsAsFloat[2] * v5->field_1AC.z) + v6->position.z;
        if ( sithAI_physidk(v5, &a2, 0) )
        {
            rdVector_MultAcc3(&v6->physicsParams.vel, &v5->field_1AC, 0.1);
            sithAI_Jump(v5, &v5->movePos, 1.0);
            return 1;
        }
        return 1;
    }
    rdVector_Copy3(&a3, &v6->position);
    rdVector_MultAcc3(&a3, &rdroid_zVector3, aiclass->argsAsFloat[1]);
    sithSector* result = sithUnk3_GetSectorLookAt(v7, &v6->position, &a3, 0.0);
    if ( result )
    {
        a2.x = v5->field_1AC.x * 0.1 + a3.x;
        a2.y = v5->field_1AC.y * 0.1 + a3.y;
        a2.z = a3.z;
        result = sithUnk3_GetSectorLookAt(result, &a3, &a2, 0.0);
        if ( result )
        {
            int tmp;
            if ( sithAI_sub_4EB640(v5, &a2, result, &tmp) == 1 )
            {
                if ( tmp )
                    sithAI_Jump(v5, &a2, 1.0);
            }
            return 1;
        }
    }
    return 0;
}

int sithAICmd_Flee(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, void *extra)
{
    int v7; // ecx
    double v8; // st7
    int result; // eax
    sithThing *v11; // edi
    int v12; // eax
    sithThing *v15; // ecx
    sithThing *v16; // eax
    rdVector3 a5; // [esp+Ch] [ebp-24h] BYREF
    rdVector3 v19; // [esp+18h] [ebp-18h] BYREF
    rdVector3 movePos; // [esp+24h] [ebp-Ch] BYREF
    float aiclass1a; // [esp+38h] [ebp+8h]
    float tmp;

    v7 = actor->flags;
    aiclass1a = aiclass->argsAsFloat[0];
    v8 = aiclass->argsAsFloat[2];
    if ( (v7 & SITHAIFLAGS_FLEEING) == 0 )
        return 0;

    if ( instinct->param0 == 0.0 )
        instinct->param0 = sithTime_curSeconds;
    if ( v8 == 0.0 )
        v8 = 10.0;
    v11 = actor->field_1C0;
    if ( !v11
      || sithTime_curSeconds > instinct->param0 + v8
      || ((v12 = aiclass->argsAsInt[1], actor->flags = v7 & ~SITHAIFLAGS_ATTACKING_TARGET, !v12) ? (instinct->nextUpdate = sithTime_curMs + 5000) : (instinct->nextUpdate = v12 + sithTime_curMs),
          sithAI_sub_4EB090(actor->thing, &actor->thing->position, v11, -1.0, aiclass1a, 0.0, &a5, &tmp)) )
    {
        v16 = actor->field_1C0;
        if ( v16 )
            sithAI_SetLookFrame(actor, &v16->position);
        actor->field_1C0 = 0;
        actor->flags &= ~(SITHAIFLAGS_FLEEING|SITHAIFLAGS_AWAKE_AND_ACTIVE);
        actor->flags |= SITHAIFLAGS_SEARCHING;
        
        instinct->param0 = 0.0;
        result = 1;
    }
    else
    {
        v19.x = 0.0;
        v19.y = 0.0;
        v19.z = 0.0;
        if ( flags )
        {
            if ( flags == SITHAIFLAGS_UNK100 || flags == SITHAIFLAGS_FLEEING )
            {
                a5.x = -a5.x;
                a5.y = -a5.y;
                a5.z = -a5.z;
                v15 = actor->thing;
                v19.y = (_frand() - 0.5) * 180.0;
                if ( (v15->physicsParams.physflags & PHYSFLAGS_FLYING) != 0 )
                    v19.x = (_frand() - 0.5) * 90.0;
                rdVector_Rotate3Acc(&a5, &v19);
            }
            else
            {
                v19.y = 90.0;
                if ( _frand() >= 0.5 )
                    v19.y = -90.0;
                rdVector_Rotate3(&a5, &actor->field_1AC, &v19);
            }
            movePos.x = a5.x * aiclass1a + actor->thing->position.x;
            movePos.y = a5.y * aiclass1a + actor->thing->position.y;
            movePos.z = a5.z * aiclass1a + actor->thing->position.z;
            sithAI_SetMoveThing(actor, &movePos, 2.5);
            sithAI_SetLookFrame(actor, &movePos);
            result = 0;
        }
        else
        {
            result = 0;
        }
    }
    return result;
}

int sithAICmd_Withdraw(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, void *extra)
{
    int result; // eax
    sithThing *v13; // eax
    sithThing *v14; // eax
    rdVector3 a5; // [esp+4h] [ebp-24h] BYREF
    rdVector3 v17; // [esp+10h] [ebp-18h] BYREF
    rdVector3 movePos; // [esp+1Ch] [ebp-Ch] BYREF
    float tmp;

    if ( (actor->flags & SITHAIFLAGS_FLEEING) == 0 )
        return 0;

    if ( actor->field_1C0 )
    {
        if ( aiclass->argsAsInt[0] )
            instinct->nextUpdate = aiclass->argsAsInt[0] + sithTime_curMs;
        else
            instinct->nextUpdate = sithTime_curMs + 5000;

        if ( sithAI_sub_4EB090(actor->thing, &actor->thing->position, actor->field_1C0, -1.0, actor->aiclass->sightDist, 0.0, &a5, &tmp) )
        {
            result = 1;
            actor->flags &= ~(SITHAIFLAGS_FLEEING|SITHAIFLAGS_AWAKE_AND_ACTIVE);
            actor->flags |= SITHAIFLAGS_SEARCHING;
        }
        else
        {
            rdVector_Zero3(&v17);
            if ( !flags || flags == SITHAIFLAGS_UNK100 || flags == SITHAIFLAGS_FLEEING )
            {
                rdVector_Neg3Acc(&a5);
                v14 = actor->thing;
                v17.y = (_frand() - 0.5) * 180.0;
                if ( (v14->physicsParams.physflags & PHYSFLAGS_FLYING) != 0 )
                {
                    v17.x = (_frand() - 0.5) * 90.0;
                }
                rdVector_Rotate3Acc(&a5, &v17);
                v13 = actor->thing;
            }
            else
            {
                v17.y = 90.0;
                if (_frand() >= 0.5)
                    v17.y = -90.0;
                rdVector_Rotate3(&a5, &actor->field_1AC, &v17);
                v13 = actor->thing;
            }
            movePos.x = aiclass->argsAsFloat[1] * a5.x + v13->position.x;
            movePos.y = aiclass->argsAsFloat[1] * a5.y + v13->position.y;
            movePos.z = aiclass->argsAsFloat[1] * a5.z + v13->position.z;
            sithAI_SetMoveThing(actor, &movePos, 1.5);
            result = 0;
        }
    }
    else
    {
        actor->flags &= ~SITHAIFLAGS_FLEEING;
        result = 0;
    }
    return result;
}

int sithAICmd_Dodge(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, sithThing *extra)
{
    sithSectorAlloc *v16; // ecx
    rdVector3 a5; // [esp+10h] [ebp-24h] BYREF
    rdVector3 movePos; // [esp+1Ch] [ebp-18h] BYREF
    rdVector3 vAngs; // [esp+28h] [ebp-Ch] BYREF
    float actora; // [esp+38h] [ebp+4h]
    float tmp;

    if ( !flags )
        return 0;
    if ( flags == SITHAIFLAGS_MOVING_TO_DEST )
    {
        if ( aiclass->argsAsFloat[1] != 0.0 && extra && (actor->flags & SITHAIFLAGS_MOVING_TO_DEST) == 0 )
        {
            vAngs.x = extra->position.x;
            vAngs.y = extra->position.y;
            vAngs.z = extra->position.z;
            a5.x = vAngs.x - actor->thing->position.x;
            a5.y = vAngs.y - actor->thing->position.y;
            a5.z = vAngs.z - actor->thing->position.z;
            actora = -aiclass->argsAsFloat[1];
            tmp = rdVector_Normalize3Acc(&a5);
            movePos.x = a5.x * actora + actor->thing->position.x;
            movePos.y = a5.y * actora + actor->thing->position.y;
            movePos.z = a5.z * actora + actor->thing->position.z;
            sithAI_SetMoveThing(actor, &movePos, 2.5);
            actor->field_28C = sithTime_curMs + 1000;
            return 0;
        }
        return 0;
    }
    if ( flags != SITHAIFLAGS_AT_EASE )
    {
        if ( (actor->flags & SITHAIFLAGS_AWAKE_AND_ACTIVE) != 0 && flags == SITHAIFLAGS_ATTACKING_TARGET && aiclass->argsAsFloat[0] != 0.0 )
        {
            v16 = &sithSector_allocPerSector[actor->thing->sector->id];
            if (v16->field_C)
            {
                if ( v16->field_60 )
                {
                    if ( sithThing_GetParent(v16->field_60) != actor->thing
                      && v16->field_60->thingType == THINGTYPE_WEAPON
                      && v16->field_60->move_type == MOVETYPE_PHYSICS
                      && !sithAI_sub_4EB090(actor->thing, &actor->thing->position, v16->field_60, actor->aiclass->fov, 1.0, 0.0, &a5, &tmp) )
                    {
                        movePos.x = a5.x * -aiclass->argsAsFloat[0] + actor->thing->position.x;
                        movePos.y = a5.y * -aiclass->argsAsFloat[0] + actor->thing->position.y;
                        movePos.z = a5.z * -aiclass->argsAsFloat[0] + actor->thing->position.z;
                        sithAI_SetMoveThing(actor, &movePos, 2.5);
                        actor->field_28C = sithTime_curMs + 1000;
                        sithSoundClass_ThingPlaySoundclass(actor->thing, SITH_SC_CURIOUS);
                    }
                }
            }
        }
        return 0;
    }
    if ( (actor->flags & SITHAIFLAGS_AWAKE_AND_ACTIVE) == 0 )
        return 0;

    if ( aiclass->argsAsFloat[1] == 0.0
      || !extra
      || sithAI_sub_4EB090(actor->thing, &actor->thing->position, extra, actor->aiclass->fov, actor->aiclass->sightDist, 0.0, &a5, (float *)&extra) )
    {
        return 0;
    }
    rdVector_Zero3(&vAngs);
    vAngs.y = _frand() * 45.0 - -45.0;
    if ( _frand() < 0.5 )
        vAngs.y = -vAngs.y;
    rdVector_Rotate3Acc(&a5, &vAngs);
    movePos.x = a5.x * -aiclass->argsAsFloat[1] + actor->thing->position.x;
    movePos.y = a5.y * -aiclass->argsAsFloat[1] + actor->thing->position.y;
    movePos.z = a5.z * -aiclass->argsAsFloat[1] + actor->thing->position.z;
    sithAI_SetMoveThing(actor, &movePos, 2.5);
    return 0;
}

int sithAICmd_RandomTurn(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, sithThing *extra)
{
    int result; // eax
    rdVector3 out; // [esp+20h] [ebp-30h] BYREF
    rdVector3 vAngs; // [esp+2Ch] [ebp-24h] BYREF
    rdVector3 arg8; // [esp+38h] [ebp-18h] BYREF
    rdVector3 a5; // [esp+44h] [ebp-Ch] BYREF
    float tmp;

    if ( aiclass->argsAsInt[0] )
        instinct->nextUpdate = sithTime_curMs + aiclass->argsAsInt[0];
    else
        instinct->nextUpdate = sithTime_curMs + 5000;
    if ( (actor->flags & 4) == 0 )
        return 0;
    vAngs.x = 0.0;
    vAngs.z = 0.0;
    out = rdroid_yVector3;
    vAngs.y = _frand() * 360.0;
    rdVector_Rotate3Acc(&out, &vAngs);
    arg8.x = aiclass->argsAsFloat[1] * out.x + actor->thing->position.x;
    arg8.y = aiclass->argsAsFloat[1] * out.y + actor->thing->position.y;
    arg8.z = aiclass->argsAsFloat[1] * out.z + actor->thing->position.z;
    result = sithAI_sub_4EB300(actor->thing, &actor->thing->position, &arg8, -1.0, aiclass->argsAsFloat[1], 0.0, &a5, &tmp);
    if ( !result )
        sithAI_SetLookFrame(actor, &arg8);
    return result;
}

int sithAICmd_Roam(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, void *extra)
{
    double randVal; // st6
    rdVector3 *v13; // [esp-8h] [ebp-30h]
    rdVector3 movePos; // [esp+4h] [ebp-24h] BYREF
    rdVector3 v16; // [esp+10h] [ebp-18h] BYREF
    rdVector3 v17; // [esp+1Ch] [ebp-Ch] BYREF

    instinct->nextUpdate = sithTime_curMs + aiclass->argsAsInt[0];
    if ( (actor->flags & SITHAIFLAGS_ATTACKING_TARGET) == 0 )
    {
        rdVector_Zero3(&v17);
        v13 = &actor->thing->lookOrientation.lvec;
        v17.y = (_frand() - 0.5) * 360.0;
        rdVector_Rotate3(&v16, v13, &v17);
        if ( aiclass->argsAsFloat[1] <= 0.0 )
        {
            randVal = _frand() * -aiclass->argsAsFloat[1];
            movePos.x = v16.x * randVal + actor->thing->position.x;
            movePos.y = v16.y * randVal + actor->thing->position.y;
            movePos.z = v16.z * randVal + actor->thing->position.z;
        }
        else
        {
            randVal = _frand() * aiclass->argsAsFloat[1];
            movePos.x = v16.x * randVal + actor->position.x;
            movePos.y = v16.y * randVal + actor->position.y;
            movePos.z = v16.z * randVal + actor->position.z;
        }
        sithAI_SetLookFrame(actor, &movePos);
        sithAI_SetMoveThing(actor, &movePos, 1.0);
    }
    return 0;
}

// sithAICmd_SenseDanger
// sithAICmd_HitAndRun
// sithAICmd_Retreat
// sithAICmd_ReturnHome
// sithAICmd_Talk

