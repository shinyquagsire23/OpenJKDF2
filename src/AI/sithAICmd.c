#include "sithAICmd.h"

#include "General/stdMath.h"
#include "AI/sithAI.h"
#include "AI/sithAIAwareness.h"
#include "World/sithThing.h"
#include "Gameplay/sithPlayerActions.h"
#include "Cog/sithCog.h"
#include "Gameplay/sithTime.h"
#include "World/sithSoundClass.h"
#include "Engine/sithAnimClass.h"
#include "Engine/sithPuppet.h"
#include "AI/sithAIClass.h"
#include "Main/jkGame.h"
#include "World/sithWeapon.h"
#include "World/jkPlayer.h"
#include "World/sithSector.h"
#include "World/sithActor.h"
#include "Engine/sithCollision.h"
#include "Dss/sithMulti.h"
#include "jk.h"

// Added: Targeting for multiple players for co-op
sithThing* sithAICmd_NearestPlayer(sithActor *actor)
{
    if (!sithNet_isMulti)
        return sithPlayer_pLocalPlayerThing;

    sithThing* closest = sithPlayer_pLocalPlayerThing;
    float closestDist = 999999.0;
    for (int i = 0; i < jkPlayer_maxPlayers; i++)
    {
        sithPlayerInfo* playerInfo = &jkPlayer_playerInfos[i];
        sithThing* playerThing = playerInfo->playerThing;
        if (!playerThing) continue;

        if ((playerThing->thingflags & (SITH_TF_DISABLED|SITH_TF_DEAD|SITH_TF_WILLBEREMOVED)) || playerThing->type != SITH_THING_PLAYER)
            continue;

        float dist = rdVector_Dist3(&playerThing->position, &actor->thing->position);
        if (dist < closestDist) {
            closestDist = dist;
            closest = playerThing;
        }
    }
    return closest;
}

void sithAICmd_Startup()
{
    sithAI_RegisterCommand("listen", sithAICmd_Listen, 
        0, // allowed flags...?
        0, // disallowed flags
        SITHAI_MODE_SEARCHING|SITHAI_MODE_ATTACKING|SITHAI_MODE_MOVING);
    
    sithAI_RegisterCommand("lookfortarget", sithAICmd_LookForTarget, 
        SITHAI_MODE_ACTIVE|SITHAI_MODE_SEARCHING, // allowed flags
        0,                              // disallowed flags
        0);
    
    if (Main_bMotsCompat) {
        sithAI_RegisterCommand("lookforopposingtarget", sithAICmd_LookForOpposingTarget, 
            SITHAI_MODE_ACTIVE|SITHAI_MODE_SEARCHING, // allowed flags
            0,                              // disallowed flags
            0);
    }

    sithAI_RegisterCommand("primaryfire", sithAICmd_PrimaryFire, 
        SITHAI_MODE_ATTACKING,   // allowed flags
        0,                              // disallowed flags
        SITHAI_MODE_UNK100);

    if (Main_bMotsCompat) {
        sithAI_RegisterCommand("leap", sithAICmd_Leap, 
            SITHAI_MODE_ATTACKING,   // allowed flags
            0,                              // disallowed flags
            SITHAI_MODE_UNK100|SITHAI_MODE_SEARCHING);
        sithAI_RegisterCommand("charge", sithAICmd_Charge, 
            SITHAI_MODE_ATTACKING,   // allowed flags
            0,                              // disallowed flags
            SITHAI_MODE_UNK100|SITHAI_MODE_SEARCHING);
    }
    sithAI_RegisterCommand("follow", sithAICmd_Follow,
        SITHAI_MODE_ATTACKING,   // allowed flags
        SITHAI_MODE_FLEEING,            // disallowed flags
        SITHAI_MODE_FLEEING|SITHAI_MODE_TARGET_VISIBLE|SITHAI_MODE_ACTIVE);
    sithAI_RegisterCommand("turretfire", sithAICmd_TurretFire, 
        SITHAI_MODE_ATTACKING,   // allowed flags
        SITHAI_MODE_FLEEING,            // disallowed flags
        SITHAI_MODE_UNK100);
    sithAI_RegisterCommand("opendoors", sithAICmd_OpenDoors, 
        SITHAI_MODE_ATTACKING,   // allowed flags
        0,                              // disallowed flags
        0);
    sithAI_RegisterCommand("jump", sithAICmd_Jump, 
        0,                      // allowed flags
        0,                      // disallowed flags
        SITHAI_MODE_TARGET_VISIBLE|SITHAI_MODE_ACTIVE|SITHAI_MODE_SEARCHING);
    sithAI_RegisterCommand("randomturn", sithAICmd_RandomTurn, 
        SITHAI_MODE_SEARCHING,  // allowed flags
        0,                      // disallowed flags
        0);
    sithAI_RegisterCommand("roam", sithAICmd_Roam, 
        SITHAI_MODE_SEARCHING,  // allowed flags
        0,                      // disallowed flags
        0);
    sithAI_RegisterCommand("flee", sithAICmd_Flee,
        SITHAI_MODE_FLEEING,    // allowed flags
        0,                      // disallowed flags
        SITHAI_MODE_FLEEING|SITHAI_MODE_TARGET_VISIBLE|SITHAI_MODE_ACTIVE|SITHAI_MODE_UNK100|SITHAI_MODE_SEARCHING|SITHAI_MODE_MOVING);
    sithAI_RegisterCommand("sensedanger", sithAICmd_SenseDanger,
        SITHAI_MODE_SEARCHING, // SenseDanger allowed flags
        SITHAI_MODE_FLEEING,   // SenseDanger disallowed flags
        SITHAI_MODE_SEARCHING|SITHAI_MODE_ATTACKING|SITHAI_MODE_MOVING); // SenseDanger idk?
    sithAI_RegisterCommand("hitandrun", sithAICmd_HitAndRun, 
        SITHAI_MODE_FLEEING|SITHAI_MODE_TARGET_VISIBLE, // HitAndRun allowed flags
        0,                            // HitAndRun disallowed flags
        0);                           // HitAndRun idk?
    sithAI_RegisterCommand("retreat", sithAICmd_Retreat, 
        SITHAI_MODE_ATTACKING, // allowed flags
        SITHAI_MODE_FLEEING,          // disallowed flags
        0);
    sithAI_RegisterCommand("circlestrafe", sithAICmd_CircleStrafe, 
        SITHAI_MODE_ATTACKING, // allowed flags
        SITHAI_MODE_FLEEING,          // disallowed flags
        0);
    sithAI_RegisterCommand("blindfire", sithAICmd_BlindFire, 
        SITHAI_MODE_ATTACKING, // allowed flags
        SITHAI_MODE_FLEEING|SITHAI_MODE_TARGET_VISIBLE, // disallowed flags
        0);
    sithAI_RegisterCommand("returnhome", sithAICmd_ReturnHome, 
        0, // allowed flags
        0, // disallowed flags
        SITHAI_MODE_FLEEING|SITHAI_MODE_UNK100);
    sithAI_RegisterCommand("lobfire", sithAICmd_LobFire, 
        SITHAI_MODE_ATTACKING,   // allowed flags
        0,                              // disallowed flags
        SITHAI_MODE_UNK100);
    sithAI_RegisterCommand("talk", sithAICmd_Talk, 
        0xFFFF, // allowed flags (any)
        0,      // disallowed flags
        0);
    sithAI_RegisterCommand("crouch", sithAICmd_Crouch, 
        SITHAI_MODE_ATTACKING, // allowed flags
        0, // disallowed flags
        SITHAI_MODE_UNK100);
    sithAI_RegisterCommand("withdraw", sithAICmd_Withdraw,
        SITHAI_MODE_FLEEING, // allowed flags
        0, // disallowed flags
        SITHAI_MODE_FLEEING|SITHAI_MODE_TARGET_VISIBLE|SITHAI_MODE_ACTIVE|SITHAI_MODE_UNK100|SITHAI_MODE_SEARCHING|SITHAI_MODE_MOVING);
    sithAI_RegisterCommand("dodge", sithAICmd_Dodge, 
        0, // allowed flags
        0, // disallowed flags
        SITHAI_MODE_SLEEPING|SITHAI_MODE_ATTACKING|SITHAI_MODE_MOVING);
}

// MoTS altered (done)
/*
p0 - Min Distance to allow
p1 - Max Dist to allow
p2 - Max Melee dist (rifle/punch combo)
p3 - Set to 1 to disable LOS checking (enemy doesn't need to see)
*/
int sithAICmd_Follow(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, intptr_t otherFlags)
{
    sithThing *v7; // ebp
    sithAIClassEntry *v8; // ebx
    sithActorInstinct *v9; // edi
    int v10; // eax
    double v16; // st7
    rdVector3 a4a; // [esp+10h] [ebp-3Ch] BYREF
    rdVector3 arg8a; // [esp+1Ch] [ebp-30h] BYREF
    rdVector3 a1; // [esp+28h] [ebp-24h] BYREF
    rdVector3 a2; // [esp+34h] [ebp-18h] BYREF
    rdVector3 a5; // [esp+40h] [ebp-Ch] BYREF
    float argMaxDistToAllow; // [esp+50h] [ebp+4h]
    float argMaxMeleeDist;
    float argMinDistToAllow;
    float tmp;

    if ( flags > SITHAI_MODE_ACTIVE )
    {
        if ( flags != SITHAI_MODE_TARGET_VISIBLE )
        {
            if ( flags != SITHAI_MODE_FLEEING || (actor->flags & SITHAI_MODE_ACTIVE) == 0 || instinct->param0 == 0.0 )
                return 0;
            a4a.x = 0.0;
            a4a.z = 0.0;
            a4a.y = (_frand() - 0.5) * 90.0;
            if ( _frand() >= 0.5 )
            {
                sithAI_sub_4EAF40(actor);
                rdVector_Rotate3(&a1, &actor->field_228, &a4a);
            }
            else
            {
                rdVector_Rotate3(&a1, &actor->thing->lookOrientation.lvec, &a4a);
            }
            rdVector_Copy3(&a2, &actor->thing->position);
            rdVector_MultAcc3(&a2, &a1, 0.7);
            sithAI_SetLookFrame(actor, &a2);
            sithAI_SetMoveThing(actor, &a2, 2.0);
            return 0;
        }
    }
    else if ( flags != SITHAI_MODE_ACTIVE )
    {
        if ( !flags)
        {
            v7 = actor->pMoveThing;
            if (!v7) {
                return 0;
            }
            
            v8 = aiclass;
            v9 = instinct;
            argMinDistToAllow = aiclass->argsAsFloat[0];
            argMaxDistToAllow = aiclass->argsAsFloat[1];
            argMaxMeleeDist = aiclass->argsAsFloat[2];
            v9->nextUpdate = sithTime_curMs + 1000;
            sithAI_sub_4EAF40(actor);
            v10 = actor->field_238;
            if ( v10 && v10 != 2 )
            {
                if (Main_bMotsCompat && sithAI_pDistractor && actor->pDistractor == sithAI_pDistractor) 
                {
                    actor->pDistractor = sithAICmd_NearestPlayer(actor);
                    return 0;
                }
                if (actor->thing->actorParams.typeflags & SITH_AF_COMBO_BLIND)
                {
                    return 0;
                }
                if (v9->param0 != 0.0 )
                {
                    return 0;
                }
                v9->param0 = 1.0;
                sithAI_SetMoveThing(actor, &actor->field_23C, 2.0);
                sithAI_SetLookFrame(actor, &actor->field_23C);
                return 0;
            }
            v9->param0 = 0.0;
            sithAI_SetLookFrame(actor, &v7->position);

            if ( actor->currentDistanceFromTarget <= argMaxDistToAllow )
            {
                if ( actor->currentDistanceFromTarget >= argMinDistToAllow ) {
                    return 0;
                }

                // TODO verify
                if ( argMaxMeleeDist == 0.0 )
                    v16 = actor->currentDistanceFromTarget - argMinDistToAllow;
                else
                    v16 = actor->currentDistanceFromTarget - argMaxMeleeDist;
            }
            else {
                v16 = actor->currentDistanceFromTarget - argMaxDistToAllow;
            }

            rdVector_Copy3(&arg8a, &actor->thing->position);
            rdVector_MultAcc3(&arg8a, &actor->field_228, v16);
            if ( (actor->thing->physicsParams.physflags & SITH_PF_FLY) != 0 )
            {
                arg8a.z = v7->position.z - -0.02;
            }
            else if ( (actor->thing->thingflags & SITH_TF_WATER) != 0 )
            {
                arg8a.z = v7->position.z;
            }
            else
            {
                arg8a.z = actor->thing->position.z;
            }
            if ( v8->argsAsFloat[3] != 0.0
              || !sithAI_sub_4EB300(v7, &v7->position, &arg8a, -1.0, actor->pAIClass->sightDist, 0.0, &a5, &tmp) )
            {
                sithAI_SetMoveThing(actor, &arg8a, 1.5);
                return 0;
            }
            return 0;
        }
        return 0;
    }

    if ( (actor->flags & SITHAI_MODE_MOVING) == 0 )
        return 0;
    if ( (actor->flags & SITHAI_MODE_ACTIVE) == 0 )
        return 0;
    _rand(); // TODO wat? did something get optimized out?
    if ( flags == SITHAI_MODE_ACTIVE
      && rdVector_Dot3(&actor->field_228, &actor->thing->physicsParams.vel) > 0.03 )
    {
        return 0;
    }
    a1.x = 0.0;
    a1.z = 0.0;
    a1.y = 45.0;
    if ( _frand() <= 0.5 )
        a1.y = -45.0;
    rdVector_Rotate3(&a4a, &actor->field_1AC, &a1);
    rdVector_Scale3Acc(&a4a, actor->field_1B8);
    rdVector_Add3Acc(&a4a, &actor->thing->position);
    sithAI_SetMoveThing(actor, &a4a, actor->moveSpeed);
    instinct->nextUpdate = sithTime_curMs + 1000;
    return 1;
}

/*
p0 - Freq of Straf Check (msec)
p1 - %Yaw change on move (30-45 typical)
p2 - Max Dist to attempt Strafe
p3 - Update interval (typically 1000msec)
p4 - 0 single dir strafe, 1 random strafe
*/
int sithAICmd_CircleStrafe(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, intptr_t otherFlags)
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
    if ( actor->pMoveThing )
    {
        v8 = aiclass->argsAsInt[4];
        sithAI_sub_4EAF40(actor);
        if ( aiclass->argsAsFloat[2] >= (double)actor->currentDistanceFromTarget && !actor->field_238 )
        {
            rdVector_Scale3(&a2a, &actor->field_228, -actor->currentDistanceFromTarget);
            if ( v8
              || actor->pMoveThing->lookOrientation.lvec.y * a2a.y + actor->pMoveThing->lookOrientation.lvec.z * a2a.z + actor->pMoveThing->lookOrientation.lvec.x * a2a.x >= 0.0 )
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
                rdVector_Add3Acc(&movePos, &actor->pMoveThing->position);
                if ( !sithAI_sub_4EB300(actor->pMoveThing, &actor->pMoveThing->position, &movePos, -1.0, actor->pAIClass->sightDist, 0.0, &a5, &unused) )
                {
                    sithAI_SetMoveThing(actor, &movePos, 0.5);
                    sithAI_SetLookFrame(actor, &actor->pMoveThing->position);
                    instinct->nextUpdate = sithTime_curMs + aiclass->argsAsInt[3];
                    return 0;
                }
                instinct->param0 = -instinct->param0;
            }
        }
    }
    return 0;
}

//p0 - How long to stand between crouches
int sithAICmd_Crouch(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, intptr_t otherFlags)
{
    instinct->nextUpdate = sithTime_curMs + aiclass->argsAsInt[0];
    if (!(actor->flags & SITHAI_MODE_MOVING) 
        && (actor->flags & SITHAI_MODE_ATTACKING)
        && (actor->flags & SITHAI_MODE_TARGET_VISIBLE))
    {
        actor->thing->physicsParams.physflags |= SITH_PF_CROUCHING;
        return 0;
    }
    else
    {
        actor->thing->physicsParams.physflags &= ~SITH_PF_CROUCHING;
        return 0;
    }
}

/*
p0 - Fire Rate in (msec)
p1 - Fire % 0 never 1 allways
p2 - Weapon 0 - primary 1 - secondary
p3 - MinDot Max shoot angle
p4 - MinDist Don't shoot closer than this
p5 - ShotError % 0 to 1
*/
int sithAICmd_BlindFire(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, intptr_t otherFlags)
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
        if ( !actor->pDistractor || !projectile )
        {
            actor->flags &= ~SITHAI_MODE_ATTACKING;
            return 1;
        }
        if ( !sithAI_sub_4EB300(weapon, &weapon->position, &actor->field_1F8, aiclass->argsAsFloat[3], 10.0, projectile->moveSize, &fireOffs, &fOut)
          && fOut >= (double)aiclass->argsAsFloat[4] )
        {
            if ( actor->attackDistance != 0.0 && aiclass->argsAsFloat[5] != 0.0 )
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

/*
p0 - Fire Rate (msec)
p1 - Min Dot
p2 - Min Dist (don't fire if closer)
p3 - Max Dist (don't fire if further)
p4 - % Error in aim
p5 - % use secondary (0 always primary, 1 always second)
*/
int sithAICmd_LobFire(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, intptr_t otherFlags)
{
    int v5; // ebx
    sithThing *v6; // eax
    sithThing *v7; // ebp
    int v11; // eax

    v5 = 0;
    v6 = actor->thing;
    v7 = actor->pDistractor;
    if ( flags )
    {
        if ( flags == SITHAI_MODE_UNK100 )
        {
            if ( (actor->flags & SITHAI_MODE_ACTIVE) != 0 )
                sithPuppet_SetArmedMode(v6, 1);
            else
                sithPuppet_SetArmedMode(v6, 0);

            // Added: co-op
            if (sithNet_isMulti && sithNet_MultiModeFlags & MULTIMODEFLAG_COOP) {
                sithThing_SetSyncFlags(actor->thing, THING_SYNC_PUPPET);
            }

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
            actor->flags |= SITHAI_MODE_TARGET_VISIBLE;
            v11 = sithTime_curMs + aiclass->argsAsInt[0];
            instinct->nextUpdate = v11;
            actor->field_288 = v11;
            return 0;
        }
        sithAI_SetLookFrame(actor, &v7->position);
        actor->flags |= SITHAI_MODE_TARGET_VISIBLE;
        instinct->nextUpdate = sithTime_curMs + 500;
        return 0;
    }
    if ( (actor->flags & SITHAI_MODE_TARGET_VISIBLE) != 0 )
    {
        sithSoundClass_PlayModeRandom(v6, SITH_SC_VICTORY);
        sithPuppet_PlayMode(actor->thing, SITH_ANIM_VICTORY, 0);

        // Added: co-op
        if (sithNet_isMulti && sithNet_MultiModeFlags & MULTIMODEFLAG_COOP) {
            sithThing_SetSyncFlags(actor->thing, THING_SYNC_PUPPET);
        }
    }

    actor->flags &= ~(SITHAI_MODE_TARGET_VISIBLE|SITHAI_MODE_ACTIVE|SITHAI_MODE_TOUGHSKIN|SITHAI_MODE_ATTACKING);
    actor->flags |= SITHAI_MODE_SEARCHING;
    return 1;
}

/*
p0 - Ave Time between shots (msec)
p1 - Min Fire dot (1.0 - facing, 0 - 180deg, -1.0 360deg)
p2 - Max Dist (wont fire if further)
p3 - Error (Error in aim 0-1)
p4 - Min Dist (Wont fire if closer)
p5 - Ready Time (between wake & first shot in msec)
p6 - Lead % (0 -1)
p7 - Use Secondary % (1.0 always)
p8 - Burst Count (#-1, 0 never)
p9 - Burst Interval (time between shots, msec)
*/
int sithAICmd_PrimaryFire(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, intptr_t otherFlags)
{
    int v5; // ebp
    int v6; // ebx
    sithThing *v7; // eax
    rdVector3 v18; // [esp+28h] [ebp-Ch] BYREF

    v5 = 0;
    v6 = 0;
    v7 = actor->thing;
    if ( flags )
    {
        if ( flags != SITHAI_MODE_UNK100 )
        {
            return 0;
        }

        if ( (actor->flags & SITHAI_MODE_ACTIVE) != 0 )
        {
            sithPuppet_SetArmedMode(v7, 1);
            instinct->param0 = aiclass->argsAsFloat[8];
            instinct->nextUpdate = sithTime_curMs + aiclass->argsAsInt[5];
        }
        else
        {
            sithPuppet_SetArmedMode(v7, 0);
        }

        // Added: co-op
        if (sithNet_isMulti && sithNet_MultiModeFlags & MULTIMODEFLAG_COOP) {
            sithThing_SetSyncFlags(actor->thing, THING_SYNC_PUPPET);
        }
        return 0;
    }
    if ( !actor->pDistractor )
        return 0;
    if ( (actor->pDistractor->thingflags & (SITH_TF_DEAD|SITH_TF_WILLBEREMOVED)) == 0 )
    {
        if ( aiclass->argsAsFloat[6] != 0.0 && aiclass->argsAsFloat[6] >= _frand() )
            v5 = 1;
        if ( aiclass->argsAsFloat[7] != 0.0 && aiclass->argsAsFloat[7] >= _frand() )
            v6 = 1;

        if ( sithAI_FireWeapon(actor, aiclass->argsAsFloat[4], aiclass->argsAsFloat[2], aiclass->argsAsFloat[1], aiclass->argsAsFloat[3], v6, v5) )
        {
            actor->flags |= SITHAI_MODE_TARGET_VISIBLE;
            if ( instinct->param0 == 0.0 )
            {
                instinct->param0 = aiclass->argsAsFloat[8];
                instinct->nextUpdate = sithTime_curMs + (int64_t)((_frand() * 0.4 - 0.2 - -1.0) * aiclass->argsAsFloat[0]);
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
            if (actor->pDistractor && actor->pDistractor->moveType == SITH_MT_PHYSICS )
            {
                rdVector_Copy3(&v18, &actor->pDistractor->position);
                rdVector_MultAcc3(&v18, &actor->pDistractor->physicsParams.vel, 0.5);
                sithAI_SetLookFrame(actor, &v18);
            }
        }
        if ( actor->field_1F4 == 3 )
        {
            actor->flags &= ~SITHAI_MODE_TARGET_VISIBLE;
        }
        instinct->nextUpdate = sithTime_curMs + 250;
        return 0;
    }
    if ( (actor->flags & SITHAI_MODE_TARGET_VISIBLE) != 0 )
    {
        sithSoundClass_PlayModeRandom(v7, SITH_SC_VICTORY);
        sithPuppet_PlayMode(actor->thing, SITH_ANIM_VICTORY, 0);

        // Added: co-op
        if (sithNet_isMulti && sithNet_MultiModeFlags & MULTIMODEFLAG_COOP) {
            sithThing_SetSyncFlags(actor->thing, THING_SYNC_PUPPET);
        }
    }

    instinct->param0 = aiclass->argsAsFloat[8];
    actor->flags &= ~(SITHAI_MODE_TARGET_VISIBLE|SITHAI_MODE_ACTIVE|SITHAI_MODE_TOUGHSKIN|SITHAI_MODE_ATTACKING);
    actor->flags |= SITHAI_MODE_SEARCHING;
    return 1;
}

/*
p0 - fire rate (msec)
p1 - turn rate (pitch & yaw, anlges/sec )
p2 - Yaw range (0 - 180)
p3 - Pitch Range (0 - 180)
p4 - Max Dist
p5 - Heath min % to cause berzerk
p6 - Fire Rate in Berzerk (msec)
p7 - Time from Berzerk till death (msec)
p8 - %lead chance (0 never, 1 always)
*/
int sithAICmd_TurretFire(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, intptr_t otherFlags)
{
    sithThing *v7; // eax
    sithThing *v8; // edi
    int result; // eax
    sithActorInstinct *v13; // edi
    sithThing *v15; // eax
    sithThing *v16; // ecx
    rdMatrix34 *v20; // esi
    double v23; // st7
    double v24; // st7
    double v25; // st7
    double v28; // st7
    sithThing *v29; // eax
    float v31; // [esp+10h] [ebp-60h]
    float v32; // [esp+14h] [ebp-5Ch]
    rdVector3 a3; // [esp+1Ch] [ebp-54h] BYREF
    rdVector3 v35; // [esp+28h] [ebp-48h] BYREF
    rdVector3 a1; // [esp+34h] [ebp-3Ch] BYREF
    rdMatrix34 v37; // [esp+40h] [ebp-30h] BYREF
    float actora; // [esp+74h] [ebp+4h]
    float actorb; // [esp+74h] [ebp+4h]
    float actorc; // [esp+74h] [ebp+4h]
    float actord; // [esp+74h] [ebp+4h]
    float flagsa; // [esp+80h] [ebp+10h]

    v7 = actor->pDistractor;
    v8 = actor->thing->actorParams.templateWeapon;
    if ( flags )
        return 0;
    if ( !v7 || !v8 )
    {
        actor->flags &= ~SITHAI_MODE_ATTACKING;
        return 1;
    }
    if ( (v7->thingflags & (SITH_TF_DEAD|SITH_TF_WILLBEREMOVED)) != 0 )
    {
        actor->flags &= ~(SITHAI_MODE_ACTIVE|SITHAI_MODE_TOUGHSKIN|SITHAI_MODE_ATTACKING);
        actor->flags |= SITHAI_MODE_SEARCHING;
        return 1;
    }
    sithPuppet_SetArmedMode(actor->thing, 1);
    flagsa = aiclass->argsAsFloat[2];
    actora = aiclass->argsAsFloat[3];
    // TODO verify (aiclass->argsAsFloat[5] == 0.0)
    if ( aiclass->argsAsFloat[5] == 0.0 || actor->thing->actorParams.health >= actor->thing->actorParams.maxHealth * aiclass->argsAsFloat[5] )
    {
        sithAI_sub_4EAD60(actor);
        if ( actor->field_1F4 )
        {
            actor->flags = actor->flags & ~(SITHAI_MODE_ACTIVE|SITHAI_MODE_TOUGHSKIN|SITHAI_MODE_ATTACKING) | SITHAI_MODE_SEARCHING;
            return 1;
        }
        v31 = aiclass->argsAsFloat[1] * sithTime_deltaSeconds;
        if ( aiclass->argsAsFloat[8] <= _frand()
          || (v16 = actor->pDistractor) == 0
          || v16->moveType != SITH_MT_PHYSICS
          || rdVector_IsZero3(&v16->physicsParams.vel) )
        {
            v20 = &actor->thing->lookOrientation;
            rdMatrix_TransformVector34Acc_0(&a1, &actor->attackError, &actor->thing->lookOrientation);
        }
        else
        {
            rdVector_Copy3(&v35, &v16->physicsParams.vel);
            rdVector_MultAcc3(&v35, &actor->attackError, v8->physicsParams.vel.y);

            rdVector_Normalize3Acc(&v35);
            v20 = &actor->thing->lookOrientation;
            rdMatrix_TransformVector34Acc_0(&a1, &v35, &actor->thing->lookOrientation);
        }
        rdVector_ExtractAngle(&a1, &a3);
        if ( a3.y < -flagsa )
        {
            a3.y = -flagsa;
        }
        else if ( a3.y > (double)flagsa )
        {
            a3.y = flagsa;
        }
        if ( a3.x < -actora )
        {
            a3.x = -actora;
        }
        else if ( a3.x > (double)actora )
        {
            a3.x = actora;
        }
        actorb = actor->thing->actorParams.eyePYR.y;
        v32 = actor->thing->actorParams.eyePYR.x;
        if ( actorb == a3.y && v32 == a3.x )
            goto LABEL_50;
        if ( flagsa >= 180.0 )
        {
            v23 = actorb - a3.y;
            if ( v23 <= 180.0 )
            {
                if ( v23 >= -180.0 )
                    goto LABEL_41;
                v24 = a3.y - 360.0;
            }
            else
            {
                v24 = a3.y - -360.0;
            }
            a3.y = v24;
        }
LABEL_41:
        v25 = actorb - v31;
        if ( a3.y < v25 || (v25 = v31 + actorb, a3.y > v25) )
            actorc = v25;
        else
            actorc = a3.y;
        actor->thing->actorParams.eyePYR.y = stdMath_NormalizeAngleAcute(actorc);
        actord = v32 - v31;
        if ( a3.x < actord )
        {
            v28 = actord;
        }
        else
        {
            v28 = v31 + v32;
            if ( a3.x <= v28 )
                v28 = a3.x;
        }
        actor->thing->actorParams.eyePYR.x = v28;
        sithActor_RotateTurretToEyePYR(actor->thing);
LABEL_50:
        if ( sithTime_curSeconds > (double)instinct->param0 && (g_debugmodeFlags & 0x80u) == 0 )
        {
            rdMatrix_Copy34(&v37, v20);
            rdMatrix_PreRotate34(&v37, &actor->thing->actorParams.eyePYR);
            sithSoundClass_ThingPlaySoundclass4(actor->thing, SITH_SC_FIRE1);
            v29 = sithWeapon_Fire(actor->thing, v8, &v37.lvec, &actor->blindAimError, 0, SITH_ANIM_FIRE, 1.0, 0, 0.0);
            if ( v29 )
                sithCog_SendMessageFromThing(actor->thing, v29, SITH_MESSAGE_FIRE);
            instinct->param0 = aiclass->argsAsFloat[0] * 0.001 + sithTime_curSeconds;
        }
        instinct->nextUpdate = sithTime_curMs + 1;
        return instinct->nextUpdate;
    }
    v13 = instinct;
    if ( instinct->param1 == 0.0 )
    {
        instinct->param0 = sithTime_curSeconds - 1.0;
        instinct->param1 = aiclass->argsAsFloat[7] * 0.001 + sithTime_curSeconds;
    }
    else if ( sithTime_curSeconds > (double)instinct->param1 )
    {
        sithActor_SpawnDeadBodyMaybe(actor->thing, actor->thing, 2);
        return 0;
    }
    actor->thing->actorParams.eyePYR.y = _frand() * (flagsa + flagsa) - flagsa;
    actor->thing->actorParams.eyePYR.x = _frand() * (actora + actora) - actora;
    sithActor_RotateTurretToEyePYR(actor->thing);
    if ( sithTime_curSeconds > (double)instinct->param0 )
    {
        _memcpy(&v37, &actor->thing->lookOrientation, sizeof(v37));
        rdMatrix_PreRotate34(&v37, &actor->thing->actorParams.eyePYR);
        sithSoundClass_ThingPlaySoundclass4(actor->thing, SITH_SC_FIRE1);
        v15 = sithWeapon_Fire(actor->thing, v8, &v37.lvec, &actor->thing->position, 0, SITH_ANIM_FIRE, 1.0, 0, 0.0);
        if ( v15 )
            sithCog_SendMessageFromThing(actor->thing, v15, SITH_MESSAGE_FIRE);
        v13 = instinct;
        instinct->param0 = aiclass->argsAsFloat[6] * 0.001 + sithTime_curSeconds;
    }
    v13->nextUpdate = sithTime_curMs + 50;
    return 0;
}

// MoTS altered
/*
p0 - Investigate % (0 never, 1 always)
p1 - Distance to move from danger?
*/
int sithAICmd_Listen(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, sithThing *extra)
{
    sithActor *actor_; // esi
    sithThing *v6; // ebx
    sithSectorAlloc *v8; // ecx
    int result; // eax
    rdVector3 *v10; // ebp
    float *v11; // ecx
    int v12; // edi
    int v13; // ecx
    double v14; // st7
    sithThing *v15; // ebp
    sithActorInstinct *instinct_; // edi
    sithThing *v17; // ebx
    sithSectorAlloc *v25; // [esp+10h] [ebp-28h]
    rdVector3 movePos; // [esp+14h] [ebp-24h] BYREF
    rdVector3 lookPos; // [esp+20h] [ebp-18h] BYREF
    rdVector3 a5; // [esp+2Ch] [ebp-Ch] BYREF
    float tmp;

    actor_ = actor;
    if ( (actor->flags & SITHAI_MODE_SEARCHING) == 0 )
        return 0;
    v6 = actor->thing;
    v8 = &sithAIAwareness_aSectors[actor->thing->sector->id];
    v25 = v8;
    if ( flags == SITHAI_MODE_MOVING )
    {
LABEL_26:
        instinct_ = instinct;
        if ( instinct->param0 == 0.0 )
        {
            if ( flags == SITHAI_MODE_MOVING )
                sithSoundClass_PlayModeRandom(v6, SITH_SC_SURPRISE);
            else
                sithSoundClass_PlayModeRandom(v6, SITH_SC_CURIOUS);
            instinct_->param0 = 0.1;
        }
        v17 = extra;
        if ( extra )
        {
            lookPos = extra->position;
            sithAI_SetLookFrame(actor_, &lookPos);
            if ( (actor_->flags & SITHAI_MODE_MOVING) == 0 )
            {
                if ( aiclass->argsAsFloat[1] != 0.0 )
                {
                    rdVector_Sub3(&movePos, &lookPos, &actor_->thing->position);
                    rdVector_Normalize3Acc(&movePos);
                    rdVector_Scale3Acc(&movePos, aiclass->argsAsFloat[1]);
                    rdVector_Add3Acc(&movePos, &actor_->thing->position);
                    sithAI_SetMoveThing(actor_, &movePos, 2.5);
                }
            }
            if ( _frand() < 0.1 && flags == SITHAI_MODE_MOVING )
            {
                if ((v17->type == SITH_THING_ACTOR || v17->type == SITH_THING_PLAYER)
                    && MOTS_ONLY_COND(actor_->pAIClass->alignment != 1.0 || (sithAI_FLOAT_005a79d8 != 1.0) || v17 != sithAICmd_NearestPlayer(actor_)) ) // TODO will sithAICmd_NearestPlayer work?
                {
                    actor_->pDistractor = v17;
                    actor_->pMoveThing = v17;
                    actor_->flags &= ~SITHAI_MODE_SEARCHING;
                    actor_->flags |= SITHAI_MODE_ACTIVE|SITHAI_MODE_TOUGHSKIN|SITHAI_MODE_HASDEST|SITHAI_MODE_ATTACKING;
                }
            }
        }
        return 0;
    }
    if ( flags != SITHAI_MODE_ATTACKING )
    {
        if ( flags != SITHAI_MODE_SEARCHING )
            return 0;
        goto LABEL_26;
    }
    v10 = &v8->field_10[2];
    v11 = &v8->field_4[2];
    v12 = 2;
    while ( 1 )
    {
        if ( *v11 != 0.0 )
        {
            v13 = sithAI_sub_4EB300(v6, &v6->position, v10, -1.0, actor_->pAIClass->sightDist, 0.0, &a5, &tmp);
            if ( tmp <= (double)actor_->pAIClass->hearDist
              && (!v13
               || tmp < 1.0 && v6->lookOrientation.lvec.y * a5.y + v6->lookOrientation.lvec.z * a5.z + v6->lookOrientation.lvec.x * a5.x > 0.5) )
            {
                break;
            }
        }
        --v12;
        --v10;
        --v11;
        if ( v12 < 0 )
        {
            // TODO ??????
            //v14 = *(float *)&instinct;
            //v15 = (sithThing *)instinct;
            
            v14 = 0.0;
            v15 = NULL;
            
            goto LABEL_15;
        }
    }
    v14 = v25->field_4[v12];
    rdVector_Copy3(&actor_->field_1C4, &v25->field_10[v12]);
    v15 = v25->field_58[v12];
LABEL_15:
    if ( v12 < 0 )
        return 0;
    if ( v14 > instinct->param0 )
        instinct->param0 = v14;

    if ( aiclass->argsAsFloat[0] > _frand() && (actor_->flags & SITHAI_MODE_MOVING) == 0 )
    {
        sithAI_SetMoveThing(actor_, &actor_->field_1C4, 1.0);
        sithSoundClass_PlayModeRandom(v6, SITH_SC_CURIOUS);
    }
    if ( v15 && v15->type )
    {
        sithAI_SetLookFrame(actor_, &v15->position);
        result = 0;
    }
    else
    {
        sithAI_SetLookFrame(actor_, &actor_->field_1C4);
        result = 0;
    }
    return result;
}

// MoTS altered
/*
p0 - interval look (msec)
p1 - Time to sleep before check again (msec)
*/
int sithAICmd_LookForTarget(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, void *extra)
{
    if (flags || (g_debugmodeFlags & 0x200))
        return 0;

    if ( (actor->flags & SITHAI_MODE_ACTIVE) != 0 )
    {
        if ( aiclass->argsAsInt[1] && aiclass->argsAsInt[1] + actor->field_204 < sithTime_curMs )
        {
            actor->flags &= ~(SITHAI_MODE_TARGET_VISIBLE|SITHAI_MODE_ACTIVE|SITHAI_MODE_TOUGHSKIN|SITHAI_MODE_ATTACKING);
            actor->flags |= SITHAI_MODE_SEARCHING;
            sithActor_MoveJointsForEyePYR(actor->thing, &rdroid_zeroVector3);
            return 1;
        }
    }
    else if ((actor->flags & SITHAI_MODE_SEARCHING) && MOTS_ONLY_COND(
            (actor->pAIClass->alignment < -1.0 ||
            (((actor->pAIClass->alignment != 0.0 && sithAI_FLOAT_005a79d8 != 0.0) &&
            (actor->pAIClass->alignment < 0.0 != sithAI_FLOAT_005a79d8 < 0.0))))
        ))
    {
        if (Main_bMotsCompat)
        {
            int uVar1 = 0;
            sithThing* psVar3 = actor->pInterest;
            instinct->nextUpdate = aiclass->argsAsInt[0] + sithTime_curMs;
            if (((!actor->pInterest 
                && sithAI_pDistractor) 
                && (uVar1 = sithAI_pDistractor->thingflags, actor->pDistractor = sithAI_pDistractor,
            (uVar1 & 0x202) == 0)) && (sithAI_sub_4EAD60(actor), actor->field_1F4 == 0)) 
            {
                actor->flags &= ~(SITHAI_MODE_SEARCHING);
                actor->flags |= (SITHAI_MODE_ACTIVE|SITHAI_MODE_TOUGHSKIN|SITHAI_MODE_HASDEST|SITHAI_MODE_ATTACKING);
                sithSoundClass_PlayModeRandom(actor->thing, SITH_SC_ALERT);
                sithSoundClass_ThingPlaySoundclass4(actor->thing, SITH_SC_ACTIVATE);
                sithAIAwareness_AddEntry(actor->pDistractor->sector, &actor->thing->position, 0, 3.0, actor->pDistractor);
                actor->pMoveThing = actor->pDistractor;
                return 1;
            }
            psVar3 = actor->pInterest;
            if (!actor->pInterest) {
                psVar3 = sithAICmd_NearestPlayer(actor);
            }
            actor->pDistractor = psVar3;
            if ((psVar3->thingflags & 0x202) == 0) 
            {
                sithAI_sub_4EAD60(actor);
                if (actor->field_1F4 == 0) 
                {
                    actor->flags &= ~(SITHAI_MODE_SEARCHING);
                    actor->flags |= (SITHAI_MODE_ACTIVE|SITHAI_MODE_TOUGHSKIN|SITHAI_MODE_HASDEST|SITHAI_MODE_ATTACKING);
                    sithSoundClass_PlayModeRandom(actor->thing, SITH_SC_ALERT);
                    sithSoundClass_ThingPlaySoundclass4(actor->thing, SITH_SC_ACTIVATE);
                    sithAIAwareness_AddEntry(actor->pDistractor->sector, &actor->thing->position, 0, 3.0, actor->pDistractor);
                    actor->pMoveThing = actor->pDistractor;
                    return 1;
                }
                if (aiclass->argsAsFloat[0] == 0.0) {
                    aiclass->argsAsFloat[0] = 500.0;
                }
            }
        }
        else {
            actor->pDistractor = sithAICmd_NearestPlayer(actor);
            instinct->nextUpdate = sithTime_curMs +  aiclass->argsAsInt[0];
            if (!(actor->pDistractor->thingflags & (SITH_TF_DEAD|SITH_TF_WILLBEREMOVED)))
            {
                sithAI_sub_4EAD60(actor);
                if ( !actor->field_1F4 )
                {
                    actor->flags &= ~SITHAI_MODE_SEARCHING;
                    actor->flags |= (SITHAI_MODE_ACTIVE|SITHAI_MODE_TOUGHSKIN|SITHAI_MODE_HASDEST|SITHAI_MODE_ATTACKING);
                    sithSoundClass_PlayModeRandom(actor->thing, SITH_SC_ALERT);
                    sithSoundClass_ThingPlaySoundclass4(actor->thing, SITH_SC_ACTIVATE);
                    sithAIAwareness_AddEntry(actor->pDistractor->sector, &actor->thing->position, 0, 3.0, actor->pDistractor);
                    actor->pMoveThing = actor->pDistractor;
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
    if ( (actor->flags & SITHAI_MODE_MOVING) != 0 )
    {
        sithPlayerActions_Activate(actor->thing);
        instinct->nextUpdate = sithTime_curMs + 1000;
    }
    return 0;
}

/*
p0 - Time between jump checks
p1 - Max jump height (Ai Thinks not Actual)
p2 - Max jump dist (Ai Thinks not Actual)
*/
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
    if (!(actor->flags & SITHAI_MODE_MOVING))
        return 0;
    if ( rdVector_Dot3(&actor->field_228, &v6->physicsParams.vel) > 0.02 )
        return 0;
    //*(_QWORD *)&a2.x = sithTime_curMs;
    if ( (double)sithTime_curMs < instinct->param0 )
        return 0;

    instinct->param0 = aiclass->argsAsFloat[0] + (double)sithTime_curMs;
    if ( flags != SITHAI_MODE_SEARCHING && flags != SITHAI_MODE_ACTIVE )
    {
        if ( flags != SITHAI_MODE_TARGET_VISIBLE )
            return 0;

        rdVector_Copy3(&a2, &v6->position);
        rdVector_MultAcc3(&a2, &v5->field_1AC, aiclass->argsAsFloat[2]);

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
    sithSector* result = sithCollision_GetSectorLookAt(v7, &v6->position, &a3, 0.0);
    if ( result )
    {
        a2.x = v5->field_1AC.x * 0.1 + a3.x;
        a2.y = v5->field_1AC.y * 0.1 + a3.y;
        a2.z = a3.z;
        result = sithCollision_GetSectorLookAt(result, &a3, &a2, 0.0);
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

/*
p0 - Distance considered to be out of danger
p1 - Interval to check for new flee dir
p2 - Duration of flee in seconds (10s is default)
*/
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
    if ( (v7 & SITHAI_MODE_FLEEING) == 0 )
        return 0;

    if ( instinct->param0 == 0.0 )
        instinct->param0 = sithTime_curSeconds;
    if ( v8 == 0.0 )
        v8 = 10.0;
    v11 = actor->pFleeThing;
    if ( !v11
      || sithTime_curSeconds > instinct->param0 + v8
      || ((v12 = aiclass->argsAsInt[1], actor->flags = v7 & ~SITHAI_MODE_ATTACKING, !v12) ? (instinct->nextUpdate = sithTime_curMs + 5000) : (instinct->nextUpdate = v12 + sithTime_curMs),
          sithAI_CheckSightThing(actor->thing, &actor->thing->position, v11, -1.0, aiclass1a, 0.0, &a5, &tmp)) )
    {
        v16 = actor->pFleeThing;
        if ( v16 )
            sithAI_SetLookFrame(actor, &v16->position);
        actor->pFleeThing = 0;
        actor->flags &= ~(SITHAI_MODE_FLEEING|SITHAI_MODE_ACTIVE);
        actor->flags |= SITHAI_MODE_SEARCHING;
        
        instinct->param0 = 0.0;
        result = 1;
    }
    else
    {
        rdVector_Zero3(&v19);
        if ( flags )
        {
            if ( flags == SITHAI_MODE_UNK100 || flags == SITHAI_MODE_FLEEING )
            {
                rdVector_Neg3Acc(&a5);
                v15 = actor->thing;
                v19.y = (_frand() - 0.5) * 180.0;
                if ( (v15->physicsParams.physflags & SITH_PF_FLY) != 0 )
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
            rdVector_Copy3(&movePos, &actor->thing->position);
            rdVector_MultAcc3(&movePos, &a5, aiclass1a);
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

/*
p0 - interval to check for new dir (typical 5000, msec)
p1 - Distance considered as withdrew
*/
int sithAICmd_Withdraw(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, void *extra)
{
    int result; // eax
    sithThing *v13; // eax
    sithThing *v14; // eax
    rdVector3 a5; // [esp+4h] [ebp-24h] BYREF
    rdVector3 v17; // [esp+10h] [ebp-18h] BYREF
    rdVector3 movePos; // [esp+1Ch] [ebp-Ch] BYREF
    float tmp;

    if ( (actor->flags & SITHAI_MODE_FLEEING) == 0 )
        return 0;

    if ( actor->pFleeThing)
    {
        if ( aiclass->argsAsInt[0] )
            instinct->nextUpdate = aiclass->argsAsInt[0] + sithTime_curMs;
        else
            instinct->nextUpdate = sithTime_curMs + 5000;

        if ( sithAI_CheckSightThing(actor->thing, &actor->thing->position, actor->pFleeThing, -1.0, actor->pAIClass->sightDist, 0.0, &a5, &tmp) )
        {
            result = 1;
            actor->flags &= ~(SITHAI_MODE_FLEEING|SITHAI_MODE_ACTIVE);
            actor->flags |= SITHAI_MODE_SEARCHING;
        }
        else
        {
            rdVector_Zero3(&v17);
            if ( !flags || flags == SITHAI_MODE_UNK100 || flags == SITHAI_MODE_FLEEING )
            {
                rdVector_Neg3Acc(&a5);
                v14 = actor->thing;
                v17.y = (_frand() - 0.5) * 180.0;
                if ( (v14->physicsParams.physflags & SITH_PF_FLY) != 0 )
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
            rdVector_Copy3(&movePos, &v13->position);
            rdVector_MultAcc3(&movePos, &a5, aiclass->argsAsFloat[1]);
            sithAI_SetMoveThing(actor, &movePos, 1.5);
            result = 0;
        }
    }
    else
    {
        actor->flags &= ~SITHAI_MODE_FLEEING;
        result = 0;
    }
    return result;
}

/*
p0 - how far to get from projectile
p1 - scale factor for how much to move
*/
int sithAICmd_Dodge(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, sithThing *extra)
{
    sithSectorAlloc *v16; // ecx
    rdVector3 a5; // [esp+10h] [ebp-24h] BYREF
    rdVector3 movePos; // [esp+1Ch] [ebp-18h] BYREF
    rdVector3 vAngs; // [esp+28h] [ebp-Ch] BYREF
    float tmp;

    if ( !flags )
        return 0;
    if ( flags == SITHAI_MODE_MOVING )
    {
        if ( aiclass->argsAsFloat[1] != 0.0 && extra && (actor->flags & SITHAI_MODE_MOVING) == 0 )
        {
            rdVector_Copy3(&vAngs, &extra->position);
            rdVector_Sub3(&a5, &vAngs, &actor->thing->position);
            tmp = rdVector_Normalize3Acc(&a5);
            rdVector_Copy3(&movePos, &actor->thing->position);
            rdVector_MultAcc3(&movePos, &a5, -aiclass->argsAsFloat[1]);
            sithAI_SetMoveThing(actor, &movePos, 2.5);
            actor->field_28C = sithTime_curMs + 1000;
            return 0;
        }
        return 0;
    }
    if ( flags != SITHAI_MODE_SLEEPING )
    {
        if ( (actor->flags & SITHAI_MODE_ACTIVE) != 0 && flags == SITHAI_MODE_ATTACKING && aiclass->argsAsFloat[0] != 0.0 )
        {
            v16 = &sithAIAwareness_aSectors[actor->thing->sector->id];
            if (v16->field_4[2])
            {
                if ( v16->field_58[2] )
                {
                    if ( sithThing_GetParent(v16->field_58[2]) != actor->thing
                      && v16->field_58[2]->type == SITH_THING_WEAPON
                      && v16->field_58[2]->moveType == SITH_MT_PHYSICS
                      && !sithAI_CheckSightThing(actor->thing, &actor->thing->position, v16->field_58[2], actor->pAIClass->fov, 1.0, 0.0, &a5, &tmp) )
                    {
                        rdVector_Copy3(&movePos, &actor->thing->position);
                        rdVector_MultAcc3(&movePos, &a5, -aiclass->argsAsFloat[0]);
                        sithAI_SetMoveThing(actor, &movePos, 2.5);
                        actor->field_28C = sithTime_curMs + 1000;
                        sithSoundClass_PlayModeRandom(actor->thing, SITH_SC_CURIOUS);
                    }
                }
            }
        }
        return 0;
    }
    if ( (actor->flags & SITHAI_MODE_ACTIVE) == 0 )
        return 0;

    if ( aiclass->argsAsFloat[1] == 0.0
      || !extra
      || sithAI_CheckSightThing(actor->thing, &actor->thing->position, extra, actor->pAIClass->fov, actor->pAIClass->sightDist, 0.0, &a5, (float *)&extra) )
    {
        return 0;
    }
    rdVector_Zero3(&vAngs);
    vAngs.y = _frand() * 45.0 - -45.0;
    if ( _frand() < 0.5 )
        vAngs.y = -vAngs.y;
    rdVector_Rotate3Acc(&a5, &vAngs);
    rdVector_Copy3(&movePos, &actor->thing->position);
    rdVector_MultAcc3(&movePos, &a5, -aiclass->argsAsFloat[1]);
    sithAI_SetMoveThing(actor, &movePos, 2.5);
    return 0;
}

/*
p0 - interval for turn (msec)
p1 - min dist to see for valid (ave 1 or 2)
*/
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
    out = rdroid_yVector3;
    rdVector_Scale3(&vAngs, &rdroid_yVector3, _frand() * 360.0);
    rdVector_Rotate3Acc(&out, &vAngs);
    rdVector_Copy3(&arg8, &actor->thing->position);
    rdVector_MultAcc3(&arg8, &out, aiclass->argsAsFloat[1]);
    result = sithAI_sub_4EB300(actor->thing, &actor->thing->position, &arg8, -1.0, aiclass->argsAsFloat[1], 0.0, &a5, &tmp);
    if ( !result )
        sithAI_SetLookFrame(actor, &arg8);
    return result;
}

/*
p0 - How often pick new roam
p1 - Radius to roam from home
*/
int sithAICmd_Roam(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, void *extra)
{
    double randVal; // st6
    rdVector3 *v13; // [esp-8h] [ebp-30h]
    rdVector3 movePos; // [esp+4h] [ebp-24h] BYREF
    rdVector3 v16; // [esp+10h] [ebp-18h] BYREF
    rdVector3 v17; // [esp+1Ch] [ebp-Ch] BYREF

    instinct->nextUpdate = sithTime_curMs + aiclass->argsAsInt[0];
    if ( (actor->flags & SITHAI_MODE_ATTACKING) == 0 )
    {
        rdVector_Zero3(&v17);
        v13 = &actor->thing->lookOrientation.lvec;
        v17.y = (_frand() - 0.5) * 360.0;
        rdVector_Rotate3(&v16, v13, &v17);
        if ( aiclass->argsAsFloat[1] <= 0.0 )
        {
            randVal = _frand() * -aiclass->argsAsFloat[1];
            rdVector_Copy3(&movePos, &actor->thing->position);
            rdVector_MultAcc3(&movePos, &v16, randVal);
        }
        else
        {
            randVal = _frand() * aiclass->argsAsFloat[1];
            rdVector_Copy3(&movePos, &actor->position);
            rdVector_MultAcc3(&movePos, &v16, randVal);
        }
        sithAI_SetLookFrame(actor, &movePos);
        sithAI_SetMoveThing(actor, &movePos, 1.0);
    }
    return 0;
}

// MoTS altered
/*
p0 - min to trigger (0 always)
p1 - on sight (nonzero flee if see player)
*/
int sithAICmd_SenseDanger(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, sithThing *extra)
{
    sithSectorAlloc *v7; // ecx
    sithThing *v8; // ebx
    int v9; // eax
    int result; // eax
    rdVector3 a5; // [esp+Ch] [ebp-Ch] BYREF
    float tmp;

    v7 = &sithAIAwareness_aSectors[actor->thing->sector->id];
    if ( (actor->flags & SITHAI_MODE_FLEEING) != 0 || (actor->flags & SITHAI_MODE_SEARCHING) == 0 )
        return 0;
    if ( !flags )
    {
        if ( aiclass->argsAsFloat[1] != 0.0 )
        {
            if (Main_bMotsCompat) {
                sithThing* psVar4 = actor->pInterest;
                if (!actor->pInterest) {
                    psVar4 = sithAICmd_NearestPlayer(actor);
                }
                actor->pDistractor = psVar4;
            }
            else {
                actor->pDistractor = sithAICmd_NearestPlayer(actor);
            }
            
            if ( (actor->pDistractor->thingflags & (SITH_TF_DEAD|SITH_TF_WILLBEREMOVED)) != 0 )
                return 0;
            sithAI_sub_4EAD60(actor);
            if ( !actor->field_1F4 )
            {
                actor->flags &= ~SITHAI_MODE_SEARCHING;
                actor->flags |= SITHAI_MODE_FLEEING;
                sithSoundClass_PlayModeRandom(actor->thing, SITH_SC_FEAR);
                sithAIAwareness_AddEntry(actor->thing->sector, &actor->thing->position, 1, 3.0, actor->thing);
                actor->pFleeThing = actor->pDistractor;
                return 1;
            }
        }
        instinct->nextUpdate = sithTime_curMs + 1000;
        return 0;
    }
    if ( flags != 1 )
    {
        if ( flags == 2 && v7->field_4[1] > (double)aiclass->argsAsFloat[0] )
        {
            v8 = v7->field_58[1];
            if ( v8 )
            {
                v9 = sithAI_CheckSightThing(actor->thing, &actor->thing->position, v8, -1.0, actor->pAIClass->hearDist, 0.0, &a5, &tmp);
                if ( v9 != 1 && v9 != 3 )
                {
                    actor->pFleeThing = v8;
                    if ( (actor->flags & SITHAI_MODE_FLEEING) == 0 )
                    {
                        sithSoundClass_PlayModeRandom(actor->thing, SITH_SC_FEAR);
                        sithAIAwareness_AddEntry(actor->thing->sector, &actor->thing->position, 1, 4.0, actor->thing);
                    }
                    actor->flags &= ~SITHAI_MODE_SEARCHING;
                    actor->flags |= SITHAI_MODE_FLEEING;
                    return 1;
                }
            }
        }
        return 0;
    }
    sithSoundClass_PlayModeRandom(actor->thing, SITH_SC_SURPRISE);
    if ( extra )
        actor->pFleeThing = sithThing_GetParent(extra);
    result = 1;
    actor->flags &= ~SITHAI_MODE_SEARCHING;
    actor->flags |= SITHAI_MODE_FLEEING;
    return result;
}

/*
p0 - Time after Attack till flee (msec)
p1 - Time till reengaging (msec)
*/
int sithAICmd_HitAndRun(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, void *extra)
{
    int result; // eax
    double v8; // st7

    if ( flags )
        return 0;

    if ( (actor->flags & SITHAI_MODE_FLEEING) != 0 )
    {
        actor->flags &= ~SITHAI_MODE_FLEEING;
        return 1;
    }
    if ( (actor->flags & SITHAI_MODE_TARGET_VISIBLE) == 0 )
    {
        instinct->param0 = 0.0;
        instinct->nextUpdate = sithTime_curMs + 1000;
        return 0;
    }
    v8 = instinct->param0 - -1000.0;
    if ( v8 <= aiclass->argsAsFloat[0] )
    {
        instinct->param0 = v8;
        result = sithTime_curMs + 1000;
        instinct->nextUpdate = result;
    }
    else
    {
        instinct->param0 = 0.0;
        actor->flags |= SITHAI_MODE_FLEEING;
        actor->pFleeThing = actor->pDistractor;
        instinct->nextUpdate = sithTime_curMs + (int)aiclass->argsAsFloat[1];
        return 1;
    }
    return result;
}

/*
p0 - Health % (below could flee)
p1 - %moral fail (will flee)
p2 - time moral checks (msec)
p3 - maximum number of times we will retreat before not retreating anymore
*/
int sithAICmd_Retreat(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, sithThing *extra)
{
    int result; // eax

    if ( flags )
        return 0;

    if ( (actor->flags & SITHAI_MODE_ATTACKING) == 0 )
        return 0;

    if ( aiclass->argsAsFloat[3] != 0.0 && aiclass->argsAsFloat[3] < (double)instinct->param0 )
    {
        instinct->field_0 |= 1;
        return 0;
    }

    if ( actor->thing->actorParams.health < aiclass->argsAsFloat[0] * actor->thing->actorParams.maxHealth )
    {
        if ( aiclass->argsAsFloat[1] > _frand() )
        {
            instinct->param0 = instinct->param0 - -1.0;
            sithSoundClass_PlayModeRandom(actor->thing, SITH_SC_FLEE);
            actor->flags |= SITHAI_MODE_FLEEING;
            actor->pFleeThing = actor->pDistractor;
            return 1;
        }

        if ( _frand() < 0.1 )
            sithSoundClass_PlayModeRandom(actor->thing, SITH_SC_FEAR);
    }

    result = sithTime_curMs + aiclass->argsAsInt[2];
    instinct->nextUpdate = result;
    return result;
}

int sithAICmd_ReturnHome(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, intptr_t extra)
{
    rdVector3 a2;

    if ( flags == SITHAI_MODE_UNK100 )
    {
        if ( (actor->flags & SITHAI_MODE_SEARCHING) && (extra & SITHAI_MODE_SEARCHING) == 0 )
        {
            sithAI_SetMoveThing(actor, &actor->position, 1.0);
            sithAI_SetLookFrame(actor, &actor->position);
        }
    }
    else if ( flags == SITHAI_MODE_FLEEING && (actor->flags & SITHAI_MODE_SEARCHING) != 0 )
    {
        rdVector_Add3(&a2, &actor->lookOrientation, &actor->thing->position);
        sithAI_SetLookFrame(actor, &a2);
        return 0;
    }
    return 0;
}

/*
p0 - interval between voice (msec)
p1 - %chance of say (0 never, 1 always)
*/
int sithAICmd_Talk(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, void *extra)
{
    double healthPercent; // st7

    instinct->nextUpdate = sithTime_curMs + aiclass->argsAsInt[0];
    if ( aiclass->argsAsFloat[1] <= _frand() )
        return 0;
    healthPercent = actor->thing->actorParams.health / actor->thing->actorParams.maxHealth;

    if (!(actor->flags & SITHAI_MODE_ACTIVE))
        return 0;

    if (actor->flags & SITHAI_MODE_FLEEING )
    {
        if ( healthPercent > 0.5 )
        {
            sithSoundClass_PlayModeRandom(actor->thing, SITH_SC_GLOAT);
            return 0;
        }
        sithSoundClass_PlayModeRandom(actor->thing, SITH_SC_FEAR);
        return 0;
    }

    if (actor->flags & SITHAI_MODE_TARGET_VISIBLE)
    {
        if ( healthPercent < 0.25 )
        {
            sithSoundClass_PlayModeRandom(actor->thing, SITH_SC_FEAR);
            return 0;
        }
        sithSoundClass_PlayModeRandom(actor->thing, SITH_SC_BOAST);
        return 0;
    }
    else
    {
        if ( healthPercent >= 0.5 )
            sithSoundClass_PlayModeRandom(actor->thing, SITH_SC_HAPPY);
        else
            sithSoundClass_PlayModeRandom(actor->thing, SITH_SC_SEARCH);
        return 0;
    }
    return 0;
}

// MOTS added
/*
p0 - interval look (msec)
p1 - Time to sleep before check again (msec)
*/
int sithAICmd_LookForOpposingTarget(sithActor *pActor, sithAIClassEntry *pAiclass, sithActorInstinct *pInstinct, int flags, intptr_t otherFlags)
{
    sithAIClass *psVar2;
    sithThing *psVar3;

    if (flags)
        return 0;
    if (g_debugmodeFlags & 0x200)
        return 0;

    if ((pActor->flags & SITHAI_MODE_ACTIVE) == 0)
    {
        if (!(pActor->flags & SITHAI_MODE_SEARCHING))
            return 0;

        psVar2 = pActor->pAIClass;
        pInstinct->nextUpdate = pAiclass->argsAsInt[0] + sithTime_curMs;
        if (psVar2->alignment == 0.0) {
            return 0;
        }

        psVar3 = pActor->pInterest;
        if (psVar3 == (sithThing *)0x0)
        {
            psVar3 = sithAI_FUN_00539a60(pActor);
        }
        pActor->pDistractor = psVar3;
        if ((psVar3 != (sithThing *)0x0) && ((psVar3->thingflags & 0x202) == 0))
        {
            sithAI_sub_4EAD60(pActor);
            if (pActor->field_1F4 == 0) {
                pActor->flags &= ~SITHAI_MODE_SEARCHING;
                pActor->flags |= (SITHAI_MODE_ACTIVE|SITHAI_MODE_TOUGHSKIN|SITHAI_MODE_HASDEST|SITHAI_MODE_ATTACKING);
                sithSoundClass_PlayModeRandom(pActor->thing, SITH_SC_ALERT);
                sithSoundClass_ThingPlaySoundclass4(pActor->thing, SITH_SC_ACTIVATE);
                sithAIAwareness_AddEntry(pActor->pDistractor->sector, &pActor->thing->position, 0, 3.0, pActor->pDistractor);
                pActor->pMoveThing = pActor->pDistractor;
                return 1;
            }
            if (pAiclass->argsAsFloat[0] == 0.0)
            {
                pAiclass->argsAsFloat[0] = 500.0;
            }
        }
    }
    else if ((pAiclass->argsAsInt[1] != 0) &&
             ((uint32_t)(pActor->field_204 + pAiclass->argsAsInt[1]) < sithTime_curMs))
    {
        pActor->flags &= ~(SITHAI_MODE_TARGET_VISIBLE|SITHAI_MODE_ACTIVE|SITHAI_MODE_TOUGHSKIN|SITHAI_MODE_ATTACKING); 
        pActor->flags |= SITHAI_MODE_SEARCHING;
        sithActor_MoveJointsForEyePYR(pActor->thing, &rdroid_zeroVector3);
        return 1;
    }

    return 0;
}

// MOTS added
/*
p0 - How often to leap
p1 - Minimum Dot
p2 - Max Dist
p3 - Min Dist
p4 - Min time from awakening to first leap
p5 - Leap speed
*/
int sithAICmd_Leap(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, intptr_t otherFlags)
{
    sithThing *psVar1;
    int iVar2;
    int64_t lVar3;
    rdVector3 *lookPos;
    rdVector3 local_c;

    psVar1 = actor->pDistractor;
    if (flags != 0) 
    {
        if (flags != SITHAI_MODE_SEARCHING) // ?
        {
            if (flags != SITHAI_MODE_UNK100)  // ?
            {
                return 0;
            }
            if ((actor->flags & SITHAI_MODE_ACTIVE) == 0) {
                return 0;
            }
            instinct->nextUpdate = aiclass->argsAsInt[4] + sithTime_curMs;
            return 0;
        }
        if ((sithThing *)otherFlags == psVar1) {
            sithAI_FireWeapon(actor, 0.0, 0.0, 0.0, 0.0, 1, 8);
        }
    }

    if (psVar1 == (sithThing *)0x0) {
        return 0;
    }

    iVar2 = sithAI_Leap(actor, aiclass->argsAsFloat[3], aiclass->argsAsFloat[2], aiclass->argsAsFloat[1], 1, aiclass->argsAsFloat[5], 0);
    if (iVar2 != 0) 
    {
        actor->flags = actor->flags | SITHAI_MODE_TARGET_VISIBLE;
        lVar3 = (int64_t)(((_frand() * 0.4 - 0.2) -
                        -1.0) * aiclass->argsAsFloat[0]);
        instinct->nextUpdate = (int)lVar3 + sithTime_curMs;
        return 0;
    }
    if (actor->field_1F4 == 2) 
    {
        lookPos = &actor->field_1D4;
    }
    else
    {
        if (((actor->field_1F4 != 0) || (psVar1 = actor->pDistractor, psVar1 == (sithThing *)0x0)) ||
        (psVar1->moveType != 1)) goto LAB_0055c4da;
        lookPos = &local_c;
        local_c.x = psVar1->physicsParams.vel.x * 0.5 + psVar1->position.x;
        local_c.y = psVar1->physicsParams.vel.y * 0.5 + psVar1->position.y;
        local_c.z = psVar1->physicsParams.vel.z * 0.5 + psVar1->position.z;
    }
    sithAI_SetLookFrame(actor, lookPos);
LAB_0055c4da:
    if (actor->field_1F4 == 3) {
        actor->flags = actor->flags & ~SITHAI_MODE_TARGET_VISIBLE;
    }
    instinct->nextUpdate = sithTime_curMs + 250;

    return 0;
}

// MOTS added
/*
p0 - How often to charge
p1 - Minimum Dot
p2 - Max Dist
p3 - Min Dist
p4 - Min time from awakening to first charge
p5 - Charge speed
*/
// TODO verify params
int sithAICmd_Charge(sithActor *pActor, sithAIClassEntry *pAiclass, sithActorInstinct *pInstinct, int flags, intptr_t otherFlags)
{
    sithThing *psVar1;
    int iVar2;
    int64_t lVar3;
    rdVector3 *lookPos;
    rdVector3 local_c;

    if (flags != 0) {
        if (flags == 4) {
            if (pActor->moveSpeed != 1313.0) {
                return 0;
            }
            sithAI_FireWeapon(pActor, 0.0, 0.0, 0.0, 0.0, 1, 8);
            return 0;
        }
        if (flags != 0x100) {
            return 0;
        }
        if ((pActor->flags & SITHAI_MODE_ACTIVE) == 0) {
            return 0;
        }
        pInstinct->nextUpdate = pAiclass->argsAsInt[4] + sithTime_curMs;
        return 0;
    }
    if (pActor->pDistractor == (sithThing *)0x0) {
        return 0;
    }
    iVar2 = sithAI_FUN_0053a520(pActor, pAiclass->argsAsFloat[3], pAiclass->argsAsFloat[2], pAiclass->argsAsFloat[1], 1, pAiclass->argsAsFloat[5], 0);
    if (iVar2 != 0) {
        pActor->flags = pActor->flags | SITHAI_MODE_TARGET_VISIBLE;
        lVar3 = (int64_t)(((_frand() * 0.4 - 0.2) -
                        -1.0) * pAiclass->argsAsFloat[0]);
        pInstinct->nextUpdate = (int)lVar3 + sithTime_curMs;
        return 0;
    }
    if (pActor->field_1F4 == 2) {
        lookPos = &pActor->field_1D4;
    }
    else {
        if (((pActor->field_1F4 != 0) || (psVar1 = pActor->pDistractor, psVar1 == (sithThing *)0x0)) ||
        (psVar1->moveType != 1)) goto LAB_0055c33d;
        lookPos = &local_c;
        local_c.x = psVar1->physicsParams.vel.x * 0.5 + psVar1->position.x;
        local_c.y = psVar1->physicsParams.vel.y * 0.5 + psVar1->position.y;
        local_c.z = psVar1->physicsParams.vel.z * 0.5 + psVar1->position.z;
    }
    sithAI_SetLookFrame(pActor, lookPos);
LAB_0055c33d:
    if (pActor->field_1F4 == 3) {
        pActor->flags = pActor->flags & ~SITHAI_MODE_TARGET_VISIBLE;
    }
    pInstinct->nextUpdate = sithTime_curMs + 250;

    return 0;
}


