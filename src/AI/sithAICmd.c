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
SithThing* sithAICmd_NearestPlayer(SithAIControlBlock *actor)
{
    if (!sithNet_isMulti)
        return sithPlayer_g_pLocalPlayerThing;

    SithThing* closest = sithPlayer_g_pLocalPlayerThing;
    flex_t closestDist = FLEX(999999.0);
    for (int i = 0; i < jkPlayer_maxPlayers; i++)
    {
        SithPlayer* playerInfo = &jkPlayer_playerInfos[i];
        SithThing* pLocalPlayer = playerInfo->pLocalPlayer;
        if (!pLocalPlayer) continue;

        if ((pLocalPlayer->flags & (SITH_TF_DISABLED|SITH_TF_DEAD|SITH_TF_DESTROYED)) || pLocalPlayer->type != SITH_THING_PLAYER)
            continue;

        flex_t dist = rdVector_Dist3(&pLocalPlayer->position, &actor->thing->position);
        if (dist < closestDist) {
            closestDist = dist;
            closest = pLocalPlayer;
        }
    }
    return closest;
}

void sithAICmd_Startup()
{
    sithAI_RegisterInstinct("listen", (sithAICommandFunc_t)sithAICmd_Listen, 
        0, // allowed flags...?
        0, // disallowed flags
        SITHAI_MODE_SEARCHING|SITHAI_MODE_ATTACKING|SITHAI_MODE_MOVING);
    
    sithAI_RegisterInstinct("lookfortarget", (sithAICommandFunc_t)sithAICmd_LookForTarget, 
        SITHAI_MODE_ACTIVE|SITHAI_MODE_SEARCHING, // allowed flags
        0,                              // disallowed flags
        0);
    
    if (Main_bMotsCompat) {
        sithAI_RegisterInstinct("lookforopposingtarget", (sithAICommandFunc_t)sithAICmd_LookForOpposingTarget, 
            SITHAI_MODE_ACTIVE|SITHAI_MODE_SEARCHING, // allowed flags
            0,                              // disallowed flags
            0);
    }

    sithAI_RegisterInstinct("primaryfire", (sithAICommandFunc_t)sithAICmd_PrimaryFire, 
        SITHAI_MODE_ATTACKING,   // allowed flags
        0,                              // disallowed flags
        SITHAI_MODE_UNK100);

    if (Main_bMotsCompat) {
        sithAI_RegisterInstinct("leap", (sithAICommandFunc_t)sithAICmd_Leap, 
            SITHAI_MODE_ATTACKING,   // allowed flags
            0,                              // disallowed flags
            SITHAI_MODE_UNK100|SITHAI_MODE_SEARCHING);
        sithAI_RegisterInstinct("charge", (sithAICommandFunc_t)sithAICmd_Charge, 
            SITHAI_MODE_ATTACKING,   // allowed flags
            0,                              // disallowed flags
            SITHAI_MODE_UNK100|SITHAI_MODE_SEARCHING);
    }
    sithAI_RegisterInstinct("follow", (sithAICommandFunc_t)sithAICmd_Follow,
        SITHAI_MODE_ATTACKING,   // allowed flags
        SITHAI_MODE_FLEEING,            // disallowed flags
        SITHAI_MODE_FLEEING|SITHAI_MODE_TARGETVISIBLE|SITHAI_MODE_ACTIVE);
    sithAI_RegisterInstinct("turretfire", (sithAICommandFunc_t)sithAICmd_TurretFire, 
        SITHAI_MODE_ATTACKING,   // allowed flags
        SITHAI_MODE_FLEEING,            // disallowed flags
        SITHAI_MODE_UNK100);
    sithAI_RegisterInstinct("opendoors", (sithAICommandFunc_t)sithAICmd_OpenDoors, 
        SITHAI_MODE_ATTACKING,   // allowed flags
        0,                              // disallowed flags
        0);
    sithAI_RegisterInstinct("jump", (sithAICommandFunc_t)sithAICmd_Jump, 
        0,                      // allowed flags
        0,                      // disallowed flags
        SITHAI_MODE_TARGETVISIBLE|SITHAI_MODE_ACTIVE|SITHAI_MODE_SEARCHING);
    sithAI_RegisterInstinct("randomturn", (sithAICommandFunc_t)sithAICmd_RandomTurn, 
        SITHAI_MODE_SEARCHING,  // allowed flags
        0,                      // disallowed flags
        0);
    sithAI_RegisterInstinct("roam", (sithAICommandFunc_t)sithAICmd_Roam, 
        SITHAI_MODE_SEARCHING,  // allowed flags
        0,                      // disallowed flags
        0);
    sithAI_RegisterInstinct("flee", (sithAICommandFunc_t)sithAICmd_Flee,
        SITHAI_MODE_FLEEING,    // allowed flags
        0,                      // disallowed flags
        SITHAI_MODE_FLEEING|SITHAI_MODE_TARGETVISIBLE|SITHAI_MODE_ACTIVE|SITHAI_MODE_UNK100|SITHAI_MODE_SEARCHING|SITHAI_MODE_MOVING);
    sithAI_RegisterInstinct("sensedanger", (sithAICommandFunc_t)sithAICmd_SenseDanger,
        SITHAI_MODE_SEARCHING, // SenseDanger allowed flags
        SITHAI_MODE_FLEEING,   // SenseDanger disallowed flags
        SITHAI_MODE_SEARCHING|SITHAI_MODE_ATTACKING|SITHAI_MODE_MOVING); // SenseDanger idk?
    sithAI_RegisterInstinct("hitandrun", (sithAICommandFunc_t)sithAICmd_HitAndRun, 
        SITHAI_MODE_FLEEING|SITHAI_MODE_TARGETVISIBLE, // HitAndRun allowed flags
        0,                            // HitAndRun disallowed flags
        0);                           // HitAndRun idk?
    sithAI_RegisterInstinct("retreat", (sithAICommandFunc_t)sithAICmd_Retreat, 
        SITHAI_MODE_ATTACKING, // allowed flags
        SITHAI_MODE_FLEEING,          // disallowed flags
        0);
    sithAI_RegisterInstinct("circlestrafe", (sithAICommandFunc_t)sithAICmd_CircleStrafe, 
        SITHAI_MODE_ATTACKING, // allowed flags
        SITHAI_MODE_FLEEING,          // disallowed flags
        0);
    sithAI_RegisterInstinct("blindfire", (sithAICommandFunc_t)sithAICmd_BlindFire, 
        SITHAI_MODE_ATTACKING, // allowed flags
        SITHAI_MODE_FLEEING|SITHAI_MODE_TARGETVISIBLE, // disallowed flags
        0);
    sithAI_RegisterInstinct("returnhome", (sithAICommandFunc_t)sithAICmd_ReturnHome, 
        0, // allowed flags
        0, // disallowed flags
        SITHAI_MODE_FLEEING|SITHAI_MODE_UNK100);
    sithAI_RegisterInstinct("lobfire", (sithAICommandFunc_t)sithAICmd_LobFire, 
        SITHAI_MODE_ATTACKING,   // allowed flags
        0,                              // disallowed flags
        SITHAI_MODE_UNK100);
    sithAI_RegisterInstinct("talk", (sithAICommandFunc_t)sithAICmd_Talk, 
        0xFFFF, // allowed flags (any)
        0,      // disallowed flags
        0);
    sithAI_RegisterInstinct("crouch", (sithAICommandFunc_t)sithAICmd_Crouch, 
        SITHAI_MODE_ATTACKING, // allowed flags
        0, // disallowed flags
        SITHAI_MODE_UNK100);
    sithAI_RegisterInstinct("withdraw", (sithAICommandFunc_t)sithAICmd_Withdraw,
        SITHAI_MODE_FLEEING, // allowed flags
        0, // disallowed flags
        SITHAI_MODE_FLEEING|SITHAI_MODE_TARGETVISIBLE|SITHAI_MODE_ACTIVE|SITHAI_MODE_UNK100|SITHAI_MODE_SEARCHING|SITHAI_MODE_MOVING);
    sithAI_RegisterInstinct("dodge", (sithAICommandFunc_t)sithAICmd_Dodge, 
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
int sithAICmd_Follow(SithAIControlBlock *actor, SithAIInstinct *aiclass, SithAIInstinctState *instinct, int flags, intptr_t otherFlags)
{
    SithThing *v7; // ebp
    SithAIInstinct *v8; // ebx
    SithAIInstinctState *v9; // edi
    int v10; // eax
    flex_d_t v16; // st7
    rdVector3 a4a; // [esp+10h] [ebp-3Ch] BYREF
    rdVector3 arg8a; // [esp+1Ch] [ebp-30h] BYREF
    rdVector3 a1; // [esp+28h] [ebp-24h] BYREF
    rdVector3 a2; // [esp+34h] [ebp-18h] BYREF
    rdVector3 a5; // [esp+40h] [ebp-Ch] BYREF
    flex_t argMaxDistToAllow; // [esp+50h] [ebp+4h]
    flex_t argMaxMeleeDist;
    flex_t argMinDistToAllow;
    flex_t tmp;

    if ( flags > SITHAI_MODE_ACTIVE )
    {
        if ( flags != SITHAI_MODE_TARGETVISIBLE )
        {
            if ( flags != SITHAI_MODE_FLEEING || (actor->flags & SITHAI_MODE_ACTIVE) == 0 || instinct->param0 == 0.0 )
                return 0;
            a4a.x = FLEX(0.0);
            a4a.z = FLEX(0.0);
            a4a.y = (_frand() - FLEX(0.5)) * FLEX(90.0);
            if ( _frand() >= FLEX(0.5) )
            {
                sithAI_sub_4EAF40(actor);
                rdVector_Rotate3(&a1, &actor->field_228, &a4a);
            }
            else
            {
                rdVector_Rotate3(&a1, &actor->thing->orient.lvec, &a4a);
            }
            rdVector_Copy3(&a2, &actor->thing->position);
            rdVector_ScaleAdd3Acc(&a2, &a1, FLEX(0.7));
            sithAI_SetLookFrame(actor, &a2);
            sithAI_SetMoveThing(actor, &a2, FLEX(2.0));
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
            argMinDistToAllow = aiclass->fltArg[0];
            argMaxDistToAllow = aiclass->fltArg[1];
            argMaxMeleeDist = aiclass->fltArg[2];
            v9->nextUpdate = sithTime_g_msecGameTime + 1000;
            sithAI_sub_4EAF40(actor);
            v10 = actor->field_238;
            if ( v10 && v10 != 2 )
            {
                if (Main_bMotsCompat && sithAI_pDistractor && actor->pDistractor == sithAI_pDistractor) 
                {
                    actor->pDistractor = sithAICmd_NearestPlayer(actor);
                    return 0;
                }
                if (actor->thing->actorParams.flags & SITH_AF_COMBO_BLIND)
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

            if ( actor->targetDistance <= argMaxDistToAllow )
            {
                if ( actor->targetDistance >= argMinDistToAllow ) {
                    return 0;
                }

                // TODO verify
                if ( argMaxMeleeDist == 0.0 )
                    v16 = actor->targetDistance - argMinDistToAllow;
                else
                    v16 = actor->targetDistance - argMaxMeleeDist;
            }
            else {
                v16 = actor->targetDistance - argMaxDistToAllow;
            }

            rdVector_Copy3(&arg8a, &actor->thing->position);
            rdVector_ScaleAdd3Acc(&arg8a, &actor->field_228, v16);
            if ( (actor->thing->physicsParams.flags & SITH_PF_FLY) != 0 )
            {
                arg8a.z = v7->position.z - -0.02;
            }
            else if ( (actor->thing->flags & SITH_TF_WATER) != 0 )
            {
                arg8a.z = v7->position.z;
            }
            else
            {
                arg8a.z = actor->thing->position.z;
            }
            if ( v8->fltArg[3] != 0.0
              || !sithAI_sub_4EB300(v7, &v7->position, &arg8a, -1.0, actor->pClass->sightDistance, 0.0, &a5, &tmp) )
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
    rdVector_Rotate3(&a4a, &actor->moveDirection, &a1);
    rdVector_Scale3Acc(&a4a, actor->moveDistance);
    rdVector_Add3Acc(&a4a, &actor->thing->position);
    sithAI_SetMoveThing(actor, &a4a, actor->moveSpeed);
    instinct->nextUpdate = sithTime_g_msecGameTime + 1000;
    return 1;
}

/*
p0 - Freq of Straf Check (msec)
p1 - %Yaw change on move (30-45 typical)
p2 - Max Dist to attempt Strafe
p3 - Update interval (typically 1000msec)
p4 - 0 single dir strafe, 1 random strafe
*/
int sithAICmd_CircleStrafe(SithAIControlBlock *actor, SithAIInstinct *aiclass, SithAIInstinctState *instinct, int flags, intptr_t otherFlags)
{
    int v8; // edi
    flex_d_t v13; // st7
    SithAIClass *v15; // edx
    rdVector3 movePos; // [esp+10h] [ebp-30h] BYREF
    rdVector3 a2a; // [esp+1Ch] [ebp-24h] BYREF
    rdVector3 a4; // [esp+28h] [ebp-18h] BYREF
    rdVector3 a5; // [esp+34h] [ebp-Ch] BYREF
    flex_t unused;

    instinct->nextUpdate = sithTime_g_msecGameTime + aiclass->intArg[0];
    if ( actor->pMoveThing )
    {
        v8 = aiclass->intArg[4];
        sithAI_sub_4EAF40(actor);
        if ( aiclass->fltArg[2] >= (flex_d_t)actor->targetDistance && !actor->field_238 )
        {
            rdVector_Scale3(&a2a, &actor->field_228, -actor->targetDistance);
            if ( v8
              || actor->pMoveThing->orient.lvec.y * a2a.y + actor->pMoveThing->orient.lvec.z * a2a.z + actor->pMoveThing->orient.lvec.x * a2a.x >= 0.0 )
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
                    v13 = (_frand() - -0.5) * instinct->param0 * aiclass->fltArg[1];
                }
                else
                {
                    v13 = aiclass->fltArg[1] * instinct->param0;
                }
                a4.y = v13;
                rdVector_Rotate3(&movePos, &a2a, &a4);
                rdVector_Add3Acc(&movePos, &actor->pMoveThing->position);
                if ( !sithAI_sub_4EB300(actor->pMoveThing, &actor->pMoveThing->position, &movePos, -1.0, actor->pClass->sightDistance, 0.0, &a5, &unused) )
                {
                    sithAI_SetMoveThing(actor, &movePos, 0.5);
                    sithAI_SetLookFrame(actor, &actor->pMoveThing->position);
                    instinct->nextUpdate = sithTime_g_msecGameTime + aiclass->intArg[3];
                    return 0;
                }
                instinct->param0 = -instinct->param0;
            }
        }
    }
    return 0;
}

//p0 - How long to stand between crouches
int sithAICmd_Crouch(SithAIControlBlock *actor, SithAIInstinct *aiclass, SithAIInstinctState *instinct, int flags, intptr_t otherFlags)
{
    instinct->nextUpdate = sithTime_g_msecGameTime + aiclass->intArg[0];
    if (!(actor->flags & SITHAI_MODE_MOVING) 
        && (actor->flags & SITHAI_MODE_ATTACKING)
        && (actor->flags & SITHAI_MODE_TARGETVISIBLE))
    {
        actor->thing->physicsParams.flags |= SITH_PF_CROUCHING;
        return 0;
    }
    else
    {
        actor->thing->physicsParams.flags &= ~SITH_PF_CROUCHING;
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
int sithAICmd_BlindFire(SithAIControlBlock *actor, SithAIInstinct *aiclass, SithAIInstinctState *instinct, int flags, intptr_t otherFlags)
{
    SithThing *weapon; // esi
    unsigned int bWhichProjectile; // ebp
    SithThing *projectile; // ebx
    SithThing *v11; // eax
    int v13; // eax
    rdVector3 fireOffs; // [esp+2Ch] [ebp-Ch] BYREF
    flex_t fOut;

    weapon = actor->thing;
    if ( aiclass->fltArg[1] < _frand() || actor->field_288 > sithTime_g_msecGameTime )
    {
        instinct->nextUpdate = sithTime_g_msecGameTime + 1000;
    }
    else
    {
        bWhichProjectile = aiclass->intArg[2];
        instinct->nextUpdate = sithTime_g_msecGameTime + aiclass->intArg[0];
        if ( bWhichProjectile > 1 )
            bWhichProjectile = 1;
        if ( bWhichProjectile == 1 )
            projectile = weapon->actorParams.templateWeapon2;
        else
            projectile = weapon->actorParams.pWeaponTemplate;
        if ( !actor->pDistractor || !projectile )
        {
            actor->flags &= ~SITHAI_MODE_ATTACKING;
            return 1;
        }
        if ( !sithAI_sub_4EB300(weapon, &weapon->position, &actor->field_1F8, aiclass->fltArg[3], 10.0, projectile->moveSize, &fireOffs, &fOut)
          && fOut >= (flex_d_t)aiclass->fltArg[4] )
        {
            if ( actor->attackDistance != 0.0 && aiclass->fltArg[5] != 0.0 )
            {
                sithAI_RandomFireVector(&fireOffs, aiclass->fltArg[5] / fOut);
            }
            if ( (g_debugmodeFlags & DEBUGFLAG_NO_AI) == 0 )
            {
                sithSoundClass_PlayModeFirst(weapon, bWhichProjectile + SITH_SC_FIRE1);
                v11 = sithWeapon_WeaponFire(weapon, projectile, &fireOffs, &actor->blindAimError, 0, bWhichProjectile + SITH_ANIM_FIRE, 1.0, 0, 0.0);
                if ( v11 )
                {
                    sithCog_ThingSendMessage(weapon, v11, SITH_MESSAGE_FIRE);
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
int sithAICmd_LobFire(SithAIControlBlock *actor, SithAIInstinct *aiclass, SithAIInstinctState *instinct, int flags, intptr_t otherFlags)
{
    int v5; // ebx
    SithThing *v6; // eax
    SithThing *v7; // ebp
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
                sithThing_SyncThing(actor->thing, THING_SYNC_PUPPET);
            }

            instinct->nextUpdate = sithTime_g_msecGameTime + 1000;
            return 0;
        }
        return 0;
    }
    if ( !v7 )
        return 0;
    if ( (v7->flags & (SITH_TF_DEAD|SITH_TF_DESTROYED)) == 0 )
    {
        if ( aiclass->fltArg[5] > _frand() )
            v5 = 1;
        if ( sithAI_FireWeapon(actor, aiclass->fltArg[2], aiclass->fltArg[3], aiclass->fltArg[1], aiclass->fltArg[4], v5, 2) )
        {
            actor->flags |= SITHAI_MODE_TARGETVISIBLE;
            v11 = sithTime_g_msecGameTime + aiclass->intArg[0];
            instinct->nextUpdate = v11;
            actor->field_288 = v11;
            return 0;
        }
        sithAI_SetLookFrame(actor, &v7->position);
        actor->flags |= SITHAI_MODE_TARGETVISIBLE;
        instinct->nextUpdate = sithTime_g_msecGameTime + 500;
        return 0;
    }
    if ( (actor->flags & SITHAI_MODE_TARGETVISIBLE) != 0 )
    {
        sithSoundClass_PlayModeRandom(v6, SITH_SC_VICTORY);
        sithPuppet_PlayMode(actor->thing, SITH_ANIM_VICTORY, 0);

        // Added: co-op
        if (sithNet_isMulti && sithNet_MultiModeFlags & MULTIMODEFLAG_COOP) {
            sithThing_SyncThing(actor->thing, THING_SYNC_PUPPET);
        }
    }

    actor->flags &= ~(SITHAI_MODE_TARGETVISIBLE|SITHAI_MODE_ACTIVE|SITHAI_MODE_TOUGHSKIN|SITHAI_MODE_ATTACKING);
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
int sithAICmd_PrimaryFire(SithAIControlBlock *actor, SithAIInstinct *aiclass, SithAIInstinctState *instinct, int flags, intptr_t otherFlags)
{
    int v5; // ebp
    int v6; // ebx
    SithThing *v7; // eax
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
            instinct->param0 = aiclass->fltArg[8];
            instinct->nextUpdate = sithTime_g_msecGameTime + aiclass->intArg[5];
        }
        else
        {
            sithPuppet_SetArmedMode(v7, 0);
        }

        // Added: co-op
        if (sithNet_isMulti && sithNet_MultiModeFlags & MULTIMODEFLAG_COOP) {
            sithThing_SyncThing(actor->thing, THING_SYNC_PUPPET);
        }
        return 0;
    }
    if ( !actor->pDistractor )
        return 0;
    if ( (actor->pDistractor->flags & (SITH_TF_DEAD|SITH_TF_DESTROYED)) == 0 )
    {
        if ( aiclass->fltArg[6] != 0.0 && aiclass->fltArg[6] >= _frand() )
            v5 = 1;
        if ( aiclass->fltArg[7] != 0.0 && aiclass->fltArg[7] >= _frand() )
            v6 = 1;

        if ( sithAI_FireWeapon(actor, aiclass->fltArg[4], aiclass->fltArg[2], aiclass->fltArg[1], aiclass->fltArg[3], v6, v5) )
        {
            actor->flags |= SITHAI_MODE_TARGETVISIBLE;
            if ( instinct->param0 == 0.0 )
            {
                instinct->param0 = aiclass->fltArg[8];
                instinct->nextUpdate = sithTime_g_msecGameTime + (int64_t)((_frand() * 0.4 - 0.2 - -1.0) * aiclass->fltArg[0]);
            }
            else
            {
                instinct->nextUpdate = sithTime_g_msecGameTime + aiclass->intArg[9];
                instinct->param0 = instinct->param0 - 1.0;
            }
            return 0;
        }
        instinct->param0 = aiclass->fltArg[8];
        if ( actor->field_1F4 == 2 )
        {
            sithAI_SetLookFrame(actor, &actor->field_1D4);
        }
        else if ( !actor->field_1F4 )
        {
            if (actor->pDistractor && actor->pDistractor->moveType == SITH_MT_PHYSICS )
            {
                rdVector_Copy3(&v18, &actor->pDistractor->position);
                rdVector_ScaleAdd3Acc(&v18, &actor->pDistractor->physicsParams.vel, 0.5);
                sithAI_SetLookFrame(actor, &v18);
            }
        }
        if ( actor->field_1F4 == 3 )
        {
            actor->flags &= ~SITHAI_MODE_TARGETVISIBLE;
        }
        instinct->nextUpdate = sithTime_g_msecGameTime + 250;
        return 0;
    }
    if ( (actor->flags & SITHAI_MODE_TARGETVISIBLE) != 0 )
    {
        sithSoundClass_PlayModeRandom(v7, SITH_SC_VICTORY);
        sithPuppet_PlayMode(actor->thing, SITH_ANIM_VICTORY, 0);

        // Added: co-op
        if (sithNet_isMulti && sithNet_MultiModeFlags & MULTIMODEFLAG_COOP) {
            sithThing_SyncThing(actor->thing, THING_SYNC_PUPPET);
        }
    }

    instinct->param0 = aiclass->fltArg[8];
    actor->flags &= ~(SITHAI_MODE_TARGETVISIBLE|SITHAI_MODE_ACTIVE|SITHAI_MODE_TOUGHSKIN|SITHAI_MODE_ATTACKING);
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
int sithAICmd_TurretFire(SithAIControlBlock *actor, SithAIInstinct *aiclass, SithAIInstinctState *instinct, int flags, intptr_t otherFlags)
{
    SithThing *v7; // eax
    SithThing *v8; // edi
    int result; // eax
    SithAIInstinctState *v13; // edi
    SithThing *v15; // eax
    SithThing *v16; // ecx
    rdMatrix34 *v20; // esi
    flex_d_t v23; // st7
    flex_d_t v24; // st7
    flex_d_t v25; // st7
    flex_d_t v28; // st7
    SithThing *v29; // eax
    flex_t v31; // [esp+10h] [ebp-60h]
    flex_t v32; // [esp+14h] [ebp-5Ch]
    rdVector3 a3; // [esp+1Ch] [ebp-54h] BYREF
    rdVector3 v35; // [esp+28h] [ebp-48h] BYREF
    rdVector3 a1; // [esp+34h] [ebp-3Ch] BYREF
    rdMatrix34 v37; // [esp+40h] [ebp-30h] BYREF
    flex_t actora; // [esp+74h] [ebp+4h]
    flex_t actorb; // [esp+74h] [ebp+4h]
    flex_t actorc; // [esp+74h] [ebp+4h]
    flex_t actord; // [esp+74h] [ebp+4h]
    flex_t flagsa; // [esp+80h] [ebp+10h]

    v7 = actor->pDistractor;
    v8 = actor->thing->actorParams.pWeaponTemplate;
    if ( flags )
        return 0;
    if ( !v7 || !v8 )
    {
        actor->flags &= ~SITHAI_MODE_ATTACKING;
        return 1;
    }
    if ( (v7->flags & (SITH_TF_DEAD|SITH_TF_DESTROYED)) != 0 )
    {
        actor->flags &= ~(SITHAI_MODE_ACTIVE|SITHAI_MODE_TOUGHSKIN|SITHAI_MODE_ATTACKING);
        actor->flags |= SITHAI_MODE_SEARCHING;
        return 1;
    }
    sithPuppet_SetArmedMode(actor->thing, 1);
    flagsa = aiclass->fltArg[2];
    actora = aiclass->fltArg[3];
    // TODO verify (aiclass->fltArg[5] == 0.0)
    if ( aiclass->fltArg[5] == 0.0 || actor->thing->actorParams.health >= actor->thing->actorParams.maxHealth * aiclass->fltArg[5] )
    {
        sithAI_sub_4EAD60(actor);
        if ( actor->field_1F4 )
        {
            actor->flags = actor->flags & ~(SITHAI_MODE_ACTIVE|SITHAI_MODE_TOUGHSKIN|SITHAI_MODE_ATTACKING) | SITHAI_MODE_SEARCHING;
            return 1;
        }
        v31 = aiclass->fltArg[1] * sithTime_g_frameTimeFlex;
        if ( aiclass->fltArg[8] <= _frand()
          || (v16 = actor->pDistractor) == 0
          || v16->moveType != SITH_MT_PHYSICS
          || rdVector_IsZero3(&v16->physicsParams.vel) )
        {
            v20 = &actor->thing->orient;
            rdMatrix_TransformVectorOrtho34(&a1, &actor->attackError, &actor->thing->orient);
        }
        else
        {
            rdVector_Copy3(&v35, &v16->physicsParams.vel);
            rdVector_ScaleAdd3Acc(&v35, &actor->attackError, v8->physicsParams.vel.y);

            rdVector_Normalize3Acc(&v35);
            v20 = &actor->thing->orient;
            rdMatrix_TransformVectorOrtho34(&a1, &v35, &actor->thing->orient);
        }
        rdVector_ExtractAngle(&a1, &a3);
        if ( a3.y < -flagsa )
        {
            a3.y = -flagsa;
        }
        else if ( a3.y > (flex_d_t)flagsa )
        {
            a3.y = flagsa;
        }
        if ( a3.x < -actora )
        {
            a3.x = -actora;
        }
        else if ( a3.x > (flex_d_t)actora )
        {
            a3.x = actora;
        }
        actorb = actor->thing->actorParams.headPYR.y;
        v32 = actor->thing->actorParams.headPYR.x;
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
        actor->thing->actorParams.headPYR.y = stdMath_NormalizeAngleAcute(actorc);
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
        actor->thing->actorParams.headPYR.x = v28;
        sithActor_UpdateAimJoints(actor->thing);
LABEL_50:
        if ( sithTime_g_secGameTime > (flex_d_t)instinct->param0 && (g_debugmodeFlags & DEBUGFLAG_NO_AI) == 0 )
        {
            rdMatrix_Copy34(&v37, v20);
            rdMatrix_PreRotate34(&v37, &actor->thing->actorParams.headPYR);
            sithSoundClass_PlayModeFirst(actor->thing, SITH_SC_FIRE1);
            v29 = sithWeapon_WeaponFire(actor->thing, v8, &v37.lvec, &actor->blindAimError, 0, SITH_ANIM_FIRE, 1.0, 0, 0.0);
            if ( v29 )
                sithCog_ThingSendMessage(actor->thing, v29, SITH_MESSAGE_FIRE);
            instinct->param0 = aiclass->fltArg[0] * 0.001 + sithTime_g_secGameTime;
        }
        instinct->nextUpdate = sithTime_g_msecGameTime + 1;
        return instinct->nextUpdate;
    }
    v13 = instinct;
    if ( instinct->param1 == 0.0 )
    {
        instinct->param0 = sithTime_g_secGameTime - 1.0;
        instinct->param1 = aiclass->fltArg[7] * 0.001 + sithTime_g_secGameTime;
    }
    else if ( sithTime_g_secGameTime > (flex_d_t)instinct->param1 )
    {
        sithActor_KillActor(actor->thing, actor->thing, 2);
        return 0;
    }
    actor->thing->actorParams.headPYR.y = _frand() * (flagsa + flagsa) - flagsa;
    actor->thing->actorParams.headPYR.x = _frand() * (actora + actora) - actora;
    sithActor_UpdateAimJoints(actor->thing);
    if ( sithTime_g_secGameTime > (flex_d_t)instinct->param0 )
    {
        _memcpy(&v37, &actor->thing->orient, sizeof(v37));
        rdMatrix_PreRotate34(&v37, &actor->thing->actorParams.headPYR);
        sithSoundClass_PlayModeFirst(actor->thing, SITH_SC_FIRE1);
        v15 = sithWeapon_WeaponFire(actor->thing, v8, &v37.lvec, &actor->thing->position, 0, SITH_ANIM_FIRE, 1.0, 0, 0.0);
        if ( v15 )
            sithCog_ThingSendMessage(actor->thing, v15, SITH_MESSAGE_FIRE);
        v13 = instinct;
        instinct->param0 = aiclass->fltArg[6] * 0.001 + sithTime_g_secGameTime;
    }
    v13->nextUpdate = sithTime_g_msecGameTime + 50;
    return 0;
}

// MoTS altered
/*
p0 - Investigate % (0 never, 1 always)
p1 - Distance to move from danger?
*/
int sithAICmd_Listen(SithAIControlBlock *actor, SithAIInstinct *aiclass, SithAIInstinctState *instinct, int flags, SithThing *extra)
{
    SithAIControlBlock *actor_; // esi
    SithThing *v6; // ebx
    sithSectorAlloc *v8; // ecx
    int result; // eax
    rdVector3 *v10; // ebp
    flex_t *v11; // ecx
    int v12; // edi
    int v13; // ecx
    flex_d_t v14; // st7
    SithThing *v15; // ebp
    SithAIInstinctState *instinct_; // edi
    SithThing *v17; // ebx
    sithSectorAlloc *v25; // [esp+10h] [ebp-28h]
    rdVector3 movePos; // [esp+14h] [ebp-24h] BYREF
    rdVector3 lookPos; // [esp+20h] [ebp-18h] BYREF
    rdVector3 a5; // [esp+2Ch] [ebp-Ch] BYREF
    flex_t tmp;

    actor_ = actor;
    if ( (actor->flags & SITHAI_MODE_SEARCHING) == 0 )
        return 0;
    v6 = actor->thing;
    v8 = &sithAIAwareness_g_aSectors[actor->thing->sector->id];
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
                if ( aiclass->fltArg[1] != 0.0 )
                {
                    rdVector_Sub3(&movePos, &lookPos, &actor_->thing->position);
                    rdVector_Normalize3Acc(&movePos);
                    rdVector_Scale3Acc(&movePos, aiclass->fltArg[1]);
                    rdVector_Add3Acc(&movePos, &actor_->thing->position);
                    sithAI_SetMoveThing(actor_, &movePos, 2.5);
                }
            }
            if ( _frand() < 0.1 && flags == SITHAI_MODE_MOVING )
            {
                if ((v17->type == SITH_THING_ACTOR || v17->type == SITH_THING_PLAYER)
                    && MOTS_ONLY_COND(actor_->pClass->alignment != 1.0 || (sithAI_FLOAT_005a79d8 != 1.0) || v17 != sithAICmd_NearestPlayer(actor_)) ) // TODO will sithAICmd_NearestPlayer work?
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
            v13 = sithAI_sub_4EB300(v6, &v6->position, v10, -1.0, actor_->pClass->sightDistance, 0.0, &a5, &tmp);
            if ( tmp <= (flex_d_t)actor_->pClass->heardDistance
              && (!v13
               || tmp < 1.0 && v6->orient.lvec.y * a5.y + v6->orient.lvec.z * a5.z + v6->orient.lvec.x * a5.x > 0.5) )
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
            //v14 = *(flex_t *)&instinct;
            //v15 = (SithThing *)instinct;
            
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

    if ( aiclass->fltArg[0] > _frand() && (actor_->flags & SITHAI_MODE_MOVING) == 0 )
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
int sithAICmd_LookForTarget(SithAIControlBlock *actor, SithAIInstinct *aiclass, SithAIInstinctState *instinct, int flags, void *extra)
{
    if (flags || (g_debugmodeFlags & DEBUGFLAG_NO_AILOOK_FOR_TARGET))
        return 0;

    if ( (actor->flags & SITHAI_MODE_ACTIVE) != 0 )
    {
        if ( aiclass->intArg[1] && aiclass->intArg[1] + actor->field_204 < sithTime_g_msecGameTime )
        {
            actor->flags &= ~(SITHAI_MODE_TARGETVISIBLE|SITHAI_MODE_ACTIVE|SITHAI_MODE_TOUGHSKIN|SITHAI_MODE_ATTACKING);
            actor->flags |= SITHAI_MODE_SEARCHING;
            sithActor_SetHeadPYR(actor->thing, &rdroid_zeroVector3);
            return 1;
        }
    }
    else if ((actor->flags & SITHAI_MODE_SEARCHING) && MOTS_ONLY_COND(
            (actor->pClass->alignment < -1.0 ||
            (((actor->pClass->alignment != 0.0 && sithAI_FLOAT_005a79d8 != 0.0) &&
            (actor->pClass->alignment < 0.0 != sithAI_FLOAT_005a79d8 < 0.0))))
        ))
    {
        if (Main_bMotsCompat)
        {
            int uVar1 = 0;
            SithThing* psVar3 = actor->pInterest;
            instinct->nextUpdate = aiclass->intArg[0] + sithTime_g_msecGameTime;
            if (((!actor->pInterest 
                && sithAI_pDistractor) 
                && (uVar1 = sithAI_pDistractor->flags, actor->pDistractor = sithAI_pDistractor,
            (uVar1 & 0x202) == 0)) && (sithAI_sub_4EAD60(actor), actor->field_1F4 == 0)) 
            {
                actor->flags &= ~(SITHAI_MODE_SEARCHING);
                actor->flags |= (SITHAI_MODE_ACTIVE|SITHAI_MODE_TOUGHSKIN|SITHAI_MODE_HASDEST|SITHAI_MODE_ATTACKING);
                sithSoundClass_PlayModeRandom(actor->thing, SITH_SC_ALERT);
                sithSoundClass_PlayModeFirst(actor->thing, SITH_SC_ACTIVATE);
                sithAIAwareness_CreateTransmittingEvent(actor->pDistractor->sector, &actor->thing->position, 0, 3.0, actor->pDistractor);
                actor->pMoveThing = actor->pDistractor;
                return 1;
            }
            psVar3 = actor->pInterest;
            if (!actor->pInterest) {
                psVar3 = sithAICmd_NearestPlayer(actor);
            }
            actor->pDistractor = psVar3;
            if ((psVar3->flags & (SITH_TF_DEAD|SITH_TF_DESTROYED)) == 0)
            {
                sithAI_sub_4EAD60(actor);
                if (actor->field_1F4 == 0) 
                {
                    actor->flags &= ~(SITHAI_MODE_SEARCHING);
                    actor->flags |= (SITHAI_MODE_ACTIVE|SITHAI_MODE_TOUGHSKIN|SITHAI_MODE_HASDEST|SITHAI_MODE_ATTACKING);
                    sithSoundClass_PlayModeRandom(actor->thing, SITH_SC_ALERT);
                    sithSoundClass_PlayModeFirst(actor->thing, SITH_SC_ACTIVATE);
                    sithAIAwareness_CreateTransmittingEvent(actor->pDistractor->sector, &actor->thing->position, 0, 3.0, actor->pDistractor);
                    actor->pMoveThing = actor->pDistractor;
                    return 1;
                }
                if (aiclass->fltArg[0] == 0.0) {
                    aiclass->fltArg[0] = 500.0;
                }
            }
        }
        else {
            actor->pDistractor = sithAICmd_NearestPlayer(actor);
            instinct->nextUpdate = sithTime_g_msecGameTime +  aiclass->intArg[0];
            if (!(actor->pDistractor->flags & (SITH_TF_DEAD|SITH_TF_DESTROYED)))
            {
                sithAI_sub_4EAD60(actor);
                if ( !actor->field_1F4 )
                {
                    actor->flags &= ~SITHAI_MODE_SEARCHING;
                    actor->flags |= (SITHAI_MODE_ACTIVE|SITHAI_MODE_TOUGHSKIN|SITHAI_MODE_HASDEST|SITHAI_MODE_ATTACKING);
                    sithSoundClass_PlayModeRandom(actor->thing, SITH_SC_ALERT);
                    sithSoundClass_PlayModeFirst(actor->thing, SITH_SC_ACTIVATE);
                    sithAIAwareness_CreateTransmittingEvent(actor->pDistractor->sector, &actor->thing->position, 0, 3.0, actor->pDistractor);
                    actor->pMoveThing = actor->pDistractor;
                    return 1;
                }
                if ( aiclass->fltArg[0] == 0.0 )
                    aiclass->fltArg[0] = 500.0;
            }
        }
        
    }
    return 0;
}

int sithAICmd_OpenDoors(SithAIControlBlock *actor, SithAIInstinct *aiclass, SithAIInstinctState *instinct, int flags, void *extra)
{
    if ( (actor->flags & SITHAI_MODE_MOVING) != 0 )
    {
        sithPlayerActions_Activate(actor->thing);
        instinct->nextUpdate = sithTime_g_msecGameTime + 1000;
    }
    return 0;
}

/*
p0 - Time between jump checks
p1 - Max jump height (Ai Thinks not Actual)
p2 - Max jump dist (Ai Thinks not Actual)
*/
int sithAICmd_Jump(SithAIControlBlock *actor, SithAIInstinct *aiclass, SithAIInstinctState *instinct, int flags, void *extra)
{
    SithAIControlBlock *_actor; // edi
    SithThing *actorThing; // esi
    SithSector *actorSector; // ebx
    rdVector3 pos; // [esp+Ch] [ebp-18h] BYREF
    rdVector3 tmpPos; // [esp+18h] [ebp-Ch] BYREF

    _actor = actor;
    actorThing = actor->thing;
    actorSector = actor->thing->sector;
    if ( !actor->thing->attach_flags )
        return 0;
    if (!(actor->flags & SITHAI_MODE_MOVING))
        return 0;
    if ( rdVector_Dot3(&actor->field_228, &actorThing->physicsParams.vel) > 0.02 )
        return 0;
    //*(_QWORD *)&pos.x = sithTime_g_msecGameTime;
    if ( (flex_d_t)sithTime_g_msecGameTime < instinct->param0 )
        return 0;

    instinct->param0 = aiclass->fltArg[0] + (flex_d_t)sithTime_g_msecGameTime;
    if ( flags != SITHAI_MODE_SEARCHING && flags != SITHAI_MODE_ACTIVE )
    {
        if ( flags != SITHAI_MODE_TARGETVISIBLE )
            return 0;

        rdVector_Copy3(&pos, &actorThing->position);
        rdVector_ScaleAdd3Acc(&pos, &_actor->moveDirection, aiclass->fltArg[2]);

        if ( sithAI_CanWalk(_actor, &pos, 0) )
        {
            rdVector_ScaleAdd3Acc(&actorThing->physicsParams.vel, &_actor->moveDirection, 0.1);
            sithAI_Jump(_actor, &_actor->movePos, 1.0);
            return 1;
        }
        return 1;
    }
    rdVector_Copy3(&tmpPos, &actorThing->position);
    rdVector_ScaleAdd3Acc(&tmpPos, &rdroid_zVector3, aiclass->fltArg[1]);
    SithSector* result = sithCollision_FindSectorInRadius(actorSector, &actorThing->position, &tmpPos, 0.0);
    if ( result )
    {
        pos.x = _actor->moveDirection.x * 0.1 + tmpPos.x;
        pos.y = _actor->moveDirection.y * 0.1 + tmpPos.y;
        pos.z = tmpPos.z;
        result = sithCollision_FindSectorInRadius(result, &tmpPos, &pos, 0.0);
        if ( result )
        {
            int tmp;
            if ( sithAI_CanWalk_ExplicitSector(_actor, &pos, result, &tmp) == 1 )
            {
                if ( tmp )
                    sithAI_Jump(_actor, &pos, 1.0);
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
int sithAICmd_Flee(SithAIControlBlock *actor, SithAIInstinct *aiclass, SithAIInstinctState *instinct, int flags, void *extra)
{
    int v7; // ecx
    flex_d_t v8; // st7
    int result; // eax
    SithThing *v11; // edi
    int v12; // eax
    SithThing *v15; // ecx
    SithThing *v16; // eax
    rdVector3 a5; // [esp+Ch] [ebp-24h] BYREF
    rdVector3 v19; // [esp+18h] [ebp-18h] BYREF
    rdVector3 movePos; // [esp+24h] [ebp-Ch] BYREF
    flex_t aiclass1a; // [esp+38h] [ebp+8h]
    flex_t tmp;

    v7 = actor->flags;
    aiclass1a = aiclass->fltArg[0];
    v8 = aiclass->fltArg[2];
    if ( (v7 & SITHAI_MODE_FLEEING) == 0 )
        return 0;

    if ( instinct->param0 == 0.0 )
        instinct->param0 = sithTime_g_secGameTime;
    if ( v8 == 0.0 )
        v8 = 10.0;
    v11 = actor->pFleeFromThing;
    if ( !v11
      || sithTime_g_secGameTime > instinct->param0 + v8
      || ((v12 = aiclass->intArg[1], actor->flags = v7 & ~SITHAI_MODE_ATTACKING, !v12) ? (instinct->nextUpdate = sithTime_g_msecGameTime + 5000) : (instinct->nextUpdate = v12 + sithTime_g_msecGameTime),
          sithAI_CheckSightThing(actor->thing, &actor->thing->position, v11, -1.0, aiclass1a, 0.0, &a5, &tmp)) )
    {
        v16 = actor->pFleeFromThing;
        if ( v16 )
            sithAI_SetLookFrame(actor, &v16->position);
        actor->pFleeFromThing = 0;
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
                if ( (v15->physicsParams.flags & SITH_PF_FLY) != 0 )
                    v19.x = (_frand() - 0.5) * 90.0;
                rdVector_Rotate3Acc(&a5, &v19);
            }
            else
            {
                v19.y = 90.0;
                if ( _frand() >= 0.5 )
                    v19.y = -90.0;
                rdVector_Rotate3(&a5, &actor->moveDirection, &v19);
            }
            rdVector_Copy3(&movePos, &actor->thing->position);
            rdVector_ScaleAdd3Acc(&movePos, &a5, aiclass1a);
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
int sithAICmd_Withdraw(SithAIControlBlock *actor, SithAIInstinct *aiclass, SithAIInstinctState *instinct, int flags, void *extra)
{
    int result; // eax
    SithThing *v13; // eax
    SithThing *v14; // eax
    rdVector3 a5; // [esp+4h] [ebp-24h] BYREF
    rdVector3 v17; // [esp+10h] [ebp-18h] BYREF
    rdVector3 movePos; // [esp+1Ch] [ebp-Ch] BYREF
    flex_t tmp;

    if ( (actor->flags & SITHAI_MODE_FLEEING) == 0 )
        return 0;

    if ( actor->pFleeFromThing)
    {
        if ( aiclass->intArg[0] )
            instinct->nextUpdate = aiclass->intArg[0] + sithTime_g_msecGameTime;
        else
            instinct->nextUpdate = sithTime_g_msecGameTime + 5000;

        if ( sithAI_CheckSightThing(actor->thing, &actor->thing->position, actor->pFleeFromThing, -1.0, actor->pClass->sightDistance, 0.0, &a5, &tmp) )
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
                if ( (v14->physicsParams.flags & SITH_PF_FLY) != 0 )
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
                rdVector_Rotate3(&a5, &actor->moveDirection, &v17);
                v13 = actor->thing;
            }
            rdVector_Copy3(&movePos, &v13->position);
            rdVector_ScaleAdd3Acc(&movePos, &a5, aiclass->fltArg[1]);
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
int sithAICmd_Dodge(SithAIControlBlock *actor, SithAIInstinct *aiclass, SithAIInstinctState *instinct, int flags, SithThing *extra)
{
    sithSectorAlloc *v16; // ecx
    rdVector3 a5; // [esp+10h] [ebp-24h] BYREF
    rdVector3 movePos; // [esp+1Ch] [ebp-18h] BYREF
    rdVector3 vAngs; // [esp+28h] [ebp-Ch] BYREF
    flex_t tmp;

    if ( !flags )
        return 0;
    if ( flags == SITHAI_MODE_MOVING )
    {
        if ( aiclass->fltArg[1] != 0.0 && extra && (actor->flags & SITHAI_MODE_MOVING) == 0 )
        {
            rdVector_Copy3(&vAngs, &extra->position);
            rdVector_Sub3(&a5, &vAngs, &actor->thing->position);
            tmp = rdVector_Normalize3Acc(&a5);
            rdVector_Copy3(&movePos, &actor->thing->position);
            rdVector_ScaleAdd3Acc(&movePos, &a5, -aiclass->fltArg[1]);
            sithAI_SetMoveThing(actor, &movePos, 2.5);
            actor->field_28C = sithTime_g_msecGameTime + 1000;
            return 0;
        }
        return 0;
    }
    if ( flags != SITHAI_MODE_SLEEPING )
    {
        if ( (actor->flags & SITHAI_MODE_ACTIVE) != 0 && flags == SITHAI_MODE_ATTACKING && aiclass->fltArg[0] != 0.0 )
        {
            v16 = &sithAIAwareness_g_aSectors[actor->thing->sector->id];
            if (v16->field_4[2])
            {
                if ( v16->field_58[2] )
                {
                    if ( sithThing_GetThingParent(v16->field_58[2]) != actor->thing
                      && v16->field_58[2]->type == SITH_THING_WEAPON
                      && v16->field_58[2]->moveType == SITH_MT_PHYSICS
                      && !sithAI_CheckSightThing(actor->thing, &actor->thing->position, v16->field_58[2], actor->pClass->fov, 1.0, 0.0, &a5, &tmp) )
                    {
                        rdVector_Copy3(&movePos, &actor->thing->position);
                        rdVector_ScaleAdd3Acc(&movePos, &a5, -aiclass->fltArg[0]);
                        sithAI_SetMoveThing(actor, &movePos, 2.5);
                        actor->field_28C = sithTime_g_msecGameTime + 1000;
                        sithSoundClass_PlayModeRandom(actor->thing, SITH_SC_CURIOUS);
                    }
                }
            }
        }
        return 0;
    }
    if ( (actor->flags & SITHAI_MODE_ACTIVE) == 0 )
        return 0;

    if ( aiclass->fltArg[1] == 0.0
      || !extra
      || sithAI_CheckSightThing(actor->thing, &actor->thing->position, extra, actor->pClass->fov, actor->pClass->sightDistance, 0.0, &a5, (flex_t *)&extra) ) // FLEXTODO
    {
        return 0;
    }
    rdVector_Zero3(&vAngs);
    vAngs.y = _frand() * 45.0 - -45.0;
    if ( _frand() < 0.5 )
        vAngs.y = -vAngs.y;
    rdVector_Rotate3Acc(&a5, &vAngs);
    rdVector_Copy3(&movePos, &actor->thing->position);
    rdVector_ScaleAdd3Acc(&movePos, &a5, -aiclass->fltArg[1]);
    sithAI_SetMoveThing(actor, &movePos, 2.5);
    return 0;
}

/*
p0 - interval for turn (msec)
p1 - min dist to see for valid (ave 1 or 2)
*/
int sithAICmd_RandomTurn(SithAIControlBlock *actor, SithAIInstinct *aiclass, SithAIInstinctState *instinct, int flags, SithThing *extra)
{
    int result; // eax
    rdVector3 out; // [esp+20h] [ebp-30h] BYREF
    rdVector3 vAngs; // [esp+2Ch] [ebp-24h] BYREF
    rdVector3 arg8; // [esp+38h] [ebp-18h] BYREF
    rdVector3 a5; // [esp+44h] [ebp-Ch] BYREF
    flex_t tmp;

    if ( aiclass->intArg[0] )
        instinct->nextUpdate = sithTime_g_msecGameTime + aiclass->intArg[0];
    else
        instinct->nextUpdate = sithTime_g_msecGameTime + 5000;
    if ( (actor->flags & 4) == 0 )
        return 0;
    out = rdroid_yVector3;
    rdVector_Scale3(&vAngs, &rdroid_yVector3, _frand() * 360.0);
    rdVector_Rotate3Acc(&out, &vAngs);
    rdVector_Copy3(&arg8, &actor->thing->position);
    rdVector_ScaleAdd3Acc(&arg8, &out, aiclass->fltArg[1]);
    result = sithAI_sub_4EB300(actor->thing, &actor->thing->position, &arg8, -1.0, aiclass->fltArg[1], 0.0, &a5, &tmp);
    if ( !result )
        sithAI_SetLookFrame(actor, &arg8);
    return result;
}

/*
p0 - How often pick new roam
p1 - Radius to roam from home
*/
int sithAICmd_Roam(SithAIControlBlock *actor, SithAIInstinct *aiclass, SithAIInstinctState *instinct, int flags, void *extra)
{
    flex_d_t randVal; // st6
    rdVector3 *v13; // [esp-8h] [ebp-30h]
    rdVector3 movePos; // [esp+4h] [ebp-24h] BYREF
    rdVector3 v16; // [esp+10h] [ebp-18h] BYREF
    rdVector3 v17; // [esp+1Ch] [ebp-Ch] BYREF

    instinct->nextUpdate = sithTime_g_msecGameTime + aiclass->intArg[0];
    if ( (actor->flags & SITHAI_MODE_ATTACKING) == 0 )
    {
        rdVector_Zero3(&v17);
        v13 = &actor->thing->orient.lvec;
        v17.y = (_frand() - 0.5) * 360.0;
        rdVector_Rotate3(&v16, v13, &v17);
        if ( aiclass->fltArg[1] <= 0.0 )
        {
            randVal = _frand() * -aiclass->fltArg[1];
            rdVector_Copy3(&movePos, &actor->thing->position);
            rdVector_ScaleAdd3Acc(&movePos, &v16, randVal);
        }
        else
        {
            randVal = _frand() * aiclass->fltArg[1];
            rdVector_Copy3(&movePos, &actor->position);
            rdVector_ScaleAdd3Acc(&movePos, &v16, randVal);
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
int sithAICmd_SenseDanger(SithAIControlBlock *actor, SithAIInstinct *aiclass, SithAIInstinctState *instinct, int flags, SithThing *extra)
{
    sithSectorAlloc *v7; // ecx
    SithThing *v8; // ebx
    int v9; // eax
    int result; // eax
    rdVector3 a5; // [esp+Ch] [ebp-Ch] BYREF
    flex_t tmp;

    v7 = &sithAIAwareness_g_aSectors[actor->thing->sector->id];
    if ( (actor->flags & SITHAI_MODE_FLEEING) != 0 || (actor->flags & SITHAI_MODE_SEARCHING) == 0 )
        return 0;
    if ( !flags )
    {
        if ( aiclass->fltArg[1] != 0.0 )
        {
            if (Main_bMotsCompat) {
                SithThing* psVar4 = actor->pInterest;
                if (!actor->pInterest) {
                    psVar4 = sithAICmd_NearestPlayer(actor);
                }
                actor->pDistractor = psVar4;
            }
            else {
                actor->pDistractor = sithAICmd_NearestPlayer(actor);
            }
            
            if ( (actor->pDistractor->flags & (SITH_TF_DEAD|SITH_TF_DESTROYED)) != 0 )
                return 0;
            sithAI_sub_4EAD60(actor);
            if ( !actor->field_1F4 )
            {
                actor->flags &= ~SITHAI_MODE_SEARCHING;
                actor->flags |= SITHAI_MODE_FLEEING;
                sithSoundClass_PlayModeRandom(actor->thing, SITH_SC_FEAR);
                sithAIAwareness_CreateTransmittingEvent(actor->thing->sector, &actor->thing->position, 1, 3.0, actor->thing);
                actor->pFleeFromThing = actor->pDistractor;
                return 1;
            }
        }
        instinct->nextUpdate = sithTime_g_msecGameTime + 1000;
        return 0;
    }
    if ( flags != 1 )
    {
        if ( flags == 2 && v7->field_4[1] > (flex_d_t)aiclass->fltArg[0] )
        {
            v8 = v7->field_58[1];
            if ( v8 )
            {
                v9 = sithAI_CheckSightThing(actor->thing, &actor->thing->position, v8, -1.0, actor->pClass->heardDistance, 0.0, &a5, &tmp);
                if ( v9 != 1 && v9 != 3 )
                {
                    actor->pFleeFromThing = v8;
                    if ( (actor->flags & SITHAI_MODE_FLEEING) == 0 )
                    {
                        sithSoundClass_PlayModeRandom(actor->thing, SITH_SC_FEAR);
                        sithAIAwareness_CreateTransmittingEvent(actor->thing->sector, &actor->thing->position, 1, 4.0, actor->thing);
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
        actor->pFleeFromThing = sithThing_GetThingParent(extra);
    result = 1;
    actor->flags &= ~SITHAI_MODE_SEARCHING;
    actor->flags |= SITHAI_MODE_FLEEING;
    return result;
}

/*
p0 - Time after Attack till flee (msec)
p1 - Time till reengaging (msec)
*/
int sithAICmd_HitAndRun(SithAIControlBlock *actor, SithAIInstinct *aiclass, SithAIInstinctState *instinct, int flags, void *extra)
{
    int result; // eax
    flex_d_t v8; // st7

    if ( flags )
        return 0;

    if ( (actor->flags & SITHAI_MODE_FLEEING) != 0 )
    {
        actor->flags &= ~SITHAI_MODE_FLEEING;
        return 1;
    }
    if ( (actor->flags & SITHAI_MODE_TARGETVISIBLE) == 0 )
    {
        instinct->param0 = 0.0;
        instinct->nextUpdate = sithTime_g_msecGameTime + 1000;
        return 0;
    }
    v8 = instinct->param0 - -1000.0;
    if ( v8 <= aiclass->fltArg[0] )
    {
        instinct->param0 = v8;
        result = sithTime_g_msecGameTime + 1000;
        instinct->nextUpdate = result;
    }
    else
    {
        instinct->param0 = 0.0;
        actor->flags |= SITHAI_MODE_FLEEING;
        actor->pFleeFromThing = actor->pDistractor;
        instinct->nextUpdate = sithTime_g_msecGameTime + (int32_t)stdMath_Floor(aiclass->fltArg[1] + 0.5);
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
int sithAICmd_Retreat(SithAIControlBlock *actor, SithAIInstinct *aiclass, SithAIInstinctState *instinct, int flags, SithThing *extra)
{
    int result; // eax

    if ( flags )
        return 0;

    if ( (actor->flags & SITHAI_MODE_ATTACKING) == 0 )
        return 0;

    if ( aiclass->fltArg[3] != 0.0 && aiclass->fltArg[3] < (flex_d_t)instinct->param0 )
    {
        instinct->field_0 |= 1;
        return 0;
    }

    if ( actor->thing->actorParams.health < aiclass->fltArg[0] * actor->thing->actorParams.maxHealth )
    {
        if ( aiclass->fltArg[1] > _frand() )
        {
            instinct->param0 = instinct->param0 - -1.0;
            sithSoundClass_PlayModeRandom(actor->thing, SITH_SC_FLEE);
            actor->flags |= SITHAI_MODE_FLEEING;
            actor->pFleeFromThing = actor->pDistractor;
            return 1;
        }

        if ( _frand() < 0.1 )
            sithSoundClass_PlayModeRandom(actor->thing, SITH_SC_FEAR);
    }

    result = sithTime_g_msecGameTime + aiclass->intArg[2];
    instinct->nextUpdate = result;
    return result;
}

int sithAICmd_ReturnHome(SithAIControlBlock *actor, SithAIInstinct *aiclass, SithAIInstinctState *instinct, int flags, intptr_t extra)
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
        rdVector_Add3(&a2, &actor->orient, &actor->thing->position);
        sithAI_SetLookFrame(actor, &a2);
        return 0;
    }
    return 0;
}

/*
p0 - interval between voice (msec)
p1 - %chance of say (0 never, 1 always)
*/
int sithAICmd_Talk(SithAIControlBlock *actor, SithAIInstinct *aiclass, SithAIInstinctState *instinct, int flags, void *extra)
{
    flex_d_t healthPercent; // st7

    instinct->nextUpdate = sithTime_g_msecGameTime + aiclass->intArg[0];
    if ( aiclass->fltArg[1] <= _frand() )
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

    if (actor->flags & SITHAI_MODE_TARGETVISIBLE)
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
int sithAICmd_LookForOpposingTarget(SithAIControlBlock *pActor, SithAIInstinct *pAiclass, SithAIInstinctState *pInstinct, int flags, intptr_t otherFlags)
{
    SithAIClass *psVar2;
    SithThing *psVar3;

    if (flags)
        return 0;
    if (g_debugmodeFlags & DEBUGFLAG_NO_AILOOK_FOR_TARGET)
        return 0;

    if ((pActor->flags & SITHAI_MODE_ACTIVE) == 0)
    {
        if (!(pActor->flags & SITHAI_MODE_SEARCHING))
            return 0;

        psVar2 = pActor->pClass;
        pInstinct->nextUpdate = pAiclass->intArg[0] + sithTime_g_msecGameTime;
        if (psVar2->alignment == 0.0) {
            return 0;
        }

        psVar3 = pActor->pInterest;
        if (psVar3 == (SithThing *)0x0)
        {
            psVar3 = sithAI_FUN_00539a60(pActor);
        }
        pActor->pDistractor = psVar3;
        if ((psVar3 != (SithThing *)0x0) && ((psVar3->flags & (SITH_TF_DEAD|SITH_TF_DESTROYED)) == 0))
        {
            sithAI_sub_4EAD60(pActor);
            if (pActor->field_1F4 == 0) {
                pActor->flags &= ~SITHAI_MODE_SEARCHING;
                pActor->flags |= (SITHAI_MODE_ACTIVE|SITHAI_MODE_TOUGHSKIN|SITHAI_MODE_HASDEST|SITHAI_MODE_ATTACKING);
                sithSoundClass_PlayModeRandom(pActor->thing, SITH_SC_ALERT);
                sithSoundClass_PlayModeFirst(pActor->thing, SITH_SC_ACTIVATE);
                sithAIAwareness_CreateTransmittingEvent(pActor->pDistractor->sector, &pActor->thing->position, 0, 3.0, pActor->pDistractor);
                pActor->pMoveThing = pActor->pDistractor;
                return 1;
            }
            if (pAiclass->fltArg[0] == 0.0)
            {
                pAiclass->fltArg[0] = 500.0;
            }
        }
    }
    else if ((pAiclass->intArg[1] != 0) &&
             ((uint32_t)(pActor->field_204 + pAiclass->intArg[1]) < sithTime_g_msecGameTime))
    {
        pActor->flags &= ~(SITHAI_MODE_TARGETVISIBLE|SITHAI_MODE_ACTIVE|SITHAI_MODE_TOUGHSKIN|SITHAI_MODE_ATTACKING); 
        pActor->flags |= SITHAI_MODE_SEARCHING;
        sithActor_SetHeadPYR(pActor->thing, &rdroid_zeroVector3);
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
int sithAICmd_Leap(SithAIControlBlock *actor, SithAIInstinct *aiclass, SithAIInstinctState *instinct, int flags, intptr_t otherFlags)
{
    SithThing *psVar1;
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
            instinct->nextUpdate = aiclass->intArg[4] + sithTime_g_msecGameTime;
            return 0;
        }
        if ((SithThing *)otherFlags == psVar1) {
            sithAI_FireWeapon(actor, 0.0, 0.0, 0.0, 0.0, 1, 8);
        }
    }

    if (psVar1 == (SithThing *)0x0) {
        return 0;
    }

    iVar2 = sithAI_Leap(actor, aiclass->fltArg[3], aiclass->fltArg[2], aiclass->fltArg[1], 1, aiclass->fltArg[5], 0);
    if (iVar2 != 0) 
    {
        actor->flags = actor->flags | SITHAI_MODE_TARGETVISIBLE;
        lVar3 = (int64_t)(((_frand() * 0.4 - 0.2) -
                        -1.0) * aiclass->fltArg[0]);
        instinct->nextUpdate = (int)lVar3 + sithTime_g_msecGameTime;
        return 0;
    }
    if (actor->field_1F4 == 2) 
    {
        lookPos = &actor->field_1D4;
    }
    else
    {
        if (((actor->field_1F4 != 0) || (psVar1 = actor->pDistractor, psVar1 == (SithThing *)0x0)) ||
        (psVar1->moveType != 1)) goto LAB_0055c4da;
        lookPos = &local_c;
        local_c.x = psVar1->physicsParams.vel.x * 0.5 + psVar1->position.x;
        local_c.y = psVar1->physicsParams.vel.y * 0.5 + psVar1->position.y;
        local_c.z = psVar1->physicsParams.vel.z * 0.5 + psVar1->position.z;
    }
    sithAI_SetLookFrame(actor, lookPos);
LAB_0055c4da:
    if (actor->field_1F4 == 3) {
        actor->flags = actor->flags & ~SITHAI_MODE_TARGETVISIBLE;
    }
    instinct->nextUpdate = sithTime_g_msecGameTime + 250;

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
int sithAICmd_Charge(SithAIControlBlock *pActor, SithAIInstinct *pAiclass, SithAIInstinctState *pInstinct, int flags, intptr_t otherFlags)
{
    SithThing *psVar1;
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
        pInstinct->nextUpdate = pAiclass->intArg[4] + sithTime_g_msecGameTime;
        return 0;
    }
    if (pActor->pDistractor == (SithThing *)0x0) {
        return 0;
    }
    iVar2 = sithAI_Charge(pActor, pAiclass->fltArg[3], pAiclass->fltArg[2], pAiclass->fltArg[1], 1, pAiclass->fltArg[5], 0);
    if (iVar2 != 0) {
        pActor->flags = pActor->flags | SITHAI_MODE_TARGETVISIBLE;
        lVar3 = (int64_t)(((_frand() * 0.4 - 0.2) -
                        -1.0) * pAiclass->fltArg[0]);
        pInstinct->nextUpdate = (int)lVar3 + sithTime_g_msecGameTime;
        return 0;
    }
    if (pActor->field_1F4 == 2) {
        lookPos = &pActor->field_1D4;
    }
    else {
        if (((pActor->field_1F4 != 0) || (psVar1 = pActor->pDistractor, psVar1 == (SithThing *)0x0)) ||
        (psVar1->moveType != 1)) goto LAB_0055c33d;
        lookPos = &local_c;
        local_c.x = psVar1->physicsParams.vel.x * 0.5 + psVar1->position.x;
        local_c.y = psVar1->physicsParams.vel.y * 0.5 + psVar1->position.y;
        local_c.z = psVar1->physicsParams.vel.z * 0.5 + psVar1->position.z;
    }
    sithAI_SetLookFrame(pActor, lookPos);
LAB_0055c33d:
    if (pActor->field_1F4 == 3) {
        pActor->flags = pActor->flags & ~SITHAI_MODE_TARGETVISIBLE;
    }
    pInstinct->nextUpdate = sithTime_g_msecGameTime + 250;

    return 0;
}


