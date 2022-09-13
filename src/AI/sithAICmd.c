#include "sithAICmd.h"

#include "General/stdMath.h"
#include "AI/sithAI.h"
#include "AI/sithAIAwareness.h"
#include "World/sithThing.h"
#include "Gameplay/sithPlayerActions.h"
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
#include "Engine/sithCollision.h"
#include "jk.h"

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
    sithAI_RegisterCommand("primaryfire", sithAICmd_PrimaryFire, 
        SITHAI_MODE_ATTACKING,   // allowed flags
        0,                              // disallowed flags
        SITHAI_MODE_UNK100);
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

int sithAICmd_Follow(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, intptr_t otherFlags)
{
    sithThing *v7; // ebp
    sithAIClassEntry *v8; // ebx
    sithActorInstinct *v9; // edi
    int v10; // eax
    double v13; // st7
    double v16; // st7
    double v18; // st7
    rdVector3 a4a; // [esp+10h] [ebp-3Ch] BYREF
    rdVector3 arg8a; // [esp+1Ch] [ebp-30h] BYREF
    rdVector3 a1; // [esp+28h] [ebp-24h] BYREF
    rdVector3 a2; // [esp+34h] [ebp-18h] BYREF
    rdVector3 a5; // [esp+40h] [ebp-Ch] BYREF
    float a1a; // [esp+50h] [ebp+4h]
    float tmp1;
    float tmp2;
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
            a2.x = a1.x * 0.7 + actor->thing->position.x;
            a2.y = a1.y * 0.7 + actor->thing->position.y;
            a2.z = a1.z * 0.7 + actor->thing->position.z;
            sithAI_SetLookFrame(actor, &a2);
            sithAI_SetMoveThing(actor, &a2, 2.0);
            return 0;
        }
    }
    else if ( flags != SITHAI_MODE_ACTIVE )
    {
        if ( !flags)
        {
            v7 = actor->thingidk;
            if ( v7 )
            {
                v8 = aiclass;
                v9 = instinct;
                tmp2 = aiclass->argsAsFloat[0];
                a1a = aiclass->argsAsFloat[1];
                tmp1 = aiclass->argsAsFloat[2];
                v9->nextUpdate = sithTime_curMs + 1000;
                sithAI_sub_4EAF40(actor);
                v10 = actor->field_238;
                if ( v10 && v10 != 2 )
                {
                    if ( (actor->thing->actorParams.typeflags & SITH_AF_BLIND) == 0 && v9->param0 == 0.0 )
                    {
                        v9->param0 = 1.0;
                        sithAI_SetMoveThing(actor, &actor->field_23C, 2.0);
                        sithAI_SetLookFrame(actor, &actor->field_23C);
                        return 0;
                    }
                    return 0;
                }
                v9->param0 = 0.0;
                sithAI_SetLookFrame(actor, &v7->position);
                v13 = actor->field_234;
                // TODO verify
                if ( v13 > tmp1 )
                {
                    v16 = v13 - a1a;
LABEL_16:
                    arg8a.x = actor->field_228.x * v16 + actor->thing->position.x;
                    arg8a.y = actor->field_228.y * v16 + actor->thing->position.y;
                    arg8a.z = actor->field_228.z * v16 + actor->thing->position.z;
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
                      || !sithAI_sub_4EB300(v7, &v7->position, &arg8a, -1.0, actor->aiclass->sightDist, 0.0, &a5, &tmp) )
                    {
                        sithAI_SetMoveThing(actor, &arg8a, 1.5);
                        return 0;
                    }
                    return 0;
                }
                if ( v13 < tmp2 )
                {
                    v18 = actor->field_234;
                    // TODO verify
                    if ( tmp1 == 0.0 )
                        v16 = v18 - tmp2;
                    else
                        v16 = v18 - tmp1;
                    goto LABEL_16;
                }
            }
        }
        return 0;
    }

    if ( (actor->flags & SITHAI_MODE_MOVING) == 0 )
        return 0;
    if ( (actor->flags & SITHAI_MODE_ACTIVE) == 0 )
        return 0;
    _rand(); // TODO wat? did something get optimized out?
    if ( flags == SITHAI_MODE_ACTIVE
      && actor->field_228.z * actor->thing->physicsParams.vel.z
       + actor->field_228.x * actor->thing->physicsParams.vel.x
       + actor->field_228.y * actor->thing->physicsParams.vel.y > 0.029999999 )
    {
        return 0;
    }
    a1.x = 0.0;
    a1.z = 0.0;
    a1.y = 45.0;
    if ( _frand() <= 0.5 )
        a1.y = -45.0;
    rdVector_Rotate3(&a4a, &actor->field_1AC, &a1);
    a4a.x = actor->field_1B8 * a4a.x;
    a4a.y = actor->field_1B8 * a4a.y;
    a4a.z = actor->field_1B8 * a4a.z;
    a4a.x = actor->thing->position.x + a4a.x;
    a4a.y = actor->thing->position.y + a4a.y;
    a4a.z = actor->thing->position.z + a4a.z;
    sithAI_SetMoveThing(actor, &a4a, actor->moveSpeed);
    instinct->nextUpdate = sithTime_curMs + 1000;
    return 1;
}

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
        if ( !actor->field_1D0 || !projectile )
        {
            actor->flags &= ~SITHAI_MODE_ATTACKING;
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

int sithAICmd_LobFire(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, intptr_t otherFlags)
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
        if ( flags == SITHAI_MODE_UNK100 )
        {
            if ( (actor->flags & SITHAI_MODE_ACTIVE) != 0 )
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
    }

    actor->flags &= ~(SITHAI_MODE_TARGET_VISIBLE|SITHAI_MODE_ACTIVE|SITHAI_MODE_TOUGHSKIN|SITHAI_MODE_ATTACKING);
    actor->flags |= SITHAI_MODE_SEARCHING;
    return 1;
}

int sithAICmd_PrimaryFire(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, intptr_t otherFlags)
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
        if ( flags == SITHAI_MODE_UNK100 )
        {
            if ( (actor->flags & SITHAI_MODE_ACTIVE) != 0 )
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
            if (actor->field_1D0 && actor->field_1D0->moveType == SITH_MT_PHYSICS )
            {
                rdVector_Copy3(&v18, &actor->field_1D0->position);
                rdVector_MultAcc3(&v18, &actor->field_1D0->physicsParams.vel, 0.5);
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
    }

    instinct->param0 = aiclass->argsAsFloat[8];
    actor->flags &= ~(SITHAI_MODE_TARGET_VISIBLE|SITHAI_MODE_ACTIVE|SITHAI_MODE_TOUGHSKIN|SITHAI_MODE_ATTACKING);
    actor->flags |= SITHAI_MODE_SEARCHING;
    return 1;
}

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

    v7 = actor->field_1D0;
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
          || (v16 = actor->field_1D0) == 0
          || v16->moveType != SITH_MT_PHYSICS
          || rdVector_IsZero3(&v16->physicsParams.vel) )
        {
            v20 = &actor->thing->lookOrientation;
            rdMatrix_TransformVector34Acc_0(&a1, &actor->field_1E4, &actor->thing->lookOrientation);
        }
        else
        {
            v35.x = actor->field_1E4.x * v8->physicsParams.vel.y;
            v35.y = actor->field_1E4.y * v8->physicsParams.vel.y;
            v35.z = actor->field_1E4.z * v8->physicsParams.vel.y;
            v35.x += v16->physicsParams.vel.x;
            v35.y += v16->physicsParams.vel.y;
            v35.z += v16->physicsParams.vel.z;
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
        sithUnk4_RotateTurretToEyePYR(actor->thing);
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
        sithThing_SpawnDeadBodyMaybe(actor->thing, actor->thing, 2);
        return 0;
    }
    actor->thing->actorParams.eyePYR.y = _frand() * (flagsa + flagsa) - flagsa;
    actor->thing->actorParams.eyePYR.x = _frand() * (actora + actora) - actora;
    sithUnk4_RotateTurretToEyePYR(actor->thing);
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
                    movePos.x = lookPos.x - actor_->thing->position.x;
                    movePos.y = lookPos.y - actor_->thing->position.y;
                    movePos.z = lookPos.z - actor_->thing->position.z;
                    rdVector_Normalize3Acc(&movePos);
                    movePos.x *= aiclass->argsAsFloat[1];
                    movePos.y *= aiclass->argsAsFloat[1];
                    movePos.z *= aiclass->argsAsFloat[1];
                    movePos.x += actor_->thing->position.x;
                    movePos.y += actor_->thing->position.y;
                    movePos.z += actor_->thing->position.z;
                    sithAI_SetMoveThing(actor_, &movePos, 2.5);
                }
            }
            if ( _frand() < 0.1 && flags == SITHAI_MODE_MOVING )
            {
                if ( v17->type == SITH_THING_ACTOR || v17->type == SITH_THING_PLAYER )
                {
                    actor_->field_1D0 = v17;
                    actor_->thingidk = v17;
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
            v13 = sithAI_sub_4EB300(v6, &v6->position, v10, -1.0, actor_->aiclass->sightDist, 0.0, &a5, &tmp);
            if ( tmp <= (double)actor_->aiclass->hearDist
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
    actor_->field_1C4.x = v25->field_10[v12].x;
    actor_->field_1C4.y = v25->field_10[v12].y;
    v15 = v25->field_58[v12];
    actor_->field_1C4.z = v25->field_10[v12].z;
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

int sithAICmd_LookForTarget(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, void *extra)
{
    int v6; // ecx
    unsigned int v9; // edx
    sithThing *v10; // eax
    int v11; // ecx
    sithThing *v12; // [esp-8h] [ebp-10h]

    if ( !flags && (g_debugmodeFlags & 0x200) == 0 )
    {
        if ( (actor->flags & SITHAI_MODE_ACTIVE) != 0 )
        {
            v6 = aiclass->argsAsInt[1];
            if ( v6 && v6 + actor->field_204 < sithTime_curMs )
            {
                actor->flags &= ~(SITHAI_MODE_TARGET_VISIBLE|SITHAI_MODE_ACTIVE|SITHAI_MODE_TOUGHSKIN|SITHAI_MODE_ATTACKING);
                actor->flags |= SITHAI_MODE_SEARCHING;
                sithUnk4_MoveJointsForEyePYR(actor->thing, &rdroid_zeroVector3);
                return 1;
            }
        }
        else if ( (actor->flags & SITHAI_MODE_SEARCHING) != 0 )
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
                    actor->flags &= ~SITHAI_MODE_SEARCHING;
                    actor->flags |= (SITHAI_MODE_ACTIVE|SITHAI_MODE_TOUGHSKIN|SITHAI_MODE_HASDEST|SITHAI_MODE_ATTACKING);
                    sithSoundClass_PlayModeRandom(v12, SITH_SC_ALERT);
                    sithSoundClass_ThingPlaySoundclass4(actor->thing, SITH_SC_ACTIVATE);
                    sithAIAwareness_AddEntry(actor->field_1D0->sector, &actor->thing->position, 0, 3.0, actor->field_1D0);
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
    if ( (actor->flags & SITHAI_MODE_MOVING) != 0 )
    {
        sithPlayerActions_Activate(actor->thing);
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
    if (!(actor->flags & SITHAI_MODE_MOVING))
        return 0;
    if ( actor->field_228.x * v6->physicsParams.vel.x
       + actor->field_228.y * v6->physicsParams.vel.y
       + actor->field_228.z * v6->physicsParams.vel.z > 0.02 )
        return 0;
    //*(_QWORD *)&a2.x = sithTime_curMs;
    if ( (double)sithTime_curMs < instinct->param0 )
        return 0;

    instinct->param0 = aiclass->argsAsFloat[0] + (double)sithTime_curMs;
    if ( flags != SITHAI_MODE_SEARCHING && flags != SITHAI_MODE_ACTIVE )
    {
        if ( flags != SITHAI_MODE_TARGET_VISIBLE )
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
    v11 = actor->field_1C0;
    if ( !v11
      || sithTime_curSeconds > instinct->param0 + v8
      || ((v12 = aiclass->argsAsInt[1], actor->flags = v7 & ~SITHAI_MODE_ATTACKING, !v12) ? (instinct->nextUpdate = sithTime_curMs + 5000) : (instinct->nextUpdate = v12 + sithTime_curMs),
          sithAI_sub_4EB090(actor->thing, &actor->thing->position, v11, -1.0, aiclass1a, 0.0, &a5, &tmp)) )
    {
        v16 = actor->field_1C0;
        if ( v16 )
            sithAI_SetLookFrame(actor, &v16->position);
        actor->field_1C0 = 0;
        actor->flags &= ~(SITHAI_MODE_FLEEING|SITHAI_MODE_ACTIVE);
        actor->flags |= SITHAI_MODE_SEARCHING;
        
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
            if ( flags == SITHAI_MODE_UNK100 || flags == SITHAI_MODE_FLEEING )
            {
                a5.x = -a5.x;
                a5.y = -a5.y;
                a5.z = -a5.z;
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

    if ( (actor->flags & SITHAI_MODE_FLEEING) == 0 )
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
            movePos.x = aiclass->argsAsFloat[1] * a5.x + v13->position.x;
            movePos.y = aiclass->argsAsFloat[1] * a5.y + v13->position.y;
            movePos.z = aiclass->argsAsFloat[1] * a5.z + v13->position.z;
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
    if ( flags == SITHAI_MODE_MOVING )
    {
        if ( aiclass->argsAsFloat[1] != 0.0 && extra && (actor->flags & SITHAI_MODE_MOVING) == 0 )
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
                      && !sithAI_sub_4EB090(actor->thing, &actor->thing->position, v16->field_58[2], actor->aiclass->fov, 1.0, 0.0, &a5, &tmp) )
                    {
                        movePos.x = a5.x * -aiclass->argsAsFloat[0] + actor->thing->position.x;
                        movePos.y = a5.y * -aiclass->argsAsFloat[0] + actor->thing->position.y;
                        movePos.z = a5.z * -aiclass->argsAsFloat[0] + actor->thing->position.z;
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
    if ( (actor->flags & SITHAI_MODE_ATTACKING) == 0 )
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
            actor->field_1D0 = g_localPlayerThing;
            if ( (g_localPlayerThing->thingflags & (SITH_TF_DEAD|SITH_TF_WILLBEREMOVED)) != 0 )
                return 0;
            sithAI_sub_4EAD60(actor);
            if ( !actor->field_1F4 )
            {
                actor->flags &= ~SITHAI_MODE_SEARCHING;
                actor->flags |= SITHAI_MODE_FLEEING;
                sithSoundClass_PlayModeRandom(actor->thing, SITH_SC_FEAR);
                sithAIAwareness_AddEntry(actor->thing->sector, &actor->thing->position, 1, 3.0, actor->thing);
                actor->field_1C0 = actor->field_1D0;
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
                v9 = sithAI_sub_4EB090(actor->thing, &actor->thing->position, v8, -1.0, actor->aiclass->hearDist, 0.0, &a5, &tmp);
                if ( v9 != 1 && v9 != 3 )
                {
                    actor->field_1C0 = v8;
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
        actor->field_1C0 = sithThing_GetParent(extra);
    result = 1;
    actor->flags &= ~SITHAI_MODE_SEARCHING;
    actor->flags |= SITHAI_MODE_FLEEING;
    return result;
}

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
        actor->field_1C0 = actor->field_1D0;
        instinct->nextUpdate = sithTime_curMs + (int)aiclass->argsAsFloat[1];
        return 1;
    }
    return result;
}

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
            actor->field_1C0 = actor->field_1D0;
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

