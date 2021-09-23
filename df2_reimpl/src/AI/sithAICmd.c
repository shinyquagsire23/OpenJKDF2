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
#define sithAICmd_Flee ((void*)sithAICmd_Flee_ADDR)
#define sithAICmd_Withdraw ((void*)sithAICmd_Withdraw_ADDR)
#define sithAICmd_Dodge ((void*)sithAICmd_Dodge_ADDR)
#define sithAICmd_RandomTurn ((void*)sithAICmd_RandomTurn_ADDR)
#define sithAICmd_Roam ((void*)sithAICmd_Roam_ADDR)
#define sithAICmd_SenseDanger ((void*)sithAICmd_SenseDanger_ADDR)
#define sithAICmd_HitAndRun ((void*)sithAICmd_HitAndRun_ADDR)
#define sithAICmd_Retreat ((void*)sithAICmd_Retreat_ADDR)
#define sithAICmd_ReturnHome ((void*)sithAICmd_ReturnHome_ADDR)
#define sithAICmd_Talk ((void*)sithAICmd_Talk_ADDR)

void sithAICmd_Startup()
{
    sithAI_RegisterCommand("listen", sithAICmd_Listen, 0, 0, 7);
    sithAI_RegisterCommand("lookfortarget", sithAICmd_LookForTarget, 0x204, 0, 0);
    sithAI_RegisterCommand("primaryfire", sithAICmd_PrimaryFire, 2, 0, 0x100);
    sithAI_RegisterCommand("follow", sithAICmd_Follow, 2, 0x800, 0xE00);
    sithAI_RegisterCommand("turretfire", sithAICmd_TurretFire, 2, 0x800, 0x100);
    sithAI_RegisterCommand("opendoors", sithAICmd_OpenDoors, 2, 0, 0);
    sithAI_RegisterCommand("jump", sithAICmd_Jump, 0, 0, 0x604);
    sithAI_RegisterCommand("randomturn", sithAICmd_RandomTurn, 4, 0, 0);
    sithAI_RegisterCommand("roam", sithAICmd_Roam, 4, 0, 0);
    sithAI_RegisterCommand("flee", sithAICmd_Flee, 0x800, 0, 0xF05);
    sithAI_RegisterCommand("sensedanger", sithAICmd_SenseDanger, 4, 0x800, 7);
    sithAI_RegisterCommand("hitandrun", sithAICmd_HitAndRun, 0xC00, 0, 0);
    sithAI_RegisterCommand("retreat", sithAICmd_Retreat, 2, 0x800, 0);
    sithAI_RegisterCommand("circlestrafe", sithAICmd_CircleStrafe, 2, 0x800, 0);
    sithAI_RegisterCommand("blindfire", sithAICmd_BlindFire, 2, 0xC00, 0);
    sithAI_RegisterCommand("returnhome", sithAICmd_ReturnHome, 0, 0, 0x900);
    sithAI_RegisterCommand("lobfire", sithAICmd_LobFire, 2, 0, 0x100);
    sithAI_RegisterCommand("talk", sithAICmd_Talk, 0xFFFF, 0, 0);
    sithAI_RegisterCommand("crouch", sithAICmd_Crouch, 2, 0, 0x100);
    sithAI_RegisterCommand("withdraw", sithAICmd_Withdraw, 0x800, 0, 0xF05);
    sithAI_RegisterCommand("dodge", sithAICmd_Dodge, 0, 0, 0x1003);
}

// sithAICmd_Follow

int sithAICmd_CircleStrafe(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, int otherFlags)
{
    int v8; // edi
    double v9; // st6
    double v10; // st7
    double v11; // st5
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
            v9 = -actor->field_234;
            v10 = actor->field_228.y * v9;
            v11 = actor->field_228.z * v9;
            a2a.x = actor->field_228.x * v9;
            a2a.y = v10;
            a2a.z = v11;
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
    float v14; // [esp+10h] [ebp-28h]
    sithThing *v15; // [esp+28h] [ebp-10h]
    rdVector3 fireOffs; // [esp+2Ch] [ebp-Ch] BYREF
    float fOut;

    weapon = actor->thing;
    v15 = actor->field_1D0;
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
        if ( !v15 || !projectile )
        {
            actor->flags &= ~SITHAIFLAGS_ATTACKING_TARGET;
            return 1;
        }
        if ( !sithAI_sub_4EB300(weapon, &weapon->position, &actor->field_1F8, aiclass->argsAsFloat[3], 10.0, projectile->moveSize, &fireOffs, &fOut)
          && fOut >= (double)aiclass->argsAsFloat[4] )
        {
            if ( actor->field_1F0 != 0.0 && aiclass->argsAsFloat[5] != 0.0 )
            {
                v14 = aiclass->argsAsFloat[5] / fOut;
                sithAI_RandomFireVector(&fireOffs, v14);
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
    signed int result; // eax
    int v11; // eax

    v5 = 0;
    v6 = actor->thing;
    v7 = actor->field_1D0;
    if ( flags )
    {
        if ( flags == 0x100 )
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
            actor->flags |= SITHAIFLAGS_SEARCHING;
            v11 = sithTime_curMs + aiclass->argsAsInt[0];
            instinct->nextUpdate = v11;
            actor->field_288 = v11;
            return 0;
        }
        sithAI_SetLookFrame(actor, &v7->position);
        actor->flags |= SITHAIFLAGS_SEARCHING;
        instinct->nextUpdate = sithTime_curMs + 500;
        return 0;
    }
    if ( (actor->flags & SITHAIFLAGS_TARGET_SIGHTED_IN_RANGE) != 0 )
    {
        sithSoundClass_ThingPlaySoundclass(v6, SITH_SC_VICTORY);
        sithPuppet_PlayMode(actor->thing, SITH_ANIM_VICTORY, 0);
    }
    result = 1;
    actor->flags &= ~(SITHAIFLAGS_TARGET_SIGHTED_IN_RANGE|SITHAIFLAGS_AWAKE_AND_ACTIVE|SITHAIFLAGS_HAS_TARGET|SITHAIFLAGS_ATTACKING_TARGET);
    actor->flags |= SITHAIFLAGS_SEARCHING;
    return result;
}

int sithAICmd_PrimaryFire(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, int otherFlags)
{
    int v5; // ebp
    int v6; // ebx
    sithThing *v7; // eax
    int v9; // edx
    int result; // eax
    double v14; // st7
    int v15; // eax
    rdVector3 v18; // [esp+28h] [ebp-Ch] BYREF

    v5 = 0;
    v6 = 0;
    v7 = actor->thing;
    if ( flags )
    {
        if ( flags == 0x100 )
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
            actor->flags |= SITHAIFLAGS_SEARCHING;
            if ( instinct->param0 == 0.0 )
            {
                instinct->param0 = aiclass->argsAsFloat[8];
                instinct->nextUpdate = sithTime_curMs + (int64_t)((_frand() * 0.40000001 - 0.2 - -1.0) * aiclass->argsAsFloat[0]);
                result = 0;
            }
            else
            {
                v14 = instinct->param0 - 1.0;
                result = 0;
                instinct->nextUpdate = sithTime_curMs + aiclass->argsAsInt[9];
                instinct->param0 = v14;
            }
            return result;
        }
        v15 = actor->field_1F4;
        instinct->param0 = aiclass->argsAsFloat[8];
        if ( v15 == 2 )
        {
            sithAI_SetLookFrame(actor, &actor->field_1D4);
        }
        else if ( !v15 )
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
            actor->flags &= ~SITHAIFLAGS_SEARCHING;
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
    sithSector *result; // eax
    double v9; // st7
    sithAIClassEntry *v10; // eax
    int v11; // ecx
    double v13; // st7
    double v14; // st6
    double v15; // rt2
    double v19; // st6
    rdVector3 a2; // [esp+Ch] [ebp-18h] BYREF
    rdVector3 a3; // [esp+18h] [ebp-Ch] BYREF

    v5 = actor;
    v6 = actor->thing;
    v7 = actor->thing->sector;
    if ( !actor->thing->attach_flags )
        return 0;
    if ( (actor->flags & SITHAIFLAGS_MOVING_TO_DEST) == 0 )
        return 0;
    if ( actor->field_228.x * v6->physicsParams.vel.x
       + actor->field_228.y * v6->physicsParams.vel.y
       + actor->field_228.z * v6->physicsParams.vel.z > 0.02 )
        return 0;
    //*(_QWORD *)&a2.x = sithTime_curMs;
    v9 = (double)sithTime_curMs;
    if ( v9 < instinct->param0 )
        return 0;
    v10 = aiclass;
    v11 = flags;
    instinct->param0 = aiclass->argsAsFloat[0] + v9;
    if ( flags != 4 && v11 != 512 )
    {
        if ( v11 != 1024 )
            return 0;
        v13 = v5->field_1AC.z;
        v14 = v10->argsAsFloat[2] * v5->field_1AC.y;
        a2.x = v10->argsAsFloat[2] * v5->field_1AC.x + v6->position.x;
        v15 = v13 * v10->argsAsFloat[2];
        a2.y = v14 + v6->position.y;
        a2.z = v15 + v6->position.z;
        if ( sithAI_physidk(v5, &a2, 0) )
        {
            rdVector_MultAcc3(&v6->physicsParams.vel, &v5->field_1AC, 0.1);
            sithAI_Jump(v5, &v5->movePos, 1.0);
            return 1;
        }
        return 1;
    }
    rdVector_Copy3(&a3, &v6->position);
    rdVector_MultAcc3(&a3, &rdroid_zVector3, v10->argsAsFloat[1]);
    result = sithUnk3_GetSectorLookAt(v7, &v6->position, &a3, 0.0);
    if ( result )
    {
        v19 = v5->field_1AC.y * 0.1 + a3.y;
        a2.x = v5->field_1AC.x * 0.1 + a3.x;
        a2.y = v19;
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
    return (int)result;
}

// sithAICmd_Flee
// sithAICmd_Withdraw
// sithAICmd_Dodge
// sithAICmd_RandomTurn
// sithAICmd_Roam
// sithAICmd_SenseDanger
// sithAICmd_HitAndRun
// sithAICmd_Retreat
// sithAICmd_ReturnHome
// sithAICmd_Talk

