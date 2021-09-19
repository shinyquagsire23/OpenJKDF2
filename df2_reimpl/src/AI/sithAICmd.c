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
#include "jk.h"

#define sithAICmd_Follow ((void*)sithAICmd_Follow_ADDR)

#define sithAICmd_PrimaryFire ((void*)sithAICmd_PrimaryFire_ADDR)
#define sithAICmd_TurretFire ((void*)sithAICmd_TurretFire_ADDR)
#define sithAICmd_Listen ((void*)sithAICmd_Listen_ADDR)
#define sithAICmd_LookForTarget ((void*)sithAICmd_LookForTarget_ADDR)
#define sithAICmd_OpenDoors ((void*)sithAICmd_OpenDoors_ADDR)
#define sithAICmd_Jump ((void*)sithAICmd_Jump_ADDR)
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
                a4.x = 0.0;
                a4.y = 0.0;
                a4.z = 0.0;
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
    sithThing *v5; // ecx
    int v6; // eax
    signed int result; // eax

    v5 = actor->thing;
    v6 = actor->flags;
    instinct->nextUpdate = sithTime_curMs + aiclass->argsAsInt[0];
    if ( (v6 & 1) == 0 && (v6 & 2) != 0 && (v6 & 0x400) != 0 )
    {
        v5->physicsParams.physflags |= PHYSFLAGS_CROUCHING;
        result = 0;
    }
    else
    {
        v5->physicsParams.physflags &= ~PHYSFLAGS_CROUCHING;
        result = 0;
    }
    return result;
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
            actor->flags &= ~2;
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
        if ( flags == 256 )
        {
            if ( (actor->flags & 0x200) != 0 )
                sithPuppet_SetArmedMode(v6, 1);
            else
                sithPuppet_SetArmedMode(v6, 0);
            instinct->nextUpdate = sithTime_curMs + 1000;
            return 0;
        }
        return 0;
    }
    if ( (v7->thingflags & 0x202) == 0 )
    {
        if ( aiclass->argsAsFloat[5] > _frand() )
            v5 = 1;
        if ( sithAI_FireWeapon(actor, aiclass->argsAsFloat[2], aiclass->argsAsFloat[3], aiclass->argsAsFloat[1], aiclass->argsAsFloat[4], v5, 2) )
        {
            actor->flags |= 4;
            v11 = sithTime_curMs + aiclass->argsAsInt[0];
            instinct->nextUpdate = v11;
            actor->field_288 = v11;
            return 0;
        }
        sithAI_SetLookFrame(actor, &v7->position);
        actor->flags |= 4;
        instinct->nextUpdate = sithTime_curMs + 500;
        return 0;
    }
    if ( (actor->flags & 0x400) != 0 )
    {
        sithSoundClass_ThingPlaySoundclass(v6, SITH_SC_VICTORY);
        sithPuppet_PlayMode(actor->thing, SITH_ANIM_VICTORY, 0);
    }
    result = 1;
    actor->flags = actor->flags & ~0x622u | 4;
    return result;
}

// sithAICmd_PrimaryFire
// sithAICmd_TurretFire
// sithAICmd_Listen
// sithAICmd_LookForTarget
// sithAICmd_OpenDoors
// sithAICmd_Jump
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

