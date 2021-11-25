#include "sithUnk4.h"

#include "Cog/sithCog.h"
#include "World/sithThing.h"
#include "Engine/sithAnimClass.h"
#include "Engine/sithSoundClass.h"
#include "Engine/sithPuppet.h"
#include "Engine/sithCollision.h"
#include "World/jkPlayer.h"
#include "World/sithThing.h"
#include "AI/sithAI.h"
#include "jk.h"

void sithUnk4_SetMaxHeathForDifficulty(sithThing *thing)
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
        thing->actorParams.maxHealth = thing->actorParams.maxHealth * 0.80000001;
        thing->actorParams.health = thing->actorParams.health * 0.80000001;
    }
}

int sithUnk4_sub_4ED1D0(sithThing *thing, sithSurface *surface, sithCollisionSearchEntry *searchEnt)
{
    int v3; // edi

    v3 = sithCollision_DefaultHitHandler(thing, surface, searchEnt);
    if ( v3 && thing->thingtype == SITH_THING_ACTOR )
        sithAI_SetActorFireTarget(thing->actor, 512, 0);
    return v3;
}

void sithUnk4_MoveJointsForEyePYR(sithThing *actor, const rdVector3 *eyePYR)
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

    actor->actorParams.typeflags &= ~0x10;
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
                    v4[primaryWeapJointIdx].x = eyePYR->x * 0.30000001;
                if ( v9 < 0 )
                    v14 = 0;
                else
                    v14 = v9 <= v10;
                if ( v14 )
                    v4[v9].x = eyePYR->x * 0.30000001;
            }
        }
    }
}

int sithUnk4_ActorActorCollide(sithThing *thing, sithThing *thing2, sithCollisionSearchEntry *a3, int a4)
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
                sithAI_SetActorFireTarget(v6, 4, (intptr_t)thing2);
        }
        if ( thing2->thingtype == SITH_THING_ACTOR )
        {
            v7 = thing2->actor;
            if ( v7 )
                sithAI_SetActorFireTarget(v7, 4, (intptr_t)thing);
        }
        result = v5;
    }
    return result;
}

void sithUnk4_RotateTurretToEyePYR(sithThing *a1)
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

int sithUnk4_thing_anim_blocked(sithThing *a1, sithThing *thing2, sithCollisionSearchEntry *a3)
{
    int result; // eax
    float v4; // ecx
    double v5; // st7
    float v6; // edx
    float v7; // eax
    double v8; // st7
    double v12; // st6
    double v13; // st4
    double v14; // st7
    double v15; // st7
    int v16; // ecx
    rdVector3 a1a; // [esp+10h] [ebp-54h] BYREF
    rdVector3 v18; // [esp+1Ch] [ebp-48h] BYREF
    rdVector3 vAngs; // [esp+28h] [ebp-3Ch] BYREF
    rdMatrix34 out; // [esp+34h] [ebp-30h] BYREF

    if ( _frand() > thing2->actorParams.chance )
        return 0;
    v4 = a1->physicsParams.vel.x;
    a1a.x = a1->position.x - thing2->position.x;
    v5 = a1->position.y - thing2->position.y;
    v6 = a1->physicsParams.vel.y;
    vAngs.x = v4;
    vAngs.y = v6;
    v7 = a1->physicsParams.vel.z;
    a1a.y = v5;
    v8 = a1->position.z - thing2->position.z;
    vAngs.z = v7;
    a1a.z = v8;
    rdVector_Normalize3Acc(&a1a);
    _memcpy(&out, &thing2->lookOrientation, sizeof(out));
    if ( thing2->type == SITH_THING_ACTOR || thing2->type == SITH_THING_PLAYER )
        rdMatrix_PreRotate34(&out, &thing2->actorParams.eyePYR);
    v18 = out.lvec;
    rdVector_Normalize3Acc(&v18);
    if ( v18.x * a1a.x + v18.y * a1a.y + v18.z * a1a.z < thing2->actorParams.fov )
        return 0;
    result = sithCollision_DebrisDebrisCollide(a1, thing2, a3, 0);
    if ( result )
    {
        a1->physicsParams.vel.x = -vAngs.x;
        a1->physicsParams.vel.y = -vAngs.y;
        a1->physicsParams.vel.z = -vAngs.z;
        if ( _frand() < thing2->actorParams.error )
        {
            vAngs.x = 0.0;
            vAngs.y = 0.0;
            vAngs.z = 0.0;
            vAngs.x = (_frand() - 0.5) * 90.0;
            vAngs.y = (_frand() - 0.5) * 90.0;
            rdVector_Rotate3Acc(&a1->physicsParams.vel, &vAngs);
        }
        rdVector_Normalize3(&a1->lookOrientation.lvec, &a1->physicsParams.vel);
        v12 = a1->lookOrientation.lvec.x;
        v13 = a1->lookOrientation.lvec.y;
        v14 = a1->lookOrientation.lvec.z * 0.0;
        a1->lookOrientation.rvec.x = v13 * 1.0 - v14;
        a1->lookOrientation.rvec.y = v14 - v12 * 1.0;
        a1->lookOrientation.rvec.z = v12 * 0.0 - v13 * 0.0;
        rdVector_Normalize3Acc(&a1->lookOrientation.rvec);
        v15 = a1->lookOrientation.rvec.z * a1->lookOrientation.lvec.x;
        a1->lookOrientation.uvec.x = a1->lookOrientation.rvec.y * a1->lookOrientation.lvec.z - a1->lookOrientation.rvec.z * a1->lookOrientation.lvec.y;
        a1->lookOrientation.uvec.y = v15 - a1->lookOrientation.lvec.z * a1->lookOrientation.rvec.x;
        a1->lookOrientation.uvec.z = a1->lookOrientation.lvec.y * a1->lookOrientation.rvec.x - a1->lookOrientation.rvec.y * a1->lookOrientation.lvec.x;
        sithSoundClass_ThingPlaySoundclass(a1, SITH_SC_DEFLECTED);
        if ( thing2->lookOrientation.uvec.x * a1a.x + thing2->lookOrientation.uvec.y * a1a.y + thing2->lookOrientation.uvec.z * a1a.z <= 0.0 )
            sithPuppet_PlayMode(thing2, SITH_ANIM_BLOCK2, 0);
        else
            sithPuppet_PlayMode(thing2, SITH_ANIM_BLOCK, 0);
        v16 = thing2->signature;
        a1->actorParams.typeflags &= ~1u;
        a1->prev_thing = thing2;
        a1->child_signature = v16;
        sithCog_SendMessageFromThing(thing2, 0, SITH_MESSAGE_BLOCKED);
        result = 1;
    }
    return result;
}
