#include "sithUnk4.h"

#include "World/sithThing.h"
#include "Engine/sithAnimClass.h"
#include "World/sithUnk3.h"
#include "World/jkPlayer.h"
#include "AI/sithAI.h"

void sithUnk4_SetMaxHeathForDifficulty(sithThing *thing)
{
    double v1; // st7
    double v2; // st7

    if ( jkPlayer_setDiff )
    {
        if ( jkPlayer_setDiff == 2 )
        {
            v1 = thing->actorParams.health * 1.2;
            thing->actorParams.maxHealth = thing->actorParams.maxHealth * 1.2;
            thing->actorParams.health = v1;
        }
    }
    else
    {
        v2 = thing->actorParams.health * 0.80000001;
        thing->actorParams.maxHealth = thing->actorParams.maxHealth * 0.80000001;
        thing->actorParams.health = v2;
    }
}

int sithUnk4_sub_4ED1D0(sithThing *thing, sithSurface *surface, sithUnk3SearchEntry *searchEnt)
{
    int v3; // edi

    v3 = sithUnk3_DefaultHitHandler(thing, surface, searchEnt);
    if ( v3 && thing->thingtype == THINGTYPE_ACTOR )
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

int sithUnk4_ActorActorCollide(sithThing *thing, sithThing *thing2, sithUnk3SearchEntry *a3, int a4)
{
    int result; // eax
    int v5; // ebx
    sithActor *v6; // eax
    sithActor *v7; // eax

    result = sithUnk3_DebrisDebrisCollide(thing, thing2, a3, a4);
    v5 = result;
    if ( result )
    {
        if ( thing->thingtype == THINGTYPE_ACTOR )
        {
            v6 = thing->actor;
            if ( v6 )
                sithAI_SetActorFireTarget(v6, 4, thing2);
        }
        if ( thing2->thingtype == THINGTYPE_ACTOR )
        {
            v7 = thing2->actor;
            if ( v7 )
                sithAI_SetActorFireTarget(v7, 4, thing);
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
