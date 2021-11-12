#ifndef _SITHUNK4_H
#define _SITHUNK4_H

#include "types.h"

#define sithUnk4_SetMaxHeathForDifficulty_ADDR (0x004ECB70)
#define sithUnk4_sub_4ED1D0_ADDR (0x004ED1D0)
#define sithUnk4_ActorActorCollide_ADDR (0x004ED210)
#define sithUnk4_MoveJointsForEyePYR_ADDR (0x004ED280)
#define sithUnk4_turretfireidk_ADDR (0x004ED3A0)
#define sithUnk4_thing_anim_blocked_ADDR (0x004ED3F0)

void sithUnk4_SetMaxHeathForDifficulty(sithThing *thing);
int sithUnk4_sub_4ED1D0(sithThing *thing, sithSurface *surface, sithCollisionSearchEntry *searchEnt);
void sithUnk4_MoveJointsForEyePYR(sithThing *actor, const rdVector3 *eyePYR);
int sithUnk4_ActorActorCollide(sithThing *thing, sithThing *thing2, sithCollisionSearchEntry *a3, int a4);
void sithUnk4_RotateTurretToEyePYR(sithThing *a1);
int sithUnk4_thing_anim_blocked(sithThing *a1, sithThing *thing2, sithCollisionSearchEntry *a3);

//static int (__cdecl *sithUnk4_ActorActorCollide)(sithThing *thing, sithThing *a2, rdMatrix34 *a3, int a4) = (void*)sithUnk4_ActorActorCollide_ADDR;
//static int (*sithUnk4_thing_anim_blocked)(sithThing *a1, sithThing *a2, rdMatrix34 *a3) = (void*)sithUnk4_thing_anim_blocked_ADDR;
//static void (*sithUnk4_MoveJointsForEyePYR)(sithThing *actor, rdVector3 *eyePYR) = (void*)sithUnk4_MoveJointsForEyePYR_ADDR;
//static void (*sithUnk4_SetMaxHeathForDifficulty)(sithThing*) = (void*)sithUnk4_SetMaxHeathForDifficulty_ADDR;

#endif // _SITHUNK4_H
