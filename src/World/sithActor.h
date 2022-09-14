#ifndef _WORLD_SITHACTOR_H
#define _WORLD_SITHACTOR_H

#include "types.h"

#define sithActor_SetMaxHeathForDifficulty_ADDR (0x004ECB70)
#define sithActor_Tick_ADDR (0x004ECBE0)
#define sithActor_Hit_ADDR (0x004ECC90)
#define sithActor_HurtSound_ADDR (0x004ECE90)
#define sithActor_SpawnDeadBodyMaybe_ADDR (0x004ECFE0)
#define sithActor_sub_4ED1D0_ADDR (0x004ED1D0)
#define sithActor_ActorActorCollide_ADDR (0x004ED210)
#define sithActor_MoveJointsForEyePYR_ADDR (0x004ED280)
#define sithActor_turretfireidk_ADDR (0x004ED3A0)
#define sithActor_thing_anim_blocked_ADDR (0x004ED3F0)
#define sithActor_Remove_ADDR (0x004ED760)
#define sithActor_RemoveCorpse_ADDR (0x004ED7B0)
#define sithActor_LoadParams_ADDR (0x004ED7E0)

void sithActor_SetMaxHeathForDifficulty(sithThing *thing);
void sithActor_Tick(sithThing *thing, int deltaMs);
float sithActor_Hit(sithThing *sender, sithThing *receiver, float amount, int flags);
void sithActor_HurtSound(sithThing *thing, float amount, int hurtType);
void sithActor_SpawnDeadBodyMaybe(sithThing *thing, sithThing *a3, int a4);
int sithActor_sub_4ED1D0(sithThing *thing, sithSurface *surface, sithCollisionSearchEntry *searchEnt);
void sithActor_MoveJointsForEyePYR(sithThing *actor, const rdVector3 *eyePYR);
int sithActor_ActorActorCollide(sithThing *thing, sithThing *thing2, sithCollisionSearchEntry *a3, int a4);
void sithActor_RotateTurretToEyePYR(sithThing *a1);
int sithActor_thing_anim_blocked(sithThing *a1, sithThing *thing2, sithCollisionSearchEntry *a3);
void sithActor_Remove(sithThing *thing);
void sithActor_RemoveCorpse(sithThing *corpse);
int sithActor_LoadParams(stdConffileArg *arg, sithThing *thing, unsigned int param);

//static int (__cdecl *sithActor_ActorActorCollide)(sithThing *thing, sithThing *a2, rdMatrix34 *a3, int a4) = (void*)sithActor_ActorActorCollide_ADDR;
//static int (*sithActor_thing_anim_blocked)(sithThing *a1, sithThing *a2, rdMatrix34 *a3) = (void*)sithActor_thing_anim_blocked_ADDR;
//static void (*sithActor_MoveJointsForEyePYR)(sithThing *actor, rdVector3 *eyePYR) = (void*)sithActor_MoveJointsForEyePYR_ADDR;
//static void (*sithActor_SetMaxHeathForDifficulty)(sithThing*) = (void*)sithActor_SetMaxHeathForDifficulty_ADDR;

#endif // _WORLD_SITHACTOR_H
