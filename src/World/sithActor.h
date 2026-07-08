#ifndef _WORLD_SITHACTOR_H
#define _WORLD_SITHACTOR_H

#include "types.h"

#define sithActor_SetDifficulty_ADDR (0x004ECB70)
#define sithActor_Update_ADDR (0x004ECBE0)
#define sithActor_DamageActor_ADDR (0x004ECC90)
#define sithActor_PlayDamageSoundFx_ADDR (0x004ECE90)
#define sithActor_KillActor_ADDR (0x004ECFE0)
#define sithActor_SurfaceCollisionHandler_ADDR (0x004ED1D0)
#define sithActor_ActorCollisionHandler_ADDR (0x004ED210)
#define sithActor_SetHeadPYR_ADDR (0x004ED280)
#define sithActor_turretfireidk_ADDR (0x004ED3A0)
#define sithActor_thing_anim_blocked_ADDR (0x004ED3F0)
#define sithActor_DestroyActor_ADDR (0x004ED760)
#define sithActor_DestroyCorpse_ADDR (0x004ED7B0)
#define sithActor_ParseArg_ADDR (0x004ED7E0)

MATH_FUNC void sithActor_SetDifficulty(sithThing *thing);
void sithActor_Update(sithThing *thing, int deltaMs);
MATH_FUNC flex_t sithActor_DamageActor(sithThing *sender, sithThing *receiver, flex_t amount, int flags);
void sithActor_PlayDamageSoundFx(sithThing *thing, flex_t amount, int hurtType);
void sithActor_KillActor(sithThing *thing, sithThing *a3, int a4);
int sithActor_SurfaceCollisionHandler(sithThing *thing, sithSurface *surface, sithCollisionSearchEntry *searchEnt);
MATH_FUNC void sithActor_SetHeadPYR(sithThing *actor, const rdVector3 *eyePYR);
int sithActor_ActorCollisionHandler(sithThing *thing, sithThing *thing2, sithCollisionSearchEntry *a3, int a4);
void sithActor_UpdateAimJoints(sithThing *a1);
MATH_FUNC int sithActor_thing_anim_blocked(sithThing *a1, sithThing *thing2, sithCollisionSearchEntry *a3);
void sithActor_DestroyActor(sithThing *thing);
void sithActor_DestroyCorpse(sithThing *corpse);
int sithActor_ParseArg(stdConffileArg *arg, sithThing *thing, unsigned int param);

//static int (__cdecl *sithActor_ActorCollisionHandler)(sithThing *thing, sithThing *a2, rdMatrix34 *a3, int a4) = (void*)sithActor_ActorCollisionHandler_ADDR;
//static int (*sithActor_thing_anim_blocked)(sithThing *a1, sithThing *a2, rdMatrix34 *a3) = (void*)sithActor_thing_anim_blocked_ADDR;
//static void (*sithActor_SetHeadPYR)(sithThing *actor, rdVector3 *eyePYR) = (void*)sithActor_SetHeadPYR_ADDR;
//static void (*sithActor_SetDifficulty)(sithThing*) = (void*)sithActor_SetDifficulty_ADDR;

#endif // _WORLD_SITHACTOR_H
