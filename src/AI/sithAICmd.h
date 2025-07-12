#ifndef _SITHAICMD_H
#define _SITHAICMD_H

#include "types.h"

#define sithAICmd_Startup_ADDR (0x005091B0)
#define sithAICmd_Follow_ADDR (0x005093F0)
#define sithAICmd_CircleStrafe_ADDR (0x00509890)
#define sithAICmd_Crouch_ADDR (0x00509AD0)
#define sithAICmd_BlindFire_ADDR (0x00509B30)
#define sithAICmd_LobFire_ADDR (0x00509CD0)
#define sithAICmd_PrimaryFire_ADDR (0x00509E40)
#define sithAICmd_TurretFire_ADDR (0x0050A0F0)
#define sithAICmd_Listen_ADDR (0x0050A6F0)
#define sithAICmd_LookForTarget_ADDR (0x0050AA80)
#define sithAICmd_OpenDoors_ADDR (0x0050ABC0)
#define sithAICmd_Jump_ADDR (0x0050ABF0)
#define sithAICmd_Flee_ADDR (0x0050AEB0)
#define sithAICmd_Withdraw_ADDR (0x0050B150)
#define sithAICmd_Dodge_ADDR (0x0050B360)
#define sithAICmd_RandomTurn_ADDR (0x0050B700)
#define sithAICmd_Roam_ADDR (0x0050B830)
#define sithAICmd_SenseDanger_ADDR (0x0050B9B0)
#define sithAICmd_HitAndRun_ADDR (0x0050BB90)
#define sithAICmd_Retreat_ADDR (0x0050BC60)
#define sithAICmd_ReturnHome_ADDR (0x0050BD70)
#define sithAICmd_Talk_ADDR (0x0050BE20)

void sithAICmd_Startup();
MATH_FUNC int sithAICmd_Follow(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, intptr_t otherFlags);
MATH_FUNC int sithAICmd_CircleStrafe(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, intptr_t otherFlags);
MATH_FUNC int sithAICmd_Crouch(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, intptr_t otherFlags);
MATH_FUNC int sithAICmd_BlindFire(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, intptr_t otherFlags);
MATH_FUNC int sithAICmd_LobFire(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, intptr_t otherFlags);
MATH_FUNC int sithAICmd_PrimaryFire(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, intptr_t otherFlags);
MATH_FUNC int sithAICmd_TurretFire(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, intptr_t otherFlags);
MATH_FUNC int sithAICmd_Listen(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, sithThing *extra);
MATH_FUNC int sithAICmd_LookForTarget(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, void *extra);
MATH_FUNC int sithAICmd_OpenDoors(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, void *extra);
MATH_FUNC int sithAICmd_Jump(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, void *extra);
MATH_FUNC int sithAICmd_Flee(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, void *extra);
MATH_FUNC int sithAICmd_Withdraw(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, void *extra);
MATH_FUNC int sithAICmd_Dodge(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, sithThing *extra);
MATH_FUNC int sithAICmd_RandomTurn(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, sithThing *extra);
MATH_FUNC int sithAICmd_Roam(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, void *extra);
MATH_FUNC int sithAICmd_SenseDanger(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, sithThing *extra);
MATH_FUNC int sithAICmd_HitAndRun(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, void *extra);
MATH_FUNC int sithAICmd_Retreat(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, sithThing *extra);
MATH_FUNC int sithAICmd_ReturnHome(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, intptr_t extra);
MATH_FUNC int sithAICmd_Talk(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, void *extra);

MATH_FUNC int sithAICmd_LookForOpposingTarget(sithActor *pActor, sithAIClassEntry *pAiclass, sithActorInstinct *pInstinct, int flags, intptr_t otherFlags);
MATH_FUNC int sithAICmd_Leap(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, intptr_t otherFlags);
MATH_FUNC int sithAICmd_Charge(sithActor *pActor, sithAIClassEntry *pAiclass, sithActorInstinct *pInstinct, int flags, intptr_t otherFlags);

#endif // _SITHAICMD_H
