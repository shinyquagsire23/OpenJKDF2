#ifndef _JKAI_H
#define _JKAI_H

#include "types.h"

#define jkAI_Startup_ADDR (0x0040F9D0)
#define jkAI_SaberFighting_ADDR (0x0040FA40)
#define jkAI_SpecialAttack_ADDR (0x0040FD00)
#define jkAI_ForcePowers_ADDR (0x0040FF40)
#define jkAI_SaberMove_ADDR (0x004100E0)

void jkAI_Startup();

MATH_FUNC int jkAI_SaberFighting(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, int extra);
int jkAI_SpecialAttack(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, sithThing *extra);
int jkAI_ForcePowers(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, int extra);
int jkAI_SaberMove();

#endif // _JKAI_H
