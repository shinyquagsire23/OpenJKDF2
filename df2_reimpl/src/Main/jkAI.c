#include "jkAI.h"

#include "AI/sithAI.h"

#define jkAI_SaberFighting ((void*)jkAI_SaberFighting_ADDR)
#define jkAI_SpecialAttack ((void*)jkAI_SpecialAttack_ADDR)
#define jkAI_ForcePowers ((void*)jkAI_ForcePowers_ADDR)
#define jkAI_SaberMove ((void*)jkAI_SaberMove_ADDR)

void jkAI_Startup()
{
    sithAI_RegisterCommand("saberfighting", jkAI_SaberFighting, 2, 0, 0);
    sithAI_RegisterCommand("forcepowers", jkAI_ForcePowers, 2, 0, 0);
    sithAI_RegisterCommand("sabermove", jkAI_SaberMove, 2, 0, 0);
    sithAI_RegisterCommand("specialattack", jkAI_SpecialAttack, 2, 0, 4);
}
