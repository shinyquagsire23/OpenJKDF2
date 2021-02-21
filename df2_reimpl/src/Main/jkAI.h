#ifndef _JKAI_H
#define _JKAI_H

#define jkAI_Startup_ADDR (0x0040F9D0)
#define jkAI_SaberFighting_ADDR (0x0040FA40)
#define jkAI_SpecialAttack_ADDR (0x0040FD00)
#define jkAI_ForcePowers_ADDR (0x0040FF40)
#define jkAI_SaberMove_ADDR (0x004100E0)

static void (*jkAI_Startup)() = (void*)jkAI_Startup_ADDR;

#endif // _JKAI_H
