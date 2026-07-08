#ifndef _SITHPARTICLE_H
#define _SITHPARTICLE_H

#include "types.h"

#define sithParticle_Startup_ADDR (0x004F18B0)
#define sithParticle_Shutdown_ADDR (0x004F18F0)
#define sithParticle_Load_ADDR (0x004F1910)
#define sithParticle_AllocWorldParticles_ADDR (0x004F1A00)
#define sithParticle_ParseArg_ADDR (0x004F1A60)
#define sithParticle_Update_ADDR (0x004F1C30)
#define sithParticle_Initalize_ADDR (0x004F1DA0)
#define sithParticle_DestroyParticle_ADDR (0x004F2010)
#define sithParticle_Free_ADDR (0x004F2080)
#define sithParticle_FreeWorldParticles_ADDR (0x004F20B0)

int sithParticle_Startup();
void sithParticle_Shutdown();
rdParticle* sithParticle_Load(const char *a1);
int sithParticle_AllocWorldParticles(SithWorld *world, int numParticles);
int sithParticle_ParseArg(StdConffileArg *arg, SithThing *thing, int param);
MATH_FUNC void sithParticle_Update(SithThing *particle, flex_t deltaMs);
MATH_FUNC void sithParticle_Initalize(SithThing *thing);
MATH_FUNC void sithParticle_DestroyParticle(SithThing *particle);
void sithParticle_Free(SithThing *thing);
void sithParticle_FreeWorldParticles(SithWorld *world);

#endif // _SITHPARTICLE_H
