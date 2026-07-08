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
rdParticle* sithParticle_Load(const char *pName);
int sithParticle_AllocWorldParticles(SithWorld *pWorld, int size);
int sithParticle_ParseArg(StdConffileArg *pArg, SithThing *pThing, int adjNum);
MATH_FUNC void sithParticle_Update(SithThing *pThing, flex_t secDeltaTime);
MATH_FUNC void sithParticle_Initalize(SithThing *pThing);
MATH_FUNC void sithParticle_DestroyParticle(SithThing *pThing);
void sithParticle_Free(SithThing *pThing);
void sithParticle_FreeWorldParticles(SithWorld *pWorld);

#endif // _SITHPARTICLE_H
