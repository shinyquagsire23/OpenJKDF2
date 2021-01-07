#ifndef _SITHPARTICLE_H
#define _SITHPARTICLE_H

#define sithParticle_Startup_ADDR (0x004F18B0)
#define sithParticle_Shutdown_ADDR (0x004F18F0)
#define sithParticle_LoadEntry_ADDR (0x004F1910)
#define sithParticle_New_ADDR (0x004F1A00)
#define sithParticle_LoadThingParams_ADDR (0x004F1A60)
#define sithParticle_Tick_ADDR (0x004F1C30)
#define sithParticle_CreateThing_ADDR (0x004F1DA0)
#define sithParticle_Remove_ADDR (0x004F2010)
#define sithParticle_Free_ADDR (0x004F2080)
#define sithParticle_FreeEntry_ADDR (0x004F20B0)

static void (*sithParticle_Free)(sithThing *thing) = (void*)sithParticle_Free_ADDR;
static void (*sithParticle_Remove)(sithThing *particle) = (void*)sithParticle_Remove_ADDR;
static void (*sithParticle_Tick)(sithThing *particle, float deltaMs) = (void*)sithParticle_Tick_ADDR;

#endif // _SITHPARTICLE_H
