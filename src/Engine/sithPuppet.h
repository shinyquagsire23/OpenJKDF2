#ifndef _SITHPUPPET_H
#define _SITHPUPPET_H

#include "types.h"
#include "globals.h"

#define sithPuppet_Startup_ADDR (0x004E3C00)
#define sithPuppet_Shutdown_ADDR (0x004E3CA0)
#define sithPuppet_NewEntry_ADDR (0x004E3D00)
#define sithPuppet_FreeEntry_ADDR (0x004E3D70)
#define sithPuppet_ResetTrack_ADDR (0x004E3DA0)
#define sithPuppet_Tick_ADDR (0x004E3DE0)
#define sithPuppet_FidgetAnim_ADDR (0x004E4150)
#define sithPuppet_resetidk_ADDR (0x004E42C0)
#define sithPuppet_advanceidk_ADDR (0x004E4310)
#define sithPuppet_sub_4E4380_ADDR (0x004E4380)
#define sithPuppet_sub_4E4760_ADDR (0x004E4760)
#define sithPuppet_SetArmedMode_ADDR (0x004E47A0)
#define sithPuppet_PlayMode_ADDR (0x004E47D0)
#define sithPuppet_StartKey_ADDR (0x004E48B0)
#define sithPuppet_StopKey_ADDR (0x004E49C0)
#define sithPuppet_sub_4E4A20_ADDR (0x004E4A20)
#define sithPuppet_DefaultCallback_ADDR (0x004E4B10)

int sithPuppet_Startup();
void sithPuppet_Shutdown();
sithPuppet* sithPuppet_NewEntry(sithThing *thing);
void sithPuppet_FreeEntry(sithThing *puppet);
void sithPuppet_sub_4E4760(sithThing *thing, int a2);
int sithPuppet_PlayMode(sithThing *thing, signed int anim, rdPuppetTrackCallback_t callback);
int sithPuppet_StartKey(rdPuppet *puppet, rdKeyframe *keyframe, int a3, int a4, int a5, rdPuppetTrackCallback_t callback);
void sithPuppet_ResetTrack(sithThing *puppet);
void sithPuppet_Tick(sithThing *thing, flex_t deltaSeconds);
flex_t sithPuppet_sub_4E4380(sithThing *thing);
void sithPuppet_sub_4E4A20(sithThing *thing, sithAnimclassEntry *animClass);
void sithPuppet_DefaultCallback(sithThing *thing, int track, uint32_t a3);
int sithPuppet_StopKey(rdPuppet *pupper, int track, flex_t a3);
void sithPuppet_SetArmedMode(sithThing *thing, int mode);
void sithPuppet_FidgetAnim(sithThing *pThing);
void sithPuppet_resetidk(sithThing *pThing);
void sithPuppet_advanceidk(sithThing *pThing, flex_t a2);

//static int (*sithPuppet_Startup)() = (void*)sithPuppet_Startup_ADDR;
//static void (*sithPuppet_FreeEntry)(sithThing *puppet) = (void*)sithPuppet_FreeEntry_ADDR;
//static void (*sithPuppet_Tick)(sithThing *thing, flex_t a2) = (void*)sithPuppet_Tick_ADDR;
//static int (__cdecl *sithPuppet_PlayMode)(sithThing *a1, signed int anim, int callback) = (void*)sithPuppet_PlayMode_ADDR;
//static int (*sithPuppet_StartKey)(rdPuppet *puppet, rdKeyframe *keyframe, int a3, int a4, int a5, int callback) = (void*)sithPuppet_StartKey_ADDR;
//static int (*sithPuppet_StopKey)(rdPuppet *a1, int track, flex_t a3) = (void*)sithPuppet_StopKey_ADDR;
//static void (*sithPuppet_SetArmedMode)(sithThing *a1, int a2) = (void*)sithPuppet_SetArmedMode_ADDR;
//static void (*sithPuppet_DefaultCallback)(sithThing *thing, int a2, int a3) = (void*)sithPuppet_DefaultCallback_ADDR;
//static flex_t (*sithPuppet_sub_4E4380)(sithThing *thing) = (void*)sithPuppet_sub_4E4380_ADDR;

#endif // _SITHPUPPET_H
