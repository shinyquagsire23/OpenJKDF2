#ifndef _SITHPUPPET_H
#define _SITHPUPPET_H

#include "types.h"

#define sithPuppet_Startup_ADDR (0x004E3C00)
#define sithPuppet_Shutdown_ADDR (0x004E3CA0)
#define sithPuppet_NewEntry_ADDR (0x004E3D00)
#define sithPuppet_FreeEntry_ADDR (0x004E3D70)
#define sithPuppet_ResetTrack_ADDR (0x004E3DA0)
#define sithPuppet_Tick_ADDR (0x004E3DE0)
#define sithPuppet_startidk_ADDR (0x004E4150)
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

struct sithPuppet
{
  int field_0;
  int field_4;
  int majorMode;
  int field_C;
  int field_10;
  int field_14;
  int field_18;
  int field_1C;
  int field_20;
};

#define sithPuppet_hashtable (*(stdHashTable**)0x00847E88)
#define sithPuppet_keyframesHashtable (*(stdHashTable**)0x00847E8C)
#define sithPuppet_animNamesToIdxHashtable (*(stdHashTable**)0x00847E90)

int sithPuppet_Startup();
static void (*sithPuppet_Shutdown)() = (void*)sithPuppet_Shutdown_ADDR;
sithPuppet* sithPuppet_NewEntry(sithThing *thing);
void sithPuppet_FreeEntry(sithThing *puppet);
void sithPuppet_sub_4E4760(sithThing *thing, int a2);
int sithPuppet_PlayMode(sithThing *thing, signed int anim, int callback);

//static int (*sithPuppet_Startup)() = (void*)sithPuppet_Startup_ADDR;
//static void (*sithPuppet_FreeEntry)(sithThing *puppet) = (void*)sithPuppet_FreeEntry_ADDR;
static void (*sithPuppet_Tick)(sithThing *thing, float a2) = (void*)sithPuppet_Tick_ADDR;
//static int (__cdecl *sithPuppet_PlayMode)(sithThing *a1, signed int anim, int callback) = (void*)sithPuppet_PlayMode_ADDR;
static int (*sithPuppet_StartKey)(rdPuppet *puppet, rdKeyframe *keyframe, int a3, int a4, int a5, int callback) = (void*)sithPuppet_StartKey_ADDR;
static int (*sithPuppet_StopKey)(rdPuppet *a1, int track, float a3) = (void*)sithPuppet_StopKey_ADDR;
static void (*sithPuppet_SetArmedMode)(sithThing *a1, int a2) = (void*)sithPuppet_SetArmedMode_ADDR;

#endif // _SITHPUPPET_H
