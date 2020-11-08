#ifndef _SITHPUPPET_H
#define _SITHPUPPET_H

#define sithPuppet_Startup_ADDR (0x004E3C00)
#define sithPuppet_Shutdown_ADDR (0x004E3CA0)
#define sithPuppet_NewEntry_ADDR (0x004E3D00)
#define sithPuppet_FreeEntry_ADDR (0x004E3D70)
#define sithPuppet_ResetTrack_ADDR (0x004E3DA0)
#define sithPuppet_tracksidk_ADDR (0x004E3DE0)
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

static int (__cdecl *sithPuppet_PlayMode)(sithThing *a1, signed int anim, int callback) = (void*)sithPuppet_PlayMode_ADDR;

#endif // _SITHPUPPET_H
