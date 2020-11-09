#ifndef _SITHUNK4_H
#define _SITHUNK4_H

#define sithUnk4_Initialize_ADDR (0x004EC330)
#define sithUnk4_Shutdown_ADDR (0x004EC360)
#define sithUnk4_DrawCircleIdk_ADDR (0x004EC380)
#define sithUnk4_sub_4EC4D0_ADDR (0x004EC4D0)
#define sithUnk4_sub_4EC550_ADDR (0x004EC550)
#define sithUnk4_sub_4EC9C0_ADDR (0x004EC9C0)
#define sithUnk4_SetMaxHeathForDifficulty_ADDR (0x004ECB70)
#define sithUnk4_sub_4ED1D0_ADDR (0x004ED1D0)
#define sithUnk4_ActorActorCollide_ADDR (0x004ED210)
#define sithUnk4_MoveJointsForEyePYR_ADDR (0x004ED280)
#define sithUnk4_turretfireidk_ADDR (0x004ED3A0)
#define sithUnk4_thing_anim_blocked_ADDR (0x004ED3F0)

static int (__cdecl *sithUnk4_ActorActorCollide)(sithThing *thing, sithThing *a2, rdMatrix34 *a3, int a4) = (void*)sithUnk4_ActorActorCollide_ADDR;

#endif // _SITHUNK4_H
