#ifndef _SITHWEAPON_H
#define _SITHWEAPON_H

#include "types.h"
#include "globals.h"

#define sithWeapon_InitDefaults_ADDR (0x004D3430)
#define sithWeapon_Startup_ADDR (0x004D34B0)
#define sithWeapon_Tick_ADDR (0x004D3530)
#define sithWeapon_sub_4D35E0_ADDR (0x004D35E0)
#define sithWeapon_sub_4D3920_ADDR (0x004D3920)
#define sithWeapon_LoadParams_ADDR (0x004D4290)
#define sithWeapon_Fire_ADDR (0x004D44F0)
#define sithWeapon_FireProjectile_0_ADDR (0x004D45A0)
#define sithWeapon_SetTimeLeft_ADDR (0x004D4880)
#define sithWeapon_Collide_ADDR (0x004D48C0)
#define sithWeapon_HitDebug_ADDR (0x004D4E40)
#define sithWeapon_Remove_ADDR (0x004D5160)
#define sithWeapon_RemoveAndExplode_ADDR (0x004D51F0)
#define sithWeapon_InitializeEntry_ADDR (0x004D5270)
#define sithWeapon_ShutdownEntry_ADDR (0x004D52C0)
#define sithWeapon_SelectWeapon_ADDR (0x004D52D0)
#define sithWeapon_SetMountWait_ADDR (0x004D5460)
#define sithWeapon_SetFireWait_ADDR (0x004D5480)
#define sithWeapon_handle_inv_msgs_ADDR (0x004D54C0)
#define sithWeapon_Activate_ADDR (0x004D5650)
#define sithWeapon_Deactivate_ADDR (0x004D5700)
#define sithWeapon_AutoSelect_ADDR (0x004D57A0)
#define sithWeapon_HandleWeaponKeys_ADDR (0x004D5830)
#define sithWeapon_ProjectileAutoAim_ADDR (0x004D5C60)
#define sithWeapon_FireProjectile_ADDR (0x004D5F20)
#define sithWeapon_GetPriority_ADDR (0x004D62B0)
#define sithWeapon_GetCurWeaponMode_ADDR (0x004D6310)
#define sithWeapon_SyncPuppet_ADDR (0x004D6320)
#define sithWeapon_WriteConf_ADDR (0x004D6370)
#define sithWeapon_ReadConf_ADDR (0x004D6430)
#define sithWeapon_Syncunused1_ADDR (0x004D6670)
#define sithWeapon_Syncunused2_ADDR (0x004D6750)
#define sithWeapon_SetFireRate_ADDR (0x004D6830)

enum SITH_WF_E
{
  SITH_WF_NO_DAMAGE_TO_SHOOTER = 0x1,
  SITH_WF_2 = 0x2,
  SITH_WF_EXPLODE_ON_SURFACE_HIT = 0x4,
  SITH_WF_EXPLODE_ON_THING_HIT = 0x8,
  SITH_WF_10 = 0x10,
  SITH_WF_20 = 0x20,
  SITH_WF_40 = 0x40,
  SITH_WF_ATTACH_TO_WALL = 0x80,
  SITH_WF_EXPLODE_AT_TIMER_TIMEOUT = 0x100,
  SITH_WF_EXPLODE_WHEN_DAMAGED = 0x200,
  SITH_WF_IMPACT_SOUND_FX = 0x400,
  SITH_WF_ATTACH_TO_THING = 0x800,
  SITH_WF_PROXIMITY = 0x1000, // "Weapon will explode when something touches its sphere."
  SITH_WF_INSTANT_IMPACT = 0x2000,
  SITH_WF_DAMAGE_DECAY = 0x4000,
  SITH_WF_OBJECT_TRAIL = 0x8000,
  SITH_WF_10000 = 0x10000,
  SITH_WF_20000 = 0x20000,
  SITH_WF_TRIGGER_AI_AWARENESS = 0x40000,
  SITH_WF_RICOCHET_OFF_SURFACE = 0x80000,
  SITH_WF_100000 = 0x100000,
  SITH_WF_TRIGGER_AIEVENT = 0x200000,
  SITH_WF_EXPLODES_ON_WORLD_FLOOR_HIT = 0x400000,
  SITH_WF_MOPHIA_BOMB = 0x800000, // Jones specific
};

void sithWeapon_InitDefaults();
void sithWeapon_Startup();
void sithWeapon_Tick(sithThing *weapon, float deltaSeconds);
void sithWeapon_sub_4D35E0(sithThing *weapon);
void sithWeapon_sub_4D3920(sithThing *weapon);
int sithWeapon_LoadParams(stdConffileArg *arg, sithThing *thing, int param);
sithThing* sithWeapon_Fire(sithThing *weapon, sithThing *projectile, rdVector3 *fireOffset, rdVector3 *aimError, sithSound *fireSound, int anim, float scale, int16_t scaleFlags, float a9);
sithThing* sithWeapon_FireProjectile_0(sithThing *sender, sithThing *projectileTemplate, rdVector3 *fireOffset, rdVector3 *aimError, sithSound *fireSound, int anim, float scale, char scaleFlags, float a9);
void sithWeapon_SetTimeLeft(sithThing *weapon, sithThing* a2, float timeLeft);
int sithWeapon_Collide(sithThing *physicsThing, sithThing *collidedThing, sithCollisionSearchEntry *a4, int a5);
int sithWeapon_HitDebug(sithThing *thing, sithSurface *surface, sithCollisionSearchEntry *a3);
void sithWeapon_Remove(sithThing *weapon);
void sithWeapon_RemoveAndExplode(sithThing *weapon, sithThing *explodeTemplate);
void sithWeapon_InitializeEntry();
void sithWeapon_ShutdownEntry();
int sithWeapon_SelectWeapon(sithThing *player, int binIdx, int a3);
void sithWeapon_SetMountWait(sithThing *a1, float mountWait);
void sithWeapon_SetFireWait(sithThing *weapon, float firewait);
void sithWeapon_handle_inv_msgs(sithThing *player);
void sithWeapon_Activate(sithThing *weapon, sithCog *cogCtx, float fireRate, int mode);
float sithWeapon_Deactivate(sithThing *weapon, sithCog *cogCtx, int mode);
int sithWeapon_AutoSelect(sithThing *player, int weapIdx);
int sithWeapon_HandleWeaponKeys(sithThing *player, float a2);
void sithWeapon_ProjectileAutoAim(rdMatrix34 *out, sithThing *sender, rdMatrix34 *in, rdVector3 *fireOffset, float autoaimFov, float autoaimMaxDist);
sithThing* sithWeapon_FireProjectile(sithThing *sender, sithThing *projectileTemplate, sithSound *fireSound, int mode, rdVector3 *fireOffset, rdVector3 *aimError, float scale, int16_t scaleFlags, float autoaimFov, float autoaimMaxDist);
float sithWeapon_GetPriority(sithThing *player, int binIdx, int mode);
int sithWeapon_GetCurWeaponMode();
void sithWeapon_SyncPuppet(sithThing *player);
int sithWeapon_WriteConf();
int sithWeapon_ReadConf();
void sithWeapon_Syncunused1();
void sithWeapon_Syncunused2();
void sithWeapon_SetFireRate(sithThing *weapon, float fireRate);


//static void (*sithWeapon_sub_4D35E0)(sithThing *a1) = (void*)sithWeapon_sub_4D35E0_ADDR;
//static void (*sithWeapon_sub_4D3920)(sithThing *a1) = (void*)sithWeapon_sub_4D3920_ADDR;
//static void (*sithWeapon_Collide)(sithThing *physicsThing, sithThing *collidedThing, rdMatrix34 *a4, int a5) = (void*)sithWeapon_Collide_ADDR;
//static void (*sithWeapon_Remove)(sithThing *weapon) = (void*)sithWeapon_Remove_ADDR;
//static int (*sithWeapon_HitDebug)(sithThing *thing, sithSurface *surface, void *a3) = (void*)sithWeapon_HitDebug_ADDR;

//static void (*sithWeapon_Activate)(sithThing *weapon, sithCog *cogCtx, float fireRate, int mode) = (void*)sithWeapon_Activate_ADDR;
//static float (*sithWeapon_Deactivate)(sithThing *weapon, sithCog *cogCtx, int mode) = (void*)sithWeapon_Deactivate_ADDR;
//static void (*sithWeapon_SetFireWait)(sithThing *weapon, float firewait) = (void*)sithWeapon_SetFireWait_ADDR;
//static void (*sithWeapon_SetMountWait)(sithThing *a1, float mountWait) = (void*)sithWeapon_SetMountWait_ADDR;
//static int (*sithWeapon_SelectWeapon)(sithThing *player, int binIdx, int a3) = (void*)sithWeapon_SelectWeapon_ADDR;
//static int (*sithWeapon_AutoSelect)(sithThing *player, int weapIdx) = (void*)sithWeapon_AutoSelect_ADDR;
//static void (*sithWeapon_ProjectileAutoAim)(rdMatrix34 *a2, sithThing *a3, rdMatrix34 *a4, rdVector3 *a5, float a6, float a7) = (void*)sithWeapon_ProjectileAutoAim_ADDR;

static sithThing* (*sithWeapon_FireProjectile_0_)(sithThing *sender, sithThing *projectileTemplate, rdVector3 *fireOffset, rdVector3 *aimError, sithSound *fireSound, int anim, float scale, char scaleFlags, float a9) = (void*)sithWeapon_FireProjectile_0_ADDR;
static int (*sithWeapon_HandleWeaponKeys_)(sithThing *a1, float a2) = (void*)sithWeapon_HandleWeaponKeys_ADDR;

#endif // _SITHWEAPON_H
