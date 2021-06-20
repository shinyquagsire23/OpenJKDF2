#ifndef _SITHWEAPON_H
#define _SITHWEAPON_H

#include "types.h"

#include "Primitives/rdMatrix.h"

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

#define sithWeapon_controlOptions (*(int*)0x008BD020)
#define g_flt_8BD040 (*(float*)0x008BD040)
#define g_flt_8BD044 (*(float*)0x008BD044)
#define g_flt_8BD048 (*(float*)0x008BD048)
#define g_flt_8BD04C (*(float*)0x008BD04C)
#define g_flt_8BD050 (*(float*)0x008BD050)
#define g_flt_8BD054 (*(float*)0x008BD054)
#define g_flt_8BD058 (*(float*)0x008BD058)
#define dword_8BD060 (*(float*)0x008BD060)
#define sithWeapon_CurWeaponMode (*(int*)0x008BD064)
#define sithWeapon_bAutoPickup (*(int*)0x008BD080)
#define sithWeapon_bAutoSwitch (*(int*)0x008BD084)
#define sithWeapon_bAutoReload (*(int*)0x008BD088)
#define sithWeapon_bMultiAutoPickup (*(int*)0x008BD08C)
#define sithWeapon_bMultiplayerAutoSwitch (*(int*)0x008BD090)
#define sithWeapon_bMultiAutoReload (*(int*)0x008BD094)
#define sithWeapon_bAutoAim (*(int*)0x008BD098)
#define sithWeapon_mountWait (*(float*)0x008BD09C)
#define sithWeapon_8BD0A0 ((float*)0x008BD0A0)
#define sithWeapon_fireWait (*(float*)0x008BD0A8)
#define sithWeapon_fireRate (*(float*)0x008BD0AC)
#define sithWeapon_LastFireTimeSecs (*(float*)0x008BD0B0)
#define sithWeapon_a8BD030 ((float*)0x008BD030)
#define sithWeapon_8BD05C ((float*)0x008BD05C)
#define sithWeapon_8BD008 ((int*)0x008BD008)
#define sithWeapon_8BD024 (*(int*)0x008BD024)
#define sithWeapon_senderIndex (*(int*)0x008BD028)

void sithWeapon_InitDefaults();
void sithWeapon_Startup();
void sithWeapon_Tick(sithThing *weapon, float deltaSeconds);
void sithWeapon_sub_4D35E0(sithThing *weapon);
void sithWeapon_sub_4D3920(sithThing *weapon);
int sithWeapon_LoadParams(stdConffileArg *arg, sithThing *thing, int param);
sithThing* sithWeapon_Fire(sithThing *weapon, sithThing *projectile, rdVector3 *fireOffset, rdVector3 *aimError, sithSound *fireSound, int anim, float scale, int16_t scaleFlags, float a9);
sithThing* sithWeapon_FireProjectile_0(sithThing *sender, sithThing *projectileTemplate, rdVector3 *fireOffset, rdVector3 *aimError, sithSound *fireSound, int anim, float scale, char scaleFlags, float a9);
void sithWeapon_SetTimeLeft(sithThing *weapon, sithThing* a2, float timeLeft);
void sithWeapon_Collide(sithThing *physicsThing, sithThing *collidedThing, rdMatrix34 *a4, int a5);
int sithWeapon_HitDebug(sithThing *thing, sithSurface *surface, sithUnk3SearchEntry *a3);
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
