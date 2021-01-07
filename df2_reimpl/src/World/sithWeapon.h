#ifndef _SITHWEAPON_H
#define _SITHWEAPON_H

#include "Primitives/rdMatrix.h"

#define sithWeapon_InitDefaults_ADDR (0x004D3430)
#define sithWeapon_Startup_ADDR (0x004D34B0)
#define sithWeapon_Tick_ADDR (0x004D3530)
#define sithWeapon_sub_4D35E0_ADDR (0x004D35E0)
#define sithWeapon_sub_4D3920_ADDR (0x004D3920)
#define sithWeapon_LoadParams_ADDR (0x004D4290)
#define sithWeapon_Fire_ADDR (0x004D44F0)
#define sithWeapon_FireProjectile_0_ADDR (0x004D45A0)
#define sithWeapon_setstimealive_ADDR (0x004D4880)
#define sithWeapon_Collide_ADDR (0x004D48C0)
#define sithWeapon_HitDebug_ADDR (0x004D4E40)
#define sithWeapon_Remove_ADDR (0x004D5160)
#define sithWeapon_sub_4D51F0_ADDR (0x004D51F0)
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
#define dword_8BD0A0 (*(float*)0x008BD0A0)
#define dword_8BD0A4 (*(float*)0x008BD0A4)
#define sithWeapon_fireWait (*(float*)0x008BD0A8)
#define sithWeapon_fireRate (*(float*)0x008BD0AC)
#define sithWeapon_LastFireTimeSecs (*(*)0x008BD0B0)

typedef struct sithThing sithThing;
typedef struct sithSurface sithSurface;
typedef struct sithSound sithSound;
typedef struct sithCog sithCog;

void sithWeapon_InitDefaults();
void sithWeapon_Startup();
void sithWeapon_Tick(sithThing *weapon, float deltaSeconds);

static void (*sithWeapon_sub_4D35E0)(sithThing *a1) = (void*)sithWeapon_sub_4D35E0_ADDR;
static void (*sithWeapon_sub_4D3920)(sithThing *a1) = (void*)sithWeapon_sub_4D3920_ADDR;
static void (*sithWeapon_Collide)(sithThing *physicsThing, sithThing *collidedThing, rdMatrix34 *a4, int a5) = (void*)sithWeapon_Collide_ADDR;
static void (*sithWeapon_Remove)(sithThing *weapon) = (void*)sithWeapon_Remove_ADDR;
static int (*sithWeapon_HitDebug)(sithThing *thing, sithSurface *surface, void *a3) = (void*)sithWeapon_HitDebug_ADDR;

static void (*sithWeapon_Activate)(sithThing *weapon, sithCog *cogCtx, float fireRate, int mode) = (void*)sithWeapon_Activate_ADDR;
static float (*sithWeapon_Deactivate)(sithThing *weapon, sithCog *cogCtx, int mode) = (void*)sithWeapon_Deactivate_ADDR;
static void (*sithWeapon_SetFireWait)(sithThing *weapon, float firewait) = (void*)sithWeapon_SetFireWait_ADDR;
static void (*sithWeapon_SetMountWait)(sithThing *a1, float mountWait) = (void*)sithWeapon_SetMountWait_ADDR;
static int (*sithWeapon_SelectWeapon)(sithThing *player, int binIdx, int a3) = (void*)sithWeapon_SelectWeapon_ADDR;
static int (*sithWeapon_AutoSelect)(sithThing *player, int weapIdx) = (void*)sithWeapon_AutoSelect_ADDR;
static float (*sithWeapon_GetPriority)(sithThing *player, int binIdx, int mode) = (void*)sithWeapon_GetPriority_ADDR;
static int (*sithWeapon_GetCurWeaponMode)() = (void*)sithWeapon_GetCurWeaponMode_ADDR;
static void (*sithWeapon_SetFireRate)(sithThing *a1, float fireRate) = (void*)sithWeapon_SetFireRate_ADDR;
static sithThing* (*sithWeapon_FireProjectile)(sithThing *sender, sithThing *projectileTemplate, sithSound *fireSound, int mode, rdVector3 *fireOffset, rdVector3 *aimError, float scale, __int16 scaleFlags, float autoaimFov, float autoaimMaxDist) = (void*)sithWeapon_FireProjectile_ADDR;
static int (*sithWeapon_WriteConf)() = (void*)sithWeapon_WriteConf_ADDR;
static int (*sithWeapon_ReadConf)() = (void*)sithWeapon_ReadConf_ADDR;

#endif // _SITHWEAPON_H
