#ifndef _SITHWEAPON_H
#define _SITHWEAPON_H

#include "types.h"
#include "globals.h"

#define sithWeapon_InitDefaults_ADDR (0x004D3430)
#define sithWeapon_Startup_ADDR (0x004D34B0)
#define sithWeapon_Update_ADDR (0x004D3530)
#define sithWeapon_HandleImpact_ADDR (0x004D35E0)
#define sithWeapon_sub_4D3920_ADDR (0x004D3920)
#define sithWeapon_ParseArg_ADDR (0x004D4290)
#define sithWeapon_WeaponFire_ADDR (0x004D44F0)
#define sithWeapon_WeaponFireProjectile_ADDR (0x004D45A0)
#define sithWeapon_DamageWeapon_ADDR (0x004D4880)
#define sithWeapon_ThingCollisionHandler_ADDR (0x004D48C0)
#define sithWeapon_SurfaceCollisionHandler_ADDR (0x004D4E40)
#define sithWeapon_DestroyWeapon_ADDR (0x004D5160)
#define sithWeapon_CreateWeaponExplosion_ADDR (0x004D51F0)
#define sithWeapon_StartupEntry_ADDR (0x004D5270)
#define sithWeapon_ShutdownEntry_ADDR (0x004D52C0)
#define sithWeapon_SelectWeapon_ADDR (0x004D52D0)
#define sithWeapon_SetMountWait_ADDR (0x004D5460)
#define sithWeapon_SetFireWait_ADDR (0x004D5480)
#define sithWeapon_UpdateActorWeaponState_ADDR (0x004D54C0)
#define sithWeapon_ActivateWeapon_ADDR (0x004D5650)
#define sithWeapon_DeactivateWeapon_ADDR (0x004D5700)
#define sithWeapon_AutoSelect_ADDR (0x004D57A0)
#define sithWeapon_ProcessWeaponControls_ADDR (0x004D5830)
#define sithWeapon_GetAimOrient_ADDR (0x004D5C60)
#define sithWeapon_FireProjectile_ADDR (0x004D5F20)
#define sithWeapon_GetPriority_ADDR (0x004D62B0)
#define sithWeapon_GetCurWeaponMode_ADDR (0x004D6310)
#define sithWeapon_SyncPuppet_ADDR (0x004D6320)
#define sithWeapon_WriteConf_ADDR (0x004D6370)
#define sithWeapon_ReadConf_ADDR (0x004D6430)
#define sithWeapon_SelectNextWeapon_ADDR (0x004D6670)
#define sithWeapon_SelectPreviousWeapon_ADDR (0x004D6750)
#define sithWeapon_SetFireRate_ADDR (0x004D6830)

void sithWeapon_InitDefaults();
void sithWeapon_Startup();
MATH_FUNC void sithWeapon_Update(SithThing *weapon, flex_t deltaSeconds);
MATH_FUNC void sithWeapon_HandleImpact(SithThing *weapon);
MATH_FUNC void sithWeapon_sub_4D3920(SithThing *weapon);
int sithWeapon_ParseArg(StdConffileArg *arg, SithThing *thing, int param);
MATH_FUNC SithThing* sithWeapon_WeaponFire(SithThing *weapon, SithThing *projectile, rdVector3 *fireOffset, rdVector3 *aimError, sithSound *fireSound, int anim, flex_t scale, int16_t scaleFlags, flex_t a9);
MATH_FUNC SithThing* sithWeapon_WeaponFireProjectile(SithThing *sender, SithThing *projectileTemplate, rdVector3 *fireOffset, rdVector3 *aimError, sithSound *fireSound, int anim, flex_t scale, char scaleFlags, flex_t a9, int extra);
void sithWeapon_DamageWeapon(SithThing *weapon, SithThing* a2, flex_t timeLeft);
MATH_FUNC int sithWeapon_ThingCollisionHandler(SithThing *physicsThing, SithThing *collidedThing, SithCollision *a4, int a5);
MATH_FUNC int sithWeapon_SurfaceCollisionHandler(SithThing *thing, SithSurface *surface, SithCollision *a3);
void sithWeapon_DestroyWeapon(SithThing *weapon);
void sithWeapon_CreateWeaponExplosion(SithThing *weapon, SithThing *pExplosionTemplate);
void sithWeapon_StartupEntry();
void sithWeapon_ShutdownEntry();
int sithWeapon_SelectWeapon(SithThing *player, int binIdx, int a3);
void sithWeapon_SetMountWait(SithThing *a1, flex32_t mountWait);
void sithWeapon_SetFireWait(SithThing *weapon, flex32_t firewait);
void sithWeapon_UpdateActorWeaponState(SithThing *player);
void sithWeapon_ActivateWeapon(SithThing *weapon, sithCog *cogCtx, flex_t fireRate, int mode);
flex_t sithWeapon_DeactivateWeapon(SithThing *weapon, sithCog *cogCtx, int mode);
int sithWeapon_AutoSelect(SithThing *player, int weapIdx);
int sithWeapon_ProcessWeaponControls(SithThing *player, flex_t a2);
MATH_FUNC void sithWeapon_GetAimOrient(rdMatrix34 *out, SithThing *sender, rdMatrix34 *in, rdVector3 *fireOffset, flex_t autoaimFov, flex_t autoaimMaxDist);
MATH_FUNC SithThing* sithWeapon_FireProjectile(SithThing *pSender, SithThing *pProjectileTemplate, sithSound *pFireSound, int mode, rdVector3 *pFireOffset, rdVector3 *pAimError, flex_t scale, int16_t scaleFlags, flex_t autoaimFov, flex_t autoaimMaxDist, int extra);
flex_t sithWeapon_GetPriority(SithThing *player, int binIdx, int mode);
int sithWeapon_GetCurWeaponMode();
void sithWeapon_SyncPuppet(SithThing *player);
int sithWeapon_WriteConf();
int sithWeapon_ReadConf();
void sithWeapon_SelectNextWeapon(SithThing* player);
void sithWeapon_SelectPreviousWeapon(SithThing* player);
void sithWeapon_SetFireRate(SithThing *weapon, flex32_t fireRate);


//static void (*sithWeapon_HandleImpact)(SithThing *a1) = (void*)sithWeapon_HandleImpact_ADDR;
//static void (*sithWeapon_sub_4D3920)(SithThing *a1) = (void*)sithWeapon_sub_4D3920_ADDR;
//static void (*sithWeapon_ThingCollisionHandler)(SithThing *physicsThing, SithThing *collidedThing, rdMatrix34 *a4, int a5) = (void*)sithWeapon_ThingCollisionHandler_ADDR;
//static void (*sithWeapon_DestroyWeapon)(SithThing *weapon) = (void*)sithWeapon_DestroyWeapon_ADDR;
//static int (*sithWeapon_SurfaceCollisionHandler)(SithThing *thing, SithSurface *surface, void *a3) = (void*)sithWeapon_SurfaceCollisionHandler_ADDR;

//static void (*sithWeapon_ActivateWeapon)(SithThing *weapon, sithCog *cogCtx, flex_t fireRate, int mode) = (void*)sithWeapon_ActivateWeapon_ADDR;
//static flex_t (*sithWeapon_DeactivateWeapon)(SithThing *weapon, sithCog *cogCtx, int mode) = (void*)sithWeapon_DeactivateWeapon_ADDR;
//static void (*sithWeapon_SetFireWait)(SithThing *weapon, flex_t firewait) = (void*)sithWeapon_SetFireWait_ADDR;
//static void (*sithWeapon_SetMountWait)(SithThing *a1, flex_t mountWait) = (void*)sithWeapon_SetMountWait_ADDR;
//static int (*sithWeapon_SelectWeapon)(SithThing *player, int binIdx, int a3) = (void*)sithWeapon_SelectWeapon_ADDR;
//static int (*sithWeapon_AutoSelect)(SithThing *player, int weapIdx) = (void*)sithWeapon_AutoSelect_ADDR;
//static void (*sithWeapon_GetAimOrient)(rdMatrix34 *a2, SithThing *a3, rdMatrix34 *a4, rdVector3 *a5, flex_t a6, flex_t a7) = (void*)sithWeapon_GetAimOrient_ADDR;

//static SithThing* (*sithWeapon_FireProjectile_0_)(SithThing *sender, SithThing *projectileTemplate, rdVector3 *fireOffset, rdVector3 *aimError, sithSound *fireSound, int anim, flex_t scale, char scaleFlags, flex_t a9) = (void*)sithWeapon_WeaponFireProjectile_ADDR;
//static int (*sithWeapon_HandleWeaponKeys_)(SithThing *a1, flex_t a2) = (void*)sithWeapon_ProcessWeaponControls_ADDR;

#endif // _SITHWEAPON_H
