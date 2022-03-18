#ifndef _DSS_SITHDSSTHING_H
#define _DSS_SITHDSSTHING_H

#include "types.h"
#include "globals.h"

#define sithDSSThing_SendTeleportThing_ADDR (0x004F3120)
#define sithDSSThing_HandleTeleportThing_ADDR (0x004F3270)
#define sithDSSThing_SendSyncThing_ADDR (0x004F3420)
#define sithDSSThing_HandleSyncThing_ADDR (0x004F35E0)
#define sithDSSThing_SendPlaySoundPos_ADDR (0x004F37B0)
#define sithDSSThing_HandlePlaySoundPos_ADDR (0x004F3870)
#define sithDSSThing_SoundClassPlay_ADDR (0x004F3960)
#define sithDSSThing_HandleSoundClassPlay_ADDR (0x004F39C0)
#define sithDSSThing_SendPlayKey_ADDR (0x004F3A30)
#define sithDSSThing_HandlePlayKey_ADDR (0x004F3AA0)
#define sithDSSThing_SendOpenDoor_ADDR (0x004F3B30)
#define sithDSSThing_HandleOpenDoor_ADDR (0x004F3B90)
#define sithDSSThing_SendSetThingModel_ADDR (0x004F3C00)
#define sithDSSThing_HandleSetThingModel_ADDR (0x004F3C80)
#define sithDSSThing_SendStopKey_ADDR (0x004F3CF0)
#define sithDSSThing_HandleStopKey_ADDR (0x004F3D50)
#define sithDSSThing_SendStopSound_ADDR (0x004F3DC0)
#define sithDSSThing_HandleStopSound_ADDR (0x004F3E10)
#define sithDSSThing_SendFireProjectile_ADDR (0x004F3E70)
#define sithDSSThing_HandleFireProjectile_ADDR (0x004F3F60)
#define sithDSSThing_SendDeath_ADDR (0x004F4040)
#define sithDSSThing_HandleDeath_ADDR (0x004F40B0)
#define sithDSSThing_SendDamage_ADDR (0x004F4120)
#define sithDSSThing_HandleDamage_ADDR (0x004F41A0)
#define sithDSSThing_SendSyncThingFull_ADDR (0x004F4210)
#define sithDSSThing_HandleSyncThingFull_ADDR (0x004F46F0)
#define sithDSSThing_SendSyncThingFrame_ADDR (0x004F4C60)
#define sithDSSThing_HandleSyncThingFrame_ADDR (0x004F4D60)
#define sithDSSThing_SendSyncThingAttachment_ADDR (0x004F4E80)
#define sithDSSThing_HandleSyncThingAttachment_ADDR (0x004F4F50)
#define sithDSSThing_SendTakeItem_ADDR (0x004F5040)
#define sithDSSThing_HandleTakeItem_ADDR (0x004F5150)
#define sithDSSThing_SendCreateThing_ADDR (0x004F5220)
#define sithDSSThing_HandleCreateThing_ADDR (0x004F52E0)
#define sithDSSThing_SendDestroyThing_ADDR (0x004F53D0)
#define sithDSSThing_HandleDestroyThing_ADDR (0x004F5410)
#define sithSector_TransitionMovingThing_ADDR (0x004F5440)

void sithDSSThing_SendTeleportThing(sithThing *pThing, int sendto_id, int bSync);
int sithDSSThing_HandleTeleportThing(sithCogMsg *msg);

void sithDSSThing_SendPlaySoundPos(sithThing *followThing, rdVector3 *pos, sithSound *sound, float volume, float a5, int flags, int refid, int sendto_id, int mpFlags);
int sithDSSThing_HandlePlaySoundPos(sithCogMsg *msg);

void sithDSSThing_SendSyncThingFull(sithThing *thing, int sendto_id, int mpFlags);
int sithDSSThing_HandleSyncThingFull(sithCogMsg *msg);

void sithDSSThing_SendSyncThingAttachment(sithThing *thing, int sendto_id, int mpFlags, int a4);
int sithDSSThing_HandleSyncThingAttachment(sithCogMsg *msg);

void sithDSSThing_SendDeath(sithThing *sender, sithThing *receiver, char cause, int sendto_id, int mpFlags);

void sithDSSThing_TransitionMovingThing(sithThing *pThing, rdVector3 *pPos, sithSector *pSector);

static void (*sithDSSThing_SendPlayKey)(sithThing *a1, rdKeyframe *a2, int a3, wchar_t a4, int a5, int a6, int a7) = (void*)sithDSSThing_SendPlayKey_ADDR;
static void (*sithDSSThing_SendStopKey)(sithThing *a1, int a2, float a3, int a4, int a5) = (void*)sithDSSThing_SendStopKey_ADDR;
static void (*sithDSSThing_SendSetThingModel)(sithThing *a1, int a2) = (void*)sithDSSThing_SendSetThingModel_ADDR;
static int (*sithDSSThing_SendStopSound)(sithPlayingSound *a1, float a2, int a3, int a4) = (void*)sithDSSThing_SendStopSound_ADDR;
static int (*sithDSSThing_SoundClassPlay)(sithThing *a1, int16_t a2, int a3, float a4) = (void*)sithDSSThing_SoundClassPlay_ADDR;
static int (*sithDSSThing_SendFireProjectile)(sithThing *weapon, sithThing *projectile, rdVector3 *fireOffset, rdVector3 *aimError, sithSound *fireSound, __int16 anim, float scale, __int16 scaleFlags, float a9, int thingId, int a11, int a12) = (void*)sithDSSThing_SendFireProjectile_ADDR;
static void (*sithDSSThing_SendSyncThingFrame)(sithThing *a1, __int16 a2, float a3, int a4, int a5, int a6) = (void*)sithDSSThing_SendSyncThingFrame_ADDR;
static void (*sithDSSThing_SendOpenDoor)(sithThing *a1, __int16 a2, int a3, int a4, int a5) = (void*)sithDSSThing_SendOpenDoor_ADDR;
static void (*sithDSSThing_SendDestroyThing)(int a1, int a2) = (void*)sithDSSThing_SendDestroyThing_ADDR;
static int (*sithDSSThing_SendCreateThing)(sithThing *a1, sithThing *a2, sithThing *a3, sithSector *a4, int *a5, int *a6, int a7, int a8) = (void*)sithDSSThing_SendCreateThing_ADDR;
static void (*sithDSSThing_SendDamage)(sithThing *a1, sithThing *a2, float a3, __int16 a4, int a5, int a6) = (void*)sithDSSThing_SendDamage_ADDR;
static void (*sithDSSThing_SendSyncThing)(sithThing *a1, int a2, int a3) = (void*)sithDSSThing_SendSyncThing_ADDR;
static void (*sithDSSThing_SendTakeItem)(sithThing *a1, sithThing *a2, int a3) = (void*)sithDSSThing_SendTakeItem_ADDR;


#endif // _DSS_SITHDSSTHING_H