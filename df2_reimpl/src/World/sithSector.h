#ifndef _SITHSECTOR_H
#define _SITHSECTOR_H

#include "types.h"
#include "globals.h"

#define sithSector_Startup_ADDR (0x004F29F0)
#define sithSector_Shutdown_ADDR (0x004F2A50)
#define sithSector_AddEntry_ADDR (0x004F2A90)
#define sithSector_sub_4F2B10_ADDR (0x004F2B10)
#define sithSector_TimerTick_ADDR (0x004F2B60)
#define sithSector_sub_4F2C30_ADDR (0x004F2C30)
#define sithSector_SetSkyParams_ADDR (0x004F2D30)
#define sithSector_Close_ADDR (0x004F2DC0)
#define sithSector_UpdateSky_ADDR (0x004F2DD0)
#define sithSector_sub_4F2E30_ADDR (0x004F2E30)
#define sithSector_sub_4F2F60_ADDR (0x004F2F60)
#define sithSector_cogMsg_SendTeleportThing_ADDR (0x004F3120)
#define sithSector_cogMsg_HandleTeleportThing_ADDR (0x004F3270)
#define sithSector_cogMsg_SendSyncThing_ADDR (0x004F3420)
#define sithSector_cogMsg_HandleSyncThing_ADDR (0x004F35E0)
#define sithSector_cogmsg_SendPlaySoundPos_ADDR (0x004F37B0)
#define sithSector_cogMsg_HandlePlaySoundPos_ADDR (0x004F3870)
#define sithSector_cogMsg_SoundClassPlay_ADDR (0x004F3960)
#define sithSector_cogMsg_HandleSoundClassPlay_ADDR (0x004F39C0)
#define sithSector_cogMsg_SendPlayKey_ADDR (0x004F3A30)
#define sithSector_cogMsg_HandlePlayKey_ADDR (0x004F3AA0)
#define sithSector_cogMsg_SendOpenDoor_ADDR (0x004F3B30)
#define sithSector_cogMsg_HandleOpenDoor_ADDR (0x004F3B90)
#define sithSector_cogMsg_SendSetThingModel_ADDR (0x004F3C00)
#define sithSector_cogMsg_HandleSetThingModel_ADDR (0x004F3C80)
#define sithSector_cogMsg_SendStopKey_ADDR (0x004F3CF0)
#define sithSector_cogMsg_HandleStopKey_ADDR (0x004F3D50)
#define sithSector_cogMsg_SendStopSound_ADDR (0x004F3DC0)
#define sithSector_cogMsg_HandleStopSound_ADDR (0x004F3E10)
#define sithSector_cogMsg_SendFireProjectile_ADDR (0x004F3E70)
#define sithSector_cogMsg_HandleFireProjectile_ADDR (0x004F3F60)
#define sithSector_cogMsg_SendDeath_ADDR (0x004F4040)
#define sithSector_cogMsg_HandleDeath_ADDR (0x004F40B0)
#define sithSector_cogMsg_SendDamage_ADDR (0x004F4120)
#define sithSector_cogMsg_HandleDamage_ADDR (0x004F41A0)
#define sithSector_cogMsg_SendSyncThingFull_ADDR (0x004F4210)
#define sithSector_cogMsg_HandleSyncThingFull_ADDR (0x004F46F0)
#define sithSector_cogMsg_SendSyncThingFrame_ADDR (0x004F4C60)
#define sithSector_cogmsg_HandleSyncThingFrame_ADDR (0x004F4D60)
#define sithSector_cogMsg_SendSyncThingAttachment_ADDR (0x004F4E80)
#define sithSector_cogMsg_HandleSyncThingAttachment_ADDR (0x004F4F50)
#define sithSector_cogMsg_SendTakeItem_ADDR (0x004F5040)
#define sithSector_cogMsg_HandleTakeItem_ADDR (0x004F5150)
#define sithSector_cogMsg_SendCreateThing_ADDR (0x004F5220)
#define sithSector_cogMsg_HandleCreateThing_ADDR (0x004F52E0)
#define sithSector_cogMsg_SendDestroyThing_ADDR (0x004F53D0)
#define sithSector_cogMsg_HandleDestroyThing_ADDR (0x004F5410)
#define sithSector_TransitionMovingThing_ADDR (0x004F5440)
#define sithSector_ThingLandIdk_ADDR (0x004F5550)
#define sithSector_ThingPhysIdk_inlined_ADDR (0x004F5870)
#define sithSector_ThingPhysicsTick_ADDR (0x004F5900)
#define sithSector_ThingApplyForce_ADDR (0x004F59B0)
#define sithSector_ThingSetLook_ADDR (0x004F5A80)
#define sithSector_ApplyDrag_ADDR (0x004F5D50)
#define sithSector_LoadThingPhysicsParams_ADDR (0x004F5EC0)
#define sithSector_StopPhysicsThing_ADDR (0x004F61A0)
#define sithSector_ThingGetInsertOffsetZ_ADDR (0x004F6210)
#define sithSector_ThingPhysGeneral_ADDR (0x004F6270)
#define sithSector_ThingPhysPlayer_ADDR (0x004F6860)
#define sithSector_ThingPhysUnderwater_ADDR (0x004F6D80)
#define sithSector_ThingPhysAttached_ADDR (0x004F7430)
#define sithSector_Load_ADDR (0x004F8720)
#define sithSector_GetIdxFromPtr_ADDR (0x004F8BB0)
#define sithSector_New_ADDR (0x004F8BF0)
#define sithSector_NewEntry_ADDR (0x004F8C70)
#define sithSector_Free_ADDR (0x004F8CA0)
#define sithSector_sub_4F8D00_ADDR (0x004F8D00)
#define sithSector_UnsetAdjoins_ADDR (0x004F8DE0)
#define sithSector_SetAdjoins_ADDR (0x004F8E10)
#define sithSector_GetThingsCount_ADDR (0x004F8E40)
#define sithSector_GetNumPlayers_ADDR (0x004F8E60)
#define sithSector_Sync_ADDR (0x004F8E80)
#define sithSector_sub_4F8EF0_ADDR (0x004F8EF0)
#define sithSector_GetPtrFromIdx_ADDR (0x004F8F50)
#define sithSector_cogMsg_SendSyncSurface_ADDR (0x004F8F80)
#define sithSector_cogMsg_HandleSyncSurface_ADDR (0x004F9050)
#define sithSector_cogMsg_SendSyncSector_ADDR (0x004F9120)
#define sithSector_cogMsg_HandleSyncSector_ADDR (0x004F91F0)
#define sithSector_cogMsg_SendSyncSectorAlt_ADDR (0x004F92E0)
#define sithSector_cogMsg_HandleSyncSectorAlt_ADDR (0x004F9350)
#define sithSector_cogMsg_SendSyncAI_ADDR (0x004F93B0)
#define sithSector_cogMsg_HandleSyncAI_ADDR (0x004F9640)
#define sithSector_cogMsg_SendSyncItemDesc_ADDR (0x004F9900)
#define sithSector_cogMsg_HandleSyncItemDesc_ADDR (0x004F99C0)
#define sithSector_cogMsg_SendStopAnim_ADDR (0x004F9A70)
#define sithSector_cogMsg_HandleStopAnim_ADDR (0x004F9BA0)
#define sithSector_cogMsg_SendSyncPuppet_ADDR (0x004F9D20)
#define sithSector_cogMsg_HandleSyncPuppet_ADDR (0x004F9E10)
#define sithSector_cogMsg_SendSyncTimers_ADDR (0x004F9F20)
#define sithSector_cogMsg_HandleSyncTimers_ADDR (0x004F9FA0)
#define sithSector_cogMsg_SendSyncCameras_ADDR (0x004F9FF0)
#define sithSector_cogMsg_HandleSyncCameras_ADDR (0x004FA130)
#define sithSector_cogMsg_SendSyncPalEffects_ADDR (0x004FA240)
#define sithSector_cogMsg_HandleSyncPalEffects_ADDR (0x004FA350)
#define sithSector_cogmsg_send31_ADDR (0x004FA420)
#define sithSector_cogmsg_31_ADDR (0x004FA5D0)

typedef enum ATTACHFLAGS
{
  ATTACHFLAGS_WORLDSURFACE = 0x1,
  ATTACHFLAGS_THINGSURFACE = 0x2,
  ATTACHFLAGS_THING = 0x4,
  ATTACHFLAGS_THING_RELATIVE = 0x8,
} ATTACHFLAGS;

typedef enum SITH_SF
{
  SITH_SF_NOGRAVITY = 0x1,
  SITH_SF_UNDERWATER = 0x2,
  SITH_SF_COGLINKED = 0x4,
  SITH_SF_HASTHRUST = 0x8,
  SITH_SF_AUTOMAPHIDE = 0x10,
  SITH_SF_NOACTORS = 0x20,
  SITH_SF_PIT = 0x40,
  SITH_SF_80 = 0x80,
  SITH_SF_100 = 0x100,
  SITH_SF_200 = 0x200,
  SITH_SF_400 = 0x400,
  SITH_SF_800 = 0x800,
  SITH_SF_COLLIDEBOX = 0x1000,
  SITH_SF_2000 = 0x2000,
  SITH_SF_AUTOMAPVISIBLE = 0x4000,
} SITH_SF;

int sithSector_Startup();
void sithSector_Shutdown();
void sithSector_Close();
int sithSector_Load(sithWorld *world, int tmp);
int sithSector_LoadThingPhysicsParams(stdConffileArg *arg, sithThing *thing, int param);

void sithSector_ApplyDrag(rdVector3 *vec, float drag, float mag, float dragCoef);
void sithSector_ThingPhysicsTick(sithThing *thing, float force);
void sithSector_ThingPhysGeneral(sithThing *thing, float deltaSeconds);
void sithSector_ThingPhysPlayer(sithThing *player, float deltaSeconds);
void sithSector_ThingLandIdk(sithThing *thing, int a3);
int sithSector_SetSkyParams(float horizontalPixelsPerRev, float horizontalDist, float ceilingSky);
void sithSector_UpdateSky();
void sithSector_StopPhysicsThing(sithThing *thing);
int sithSector_GetIdxFromPtr(sithSector *sector);
void sithSector_SetAdjoins(sithSector *sector);
void sithSector_UnsetAdjoins(sithSector *sector);
int sithSector_GetThingsCount(sithSector *sector);
void sithSector_Free(sithWorld *world);
int sithSector_GetNumPlayers(sithSector *sector);
void sithSector_sub_4F2E30(rdProcEntry *a1, sithSurfaceInfo *a2, int num_vertices);
void sithSector_ThingPhysAttached(sithThing *thing, float deltaSeconds);
void sithSector_ThingSetLook(sithThing *thing, const rdVector3 *look, float a3);
void sithSector_ThingApplyForce(sithThing *thing, rdVector3 *forceVec);
void sithSector_sub_4F2F60(rdProcEntry *a1, sithSurfaceInfo *a2, rdVector3 *a3, unsigned int a4);
int sithSector_AddEntry(sithSector *sector, rdVector3 *pos, int a3, float a4, sithThing *thing);
void sithSector_ThingPhysUnderwater(sithThing *thing, float deltaSeconds);
float sithSector_ThingGetInsertOffsetZ(sithThing *thing);
int sithSector_TimerTick();
void sithSector_sub_4F2C30(sithSectorEntry *sectorEntry, sithSector *sector, rdVector3 *pos1, rdVector3 *pos2, float a5, float a6, sithThing *thing);

void sithSector_cogMsg_SendSyncThingFull(sithThing *thing, int sendto_id, int mpFlags);
void sithSector_cogMsg_SendSyncPuppet(sithThing *thing, int sendto_id, int mpFlags);
void sithSector_cogMsg_SendSyncAI(sithActor *actor, int sendto_id, int idx);
void sithSector_cogMsg_SendSyncSurface(sithSurface *surface, int sendto_id, int mpFlags);
void sithSector_cogMsg_SendSyncSector(sithSector *sector, int sendto_id, int mpFlags);
void sithSector_cogMsg_SendSyncItemDesc(sithThing *thing, int binIdx, int sendto_id, int mpFlags);
void sithSector_cogMsg_SendStopAnim(rdSurface *surface, int sendto_id, int mpFlags);
void sithSector_cogMsg_SendSyncTimers(sithTimer *timer, int sendto_id, int mpFlags);
void sithSector_cogMsg_SendSyncPalEffects(int sendto_id, int mpFlags);
void sithSector_cogMsg_SendSyncCameras(int sendto_id, int mpFlags);
void sithSector_cogmsg_send31(int sendto_id, int mpFlags);

//static int (*sithSector_LoadThingPhysicsParams)(stdConffileArg *arg, sithThing *thing, int param) = (void*)sithSector_LoadThingPhysicsParams_ADDR;
//static void (*sithSector_ThingPhysGeneral)(sithThing *thing, float deltaSeconds) = (void*)sithSector_ThingPhysGeneral_ADDR;
//static void (*sithSector_ThingPhysPlayer)(sithThing *player, float deltaSeconds) = (void*)sithSector_ThingPhysPlayer_ADDR;
//static void (*sithSector_ThingPhysUnderwater)(sithThing *a1, float a2) = (void*)sithSector_ThingPhysUnderwater_ADDR;
static void (*_sithSector_ThingPhysAttached)(sithThing *thing, float deltaSeconds) = (void*)sithSector_ThingPhysAttached_ADDR;
//static void (*sithSector_ThingSetLook)(sithThing *a1, const rdVector3 *a2, float a3) = (void*)sithSector_ThingSetLook_ADDR;
//static void (*sithSector_Free)(sithWorld* world) = (void*)sithSector_Free_ADDR;

//static signed int (*sithSector_AddEntry)(sithSector *sector, rdVector3 *a2, int a3, float a4, sithThing *a5) = (void*)sithSector_AddEntry_ADDR;
//static int (*sithSector_cogMsg_SendStopAnim)(rdSurface*, int, int) = (void*)sithSector_cogMsg_SendStopAnim_ADDR;
static int (*sithSector_cogMsg_SendCreateThing)(sithThing *a1, sithThing *a2, sithThing *a3, sithSector *a4, int *a5, int *a6, int a7, int a8) = (void*)sithSector_cogMsg_SendCreateThing_ADDR;
static void (*sithSector_cogMsg_SendTakeItem)(sithThing *a1, sithThing *a2, int a3) = (void*)sithSector_cogMsg_SendTakeItem_ADDR;
static void (*sithSector_cogMsg_SendSyncThing)(sithThing *a1, int a2, int a3) = (void*)sithSector_cogMsg_SendSyncThing_ADDR;
static void (*sithSector_cogMsg_SendTeleportThing)(sithThing *a1, int a2, int a3) = (void*)sithSector_cogMsg_SendTeleportThing_ADDR;
static void (*sithSector_cogMsg_SendDamage)(sithThing *a1, sithThing *a2, float a3, __int16 a4, int a5, int a6) = (void*)sithSector_cogMsg_SendDamage_ADDR;
static void (*sithSector_cogMsg_SendDestroyThing)(int a1, int a2) = (void*)sithSector_cogMsg_SendDestroyThing_ADDR;
static void (*sithSector_cogMsg_SendSyncThingFrame)(sithThing *a1, __int16 a2, float a3, int a4, int a5, int a6) = (void*)sithSector_cogMsg_SendSyncThingFrame_ADDR;
//static void (*sithSector_ThingApplyForce)(sithThing *a1, rdVector3 *a2) = (void*)sithSector_ThingApplyForce_ADDR;
static void (*sithSector_cogMsg_SendSyncThingAttachment)(sithThing *a1, int a2, int a3, int a4) = (void*)sithSector_cogMsg_SendSyncThingAttachment_ADDR;
static void (*sithSector_cogMsg_SendOpenDoor)(sithThing *a1, __int16 a2, int a3, int a4, int a5) = (void*)sithSector_cogMsg_SendOpenDoor_ADDR;
static void (*sithSector_cogMsg_SendPlayKey)(sithThing *a1, rdKeyframe *a2, int a3, wchar_t a4, int a5, int a6, int a7) = (void*)sithSector_cogMsg_SendPlayKey_ADDR;
static void (*sithSector_cogMsg_SendStopKey)(sithThing *a1, int a2, float a3, int a4, int a5) = (void*)sithSector_cogMsg_SendStopKey_ADDR;
static void (*sithSector_cogMsg_SendSetThingModel)(sithThing *a1, int a2) = (void*)sithSector_cogMsg_SendSetThingModel_ADDR;
//static void (*sithSector_ThingLandIdk)(sithThing *thing, int a3) = (void*)sithSector_ThingLandIdk_ADDR;
static int (*sithSector_cogMsg_SendFireProjectile)(sithThing *weapon, sithThing *projectile, rdVector3 *fireOffset, rdVector3 *aimError, sithSound *fireSound, __int16 anim, float scale, __int16 scaleFlags, float a9, int thingId, int a11, int a12) = (void*)sithSector_cogMsg_SendFireProjectile_ADDR;
static int (*sithSector_cogmsg_SendPlaySoundPos)(sithThing *a1, rdVector3 *a2, sithSound *a3, float a4, float a5, int a6, int a7, int a8, int a9) = (void*)sithSector_cogmsg_SendPlaySoundPos_ADDR;
static int (*sithSector_cogMsg_SendStopSound)(sithPlayingSound *a1, float a2, int a3, int a4) = (void*)sithSector_cogMsg_SendStopSound_ADDR;
static int (*sithSector_cogMsg_SoundClassPlay)(sithThing *a1, int16_t a2, int a3, float a4) = (void*)sithSector_cogMsg_SoundClassPlay_ADDR;
//static int (*sithSector_SetSkyParams)(float horizontalPixelsPerRev, float horizontalDist, float ceilingSky) = (void*)sithSector_SetSkyParams_ADDR;
//static void (*sithSector_UpdateSky)() = (void*)sithSector_UpdateSky_ADDR;
//static void (*sithSector_sub_4F2E30)(rdProcEntry *a1, sithSurfaceInfo* a2, int num_vertices) = (void*)sithSector_sub_4F2E30_ADDR;
//static void (*sithSector_sub_4F2F60)(rdProcEntry *a1, sithSurfaceInfo *a2, rdVector3 *a3, unsigned int a4) = (void*)sithSector_sub_4F2F60_ADDR;
//static int (*sithSector_TimerTick)() = (void*)sithSector_TimerTick_ADDR;
static int (*sithSector_Sync)(sithSector *sector, int a2) = (void*)sithSector_Sync_ADDR;
static int (*sithSector_cogMsg_SendDeath)(sithThing *sender, sithThing *receiver, char a3, int a4, int a5) = (void*)sithSector_cogMsg_SendDeath_ADDR;
//static int (*sithSector_cogMsg_SendSyncAI)(sithActor *actor, int sendto_id, int idx) = (void*)sithSector_cogMsg_SendSyncAI_ADDR;
//static int (*_sithSector_cogMsg_SendSyncThingFull)(sithThing *thing, int sendto_id, int mpFlags) = (void*)sithSector_cogMsg_SendSyncThingFull_ADDR;
//static int (*sithSector_cogMsg_SendSyncPuppet)(sithThing *thing, int sendto_id, int mpFlags) = (void*)sithSector_cogMsg_SendSyncPuppet_ADDR;
//static int (*sithSector_cogMsg_SendSyncSurface)(sithSurface *surface, int sendto_id, int mpFlags) = (void*)sithSector_cogMsg_SendSyncSurface_ADDR;
//static int (*sithSector_cogMsg_SendSyncSector)(sithSector *sector, int sendto_id, int mpFlags) = (void*)sithSector_cogMsg_SendSyncSector_ADDR;
//static void (*sithSector_cogMsg_SendSyncItemDesc)(sithThing *thing, int binIdx, int sendto_id, int mpFlags) = (void*)sithSector_cogMsg_SendSyncItemDesc_ADDR;
//static void (*sithSector_cogMsg_SendSyncTimers)(sithTimer *a1, int sendto_id, int mpFlags) = (void*)sithSector_cogMsg_SendSyncTimers_ADDR;
//static int (*sithSector_cogMsg_SendSyncPalEffects)(int sendto_id, int mpFlags) = (void*)sithSector_cogMsg_SendSyncPalEffects_ADDR;
//static int (*sithSector_cogMsg_SendSyncCameras)(int sendto_id, int mpFlags) = (void*)sithSector_cogMsg_SendSyncCameras_ADDR;
//static int (*sithSector_cogmsg_send31)(int sendto_id, int mpFlags) = (void*)sithSector_cogmsg_send31_ADDR;
//static void (*sithSector_sub_4F2C30)(sithSectorEntry *sectorEntry, sithSector *sector, rdVector3 *pos1, rdVector3 *pos2, float a5, float a6, sithThing *thing) = (void*)sithSector_sub_4F2C30_ADDR;

#endif // _SITHSECTOR_H
