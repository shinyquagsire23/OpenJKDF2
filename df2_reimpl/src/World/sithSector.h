#ifndef _SITHSECTOR_H
#define _SITHSECTOR_H

typedef struct sithSurface sithSurface;

#define sithSector_Startup_ADDR (0x004F29F0)
#define sithSector_Shutdown_ADDR (0x004F2A50)
#define sithSector_AddEntry_ADDR (0x004F2A90)
#define sithSector_sub_4F2B10_ADDR (0x004F2B10)
#define sithSector_TimerTick_ADDR (0x004F2B60)
#define sithSector_sub_4F2C30_ADDR (0x004F2C30)
#define sithSector_SetSkyParams_ADDR (0x004F2D30)
#define sithSector_Close_ADDR (0x004F2DC0)
#define sithSector_sub_4F2DD0_ADDR (0x004F2DD0)
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
#define sithSector_Thingidkphys2_ADDR (0x004F5900)
#define sithSector_ThingApplyForce_ADDR (0x004F59B0)
#define sithSector_ThingSetLook_ADDR (0x004F5A80)
#define sithSector_Thingphyshelper_ADDR (0x004F5D50)
#define sithSector_LoadThingPhysicsParams_ADDR (0x004F5EC0)
#define sithSector_StopPhysicsThing_ADDR (0x004F61A0)
#define sithSector_ThingGetInsertOffsetZ_ADDR (0x004F6210)
#define sithSector_ThingPhysIdk1000_ADDR (0x004F6270)
#define sithSector_Thingphysidk3_ADDR (0x004F6860)
#define sithSector_Thingphysidk2_ADDR (0x004F6D80)
#define sithSector_Thingphysidk_ADDR (0x004F7430)
#define sithSector_Load_ADDR (0x004F8720)
#define sithSector_GetIdxFromPtr_ADDR (0x004F8BB0)
#define sithSector_New_ADDR (0x004F8BF0)
#define sithSector_NewEntry_ADDR (0x004F8C70)
#define sithSector_Free_ADDR (0x004F8CA0)
#define sithSector_sub_4F8D00_ADDR (0x004F8D00)
#define sithSector_setAdjoins2_ADDR (0x004F8DE0)
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

typedef struct rdClipFrustum rdClipFrustum;
typedef struct sithThing sithThing;
typedef struct sithAdjoin sithAdjoin;
typedef struct rdColormap rdColormap;

typedef struct sithSector
{
    uint32_t id;
    float ambientLight;
    float extraLight;
    rdColormap* colormap;
    rdVector3 tint;
    uint32_t numVertices;
    int* verticeIdxs;
    uint32_t numSurfaces;
    sithSurface* surfaces;
    sithAdjoin* adjoins;
    sithThing* thingsList;
    uint32_t flags;
    rdVector3 center;
    rdVector3 thrust;
    uint32_t field_50;
    uint32_t field_54;
    rdVector3 collidebox_onecorner;
    rdVector3 collidebox_othercorner;
    rdVector3 boundingbox_onecorner;
    rdVector3 boundingbox_othercorner;
    float radius;
    uint32_t field_8C;
    uint32_t field_90;
    rdClipFrustum* clipFrustum;
} sithSector;

static void (*sithSector_StopPhysicsThing)(sithThing* thing) = (void*)sithSector_StopPhysicsThing_ADDR;
static int (*sithSector_cogMsg_SendStopAnim)(sithSurface*, int, int) = (void*)sithSector_cogMsg_SendStopAnim_ADDR;
static int (*sithSector_cogMsg_SendCreateThing)(sithThing *a1, sithThing *a2, sithThing *a3, sithSector *a4, int *a5, int *a6, int a7, int a8) = (void*)sithSector_cogMsg_SendCreateThing_ADDR;
static void (*sithSector_cogMsg_SendTakeItem)(sithThing *a1, sithThing *a2, int a3) = (void*)sithSector_cogMsg_SendTakeItem_ADDR;
static void (*sithSector_cogMsg_SendSyncThing)(sithThing *a1, int a2, int a3) = (void*)sithSector_cogMsg_SendSyncThing_ADDR;
static void (*sithSector_cogMsg_SendTeleportThing)(sithThing *a1, int a2, int a3) = (void*)sithSector_cogMsg_SendTeleportThing_ADDR;
static void (*sithSector_cogMsg_SendDamage)(sithThing *a1, sithThing *a2, float a3, __int16 a4, int a5, int a6) = (void*)sithSector_cogMsg_SendDamage_ADDR;
static void (*sithSector_cogMsg_SendDestroyThing)(int a1, int a2) = (void*)sithSector_cogMsg_SendDestroyThing_ADDR;
static void (*sithSector_cogMsg_SendSyncThingFrame)(sithThing *a1, __int16 a2, float a3, int a4, int a5, int a6) = (void*)sithSector_cogMsg_SendSyncThingFrame_ADDR;
static void (*sithSector_ThingApplyForce)(sithThing *a1, rdVector3 *a2) = (void*)sithSector_ThingApplyForce_ADDR;

#endif // _SITHSECTOR_H
