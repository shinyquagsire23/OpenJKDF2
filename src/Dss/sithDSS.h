#ifndef _DSS_SITHDSS_H
#define _DSS_SITHDSS_H

#include "types.h"
#include "globals.h"

#define sithDSS_SurfaceStatus_ADDR (0x004F8F80)
#define sithDSS_ProcessSurfaceStatus_ADDR (0x004F9050)
#define sithDSS_SectorStatus_ADDR (0x004F9120)
#define sithDSS_ProcessSectorStatus_ADDR (0x004F91F0)
#define sithDSS_SectorFlags_ADDR (0x004F92E0)
#define sithDSS_ProcessSectorFlags_ADDR (0x004F9350)
#define sithDSS_AIStatus_ADDR (0x004F93B0)
#define sithDSS_ProcessAIStatus_ADDR (0x004F9640)
#define sithDSS_Inventory_ADDR (0x004F9900)
#define sithDSS_ProcessInventory_ADDR (0x004F99C0)
#define sithDSS_AnimStatus_ADDR (0x004F9A70)
#define sithDSS_ProcessAnimStatus_ADDR (0x004F9BA0)
#define sithDSS_PuppetStatus_ADDR (0x004F9D20)
#define sithDSS_ProcessPuppetStatus_ADDR (0x004F9E10)
#define sithDSS_SendSyncTimers_ADDR (0x004F9F20)
#define sithDSS_ProcessSyncTimers_ADDR (0x004F9FA0)
#define sithDSS_SyncCameras_ADDR (0x004F9FF0)
#define sithDSS_ProcessSyncCameras_ADDR (0x004FA130)
#define sithDSS_SendSyncPalEffects_ADDR (0x004FA240)
#define sithDSS_ProcessSyncPalEffects_ADDR (0x004FA350)
#define sithDSS_SyncGameState_ADDR (0x004FA420)
#define sithDSS_ProcessSyncGameState_ADDR (0x004FA5D0)

void sithDSS_SurfaceStatus(SithSurface *surface, int sendto_id, int mpFlags);
int sithDSS_ProcessSurfaceStatus(SithMessage *msg);
void sithDSS_SectorStatus(SithSector *sector, int sendto_id, int mpFlags);
int sithDSS_ProcessSectorStatus(SithMessage *msg);
void sithDSS_SectorFlags(SithSector *pSector, int sendto_id, int mpFlags);
int sithDSS_ProcessSectorFlags(SithMessage *msg);
void sithDSS_AIStatus(SithAIControlBlock *actor, int sendto_id, int idx);
int sithDSS_ProcessAIStatus(SithMessage *msg);
void sithDSS_Inventory(SithThing *thing, int binIdx, int sendto_id, int mpFlags);
int sithDSS_ProcessInventory(SithMessage *msg);
void sithDSS_AnimStatus(rdSurface *surface, int sendto_id, int mpFlags);
int sithDSS_ProcessAnimStatus(SithMessage *msg);
void sithDSS_PuppetStatus(SithThing *thing, int sendto_id, int mpFlags);
int sithDSS_ProcessPuppetStatus(SithMessage *msg);
void sithDSS_SyncTaskEvents(SithEvent *timer, int sendto_id, int mpFlags);
int sithDSS_ProcessSyncTaskEvents(SithMessage *msg);
void sithDSS_SendSyncPalEffects(int sendto_id, int mpFlags);
int sithDSS_ProcessSyncPalEffects(SithMessage *msg);
void sithDSS_SyncCameras(int sendto_id, int mpFlags);
int sithDSS_ProcessSyncCameras(SithMessage *msg);
void sithDSS_SyncGameState(int sendto_id, int mpFlags);
int sithDSS_ProcessSyncGameState(SithMessage *msg);


//static int (*_sithDSS_ProcessSyncPuppet)(SithMessage *msg) = (void*)sithDSS_ProcessPuppetStatus_ADDR;

#endif // _DSS_SITHDSS_H