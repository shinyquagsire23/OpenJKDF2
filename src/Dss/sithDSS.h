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

void sithDSS_SurfaceStatus(SithSurface *pSurf, int idTo, int outstream);
int sithDSS_ProcessSurfaceStatus(SithMessage *pMsg);
void sithDSS_SectorStatus(SithSector *pSector, int sendto_id, int outstream);
int sithDSS_ProcessSectorStatus(SithMessage *pMsg);
void sithDSS_SectorFlags(SithSector *pSector, int idTo, int outstream);
int sithDSS_ProcessSectorFlags(SithMessage *pMsg);
void sithDSS_AIStatus(SithAIControlBlock *pLocal, int idTo, int outstream);
int sithDSS_ProcessAIStatus(SithMessage *pMsg);
void sithDSS_Inventory(SithThing *pThing, int inventoryId, int idTo, int outstream);
int sithDSS_ProcessInventory(SithMessage *pMsg);
void sithDSS_AnimStatus(rdSurface *pAnim, int idTo, int outstream);
int sithDSS_ProcessAnimStatus(SithMessage *pMsg);
void sithDSS_PuppetStatus(SithThing *pThing, int idTo, int outstream);
int sithDSS_ProcessPuppetStatus(SithMessage *pMsg);
void sithDSS_SyncTaskEvents(SithEvent *pEvent, int idTo, int outstream);
int sithDSS_ProcessSyncTaskEvents(SithMessage *pMsg);
void sithDSS_SendSyncPalEffects(int sendto_id, int mpFlags);
int sithDSS_ProcessSyncPalEffects(SithMessage *msg);
void sithDSS_SyncCameras(int idTo, int outstream);
int sithDSS_ProcessSyncCameras(SithMessage *pMsg);
void sithDSS_SyncGameState(int idTo, int outstream);
int sithDSS_ProcessSyncGameState(SithMessage *pMsg);


//static int (*_sithDSS_ProcessSyncPuppet)(SithMessage *msg) = (void*)sithDSS_ProcessPuppetStatus_ADDR;

#endif // _DSS_SITHDSS_H