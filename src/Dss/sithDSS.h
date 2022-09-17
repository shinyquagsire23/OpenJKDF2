#ifndef _DSS_SITHDSS_H
#define _DSS_SITHDSS_H

#include "types.h"
#include "globals.h"

#define sithDSS_SendSurfaceStatus_ADDR (0x004F8F80)
#define sithDSS_ProcessSurfaceStatus_ADDR (0x004F9050)
#define sithDSS_SendSectorStatus_ADDR (0x004F9120)
#define sithDSS_ProcessSectorStatus_ADDR (0x004F91F0)
#define sithDSS_SendSectorFlags_ADDR (0x004F92E0)
#define sithDSS_ProcessSectorFlags_ADDR (0x004F9350)
#define sithDSS_SendAIStatus_ADDR (0x004F93B0)
#define sithDSS_ProcessAIStatus_ADDR (0x004F9640)
#define sithDSS_SendInventory_ADDR (0x004F9900)
#define sithDSS_ProcessInventory_ADDR (0x004F99C0)
#define sithDSS_SendSurface_ADDR (0x004F9A70)
#define sithDSS_ProcessSurface_ADDR (0x004F9BA0)
#define sithDSS_SendSyncPuppet_ADDR (0x004F9D20)
#define sithDSS_ProcessSyncPuppet_ADDR (0x004F9E10)
#define sithDSS_SendSyncTimers_ADDR (0x004F9F20)
#define sithDSS_ProcessSyncTimers_ADDR (0x004F9FA0)
#define sithDSS_SendSyncCameras_ADDR (0x004F9FF0)
#define sithDSS_ProcessSyncCameras_ADDR (0x004FA130)
#define sithDSS_SendSyncPalEffects_ADDR (0x004FA240)
#define sithDSS_ProcessSyncPalEffects_ADDR (0x004FA350)
#define sithDSS_SendMisc_ADDR (0x004FA420)
#define sithDSS_ProcessMisc_ADDR (0x004FA5D0)

void sithDSS_SendSurfaceStatus(sithSurface *surface, int sendto_id, int mpFlags);
int sithDSS_ProcessSurfaceStatus(sithCogMsg *msg);
void sithDSS_SendSectorStatus(sithSector *sector, int sendto_id, int mpFlags);
int sithDSS_ProcessSectorStatus(sithCogMsg *msg);
void sithDSS_SendSectorFlags(sithSector *pSector, int sendto_id, int mpFlags);
int sithDSS_ProcessSectorFlags(sithCogMsg *msg);
void sithDSS_SendAIStatus(sithActor *actor, int sendto_id, int idx);
int sithDSS_ProcessAIStatus(sithCogMsg *msg);
void sithDSS_SendInventory(sithThing *thing, int binIdx, int sendto_id, int mpFlags);
int sithDSS_ProcessInventory(sithCogMsg *msg);
void sithDSS_SendSurface(rdSurface *surface, int sendto_id, int mpFlags);
int sithDSS_ProcessSurface(sithCogMsg *msg);
void sithDSS_SendSyncPuppet(sithThing *thing, int sendto_id, int mpFlags);
int sithDSS_ProcessSyncPuppet(sithCogMsg *msg);
void sithDSS_SendSyncEvents(sithEvent *timer, int sendto_id, int mpFlags);
int sithDSS_ProcessSyncEvents(sithCogMsg *msg);
void sithDSS_SendSyncPalEffects(int sendto_id, int mpFlags);
int sithDSS_ProcessSyncPalEffects(sithCogMsg *msg);
void sithDSS_SendSyncCameras(int sendto_id, int mpFlags);
int sithDSS_ProcessSyncCameras(sithCogMsg *msg);
void sithDSS_SendMisc(int sendto_id, int mpFlags);
int sithDSS_ProcessMisc(sithCogMsg *msg);


static int (*_sithDSS_ProcessSyncPuppet)(sithCogMsg *msg) = (void*)sithDSS_ProcessSyncPuppet_ADDR;

#endif // _DSS_SITHDSS_H