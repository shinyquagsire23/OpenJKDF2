#ifndef _DSS_SITHDSS_H
#define _DSS_SITHDSS_H

#include "types.h"
#include "globals.h"

#define sithDSS_SendSyncSurface_ADDR (0x004F8F80)
#define sithDSS_HandleSyncSurface_ADDR (0x004F9050)
#define sithDSS_SendSyncSector_ADDR (0x004F9120)
#define sithDSS_HandleSyncSector_ADDR (0x004F91F0)
#define sithDSS_SendSyncSectorAlt_ADDR (0x004F92E0)
#define sithDSS_HandleSyncSectorAlt_ADDR (0x004F9350)
#define sithDSS_SendSyncAI_ADDR (0x004F93B0)
#define sithDSS_HandleSyncAI_ADDR (0x004F9640)
#define sithDSS_SendSyncItemDesc_ADDR (0x004F9900)
#define sithDSS_HandleSyncItemDesc_ADDR (0x004F99C0)
#define sithDSS_SendStopAnim_ADDR (0x004F9A70)
#define sithDSS_HandleStopAnim_ADDR (0x004F9BA0)
#define sithDSS_SendSyncPuppet_ADDR (0x004F9D20)
#define sithDSS_HandleSyncPuppet_ADDR (0x004F9E10)
#define sithDSS_SendSyncTimers_ADDR (0x004F9F20)
#define sithDSS_HandleSyncTimers_ADDR (0x004F9FA0)
#define sithDSS_SendSyncCameras_ADDR (0x004F9FF0)
#define sithDSS_HandleSyncCameras_ADDR (0x004FA130)
#define sithDSS_SendSyncPalEffects_ADDR (0x004FA240)
#define sithDSS_HandleSyncPalEffects_ADDR (0x004FA350)
#define sithDSS_SendMisc_ADDR (0x004FA420)
#define sithDSS_HandleMisc_ADDR (0x004FA5D0)

void sithDSS_SendSyncSurface(sithSurface *surface, int sendto_id, int mpFlags);
int sithDSS_HandleSyncSurface(sithCogMsg *msg);
void sithDSS_SendSyncSector(sithSector *sector, int sendto_id, int mpFlags);
int sithDSS_HandleSyncSector(sithCogMsg *msg);
void sithDSS_SendSyncSectorAlt(sithSector *pSector, int sendto_id, int mpFlags);
int sithDSS_HandleSyncSectorAlt(sithCogMsg *msg);
void sithDSS_SendSyncAI(sithActor *actor, int sendto_id, int idx);
int sithDSS_HandleSyncAI(sithCogMsg *msg);
void sithDSS_SendSyncItemDesc(sithThing *thing, int binIdx, int sendto_id, int mpFlags);
int sithDSS_HandleSyncItemDesc(sithCogMsg *msg);
void sithDSS_SendStopAnim(rdSurface *surface, int sendto_id, int mpFlags);
int sithDSS_HandleStopAnim(sithCogMsg *msg);
void sithDSS_SendSyncPuppet(sithThing *thing, int sendto_id, int mpFlags);
int sithDSS_HandleSyncPuppet(sithCogMsg *msg);
void sithDSS_SendSyncEvents(sithEvent *timer, int sendto_id, int mpFlags);
int sithDSS_HandleSyncEvents(sithCogMsg *msg);
void sithDSS_SendSyncPalEffects(int sendto_id, int mpFlags);
int sithDSS_HandleSyncPalEffects(sithCogMsg *msg);
void sithDSS_SendSyncCameras(int sendto_id, int mpFlags);
int sithDSS_HandleSyncCameras(sithCogMsg *msg);
void sithDSS_SendMisc(int sendto_id, int mpFlags);
int sithDSS_HandleMisc(sithCogMsg *msg);


static int (*_sithDSS_HandleSyncPuppet)(sithCogMsg *msg) = (void*)sithDSS_HandleSyncPuppet_ADDR;

#endif // _DSS_SITHDSS_H