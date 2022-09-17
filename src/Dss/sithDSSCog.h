#ifndef _SITHDSSCOG_H
#define _SITHDSSCOG_H

#include "types.h"
#include "globals.h"

#define sithDSSCog_SendSendTrigger_ADDR (0x004FC520)
#define sithDSSCog_ProcessSendTrigger_ADDR (0x004FC630)
#define sithDSSCog_SendSyncCog_ADDR (0x004FC770)
#define sithDSSCog_ProcessSyncCog_ADDR (0x004FC8A0)

int sithDSSCog_SendSendTrigger(sithCog *a1, int a2, int a3, int a4, int a5, int a6, int a7, float a8_, float a8, float a9, float a10, int a11);
int sithDSSCog_ProcessSendTrigger(sithCogMsg *in_netMsg);
int sithDSSCog_SendSyncCog(sithCog *cog, int sendto_id, int mpFlags);
int sithDSSCog_ProcessSyncCog(sithCogMsg *msg);

//static int (*sithDSSCog_SendSendTrigger)(sithCog* a1, int a2, int a3, int a4, int a5, int a6, int a7, float a8_, float a8, float a9, float a10, int a11) = (void*)sithDSSCog_SendSendTrigger_ADDR;
//static int (*sithDSSCog_SendSyncCog)(sithCog *cog, int sendto_id, int mpFlags) = (void*)sithDSSCog_SendSyncCog_ADDR;

#endif // _SITHDSSCOG_H
