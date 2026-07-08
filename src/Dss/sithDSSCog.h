#ifndef _SITHDSSCOG_H
#define _SITHDSSCOG_H

#include "types.h"
#include "globals.h"

#define sithDSSCog_SendMessage_ADDR (0x004FC520)
#define sithDSSCog_ProcessMessage_ADDR (0x004FC630)
#define sithDSSCog_SyncCogState_ADDR (0x004FC770)
#define sithDSSCog_ProcessCogState_ADDR (0x004FC8A0)

int sithDSSCog_SendMessage(sithCog *a1, int a2, int a3, int a4, int a5, int a6, int a7, flex32_t a8_, flex32_t a8, flex32_t a9, flex32_t a10, int a11);
int sithDSSCog_ProcessMessage(sithCogMsg *in_netMsg);
int sithDSSCog_SyncCogState(sithCog *cog, int sendto_id, int mpFlags);
int sithDSSCog_ProcessCogState(sithCogMsg *msg);

//static int (*sithDSSCog_SendMessage)(sithCog* a1, int a2, int a3, int a4, int a5, int a6, int a7, flex32_t a8_, flex32_t a8, flex32_t a9, flex32_t a10, int a11) = (void*)sithDSSCog_SendMessage_ADDR;
//static int (*sithDSSCog_SyncCogState)(sithCog *cog, int sendto_id, int mpFlags) = (void*)sithDSSCog_SyncCogState_ADDR;

#endif // _SITHDSSCOG_H
