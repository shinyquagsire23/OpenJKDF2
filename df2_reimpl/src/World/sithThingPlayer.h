#ifndef _SITHTHINGPLAYER_H
#define _SITHTHINGPLAYER_H

#define sithThingPlayer_cogMsg_SendSendTrigger_ADDR (0x004FC520)
#define sithThingPlayer_cogMsg_HandleSendTrigger_ADDR (0x004FC630)
#define sithThingPlayer_cogMsg_SendSyncCog_ADDR (0x004FC770)
#define sithThingPlayer_cogMsg_HandleSyncCog_ADDR (0x004FC8A0)

typedef struct sithCog sithCog;

int sithThingPlayer_cogMsg_SendSendTrigger(sithCog *a1, int a2, int a3, int a4, int a5, int a6, int a7, float a8_, float a8, float a9, float a10, int a11);

//static int (*sithThingPlayer_cogMsg_SendSendTrigger)(sithCog* a1, int a2, int a3, int a4, int a5, int a6, int a7, float a8_, float a8, float a9, float a10, int a11) = (void*)sithThingPlayer_cogMsg_SendSendTrigger_ADDR;
static int (*sithThingPlayer_cogMsg_SendSyncCog)(sithCog *cog, int sendto_id, int mpFlags) = (void*)sithThingPlayer_cogMsg_SendSyncCog_ADDR;

#endif // _SITHTHINGPLAYER_H
