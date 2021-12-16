#ifndef _SITHPLAYER_H
#define _SITHPLAYER_H

#include "types.h"
#include "globals.h"
#include "World/sithInventory.h"

#define sithPlayer_Open_ADDR (0x004C8610)
#define sithPlayer_Close_ADDR (0x004C8620)
#define sithPlayer_NewEntry_ADDR (0x004C8670)
#define sithPlayer_Initialize_ADDR (0x004C8750)
#define sithPlayer_sub_4C87C0_ADDR (0x004C87C0)
#define sithPlayer_idk_ADDR (0x004C8810)
#define sithPlayer_ResetPalEffects_ADDR (0x004C88D0)
#define sithPlayer_sub_4C8910_ADDR (0x004C8910)
#define sithPlayer_Tick_ADDR (0x004C89D0)
#define sithPlayer_AddDynamicTint_ADDR (0x004C8C10)
#define sithPlayer_AddDyamicAdd_ADDR (0x004C8CD0)
#define sithPlayer_SetScreenTint_ADDR (0x004C8D30)
#define sithPlayer_debug_loadauto_ADDR (0x004C8E10)
#define sithPlayer_debug_ToNextCheckpoint_ADDR (0x004C8EC0)
#define sithPlayer_sub_4C9060_ADDR (0x004C9060)
#define sithPlayer_FindPlayerByName_ADDR (0x004C90C0)
#define sithPlayer_ThingIdxToPlayerIdx_ADDR (0x004C9120)
#define sithPlayer_sub_4C9150_ADDR (0x004C9150)
#define sithPlayer_HandleSentDeathPkt_ADDR (0x004C91E0)
#define sithPlayer_GetBinAmt_ADDR (0x004C9350)
#define sithPlayer_SetBinAmt_ADDR (0x004C9380)
#define sithPlayer_sub_4C93B0_ADDR (0x004C93B0)
#define sithPlayer_sub_4C93F0_ADDR (0x004C93F0)
#define sithPlayer_GetNum_ADDR (0x004C9420)
#define sithPlayer_GetNumidk_ADDR (0x004C9470)
#define sithPlayer_SetBinCarries_ADDR (0x004C94C0)
#define sithPlayer_idk2_ADDR (0x004C9500)

void sithPlayer_Initialize(int idx);
void sithPlayer_Close();
void sithPlayer_NewEntry(sithWorld *world);
float sithPlayer_GetBinAmt(int idx);
void sithPlayer_SetBinAmt(int idx, float amt);
int sithPlayer_GetNum(sithThing *player);
void sithPlayer_ResetPalEffects();
void sithPlayer_idk(int idx);
void sithPlayer_Tick(sithPlayerInfo *playerInfo, float a2);
void sithPlayer_debug_loadauto(sithThing *player);
void sithPlayer_SetScreenTint(float tintR, float tintG, float tintB);
void sithPlayer_AddDynamicTint(float fR, float fG, float fB);
void sithPlayer_AddDyamicAdd(int r, int g, int b);
int sithPlayer_sub_4C9060(sithThing *thing1, sithThing *thing2);
void sithPlayer_HandleSentDeathPkt(sithThing *thing);
void sithPlayer_sub_4C9150(sithThing *player, sithThing *killedBy);
int sithPlayer_GetNumidk(int a1);
void sithPlayer_SetBinCarries(int binIdx, int bCarries);

static void (*sithPlayer_debug_ToNextCheckpoint)(sithThing *player) = (void*)sithPlayer_debug_ToNextCheckpoint_ADDR;
//static void (*sithPlayer_Initialize)(int) = (void*)sithPlayer_Initialize_ADDR;
//static void (*sithPlayer_Tick)(sithPlayerInfo *playerInfo, float a2) = (void*)sithPlayer_Tick_ADDR;
//static void (*sithPlayer_SetBinCarries)(int a1, int a2) = (void*)sithPlayer_SetBinCarries_ADDR;
//static double (*sithPlayer_GetBinAmt)(int idx) = (void*)sithPlayer_GetBinAmt_ADDR;
//static void (*sithPlayer_SetBinAmt)(int idx, float a2) =(void*)sithPlayer_SetBinAmt_ADDR;
//static void (*sithPlayer_AddDynamicTint)(float fR, float fG, float fB) = (void*)sithPlayer_AddDynamicTint_ADDR;
//static void (*sithPlayer_AddDyamicAdd)(int r, int g, int b) = (void*)sithPlayer_AddDyamicAdd_ADDR;
static unsigned int (*sithPlayer_ThingIdxToPlayerIdx)(int id) = (void*)sithPlayer_ThingIdxToPlayerIdx_ADDR;
//static void (*sithPlayer_SetScreenTint)(float r, float g, float b) = (void*)sithPlayer_SetScreenTint_ADDR;
//static void (*sithPlayer_idk)(int) = (void*)sithPlayer_idk_ADDR;
//static void (*sithPlayer_ResetPalEffects)() = (void*)sithPlayer_ResetPalEffects_ADDR;
//static void (*sithPlayer_HandleSentDeathPkt)(sithThing *thing) = (void*)sithPlayer_HandleSentDeathPkt_ADDR;
//static int (*sithPlayer_GetNumidk)(int a1) = (void*)sithPlayer_GetNumidk_ADDR;
//static void (*sithPlayer_sub_4C9150)(sithThing *a1, sithThing *a2) = (void*)sithPlayer_sub_4C9150_ADDR;

#endif // _SITHPLAYER_H
