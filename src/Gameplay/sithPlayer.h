#ifndef _SITHPLAYER_H
#define _SITHPLAYER_H

#include "types.h"
#include "globals.h"
#include "Gameplay/sithInventory.h"

#define sithPlayer_Open_ADDR (0x004C8610)
#define sithPlayer_Close_ADDR (0x004C8620)
#define sithPlayer_PlacePlayers_ADDR (0x004C8670)
#define sithPlayer_Startup_ADDR (0x004C8750)
#define sithPlayer_ShowPlayer_ADDR (0x004C87C0)
#define sithPlayer_SetLocalPlayer_ADDR (0x004C8810)
#define sithPlayer_ResetPalEffects_ADDR (0x004C88D0)
#define sithPlayer_Reset_ADDR (0x004C8910)
#define sithPlayer_Update_ADDR (0x004C89D0)
#define sithPlayer_AddDynamicTint_ADDR (0x004C8C10)
#define sithPlayer_AddDyamicAdd_ADDR (0x004C8CD0)
#define sithPlayer_SetScreenTint_ADDR (0x004C8D30)
#define sithPlayer_debug_loadauto_ADDR (0x004C8E10)
#define sithPlayer_NewPlayer_ADDR (0x004C8EC0)
#define sithPlayer_sub_4C9060_ADDR (0x004C9060)
#define sithPlayer_GetPlayerNumByName_ADDR (0x004C90C0)
#define sithPlayer_GetPlayerNum_ADDR (0x004C9120)
#define sithPlayer_PlayerKilledAction_ADDR (0x004C9150)
#define sithPlayer_KillPlayer_ADDR (0x004C91E0)
#define sithPlayer_GetInvItemAmount_ADDR (0x004C9350)
#define sithPlayer_SetInvItemAmount_ADDR (0x004C9380)
#define sithPlayer_sub_4C93B0_ADDR (0x004C93B0)
#define sithPlayer_sub_4C93F0_ADDR (0x004C93F0)
#define sithPlayer_GetThingPlayerNum_ADDR (0x004C9420)
#define sithPlayer_GetThingPlayerNumByIndex_ADDR (0x004C9470)
#define sithPlayer_SetInvItemAvailable_ADDR (0x004C94C0)
#define sithPlayer_idk2_ADDR (0x004C9500)

extern int sithPlayer_bNoClippingRend;

void sithPlayer_Startup(int idx);
void sithPlayer_Open();
void sithPlayer_Close();
void sithPlayer_PlacePlayers(SithWorld *pWorld);
int sithPlayer_GetBinItemActive(int binIdx);
int sithPlayer_IsInvItemAvailable(int binIndex);
void sithPlayer_SetBinItemActive(int binIdx, int bEnabled);
flex_t sithPlayer_GetInvItemAmount(int binIndex);
void sithPlayer_SetInvItemAmount(int binIndex, flex_t amount);
int sithPlayer_GetThingPlayerNum(SithThing *pThing);
void sithPlayer_ResetPalEffects();
void sithPlayer_SetLocalPlayer(int playerNum);
MATH_FUNC void sithPlayer_Update(SithPlayer *pPlayer, flex_t secDeltaTime);
void sithPlayer_debug_loadauto(SithThing *player);
void sithPlayer_SetScreenTint(flex_t tintR, flex_t tintG, flex_t tintB);
void sithPlayer_AddDynamicTint(flex_t fR, flex_t fG, flex_t fB);
void sithPlayer_AddDyamicAdd(int r, int g, int b);
int sithPlayer_sub_4C9060(SithThing *thing1, SithThing *thing2);
void sithPlayer_KillPlayer(SithThing *pPlayerThing);
void sithPlayer_PlayerKilledAction(SithThing *pPlayerThing, SithThing *pSrcThing);
int sithPlayer_GetThingPlayerNumByIndex(int thingIdx);
void sithPlayer_SetInvItemAvailable(int binIndex, int bAvailable);
void sithPlayer_Reset(unsigned int playerNum);
int sithPlayer_ShowPlayer(int playerNum, int id);
void sithPlayer_NewPlayer(SithThing *pPlayer);
uint32_t sithPlayer_GetPlayerNum(int playerId);
int sithPlayer_GetPlayerNumByName(wchar_t *pwName);

//static void (*sithPlayer_NewPlayer)(SithThing *player) = (void*)sithPlayer_NewPlayer_ADDR;
//static void (*sithPlayer_Startup)(int) = (void*)sithPlayer_Startup_ADDR;
//static void (*sithPlayer_Update)(SithPlayer *playerInfo, flex_t a2) = (void*)sithPlayer_Update_ADDR;
//static void (*sithPlayer_SetInvItemAvailable)(int a1, int a2) = (void*)sithPlayer_SetInvItemAvailable_ADDR;
//static double (*sithPlayer_GetInvItemAmount)(int idx) = (void*)sithPlayer_GetInvItemAmount_ADDR;
//static void (*sithPlayer_SetInvItemAmount)(int idx, flex_t a2) =(void*)sithPlayer_SetInvItemAmount_ADDR;
//static void (*sithPlayer_AddDynamicTint)(flex_t fR, flex_t fG, flex_t fB) = (void*)sithPlayer_AddDynamicTint_ADDR;
//static void (*sithPlayer_AddDyamicAdd)(int r, int g, int b) = (void*)sithPlayer_AddDyamicAdd_ADDR;
//static unsigned int (*sithPlayer_GetPlayerNum)(int id) = (void*)sithPlayer_GetPlayerNum_ADDR;
//static void (*sithPlayer_SetScreenTint)(flex_t r, flex_t g, flex_t b) = (void*)sithPlayer_SetScreenTint_ADDR;
//static void (*sithPlayer_SetLocalPlayer)(int) = (void*)sithPlayer_SetLocalPlayer_ADDR;
//static void (*sithPlayer_ResetPalEffects)() = (void*)sithPlayer_ResetPalEffects_ADDR;
//static void (*sithPlayer_KillPlayer)(SithThing *thing) = (void*)sithPlayer_KillPlayer_ADDR;
//static int (*sithPlayer_GetThingPlayerNumByIndex)(int a1) = (void*)sithPlayer_GetThingPlayerNumByIndex_ADDR;
//static void (*sithPlayer_PlayerKilledAction)(SithThing *a1, SithThing *a2) = (void*)sithPlayer_PlayerKilledAction_ADDR;

#endif // _SITHPLAYER_H
