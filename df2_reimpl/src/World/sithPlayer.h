#ifndef _SITHPLAYER_H
#define _SITHPLAYER_H

#include "World/sithInventory.h"

#define sithPlayer_Open_ADDR (0x004C8610)
#define sithPlayer_Close_ADDR (0x004C8620)
#define sithPlayer_NewEntry_ADDR (0x004C8670)
#define sithPlayer_Initialize_ADDR (0x004C8750)
#define sithPlayer_sub_4C87C0_ADDR (0x004C87C0)
#define sithPlayer_idk_ADDR (0x004C8810)
#define sithPlayer_ResetPalEffects_ADDR (0x004C88D0)
#define sithPlayer_sub_4C8910_ADDR (0x004C8910)
#define sithPlayer_Underwater_ADDR (0x004C89D0)
#define sithPlayer_AddDynamicTint_ADDR (0x004C8C10)
#define sithPlayer_AddDyamicAdd_ADDR (0x004C8CD0)
#define sithPlayer_SetScreenTint_ADDR (0x004C8D30)
#define sithPlayer_debug_loadauto_ADDR (0x004C8E10)
#define sithPlayer_debug_ToNextCheckpoint_ADDR (0x004C8EC0)
#define sithPlayer_sub_4C9060_ADDR (0x004C9060)
#define sithPlayer_FindPlayerByName_ADDR (0x004C90C0)
#define sithPlayer_DoesNetIdExist_ADDR (0x004C9120)
#define sithPlayer_sub_4C9150_ADDR (0x004C9150)
#define sithPlayer_HandleSentDeathPkt_ADDR (0x004C91E0)
#define sithPlayer_episode_getsomevar_ADDR (0x004C9350)
#define sithPlayer_episode_setsomevar_ADDR (0x004C9380)
#define sithPlayer_sub_4C93B0_ADDR (0x004C93B0)
#define sithPlayer_sub_4C93F0_ADDR (0x004C93F0)
#define sithPlayer_GetNum_ADDR (0x004C9420)
#define sithPlayer_GetNumidk_ADDR (0x004C9470)
#define sithPlayer_idk3_ADDR (0x004C94C0)
#define sithPlayer_idk2_ADDR (0x004C9500)


typedef struct sithThing sithThing;

typedef struct sithPlayerInfo
{
    wchar_t player_name[32];
    uint32_t field_40;
    uint32_t field_44;
    uint32_t field_48;
    uint32_t field_4C;
    uint32_t field_50;
    uint32_t field_54;
    uint32_t field_58;
    uint32_t field_5C;
    uint32_t field_60;
    uint32_t field_64;
    uint32_t field_68;
    uint32_t field_6C;
    uint32_t field_70;
    uint32_t field_74;
    uint32_t field_78;
    uint32_t field_7C;
    uint32_t flags;
    uint32_t net_id;
    sithItemInfo iteminfo[200];
    int curItem;
    int curWeapon;
    int curPower;
    sithItemInfo field_1354;
    sithThing* playerThing;
    uint32_t field_135C;
    uint32_t field_1360;
    uint32_t field_1364;
    uint32_t field_1368;
    uint32_t field_136C;
    uint32_t field_1370;
    uint32_t field_1374;
    uint32_t field_1378;
    uint32_t field_137C;
    uint32_t field_1380;
    uint32_t field_1384;
    uint32_t field_1388;
    uint32_t field_138C;
    uint32_t field_1390;
    uint32_t field_1394;
    uint32_t field_1398;
    uint32_t field_139C;
    uint32_t field_13A0;
    uint32_t field_13A4;
    uint32_t field_13A8;
    uint32_t score;
    uint32_t field_13B0;
} sithPlayerInfo;

void (*sithPlayer_AddDynamicTint)(float fR, float fG, float fB) = (void*)sithPlayer_AddDynamicTint_ADDR;
void (*sithPlayer_AddDyamicAdd)(int r, int g, int b) = (void*)sithPlayer_AddDyamicAdd_ADDR;

#endif // _SITHPLAYER_H
