#ifndef _SITHPLAYER_H
#define _SITHPLAYER_H

#include "World/sithInventory.h"

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

#endif // _SITHPLAYER_H
