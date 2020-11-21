#ifndef _JK_PLAYER_H
#define _JK_PLAYER_H

#include "Primitives/rdPolyLine.h"
#include "Primitives/rdMatrix.h"
#include "Engine/rdThing.h"
#include "World/sithPlayer.h"

#define jkPlayer_renderSaberWeaponMesh_ADDR (0x405520)
#define jkPlayer_renderSaberTwinkle_ADDR (0x405720)
#define jkPlayer_sub_405CF0_ADDR (0x405CF0)
#define jkPlayer_sub_405CC0_ADDR (0x405CC0)
#define jkPlayer_sub_407040_ADDR (0x407040)
#define jkPlayer_GetJediRank_ADDR (0x4074D0)
#define jkPlayer_sub_407210_ADDR (0x407210)
#define jkPlayer_SetAccessiblePowers_ADDR (0x406860)
#define jkPlayer_SetProtectionDeadlysight_ADDR (0x407040)
#define jkPlayer_GetAlignment_ADDR (0x406570)

typedef struct sithSurface sithSurface;

enum JKFLAG
{
    JKFLAG_SABERON = 1,
    JKFLAG_SABERNODAMAGE = 2,
    JKFLAG_SABEREXTEND = 4,
    JKFLAG_SABERRETRACT = 8,
    JKFLAG_DUALSABERS = 0x10,
    JKFLAG_PERSUASION = 0x20,
    JKFLAG_SABERFORCEON = 0x80
};

typedef struct jkSaberInfo
{
    uint32_t field_0;
    rdThing rd_thing;
    rdThing field_4C;
    float length;
    uint32_t field_98;
    rdPolyLine polyline;
    rdThing polylineThing;
    uint32_t field_1A4;
    float damage;
    uint32_t field_1AC;
    uint32_t field_1B0;
    uint32_t field_1B4;
    uint32_t numDamagedThings;
    sithThing* damagedThings[6];
    uint32_t numDamagedSurfaces;
    sithSurface* damagedSurfaces[6];
    uint32_t lastSparkSpawnMs;
    sithThing* wall_sparks;
    sithThing* blood_sparks;
    sithThing* saber_sparks;
    sithThing* spawnedSparks;
    uint32_t field_204;
    uint32_t field_208;
    uint32_t field_20C;
    uint32_t field_210;
    uint32_t field_214;
    uint32_t field_218;
    uint32_t field_21C;
    uint32_t field_220;
    uint32_t field_224;
} jkSaberInfo;

#define jkPlayer_playerInfos ((sithPlayerInfo*)0x008C4CA0)
#define jkPlayer_playerShortName ((wchar_t*)0x08EC320)

#define bShowInvisibleThings (*(int*)0x8EE640)
#define playerThingIdx (*(int*)0x83199C)
#define g_localPlayerThing (*(sithThing**)0x8319A4)
#define g_selfPlayerInfo (*(sithPlayerInfo **)0x8319A8)
#define playerThings ((jkSaberInfo*)0x85B580)
#define jkSaber_rotateMat (*(rdMatrix34*)0x85FA80)

void jkPlayer_renderSaberWeaponMesh(sithThing *a1);

static void (*jkPlayer_SetAccessiblePowers)(int rank) = (void*)jkPlayer_SetAccessiblePowers_ADDR;
static int (*jkPlayer_SetProtectionDeadlysight)() = (void*)jkPlayer_SetProtectionDeadlysight_ADDR;
static int (*jkPlayer_GetAlignment)() = (void*)jkPlayer_GetAlignment_ADDR;
static int (*jkPlayer_sub_407040)() = (void*)jkPlayer_sub_407040_ADDR;
static int (*jkPlayer_GetJediRank)() = (void*)jkPlayer_GetJediRank_ADDR;
static int (*jkPlayer_sub_407210)() = (void*)jkPlayer_sub_407210_ADDR;
static void (*jkPlayer_sub_405CC0)(signed int a1) = (void*)jkPlayer_sub_405CC0_ADDR;
static double (*jkPlayer_sub_405CF0)(float a1) = (void*)jkPlayer_sub_405CF0_ADDR;
static void (__cdecl *jkPlayer_renderSaberTwinkle)(sithThing *a1) = (void*)jkPlayer_renderSaberTwinkle_ADDR;

#endif // _JK_PLAYER_H
