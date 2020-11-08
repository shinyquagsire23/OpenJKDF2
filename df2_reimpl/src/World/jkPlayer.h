#ifndef _JK_PLAYER_H
#define _JK_PLAYER_H

#include "Primitives/rdPolyLine.h"
#include "Primitives/rdMatrix.h"
#include "Engine/rdThing.h"
#include "World/sithPlayer.h"

#define jkPlayer_renderSaberWeaponMesh_ADDR (0x405520)
#define jkPlayer_renderSaberTwinkle_ADDR (0x405720)

enum JKFLAG
{
    JKFLAG_SABERON = 1,
    JKFLAG_DUALSABERS = 0x10,
    JKFLAG_PERSUASION = 0x20
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
    uint32_t field_1A8;
    uint32_t field_1AC;
    uint32_t field_1B0;
    uint32_t field_1B4;
    uint32_t field_1B8;
    uint32_t field_1BC;
    uint32_t field_1C0;
    uint32_t field_1C4;
    uint32_t field_1C8;
    uint32_t field_1CC;
    uint32_t field_1D0;
    uint32_t numIdks;
    void* idk;
    uint32_t field_1DC;
    uint32_t field_1E0;
    uint32_t field_1E4;
    uint32_t field_1E8;
    uint32_t field_1EC;
    uint32_t field_1F0;
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

#define bShowInvisibleThings (*(int*)0x8EE640)
#define playerThingIdx (*(int*)0x83199C)
#define selfPlayerInfo (*(sithPlayerInfo **)0x8319A8)
#define playerThings ((jkSaberInfo*)0x85B580)
#define jkSaber_rotateMat (*(rdMatrix34*)0x85FA80)

void jkPlayer_renderSaberWeaponMesh(sithThing *a1);

static void (__cdecl *jkPlayer_renderSaberTwinkle)(sithThing *a1) = (void*)jkPlayer_renderSaberTwinkle_ADDR;

#endif // _JK_PLAYER_H
