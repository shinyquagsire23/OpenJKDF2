#ifndef _JK_PLAYER_H
#define _JK_PLAYER_H

#include "Primitives/rdPolyLine.h"
#include "Primitives/rdMatrix.h"
#include "Engine/rdThing.h"
#include "World/sithPlayer.h"

#define jkPlayer_LoadAutosave_ADDR (0x00404600)
#define jkPlayer_LoadSave_ADDR (0x00404660)
#define jkPlayer_Startup_ADDR (0x00404680)
#define jkPlayer_Shutdown_ADDR (0x004046A0)
#define jkPlayer_nullsub_29_ADDR (0x00404740)
#define jkPlayer_nullsub_30_ADDR (0x00404750)
#define jkPlayer_InitSaber_ADDR (0x00404760)
#define jkPlayer_InitThings_ADDR (0x00404830)
#define jkPlayer_nullsub_1_ADDR (0x00404900)
#define jkPlayer_CreateConf_ADDR (0x00404910)
#define jkPlayer_WriteConf_ADDR (0x00404D20)
#define jkPlayer_ReadConf_ADDR (0x00404EA0)
#define jkPlayer_SetPovModel_ADDR (0x00405190)
#define jkPlayer_DrawPov_ADDR (0x004051E0)
#define jkPlayer_renderSaberWeaponMesh_ADDR (0x00405520)
#define jkPlayer_renderSaberTwinkle_ADDR (0x00405720)
#define jkPlayer_SetWaggle_ADDR (0x00405930)
#define jkPlayer_SanitizeName_ADDR (0x00405980)
#define jkPlayer_wchar_to_char_helper_ADDR (0x00405B30)
#define jkPlayer_SetPlayerInfoidk_ADDR (0x00405B70)
#define jkPlayer_SetPlayerstridk_ADDR (0x00405C10)
#define jkPlayer_GetPlayerInfoidk_ADDR (0x00405C30)
#define jkPlayer_sub_405CC0_ADDR (0x00405CC0)
#define jkPlayer_GetChoice_ADDR (0x00405CE0)
#define jkPlayer_CalcDarkLightBalance_ADDR (0x00405CF0)
#define jkPlayer_net_thingstuff_ADDR (0x00405E30)
#define jkPlayer_MPCParse_ADDR (0x00405FB0)
#define jkPlayer_MPCWrite_ADDR (0x00406270)
#define jkPlayer_DebugWrite_ADDR (0x004063D0)
#define jkPlayer_DebugRead_ADDR (0x00406440)
#define jkPlayer_sub_4064E0_ADDR (0x004064E0)
#define jkPlayer_GetAlignment_ADDR (0x00406570)
#define jkPlayer_SetAccessiblePowers_ADDR (0x00406860)
#define jkPlayer_sub_406990_ADDR (0x00406990)
#define jkPlayer_WriteConfSwap_ADDR (0x004069B0)
#define jkPlayer_WriteCutsceneConf_ADDR (0x00406C00)
#define jkPlayer_ReadCutsceneConf_ADDR (0x00406C70)
#define jkPlayer_sub_406D50_ADDR (0x00406D50)
#define jkPlayer_sub_406FE0_ADDR (0x00406FE0)
#define jkPlayer_SetProtectionDeadlysight_ADDR (0x00407040)
#define jkPlayer_sub_407210_ADDR (0x00407210)
#define jkPlayer_WriteOptionsConf_ADDR (0x00407320)
#define jkPlayer_ReadOptionsConf_ADDR (0x004073C0)
#define jkPlayer_GetJediRank_ADDR (0x004074D0)
#define jkPlayer_SetRank_ADDR (0x004074E0)

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
    rdThing povModel;
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

#define jkPlayer_numOtherThings (*(int*)0x0085FF44)
#define jkPlayer_numThings (*(int*)0x0085B560)
#define jkPlayer_otherThings ((jkSaberInfo*)0x008592E0)
#define jkPlayer_dword_525470 (*(int*)0x525470)
#define bShowInvisibleThings (*(int*)0x8EE640)
#define playerThingIdx (*(int*)0x83199C)
#define jkPlayer_maxPlayers (*(int*)0x8319A0)
#define g_localPlayerThing (*(sithThing**)0x8319A4)
#define g_selfPlayerInfo (*(sithPlayerInfo **)0x8319A8)
#define playerThings ((jkSaberInfo*)0x85B580)
#define jkSaber_rotateMat (*(rdMatrix34*)0x85FA80)


#define jkPlayer_setRotateOverlayMap (*(int*)0x00860764)
#define jkPlayer_setDrawStatus (*(int*)0x00860768)
#define jkPlayer_setCrosshair (*(int*)0x0086076C)
#define jkPlayer_setSaberCam (*(int*)0x00860770)
#define jkPlayer_setFullSubtitles (*(int*)0x00860774)
#define jkPlayer_setDisableCutscenes (*(int*)0x00860778)
#define jkPlayer_aCutsceneVal ((int*)0x0085FAC0)
#define jkPlayer_cutscenePath ((char*)0x0085FB40)
#define jkPlayer_setNumCutscenes (*(int*)0x0085FF40)
#define jkPlayer_numOtherThings (*(int*)0x0085FF44)
#define jkPlayer_setDiff (*(int*)0x008EE670)

int jkPlayer_LoadAutosave();
int jkPlayer_LoadSave(char *path);
void jkPlayer_Startup();
void jkPlayer_Shutdown();
void jkPlayer_nullsub_29();
void jkPlayer_nullsub_30();
void jkPlayer_InitSaber();
void jkPlayer_InitThings();
void jkPlayer_nullsub_1();
void jkPlayer_CreateConf(wchar_t *name);
void jkPlayer_WriteConf(wchar_t *name);
int jkPlayer_ReadConf(wchar_t *name);
void jkPlayer_SetPovModel(jkSaberInfo *info, rdModel3 *model);
void jkPlayer_renderSaberWeaponMesh(sithThing *a1);

//static void (*jkPlayer_InitThings)() = (void*)jkPlayer_InitThings_ADDR;
//static int (*jkPlayer_ReadConf)(wchar_t *a1) = (void*)jkPlayer_ReadConf_ADDR;
static int (*jkPlayer_SanitizeName)(wchar_t *a1) = (void*)jkPlayer_SanitizeName_ADDR;
static void (*jkPlayer_SetAccessiblePowers)(int rank) = (void*)jkPlayer_SetAccessiblePowers_ADDR;
static int (*jkPlayer_SetProtectionDeadlysight)() = (void*)jkPlayer_SetProtectionDeadlysight_ADDR;
static int (*jkPlayer_GetAlignment)() = (void*)jkPlayer_GetAlignment_ADDR;
static int (*jkPlayer_GetJediRank)() = (void*)jkPlayer_GetJediRank_ADDR;
static int (*jkPlayer_sub_407210)() = (void*)jkPlayer_sub_407210_ADDR;
static void (*jkPlayer_sub_405CC0)(signed int a1) = (void*)jkPlayer_sub_405CC0_ADDR;
static double (*jkPlayer_CalcDarkLightBalance)(float a1) = (void*)jkPlayer_CalcDarkLightBalance_ADDR;
static void (__cdecl *jkPlayer_renderSaberTwinkle)(sithThing *a1) = (void*)jkPlayer_renderSaberTwinkle_ADDR;

#endif // _JK_PLAYER_H
