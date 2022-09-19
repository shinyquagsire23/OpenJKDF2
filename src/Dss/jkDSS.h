#ifndef _DSS_JKDSS_H
#define _DSS_JKDSS_H

#include "types.h"

int jkDSS_Startup();
void jkDSS_Shutdown();
int jkDSS_idk4();
void jkDSS_playerconfig_idksync();
void jkDSS_player_thingsidkfunc();
void jkDSS_nullsub_2();
void jkDSS_Write();
void jkDSS_Load();

int jkDSS_wrap_SendSaberInfo_alt();
int jkDSS_SendSaberInfo_alt(sithThing *pPlayerThing, char *pModelStr, char *pSoundclassStr, char *pSideMatStr, char *pTipMatStr);

void jkDSS_SendSetSaberInfo(sithThing *thing);
int jkDSS_ProcessSetSaberInfo(sithCogMsg *msg);

void jkDSS_SendJKEnableSaber(sithThing *pPlayerThing);
int jkDSS_ProcessJKEnableSaber(sithCogMsg *msg);

void jkDSS_SendSetSaberInfo2(sithThing *thing);
int jkDSS_ProcessSetSaberInfo2(sithCogMsg *msg);

void jkDSS_SendJKSetWeaponMesh(sithThing *pPlayerThing);
int jkDSS_ProcessJKSetWeaponMesh(sithCogMsg *msg);

int jkDSS_SendHudTarget();
int jkDSS_ProcessHudTarget(sithCogMsg *msg);

void jkDSS_Sendx32(jkPlayerInfo *playerInfo);
int jkDSS_Processx32(sithCogMsg *msg);

int jkDSS_Sendx33(sithThing* pThing, rdKeyframe* pKeyframe, int a3, int16_t a4);
int jkDSS_Processx33(sithCogMsg *msg);

int jkDSS_Sendx36();
int jkDSS_Processx36_setwaggle(sithCogMsg *msg);

void jkDSS_SendJKPrintUniString(int a1, unsigned int a2);
int jkDSS_ProcessJKPrintUniString(sithCogMsg *msg);

void jkDSS_SendEndLevel();
int jkDSS_ProcessEndLevel(sithCogMsg *msg);

void jkDSS_SendSetTeam(int16_t teamNum);
int jkDSS_ProcessSetTeam(sithCogMsg *pMsg);

//static void (*jkDSS_Shutdown)() = (void*)jkDSS_Shutdown_ADDR;
//static int (*jkDSS_wrap_SendSaberInfo_alt)() = (void*)jkDSS_wrap_SendSaberInfo_alt_ADDR;
//static int (*jkDSS_SendEndLevel)() = (void*)jkDSS_SendEndLevel_ADDR;
//static int (*jkDSS_SendJKPrintUniString)(int a1, unsigned int a2) = (void*)jkDSS_SendJKPrintUniString_ADDR;
//static int (*jkDSS_SendJKSetWeaponMesh)(sithThing *a1) = (void*)jkDSS_SendJKSetWeaponMesh_ADDR;
//static int (*jkDSS_SendSetSaberInfo)(sithThing *a1) = (void*)jkDSS_SendSetSaberInfo_ADDR;
//static int (*jkDSS_SendSetSaberInfo2)(sithThing *a1) = (void*)jkDSS_SendSetSaberInfo2_ADDR;
//static int (*jkDSS_SendJKEnableSaber)(sithThing *player) = (void*)jkDSS_SendJKEnableSaber_ADDR;
//static void (*jkDSS_Sendx32)(jkPlayerInfo *playerInfo) = (void*)jkDSS_Sendx32_ADDR;

#endif // _DSS_JKDSS_H