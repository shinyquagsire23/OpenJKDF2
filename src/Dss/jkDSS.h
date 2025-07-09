#ifndef _DSS_JKDSS_H
#define _DSS_JKDSS_H

#include "types.h"

#define jkDSS_Startup_ADDR (0x0040C040)
#define jkDSS_Shutdown_ADDR (0x0040C140)
#define jkDSS_idk4_ADDR (0x0040C150)
#define jkDSS_playerconfig_idksync_ADDR (0x0040C220)
#define jkDSS_player_thingsidkfunc_ADDR (0x0040C370)
#define jkDSS_nullsub_2_ADDR (0x0040C390)
#define jkDSS_Write_ADDR (0x0040C3A0)
#define jkDSS_Load_ADDR (0x0040C3C0)
#define jkDSS_wrap_SendSaberInfo_alt_ADDR (0x0040C400)
#define jkDSS_SendSaberInfo_alt_ADDR (0x0040C430)
#define jkDSS_SendSetSaberInfo_ADDR (0x0040C500)
#define jkDSS_ProcessSetSaberInfo_ADDR (0x0040C5C0)
#define jkDSS_SendJKEnableSaber_ADDR (0x0040C840)
#define jkDSS_ProcessJKEnableSaber_ADDR (0x0040C8B0)
#define jkDSS_SendSetSaberInfo2_ADDR (0x0040C920)
#define jkDSS_ProcessSetSaberInfo2_ADDR (0x0040CB00)
#define jkDSS_SendJKSetWeaponMesh_ADDR (0x0040CCB0)
#define jkDSS_ProcessJKSetWeaponMesh_ADDR (0x0040CD30)
#define jkDSS_SendHudTarget_ADDR (0x0040CDB0)
#define jkDSS_ProcessHudTarget_ADDR (0x0040CE40)
#define jkDSS_Sendx32_ADDR (0x0040CEB0)
#define jkDSS_Processx32_ADDR (0x0040CFA0)
#define jkDSS_Sendx33_ADDR (0x0040D080)
#define jkDSS_Processx33_ADDR (0x0040D0F0)
#define jkDSS_Sendx36_ADDR (0x0040D190)
#define jkDSS_Processx36_setwaggle_ADDR (0x0040D1F0)
#define jkDSS_SendJKPrintUniString_ADDR (0x0040D230)
#define jkDSS_ProcessJKPrintUniString_ADDR (0x0040D2B0)
#define jkDSS_SendEndLevel_ADDR (0x0040D310)
#define jkDSS_ProcessEndLevel_ADDR (0x0040D3A0)
#define jkDSS_SendSetTeam_ADDR (0x0040D3E0)
#define jkDSS_ProcessSetTeam_ADDR (0x0040D450)

int jkDSS_Startup();
int jkDSS_JKM1(int32_t unused1, sithEventInfo* unused2); // MOTS added
void jkDSS_Shutdown();
int jkDSS_idk4();
void jkDSS_playerconfig_idksync();
void jkDSS_player_thingsidkfunc();
void jkDSS_nullsub_2();
void jkDSS_Write();
void jkDSS_Load();

int jkDSS_SendSaberInfo_alt_Mots(sithThing *pPlayerThing, char *pModelStr, char *pSoundclassStr, char *pSideMatStr, char *pTipMatStr, int personality);

int jkDSS_wrap_SendSaberInfo_alt();
int jkDSS_SendSaberInfo_alt(sithThing *pPlayerThing, char *pModelStr, char *pSoundclassStr, char *pSideMatStr, char *pTipMatStr);

void jkDSS_SendSetSaberInfoMots(sithThing *thing, int personality);
int jkDSS_ProcessSetSaberInfoMots(sithCogMsg *msg);

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

void jkDSS_SendJKPrintUniString(int a1, uint32_t a2);
int jkDSS_ProcessJKPrintUniString(sithCogMsg *msg);

void jkDSS_SendEndLevel();
int jkDSS_ProcessEndLevel(sithCogMsg *msg);

void jkDSS_SendSetTeam(int16_t teamNum);
int jkDSS_ProcessSetTeam(sithCogMsg *pMsg);

//static void (*jkDSS_Shutdown)() = (void*)jkDSS_Shutdown_ADDR;
//static int (*jkDSS_wrap_SendSaberInfo_alt)() = (void*)jkDSS_wrap_SendSaberInfo_alt_ADDR;
//static int (*jkDSS_SendEndLevel)() = (void*)jkDSS_SendEndLevel_ADDR;
//static int (*jkDSS_SendJKPrintUniString)(int a1, uint32_t a2) = (void*)jkDSS_SendJKPrintUniString_ADDR;
//static int (*jkDSS_SendJKSetWeaponMesh)(sithThing *a1) = (void*)jkDSS_SendJKSetWeaponMesh_ADDR;
//static int (*jkDSS_SendSetSaberInfo)(sithThing *a1) = (void*)jkDSS_SendSetSaberInfo_ADDR;
//static int (*jkDSS_SendSetSaberInfo2)(sithThing *a1) = (void*)jkDSS_SendSetSaberInfo2_ADDR;
//static int (*jkDSS_SendJKEnableSaber)(sithThing *player) = (void*)jkDSS_SendJKEnableSaber_ADDR;
//static void (*jkDSS_Sendx32)(jkPlayerInfo *playerInfo) = (void*)jkDSS_Sendx32_ADDR;

#endif // _DSS_JKDSS_H