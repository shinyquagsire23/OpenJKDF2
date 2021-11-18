#ifndef _JKSABER_H
#define _JKSABER_H

#include "types.h"

#define jkSaber_InitializeSaberInfo_ADDR (0x0040B4C0)
#define jkSaber_PolylineRand_ADDR (0x0040B590)
#define jkSaber_Draw_ADDR (0x0040B5E0)
#define jkSaber_UpdateLength_ADDR (0x0040B6D0)
#define jkSaber_UpdateCollision_ADDR (0x0040B860)
#define jkSaber_idk3_ADDR (0x0040BF40)
#define jkSaber_Enable_ADDR (0x0040BFC0)
#define jkSaber_Disable_ADDR (0x0040C020)
#define jkSaber_Startup_ADDR (0x0040C040)
#define jkSaber_Shutdown_ADDR (0x0040C140)
#define jkSaber_idk4_ADDR (0x0040C150)
#define jkSaber_playerconfig_idksync_ADDR (0x0040C220)
#define jkSaber_player_thingsidkfunc_ADDR (0x0040C370)
#define jkSaber_nullsub_2_ADDR (0x0040C390)
#define jkSaber_Write_ADDR (0x0040C3A0)
#define jkSaber_Load_ADDR (0x0040C3C0)
#define jkSaber_cogMsg_wrap_SendSaberInfo_alt_ADDR (0x0040C400)
#define jkSaber_cogMsg_SendSaberInfo_alt_ADDR (0x0040C430)
#define jkSaber_cogMsg_SendSetSaberInfo_ADDR (0x0040C500)
#define jkSaber_cogMsg_HandleSetSaberInfo_ADDR (0x0040C5C0)
#define jkSaber_cogMsg_SendJKEnableSaber_ADDR (0x0040C840)
#define jkSaber_cogMsg_HandleJKEnableSaber_ADDR (0x0040C8B0)
#define jkSaber_cogMsg_SendSetSaberInfo2_ADDR (0x0040C920)
#define jkSaber_cogMsg_HandleSetSaberInfo2_ADDR (0x0040CB00)
#define jkSaber_cogMsg_SendJKSetWeaponMesh_ADDR (0x0040CCB0)
#define jkSaber_cogMsg_HandleJKSetWeaponMesh_ADDR (0x0040CD30)
#define jkSaber_cogMsg_SendHudTarget_ADDR (0x0040CDB0)
#define jkSaber_cogMsg_HandleHudTarget_ADDR (0x0040CE40)
#define jkSaber_cogMsg_Sendx32_ADDR (0x0040CEB0)
#define jkSaber_cogMsg_Handlex32_ADDR (0x0040CFA0)
#define jkSaber_cogMsg_Sendx33_ADDR (0x0040D080)
#define jkSaber_cogMsg_Handlex33_ADDR (0x0040D0F0)
#define jkSaber_cogMsg_Sendx36_ADDR (0x0040D190)
#define jkSaber_cogMsg_Handlex36_setwaggle_ADDR (0x0040D1F0)
#define jkSaber_cogMsg_SendJKPrintUniString_ADDR (0x0040D230)
#define jkSaber_cogMsg_HandleJKPrintUniString_ADDR (0x0040D2B0)
#define jkSaber_cogMsg_SendEndLevel_ADDR (0x0040D310)
#define jkSaber_cogMsg_HandleEndLevel_ADDR (0x0040D3A0)
#define jkSaber_cogMsg_SendSetTeam_ADDR (0x0040D3E0)
#define jkSaber_cogMsg_HandleSetTeam_ADDR (0x0040D450)

int jkSaber_Startup();
void jkSaber_InitializeSaberInfo(sithThing *thing, char *material_side_fname, char *material_tip_fname, float base_rad, float tip_rad, float len, sithThing *wall_sparks, sithThing *blood_sparks, sithThing *saber_sparks);
void jkSaber_PolylineRand(rdThing *thing);
void jkSaber_Draw(rdMatrix34 *posRotMat);
void jkSaber_UpdateLength(sithThing *thing);
void jkSaber_UpdateCollision(sithThing *player, int joint);
int jkSaber_Load();
int jkSaber_Write();
void jkSaber_player_thingsidkfunc();
void jkSaber_nullsub_2();
void jkSaber_Disable(sithThing *player);
void jkSaber_Enable(sithThing *a1, float a2, float a3, float a4);
void jkSaber_playerconfig_idksync();
void jkSaber_cogMsg_SendSetSaberInfo2(sithThing *thing);
int jkSaber_cogMsg_HandleSetSaberInfo2(sithCogMsg *msg);
void jkSaber_cogMsg_SendSetSaberInfo(sithThing *thing);
int jkSaber_cogMsg_HandleSetSaberInfo(sithCogMsg *msg);
void jkSaber_cogMsg_Sendx32(jkPlayerInfo *playerInfo);
int jkSaber_cogMsg_Handlex32(sithCogMsg *msg);
int jkSaber_cogMsg_Handlex36_setwaggle(sithCogMsg *msg);
int jkSaber_cogMsg_HandleHudTarget(sithCogMsg *msg);

void jkSaber_cogMsg_SendSetTeam(int16_t teamNum);
int jkSaber_cogMsg_HandleSetTeam(sithCogMsg *pMsg);

static void (*jkSaber_Shutdown)() = (void*)jkSaber_Shutdown_ADDR;
static int (*jkSaber_cogMsg_wrap_SendSaberInfo_alt)() = (void*)jkSaber_cogMsg_wrap_SendSaberInfo_alt_ADDR;
static int (*jkSaber_cogMsg_SendEndLevel)() = (void*)jkSaber_cogMsg_SendEndLevel_ADDR;
static int (*jkSaber_cogMsg_SendJKPrintUniString)(int a1, unsigned int a2) = (void*)jkSaber_cogMsg_SendJKPrintUniString_ADDR;
static int (*jkSaber_cogMsg_SendJKSetWeaponMesh)(sithThing *a1) = (void*)jkSaber_cogMsg_SendJKSetWeaponMesh_ADDR;
//static int (*jkSaber_cogMsg_SendSetSaberInfo)(sithThing *a1) = (void*)jkSaber_cogMsg_SendSetSaberInfo_ADDR;
//static int (*jkSaber_cogMsg_SendSetSaberInfo2)(sithThing *a1) = (void*)jkSaber_cogMsg_SendSetSaberInfo2_ADDR;
static int (*jkSaber_cogMsg_SendJKEnableSaber)(sithThing *player) = (void*)jkSaber_cogMsg_SendJKEnableSaber_ADDR;
//static void (*jkSaber_UpdateCollision)(sithThing *player, int joint) = (void*)jkSaber_UpdateCollision_ADDR;
//static void (*jkSaber_cogMsg_Sendx32)(jkPlayerInfo *playerInfo) = (void*)jkSaber_cogMsg_Sendx32_ADDR;

#endif // _JKSABER_H
