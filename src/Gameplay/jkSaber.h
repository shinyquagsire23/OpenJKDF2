#ifndef _JKSABER_H
#define _JKSABER_H

#include "types.h"

#define jkSaber_InitializeSaberInfo_ADDR (0x0040B4C0)
#define jkSaber_PolylineRand_ADDR (0x0040B590)
#define jkSaber_Draw_ADDR (0x0040B5E0)
#define jkSaber_UpdateLength_ADDR (0x0040B6D0)
#define jkSaber_UpdateCollision_ADDR (0x0040B860)
#define jkSaber_SpawnSparks_ADDR (0x0040BF40)
#define jkSaber_Enable_ADDR (0x0040BFC0)
#define jkSaber_Disable_ADDR (0x0040C020)

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

void jkSaber_InitializeSaberInfo(sithThing *thing, char *material_side_fname, char *material_tip_fname, float base_rad, float tip_rad, float len, sithThing *wall_sparks, sithThing *blood_sparks, sithThing *saber_sparks);
void jkSaber_PolylineRand(rdThing *thing);
void jkSaber_Draw(rdMatrix34 *posRotMat);
void jkSaber_UpdateLength(sithThing *thing);
void jkSaber_UpdateCollision(sithThing *player, int joint);
void jkSaber_SpawnSparks(jkPlayerInfo *pPlayerInfo, rdVector3 *pPos, sithSector *psector, int sparkType);
void jkSaber_Enable(sithThing *a1, float a2, float a3, float a4);
void jkSaber_Disable(sithThing *player);

//static void (*jkSaber_UpdateCollision)(sithThing *player, int joint) = (void*)jkSaber_UpdateCollision_ADDR;

#endif // _JKSABER_H
