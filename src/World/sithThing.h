#ifndef _SITHTHING_H
#define _SITHTHING_H

#include "types.h"
#include "globals.h"

#include "Engine/rdThing.h"
#include "Gameplay/sithPlayer.h"
#include "General/stdConffile.h"

#define sithThing_Startup_ADDR (0x004CC130)
#define sithThing_Shutdown_ADDR (0x004CC1A0)
#define sithThing_SetHandler_ADDR (0x004CC1D0)
#define sithThing_TickAll_ADDR (0x004CC1E0)
#define sithThing_TickPhysics_ADDR (0x004CC4C0)
#define sithThing_Remove_ADDR (0x004CC610)
#define sithThing_GetParent_ADDR (0x004CC6A0)
#define sithThing_GetThingByIdx_ADDR (0x004CC6D0)
#define sithThing_GetById_ADDR (0x004CC710)
#define sithThing_Destroy_ADDR (0x004CC7A0)
#define sithThing_Damage_ADDR (0x004CC7D0)
#define sithThing_Create_idk_ADDR (0x004CC8C0)
#define sithThing_Free_ADDR (0x004CCA10)
#define sithThing_freestuff_ADDR (0x004CCBC0)
#define sithThing_idkjkl_ADDR (0x004CCD40)
#define sithThing_sub_4CCE60_ADDR (0x004CCE60)
#define sithThing_FreeEverythingNet_ADDR (0x004CCF20)
#define sithThing_FreeEverything_ADDR (0x004CD050)
#define sithThing_sub_4CD100_ADDR (0x004CD100)
#define sithThing_DoesRdThingInit_ADDR (0x004CD190)
#define sithThing_MoveToSector_ADDR (0x004CD1E0)
#define sithThing_LeaveSector_ADDR (0x004CD220)
#define sithThing_EnterSector_ADDR (0x004CD2C0)
#define sithThing_EnterWater_ADDR (0x004CD370)
#define sithThing_ExitWater_ADDR (0x004CD480)
#define sithThing_doesinitidk_ADDR (0x004CD570)
#define sithThing_SetPosAndRot_ADDR (0x004CD7E0)
#define sithThing_SetNewModel_ADDR (0x004CD830)
#define sithThing_sub_4CD8A0_ADDR (0x004CD8A0)
#define sithThing_Create_ADDR (0x004CD9E0)
#define sithThing_SpawnTemplate_ADDR (0x004CDCD0)
#define sithThing_AttachToSurface_ADDR (0x004CDE80)
#define sithThing_LandThing_ADDR (0x004CE050)
#define sithThing_AttachThing_ADDR (0x004CE2C0)
#define sithThing_DetachThing_ADDR (0x004CE380)
#define sithThing_detachallchildren_ADDR (0x004CE540)
#define sithThing_IsAttachFlagsAnd6_ADDR (0x004CE560)
#define sithThing_LotsOfFreeing_ADDR (0x004CE580)
#define sithThing_Load_ADDR (0x004CE710)
#define sithThing_ParseArgs_ADDR (0x004CEB90)
#define sithThing_LoadThingParam_ADDR (0x004CECB0)
#define sithThing_TypeIdxFromStr_ADDR (0x004CF320)
#define sithThing_GetIdxFromThing_ADDR (0x004CF380)
#define sithThing_Checksum_ADDR (0x004CF3C0)
#define sithThing_SetSyncFlags_ADDR (0x004CF560)
#define sithThing_Sync_ADDR (0x004CF5D0)
#define sithThing_ShouldSync_ADDR (0x004CF660)
#define sithThing_netidk2_ADDR (0x004CF690)
#define sithThing_Release_ADDR (0x004E0740)

int sithThing_Startup();
int sithThing_Shutdown();
void sithThing_SetHandler(sithThing_handler_t handler);
void sithThing_TickAll(float deltaSeconds, int deltaMs);
void sithThing_Remove(sithThing* pThing);
sithThing* sithThing_GetParent(sithThing* pThing);
sithThing* sithThing_GetThingByIdx(int idx);
void sithThing_sub_4CCE60();
void sithThing_FreeEverything(sithThing* pThing);
void sithThing_sub_4CD100(sithThing* pThing);
int sithThing_DoesRdThingInit(sithThing* pThing);
sithThing* sithThing_sub_4CD8A0(sithThing* pThing, sithThing *a2);
int sithThing_ParseArgs(stdConffileArg *arg, sithThing* pThing);
int sithThing_Load(sithWorld *pWorld, int a2);
int sithThing_LoadThingParam(stdConffileArg *arg, sithThing* pThing, int param);
void sithThing_SetPosAndRot(sithThing *this, rdVector3 *pos, rdMatrix34 *rot);
int sithThing_SetNewModel(sithThing* pThing, rdModel3 *model);
void sithThing_LeaveSector(sithThing* pThing);
void sithThing_EnterSector(sithThing* pThing, sithSector *sector, int a3, int a4);
void sithThing_EnterWater(sithThing* pThing, int a2);
void sithThing_ExitWater(sithThing* pThing, int a2);
uint32_t sithThing_Checksum(sithThing* pThing, unsigned int last_hash);
int sithThing_netidk2(int a1);
int sithThing_GetIdxFromThing(sithThing* pThing);
void sithThing_TickPhysics(sithThing* pThing, float deltaSecs);
void sithThing_freestuff(sithWorld *pWorld);
void sithThing_Free(sithWorld *pWorld);
sithThing* sithThing_SpawnTemplate(sithThing *templateThing, sithThing *spawnThing);
sithThing* sithThing_Create(sithThing *templateThing, const rdVector3 *position, const rdMatrix34 *lookOrientation, sithSector *sector, sithThing *prevThing);
void sithThing_FreeEverythingNet(sithThing* pThing);
void sithThing_AttachToSurface(sithThing* pThing, sithSurface *surface, int a3);
void sithThing_LandThing(sithThing *a1, sithThing *a2, rdFace *a3, rdVector3 *a4, int a5);
void sithThing_MoveToSector(sithThing* pThing, sithSector *sector, int a4);
int sithThing_DetachThing(sithThing* pThing);
void sithThing_Destroy(sithThing* pThing);
float sithThing_Damage(sithThing *sender, sithThing *reciever, float amount, int damageClass);
void sithThing_detachallchildren(sithThing* pThing);
void sithThing_AttachThing(sithThing *parent, sithThing *child);
void sithThing_SetSyncFlags(sithThing *pThing, int flags);
int sithThing_ShouldSync(sithThing* pThing);
sithThing* sithThing_GetById(int thing_id);
int sithThing_HasAttachment(sithThing* pThing);
void sithThing_Sync();
int sithThing_Release(sithThing *pThing);

int sithThing_MotsTick(int param_1,int param_2,float param_3); // MOTS added

//static float (*sithThing_Hit)(sithThing *sender, sithThing *receiver, float amount, int a4) = (void*)sithThing_Hit_ADDR;
//static void (*sithThing_LandThing)(sithThing *a1, sithThing *a2, rdFace *a3, rdVector3* a4, int a5) = (void*)sithThing_LandThing_ADDR;
static int (*_sithThing_Load)(sithWorld *pWorld, int a2) = (void*)sithThing_Load_ADDR;
//static int (*sithThing_LoadThingParam)(stdConffileArg *arg, sithThing* pThing, int param) = (void*)sithThing_LoadThingParam_ADDR;
//static int (*sithThing_LoadActorPlayerParams)(stdConffileArg *arg, sithThing* pThing, unsigned int param) = (void*)sithThing_LoadActorPlayerParams_ADDR;
//static void (*sithThing_TickPhysics)(sithThing* pThing, float arg4) = (void*)sithThing_TickPhysics_ADDR;
//static int (__cdecl *sithThing_DoesRdThingInit)(sithThing* pThing) = (void*)0x4CD190;
//static int (__cdecl *sithThing_sub_4CD8A0)(sithThing* pThing, sithThing *a2) = (void*)0x4CD8A0;
//static signed int (*sithThing_ParseArgs)(stdConffileArg *a1, sithThing* pThing) = (void*)0x004CEB90;
//static void (*sithThing_Free)(sithWorld* pWorld) = (void*)sithThing_Free_ADDR;

//static sithThing* (*sithThing_Create)(sithThing *a1, rdVector3 *a2, const rdMatrix34 *a3, sithSector *sector, sithThing *a5) = (void*)sithThing_Create_ADDR;
//static sithThing* (*sithThing_SpawnTemplate)(sithThing *a1, sithThing *a2) = (void*)sithThing_SpawnTemplate_ADDR;
//static float (*sithThing_Damage)(sithThing *sender, sithThing *reciever, float amount, int damageClass) = (void*)sithThing_Damage_ADDR;
//static void (*sithThing_Destroy)(sithThing *a1) = (void*)sithThing_Destroy_ADDR;
//static void (*sithThing_LeaveSector)(sithThing *a1) = (void*)sithThing_LeaveSector_ADDR;
//static void (*sithThing_SetPosAndRot)(sithThing* pThing, rdVector3 *pos, rdMatrix34 *rot) = (void*)sithThing_SetPosAndRot_ADDR;
//static void (*sithThing_MoveToSector)(sithThing *a1, sithSector *a2, int a4) = (void*)sithThing_MoveToSector_ADDR;
//static void (*sithThing_EnterSector)(sithThing *a1, sithSector *a2, int a3, int a4) = (void*)sithThing_EnterSector_ADDR;
//static int (*sithThing_DetachThing)(sithThing *a1) = (void*)sithThing_DetachThing_ADDR;
//static int (*sithThing_Release)(sithThing *a1) = (void*)sithThing_Release_ADDR;
//static sithThing* (*sithThing_GetParent)(sithThing *a1) = (void*)sithThing_GetParent_ADDR;
//static void (*sithThing_SetSyncFlags)(sithThing *a1, int a2) = (void*)sithThing_SetSyncFlags_ADDR;
//static void (*sithThing_AttachToSurface)(sithThing *a1, sithSurface *a2, int a3) = (void*)sithThing_AttachToSurface_ADDR;
//static void (*sithThing_AttachThing)(sithThing *parent, sithThing *child) = (void*)sithThing_AttachThing_ADDR;
//static int (*sithThing_SetNewModel)(sithThing *a1, rdModel3 *a2) = (void*)sithThing_SetNewModel_ADDR;

#endif // _SITHTHING_H
