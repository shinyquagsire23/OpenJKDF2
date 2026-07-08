#ifndef _SITHTHING_H
#define _SITHTHING_H

#include "types.h"
#include "globals.h"

#include "Engine/rdThing.h"
#include "Gameplay/sithPlayer.h"
#include "General/stdConffile.h"

#define sithThing_Startup_ADDR (0x004CC130)
#define sithThing_Shutdown_ADDR (0x004CC1A0)
#define sithThing_RegisterUnknownFunc_ADDR (0x004CC1D0)
#define sithThing_Update_ADDR (0x004CC1E0)
#define sithThing_UpdateMove_ADDR (0x004CC4C0)
#define sithThing_DestroyDyingThing_ADDR (0x004CC610)
#define sithThing_GetThingParent_ADDR (0x004CC6A0)
#define sithThing_GetThingByIndex_ADDR (0x004CC6D0)
#define sithThing_GetGuidThing_ADDR (0x004CC710)
#define sithThing_DestroyThing_ADDR (0x004CC7A0)
#define sithThing_DamageThing_ADDR (0x004CC7D0)
#define sithThing_Create_idk_ADDR (0x004CC8C0)
#define sithThing_FreeWorldThings_ADDR (0x004CCA10)
#define sithThing_RemoveWorldThings_ADDR (0x004CCBC0)
#define sithThing_InitializeWorldThings_ADDR (0x004CCD40)
#define sithThing_LoadPostProcess_ADDR (0x004CCE60)
#define sithThing_RemoveThing_ADDR (0x004CCF20)
#define sithThing_FreeThing_ADDR (0x004CD050)
#define sithThing_Initialize_ADDR (0x004CD100)
#define sithThing_Reset_ADDR (0x004CD190)
#define sithThing_SetSector_ADDR (0x004CD1E0)
#define sithThing_ExitSector_ADDR (0x004CD220)
#define sithThing_EnterSector_ADDR (0x004CD2C0)
#define sithThing_EnterWater_ADDR (0x004CD370)
#define sithThing_ExitWater_ADDR (0x004CD480)
#define sithThing_Create_ADDR (0x004CD570)
#define sithThing_SetPositionAndOrient_ADDR (0x004CD7E0)
#define sithThing_SetThingModel_ADDR (0x004CD830)
#define sithThing_SetThingBasedOn_ADDR (0x004CD8A0)
#define sithThing_CreateThingAtPos_ADDR (0x004CD9E0)
#define sithThing_CreateThing_ADDR (0x004CDCD0)
#define sithThing_AttachThingToSurface_ADDR (0x004CDE80)
#define sithThing_AttachThingToThingFace_ADDR (0x004CE050)
#define sithThing_AttachThingToThing_ADDR (0x004CE2C0)
#define sithThing_DetachThing_ADDR (0x004CE380)
#define sithThing_DetachAttachedThings_ADDR (0x004CE540)
#define sithThing_IsAttachFlagsAnd6_ADDR (0x004CE560)
#define sithThing_LotsOfFreeing_ADDR (0x004CE580)
#define sithThing_ReadStaticThingsListText_ADDR (0x004CE710)
#define sithThing_ParseArg_ADDR (0x004CEB90)
#define sithThing_ParseThingArg_ADDR (0x004CECB0)
#define sithThing_TypeIdxFromStr_ADDR (0x004CF320)
#define sithThing_ValidateThingPointer_ADDR (0x004CF380)
#define sithThing_CalcThingChecksum_ADDR (0x004CF3C0)
#define sithThing_SyncThing_ADDR (0x004CF560)
#define sithThing_SyncThings_ADDR (0x004CF5D0)
#define sithThing_CanSync_ADDR (0x004CF660)
#define sithThing_FreeThingIndex_ADDR (0x004CF690)
#define sithThing_Release_ADDR (0x004E0740)

int sithThing_Startup();
int sithThing_Shutdown();
void sithThing_RegisterUnknownFunc(sithThing_handler_t handler);
MATH_FUNC void sithThing_Update(flex_t deltaSeconds, int deltaMs);
void sithThing_DestroyDyingThing(sithThing* pThing);
sithThing* sithThing_GetThingParent(sithThing* pThing);
sithThing* sithThing_GetThingByIndex(int idx);
void sithThing_InitializeWorldThings(void);
void sithThing_LoadPostProcess();
void sithThing_FreeThing(sithThing* pThing);
MATH_FUNC void sithThing_Initialize(sithThing* pThing);
int sithThing_Reset(sithThing* pThing);
sithThing* sithThing_SetThingBasedOn(sithThing *pThing, sithThing *pTemplateThing);
int sithThing_ParseArg(stdConffileArg *arg, sithThing* pThing);
int sithThing_ReadStaticThingsListText(sithWorld *pWorld, int a2);
int sithThing_ParseThingArg(stdConffileArg *arg, sithThing* pThing, int param);
void sithThing_SetPositionAndOrient(sithThing *pThing, rdVector3 *pos, rdMatrix34 *rot);
int sithThing_SetThingModel(sithThing* pThing, rdModel3 *model);
void sithThing_ExitSector(sithThing* pThing);
void sithThing_EnterSector(sithThing* pThing, sithSector *sector, int a3, int a4);
sithThing* sithThing_Create(uint32_t thingType);
void sithThing_EnterWater(sithThing* pThing, int a2);
void sithThing_ExitWater(sithThing* pThing, int a2);
uint32_t sithThing_CalcThingChecksum(sithThing* pThing, uint32_t last_hash);
int sithThing_FreeThingIndex(int a1);
int sithThing_ValidateThingPointer(sithThing* pThing);
void sithThing_UpdateMove(sithThing* pThing, flex_t deltaSecs);
void sithThing_RemoveWorldThings(sithWorld *pWorld);
void sithThing_FreeWorldThings(sithWorld *pWorld);
sithThing* sithThing_CreateThing(sithThing *pTemplateThing, sithThing *spawnThing);
sithThing* sithThing_CreateThingAtPos(sithThing *pTemplateThing, const rdVector3 *position, const rdMatrix34 *lookOrientation, sithSector *sector, sithThing *prevThing);
void sithThing_RemoveThing(sithThing* pThing);
void sithThing_AttachThingToSurface(sithThing* pThing, sithSurface *surface, int a3);
void sithThing_AttachThingToThingFace(sithThing *a1, sithThing *a2, rdFace *a3, rdVector3 *a4, int a5);
void sithThing_SetSector(sithThing* pThing, sithSector *sector, int a4);
MATH_FUNC int sithThing_DetachThing(sithThing* pThing);
void sithThing_DestroyThing(sithThing* pThing);
flex_t sithThing_DamageThing(sithThing *sender, sithThing *reciever, flex_t amount, int damageClass);
MATH_FUNC void sithThing_DetachAttachedThings(sithThing* pThing);
void sithThing_AttachThingToThing(sithThing *parent, sithThing *child);
void sithThing_SyncThing(sithThing *pThing, int flags);
int sithThing_CanSync(sithThing* pThing);
sithThing* sithThing_GetGuidThing(int thing_id);
int sithThing_HasAttachment(sithThing* pThing);
void sithThing_SyncThings();
int sithThing_Release(sithThing *pThing);

int sithThing_MotsTick(int param_1,int param_2,flex_t param_3); // MOTS added

//static flex_t (*sithThing_Hit)(sithThing *sender, sithThing *receiver, flex_t amount, int a4) = (void*)sithThing_Hit_ADDR;
//static void (*sithThing_AttachThingToThingFace)(sithThing *a1, sithThing *a2, rdFace *a3, rdVector3* a4, int a5) = (void*)sithThing_AttachThingToThingFace_ADDR;
//static int (*_sithThing_Load)(sithWorld *pWorld, int a2) = (void*)sithThing_ReadStaticThingsListText_ADDR;
//static int (*sithThing_ParseThingArg)(stdConffileArg *arg, sithThing* pThing, int param) = (void*)sithThing_ParseThingArg_ADDR;
//static int (*sithThing_LoadActorPlayerParams)(stdConffileArg *arg, sithThing* pThing, unsigned int param) = (void*)sithThing_LoadActorPlayerParams_ADDR;
//static void (*sithThing_UpdateMove)(sithThing* pThing, flex_t arg4) = (void*)sithThing_UpdateMove_ADDR;
//static int (__cdecl *sithThing_Reset)(sithThing* pThing) = (void*)0x4CD190;
//static int (__cdecl *sithThing_SetThingBasedOn)(sithThing* pThing, sithThing *a2) = (void*)0x4CD8A0;
//static signed int (*sithThing_ParseArg)(stdConffileArg *a1, sithThing* pThing) = (void*)0x004CEB90;
//static void (*sithThing_FreeWorldThings)(sithWorld* pWorld) = (void*)sithThing_FreeWorldThings_ADDR;

//static sithThing* (*sithThing_CreateThingAtPos)(sithThing *a1, rdVector3 *a2, const rdMatrix34 *a3, sithSector *sector, sithThing *a5) = (void*)sithThing_CreateThingAtPos_ADDR;
//static sithThing* (*sithThing_CreateThing)(sithThing *a1, sithThing *a2) = (void*)sithThing_CreateThing_ADDR;
//static flex_t (*sithThing_DamageThing)(sithThing *sender, sithThing *reciever, flex_t amount, int damageClass) = (void*)sithThing_DamageThing_ADDR;
//static void (*sithThing_DestroyThing)(sithThing *a1) = (void*)sithThing_DestroyThing_ADDR;
//static void (*sithThing_ExitSector)(sithThing *a1) = (void*)sithThing_ExitSector_ADDR;
//static void (*sithThing_SetPositionAndOrient)(sithThing* pThing, rdVector3 *pos, rdMatrix34 *rot) = (void*)sithThing_SetPositionAndOrient_ADDR;
//static void (*sithThing_SetSector)(sithThing *a1, sithSector *a2, int a4) = (void*)sithThing_SetSector_ADDR;
//static void (*sithThing_EnterSector)(sithThing *a1, sithSector *a2, int a3, int a4) = (void*)sithThing_EnterSector_ADDR;
//static int (*sithThing_DetachThing)(sithThing *a1) = (void*)sithThing_DetachThing_ADDR;
//static int (*sithThing_Release)(sithThing *a1) = (void*)sithThing_Release_ADDR;
//static sithThing* (*sithThing_GetThingParent)(sithThing *a1) = (void*)sithThing_GetThingParent_ADDR;
//static void (*sithThing_SyncThing)(sithThing *a1, int a2) = (void*)sithThing_SyncThing_ADDR;
//static void (*sithThing_AttachThingToSurface)(sithThing *a1, sithSurface *a2, int a3) = (void*)sithThing_AttachThingToSurface_ADDR;
//static void (*sithThing_AttachThingToThing)(sithThing *parent, sithThing *child) = (void*)sithThing_AttachThingToThing_ADDR;
//static int (*sithThing_SetThingModel)(sithThing *a1, rdModel3 *a2) = (void*)sithThing_SetThingModel_ADDR;

#endif // _SITHTHING_H
