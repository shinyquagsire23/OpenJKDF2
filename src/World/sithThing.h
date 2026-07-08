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
void sithThing_RegisterUnknownFunc(sithThing_handler_t pFunc);
MATH_FUNC void sithThing_Update(flex_t secDeltaTime, int msecDeltaTime);
void sithThing_DestroyDyingThing(SithThing* pThing);
SithThing* sithThing_GetThingParent(SithThing* pThing);
SithThing* sithThing_GetThingByIndex(int idx);
void sithThing_InitializeWorldThings(void);
void sithThing_LoadPostProcess();
void sithThing_FreeThing(SithThing* pThing);
MATH_FUNC void sithThing_Initialize(SithThing* pThing);
int sithThing_Reset(SithThing* pThing);
SithThing* sithThing_SetThingBasedOn(SithThing *pThing, SithThing *pTemplate);
int sithThing_ParseArg(StdConffileArg *arg, SithThing* pThing);
int sithThing_ReadStaticThingsListText(SithWorld *pWorld, int bSkip);
int sithThing_ParseThingArg(StdConffileArg *arg, SithThing* pThing, int param);
void sithThing_SetPositionAndOrient(SithThing *pThing, rdVector3 *pos, rdMatrix34 *pOrient);
int sithThing_SetThingModel(SithThing* pThing, rdModel3 *model);
void sithThing_ExitSector(SithThing* pThing);
void sithThing_EnterSector(SithThing* pThing, SithSector *pNewSector, int bNoWaterSplash, int bNoNotify);
SithThing* sithThing_Create(uint32_t type);
void sithThing_EnterWater(SithThing* pThing, int bNoSplash);
void sithThing_ExitWater(SithThing* pThing, int bNoSplash);
uint32_t sithThing_CalcThingChecksum(SithThing* pTemplate, uint32_t seed);
int sithThing_FreeThingIndex(int a1);
int sithThing_ValidateThingPointer(SithThing* pThing);
void sithThing_UpdateMove(SithThing* pThing, flex_t secDeltaTime);
void sithThing_RemoveWorldThings(SithWorld *pWorld);
void sithThing_FreeWorldThings(SithWorld *pWorld);
SithThing* sithThing_CreateThing(SithThing *pTemplate, SithThing *pMarker);
SithThing* sithThing_CreateThingAtPos(SithThing *pTemplate, const rdVector3 *pos, const rdMatrix34 *orient, SithSector *pSector, SithThing *pParent);
void sithThing_RemoveThing(SithThing* pThing);
void sithThing_AttachThingToSurface(SithThing* pThing, SithSurface *pSurface, int bNoImpactUpdate);
void sithThing_AttachThingToThingFace(SithThing *pThing, SithThing *pAttachThing, rdFace *pFace, rdVector3 *aVertices, int bNoImpactUpdate);
void sithThing_SetSector(SithThing* pThing, SithSector *pSector, int bNotify);
MATH_FUNC int sithThing_DetachThing(SithThing* pThing);
void sithThing_DestroyThing(SithThing* pThing);
flex_t sithThing_DamageThing(SithThing *pThing, SithThing *pDamageThing, flex_t damage, int hitType);
MATH_FUNC void sithThing_DetachAttachedThings(SithThing* pThing);
void sithThing_AttachThingToThing(SithThing *pThing, SithThing *pAttachThing);
void sithThing_SyncThing(SithThing *pThing, int flags);
int sithThing_CanSync(SithThing* pThing);
SithThing* sithThing_GetGuidThing(int guid);
int sithThing_HasAttachment(SithThing* pThing);
void sithThing_SyncThings();
int sithThing_Release(SithThing *pThing);

int sithThing_MotsTick(int param_1,int param_2,flex_t param_3); // MOTS added

//static flex_t (*sithThing_Hit)(SithThing *pMeshCollided, SithThing *pThingCollided, flex_t amount, int a4) = (void*)sithThing_Hit_ADDR;
//static void (*sithThing_AttachThingToThingFace)(SithThing *a1, SithThing *a2, rdFace *a3, rdVector3* a4, int a5) = (void*)sithThing_AttachThingToThingFace_ADDR;
//static int (*_sithThing_Load)(SithWorld *pWorld, int a2) = (void*)sithThing_ReadStaticThingsListText_ADDR;
//static int (*sithThing_ParseThingArg)(StdConffileArg *arg, SithThing* pThing, int param) = (void*)sithThing_ParseThingArg_ADDR;
//static int (*sithThing_LoadActorPlayerParams)(StdConffileArg *arg, SithThing* pThing, unsigned int param) = (void*)sithThing_LoadActorPlayerParams_ADDR;
//static void (*sithThing_UpdateMove)(SithThing* pThing, flex_t arg4) = (void*)sithThing_UpdateMove_ADDR;
//static int (__cdecl *sithThing_Reset)(SithThing* pThing) = (void*)0x4CD190;
//static int (__cdecl *sithThing_SetThingBasedOn)(SithThing* pThing, SithThing *a2) = (void*)0x4CD8A0;
//static signed int (*sithThing_ParseArg)(StdConffileArg *a1, SithThing* pThing) = (void*)0x004CEB90;
//static void (*sithThing_FreeWorldThings)(SithWorld* pWorld) = (void*)sithThing_FreeWorldThings_ADDR;

//static SithThing* (*sithThing_CreateThingAtPos)(SithThing *a1, rdVector3 *a2, const rdMatrix34 *a3, SithSector *sector, SithThing *a5) = (void*)sithThing_CreateThingAtPos_ADDR;
//static SithThing* (*sithThing_CreateThing)(SithThing *a1, SithThing *a2) = (void*)sithThing_CreateThing_ADDR;
//static flex_t (*sithThing_DamageThing)(SithThing *pMeshCollided, SithThing *reciever, flex_t amount, int damageType) = (void*)sithThing_DamageThing_ADDR;
//static void (*sithThing_DestroyThing)(SithThing *a1) = (void*)sithThing_DestroyThing_ADDR;
//static void (*sithThing_ExitSector)(SithThing *a1) = (void*)sithThing_ExitSector_ADDR;
//static void (*sithThing_SetPositionAndOrient)(SithThing* pThing, rdVector3 *pos, rdMatrix34 *rot) = (void*)sithThing_SetPositionAndOrient_ADDR;
//static void (*sithThing_SetSector)(SithThing *a1, SithSector *a2, int a4) = (void*)sithThing_SetSector_ADDR;
//static void (*sithThing_EnterSector)(SithThing *a1, SithSector *a2, int a3, int a4) = (void*)sithThing_EnterSector_ADDR;
//static int (*sithThing_DetachThing)(SithThing *a1) = (void*)sithThing_DetachThing_ADDR;
//static int (*sithThing_Release)(SithThing *a1) = (void*)sithThing_Release_ADDR;
//static SithThing* (*sithThing_GetThingParent)(SithThing *a1) = (void*)sithThing_GetThingParent_ADDR;
//static void (*sithThing_SyncThing)(SithThing *a1, int a2) = (void*)sithThing_SyncThing_ADDR;
//static void (*sithThing_AttachThingToSurface)(SithThing *a1, SithSurface *a2, int a3) = (void*)sithThing_AttachThingToSurface_ADDR;
//static void (*sithThing_AttachThingToThing)(SithThing *parent, SithThing *child) = (void*)sithThing_AttachThingToThing_ADDR;
//static int (*sithThing_SetThingModel)(SithThing *a1, rdModel3 *a2) = (void*)sithThing_SetThingModel_ADDR;

#endif // _SITHTHING_H
