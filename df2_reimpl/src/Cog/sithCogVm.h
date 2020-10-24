#ifndef _SITHCOGVM_H
#define _SITHCOGVM_H

#include "Primitives/rdVector.h"
#include "Engine/rdKeyframe.h"
#include "sithCog.h"

#define sithCogVm_Startup_ADDR (0x004E1700)
#define sithCogVm_Shutdown_ADDR (0x004E18E0)
#define sithCogVm_SetMsgFunc_ADDR (0x004E1900)
#define sithCogVm_SendMsgToPlayer_ADDR (0x004E1910)
#define sithCogVm_FileWrite_ADDR (0x004E1B30)
#define sithCogVm_sub_4E1B70_ADDR (0x004E1B70)
#define sithCogVm_Set104_ADDR (0x004E1DC0)
#define sithCogVm_InvokeMsgByIdx_ADDR (0x004E1DD0)
#define sithCogVm_SyncWithPlayers_ADDR (0x004E1E00)
#define sithCogVm_ClearMsgTmpBuf_ADDR (0x004E1EC0)
#define sithCogVm_ClearTmpBuf2_cogmsg_40_ADDR (0x004E1EE0)
#define sithCogVm_Exec_ADDR (0x004E1F60)
#define sithCogVm_ExecCog_ADDR (0x004E2350)

#define sithCogVm_PopValue_ADDR (0x004E2440)
#define sithCogVm_PopFlex_ADDR (0x004E24F0)
#define sithCogVm_PopInt_ADDR (0x004E25C0)
#define sithCogVm_PopUnk_ADDR (0x004E2690)
#define sithCogVm_PopVector3_ADDR (0x004E26E0)
#define sithCogVm_PopCog_ADDR (0x004E27B0)
#define sithCogVm_PopThing_ADDR (0x004E28C0)
#define sithCogVm_PopTemplate_ADDR (0x004E29C0)
#define sithCogVm_PopSound_ADDR (0x004E2AD0)
#define sithCogVm_PopSector_ADDR (0x004E2BD0)
#define sithCogVm_PopSurface_ADDR (0x004E2CC0)
#define sithCogVm_PopMaterial_ADDR (0x004E2DB0)
#define sithCogVm_PopModel3_ADDR (0x004E2EB0)
#define sithCogVm_PopKeyframe_ADDR (0x004E2FB0)
#define sithCogVm_PopAIClass_ADDR (0x004E30B0)
#define sithCogVm_PopUnk2_ADDR (0x004E31B0)
#define sithCogVm_PopString_ADDR (0x004E3260)

#define sithCogVm_PushVar_ADDR (0x004E32D0)
#define sithCogVm_PushInt_ADDR (0x004E3340)
#define sithCogVm_PushFlex_ADDR (0x004E33C0)
#define sithCogVm_PushVector3_ADDR (0x004E3450)
#define sithCogVm_StackPopVal_ADDR (0x004E34E0)
#define sithCogVm_sub_4E3510_ADDR (0x004E3510)
#define sithCogVm_Call_ADDR (0x004E3530)
#define sithCogVm_Ret_ADDR (0x004E3590)
#define sithCogVm_PopStackVar_ADDR (0x004E35E0)
#define sithCogVm_BitOperation_ADDR (0x004E3630)
#define sithCogVm_MathOperation_ADDR (0x004E3870)
#define sithCogVm_GetSymbolIdk_ADDR (0x004E3B90)

#define sithCogVm_isMultiplayer (*(int*)0x847E70)

static int (__cdecl *sithCogVm_PopValue)(sithCog *ctx, int *out) = sithCogVm_PopValue_ADDR;
static float (__cdecl *sithCogVm_PopFlex)(sithCog *ctx) = sithCogVm_PopFlex_ADDR;
static int (__cdecl *sithCogVm_PopInt)(sithCog *ctx) = sithCogVm_PopInt_ADDR;
static int (__cdecl *sithCogVm_PopVector3)(sithCog *ctx, rdVector3* out) = sithCogVm_PopVector3_ADDR;
static char* (__cdecl *sithCogVm_PopString)(sithCog *ctx) = sithCogVm_PopString_ADDR;
static void* (__cdecl *sithCogVm_PopSurface)(sithCog* ctx) = sithCogVm_PopSurface_ADDR;
static void* (__cdecl *sithCogVm_PopMaterial)(sithCog* ctx) = sithCogVm_PopMaterial_ADDR;
static rdKeyframe* (__cdecl *sithCogVm_PopKeyframe)(sithCog* ctx) = sithCogVm_PopKeyframe_ADDR;
static sithCog* (__cdecl *sithCogVm_PopCog)(sithCog* ctx) = sithCogVm_PopCog_ADDR;

static void (__cdecl *sithCogVm_PushVar)(sithCog *ctx, sithCogStackvar *val) = sithCogVm_PushVar_ADDR;
static void (__cdecl *sithCogVm_PushInt)(sithCog *ctx, int val) = sithCogVm_PushInt_ADDR;
static void (__cdecl *sithCogVm_PushFlex)(sithCog *ctx, float val) = sithCogVm_PushFlex_ADDR;
static void (__cdecl *sithCogVm_PushVector3)(sithCog *ctx, rdVector3 *val) = sithCogVm_PushVector3_ADDR;


#endif // _SITHCOGVM_H
