#ifndef _SITHCOGVM_H
#define _SITHCOGVM_H

#include "Primitives/rdVector.h"
#include "Engine/rdKeyframe.h"
#include "sithCog.h"
#include <stdint.h>

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

enum COG_TYPE
{
    COG_TYPE_VERB    = 0,
    COG_TYPE_1       = 1,
    COG_TYPE_GLOBAL  = 2,
    COG_TYPE_MESSAGE  = 3
};

enum COG_VARTYPE
{
    COG_VARTYPE_VERB  = 0,
    COG_VARTYPE_SYMBOL  = 1,
    COG_VARTYPE_FLEX  = 2,
    COG_VARTYPE_INT  = 3,
    COG_VARTYPE_STR  = 4,
    COG_VARTYPE_VECTOR  = 5
};

enum COG_OPCODE
{
    COG_OPCODE_NOP   = 0,
    COG_OPCODE_PUSHINT  = 1,
    COG_OPCODE_PUSHFLOAT  = 2,
    COG_OPCODE_PUSHSYMBOL  = 3,
    COG_OPCODE_ARRAYINDEX  = 4,
    COG_OPCODE_CALLFUNC  = 5,
    COG_OPCODE_ASSIGN  = 6,
    COG_OPCODE_PUSHVECTOR  = 7,
    COG_OPCODE_ADD   = 8,
    COG_OPCODE_SUB   = 9,
    COG_OPCODE_MUL   = 10,
    COG_OPCODE_DIV   = 11,
    COG_OPCODE_MOD   = 12,
    COG_OPCODE_CMPFALSE  = 13,
    COG_OPCODE_NEG   = 14,
    COG_OPCODE_CMPGT  = 15,
    COG_OPCODE_CMPLS  = 16,
    COG_OPCODE_CMPEQ  = 17,
    COG_OPCODE_CMPLE  = 18,
    COG_OPCODE_CMPGE  = 19,
    COG_OPCODE_CMPAND  = 20,
    COG_OPCODE_CMPOR  = 21,
    COG_OPCODE_CMPNE  = 22,
    COG_OPCODE_ANDI  = 23,
    COG_OPCODE_ORI   = 24,
    COG_OPCODE_XORI  = 25,
    COG_OPCODE_GOFALSE  = 26,
    COG_OPCODE_GOTRUE  = 27,
    COG_OPCODE_GO    = 28,
    COG_OPCODE_RET   = 29,
    COG_OPCODE_UNK30  = 30,
    COG_OPCODE_CALL  = 31
};

typedef struct net_msg
{
    uint32_t field_0;
    uint32_t flag_maybe;
    uint32_t field_8;
    uint32_t field_C;
    uint32_t field_10;
    uint32_t field_14;
    uint32_t field_18;
    uint32_t anonymous_0;
    uint32_t msg_size;
    uint16_t msg_id;
    uint16_t field_26;
    char strptr_8B4C28[4];
    uint32_t some_thing_id;
    uint16_t net_num_players;
} net_msg;

typedef int (__cdecl *cogMsg_Handler)(net_msg*);

typedef struct jkl_map_idk
{
    uint32_t anonymous_0;
    uint32_t anonymous_1;
    uint8_t anonymous_2[16];
    uint8_t field_18[1000];
} jkl_map_idk;

typedef struct sithCogVmGlobals
{
    cogMsg_Handler msgFuncs[60];
    uint32_t field_F0;
    uint32_t field_F4;
    uint32_t field_F8;
    uint32_t field_FC;
    uint32_t field_100;
} sithCogVmGlobals;

typedef struct cogMsg_Entry
{
    uint32_t field_0;
    uint32_t field_4;
    uint32_t field_8;
    uint32_t field_C;
    uint32_t field_10;
    uint32_t field_14;
    uint32_t field_18;
    uint32_t field_1C;
    uint32_t field_20;
    uint32_t field_24;
    uint32_t field_28;
    uint32_t field_2C;
    uint32_t field_30;
    uint32_t field_34;
    uint32_t field_38;
    uint32_t field_3C;
    uint32_t field_40;
    uint32_t field_44;
    uint32_t field_48;
    uint32_t field_4C;
    uint32_t field_50;
    uint32_t field_54;
    uint32_t field_58[499];
    uint32_t field_824;
} cogMsg_Entry;

#define sithCogVm_MsgTmpBuf (*(cogMsg_Entry**)0xcogMsg_Entry)
#define sithCogVm_jkl_map_idk (*(jkl_map_idk*)0x00847968)
#define sithCogVm_globals (*(sithCogVmGlobals*)0x00847D68)
#define sithCogVm_idk (*(int*)0x00847E6C)
#define sithCogVm_isMultiplayer (*(int*)0x847E70)
#define sithCogVm_multiIdk (*(int*)0x847E74)
#define sithCogVm_idk2 (*(int*)0x00847E7C)
#define sithCogVm_bInit (*(int*)0x00847E80)
#define sithCogVm_dword_847E84 (*(int*)0x00847E84)
#define jkl_map_idk_set_one (*(int*)0x54B004)

int sithCogVm_Startup();
void sithCogVm_Shutdown();
void sithCogVm_SetMsgFunc(int msgid, void *func);

void sithCogVm_Set104();
int sithCogVm_InvokeMsgByIdx(net_msg *a1);

void sithCogVm_Exec(sithCog *cog_ctx);

static void (__cdecl *sithCogVm_Ret)(sithCog *cog) = (void*)sithCogVm_Ret_ADDR;
static void (__cdecl *sithCogVm_Call)(sithCog *cog) = (void*)sithCogVm_Call_ADDR;

static int (__cdecl *sithCogVm_StackPopVal)(sithCog *cog) = (void*)sithCogVm_StackPopVal_ADDR;
static int (__cdecl *sithCogVm_PopStackVar)(sithCog *cog, sithCogStackvar *out) = (void*)sithCogVm_PopStackVar_ADDR;
static sithCogStackvar* (__cdecl *sithCogVm_GetSymbolIdk)(sithCogStackvar *a1, int a2, sithCogStackvar *a3) = (void*)sithCogVm_GetSymbolIdk_ADDR;
static void (__cdecl *sithCogVm_MathOperation)(sithCog *cog, int op) = (void*)sithCogVm_MathOperation_ADDR;
static void (__cdecl *sithCogVm_BitOperation)(sithCog *cog, int op) = (void*)sithCogVm_BitOperation_ADDR;
static int (__cdecl *sithCogVm_PopValue)(sithCog *ctx, int *out) = (void*)sithCogVm_PopValue_ADDR;
static float (__cdecl *sithCogVm_PopFlex)(sithCog *ctx) = (void*)sithCogVm_PopFlex_ADDR;
static int (__cdecl *sithCogVm_PopInt)(sithCog *ctx) = (void*)sithCogVm_PopInt_ADDR;
static int (__cdecl *sithCogVm_PopVector3)(sithCog *ctx, rdVector3* out) = (void*)sithCogVm_PopVector3_ADDR;
static char* (__cdecl *sithCogVm_PopString)(sithCog *ctx) = (void*)sithCogVm_PopString_ADDR;
static void* (__cdecl *sithCogVm_PopSurface)(sithCog* ctx) = (void*)sithCogVm_PopSurface_ADDR;
static void* (__cdecl *sithCogVm_PopMaterial)(sithCog* ctx) = (void*)sithCogVm_PopMaterial_ADDR;
static rdKeyframe* (__cdecl *sithCogVm_PopKeyframe)(sithCog* ctx) = (void*)sithCogVm_PopKeyframe_ADDR;
static sithCog* (__cdecl *sithCogVm_PopCog)(sithCog* ctx) = (void*)sithCogVm_PopCog_ADDR;

static void (__cdecl *sithCogVm_PushVar)(sithCog *ctx, sithCogStackvar *val) = (void*)sithCogVm_PushVar_ADDR;
static void (__cdecl *sithCogVm_PushInt)(sithCog *ctx, int val) = (void*)sithCogVm_PushInt_ADDR;
static void (__cdecl *sithCogVm_PushFlex)(sithCog *ctx, float val) = (void*)sithCogVm_PushFlex_ADDR;
static void (__cdecl *sithCogVm_PushVector3)(sithCog *ctx, rdVector3 *val) = (void*)sithCogVm_PushVector3_ADDR;


#endif // _SITHCOGVM_H
