#ifndef _COG_SITHCOGEXEC_H
#define _COG_SITHCOGEXEC_H

#include "types.h"
#include "globals.h"
#include "Engine/rdKeyframe.h"
#include "World/sithThing.h"
#include "Engine/rdMaterial.h"


#define sithCogExec_Exec_ADDR (0x004E1F60)
#define sithCogExec_ExecCog_ADDR (0x004E2350)
#define sithCogExec_PopValue_ADDR (0x004E2440)
#define sithCogExec_PopFlex_ADDR (0x004E24F0)
#define sithCogExec_PopInt_ADDR (0x004E25C0)
#define sithCogExec_PopSymbolIdx_ADDR (0x004E2690)
#define sithCogExec_PopVector3_ADDR (0x004E26E0)
#define sithCogExec_PopCog_ADDR (0x004E27B0)
#define sithCogExec_PopThing_ADDR (0x004E28C0)
#define sithCogExec_PopTemplate_ADDR (0x004E29C0)
#define sithCogExec_PopSound_ADDR (0x004E2AD0)
#define sithCogExec_PopSector_ADDR (0x004E2BD0)
#define sithCogExec_PopSurface_ADDR (0x004E2CC0)
#define sithCogExec_PopMaterial_ADDR (0x004E2DB0)
#define sithCogExec_PopModel3_ADDR (0x004E2EB0)
#define sithCogExec_PopKeyframe_ADDR (0x004E2FB0)
#define sithCogExec_PopAIClass_ADDR (0x004E30B0)
#define sithCogExec_PopSymbolFunc_ADDR (0x004E31B0)
#define sithCogExec_PopString_ADDR (0x004E3260)

#define sithCogExec_PushVar_ADDR (0x004E32D0)
#define sithCogExec_PushInt_ADDR (0x004E3340)
#define sithCogExec_PushFlex_ADDR (0x004E33C0)
#define sithCogExec_PushVector3_ADDR (0x004E3450)
#define sithCogExec_PopProgramVal_ADDR (0x004E34E0)
#define sithCogExec_ResetStack_ADDR (0x004E3510)
#define sithCogExec_Call_ADDR (0x004E3530)
#define sithCogExec_Ret_ADDR (0x004E3590)
#define sithCogExec_PopStackVar_ADDR (0x004E35E0)
#define sithCogExec_BitOperation_ADDR (0x004E3630)
#define sithCogExec_MathOperation_ADDR (0x004E3870)
#define sithCogExec_AssignStackVar_ADDR (0x004E3B90)

// MOTS added
extern int sithCogExec_009d39b0;
extern sithCog* sithCogExec_pIdkMotsCtx;
extern sithCog* sithCog_pActionCog;
extern int sithCog_actionCogIdk;

void sithCogExec_Exec(sithCog *cog_ctx);
void sithCogExec_ExecCog(sithCog *ctx, int trigIdx);
int sithCogExec_PopValue(sithCog *ctx, sithCogStackvar *stackVar);
flex_t sithCogExec_PopFlex(sithCog *ctx);
int sithCogExec_PopInt(sithCog *ctx);
int sithCogExec_PopSymbolIdx(sithCog *ctx);
int sithCogExec_PopVector3(sithCog *ctx, rdVector3* out);
sithCog* sithCogExec_PopCog(sithCog *ctx);
sithThing* sithCogExec_PopThing(sithCog *ctx);
sithThing* sithCogExec_PopTemplate(sithCog *ctx);
sithSound* sithCogExec_PopSound(sithCog *ctx);
sithSector* sithCogExec_PopSector(sithCog *ctx);
sithSurface* sithCogExec_PopSurface(sithCog *ctx);
rdMaterial* sithCogExec_PopMaterial(sithCog *ctx);
rdModel3* sithCogExec_PopModel3(sithCog *ctx);
rdKeyframe* sithCogExec_PopKeyframe(sithCog *ctx);
sithAIClass* sithCogExec_PopAIClass(sithCog *ctx);
char* sithCogExec_PopString(sithCog *ctx);
cogSymbolFunc_t sithCogExec_PopSymbolFunc(sithCog *cog_ctx);
void sithCogExec_PushVar(sithCog *ctx, sithCogStackvar *val);
void sithCogExec_PushInt(sithCog *ctx, int val);
void sithCogExec_PushFlex(sithCog *ctx, flex_t val);
void sithCogExec_PushVector3(sithCog *ctx, const rdVector3* val);
int sithCogExec_PopProgramVal(sithCog *ctx);
void sithCogExec_ResetStack(sithCog *ctx);
void sithCogExec_Call(sithCog *ctx);
void sithCogExec_Ret(sithCog *cog_ctx);
int sithCogExec_PopStackVar(sithCog *cog, sithCogStackvar *out);
void sithCogExec_BitOperation(sithCog *cog_ctx, int op);
void sithCogExec_MathOperation(sithCog *cog_ctx, int op);
sithCogStackvar* sithCogExec_AssignStackVar(sithCogStackvar *out, sithCog *ctx, sithCogStackvar *in);

//static void (__cdecl *sithCogExec_Ret)(sithCog *cog) = (void*)sithCogExec_Ret_ADDR;
//static void (__cdecl *sithCogExec_Call)(sithCog *cog) = (void*)sithCogExec_Call_ADDR;

//static int (__cdecl *sithCogExec_PopProgramVal)(sithCog *cog) = (void*)sithCogExec_PopProgramVal_ADDR;
//static int (__cdecl *sithCogExec_PopStackVar)(sithCog *cog, sithCogStackvar *out) = (void*)sithCogExec_PopStackVar_ADDR;
//static sithCogStackvar* (__cdecl *sithCogExec_AssignStackVar)(sithCogStackvar *a1, sithCog* a2, sithCogStackvar *a3) = (void*)sithCogExec_AssignStackVar_ADDR;
//static void (__cdecl *sithCogExec_MathOperation)(sithCog *cog, int op) = (void*)sithCogExec_MathOperation_ADDR;
//static void (__cdecl *sithCogExec_BitOperation)(sithCog *cog, int op) = (void*)sithCogExec_BitOperation_ADDR;
//static int (__cdecl *sithCogExec_PopValue)(sithCog *ctx, int *out) = (void*)sithCogExec_PopValue_ADDR;
//static flex_t (__cdecl *sithCogExec_PopFlex)(sithCog *ctx) = (void*)sithCogExec_PopFlex_ADDR;
//static int (__cdecl *sithCogExec_PopInt)(sithCog *ctx) = (void*)sithCogExec_PopInt_ADDR;
//static int (__cdecl *sithCogExec_PopVector3)(sithCog *ctx, rdVector3* out) = (void*)sithCogExec_PopVector3_ADDR;
//static char* (__cdecl *sithCogExec_PopString)(sithCog *ctx) = (void*)sithCogExec_PopString_ADDR;
//static sithSurface* (__cdecl *sithCogExec_PopSurface)(sithCog* ctx) = (void*)sithCogExec_PopSurface_ADDR;
//static void* (__cdecl *sithCogExec_PopMaterial)(sithCog* ctx) = (void*)sithCogExec_PopMaterial_ADDR;
//static rdKeyframe* (__cdecl *sithCogExec_PopKeyframe_)(sithCog* ctx) = (void*)sithCogExec_PopKeyframe_ADDR;
//static sithCog* (__cdecl *sithCogExec_PopCog)(sithCog* ctx) = (void*)sithCogExec_PopCog_ADDR;
//static int (__cdecl *sithCogExec_PopSymbolIdx)(sithCog *ctx) = (void*)sithCogExec_PopSymbolIdx_ADDR;
//static cogSymbolFunc_t (__cdecl *sithCogExec_PopSymbolFunc)(sithCog *cog_ctx) = (void*)sithCogExec_PopSymbolFunc_ADDR;

//static void (__cdecl *sithCogExec_PushVar)(sithCog *ctx, sithCogStackvar *val) = (void*)sithCogExec_PushVar_ADDR;
//static void (__cdecl *sithCogExec_PushInt)(sithCog *ctx, int val) = (void*)sithCogExec_PushInt_ADDR;
//static void (__cdecl *sithCogExec_PushFlex)(sithCog *ctx, flex_t val) = (void*)sithCogExec_PushFlex_ADDR;
//static void (__cdecl *sithCogExec_PushVector3)(sithCog *ctx, const rdVector3 *val) = (void*)sithCogExec_PushVector3_ADDR;


#endif // _COG_SITHCOGEXEC_H
