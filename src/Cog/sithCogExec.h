#ifndef _COG_SITHCOGEXEC_H
#define _COG_SITHCOGEXEC_H

#include "types.h"
#include "globals.h"
#include "Engine/rdKeyframe.h"
#include "World/sithThing.h"
#include "Engine/rdMaterial.h"


#define sithCogExec_Execute_ADDR (0x004E1F60)
#define sithCogExec_ExecuteMessage_ADDR (0x004E2350)
#define sithCogExec_PopSymbol_ADDR (0x004E2440)
#define sithCogExec_PopFlex_ADDR (0x004E24F0)
#define sithCogExec_PopInt_ADDR (0x004E25C0)
#define sithCogExec_PopArray_ADDR (0x004E2690)
#define sithCogExec_PopVector_ADDR (0x004E26E0)
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

#define sithCogExec_PushStack_ADDR (0x004E32D0)
#define sithCogExec_PushInt_ADDR (0x004E3340)
#define sithCogExec_PushFlex_ADDR (0x004E33C0)
#define sithCogExec_PushVector_ADDR (0x004E3450)
#define sithCogExec_GetOpCode_ADDR (0x004E34E0)
#define sithCogExec_ResetStack_ADDR (0x004E3510)
#define sithCogExec_PushCallstack_ADDR (0x004E3530)
#define sithCogExec_PopCallstack_ADDR (0x004E3590)
#define sithCogExec_PopStack_ADDR (0x004E35E0)
#define sithCogExec_IntererOps_ADDR (0x004E3630)
#define sithCogExec_FloatOps_ADDR (0x004E3870)
#define sithCogExec_GetSymbolValue_ADDR (0x004E3B90)

// MOTS added
extern int32_t sithCogExec_009d39b0;
extern sithCog* sithCogExec_pIdkMotsCtx;
extern sithCog* sithCog_pActionCog;
extern int32_t sithCog_actionCogIdk;

void sithCogExec_Execute(sithCog *cog_ctx);
void sithCogExec_ExecuteMessage(sithCog *ctx, int32_t trigIdx);
int32_t sithCogExec_PopSymbol(sithCog *ctx, SithCogSymbolValue *stackVar);
cog_flex_t sithCogExec_PopFlex(sithCog *ctx);
int32_t sithCogExec_PopInt(sithCog *ctx);
int32_t sithCogExec_PopArray(sithCog *ctx);
int32_t sithCogExec_PopVector(sithCog *ctx, rdVector3* out);
sithCog* sithCogExec_PopCog(sithCog *ctx);
SithThing* sithCogExec_PopThing(sithCog *ctx);
SithThing* sithCogExec_PopTemplate(sithCog *ctx);
sithSound* sithCogExec_PopSound(sithCog *ctx);
SithSector* sithCogExec_PopSector(sithCog *ctx);
SithSurface* sithCogExec_PopSurface(sithCog *ctx);
rdMaterial* sithCogExec_PopMaterial(sithCog *ctx);
rdModel3* sithCogExec_PopModel3(sithCog *ctx);
rdKeyframe* sithCogExec_PopKeyframe(sithCog *ctx);
SithAIClass* sithCogExec_PopAIClass(sithCog *ctx);
char* sithCogExec_PopString(sithCog *ctx);
cogSymbolFunc_t sithCogExec_PopSymbolFunc(sithCog *cog_ctx);
void sithCogExec_PushStack(sithCog *ctx, SithCogSymbolValue *val);
void sithCogExec_PushInt(sithCog *ctx, int32_t val);
void sithCogExec_PushFlex(sithCog *ctx, cog_flex_t val);
void sithCogExec_PushVector(sithCog *ctx, const rdVector3* val);
int32_t sithCogExec_GetOpCode(sithCog *ctx);
void sithCogExec_ResetStack(sithCog *ctx);
void sithCogExec_PushCallstack(sithCog *ctx);
void sithCogExec_PopCallstack(sithCog *cog_ctx);
int32_t sithCogExec_PopStack(sithCog *cog, SithCogSymbolValue *out);
void sithCogExec_IntererOps(sithCog *cog_ctx, int32_t op);
void sithCogExec_FloatOps(sithCog *cog_ctx, int32_t op);
SithCogSymbolValue* sithCogExec_GetSymbolValue(SithCogSymbolValue *out, sithCog *ctx, SithCogSymbolValue *in);

#ifdef COG_DYNAMIC_STACKS
void sithCogExec_GrowStack(sithCog* pCtx, uint32_t sz);
#endif

void sithCogExec_Push3Floats(sithCog *ctx, const cog_flex_t* val);

//static void (__cdecl *sithCogExec_PopCallstack)(sithCog *cog) = (void*)sithCogExec_PopCallstack_ADDR;
//static void (__cdecl *sithCogExec_PushCallstack)(sithCog *cog) = (void*)sithCogExec_PushCallstack_ADDR;

//static int32_t (__cdecl *sithCogExec_GetOpCode)(sithCog *cog) = (void*)sithCogExec_GetOpCode_ADDR;
//static int32_t (__cdecl *sithCogExec_PopStack)(sithCog *cog, SithCogSymbolValue *out) = (void*)sithCogExec_PopStack_ADDR;
//static SithCogSymbolValue* (__cdecl *sithCogExec_GetSymbolValue)(SithCogSymbolValue *a1, sithCog* a2, SithCogSymbolValue *a3) = (void*)sithCogExec_GetSymbolValue_ADDR;
//static void (__cdecl *sithCogExec_FloatOps)(sithCog *cog, int32_t op) = (void*)sithCogExec_FloatOps_ADDR;
//static void (__cdecl *sithCogExec_IntererOps)(sithCog *cog, int32_t op) = (void*)sithCogExec_IntererOps_ADDR;
//static int32_t (__cdecl *sithCogExec_PopSymbol)(sithCog *ctx, int32_t *out) = (void*)sithCogExec_PopSymbol_ADDR;
//static cog_flex_t (__cdecl *sithCogExec_PopFlex)(sithCog *ctx) = (void*)sithCogExec_PopFlex_ADDR;
//static int32_t (__cdecl *sithCogExec_PopInt)(sithCog *ctx) = (void*)sithCogExec_PopInt_ADDR;
//static int32_t (__cdecl *sithCogExec_PopVector)(sithCog *ctx, rdVector3* out) = (void*)sithCogExec_PopVector_ADDR;
//static char* (__cdecl *sithCogExec_PopString)(sithCog *ctx) = (void*)sithCogExec_PopString_ADDR;
//static SithSurface* (__cdecl *sithCogExec_PopSurface)(sithCog* ctx) = (void*)sithCogExec_PopSurface_ADDR;
//static void* (__cdecl *sithCogExec_PopMaterial)(sithCog* ctx) = (void*)sithCogExec_PopMaterial_ADDR;
//static rdKeyframe* (__cdecl *sithCogExec_PopKeyframe_)(sithCog* ctx) = (void*)sithCogExec_PopKeyframe_ADDR;
//static sithCog* (__cdecl *sithCogExec_PopCog)(sithCog* ctx) = (void*)sithCogExec_PopCog_ADDR;
//static int32_t (__cdecl *sithCogExec_PopArray)(sithCog *ctx) = (void*)sithCogExec_PopArray_ADDR;
//static cogSymbolFunc_t (__cdecl *sithCogExec_PopSymbolFunc)(sithCog *cog_ctx) = (void*)sithCogExec_PopSymbolFunc_ADDR;

//static void (__cdecl *sithCogExec_PushStack)(sithCog *ctx, SithCogSymbolValue *val) = (void*)sithCogExec_PushStack_ADDR;
//static void (__cdecl *sithCogExec_PushInt)(sithCog *ctx, int32_t val) = (void*)sithCogExec_PushInt_ADDR;
//static void (__cdecl *sithCogExec_PushFlex)(sithCog *ctx, cog_flex_t val) = (void*)sithCogExec_PushFlex_ADDR;
//static void (__cdecl *sithCogExec_PushVector)(sithCog *ctx, const rdVector3 *val) = (void*)sithCogExec_PushVector_ADDR;


#endif // _COG_SITHCOGEXEC_H
