#include "sithCogAI.h"

static void (*sithCogAI_AISetMoveSpeed)(sithCog* ctx) = (void*)0x00500C60;
static void (*sithCogAI_SetMovePos)(sithCog* ctx) = (void*)0x00500CD0;
static void (*sithCogAI_AIJump)(sithCog* ctx) = (void*)0x00500D30;
static void (*sithCogAI_AISetMoveFrame)(sithCog* ctx) = (void*)0x00500DA0;
static void (*sithCogAI_AISetMoveThing)(sithCog* ctx) = (void*)0x00500E00;
static void (*sithCogAI_AISetLookPos)(sithCog* ctx) = (void*)0x00500E60;
static void (*sithCogAI_AISetLookFrame)(sithCog* ctx) = (void*)0x00500EB0;
static void (*sithCogAI_GetMovePos)(sithCog* ctx) = (void*)0x00500F10;
static void (*sithCogAI_AISetMode)(sithCog* ctx) = (void*)0x00500F50;
static void (*sithCogAI_AIGetMode)(sithCog* ctx) = (void*)0x00500FA0;
static void (*sithCogAI_AIClearMode)(sithCog* ctx) = (void*)0x00500FE0;
static void (*sithCogAI_FirstThingInView)(sithCog* ctx) = (void*)0x00501030;
static void (*sithCogAI_NextThingInView)(sithCog* ctx) = (void*)0x00501150;
static void (*sithCogAI_ThingVieweDot)(sithCog* ctx) = (void*)0x005011A0;
static void (*sithCogAI_AISetFireTarget)(sithCog* ctx) = (void*)0x005012C0;
static void (*sithCogAI_sub_501330)(sithCog* ctx) = (void*)0x00501330;
static void (*sithCogAI_IsAITargetInSight)(sithCog* ctx) = (void*)0x005013C0;
static void (*sithCogAI_AIFlee)(sithCog* ctx) = (void*)0x00501420;
static void (*sithCogAI_AISetClass)(sithCog* ctx) = (void*)0x00501490;

void sithCogAI_Initialize(void* ctx)
{
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogAI_AIGetMode, "aigetmode");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogAI_AISetMode, "aisetmode");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogAI_AIClearMode, "aiclearmode");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogAI_GetMovePos, "aigetmovepos");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogAI_SetMovePos, "aisetmovepos");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogAI_FirstThingInView, "firstthinginview");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogAI_NextThingInView, "nextthinginview");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogAI_ThingVieweDot, "thingviewdot");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogAI_AISetFireTarget, "aisetfiretarget");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogAI_AISetMoveThing, "aisetmovething");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogAI_AISetLookPos, "aisetlookpos");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogAI_AISetMoveSpeed, "aisetmovespeed");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogAI_AISetLookFrame, "aisetlookframe");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogAI_AISetMoveFrame, "aisetmoveframe");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogAI_IsAITargetInSight, "isaitargetinsight");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogAI_AIFlee, "aiflee");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogAI_AISetClass, "aisetclass");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogAI_AIJump, "aijump");
}
