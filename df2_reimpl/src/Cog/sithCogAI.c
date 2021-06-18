#include "sithCogAI.h"

#include "AI/sithAI.h"

void sithCogAI_AISetMoveSpeed(sithCog *ctx);
void sithCogAI_SetMovePos(sithCog *ctx);
void sithCogAI_AIJump(sithCog *ctx);
void sithCogAI_AISetMoveFrame(sithCog *ctx);
void sithCogAI_AISetMoveThing(sithCog *ctx);
void sithCogAI_AISetLookPos(sithCog *ctx);
void sithCogAI_AISetLookFrame(sithCog *ctx);
void sithCogAI_GetMovePos(sithCog *ctx);
void sithCogAI_AISetMode(sithCog *ctx);
void sithCogAI_AIGetMode(sithCog *ctx);
void sithCogAI_AIClearMode(sithCog *ctx);

static void (*sithCogAI_FirstThingInView)(sithCog* ctx) = (void*)0x00501030;
static void (*sithCogAI_NextThingInView)(sithCog* ctx) = (void*)0x00501150;
static void (*sithCogAI_ThingVieweDot)(sithCog* ctx) = (void*)0x005011A0;
static void (*sithCogAI_AISetFireTarget)(sithCog* ctx) = (void*)0x005012C0;
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

void sithCogAI_AISetMoveSpeed(sithCog *ctx)
{
    double v2; // st7
    sithThing *v3; // eax
    sithActor *v4; // eax
    float a1a; // [esp+8h] [ebp+4h]

    v2 = sithCogVm_PopFlex(ctx);
    a1a = v2;
    if ( v2 < 0.0 )
    {
        a1a = 0.0;
    }
    else if ( a1a > 2.0 )
    {
        a1a = 2.0;
    }
    v3 = sithCogVm_PopThing(ctx);
    if ( v3 && v3->thingtype == THINGTYPE_ACTOR )
    {
        v4 = v3->actor;
        if ( v4 )
            v4->moveSpeed = a1a;
    }
}

void sithCogAI_SetMovePos(sithCog *ctx)
{
    sithThing *v1; // eax
    sithActor *v2; // eax
    rdVector3 v3; // [esp+4h] [ebp-Ch] BYREF

    if ( sithCogVm_PopVector3(ctx, &v3) )
    {
        v1 = sithCogVm_PopThing(ctx);
        if ( v1 )
        {
            if ( v1->thingtype == THINGTYPE_ACTOR )
            {
                v2 = v1->actor;
                if ( v2 )
                    sithAI_SetMoveThing(v2, &v3, v2->moveSpeed);
            }
        }
    }
}

void sithCogAI_AIJump(sithCog *ctx)
{
    signed int v2; // edi
    sithThing *v3; // eax
    sithActor *v4; // eax
    rdVector3 v5; // [esp+8h] [ebp-Ch] BYREF
    float a1; // [esp+18h] [ebp+4h]

    a1 = sithCogVm_PopFlex(ctx);
    v2 = sithCogVm_PopVector3(ctx, &v5);
    v3 = sithCogVm_PopThing(ctx);
    if ( v3 && v2 && v3->attach_flags && v3->thingtype == THINGTYPE_ACTOR )
    {
        v4 = v3->actor;
        if ( v4 )
            sithAI_Jump(v4, &v5, a1);
    }
}

void sithCogAI_AISetMoveFrame(sithCog *ctx)
{
    unsigned int v1; // esi
    sithThing *v2; // eax
    sithActor *v3; // eax
    rdVector3 *v4; // ecx

    v1 = sithCogVm_PopInt(ctx);
    v2 = sithCogVm_PopThing(ctx);
    if ( v2 )
    {
        if ( v2->thingtype == THINGTYPE_ACTOR )
        {
            v3 = v2->actor;
            if ( v3 )
            {
                v4 = v3->framesAlloc;
                if ( v4 )
                {
                    if ( v1 < v3->loadedFrames )
                        sithAI_SetMoveThing(v3, &v4[v1], v3->moveSpeed);
                }
            }
        }
    }
}

void sithCogAI_AISetMoveThing(sithCog *ctx)
{
    sithThing *v1; // edi
    sithThing *v2; // eax
    sithActor *v3; // eax

    v1 = sithCogVm_PopThing(ctx);
    v2 = sithCogVm_PopThing(ctx);
    if ( v2 && v1 && v2->thingtype == THINGTYPE_ACTOR )
    {
        v3 = v2->actor;
        if ( v3 )
        {
            v3->thingidk = v1;
            sithAI_SetMoveThing(v3, &v1->position, v3->moveSpeed);
        }
    }
}

void sithCogAI_AISetLookPos(sithCog *ctx)
{
    sithThing *v1; // eax
    sithActor *v2; // eax
    rdVector3 v3; // [esp+4h] [ebp-Ch] BYREF

    if ( sithCogVm_PopVector3(ctx, &v3) )
    {
        v1 = sithCogVm_PopThing(ctx);
        if ( v1 )
        {
            if ( v1->thingtype == THINGTYPE_ACTOR )
            {
                v2 = v1->actor;
                if ( v2 )
                    sithAI_SetLookFrame(v2, &v3);
            }
        }
    }
}

void sithCogAI_AISetLookFrame(sithCog *ctx)
{
    unsigned int v1; // esi
    sithThing *v2; // eax
    sithActor *v3; // eax
    rdVector3 *v4; // ecx

    v1 = sithCogVm_PopInt(ctx);
    v2 = sithCogVm_PopThing(ctx);
    if ( v2 )
    {
        if ( v2->thingtype == THINGTYPE_ACTOR )
        {
            v3 = v2->actor;
            if ( v3 )
            {
                v4 = v3->framesAlloc;
                if ( v4 )
                {
                    if ( v1 < v3->loadedFrames )
                        sithAI_SetLookFrame(v3, &v4[v1]);
                }
            }
        }
    }
}

void sithCogAI_GetMovePos(sithCog *ctx)
{
    sithThing *v1; // eax
    sithActor *v2; // eax

    v1 = sithCogVm_PopThing(ctx);
    if ( v1 && v1->thingtype == THINGTYPE_ACTOR )
    {
        v2 = v1->actor;
        if ( v2 )
            sithCogVm_PushVector3(ctx, &v2->movepos);
    }
}

void sithCogAI_AISetMode(sithCog *ctx)
{
    signed int v1; // edi
    sithThing *v2; // eax
    sithActor *v3; // ecx
    int v4; // edx

    v1 = sithCogVm_PopInt(ctx);
    v2 = sithCogVm_PopThing(ctx);
    if ( v2 )
    {
        if ( v2->thingtype == THINGTYPE_ACTOR )
        {
            v3 = v2->actor;
            if ( v3 )
            {
                v4 = v3->mode;
                v3->mode = v4 | v1;
                if ( v4 != (v4 | v1) )
                    sithAI_SetActorFireTarget(v3, 256, v4);
            }
        }
    }
}

void sithCogAI_AIGetMode(sithCog *ctx)
{
    sithThing *v1; // eax
    sithActor *v2; // eax

    v1 = sithCogVm_PopThing(ctx);
    if ( v1 && v1->thingtype == THINGTYPE_ACTOR && (v2 = v1->actor) != 0 )
        sithCogVm_PushInt(ctx, v2->mode);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogAI_AIClearMode(sithCog *ctx)
{
    signed int mode; // esi
    sithThing *thing; // eax
    sithActor *v3; // ecx
    int v4; // edx
    int mode_inv; // esi

    mode = sithCogVm_PopInt(ctx);
    thing = sithCogVm_PopThing(ctx);
    if ( thing )
    {
        if ( thing->thingtype == THINGTYPE_ACTOR )
        {
            v3 = thing->actor;
            if ( v3 )
            {
                v4 = v3->mode;
                mode_inv = ~mode;
                v3->mode = v4 & mode_inv;
                if ( v4 != (v4 & mode_inv) )
                    sithAI_SetActorFireTarget(v3, 256, v4);
            }
        }
    }
}
