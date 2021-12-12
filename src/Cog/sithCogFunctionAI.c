#include "sithCogFunctionAI.h"

#include "Engine/sithTime.h"
#include "AI/sithAI.h"
#include "AI/sithAIClass.h"
#include "Main/jkGame.h"
#include "jk.h"

void sithCogFunctionAI_AISetMoveSpeed(sithCog *ctx);
void sithCogFunctionAI_SetMovePos(sithCog *ctx);
void sithCogFunctionAI_AIJump(sithCog *ctx);
void sithCogFunctionAI_AISetMoveFrame(sithCog *ctx);
void sithCogFunctionAI_AISetMoveThing(sithCog *ctx);
void sithCogFunctionAI_AISetLookPos(sithCog *ctx);
void sithCogFunctionAI_AISetLookFrame(sithCog *ctx);
void sithCogFunctionAI_GetMovePos(sithCog *ctx);
void sithCogFunctionAI_AISetMode(sithCog *ctx);
void sithCogFunctionAI_AIGetMode(sithCog *ctx);
void sithCogFunctionAI_AIClearMode(sithCog *ctx);
void sithCogFunctionAI_FirstThingInView(sithCog *ctx);
void sithCogFunctionAI_NextThingInView(sithCog *ctx);
void sithCogFunctionAI_ThingViewDot(sithCog *ctx);
void sithCogFunctionAI_AISetFireTarget(sithCog *ctx);
void sithCogFunctionAI_IsAITargetInSight(sithCog *ctx);
void sithCogFunctionAI_AIFlee(sithCog *ctx);
void sithCogFunctionAI_AISetClass(sithCog *ctx);

void sithCogFunctionAI_Initialize(void* ctx)
{
    sithCogScript_RegisterVerb(ctx, sithCogFunctionAI_AIGetMode, "aigetmode");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionAI_AISetMode, "aisetmode");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionAI_AIClearMode, "aiclearmode");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionAI_GetMovePos, "aigetmovepos");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionAI_SetMovePos, "aisetmovepos");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionAI_FirstThingInView, "firstthinginview");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionAI_NextThingInView, "nextthinginview");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionAI_ThingViewDot, "thingviewdot");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionAI_AISetFireTarget, "aisetfiretarget");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionAI_AISetMoveThing, "aisetmovething");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionAI_AISetLookPos, "aisetlookpos");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionAI_AISetMoveSpeed, "aisetmovespeed");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionAI_AISetLookFrame, "aisetlookframe");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionAI_AISetMoveFrame, "aisetmoveframe");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionAI_IsAITargetInSight, "isaitargetinsight");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionAI_AIFlee, "aiflee");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionAI_AISetClass, "aisetclass");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionAI_AIJump, "aijump");
}

void sithCogFunctionAI_AISetMoveSpeed(sithCog *ctx)
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
    if ( v3 && v3->thingtype == SITH_THING_ACTOR )
    {
        v4 = v3->actor;
        if ( v4 )
            v4->moveSpeed = a1a;
    }
}

void sithCogFunctionAI_SetMovePos(sithCog *ctx)
{
    sithThing *v1; // eax
    sithActor *v2; // eax
    rdVector3 v3; // [esp+4h] [ebp-Ch] BYREF

    if ( sithCogVm_PopVector3(ctx, &v3) )
    {
        v1 = sithCogVm_PopThing(ctx);
        
        // Added
        if (g_debugmodeFlags & 1) return;
        
        if ( v1 )
        {
            if ( v1->thingtype == SITH_THING_ACTOR )
            {
                v2 = v1->actor;
                if ( v2 )
                    sithAI_SetMoveThing(v2, &v3, v2->moveSpeed);
            }
        }
    }
}

void sithCogFunctionAI_AIJump(sithCog *ctx)
{
    signed int v2; // edi
    sithThing *v3; // eax
    sithActor *v4; // eax
    rdVector3 v5; // [esp+8h] [ebp-Ch] BYREF
    float a1; // [esp+18h] [ebp+4h]

    a1 = sithCogVm_PopFlex(ctx);
    v2 = sithCogVm_PopVector3(ctx, &v5);
    v3 = sithCogVm_PopThing(ctx);
    
    // Added
    if (g_debugmodeFlags & 1) return;
    
    if ( v3 && v2 && v3->attach_flags && v3->thingtype == SITH_THING_ACTOR )
    {
        v4 = v3->actor;
        if ( v4 )
            sithAI_Jump(v4, &v5, a1);
    }
}

void sithCogFunctionAI_AISetMoveFrame(sithCog *ctx)
{
    unsigned int v1; // esi
    sithThing *v2; // eax
    sithActor *v3; // eax
    rdVector3 *v4; // ecx

    v1 = sithCogVm_PopInt(ctx);
    v2 = sithCogVm_PopThing(ctx);
    
    // Added
    if (g_debugmodeFlags & 1) return;
    
    if ( v2 )
    {
        if ( v2->thingtype == SITH_THING_ACTOR )
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

void sithCogFunctionAI_AISetMoveThing(sithCog *ctx)
{
    sithThing *v1; // edi
    sithThing *v2; // eax
    sithActor *v3; // eax

    v1 = sithCogVm_PopThing(ctx);
    v2 = sithCogVm_PopThing(ctx);
    
    // Added
    if (g_debugmodeFlags & 1) return;
    
    if ( v2 && v1 && v2->thingtype == SITH_THING_ACTOR )
    {
        v3 = v2->actor;
        if ( v3 )
        {
            v3->thingidk = v1;
            sithAI_SetMoveThing(v3, &v1->position, v3->moveSpeed);
        }
    }
}

void sithCogFunctionAI_AISetLookPos(sithCog *ctx)
{
    sithThing *v1; // eax
    sithActor *v2; // eax
    rdVector3 v3; // [esp+4h] [ebp-Ch] BYREF

    if ( sithCogVm_PopVector3(ctx, &v3) )
    {
        v1 = sithCogVm_PopThing(ctx);
        
        // Added
        if (g_debugmodeFlags & 1) return;
        
        if ( v1 )
        {
            if ( v1->thingtype == SITH_THING_ACTOR )
            {
                v2 = v1->actor;
                if ( v2 )
                    sithAI_SetLookFrame(v2, &v3);
            }
        }
    }
}

void sithCogFunctionAI_AISetLookFrame(sithCog *ctx)
{
    unsigned int v1; // esi
    sithThing *v2; // eax
    sithActor *v3; // eax
    rdVector3 *v4; // ecx

    v1 = sithCogVm_PopInt(ctx);
    v2 = sithCogVm_PopThing(ctx);
    
    // Added
    if (g_debugmodeFlags & 1) return;
    
    if ( v2 )
    {
        if ( v2->thingtype == SITH_THING_ACTOR )
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

void sithCogFunctionAI_GetMovePos(sithCog *ctx)
{
    sithThing *v1; // eax
    sithActor *v2; // eax

    v1 = sithCogVm_PopThing(ctx);
    if ( v1 && v1->thingtype == SITH_THING_ACTOR )
    {
        v2 = v1->actor;
        if ( v2 )
            sithCogVm_PushVector3(ctx, &v2->movepos);
    }
}

void sithCogFunctionAI_AISetMode(sithCog *ctx)
{
    signed int v1; // edi
    sithThing *v2; // eax
    sithActor *v3; // ecx
    int v4; // edx

    v1 = sithCogVm_PopInt(ctx);
    v2 = sithCogVm_PopThing(ctx);
    
    // Added
    if (g_debugmodeFlags & 1) return;
    
    if ( v2 )
    {
        if ( v2->thingtype == SITH_THING_ACTOR )
        {
            v3 = v2->actor;
            if ( v3 )
            {
                v4 = v3->flags;
                v3->flags = v4 | v1;
                if ( v4 != (v4 | v1) )
                    sithAI_SetActorFireTarget(v3, 256, v4);
            }
        }
    }
}

void sithCogFunctionAI_AIGetMode(sithCog *ctx)
{
    sithThing *v1; // eax
    sithActor *v2; // eax

    v1 = sithCogVm_PopThing(ctx);
    if ( v1 && v1->thingtype == SITH_THING_ACTOR && (v2 = v1->actor) != 0 )
        sithCogVm_PushInt(ctx, v2->flags);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionAI_AIClearMode(sithCog *ctx)
{
    signed int mode; // esi
    sithThing *thing; // eax
    sithActor *v3; // ecx
    int v4; // edx
    int mode_inv; // esi

    mode = sithCogVm_PopInt(ctx);
    thing = sithCogVm_PopThing(ctx);
    
    // Added
    if (g_debugmodeFlags & 1) return;
    
    if ( thing )
    {
        if ( thing->thingtype == SITH_THING_ACTOR )
        {
            v3 = thing->actor;
            if ( v3 )
            {
                v4 = v3->flags;
                mode_inv = ~mode;
                v3->flags = v4 & mode_inv;
                if ( v4 != (v4 & mode_inv) )
                    sithAI_SetActorFireTarget(v3, 256, v4);
            }
        }
    }
}

void sithCogFunctionAI_FirstThingInView(sithCog *ctx)
{
    sithThing *v2; // eax
    sithThing *v3; // ebx
    int v4; // eax
    signed int v5; // [esp+10h] [ebp-38h]
    float v6; // [esp+14h] [ebp-34h]
    rdMatrix34 v7; // [esp+18h] [ebp-30h] BYREF
    float a1; // [esp+4Ch] [ebp+4h]

    v5 = sithCogVm_PopInt(ctx);
    a1 = sithCogVm_PopFlex(ctx);
    v6 = sithCogVm_PopFlex(ctx);
    v2 = sithCogVm_PopThing(ctx);
    
    // Added
    if (g_debugmodeFlags & 1)
    {
        sithCogVm_PushInt(ctx, -1);
        return;
    }
    
    v3 = v2;
    if ( v2
      && ((_memcpy(&v7, &v2->lookOrientation, sizeof(v7)), v4 = v2->type, v4 == SITH_THING_ACTOR) || v4 == SITH_THING_PLAYER ? (rdMatrix_PreRotate34(
                                                                                                                                       &v7,
                                                                                                                                       &v3->actorParams.eyePYR),
                                                                                                                                   rdMatrix_PostTranslate34(
                                                                                                                                       &v7,
                                                                                                                                       &v3->position),
                                                                                                                                   rdMatrix_PreTranslate34(
                                                                                                                                       &v7,
                                                                                                                                       &v3->actorParams.eyeOffset)) : rdMatrix_PostTranslate34(&v7, &v3->position),
          (sithCogFunctionAI_unk1 = sithAI_FirstThingInView(v3->sector, &v7, v6, v6, 32, sithCogFunctionAI_apViewThings, v5, a1), sithCogFunctionAI_viewThingIdx = 0, sithCogFunctionAI_unk1 > 0)
       && sithCogFunctionAI_apViewThings[0]) )
    {
        sithCogVm_PushInt(ctx, sithCogFunctionAI_apViewThings[0]->thingIdx);
    }
    else
    {
        sithCogVm_PushInt(ctx, -1);
    }
}

void sithCogFunctionAI_NextThingInView(sithCog *ctx)
{
    int v1; // eax
    sithThing *v2; // eax

    v1 = ++sithCogFunctionAI_viewThingIdx;
    if ( sithCogFunctionAI_viewThingIdx < sithCogFunctionAI_unk1 && (v2 = sithCogFunctionAI_apViewThings[v1]) != 0 )
        sithCogVm_PushInt(ctx, v2->thingIdx);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionAI_ThingViewDot(sithCog *ctx)
{
    sithThing *v1; // ebp
    sithThing *v2; // eax
    sithThing *v3; // ebx
    float a2; // [esp+0h] [ebp-5Ch]
    rdVector3 v6; // [esp+14h] [ebp-48h] BYREF
    rdVector3 v7; // [esp+20h] [ebp-3Ch] BYREF
    rdMatrix34 v8; // [esp+2Ch] [ebp-30h] BYREF

    v1 = sithCogVm_PopThing(ctx);
    v2 = sithCogVm_PopThing(ctx);
    
    // Added
    if (g_debugmodeFlags & 1)
    {
        sithCogVm_PushFlex(ctx, -1000.0);
        return;
    }
    
    v3 = v2;
    if ( v1 && v2 )
    {
        _memcpy(&v8, &v2->lookOrientation, sizeof(v8));
        if ( v2->type == SITH_THING_ACTOR || v2->type == SITH_THING_PLAYER )
            rdMatrix_PreRotate34(&v8, &v3->actorParams.eyePYR);
        v6 = v8.lvec;
        v7.x = v1->position.x - v3->position.x;
        v7.y = v1->position.y - v3->position.y;
        v7.z = v1->position.z - v3->position.z;
        rdVector_Normalize3Acc(&v6);
        rdVector_Normalize3Acc(&v7);
        a2 = v6.x * v7.x + v6.y * v7.y + v6.z * v7.z;
        sithCogVm_PushFlex(ctx, a2);
    }
    else
    {
        sithCogVm_PushFlex(ctx, -1000.0);
    }
}

void sithCogFunctionAI_AISetFireTarget(sithCog *ctx)
{
    sithThing *v1; // esi
    sithThing *v2; // eax
    sithActor *v3; // eax
    unsigned int v4; // ecx
    int v5; // ecx
    unsigned int v6; // edx

    v1 = sithCogVm_PopThing(ctx);
    v2 = sithCogVm_PopThing(ctx);
    
    // Added
    if (g_debugmodeFlags & 1) return;
    
    if ( v2 )
    {
        if ( v2->thingtype == SITH_THING_ACTOR )
        {
            v3 = v2->actor;
            if ( v3 )
            {
                v4 = sithTime_curMs;
                v3->field_1D0 = v1;
                v3->field_204 = v4;
                v5 = v3->flags;
                if ( v1 )
                    v6 = v5 | 0x20;
                else
                    v6 = v5 & ~0x20u;
                v3->flags = v6;
                if ( v6 != v5 )
                    sithAI_SetActorFireTarget(v3, 256, v5);
            }
        }
    }
}

// Unused?
void sithCogFunctionAI_sub_501330(sithCog *ctx)
{
    char *v1; // edi
    sithThing *v2; // eax
    sithActor *v3; // esi
    sithAICommand *v4; // eax
    unsigned int v5; // edx
    unsigned int v6; // ecx
    void *v7; // edi

    v1 = sithCogVm_PopString(ctx);
    v2 = sithCogVm_PopThing(ctx);
    if ( !v2 )
        goto LABEL_12;
    if ( !v1 )
        goto LABEL_12;
    if ( v2->thingtype != SITH_THING_ACTOR )
        goto LABEL_12;
    v3 = v2->actor;
    if ( !v3 )
        goto LABEL_12;
    v4 = sithAI_FindCommand(v1);
    if ( !v4 )
        goto LABEL_12;
    v5 = v3->numAIClassEntries;
    v6 = 0;
    if ( v5 )
    {
        v7 = (void *)v4->func;
        do
        {
            if ( v3->aiclass->entries[v6].func == v7 )
                break;
            ++v6;
        }
        while ( v6 < v5 );
    }
    if ( v6 < v5 )
        sithCogVm_PushInt(ctx, v6);
    else
LABEL_12:
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionAI_IsAITargetInSight(sithCog *ctx)
{
    sithThing *v1; // eax
    sithActor *v2; // eax

    v1 = sithCogVm_PopThing(ctx);
    if ( v1 && v1->type == SITH_THING_ACTOR && v1->thingtype == SITH_THING_ACTOR && (v2 = v1->actor) != 0 && !v2->field_1F4 )
        sithCogVm_PushInt(ctx, 1);
    else
        sithCogVm_PushInt(ctx, 0);
}

void sithCogFunctionAI_AIFlee(sithCog *ctx)
{
    sithThing *v1; // edi
    sithThing *v2; // eax
    sithActor *v3; // eax
    int v4; // ecx

    v1 = sithCogVm_PopThing(ctx);
    v2 = sithCogVm_PopThing(ctx);
    
    // Added
    if (g_debugmodeFlags & 1) return;
    
    if ( v1 )
    {
        if ( v2 )
        {
            if ( v2->type == SITH_THING_ACTOR && v2->thingtype == SITH_THING_ACTOR )
            {
                v3 = v2->actor;
                if ( v3 )
                {
                    v4 = v3->flags;
                    v3->field_1C0 = v1;
                    if ( (v4 & 0x800) == 0 )
                    {
                        v3->flags |= 0x800;
                        sithAI_SetActorFireTarget(v3, 256, v4);
                    }
                }
            }
        }
    }
}

void sithCogFunctionAI_AISetClass(sithCog *ctx)
{
    sithAIClass *aiclass; // esi
    sithThing *thing; // eax
    sithActor *v3; // ecx
    int v4; // eax

    aiclass = sithCogVm_PopAIClass(ctx);
    thing = sithCogVm_PopThing(ctx);
    if ( aiclass && thing && thing->thingtype == SITH_THING_ACTOR )
    {
        v3 = thing->actor;
        if ( v3 )
        {
            thing->aiclass = aiclass;
            v4 = aiclass->numEntries;
            v3->aiclass = aiclass;
            v3->numAIClassEntries = v4;
        }
    }
}
