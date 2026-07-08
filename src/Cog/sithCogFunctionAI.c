#include "sithCogFunctionAI.h"

#include "General/stdMath.h" 
#include "Gameplay/sithTime.h"
#include "AI/sithAI.h"
#include "AI/sithAIClass.h"
#include "Main/jkGame.h"
#include "jk.h"


void sithCogFunctionAI_AISetMoveSpeed(sithCog *pCog)
{
    // Added: assert ported from OpenJones3D
    SITH_ASSERTREL(pCog);

    cog_flex_t moveSpeed = stdMath_Clamp(sithCogExec_PopFlex(pCog), 0.0, 2.0);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing && pThing->controlType == SITH_CT_AI && pThing->actor)
    {
        pThing->actor->moveSpeed = moveSpeed;
    }
}

void sithCogFunctionAI_AISetMovePos(sithCog *pCog)
{
    SithThing *v1; // eax
    SithAIControlBlock *v2; // eax
    rdVector3 v3; // [esp+4h] [ebp-Ch] BYREF

    // Added: assert ported from OpenJones3D
    SITH_ASSERTREL(pCog);

    // TODO: Bug? If the vector is invalid, other aArgs will never get popped.
    if (sithCogExec_PopVector(pCog, &v3))
    {
        SithThing* pThing = sithCogExec_PopThing(pCog);
        
        // Added
        if (g_debugmodeFlags & DEBUGFLAG_NO_AIEVENTS) return;
        
        if (pThing && pThing->controlType == SITH_CT_AI && pThing->actor)
        {
            sithAI_SetMoveThing(pThing->actor, &v3, pThing->actor->moveSpeed);
        }
    }
}

void sithCogFunctionAI_AIJump(sithCog *pCog)
{
    signed int v2; // edi
    SithThing *v3; // eax
    SithAIControlBlock *v4; // eax
    rdVector3 v5; // [esp+8h] [ebp-Ch] BYREF

    // Added: assert ported from OpenJones3D
    SITH_ASSERTREL(pCog);

    cog_flex_t a1 = sithCogExec_PopFlex(pCog);
    v2 = sithCogExec_PopVector(pCog, &v5);
    v3 = sithCogExec_PopThing(pCog);
    
    // Added
    if (g_debugmodeFlags & DEBUGFLAG_NO_AIEVENTS) return;
    
    if ( v3 && v2 && v3->attach_flags && v3->controlType == SITH_CT_AI )
    {
        v4 = v3->actor;
        if ( v4 )
            sithAI_Jump(v4, &v5, a1);
    }
}

void sithCogFunctionAI_AISetMoveFrame(sithCog *pCog)
{
    unsigned int v1; // esi
    SithThing *v2; // eax
    SithAIControlBlock *v3; // eax
    rdVector3 *v4; // ecx

    // Added: assert ported from OpenJones3D
    SITH_ASSERTREL(pCog);

    v1 = sithCogExec_PopInt(pCog);
    v2 = sithCogExec_PopThing(pCog);
    
    // Added
    if (g_debugmodeFlags & DEBUGFLAG_NO_AIEVENTS) return;
    
    if ( v2 )
    {
        if ( v2->controlType == SITH_CT_AI )
        {
            v3 = v2->actor;
            if ( v3 )
            {
                v4 = v3->aFrames;
                if ( v4 )
                {
                    if ( v1 < v3->loadedFrames )
                        sithAI_SetMoveThing(v3, &v4[v1], v3->moveSpeed);
                }
            }
        }
    }
}

void sithCogFunctionAI_AISetMoveThing(sithCog *pCog)
{
    SithThing *v1; // edi
    SithThing *v2; // eax
    SithAIControlBlock *v3; // eax

    // Added: assert ported from OpenJones3D
    SITH_ASSERTREL(pCog);

    v1 = sithCogExec_PopThing(pCog);
    v2 = sithCogExec_PopThing(pCog);
    
    // Added
    if (g_debugmodeFlags & DEBUGFLAG_NO_AIEVENTS) return;
    
    if ( v2 && v1 && v2->controlType == SITH_CT_AI )
    {
        v3 = v2->actor;
        if ( v3 )
        {
            v3->pMoveThing = v1;
            sithAI_SetMoveThing(v3, &v1->position, v3->moveSpeed);
        }
    }
}

void sithCogFunctionAI_AISetLookPos(sithCog *pCog)
{
    SithThing *v1; // eax
    SithAIControlBlock *v2; // eax
    rdVector3 v3; // [esp+4h] [ebp-Ch] BYREF

    // Added: assert ported from OpenJones3D
    SITH_ASSERTREL(pCog);

    // TODO: Bug? If the vector is invalid, other aArgs will never get popped.
    if ( sithCogExec_PopVector(pCog, &v3) )
    {
        v1 = sithCogExec_PopThing(pCog);
        
        // Added: Fully disable AI including cog verbs
        if (g_debugmodeFlags & DEBUGFLAG_NO_AIEVENTS) return;
        
        if ( v1 )
        {
            if ( v1->controlType == SITH_CT_AI )
            {
                v2 = v1->actor;
                if ( v2 )
                    sithAI_SetLookFrame(v2, &v3);
            }
        }
    }
}

void sithCogFunctionAI_AISetLookFrame(sithCog *pCog)
{
    unsigned int v1; // esi
    SithThing *v2; // eax
    SithAIControlBlock *v3; // eax
    rdVector3 *v4; // ecx

    // Added: assert ported from OpenJones3D
    SITH_ASSERTREL(pCog);

    v1 = sithCogExec_PopInt(pCog);
    v2 = sithCogExec_PopThing(pCog);
    
    // Added
    if (g_debugmodeFlags & DEBUGFLAG_NO_AIEVENTS) return;
    
    if ( v2 )
    {
        if ( v2->controlType == SITH_CT_AI )
        {
            v3 = v2->actor;
            if ( v3 )
            {
                v4 = v3->aFrames;
                if ( v4 )
                {
                    if ( v1 < v3->loadedFrames )
                        sithAI_SetLookFrame(v3, &v4[v1]);
                }
            }
        }
    }
}

void sithCogFunctionAI_AIGetMovePos(sithCog *pCog)
{
    SithThing *v1; // eax
    SithAIControlBlock *v2; // eax

    // Added: assert ported from OpenJones3D
    SITH_ASSERTREL(pCog);

    v1 = sithCogExec_PopThing(pCog);
    if ( v1 && v1->controlType == SITH_CT_AI )
    {
        v2 = v1->actor;
        if ( v2 )
            sithCogExec_PushVector(pCog, &v2->movepos);
    }
}

void sithCogFunctionAI_AISetMode(sithCog *pCog)
{
    signed int v1; // edi
    SithThing *v2; // eax
    SithAIControlBlock *v3; // ecx
    int v4; // edx

    // Added: assert ported from OpenJones3D
    SITH_ASSERTREL(pCog);

    v1 = sithCogExec_PopInt(pCog);
    v2 = sithCogExec_PopThing(pCog);
    
    // Added
    if (g_debugmodeFlags & DEBUGFLAG_NO_AIEVENTS) return;
    
    if ( v2 )
    {
        if ( v2->controlType == SITH_CT_AI )
        {
            v3 = v2->actor;
            if ( v3 )
            {
                v4 = v3->flags;
                v3->flags = v4 | v1;
                if ( v4 != (v4 | v1) )
                    sithAI_EmitEvent(v3, SITHAI_MODE_UNK100, v4);
            }
        }
    }
}

void sithCogFunctionAI_AIGetMode(sithCog *pCog)
{
    SithThing *v1; // eax
    SithAIControlBlock *v2; // eax

    // Added: assert ported from OpenJones3D
    SITH_ASSERTREL(pCog);

    v1 = sithCogExec_PopThing(pCog);
    if ( v1 && v1->controlType == SITH_CT_AI && (v2 = v1->actor) != 0 )
        sithCogExec_PushInt(pCog, v2->flags);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionAI_AIClearMode(sithCog *pCog)
{
    signed int mode; // esi
    SithThing *thing; // eax
    SithAIControlBlock *v3; // ecx
    int v4; // edx
    int mode_inv; // esi

    // Added: assert ported from OpenJones3D
    SITH_ASSERTREL(pCog);

    mode = sithCogExec_PopInt(pCog);
    thing = sithCogExec_PopThing(pCog);
    
    // Added
    if (g_debugmodeFlags & DEBUGFLAG_NO_AIEVENTS) return;
    
    if ( thing )
    {
        if ( thing->controlType == SITH_CT_AI )
        {
            v3 = thing->actor;
            if ( v3 )
            {
                v4 = v3->flags;
                mode_inv = ~mode;
                v3->flags = v4 & mode_inv;
                if ( v4 != (v4 & mode_inv) )
                    sithAI_EmitEvent(v3, SITHAI_MODE_UNK100, v4);
            }
        }
    }
}

void sithCogFunctionAI_FirstThingInView(sithCog *pCog)
{
    SithThing *v2; // eax
    SithThing *v3; // ebx
    int v4; // eax
    signed int v5; // [esp+10h] [ebp-38h]
    rdMatrix34 v7; // [esp+18h] [ebp-30h] BYREF

    v5 = sithCogExec_PopInt(pCog);
    cog_flex_t a1 = sithCogExec_PopFlex(pCog);
    cog_flex_t v6 = sithCogExec_PopFlex(pCog);
    v2 = sithCogExec_PopThing(pCog);
    
    // Added
    if (g_debugmodeFlags & DEBUGFLAG_NO_AIEVENTS)
    {
        sithCogExec_PushInt(pCog, -1);
        return;
    }
    
    v3 = v2;
    if ( v2
      && ((_memcpy(&v7, &v2->orient, sizeof(v7)), v4 = v2->type, v4 == SITH_THING_ACTOR) || v4 == SITH_THING_PLAYER ? (rdMatrix_PreRotate34(
                                                                                                                                       &v7,
                                                                                                                                       &v3->actorParams.headPYR),
                                                                                                                                   rdMatrix_PostTranslate34(
                                                                                                                                       &v7,
                                                                                                                                       &v3->position),
                                                                                                                                   rdMatrix_PreTranslate34(
                                                                                                                                       &v7,
                                                                                                                                       &v3->actorParams.eyeOffset)) : rdMatrix_PostTranslate34(&v7, &v3->position),
          (sithCogFunctionAI_numThingsInView = sithAI_FirstThingInView(v3->sector, &v7, v6, v6, 32, sithCogFunctionAI_aThingsInView, v5, a1), sithCogFunctionAI_curThingInView = 0, sithCogFunctionAI_numThingsInView > 0)
       && sithCogFunctionAI_aThingsInView[0]) )
    {
        sithCogExec_PushInt(pCog, sithCogFunctionAI_aThingsInView[0]->idx);
    }
    else
    {
        sithCogExec_PushInt(pCog, -1);
    }
}

void sithCogFunctionAI_NextThingInView(sithCog *pCog)
{
    int v1; // eax
    SithThing *v2; // eax

    v1 = ++sithCogFunctionAI_curThingInView;
    if ( sithCogFunctionAI_curThingInView < sithCogFunctionAI_numThingsInView && (v2 = sithCogFunctionAI_aThingsInView[v1]) != 0 )
        sithCogExec_PushInt(pCog, v2->idx);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionAI_ThingViewDot(sithCog *pCog)
{
    SithThing *v1; // ebp
    SithThing *v2; // eax
    SithThing *v3; // ebx
    cog_flex_t a2; // [esp+0h] [ebp-5Ch]
    rdVector3 v6; // [esp+14h] [ebp-48h] BYREF
    rdVector3 v7; // [esp+20h] [ebp-3Ch] BYREF
    rdMatrix34 v8; // [esp+2Ch] [ebp-30h] BYREF

    v1 = sithCogExec_PopThing(pCog);
    v2 = sithCogExec_PopThing(pCog);
    
    // Added
    if (g_debugmodeFlags & DEBUGFLAG_NO_AIEVENTS)
    {
        sithCogExec_PushFlex(pCog, -1000.0);
        return;
    }
    
    v3 = v2;
    if ( v1 && v2 )
    {
        _memcpy(&v8, &v2->orient, sizeof(v8));
        if ( v2->type == SITH_THING_ACTOR || v2->type == SITH_THING_PLAYER )
            rdMatrix_PreRotate34(&v8, &v3->actorParams.headPYR);
        v6 = v8.lvec;
        v7.x = v1->position.x - v3->position.x;
        v7.y = v1->position.y - v3->position.y;
        v7.z = v1->position.z - v3->position.z;
        rdVector_Normalize3Acc(&v6);
        rdVector_Normalize3Acc(&v7);
        a2 = v6.x * v7.x + v6.y * v7.y + v6.z * v7.z;
        sithCogExec_PushFlex(pCog, a2);
    }
    else
    {
        sithCogExec_PushFlex(pCog, -1000.0);
    }
}

void sithCogFunctionAI_AISetFireTarget(sithCog *pCog)
{
    SithThing *v1; // esi
    SithThing *v2; // eax
    SithAIControlBlock *v3; // eax
    unsigned int v4; // ecx
    int v5; // ecx
    unsigned int v6; // edx

    v1 = sithCogExec_PopThing(pCog);
    v2 = sithCogExec_PopThing(pCog);
    
    // Added
    if (g_debugmodeFlags & DEBUGFLAG_NO_AIEVENTS) return;
    
    if ( v2 )
    {
        if ( v2->controlType == SITH_CT_AI )
        {
            v3 = v2->actor;
            if ( v3 )
            {
                v4 = sithTime_g_msecGameTime;
                v3->pDistractor = v1;
                v3->field_204 = v4;
                v5 = v3->flags;
                if ( v1 )
                    v6 = v5 | SITHAI_MODE_TOUGHSKIN;
                else
                    v6 = v5 & ~SITHAI_MODE_TOUGHSKIN;
                v3->flags = v6;
                if ( v6 != v5 )
                    sithAI_EmitEvent(v3, SITHAI_MODE_UNK100, v5);
            }
        }
    }
}

// Unused?
void sithCogFunctionAI_sub_501330(sithCog *pCog)
{
    char *v1; // edi
    SithThing *v2; // eax
    SithAIControlBlock *v3; // esi
    SithAIRegisteredInstinct *v4; // eax
    unsigned int v5; // edx
    unsigned int v6; // ecx
    void *v7; // edi

    v1 = sithCogExec_PopString(pCog);
    v2 = sithCogExec_PopThing(pCog);
    if ( !v2 )
        goto LABEL_12;
    if ( !v1 )
        goto LABEL_12;
    if ( v2->controlType != SITH_CT_AI )
        goto LABEL_12;
    v3 = v2->actor;
    if ( !v3 )
        goto LABEL_12;
    v4 = sithAI_FindInstinct(v1);
    if ( !v4 )
        goto LABEL_12;
    v5 = v3->numInstincts;
    v6 = 0;
    if ( v5 )
    {
        v7 = (void *)v4->func;
        do
        {
            if ( v3->pClass->entries[v6].func == v7 )
                break;
            ++v6;
        }
        while ( v6 < v5 );
    }
    if ( v6 < v5 )
        sithCogExec_PushInt(pCog, v6);
    else
LABEL_12:
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionAI_IsAITargetInSight(sithCog *pCog)
{
    SithThing *v1; // eax
    SithAIControlBlock *v2; // eax

    v1 = sithCogExec_PopThing(pCog);
    if ( v1 && v1->type == SITH_THING_ACTOR && v1->controlType == SITH_CT_AI && (v2 = v1->actor) != 0 && !v2->field_1F4 )
        sithCogExec_PushInt(pCog, 1);
    else
        sithCogExec_PushInt(pCog, 0);
}

void sithCogFunctionAI_AIFlee(sithCog *pCog)
{
    SithThing *v1; // edi
    SithThing *v2; // eax
    SithAIControlBlock *v3; // eax
    int v4; // ecx

    v1 = sithCogExec_PopThing(pCog);
    v2 = sithCogExec_PopThing(pCog);
    
    // Added
    if (g_debugmodeFlags & DEBUGFLAG_NO_AIEVENTS) return;
    
    if ( v1 )
    {
        if ( v2 )
        {
            if ( v2->type == SITH_THING_ACTOR && v2->controlType == SITH_CT_AI )
            {
                v3 = v2->actor;
                if ( v3 )
                {
                    v4 = v3->flags;
                    v3->pFleeFromThing = v1;
                    if ( (v4 & SITHAI_MODE_FLEEING) == 0 )
                    {
                        v3->flags |= SITHAI_MODE_FLEEING;
                        sithAI_EmitEvent(v3, SITHAI_MODE_UNK100, v4);
                    }
                }
            }
        }
    }
}

void sithCogFunctionAI_AISetClass(sithCog *pCog)
{
    SithAIClass *aiclass; // esi
    SithThing *thing; // eax
    SithAIControlBlock *v3; // ecx
    int v4; // eax

    aiclass = sithCogExec_PopAIClass(pCog);
    thing = sithCogExec_PopThing(pCog);
    if ( aiclass && thing && thing->controlType == SITH_CT_AI )
    {
        v3 = thing->actor;
        if ( v3 )
        {
            thing->pClass = aiclass;
            v4 = aiclass->numEntries;
            v3->pClass = aiclass;
            v3->numInstincts = v4;
        }
    }
}

// MOTS added
void sithCogFunctionAI_AIGetAlignment(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing && pThing->controlType == SITH_CT_AI && pThing->actor && pThing->actor->pClass) 
    {
        sithCogExec_PushFlex(pCog, pThing->actor->pClass->alignment);
        return;
    }
    sithCogExec_PushFlex(pCog, 0.0);
}

// MOTS added
void sithCogFunctionAI_AISetAlignment(sithCog *pCog)
{
    cog_flex_t val = sithCogExec_PopFlex(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing && pThing->controlType == SITH_CT_AI && pThing->actor && pThing->actor->pClass) 
    {
        pThing->actor->pClass->alignment = val;
    }
}

// MOTS added
void sithCogFunctionAI_AISetInterest(sithCog *pCog)
{
    SithThing* pInterest = sithCogExec_PopThing(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing && pThing->controlType == SITH_CT_AI && pThing->actor) 
    {
        if (pInterest == sithPlayer_g_pLocalPlayerThing) {
            pThing->actor->pInterest = 0;
        }
        else {
            pThing->actor->pInterest = pInterest;
        }
    }
}

// MOTS added
void sithCogFunctionAI_AIGetInterest(sithCog *pCog)
{
    SithThing* pThing = sithCogExec_PopThing(pCog);
    if (pThing && pThing->controlType == SITH_CT_AI && pThing->actor && pThing->actor->pInterest) 
    {
        sithCogExec_PushInt(pCog, pThing->actor->pInterest->idx);
        return;
    }
    sithCogExec_PushInt(pCog, -1);
}

// MOTS added
void sithCogFunctionAI_AISetDistractor(sithCog *pCog)
{
    SithThing *pThing;

    pThing = sithCogExec_PopThing(pCog);
    sithAI_SetDistractor(pThing);
}

// MOTS added
void sithCogFunctionAI_AIAddAlignmentPriority(sithCog *pCog)
{
    int iVar1;
    int *piVar3;
    int val;
    int iVar5;
    cog_flex_t local_4;

    local_4 = 1.0;
    iVar5 = -1000;
    val = -1;
    iVar1 = sithCogExec_PopInt(pCog);
    cog_flex_t fVar6 = sithCogExec_PopFlex(pCog);

    for (int i = 0; i < 10; i++) {
        if (sithAI_aAlignments[i].bValid == 0) {
            sithAI_aAlignments[i].bValid = 1;
            sithAI_aAlignments[i].field_4 = iVar1;
            sithAI_aAlignments[i].field_8 = fVar6;
            val = i;
            break;
        }
    }

    if (val != -1) 
    {
        for (int i = 0; i < 10; i++) {
            if (sithAI_aAlignments[i].bValid != 0 && iVar5 < sithAI_aAlignments[i].field_4) {
                iVar5 = sithAI_aAlignments[i].field_4;
                local_4 = sithAI_aAlignments[i].field_8;
            }
        }
    }

    sithAI_AddAlignmentPriority(local_4);
    sithCogExec_PushInt(pCog,val);
    return;
}


void sithCogFunctionAI_AIRemoveAlignmentPriority(sithCog *pCog)
{
    int iVar1;
    sithAIAlign *psVar2;
    int *piVar3;
    int iVar4;

    iVar1 = sithCogExec_PopInt(pCog);
    if (iVar1 == -1) {
        for (int i = 0; i < 10; i++) {
            sithAI_aAlignments[i].bValid = 0;
        }
        return;
    }

    if ((-1 < iVar1) && (iVar1 < 11)) 
    {
        cog_flex_t tmp = 1.0;
        iVar4 = -1000;
        sithAI_aAlignments[iVar1].bValid = 0;
        for (int i = 0; i < 10; i++) {
            if (sithAI_aAlignments[i].bValid != 0 && iVar4 < sithAI_aAlignments[i].field_4) {
                iVar4 = sithAI_aAlignments[i].field_4;
                tmp = sithAI_aAlignments[i].field_8;
            }
        }
        sithAI_AddAlignmentPriority(tmp);
    }
}

// MoTS Added
void sithCogFunctionAI_FirstThingInCone(sithCog *pCog)
{
    SithThing *v2; // eax
    SithThing *v3; // ebx
    int v4; // eax
    signed int v5; // [esp+10h] [ebp-38h]
    cog_flex_t v6; // [esp+14h] [ebp-34h]
    rdMatrix34 v7; // [esp+18h] [ebp-30h] BYREF
    cog_flex_t a1; // [esp+4Ch] [ebp+4h]

    v5 = sithCogExec_PopInt(pCog);
    a1 = sithCogExec_PopFlex(pCog);
    v6 = sithCogExec_PopFlex(pCog);
    v2 = sithCogExec_PopThing(pCog);
    
    // Added
    if (g_debugmodeFlags & DEBUGFLAG_NO_AIEVENTS)
    {
        sithCogExec_PushInt(pCog, -1);
        return;
    }
    
    v3 = v2;
    if ( v2
      && ((_memcpy(&v7, &v2->orient, sizeof(v7)), v4 = v2->type, v4 == SITH_THING_ACTOR) || v4 == SITH_THING_PLAYER ? (rdMatrix_PreRotate34(
                                                                                                                                       &v7,
                                                                                                                                       &v3->actorParams.headPYR),
                                                                                                                                   rdMatrix_PostTranslate34(
                                                                                                                                       &v7,
                                                                                                                                       &v3->position),
                                                                                                                                   rdMatrix_PreTranslate34(
                                                                                                                                       &v7,
                                                                                                                                       &v3->actorParams.eyeOffset)) : rdMatrix_PostTranslate34(&v7, &v3->position),
          (sithCogFunctionAI_numThingsInView = sithAI_FirstThingInCone(v3->sector, &v7, v6, v6, 32, sithCogFunctionAI_aThingsInView, v5, a1), sithCogFunctionAI_curThingInView = 0, sithCogFunctionAI_numThingsInView > 0)
       && sithCogFunctionAI_aThingsInView[0]) )
    {
        sithCogExec_PushInt(pCog, sithCogFunctionAI_aThingsInView[0]->idx);
    }
    else
    {
        sithCogExec_PushInt(pCog, -1);
    }
}


// MoTS added
void sithCogFunctionAI_NextThingInCone(sithCog *pCog)
{
    sithCogFunctionAI_curThingInView++;

    if (sithCogFunctionAI_curThingInView < sithCogFunctionAI_numThingsInView 
        && sithCogFunctionAI_aThingsInView[sithCogFunctionAI_curThingInView]) 
    {
        sithCogExec_PushInt(pCog,sithCogFunctionAI_aThingsInView[sithCogFunctionAI_curThingInView]->idx);
        return;
    }
    sithCogExec_PushInt(pCog,-1);
}



void sithCogFunctionAI_Startup(SithCogSymbolTable* pCog)
{
    sithCog_RegisterFunction(pCog, sithCogFunctionAI_AIGetMode, "aigetmode");
    sithCog_RegisterFunction(pCog, sithCogFunctionAI_AISetMode, "aisetmode");
    sithCog_RegisterFunction(pCog, sithCogFunctionAI_AIClearMode, "aiclearmode");
    sithCog_RegisterFunction(pCog, sithCogFunctionAI_AIGetMovePos, "aigetmovepos");
    sithCog_RegisterFunction(pCog, sithCogFunctionAI_AISetMovePos, "aisetmovepos");
    sithCog_RegisterFunction(pCog, sithCogFunctionAI_FirstThingInView, "firstthinginview");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(pCog, sithCogFunctionAI_FirstThingInCone,"firstthingincone");
    }
    sithCog_RegisterFunction(pCog, sithCogFunctionAI_NextThingInView, "nextthinginview");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(pCog, sithCogFunctionAI_NextThingInCone,"nextthingincone");
    }
    sithCog_RegisterFunction(pCog, sithCogFunctionAI_ThingViewDot, "thingviewdot");
    sithCog_RegisterFunction(pCog, sithCogFunctionAI_AISetFireTarget, "aisetfiretarget");
    sithCog_RegisterFunction(pCog, sithCogFunctionAI_AISetMoveThing, "aisetmovething");
    sithCog_RegisterFunction(pCog, sithCogFunctionAI_AISetLookPos, "aisetlookpos");
    sithCog_RegisterFunction(pCog, sithCogFunctionAI_AISetMoveSpeed, "aisetmovespeed");
    sithCog_RegisterFunction(pCog, sithCogFunctionAI_AISetLookFrame, "aisetlookframe");
    sithCog_RegisterFunction(pCog, sithCogFunctionAI_AISetMoveFrame, "aisetmoveframe");
    sithCog_RegisterFunction(pCog, sithCogFunctionAI_IsAITargetInSight, "isaitargetinsight");
    sithCog_RegisterFunction(pCog, sithCogFunctionAI_AIFlee, "aiflee");
    sithCog_RegisterFunction(pCog, sithCogFunctionAI_AISetClass, "aisetclass");
    sithCog_RegisterFunction(pCog, sithCogFunctionAI_AIJump, "aijump");
#ifdef JKM_AI
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(pCog, sithCogFunctionAI_AIGetAlignment, "aigetalignment");
        sithCog_RegisterFunction(pCog, sithCogFunctionAI_AISetAlignment, "aisetalignment");
        sithCog_RegisterFunction(pCog, sithCogFunctionAI_AISetInterest, "aisetinterest");
        sithCog_RegisterFunction(pCog, sithCogFunctionAI_AIGetInterest, "aigetinterest");
        sithCog_RegisterFunction(pCog, sithCogFunctionAI_AISetDistractor, "aisetdistractor");
        sithCog_RegisterFunction(pCog, sithCogFunctionAI_AIAddAlignmentPriority, "aiaddalignmentpriority");
        sithCog_RegisterFunction(pCog, sithCogFunctionAI_AIRemoveAlignmentPriority, "airemovealignmentpriority");
    
        //TODO: actor_rc.cog references a "AISetMoveTarget"?
    }
#endif
}
