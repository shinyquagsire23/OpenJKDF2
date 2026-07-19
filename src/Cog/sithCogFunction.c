#include "sithCogFunction.h"

#include "types.h"
#include "Cog/sithCog.h"
#include "Cog/sithCogExec.h"
#include "jk.h"

#include "Devices/sithConsole.h"
#include "Gameplay/sithTime.h"
#include "stdPlatform.h"
#include "General/stdString.h"
#include "General/stdMath.h"
#include "World/sithSurface.h"
#include "World/sithSector.h"
#include "World/sithTrackThing.h"
#include "World/sithTemplate.h"
#include "Engine/sithKeyFrame.h"
#include "Engine/rdKeyframe.h"
#include "World/sithModel.h"
#include "Engine/sithRender.h"
#include "Engine/sithCamera.h"
#include "Devices/sithSound.h"
#include "Dss/sithGamesave.h"
#include "Gameplay/sithEvent.h"
#include "Engine/sithPhysics.h"
#include "Gameplay/sithPlayer.h"
#include "World/sithWorld.h"
#include "World/sithWeapon.h"
#include "World/jkPlayer.h"
#include "Main/jkGame.h"
#include "General/stdFnames.h"
#include "General/stdPalEffects.h"
#include "Dss/sithDSS.h"
#include "Dss/sithDSSCog.h"
#include "Engine/sithRender.h"

#include <time.h>

void sithCogFunction_ReturnBool(int a1, sithCog *a2);

void sithCogFunction_GetSenderID(sithCog* pCog)
{
    sithCogExec_PushInt(pCog, pCog->senderId);
}

void sithCogFunction_GetSenderRef(sithCog *pCog)
{
    sithCogExec_PushInt(pCog, pCog->senderRef);
}

void sithCogFunction_GetSenderType(sithCog *pCog)
{
    sithCogExec_PushInt(pCog, pCog->senderType);
}

void sithCogFunction_GetSourceRef(sithCog *pCog)
{
    sithCogExec_PushInt(pCog, pCog->sourceIdx);
}

void sithCogFunction_GetSourceType(sithCog *pCog)
{
    sithCogExec_PushInt(pCog, pCog->sourceType);
}

void sithCogFunction_Rand(sithCog *pCog)
{
    cog_flex_t val = _frand();
    sithCogExec_PushFlex(pCog, val);
}

void sithCogFunction_RandVec(sithCog *pCog)
{
    rdVector3 rvec;

    rvec.x = _frand();
    rvec.y = _frand();
    rvec.z = _frand();
    sithCogExec_PushVector(pCog, &rvec);
}

void sithCogFunction_Sleep(sithCog *pCog)
{
    sithCog *ctx_;
    flex_d_t fSecs;

    ctx_ = pCog;
    fSecs = sithCogExec_PopFlex(pCog);
    if ( fSecs <= 0.0 )
        fSecs = 0.1;

    // In the original game, sleeps < 0.02s will always round up to 0.02s.
    // For consistency on some sector thrusts (Lv18's air shafts for example)
    // we have to round up.
#ifdef FIXED_TIMESTEP_PHYS
    if (NEEDS_STEPPED_PHYS) {
        if ( fSecs <= jkPlayer_canonicalCogTickrate ) {
            fSecs = jkPlayer_canonicalCogTickrate;
        }
    }
#endif

    // TODO this is probably an inlined func?
    if ( ctx_->flags & SITH_COG_DEBUG )
    {
#ifdef SITH_DEBUG_STRUCT_NAMES
        _sprintf(std_g_genBuffer, "Cog %s: Sleeping for %f seconds.\n", ctx_->aName, fSecs);
        sithConsole_PrintString(std_g_genBuffer);
#endif
    }
    ctx_->script_running = 2;
    ctx_->msecTimerTimeout = sithTime_g_msecGameTime + (int)(fSecs * 1000.0);
}

void sithCogFunction_Print(sithCog *pCog)
{
    char *str;

    str = sithCogExec_PopString(pCog);
    if (str)
        sithConsole_PrintString(str);
}

void sithCogFunction_PrintInt(sithCog *pCog)
{
    char tmp[32];

    stdString_snprintf(tmp, 32, "%d", sithCogExec_PopInt(pCog));
    sithConsole_PrintString(tmp);
}

void sithCogFunction_PrintVector(sithCog *pCog)
{
    rdVector3 popVec;
    char tmp[32];

    if (sithCogExec_PopVector(pCog, &popVec))
        stdString_snprintf(tmp, 32, "<%f %f %f>", popVec.x, popVec.y, popVec.z);
    else
        stdString_snprintf(tmp, 32, "Bad vector");

    sithConsole_PrintString(tmp);
}

void sithCogFunction_PrintFlex(sithCog *pCog)
{
    char tmp[32];

    stdString_snprintf(tmp, 32, "%f", sithCogExec_PopFlex(pCog));
    sithConsole_PrintString(tmp);
}

void sithCogFunction_SurfaceAnim(sithCog *pCog)
{
    sithCog *ctx_;
    int popInt; // edi
    SithSurface *surface; // ecx
    rdSurface *v4; // eax
    cog_flex_t popFlex; // [esp+Ch] [ebp+4h]

    // TODO: is this inlined?
    ctx_ = pCog;
    popInt = sithCogExec_PopInt(pCog);
    popFlex = sithCogExec_PopFlex(pCog);
    surface = sithCogExec_PopSurface(ctx_); // TODO
    if ( !surface )
    {
        SITHLOG_ERROR("Cog %s: Bad surface index.\n", pCog->aName); // Added: J3D log
        sithCogExec_PushInt(ctx_, -1);
        return;
    }
    
    if ( popFlex <= 0.0 )
        popFlex = 15.0;

    v4 = sithSurface_SurfaceAnim(surface, popFlex, popInt);
    if ( v4 )
        sithCogExec_PushInt(ctx_, v4->index);
    else
        sithCogExec_PushInt(ctx_, -1);
}

void sithCogFunction_MaterialAnim(sithCog *pCog)
{
    sithCog *ctx_; // esi
    int popInt; // edi
    rdMaterial *material; // ecx
    rdSurface *v4; // eax
    cog_flex_t popFlex; // [esp+Ch] [ebp+4h]

    // TODO is this inlined
    ctx_ = pCog;
    popInt = sithCogExec_PopInt(pCog);
    popFlex = sithCogExec_PopFlex(pCog);
    material = sithCogExec_PopMaterial(ctx_);
    if ( !material )
    {
        SITHLOG_ERROR("Cog %s: Bad material index.\n", pCog->aName); // Added: J3D log
        sithCogExec_PushInt(ctx_, -1);
        return;
    }
    
    if ( popFlex <= 0.0 )
        popFlex = 15.0;
    v4 = sithSurface_MaterialAnim(material, popFlex, popInt);
    if ( v4 )
        sithCogExec_PushInt(ctx_, v4->index);
    else
        sithCogExec_PushInt(ctx_, -1);
}

void sithCogFunction_StopThing(sithCog *ctx) // unused
{
    SithThing *v1;

    v1 = sithCogExec_PopThing(ctx);
    if ( v1 )
    {
        if ( v1->moveType == SITH_MT_PHYSICS )
        {
            sithPhysics_ResetThingMovement(v1);
        }
        else if ( v1->moveType == SITH_MT_PATH )
        {
            sithTrackThing_Stop(v1);
        }
    }
}

void sithCogFunction_StopAnim(sithCog *pCog)
{
    int v1; // eax
    rdSurface *v2; // eax

    v1 = sithCogExec_PopInt(pCog);
    v2 = sithSurface_GetByIdx(v1);
    if ( v2 )
    {
        sithSurface_StopAnim(v2);
        if ( sithMessage_g_outputstream )
            sithDSS_AnimStatus(v2, -1, 255); // TODO ??
    }
}

void sithCogFunction_StopSurfaceAnim(sithCog *pCog)
{
    SithSurface *v1; // eax
    rdSurface *v2; // eax

    v1 = sithCogExec_PopSurface(pCog);
    if ( v1 )
    {
        v2 = sithSurface_GetRdSurface(v1);
        if ( v2 )
        {
            sithSurface_StopAnim(v2);
            if ( sithMessage_g_outputstream )
                sithDSS_AnimStatus(v2, -1, 255); // TODO ??
        }
    }
}

void sithCogFunction_GetSurfaceAnim(sithCog *pCog)
{
    SithSurface *v1; // eax
    int v2; // eax

    v1 = sithCogExec_PopSurface(pCog);
    if ( v1 )
    {
        v2 = sithSurface_GetSurfaceAnim(v1);
        sithCogExec_PushInt(pCog, v2);
    }
    else
    {
        SITHLOG_ERROR("Cog %s: Trying to call GetSurfaceAnim on an invalid surface.\n", pCog->aName); // Added: J3D log
        sithCogExec_PushInt(pCog, -1);
    }
}

void sithCogFunction_LoadTemplate(sithCog *pCog)
{
    char *v1; // eax
    SithThing *v2; // eax

    v1 = sithCogExec_PopString(pCog);
    if ( v1 && (v2 = sithTemplate_GetTemplate(v1)) != 0 )
        sithCogExec_PushInt(pCog, v2->idx);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunction_LoadKeyframe(sithCog *pCog)
{
    char *v1; // eax
    rdKeyframe *v2; // eax

    v1 = sithCogExec_PopString(pCog);
    if ( v1 && (v2 = sithKeyFrame_LoadEntry(v1)) != 0 )
        sithCogExec_PushInt(pCog, v2->id);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunction_LoadModel(sithCog *pCog)
{
    char *v1; // eax
    rdModel3 *v2; // eax

    v1 = sithCogExec_PopString(pCog);
    if ( v1 && (v2 = sithModel_Load(v1, 1)) != 0 )
        sithCogExec_PushInt(pCog, v2->id);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunction_SetPulse(sithCog *pCog)
{
    cog_flex_t popFlex;

    popFlex = sithCogExec_PopFlex(pCog);
    if ( popFlex <= 0.0 )
    {
        if ( pCog->flags & SITH_COG_DEBUG )
        {
#ifdef SITH_DEBUG_STRUCT_NAMES
            _sprintf(std_g_genBuffer, "Cog %s: Pulse disabled.\n", pCog->aName);
            sithConsole_PrintString(std_g_genBuffer);
#endif
        }
        pCog->flags &= ~SITH_COG_PULSE_SET;
    }
    else
    {
        if ( pCog->flags & SITH_COG_DEBUG )
        {
#ifdef SITH_DEBUG_STRUCT_NAMES
            _sprintf(std_g_genBuffer, "Cog %s: Pulse set to %f seconds.\n", pCog->aName, popFlex);
            sithConsole_PrintString(std_g_genBuffer);
#endif
        }
        pCog->flags |= SITH_COG_PULSE_SET;
        pCog->msecPulseInterval = (int)(popFlex * 1000.0);
        pCog->msecNextPulseTime = (int)(popFlex * 1000.0) + sithTime_g_msecGameTime;
    }
}

void sithCogFunction_SetTimer(sithCog *pCog)
{
    cog_flex_t popFlex = sithCogExec_PopFlex(pCog);
    if ( popFlex <= 0.0 )
    {
        if ( pCog->flags & SITH_COG_DEBUG )
        {
#ifdef SITH_DEBUG_STRUCT_NAMES
            _sprintf(std_g_genBuffer, "Cog %s: Timer cancelled.\n", pCog->aName);
            sithConsole_PrintString(std_g_genBuffer);
#endif
        }
        pCog->flags &= ~SITH_COG_TIMER_SET;
    }
    else
    {
        if ( pCog->flags & SITH_COG_DEBUG )
        {
#ifdef SITH_DEBUG_STRUCT_NAMES
            _sprintf(std_g_genBuffer, "Cog %s: Timer set for %f seconds.\n", pCog->aName, popFlex);
            sithConsole_PrintString(std_g_genBuffer);
#endif
        }
        pCog->flags |= SITH_COG_TIMER_SET;
        pCog->field_20 = sithTime_g_msecGameTime + (int)(popFlex * 1000.0);
    }
}

void sithCogFunction_SetTimerEx(sithCog *pCog)
{
    SithEventParams params;

    params.field_14 = sithCogExec_PopFlex(pCog);
    params.field_10 = sithCogExec_PopFlex(pCog);
    params.timerIdx = sithCogExec_PopInt(pCog);
    params.idx = pCog->idx;
    cog_flex_t a1a = sithCogExec_PopFlex(pCog) * 1000.0;
    int timerMs = (signed int)a1a;
    if ( timerMs >= 0 ) {
        sithEvent_CreateEvent(4, &params, timerMs);
    }
}

void sithCogFunction_KillTimerEx(sithCog *pCog)
{
    SithEvent *v2; // eax
    SithEvent *v3; // edi
    SithEvent *v4; // esi

    int v1 = sithCogExec_PopInt(pCog);
    if ( v1 > 0 )
    {
        v2 = sithEvent_g_pFirstQueuedEvent;
        v3 = 0;
        if ( sithEvent_g_pFirstQueuedEvent )
        {
            do
            {
                v4 = v2->pNextEvent;
                if ( v2->taskNum == 4 && v2->params.idx == pCog->idx && v2->params.timerIdx == v1 )
                {
                    if ( v3 )
                        v3->pNextEvent = v4;
                    else
                        sithEvent_g_pFirstQueuedEvent = v2->pNextEvent;
                    sithEvent_FreeEvent(v2);
                    v2 = v3;
                }
                v3 = v2;
                v2 = v4;
            }
            while ( v4 );
        }
    }
}

void sithCogFunction_Reset(sithCog *pCog)
{
    pCog->callDepth = 0;
}

void sithCogFunction_VectorSet(sithCog *pCog)
{
    rdVector3 out;

    out.z = sithCogExec_PopFlex(pCog);
    out.y = sithCogExec_PopFlex(pCog);
    out.x = sithCogExec_PopFlex(pCog);
    sithCogExec_PushVector(pCog, &out);
}

void sithCogFunction_VectorAdd(sithCog *pCog)
{
    rdVector3 inA;
    rdVector3 inB;
    rdVector3 out;

    sithCogExec_PopVector(pCog, &inA);
    sithCogExec_PopVector(pCog, &inB);
    rdVector_Add3(&out, &inA, &inB);
    sithCogExec_PushVector(pCog, &out);
}

void sithCogFunction_VectorSub(sithCog *pCog)
{
    rdVector3 inA;
    rdVector3 inB;
    rdVector3 out;

    sithCogExec_PopVector(pCog, &inA);
    sithCogExec_PopVector(pCog, &inB);
    rdVector_Sub3(&out, &inB, &inA);
    sithCogExec_PushVector(pCog, &out);
}

void sithCogFunction_VectorDot(sithCog *pCog)
{
    rdVector3 inA;
    rdVector3 inB;

    sithCogExec_PopVector(pCog, &inA);
    sithCogExec_PopVector(pCog, &inB);
    sithCogExec_PushFlex(pCog, rdVector_Dot3(&inA, &inB));
}

void sithCogFunction_VectorCross(sithCog *pCog)
{
    rdVector3 inA;
    rdVector3 inB;
    rdVector3 out;

    sithCogExec_PopVector(pCog, &inA);
    sithCogExec_PopVector(pCog, &inB);
    rdVector_Cross3(&out, &inA, &inB);
    sithCogExec_PushVector(pCog, &out);
}

void sithCogFunction_VectorLen(sithCog *pCog)
{
    rdVector3 in;

    sithCogExec_PopVector(pCog, &in);
    sithCogExec_PushFlex(pCog, rdVector_Len3(&in));
}

void sithCogFunction_VectorScale(sithCog *pCog)
{
    rdVector3 inA;
    rdVector3 out;

    cog_flex_t scale = sithCogExec_PopFlex(pCog);
    sithCogExec_PopVector(pCog, &inA);
    rdVector_Scale3(&out, &inA, scale);
    sithCogExec_PushVector(pCog, &out);
}

void sithCogFunction_VectorDist(sithCog *pCog)
{
    rdVector3 inA;
    rdVector3 inB;
    rdVector3 tmp;

    sithCogExec_PopVector(pCog, &inA);
    sithCogExec_PopVector(pCog, &inB);
    rdVector_Sub3(&tmp, &inB, &inA);
    sithCogExec_PushFlex(pCog, rdVector_Len3(&tmp));
}

// MOTS added
void sithCogFunction_VectorEqual(sithCog *pCog)
{
    rdVector3 popB;
    rdVector3 popA;
    
    sithCogExec_PopVector(pCog,&popA);
    sithCogExec_PopVector(pCog,&popB);
    if (((popB.x == popA.x) && (popB.y == popA.y)) && (popB.z == popA.z)) {
        sithCogExec_PushInt(pCog,1);
        return;
    }
    sithCogExec_PushInt(pCog,0);
    return;
}

void sithCogFunction_SendMessage(sithCog *pCog)
{
    int msgId = sithCogExec_PopInt(pCog);
    sithCog* cog = sithCogExec_PopCog(pCog);

    if (cog && msgId >= 0 && msgId < SITH_MESSAGE_MAX)
        sithCog_SendMessage(cog, msgId, SENDERTYPE_COG, pCog->idx, pCog->sourceType, pCog->sourceIdx, 0);
}

void sithCogFunction_SendMessageEx(struct sithCog *pCog)
{
    cog_flex_t param3 = sithCogExec_PopFlex(pCog);
    cog_flex_t param2 = sithCogExec_PopFlex(pCog);
    cog_flex_t param1 = sithCogExec_PopFlex(pCog);
    cog_flex_t param0 = sithCogExec_PopFlex(pCog);
    int msgId = sithCogExec_PopInt(pCog);
    sithCog* cog = sithCogExec_PopCog(pCog);

    if (cog && msgId >= 0 && msgId < SITH_MESSAGE_MAX)
    {
        cog_flex_t flexRet = sithCog_SendMessageEx(cog, msgId, SENDERTYPE_COG, pCog->idx, pCog->sourceType, pCog->sourceIdx, 0, param0, param1, param2, param3);
        sithCogExec_PushFlex(pCog, flexRet);
    }
}

void sithCogFunction_GetKeyLen(sithCog *pCog)
{
    rdKeyframe* keyframe = sithCogExec_PopKeyframe(pCog);

    if (!keyframe || keyframe->fps == 0.0)
    {
        SITHLOG_ERROR("Cog %s: Bad Track reference passed to GetKeyLen.\n", pCog->aName); // Added: J3D log
        sithCogExec_PushFlex(pCog, 0.0);
        return;
    }

    sithCogExec_PushFlex(pCog, (flex_d_t)keyframe->numFrames / keyframe->fps);
}

void sithCogFunction_GetSithMode(sithCog* pCog)
{
    sithCogExec_PushInt(pCog, g_sithMode);
}

void sithCogFunction_GetGameTime(sithCog *pCog)
{
    sithCogExec_PushInt(pCog, sithTime_g_msecGameTime);
}

void sithCogFunction_GetFlexGameTime(sithCog *pCog)
{
    sithCogExec_PushFlex(pCog, sithTime_g_secGameTime);
}

void sithCogFunction_GetDifficulty(sithCog *pCog)
{
    sithCogExec_PushInt(pCog, jkPlayer_setDiff);
}

void sithCogFunction_SetSubModeFlags(sithCog *pCog)
{
    g_submodeFlags |= sithCogExec_PopInt(pCog);
}

void sithCogFunction_ClearSubModeFlags(sithCog *pCog)
{
    g_submodeFlags &= ~sithCogExec_PopInt(pCog);
}

void sithCogFunction_GetSubModeFlags(sithCog *pCog)
{
    sithCogExec_PushInt(pCog, g_submodeFlags);
}

void sithCogFunction_SetDebugModeFlags(sithCog *pCog)
{
    g_debugmodeFlags |= sithCogExec_PopInt(pCog);
}

void sithCogFunction_ClearDebugModeFlags(sithCog *pCog)
{
    g_debugmodeFlags &= ~sithCogExec_PopInt(pCog);
}

void sithCogFunction_GetDebugModeFlags(sithCog *pCog)
{
    sithCogExec_PushInt(pCog, g_debugmodeFlags);
}

void sithCogFunction_BitSet(sithCog *pCog)
{
    signed int a;
    signed int b;

    a = sithCogExec_PopInt(pCog);
    b = sithCogExec_PopInt(pCog);
    sithCogExec_PushInt(pCog, b | a);
}

void sithCogFunction_BitTest(sithCog *pCog)
{
    signed int a;
    signed int b;

    a = sithCogExec_PopInt(pCog);
    b = sithCogExec_PopInt(pCog);
    sithCogExec_PushInt(pCog, b & a);
}

void sithCogFunction_BitClear(sithCog *pCog)
{
    signed int a;
    signed int b;

    a = sithCogExec_PopInt(pCog);
    b = sithCogExec_PopInt(pCog);
    sithCogExec_PushInt(pCog, b & ~a);
}

void sithCogFunction_GetLevelTime(sithCog *pCog)
{
    sithCogExec_PushFlex(pCog, sithTime_g_msecGameTime * 0.001);
}

void sithCogFunction_GetThingCount(sithCog *pCog)
{
    sithCogExec_PushInt(pCog, sithWorld_g_pCurrentWorld->numThingsLoaded);
}

void sithCogFunction_GetThingTemplateCount(sithCog *pCog)
{
    SithWorld *v1; // esi
    SithThing *v2; // eax
    int template_count; // edi

    v1 = sithWorld_g_pCurrentWorld;
    v2 = sithCogExec_PopTemplate(pCog);
    if ( v2 )
    {
        template_count = 0;
        for (int i = 0; i < v1->numThings; i++ )
        {
            SithThing* thing = &v1->aThings[i];
            if ( thing->type && thing->type != SITH_THING_CORPSE && thing->pTemplate == v2 )
                ++template_count;
        }
        sithCogExec_PushInt(pCog, template_count);
    }
}

void sithCogFunction_GetGravity(sithCog *pCog)
{
    sithCogExec_PushFlex(pCog, sithWorld_g_pCurrentWorld->gravity);
}

void sithCogFunction_SetGravity(sithCog *pCog)
{
    sithWorld_g_pCurrentWorld->gravity = sithCogExec_PopFlex(pCog);
}

void sithCogFunction_ReturnEx(sithCog *pCog)
{
    pCog->returnValue = sithCogExec_PopFlex(pCog);
}

void sithCogFunction_GetParam(sithCog *pCog)
{
    int idx = sithCogExec_PopInt(pCog);
    if ( idx < 0 || idx >= 4 )
        sithCogExec_PushFlex(pCog, -9999.0);
    else
        sithCogExec_PushFlex(pCog, pCog->params[idx]);
}

void sithCogFunction_SetParam(sithCog *pCog)
{
    cog_flex_t val = sithCogExec_PopFlex(pCog);
    int idx = sithCogExec_PopInt(pCog);
    if (idx >= 0 && idx < 4)
        pCog->params[idx] = val;
}

void sithCogFunction_VectorX(sithCog *pCog)
{
    rdVector3 popVec;

    sithCogExec_PopVector(pCog, &popVec);
    sithCogExec_PushFlex(pCog, popVec.x);
}

void sithCogFunction_VectorY(sithCog *pCog)
{
    rdVector3 popVec;

    sithCogExec_PopVector(pCog, &popVec);
    sithCogExec_PushFlex(pCog, popVec.y);
}

void sithCogFunction_VectorZ(sithCog *pCog)
{
    rdVector3 popVec;

    sithCogExec_PopVector(pCog, &popVec);
    sithCogExec_PushFlex(pCog, popVec.z);
}

void sithCogFunction_VectorNorm(sithCog *pCog)
{
    rdVector3 popVec;
    rdVector3 out;

    sithCogExec_PopVector(pCog, &popVec);
    rdVector_Normalize3(&out, &popVec);
    sithCogExec_PushVector(pCog, &out);
}

void sithCogFunction_SetMaterialCel(sithCog *pCog)
{
    signed int cel; // esi
    rdMaterial *mat; // eax

    cel = sithCogExec_PopInt(pCog);
    mat = sithCogExec_PopMaterial(pCog);
    if ( mat && cel >= 0 && (unsigned int)cel < mat->num_texinfo )
        mat->curCelNum = cel;
    sithCogExec_PushInt(pCog, -1);
}

void sithCogFunction_GetMaterialCel(sithCog *pCog)
{
    rdMaterial *mat; // eax

    mat = sithCogExec_PopMaterial(pCog);
    if ( mat )
        sithCogExec_PushInt(pCog, mat->curCelNum);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunction_EnableIRMode(sithCog *pCog)
{
    cog_flex_t flex1 = sithCogExec_PopFlex(pCog);
    cog_flex_t flex2 = sithCogExec_PopFlex(pCog);
    sithRender_EnableIRMode(flex2, flex1);
}

void sithCogFunction_DisableIRMode(sithCog *pCog)
{
    sithRender_DisableIRMode();
}

void sithCogFunction_SetInvFlags(sithCog *pCog)
{
    int flags;
    int binIdx;
    SithThing *player;

    flags = sithCogExec_PopInt(pCog);
    binIdx = sithCogExec_PopInt(pCog);
    player = sithCogExec_PopThing(pCog);
    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }
    if ( player && player->type == SITH_THING_PLAYER && player->actorParams.pPlayer && binIdx < SITHBIN_NUMBINS )
        sithInventory_SetInventoryFlags(player, binIdx, flags);
}

void sithCogFunction_SetMapModeFlags(sithCog *pCog)
{
    g_mapModeFlags |= sithCogExec_PopInt(pCog);
}

void sithCogFunction_GetMapModelFlags(sithCog *pCog)
{
    sithCogExec_PushInt(pCog, g_mapModeFlags);
}

void sithCogFunction_ClearMapModeFlags(sithCog *pCog)
{
    g_mapModeFlags &= ~sithCogExec_PopInt(pCog);
}

void sithCogFunction_SetCameraFocus(sithCog *pCog)
{
    SithThing *focusThing; // esi
    signed int camIdx; // eax

    focusThing = sithCogExec_PopThing(pCog);
    camIdx = sithCogExec_PopInt(pCog);

#ifdef QOL_IMPROVEMENTS
    // Droidworks tmp
    if (camIdx == 7)
        camIdx = 0;
#endif

    if ( camIdx > -1 && camIdx < 7 )
    {
        if ( focusThing )
            sithCamera_SetCameraFocus(&sithCamera_g_aCameras[camIdx], focusThing, 0);
    }
}

void sithCogFunction_GetPrimaryFocus(sithCog *pCog)
{
    signed int camIdx; // eax
    SithThing *v2; // eax

    camIdx = sithCogExec_PopInt(pCog);

#ifdef QOL_IMPROVEMENTS
    // Droidworks tmp
    if (camIdx == 7)
        camIdx = 0;
#endif

    if ( camIdx > -1 && camIdx < 7 && (v2 = sithCamera_GetPrimaryFocus(&sithCamera_g_aCameras[camIdx])) != 0 )
        sithCogExec_PushInt(pCog, v2->idx);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunction_GetSecondaryFocus(sithCog *pCog)
{
    signed int camIdx; // eax
    SithThing *v2; // eax

    camIdx = sithCogExec_PopInt(pCog);
    
#ifdef QOL_IMPROVEMENTS
    // Droidworks tmp
    if (camIdx == 7)
        camIdx = 0;
#endif
    
    if ( camIdx > -1 && camIdx < 7 && (v2 = sithCamera_GetSecondaryFocus(&sithCamera_g_aCameras[camIdx])) != 0 )
        sithCogExec_PushInt(pCog, v2->idx);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunction_SetCameraMode(sithCog *pCog)
{
    signed int camIdx; // eax

    camIdx = sithCogExec_PopInt(pCog);

    // DroidWorks: the binary's twin accepts slots 0..7 (the DW slot-7 follow
    // cam exists); JK clamps to < 7. Replaces the old 7->0 "Droidworks tmp"
    // hack (BUG 21: cutscene camera restores went to first-person).
    int camMax = Main_bDwCompat ? 8 : 7;
    if ( camIdx > -1 && camIdx < camMax )
        sithCamera_SetCurrentCamera(&sithCamera_g_aCameras[camIdx]);
}

void sithCogFunction_GetCameraMode(sithCog *pCog)
{
    int camIdx; // edx

    // DroidWorks: the binary's twin reports slots 0..7 (BUG 21).
    if ( sithCamera_g_pCurCamera && (camIdx = sithCamera_g_pCurCamera - sithCamera_g_aCameras, camIdx < (Main_bDwCompat ? 8 : 7)) )
        sithCogExec_PushInt(pCog, camIdx);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunction_CycleCamera(sithCog *pCog)
{
    sithCamera_CycleCamera();
}

// MOTS added
void sithCogFunction_SetCameraZoom(sithCog *pCog)
{
    cog_flex_t zoomSpeed = sithCogExec_PopFlex(pCog);
    cog_flex_t zoomScale = sithCogExec_PopFlex(pCog);
    int camIdx = sithCogExec_PopInt(pCog);

    if ((-1 < camIdx) && (camIdx < 7)) {
        sithCamera_SetZoom(sithCamera_g_aCameras + camIdx, zoomScale, zoomSpeed);
    }
}

void sithCogFunction_SetPOVShake(sithCog *pCog)
{
    rdVector3 v3;
    rdVector3 v4;

    cog_flex_t a1a = sithCogExec_PopFlex(pCog);
    cog_flex_t v2 = sithCogExec_PopFlex(pCog);
    if ( sithCogExec_PopVector(pCog, &v3) )
    {
        if ( sithCogExec_PopVector(pCog, &v4) )
            sithCamera_SetPOVShake(&v4, &v3, v2, a1a);
    }
}

void sithCogFunction_HeapNew(sithCog *pCog)
{
    SithCogSymbolValue *oldHeap; // eax
    SithCogSymbolValue *newHeap; // edi

    int heapSize = sithCogExec_PopInt(pCog);
    if ( heapSize > 0 )
    {
        oldHeap = pCog->heap;
        if ( oldHeap )
        {
            SITH_FREE(oldHeap);
            pCog->heapSize = 0;
        }
        { TWL_EXTRAM_SUGGEST(pSithHS); // Added: heap vars are word-safe stackvars
        newHeap = (SithCogSymbolValue *)SITH_ALLOC(sizeof(SithCogSymbolValue) * heapSize);
        TWL_EXTRAM_RESTORE(pSithHS); }
        pCog->heap = newHeap;
        if (!newHeap) { // Added: don't memset NULL on OOM
            pCog->heapSize = 0;
            return;
        }
        stdPlatform_Memzero32(newHeap, (sizeof(SithCogSymbolValue) * heapSize)); // Added: word-safe
        pCog->heapSize = heapSize;
    }
}

void sithCogFunction_HeapSet(sithCog *pCog)
{
    SithCogSymbolValue stackVar;

    int val = sithCogExec_PopSymbol(pCog, &stackVar);
    int idx = sithCogExec_PopInt(pCog);
    if ( val && idx >= 0 && idx < pCog->heapSize )
        pCog->heap[idx] = stackVar;
}

void sithCogFunction_HeapGet(sithCog *pCog)
{
    SithCogSymbolValue *heapVar;
    SithCogSymbolValue tmp;

    int idx = sithCogExec_PopInt(pCog);
    if (idx < 0 || idx >= pCog->heapSize)
    {
        SITHLOG_ERROR("HeapGet: index %d out of range.\n", idx); // Added: J3D log
        sithCogExec_PushInt(pCog, 0);
    }
    else
    {
        SITH_ASSERTREL(pCog->heap); // Added: J3D assert
        heapVar = &pCog->heap[idx];
        tmp.type = heapVar->type;
        tmp.data[0] = heapVar->data[0];
        tmp.data[1] = heapVar->data[1];
        tmp.data[2] = heapVar->data[2];
        sithCogExec_PushStack(pCog, &tmp);
    }
}

void sithCogFunction_HeapFree(sithCog *pCog)
{
    if ( pCog->heap )
    {
        SITH_FREE(pCog->heap);
        pCog->heapSize = 0;
    }
}

void sithCogFunction_GetSelfCog(sithCog *pCog)
{
    sithCogExec_PushInt(pCog, pCog->idx);
}

void sithCogFunction_GetMasterCog(sithCog *pCog)
{
    if ( sithCog_g_pMasterCog )
        sithCogExec_PushInt(pCog, sithCog_g_pMasterCog->idx);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunction_SetMasterCog(sithCog *pCog)
{
    sithCog_g_pMasterCog = sithCogExec_PopCog(pCog);
}

// MOTS added
void sithCogFunction_GetActionCog(sithCog *pCog)
{
    if ( sithCog_pActionCog )
        sithCogExec_PushInt(pCog, sithCog_pActionCog->idx);
    else
        sithCogExec_PushInt(pCog, -1);
}

// MOTS added
void sithCogFunction_SetActionCog(sithCog *ctx)
{
    sithCog_actionCogIdk = sithCogExec_PopInt(ctx);
    sithCog* pCog = sithCogExec_PopCog(ctx);
    sithCog_pActionCog = (pCog == (void*)-1) ? NULL : pCog;
}

void sithCogFunction_NewColorEffect(sithCog *pCog)
{
    int addB; // ebx
    int addG; // ebp
    int idx; // edi
    signed int filterG; // [esp+10h] [ebp-1Ch]
    signed int filterR; // [esp+14h] [ebp-18h]
    cog_flex_t tintB; // [esp+18h] [ebp-14h]
    cog_flex_t tintG; // [esp+1Ch] [ebp-10h]
    cog_flex_t tintR; // [esp+20h] [ebp-Ch]
    signed int addR; // [esp+24h] [ebp-8h]
    cog_flex_t fade; // [esp+28h] [ebp-4h]
    int filterB; // [esp+30h] [ebp+4h]

    fade = sithCogExec_PopFlex(pCog);
    addB = sithCogExec_PopInt(pCog);
    addG = sithCogExec_PopInt(pCog);
    addR = sithCogExec_PopInt(pCog);
    tintB = sithCogExec_PopFlex(pCog);
    tintG = sithCogExec_PopFlex(pCog);
    tintR = sithCogExec_PopFlex(pCog);
    filterB = sithCogExec_PopInt(pCog);
    filterG = sithCogExec_PopInt(pCog);
    filterR = sithCogExec_PopInt(pCog);
    idx = stdPalEffects_NewRequest(1);
    if ( idx == -1 )
    {
        sithCogExec_PushInt(pCog, -1);
    }
    else
    {
        stdPalEffects_SetFilter(idx, filterR, filterG, filterB);
        stdPalEffects_SetTint(idx, tintR, tintG, tintB);
        stdPalEffects_SetAdd(idx, addR, addG, addB);
        stdPalEffects_SetFade(idx, fade);
        sithCogExec_PushInt(pCog, idx);
    }
}

void sithCogFunction_ModifyColorEffect(sithCog *pCog)
{
    cog_flex_t fade; // ST34_4
    int addB; // edi
    int addG; // ebx
    int addR; // ebp
    cog_flex_t tintB; // ST28_4
    cog_flex_t tintG; // ST2C_4
    cog_flex_t tintR; // ST30_4
    signed int filterG; // ST20_4
    signed int filterR; // ST24_4
    int idx; // esi
    int filterB; // [esp+2Ch] [ebp+4h]

    fade = sithCogExec_PopFlex(pCog);
    addB = sithCogExec_PopInt(pCog);
    addG = sithCogExec_PopInt(pCog);
    addR = sithCogExec_PopInt(pCog);
    tintB = sithCogExec_PopFlex(pCog);
    tintG = sithCogExec_PopFlex(pCog);
    tintR = sithCogExec_PopFlex(pCog);
    filterB = sithCogExec_PopInt(pCog);
    filterG = sithCogExec_PopInt(pCog);
    filterR = sithCogExec_PopInt(pCog);
    idx = sithCogExec_PopInt(pCog);
    stdPalEffects_SetFilter(idx, filterR, filterG, filterB);
    stdPalEffects_SetTint(idx, tintR, tintG, tintB);
    stdPalEffects_SetAdd(idx, addR, addG, addB);
    stdPalEffects_SetFade(idx, fade);
}

void sithCogFunction_FreeColorEffect(sithCog *pCog)
{
    uint32_t v1; // eax

    v1 = sithCogExec_PopInt(pCog);
    stdPalEffects_FreeRequest(v1);
}

void sithCogFunction_AddDynamicTint(sithCog *pCog)
{
    sithCog *v1; // esi
    SithThing *player; // eax

    v1 = pCog;
    cog_flex_t fB = sithCogExec_PopFlex(pCog);
    cog_flex_t fG = sithCogExec_PopFlex(v1);
    cog_flex_t fR = sithCogExec_PopFlex(v1);
    player = sithCogExec_PopThing(v1);
    if ( player && player->type == SITH_THING_PLAYER && player == sithPlayer_g_pLocalPlayerThing )
        sithPlayer_AddDynamicTint(fR, fG, fB);
}

void sithCogFunction_AddDynamicAdd(sithCog *pCog)
{
    int b; // edi
    int g; // ebx
    int r; // ebp
    SithThing *pLocalPlayer; // eax

    b = sithCogExec_PopInt(pCog);
    g = sithCogExec_PopInt(pCog);
    r = sithCogExec_PopInt(pCog);
    pLocalPlayer = sithCogExec_PopThing(pCog);
    if ( pLocalPlayer && pLocalPlayer->type == SITH_THING_PLAYER && pLocalPlayer == sithPlayer_g_pLocalPlayerThing )
        sithPlayer_AddDyamicAdd(r, g, b);
}

// modifycoloreffect, freecoloreffect, adddynamictint, adddynamicadd

// MOTS added
void sithCogFunction_FireProjectileInternal(sithCog *pCog, int extra)
{
    rdVector3 aimError;
    rdVector3 fireOffset;
    
    cog_flex_t autoaimMaxDist = sithCogExec_PopFlex(pCog);
    cog_flex_t autoaimFov = sithCogExec_PopFlex(pCog);
    int scaleFlags = sithCogExec_PopInt(pCog);
    cog_flex_t scale = sithCogExec_PopFlex(pCog);
    sithCogExec_PopVector(pCog,&aimError);
    sithCogExec_PopVector(pCog,&fireOffset);
    int mode = sithCogExec_PopInt(pCog);
    sithSound* fireSound = sithCogExec_PopSound(pCog);
    SithThing* projectileTemplate = sithCogExec_PopTemplate(pCog);
    SithThing* pMeshCollided = sithCogExec_PopThing(pCog);

    if (pMeshCollided) {
        projectileTemplate = sithWeapon_FireProjectile(pMeshCollided,projectileTemplate,fireSound,mode,&fireOffset,&aimError,scale,(int16_t)scaleFlags,autoaimFov,autoaimMaxDist,extra);
        if (projectileTemplate) {
            sithCogExec_PushInt(pCog,projectileTemplate->idx);
            return;
        }
    }
    sithCogExec_PushInt(pCog,-1);
}

void sithCogFunction_FireProjectile(sithCog *pCog)
{
    sithCogFunction_FireProjectileInternal(pCog, 0);
}

// MOTS added
void sithCogFunction_FireProjectileData(sithCog *pCog)
{
    int popA = sithCogExec_PopInt(pCog);
    sithCogFunction_FireProjectileInternal(pCog,popA);
}

// MOTS added
void sithCogFunction_FireProjectileLocal(sithCog *pCog)
{
    int tmp = sithMessage_g_outputstream;
    sithMessage_g_outputstream = 0;
    sithCogFunction_FireProjectile(pCog);
    sithMessage_g_outputstream = tmp;
    return;
}

void sithCogFunction_SendTrigger(sithCog *pCog)
{
    SithPlayer* pPlayer;

    cog_flex_t arg3 = sithCogExec_PopFlex(pCog);
    cog_flex_t arg2 = sithCogExec_PopFlex(pCog);
    cog_flex_t arg1 = sithCogExec_PopFlex(pCog);
    cog_flex_t arg0 = sithCogExec_PopFlex(pCog);
    int sourceType = sithCogExec_PopInt(pCog);
    SithThing* sourceThing = sithCogExec_PopThing(pCog);
    
    if ( sourceThing )
    {
        if ( sourceThing->type == SITH_THING_PLAYER )
        {
            pPlayer = sourceThing->actorParams.pPlayer;
            if ( pPlayer )
            {
                if ( pPlayer->flags & 1 )
                {
                    if ( sourceThing == sithPlayer_g_pLocalPlayerThing )
                        sithCog_BroadcastMessageEx(SITH_MESSAGE_TRIGGER, SENDERTYPE_THING, sithPlayer_g_pLocalPlayerThing->idx, 0, sourceType, arg0, arg1, arg2, arg3);
                    else
                        sithDSSCog_SendMessage(
                            0,
                            SITH_MESSAGE_TRIGGER,
                            SENDERTYPE_THING,
                            sithPlayer_g_pLocalPlayerThing->idx,
                            0,
                            sourceType,
                            0,
                            arg0,
                            arg1,
                            arg2,
                            arg3,
                            pPlayer->playerNetId);
                }
            }
        }
    }
    else
    {
        sithDSSCog_SendMessage(
            0,
            SITH_MESSAGE_TRIGGER,
            SENDERTYPE_THING,
            sithPlayer_g_pLocalPlayerThing->idx,
            0,
            sourceType,
            0,
            arg0,
            arg1,
            arg2,
            arg3,
            -1);
        sithCog_BroadcastMessageEx(SITH_MESSAGE_TRIGGER, SENDERTYPE_THING, sithPlayer_g_pLocalPlayerThing->idx, 0, sourceType, arg0, arg1, arg2, arg3);
    }
}

void sithCogFunction_ActivateWeapon(sithCog *pCog)
{
    int mode = sithCogExec_PopInt(pCog);
    cog_flex_t fireRate = sithCogExec_PopFlex(pCog);
    SithThing* weaponThing = sithCogExec_PopThing(pCog);

    if ( weaponThing && fireRate >= 0.0 && mode >= 0 && mode < 2 )
        sithWeapon_ActivateWeapon(weaponThing, pCog, fireRate, mode);
}

void sithCogFunction_DeactivateWeapon(sithCog *pCog)
{
    int mode = sithCogExec_PopInt(pCog);
    SithThing* weapon = sithCogExec_PopThing(pCog);
    if ( weapon && mode >= 0 && mode < 2 )
    {
        sithCogExec_PushFlex(pCog, sithWeapon_DeactivateWeapon(weapon, pCog, mode));
    }
    else
    {
        sithCogExec_PushFlex(pCog, -1.0);
    }
}

void sithCogFunction_SetFireWait(sithCog *pCog)
{
    cog_flex_t fireRate = sithCogExec_PopFlex(pCog);
    SithThing* weapon = sithCogExec_PopThing(pCog);

    if ( weapon && weapon == sithPlayer_g_pLocalPlayerThing && fireRate >= -1.0 )
        sithWeapon_SetFireWait(weapon, fireRate);
}

void sithCogFunction_SetMountWait(sithCog *pCog)
{
    cog_flex_t mountWait = sithCogExec_PopFlex(pCog);
    SithThing* weapon = sithCogExec_PopThing(pCog);

    if ( weapon && weapon == sithPlayer_g_pLocalPlayerThing && mountWait >= -1.0 )
        sithWeapon_SetMountWait(weapon, mountWait);
}

void sithCogFunction_SelectWeapon(sithCog *pCog)
{
    int binIdx = sithCogExec_PopInt(pCog);
    SithThing* player = sithCogExec_PopThing(pCog);

    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }

    if ( player )
    {
        if ( binIdx >= 0 )
            sithWeapon_SelectWeapon(player, binIdx, 0);
    }
}

void sithCogFunction_AssignWeapon(sithCog *pCog)
{
    int binIdx = sithCogExec_PopInt(pCog);
    SithThing* player = sithCogExec_PopThing(pCog);

    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }

    if ( player )
    {
        if ( binIdx >= 1 )
            sithWeapon_SelectWeapon(player, binIdx, 1);
    }
}

void sithCogFunction_AutoSelectWeapon(sithCog *pCog)
{
    int weapIdx = sithCogExec_PopInt(pCog);
    SithThing* player = sithCogExec_PopThing(pCog);

    if ( weapIdx >= 0 && weapIdx <= 2 && player )
    {
        int binIdx = sithWeapon_AutoSelect(player, weapIdx);
        if (Main_bMotsCompat) {
            binIdx = sithInventory_SelectWeaponPrior(binIdx);
        }

        sithCogExec_PushInt(pCog, binIdx);
    }
    else
    {
        sithCogExec_PushInt(pCog, -1);
    }
}

void sithCogFunction_SetCurWeapon(sithCog *pCog)
{
    int v4; // eax

    int binIdx = sithCogExec_PopInt(pCog);
    SithThing* player = sithCogExec_PopThing(pCog);

    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }

    if ( player )
    {
        if ( player->type == SITH_THING_PLAYER )
        {
            if (!Main_bMotsCompat)
                binIdx = sithInventory_SelectWeaponFollowing(binIdx);
            sithInventory_SetCurrentWeapon(player, binIdx);
        }
    }
}

void sithCogFunction_GetWeaponPriority(sithCog *pCog)
{
    int mode = sithCogExec_PopInt(pCog);
    int binIdx = sithCogExec_PopInt(pCog);
    SithThing* player = sithCogExec_PopThing(pCog);

    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }

    if ( player && player->type == SITH_THING_PLAYER )
    {
        if ( mode < 0 || mode > 2 )
        {
            sithCogExec_PushInt(pCog, -1);
            return;
        }
        if ( binIdx >= 0 && binIdx < SITHBIN_NUMBINS )
        {
            sithCogExec_PushFlex(pCog, sithWeapon_GetPriority(player, binIdx, mode));
            return;
        }
    }
    sithCogExec_PushFlex(pCog, -1.0);
}

void sithCogFunction_GetCurWeaponMode(sithCog *pCog)
{
    sithCogExec_PushInt(pCog, sithWeapon_GetCurWeaponMode());
}

void sithCogFunction_GetCurWeapon(sithCog *pCog)
{
    SithThing* player = sithCogExec_PopThing(pCog);

    if ( player && player->type == SITH_THING_PLAYER )
    {
        int binIdx = sithInventory_GetCurrentWeapon(player);
        if (Main_bMotsCompat) {
            binIdx = sithInventory_SelectWeaponPrior(binIdx);
        }
        sithCogExec_PushInt(pCog, binIdx);
    }
    else
    {
        SITHLOG_ERROR("Cog %s: Invalid thing called from GetCurWeapon.\n", pCog->aName); // Added: J3D log
        sithCogExec_PushInt(pCog, -1);
    }
}

// MOTS added
void sithCogFunction_GetWeaponBin(sithCog *pCog)
{
    int popA;
    
    popA = sithCogExec_PopInt(pCog);
    popA = sithInventory_SelectWeaponFollowing(popA);
    sithCogExec_PushInt(pCog,popA);
}

void sithCogFunction_GetCameraStateFlags(sithCog *pCog)
{
    int v1; // eax

    v1 = sithCamera_GetCameraStateFlags();
    sithCogExec_PushInt(pCog, v1);
}

void sithCogFunction_SetCameraStateFlags(sithCog *pCog)
{
    int v1; // eax

    v1 = sithCogExec_PopInt(pCog);
    sithCamera_SetCameraStateFlags(v1);
}

void sithCogFunction_SetMultiModeFlags(sithCog *pCog)
{
    sithNet_MultiModeFlags |= sithCogExec_PopInt(pCog);
}

void sithCogFunction_GetMultiModeFlags(sithCog *pCog)
{
    sithCogExec_PushInt(pCog, sithNet_MultiModeFlags);
}

void sithCogFunction_ClearMultiModeFlags(sithCog *pCog)
{
    sithNet_MultiModeFlags &= ~sithCogExec_PopInt(pCog);
}

void sithCogFunction_IsMulti(sithCog *pCog)
{
    if ( sithNet_isMulti )
        sithCogExec_PushInt(pCog, 1);
    else
        sithCogExec_PushInt(pCog, 0);
}

void sithCogFunction_IsServer(sithCog *pCog)
{
    sithCogFunction_ReturnBool(sithNet_isServer, pCog);
}

// unused
void sithCogFunction_ReturnBool(int pCog, sithCog *a2)
{
    if ( pCog )
        sithCogExec_PushInt(a2, 1);
    else
        sithCogExec_PushInt(a2, 0);
}

void sithCogFunction_GetTeamScore(sithCog *pCog)
{
    signed int idx; // eax

    idx = sithCogExec_PopInt(pCog);
    if ( idx <= 0 || idx >= 5 )
        sithCogExec_PushInt(pCog, -999999);
    else
        sithCogExec_PushInt(pCog, sithNet_teamScore[idx]);
}

void sithCogFunction_SetTeamScore(sithCog *pCog)
{
    signed int score; // edi
    signed int idx; // eax

    score = sithCogExec_PopInt(pCog);
    idx = sithCogExec_PopInt(pCog);
    if ( idx > 0 && idx < 5 )
        sithNet_teamScore[idx] = score;
}

void sithCogFunction_GetTimeLimit(sithCog *pCog)
{
    cog_flex_t a2 = (flex_d_t)(unsigned int)sithNet_multiplayer_timelimit * 0.000016666667;
    sithCogExec_PushFlex(pCog, a2);
}

void sithCogFunction_SetTimeLimit(sithCog *pCog)
{
    cog_flex_t v1 = sithCogExec_PopFlex(pCog);
    if ( v1 >= 0.0 )
        sithNet_multiplayer_timelimit = (int)(v1 * 60000.0);
}

void sithCogFunction_GetScoreLimit(sithCog *pCog)
{
    sithCogExec_PushInt(pCog, sithNet_scorelimit);
}

void sithCogFunction_SetScoreLimit(sithCog *pCog)
{
    sithNet_scorelimit = sithCogExec_PopInt(pCog);
}

void sithCogFunction_ChangeFireRate(sithCog *pCog)
{
    cog_flex_t fireRate = sithCogExec_PopFlex(pCog);
    SithThing* player = sithCogExec_PopThing(pCog);

    if ( player && player == sithPlayer_g_pLocalPlayerThing && fireRate > 0.0 )
        sithWeapon_SetFireRate(player, fireRate);
}

void sithCogFunction_AutoSavegame(sithCog *pCog)
{
    char tmp[128];

    stdString_snprintf(tmp, 128, "%s%s", "_JKAUTO_", sithGamesave_AutosaveMapName()); // Added: single-slot on DC
    stdFnames_ChangeExt(tmp, "jks");
    sithGamesave_Save(tmp, 1, 0, 0);
}

void sithCogFunction_SetCameraFocii(sithCog *pCog)
{
    SithThing* focusThing2 = sithCogExec_PopThing(pCog);
    SithThing* focusThing = sithCogExec_PopThing(pCog);
    int camIdx = sithCogExec_PopInt(pCog);

    // DroidWorks: the binary's twin accepts slots 0..7 AND requires both foci
    // (BUG 21; replaces the old 7->0 "Droidworks tmp" hack).
    int camMax = Main_bDwCompat ? 8 : 7;
    if ( camIdx > -1 && camIdx < camMax )
    {
        if ( focusThing && (!Main_bDwCompat || focusThing2) )
            sithCamera_SetCameraFocus(&sithCamera_g_aCameras[camIdx], focusThing, focusThing2);
    }
}

// MOTS added
void sithCogFunction_Pow(sithCog *pCog)
{
    cog_flex_t fVar2 = sithCogExec_PopFlex(pCog);
    cog_flex_t fVar3 = sithCogExec_PopFlex(pCog);
    if ((fVar2 == 0.0) && (fVar3 == 0.0)) {
        SITHLOG_ERROR("Cog %s: 0 to the 0 power is undefined\n", pCog->aName); // Added: J3D log
        sithCogExec_PushFlex(pCog,0.0);
        return;
    }
    sithCogExec_PushFlex(pCog,stdMath_FlexPower(fVar2, fVar3)); // TODO verify
    return;
}

// MOTS added
void sithCogFunction_Wakeup(sithCog *pCtx)
{
    sithCogExec_009d39b0 = 1;
    sithCogExec_pIdkMotsCtx = pCtx;
    return;
}

// MOTS added
void sithCogFunction_Sin(sithCog *pCog)
{
    flex_t outSin;
    flex_t outCos;
    
    cog_flex_t angle = sithCogExec_PopFlex(pCog);
    stdMath_SinCos(angle,&outSin,&outCos);
    sithCogExec_PushFlex(pCog,outSin);
}

// MOTS added
void sithCogFunction_Cos(sithCog *pCog)
{
    flex_t outSin;
    flex_t outCos;
    
    cog_flex_t angle = sithCogExec_PopFlex(pCog);
    stdMath_SinCos(angle,&outSin,&outCos);
    sithCogExec_PushFlex(pCog,outCos);
}

// MOTS added
void sithCogFunction_Tan(sithCog *pCog)
{
    cog_flex_t fVar1 = sithCogExec_PopFlex(pCog);
    fVar1 = stdMath_Tan(fVar1);
    sithCogExec_PushFlex(pCog,fVar1);
}

// MOTS added
void sithCogFunction_GetCogFlags(sithCog *ctx)
{
    sithCog* pCog = sithCogExec_PopCog(ctx);
    sithCogExec_PushInt(ctx,pCog->flags);
}

// MOTS added
void sithCogFunction_SetCogFlags(sithCog *ctx)
{
    int val = sithCogExec_PopInt(ctx);
    sithCog* pCog = sithCogExec_PopCog(ctx);

    pCog->flags |= val;
}

// MOTS added
void sithCogFunction_ClearCogFlags(sithCog *ctx)
{
    int val = sithCogExec_PopInt(ctx);
    sithCog* pCog = sithCogExec_PopCog(ctx);

    pCog->flags &= ~val;
}

// MOTS added
void sithCogFunction_DebugBreak(sithCog *pCog)
{
    // TODO
}

// MOTS added
void sithCogFunction_WorldFlash(sithCog *pCog)
{
    cog_flex_t arg2 = sithCogExec_PopFlex(pCog);
    cog_flex_t arg1 = sithCogExec_PopFlex(pCog);
    sithRender_WorldFlash(arg1, arg2);
}

// MOTS added
void sithCogFunction_GetSysDate(sithCog *pCog)
{
    rdVector3 out;

    time_t t = time(NULL);
    struct tm* tm = localtime(&t);

    // TODO verify this matches the original behavior
    /*
    SYSTEMTIME local_10;

    GetLocalTime(&local_10);
    local_1c.x = (cog_flex_t)(uint)local_10.wYear;
    local_1c.y = (cog_flex_t)(uint)local_10.wMonth;
    local_1c.z = (cog_flex_t)(local_10._6_4_ & 0xffff);
    */

    if (tm) {
        out.x = (cog_flex_t)(tm->tm_year + 1900); // year
        out.y = (cog_flex_t)(tm->tm_mon + 1); // month
        out.z = (cog_flex_t)(tm->tm_mday); // day
    }
    else {
        rdVector_Zero3(&out);
    }

    sithCogExec_PushVector(pCog, &out);
}

// MOTS added
void sithCogFunction_GetSysTime(sithCog *pCog)
{
    rdVector3 out;

    time_t t = time(NULL);
    struct tm* tm = localtime(&t);
  
    // TODO verify this matches the original behavior
    /*
    _SYSTEMTIME local_10;
    GetLocalTime(&local_10);
    out.x = (cog_flex_t)(uint)local_10.wHour;
    out.y = (cog_flex_t)(uint)local_10.wMinute;
    out.z = (cog_flex_t)(uint)local_10.wSecond;
    */

    if (tm) {
        out.x = (cog_flex_t)(tm->tm_hour);
        out.y = (cog_flex_t)(tm->tm_min);
        out.z = (cog_flex_t)(tm->tm_sec);
    }
    else {
        rdVector_Zero3(&out);
    }
    

    sithCogExec_PushVector(pCog, &out);
}

// MOTS added
void sithCogFunction_SendMessageExRadius(sithCog *pCog)
{
    cog_flex_t fVar1;
    cog_flex_t fVar2;
    cog_flex_t fVar3;
    int message;
    uint32_t uVar4;
    int iVar5;
    SithThing *pMeshCollided;
    int local_28;
    rdVector3 local_1c;

    cog_flex_t local_4 = sithCogExec_PopFlex(pCog);
    cog_flex_t local_8 = sithCogExec_PopFlex(pCog);
    cog_flex_t local_c = sithCogExec_PopFlex(pCog);
    cog_flex_t local_10 = sithCogExec_PopFlex(pCog);
    message = sithCogExec_PopInt(pCog);
    uVar4 = sithCogExec_PopInt(pCog);
    cog_flex_t fVar6 = sithCogExec_PopFlex(pCog);
    iVar5 = sithCogExec_PopVector(pCog,&local_1c);
    cog_flex_t param1 = local_c;
    cog_flex_t param0 = local_10;
    if ((((iVar5 != 0) && (-1 < message)) && (message < SITH_MESSAGE_ENTERBUBBLE)) 
        && (local_28 = sithWorld_g_pCurrentWorld->numThings, -1 < local_28)) 
    {
        int iVar5_idx = local_28;
        local_28 = local_28 + 1;
        do 
        {
            pMeshCollided = &sithWorld_g_pCurrentWorld->aThings[iVar5_idx];
            if (((((uVar4 & 1 << (pMeshCollided->type & 0x1f)) != 0) 
                && ((pMeshCollided->flags & (SITH_TF_DISABLED|SITH_TF_DEAD|SITH_TF_DESTROYED)) == 0))
                && ((pMeshCollided->type != 10 || ((uVar4 & 0x400) != 0)))) 
                && (fVar3 = (pMeshCollided->position).x - local_1c.x, fVar1 = (pMeshCollided->position).y - local_1c.y,
                    fVar2 = (pMeshCollided->position).z - local_1c.z,
                    fVar1 = stdMath_Sqrt(fVar2 * fVar2 + fVar1 * fVar1 + fVar3 * fVar3),
                    fVar1 <= fVar6))
            {
                sithCog_ThingSendMessageEx(pMeshCollided, NULL, message, param0, param1, local_8, local_4);
            }
            iVar5_idx--;
            local_28--;
        } while (local_28 != 0);
    }
}



void sithCogFunction_Startup(SithCogSymbolTable* pCog)
{
    sithCog_RegisterFunction(pCog, sithCogFunction_Sleep, "sleep");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(pCog, sithCogFunction_Pow, "pow"); // MOTS
        sithCog_RegisterFunction(pCog, sithCogFunction_Wakeup, "wakeup"); // MOTS
    }
    sithCog_RegisterFunction(pCog, sithCogFunction_Rand, "rand");
    sithCog_RegisterFunction(pCog, sithCogFunction_RandVec, "randvec");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetSenderRef, "getsenderref");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetSenderType, "getsendertype");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetSenderID, "getsenderid");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetSourceType, "getsourcetype");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetSourceRef, "getsourceref");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetThingCount, "getthingcount");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetGravity, "getgravity");
    sithCog_RegisterFunction(pCog, sithCogFunction_SetGravity, "setgravity");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetLevelTime, "getleveltime");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetGameTime, "getgametime");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetFlexGameTime, "getflexgametime");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetThingTemplateCount, "getthingtemplatecount");
    sithCog_RegisterFunction(pCog, sithCogFunction_SetPulse, "setpulse");
    sithCog_RegisterFunction(pCog, sithCogFunction_SetTimer, "settimer");
    sithCog_RegisterFunction(pCog, sithCogFunction_SetTimerEx, "settimerex");
    sithCog_RegisterFunction(pCog, sithCogFunction_KillTimerEx, "killtimerex");
    sithCog_RegisterFunction(pCog, sithCogFunction_Reset, "reset");
    sithCog_RegisterFunction(pCog, sithCogFunction_MaterialAnim, "materialanim");
    sithCog_RegisterFunction(pCog, sithCogFunction_StopAnim, "stopanim");
    sithCog_RegisterFunction(pCog, sithCogFunction_StopSurfaceAnim, "stopsurfaceanim");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetSurfaceAnim, "getsurfaceanim");
    sithCog_RegisterFunction(pCog, sithCogFunction_SurfaceAnim, "surfaceanim");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetKeyLen, "getkeylen");
    sithCog_RegisterFunction(pCog, sithCogFunction_LoadTemplate, "loadtemplate");
    sithCog_RegisterFunction(pCog, sithCogFunction_LoadKeyframe, "loadkeyframe");
    sithCog_RegisterFunction(pCog, sithCogFunction_LoadModel, "loadmodel");
    sithCog_RegisterFunction(pCog, sithCogFunction_Print, "print");
    sithCog_RegisterFunction(pCog, sithCogFunction_PrintInt, "printint");
    sithCog_RegisterFunction(pCog, sithCogFunction_PrintFlex, "printflex");
    sithCog_RegisterFunction(pCog, sithCogFunction_PrintVector, "printvector");
    sithCog_RegisterFunction(pCog, sithCogFunction_VectorAdd, "vectoradd");
    sithCog_RegisterFunction(pCog, sithCogFunction_VectorSub, "vectorsub");
    sithCog_RegisterFunction(pCog, sithCogFunction_VectorDot, "vectordot");
    sithCog_RegisterFunction(pCog, sithCogFunction_VectorCross, "vectorcross");
    sithCog_RegisterFunction(pCog, sithCogFunction_VectorSet, "vectorset");
    sithCog_RegisterFunction(pCog, sithCogFunction_VectorLen, "vectorlen");
    sithCog_RegisterFunction(pCog, sithCogFunction_VectorScale, "vectorscale");
    sithCog_RegisterFunction(pCog, sithCogFunction_VectorDist, "vectordist");
    sithCog_RegisterFunction(pCog, sithCogFunction_VectorX, "vectorx");
    sithCog_RegisterFunction(pCog, sithCogFunction_VectorY, "vectory");
    sithCog_RegisterFunction(pCog, sithCogFunction_VectorZ, "vectorz");
    sithCog_RegisterFunction(pCog, sithCogFunction_VectorNorm, "vectornorm");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(pCog,sithCogFunction_VectorEqual,"vectorequal"); // MOTS
    }
    sithCog_RegisterFunction(pCog, sithCogFunction_GetSithMode, "getsithmode");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetDifficulty, "getdifficulty");
    sithCog_RegisterFunction(pCog, sithCogFunction_SetSubModeFlags, "setsubmodeflags");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetSubModeFlags, "getsubmodeflags");
    sithCog_RegisterFunction(pCog, sithCogFunction_ClearSubModeFlags, "clearsubmodeflags");
    sithCog_RegisterFunction(pCog, sithCogFunction_SetDebugModeFlags, "setdebugmodeflags");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetDebugModeFlags, "getdebugmodeflags");
    sithCog_RegisterFunction(pCog, sithCogFunction_ClearDebugModeFlags, "cleardebugmodeflags");
    sithCog_RegisterFunction(pCog, sithCogFunction_BitSet, "bitset");
    sithCog_RegisterFunction(pCog, sithCogFunction_BitTest, "bittest");
    sithCog_RegisterFunction(pCog, sithCogFunction_BitClear, "bitclear");
    sithCog_RegisterFunction(pCog, sithCogFunction_FireProjectile, "fireprojectile");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(pCog,sithCogFunction_FireProjectileData,"fireprojectiledata"); // MOTS
        sithCog_RegisterFunction(pCog,sithCogFunction_FireProjectileLocal,"fireprojectilelocal"); // MOTS
    }
    sithCog_RegisterFunction(pCog, sithCogFunction_ActivateWeapon, "activateweapon");
    sithCog_RegisterFunction(pCog, sithCogFunction_DeactivateWeapon, "deactivateweapon");
    sithCog_RegisterFunction(pCog, sithCogFunction_SetMountWait, "setmountwait");
    sithCog_RegisterFunction(pCog, sithCogFunction_SetFireWait, "setfirewait");
    sithCog_RegisterFunction(pCog, sithCogFunction_SelectWeapon, "selectweapon");
    sithCog_RegisterFunction(pCog, sithCogFunction_AssignWeapon, "assignweapon");
    sithCog_RegisterFunction(pCog, sithCogFunction_AutoSelectWeapon, "autoselectweapon");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetWeaponPriority, "getweaponpriority");
    sithCog_RegisterFunction(pCog, sithCogFunction_SetCurWeapon, "setcurweapon");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetCurWeapon, "getcurweapon");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetCurWeaponMode, "getcurweaponmode");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(pCog,sithCogFunction_GetWeaponBin,"getweaponbin"); // MOTS
    }
    sithCog_RegisterFunction(pCog, sithCogFunction_ChangeFireRate, "changefirerate");
    sithCog_RegisterFunction(pCog, sithCogFunction_SendMessage, "sendmessage");
    sithCog_RegisterFunction(pCog, sithCogFunction_SendMessageEx, "sendmessageex");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(pCog,sithCogFunction_SendMessageExRadius,"sendmessageexradius"); // MOTS
    }
    sithCog_RegisterFunction(pCog, sithCogFunction_ReturnEx, "returnex");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetParam, "getparam");
    sithCog_RegisterFunction(pCog, sithCogFunction_SetParam, "setparam");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(pCog,sithCogFunction_WorldFlash,"worldflash"); // MOTS
    }
    sithCog_RegisterFunction(pCog, sithCogFunction_EnableIRMode, "enableirmode");
    sithCog_RegisterFunction(pCog, sithCogFunction_DisableIRMode, "disableirmode");
    sithCog_RegisterFunction(pCog, sithCogFunction_SetInvFlags, "setinvflags");
    sithCog_RegisterFunction(pCog, sithCogFunction_SetMapModeFlags, "setmapmodeflags");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetMapModelFlags, "getmapmodeflags");
    sithCog_RegisterFunction(pCog, sithCogFunction_ClearMapModeFlags, "clearmapmodeflags");
    sithCog_RegisterFunction(pCog, sithCogFunction_NewColorEffect, "newcoloreffect");
    sithCog_RegisterFunction(pCog, sithCogFunction_FreeColorEffect, "freecoloreffect");
    if (Main_bDwCompat) {
        sithCog_RegisterFunction(pCog, sithCogFunction_ModifyColorEffect, "modifycoloreffect");
    }
    else {
        sithCog_RegisterFunction(pCog, sithCogFunction_FreeColorEffect, "modifycoloreffect"); // oops? Droidworks fixes this
    }
    sithCog_RegisterFunction(pCog, sithCogFunction_AddDynamicTint, "adddynamictint");
    sithCog_RegisterFunction(pCog, sithCogFunction_AddDynamicAdd, "adddynamicadd");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetMaterialCel, "getmaterialcel");
    sithCog_RegisterFunction(pCog, sithCogFunction_SetMaterialCel, "setmaterialcel");
    sithCog_RegisterFunction(pCog, sithCogFunction_SetCameraFocus, "setcamerafocus");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetPrimaryFocus, "getprimaryfocus");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetSecondaryFocus, "getsecondaryfocus");
    sithCog_RegisterFunction(pCog, sithCogFunction_SetCameraMode, "setcurrentcamera");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetCameraMode, "getcurrentcamera");
    sithCog_RegisterFunction(pCog, sithCogFunction_CycleCamera, "cyclecamera");
    sithCog_RegisterFunction(pCog, sithCogFunction_SetPOVShake, "setpovshake");
    sithCog_RegisterFunction(pCog, sithCogFunction_SetCameraStateFlags, "setcamerastateflags");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetCameraStateFlags, "getcamerastateflags");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(pCog,sithCogFunction_SetCameraZoom,"setcamerazoom"); // MOTS
    }
    sithCog_RegisterFunction(pCog, sithCogFunction_HeapNew, "heapnew");
    sithCog_RegisterFunction(pCog, sithCogFunction_HeapSet, "heapset");
    sithCog_RegisterFunction(pCog, sithCogFunction_HeapGet, "heapget");
    sithCog_RegisterFunction(pCog, sithCogFunction_HeapFree, "heapfree");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetSelfCog, "getselfcog");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetMasterCog, "getmastercog");
    sithCog_RegisterFunction(pCog, sithCogFunction_SetMasterCog, "setmastercog");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(pCog,sithCogFunction_GetActionCog,"getactioncog"); // MOTS
        sithCog_RegisterFunction(pCog,sithCogFunction_SetActionCog,"setactioncog"); // MOTS
    }

    // Droidworks removes start
    sithCog_RegisterFunction(pCog, sithCogFunction_SetMultiModeFlags, "setmultimodeflags");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetMultiModeFlags, "getmultimodeflags");
    sithCog_RegisterFunction(pCog, sithCogFunction_ClearMultiModeFlags, "clearmultimodeflags");
    sithCog_RegisterFunction(pCog, sithCogFunction_IsMulti, "ismulti");
    sithCog_RegisterFunction(pCog, sithCogFunction_IsServer, "isserver");
    sithCog_RegisterFunction(pCog, sithCogFunction_SetTeamScore, "setteamscore");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetTeamScore, "getteamscore");
    sithCog_RegisterFunction(pCog, sithCogFunction_SetTimeLimit, "settimelimit");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetTimeLimit, "gettimelimit");
    sithCog_RegisterFunction(pCog, sithCogFunction_SetScoreLimit, "setscorelimit");
    sithCog_RegisterFunction(pCog, sithCogFunction_GetScoreLimit, "getscorelimit");
    // Droidworks removes end

    sithCog_RegisterFunction(pCog, sithCogFunction_SendTrigger, "sendtrigger");
    sithCog_RegisterFunction(pCog, sithCogFunction_AutoSavegame, "autosavegame");

    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(pCog,sithCogFunction_Sin,"sin"); // MOTS
        sithCog_RegisterFunction(pCog,sithCogFunction_Cos,"cos"); // MOTS
        sithCog_RegisterFunction(pCog,sithCogFunction_Tan,"tan"); // MOTS
        sithCog_RegisterFunction(pCog,sithCogFunction_GetCogFlags,"getcogflags"); // MOTS
        sithCog_RegisterFunction(pCog,sithCogFunction_SetCogFlags,"setcogflags"); // MOTS
        sithCog_RegisterFunction(pCog,sithCogFunction_ClearCogFlags,"clearcogflags"); // MOTS
        sithCog_RegisterFunction(pCog,sithCogFunction_DebugBreak,"debugbreak"); // MOTS
        sithCog_RegisterFunction(pCog,sithCogFunction_GetSysDate,"getsysdate"); // MOTS
        sithCog_RegisterFunction(pCog,sithCogFunction_GetSysTime,"getsystime"); // MOTS
    }
    
    // Droidworks
    if (Main_bDwCompat) {
        sithCog_RegisterFunction(pCog, sithCogFunction_SetCameraFocii, "setcamerafocii");
    }
}
