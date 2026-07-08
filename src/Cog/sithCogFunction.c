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

void sithCogFunction_GetSenderID(sithCog* ctx)
{
    sithCogExec_PushInt(ctx, ctx->senderId);
}

void sithCogFunction_GetSenderRef(sithCog *ctx)
{
    sithCogExec_PushInt(ctx, ctx->senderRef);
}

void sithCogFunction_GetSenderType(sithCog *ctx)
{
    sithCogExec_PushInt(ctx, ctx->senderType);
}

void sithCogFunction_GetSourceRef(sithCog *ctx)
{
    sithCogExec_PushInt(ctx, ctx->sourceRef);
}

void sithCogFunction_GetSourceType(sithCog *ctx)
{
    sithCogExec_PushInt(ctx, ctx->sourceType);
}

void sithCogFunction_Rand(sithCog *ctx)
{
    cog_flex_t val = _frand();
    sithCogExec_PushFlex(ctx, val);
}

void sithCogFunction_RandVec(sithCog *ctx)
{
    rdVector3 rvec;

    rvec.x = _frand();
    rvec.y = _frand();
    rvec.z = _frand();
    sithCogExec_PushVector(ctx, &rvec);
}

void sithCogFunction_Sleep(sithCog *ctx)
{
    sithCog *ctx_;
    flex_d_t fSecs;

    ctx_ = ctx;
    fSecs = sithCogExec_PopFlex(ctx);
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
        _sprintf(std_g_genBuffer, "Cog %s: Sleeping for %f seconds.\n", ctx_->cogscript_fpath, fSecs);
        sithConsole_PrintString(std_g_genBuffer);
#endif
    }
    ctx_->script_running = 2;
    ctx_->wakeTimeMs = sithTime_g_msecGameTime + (int)(fSecs * 1000.0);
}

void sithCogFunction_Print(sithCog *ctx)
{
    char *str;

    str = sithCogExec_PopString(ctx);
    if (str)
        sithConsole_PrintString(str);
}

void sithCogFunction_PrintInt(sithCog *ctx)
{
    char tmp[32];

    stdString_snprintf(tmp, 32, "%d", sithCogExec_PopInt(ctx));
    sithConsole_PrintString(tmp);
}

void sithCogFunction_PrintVector(sithCog *ctx)
{
    rdVector3 popVec;
    char tmp[32];

    if (sithCogExec_PopVector(ctx, &popVec))
        stdString_snprintf(tmp, 32, "<%f %f %f>", popVec.x, popVec.y, popVec.z);
    else
        stdString_snprintf(tmp, 32, "Bad vector");

    sithConsole_PrintString(tmp);
}

void sithCogFunction_PrintFlex(sithCog *ctx)
{
    char tmp[32];

    stdString_snprintf(tmp, 32, "%f", sithCogExec_PopFlex(ctx));
    sithConsole_PrintString(tmp);
}

void sithCogFunction_SurfaceAnim(sithCog *ctx)
{
    sithCog *ctx_;
    int popInt; // edi
    SithSurface *surface; // ecx
    rdSurface *v4; // eax
    cog_flex_t popFlex; // [esp+Ch] [ebp+4h]

    // TODO: is this inlined?
    ctx_ = ctx;
    popInt = sithCogExec_PopInt(ctx);
    popFlex = sithCogExec_PopFlex(ctx);
    surface = sithCogExec_PopSurface(ctx_); // TODO
    if ( !surface )
    {
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

void sithCogFunction_MaterialAnim(sithCog *ctx)
{
    sithCog *ctx_; // esi
    int popInt; // edi
    rdMaterial *material; // ecx
    rdSurface *v4; // eax
    cog_flex_t popFlex; // [esp+Ch] [ebp+4h]

    // TODO is this inlined
    ctx_ = ctx;
    popInt = sithCogExec_PopInt(ctx);
    popFlex = sithCogExec_PopFlex(ctx);
    material = sithCogExec_PopMaterial(ctx_);
    if ( !material )
    {
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

void sithCogFunction_StopAnim(sithCog *ctx)
{
    int v1; // eax
    rdSurface *v2; // eax

    v1 = sithCogExec_PopInt(ctx);
    v2 = sithSurface_GetByIdx(v1);
    if ( v2 )
    {
        sithSurface_StopAnim(v2);
        if ( sithMessage_g_outputstream )
            sithDSS_AnimStatus(v2, -1, 255); // TODO ??
    }
}

void sithCogFunction_StopSurfaceAnim(sithCog *ctx)
{
    SithSurface *v1; // eax
    rdSurface *v2; // eax

    v1 = sithCogExec_PopSurface(ctx);
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

void sithCogFunction_GetSurfaceAnim(sithCog *ctx)
{
    SithSurface *v1; // eax
    int v2; // eax

    v1 = sithCogExec_PopSurface(ctx);
    if ( v1 )
    {
        v2 = sithSurface_GetSurfaceAnim(v1);
        sithCogExec_PushInt(ctx, v2);
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunction_LoadTemplate(sithCog *ctx)
{
    char *v1; // eax
    SithThing *v2; // eax

    v1 = sithCogExec_PopString(ctx);
    if ( v1 && (v2 = sithTemplate_GetTemplate(v1)) != 0 )
        sithCogExec_PushInt(ctx, v2->idx);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunction_LoadKeyframe(sithCog *a1)
{
    char *v1; // eax
    rdKeyframe *v2; // eax

    v1 = sithCogExec_PopString(a1);
    if ( v1 && (v2 = sithKeyFrame_LoadEntry(v1)) != 0 )
        sithCogExec_PushInt(a1, v2->id);
    else
        sithCogExec_PushInt(a1, -1);
}

void sithCogFunction_LoadModel(sithCog *ctx)
{
    char *v1; // eax
    rdModel3 *v2; // eax

    v1 = sithCogExec_PopString(ctx);
    if ( v1 && (v2 = sithModel_Load(v1, 1)) != 0 )
        sithCogExec_PushInt(ctx, v2->id);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunction_SetPulse(sithCog *ctx)
{
    cog_flex_t popFlex;

    popFlex = sithCogExec_PopFlex(ctx);
    if ( popFlex <= 0.0 )
    {
        if ( ctx->flags & SITH_COG_DEBUG )
        {
#ifdef SITH_DEBUG_STRUCT_NAMES
            _sprintf(std_g_genBuffer, "Cog %s: Pulse disabled.\n", ctx->cogscript_fpath);
            sithConsole_PrintString(std_g_genBuffer);
#endif
        }
        ctx->flags &= ~SITH_COG_PULSE_SET;
    }
    else
    {
        if ( ctx->flags & SITH_COG_DEBUG )
        {
#ifdef SITH_DEBUG_STRUCT_NAMES
            _sprintf(std_g_genBuffer, "Cog %s: Pulse set to %f seconds.\n", ctx->cogscript_fpath, popFlex);
            sithConsole_PrintString(std_g_genBuffer);
#endif
        }
        ctx->flags |= SITH_COG_PULSE_SET;
        ctx->pulsePeriodMs = (int)(popFlex * 1000.0);
        ctx->nextPulseMs = (int)(popFlex * 1000.0) + sithTime_g_msecGameTime;
    }
}

void sithCogFunction_SetTimer(sithCog *ctx)
{
    cog_flex_t popFlex = sithCogExec_PopFlex(ctx);
    if ( popFlex <= 0.0 )
    {
        if ( ctx->flags & SITH_COG_DEBUG )
        {
#ifdef SITH_DEBUG_STRUCT_NAMES
            _sprintf(std_g_genBuffer, "Cog %s: Timer cancelled.\n", ctx->cogscript_fpath);
            sithConsole_PrintString(std_g_genBuffer);
#endif
        }
        ctx->flags &= ~SITH_COG_TIMER_SET;
    }
    else
    {
        if ( ctx->flags & SITH_COG_DEBUG )
        {
#ifdef SITH_DEBUG_STRUCT_NAMES
            _sprintf(std_g_genBuffer, "Cog %s: Timer set for %f seconds.\n", ctx->cogscript_fpath, popFlex);
            sithConsole_PrintString(std_g_genBuffer);
#endif
        }
        ctx->flags |= SITH_COG_TIMER_SET;
        ctx->field_20 = sithTime_g_msecGameTime + (int)(popFlex * 1000.0);
    }
}

void sithCogFunction_SetTimerEx(sithCog *ctx)
{
    SithEventParams timerInfo;

    timerInfo.field_14 = sithCogExec_PopFlex(ctx);
    timerInfo.field_10 = sithCogExec_PopFlex(ctx);
    timerInfo.timerIdx = sithCogExec_PopInt(ctx);
    timerInfo.cogIdx = ctx->selfCog;
    cog_flex_t a1a = sithCogExec_PopFlex(ctx) * 1000.0;
    int timerMs = (signed int)a1a;
    if ( timerMs >= 0 ) {
        sithEvent_CreateEvent(4, &timerInfo, timerMs);
    }
}

void sithCogFunction_KillTimerEx(sithCog *ctx)
{
    SithEvent *v2; // eax
    SithEvent *v3; // edi
    SithEvent *v4; // esi

    int v1 = sithCogExec_PopInt(ctx);
    if ( v1 > 0 )
    {
        v2 = sithEvent_g_pFirstQueuedEvent;
        v3 = 0;
        if ( sithEvent_g_pFirstQueuedEvent )
        {
            do
            {
                v4 = v2->nextTimer;
                if ( v2->taskNum == 4 && v2->timerInfo.cogIdx == ctx->selfCog && v2->timerInfo.timerIdx == v1 )
                {
                    if ( v3 )
                        v3->nextTimer = v4;
                    else
                        sithEvent_g_pFirstQueuedEvent = v2->nextTimer;
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

void sithCogFunction_Reset(sithCog *ctx)
{
    ctx->calldepth = 0;
}

void sithCogFunction_VectorSet(sithCog *ctx)
{
    rdVector3 out;

    out.z = sithCogExec_PopFlex(ctx);
    out.y = sithCogExec_PopFlex(ctx);
    out.x = sithCogExec_PopFlex(ctx);
    sithCogExec_PushVector(ctx, &out);
}

void sithCogFunction_VectorAdd(sithCog *ctx)
{
    rdVector3 inA;
    rdVector3 inB;
    rdVector3 out;

    sithCogExec_PopVector(ctx, &inA);
    sithCogExec_PopVector(ctx, &inB);
    rdVector_Add3(&out, &inA, &inB);
    sithCogExec_PushVector(ctx, &out);
}

void sithCogFunction_VectorSub(sithCog *ctx)
{
    rdVector3 inA;
    rdVector3 inB;
    rdVector3 out;

    sithCogExec_PopVector(ctx, &inA);
    sithCogExec_PopVector(ctx, &inB);
    rdVector_Sub3(&out, &inB, &inA);
    sithCogExec_PushVector(ctx, &out);
}

void sithCogFunction_VectorDot(sithCog *ctx)
{
    rdVector3 inA;
    rdVector3 inB;

    sithCogExec_PopVector(ctx, &inA);
    sithCogExec_PopVector(ctx, &inB);
    sithCogExec_PushFlex(ctx, rdVector_Dot3(&inA, &inB));
}

void sithCogFunction_VectorCross(sithCog *ctx)
{
    rdVector3 inA;
    rdVector3 inB;
    rdVector3 out;

    sithCogExec_PopVector(ctx, &inA);
    sithCogExec_PopVector(ctx, &inB);
    rdVector_Cross3(&out, &inA, &inB);
    sithCogExec_PushVector(ctx, &out);
}

void sithCogFunction_VectorLen(sithCog *ctx)
{
    rdVector3 in;

    sithCogExec_PopVector(ctx, &in);
    sithCogExec_PushFlex(ctx, rdVector_Len3(&in));
}

void sithCogFunction_VectorScale(sithCog *ctx)
{
    rdVector3 inA;
    rdVector3 out;

    cog_flex_t scale = sithCogExec_PopFlex(ctx);
    sithCogExec_PopVector(ctx, &inA);
    rdVector_Scale3(&out, &inA, scale);
    sithCogExec_PushVector(ctx, &out);
}

void sithCogFunction_VectorDist(sithCog *ctx)
{
    rdVector3 inA;
    rdVector3 inB;
    rdVector3 tmp;

    sithCogExec_PopVector(ctx, &inA);
    sithCogExec_PopVector(ctx, &inB);
    rdVector_Sub3(&tmp, &inB, &inA);
    sithCogExec_PushFlex(ctx, rdVector_Len3(&tmp));
}

// MOTS added
void sithCogFunction_VectorEqual(sithCog *ctx)
{
    rdVector3 popB;
    rdVector3 popA;
    
    sithCogExec_PopVector(ctx,&popA);
    sithCogExec_PopVector(ctx,&popB);
    if (((popB.x == popA.x) && (popB.y == popA.y)) && (popB.z == popA.z)) {
        sithCogExec_PushInt(ctx,1);
        return;
    }
    sithCogExec_PushInt(ctx,0);
    return;
}

void sithCogFunction_SendMessage(sithCog *ctx)
{
    int msgId = sithCogExec_PopInt(ctx);
    sithCog* cog = sithCogExec_PopCog(ctx);

    if (cog && msgId >= 0 && msgId < SITH_MESSAGE_MAX)
        sithCog_SendMessage(cog, msgId, SENDERTYPE_COG, ctx->selfCog, ctx->sourceType, ctx->sourceRef, 0);
}

void sithCogFunction_SendMessageEx(struct sithCog *ctx)
{
    cog_flex_t param3 = sithCogExec_PopFlex(ctx);
    cog_flex_t param2 = sithCogExec_PopFlex(ctx);
    cog_flex_t param1 = sithCogExec_PopFlex(ctx);
    cog_flex_t param0 = sithCogExec_PopFlex(ctx);
    int msgId = sithCogExec_PopInt(ctx);
    sithCog* cog = sithCogExec_PopCog(ctx);

    if (cog && msgId >= 0 && msgId < SITH_MESSAGE_MAX)
    {
        cog_flex_t flexRet = sithCog_SendMessageEx(cog, msgId, SENDERTYPE_COG, ctx->selfCog, ctx->sourceType, ctx->sourceRef, 0, param0, param1, param2, param3);
        sithCogExec_PushFlex(ctx, flexRet);
    }
}

void sithCogFunction_GetKeyLen(sithCog *ctx)
{
    rdKeyframe* keyframe = sithCogExec_PopKeyframe(ctx);

    if (!keyframe || keyframe->fps == 0.0)
    {
        sithCogExec_PushFlex(ctx, 0.0);
        return;
    }

    sithCogExec_PushFlex(ctx, (flex_d_t)keyframe->numFrames / keyframe->fps);
}

void sithCogFunction_GetSithMode(sithCog* ctx)
{
    sithCogExec_PushInt(ctx, g_sithMode);
}

void sithCogFunction_GetGameTime(sithCog *ctx)
{
    sithCogExec_PushInt(ctx, sithTime_g_msecGameTime);
}

void sithCogFunction_GetFlexGameTime(sithCog *ctx)
{
    sithCogExec_PushFlex(ctx, sithTime_g_secGameTime);
}

void sithCogFunction_GetDifficulty(sithCog *ctx)
{
    sithCogExec_PushInt(ctx, jkPlayer_setDiff);
}

void sithCogFunction_SetSubModeFlags(sithCog *ctx)
{
    g_submodeFlags |= sithCogExec_PopInt(ctx);
}

void sithCogFunction_ClearSubModeFlags(sithCog *ctx)
{
    g_submodeFlags &= ~sithCogExec_PopInt(ctx);
}

void sithCogFunction_GetSubModeFlags(sithCog *ctx)
{
    sithCogExec_PushInt(ctx, g_submodeFlags);
}

void sithCogFunction_SetDebugModeFlags(sithCog *ctx)
{
    g_debugmodeFlags |= sithCogExec_PopInt(ctx);
}

void sithCogFunction_ClearDebugModeFlags(sithCog *ctx)
{
    g_debugmodeFlags &= ~sithCogExec_PopInt(ctx);
}

void sithCogFunction_GetDebugModeFlags(sithCog *ctx)
{
    sithCogExec_PushInt(ctx, g_debugmodeFlags);
}

void sithCogFunction_BitSet(sithCog *ctx)
{
    signed int a;
    signed int b;

    a = sithCogExec_PopInt(ctx);
    b = sithCogExec_PopInt(ctx);
    sithCogExec_PushInt(ctx, b | a);
}

void sithCogFunction_BitTest(sithCog *ctx)
{
    signed int a;
    signed int b;

    a = sithCogExec_PopInt(ctx);
    b = sithCogExec_PopInt(ctx);
    sithCogExec_PushInt(ctx, b & a);
}

void sithCogFunction_BitClear(sithCog *ctx)
{
    signed int a;
    signed int b;

    a = sithCogExec_PopInt(ctx);
    b = sithCogExec_PopInt(ctx);
    sithCogExec_PushInt(ctx, b & ~a);
}

void sithCogFunction_GetLevelTime(sithCog *ctx)
{
    sithCogExec_PushFlex(ctx, sithTime_g_msecGameTime * 0.001);
}

void sithCogFunction_GetThingCount(sithCog *ctx)
{
    sithCogExec_PushInt(ctx, sithWorld_g_pCurrentWorld->numThingsLoaded);
}

void sithCogFunction_GetThingTemplateCount(sithCog *ctx)
{
    SithWorld *v1; // esi
    SithThing *v2; // eax
    int template_count; // edi

    v1 = sithWorld_g_pCurrentWorld;
    v2 = sithCogExec_PopTemplate(ctx);
    if ( v2 )
    {
        template_count = 0;
        for (int i = 0; i < v1->numThings; i++ )
        {
            SithThing* thing = &v1->aThings[i];
            if ( thing->type && thing->type != SITH_THING_CORPSE && thing->pTemplate == v2 )
                ++template_count;
        }
        sithCogExec_PushInt(ctx, template_count);
    }
}

void sithCogFunction_GetGravity(sithCog *ctx)
{
    sithCogExec_PushFlex(ctx, sithWorld_g_pCurrentWorld->gravity);
}

void sithCogFunction_SetGravity(sithCog *ctx)
{
    sithWorld_g_pCurrentWorld->gravity = sithCogExec_PopFlex(ctx);
}

void sithCogFunction_ReturnEx(sithCog *ctx)
{
    ctx->returnEx = sithCogExec_PopFlex(ctx);
}

void sithCogFunction_GetParam(sithCog *ctx)
{
    int idx = sithCogExec_PopInt(ctx);
    if ( idx < 0 || idx >= 4 )
        sithCogExec_PushFlex(ctx, -9999.0);
    else
        sithCogExec_PushFlex(ctx, ctx->params[idx]);
}

void sithCogFunction_SetParam(sithCog *ctx)
{
    cog_flex_t val = sithCogExec_PopFlex(ctx);
    int idx = sithCogExec_PopInt(ctx);
    if (idx >= 0 && idx < 4)
        ctx->params[idx] = val;
}

void sithCogFunction_VectorX(sithCog *ctx)
{
    rdVector3 popVec;

    sithCogExec_PopVector(ctx, &popVec);
    sithCogExec_PushFlex(ctx, popVec.x);
}

void sithCogFunction_VectorY(sithCog *ctx)
{
    rdVector3 popVec;

    sithCogExec_PopVector(ctx, &popVec);
    sithCogExec_PushFlex(ctx, popVec.y);
}

void sithCogFunction_VectorZ(sithCog *ctx)
{
    rdVector3 popVec;

    sithCogExec_PopVector(ctx, &popVec);
    sithCogExec_PushFlex(ctx, popVec.z);
}

void sithCogFunction_VectorNorm(sithCog *ctx)
{
    rdVector3 popVec;
    rdVector3 out;

    sithCogExec_PopVector(ctx, &popVec);
    rdVector_Normalize3(&out, &popVec);
    sithCogExec_PushVector(ctx, &out);
}

void sithCogFunction_SetMaterialCel(sithCog *ctx)
{
    signed int cel; // esi
    rdMaterial *mat; // eax

    cel = sithCogExec_PopInt(ctx);
    mat = sithCogExec_PopMaterial(ctx);
    if ( mat && cel >= 0 && (unsigned int)cel < mat->num_texinfo )
        mat->celIdx = cel;
    sithCogExec_PushInt(ctx, -1);
}

void sithCogFunction_GetMaterialCel(sithCog *ctx)
{
    rdMaterial *mat; // eax

    mat = sithCogExec_PopMaterial(ctx);
    if ( mat )
        sithCogExec_PushInt(ctx, mat->celIdx);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunction_EnableIRMode(sithCog *ctx)
{
    cog_flex_t flex1 = sithCogExec_PopFlex(ctx);
    cog_flex_t flex2 = sithCogExec_PopFlex(ctx);
    sithRender_EnableIRMode(flex2, flex1);
}

void sithCogFunction_DisableIRMode(sithCog *ctx)
{
    sithRender_DisableIRMode();
}

void sithCogFunction_SetInvFlags(sithCog *ctx)
{
    int flags;
    int binIdx;
    SithThing *player;

    flags = sithCogExec_PopInt(ctx);
    binIdx = sithCogExec_PopInt(ctx);
    player = sithCogExec_PopThing(ctx);
    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }
    if ( player && player->type == SITH_THING_PLAYER && player->actorParams.pPlayer && binIdx < SITHBIN_NUMBINS )
        sithInventory_SetInventoryFlags(player, binIdx, flags);
}

void sithCogFunction_SetMapModeFlags(sithCog *ctx)
{
    g_mapModeFlags |= sithCogExec_PopInt(ctx);
}

void sithCogFunction_GetMapModelFlags(sithCog *ctx)
{
    sithCogExec_PushInt(ctx, g_mapModeFlags);
}

void sithCogFunction_ClearMapModeFlags(sithCog *ctx)
{
    g_mapModeFlags &= ~sithCogExec_PopInt(ctx);
}

void sithCogFunction_SetCameraFocus(sithCog *ctx)
{
    SithThing *focusThing; // esi
    signed int camIdx; // eax

    focusThing = sithCogExec_PopThing(ctx);
    camIdx = sithCogExec_PopInt(ctx);

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

void sithCogFunction_GetPrimaryFocus(sithCog *ctx)
{
    signed int camIdx; // eax
    SithThing *v2; // eax

    camIdx = sithCogExec_PopInt(ctx);

#ifdef QOL_IMPROVEMENTS
    // Droidworks tmp
    if (camIdx == 7)
        camIdx = 0;
#endif

    if ( camIdx > -1 && camIdx < 7 && (v2 = sithCamera_GetPrimaryFocus(&sithCamera_g_aCameras[camIdx])) != 0 )
        sithCogExec_PushInt(ctx, v2->idx);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunction_GetSecondaryFocus(sithCog *ctx)
{
    signed int camIdx; // eax
    SithThing *v2; // eax

    camIdx = sithCogExec_PopInt(ctx);
    
#ifdef QOL_IMPROVEMENTS
    // Droidworks tmp
    if (camIdx == 7)
        camIdx = 0;
#endif
    
    if ( camIdx > -1 && camIdx < 7 && (v2 = sithCamera_GetSecondaryFocus(&sithCamera_g_aCameras[camIdx])) != 0 )
        sithCogExec_PushInt(ctx, v2->idx);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunction_SetCameraMode(sithCog *ctx)
{
    signed int camIdx; // eax

    camIdx = sithCogExec_PopInt(ctx);

#ifdef QOL_IMPROVEMENTS
    // Droidworks tmp
    if (camIdx == 7)
    {
        camIdx = 0;
        sithCamera_SetCameraFocus(&sithCamera_g_aCameras[camIdx], sithPlayer_g_pLocalPlayerThing, 0);
    }
#endif

    //printf("%u -> %u\n", sithCamera_g_pCurCamera - sithCamera_g_aCameras, camIdx);
    
    if ( camIdx > -1 && camIdx < 7 )
        sithCamera_SetCurrentCamera(&sithCamera_g_aCameras[camIdx]);
}

void sithCogFunction_GetCameraMode(sithCog *ctx)
{
    int camIdx; // edx

    if ( sithCamera_g_pCurCamera && (camIdx = sithCamera_g_pCurCamera - sithCamera_g_aCameras, camIdx < 7) )
        sithCogExec_PushInt(ctx, camIdx);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunction_CycleCamera(sithCog *ctx)
{
    sithCamera_CycleCamera();
}

// MOTS added
void sithCogFunction_SetCameraZoom(sithCog *ctx)
{
    cog_flex_t zoomSpeed = sithCogExec_PopFlex(ctx);
    cog_flex_t zoomScale = sithCogExec_PopFlex(ctx);
    int camIdx = sithCogExec_PopInt(ctx);

    if ((-1 < camIdx) && (camIdx < 7)) {
        sithCamera_SetZoom(sithCamera_g_aCameras + camIdx, zoomScale, zoomSpeed);
    }
}

void sithCogFunction_SetPOVShake(sithCog *ctx)
{
    rdVector3 v3;
    rdVector3 v4;

    cog_flex_t a1a = sithCogExec_PopFlex(ctx);
    cog_flex_t v2 = sithCogExec_PopFlex(ctx);
    if ( sithCogExec_PopVector(ctx, &v3) )
    {
        if ( sithCogExec_PopVector(ctx, &v4) )
            sithCamera_SetPOVShake(&v4, &v3, v2, a1a);
    }
}

void sithCogFunction_HeapNew(sithCog *ctx)
{
    SithCogSymbolValue *oldHeap; // eax
    SithCogSymbolValue *newHeap; // edi

    int numHeapVars = sithCogExec_PopInt(ctx);
    if ( numHeapVars > 0 )
    {
        oldHeap = ctx->heap;
        if ( oldHeap )
        {
            SITH_FREE(oldHeap);
            ctx->numHeapVars = 0;
        }
        { TWL_EXTRAM_SUGGEST(pSithHS); // Added: heap vars are word-safe stackvars
        newHeap = (SithCogSymbolValue *)SITH_ALLOC(sizeof(SithCogSymbolValue) * numHeapVars);
        TWL_EXTRAM_RESTORE(pSithHS); }
        ctx->heap = newHeap;
        if (!newHeap) { // Added: don't memset NULL on OOM
            ctx->numHeapVars = 0;
            return;
        }
        stdPlatform_Memzero32(newHeap, (sizeof(SithCogSymbolValue) * numHeapVars)); // Added: word-safe
        ctx->numHeapVars = numHeapVars;
    }
}

void sithCogFunction_HeapSet(sithCog *ctx)
{
    SithCogSymbolValue stackVar;

    int val = sithCogExec_PopSymbol(ctx, &stackVar);
    int idx = sithCogExec_PopInt(ctx);
    if ( val && idx >= 0 && idx < ctx->numHeapVars )
        ctx->heap[idx] = stackVar;
}

void sithCogFunction_HeapGet(sithCog *ctx)
{
    SithCogSymbolValue *heapVar;
    SithCogSymbolValue tmp;

    int idx = sithCogExec_PopInt(ctx);
    if (idx < 0 || idx >= ctx->numHeapVars)
    {
        sithCogExec_PushInt(ctx, 0);
    }
    else
    {
        heapVar = &ctx->heap[idx];
        tmp.type = heapVar->type;
        tmp.data[0] = heapVar->data[0];
        tmp.data[1] = heapVar->data[1];
        tmp.data[2] = heapVar->data[2];
        sithCogExec_PushStack(ctx, &tmp);
    }
}

void sithCogFunction_HeapFree(sithCog *ctx)
{
    if ( ctx->heap )
    {
        SITH_FREE(ctx->heap);
        ctx->numHeapVars = 0;
    }
}

void sithCogFunction_GetSelfCog(sithCog *ctx)
{
    sithCogExec_PushInt(ctx, ctx->selfCog);
}

void sithCogFunction_GetMasterCog(sithCog *ctx)
{
    if ( sithCog_g_pMasterCog )
        sithCogExec_PushInt(ctx, sithCog_g_pMasterCog->selfCog);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunction_SetMasterCog(sithCog *ctx)
{
    sithCog_g_pMasterCog = sithCogExec_PopCog(ctx);
}

// MOTS added
void sithCogFunction_GetActionCog(sithCog *ctx)
{
    if ( sithCog_pActionCog )
        sithCogExec_PushInt(ctx, sithCog_pActionCog->selfCog);
    else
        sithCogExec_PushInt(ctx, -1);
}

// MOTS added
void sithCogFunction_SetActionCog(sithCog *ctx)
{
    sithCog_actionCogIdk = sithCogExec_PopInt(ctx);
    sithCog* pCog = sithCogExec_PopCog(ctx);
    sithCog_pActionCog = (pCog == (void*)-1) ? NULL : pCog;
}

void sithCogFunction_NewColorEffect(sithCog *ctx)
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

    fade = sithCogExec_PopFlex(ctx);
    addB = sithCogExec_PopInt(ctx);
    addG = sithCogExec_PopInt(ctx);
    addR = sithCogExec_PopInt(ctx);
    tintB = sithCogExec_PopFlex(ctx);
    tintG = sithCogExec_PopFlex(ctx);
    tintR = sithCogExec_PopFlex(ctx);
    filterB = sithCogExec_PopInt(ctx);
    filterG = sithCogExec_PopInt(ctx);
    filterR = sithCogExec_PopInt(ctx);
    idx = stdPalEffects_NewRequest(1);
    if ( idx == -1 )
    {
        sithCogExec_PushInt(ctx, -1);
    }
    else
    {
        stdPalEffects_SetFilter(idx, filterR, filterG, filterB);
        stdPalEffects_SetTint(idx, tintR, tintG, tintB);
        stdPalEffects_SetAdd(idx, addR, addG, addB);
        stdPalEffects_SetFade(idx, fade);
        sithCogExec_PushInt(ctx, idx);
    }
}

void sithCogFunction_ModifyColorEffect(sithCog *ctx)
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

    fade = sithCogExec_PopFlex(ctx);
    addB = sithCogExec_PopInt(ctx);
    addG = sithCogExec_PopInt(ctx);
    addR = sithCogExec_PopInt(ctx);
    tintB = sithCogExec_PopFlex(ctx);
    tintG = sithCogExec_PopFlex(ctx);
    tintR = sithCogExec_PopFlex(ctx);
    filterB = sithCogExec_PopInt(ctx);
    filterG = sithCogExec_PopInt(ctx);
    filterR = sithCogExec_PopInt(ctx);
    idx = sithCogExec_PopInt(ctx);
    stdPalEffects_SetFilter(idx, filterR, filterG, filterB);
    stdPalEffects_SetTint(idx, tintR, tintG, tintB);
    stdPalEffects_SetAdd(idx, addR, addG, addB);
    stdPalEffects_SetFade(idx, fade);
}

void sithCogFunction_FreeColorEffect(sithCog *ctx)
{
    uint32_t v1; // eax

    v1 = sithCogExec_PopInt(ctx);
    stdPalEffects_FreeRequest(v1);
}

void sithCogFunction_AddDynamicTint(sithCog *ctx)
{
    sithCog *v1; // esi
    SithThing *player; // eax

    v1 = ctx;
    cog_flex_t fB = sithCogExec_PopFlex(ctx);
    cog_flex_t fG = sithCogExec_PopFlex(v1);
    cog_flex_t fR = sithCogExec_PopFlex(v1);
    player = sithCogExec_PopThing(v1);
    if ( player && player->type == SITH_THING_PLAYER && player == sithPlayer_g_pLocalPlayerThing )
        sithPlayer_AddDynamicTint(fR, fG, fB);
}

void sithCogFunction_AddDynamicAdd(sithCog *ctx)
{
    int b; // edi
    int g; // ebx
    int r; // ebp
    SithThing *pLocalPlayer; // eax

    b = sithCogExec_PopInt(ctx);
    g = sithCogExec_PopInt(ctx);
    r = sithCogExec_PopInt(ctx);
    pLocalPlayer = sithCogExec_PopThing(ctx);
    if ( pLocalPlayer && pLocalPlayer->type == SITH_THING_PLAYER && pLocalPlayer == sithPlayer_g_pLocalPlayerThing )
        sithPlayer_AddDyamicAdd(r, g, b);
}

// modifycoloreffect, freecoloreffect, adddynamictint, adddynamicadd

// MOTS added
void sithCogFunction_FireProjectileInternal(sithCog *ctx, int extra)
{
    rdVector3 aimError;
    rdVector3 fireOffset;
    
    cog_flex_t autoaimMaxDist = sithCogExec_PopFlex(ctx);
    cog_flex_t autoaimFov = sithCogExec_PopFlex(ctx);
    int scaleFlags = sithCogExec_PopInt(ctx);
    cog_flex_t scale = sithCogExec_PopFlex(ctx);
    sithCogExec_PopVector(ctx,&aimError);
    sithCogExec_PopVector(ctx,&fireOffset);
    int mode = sithCogExec_PopInt(ctx);
    sithSound* fireSound = sithCogExec_PopSound(ctx);
    SithThing* projectileTemplate = sithCogExec_PopTemplate(ctx);
    SithThing* sender = sithCogExec_PopThing(ctx);

    if (sender) {
        projectileTemplate = sithWeapon_FireProjectile(sender,projectileTemplate,fireSound,mode,&fireOffset,&aimError,scale,(int16_t)scaleFlags,autoaimFov,autoaimMaxDist,extra);
        if (projectileTemplate) {
            sithCogExec_PushInt(ctx,projectileTemplate->idx);
            return;
        }
    }
    sithCogExec_PushInt(ctx,-1);
}

void sithCogFunction_FireProjectile(sithCog *ctx)
{
    sithCogFunction_FireProjectileInternal(ctx, 0);
}

// MOTS added
void sithCogFunction_FireProjectileData(sithCog *ctx)
{
    int popA = sithCogExec_PopInt(ctx);
    sithCogFunction_FireProjectileInternal(ctx,popA);
}

// MOTS added
void sithCogFunction_FireProjectileLocal(sithCog *ctx)
{
    int tmp = sithMessage_g_outputstream;
    sithMessage_g_outputstream = 0;
    sithCogFunction_FireProjectile(ctx);
    sithMessage_g_outputstream = tmp;
    return;
}

void sithCogFunction_SendTrigger(sithCog *ctx)
{
    SithPlayer* pPlayer;

    cog_flex_t arg3 = sithCogExec_PopFlex(ctx);
    cog_flex_t arg2 = sithCogExec_PopFlex(ctx);
    cog_flex_t arg1 = sithCogExec_PopFlex(ctx);
    cog_flex_t arg0 = sithCogExec_PopFlex(ctx);
    int sourceType = sithCogExec_PopInt(ctx);
    SithThing* sourceThing = sithCogExec_PopThing(ctx);
    
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
                            pPlayer->net_id);
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

void sithCogFunction_ActivateWeapon(sithCog *ctx)
{
    int mode = sithCogExec_PopInt(ctx);
    cog_flex_t fireRate = sithCogExec_PopFlex(ctx);
    SithThing* weaponThing = sithCogExec_PopThing(ctx);

    if ( weaponThing && fireRate >= 0.0 && mode >= 0 && mode < 2 )
        sithWeapon_ActivateWeapon(weaponThing, ctx, fireRate, mode);
}

void sithCogFunction_DeactivateWeapon(sithCog *ctx)
{
    int mode = sithCogExec_PopInt(ctx);
    SithThing* weapon = sithCogExec_PopThing(ctx);
    if ( weapon && mode >= 0 && mode < 2 )
    {
        sithCogExec_PushFlex(ctx, sithWeapon_DeactivateWeapon(weapon, ctx, mode));
    }
    else
    {
        sithCogExec_PushFlex(ctx, -1.0);
    }
}

void sithCogFunction_SetFireWait(sithCog *ctx)
{
    cog_flex_t fireRate = sithCogExec_PopFlex(ctx);
    SithThing* weapon = sithCogExec_PopThing(ctx);

    if ( weapon && weapon == sithPlayer_g_pLocalPlayerThing && fireRate >= -1.0 )
        sithWeapon_SetFireWait(weapon, fireRate);
}

void sithCogFunction_SetMountWait(sithCog *ctx)
{
    cog_flex_t mountWait = sithCogExec_PopFlex(ctx);
    SithThing* weapon = sithCogExec_PopThing(ctx);

    if ( weapon && weapon == sithPlayer_g_pLocalPlayerThing && mountWait >= -1.0 )
        sithWeapon_SetMountWait(weapon, mountWait);
}

void sithCogFunction_SelectWeapon(sithCog *ctx)
{
    int binIdx = sithCogExec_PopInt(ctx);
    SithThing* player = sithCogExec_PopThing(ctx);

    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }

    if ( player )
    {
        if ( binIdx >= 0 )
            sithWeapon_SelectWeapon(player, binIdx, 0);
    }
}

void sithCogFunction_AssignWeapon(sithCog *ctx)
{
    int binIdx = sithCogExec_PopInt(ctx);
    SithThing* player = sithCogExec_PopThing(ctx);

    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }

    if ( player )
    {
        if ( binIdx >= 1 )
            sithWeapon_SelectWeapon(player, binIdx, 1);
    }
}

void sithCogFunction_AutoSelectWeapon(sithCog *ctx)
{
    int weapIdx = sithCogExec_PopInt(ctx);
    SithThing* player = sithCogExec_PopThing(ctx);

    if ( weapIdx >= 0 && weapIdx <= 2 && player )
    {
        int binIdx = sithWeapon_AutoSelect(player, weapIdx);
        if (Main_bMotsCompat) {
            binIdx = sithInventory_SelectWeaponPrior(binIdx);
        }

        sithCogExec_PushInt(ctx, binIdx);
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunction_SetCurWeapon(sithCog *ctx)
{
    int v4; // eax

    int binIdx = sithCogExec_PopInt(ctx);
    SithThing* player = sithCogExec_PopThing(ctx);

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

void sithCogFunction_GetWeaponPriority(sithCog *ctx)
{
    int mode = sithCogExec_PopInt(ctx);
    int binIdx = sithCogExec_PopInt(ctx);
    SithThing* player = sithCogExec_PopThing(ctx);

    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }

    if ( player && player->type == SITH_THING_PLAYER )
    {
        if ( mode < 0 || mode > 2 )
        {
            sithCogExec_PushInt(ctx, -1);
            return;
        }
        if ( binIdx >= 0 && binIdx < SITHBIN_NUMBINS )
        {
            sithCogExec_PushFlex(ctx, sithWeapon_GetPriority(player, binIdx, mode));
            return;
        }
    }
    sithCogExec_PushFlex(ctx, -1.0);
}

void sithCogFunction_GetCurWeaponMode(sithCog *ctx)
{
    sithCogExec_PushInt(ctx, sithWeapon_GetCurWeaponMode());
}

void sithCogFunction_GetCurWeapon(sithCog *ctx)
{
    SithThing* player = sithCogExec_PopThing(ctx);

    if ( player && player->type == SITH_THING_PLAYER )
    {
        int binIdx = sithInventory_GetCurrentWeapon(player);
        if (Main_bMotsCompat) {
            binIdx = sithInventory_SelectWeaponPrior(binIdx);
        }
        sithCogExec_PushInt(ctx, binIdx);
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}

// MOTS added
void sithCogFunction_GetWeaponBin(sithCog *ctx)
{
    int popA;
    
    popA = sithCogExec_PopInt(ctx);
    popA = sithInventory_SelectWeaponFollowing(popA);
    sithCogExec_PushInt(ctx,popA);
}

void sithCogFunction_GetCameraStateFlags(sithCog *ctx)
{
    int v1; // eax

    v1 = sithCamera_GetCameraStateFlags();
    sithCogExec_PushInt(ctx, v1);
}

void sithCogFunction_SetCameraStateFlags(sithCog *ctx)
{
    int v1; // eax

    v1 = sithCogExec_PopInt(ctx);
    sithCamera_SetCameraStateFlags(v1);
}

void sithCogFunction_SetMultiModeFlags(sithCog *ctx)
{
    sithNet_MultiModeFlags |= sithCogExec_PopInt(ctx);
}

void sithCogFunction_GetMultiModeFlags(sithCog *ctx)
{
    sithCogExec_PushInt(ctx, sithNet_MultiModeFlags);
}

void sithCogFunction_ClearMultiModeFlags(sithCog *ctx)
{
    sithNet_MultiModeFlags &= ~sithCogExec_PopInt(ctx);
}

void sithCogFunction_IsMulti(sithCog *ctx)
{
    if ( sithNet_isMulti )
        sithCogExec_PushInt(ctx, 1);
    else
        sithCogExec_PushInt(ctx, 0);
}

void sithCogFunction_IsServer(sithCog *ctx)
{
    sithCogFunction_ReturnBool(sithNet_isServer, ctx);
}

// unused
void sithCogFunction_ReturnBool(int a1, sithCog *a2)
{
    if ( a1 )
        sithCogExec_PushInt(a2, 1);
    else
        sithCogExec_PushInt(a2, 0);
}

void sithCogFunction_GetTeamScore(sithCog *ctx)
{
    signed int idx; // eax

    idx = sithCogExec_PopInt(ctx);
    if ( idx <= 0 || idx >= 5 )
        sithCogExec_PushInt(ctx, -999999);
    else
        sithCogExec_PushInt(ctx, sithNet_teamScore[idx]);
}

void sithCogFunction_SetTeamScore(sithCog *ctx)
{
    signed int score; // edi
    signed int idx; // eax

    score = sithCogExec_PopInt(ctx);
    idx = sithCogExec_PopInt(ctx);
    if ( idx > 0 && idx < 5 )
        sithNet_teamScore[idx] = score;
}

void sithCogFunction_GetTimeLimit(sithCog *a1)
{
    cog_flex_t a2 = (flex_d_t)(unsigned int)sithNet_multiplayer_timelimit * 0.000016666667;
    sithCogExec_PushFlex(a1, a2);
}

void sithCogFunction_SetTimeLimit(sithCog *ctx)
{
    cog_flex_t v1 = sithCogExec_PopFlex(ctx);
    if ( v1 >= 0.0 )
        sithNet_multiplayer_timelimit = (int)(v1 * 60000.0);
}

void sithCogFunction_GetScoreLimit(sithCog *ctx)
{
    sithCogExec_PushInt(ctx, sithNet_scorelimit);
}

void sithCogFunction_SetScoreLimit(sithCog *ctx)
{
    sithNet_scorelimit = sithCogExec_PopInt(ctx);
}

void sithCogFunction_ChangeFireRate(sithCog *ctx)
{
    cog_flex_t fireRate = sithCogExec_PopFlex(ctx);
    SithThing* player = sithCogExec_PopThing(ctx);

    if ( player && player == sithPlayer_g_pLocalPlayerThing && fireRate > 0.0 )
        sithWeapon_SetFireRate(player, fireRate);
}

void sithCogFunction_AutoSavegame(sithCog *ctx)
{
    char tmp[128];

    stdString_snprintf(tmp, 128, "%s%s", "_JKAUTO_", sithGamesave_AutosaveMapName()); // Added: single-slot on DC
    stdFnames_ChangeExt(tmp, "jks");
    sithGamesave_Save(tmp, 1, 0, 0);
}

void sithCogFunction_SetCameraFocii(sithCog *ctx)
{
    SithThing* focusThing2 = sithCogExec_PopThing(ctx);
    SithThing* focusThing = sithCogExec_PopThing(ctx);
    int camIdx = sithCogExec_PopInt(ctx);

#ifdef QOL_IMPROVEMENTS
    // Droidworks tmp
    if (camIdx == 7)
        camIdx = 0;
#endif

    if ( camIdx > -1 && camIdx < 7 ) // TODO macro this 7?
    {
        if ( focusThing )
            sithCamera_SetCameraFocus(&sithCamera_g_aCameras[camIdx], focusThing, focusThing2);
    }
}

// MOTS added
void sithCogFunction_Pow(sithCog *ctx)
{
    cog_flex_t fVar2 = sithCogExec_PopFlex(ctx);
    cog_flex_t fVar3 = sithCogExec_PopFlex(ctx);
    if ((fVar2 == 0.0) && (fVar3 == 0.0)) {
        sithCogExec_PushFlex(ctx,0.0);
        return;
    }
    sithCogExec_PushFlex(ctx,stdMath_FlexPower(fVar2, fVar3)); // TODO verify
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
void sithCogFunction_Sin(sithCog *ctx)
{
    flex_t outSin;
    flex_t outCos;
    
    cog_flex_t angle = sithCogExec_PopFlex(ctx);
    stdMath_SinCos(angle,&outSin,&outCos);
    sithCogExec_PushFlex(ctx,outSin);
}

// MOTS added
void sithCogFunction_Cos(sithCog *ctx)
{
    flex_t outSin;
    flex_t outCos;
    
    cog_flex_t angle = sithCogExec_PopFlex(ctx);
    stdMath_SinCos(angle,&outSin,&outCos);
    sithCogExec_PushFlex(ctx,outCos);
}

// MOTS added
void sithCogFunction_Tan(sithCog *ctx)
{
    cog_flex_t fVar1 = sithCogExec_PopFlex(ctx);
    fVar1 = stdMath_Tan(fVar1);
    sithCogExec_PushFlex(ctx,fVar1);
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
void sithCogFunction_DebugBreak(sithCog *ctx)
{
    // TODO
}

// MOTS added
void sithCogFunction_WorldFlash(sithCog *ctx)
{
    cog_flex_t arg2 = sithCogExec_PopFlex(ctx);
    cog_flex_t arg1 = sithCogExec_PopFlex(ctx);
    sithRender_WorldFlash(arg1, arg2);
}

// MOTS added
void sithCogFunction_GetSysDate(sithCog *ctx)
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

    sithCogExec_PushVector(ctx, &out);
}

// MOTS added
void sithCogFunction_GetSysTime(sithCog *ctx)
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
    

    sithCogExec_PushVector(ctx, &out);
}

// MOTS added
void sithCogFunction_SendMessageExRadius(sithCog *ctx)
{
    cog_flex_t fVar1;
    cog_flex_t fVar2;
    cog_flex_t fVar3;
    int message;
    uint32_t uVar4;
    int iVar5;
    SithThing *sender;
    int local_28;
    rdVector3 local_1c;

    cog_flex_t local_4 = sithCogExec_PopFlex(ctx);
    cog_flex_t local_8 = sithCogExec_PopFlex(ctx);
    cog_flex_t local_c = sithCogExec_PopFlex(ctx);
    cog_flex_t local_10 = sithCogExec_PopFlex(ctx);
    message = sithCogExec_PopInt(ctx);
    uVar4 = sithCogExec_PopInt(ctx);
    cog_flex_t fVar6 = sithCogExec_PopFlex(ctx);
    iVar5 = sithCogExec_PopVector(ctx,&local_1c);
    cog_flex_t param1 = local_c;
    cog_flex_t param0 = local_10;
    if ((((iVar5 != 0) && (-1 < message)) && (message < SITH_MESSAGE_ENTERBUBBLE)) 
        && (local_28 = sithWorld_g_pCurrentWorld->numThings, -1 < local_28)) 
    {
        int iVar5_idx = local_28;
        local_28 = local_28 + 1;
        do 
        {
            sender = &sithWorld_g_pCurrentWorld->aThings[iVar5_idx];
            if (((((uVar4 & 1 << (sender->type & 0x1f)) != 0) 
                && ((sender->flags & (SITH_TF_DISABLED|SITH_TF_DEAD|SITH_TF_DESTROYED)) == 0))
                && ((sender->type != 10 || ((uVar4 & 0x400) != 0)))) 
                && (fVar3 = (sender->position).x - local_1c.x, fVar1 = (sender->position).y - local_1c.y,
                    fVar2 = (sender->position).z - local_1c.z,
                    fVar1 = stdMath_Sqrt(fVar2 * fVar2 + fVar1 * fVar1 + fVar3 * fVar3),
                    fVar1 <= fVar6))
            {
                sithCog_ThingSendMessageEx(sender, NULL, message, param0, param1, local_8, local_4);
            }
            iVar5_idx--;
            local_28--;
        } while (local_28 != 0);
    }
}



void sithCogFunction_Startup(SithCogSymbolTable* ctx)
{
    sithCog_RegisterFunction(ctx, sithCogFunction_Sleep, "sleep");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(ctx, sithCogFunction_Pow, "pow"); // MOTS
        sithCog_RegisterFunction(ctx, sithCogFunction_Wakeup, "wakeup"); // MOTS
    }
    sithCog_RegisterFunction(ctx, sithCogFunction_Rand, "rand");
    sithCog_RegisterFunction(ctx, sithCogFunction_RandVec, "randvec");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetSenderRef, "getsenderref");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetSenderType, "getsendertype");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetSenderID, "getsenderid");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetSourceType, "getsourcetype");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetSourceRef, "getsourceref");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetThingCount, "getthingcount");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetGravity, "getgravity");
    sithCog_RegisterFunction(ctx, sithCogFunction_SetGravity, "setgravity");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetLevelTime, "getleveltime");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetGameTime, "getgametime");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetFlexGameTime, "getflexgametime");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetThingTemplateCount, "getthingtemplatecount");
    sithCog_RegisterFunction(ctx, sithCogFunction_SetPulse, "setpulse");
    sithCog_RegisterFunction(ctx, sithCogFunction_SetTimer, "settimer");
    sithCog_RegisterFunction(ctx, sithCogFunction_SetTimerEx, "settimerex");
    sithCog_RegisterFunction(ctx, sithCogFunction_KillTimerEx, "killtimerex");
    sithCog_RegisterFunction(ctx, sithCogFunction_Reset, "reset");
    sithCog_RegisterFunction(ctx, sithCogFunction_MaterialAnim, "materialanim");
    sithCog_RegisterFunction(ctx, sithCogFunction_StopAnim, "stopanim");
    sithCog_RegisterFunction(ctx, sithCogFunction_StopSurfaceAnim, "stopsurfaceanim");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetSurfaceAnim, "getsurfaceanim");
    sithCog_RegisterFunction(ctx, sithCogFunction_SurfaceAnim, "surfaceanim");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetKeyLen, "getkeylen");
    sithCog_RegisterFunction(ctx, sithCogFunction_LoadTemplate, "loadtemplate");
    sithCog_RegisterFunction(ctx, sithCogFunction_LoadKeyframe, "loadkeyframe");
    sithCog_RegisterFunction(ctx, sithCogFunction_LoadModel, "loadmodel");
    sithCog_RegisterFunction(ctx, sithCogFunction_Print, "print");
    sithCog_RegisterFunction(ctx, sithCogFunction_PrintInt, "printint");
    sithCog_RegisterFunction(ctx, sithCogFunction_PrintFlex, "printflex");
    sithCog_RegisterFunction(ctx, sithCogFunction_PrintVector, "printvector");
    sithCog_RegisterFunction(ctx, sithCogFunction_VectorAdd, "vectoradd");
    sithCog_RegisterFunction(ctx, sithCogFunction_VectorSub, "vectorsub");
    sithCog_RegisterFunction(ctx, sithCogFunction_VectorDot, "vectordot");
    sithCog_RegisterFunction(ctx, sithCogFunction_VectorCross, "vectorcross");
    sithCog_RegisterFunction(ctx, sithCogFunction_VectorSet, "vectorset");
    sithCog_RegisterFunction(ctx, sithCogFunction_VectorLen, "vectorlen");
    sithCog_RegisterFunction(ctx, sithCogFunction_VectorScale, "vectorscale");
    sithCog_RegisterFunction(ctx, sithCogFunction_VectorDist, "vectordist");
    sithCog_RegisterFunction(ctx, sithCogFunction_VectorX, "vectorx");
    sithCog_RegisterFunction(ctx, sithCogFunction_VectorY, "vectory");
    sithCog_RegisterFunction(ctx, sithCogFunction_VectorZ, "vectorz");
    sithCog_RegisterFunction(ctx, sithCogFunction_VectorNorm, "vectornorm");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(ctx,sithCogFunction_VectorEqual,"vectorequal"); // MOTS
    }
    sithCog_RegisterFunction(ctx, sithCogFunction_GetSithMode, "getsithmode");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetDifficulty, "getdifficulty");
    sithCog_RegisterFunction(ctx, sithCogFunction_SetSubModeFlags, "setsubmodeflags");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetSubModeFlags, "getsubmodeflags");
    sithCog_RegisterFunction(ctx, sithCogFunction_ClearSubModeFlags, "clearsubmodeflags");
    sithCog_RegisterFunction(ctx, sithCogFunction_SetDebugModeFlags, "setdebugmodeflags");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetDebugModeFlags, "getdebugmodeflags");
    sithCog_RegisterFunction(ctx, sithCogFunction_ClearDebugModeFlags, "cleardebugmodeflags");
    sithCog_RegisterFunction(ctx, sithCogFunction_BitSet, "bitset");
    sithCog_RegisterFunction(ctx, sithCogFunction_BitTest, "bittest");
    sithCog_RegisterFunction(ctx, sithCogFunction_BitClear, "bitclear");
    sithCog_RegisterFunction(ctx, sithCogFunction_FireProjectile, "fireprojectile");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(ctx,sithCogFunction_FireProjectileData,"fireprojectiledata"); // MOTS
        sithCog_RegisterFunction(ctx,sithCogFunction_FireProjectileLocal,"fireprojectilelocal"); // MOTS
    }
    sithCog_RegisterFunction(ctx, sithCogFunction_ActivateWeapon, "activateweapon");
    sithCog_RegisterFunction(ctx, sithCogFunction_DeactivateWeapon, "deactivateweapon");
    sithCog_RegisterFunction(ctx, sithCogFunction_SetMountWait, "setmountwait");
    sithCog_RegisterFunction(ctx, sithCogFunction_SetFireWait, "setfirewait");
    sithCog_RegisterFunction(ctx, sithCogFunction_SelectWeapon, "selectweapon");
    sithCog_RegisterFunction(ctx, sithCogFunction_AssignWeapon, "assignweapon");
    sithCog_RegisterFunction(ctx, sithCogFunction_AutoSelectWeapon, "autoselectweapon");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetWeaponPriority, "getweaponpriority");
    sithCog_RegisterFunction(ctx, sithCogFunction_SetCurWeapon, "setcurweapon");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetCurWeapon, "getcurweapon");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetCurWeaponMode, "getcurweaponmode");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(ctx,sithCogFunction_GetWeaponBin,"getweaponbin"); // MOTS
    }
    sithCog_RegisterFunction(ctx, sithCogFunction_ChangeFireRate, "changefirerate");
    sithCog_RegisterFunction(ctx, sithCogFunction_SendMessage, "sendmessage");
    sithCog_RegisterFunction(ctx, sithCogFunction_SendMessageEx, "sendmessageex");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(ctx,sithCogFunction_SendMessageExRadius,"sendmessageexradius"); // MOTS
    }
    sithCog_RegisterFunction(ctx, sithCogFunction_ReturnEx, "returnex");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetParam, "getparam");
    sithCog_RegisterFunction(ctx, sithCogFunction_SetParam, "setparam");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(ctx,sithCogFunction_WorldFlash,"worldflash"); // MOTS
    }
    sithCog_RegisterFunction(ctx, sithCogFunction_EnableIRMode, "enableirmode");
    sithCog_RegisterFunction(ctx, sithCogFunction_DisableIRMode, "disableirmode");
    sithCog_RegisterFunction(ctx, sithCogFunction_SetInvFlags, "setinvflags");
    sithCog_RegisterFunction(ctx, sithCogFunction_SetMapModeFlags, "setmapmodeflags");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetMapModelFlags, "getmapmodeflags");
    sithCog_RegisterFunction(ctx, sithCogFunction_ClearMapModeFlags, "clearmapmodeflags");
    sithCog_RegisterFunction(ctx, sithCogFunction_NewColorEffect, "newcoloreffect");
    sithCog_RegisterFunction(ctx, sithCogFunction_FreeColorEffect, "freecoloreffect");
    if (Main_bDwCompat) {
        sithCog_RegisterFunction(ctx, sithCogFunction_ModifyColorEffect, "modifycoloreffect");
    }
    else {
        sithCog_RegisterFunction(ctx, sithCogFunction_FreeColorEffect, "modifycoloreffect"); // oops? Droidworks fixes this
    }
    sithCog_RegisterFunction(ctx, sithCogFunction_AddDynamicTint, "adddynamictint");
    sithCog_RegisterFunction(ctx, sithCogFunction_AddDynamicAdd, "adddynamicadd");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetMaterialCel, "getmaterialcel");
    sithCog_RegisterFunction(ctx, sithCogFunction_SetMaterialCel, "setmaterialcel");
    sithCog_RegisterFunction(ctx, sithCogFunction_SetCameraFocus, "setcamerafocus");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetPrimaryFocus, "getprimaryfocus");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetSecondaryFocus, "getsecondaryfocus");
    sithCog_RegisterFunction(ctx, sithCogFunction_SetCameraMode, "setcurrentcamera");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetCameraMode, "getcurrentcamera");
    sithCog_RegisterFunction(ctx, sithCogFunction_CycleCamera, "cyclecamera");
    sithCog_RegisterFunction(ctx, sithCogFunction_SetPOVShake, "setpovshake");
    sithCog_RegisterFunction(ctx, sithCogFunction_SetCameraStateFlags, "setcamerastateflags");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetCameraStateFlags, "getcamerastateflags");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(ctx,sithCogFunction_SetCameraZoom,"setcamerazoom"); // MOTS
    }
    sithCog_RegisterFunction(ctx, sithCogFunction_HeapNew, "heapnew");
    sithCog_RegisterFunction(ctx, sithCogFunction_HeapSet, "heapset");
    sithCog_RegisterFunction(ctx, sithCogFunction_HeapGet, "heapget");
    sithCog_RegisterFunction(ctx, sithCogFunction_HeapFree, "heapfree");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetSelfCog, "getselfcog");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetMasterCog, "getmastercog");
    sithCog_RegisterFunction(ctx, sithCogFunction_SetMasterCog, "setmastercog");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(ctx,sithCogFunction_GetActionCog,"getactioncog"); // MOTS
        sithCog_RegisterFunction(ctx,sithCogFunction_SetActionCog,"setactioncog"); // MOTS
    }

    // Droidworks removes start
    sithCog_RegisterFunction(ctx, sithCogFunction_SetMultiModeFlags, "setmultimodeflags");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetMultiModeFlags, "getmultimodeflags");
    sithCog_RegisterFunction(ctx, sithCogFunction_ClearMultiModeFlags, "clearmultimodeflags");
    sithCog_RegisterFunction(ctx, sithCogFunction_IsMulti, "ismulti");
    sithCog_RegisterFunction(ctx, sithCogFunction_IsServer, "isserver");
    sithCog_RegisterFunction(ctx, sithCogFunction_SetTeamScore, "setteamscore");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetTeamScore, "getteamscore");
    sithCog_RegisterFunction(ctx, sithCogFunction_SetTimeLimit, "settimelimit");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetTimeLimit, "gettimelimit");
    sithCog_RegisterFunction(ctx, sithCogFunction_SetScoreLimit, "setscorelimit");
    sithCog_RegisterFunction(ctx, sithCogFunction_GetScoreLimit, "getscorelimit");
    // Droidworks removes end

    sithCog_RegisterFunction(ctx, sithCogFunction_SendTrigger, "sendtrigger");
    sithCog_RegisterFunction(ctx, sithCogFunction_AutoSavegame, "autosavegame");

    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(ctx,sithCogFunction_Sin,"sin"); // MOTS
        sithCog_RegisterFunction(ctx,sithCogFunction_Cos,"cos"); // MOTS
        sithCog_RegisterFunction(ctx,sithCogFunction_Tan,"tan"); // MOTS
        sithCog_RegisterFunction(ctx,sithCogFunction_GetCogFlags,"getcogflags"); // MOTS
        sithCog_RegisterFunction(ctx,sithCogFunction_SetCogFlags,"setcogflags"); // MOTS
        sithCog_RegisterFunction(ctx,sithCogFunction_ClearCogFlags,"clearcogflags"); // MOTS
        sithCog_RegisterFunction(ctx,sithCogFunction_DebugBreak,"debugbreak"); // MOTS
        sithCog_RegisterFunction(ctx,sithCogFunction_GetSysDate,"getsysdate"); // MOTS
        sithCog_RegisterFunction(ctx,sithCogFunction_GetSysTime,"getsystime"); // MOTS
    }
    
    // Droidworks
    if (Main_bDwCompat) {
        sithCog_RegisterFunction(ctx, sithCogFunction_SetCameraFocii, "setcamerafocii");
    }
}
