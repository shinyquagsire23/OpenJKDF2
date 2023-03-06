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

void sithCogFunction_GetSenderId(sithCog* ctx)
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
    float val = _frand();
    sithCogExec_PushFlex(ctx, val);
}

void sithCogFunction_RandVec(sithCog *ctx)
{
    rdVector3 rvec;

    rvec.x = _frand();
    rvec.y = _frand();
    rvec.z = _frand();
    sithCogExec_PushVector3(ctx, &rvec);
}

void sithCogFunction_Sleep(sithCog *ctx)
{
    sithCog *ctx_;
    double fSecs;

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
        _sprintf(std_genBuffer, "Cog %s: Sleeping for %f seconds.\n", ctx_->cogscript_fpath, fSecs);
        sithConsole_Print(std_genBuffer);
    }
    ctx_->script_running = 2;
    ctx_->wakeTimeMs = sithTime_curMs + (int)(fSecs * 1000.0);
}

void sithCogFunction_Print(sithCog *ctx)
{
    char *str;

    str = sithCogExec_PopString(ctx);
    if (str)
        sithConsole_Print(str);
}

void sithCogFunction_PrintInt(sithCog *ctx)
{
    char tmp[32];

    stdString_snprintf(tmp, 32, "%d", sithCogExec_PopInt(ctx));
    sithConsole_Print(tmp);
}

void sithCogFunction_PrintVector(sithCog *ctx)
{
    rdVector3 popVec;
    char tmp[32];

    if (sithCogExec_PopVector3(ctx, &popVec))
        stdString_snprintf(tmp, 32, "<%f %f %f>", popVec.x, popVec.y, popVec.z);
    else
        stdString_snprintf(tmp, 32, "Bad vector");

    sithConsole_Print(tmp);
}

void sithCogFunction_PrintFlex(sithCog *ctx)
{
    char tmp[32];

    stdString_snprintf(tmp, 32, "%f", sithCogExec_PopFlex(ctx));
    sithConsole_Print(tmp);
}

void sithCogFunction_SurfaceAnim(sithCog *ctx)
{
    sithCog *ctx_;
    int popInt; // edi
    sithSurface *surface; // ecx
    rdSurface *v4; // eax
    float popFlex; // [esp+Ch] [ebp+4h]

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
    void *material; // ecx
    rdSurface *v4; // eax
    float popFlex; // [esp+Ch] [ebp+4h]

    // TODO is this inlined
    ctx_ = ctx;
    popInt = sithCogExec_PopInt(ctx);
    popFlex = sithCogExec_PopFlex(ctx);
    material = sithCogExec_PopMaterial(ctx_); // TODO rdMaterial*
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
    sithThing *v1;

    v1 = sithCogExec_PopThing(ctx);
    if ( v1 )
    {
        if ( v1->moveType == SITH_MT_PHYSICS )
        {
            sithPhysics_ThingStop(v1);
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
        if ( sithComm_multiplayerFlags )
            sithDSS_SendSurface(v2, -1, 255); // TODO ??
    }
}

void sithCogFunction_StopSurfaceAnim(sithCog *ctx)
{
    sithSurface *v1; // eax
    rdSurface *v2; // eax

    v1 = sithCogExec_PopSurface(ctx);
    if ( v1 )
    {
        v2 = sithSurface_GetRdSurface(v1);
        if ( v2 )
        {
            sithSurface_StopAnim(v2);
            if ( sithComm_multiplayerFlags )
                sithDSS_SendSurface(v2, -1, 255); // TODO ??
        }
    }
}

void sithCogFunction_GetSurfaceAnim(sithCog *ctx)
{
    sithSurface *v1; // eax
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
    sithThing *v2; // eax

    v1 = sithCogExec_PopString(ctx);
    if ( v1 && (v2 = sithTemplate_GetEntryByName(v1)) != 0 )
        sithCogExec_PushInt(ctx, v2->thingIdx);
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
    if ( v1 && (v2 = sithModel_LoadEntry(v1, 1)) != 0 )
        sithCogExec_PushInt(ctx, v2->id);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunction_SetPulse(sithCog *ctx)
{
    float popFlex;

    popFlex = sithCogExec_PopFlex(ctx);
    if ( popFlex <= 0.0 )
    {
        if ( ctx->flags & SITH_COG_DEBUG )
        {
            _sprintf(std_genBuffer, "Cog %s: Pulse disabled.\n", ctx->cogscript_fpath);
            sithConsole_Print(std_genBuffer);
        }
        ctx->flags &= ~SITH_COG_PULSE_SET;
    }
    else
    {
        if ( ctx->flags & SITH_COG_DEBUG )
        {
            _sprintf(std_genBuffer, "Cog %s: Pulse set to %f seconds.\n", ctx->cogscript_fpath, popFlex);
            sithConsole_Print(std_genBuffer);
        }
        ctx->flags |= SITH_COG_PULSE_SET;
        ctx->pulsePeriodMs = (int)(popFlex * 1000.0);
        ctx->nextPulseMs = (int)(popFlex * 1000.0) + sithTime_curMs;
    }
}

void sithCogFunction_SetTimer(sithCog *ctx)
{
    float popFlex = sithCogExec_PopFlex(ctx);
    if ( popFlex <= 0.0 )
    {
        if ( ctx->flags & SITH_COG_DEBUG )
        {
            _sprintf(std_genBuffer, "Cog %s: Timer cancelled.\n", ctx->cogscript_fpath);
            sithConsole_Print(std_genBuffer);
        }
        ctx->flags &= ~SITH_COG_TIMER_SET;
    }
    else
    {
        if ( ctx->flags & SITH_COG_DEBUG )
        {
            _sprintf(std_genBuffer, "Cog %s: Timer set for %f seconds.\n", ctx->cogscript_fpath, popFlex);
            sithConsole_Print(std_genBuffer);
        }
        ctx->flags |= SITH_COG_TIMER_SET;
        ctx->field_20 = sithTime_curMs + (int)(popFlex * 1000.0);
    }
}

void sithCogFunction_SetTimerEx(sithCog *ctx)
{
    sithEventInfo timerInfo; // [esp+4h] [ebp-14h]
    int timerMs; // [esp+14h] [ebp-4h]
    float a1a; // [esp+20h] [ebp+8h]

    timerInfo.field_14 = sithCogExec_PopFlex(ctx);
    timerInfo.field_10 = sithCogExec_PopFlex(ctx);
    timerInfo.timerIdx = sithCogExec_PopInt(ctx);
    timerInfo.cogIdx = ctx->selfCog;
    a1a = sithCogExec_PopFlex(ctx) * 1000.0;
    timerMs = (signed int)a1a;
    if ( timerMs >= 0 ) {
        sithEvent_Set(4, &timerInfo, timerMs);
    }
}

void sithCogFunction_KillTimerEx(sithCog *ctx)
{
    signed int v1; // ebx
    sithEvent *v2; // eax
    sithEvent *v3; // edi
    sithEvent *v4; // esi

    v1 = sithCogExec_PopInt(ctx);
    if ( v1 > 0 )
    {
        v2 = sithEvent_list;
        v3 = 0;
        if ( sithEvent_list )
        {
            do
            {
                v4 = v2->nextTimer;
                if ( v2->taskNum == 4 && v2->timerInfo.cogIdx == ctx->selfCog && v2->timerInfo.timerIdx == v1 )
                {
                    if ( v3 )
                        v3->nextTimer = v4;
                    else
                        sithEvent_list = v2->nextTimer;
                    sithEvent_Kill(v2);
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
    sithCogExec_PushVector3(ctx, &out);
}

void sithCogFunction_VectorAdd(sithCog *ctx)
{
    rdVector3 inA;
    rdVector3 inB;
    rdVector3 out;

    sithCogExec_PopVector3(ctx, &inA);
    sithCogExec_PopVector3(ctx, &inB);
    rdVector_Add3(&out, &inA, &inB);
    sithCogExec_PushVector3(ctx, &out);
}

void sithCogFunction_VectorSub(sithCog *ctx)
{
    rdVector3 inA;
    rdVector3 inB;
    rdVector3 out;

    sithCogExec_PopVector3(ctx, &inA);
    sithCogExec_PopVector3(ctx, &inB);
    rdVector_Sub3(&out, &inB, &inA);
    sithCogExec_PushVector3(ctx, &out);
}

void sithCogFunction_VectorDot(sithCog *ctx)
{
    rdVector3 inA;
    rdVector3 inB;

    sithCogExec_PopVector3(ctx, &inA);
    sithCogExec_PopVector3(ctx, &inB);
    sithCogExec_PushFlex(ctx, rdVector_Dot3(&inA, &inB));
}

void sithCogFunction_VectorCross(sithCog *ctx)
{
    rdVector3 inA;
    rdVector3 inB;
    rdVector3 out;

    sithCogExec_PopVector3(ctx, &inA);
    sithCogExec_PopVector3(ctx, &inB);
    rdVector_Cross3(&out, &inA, &inB);
    sithCogExec_PushVector3(ctx, &out);
}

void sithCogFunction_VectorLen(sithCog *ctx)
{
    rdVector3 in;

    sithCogExec_PopVector3(ctx, &in);
    sithCogExec_PushFlex(ctx, rdVector_Len3(&in));
}

void sithCogFunction_VectorScale(sithCog *ctx)
{
    rdVector3 inA;
    rdVector3 out;

    float scale = sithCogExec_PopFlex(ctx);
    sithCogExec_PopVector3(ctx, &inA);
    rdVector_Scale3(&out, &inA, scale);
    sithCogExec_PushVector3(ctx, &out);
}

void sithCogFunction_VectorDist(sithCog *ctx)
{
    rdVector3 inA;
    rdVector3 inB;
    rdVector3 tmp;

    sithCogExec_PopVector3(ctx, &inA);
    sithCogExec_PopVector3(ctx, &inB);
    rdVector_Sub3(&tmp, &inB, &inA);
    sithCogExec_PushFlex(ctx, rdVector_Len3(&tmp));
}

// MOTS added
void sithCogFunction_VectorEqual(sithCog *ctx)
{
    rdVector3 popB;
    rdVector3 popA;
    
    sithCogExec_PopVector3(ctx,&popA);
    sithCogExec_PopVector3(ctx,&popB);
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
    float param3 = sithCogExec_PopFlex(ctx);
    float param2 = sithCogExec_PopFlex(ctx);
    float param1 = sithCogExec_PopFlex(ctx);
    float param0 = sithCogExec_PopFlex(ctx);
    int msgId = sithCogExec_PopInt(ctx);
    sithCog* cog = sithCogExec_PopCog(ctx);

    if (cog && msgId >= 0 && msgId < SITH_MESSAGE_MAX)
    {
        float flexRet = sithCog_SendMessageEx(cog, msgId, SENDERTYPE_COG, ctx->selfCog, ctx->sourceType, ctx->sourceRef, 0, param0, param1, param2, param3);
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

    sithCogExec_PushFlex(ctx, (double)keyframe->numFrames / keyframe->fps);
}

void sithCogFunction_GetSithMode(sithCog* ctx)
{
    sithCogExec_PushInt(ctx, g_sithMode);
}

void sithCogFunction_GetGametime(sithCog *ctx)
{
    sithCogExec_PushInt(ctx, sithTime_curMs);
}

void sithCogFunction_GetFlexGameTime(sithCog *ctx)
{
    sithCogExec_PushFlex(ctx, sithTime_curSeconds);
}

void sithCogFunction_GetDifficulty(sithCog *ctx)
{
    sithCogExec_PushInt(ctx, jkPlayer_setDiff);
}

void sithCogFunction_SetSubmodeFlags(sithCog *ctx)
{
    g_submodeFlags |= sithCogExec_PopInt(ctx);
}

void sithCogFunction_ClearSubmodeFlags(sithCog *ctx)
{
    g_submodeFlags &= ~sithCogExec_PopInt(ctx);
}

void sithCogFunction_GetSubmodeFlags(sithCog *ctx)
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
    sithCogExec_PushFlex(ctx, sithTime_curMs * 0.001);
}

void sithCogFunction_GetThingCount(sithCog *ctx)
{
    sithCogExec_PushInt(ctx, sithWorld_pCurrentWorld->numThingsLoaded);
}

void sithCogFunction_GetThingTemplateCount(sithCog *ctx)
{
    sithWorld *v1; // esi
    sithThing *v2; // eax
    int template_count; // edi

    v1 = sithWorld_pCurrentWorld;
    v2 = sithCogExec_PopTemplate(ctx);
    if ( v2 )
    {
        template_count = 0;
        for (int i = 0; i < v1->numThings; i++ )
        {
            sithThing* thing = &v1->things[i];
            if ( thing->type && thing->type != SITH_THING_CORPSE && thing->templateBase == v2 )
                ++template_count;
        }
        sithCogExec_PushInt(ctx, template_count);
    }
}

void sithCogFunction_GetGravity(sithCog *ctx)
{
    sithCogExec_PushFlex(ctx, sithWorld_pCurrentWorld->worldGravity);
}

void sithCogFunction_SetGravity(sithCog *ctx)
{
    sithWorld_pCurrentWorld->worldGravity = sithCogExec_PopFlex(ctx);
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
    int idx;
    float val;

    val = sithCogExec_PopFlex(ctx);
    idx = sithCogExec_PopInt(ctx);
    if (idx >= 0 && idx < 4)
        ctx->params[idx] = val;
}

void sithCogFunction_VectorX(sithCog *ctx)
{
    rdVector3 popVec;

    sithCogExec_PopVector3(ctx, &popVec);
    sithCogExec_PushFlex(ctx, popVec.x);
}

void sithCogFunction_VectorY(sithCog *ctx)
{
    rdVector3 popVec;

    sithCogExec_PopVector3(ctx, &popVec);
    sithCogExec_PushFlex(ctx, popVec.y);
}

void sithCogFunction_VectorZ(sithCog *ctx)
{
    rdVector3 popVec;

    sithCogExec_PopVector3(ctx, &popVec);
    sithCogExec_PushFlex(ctx, popVec.z);
}

void sithCogFunction_VectorNorm(sithCog *ctx)
{
    rdVector3 popVec;
    rdVector3 out;

    sithCogExec_PopVector3(ctx, &popVec);
    rdVector_Normalize3(&out, &popVec);
    sithCogExec_PushVector3(ctx, &out);
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
    float flex1 = sithCogExec_PopFlex(ctx);
    float flex2 = sithCogExec_PopFlex(ctx);
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
    sithThing *player;

    flags = sithCogExec_PopInt(ctx);
    binIdx = sithCogExec_PopInt(ctx);
    player = sithCogExec_PopThing(ctx);
    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }
    if ( player && player->type == SITH_THING_PLAYER && player->actorParams.playerinfo && binIdx < SITHBIN_NUMBINS )
        sithInventory_SetFlags(player, binIdx, flags);
}

void sithCogFunction_SetMapModeFlags(sithCog *ctx)
{
    g_mapModeFlags |= sithCogExec_PopInt(ctx);
}

void sithCogFunction_GetMapModeFlags(sithCog *ctx)
{
    sithCogExec_PushInt(ctx, g_mapModeFlags);
}

void sithCogFunction_ClearMapModeFlags(sithCog *ctx)
{
    g_mapModeFlags &= ~sithCogExec_PopInt(ctx);
}

void sithCogFunction_SetCameraFocus(sithCog *ctx)
{
    sithThing *focusThing; // esi
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
            sithCamera_SetCameraFocus(&sithCamera_cameras[camIdx], focusThing, 0);
    }
}

void sithCogFunction_GetPrimaryFocus(sithCog *ctx)
{
    signed int camIdx; // eax
    sithThing *v2; // eax

    camIdx = sithCogExec_PopInt(ctx);

#ifdef QOL_IMPROVEMENTS
    // Droidworks tmp
    if (camIdx == 7)
        camIdx = 0;
#endif

    if ( camIdx > -1 && camIdx < 7 && (v2 = sithCamera_GetPrimaryFocus(&sithCamera_cameras[camIdx])) != 0 )
        sithCogExec_PushInt(ctx, v2->thingIdx);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunction_GetSecondaryFocus(sithCog *ctx)
{
    signed int camIdx; // eax
    sithThing *v2; // eax

    camIdx = sithCogExec_PopInt(ctx);
    
#ifdef QOL_IMPROVEMENTS
    // Droidworks tmp
    if (camIdx == 7)
        camIdx = 0;
#endif
    
    if ( camIdx > -1 && camIdx < 7 && (v2 = sithCamera_GetSecondaryFocus(&sithCamera_cameras[camIdx])) != 0 )
        sithCogExec_PushInt(ctx, v2->thingIdx);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunction_SetCurrentCamera(sithCog *ctx)
{
    signed int camIdx; // eax

    camIdx = sithCogExec_PopInt(ctx);

#ifdef QOL_IMPROVEMENTS
    // Droidworks tmp
    if (camIdx == 7)
    {
        camIdx = 0;
        sithCamera_SetCameraFocus(&sithCamera_cameras[camIdx], sithPlayer_pLocalPlayerThing, 0);
    }
#endif

    //printf("%u -> %u\n", sithCamera_currentCamera - sithCamera_cameras, camIdx);
    
    if ( camIdx > -1 && camIdx < 7 )
        sithCamera_SetCurrentCamera(&sithCamera_cameras[camIdx]);
}

void sithCogFunction_GetCurrentCamera(sithCog *ctx)
{
    int camIdx; // edx

    if ( sithCamera_currentCamera && (camIdx = sithCamera_currentCamera - sithCamera_cameras, camIdx < 7) )
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
    float zoomSpeed = sithCogExec_PopFlex(ctx);
    float zoomScale = sithCogExec_PopFlex(ctx);
    int camIdx = sithCogExec_PopInt(ctx);

    if ((-1 < camIdx) && (camIdx < 7)) {
        sithCamera_SetZoom(sithCamera_cameras + camIdx, zoomScale, zoomSpeed);
    }
}

void sithCogFunction_SetPovShake(sithCog *ctx)
{
    float v2; // [esp+4h] [ebp-1Ch]
    rdVector3 v3; // [esp+8h] [ebp-18h]
    rdVector3 v4; // [esp+14h] [ebp-Ch]
    float a1a; // [esp+24h] [ebp+4h]

    a1a = sithCogExec_PopFlex(ctx);
    v2 = sithCogExec_PopFlex(ctx);
    if ( sithCogExec_PopVector3(ctx, &v3) )
    {
        if ( sithCogExec_PopVector3(ctx, &v4) )
            sithCamera_SetPovShake(&v4, &v3, v2, a1a);
    }
}

void sithCogFunction_HeapNew(sithCog *ctx)
{
    int numHeapVars; // ebp
    sithCogStackvar *oldHeap; // eax
    sithCogStackvar *newHeap; // edi

    numHeapVars = sithCogExec_PopInt(ctx);
    if ( numHeapVars > 0 )
    {
        oldHeap = ctx->heap;
        if ( oldHeap )
        {
            pSithHS->free(oldHeap);
            ctx->numHeapVars = 0;
        }
        newHeap = (sithCogStackvar *)pSithHS->alloc(sizeof(sithCogStackvar) * numHeapVars);
        ctx->heap = newHeap;
        _memset(newHeap, 0, (sizeof(sithCogStackvar) * numHeapVars));
        ctx->numHeapVars = numHeapVars;
    }
}

void sithCogFunction_HeapSet(sithCog *ctx)
{
    int val;
    int idx;
    sithCogStackvar stackVar;

    val = sithCogExec_PopValue(ctx, &stackVar);
    idx = sithCogExec_PopInt(ctx);
    if ( val && idx >= 0 && idx < ctx->numHeapVars )
        ctx->heap[idx] = stackVar;
}

void sithCogFunction_HeapGet(sithCog *ctx)
{
    int idx;
    sithCogStackvar *heapVar;
    sithCogStackvar tmp;

    idx = sithCogExec_PopInt(ctx);
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
        sithCogExec_PushVar(ctx, &tmp);
    }
}

void sithCogFunction_HeapFree(sithCog *ctx)
{
    if ( ctx->heap )
    {
        pSithHS->free(ctx->heap);
        ctx->numHeapVars = 0;
    }
}

void sithCogFunction_GetSelfCog(sithCog *ctx)
{
    sithCogExec_PushInt(ctx, ctx->selfCog);
}

void sithCogFunction_GetMasterCog(sithCog *ctx)
{
    if ( sithCog_masterCog )
        sithCogExec_PushInt(ctx, sithCog_masterCog->selfCog);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunction_SetMasterCog(sithCog *ctx)
{
    sithCog_masterCog = sithCogExec_PopCog(ctx);
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
    sithCog *v1; // esi
    int v2; // ebx
    int v3; // ebp
    int idx; // edi
    signed int a3; // [esp+10h] [ebp-1Ch]
    signed int a2; // [esp+14h] [ebp-18h]
    float a4; // [esp+18h] [ebp-14h]
    float v8; // [esp+1Ch] [ebp-10h]
    float v9; // [esp+20h] [ebp-Ch]
    signed int v10; // [esp+24h] [ebp-8h]
    float v11; // [esp+28h] [ebp-4h]
    int a1a; // [esp+30h] [ebp+4h]

    v1 = ctx;
    v11 = sithCogExec_PopFlex(ctx);
    v2 = sithCogExec_PopInt(ctx);
    v3 = sithCogExec_PopInt(ctx);
    v10 = sithCogExec_PopInt(ctx);
    a4 = sithCogExec_PopFlex(ctx);
    v8 = sithCogExec_PopFlex(ctx);
    v9 = sithCogExec_PopFlex(ctx);
    a1a = sithCogExec_PopInt(ctx);
    a3 = sithCogExec_PopInt(v1);
    a2 = sithCogExec_PopInt(v1);
    idx = stdPalEffects_NewRequest(1);
    if ( idx == -1 )
    {
        sithCogExec_PushInt(v1, -1);
    }
    else
    {
        stdPalEffects_SetFilter(idx, a2, a3, a1a);
        stdPalEffects_SetTint(idx, v9, v8, a4);
        stdPalEffects_SetAdd(idx, v10, v3, v2);
        stdPalEffects_SetFade(idx, v11);
        sithCogExec_PushInt(v1, idx);
    }
}

void sithCogFunction_ModifyColorEffect(sithCog *ctx)
{
    sithCog *v1; // esi
    float v2; // ST34_4
    int v3; // edi
    int v4; // ebx
    int v5; // ebp
    float a4; // ST28_4
    float v7; // ST2C_4
    float v8; // ST30_4
    signed int a3; // ST20_4
    signed int a2; // ST24_4
    int v11; // esi
    int a1a; // [esp+2Ch] [ebp+4h]

    v1 = ctx;
    v2 = sithCogExec_PopFlex(ctx);
    v3 = sithCogExec_PopInt(ctx);
    v4 = sithCogExec_PopInt(ctx);
    v5 = sithCogExec_PopInt(ctx);
    a4 = sithCogExec_PopFlex(ctx);
    v7 = sithCogExec_PopFlex(ctx);
    v8 = sithCogExec_PopFlex(ctx);
    a1a = sithCogExec_PopInt(ctx);
    a3 = sithCogExec_PopInt(v1);
    a2 = sithCogExec_PopInt(v1);
    v11 = sithCogExec_PopInt(v1);
    stdPalEffects_SetFilter(v11, a2, a3, a1a);
    stdPalEffects_SetTint(v11, v8, v7, a4);
    stdPalEffects_SetAdd(v11, v5, v4, v3);
    stdPalEffects_SetFade(v11, v2);
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
    sithThing *player; // eax
    float fG; // [esp+4h] [ebp-8h]
    float fR; // [esp+8h] [ebp-4h]
    float fB; // [esp+10h] [ebp+4h]

    v1 = ctx;
    fB = sithCogExec_PopFlex(ctx);
    fG = sithCogExec_PopFlex(v1);
    fR = sithCogExec_PopFlex(v1);
    player = sithCogExec_PopThing(v1);
    if ( player && player->type == SITH_THING_PLAYER && player == sithPlayer_pLocalPlayerThing )
        sithPlayer_AddDynamicTint(fR, fG, fB);
}

void sithCogFunction_AddDynamicAdd(sithCog *ctx)
{
    int b; // edi
    int g; // ebx
    int r; // ebp
    sithThing *playerThing; // eax

    b = sithCogExec_PopInt(ctx);
    g = sithCogExec_PopInt(ctx);
    r = sithCogExec_PopInt(ctx);
    playerThing = sithCogExec_PopThing(ctx);
    if ( playerThing && playerThing->type == SITH_THING_PLAYER && playerThing == sithPlayer_pLocalPlayerThing )
        sithPlayer_AddDyamicAdd(r, g, b);
}

// modifycoloreffect, freecoloreffect, adddynamictint, adddynamicadd

// MOTS added
void sithCogFunction_FireProjectileInternal(sithCog *ctx, int extra)
{
    int scaleFlags;
    int mode;
    sithSound *fireSound;
    sithThing *projectileTemplate;
    sithThing *sender;
    float autoaimMaxDist;
    float autoaimFov;
    float scale;
    rdVector3 aimError;
    rdVector3 fireOffset;
    
    autoaimMaxDist = sithCogExec_PopFlex(ctx);
    autoaimFov = sithCogExec_PopFlex(ctx);
    scaleFlags = sithCogExec_PopInt(ctx);
    scale = sithCogExec_PopFlex(ctx);
    sithCogExec_PopVector3(ctx,&aimError);
    sithCogExec_PopVector3(ctx,&fireOffset);
    mode = sithCogExec_PopInt(ctx);
    fireSound = sithCogExec_PopSound(ctx);
    projectileTemplate = sithCogExec_PopTemplate(ctx);
    sender = sithCogExec_PopThing(ctx);
    if (sender) {
        projectileTemplate = sithWeapon_FireProjectile(sender,projectileTemplate,fireSound,mode,&fireOffset,&aimError,scale,(int16_t)scaleFlags,autoaimFov,autoaimMaxDist,extra);
        if (projectileTemplate) {
            sithCogExec_PushInt(ctx,projectileTemplate->thingIdx);
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
    int tmp = sithComm_multiplayerFlags;
    sithComm_multiplayerFlags = 0;
    sithCogFunction_FireProjectile(ctx);
    sithComm_multiplayerFlags = tmp;
    return;
}

void sithCogFunction_SendTrigger(sithCog *ctx)
{
    int sourceType; // edi
    sithThing *sourceThing; // eax
    sithPlayerInfo *playerinfo; // ecx
    float arg3; // [esp+10h] [ebp-Ch]
    float arg2; // [esp+14h] [ebp-8h]
    float arg1; // [esp+18h] [ebp-4h]
    float arg0; // [esp+20h] [ebp+4h]

    arg3 = sithCogExec_PopFlex(ctx);
    arg2 = sithCogExec_PopFlex(ctx);
    arg1 = sithCogExec_PopFlex(ctx);
    arg0 = sithCogExec_PopFlex(ctx);
    sourceType = sithCogExec_PopInt(ctx);
    sourceThing = sithCogExec_PopThing(ctx);
    if ( sourceThing )
    {
        if ( sourceThing->type == SITH_THING_PLAYER )
        {
            playerinfo = sourceThing->actorParams.playerinfo;
            if ( playerinfo )
            {
                if ( playerinfo->flags & 1 )
                {
                    if ( sourceThing == sithPlayer_pLocalPlayerThing )
                        sithCog_SendMessageToAll(SITH_MESSAGE_TRIGGER, SENDERTYPE_THING, sithPlayer_pLocalPlayerThing->thingIdx, 0, sourceType, arg0, arg1, arg2, arg3);
                    else
                        sithDSSCog_SendSendTrigger(
                            0,
                            SITH_MESSAGE_TRIGGER,
                            SENDERTYPE_THING,
                            sithPlayer_pLocalPlayerThing->thingIdx,
                            0,
                            sourceType,
                            0,
                            arg0,
                            arg1,
                            arg2,
                            arg3,
                            playerinfo->net_id);
                }
            }
        }
    }
    else
    {
        sithDSSCog_SendSendTrigger(
            0,
            SITH_MESSAGE_TRIGGER,
            SENDERTYPE_THING,
            sithPlayer_pLocalPlayerThing->thingIdx,
            0,
            sourceType,
            0,
            arg0,
            arg1,
            arg2,
            arg3,
            -1);
        sithCog_SendMessageToAll(SITH_MESSAGE_TRIGGER, SENDERTYPE_THING, sithPlayer_pLocalPlayerThing->thingIdx, 0, sourceType, arg0, arg1, arg2, arg3);
    }
}

void sithCogFunction_ActivateWeapon(sithCog *ctx)
{
    int mode = sithCogExec_PopInt(ctx);
    float fireRate = sithCogExec_PopFlex(ctx);
    sithThing* weaponThing = sithCogExec_PopThing(ctx);

    if ( weaponThing && fireRate >= 0.0 && mode >= 0 && mode < 2 )
        sithWeapon_Activate(weaponThing, ctx, fireRate, mode);
}

void sithCogFunction_DeactivateWeapon(sithCog *ctx)
{
    int mode; // edi
    sithThing *weapon; // eax
    float a1a; // [esp+Ch] [ebp+4h]

    mode = sithCogExec_PopInt(ctx);
    weapon = sithCogExec_PopThing(ctx);
    if ( weapon && mode >= 0 && mode < 2 )
    {
        sithCogExec_PushFlex(ctx, sithWeapon_Deactivate(weapon, ctx, mode));
    }
    else
    {
        sithCogExec_PushFlex(ctx, -1.0);
    }
}

void sithCogFunction_SetFireWait(sithCog *ctx)
{
    float fireRate = sithCogExec_PopFlex(ctx);
    sithThing* weapon = sithCogExec_PopThing(ctx);

    if ( weapon && weapon == sithPlayer_pLocalPlayerThing && fireRate >= -1.0 )
        sithWeapon_SetFireWait(weapon, fireRate);
}

void sithCogFunction_SetMountWait(sithCog *ctx)
{
    float mountWait = sithCogExec_PopFlex(ctx);
    sithThing* weapon = sithCogExec_PopThing(ctx);

    if ( weapon && weapon == sithPlayer_pLocalPlayerThing && mountWait >= -1.0 )
        sithWeapon_SetMountWait(weapon, mountWait);
}

void sithCogFunction_SelectWeapon(sithCog *ctx)
{
    int binIdx = sithCogExec_PopInt(ctx);
    sithThing* player = sithCogExec_PopThing(ctx);

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
    sithThing* player = sithCogExec_PopThing(ctx);

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
    sithThing* player = sithCogExec_PopThing(ctx);

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
    sithThing* player = sithCogExec_PopThing(ctx);

    if (Main_bMotsCompat && binIdx < SITHBIN_ENERGY) {
        binIdx = sithInventory_SelectWeaponFollowing(binIdx);
    }

    if ( player )
    {
        if ( player->type == SITH_THING_PLAYER )
        {
            if (!Main_bMotsCompat)
                binIdx = sithInventory_SelectWeaponFollowing(binIdx);
            sithInventory_SetCurWeapon(player, binIdx);
        }
    }
}

void sithCogFunction_GetWeaponPriority(sithCog *ctx)
{
    int mode = sithCogExec_PopInt(ctx);
    int binIdx = sithCogExec_PopInt(ctx);
    sithThing* player = sithCogExec_PopThing(ctx);

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
    sithThing* player = sithCogExec_PopThing(ctx);

    if ( player && player->type == SITH_THING_PLAYER )
    {
        int binIdx = sithInventory_GetCurWeapon(player);
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

    v1 = sithCamera_GetState();
    sithCogExec_PushInt(ctx, v1);
}

void sithCogFunction_SetCameraStateFlags(sithCog *ctx)
{
    int v1; // eax

    v1 = sithCogExec_PopInt(ctx);
    sithCamera_SetState(v1);
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
    float a2; // ST04_4

    a2 = (double)(unsigned int)sithNet_multiplayer_timelimit * 0.000016666667;
    sithCogExec_PushFlex(a1, a2);
}

void sithCogFunction_SetTimeLimit(sithCog *ctx)
{
    float v1 = sithCogExec_PopFlex(ctx);
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
    float fireRate = sithCogExec_PopFlex(ctx);
    sithThing* player = sithCogExec_PopThing(ctx);

    if ( player && player == sithPlayer_pLocalPlayerThing && fireRate > 0.0 )
        sithWeapon_SetFireRate(player, fireRate);
}

void sithCogFunction_AutoSaveGame(sithCog *ctx)
{
    char tmp[128];

    stdString_snprintf(tmp, 128, "%s%s", "_JKAUTO_", sithWorld_pCurrentWorld->map_jkl_fname);
    stdFnames_ChangeExt(tmp, "jks");
    sithGamesave_Write(tmp, 1, 0, 0);
}

void sithCogFunction_SetCameraFocii(sithCog *ctx)
{
    sithThing* focusThing2 = sithCogExec_PopThing(ctx);
    sithThing* focusThing = sithCogExec_PopThing(ctx);
    int camIdx = sithCogExec_PopInt(ctx);

#ifdef QOL_IMPROVEMENTS
    // Droidworks tmp
    if (camIdx == 7)
        camIdx = 0;
#endif

    if ( camIdx > -1 && camIdx < 7 ) // TODO macro this 7?
    {
        if ( focusThing )
            sithCamera_SetCameraFocus(&sithCamera_cameras[camIdx], focusThing, focusThing2);
    }
}

// MOTS added
void sithCogFunction_Pow(sithCog *ctx)
{
    float fVar2;
    float fVar3;
    
    fVar2 = sithCogExec_PopFlex(ctx);
    fVar3 = sithCogExec_PopFlex(ctx);
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
    float angle;
    float outSin;
    float outCos;
    
    angle = sithCogExec_PopFlex(ctx);
    stdMath_SinCos(angle,&outSin,&outCos);
    sithCogExec_PushFlex(ctx,outSin);
}

// MOTS added
void sithCogFunction_Cos(sithCog *ctx)
{
    float angle;
    float outSin;
    float outCos;
    
    angle = sithCogExec_PopFlex(ctx);
    stdMath_SinCos(angle,&outSin,&outCos);
    sithCogExec_PushFlex(ctx,outCos);
}

// MOTS added
void sithCogFunction_Tan(sithCog *ctx)
{
    float fVar1;
    
    fVar1 = sithCogExec_PopFlex(ctx);
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
    float arg2 = sithCogExec_PopFlex(ctx);
    float arg1 = sithCogExec_PopFlex(ctx);
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
    local_1c.x = (float)(uint)local_10.wYear;
    local_1c.y = (float)(uint)local_10.wMonth;
    local_1c.z = (float)(local_10._6_4_ & 0xffff);
    */

    if (tm) {
        out.x = (float)(tm->tm_year + 1900); // year
        out.y = (float)(tm->tm_mon + 1); // month
        out.z = (float)(tm->tm_mday); // day
    }
    else {
        rdVector_Zero3(&out);
    }

    sithCogExec_PushVector3(ctx, &out);
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
    out.x = (float)(uint)local_10.wHour;
    out.y = (float)(uint)local_10.wMinute;
    out.z = (float)(uint)local_10.wSecond;
    */

    if (tm) {
        out.x = (float)(tm->tm_hour);
        out.y = (float)(tm->tm_min);
        out.z = (float)(tm->tm_sec);
    }
    else {
        rdVector_Zero3(&out);
    }
    

    sithCogExec_PushVector3(ctx, &out);
}

// MOTS added
void sithCogFunction_SendMessageExRadius(sithCog *ctx)
{
    float fVar1;
    float fVar2;
    float fVar3;
    float param0;
    float param1;
    int message;
    uint32_t uVar4;
    int iVar5;
    sithThing *sender;
    float fVar6;
    int local_28;
    rdVector3 local_1c;
    float local_10;
    float local_c;
    float local_8;
    float local_4;

    local_4 = sithCogExec_PopFlex(ctx);
    local_8 = sithCogExec_PopFlex(ctx);
    local_c = sithCogExec_PopFlex(ctx);
    local_10 = sithCogExec_PopFlex(ctx);
    message = sithCogExec_PopInt(ctx);
    uVar4 = sithCogExec_PopInt(ctx);
    fVar6 = sithCogExec_PopFlex(ctx);
    iVar5 = sithCogExec_PopVector3(ctx,&local_1c);
    param1 = local_c;
    param0 = local_10;
    if ((((iVar5 != 0) && (-1 < message)) && (message < SITH_MESSAGE_ENTERBUBBLE)) 
        && (local_28 = sithWorld_pCurrentWorld->numThings, -1 < local_28)) 
    {
        int iVar5_idx = local_28;
        local_28 = local_28 + 1;
        do 
        {
            sender = &sithWorld_pCurrentWorld->things[iVar5_idx];
            if (((((uVar4 & 1 << (sender->type & 0x1f)) != 0) 
                && ((sender->thingflags & 0x80202) == 0)) 
                && ((sender->type != 10 || ((uVar4 & 0x400) != 0)))) 
                && (fVar3 = (sender->position).x - local_1c.x, fVar1 = (sender->position).y - local_1c.y,
                    fVar2 = (sender->position).z - local_1c.z,
                    fVar1 = stdMath_Sqrt(fVar2 * fVar2 + fVar1 * fVar1 + fVar3 * fVar3),
                    fVar1 <= fVar6))
            {
                sithCog_SendMessageFromThingEx(sender, NULL, message, param0, param1, local_8, local_4);
            }
            iVar5_idx--;
            local_28--;
        } while (local_28 != 0);
    }
}



void sithCogFunction_Startup(void* ctx)
{
    sithCogScript_RegisterVerb(ctx, sithCogFunction_Sleep, "sleep");
    if (Main_bMotsCompat) {
        sithCogScript_RegisterVerb(ctx, sithCogFunction_Pow, "pow"); // MOTS
        sithCogScript_RegisterVerb(ctx, sithCogFunction_Wakeup, "wakeup"); // MOTS
    }
    sithCogScript_RegisterVerb(ctx, sithCogFunction_Rand, "rand");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_RandVec, "randvec");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetSenderRef, "getsenderref");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetSenderType, "getsendertype");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetSenderId, "getsenderid");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetSourceType, "getsourcetype");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetSourceRef, "getsourceref");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetThingCount, "getthingcount");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetGravity, "getgravity");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_SetGravity, "setgravity");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetLevelTime, "getleveltime");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetGametime, "getgametime");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetFlexGameTime, "getflexgametime");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetThingTemplateCount, "getthingtemplatecount");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_SetPulse, "setpulse");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_SetTimer, "settimer");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_SetTimerEx, "settimerex");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_KillTimerEx, "killtimerex");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_Reset, "reset");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_MaterialAnim, "materialanim");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_StopAnim, "stopanim");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_StopSurfaceAnim, "stopsurfaceanim");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetSurfaceAnim, "getsurfaceanim");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_SurfaceAnim, "surfaceanim");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetKeyLen, "getkeylen");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_LoadTemplate, "loadtemplate");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_LoadKeyframe, "loadkeyframe");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_LoadModel, "loadmodel");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_Print, "print");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_PrintInt, "printint");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_PrintFlex, "printflex");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_PrintVector, "printvector");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_VectorAdd, "vectoradd");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_VectorSub, "vectorsub");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_VectorDot, "vectordot");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_VectorCross, "vectorcross");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_VectorSet, "vectorset");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_VectorLen, "vectorlen");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_VectorScale, "vectorscale");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_VectorDist, "vectordist");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_VectorX, "vectorx");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_VectorY, "vectory");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_VectorZ, "vectorz");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_VectorNorm, "vectornorm");
    if (Main_bMotsCompat) {
        sithCogScript_RegisterVerb(ctx,sithCogFunction_VectorEqual,"vectorequal"); // MOTS
    }
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetSithMode, "getsithmode");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetDifficulty, "getdifficulty");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_SetSubmodeFlags, "setsubmodeflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetSubmodeFlags, "getsubmodeflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_ClearSubmodeFlags, "clearsubmodeflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_SetDebugModeFlags, "setdebugmodeflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetDebugModeFlags, "getdebugmodeflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_ClearDebugModeFlags, "cleardebugmodeflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_BitSet, "bitset");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_BitTest, "bittest");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_BitClear, "bitclear");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_FireProjectile, "fireprojectile");
    if (Main_bMotsCompat) {
        sithCogScript_RegisterVerb(ctx,sithCogFunction_FireProjectileData,"fireprojectiledata"); // MOTS
        sithCogScript_RegisterVerb(ctx,sithCogFunction_FireProjectileLocal,"fireprojectilelocal"); // MOTS
    }
    sithCogScript_RegisterVerb(ctx, sithCogFunction_ActivateWeapon, "activateweapon");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_DeactivateWeapon, "deactivateweapon");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_SetMountWait, "setmountwait");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_SetFireWait, "setfirewait");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_SelectWeapon, "selectweapon");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_AssignWeapon, "assignweapon");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_AutoSelectWeapon, "autoselectweapon");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetWeaponPriority, "getweaponpriority");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_SetCurWeapon, "setcurweapon");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetCurWeapon, "getcurweapon");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetCurWeaponMode, "getcurweaponmode");
    if (Main_bMotsCompat) {
        sithCogScript_RegisterVerb(ctx,sithCogFunction_GetWeaponBin,"getweaponbin"); // MOTS
    }
    sithCogScript_RegisterVerb(ctx, sithCogFunction_ChangeFireRate, "changefirerate");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_SendMessage, "sendmessage");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_SendMessageEx, "sendmessageex");
    if (Main_bMotsCompat) {
        sithCogScript_RegisterVerb(ctx,sithCogFunction_SendMessageExRadius,"sendmessageexradius"); // MOTS
    }
    sithCogScript_RegisterVerb(ctx, sithCogFunction_ReturnEx, "returnex");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetParam, "getparam");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_SetParam, "setparam");
    if (Main_bMotsCompat) {
        sithCogScript_RegisterVerb(ctx,sithCogFunction_WorldFlash,"worldflash"); // MOTS
    }
    sithCogScript_RegisterVerb(ctx, sithCogFunction_EnableIRMode, "enableirmode");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_DisableIRMode, "disableirmode");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_SetInvFlags, "setinvflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_SetMapModeFlags, "setmapmodeflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetMapModeFlags, "getmapmodeflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_ClearMapModeFlags, "clearmapmodeflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_NewColorEffect, "newcoloreffect");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_FreeColorEffect, "freecoloreffect");
    if (Main_bDwCompat) {
        sithCogScript_RegisterVerb(ctx, sithCogFunction_ModifyColorEffect, "modifycoloreffect");
    }
    else {
        sithCogScript_RegisterVerb(ctx, sithCogFunction_FreeColorEffect, "modifycoloreffect"); // oops? Droidworks fixes this
    }
    sithCogScript_RegisterVerb(ctx, sithCogFunction_AddDynamicTint, "adddynamictint");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_AddDynamicAdd, "adddynamicadd");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetMaterialCel, "getmaterialcel");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_SetMaterialCel, "setmaterialcel");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_SetCameraFocus, "setcamerafocus");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetPrimaryFocus, "getprimaryfocus");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetSecondaryFocus, "getsecondaryfocus");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_SetCurrentCamera, "setcurrentcamera");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetCurrentCamera, "getcurrentcamera");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_CycleCamera, "cyclecamera");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_SetPovShake, "setpovshake");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_SetCameraStateFlags, "setcamerastateflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetCameraStateFlags, "getcamerastateflags");
    if (Main_bMotsCompat) {
        sithCogScript_RegisterVerb(ctx,sithCogFunction_SetCameraZoom,"setcamerazoom"); // MOTS
    }
    sithCogScript_RegisterVerb(ctx, sithCogFunction_HeapNew, "heapnew");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_HeapSet, "heapset");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_HeapGet, "heapget");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_HeapFree, "heapfree");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetSelfCog, "getselfcog");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetMasterCog, "getmastercog");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_SetMasterCog, "setmastercog");
    if (Main_bMotsCompat) {
        sithCogScript_RegisterVerb(ctx,sithCogFunction_GetActionCog,"getactioncog"); // MOTS
        sithCogScript_RegisterVerb(ctx,sithCogFunction_SetActionCog,"setactioncog"); // MOTS
    }

    // Droidworks removes start
    sithCogScript_RegisterVerb(ctx, sithCogFunction_SetMultiModeFlags, "setmultimodeflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetMultiModeFlags, "getmultimodeflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_ClearMultiModeFlags, "clearmultimodeflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_IsMulti, "ismulti");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_IsServer, "isserver");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_SetTeamScore, "setteamscore");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetTeamScore, "getteamscore");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_SetTimeLimit, "settimelimit");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetTimeLimit, "gettimelimit");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_SetScoreLimit, "setscorelimit");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_GetScoreLimit, "getscorelimit");
    // Droidworks removes end

    sithCogScript_RegisterVerb(ctx, sithCogFunction_SendTrigger, "sendtrigger");
    sithCogScript_RegisterVerb(ctx, sithCogFunction_AutoSaveGame, "autosavegame");

    if (Main_bMotsCompat) {
        sithCogScript_RegisterVerb(ctx,sithCogFunction_Sin,"sin"); // MOTS
        sithCogScript_RegisterVerb(ctx,sithCogFunction_Cos,"cos"); // MOTS
        sithCogScript_RegisterVerb(ctx,sithCogFunction_Tan,"tan"); // MOTS
        sithCogScript_RegisterVerb(ctx,sithCogFunction_GetCogFlags,"getcogflags"); // MOTS
        sithCogScript_RegisterVerb(ctx,sithCogFunction_SetCogFlags,"setcogflags"); // MOTS
        sithCogScript_RegisterVerb(ctx,sithCogFunction_ClearCogFlags,"clearcogflags"); // MOTS
        sithCogScript_RegisterVerb(ctx,sithCogFunction_DebugBreak,"debugbreak"); // MOTS
        sithCogScript_RegisterVerb(ctx,sithCogFunction_GetSysDate,"getsysdate"); // MOTS
        sithCogScript_RegisterVerb(ctx,sithCogFunction_GetSysTime,"getsystime"); // MOTS
    }
    
    // Droidworks
    if (Main_bDwCompat) {
        sithCogScript_RegisterVerb(ctx, sithCogFunction_SetCameraFocii, "setcamerafocii");
    }
}
