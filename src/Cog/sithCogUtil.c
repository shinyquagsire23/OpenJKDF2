#include "sithCogUtil.h"

#include "types.h"
#include "sithCog.h"
#include "sithCogVm.h"
#include "jk.h"

#include "Win95/DebugConsole.h"
#include "Engine/sithTime.h"
#include "stdPlatform.h"
#include "General/stdString.h"
#include "Engine/sithSurface.h"
#include "World/sithSector.h"
#include "World/sithTrackThing.h"
#include "Engine/sithTemplate.h"
#include "Engine/sithKeyFrame.h"
#include "Engine/rdKeyframe.h"
#include "Engine/sithModel.h"
#include "Engine/sithRender.h"
#include "Engine/sithCamera.h"
#include "Engine/sithSound.h"
#include "Engine/sithNet.h"
#include "Engine/sithSave.h"
#include "Engine/sithTimer.h"
#include "World/sithPlayer.h"
#include "World/sithThingPlayer.h"
#include "World/sithWorld.h"
#include "World/sithWeapon.h"
#include "World/jkPlayer.h"
#include "Main/jkGame.h"
#include "General/stdFnames.h"
#include "General/stdPalEffects.h"

void sithCogUtil_ReturnBool(int a1, sithCog *a2);

void sithCogUtil_GetSenderId(sithCog* ctx)
{
    sithCogVm_PushInt(ctx, ctx->senderId);
}

void sithCogUtil_GetSenderRef(sithCog *ctx)
{
    sithCogVm_PushInt(ctx, ctx->senderRef);
}

void sithCogUtil_GetSenderType(sithCog *ctx)
{
    sithCogVm_PushInt(ctx, ctx->senderType);
}

void sithCogUtil_GetSourceRef(sithCog *ctx)
{
    sithCogVm_PushInt(ctx, ctx->sourceRef);
}

void sithCogUtil_GetSourceType(sithCog *ctx)
{
    sithCogVm_PushInt(ctx, ctx->sourceType);
}

void sithCogUtil_Rand(sithCog *ctx)
{
    sithCogVm_PushFlex(ctx, _frand());
}

void sithCogUtil_RandVec(sithCog *ctx)
{
    rdVector3 rvec;

    rvec.x = _frand();
    rvec.y = _frand();
    rvec.z = _frand();
    sithCogVm_PushVector3(ctx, &rvec);
}

void sithCogUtil_Sleep(sithCog *ctx)
{
    sithCog *ctx_;
    double fSecs;
    float fSecs_;

    ctx_ = ctx;
    fSecs = sithCogVm_PopFlex(ctx);
    fSecs_ = fSecs;
    if ( fSecs <= 0.0 )
        fSecs_ = 0.1;
    
    // TODO this is probably an inlined func?
    if ( ctx_->flags & COGFLAGS_TRACE )
    {
        _sprintf(std_genBuffer, "Cog %s: Sleeping for %f seconds.\n", ctx_->cogscript_fpath, fSecs_);
        DebugConsole_Print(std_genBuffer);
    }
    ctx_->script_running = 2;
    ctx_->wakeTimeMs = sithTime_curMs + (int)(fSecs_ * 1000.0);
}

void sithCogUtil_Print(sithCog *ctx)
{
    char *str;

    str = sithCogVm_PopString(ctx);
    if (str)
        DebugConsole_Print(str);
}

void sithCogUtil_PrintInt(sithCog *ctx)
{
    char tmp[32];

    stdString_snprintf(tmp, 32, "%d", sithCogVm_PopInt(ctx));
    DebugConsole_Print(tmp);
}

void sithCogUtil_PrintVector(sithCog *ctx)
{
    rdVector3 popVec;
    char tmp[32];

    if (sithCogVm_PopVector3(ctx, &popVec))
        stdString_snprintf(tmp, 32, "<%f %f %f>", popVec.x, popVec.y, popVec.z);
    else
        stdString_snprintf(tmp, 32, "Bad vector");

    DebugConsole_Print(tmp);
}

void sithCogUtil_PrintFlex(sithCog *ctx)
{
    char tmp[32];

    stdString_snprintf(tmp, 32, "%f", sithCogVm_PopFlex(ctx));
    DebugConsole_Print(tmp);
}

void sithCogUtil_SurfaceAnim(sithCog *ctx)
{
    sithCog *ctx_;
    int popInt; // edi
    void *surface; // ecx
    rdSurface *v4; // eax
    float popFlex; // [esp+Ch] [ebp+4h]

    // TODO: is this inlined?
    ctx_ = ctx;
    popInt = sithCogVm_PopInt(ctx);
    popFlex = sithCogVm_PopFlex(ctx);
    surface = sithCogVm_PopSurface(ctx_); // TODO
    if ( !surface )
    {
        sithCogVm_PushInt(ctx_, -1);
        return;
    }
    
    if ( popFlex <= 0.0 )
        popFlex = 15.0;

    v4 = sithSurface_SurfaceAnim(surface, popFlex, popInt);
    if ( v4 )
        sithCogVm_PushInt(ctx_, v4->index);
    else
        sithCogVm_PushInt(ctx_, -1);
}

void sithCogUtil_MaterialAnim(sithCog *ctx)
{
    sithCog *ctx_; // esi
    int popInt; // edi
    void *material; // ecx
    rdSurface *v4; // eax
    float popFlex; // [esp+Ch] [ebp+4h]

    // TODO is this inlined
    ctx_ = ctx;
    popInt = sithCogVm_PopInt(ctx);
    popFlex = sithCogVm_PopFlex(ctx);
    material = sithCogVm_PopMaterial(ctx_); // TODO rdMaterial*
    if ( !material )
    {
        sithCogVm_PushInt(ctx_, -1);
        return;
    }
    
    if ( popFlex <= 0.0 )
        popFlex = 15.0;
    v4 = sithSurface_MaterialAnim(material, popFlex, popInt);
    if ( v4 )
        sithCogVm_PushInt(ctx_, v4->index);
    else
        sithCogVm_PushInt(ctx_, -1);
}

void sithCogUtil_StopThing(sithCog *ctx) // unused
{
    sithThing *v1;

    v1 = sithCogVm_PopThing(ctx);
    if ( v1 )
    {
        if ( v1->moveType == SITH_MT_PHYSICS )
        {
            sithSector_StopPhysicsThing(v1);
        }
        else if ( v1->moveType == SITH_MT_PATH )
        {
            sithTrackThing_Stop(v1);
        }
    }
}

void sithCogUtil_StopAnim(sithCog *ctx)
{
    int v1; // eax
    rdSurface *v2; // eax

    v1 = sithCogVm_PopInt(ctx);
    v2 = sithSurface_GetByIdx(v1);
    if ( v2 )
    {
        sithSurface_StopAnim(v2);
        if ( sithCogVm_multiplayerFlags )
            sithSector_cogMsg_SendStopAnim((sithSurface *)v2, -1, 255); // TODO ??
    }
}

void sithCogUtil_StopSurfaceAnim(sithCog *ctx)
{
    sithSurface *v1; // eax
    rdSurface *v2; // eax

    v1 = sithCogVm_PopSurface(ctx);
    if ( v1 )
    {
        v2 = sithSurface_GetRdSurface(v1);
        if ( v2 )
        {
            sithSurface_StopAnim(v2);
            if ( sithCogVm_multiplayerFlags )
                sithSector_cogMsg_SendStopAnim((sithSurface *)v2, -1, 255); // TODO ??
        }
    }
}

void sithCogUtil_GetSurfaceAnim(sithCog *ctx)
{
    sithSurface *v1; // eax
    int v2; // eax

    v1 = sithCogVm_PopSurface(ctx);
    if ( v1 )
    {
        v2 = sithSurface_GetSurfaceAnim(v1);
        sithCogVm_PushInt(ctx, v2);
    }
    else
    {
        sithCogVm_PushInt(ctx, -1);
    }
}

void sithCogUtil_LoadTemplate(sithCog *ctx)
{
    char *v1; // eax
    sithThing *v2; // eax

    v1 = sithCogVm_PopString(ctx);
    if ( v1 && (v2 = sithTemplate_GetEntryByName(v1)) != 0 )
        sithCogVm_PushInt(ctx, v2->thingIdx);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogUtil_LoadKeyframe(sithCog *a1)
{
    char *v1; // eax
    rdKeyframe *v2; // eax

    v1 = sithCogVm_PopString(a1);
    if ( v1 && (v2 = sithKeyFrame_LoadEntry(v1)) != 0 )
        sithCogVm_PushInt(a1, v2->id);
    else
        sithCogVm_PushInt(a1, -1);
}

void sithCogUtil_LoadModel(sithCog *ctx)
{
    char *v1; // eax
    rdModel3 *v2; // eax

    v1 = sithCogVm_PopString(ctx);
    if ( v1 && (v2 = sithModel_LoadEntry(v1, 1)) != 0 )
        sithCogVm_PushInt(ctx, v2->id);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogUtil_SetPulse(sithCog *ctx)
{
    float popFlex;

    popFlex = sithCogVm_PopFlex(ctx);
    if ( popFlex <= 0.0 )
    {
        if ( ctx->flags & 1 )
        {
            _sprintf(std_genBuffer, "Cog %s: Pulse disabled.\n", ctx->cogscript_fpath);
            DebugConsole_Print(std_genBuffer);
        }
        ctx->flags &= ~4;
    }
    else
    {
        if ( ctx->flags & 1 )
        {
            _sprintf(std_genBuffer, "Cog %s: Pulse set to %f seconds.\n", ctx->cogscript_fpath, popFlex);
            DebugConsole_Print(std_genBuffer);
        }
        ctx->flags |= 4;
        ctx->pulsePeriodMs = (int)(popFlex * 1000.0);
        ctx->nextPulseMs = (int)(popFlex * 1000.0) + sithTime_curMs;
    }
}

void sithCogUtil_SetTimer(sithCog *ctx)
{
    float popFlex = sithCogVm_PopFlex(ctx);
    if ( popFlex <= 0.0 )
    {
        if ( ctx->flags & 1 )
        {
            _sprintf(std_genBuffer, "Cog %s: Timer cancelled.\n", ctx->cogscript_fpath);
            DebugConsole_Print(std_genBuffer);
        }
        ctx->flags &= ~8;
    }
    else
    {
        if ( ctx->flags & 1 )
        {
            _sprintf(std_genBuffer, "Cog %s: Timer set for %f seconds.\n", ctx->cogscript_fpath, popFlex);
            DebugConsole_Print(std_genBuffer);
        }
        ctx->flags |= 8u;
        ctx->field_20 = sithTime_curMs + (int)(popFlex * 1000.0);
    }
}

void sithCogUtil_SetTimerEx(sithCog *ctx)
{
    sithTimerInfo timerInfo; // [esp+4h] [ebp-14h]
    int timerMs; // [esp+14h] [ebp-4h]
    float a1a; // [esp+20h] [ebp+8h]

    timerInfo.field_14 = sithCogVm_PopFlex(ctx);
    timerInfo.field_10 = sithCogVm_PopFlex(ctx);
    timerInfo.timerIdx = sithCogVm_PopInt(ctx);
    timerInfo.cogIdx = ctx->selfCog;
    a1a = sithCogVm_PopFlex(ctx) * 1000.0;
    timerMs = (signed int)a1a;
    if ( timerMs >= 0 )
        sithTimer_Set(4, &timerInfo, (signed int)a1a);
}

void sithCogUtil_KillTimerEx(sithCog *ctx)
{
    signed int v1; // ebx
    sithTimer *v2; // eax
    sithTimer *v3; // edi
    sithTimer *v4; // esi

    v1 = sithCogVm_PopInt(ctx);
    if ( v1 > 0 )
    {
        v2 = sithTimer_list;
        v3 = 0;
        if ( sithTimer_list )
        {
            do
            {
                v4 = v2->nextTimer;
                if ( v2->field_4 == 4 && v2->timerInfo.cogIdx == ctx->selfCog && v2->timerInfo.timerIdx == v1 )
                {
                    if ( v3 )
                        v3->nextTimer = v4;
                    else
                        sithTimer_list = v2->nextTimer;
                    sithTimer_Kill(v2);
                    v2 = v3;
                }
                v3 = v2;
                v2 = v4;
            }
            while ( v4 );
        }
    }
}

void sithCogUtil_Reset(sithCog *ctx)
{
    ctx->calldepth = 0;
}

void sithCogUtil_VectorSet(sithCog *ctx)
{
    rdVector3 out;

    out.z = sithCogVm_PopFlex(ctx);
    out.y = sithCogVm_PopFlex(ctx);
    out.x = sithCogVm_PopFlex(ctx);
    sithCogVm_PushVector3(ctx, &out);
}

void sithCogUtil_VectorAdd(sithCog *ctx)
{
    rdVector3 inA;
    rdVector3 inB;
    rdVector3 out;

    sithCogVm_PopVector3(ctx, &inA);
    sithCogVm_PopVector3(ctx, &inB);
    rdVector_Add3(&out, &inA, &inB);
    sithCogVm_PushVector3(ctx, &out);
}

void sithCogUtil_VectorSub(sithCog *ctx)
{
    rdVector3 inA;
    rdVector3 inB;
    rdVector3 out;

    sithCogVm_PopVector3(ctx, &inA);
    sithCogVm_PopVector3(ctx, &inB);
    rdVector_Sub3(&out, &inB, &inA);
    sithCogVm_PushVector3(ctx, &out);
}

void sithCogUtil_VectorDot(sithCog *ctx)
{
    rdVector3 inA;
    rdVector3 inB;

    sithCogVm_PopVector3(ctx, &inA);
    sithCogVm_PopVector3(ctx, &inB);
    sithCogVm_PushFlex(ctx, rdVector_Dot3(&inA, &inB));
}

void sithCogUtil_VectorCross(sithCog *ctx)
{
    rdVector3 inA;
    rdVector3 inB;
    rdVector3 out;

    sithCogVm_PopVector3(ctx, &inA);
    sithCogVm_PopVector3(ctx, &inB);
    rdVector_Cross3(&out, &inA, &inB);
    sithCogVm_PushVector3(ctx, &out);
}

void sithCogUtil_VectorLen(sithCog *ctx)
{
    rdVector3 in;

    sithCogVm_PopVector3(ctx, &in);
    sithCogVm_PushFlex(ctx, rdVector_Len3(&in));
}

void sithCogUtil_VectorScale(sithCog *ctx)
{
    rdVector3 inA;
    rdVector3 out;

    float scale = sithCogVm_PopFlex(ctx);
    sithCogVm_PopVector3(ctx, &inA);
    rdVector_Scale3(&out, &inA, scale);
    sithCogVm_PushVector3(ctx, &out);
}

void sithCogUtil_VectorDist(sithCog *ctx)
{
    rdVector3 inA;
    rdVector3 inB;
    rdVector3 tmp;

    sithCogVm_PopVector3(ctx, &inA);
    sithCogVm_PopVector3(ctx, &inB);
    rdVector_Sub3(&tmp, &inB, &inA);
    sithCogVm_PushFlex(ctx, rdVector_Len3(&tmp));
}

void sithCogUtil_SendMessage(sithCog *ctx)
{
    int msgId = sithCogVm_PopInt(ctx);
    sithCog* cog = sithCogVm_PopCog(ctx);

    if (cog && msgId >= 0 && msgId < COGMSG_ENUMPLAYERS)
        sithCog_SendMessage(cog, msgId, SENDERTYPE_COG, ctx->selfCog, ctx->sourceType, ctx->sourceRef, 0);
}

void sithCogUtil_SendMessageEx(struct sithCog *ctx)
{
    float param3 = sithCogVm_PopFlex(ctx);
    float param2 = sithCogVm_PopFlex(ctx);
    float param1 = sithCogVm_PopFlex(ctx);
    float param0 = sithCogVm_PopFlex(ctx);
    int msgId = sithCogVm_PopInt(ctx);
    sithCog* cog = sithCogVm_PopCog(ctx);

    if (cog && msgId >= 0 && msgId < COGMSG_ENUMPLAYERS)
    {
        float flexRet = sithCog_SendMessageEx(cog, msgId, SENDERTYPE_COG, ctx->selfCog, ctx->sourceType, ctx->sourceRef, 0, param0, param1, param2, param3);
        sithCogVm_PushFlex(ctx, flexRet);
    }
}

void sithCogUtil_GetKeyLen(sithCog *ctx)
{
    rdKeyframe* keyframe = sithCogVm_PopKeyframe(ctx);

    if (!keyframe || keyframe->fps == 0.0)
        sithCogVm_PushFlex(ctx, 0.0);

    sithCogVm_PushFlex(ctx, (double)keyframe->numFrames / keyframe->fps);
}

void sithCogUtil_GetSithMode(sithCog* ctx)
{
    sithCogVm_PushInt(ctx, g_sithMode);
}

void sithCogUtil_GetGametime(sithCog *ctx)
{
    sithCogVm_PushInt(ctx, sithTime_curMs);
}

void sithCogUtil_GetFlexGameTime(sithCog *ctx)
{
    sithCogVm_PushFlex(ctx, sithTime_curSeconds);
}

void sithCogUtil_GetDifficulty(sithCog *ctx)
{
    sithCogVm_PushInt(ctx, jkPlayer_setDiff);
}

void sithCogUtil_SetSubmodeFlags(sithCog *ctx)
{
    g_submodeFlags |= sithCogVm_PopInt(ctx);
}

void sithCogUtil_ClearSubmodeFlags(sithCog *ctx)
{
    g_submodeFlags &= ~sithCogVm_PopInt(ctx);
}

void sithCogUtil_GetSubmodeFlags(sithCog *ctx)
{
    sithCogVm_PushInt(ctx, g_submodeFlags);
}

void sithCogUtil_SetDebugModeFlags(sithCog *ctx)
{
    g_debugmodeFlags |= sithCogVm_PopInt(ctx);
}

void sithCogUtil_ClearDebugModeFlags(sithCog *ctx)
{
    g_debugmodeFlags &= ~sithCogVm_PopInt(ctx);
}

void sithCogUtil_GetDebugModeFlags(sithCog *ctx)
{
    sithCogVm_PushInt(ctx, g_debugmodeFlags);
}

void sithCogUtil_BitSet(sithCog *ctx)
{
    signed int a;
    signed int b;

    a = sithCogVm_PopInt(ctx);
    b = sithCogVm_PopInt(ctx);
    sithCogVm_PushInt(ctx, b | a);
}

void sithCogUtil_BitTest(sithCog *ctx)
{
    signed int a;
    signed int b;

    a = sithCogVm_PopInt(ctx);
    b = sithCogVm_PopInt(ctx);
    sithCogVm_PushInt(ctx, b & a);
}

void sithCogUtil_BitClear(sithCog *ctx)
{
    signed int a;
    signed int b;

    a = sithCogVm_PopInt(ctx);
    b = sithCogVm_PopInt(ctx);
    sithCogVm_PushInt(ctx, b & ~a);
}

void sithCogUtil_GetLevelTime(sithCog *ctx)
{
    sithCogVm_PushFlex(ctx, sithTime_curMs * 0.001);
}

void sithCogUtil_GetThingCount(sithCog *ctx)
{
    sithCogVm_PushInt(ctx, sithWorld_pCurWorld->numThingsLoaded);
}

void sithCogUtil_GetThingTemplateCount(sithCog *ctx)
{
    sithWorld *v1; // esi
    sithThing *v2; // eax
    int template_count; // edi

    v1 = sithWorld_pCurWorld;
    v2 = sithCogVm_PopTemplate(ctx);
    if ( v2 )
    {
        template_count = 0;
        for (int i = 0; i < v1->numThings; i++ )
        {
            sithThing* thing = &v1->things[i];
            if ( thing->type && thing->type != SITH_THING_CORPSE && thing->templateBase == v2 )
                ++template_count;
        }
        sithCogVm_PushInt(ctx, template_count);
    }
}

void sithCogUtil_GetGravity(sithCog *ctx)
{
    sithCogVm_PushFlex(ctx, sithWorld_pCurWorld->worldGravity);
}

void sithCogUtil_SetGravity(sithCog *ctx)
{
    sithWorld_pCurWorld->worldGravity = sithCogVm_PopFlex(ctx);
}

void sithCogUtil_ReturnEx(sithCog *ctx)
{
    ctx->returnEx = sithCogVm_PopFlex(ctx);
}

void sithCogUtil_GetParam(sithCog *ctx)
{
    int idx = sithCogVm_PopInt(ctx);
    if ( idx < 0 || idx >= 4 )
        sithCogVm_PushFlex(ctx, -9999.0);
    else
        sithCogVm_PushFlex(ctx, ctx->params[idx]);
}

void sithCogUtil_SetParam(sithCog *ctx)
{
    int idx;
    float val;

    val = sithCogVm_PopFlex(ctx);
    idx = sithCogVm_PopInt(ctx);
    if (idx >= 0 && idx < 4)
        ctx->params[idx] = val;
}

void sithCogUtil_VectorX(sithCog *ctx)
{
    rdVector3 popVec;

    sithCogVm_PopVector3(ctx, &popVec);
    sithCogVm_PushFlex(ctx, popVec.x);
}

void sithCogUtil_VectorY(sithCog *ctx)
{
    rdVector3 popVec;

    sithCogVm_PopVector3(ctx, &popVec);
    sithCogVm_PushFlex(ctx, popVec.y);
}

void sithCogUtil_VectorZ(sithCog *ctx)
{
    rdVector3 popVec;

    sithCogVm_PopVector3(ctx, &popVec);
    sithCogVm_PushFlex(ctx, popVec.z);
}

void sithCogUtil_VectorNorm(sithCog *ctx)
{
    rdVector3 popVec;
    rdVector3 out;

    sithCogVm_PopVector3(ctx, &popVec);
    rdVector_Normalize3(&out, &popVec);
    sithCogVm_PushVector3(ctx, &out);
}

void sithCogUtil_SetMaterialCel(sithCog *ctx)
{
    signed int cel; // esi
    rdMaterial *mat; // eax

    cel = sithCogVm_PopInt(ctx);
    mat = sithCogVm_PopMaterial(ctx);
    if ( mat && cel >= 0 && (unsigned int)cel < mat->num_texinfo )
        mat->celIdx = cel;
    sithCogVm_PushInt(ctx, -1);
}

void sithCogUtil_GetMaterialCel(sithCog *ctx)
{
    rdMaterial *mat; // eax

    mat = sithCogVm_PopMaterial(ctx);
    if ( mat )
        sithCogVm_PushInt(ctx, mat->celIdx);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogUtil_EnableIRMode(sithCog *ctx)
{
    float flex1 = sithCogVm_PopFlex(ctx);
    float flex2 = sithCogVm_PopFlex(ctx);
    sithRender_EnableIRMode(flex2, flex1);
}

void sithCogUtil_DisableIRMode()
{
    sithRender_DisableIRMode();
}

void sithCogUtil_SetInvFlags(sithCog *ctx)
{
    int flags;
    int binIdx;
    sithThing *player;

    flags = sithCogVm_PopInt(ctx);
    binIdx = sithCogVm_PopInt(ctx);
    player = sithCogVm_PopThing(ctx);
    if ( player && player->type == SITH_THING_PLAYER && player->actorParams.playerinfo && binIdx < SITHBIN_NUMBINS )
        sithInventory_SetFlags(player, binIdx, flags);
}

void sithCogUtil_SetMapModeFlags(sithCog *ctx)
{
    g_mapModeFlags |= sithCogVm_PopInt(ctx);
}

void sithCogUtil_GetMapModeFlags(sithCog *ctx)
{
    sithCogVm_PushInt(ctx, g_mapModeFlags);
}

void sithCogUtil_ClearMapModeFlags(sithCog *ctx)
{
    g_mapModeFlags &= ~sithCogVm_PopInt(ctx);
}

void sithCogUtil_SetCameraFocus(sithCog *ctx)
{
    sithThing *focusThing; // esi
    signed int camIdx; // eax

    focusThing = sithCogVm_PopThing(ctx);
    camIdx = sithCogVm_PopInt(ctx);

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

void sithCogUtil_GetPrimaryFocus(sithCog *ctx)
{
    signed int camIdx; // eax
    sithThing *v2; // eax

    camIdx = sithCogVm_PopInt(ctx);

#ifdef QOL_IMPROVEMENTS
    // Droidworks tmp
    if (camIdx == 7)
        camIdx = 0;
#endif

    if ( camIdx > -1 && camIdx < 7 && (v2 = sithCamera_GetPrimaryFocus(&sithCamera_cameras[camIdx])) != 0 )
        sithCogVm_PushInt(ctx, v2->thingIdx);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogUtil_GetSecondaryFocus(sithCog *ctx)
{
    signed int camIdx; // eax
    sithThing *v2; // eax

    camIdx = sithCogVm_PopInt(ctx);
    
#ifdef QOL_IMPROVEMENTS
    // Droidworks tmp
    if (camIdx == 7)
        camIdx = 0;
#endif
    
    if ( camIdx > -1 && camIdx < 7 && (v2 = sithCamera_GetSecondaryFocus(&sithCamera_cameras[camIdx])) != 0 )
        sithCogVm_PushInt(ctx, v2->thingIdx);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogUtil_SetCurrentCamera(sithCog *ctx)
{
    signed int camIdx; // eax

    camIdx = sithCogVm_PopInt(ctx);

#ifdef QOL_IMPROVEMENTS
    // Droidworks tmp
    if (camIdx == 7)
    {
        camIdx = 0;
        sithCamera_SetCameraFocus(&sithCamera_cameras[camIdx], g_localPlayerThing, 0);
    }
#endif

    //printf("%u -> %u\n", sithCamera_currentCamera - sithCamera_cameras, camIdx);
    
    if ( camIdx > -1 && camIdx < 7 )
        sithCamera_SetCurrentCamera(&sithCamera_cameras[camIdx]);
}

void sithCogUtil_GetCurrentCamera(sithCog *ctx)
{
    int camIdx; // edx

    if ( sithCamera_currentCamera && (camIdx = sithCamera_currentCamera - sithCamera_cameras, camIdx < 7) )
        sithCogVm_PushInt(ctx, camIdx);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogUtil_CycleCamera()
{
    sithCamera_CycleCamera();
}

void sithCogUtil_SetPovShake(sithCog *ctx)
{
    float v2; // [esp+4h] [ebp-1Ch]
    rdVector3 v3; // [esp+8h] [ebp-18h]
    rdVector3 v4; // [esp+14h] [ebp-Ch]
    float a1a; // [esp+24h] [ebp+4h]

    a1a = sithCogVm_PopFlex(ctx);
    v2 = sithCogVm_PopFlex(ctx);
    if ( sithCogVm_PopVector3(ctx, &v3) )
    {
        if ( sithCogVm_PopVector3(ctx, &v4) )
            sithCamera_SetPovShake(&v4, &v3, v2, a1a);
    }
}

void sithCogUtil_HeapNew(sithCog *ctx)
{
    int numHeapVars; // ebp
    sithCogStackvar *oldHeap; // eax
    sithCogStackvar *newHeap; // edi

    numHeapVars = sithCogVm_PopInt(ctx);
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

void sithCogUtil_HeapSet(sithCog *ctx)
{
    int val;
    int idx;
    sithCogStackvar stackVar;

    val = sithCogVm_PopValue(ctx, &stackVar);
    idx = sithCogVm_PopInt(ctx);
    if ( val && idx >= 0 && idx < ctx->numHeapVars )
        ctx->heap[idx] = stackVar;
}

void sithCogUtil_HeapGet(sithCog *ctx)
{
    int idx;
    sithCogStackvar *heapVar;
    sithCogStackvar tmp;

    idx = sithCogVm_PopInt(ctx);
    if (idx < 0 || idx >= ctx->numHeapVars)
    {
        sithCogVm_PushInt(ctx, 0);
    }
    else
    {
        heapVar = &ctx->heap[idx];
        tmp.type = heapVar->type;
        tmp.data[0] = heapVar->data[0];
        tmp.data[1] = heapVar->data[1];
        tmp.data[2] = heapVar->data[2];
        sithCogVm_PushVar(ctx, &tmp);
    }
}

void sithCogUtil_HeapFree(sithCog *ctx)
{
    if ( ctx->heap )
    {
        pSithHS->free(ctx->heap);
        ctx->numHeapVars = 0;
    }
}

void sithCogUtil_GetSelfCog(sithCog *ctx)
{
    sithCogVm_PushInt(ctx, ctx->selfCog);
}

void sithCogUtil_GetMasterCog(sithCog *ctx)
{
    if ( sithCog_masterCog )
        sithCogVm_PushInt(ctx, sithCog_masterCog->selfCog);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogUtil_SetMasterCog(sithCog *ctx)
{
    sithCog_masterCog = sithCogVm_PopCog(ctx);
}

void sithCogUtil_NewColorEffect(sithCog *ctx)
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
    v11 = sithCogVm_PopFlex(ctx);
    v2 = sithCogVm_PopInt(ctx);
    v3 = sithCogVm_PopInt(ctx);
    v10 = sithCogVm_PopInt(ctx);
    a4 = sithCogVm_PopFlex(ctx);
    v8 = sithCogVm_PopFlex(ctx);
    v9 = sithCogVm_PopFlex(ctx);
    a1a = sithCogVm_PopInt(ctx);
    a3 = sithCogVm_PopInt(v1);
    a2 = sithCogVm_PopInt(v1);
    idx = stdPalEffects_NewRequest(1);
    if ( idx == -1 )
    {
        sithCogVm_PushInt(v1, -1);
    }
    else
    {
        stdPalEffects_SetFilter(idx, a2, a3, a1a);
        stdPalEffects_SetTint(idx, v9, v8, a4);
        stdPalEffects_SetAdd(idx, v10, v3, v2);
        stdPalEffects_SetFade(idx, v11);
        sithCogVm_PushInt(v1, idx);
    }
}

void sithCogUtil_ModifyColorEffect(sithCog *ctx)
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
    v2 = sithCogVm_PopFlex(ctx);
    v3 = sithCogVm_PopInt(ctx);
    v4 = sithCogVm_PopInt(ctx);
    v5 = sithCogVm_PopInt(ctx);
    a4 = sithCogVm_PopFlex(ctx);
    v7 = sithCogVm_PopFlex(ctx);
    v8 = sithCogVm_PopFlex(ctx);
    a1a = sithCogVm_PopInt(ctx);
    a3 = sithCogVm_PopInt(v1);
    a2 = sithCogVm_PopInt(v1);
    v11 = sithCogVm_PopInt(v1);
    stdPalEffects_SetFilter(v11, a2, a3, a1a);
    stdPalEffects_SetTint(v11, v8, v7, a4);
    stdPalEffects_SetAdd(v11, v5, v4, v3);
    stdPalEffects_SetFade(v11, v2);
}

void sithCogUtil_FreeColorEffect(sithCog *ctx)
{
    uint32_t v1; // eax

    v1 = sithCogVm_PopInt(ctx);
    stdPalEffects_FreeRequest(v1);
}

void sithCogUtil_AddDynamicTint(sithCog *ctx)
{
    sithCog *v1; // esi
    sithThing *player; // eax
    float fG; // [esp+4h] [ebp-8h]
    float fR; // [esp+8h] [ebp-4h]
    float fB; // [esp+10h] [ebp+4h]

    v1 = ctx;
    fB = sithCogVm_PopFlex(ctx);
    fG = sithCogVm_PopFlex(v1);
    fR = sithCogVm_PopFlex(v1);
    player = sithCogVm_PopThing(v1);
    if ( player && player->type == SITH_THING_PLAYER && player == g_localPlayerThing )
        sithPlayer_AddDynamicTint(fR, fG, fB);
}

void sithCogUtil_AddDynamicAdd(sithCog *ctx)
{
    int b; // edi
    int g; // ebx
    int r; // ebp
    sithThing *playerThing; // eax

    b = sithCogVm_PopInt(ctx);
    g = sithCogVm_PopInt(ctx);
    r = sithCogVm_PopInt(ctx);
    playerThing = sithCogVm_PopThing(ctx);
    if ( playerThing && playerThing->type == SITH_THING_PLAYER && playerThing == g_localPlayerThing )
        sithPlayer_AddDyamicAdd(r, g, b);
}

// modifycoloreffect, freecoloreffect, adddynamictint, adddynamicadd

void sithCogUtil_FireProjectile(sithCog *ctx)
{
    int scaleFlags; // di
    int mode; // ebx
    sithSound *fireSound; // ebp
    sithThing *sender; // eax
    sithThing *spawnedProjectile; // eax
    float autoaimFov; // [esp+10h] [ebp-24h]
    float scale; // [esp+14h] [ebp-20h]
    sithThing *projectileTemplate; // [esp+18h] [ebp-1Ch]
    rdVector3 aimError; // [esp+1Ch] [ebp-18h]
    rdVector3 fireOffset; // [esp+28h] [ebp-Ch]
    float autoaimMaxDist; // [esp+38h] [ebp+4h]

    autoaimMaxDist = sithCogVm_PopFlex(ctx);
    autoaimFov = sithCogVm_PopFlex(ctx);
    scaleFlags = sithCogVm_PopInt(ctx);
    scale = sithCogVm_PopFlex(ctx);
    sithCogVm_PopVector3(ctx, &aimError);
    sithCogVm_PopVector3(ctx, &fireOffset);
    mode = sithCogVm_PopInt(ctx);
    fireSound = sithCogVm_PopSound(ctx);
    projectileTemplate = sithCogVm_PopTemplate(ctx);
    sender = sithCogVm_PopThing(ctx);
    if ( sender
      && (spawnedProjectile = sithWeapon_FireProjectile(
                                  sender,
                                  projectileTemplate,
                                  fireSound,
                                  mode,
                                  &fireOffset,
                                  &aimError,
                                  scale,
                                  scaleFlags,
                                  autoaimFov,
                                  autoaimMaxDist)) != 0 )
    {
        sithCogVm_PushInt(ctx, spawnedProjectile->thingIdx);
    }
    else
    {
        sithCogVm_PushInt(ctx, -1);
    }
}

void sithCogUtil_SendTrigger(sithCog *ctx)
{
    int sourceType; // edi
    sithThing *sourceThing; // eax
    sithPlayerInfo *playerinfo; // ecx
    float arg3; // [esp+10h] [ebp-Ch]
    float arg2; // [esp+14h] [ebp-8h]
    float arg1; // [esp+18h] [ebp-4h]
    float arg0; // [esp+20h] [ebp+4h]

    arg3 = sithCogVm_PopFlex(ctx);
    arg2 = sithCogVm_PopFlex(ctx);
    arg1 = sithCogVm_PopFlex(ctx);
    arg0 = sithCogVm_PopFlex(ctx);
    sourceType = sithCogVm_PopInt(ctx);
    sourceThing = sithCogVm_PopThing(ctx);
    if ( sourceThing )
    {
        if ( sourceThing->type == SITH_THING_PLAYER )
        {
            playerinfo = sourceThing->actorParams.playerinfo;
            if ( playerinfo )
            {
                if ( playerinfo->flags & 1 )
                {
                    if ( sourceThing == g_localPlayerThing )
                        sithCog_SendMessageToAll(SITH_MESSAGE_TRIGGER, SENDERTYPE_THING, g_localPlayerThing->thingIdx, 0, sourceType, arg0, arg1, arg2, arg3);
                    else
                        sithThingPlayer_cogMsg_SendSendTrigger(
                            0,
                            SITH_MESSAGE_TRIGGER,
                            SENDERTYPE_THING,
                            g_localPlayerThing->thingIdx,
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
        sithThingPlayer_cogMsg_SendSendTrigger(
            0,
            SITH_MESSAGE_TRIGGER,
            SENDERTYPE_THING,
            g_localPlayerThing->thingIdx,
            0,
            sourceType,
            0,
            arg0,
            arg1,
            arg2,
            arg3,
            -1);
        sithCog_SendMessageToAll(SITH_MESSAGE_TRIGGER, SENDERTYPE_THING, g_localPlayerThing->thingIdx, 0, sourceType, arg0, arg1, arg2, arg3);
    }
}

void sithCogUtil_ActivateWeapon(sithCog *ctx)
{
    int mode = sithCogVm_PopInt(ctx);
    float fireRate = sithCogVm_PopFlex(ctx);
    sithThing* weaponThing = sithCogVm_PopThing(ctx);

    if ( weaponThing && fireRate >= 0.0 && mode >= 0 && mode < 2 )
        sithWeapon_Activate(weaponThing, ctx, fireRate, mode);
}

void sithCogUtil_DeactivateWeapon(sithCog *ctx)
{
    int mode; // edi
    sithThing *weapon; // eax
    float a1a; // [esp+Ch] [ebp+4h]

    mode = sithCogVm_PopInt(ctx);
    weapon = sithCogVm_PopThing(ctx);
    if ( weapon && mode >= 0 && mode < 2 )
    {
        sithCogVm_PushFlex(ctx, sithWeapon_Deactivate(weapon, ctx, mode));
    }
    else
    {
        sithCogVm_PushFlex(ctx, -1.0);
    }
}

void sithCogUtil_SetFireWait(sithCog *ctx)
{
    float fireRate = sithCogVm_PopFlex(ctx);
    sithThing* weapon = sithCogVm_PopThing(ctx);

    if ( weapon && weapon == g_localPlayerThing && fireRate >= -1.0 )
        sithWeapon_SetFireWait(weapon, fireRate);
}

void sithCogUtil_SetMountWait(sithCog *ctx)
{
    float mountWait = sithCogVm_PopFlex(ctx);
    sithThing* weapon = sithCogVm_PopThing(ctx);

    if ( weapon && weapon == g_localPlayerThing && mountWait >= -1.0 )
        sithWeapon_SetMountWait(weapon, mountWait);
}

void sithCogUtil_SelectWeapon(sithCog *ctx)
{
    int binIdx = sithCogVm_PopInt(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);

    if ( player )
    {
        if ( binIdx >= 0 )
            sithWeapon_SelectWeapon(player, binIdx, 0);
    }
}

void sithCogUtil_AssignWeapon(sithCog *ctx)
{
    int binIdx = sithCogVm_PopInt(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);

    if ( player )
    {
        if ( binIdx >= 1 )
            sithWeapon_SelectWeapon(player, binIdx, 1);
    }
}

void sithCogUtil_AutoSelectWeapon(sithCog *ctx)
{
    int weapIdx = sithCogVm_PopInt(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);

    if ( weapIdx >= 0 && weapIdx <= 2 && player )
    {
        sithCogVm_PushInt(ctx, sithWeapon_AutoSelect(player, weapIdx));
    }
    else
    {
        sithCogVm_PushInt(ctx, -1);
    }
}

void sithCogUtil_SetCurWeapon(sithCog *ctx)
{
    int v4; // eax

    int idx = sithCogVm_PopInt(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);
    if ( player )
    {
        if ( player->type == SITH_THING_PLAYER )
        {
            v4 = sithInventory_SelectWeaponFollowing(idx);
            sithInventory_SetCurWeapon(player, v4);
        }
    }
}

void sithCogUtil_GetWeaponPriority(sithCog *ctx)
{
    int mode = sithCogVm_PopInt(ctx);
    int binIdx = sithCogVm_PopInt(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);

    if ( player && player->type == SITH_THING_PLAYER )
    {
        if ( mode < 0 || mode > 2 )
        {
            sithCogVm_PushInt(ctx, -1);
            return;
        }
        if ( binIdx >= 0 && binIdx < SITHBIN_NUMBINS )
        {
            sithCogVm_PushFlex(ctx, sithWeapon_GetPriority(player, binIdx, mode));
            return;
        }
    }
    sithCogVm_PushFlex(ctx, -1.0);
}

void sithCogUtil_GetCurWeaponMode(sithCog *ctx)
{
    sithCogVm_PushInt(ctx, sithWeapon_GetCurWeaponMode());
}

void sithCogUtil_GetCurWeapon(sithCog *ctx)
{
    sithThing* player = sithCogVm_PopThing(ctx);

    if ( player && player->type == SITH_THING_PLAYER )
    {
        sithCogVm_PushInt(ctx, sithInventory_GetCurWeapon(player));
    }
    else
    {
        sithCogVm_PushInt(ctx, -1);
    }
}

void sithCogUtil_GetCameraState(sithCog *ctx)
{
    int v1; // eax

    v1 = sithCamera_GetState();
    sithCogVm_PushInt(ctx, v1);
}

void sithCogUtil_SetCameraStateFlags(sithCog *ctx)
{
    int v1; // eax

    v1 = sithCogVm_PopInt(ctx);
    sithCamera_SetState(v1);
}

void sithCogUtil_SetMultiModeFlags(sithCog *ctx)
{
    sithNet_MultiModeFlags |= sithCogVm_PopInt(ctx);
}

void sithCogUtil_GetMultiModeFlags(sithCog *ctx)
{
    sithCogVm_PushInt(ctx, sithNet_MultiModeFlags);
}

void sithCogUtil_ClearMultiModeFlags(sithCog *ctx)
{
    sithNet_MultiModeFlags &= ~sithCogVm_PopInt(ctx);
}

void sithCogUtil_IsMulti(sithCog *ctx)
{
    if ( sithNet_isMulti )
        sithCogVm_PushInt(ctx, 1);
    else
        sithCogVm_PushInt(ctx, 0);
}

void sithCogUtil_IsServer(sithCog *ctx)
{
    sithCogUtil_ReturnBool(sithNet_isServer, ctx);
}

// unused
void sithCogUtil_ReturnBool(int a1, sithCog *a2)
{
    if ( a1 )
        sithCogVm_PushInt(a2, 1);
    else
        sithCogVm_PushInt(a2, 0);
}

void sithCogUtil_GetTeamScore(sithCog *ctx)
{
    signed int idx; // eax

    idx = sithCogVm_PopInt(ctx);
    if ( idx <= 0 || idx >= 5 )
        sithCogVm_PushInt(ctx, -999999);
    else
        sithCogVm_PushInt(ctx, sithNet_teamScore[idx]);
}

void sithCogUtil_SetTeamScore(sithCog *ctx)
{
    signed int score; // edi
    signed int idx; // eax

    score = sithCogVm_PopInt(ctx);
    idx = sithCogVm_PopInt(ctx);
    if ( idx > 0 && idx < 5 )
        sithNet_teamScore[idx] = score;
}

void sithCogUtil_GetTimeLimit(sithCog *a1)
{
    float a2; // ST04_4

    a2 = (double)(unsigned int)sithNet_multiplayer_timelimit * 0.000016666667;
    sithCogVm_PushFlex(a1, a2);
}

void sithCogUtil_SetTimeLimit(sithCog *ctx)
{
    float v1 = sithCogVm_PopFlex(ctx);
    if ( v1 >= 0.0 )
        sithNet_multiplayer_timelimit = (int)(v1 * 60000.0);
}

void sithCogUtil_GetScoreLimit(sithCog *ctx)
{
    sithCogVm_PushInt(ctx, sithNet_scorelimit);
}

void sithCogUtil_SetScoreLimit(sithCog *ctx)
{
    sithNet_scorelimit = sithCogVm_PopInt(ctx);
}

void sithCogUtil_ChangeFireRate(sithCog *ctx)
{
    float fireRate = sithCogVm_PopFlex(ctx);
    sithThing* player = sithCogVm_PopThing(ctx);

    if ( player && player == g_localPlayerThing && fireRate > 0.0 )
        sithWeapon_SetFireRate(player, fireRate);
}

void sithCogUtil_AutoSaveGame()
{
    char tmp[128];

    stdString_snprintf(tmp, 128, "%s%s", "_JKAUTO_", sithWorld_pCurWorld->map_jkl_fname);
    stdFnames_ChangeExt(tmp, "jks");
    sithSave_Write(tmp, 1, 0, 0);
}

void sithCogUtil_SetCameraFocii(sithCog *ctx)
{
    sithThing* focusThing2 = sithCogVm_PopThing(ctx);
    sithThing* focusThing = sithCogVm_PopThing(ctx);
    int camIdx = sithCogVm_PopInt(ctx);

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

void sithCogUtil_Initialize(void* ctx)
{
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_Sleep, "sleep");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_Rand, "rand");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_RandVec, "randvec");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetSenderRef, "getsenderref");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetSenderType, "getsendertype");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetSenderId, "getsenderid");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetSourceType, "getsourcetype");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetSourceRef, "getsourceref");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetThingCount, "getthingcount");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetGravity, "getgravity");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_SetGravity, "setgravity");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetLevelTime, "getleveltime");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetGametime, "getgametime");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetFlexGameTime, "getflexgametime");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetThingTemplateCount, "getthingtemplatecount");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_SetPulse, "setpulse");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_SetTimer, "settimer");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_SetTimerEx, "settimerex");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_KillTimerEx, "killtimerex");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_Reset, "reset");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_MaterialAnim, "materialanim");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_StopAnim, "stopanim");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_StopSurfaceAnim, "stopsurfaceanim");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetSurfaceAnim, "getsurfaceanim");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_SurfaceAnim, "surfaceanim");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetKeyLen, "getkeylen");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_LoadTemplate, "loadtemplate");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_LoadKeyframe, "loadkeyframe");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_LoadModel, "loadmodel");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_Print, "print");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_PrintInt, "printint");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_PrintFlex, "printflex");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_PrintVector, "printvector");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_VectorAdd, "vectoradd");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_VectorSub, "vectorsub");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_VectorDot, "vectordot");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_VectorCross, "vectorcross");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_VectorSet, "vectorset");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_VectorLen, "vectorlen");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_VectorScale, "vectorscale");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_VectorDist, "vectordist");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_VectorX, "vectorx");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_VectorY, "vectory");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_VectorZ, "vectorz");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_VectorNorm, "vectornorm");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetSithMode, "getsithmode");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetDifficulty, "getdifficulty");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_SetSubmodeFlags, "setsubmodeflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetSubmodeFlags, "getsubmodeflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_ClearSubmodeFlags, "clearsubmodeflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_SetDebugModeFlags, "setdebugmodeflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetDebugModeFlags, "getdebugmodeflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_ClearDebugModeFlags, "cleardebugmodeflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_BitSet, "bitset");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_BitTest, "bittest");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_BitClear, "bitclear");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_FireProjectile, "fireprojectile");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_ActivateWeapon, "activateweapon");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_DeactivateWeapon, "deactivateweapon");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_SetMountWait, "setmountwait");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_SetFireWait, "setfirewait");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_SelectWeapon, "selectweapon");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_AssignWeapon, "assignweapon");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_AutoSelectWeapon, "autoselectweapon");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetWeaponPriority, "getweaponpriority");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_SetCurWeapon, "setcurweapon");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetCurWeapon, "getcurweapon");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetCurWeaponMode, "getcurweaponmode");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_ChangeFireRate, "changefirerate");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_SendMessage, "sendmessage");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_SendMessageEx, "sendmessageex");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_ReturnEx, "returnex");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetParam, "getparam");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_SetParam, "setparam");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_EnableIRMode, "enableirmode");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_DisableIRMode, "disableirmode");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_SetInvFlags, "setinvflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_SetMapModeFlags, "setmapmodeflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetMapModeFlags, "getmapmodeflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_ClearMapModeFlags, "clearmapmodeflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_NewColorEffect, "newcoloreffect");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_FreeColorEffect, "freecoloreffect");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_FreeColorEffect, "modifycoloreffect");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_AddDynamicTint, "adddynamictint");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_AddDynamicAdd, "adddynamicadd");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetMaterialCel, "getmaterialcel");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_SetMaterialCel, "setmaterialcel");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_SetCameraFocus, "setcamerafocus");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetPrimaryFocus, "getprimaryfocus");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetSecondaryFocus, "getsecondaryfocus");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_SetCurrentCamera, "setcurrentcamera");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetCurrentCamera, "getcurrentcamera");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_CycleCamera, "cyclecamera");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_SetPovShake, "setpovshake");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_SetCameraStateFlags, "setcamerastateflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetCameraState, "getcamerastateflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_HeapNew, "heapnew");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_HeapSet, "heapset");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_HeapGet, "heapget");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_HeapFree, "heapfree");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetSelfCog, "getselfcog");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetMasterCog, "getmastercog");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_SetMasterCog, "setmastercog");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_SetMultiModeFlags, "setmultimodeflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetMultiModeFlags, "getmultimodeflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_ClearMultiModeFlags, "clearmultimodeflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_IsMulti, "ismulti");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_IsServer, "isserver");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_SetTeamScore, "setteamscore");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetTeamScore, "getteamscore");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_SetTimeLimit, "settimelimit");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetTimeLimit, "gettimelimit");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_SetScoreLimit, "setscorelimit");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_GetScoreLimit, "getscorelimit");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_SendTrigger, "sendtrigger");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_AutoSaveGame, "autosavegame");
    
    // Droidworks
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogUtil_SetCameraFocii, "setcamerafocii");
}
