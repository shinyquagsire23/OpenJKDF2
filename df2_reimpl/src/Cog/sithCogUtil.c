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

static void (*sithCogUtil_StopThing)(sithCog* ctx) = (void*)0x005060B0; // unused?
static void (*sithCogUtil_StopAnim)(sithCog* ctx) = (void*)0x005060E0;
static void (*sithCogUtil_StopSurfaceAnim)(sithCog* ctx) = (void*)0x00506130;
static void (*sithCogUtil_GetSurfaceAnim)(sithCog* ctx) = (void*)0x00506180;
static void (*sithCogUtil_LoadTemplate)(sithCog* ctx) = (void*)0x005061C0;
static void (*sithCogUtil_LoadKeyframe)(sithCog* ctx) = (void*)0x00506200;
static void (*sithCogUtil_LoadModel)(sithCog* ctx) = (void*)0x00506240;
static void (*sithCogUtil_SetPulse)(sithCog* ctx) = (void*)0x00506280;
static void (*sithCogUtil_SetTimer)(sithCog* ctx) = (void*)0x00506340;
static void (*sithCogUtil_SetTimerEx)(sithCog* ctx) = (void*)0x005063F0;
static void (*sithCogUtil_KillTimerEx)(sithCog* ctx) = (void*)0x00506470;

static void (*sithCogUtil_GetSithMode)(sithCog* ctx) = (void*)0x005069B0;
static void (*sithCogUtil_GetGametime)(sithCog* ctx) = (void*)0x005069D0;
static void (*sithCogUtil_GetFlexGameTime)(sithCog* ctx) = (void*)0x005069F0;
static void (*sithCogUtil_GetDifficulty)(sithCog* ctx) = (void*)0x00506A10;
static void (*sithCogUtil_SetSubmodeFlags)(sithCog* ctx) = (void*)0x00506A30;
static void (*sithCogUtil_ClearSubmodeFlags)(sithCog* ctx) = (void*)0x00506A50;
static void (*sithCogUtil_GetSubmodeFlags)(sithCog* ctx) = (void*)0x00506A70;
static void (*sithCogUtil_SetDebugModeFlags)(sithCog* ctx) = (void*)0x00506A90;
static void (*sithCogUtil_ClearDebugModeFlags)(sithCog* ctx) = (void*)0x00506AB0;
static void (*sithCogUtil_GetDebugModeFlags)(sithCog* ctx) = (void*)0x00506AD0;

static void (*sithCogUtil_GetLevelTime)(sithCog* ctx) = (void*)0x00506B80;
static void (*sithCogUtil_GetThingCount)(sithCog* ctx) = (void*)0x00506BC0;
static void (*sithCogUtil_GetThingTemplateCount)(sithCog* ctx) = (void*)0x00506BE0;
static void (*sithCogUtil_GetGravity)(sithCog* ctx) = (void*)0x00506C40;
static void (*sithCogUtil_SetGravity)(sithCog* ctx) = (void*)0x00506C60;

static void (*sithCogUtil_SetMaterialCel)(sithCog* ctx) = (void*)0x00506DE0;
static void (*sithCogUtil_GetMaterialCel)(sithCog* ctx) = (void*)0x00506E20;
static void (*sithCogUtil_EnableIRMode)(sithCog* ctx) = (void*)0x00506E50;
static void (*sithCogUtil_DisableIRMode)(sithCog* ctx) = (void*)0x00506E90;
static void (*sithCogUtil_SetInvFlags)(sithCog* ctx) = (void*)0x00506EA0;
static void (*sithCogUtil_SetMapModeFlags)(sithCog* ctx) = (void*)0x00506F00;
static void (*sithCogUtil_GetMapModeFlags)(sithCog* ctx) = (void*)0x00506F20;
static void (*sithCogUtil_ClearMapModeFlags)(sithCog* ctx) = (void*)0x00506F40;
static void (*sithCogUtil_SetCameraFocus)(sithCog* ctx) = (void*)0x00506F60;
static void (*sithCogUtil_GetPrimaryFocus)(sithCog* ctx) = (void*)0x00506FB0;
static void (*sithCogUtil_GetSecondaryFocus)(sithCog* ctx) = (void*)0x00507010;
static void (*sithCogUtil_SetCurrentCamera)(sithCog* ctx) = (void*)0x00507070;
static void (*sithCogUtil_GetCurrentCamera)(sithCog* ctx) = (void*)0x005070B0;
static void (*sithCogUtil_CycleCamera)(sithCog* ctx) = (void*)0x00507100;
static void (*sithCogUtil_SetPovShake)(sithCog* ctx) = (void*)0x00507110;
static void (*sithCogUtil_HeapNew)(sithCog* ctx) = (void*)0x00507180;
static void (*sithCogUtil_HeapSet)(sithCog* ctx) = (void*)0x005071F0;
static void (*sithCogUtil_HeapGet)(sithCog* ctx) = (void*)0x00507250;
static void (*sithCogUtil_HeapFree)(sithCog* ctx) = (void*)0x005072C0;
static void (*sithCogUtil_GetSelfCog)(sithCog* ctx) = (void*)0x005072F0;
static void (*sithCogUtil_GetMasterCog)(sithCog* ctx) = (void*)0x00507310;
static void (*sithCogUtil_SetMasterCog)(sithCog* ctx) = (void*)0x00507340;
static void (*sithCogUtil_NewColorEffect)(sithCog* ctx) = (void*)0x00507360;
static void (*sithCogUtil_ModifyColorEffect)(sithCog* ctx) = (void*)0x00507470;
static void (*sithCogUtil_FreeColorEffect)(sithCog* ctx) = (void*)0x00507560;
static void (*sithCogUtil_AddDynamicTint)(sithCog* ctx) = (void*)0x00507580;
static void (*sithCogUtil_AddDynamicAdd)(sithCog* ctx) = (void*)0x005075F0;
static void (*sithCogUtil_FireProjectile)(sithCog* ctx) = (void*)0x00507650;
static void (*sithCogUtil_SendTrigger)(sithCog* ctx) = (void*)0x00507730;
static void (*sithCogUtil_ActivateWeapon)(sithCog* ctx) = (void*)0x00507870;
static void (*sithCogUtil_DeactivateWeapon)(sithCog* ctx) = (void*)0x005078D0;
static void (*sithCogUtil_SetFireWait)(sithCog* ctx) = (void*)0x00507930;
static void (*sithCogUtil_SetMountWait)(sithCog* ctx) = (void*)0x00507980;
static void (*sithCogUtil_SelectWeapon)(sithCog* ctx) = (void*)0x005079D0;
static void (*sithCogUtil_AssignWeapon)(sithCog* ctx) = (void*)0x00507A10;
static void (*sithCogUtil_AutoSelectWeapon)(sithCog* ctx) = (void*)0x00507A50;
static void (*sithCogUtil_SetCurWeapon)(sithCog* ctx) = (void*)0x00507AA0;
static void (*sithCogUtil_GetWeaponPriority)(sithCog* ctx) = (void*)0x00507AE0;
static void (*sithCogUtil_GetCurWeaponMode)(sithCog* ctx) = (void*)0x00507B70;
static void (*sithCogUtil_GetCurWeapon)(sithCog* ctx) = (void*)0x00507B90;
static void (*sithCogUtil_GetCameraState)(sithCog* ctx) = (void*)0x00507BD0;
static void (*sithCogUtil_SetCameraStateFlags)(sithCog* ctx) = (void*)0x00507BF0;
static void (*sithCogUtil_SetMultiModeFlags)(sithCog* ctx) = (void*)0x00507C10;
static void (*sithCogUtil_ClearMultiModeFlags)(sithCog* ctx) = (void*)0x00507C30;
static void (*sithCogUtil_GetMultiModeFlags)(sithCog* ctx) = (void*)0x00507C50;
static void (*sithCogUtil_IsMulti)(sithCog* ctx) = (void*)0x00507C70;
static void (*sithCogUtil_IsServer)(sithCog* ctx) = (void*)0x00507CA0;
static void (*sithCogUtil_ReturnBool)(sithCog* ctx) = (void*)0x00507CA5; // util func
static void (*sithCogUtil_GetTeamScore)(sithCog* ctx) = (void*)0x00507CD0;
static void (*sithCogUtil_SetTeamScore)(sithCog* ctx) = (void*)0x00507D10;
static void (*sithCogUtil_GetTimeLimit)(sithCog* ctx) = (void*)0x00507D40;
static void (*sithCogUtil_SetTimeLimit)(sithCog* ctx) = (void*)0x00507D80;
static void (*sithCogUtil_GetScoreLimit)(sithCog* ctx) = (void*)0x00507DB0;
static void (*sithCogUtil_SetScoreLimit)(sithCog* ctx) = (void*)0x00507DD0;
static void (*sithCogUtil_ChangeFireRate)(sithCog* ctx) = (void*)0x00507DF0;
static void (*sithCogUtil_AutoSaveGame)(sithCog* ctx) = (void*)0x00507E40;


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
    float rval = (double)_rand() * 0.000030518509;
    sithCogVm_PushFlex(ctx, rval);
}

void sithCogUtil_RandVec(sithCog *ctx)
{
    rdVector3 rvec;

    rvec.x = (double)_rand() * 0.000030518509;
    rvec.y = (double)_rand() * 0.000030518509;
    rvec.z = (double)_rand() * 0.000030518509;
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
    int *v4; // eax
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
        sithCogVm_PushInt(ctx_, *v4);
    else
        sithCogVm_PushInt(ctx_, -1);
}

void sithCogUtil_MaterialAnim(sithCog *ctx)
{
    sithCog *ctx_; // esi
    int popInt; // edi
    void *material; // ecx
    int *v4; // eax
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
        sithCogVm_PushInt(ctx_, *v4);
    else
        sithCogVm_PushInt(ctx_, -1);
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
    rdVector_Sub3(&tmp, &inA, &inB);
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

void sithCogUtil_BitSet(sithCog *ctx)
{
    signed int a; // esi
    signed int b; // eax

    a = sithCogVm_PopInt(ctx);
    b = sithCogVm_PopInt(ctx);
    sithCogVm_PushInt(ctx, b | a);
}

void sithCogUtil_BitTest(sithCog *ctx)
{
    signed int a; // esi
    signed int b; // eax

    a = sithCogVm_PopInt(ctx);
    b = sithCogVm_PopInt(ctx);
    sithCogVm_PushInt(ctx, b & a);
}

void sithCogUtil_BitClear(sithCog *ctx)
{
    signed int a; // esi
    signed int b; // eax

    a = sithCogVm_PopInt(ctx);
    b = sithCogVm_PopInt(ctx);
    sithCogVm_PushInt(ctx, b & ~a);
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
}
