#include "jkCog.h"

#include <math.h>

#include "General/stdStrTable.h"
#include "Main/jkHud.h"
#include "Main/jkDev.h"
#include "Main/jkStrings.h"
#include "Main/jkMain.h"
#include "World/jkPlayer.h"
#include "Gameplay/jkSaber.h"
#include "Gameplay/sithPlayer.h"
#include "Engine/sithPuppet.h"
#include "Engine/sithNet.h"
#include "Dss/sithMulti.h"
#include "General/stdString.h"
#include "Cog/sithCogFunctionPlayer.h"
#include "Dss/jkDSS.h"

#include "jk.h"

void jkCog_SetFlags(sithCog *ctx);
void jkCog_ClearFlags(sithCog *ctx);
void jkCog_GetFlags(sithCog *ctx);
void jkCog_SetWeaponMesh(sithCog *ctx);
void jkCog_EndLevel(sithCog *ctx);
void jkCog_SetPovModel(sithCog *ctx);
void jkCog_PlayPovKey(sithCog *ctx);
void jkCog_StopPovKey(sithCog *ctx);
void jkCog_SetForceSpeed(sithCog *pCog);
void jkCog_SetInvis(sithCog *pCog);
void jkCog_SetInvulnerable(sithCog *pCog);
void jkCog_EndTarget(sithCog *ctx);
void jkCog_SetSuperFlags(sithCog *ctx);
void jkCog_ClearSuperFlags(sithCog *ctx);
void jkCog_GetSuperFlags(sithCog *ctx);
void jkCog_PrintUniString(sithCog *ctx);
void jkCog_SetPersuasionInfo(sithCog *ctx);
void jkCog_SetTarget(sithCog *ctx);
void jkCog_SetTargetColors(sithCog *ctx);
void jkCog_SetSaberInfo(sithCog *ctx);
void jkCog_GetSaberCam(sithCog *ctx);
void jkCog_EnableSaber(sithCog *ctx);
void jkCog_DisableSaber(sithCog *ctx);
void jkCog_SetWaggle(sithCog *ctx);
void jkCog_GetChoice(sithCog *ctx);
void jkCog_StringClear(sithCog *pCog);
void jkCog_StringConcatUnistring(sithCog *pCog);
void jkCog_StringConcatAsciiString(sithCog *pCog);
void jkCog_StringConcatPlayerName(sithCog *pCog);
void jkCog_StringConcatSpace(sithCog *pCog);
void jkCog_StringConcatInt(sithCog *pCog);
void jkCog_StringConcatFormattedInt(sithCog *ctx);
void jkCog_StringConcatFlex(sithCog *pCog);
void jkCog_StringConcatFormattedFlex(sithCog *pCog);
void jkCog_StringConcatVector(sithCog *pCog);
void jkCog_StringOutput(sithCog *ctx);

//static void (*jkCog_SetFlags)(sithCog* ctx) = (void*)0x0040A3E0;
//static void (*jkCog_ClearFlags)(sithCog* ctx) = (void*)0x0040A450;
//static void (*jkCog_GetFlags)(sithCog* ctx) = (void*)0x0040A4C0;
//static void (*jkCog_SetWeaponMesh)(sithCog* ctx) = (void*)0x0040A4F0;
//static void (*jkCog_EndLevel)(sithCog* ctx) = (void*)0x0040A580;
//static void (*jkCog_SetPovModel)(sithCog* ctx) = (void*)0x0040A5D0;
//static void (*jkCog_PlayPovKey)(sithCog* ctx) = (void*)0x0040A620;
//static void (*jkCog_StopPovKey)(sithCog* ctx) = (void*)0x0040A6B0;
//static void (*jkCog_SetForceSpeed)(sithCog* ctx) = (void*)0x0040A710;
//static void (*jkCog_SetInvis)(sithCog* ctx) = (void*)0x0040A730;
//static void (*jkCog_SetInvulnerable)(sithCog* ctx) = (void*)0x0040A7A0;
//jkCog_PrintUniString
//jkCog_SetSuperFlags 
//jkCog_ClearSuperFlags
//static void (*jkCog_GetSuperFlags)(sithCog* ctx) = (void*)0x0040AA50;
//static void (*jkCog_EnableSaber)(sithCog* ctx) = (void*)0x0040AAA0;
//static void (*jkCog_DisableSaber)(sithCog* ctx) = (void*)0x0040AB20;
//static void (*jkCog_SetWaggle)(sithCog* ctx) = (void*)0x0040AB50;
//static void (*jkCog_SetSaberInfo)(sithCog* ctx) = (void*)0x0040ABA0;
//static void (*jkCog_SetPersuasionInfo)(sithCog* ctx) = (void*)0x0040AC90;
//static void (*jkCog_SetTarget)(sithCog* ctx) = (void*)0x0040AD00;
//static void (*jkCog_SetTargetColors)(sithCog* ctx) = (void*)0x0040AD30;
//static void (*jkCog_StringClear)(sithCog* ctx) = (void*)0x0040AD80;
//static void (*jkCog_StringConcatUnistring)(sithCog* ctx) = (void*)0x0040ADA0;
//static void (*jkCog_StringConcatAsciiString)(sithCog* ctx) = (void*)0x0040AE30;
//static void (*jkCog_StringConcatPlayerName)(sithCog* ctx) = (void*)0x0040AEB0;
//static void (*jkCog_StringConcatSpace)(sithCog* ctx) = (void*)0x0040AF10;
//static void (*jkCog_StringConcatInt)(sithCog* ctx) = (void*)0x0040AF70;
//static void (*jkCog_StringConcatFormattedInt)(sithCog* ctx) = (void*)0x0040AFE0;
//static void (*jkCog_StringConcatFlex)(sithCog* ctx) = (void*)0x0040B090;
//static void (*jkCog_StringConcatFormattedFlex)(sithCog* ctx) = (void*)0x0040B100;
//static void (*jkCog_StringConcatVector)(sithCog* ctx) = (void*)0x0040B1C0;
//static void (*jkCog_StringOutput)(sithCog* ctx) = (void*)0x0040B270;
//static void (*jkCog_GetSaberCam)(sithCog* ctx) = (void*)0x0040B3B0;
//static void (*jkCog_GetChoice)(sithCog* ctx) = (void*)0x0040B3D0;

#ifdef QOL_IMPROVEMENTS
void jkCog_stub0Args(sithCog *ctx)
{

}

void jkCog_stub1Args(sithCog *ctx)
{
    sithCogExec_PopInt(ctx);
}

void jkCog_stub2Args(sithCog *ctx)
{
    sithCogExec_PopInt(ctx);
    sithCogExec_PopInt(ctx);
}

void jkCog_stub3Args(sithCog *ctx)
{
    sithCogExec_PopInt(ctx);
    sithCogExec_PopInt(ctx);
    sithCogExec_PopInt(ctx);
}

void jkCog_stub4Args(sithCog *ctx)
{
    sithCogExec_PopInt(ctx);
    sithCogExec_PopInt(ctx);
    sithCogExec_PopInt(ctx);
    sithCogExec_PopInt(ctx);
}

void jkCog_stub4ArgsRet1(sithCog *ctx)
{
    sithCogExec_PopInt(ctx);
    sithCogExec_PopInt(ctx);
    sithCogExec_PopInt(ctx);
    sithCogExec_PopInt(ctx);
    sithCogExec_PushInt(ctx, 0);
}

void jkCog_addLaser(sithCog *ctx)
{
    float a = sithCogExec_PopFlex(ctx);
    int b = sithCogExec_PopInt(ctx);
    sithThing* c = sithCogExec_PopThing(ctx);
    sithCogExec_PushInt(ctx, -1);
}

void jkCog_removeLaser(sithCog *ctx)
{
    int a = sithCogExec_PopInt(ctx);
}

void jkCog_getLaserId(sithCog *ctx)
{
    sithThing* a = sithCogExec_PopThing(ctx);
    sithCogExec_PushInt(ctx, -1);
}

void jkCog_addBeam(sithCog *ctx)
{
    float a = sithCogExec_PopFlex(ctx);
    int b = sithCogExec_PopInt(ctx);
    sithThing* c = sithCogExec_PopThing(ctx);
    sithThing* d = sithCogExec_PopThing(ctx);
    sithCogExec_PushInt(ctx, -1);
}

void jkCog_computeCatapaultVelocity(sithCog *ctx)
{
    rdVector3 ret;
    float a = sithCogExec_PopFlex(ctx);
    sithThing* b = sithCogExec_PopThing(ctx);
    sithThing* c = sithCogExec_PopThing(ctx);
    float d = sithCogExec_PopFlex(ctx);
    
    ret.x = b->position.x - c->position.x;
    ret.y = b->position.y - c->position.y;
    ret.z = b->position.z - c->position.z;
    float v4 = rdVector_Normalize3Acc(&ret);
    float ctxb = sqrt(v4 * v4 * a / d);
    ret.x = ret.x * ctxb;
    ret.y = ret.y * ctxb;
    ret.z = ret.z * ctxb;
    sithCogExec_PushVector3(ctx, &ret);
}

void jkCog_dwPlayCammySpeech(sithCog* ctx)
{
    int a = sithCogExec_PopInt(ctx);
    int b = sithCogExec_PopFlex(ctx);
    char* c = sithCogExec_PopString(ctx);
    int d = sithCogExec_PopInt(ctx);
}

void jkCog_dwGetActivateBin(sithCog *ctx)
{
    sithCogExec_PushInt(ctx, sithInventory_GetCurItem(sithPlayer_pLocalPlayerThing));
}
#endif

void jkCog_RegisterVerbs()
{
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, sithCogFunctionPlayer_GetLocalPlayerThing, "jkgetlocalplayer");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_SetFlags, "jksetflags");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_GetFlags, "jkgetflags");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_ClearFlags, "jkclearflags");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_EndLevel, "jkendlevel");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_PrintUniString, "jkprintunistring");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_SetPovModel, "jksetpovmodel");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_PlayPovKey, "jkplaypovkey");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_StopPovKey, "jkstoppovkey");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_SetWeaponMesh, "jksetweaponmesh");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_EnableSaber, "jkenablesaber");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_DisableSaber, "jkdisablesaber");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_SetSaberInfo, "jksetsaberinfo");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_SetPersuasionInfo, "jksetpersuasioninfo");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_SetForceSpeed, "jksetforcespeed");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_SetInvis, "jksetinvis");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_SetInvulnerable, "jksetinvulnerable");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_SetWaggle, "jksetwaggle");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_SetSuperFlags, "jksetsuperflags");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_ClearSuperFlags, "jkclearsuperflags");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_GetSuperFlags, "jkgetsuperflags");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_SetTarget, "jksettarget");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_EndTarget, "jkendtarget");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_SetTargetColors, "jksettargetcolors");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_StringClear, "jkstringclear");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_StringConcatSpace, "jkstringconcatspace");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_StringConcatUnistring, "jkstringconcatunistring");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_StringConcatAsciiString, "jkstringconcatasciistring");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_StringConcatPlayerName, "jkstringconcatplayername");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_StringConcatInt, "jkstringconcatint");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_StringConcatFormattedInt, "jkstringconcatformattedint");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_StringConcatFlex, "jkstringconcatflex");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_StringConcatFormattedFlex, "jkstringconcatformattedflex");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_StringConcatVector, "jkstringconcatvector");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_StringOutput, "jkstringoutput");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_GetSaberCam, "jkgetsabercam");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_GetChoice, "jkgetchoice");
    
#ifdef QOL_IMPROVEMENTS
    // Added for droidwork tests
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_dwGetActivateBin, "dwGetActivateBin");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_stub1Args, "dwsetreftopic");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_addBeam, "addbeam");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_addLaser, "addlaser");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_removeLaser, "removelaser");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_getLaserId, "getlaserid");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_stub0Args, "dwFlashInventory");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_dwPlayCammySpeech, "dwplaycammyspeech");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_stub0Args, "dwfreezeplayer");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_stub0Args, "dwunfreezeplayer");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_stub2Args, "dwplaycharacterspeech");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_stub0Args, "dwcleardialog");
#endif
}

int jkCog_Startup()
{
    jkCog_RegisterVerbs();
    jkCog_bInitted = 1;
    return 1;
}

void jkCog_Shutdown()
{
    stdStrTable_Free(&jkCog_strings);
    jkCog_bInitted = 0;
}

int jkCog_StringsInit()
{
    stdStrTable_Free(&jkCog_strings);
    return stdStrTable_Load(&jkCog_strings, "misc\\cogStrings.uni");
}

void jkCog_SetFlags(sithCog *ctx)
{
    signed int flags; // esi
    sithThing *thing; // eax

    flags = sithCogExec_PopInt(ctx);
    thing = sithCogExec_PopThing(ctx);
    if ( thing && flags)
    {
        thing->jkFlags |= flags;
        if ( COG_SHOULD_SYNC(ctx) )
        {
            sithThing_SetSyncFlags(thing, THING_SYNC_STATE);
        }
    }
}

void jkCog_ClearFlags(sithCog *ctx)
{
    signed int v1; // esi
    sithThing *v2; // eax

    v1 = sithCogExec_PopInt(ctx);
    v2 = sithCogExec_PopThing(ctx);
    if ( v2 )
    {
        if ( v1 )
        {
            v2->jkFlags &= ~v1;
            if ( COG_SHOULD_SYNC(ctx) )
            {
                sithThing_SetSyncFlags(v2, THING_SYNC_STATE);
            }
        }
    }
}

void jkCog_GetFlags(sithCog *ctx)
{
    int v1; // esi
    sithThing *v2; // eax

    v1 = 0;
    v2 = sithCogExec_PopThing(ctx);
    if ( v2 )
        v1 = v2->jkFlags;
    sithCogExec_PushInt(ctx, v1);
}

// MOTS altered
void jkCog_SetWeaponMesh(sithCog *ctx)
{
    rdModel3 *model3; // edi
    sithThing *actorThing; // eax
    sithThing *v3; // ebx
    jkPlayerInfo *v4; // eax
    rdThing *v5; // esi
    int v6; // eax

    model3 = sithCogExec_PopModel3(ctx);
    actorThing = sithCogExec_PopThing(ctx);
    v3 = actorThing;
    if ( actorThing )
    {
        // MOTS added:
        if (!actorThing->playerInfo) {
            //jkPlayer_FUN_00404fe0(actorThing);
        }
        v4 = actorThing->playerInfo;
        if ( v4 )
        {
            if ( model3 )
            {
                if ( model3->numGeosets == 1 && model3->geosets[0].numMeshes == 1 )
                {
                    v5 = &v4->rd_thing;
                    rdThing_FreeEntry(v5); // Added: fix memleak
                    rdThing_NewEntry(&v4->rd_thing, v3);
                    rdThing_SetModel3(v5, model3);
                    if ( sithComm_multiplayerFlags )
                    {
                        if ( (ctx->flags & SITH_COG_NO_SYNC) == 0 )
                        {
                            v6 = ctx->trigId;
                            if ( v6 != SITH_MESSAGE_STARTUP && v6 != SITH_MESSAGE_SHUTDOWN )
                                jkDSS_SendJKSetWeaponMesh(v3);
                        }
                    }
                }
            }
        }
    }
}

void jkCog_EndLevel(sithCog *ctx)
{
    int v1; // esi

    v1 = sithCogExec_PopInt(ctx) != 0;
    if ( sithNet_isMulti )
    {
        if ( sithNet_isServer )
            jkDSS_SendEndLevel();
    }
    else
    {
        jkMain_EndLevel(v1);
    }
}

void jkCog_SetPovModel(sithCog *ctx)
{
    rdModel3 *model3; // edi
    sithThing *actorThing; // eax

    model3 = sithCogExec_PopModel3(ctx);
    actorThing = sithCogExec_PopThing(ctx);
    if ( actorThing )
    {
        if ( model3 )
        {
            if ( actorThing->type == SITH_THING_ACTOR || actorThing->type == SITH_THING_PLAYER )
                jkPlayer_SetPovModel(actorThing->playerInfo, model3);
        }
    }
}

void jkCog_PlayPovKey(sithCog *ctx)
{
    int v1; // ebp
    int v2; // edi
    rdKeyframe *keyframe; // ebx
    sithThing *actorThing; // eax
    int v5; // ecx
    rdPuppet *v6; // eax
    int v7; // eax

    v1 = sithCogExec_PopInt(ctx);
    v2 = sithCogExec_PopInt(ctx);
    keyframe = sithCogExec_PopKeyframe(ctx);
    actorThing = sithCogExec_PopThing(ctx);
    if ( actorThing
      && keyframe
      && ((v5 = actorThing->type, v5 == SITH_THING_ACTOR) || v5 == SITH_THING_PLAYER)
      && (v6 = actorThing->playerInfo->povModel.puppet) != 0 )
    {
        v7 = sithPuppet_StartKey(v6, keyframe, v2, v2 + 2, v1, 0);
        sithCogExec_PushInt(ctx, v7);
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}

void jkCog_StopPovKey(sithCog *ctx)
{
    int v2; // edi
    sithThing *actorThing; // eax
    rdPuppet *v5; // eax
    float a1a; // [esp+Ch] [ebp+4h]

    a1a = sithCogExec_PopFlex(ctx);
    v2 = sithCogExec_PopInt(ctx);
    actorThing = sithCogExec_PopThing(ctx);
    if ( actorThing )
    {
        if ( actorThing->type == SITH_THING_ACTOR || actorThing->type == SITH_THING_PLAYER )
        {
            v5 = actorThing->playerInfo->povModel.puppet;
            if ( v5 && v2 >= 0 && v2 < 4 )
                sithPuppet_StopKey(v5, v2, a1a);
        }
    }
}

void jkCog_SetForceSpeed(sithCog *pCog)
{
    sithPlayer_pLocalPlayerThing->actorParams.extraSpeed = sithCogExec_PopFlex(pCog);
}

void jkCog_SetInvis(sithCog *pCog)
{
    int v1; // edi
    sithThing *v2; // eax
    int v3; // esi

    v1 = sithCogExec_PopInt(pCog);
    v2 = sithCogExec_PopThing(pCog);
    if ( v1 <= 0 )
        v2->rdthing.curGeoMode = v2->rdthing.desiredGeoMode;
    else
        v2->rdthing.curGeoMode = RD_GEOMODE_VERTICES;
    if ( sithComm_multiplayerFlags )
    {
        if ( (pCog->flags & SITH_COG_NO_SYNC) == 0 )
        {
            v3 = pCog->trigId;
            if ( v3 != SITH_MESSAGE_STARTUP && v3 != SITH_MESSAGE_SHUTDOWN )
                sithThing_SetSyncFlags(v2, THING_SYNC_STATE);
        }
    }
}

void jkCog_SetInvulnerable(sithCog *pCog)
{
    int v1; // edi
    sithThing *v2; // eax
    uint32_t v3; // ecx
    unsigned int v4; // ecx
    int v5; // esi

    v1 = sithCogExec_PopInt(pCog);
    v2 = sithCogExec_PopThing(pCog);
    v3 = v2->actorParams.typeflags;
    if ( v1 <= 0 )
        v4 = v3 & ~8u;
    else
        v4 = v3 | 8;
    v2->actorParams.typeflags = v4;
    if ( sithComm_multiplayerFlags )
    {
        if ( (pCog->flags & SITH_COG_NO_SYNC) == 0 )
        {
            v5 = pCog->trigId;
            if ( v5 != SITH_MESSAGE_STARTUP && v5 != SITH_MESSAGE_SHUTDOWN )
                sithThing_SetSyncFlags(v2, THING_SYNC_STATE);
        }
    }
}

void jkCog_EndTarget(sithCog *ctx)
{
    jkHud_EndTarget();
}

void jkCog_SetSuperFlags(sithCog *ctx)
{
    int flags = sithCogExec_PopInt(ctx);

    if ( (flags & 1) != 0 )
        playerThings[playerThingIdx].field_21C = 1;
    if ( (flags & 2) != 0 )
        playerThings[playerThingIdx].shields = 1;
    if ( (flags & 4) != 0 )
        playerThings[playerThingIdx].field_224 = 1;
}

void jkCog_ClearSuperFlags(sithCog *ctx)
{
    int flags = sithCogExec_PopInt(ctx);

    if ( (flags & 1) != 0 )
        playerThings[playerThingIdx].field_21C = 0;
    if ( (flags & 2) != 0 )
        playerThings[playerThingIdx].shields = 0;
    if ( (flags & 4) != 0 )
        playerThings[playerThingIdx].field_224 = 0;
}

void jkCog_GetSuperFlags(sithCog *cog)
{
    int flags = 0;

    // Added: Original used +, not |
    if (playerThings[playerThingIdx].field_21C)
        flags |= 1;
    if ( playerThings[playerThingIdx].shields )
        flags |= 2;
    if ( playerThings[playerThingIdx].field_224 )
        flags |= 4;
    sithCogExec_PushInt(cog, flags);
}

void jkCog_PrintUniString(sithCog *ctx)
{
    int v1; // ebp
    int v2; // eax
    int v3; // esi
    wchar_t *v4; // edi
    int v5; // ebx
    int v6; // ebx
    char key[64]; // [esp+10h] [ebp-C0h] BYREF
    char v8[128]; // [esp+50h] [ebp-80h] BYREF

    v1 = sithCogExec_PopInt(ctx);
    v2 = sithCogExec_PopInt(ctx);

    v3 = v2;
    if ( v2 >= 0 )
        v3 = sithPlayer_GetNumidk(v2);
    stdString_snprintf(key, 64, "COG_%05d", v1);
    v4 = stdStrTable_GetUniString(&jkCog_strings, key);
    if ( !v4 )
        v4 = jkStrings_GetText(key);
    stdString_WcharToChar(v8, v4, 127);
    v8[127] = 0;
    if ( v3 >= 0 )
    {
        if ( v3 == playerThingIdx )
        {
            jkDev_PrintUniString(v4);
            return;
        }
        if ( COG_SHOULD_SYNC(ctx) && v3 < jkPlayer_maxPlayers && (jkPlayer_playerInfos[v3].flags & 1) != 0 )
        {
            
            jkDSS_SendJKPrintUniString(v1, v3);
        }
    }
    else
    {
        if ( v3 != -3 )
        {
            if ( v3 != -1 )
                return;
            jkDev_PrintUniString(v4);
            return;
        }
        jkDev_PrintUniString(v4);
        if ( COG_SHOULD_SYNC(ctx) )
        {
            jkDSS_SendJKPrintUniString(v1, 0xFFFFFFFF);
        }
    }
}

void jkCog_SetPersuasionInfo(sithCog *ctx)
{
    signed int v1; // edi
    signed int v2; // ebx
    sithThing *v3; // eax
    jkPlayerInfo *v4; // ecx
    int v5; // esi

    v1 = sithCogExec_PopInt(ctx);
    v2 = sithCogExec_PopInt(ctx);
    v3 = sithCogExec_PopThing(ctx);
    v4 = v3->playerInfo;
    v4->maxTwinkles = v2;
    v4->twinkleSpawnRate = v1;
    if ( COG_SHOULD_SYNC(ctx) )
    {
        jkDSS_SendJKSetWeaponMesh(v3);
    }
}

void jkCog_SetTarget(sithCog *ctx)
{
    sithThing *v1; // eax

    v1 = sithCogExec_PopThing(ctx);
    jkHud_SetTarget(v1);
}

void jkCog_SetTargetColors(sithCog *ctx)
{
    int tmp[3]; // [esp+4h] [ebp-Ch] BYREF

    tmp[0] = sithCogExec_PopInt(ctx);
    tmp[1] = sithCogExec_PopInt(ctx);
    tmp[2] = sithCogExec_PopInt(ctx);
    jkHud_SetTargetColors(tmp);
}

void jkCog_SetSaberInfo(sithCog *ctx)
{
    sithThing *saber_sparks; // ebx
    sithThing *blood_sparks; // ebp
    sithThing *v4; // edi
    int v5; // esi
    float len; // [esp+10h] [ebp-14h]
    float tip_rad; // [esp+14h] [ebp-10h]
    float base_rad; // [esp+18h] [ebp-Ch]
    rdMaterial *v9; // [esp+1Ch] [ebp-8h]
    rdMaterial *v10; // [esp+20h] [ebp-4h]
    sithThing *wall_sparks; // [esp+28h] [ebp+4h]

    saber_sparks = sithCogExec_PopTemplate(ctx);
    blood_sparks = sithCogExec_PopTemplate(ctx);
    wall_sparks = sithCogExec_PopTemplate(ctx);
    len = sithCogExec_PopFlex(ctx);
    tip_rad = sithCogExec_PopFlex(ctx);
    base_rad = sithCogExec_PopFlex(ctx);
    v9 = sithCogExec_PopMaterial(ctx);
    v10 = sithCogExec_PopMaterial(ctx);
    v4 = sithCogExec_PopThing(ctx);
    if ( v4->playerInfo )
    {
        jkSaber_InitializeSaberInfo(v4, v10->mat_fpath, v9->mat_fpath, base_rad, tip_rad, len, wall_sparks, blood_sparks, saber_sparks);
        if ( sithComm_multiplayerFlags )
        {
            if ( (ctx->flags & SITH_COG_NO_SYNC) == 0 )
            {
                v5 = ctx->trigId;
                if ( v5 != SITH_MESSAGE_STARTUP && v5 != SITH_MESSAGE_SHUTDOWN )
                {
                    jkDSS_SendSetSaberInfo(v4);
                    jkDSS_SendSetSaberInfo2(v4);
                }
            }
        }
    }
}

void jkCog_GetSaberCam(sithCog *ctx)
{
    sithCogExec_PushInt(ctx, jkPlayer_setSaberCam);
}

void jkCog_EnableSaber(sithCog *ctx)
{
    sithThing *v2; // eax
    sithThing *v3; // esi
    float a3; // [esp+4h] [ebp-8h]
    float a2; // [esp+8h] [ebp-4h]
    float a1a; // [esp+10h] [ebp+4h]

    a1a = sithCogExec_PopFlex(ctx);
    a3 = sithCogExec_PopFlex(ctx);
    a2 = sithCogExec_PopFlex(ctx);
    v2 = sithCogExec_PopThing(ctx);
    v3 = v2;
    if ( v2 && v2->type == SITH_THING_PLAYER )
    {
        jkSaber_Enable(v2, a2, a3, a1a);
        if ( sithComm_multiplayerFlags )
            jkDSS_SendJKEnableSaber(v3);
    }
}

void jkCog_DisableSaber(sithCog *ctx)
{
    sithThing *v1; // eax

    v1 = sithCogExec_PopThing(ctx);
    if ( v1 )
    {
        if ( v1->type == SITH_THING_PLAYER )
            jkSaber_Disable(v1);
    }
}

void jkCog_SetWaggle(sithCog *ctx)
{
    sithThing *v2; // eax
    rdVector3 a2; // [esp+4h] [ebp-Ch] BYREF
    float a1a; // [esp+14h] [ebp+4h]

    a1a = sithCogExec_PopFlex(ctx);
    sithCogExec_PopVector3(ctx, &a2);
    v2 = sithCogExec_PopThing(ctx);
    if ( v2 )
    {
        if ( v2->type == SITH_THING_PLAYER )
            jkPlayer_SetWaggle(v2, &a2, a1a);
    }
}

void jkCog_GetChoice(sithCog *ctx)
{
    sithCogExec_PushInt(ctx, jkPlayer_GetChoice());
}

void jkCog_StringClear(sithCog *pCog)
{
    _wcscpy(jkCog_jkstring, jkCog_emptystring);
}

void jkCog_StringConcatUnistring(sithCog *pCog)
{
    signed int uniID; // eax
    wchar_t *str; // esi
    size_t finalLen;
    char key[32]; // [esp+8h] [ebp-20h] BYREF

    uniID = sithCogExec_PopInt(pCog);
    stdString_snprintf(key, 32, "COG_%05d", uniID);
    str = stdStrTable_GetUniString(&jkCog_strings, key);
    if ( !str )
        str = jkStrings_GetText(key);

    finalLen = _wcslen(str) + _wcslen(jkCog_jkstring);
    if (finalLen < 0x81)
    {
        __wcscat(jkCog_jkstring, str);
        jkCog_jkstring[finalLen] = 0;
    }
}

void jkCog_StringConcatAsciiString(sithCog *pCog)
{
    char *mbString; // edx
    size_t finalLen;
    wchar_t wcStr[130]; // [esp+8h] [ebp-104h] BYREF

    mbString = sithCogExec_PopString(pCog);
    stdString_CharToWchar(wcStr, mbString, strlen(mbString) + 1);

    finalLen = _wcslen(wcStr) + _wcslen(jkCog_jkstring);
    if (finalLen < 0x81)
    {
        __wcscat(jkCog_jkstring, wcStr);
        jkCog_jkstring[finalLen] = 0;
    }
}

void jkCog_StringConcatPlayerName(sithCog *pCog)
{
    sithThing *v1; // eax
    size_t finalLen;
    sithPlayerInfo *v2; // esi

    v1 = sithCogExec_PopThing(pCog);
    if ( v1 )
    {
        if ( v1->type == SITH_THING_PLAYER )
        {
            v2 = v1->actorParams.playerinfo;
            if ( v2 )
            {
                finalLen = _wcslen(v2->player_name) + _wcslen(jkCog_jkstring);
                if (finalLen < 0x81)
                {
                    __wcscat(jkCog_jkstring, v2->player_name);
                    jkCog_jkstring[finalLen] = 0;
                }
            }
        }
    }
}

void jkCog_StringConcatSpace(sithCog *pCog)
{
    size_t finalLen;
    wchar_t v2[130]; // [esp+4h] [ebp-104h] BYREF

    _wcscpy(v2, L" ");

    finalLen = _wcslen(v2) + _wcslen(jkCog_jkstring);
    if (finalLen < 0x81)
    {
        __wcscat(jkCog_jkstring, v2);
        jkCog_jkstring[finalLen] = 0;
    }
}

void jkCog_StringConcatInt(sithCog *pCog)
{
    signed int v1; // eax
    size_t finalLen;
    wchar_t v3[130]; // [esp+4h] [ebp-104h] BYREF

    v1 = sithCogExec_PopInt(pCog);
    jk_snwprintf(v3, 130, L"%d", v1); // Added: bounds check
    finalLen = _wcslen(v3) + _wcslen(jkCog_jkstring);
    if (finalLen < 0x81)
    {
        __wcscat(jkCog_jkstring, v3);
        jkCog_jkstring[finalLen] = 0;
    }
}

void jkCog_StringConcatFormattedInt(sithCog *ctx)
{
    char *v1; // esi
    signed int v2; // eax
    signed int v3; // ebx
    size_t finalLen; // esi
    wchar_t v5[130]; // [esp+Ch] [ebp-208h] BYREF
    wchar_t v6[130]; // [esp+110h] [ebp-104h] BYREF

    v1 = sithCogExec_PopString(ctx);
    v2 = sithCogExec_PopInt(ctx);
    v3 = v2;
    if ( v1 )
    {
        stdString_CharToWchar(v6, v1, _strlen(v1) + 1);
        jk_snwprintf(v5, 130, v6, v3); // added bounds
    }
    else
    {
        jk_snwprintf(v5, 130, L"%d", v2);
    }
    finalLen = _wcslen(v5) + _wcslen(jkCog_jkstring);
    if (finalLen < 0x81)
    {
        __wcscat(jkCog_jkstring, v5);
        jkCog_jkstring[finalLen] = 0;
    }
}

void jkCog_StringConcatFlex(sithCog *pCog)
{
    double v1; // st7
    size_t finalLen; // esi
    wchar_t v3[130]; // [esp+Ch] [ebp-104h] BYREF

    v1 = sithCogExec_PopFlex(pCog);
    jk_snwprintf(v3, 130, L"%f", v1); // Added: bounds check
    finalLen = _wcslen(v3) + _wcslen(jkCog_jkstring);
    if (finalLen < 0x81)
    {
        __wcscat(jkCog_jkstring, v3);
        jkCog_jkstring[finalLen] = 0;
    }
}

void jkCog_StringConcatFormattedFlex(sithCog *pCog)
{
    char *v1; // esi
    size_t finalLen; // esi
    float v3; // [esp+10h] [ebp-20Ch]
    wchar_t v4[130]; // [esp+14h] [ebp-208h] BYREF
    wchar_t v5[130]; // [esp+118h] [ebp-104h] BYREF

    v1 = sithCogExec_PopString(pCog);
    v3 = sithCogExec_PopFlex(pCog);
    if ( v1 )
    {
        stdString_CharToWchar(v5, v1, strlen(v1) + 1);
        jk_snwprintf(v4, 130, v5, v3); // Added: bounds
    }
    else
    {
        jk_snwprintf(v4, 130, L"%f", v3); // Added: bounds
    }
    finalLen = _wcslen(v4) + _wcslen(jkCog_jkstring);
    if (finalLen < 0x81)
    {
        __wcscat(jkCog_jkstring, v4);
        jkCog_jkstring[finalLen] = 0;
    }
}

void jkCog_StringConcatVector(sithCog *pCog)
{
    size_t finalLen; // esi
    rdVector3 v2; // [esp+1Ch] [ebp-110h] BYREF
    wchar_t v3[130]; // [esp+28h] [ebp-104h] BYREF

    if ( sithCogExec_PopVector3(pCog, &v2) )
        jk_snwprintf(v3, 130, L"<%f %f %f>", v2.x, v2.y, v2.z);
    else
        _wcscpy(v3, L"<Bad Vector>");
    finalLen = _wcslen(v3) + _wcslen(jkCog_jkstring);
    if (finalLen < 0x81)
    {
        __wcscat(jkCog_jkstring, v3);
        jkCog_jkstring[finalLen] = 0;
    }
}

void jkCog_StringOutput(sithCog *ctx)
{
    int v1; // ebx
    int v2; // esi
    int v3; // edi
    int v4; // edi
    char v5[128]; // [esp+Ch] [ebp-80h] BYREF

    v1 = sithCogExec_PopInt(ctx);
    v2 = sithCogExec_PopInt(ctx);
    if ( v1 >= 0 )
        v1 = sithPlayer_GetNumidk(v1);
    if ( v2 >= 0 )
        v2 = sithPlayer_GetNumidk(v2);
    stdString_WcharToChar(v5, jkCog_jkstring, 127);
    v5[127] = 0;
    if ( v2 >= 0 )
    {
        if ( v2 == playerThingIdx )
        {
LABEL_8:
            jkDev_PrintUniString(jkCog_jkstring);
            return;
        }
        if ( sithComm_multiplayerFlags )
        {
            if ( (ctx->flags & SITH_COG_NO_SYNC) == 0 )
            {
                v4 = ctx->trigId;
                if ( v4 != SITH_MESSAGE_STARTUP && v4 != SITH_MESSAGE_SHUTDOWN && v2 < jkPlayer_maxPlayers && (jkPlayer_playerInfos[v2].flags & 1) != 0 )
                    sithMulti_SendChat(v5, v2, v1);
            }
        }
    }
    else
    {
        if ( v2 != -3 )
        {
            if ( v2 != -1 )
                return;
            goto LABEL_8;
        }
        jkDev_PrintUniString(jkCog_jkstring);
        if ( sithComm_multiplayerFlags )
        {
            if ( (ctx->flags & SITH_COG_NO_SYNC) == 0 )
            {
                v3 = ctx->trigId;
                if ( v3 != SITH_MESSAGE_STARTUP && v3 != SITH_MESSAGE_SHUTDOWN )
                    sithMulti_SendChat(v5, -1, v1);
            }
        }
    }
}
