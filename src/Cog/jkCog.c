#include "jkCog.h"

#include <math.h>

#include "General/stdStrTable.h"
#include "Main/jkHud.h"
#include "Main/jkDev.h"
#include "Main/jkStrings.h"
#include "Main/jkMain.h"
#include "World/jkPlayer.h"
#include "World/jkSaber.h"
#include "World/sithPlayer.h"
#include "Engine/sithPuppet.h"
#include "Engine/sithNet.h"
#include "Engine/sithMulti.h"
#include "General/stdString.h"
#include "Cog/sithCogFunctionPlayer.h"

#include "jk.h"

void jkCog_SetFlags(sithCog *ctx);
void jkCog_ClearFlags(sithCog *ctx);
void jkCog_GetFlags(sithCog *ctx);
void jkCog_SetWeaponMesh(sithCog *ctx);
void jkCog_EndLevel(sithCog *ctx);
void jkCog_SetPovModel(sithCog *ctx);
void jkCog_PlayPovKey(sithCog *ctx);
void jkCog_StopPovKey(sithCog *ctx);
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
void jkCog_StringClear();
void jkCog_StringConcatFormattedInt(sithCog *ctx);
void jkCog_StringOutput(sithCog *ctx);

//static void (*jkCog_SetFlags)(sithCog* ctx) = (void*)0x0040A3E0;
//static void (*jkCog_ClearFlags)(sithCog* ctx) = (void*)0x0040A450;
//static void (*jkCog_GetFlags)(sithCog* ctx) = (void*)0x0040A4C0;
//static void (*jkCog_SetWeaponMesh)(sithCog* ctx) = (void*)0x0040A4F0;
//static void (*jkCog_EndLevel)(sithCog* ctx) = (void*)0x0040A580;
//static void (*jkCog_SetPovModel)(sithCog* ctx) = (void*)0x0040A5D0;
//static void (*jkCog_PlayPovKey)(sithCog* ctx) = (void*)0x0040A620;
//static void (*jkCog_StopPovKey)(sithCog* ctx) = (void*)0x0040A6B0;
static void (*jkCog_SetForceSpeed)(sithCog* ctx) = (void*)0x0040A710;
static void (*jkCog_SetInvis)(sithCog* ctx) = (void*)0x0040A730;
static void (*jkCog_SetInvulnerable)(sithCog* ctx) = (void*)0x0040A7A0;
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
static void (*jkCog_StringConcatUnistring)(sithCog* ctx) = (void*)0x0040ADA0;
static void (*jkCog_StringConcatAsciiString)(sithCog* ctx) = (void*)0x0040AE30;
static void (*jkCog_StringConcatPlayerName)(sithCog* ctx) = (void*)0x0040AEB0;
static void (*jkCog_StringConcatSpace)(sithCog* ctx) = (void*)0x0040AF10;
static void (*jkCog_StringConcatInt)(sithCog* ctx) = (void*)0x0040AF70;
//static void (*jkCog_StringConcatFormattedInt)(sithCog* ctx) = (void*)0x0040AFE0;
static void (*jkCog_StringConcatFlex)(sithCog* ctx) = (void*)0x0040B090;
static void (*jkCog_StringConcatFormattedFlex)(sithCog* ctx) = (void*)0x0040B100;
static void (*jkCog_StringConcatVector)(sithCog* ctx) = (void*)0x0040B1C0;
//static void (*jkCog_StringOutput)(sithCog* ctx) = (void*)0x0040B270;
//static void (*jkCog_GetSaberCam)(sithCog* ctx) = (void*)0x0040B3B0;
//static void (*jkCog_GetChoice)(sithCog* ctx) = (void*)0x0040B3D0;

#ifdef QOL_IMPROVEMENTS
void jkCog_stub0Args(sithCog *ctx)
{

}

void jkCog_stub1Args(sithCog *ctx)
{
    sithCogVm_PopInt(ctx);
}

void jkCog_stub2Args(sithCog *ctx)
{
    sithCogVm_PopInt(ctx);
    sithCogVm_PopInt(ctx);
}

void jkCog_stub3Args(sithCog *ctx)
{
    sithCogVm_PopInt(ctx);
    sithCogVm_PopInt(ctx);
    sithCogVm_PopInt(ctx);
}

void jkCog_stub4Args(sithCog *ctx)
{
    sithCogVm_PopInt(ctx);
    sithCogVm_PopInt(ctx);
    sithCogVm_PopInt(ctx);
    sithCogVm_PopInt(ctx);
}

void jkCog_stub4ArgsRet1(sithCog *ctx)
{
    sithCogVm_PopInt(ctx);
    sithCogVm_PopInt(ctx);
    sithCogVm_PopInt(ctx);
    sithCogVm_PopInt(ctx);
    sithCogVm_PushInt(ctx, 0);
}

void jkCog_addLaser(sithCog *ctx)
{
    float a = sithCogVm_PopFlex(ctx);
    int b = sithCogVm_PopInt(ctx);
    sithThing* c = sithCogVm_PopThing(ctx);
    sithCogVm_PushInt(ctx, -1);
}

void jkCog_removeLaser(sithCog *ctx)
{
    int a = sithCogVm_PopInt(ctx);
}

void jkCog_getLaserId(sithCog *ctx)
{
    sithThing* a = sithCogVm_PopThing(ctx);
    sithCogVm_PushInt(ctx, -1);
}

void jkCog_addBeam(sithCog *ctx)
{
    float a = sithCogVm_PopFlex(ctx);
    int b = sithCogVm_PopInt(ctx);
    sithThing* c = sithCogVm_PopThing(ctx);
    sithThing* d = sithCogVm_PopThing(ctx);
    sithCogVm_PushInt(ctx, -1);
}

void jkCog_computeCatapaultVelocity(sithCog *ctx)
{
    rdVector3 ret;
    float a = sithCogVm_PopFlex(ctx);
    sithThing* b = sithCogVm_PopThing(ctx);
    sithThing* c = sithCogVm_PopThing(ctx);
    float d = sithCogVm_PopFlex(ctx);
    
    ret.x = b->position.x - c->position.x;
    ret.y = b->position.y - c->position.y;
    ret.z = b->position.z - c->position.z;
    float v4 = rdVector_Normalize3Acc(&ret);
    float ctxb = sqrt(v4 * v4 * a / d);
    ret.x = ret.x * ctxb;
    ret.y = ret.y * ctxb;
    ret.z = ret.z * ctxb;
    sithCogVm_PushVector3(ctx, &ret);
}

void jkCog_dwPlayCammySpeech(sithCog* ctx)
{
    int a = sithCogVm_PopInt(ctx);
    int b = sithCogVm_PopFlex(ctx);
    char* c = sithCogVm_PopString(ctx);
    int d = sithCogVm_PopInt(ctx);
}

void jkCog_dwGetActivateBin(sithCog *ctx)
{
    sithCogVm_PushInt(ctx, sithInventory_GetCurItem(g_localPlayerThing));
}
#endif

void jkCog_RegisterVerbs()
{
    sithCogScript_RegisterVerb(g_cog_symbolTable, sithCogFunctionPlayer_GetLocalPlayerThing, "jkgetlocalplayer");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_SetFlags, "jksetflags");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_GetFlags, "jkgetflags");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_ClearFlags, "jkclearflags");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_EndLevel, "jkendlevel");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_PrintUniString, "jkprintunistring");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_SetPovModel, "jksetpovmodel");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_PlayPovKey, "jkplaypovkey");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_StopPovKey, "jkstoppovkey");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_SetWeaponMesh, "jksetweaponmesh");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_EnableSaber, "jkenablesaber");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_DisableSaber, "jkdisablesaber");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_SetSaberInfo, "jksetsaberinfo");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_SetPersuasionInfo, "jksetpersuasioninfo");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_SetForceSpeed, "jksetforcespeed");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_SetInvis, "jksetinvis");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_SetInvulnerable, "jksetinvulnerable");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_SetWaggle, "jksetwaggle");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_SetSuperFlags, "jksetsuperflags");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_ClearSuperFlags, "jkclearsuperflags");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_GetSuperFlags, "jkgetsuperflags");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_SetTarget, "jksettarget");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_EndTarget, "jkendtarget");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_SetTargetColors, "jksettargetcolors");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_StringClear, "jkstringclear");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_StringConcatSpace, "jkstringconcatspace");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_StringConcatUnistring, "jkstringconcatunistring");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_StringConcatAsciiString, "jkstringconcatasciistring");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_StringConcatPlayerName, "jkstringconcatplayername");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_StringConcatInt, "jkstringconcatint");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_StringConcatFormattedInt, "jkstringconcatformattedint");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_StringConcatFlex, "jkstringconcatflex");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_StringConcatFormattedFlex, "jkstringconcatformattedflex");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_StringConcatVector, "jkstringconcatvector");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_StringOutput, "jkstringoutput");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_GetSaberCam, "jkgetsabercam");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_GetChoice, "jkgetchoice");
    
#ifdef QOL_IMPROVEMENTS
    // Added for droidwork tests
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_dwGetActivateBin, "dwGetActivateBin");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_stub1Args, "dwsetreftopic");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_addBeam, "addbeam");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_addLaser, "addlaser");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_removeLaser, "removelaser");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_getLaserId, "getlaserid");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_stub0Args, "dwFlashInventory");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_dwPlayCammySpeech, "dwplaycammyspeech");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_stub0Args, "dwfreezeplayer");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_stub0Args, "dwunfreezeplayer");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_stub2Args, "dwplaycharacterspeech");
    sithCogScript_RegisterVerb(g_cog_symbolTable, jkCog_stub0Args, "dwcleardialog");
#endif
}

int jkCog_Initialize()
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
    int v3; // edx
    int v5; // edi

    flags = sithCogVm_PopInt(ctx);
    thing = sithCogVm_PopThing(ctx);
    if ( thing )
    {
        if ( flags )
        {
            v3 = thing->jkFlags;
            thing->jkFlags = v3 | flags;
            if ( sithCogVm_multiplayerFlags != 0 && (ctx->flags & 0x200) == 0 )
            {
                v5 = ctx->trigId;
                if ( v5 != SITH_MESSAGE_STARTUP && v5 != SITH_MESSAGE_SHUTDOWN && v3 != (v3 | flags) )
                    sithThing_SyncThingPos(thing, 2);
            }
        }
    }
}

void jkCog_ClearFlags(sithCog *ctx)
{
    signed int v1; // esi
    sithThing *v2; // eax
    int v3; // ecx
    int v4; // esi
    int v6; // edi

    v1 = sithCogVm_PopInt(ctx);
    v2 = sithCogVm_PopThing(ctx);
    if ( v2 )
    {
        if ( v1 )
        {
            v3 = v2->jkFlags;
            v4 = v3 & ~v1;
            v2->jkFlags = v4;
            if ( sithCogVm_multiplayerFlags && (ctx->flags & 0x200) == 0 )
            {
                v6 = ctx->trigId;
                if ( v6 != SITH_MESSAGE_STARTUP && v6 != SITH_MESSAGE_SHUTDOWN && v3 != v4 )
                    sithThing_SyncThingPos(v2, 2);
            }
        }
    }
}

void jkCog_GetFlags(sithCog *ctx)
{
    int v1; // esi
    sithThing *v2; // eax

    v1 = 0;
    v2 = sithCogVm_PopThing(ctx);
    if ( v2 )
        v1 = v2->jkFlags;
    sithCogVm_PushInt(ctx, v1);
}

void jkCog_SetWeaponMesh(sithCog *ctx)
{
    rdModel3 *model3; // edi
    sithThing *actorThing; // eax
    sithThing *v3; // ebx
    jkPlayerInfo *v4; // eax
    rdThing *v5; // esi
    int v6; // eax

    model3 = sithCogVm_PopModel3(ctx);
    actorThing = sithCogVm_PopThing(ctx);
    v3 = actorThing;
    if ( actorThing )
    {
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
                    if ( sithCogVm_multiplayerFlags )
                    {
                        if ( (ctx->flags & 0x200) == 0 )
                        {
                            v6 = ctx->trigId;
                            if ( v6 != SITH_MESSAGE_STARTUP && v6 != SITH_MESSAGE_SHUTDOWN )
                                jkSaber_cogMsg_SendJKSetWeaponMesh(v3);
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

    v1 = sithCogVm_PopInt(ctx) != 0;
    if ( sithNet_isMulti )
    {
        if ( sithNet_isServer )
            jkSaber_cogMsg_SendEndLevel();
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

    model3 = sithCogVm_PopModel3(ctx);
    actorThing = sithCogVm_PopThing(ctx);
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

    v1 = sithCogVm_PopInt(ctx);
    v2 = sithCogVm_PopInt(ctx);
    keyframe = sithCogVm_PopKeyframe(ctx);
    actorThing = sithCogVm_PopThing(ctx);
    if ( actorThing
      && keyframe
      && ((v5 = actorThing->type, v5 == SITH_THING_ACTOR) || v5 == SITH_THING_PLAYER)
      && (v6 = actorThing->playerInfo->povModel.puppet) != 0 )
    {
        v7 = sithPuppet_StartKey(v6, keyframe, v2, v2 + 2, v1, 0);
        sithCogVm_PushInt(ctx, v7);
    }
    else
    {
        sithCogVm_PushInt(ctx, -1);
    }
}

void jkCog_StopPovKey(sithCog *ctx)
{
    int v2; // edi
    sithThing *actorThing; // eax
    rdPuppet *v5; // eax
    float a1a; // [esp+Ch] [ebp+4h]

    a1a = sithCogVm_PopFlex(ctx);
    v2 = sithCogVm_PopInt(ctx);
    actorThing = sithCogVm_PopThing(ctx);
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

void jkCog_EndTarget(sithCog *ctx)
{
    jkHud_EndTarget();
}

void jkCog_SetSuperFlags(sithCog *ctx)
{
    int flags = sithCogVm_PopInt(ctx);

    if ( (flags & 1) != 0 )
        playerThings[playerThingIdx].field_21C = 1;
    if ( (flags & 2) != 0 )
        playerThings[playerThingIdx].shields = 1;
    if ( (flags & 4) != 0 )
        playerThings[playerThingIdx].field_224 = 1;
}

void jkCog_ClearSuperFlags(sithCog *ctx)
{
    int flags = sithCogVm_PopInt(ctx);

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
    sithCogVm_PushInt(cog, flags);
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

    v1 = sithCogVm_PopInt(ctx);
    v2 = sithCogVm_PopInt(ctx);

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
LABEL_8:
            jkDev_PrintUniString(v4);
            return;
        }
        if ( sithCogVm_multiplayerFlags )
        {
            if ( (ctx->flags & 0x200) == 0 )
            {
                v6 = ctx->trigId;
                if ( v6 != SITH_MESSAGE_STARTUP && v6 != SITH_MESSAGE_SHUTDOWN && v3 < jkPlayer_maxPlayers && (jkPlayer_playerInfos[v3].flags & 1) != 0 )
                    jkSaber_cogMsg_SendJKPrintUniString(v1, v3);
            }
        }
    }
    else
    {
        if ( v3 != -3 )
        {
            if ( v3 != -1 )
                return;
            goto LABEL_8;
        }
        jkDev_PrintUniString(v4);
        if ( sithCogVm_multiplayerFlags )
        {
            if ( (ctx->flags & 0x200) == 0 )
            {
                v5 = ctx->trigId;
                if ( v5 != SITH_MESSAGE_STARTUP && v5 != SITH_MESSAGE_SHUTDOWN )
                    jkSaber_cogMsg_SendJKPrintUniString(v1, 0xFFFFFFFF);
            }
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

    v1 = sithCogVm_PopInt(ctx);
    v2 = sithCogVm_PopInt(ctx);
    v3 = sithCogVm_PopThing(ctx);
    v4 = v3->playerInfo;
    v4->maxTwinkles = v2;
    v4->twinkleSpawnRate = v1;
    if ( sithCogVm_multiplayerFlags )
    {
        if ( (ctx->flags & 0x200) == 0 )
        {
            v5 = ctx->trigId;
            if ( v5 != SITH_MESSAGE_STARTUP && v5 != SITH_MESSAGE_SHUTDOWN )
                jkSaber_cogMsg_SendJKSetWeaponMesh(v3);
        }
    }
}

void jkCog_SetTarget(sithCog *ctx)
{
    sithThing *v1; // eax

    v1 = sithCogVm_PopThing(ctx);
    jkHud_SetTarget(v1);
}

void jkCog_SetTargetColors(sithCog *ctx)
{
    int tmp[3]; // [esp+4h] [ebp-Ch] BYREF

    tmp[0] = sithCogVm_PopInt(ctx);
    tmp[1] = sithCogVm_PopInt(ctx);
    tmp[2] = sithCogVm_PopInt(ctx);
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

    saber_sparks = sithCogVm_PopTemplate(ctx);
    blood_sparks = sithCogVm_PopTemplate(ctx);
    wall_sparks = sithCogVm_PopTemplate(ctx);
    len = sithCogVm_PopFlex(ctx);
    tip_rad = sithCogVm_PopFlex(ctx);
    base_rad = sithCogVm_PopFlex(ctx);
    v9 = sithCogVm_PopMaterial(ctx);
    v10 = sithCogVm_PopMaterial(ctx);
    v4 = sithCogVm_PopThing(ctx);
    if ( v4->playerInfo )
    {
        jkSaber_InitializeSaberInfo(v4, v10->mat_fpath, v9->mat_fpath, base_rad, tip_rad, len, wall_sparks, blood_sparks, saber_sparks);
        if ( sithCogVm_multiplayerFlags )
        {
            if ( (ctx->flags & 0x200) == 0 )
            {
                v5 = ctx->trigId;
                if ( v5 != SITH_MESSAGE_STARTUP && v5 != SITH_MESSAGE_SHUTDOWN )
                {
                    jkSaber_cogMsg_SendSetSaberInfo(v4);
                    jkSaber_cogMsg_SendSetSaberInfo2(v4);
                }
            }
        }
    }
}

void jkCog_GetSaberCam(sithCog *ctx)
{
    sithCogVm_PushInt(ctx, jkPlayer_setSaberCam);
}

void jkCog_EnableSaber(sithCog *ctx)
{
    sithThing *v2; // eax
    sithThing *v3; // esi
    float a3; // [esp+4h] [ebp-8h]
    float a2; // [esp+8h] [ebp-4h]
    float a1a; // [esp+10h] [ebp+4h]

    a1a = sithCogVm_PopFlex(ctx);
    a3 = sithCogVm_PopFlex(ctx);
    a2 = sithCogVm_PopFlex(ctx);
    v2 = sithCogVm_PopThing(ctx);
    v3 = v2;
    if ( v2 && v2->type == SITH_THING_PLAYER )
    {
        jkSaber_Enable(v2, a2, a3, a1a);
        if ( sithCogVm_multiplayerFlags )
            jkSaber_cogMsg_SendJKEnableSaber(v3);
    }
}

void jkCog_DisableSaber(sithCog *ctx)
{
    sithThing *v1; // eax

    v1 = sithCogVm_PopThing(ctx);
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

    a1a = sithCogVm_PopFlex(ctx);
    sithCogVm_PopVector3(ctx, &a2);
    v2 = sithCogVm_PopThing(ctx);
    if ( v2 )
    {
        if ( v2->type == SITH_THING_PLAYER )
            jkPlayer_SetWaggle(v2, &a2, a1a);
    }
}

void jkCog_GetChoice(sithCog *ctx)
{
    sithCogVm_PushInt(ctx, jkPlayer_GetChoice());
}

void jkCog_StringClear()
{
    _wcscpy(jkCog_jkstring, jkCog_emptystring);
}

void jkCog_StringConcatFormattedInt(sithCog *ctx)
{
    char *v1; // esi
    signed int v2; // eax
    signed int v3; // ebx
    size_t v4; // esi
    wchar_t v5[130]; // [esp+Ch] [ebp-208h] BYREF
    wchar_t v6[130]; // [esp+110h] [ebp-104h] BYREF

    v1 = sithCogVm_PopString(ctx);
    v2 = sithCogVm_PopInt(ctx);
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
    v4 = _wcslen(v5);
    if ( _wcslen(jkCog_jkstring) + v4 < 0x81 )
        __wcscat(jkCog_jkstring, v5);
}

void jkCog_StringOutput(sithCog *ctx)
{
    int v1; // ebx
    int v2; // esi
    int v3; // edi
    int v4; // edi
    char v5[128]; // [esp+Ch] [ebp-80h] BYREF

    v1 = sithCogVm_PopInt(ctx);
    v2 = sithCogVm_PopInt(ctx);
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
        if ( sithCogVm_multiplayerFlags )
        {
            if ( (ctx->flags & 0x200) == 0 )
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
        if ( sithCogVm_multiplayerFlags )
        {
            if ( (ctx->flags & 0x200) == 0 )
            {
                v3 = ctx->trigId;
                if ( v3 != SITH_MESSAGE_STARTUP && v3 != SITH_MESSAGE_SHUTDOWN )
                    sithMulti_SendChat(v5, -1, v1);
            }
        }
    }
}
