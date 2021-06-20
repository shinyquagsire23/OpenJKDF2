#include "jkCog.h"

#include "General/stdStrTable.h"
#include "Main/jkHud.h"
#include "Main/jkDev.h"
#include "Main/jkStrings.h"
#include "World/jkPlayer.h"
#include "World/jkSaber.h"
#include "World/sithPlayer.h"
#include "General/stdString.h"
#include "Cog/sithCogPlayer.h"

#include "jk.h"

void jkCog_SetFlags(sithCog *ctx);
void jkCog_EndTarget(sithCog *ctx);
void jkCog_SetSuperFlags(sithCog *ctx);
void jkCog_ClearSuperFlags(sithCog *ctx);
void jkCog_PrintUniString(sithCog *ctx);
void jkCog_SetPersuasionInfo(sithCog *ctx);
void jkCog_SetSaberInfo(sithCog *ctx);


//static void (*jkCog_SetFlags)(sithCog* ctx) = (void*)0x0040A3E0;
static void (*jkCog_ClearFlags)(sithCog* ctx) = (void*)0x0040A450;
static void (*jkCog_GetFlags)(sithCog* ctx) = (void*)0x0040A4C0;
static void (*jkCog_SetWeaponMesh)(sithCog* ctx) = (void*)0x0040A4F0;
static void (*jkCog_EndLevel)(sithCog* ctx) = (void*)0x0040A580;
static void (*jkCog_SetPovModel)(sithCog* ctx) = (void*)0x0040A5D0;
static void (*jkCog_PlayPovKey)(sithCog* ctx) = (void*)0x0040A620;
static void (*jkCog_StopPovKey)(sithCog* ctx) = (void*)0x0040A6B0;
static void (*jkCog_SetForceSpeed)(sithCog* ctx) = (void*)0x0040A710;
static void (*jkCog_SetInvis)(sithCog* ctx) = (void*)0x0040A730;
static void (*jkCog_SetInvulnerable)(sithCog* ctx) = (void*)0x0040A7A0;
//jkCog_PrintUniString
//jkCog_SetSuperFlags 
//jkCog_ClearSuperFlags
static void (*jkCog_GetSuperFlags)(sithCog* ctx) = (void*)0x0040AA50;
static void (*jkCog_EnableSaber)(sithCog* ctx) = (void*)0x0040AAA0;
static void (*jkCog_DisableSaber)(sithCog* ctx) = (void*)0x0040AB20;
static void (*jkCog_SetWaggle)(sithCog* ctx) = (void*)0x0040AB50;
//static void (*jkCog_SetSaberInfo)(sithCog* ctx) = (void*)0x0040ABA0;
//static void (*jkCog_SetPersuasionInfo)(sithCog* ctx) = (void*)0x0040AC90;
static void (*jkCog_SetTarget)(sithCog* ctx) = (void*)0x0040AD00;
static void (*jkCog_SetTargetColors)(sithCog* ctx) = (void*)0x0040AD30;
static void (*jkCog_StringClear)(sithCog* ctx) = (void*)0x0040AD80;
static void (*jkCog_StringConcatUnistring)(sithCog* ctx) = (void*)0x0040ADA0;
static void (*jkCog_StringConcatAsciiString)(sithCog* ctx) = (void*)0x0040AE30;
static void (*jkCog_StringConcatPlayerName)(sithCog* ctx) = (void*)0x0040AEB0;
static void (*jkCog_StringConcatSpace)(sithCog* ctx) = (void*)0x0040AF10;
static void (*jkCog_StringConcatInt)(sithCog* ctx) = (void*)0x0040AF70;
static void (*jkCog_StringConcatFormattedInt)(sithCog* ctx) = (void*)0x0040AFE0;
static void (*jkCog_StringConcatFlex)(sithCog* ctx) = (void*)0x0040B090;
static void (*jkCog_StringConcatFormattedFlex)(sithCog* ctx) = (void*)0x0040B100;
static void (*jkCog_StringConcatVector)(sithCog* ctx) = (void*)0x0040B1C0;
static void (*jkCog_StringOutput)(sithCog* ctx) = (void*)0x0040B270;
static void (*jkCog_GetSaberCam)(sithCog* ctx) = (void*)0x0040B3B0;
static void (*jkCog_GetChoice)(sithCog* ctx) = (void*)0x0040B3D0;

void jkCog_RegisterVerbs()
{
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)sithCogPlayer_GetLocalPlayerThing, "jkgetlocalplayer");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_SetFlags, "jksetflags");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_GetFlags, "jkgetflags");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_ClearFlags, "jkclearflags");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_EndLevel, "jkendlevel");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_PrintUniString, "jkprintunistring");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_SetPovModel, "jksetpovmodel");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_PlayPovKey, "jkplaypovkey");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_StopPovKey, "jkstoppovkey");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_SetWeaponMesh, "jksetweaponmesh");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_EnableSaber, "jkenablesaber");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_DisableSaber, "jkdisablesaber");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_SetSaberInfo, "jksetsaberinfo");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_SetPersuasionInfo, "jksetpersuasioninfo");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_SetForceSpeed, "jksetforcespeed");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_SetInvis, "jksetinvis");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_SetInvulnerable, "jksetinvulnerable");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_SetWaggle, "jksetwaggle");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_SetSuperFlags, "jksetsuperflags");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_ClearSuperFlags, "jkclearsuperflags");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_GetSuperFlags, "jkgetsuperflags");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_SetTarget, "jksettarget");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_EndTarget, "jkendtarget");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_SetTargetColors, "jksettargetcolors");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_StringClear, "jkstringclear");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_StringConcatSpace, "jkstringconcatspace");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_StringConcatUnistring, "jkstringconcatunistring");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_StringConcatAsciiString, "jkstringconcatasciistring");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_StringConcatPlayerName, "jkstringconcatplayername");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_StringConcatInt, "jkstringconcatint");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_StringConcatFormattedInt, "jkstringconcatformattedint");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_StringConcatFlex, "jkstringconcatflex");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_StringConcatFormattedFlex, "jkstringconcatformattedflex");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_StringConcatVector, "jkstringconcatvector");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_StringOutput, "jkstringoutput");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_GetSaberCam, "jkgetsabercam");
    sithCogScript_RegisterVerb(g_cog_symbolTable, (intptr_t)jkCog_GetChoice, "jkgetchoice");
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

#ifdef LINUX_TMP
    return;
#endif

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
