#include "jkCog.h"

#include "General/stdStrTable.h"
#include "Main/jkHud.h"

#include "jk.h"

void jkCog_EndTarget(sithCog *ctx);

static void (*sithCogPlayer_GetLocalPlayerThing)(sithCog* ctx) = (void*)0x004E0DA0;

static void (*jkCog_SetFlags)(sithCog* ctx) = (void*)0x0040A3E0;
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
static void (*jkCog_PrintUniString)(sithCog* ctx) = (void*)0x0040A800;
static void (*jkCog_SetSuperFlags)(sithCog* ctx) = (void*)0x0040A970;
static void (*jkCog_ClearSuperFlags)(sithCog* ctx) = (void*)0x0040A9E0;
static void (*jkCog_GetSuperFlags)(sithCog* ctx) = (void*)0x0040AA50;
static void (*jkCog_EnableSaber)(sithCog* ctx) = (void*)0x0040AAA0;
static void (*jkCog_DisableSaber)(sithCog* ctx) = (void*)0x0040AB20;
static void (*jkCog_SetWaggle)(sithCog* ctx) = (void*)0x0040AB50;
static void (*jkCog_SetSaberInfo)(sithCog* ctx) = (void*)0x0040ABA0;
static void (*jkCog_SetPersuasionInfo)(sithCog* ctx) = (void*)0x0040AC90;
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

void jkCog_EndTarget(sithCog *ctx)
{
    jkHud_EndTarget();
}
