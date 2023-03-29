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
#include "Dss/sithMulti.h"
#include "General/stdString.h"
#include "Cog/sithCogFunctionPlayer.h"
#include "Dss/jkDSS.h"
#include "General/stdMath.h"
#include "Main/jkEpisode.h"
#include "Main/jkGame.h"
#include "World/sithSector.h"
#include "Win95/Windows.h"

#include "jk.h"

// MOTS added
int jkCog_bubbleIdx = 0;

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

    // Added: clean reset
    jkCog_bubbleIdx = 0;
}

int jkCog_StringsInit()
{
    // Added: HACK HACK HACK
    // TODO AAAAAAAAAAAAAAAAA UAF hell
    stdStrTable_Free(&jkCog_strings);
    //memset(&jkCog_strings, 0, sizeof(jkCog_strings));


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
            jkPlayer_FUN_00404fe0(actorThing);
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
                    if ( COG_SHOULD_SYNC(ctx) )
                    {
                        jkDSS_SendJKSetWeaponMesh(v3);
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
    if ( COG_SHOULD_SYNC(pCog) )
    {
        sithThing_SetSyncFlags(v2, THING_SYNC_STATE);
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
    if ( COG_SHOULD_SYNC(pCog) )
    {
        sithThing_SetSyncFlags(v2, THING_SYNC_STATE);
    }
}

// MOTS added
void jkCog_SyncForcePowers(sithCog *ctx)
{
    jkPlayer_SyncForcePowers(jkPlayer_GetJediRank(),sithNet_isMulti);
}

void jkCog_EndTarget(sithCog *ctx)
{
    jkHud_EndTarget();
}

void jkCog_SetSuperFlags(sithCog *ctx)
{
    int flags = sithCogExec_PopInt(ctx);

    if ( (flags & 1) != 0 )
        playerThings[playerThingIdx].bHasSuperWeapon = 1;
    if ( (flags & 2) != 0 )
        playerThings[playerThingIdx].bHasSuperShields = 1;
    if ( (flags & 4) != 0 )
        playerThings[playerThingIdx].bHasForceSurge = 1;
}

void jkCog_ClearSuperFlags(sithCog *ctx)
{
    int flags = sithCogExec_PopInt(ctx);

    if ( (flags & 1) != 0 )
        playerThings[playerThingIdx].bHasSuperWeapon = 0;
    if ( (flags & 2) != 0 )
        playerThings[playerThingIdx].bHasSuperShields = 0;
    if ( (flags & 4) != 0 )
        playerThings[playerThingIdx].bHasForceSurge = 0;
}

void jkCog_GetSuperFlags(sithCog *cog)
{
    int flags = 0;

    // Added: Original used +, not |
    if (playerThings[playerThingIdx].bHasSuperWeapon)
        flags |= 1;
    if ( playerThings[playerThingIdx].bHasSuperShields )
        flags |= 2;
    if ( playerThings[playerThingIdx].bHasForceSurge )
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

    // Added: Allow openjkdf2_i8n.uni to override everything
#ifdef QOL_IMPROVEMENTS
    v4 = stdStrTable_GetUniString(&jkStrings_tableExtOver, key);
    if ( !v4 )
#endif

    v4 = stdStrTable_GetUniString(&jkCog_strings, key);
    if ( !v4 )
        v4 = jkStrings_GetUniStringWithFallback(key);
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

// MOTS added
void jkCog_PrintUniVoice(sithCog *ctx)
{
    if (jkPlayer_setFullSubtitles != 0) {
        jkCog_PrintUniString(ctx);
    }
    sithCogExec_PopInt(ctx);
    sithCogExec_PopInt(ctx);
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
        if ( COG_SHOULD_SYNC(ctx))
        {
            if (Main_bMotsCompat) {
                jkDSS_SendSetSaberInfoMots(v4, 1000);
                jkDSS_SendSetSaberInfo2(v4);
            }
            else {
                jkDSS_SendSetSaberInfo(v4);
                jkDSS_SendSetSaberInfo2(v4);
            }
        }
    }
}

// MOTS added
void jkCog_GetSaberSideMat(sithCog *ctx)
{
    sithThing* pPlayerThing = sithCogExec_PopThing(ctx);
    if (pPlayerThing->playerInfo) {
        sithCogExec_PushInt(ctx,((pPlayerThing->playerInfo->polyline).edgeFace.material)->id);
    }
    // TODO bugfix: push a -1??
    return;
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

// Added: Allow openjkdf2_i8n.uni to override everything
#ifdef QOL_IMPROVEMENTS
    str = stdStrTable_GetUniString(&jkStrings_tableExtOver, key);
    if ( !str )
#endif

    str = stdStrTable_GetUniString(&jkCog_strings, key);
    if ( !str )
        str = jkStrings_GetUniStringWithFallback(key);

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

// MOTS added
void jkCog_BeginCutscene(sithCog *ctx)
{
    jkGuiMultiplayer_mpcInfo.pCutsceneCog = ctx;
    if (sithPlayer_pLocalPlayerThing) {
        sithPlayer_pLocalPlayerThing->actorParams.typeflags |= SITH_AF_NOHUD;
    }
}

// MOTS added
void jkCog_EndCutscene(sithCog *ctx)
{
    jkGuiMultiplayer_mpcInfo.pCutsceneCog = NULL;
    if (sithPlayer_pLocalPlayerThing) {
        sithPlayer_pLocalPlayerThing->actorParams.typeflags &= ~SITH_AF_NOHUD;
    }
}

// MOTS added
void jkCog_StartupCutscene(sithCog *ctx)
{
    char *pStr;
    
    pStr = sithCogExec_PopString(ctx);
    if (pStr) {
        jkMain_StartupCutscene(pStr);
    }
    return;
}


// MOTS added
void jkCog_GetMultiParam(sithCog *ctx)
{
    uint32_t idx = sithCogExec_PopInt(ctx);
    if (idx < 0x100) {
        sithCogExec_PushFlex(ctx, jkPlayer_aMultiParams[idx]);
        return;
    }
    sithCogExec_PushFlex(ctx, 0.0);
}

// MOTS added
void jkCog_InsideLeia(sithCog *ctx)
{
    sithCogExec_PushInt(ctx,0);
}

// MOTS added
void jkCog_CreateBubble(sithCog *ctx)
{
    int type = sithCogExec_PopInt(ctx);
    float radius = sithCogExec_PopFlex(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);

    if (pThing && radius > 0.0) {
        jkEpisode_CreateBubble(pThing, radius, type);
    }
}

// MOTS added
void jkCog_DestroyBubble(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing) {
        jkEpisode_DestroyBubble(pThing);
    }
}

// MOTS added
void jkCog_GetBubbleDistance(sithCog *ctx)
{
    int iVar1;
    float tmp;
    
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing == sithPlayer_pLocalPlayerThing) {
        iVar1 = playerThings[playerThingIdx].jkmUnk4;
        tmp = playerThings[playerThingIdx].jkmUnk6;
    }
    else {
        iVar1 = jkEpisode_GetBubbleInfo(pThing, NULL, NULL,&tmp);
    }

    if (iVar1 != 0) {
        sithCogExec_PushFlex(ctx,stdMath_Sqrt(tmp));
        return;
    }
    sithCogExec_PushFlex(ctx, 1000000.0);
}

// MOTS added
void jkCog_ThingInBubble(sithCog *ctx)
{
    sithThing *pThingOut = NULL;

    sithThing* pThing = sithCogExec_PopThing(ctx);
    int iVar1 = jkEpisode_GetBubbleInfo(pThing, NULL, &pThingOut, NULL);
    if (iVar1 != 0) {
        sithCogExec_PushInt(ctx,pThingOut->thingIdx);
        return;
    }
    sithCogExec_PushInt(ctx,-1);
}

// MOTS added
void jkCog_GetFirstBubble(sithCog *ctx)
{
    jkCog_bubbleIdx = 0;
    for (int i = 0; i < 64; i++) {
        if (jkPlayer_aBubbleInfo[i].pThing) break;
        jkCog_bubbleIdx = jkCog_bubbleIdx + 1;
    }
    if (jkCog_bubbleIdx < 0x40) {
        sithCogExec_PushInt(ctx,(jkPlayer_aBubbleInfo[jkCog_bubbleIdx].pThing)->thingIdx);
        return;
    }
    sithCogExec_PushInt(ctx,-1);
}

// MOTS added
void jkCog_GetNextBubble(sithCog *ctx)
{
    for (int i = jkCog_bubbleIdx; i < 64; i++) {
        if (jkPlayer_aBubbleInfo[i].pThing) break;
        jkCog_bubbleIdx = jkCog_bubbleIdx + 1;
    }
    if (jkCog_bubbleIdx < 0x40) {
        sithCogExec_PushInt(ctx,(jkPlayer_aBubbleInfo[jkCog_bubbleIdx].pThing)->thingIdx);
        return;
    }
    sithCogExec_PushInt(ctx,-1);
}

// MOTS added
void jkCog_GetBubbleType(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    for (int i = 0; i < 64; i++) {
        if (jkPlayer_aBubbleInfo[i].pThing == pThing) {
            sithCogExec_PushInt(ctx,jkPlayer_aBubbleInfo[i].type);
            return;
        }
    }
    sithCogExec_PushInt(ctx,-1);
}

// MOTS added
void jkCog_GetBubbleRadius(sithCog *ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    for (int i = 0; i < 64; i++) {
        if (jkPlayer_aBubbleInfo[i].pThing == pThing) {
            sithCogExec_PushFlex(ctx,stdMath_Sqrt(jkPlayer_aBubbleInfo[i].radiusSquared));
            return;
        }
    }
    sithCogExec_PushInt(ctx,-1);
}

// MOTS added
void jkCog_SetBubbleType(sithCog *ctx)
{
    int val = sithCogExec_PopInt(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    for (int i = 0; i < 64; i++) 
    {
        if (jkPlayer_aBubbleInfo[i].pThing == pThing) {
            jkPlayer_aBubbleInfo[i].type = val;
            return;
        }
    }
}

// MOTS added
void jkCog_SetBubbleRadius(sithCog *ctx)
{
    float val = sithCogExec_PopFlex(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    for (int i = 0; i < 64; i++) 
    {
        if (jkPlayer_aBubbleInfo[i].pThing == pThing) {
            jkPlayer_aBubbleInfo[i].radiusSquared = val * val;
            return;
        }
    }
}

// MOTS added
void jkCog_Screenshot(sithCog *ctx)
{
    jkGame_Screenshot();
}

// MOTS added
void jkCog_GetOpenFrames(sithCog *ctx)
{
    sithCogExec_PushInt(ctx,Video_dword_5528A0);
}

void jkCog_RegisterVerbsExt();

void jkCog_RegisterVerbs()
{
    if (Main_bMotsCompat) {
        sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 45, "enterbubble");
        sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 46, "exitbubble");
    }
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, sithCogFunctionPlayer_GetLocalPlayerThing, "jkgetlocalplayer");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_SetFlags, "jksetflags");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_GetFlags, "jkgetflags");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_ClearFlags, "jkclearflags");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_EndLevel, "jkendlevel");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_PrintUniString, "jkprintunistring");
    if (Main_bMotsCompat) {
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_PrintUniVoice, "jkprintunivoice");
    }
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_SetPovModel, "jksetpovmodel");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_PlayPovKey, "jkplaypovkey");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_StopPovKey, "jkstoppovkey");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_SetWeaponMesh, "jksetweaponmesh");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_EnableSaber, "jkenablesaber");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_DisableSaber, "jkdisablesaber");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_SetSaberInfo, "jksetsaberinfo");
    if (Main_bMotsCompat) {
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_GetSaberSideMat, "jkgetsabersidemat");
    }
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_SetPersuasionInfo, "jksetpersuasioninfo");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_SetForceSpeed, "jksetforcespeed");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_SetInvis, "jksetinvis");
    sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_SetInvulnerable, "jksetinvulnerable");
    if (Main_bMotsCompat) {
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_SyncForcePowers, "jksyncforcepowers");
    }
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

    if (Main_bMotsCompat) {
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_BeginCutscene,"jkbegincutscene");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_EndCutscene,"jkendcutscene");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_StartupCutscene,"jkstartupcutscene");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_GetMultiParam,"jkgetmultiparam");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_InsideLeia,"insideleia");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_CreateBubble,"jkcreatebubble");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_DestroyBubble,"jkdestroybubble");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_GetBubbleDistance,"jkgetbubbledistance");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_ThingInBubble,"jkthinginbubble");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_GetFirstBubble,"jkgetfirstbubble");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_GetNextBubble,"jkgetnextbubble");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_GetBubbleType,"jkgetbubbletype");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_GetBubbleRadius,"jkgetbubbleradius");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_SetBubbleType,"jksetbubbletype");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_SetBubbleRadius,"jksetbubbleradius");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_Screenshot,"jkscreenshot");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_GetOpenFrames,"jkgetopenframes");
    }
    
#ifdef QOL_IMPROVEMENTS
    if (Main_bDwCompat) {
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
    }
#endif
}

/*
void jkCogExt_(sithCog* ctx)
{

}
*/

void jkCogExt_GetThingAttachSurface(sithCog* ctx)
{
    int retval = -1;
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
    {
        if (pThing->attach_flags == SITH_ATTACH_WORLDSURFACE) {
            sithSurface* pAttached = pThing->attachedSurface;
            if (pAttached) {
                retval = pAttached->field_0;
            }
        }
    }
    sithCogExec_PushInt(ctx, retval);
}

void jkCogExt_GetThingAttachThing(sithCog* ctx)
{
    int retval = -1;
    sithThing* pThing = sithCogExec_PopThing(ctx);
    if (pThing)
    {
        if (pThing->attach_flags == SITH_ATTACH_THINGSURFACE) {
            sithThing* pAttached = pThing->attachedThing;
            if (pAttached) {
                retval = pAttached->thing_id;
            }
        }
    }
    sithCogExec_PushInt(ctx, retval);
}

void jkCogExt_GetCameraFov(sithCog* ctx)
{
    int camIdx = sithCogExec_PopInt(ctx);

    // TODO verify
    sithCogExec_PushFlex(ctx, sithCamera_cameras[camIdx].rdCam.fov);
    Windows_ErrorMsgboxWide("Unimplemented %s\n", __func__);
}

void jkCogExt_GetCameraOffset(sithCog* ctx)
{
    int camIdx = sithCogExec_PopInt(ctx);

    //TODO
    rdVector3 vec = {0};
    sithCogExec_PushVector3(ctx, &vec);
    Windows_ErrorMsgboxWide("Unimplemented %s\n", __func__);
}

void jkCogExt_SetCameraFov(sithCog* ctx)
{
    float fov = sithCogExec_PopFlex(ctx);
    int camIdx = sithCogExec_PopInt(ctx);

    // TODO
    sithCamera_cameras[camIdx].rdCam.fov = fov;
    Windows_ErrorMsgboxWide("Unimplemented %s\n", __func__);
}

void jkCogExt_SetCameraOffset(sithCog* ctx)
{
    rdVector3 vec;
    sithCogExec_PopVector3(ctx, &vec);
    int camIdx = sithCogExec_PopInt(ctx);

    // TODO
    Windows_ErrorMsgboxWide("Unimplemented %s\n", __func__);
}

void jkCogExt_Absolute(sithCog* ctx)
{
    float val = sithCogExec_PopFlex(ctx);

    if (val == (int)val) {
        sithCogExec_PushInt(ctx, abs((int)val));
    }
    else {
        sithCogExec_PushFlex(ctx, fabs(val));
    }
}

void jkCogExt_Arccosine(sithCog* ctx)
{
    float val = sithCogExec_PopFlex(ctx);
    sithCogExec_PushFlex(ctx, acos(val) * 57.2957795);
}

void jkCogExt_Arcsine(sithCog* ctx)
{
    float val = sithCogExec_PopFlex(ctx);
    sithCogExec_PushFlex(ctx, asin(val) * 57.2957795);
}

void jkCogExt_Arctangent(sithCog* ctx)
{
    float val = sithCogExec_PopFlex(ctx);
    sithCogExec_PushFlex(ctx, atan(val) * 57.2957795);
}

void jkCogExt_Ceiling(sithCog* ctx)
{
    float val = sithCogExec_PopFlex(ctx);
    sithCogExec_PushFlex(ctx, ceil(val));
}

void jkCogExt_Cosine(sithCog* ctx)
{
    float val = sithCogExec_PopFlex(ctx);
    sithCogExec_PushFlex(ctx, cos(val * 0.0174532925));
}

void jkCogExt_Floor(sithCog* ctx)
{
    float val = sithCogExec_PopFlex(ctx);
    sithCogExec_PushFlex(ctx, floor(val));
}

void jkCogExt_Power(sithCog* ctx)
{
    float b = sithCogExec_PopFlex(ctx);
    float a = sithCogExec_PopFlex(ctx);
    sithCogExec_PushFlex(ctx, pow(a,b));
}

void jkCogExt_Randomflex(sithCog* ctx)
{
    float b = sithCogExec_PopFlex(ctx);
    float a = sithCogExec_PopFlex(ctx);
    float f = _frand();
    float f2 = b-a+1.0;
    sithCogExec_PushFlex(ctx, fmodf(f,f2)+a);
}

void jkCogExt_Randomint(sithCog* ctx)
{
    int b = sithCogExec_PopInt(ctx);
    int a = sithCogExec_PopInt(ctx);
    
    sithCogExec_PushInt(ctx, a + (rand() % (b-a+1)));
}

void jkCogExt_Sine(sithCog* ctx)
{
    float val = sithCogExec_PopFlex(ctx);
    sithCogExec_PushFlex(ctx, sin(val * 0.0174532925));
}

void jkCogExt_Squareroot(sithCog* ctx)
{
    float val = sithCogExec_PopFlex(ctx);
    sithCogExec_PushFlex(ctx, sqrtf(val));
}

void jkCogExt_GetHotkeyCog(sithCog* ctx)
{

}

void jkCogExt_SetHotkeyCog(sithCog* ctx)
{

}

void jkCogExt_IsAdjoin(sithCog* ctx)
{
    sithSurface* pSurface = sithCogExec_PopSurface(ctx);
    int retval = 0;
    if (pSurface && pSurface->adjoin) {
        retval = 1;
    }

    sithCogExec_PushInt(ctx, retval);
}

void jkCogExt_SetGameSpeed(sithCog* ctx)
{
    float val = sithCogExec_PopFlex(ctx);
    float val2 = sithCogExec_PopFlex(ctx);
    //TODO
    Windows_ErrorMsgboxWide("Unimplemented %s\n", __func__);
}

void jkCogExt_GetThingHeadLvec(sithCog* ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);

    // TODO
    rdVector3 vec = {0};
    sithCogExec_PushVector3(ctx, &vec);
    Windows_ErrorMsgboxWide("Unimplemented %s\n", __func__);
}

void jkCogExt_GetThingHeadPitch(sithCog* ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    sithCogExec_PushFlex(ctx, 0.0); // TODO
    Windows_ErrorMsgboxWide("Unimplemented %s\n", __func__);
}

void jkCogExt_GetThingHeadPYR(sithCog* ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);

    // TODO
    rdVector3 vec = {0};
    sithCogExec_PushVector3(ctx, &vec);
    Windows_ErrorMsgboxWide("Unimplemented %s\n", __func__);
}

void jkCogExt_GetThingPYR(sithCog* ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);

    // TODO
    rdVector3 vec = {0};
    sithCogExec_PushVector3(ctx, &vec);
    Windows_ErrorMsgboxWide("Unimplemented %s\n", __func__);
}

void jkCogExt_SetThingHeadPYR(sithCog* ctx)
{
    //TODO
    rdVector3 vec = {0};
    sithCogExec_PopVector3(ctx, &vec);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    Windows_ErrorMsgboxWide("Unimplemented %s\n", __func__);
}

void jkCogExt_SetThingPosEx(sithCog* ctx)
{
    //TODO
    sithSector* pSector = sithCogExec_PopSector(ctx);
    rdVector3 vec = {0};
    sithCogExec_PopVector3(ctx, &vec);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    Windows_ErrorMsgboxWide("Unimplemented %s\n", __func__);
}

void jkCogExt_SetThingPYR(sithCog* ctx)
{
    //TODO
    rdVector3 vec = {0};
    sithCogExec_PopVector3(ctx, &vec);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    Windows_ErrorMsgboxWide("Unimplemented %s\n", __func__);
}

void jkCogExt_SetThingLRUVecs(sithCog* ctx)
{
    //TODO
    rdVector3 vec = {0};
    sithCogExec_PopVector3(ctx, &vec);
    sithCogExec_PopVector3(ctx, &vec);
    sithCogExec_PopVector3(ctx, &vec);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    Windows_ErrorMsgboxWide("Unimplemented %s\n", __func__);
}

void jkCogExt_SetThingSector(sithCog* ctx)
{
    sithSector* pSector = sithCogExec_PopSector(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    sithCogExec_PushInt(ctx, -1); // TODO
    Windows_ErrorMsgboxWide("Unimplemented %s\n", __func__);
}

void jkCogExt_RestoreJoint(sithCog* ctx)
{
    int val = sithCogExec_PopInt(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    Windows_ErrorMsgboxWide("Unimplemented %s\n", __func__);
}

void jkCogExt_GetThingAirDrag(sithCog* ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    sithCogExec_PushFlex(ctx, 0.0); // TODO
    Windows_ErrorMsgboxWide("Unimplemented %s\n", __func__);
}

void jkCogExt_GetThingEyeOffset(sithCog* ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    // TODO
    rdVector3 vec = {0};
    sithCogExec_PushVector3(ctx, &vec);
    Windows_ErrorMsgboxWide("Unimplemented %s\n", __func__);
}

void jkCogExt_GetThingHeadPitchMax(sithCog* ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    sithCogExec_PushFlex(ctx, 0.0); // TODO
    Windows_ErrorMsgboxWide("Unimplemented %s\n", __func__);
}

void jkCogExt_GetThingHeadPitchMin(sithCog* ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    sithCogExec_PushFlex(ctx, 0.0); // TODO
    Windows_ErrorMsgboxWide("Unimplemented %s\n", __func__);
}

void jkCogExt_GetThingJumpSpeed(sithCog* ctx)
{
    sithThing* pThing = sithCogExec_PopThing(ctx);
    sithCogExec_PushFlex(ctx, 0.0); // TODO
    Windows_ErrorMsgboxWide("Unimplemented %s\n", __func__);
}

void jkCogExt_SetThingAirDrag(sithCog* ctx)
{
    float a = sithCogExec_PopFlex(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    Windows_ErrorMsgboxWide("Unimplemented %s\n", __func__);
}

void jkCogExt_SetThingEyeOffset(sithCog* ctx)
{
    //TODO
    rdVector3 vec = {0};
    sithCogExec_PopVector3(ctx, &vec);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    Windows_ErrorMsgboxWide("Unimplemented %s\n", __func__);
}

void jkCogExt_SetThingHeadPitchMinMax(sithCog* ctx)
{
    float a = sithCogExec_PopFlex(ctx);
    float b = sithCogExec_PopFlex(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    Windows_ErrorMsgboxWide("Unimplemented %s\n", __func__);
}

void jkCogExt_SetThingJumpSpeed(sithCog* ctx)
{
    float a = sithCogExec_PopFlex(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    Windows_ErrorMsgboxWide("Unimplemented %s\n", __func__);
}

void jkCogExt_SetThingMesh(sithCog* ctx)
{
    char* a = sithCogExec_PopString(ctx);
    rdModel3* model3 = sithCogExec_PopModel3(ctx);
    char* c = sithCogExec_PopString(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    Windows_ErrorMsgboxWide("Unimplemented %s\n", __func__);
}

void jkCogExt_SetThingParent(sithCog* ctx)
{
    sithThing* pThing2 = sithCogExec_PopThing(ctx);
    sithThing* pThing = sithCogExec_PopThing(ctx);
    Windows_ErrorMsgboxWide("Unimplemented %s\n", __func__);
}

void jkCogExt_SetSaberFaceFlags(sithCog* ctx)
{
    sithThing* pPlayer = sithCogExec_PopThing(ctx);
    int flags = sithCogExec_PopInt(ctx);

    jkPlayerInfo* pPlayerInfo = pPlayer->playerInfo;
    if ( pPlayerInfo && pPlayerInfo->polylineThing.polyline )
    {
        pPlayerInfo->polylineThing.polyline->edgeFace.type = flags;
        pPlayerInfo->polylineThing.polyline->tipFace.type = flags;
    }
}