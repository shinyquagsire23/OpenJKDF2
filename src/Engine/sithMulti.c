#include "sithMulti.h"

#include "Win95/sithDplay.h"
#include "Gameplay/sithEvent.h"
#include "World/sithWorld.h"
#include "World/sithPlayer.h"
#include "Cog/sithCog.h"
#include "Engine/sithCollision.h"
#include "jk.h"
#include "General/sithStrTable.h"
#include "Win95/DebugConsole.h"

void sithMulti_SetHandleridk(sithMultiHandler_t a1)
{
    sithMulti_handlerIdk = a1;
}

#ifndef WIN32_BLOBS
int sithMulti_SendChat(char *a1, int a2, int a3)
{
    return 1;
}
#endif

HRESULT sithMulti_CreatePlayer(const wchar_t *a1, const wchar_t *a2, const char *a3, const char *a4, int a5, int a6, int multiModeFlags, int rate, int a9)
{
    HRESULT result; // eax
    jkMultiEntry multiEntry; // [esp+Ch] [ebp-F0h] BYREF

    _memset(&multiEntry, 0, sizeof(multiEntry));
    _wcsncpy(multiEntry.field_18, a1, 0x1Fu);
    multiEntry.field_18[31] = 0;
    _strncpy(multiEntry.field_58, a3, 0x1Fu);
    multiEntry.field_58[31] = 0;
    _strncpy(multiEntry.field_78, a4, 0x1Fu);
    multiEntry.field_78[31] = 0;
    _wcsncpy(multiEntry.field_98, a2, 0x1Fu);
    multiEntry.field_10 = a5;
    idx_13b4_related = a5;
    multiEntry.field_EC = a9;
    multiEntry.field_98[31] = 0;
    multiEntry.field_E4 = multiModeFlags;
    multiEntry.field_E8 = rate;
    multiEntry.field_D8 = a6;
    if ( sithDplay_dword_8321E0 )
        result = sithDplay_seed_idk(&multiEntry);
    else
        result = sithDplay_CreatePlayer(&multiEntry);
    if ( !result )
    {
        sithNet_dword_83262C = sithDplay_dword_8321EC;
        sithNet_dword_8C4BA8 = 0;
        sithNet_dword_8C4BA4 = sithDplay_dword_8321EC;
        sithNet_isServer = 1;
        sithNet_isMulti = 1;
        sithNet_MultiModeFlags = multiModeFlags;
        sithMulti_multiModeFlags = multiModeFlags;
        sithMulti_multiplayerTimelimit = sithNet_multiplayer_timelimit;
        sithDplay_dword_832204 = sithNet_scorelimit;
        sithNet_tickrate = rate;
#ifdef WIN32_BLOBS // TODO impl
        sithEvent_RegisterFunc(2, sithMulti_ServerLeft, rate, 1); // TODO enum
#endif
        result = 0;
    }
    return result;
}

int sithMulti_Startup()
{
    sithWorld *v0; // ebp
    int *v1; // esi
    int v2; // eax
    int v3; // edi
    int v4; // ebx
    sithThing **v5; // ebp
    sithThing *v6; // eax
    int v7; // ecx
    unsigned int v8; // esi
    unsigned int i; // edi

    v0 = sithWorld_pCurrentWorld;
    g_submodeFlags |= 1u;
    v1 = &sithWorld_pCurrentWorld->numThings;
    v2 = sithWorld_pCurrentWorld->numThings;
    v3 = 0;
    v4 = 0;
    sithNet_dword_83263C = 0;
    sithNet_dword_832638 = 0;
    sithCogVm_multiplayerFlags |= 1u;
    sithCogVm_bSyncMultiplayer |= 1u;
    sithMulti_dword_83265C = 0;
    if ( v2 >= 0 )
    {
        v5 = &sithWorld_pCurrentWorld->things;
        do
        {
            v6 = &(*v5)[v3];
            if ( v6->thingtype == SITH_THING_ACTOR )
            {
                sithThing_FreeEverythingNet(&(*v5)[v3]);
            }
            else if ( !sithNet_isServer )
            {
                v6->thingflags |= SITH_TF_INVULN;
            }
            ++v4;
            ++v3;
        }
        while ( v4 <= *v1 );
        v0 = sithWorld_pCurrentWorld;
    }
    v8 = 0;
    sithNet_checksum = sithWorld_CalcChecksum(v0, jkGuiNet_checksumSeed);
    sithNet_syncIdx = 0;
    sithSurface_numSurfaces_0 = 0;
    sithSector_numSync = 0;
    sithNet_dword_832640 = 0;
    sithCogVm_ClearMsgTmpBuf();
    if ( sithDplay_dword_8321E4 )
    {
        sithNet_MultiModeFlags = sithMulti_multiModeFlags;
        sithNet_scorelimit = sithDplay_dword_832204;
        sithNet_multiplayer_timelimit = sithMulti_multiplayerTimelimit;
        for ( i = 0; i < 0x20; ++i )
        {
            sithPlayer_sub_4C8910(i);
            sithPlayer_Initialize(i);
        }
        sithNet_teamScore[0] = 0;
        sithNet_teamScore[1] = 0;
        sithNet_teamScore[2] = 0;
        sithNet_teamScore[3] = 0;
        sithNet_teamScore[4] = 0;
        sithPlayer_sub_4C87C0(0, sithDplay_dword_8321EC);
        sithPlayer_idk(0);
        sithPlayer_ResetPalEffects();
        if ( (sithNet_MultiModeFlags & 0x100) != 0 )
        {
            jkPlayer_playerInfos[0].teamNum = 1;
            sithDplay_DoReceive();
            return 1;
        }
    }
    else
    {
        sithNet_isServer = 0;
        sithNet_isMulti = 1;
        do
        {
            sithPlayer_sub_4C8910(v8);
            sithPlayer_Initialize(v8++);
        }
        while ( v8 < 0x20 );
        sithNet_teamScore[0] = 0;
        sithNet_teamScore[1] = 0;
        sithNet_teamScore[2] = 0;
        sithNet_teamScore[3] = 0;
        sithNet_teamScore[4] = 0;
    }
    sithDplay_DoReceive();
    return 1;
}

void sithMulti_FreeThing(int a1)
{
    uint32_t v1; // eax

    v1 = sithMulti_dword_83265C;
    if ( sithMulti_dword_83265C < 0x100 )
    {
        sithMulti_arr_832218[sithMulti_dword_83265C] = a1;
        sithMulti_dword_83265C = v1 + 1;
    }
}

void sithMulti_Shutdown()
{
    sithCogVm_multiplayerFlags &= ~1u;
    sithNet_isMulti = 0;
    sithNet_isServer = 0;
    sithCogVm_bSyncMultiplayer &= ~1u;
    sithEvent_RegisterFunc(2, 0, 0, 0);
    sithDplay_Close();
    sithDplay_CloseConnection();
}

int sithMulti_SendRequestConnect(int sendto_id)
{
    NETMSG_START;

    NETMSG_PUSHSTR(sithWorld_pCurrentWorld->map_jkl_fname, 0x20);
    NETMSG_PUSHWSTR(jkPlayer_playerShortName, 0x10);
    NETMSG_PUSHWSTR(sithMulti_name, 0x20);
    NETMSG_PUSHU32(sithNet_checksum);

    NETMSG_END(COGMSG_REQUESTCONNECT);
    return sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendto_id, 1, 0);
}

int sithMulti_sub_4CBFC0(sithThing *pPlayerThing)
{
    unsigned int v1; // esi
    unsigned int v2; // ebp
    unsigned int v3; // ecx
    int *v4; // eax
    int v5; // edx
    unsigned int v7; // ebx
    int v8; // edi
    sithCollisionSearchEntry *i; // esi
    sithThing *v10; // eax
    unsigned int v11; // [esp+10h] [ebp-90h]
    int v12[32]; // [esp+20h] [ebp-80h] BYREF

    v1 = jkPlayer_maxPlayers;
    v2 = 0;
    v3 = 0;
    v11 = 0;
    if ( jkPlayer_maxPlayers )
    {
        v4 = v12;
        v5 = pPlayerThing->actorParams.playerinfo->respawnMask;
        do
        {
            if ( ((1 << v3) & v5) == 0 )
            {
                *v4 = v3;
                ++v2;
                ++v4;
            }
            ++v3;
        }
        while ( v3 < v1 );
    }
    if ( !v2 )
        return 0;
    if ( v2 == 1 )
        return v12[0];
    v7 = (__int64)(_frand() * (double)v2);
    if ( v7 > v2 - 1 )
        v7 = v2 - 1;
    while ( 1 )
    {
        v8 = v12[v7];
        sithCollision_SearchRadiusForThings(
            jkPlayer_playerInfos[v8].field_138C,
            0,
            &jkPlayer_playerInfos[v8].field_135C.scale,
            &rdroid_zeroVector3,
            0.0,
            pPlayerThing->moveSize,
            1154);
        for ( i = sithCollision_NextSearchResult(); i; i = sithCollision_NextSearchResult() )
        {
            if ( (i->hitType & SITHCOLLISION_THING) != 0 )
            {
                v10 = i->receiver;
                if ( v10->thingtype == SITH_THING_PLAYER && (v10->thingflags & (SITH_TF_DEAD|SITH_TF_WILLBEREMOVED)) == 0 )
                    break;
            }
        }
        sithCollision_SearchClose();
        if ( !i || v11 >= v2 )
            break;
        ++v11;
        v7 = (v7 + 1) % v2;
    }
    return v8;
}

void sithMulti_SyncScores()
{
    sithNet_dword_832648 = 1;
}

void sithMulti_HandleDeath(sithPlayerInfo *pPlayerInfo, sithThing *pKilledThing, sithThing *pKilledByThing)
{
    double v3; // st7
    wchar_t *v4; // eax
    wchar_t *v5; // eax
    wchar_t *v6; // eax
    wchar_t *v7; // [esp-8h] [ebp-114h]
    wchar_t *v8; // [esp-8h] [ebp-114h]
    sithPlayerInfo *v9; // [esp-4h] [ebp-110h]
    sithPlayerInfo *v10; // [esp-4h] [ebp-110h]
    wchar_t a1a[128]; // [esp+Ch] [ebp-100h] BYREF

    ++pPlayerInfo->numKilled;
    if ( !pKilledByThing || pKilledByThing->thingtype != SITH_THING_PLAYER )
    {
        v6 = sithStrTable_GetString("%s_DIED");
        jk_snwprintf(a1a, 0x80u, v6, pPlayerInfo);
        DebugConsole_PrintUniStr(a1a);
        goto LABEL_15;
    }
    if ( pKilledByThing != pKilledThing )
    {
        v10 = pKilledByThing->actorParams.playerinfo;
        v5 = sithStrTable_GetString("%s_WAS_KILLED_BY_%s");
        jk_snwprintf(a1a, 0x80u, v5, pPlayerInfo, v10);
        DebugConsole_PrintUniStr(a1a);
        ++pKilledByThing->actorParams.playerinfo->numKills;
        sithMulti_HandleScore();
        return;
    }
    v3 = _frand() * 4.0;
    if ( v3 < 1.0 )
    {
        v9 = pPlayerInfo;
        v4 = sithStrTable_GetString("%s_COMMITTED_SUICIDE0");
LABEL_11:
        jk_snwprintf(a1a, 0x80u, v4, v9);
        goto LABEL_12;
    }
    if ( v3 >= 2.0 )
    {
        v9 = pPlayerInfo;
        if ( v3 >= 3.0 )
        {
            v4 = sithStrTable_GetString("%s_COMMITTED_SUICIDE3");
            goto LABEL_11;
        }
        v8 = sithStrTable_GetString("%s_COMMITTED_SUICIDE2");
        jk_snwprintf(a1a, 0x80u, v8, pPlayerInfo);
    }
    else
    {
        v7 = sithStrTable_GetString("%s_COMMITTED_SUICIDE1");
        jk_snwprintf(a1a, 0x80u, v7, pPlayerInfo);
    }
LABEL_12:
    DebugConsole_PrintUniStr(a1a);
LABEL_15:
    ++pPlayerInfo->numSuicides;
    sithMulti_HandleScore();
}

#ifndef WIN32_BLOBS
void sithMulti_HandleScore()
{

}
#endif