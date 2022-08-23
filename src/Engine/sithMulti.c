#include "sithMulti.h"

#include "Win95/sithDplay.h"
#include "Gameplay/sithEvent.h"
#include "World/sithWorld.h"
#include "World/sithPlayer.h"
#include "Cog/sithCog.h"
#include "Engine/sithCollision.h"
#include "jk.h"
#include "General/sithStrTable.h"
#include "General/stdString.h"
#include "Win95/DebugConsole.h"
#include "Dss/sithDSSThing.h"
#include "Engine/sithSoundClass.h"

void sithMulti_SetHandleridk(sithMultiHandler_t a1)
{
    sithMulti_handlerIdk = a1;
}

void sithMulti_SendChat(char *pStr, int arg0, int arg1)
{
    unsigned int pStr_len; // esi

    pStr_len = strlen(pStr) + 1;
    if ( pStr_len >= 0x80 )
        pStr_len = 128;

    NETMSG_START;

    NETMSG_PUSHS32(arg0);
    NETMSG_PUSHS32(arg1);
    NETMSG_PUSHS32(pStr_len);
    NETMSG_PUSHSTR(pStr, pStr_len);

    NETMSG_END(COGMSG_CHAT);

    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, -1, 1, 1);
}

int sithMulti_HandleChat(sithCogMsg *msg)
{
    char v5[132];

    NETMSG_IN_START(msg);

    int arg0 = NETMSG_POPS32();
    int arg1 = NETMSG_POPS32();
    int arg2 = NETMSG_POPS32();

    if ( arg2 >= 0x80 )
        arg2 = 128;
    NETMSG_POPSTR(v5, arg2);
    v5[arg2 + 1] = 0;

    if ( arg1 < 0 )
        _sprintf(std_genBuffer, "%s", v5);
    else
        _sprintf(std_genBuffer, "%S says '%s'", jkPlayer_playerInfos[arg1].player_name, v5);
    DebugConsole_AlertSound();
    DebugConsole_Print(std_genBuffer);
    return 1;
}

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
        sithNet_dword_83262C = sithDplay_dplayIdSelf;
        sithNet_dword_8C4BA8 = 0;
        sithNet_dword_8C4BA4 = sithDplay_dplayIdSelf;
        sithNet_isServer = 1;
        sithNet_isMulti = 1;
        sithNet_MultiModeFlags = multiModeFlags;
        sithMulti_multiModeFlags = multiModeFlags;
        sithMulti_multiplayerTimelimit = sithNet_multiplayer_timelimit;
        sithDplay_dword_832204 = sithNet_scorelimit;
        sithNet_tickrate = rate;
        sithEvent_RegisterFunc(2, sithMulti_ServerLeft, rate, 1); // TODO enum
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
        sithPlayer_sub_4C87C0(0, sithDplay_dplayIdSelf);
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

void sithMulti_HandleScore()
{
    int score_limit_met;

    if ( (sithNet_MultiModeFlags & 4) == 0 )
    {
        sithNet_teamScore[0] = 0;
        sithNet_teamScore[1] = 0;
        sithNet_teamScore[2] = 0;
        sithNet_teamScore[3] = 0;
        sithNet_teamScore[4] = 0;
        for (int i = 0; i < jkPlayer_maxPlayers; i++)
        {
            int v4 = jkPlayer_playerInfos[i].numKills - jkPlayer_playerInfos[i].numSuicides;
            jkPlayer_playerInfos[i].score = v4;
            if ( (sithNet_MultiModeFlags & 1) != 0 )
                sithNet_teamScore[jkPlayer_playerInfos[i].teamNum] += v4;
        }
    }
    sithNet_dword_832648 = 1;
    if ( sithNet_isServer && (sithNet_MultiModeFlags & 0x10) != 0 )
    {
        score_limit_met = 0;
        if ( (sithNet_MultiModeFlags & 1) != 0 )
        {
            for (int i = 0; i < 5; i++)
            {
                if ( sithNet_teamScore[i] >= sithNet_scorelimit )
                    score_limit_met = 1;
            }
        }
        else
        {
            for (int i = 0; i < jkPlayer_maxPlayers; i++)
            {
                if ( jkPlayer_playerInfos[i].score >= sithNet_scorelimit )
                    score_limit_met = 1;
            }
        }
        if ( score_limit_met )
        {
            wchar_t* v9 = sithStrTable_GetString("MULTI_SCORELIMIT");
            stdString_WcharToChar(std_genBuffer, v9, 127);
            std_genBuffer[127] = 0;
            DebugConsole_Print(std_genBuffer);
            DebugConsole_AlertSound();
            uint32_t v10 = strlen(std_genBuffer) + 1;
            if ( v10 >= 0x80 )
                v10 = 128;

            NETMSG_START;
            NETMSG_PUSHS32(-1);
            NETMSG_PUSHS32(-1);
            NETMSG_PUSHS32(v10);
            NETMSG_PUSHSTR(std_genBuffer, v10);
            NETMSG_END(COGMSG_CHAT);
            
            sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, -1, 1, 1);
            
            sithNet_dword_832638 = 1;
            sithNet_MultiModeFlags &= ~0x8;
        }
    }
}

void sithMulti_EndLevel(unsigned int a1, int a2)
{
    if ( sithNet_dword_83263C != a2 || a1 < sithMulti_dword_832658 )
    {
        sithNet_dword_83263C = a2;
        sithMulti_dword_832658 = a1;
    }
}

void sithMulti_sendmsgidk3(int a1, int playerIdx, int sendtoId)
{
    NETMSG_START;

    NETMSG_PUSHS32(playerIdx);
    NETMSG_PUSHS32(a1);
    NETMSG_PUSHWSTR(jkPlayer_playerInfos[playerIdx].player_name, 0x10);
    NETMSG_END(COGMSG_JOINLEAVE);
    
    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendtoId, 1, 1);
}

void sithMulti_SendKickPlayer(int idx)
{
    if (!sithNet_isServer) return;
    
    NETMSG_START;

    NETMSG_PUSHS32(idx);
    NETMSG_END(COGMSG_KICK);

    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, idx, 1, 1);
}

int sithMulti_LobbyMessage()
{
    int16_t v0; // bp

    NETMSG_START;

    if ( sithNet_isServer )
    {
        if ( sithNet_dword_832640 )
        {
            if ( sithMulti_sendto_id )
            {
                sithCogVm_netMsgTmp.pktData[0] = 3;
                sithCogVm_netMsgTmp.pktData[1] = 0;
                sithCogVm_netMsgTmp.netMsg.msg_size = 8;
                sithCogVm_netMsgTmp.netMsg.flag_maybe = 0;
                sithCogVm_netMsgTmp.netMsg.cogMsgId = COGMSG_JOINING;
                sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sithMulti_sendto_id, 1, 0);
            }
            sithNet_dword_832640 = 0;
            sithMulti_sendto_id = 0;
            sithDplay_dword_83220C = 2;
            sithDplay_dword_832208 = 0;
        }
        if ( sithDplay_dword_8321F8 )
        {
            NETMSG_PUSHS32(sithNet_MultiModeFlags);
            for (int i = 0; i < 5; i++)
            {
                NETMSG_PUSHS32(sithNet_teamScore[i]);
            }
            v0 = 0;
            for (int i = 0; i < jkPlayer_maxPlayers; i++ )
            {
                if ( (jkPlayer_playerInfos[i].flags & 1) != 0 )
                    ++v0;
            }
            NETMSG_PUSHS16(v0);
            
            for (int i = 0; i < jkPlayer_maxPlayers; i++)
            {
                sithPlayerInfo* v6 = &jkPlayer_playerInfos[i];
                if ( (v6->flags & 1) != 0 )
                {
                    NETMSG_PUSHWSTR(v6->multi_name, 0x20);
                    NETMSG_PUSHS16(v6->numKills);
                    NETMSG_PUSHS16(v6->numKilled);
                    NETMSG_PUSHS16(v6->numSuicides);
                    NETMSG_PUSHS16(v6->teamNum);
                    NETMSG_PUSHS32(v6->score);
                }
            }
            DirectPlay_SendLobbyMessage(sithCogVm_netMsgTmp.pktData, NETMSG_LEN());
        }
    }
    return sithDplay_DoReceive();
}

int sithMulti_HandleJoinLeave(sithCogMsg *msg)
{
    int v1; // edi
    int v2; // ebx
    int v4; // ecx
    int v5; // edx
    sithPlayerInfo* v6; // eax
    wchar_t *v8; // eax
    wchar_t a1a[128]; // [esp+10h] [ebp-100h] BYREF

    NETMSG_IN_START(msg);

    v1 = NETMSG_POPS32();
    v2 = NETMSG_POPS32();
    NETMSG_POPWSTR(jkPlayer_playerInfos[v1].player_name, 0x10);

    if ( v2 != sithDplay_dplayIdSelf )
    {
        if ( (jkPlayer_playerInfos[v1].flags & 1) == 0 )
        {
            sithPlayer_sub_4C87C0(v1, v2);
            v8 = sithStrTable_GetString("%s_HAS_JOINED_THE_GAME");
            jk_snwprintf(a1a, 0x80u, v8, &jkPlayer_playerInfos[v1]);
            DebugConsole_PrintUniStr(a1a);
            jkPlayer_playerInfos[v1].field_13B0 = sithTime_curMs;
            if ( sithNet_isServer )
                sithCog_SendSimpleMessageToAll(SITH_MESSAGE_JOIN, 3, jkPlayer_playerInfos[v1].playerThing->thingIdx, 0, v1);
            if ( sithMulti_handlerIdk )
                sithMulti_handlerIdk();
            sithDSSThing_SendSyncThing(g_localPlayerThing, -1, 255);
            if ( sithNet_isServer )
                sithNet_dword_832648 = 1;
        }
        return 1;
    }
    if ( (g_submodeFlags & 8) == 0 )
        return 1;
    v4 = jkPlayer_maxPlayers;
    if ( jkPlayer_maxPlayers )
    {
        v5 = sithTime_curMs;
        v6 = &jkPlayer_playerInfos[0];
        do
        {
            v6->field_13B0 = v5;
            v6++;
            --v4;
        }
        while ( v4 );
    }
    g_submodeFlags &= ~8u;
    sithThing_sub_4CCE60();
    sithPlayer_sub_4C87C0(v1, v2);
    sithPlayer_idk(v1);
    sithPlayer_ResetPalEffects();
    sithEvent_RegisterFunc(2, sithMulti_ServerLeft, sithNet_tickrate, 1);
    sithCogVm_SetNeedsSync();
    return 1;
}

int sithMulti_HandlePing(sithCogMsg *msg)
{
    msg->netMsg.cogMsgId = COGMSG_PINGREPLY;
    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, msg->netMsg.thingIdx, 1, 0);
    return 1;
}

int sithMulti_HandlePingResponse(sithCogMsg *msg)
{
    int v1; // eax
    sithPlayerInfo* i; // ecx

    if ( msg->pktData[0] == sithMulti_dword_832654 )
    {
        v1 = 0;
        if ( jkPlayer_maxPlayers )
        {
            for ( i = &jkPlayer_playerInfos[0]; i->net_id != msg->netMsg.thingIdx; ++i )
            {
                if ( ++v1 >= jkPlayer_maxPlayers )
                    return 1;
            }
            _sprintf(std_genBuffer, "Ping time to %S is %d msec", jkPlayer_playerInfos[v1].player_name, sithTime_curMs - sithMulti_dword_832654);
            DebugConsole_Print(std_genBuffer);
        }
    }
    return 1;
}

int sithMulti_HandleKickPlayer(sithCogMsg *msg)
{
    wchar_t *v2; // eax
    int v3; // eax
    int v4; // edi
    int v5; // esi
    wchar_t *v6; // eax
    wchar_t *v7; // eax
    wchar_t a1a[128]; // [esp+Ch] [ebp-100h] BYREF

    if ( msg->netMsg.thingIdx != sithNet_dword_8C4BA4 )
        return 0;
    if ( msg->pktData[0] == sithDplay_dplayIdSelf )
    {
        if ( sithNet_dword_83263C != 2 )
        {
            v2 = sithStrTable_GetString("MULTI_EJECTED");
            DebugConsole_PrintUniStr(v2);
            DebugConsole_AlertSound();
            if ( sithNet_dword_83263C != 2 || sithTime_curMs + 5000 < sithMulti_dword_832658 )
            {
                sithMulti_dword_832658 = sithTime_curMs + 5000;
                sithNet_dword_83263C = 2;
                return 1;
            }
        }
    }
    else
    {
        v3 = sithPlayer_ThingIdxToPlayerIdx(msg->pktData[0]);
        v4 = v3;
        if ( v3 >= 0 )
        {
            v5 = v3;
            v6 = sithStrTable_GetString("%s_HAS_LEFT_THE_GAME");
            jk_snwprintf(a1a, 0x80u, v6, &jkPlayer_playerInfos[v5]);
            DebugConsole_PrintUniStr(a1a);
            DebugConsole_AlertSound();
            if ( jkPlayer_playerInfos[v5].net_id == sithNet_dword_8C4BA4 )
            {
                v7 = sithStrTable_GetString("SERVER_LEFT_GAME");
                DebugConsole_PrintUniStr(v7);
                DebugConsole_AlertSound();
                if ( sithNet_dword_83263C != 2 || sithTime_curMs + 5000 < sithMulti_dword_832658 )
                {
                    sithNet_dword_83263C = 2;
                    sithMulti_dword_832658 = sithTime_curMs + 5000;
                }
            }
            sithSoundClass_StopSound(jkPlayer_playerInfos[v5].playerThing, 0);
            sithPlayer_Initialize(v4);
            if ( sithNet_isServer )
                sithCog_SendSimpleMessageToAll(SITH_MESSAGE_LEAVE, 3, jkPlayer_playerInfos[v5].playerThing->thingIdx, 0, v4);
        }
    }
    return 1;
}

int sithMulti_ServerLeft()
{
    unsigned int v0; // edi
    sithPlayerInfo* v1; // esi
    int v2; // eax
    wchar_t *v3; // eax
    wchar_t *v4; // eax
    wchar_t *v6; // eax
    wchar_t *v7; // eax
    wchar_t a1[128]; // [esp+10h] [ebp-100h] BYREF

    if ( sithWorld_pCurrentWorld && g_localPlayerThing && (g_submodeFlags & 8) == 0 )
        sithDSSThing_SendTeleportThing(g_localPlayerThing, -1, 0);
    if ( sithNet_isServer )
    {
        v0 = 1;
        if ( jkPlayer_maxPlayers > 1 )
        {
            v1 = &jkPlayer_playerInfos[1];
            do
            {
                if ( (v1->flags & 1) != 0 && sithTime_curMs > v1->field_13B0 + 45000 )
                {
                    v2 = v1->net_id;
                    if ( sithNet_isServer )
                    {
                        sithCogVm_netMsgTmp.pktData[0] = v1->net_id;
                        sithCogVm_netMsgTmp.netMsg.msg_size = 4;
                        sithCogVm_netMsgTmp.netMsg.flag_maybe = 0;
                        sithCogVm_netMsgTmp.netMsg.cogMsgId = COGMSG_KICK;
                        sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, v2, 1, 1);
                    }
                    v3 = sithStrTable_GetString("%s_HAS_LEFT_THE_GAME");
                    jk_snwprintf(a1, 0x80u, v3, v1);
                    DebugConsole_PrintUniStr(a1);
                    DebugConsole_AlertSound();
                    if ( v1->net_id == sithNet_dword_8C4BA4 )
                    {
                        v4 = sithStrTable_GetString("SERVER_LEFT_GAME");
                        DebugConsole_PrintUniStr(v4);
                        DebugConsole_AlertSound();
                        if ( sithNet_dword_83263C != 2 || sithTime_curMs + 5000 < sithMulti_dword_832658 )
                        {
                            sithNet_dword_83263C = 2;
                            sithMulti_dword_832658 = sithTime_curMs + 5000;
                        }
                    }
                    sithSoundClass_StopSound(v1->playerThing, 0);
                    sithPlayer_Initialize(v0);
                    if ( sithNet_isServer )
                        sithCog_SendSimpleMessageToAll(38, 3, v1->playerThing->thingIdx, 0, v0);
                }
                ++v0;
                ++v1;
            }
            while ( v0 < jkPlayer_maxPlayers );
        }
        if ( sithMulti_dword_832660 + 10000 < sithTime_curMsAbsolute )
        {
            sithMulti_dword_832660 = sithTime_curMsAbsolute;
            sithNet_dword_832648 = 1;
            return 1;
        }
    }
    else if ( sithTime_curMs > jkPlayer_playerInfos[0].field_13B0 + 45000 )
    {
        jkPlayer_playerInfos[0].field_13B0 = sithTime_curMs;
        v6 = sithStrTable_GetString("%s_HAS_LEFT_THE_GAME");
        jk_snwprintf(a1, 0x80u, v6, jkPlayer_playerInfos);
        DebugConsole_PrintUniStr(a1);
        DebugConsole_AlertSound();
        if ( jkPlayer_playerInfos[0].net_id == sithNet_dword_8C4BA4 )
        {
            v7 = sithStrTable_GetString("SERVER_LEFT_GAME");
            DebugConsole_PrintUniStr(v7);
            DebugConsole_AlertSound();
            if ( sithNet_dword_83263C != 2 || sithTime_curMs + 5000 < sithMulti_dword_832658 )
            {
                sithNet_dword_83263C = 2;
                sithMulti_dword_832658 = sithTime_curMs + 5000;
            }
        }
        sithSoundClass_StopSound(jkPlayer_playerInfos[0].playerThing, 0);
        sithPlayer_Initialize(0);
        if ( sithNet_isServer )
            sithCog_SendSimpleMessageToAll(38, 3, jkPlayer_playerInfos[0].playerThing->thingIdx, 0, 0);
    }
    return 1;
}

void sithMulti_SendLeaveJoin(int sendtoId, int bSync)
{
    char v15[32]; // [esp+10h] [ebp-20h] BYREF

    NETMSG_START;

    NETMSG_PUSHS32(sithNet_MultiModeFlags);
    NETMSG_PUSHS32(sithNet_dword_8C4BA4);
    NETMSG_PUSHS16(jkPlayer_maxPlayers)

    for (int i = 0; i < jkPlayer_maxPlayers; i++)
    {
        sithPlayerInfo* v6 = &jkPlayer_playerInfos[i];
        NETMSG_PUSHS32(v6->flags);
        if ( (v6->flags & 4) != 0 )
        {
            NETMSG_PUSHU8(v6->net_id);

            stdString_WcharToChar(v15, v6->player_name, 15);
            v15[15] = 0;

            NETMSG_PUSHSTR(v15, 0x10);
            NETMSG_PUSHS16(v6->numKills);
            NETMSG_PUSHS16(v6->numKilled);
            NETMSG_PUSHS16(v6->numSuicides);
            NETMSG_PUSHS16(v6->teamNum);
            NETMSG_PUSHS16(v6->score); // why is this s16 here but s32 in LobbyMessage?
        }
    }

    if ( (sithNet_MultiModeFlags & 1) != 0 )
    {
        for (int i = 0; i < 5; i++)
        {
            NETMSG_PUSHS16(sithNet_teamScore[i]);
        }
    }
    NETMSG_END(COGMSG_LEAVEJOIN);
    sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sendtoId, 1, bSync);
}

void sithMulti_sub_4CA470(int a1)
{
    uint32_t v1; // eax
    sithPlayerInfo* v2; // ecx
    int v3; // edi
    wchar_t *v4; // eax
    wchar_t *v5; // eax
    wchar_t a1a[128]; // [esp+Ch] [ebp-100h] BYREF

    if ( sithNet_dword_832640 && a1 == sithMulti_sendto_id )
    {
        if ( sithMulti_sendto_id )
        {
            sithCogVm_netMsgTmp.pktData[0] = 3;
            sithCogVm_netMsgTmp.pktData[1] = 0;
            sithCogVm_netMsgTmp.netMsg.msg_size = 8;
            sithCogVm_netMsgTmp.netMsg.flag_maybe = 0;
            sithCogVm_netMsgTmp.netMsg.cogMsgId = COGMSG_JOINING;
            sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, sithMulti_sendto_id, 1, 0);
        }
        sithNet_dword_832640 = 0;
        sithMulti_sendto_id = 0;
        sithDplay_dword_83220C = 2;
        sithDplay_dword_832208 = 0;
    }
    v1 = 0;
    if ( jkPlayer_maxPlayers )
    {
        v2 = &jkPlayer_playerInfos[0];
        while ( a1 != v2->net_id )
        {
            ++v1;
            ++v2;
            if ( v1 >= jkPlayer_maxPlayers )
                goto LABEL_10;
        }
        v3 = v1;
    }
    else
    {
LABEL_10:
        v3 = -1;
    }
    if ( v3 >= 0 )
    {
        v4 = sithStrTable_GetString("%s_HAS_LEFT_THE_GAME");
        jk_snwprintf(a1a, 0x80u, v4, &jkPlayer_playerInfos[v3]);
        DebugConsole_PrintUniStr(a1a);
        DebugConsole_AlertSound();
        if ( jkPlayer_playerInfos[v3].net_id == sithNet_dword_8C4BA4 )
        {
            v5 = sithStrTable_GetString("SERVER_LEFT_GAME");
            DebugConsole_PrintUniStr(v5);
            DebugConsole_AlertSound();
            if ( sithNet_dword_83263C != 2 || sithTime_curMs + 5000 < sithMulti_dword_832658 )
            {
                sithNet_dword_83263C = 2;
                sithMulti_dword_832658 = sithTime_curMs + 5000;
            }
        }
        sithSoundClass_StopSound(jkPlayer_playerInfos[v3].playerThing, 0);
        sithPlayer_Initialize(v3);
        if ( sithNet_isServer )
            sithCog_SendSimpleMessageToAll(SITH_MESSAGE_LEAVE, 3, jkPlayer_playerInfos[v3].playerThing->thingIdx, 0, v3);
    }
}

void sithMulti_InitTick(unsigned int tickrate)
{
    sithNet_isMulti = 1;
    sithNet_dword_83262C = sithDplay_dplayIdSelf;
    sithNet_dword_8C4BA4 = 0;
    sithNet_isServer = 0;
    if ( tickrate < 100 )
    {
        sithNet_tickrate = 100;
    }
    else if ( tickrate > 300 )
    {
        sithNet_tickrate = 300;
    }
    else
    {
        sithNet_tickrate = tickrate;
    }
    sithNet_MultiModeFlags = 0;
    sithNet_dword_8C4BA4 = 0;
    sithNet_dword_8C4BA8 = 0;
}

int sithMulti_HandleRequestConnect(sithCogMsg *msg)
{
    int v1; // esi
    uint32_t v3; // eax
    sithPlayerInfo* v4; // ecx
    uint32_t v5; // ecx
    sithPlayerInfo* v6; // eax
    uint32_t v7; // eax
    int *v8; // ecx
    unsigned int v9; // eax
    int v10; // ecx
    char v11[32]; // [esp+Ch] [ebp-20h] BYREF

    v1 = msg->netMsg.thingIdx;
    if ( sithDplay_dword_8321E4 && v1 )
    {
        _strncpy(v11, (const char *)msg->pktData, 0x1Fu);
        v11[31] = 0;
        if ( __strcmpi(v11, sithWorld_pCurrentWorld->map_jkl_fname) )
        {
            sithCogVm_netMsgTmp.pktData[0] = 6;
            sithCogVm_netMsgTmp.pktData[1] = 0;
            sithCogVm_netMsgTmp.netMsg.msg_size = 8;
            sithCogVm_netMsgTmp.netMsg.flag_maybe = 0;
            sithCogVm_netMsgTmp.netMsg.cogMsgId = COGMSG_JOINING;
            sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp.netMsg, v1, 1, 0);
            return 1;
        }
        v3 = 0;
        if ( jkPlayer_maxPlayers )
        {
            v4 = &jkPlayer_playerInfos[0];
            do
            {
                if ( v4->net_id == v1 )
                    break;
                ++v3;
                ++v4;
            }
            while ( v3 < jkPlayer_maxPlayers );
        }
        if ( v3 < jkPlayer_maxPlayers )
        {
            NETMSG_START;

            NETMSG_PUSHS32(v3);
            NETMSG_PUSHS32(v1);
            NETMSG_PUSHWSTR(jkPlayer_playerInfos[v3].player_name, 0x10);
            NETMSG_END(COGMSG_JOINLEAVE);

            sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp, v1, 1, 1);
            return 1;
        }
        sithDplay_cogMsg_SendEnumPlayers(v1);
        if ( sithNet_dword_83263C )
        {
            sithCogVm_netMsgTmp.pktData[0] = 3;
            sithCogVm_netMsgTmp.pktData[1] = 0;
            sithCogVm_netMsgTmp.netMsg.msg_size = 8;
            sithCogVm_netMsgTmp.netMsg.flag_maybe = 0;
            sithCogVm_netMsgTmp.netMsg.cogMsgId = COGMSG_JOINING;
            sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp.netMsg, v1, 1, 0);
            return 1;
        }
        if ( sithNet_dword_832640 )
        {
            if ( sithMulti_sendto_id == v1 )
            {
                sithCogVm_netMsgTmp.pktData[0] = 0;
                sithCogVm_netMsgTmp.pktData[1] = 0x3F000000;
LABEL_32:
                sithCogVm_netMsgTmp.netMsg.msg_size = 8;
                sithCogVm_netMsgTmp.netMsg.flag_maybe = 0;
                sithCogVm_netMsgTmp.netMsg.cogMsgId = COGMSG_JOINING;
                sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp.netMsg, v1, 1, 0);
                return 1;
            }
            sithCogVm_netMsgTmp.pktData[0] = 1;
LABEL_31:
            sithCogVm_netMsgTmp.pktData[1] = 0;
            goto LABEL_32;
        }
        v5 = 0;
        if ( jkPlayer_maxPlayers )
        {
            v6 = &jkPlayer_playerInfos[0];
            do
            {
                if ( (v6->flags & 2) != 0 && !v6->net_id )
                    break;
                ++v5;
                ++v6;
            }
            while ( v5 < jkPlayer_maxPlayers );
        }
        if ( v5 == jkPlayer_maxPlayers )
        {
            sithCogVm_netMsgTmp.pktData[0] = 5;
            sithCogVm_netMsgTmp.pktData[1] = 0;
            sithCogVm_netMsgTmp.netMsg.msg_size = 8;
            sithCogVm_netMsgTmp.netMsg.flag_maybe = 0;
            sithCogVm_netMsgTmp.netMsg.cogMsgId = COGMSG_JOINING;
            sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp.netMsg, v1, 1, 0);
            return 1;
        }
        sithMulti_requestConnectIdx = v5;
        DirectPlay_EnumPlayers(0);
        v7 = 0;
        if ( DirectPlay_numPlayers )
        {
            v8 = &DirectPlay_aPlayers[0].dpId;
            do
            {
                if ( *v8 == v1 )
                    break;
                ++v7;
                v8 += 37;
            }
            while ( v7 < DirectPlay_numPlayers );
        }
        if ( v7 != DirectPlay_numPlayers )
        {
            sithPlayer_sub_4C8910(sithMulti_requestConnectIdx);
            _wcsncpy(jkPlayer_playerInfos[sithMulti_requestConnectIdx].player_name, (const wchar_t *)&msg->pktData[8], 0xFu);
            v9 = sithMulti_requestConnectIdx;
            jkPlayer_playerInfos[v9].player_name[15] = 0;
            _wcsncpy(jkPlayer_playerInfos[v9].multi_name, (const wchar_t *)&msg->pktData[16], 0x1Fu);
            v10 = sithNet_checksum;
            jkPlayer_playerInfos[sithMulti_requestConnectIdx].multi_name[31] = 0;
            if ( v10 != msg->pktData[32] )
            {
                sithCogVm_netMsgTmp.pktData[0] = 4;
                goto LABEL_31;
            }
            sithCogVm_netMsgTmp.pktData[0] = 0;
            sithCogVm_netMsgTmp.pktData[1] = 0x3E800000;
            sithCogVm_netMsgTmp.netMsg.msg_size = 8;
            sithCogVm_netMsgTmp.netMsg.flag_maybe = 0;
            sithCogVm_netMsgTmp.netMsg.cogMsgId = COGMSG_JOINING;
            sithCogVm_SendMsgToPlayer(&sithCogVm_netMsgTmp.netMsg, v1, 1, 0);
            sithMulti_SendLeaveJoin(v1, 0);
            sithNet_dword_832640 = 1;
            sithMulti_sendto_id = v1;
            sithDplay_dword_83220C = 2;
            sithDplay_dword_832208 = 0;
            sithDplay_dword_832200 = 0;
            sithDplay_dword_832210 = 0;
            sithMulti_dword_832620 = 0;
        }
    }
    return 1;
}

void sithDplay_cogMsg_SendEnumPlayers(int sendtoId)
{
    NETMSG_START;

    DirectPlay_EnumPlayers(0);
    

    NETMSG_PUSHU8(DirectPlay_numPlayers);

    for (int i = 0; i < DirectPlay_numPlayers; i++)
    {
        NETMSG_PUSHS32(DirectPlay_aPlayers[i].dpId)
    }

    NETMSG_END(COGMSG_ENUMPLAYERS);
    sithCogVm_SendMsgToPlayer(&sithDplay_cogMsgTmp, sendtoId, 1, 1);
}