#include "sithMulti.h"

#include "Win95/stdComm.h"
#include "Gameplay/sithEvent.h"
#include "World/sithWorld.h"
#include "Gameplay/sithPlayer.h"
#include "Cog/sithCog.h"
#include "Engine/sithCollision.h"
#include "jk.h"
#include "General/sithStrTable.h"
#include "General/stdString.h"
#include "Devices/sithConsole.h"
#include "Dss/sithDSSThing.h"
#include "Dss/sithDSS.h"
#include "Dss/sithDSSCog.h"
#include "World/sithSoundClass.h"
#include "stdPlatform.h"
#include "World/sithSector.h"
#include "World/sithSurface.h"
#include "Main/sithMain.h"
#include "Main/Main.h"
#include "AI/sithAI.h"
#include "Devices/sithComm.h"
#include "stdPlatform.h"

#define sithMulti_infoPrintf(fmt, ...) stdPlatform_Printf(fmt, ##__VA_ARGS__)
#define sithMulti_verbosePrintf(fmt, ...) if (Main_bVerboseNetworking) \
    { \
        stdPlatform_Printf(fmt, ##__VA_ARGS__);  \
    } \
    ;

static wchar_t sithMulti_chatWStrTmp[256]; // Added

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

    NETMSG_END(DSS_CHAT);

    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, -1, 1, 1);
}

// MOTS altered
int sithMulti_ProcessChat(sithCogMsg *msg)
{
    // Added: 132 -> 256
    char v5[256];

    NETMSG_IN_START(msg);

    int arg0 = NETMSG_POPS32();
    int arg1 = NETMSG_POPS32();
    int arg2 = NETMSG_POPS32();

    if ( arg2 >= 0x80 )
        arg2 = 128;
    NETMSG_POPSTR(v5, arg2);
    v5[arg2 + 1] = 0;

    if ( arg1 < 0 )
        jk_snwprintf(sithMulti_chatWStrTmp, 256, L"%S", v5); // Added: char -> wchar
    else
        jk_snwprintf(sithMulti_chatWStrTmp, 256, L"%s says '%S'", jkPlayer_playerInfos[arg1].player_name, v5); // Added: char -> wchar
    sithConsole_AlertSound();
    sithConsole_PrintUniStr(sithMulti_chatWStrTmp); // Added: char -> wchar
    return 1;
}

HRESULT sithMulti_CreatePlayer(const wchar_t *a1, const wchar_t *a2, const char *a3, const char *a4, int maxPlayers, int sessionFlags, int multiModeFlags, int rate, int maxRank)
{
    HRESULT result; // eax
    jkMultiEntry multiEntry; // [esp+Ch] [ebp-F0h] BYREF

    _memset(&multiEntry, 0, sizeof(multiEntry));
    stdString_SafeWStrCopy(multiEntry.serverName, a1, 0x20);
    stdString_SafeStrCopy(multiEntry.episodeGobName, a3, 0x20);
    stdString_SafeStrCopy(multiEntry.mapJklFname, a4, 0x20);
    stdString_SafeWStrCopy(multiEntry.wPassword, a2, 0x20);
    multiEntry.maxPlayers = maxPlayers;
    idx_13b4_related = maxPlayers;
    multiEntry.maxRank = maxRank;
    multiEntry.multiModeFlags = multiModeFlags;
    multiEntry.tickRateMs = rate;
    multiEntry.sessionFlags = sessionFlags;
    if ( stdComm_dword_8321E0 )
        result = stdComm_seed_idk(&multiEntry);
    else
        result = stdComm_CreatePlayer(&multiEntry);
    if ( !result )
    {
        sithNet_dword_83262C = stdComm_dplayIdSelf;
        sithNet_dword_8C4BA8 = 0;
        sithNet_serverNetId = stdComm_dplayIdSelf;
        sithNet_isServer = 1;
        sithNet_isMulti = 1;
        sithNet_MultiModeFlags = multiModeFlags;
        sithMulti_multiModeFlags = multiModeFlags;
        sithMulti_multiplayerTimelimit = sithNet_multiplayer_timelimit;
        stdComm_dword_832204 = sithNet_scorelimit;
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
    sithMulti_leaveJoinType = 0;
    sithMulti_bTimelimitMet = 0;
    sithComm_multiplayerFlags |= 1u;
    sithComm_bSyncMultiplayer |= 1u;
    sithMulti_dword_83265C = 0;

    // Remove all actor things from the world
    if (!(sithMulti_multiModeFlags & MULTIMODEFLAG_COOP) && v2 >= 0 ) // Added: Co-op
    {
        v5 = &sithWorld_pCurrentWorld->things;
        do
        {
            v6 = &(*v5)[v3];
            if ( v6->type == SITH_THING_ACTOR )
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
    sithNet_checksum = sithWorld_CalcChecksum(v0, 0/*jkGuiMultiplayer_checksumSeed*/); // Added: TODO fix the checksum seed
    sithNet_syncIdx = 0;
    sithSurface_numSurfaces_0 = 0;
    sithSector_numSync = 0;
    sithNet_dword_832640 = 0;
    sithComm_ClearMsgTmpBuf();
    if ( stdComm_bIsServer )
    {
        sithNet_MultiModeFlags = sithMulti_multiModeFlags;
        sithNet_scorelimit = stdComm_dword_832204;
        sithNet_multiplayer_timelimit = sithMulti_multiplayerTimelimit;
        for ( i = 0; i < 0x20; ++i )
        {
            sithPlayer_sub_4C8910(i);
            sithPlayer_Startup(i);
        }
        sithNet_teamScore[0] = 0;
        sithNet_teamScore[1] = 0;
        sithNet_teamScore[2] = 0;
        sithNet_teamScore[3] = 0;
        sithNet_teamScore[4] = 0;
        sithPlayer_sub_4C87C0(0, stdComm_dplayIdSelf);
        sithPlayer_idk(0);
        sithPlayer_ResetPalEffects();

        // Added: dedicated server
        if (jkGuiNetHost_bIsDedicated) {
            jkPlayer_playerInfos[0].flags = 6;
            jkPlayer_playerInfos[0].playerThing->thingflags |= SITH_TF_DISABLED;
            jkPlayer_playerInfos[0].playerThing->attach_flags = 0;
        }

        if ( (sithNet_MultiModeFlags & MULTIMODEFLAG_100) != 0 )
        {
            jkPlayer_playerInfos[0].teamNum = 1;
            stdComm_DoReceive();
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
            sithPlayer_Startup(v8++);
        }
        while ( v8 < 0x20 );
        sithNet_teamScore[0] = 0;
        sithNet_teamScore[1] = 0;
        sithNet_teamScore[2] = 0;
        sithNet_teamScore[3] = 0;
        sithNet_teamScore[4] = 0;
    }
    stdComm_DoReceive();
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
    sithComm_multiplayerFlags &= ~1u;
    sithNet_isMulti = 0;
    sithNet_isServer = 0;
    sithComm_bSyncMultiplayer &= ~1u;
    sithEvent_RegisterFunc(2, 0, 0, 0);
    stdComm_Close();
    stdComm_CloseConnection();
}

int sithMulti_SendJoinRequest(int sendto_id)
{
    NETMSG_START;

    NETMSG_PUSHSTR(sithWorld_pCurrentWorld->map_jkl_fname, 0x20);
    NETMSG_PUSHWSTR(jkPlayer_playerShortName, 0x10);
    NETMSG_PUSHWSTR(sithMulti_name, 0x20);
    NETMSG_PUSHU32(sithNet_checksum);

    NETMSG_END(DSS_JOINREQUEST);
    return sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sendto_id, 1, 0);
}

int sithMulti_GetSpawnIdx(sithThing *pPlayerThing)
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

    // Added: Spawn at start in co-op.
    if (sithNet_MultiModeFlags & MULTIMODEFLAG_COOP) {
        return 0;
    }

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
            jkPlayer_playerInfos[v8].pSpawnSector,
            0,
            &jkPlayer_playerInfos[v8].spawnPosOrient.scale,
            &rdroid_zeroVector3,
            0.0,
            pPlayerThing->moveSize,
            1154);
        for ( i = sithCollision_NextSearchResult(); i; i = sithCollision_NextSearchResult() )
        {
            if ( (i->hitType & SITHCOLLISION_THING) != 0 )
            {
                v10 = i->receiver;
                if ( v10->type == SITH_THING_PLAYER && (v10->thingflags & (SITH_TF_DEAD|SITH_TF_WILLBEREMOVED)) == 0 )
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
    sithNet_bSyncScores = 1;
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
    if ( !pKilledByThing || pKilledByThing->type != SITH_THING_PLAYER )
    {
        v6 = sithStrTable_GetUniStringWithFallback("%s_DIED");
        jk_snwprintf(a1a, 0x80u, v6, pPlayerInfo);
        sithConsole_PrintUniStr(a1a);
        goto LABEL_15;
    }
    if ( pKilledByThing != pKilledThing )
    {
        v10 = pKilledByThing->actorParams.playerinfo;
        v5 = sithStrTable_GetUniStringWithFallback("%s_WAS_KILLED_BY_%s");
        jk_snwprintf(a1a, 0x80u, v5, pPlayerInfo, v10);
        sithConsole_PrintUniStr(a1a);
        ++pKilledByThing->actorParams.playerinfo->numKills;
        sithMulti_ProcessScore();
        return;
    }
    v3 = _frand() * 4.0;
    if ( v3 < 1.0 )
    {
        v9 = pPlayerInfo;
        v4 = sithStrTable_GetUniStringWithFallback("%s_COMMITTED_SUICIDE0");
LABEL_11:
        jk_snwprintf(a1a, 0x80u, v4, v9);
        goto LABEL_12;
    }
    if ( v3 >= 2.0 )
    {
        v9 = pPlayerInfo;
        if ( v3 >= 3.0 )
        {
            v4 = sithStrTable_GetUniStringWithFallback("%s_COMMITTED_SUICIDE3");
            goto LABEL_11;
        }
        v8 = sithStrTable_GetUniStringWithFallback("%s_COMMITTED_SUICIDE2");
        jk_snwprintf(a1a, 0x80u, v8, pPlayerInfo);
    }
    else
    {
        v7 = sithStrTable_GetUniStringWithFallback("%s_COMMITTED_SUICIDE1");
        jk_snwprintf(a1a, 0x80u, v7, pPlayerInfo);
    }
LABEL_12:
    sithConsole_PrintUniStr(a1a);
LABEL_15:
    ++pPlayerInfo->numSuicides;
    sithMulti_ProcessScore();
}

// MOTS altered?
void sithMulti_ProcessScore()
{
    int score_limit_met;

    if ( (sithNet_MultiModeFlags & MULTIMODEFLAG_4) == 0 )
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
            if ( (sithNet_MultiModeFlags & MULTIMODEFLAG_TEAMS) != 0 )
                sithNet_teamScore[jkPlayer_playerInfos[i].teamNum] += v4;
        }
    }
    sithNet_bSyncScores = 1;
    if ( sithNet_isServer && (sithNet_MultiModeFlags & MULTIMODEFLAG_SCORELIMIT) != 0 )
    {
        score_limit_met = 0;
        if ( (sithNet_MultiModeFlags & MULTIMODEFLAG_TEAMS) != 0 )
        {
            for (int i = 0; i < 5; i++)
            {
                if ( sithNet_teamScore[i] >= sithNet_scorelimit ) {
                    score_limit_met = 1;
                    sithMulti_infoPrintf("Team score limit met by team %d, %u pts of %u\n", i, sithNet_teamScore[i], sithNet_scorelimit);
                }
            }
        }
        else
        {
            for (int i = 0; i < jkPlayer_maxPlayers; i++)
            {
                if ( jkPlayer_playerInfos[i].score >= sithNet_scorelimit ) {
                    score_limit_met = 1;
                    sithMulti_infoPrintf("Player score limit met by player %d (netid %u), %u pts of %u\n", i, jkPlayer_playerInfos[i].net_id, jkPlayer_playerInfos[i].score, sithNet_scorelimit);
                }
            }
        }
        if ( score_limit_met )
        {
            wchar_t* v9 = sithStrTable_GetUniStringWithFallback("MULTI_SCORELIMIT");
            stdString_WcharToChar(std_genBuffer, v9, 127);
            std_genBuffer[127] = 0;
            sithConsole_Print(std_genBuffer);
            sithConsole_AlertSound();
            uint32_t v10 = strlen(std_genBuffer) + 1;
            if ( v10 >= 0x80 )
                v10 = 128;

            NETMSG_START;
            //NETMSG_PUSHS16(1);// MOTS added
            NETMSG_PUSHS32(-1);
            NETMSG_PUSHS32(-1);
            NETMSG_PUSHS32(v10);
            NETMSG_PUSHSTR(std_genBuffer, v10);
            NETMSG_END(DSS_CHAT);

            sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, -1, 1, 1);

            sithMulti_bTimelimitMet = 1;
            sithNet_MultiModeFlags &= ~MULTIMODEFLAG_TIMELIMIT;
        }
    }
}

void sithMulti_EndLevel(unsigned int waitMs, int type)
{
    if ( sithMulti_leaveJoinType != type || waitMs < sithMulti_leaveJoinWaitMs )
    {
        sithMulti_leaveJoinType = type;
        sithMulti_leaveJoinWaitMs = waitMs;
    }
}

void sithMulti_SendWelcome(int a1, int playerIdx, int sendtoId)
{
    NETMSG_START;

    NETMSG_PUSHS32(playerIdx);
    NETMSG_PUSHS32(a1);
    NETMSG_PUSHWSTR(jkPlayer_playerInfos[playerIdx].player_name, 0x10);
    NETMSG_END(DSS_WELCOME);

    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sendtoId, 1, 1);
}

void sithMulti_SendQuit(int idx)
{
    if (!sithNet_isServer) return;

    NETMSG_START;

    NETMSG_PUSHS32(idx);
    NETMSG_END(DSS_QUIT);

    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, idx, 1, 1);
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
                sithComm_netMsgTmp.pktData[0] = 3;
                sithComm_netMsgTmp.pktData[1] = 0;
                sithComm_netMsgTmp.netMsg.msg_size = 8;
                sithComm_netMsgTmp.netMsg.flag_maybe = 0;
                sithComm_netMsgTmp.netMsg.cogMsgId = DSS_JOINING;
                sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sithMulti_sendto_id, 1, 0);
            }
            sithNet_dword_832640 = 0;
            sithMulti_sendto_id = 0;
            stdComm_dword_83220C = 2;
            stdComm_dword_832208 = 0;
        }
        if ( stdComm_dword_8321F8 )
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
            DirectPlay_SendLobbyMessage(sithComm_netMsgTmp.pktData, NETMSG_LEN());
        }
    }
    return stdComm_DoReceive();
}

int sithMulti_ProcessJoinLeave(sithCogMsg *msg)
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

    sithMulti_verbosePrintf("sithMulti_ProcessJoinLeave %x %x %x\n", v1, v2, stdComm_dplayIdSelf);

    if ( v2 != stdComm_dplayIdSelf )
    {
        if ( (jkPlayer_playerInfos[v1].flags & 1) == 0 )
        {
            sithPlayer_sub_4C87C0(v1, v2);
            v8 = sithStrTable_GetUniStringWithFallback("%s_HAS_JOINED_THE_GAME");
            jk_snwprintf(a1a, 0x80u, v8, jkPlayer_playerInfos[v1].player_name);
            sithConsole_PrintUniStr(a1a);
            jkPlayer_playerInfos[v1].lastUpdateMs = sithTime_curMs;
            if ( sithNet_isServer )
                sithCog_SendSimpleMessageToAll(SITH_MESSAGE_JOIN, 3, jkPlayer_playerInfos[v1].playerThing->thingIdx, 0, v1);
            if ( sithMulti_handlerIdk )
                sithMulti_handlerIdk();
            sithDSSThing_SendSyncThing(sithPlayer_pLocalPlayerThing, -1, 255);
            if ( sithNet_isServer )
                sithNet_bSyncScores = 1;
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
            v6->lastUpdateMs = v5;
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
    sithComm_SetNeedsSync();
    return 1;
}

int sithMulti_ProcessPing(sithCogMsg *msg)
{
    msg->netMsg.cogMsgId = DSS_PINGREPLY;
    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, msg->netMsg.thingIdx, 1, 0);
    return 1;
}

int sithMulti_ProcessPingResponse(sithCogMsg *msg)
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
            sithConsole_Print(std_genBuffer);
        }
    }
    return 1;
}

int sithMulti_ProcessQuit(sithCogMsg *msg)
{
    wchar_t *v2; // eax
    int v3; // eax
    int v4; // edi
    int v5; // esi
    wchar_t *v6; // eax
    wchar_t *v7; // eax
    wchar_t a1a[128]; // [esp+Ch] [ebp-100h] BYREF

    if ( msg->netMsg.thingIdx != sithNet_serverNetId )
        return 0;
    if ( msg->pktData[0] == stdComm_dplayIdSelf )
    {
        if ( sithMulti_leaveJoinType != 2 )
        {
            v2 = sithStrTable_GetUniStringWithFallback("MULTI_EJECTED");
            sithConsole_PrintUniStr(v2);
            sithConsole_AlertSound();
            if ( sithMulti_leaveJoinType != 2 || sithTime_curMs + MULTI_LEAVEJOIN_DELAY_MS < sithMulti_leaveJoinWaitMs )
            {
                sithMulti_leaveJoinWaitMs = sithTime_curMs + MULTI_LEAVEJOIN_DELAY_MS;
                sithMulti_leaveJoinType = 2;
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
            v6 = sithStrTable_GetUniStringWithFallback("%s_HAS_LEFT_THE_GAME");
            jk_snwprintf(a1a, 0x80u, v6, &jkPlayer_playerInfos[v5]);
            sithConsole_PrintUniStr(a1a);
            sithConsole_AlertSound();
            if ( jkPlayer_playerInfos[v5].net_id == sithNet_serverNetId )
            {
                v7 = sithStrTable_GetUniStringWithFallback("SERVER_LEFT_GAME");
                sithConsole_PrintUniStr(v7);
                sithConsole_AlertSound();
                if ( sithMulti_leaveJoinType != 2 || sithTime_curMs + MULTI_LEAVEJOIN_DELAY_MS < sithMulti_leaveJoinWaitMs )
                {
                    sithMulti_leaveJoinType = 2;
                    sithMulti_leaveJoinWaitMs = sithTime_curMs + MULTI_LEAVEJOIN_DELAY_MS;
                }
            }
            sithSoundClass_StopSound(jkPlayer_playerInfos[v5].playerThing, 0);
            sithPlayer_Startup(v4);
            if ( sithNet_isServer )
                sithCog_SendSimpleMessageToAll(SITH_MESSAGE_LEAVE, 3, jkPlayer_playerInfos[v5].playerThing->thingIdx, 0, v4);
        }
    }
    return 1;
}

int sithMulti_ServerLeft(int a, sithEventInfo* b)
{
    unsigned int v0; // edi
    sithPlayerInfo* v1; // esi
    int v2; // eax
    wchar_t *v3; // eax
    wchar_t *v4; // eax
    wchar_t *v6; // eax
    wchar_t *v7; // eax
    wchar_t a1[128]; // [esp+10h] [ebp-100h] BYREF

    if ( sithWorld_pCurrentWorld && sithPlayer_pLocalPlayerThing && (g_submodeFlags & 8) == 0 )
        sithDSSThing_SendPos(sithPlayer_pLocalPlayerThing, -1, 0);
    if ( sithNet_isServer )
    {
        v0 = 1;
        if ( jkPlayer_maxPlayers > 1 )
        {
            v1 = &jkPlayer_playerInfos[1];
            do
            {
                if ( (v1->flags & 1) != 0 && sithTime_curMs > v1->lastUpdateMs + MULTI_TIMEOUT_MS )
                {
                    v2 = v1->net_id;
                    if ( sithNet_isServer )
                    {
                        sithComm_netMsgTmp.pktData[0] = v1->net_id;
                        sithComm_netMsgTmp.netMsg.msg_size = 4;
                        sithComm_netMsgTmp.netMsg.flag_maybe = 0;
                        sithComm_netMsgTmp.netMsg.cogMsgId = DSS_QUIT;
                        sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, v2, 1, 1);
                    }
                    v3 = sithStrTable_GetUniStringWithFallback("%s_HAS_LEFT_THE_GAME");
                    jk_snwprintf(a1, 0x80u, v3, v1);
                    sithConsole_PrintUniStr(a1);
                    sithConsole_AlertSound();
                    if ( v1->net_id == sithNet_serverNetId )
                    {
                        v4 = sithStrTable_GetUniStringWithFallback("SERVER_LEFT_GAME");
                        sithConsole_PrintUniStr(v4);
                        sithConsole_AlertSound();
                        if ( sithMulti_leaveJoinType != 2 || sithTime_curMs + MULTI_LEAVEJOIN_DELAY_MS < sithMulti_leaveJoinWaitMs )
                        {
                            sithMulti_leaveJoinType = 2;
                            sithMulti_leaveJoinWaitMs = sithTime_curMs + MULTI_LEAVEJOIN_DELAY_MS;
                        }
                    }
                    sithSoundClass_StopSound(v1->playerThing, 0);
                    sithPlayer_Startup(v0);
                    if ( sithNet_isServer )
                        sithCog_SendSimpleMessageToAll(SITH_MESSAGE_LEAVE, 3, v1->playerThing->thingIdx, 0, v0);
                }
                ++v0;
                ++v1;
            }
            while ( v0 < jkPlayer_maxPlayers );
        }
        if ( sithMulti_lastScoreUpdateMs + MULTI_SCORE_UPDATE_INTERVAL_MS < sithTime_curMsAbsolute )
        {
            sithMulti_lastScoreUpdateMs = sithTime_curMsAbsolute;
            sithNet_bSyncScores = 1;
            return 1;
        }
    }
    else if ( sithTime_curMs > jkPlayer_playerInfos[0].lastUpdateMs + MULTI_TIMEOUT_MS )
    {
        jkPlayer_playerInfos[0].lastUpdateMs = sithTime_curMs;
        v6 = sithStrTable_GetUniStringWithFallback("%s_HAS_LEFT_THE_GAME");
        jk_snwprintf(a1, 0x80u, v6, jkPlayer_playerInfos);
        sithConsole_PrintUniStr(a1);
        sithConsole_AlertSound();
        if ( jkPlayer_playerInfos[0].net_id == sithNet_serverNetId )
        {
            v7 = sithStrTable_GetUniStringWithFallback("SERVER_LEFT_GAME");
            sithConsole_PrintUniStr(v7);
            sithConsole_AlertSound();
            if ( sithMulti_leaveJoinType != 2 || sithTime_curMs + MULTI_LEAVEJOIN_DELAY_MS < sithMulti_leaveJoinWaitMs )
            {
                sithMulti_leaveJoinType = 2;
                sithMulti_leaveJoinWaitMs = sithTime_curMs + MULTI_LEAVEJOIN_DELAY_MS;
            }
        }
        sithSoundClass_StopSound(jkPlayer_playerInfos[0].playerThing, 0);
        sithPlayer_Startup(0);
        if ( sithNet_isServer )
            sithCog_SendSimpleMessageToAll(SITH_MESSAGE_LEAVE, 3, jkPlayer_playerInfos[0].playerThing->thingIdx, 0, 0);
    }
    return 1;
}

void sithMulti_SendLeaveJoin(int sendtoId, int bSync)
{
    char v15[32]; // [esp+10h] [ebp-20h] BYREF

    NETMSG_START;

    NETMSG_PUSHS32(sithNet_MultiModeFlags);
    NETMSG_PUSHS32(sithNet_serverNetId);
    NETMSG_PUSHS16(jkPlayer_maxPlayers)

    for (int i = 0; i < jkPlayer_maxPlayers; i++)
    {
        sithPlayerInfo* v6 = &jkPlayer_playerInfos[i];
        NETMSG_PUSHS32((sithNet_isServer && jkGuiNetHost_bIsDedicated && !i) ? v6->flags & ~2 : v6->flags);
        if ( (v6->flags & 4) != 0 )
        {
            NETMSG_PUSHS32(v6->net_id);

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

    if ( (sithNet_MultiModeFlags & MULTIMODEFLAG_TEAMS) != 0 )
    {
        for (int i = 0; i < 5; i++)
        {
            NETMSG_PUSHS16(sithNet_teamScore[i]);
        }
    }
    NETMSG_END(DSS_LEAVEJOIN);
    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sendtoId, 1, bSync);
}

int sithMulti_ProcessLeaveJoin(sithCogMsg *msg)
{
    uint32_t v1; // eax
    int v2; // edx
    unsigned int v3; // ebp
    uint32_t v4; // eax
    sithPlayerInfo* v6; // edi
    int v7; // ecx
    int v8; // eax
    wchar_t *v10; // eax
    wchar_t *v12; // eax
    wchar_t *v13; // eax
    char a2[32]; // [esp+10h] [ebp-220h] BYREF
    wchar_t a1a[128]; // [esp+30h] [ebp-200h] BYREF
    wchar_t v22[128]; // [esp+130h] [ebp-100h] BYREF

    NETMSG_IN_START(msg);

    sithNet_MultiModeFlags = 0;
    sithNet_serverNetId = 0;
    sithNet_dword_8C4BA8 = 0;
    v1 = stdPlatform_GetTimeMsec();
    v2 = NETMSG_POPS32();
    sithNet_dword_8C4BA8 = v1;
    sithNet_serverNetId = NETMSG_POPS32();
    v3 = 0;
    v4 = NETMSG_POPS16();

    sithNet_MultiModeFlags = v2;
    jkPlayer_maxPlayers = v4;
    for (v3 = 0; v3 < jkPlayer_maxPlayers; v3++)
    {
        v6 = &jkPlayer_playerInfos[v3];
        v7 = v6->flags;
        v6->flags = NETMSG_POPS32();
        if ( (v6->flags & 4) != 0 )
        {
            v8 = NETMSG_POPS32();
            v6->net_id = v8;
            if ( (v6->flags & 1) == 0 || (v7 & 1) != 0 || (g_submodeFlags & 8) != 0 )
            {
                if ( !v6->net_id && (v7 & 1) != 0 && (g_submodeFlags & 8) == 0 )
                {
                    v12 = sithStrTable_GetUniStringWithFallback("%s_HAS_LEFT_THE_GAME");
                    jk_snwprintf(v22, 0x80u, v12, v6);
                    sithConsole_PrintUniStr(v22);
                    sithConsole_AlertSound();
                    if ( v6->net_id == sithNet_serverNetId )
                    {
                        v13 = sithStrTable_GetUniStringWithFallback("SERVER_LEFT_GAME");
                        sithConsole_PrintUniStr(v13);
                        sithConsole_AlertSound();
                        if ( sithMulti_leaveJoinType != 2 || sithTime_curMs + MULTI_LEAVEJOIN_DELAY_MS < sithMulti_leaveJoinWaitMs )
                        {
                            sithMulti_leaveJoinType = 2;
                            sithMulti_leaveJoinWaitMs = sithTime_curMs + MULTI_LEAVEJOIN_DELAY_MS;
                        }
                    }
                    sithSoundClass_StopSound(v6->playerThing, 0);
                    sithPlayer_Startup(v3);
                    if ( sithNet_isServer )
                        sithCog_SendSimpleMessageToAll(SITH_MESSAGE_LEAVE, 3, v6->playerThing->thingIdx, 0, v3);
                }
            }
            else
            {
                v10 = sithStrTable_GetUniStringWithFallback("%s_HAS_JOINED_THE_GAME");
                jk_snwprintf(a1a, 0x80u, v10, v6);
                sithConsole_PrintUniStr(a1a);

                v6->lastUpdateMs = sithTime_curMs;
                if ( sithNet_isServer != 0 )
                    sithCog_SendSimpleMessageToAll(SITH_MESSAGE_JOIN, 3, v6->playerThing->thingIdx, 0, v3);
                if ( sithMulti_handlerIdk )
                    sithMulti_handlerIdk();
                sithDSSThing_SendSyncThing(sithPlayer_pLocalPlayerThing, -1, 255);
            }
            NETMSG_POPSTR(a2, 0x10);

            stdString_CharToWchar(v6->player_name, a2, 15);

            v6->numKills = NETMSG_POPS16();
            v6->numKilled = NETMSG_POPS16();
            v6->numSuicides = NETMSG_POPS16();
            v6->teamNum = NETMSG_POPS16();
            v6->score = NETMSG_POPS16();
        }
    }
    if ( (sithNet_MultiModeFlags & MULTIMODEFLAG_TEAMS) != 0 )
    {
        int* v18 = sithNet_teamScore;
        do
        {
            *v18++ = NETMSG_POPS16();
        }
        while ( v18 < &sithNet_teamScore[5] );
    }
    return 1;
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
            sithComm_netMsgTmp.pktData[0] = 3;
            sithComm_netMsgTmp.pktData[1] = 0;
            sithComm_netMsgTmp.netMsg.msg_size = 8;
            sithComm_netMsgTmp.netMsg.flag_maybe = 0;
            sithComm_netMsgTmp.netMsg.cogMsgId = DSS_JOINING;
            sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sithMulti_sendto_id, 1, 0);
        }
        sithNet_dword_832640 = 0;
        sithMulti_sendto_id = 0;
        stdComm_dword_83220C = 2;
        stdComm_dword_832208 = 0;
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
        v4 = sithStrTable_GetUniStringWithFallback("%s_HAS_LEFT_THE_GAME");
        jk_snwprintf(a1a, 0x80u, v4, &jkPlayer_playerInfos[v3]);
        sithConsole_PrintUniStr(a1a);
        sithConsole_AlertSound();
        if ( jkPlayer_playerInfos[v3].net_id == sithNet_serverNetId )
        {
            v5 = sithStrTable_GetUniStringWithFallback("SERVER_LEFT_GAME");
            sithConsole_PrintUniStr(v5);
            sithConsole_AlertSound();
            if ( sithMulti_leaveJoinType != 2 || sithTime_curMs + MULTI_LEAVEJOIN_DELAY_MS < sithMulti_leaveJoinWaitMs )
            {
                sithMulti_leaveJoinType = 2;
                sithMulti_leaveJoinWaitMs = sithTime_curMs + MULTI_LEAVEJOIN_DELAY_MS;
            }
        }
        sithSoundClass_StopSound(jkPlayer_playerInfos[v3].playerThing, 0);
        sithPlayer_Startup(v3);
        if ( sithNet_isServer )
            sithCog_SendSimpleMessageToAll(SITH_MESSAGE_LEAVE, 3, jkPlayer_playerInfos[v3].playerThing->thingIdx, 0, v3);
    }
}

void sithMulti_InitTick(unsigned int tickrate)
{
    sithNet_isMulti = 1;
    sithNet_dword_83262C = stdComm_dplayIdSelf;
    sithNet_serverNetId = 0;
    sithNet_isServer = 0;
    if ( tickrate < TICKRATE_MIN )
    {
        sithNet_tickrate = TICKRATE_MIN;
    }
    else if ( tickrate > TICKRATE_MAX )
    {
        sithNet_tickrate = TICKRATE_MAX;
    }
    else
    {
        sithNet_tickrate = tickrate;
    }
    sithNet_MultiModeFlags = 0;
    sithNet_serverNetId = 0;
    sithNet_dword_8C4BA8 = 0;
}

int sithMulti_ProcessJoinRequest(sithCogMsg *msg)
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

    NETMSG_IN_START(msg);

    v1 = msg->netMsg.thingIdx;

    if ( stdComm_bIsServer && v1 )
    {
        NETMSG_POPSTR(v11, 32);

        sithMulti_verbosePrintf("sithMulti_ProcessJoinRequest, id %x map %s\n", v1, v11);

        if ( __strcmpi(v11, sithWorld_pCurrentWorld->map_jkl_fname) )
        {
            sithMulti_verbosePrintf("Bad map name %s\n", v11);

            NETMSG_START;
            NETMSG_PUSHS32(6);
            NETMSG_PUSHS32(0);
            NETMSG_END(DSS_JOINING);

            sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, v1, 1, 0);
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
            sithMulti_verbosePrintf("Idk 2, %x %x\n", v3, jkPlayer_maxPlayers);
            sithMulti_SendWelcome(v1, v3, v1);
            return 1;
        }
        stdComm_cogMsg_SendEnumPlayers(v1);
        if ( sithMulti_leaveJoinType )
        {
            sithMulti_verbosePrintf("Idk 1\n");
            NETMSG_START;
            NETMSG_PUSHS32(3);
            NETMSG_PUSHS32(0);
            NETMSG_END(DSS_JOINING);

            sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, v1, 1, 0);
            return 1;
        }
        if ( sithNet_dword_832640 )
        {
            if ( sithMulti_sendto_id == v1 )
            {
                sithMulti_verbosePrintf("idk 2\n");
                NETMSG_START;
                NETMSG_PUSHS32(0);
                NETMSG_PUSHF32(0.5);
                NETMSG_END(DSS_JOINING);
                sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, v1, 1, 0);
                return 1;
            }
            else
            {
                sithMulti_verbosePrintf("idk 3\n");
                NETMSG_START;
                NETMSG_PUSHS32(1);
                NETMSG_PUSHS32(0);
                NETMSG_END(DSS_JOINING);
                sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, v1, 1, 0);
                return 1;
            }
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
            sithMulti_verbosePrintf("Too many players\n");
            NETMSG_START;
            NETMSG_PUSHS32(5);
            NETMSG_PUSHS32(0);
            NETMSG_END(DSS_JOINING);
            sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, v1, 1, 0);

            return 1;
        }
        sithMulti_requestConnectIdx = v5;
        DirectPlay_EnumPlayers(0);
        v7 = 0;
        for (v7 = 0; v7 < DirectPlay_numPlayers; v7++)
        {
            if (DirectPlay_aPlayers[v7].dpId == v1) break;
        }
        if ( v7 != DirectPlay_numPlayers )
        {
            sithMulti_verbosePrintf("aaaaaa %x\n", sithMulti_requestConnectIdx);
            sithPlayer_sub_4C8910(sithMulti_requestConnectIdx);

            NETMSG_POPWSTR(jkPlayer_playerInfos[sithMulti_requestConnectIdx].player_name, 0x10);
            NETMSG_POPWSTR(jkPlayer_playerInfos[sithMulti_requestConnectIdx].multi_name, 0x20);
            //jkPlayer_playerInfos[sithMulti_requestConnectIdx].net_id = v1; // Added?
            //jkPlayer_playerInfos[sithMulti_requestConnectIdx].flags = 5;

            uint32_t popped_check = NETMSG_POPS32();
            v10 = sithNet_checksum;
            if ( v10 != popped_check )
            {
                sithMulti_verbosePrintf("Bad checksum %x vs %x\n", v10, popped_check);
#if 0
                NETMSG_START;
                NETMSG_PUSHS32(4);
                NETMSG_PUSHS32(0);
                NETMSG_END(DSS_JOINING);
                sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, v1, 1, 0);
                return 1;
#endif
            }

            sithMulti_verbosePrintf("Sending the final\n");
            NETMSG_START;
            NETMSG_PUSHS32(0);
            NETMSG_PUSHF32(0.25);
            NETMSG_END(DSS_JOINING);
            sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, v1, 1, 0);

            sithMulti_SendLeaveJoin(v1, 0);
            sithNet_dword_832640 = 1;
            sithMulti_sendto_id = v1;
            stdComm_dword_83220C = 2;
            stdComm_dword_832208 = 0;
            stdComm_dword_832200 = 0;
            stdComm_dword_832210 = 0;
            sithNet_dword_832620 = 0;
        }
    }
    return 1;
}

void stdComm_cogMsg_SendEnumPlayers(int sendtoId)
{
    NETMSG_START_2;

    DirectPlay_EnumPlayers(0);


    NETMSG_PUSHU8(DirectPlay_numPlayers);

    for (int i = 0; i < DirectPlay_numPlayers; i++)
    {
        NETMSG_PUSHS32(DirectPlay_aPlayers[i].dpId)
    }

    NETMSG_END_2(DSS_ENUMPLAYERS);
    sithComm_SendMsgToPlayer(&stdComm_cogMsgTmp, sendtoId, 1, 1);
}

int stdComm_cogMsg_HandleEnumPlayers(sithCogMsg *msg)
{
    int v2; // ebx
    int v3; // edi
    uint32_t v4; // eax
    sithDplayPlayer* v5; // ecx
    signed int result; // eax

    NETMSG_IN_START(msg);

    uint8_t arg0 = NETMSG_POPU8();

    if ( !sithNet_isServer && !stdComm_dword_8321E8 && (g_submodeFlags & 8) != 0 )
    {
        DirectPlay_EnumPlayers(0);
        v2 = 0;
        if ( !arg0 )
        {
LABEL_11:
            result = 1;
            stdComm_dword_8321E8 = 1;
            return result;
        }
        while ( 1 )
        {
            v3 = NETMSG_POPS32();
            v4 = 0;
            if ( DirectPlay_numPlayers )
            {
                v5 = &DirectPlay_aPlayers[0];
                do
                {
                    if ( v3 == v5->dpId )
                        break;
                    ++v4;
                    ++v5;
                }
                while ( v4 < DirectPlay_numPlayers );
            }
            if ( v4 == DirectPlay_numPlayers )
                break;
            if ( ++v2 >= arg0 )
                goto LABEL_11;
        }
        DirectPlay_StartSession(&stdComm_dplayIdSelf, jkPlayer_playerShortName);
    }
    return 1;
}

// MOTS altered
void sithMulti_HandleTimeLimit(int deltaMs)
{
    wchar_t *v1; // eax
    unsigned int v2; // esi
    int v4; // ecx
    unsigned int v7; // esi
    sithSurface *v8; // edx
    sithSurface *v9; // ecx
    unsigned int v10; // edi
    sithSector *v11; // esi
    sithSector *v12; // ecx
    sithThing *v14; // esi
    unsigned int v16; // ecx
    unsigned int v19; // [esp+10h] [ebp-4h]
    unsigned int deltaMsa; // [esp+18h] [ebp+4h]

    if (!sithNet_isMulti)
        return;

    sithThing_Sync();
    sithSurface_Sync();
    sithSector_Sync();
    if ( sithMulti_leaveJoinType && sithTime_curMs > sithMulti_leaveJoinWaitMs )
    {
        if ( sithMulti_leaveJoinType == 1 )
        {
            sithMulti_leaveJoinType = 0;
            sithMain_SetEndLevel();
        }
        else if ( sithMulti_leaveJoinType == 2 )
        {
            sithMulti_leaveJoinType = 0;
            sithMain_set_sithmode_5();
        }
    }
    else if ( sithNet_isServer )
    {
        if ( sithNet_bSyncScores )
        {
            sithNet_bSyncScores = 0;
            sithMulti_SendLeaveJoin(-1, 0);
        }
        if ( (sithNet_MultiModeFlags & MULTIMODEFLAG_TIMELIMIT) != 0 && sithTime_curMs > sithNet_multiplayer_timelimit )
        {
            v1 = sithStrTable_GetUniStringWithFallback("MULTI_TIMELIMIT");
            stdString_WcharToChar(std_genBuffer, v1, 127);
            std_genBuffer[127] = 0;
            sithConsole_Print(std_genBuffer);
            sithConsole_AlertSound();
            v2 = strlen(std_genBuffer) + 1;
            if ( v2 >= 0x80 )
                v2 = 128;

            NETMSG_START;

            NETMSG_PUSHS32(-1);
            NETMSG_PUSHS32(-1);
            NETMSG_PUSHS32(v2);
            NETMSG_PUSHSTR(std_genBuffer, v2);
            NETMSG_END(DSS_CHAT);

            sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, -1, 1, 1);
            sithMulti_bTimelimitMet = 1;
            sithNet_MultiModeFlags &= ~MULTIMODEFLAG_TIMELIMIT;
        }
        if ( sithNet_dword_832640 )
        {
            if ( sithMulti_leaveJoinType )
            {
                if ( sithMulti_sendto_id )
                {
                    NETMSG_START;

                    NETMSG_PUSHS32(3);
                    NETMSG_PUSHS32(0);
                    NETMSG_END(DSS_JOINING);
                    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sithMulti_sendto_id, 1, 0);
                }
                sithNet_dword_832640 = 0;
                sithMulti_sendto_id = 0;
                stdComm_dword_83220C = 2;
                stdComm_dword_832208 = 0;
            }
            else
            {
                v4 = sithMulti_dword_832664 + deltaMs;
                v19 = (sithMulti_dword_832664 + deltaMs) / MULTI_BIG_UPDATE_INTERVAL_MS;
                deltaMsa = 0;
                sithMulti_dword_832664 = v4 - MULTI_BIG_UPDATE_INTERVAL_MS * v19;
                if ( v19 )
                {
                    do
                    {
                        switch ( stdComm_dword_83220C )
                        {
                        case 1:
                            v10 = sithWorld_pCurrentWorld->numSectors;
                            if ( stdComm_dword_832208 >= v10 )
                                goto LABEL_42;
                            v11 = &sithWorld_pCurrentWorld->sectors[stdComm_dword_832208];
                            while ( 1 )
                            {
                                v12 = v11;
                                ++stdComm_dword_832208;
                                ++v11;
                                if ( v12->flags & SITH_SECTOR_SYNC )
                                    break;
                                if ( (v12->flags & SITH_SECTOR_ADJOINS_SET) != 0 )
                                {
                                    sithDSS_SendSectorFlags(v12, sithMulti_sendto_id, 1);
                                    goto LABEL_41;
                                }
                                if ( stdComm_dword_832208 >= v10 )
                                {
LABEL_42:
                                    if ( stdComm_dword_832208 >= sithWorld_pCurrentWorld->numSectors )
                                    {
                                        stdComm_dword_832208 = 0;
                                        stdComm_dword_83220C = 3;
                                        stdComm_dword_832208 = 0;
                                    }
                                    ++stdComm_dword_832210;
                                    goto LABEL_64;
                                }
                            }
                            sithDSS_SendSectorStatus(v12, sithMulti_sendto_id, 1);
LABEL_41:
                            goto LABEL_42;
                        case 2:
                            v7 = sithWorld_pCurrentWorld->numSurfaces;
                            if ( stdComm_dword_832208 >= v7 )
                                goto LABEL_30;
                            v8 = &sithWorld_pCurrentWorld->surfaces[stdComm_dword_832208];
                            while ( 1 )
                            {
                                v9 = v8;
                                ++stdComm_dword_832208;
                                ++v8;
                                if ( (v9->surfaceFlags & SITH_SURFACE_CHANGED) != 0 )
                                    break;
                                if ( stdComm_dword_832208 >= v7 )
                                {
                                    goto LABEL_30;
                                }
                            }
                            sithDSS_SendSurfaceStatus(v9, sithMulti_sendto_id, 1);
LABEL_30:
                            if ( stdComm_dword_832208 >= sithWorld_pCurrentWorld->numSurfaces )
                            {
                                stdComm_dword_832208 = 0;
                                stdComm_dword_83220C = 1;
                                stdComm_dword_832208 = 0;
                            }
                            ++stdComm_dword_832200;
                            goto LABEL_64;
                        case 3:
                            if ( (signed int)stdComm_dword_832208 > sithWorld_pCurrentWorld->numThings )
                                goto LABEL_56;
                            break;
                        case 4:
                            if ( stdComm_dword_832208 >= sithMulti_dword_83265C
                                    || (sithDSSThing_SendDestroyThing(sithMulti_arr_832218[stdComm_dword_832208], sithMulti_sendto_id),
                                        ++stdComm_dword_832208,
                                        stdComm_dword_832208 >= sithMulti_dword_83265C) )
                            {
                                v16 = sithMulti_requestConnectIdx;
                                if ( (sithNet_MultiModeFlags & MULTIMODEFLAG_TEAMS) != 0 && (sithNet_MultiModeFlags & MULTIMODEFLAG_100) != 0 )
                                    jkPlayer_playerInfos[sithMulti_requestConnectIdx].teamNum = (sithMulti_requestConnectIdx & 1) + 1;
                                sithMulti_verbosePrintf("Last sync %x %x\n", sithMulti_sendto_id, sithMulti_requestConnectIdx);
                                jkPlayer_playerInfos[v16].net_id = sithMulti_sendto_id;
                                sithMulti_SendLeaveJoin(sithMulti_sendto_id, 1);
                                sithMulti_SendWelcome(sithMulti_sendto_id, sithMulti_requestConnectIdx, sithMulti_sendto_id);

                                stdComm_dword_832208 = 0;
                                sithNet_dword_832640 = 0;
                                sithMulti_sendto_id = 0;
                                stdComm_dword_83220C = 2;
                                stdComm_dword_832208 = 0;
                                sithNet_bSyncScores = 1;
                            }
                            goto LABEL_64;
                        default:
                            return;
                        }

                        while ( 1 )
                        {
                            v14 = &sithWorld_pCurrentWorld->things[stdComm_dword_832208];
                            stdComm_dword_832208++;
                            if ( sithThing_ShouldSync(v14) )
                            {
                                if ( v14->type != SITH_THING_WEAPON && v14->type != SITH_THING_EXPLOSION )
                                    break;
                            }
                            if ( stdComm_dword_832208 > sithWorld_pCurrentWorld->numThings )
                                goto LABEL_55;
                        }

                        if ( (v14->thing_id & 0xFFFF0000) != 0 )
                            sithDSSThing_SendFullDesc(v14, sithMulti_sendto_id, 1);
                        else
                            sithDSSThing_SendSyncThing(v14, sithMulti_sendto_id, 1);

                        sithDSSThing_SendPos(v14, sithMulti_sendto_id, 0);

                        // Added: co-op
                        if (v14->type == SITH_THING_CORPSE || ((v14->type == SITH_THING_ACTOR || v14->type == SITH_THING_PLAYER) && v14->thingflags & SITH_TF_DEAD)) {
                            //sithDSSThing_SendSyncThing(v14, sithMulti_sendto_id, 1);
                            //sithDSS_SendSyncAI(v14->actor, sithMulti_sendto_id, 1);
                            if (v14->rdthing.puppet)
                                sithDSS_SendSyncPuppet(v14, sithMulti_sendto_id, 255);
                        }

LABEL_55:
                        if ( (signed int)stdComm_dword_832208 > sithWorld_pCurrentWorld->numThings )
                        {
LABEL_56:
                            stdComm_dword_832208 = 0;
                            stdComm_dword_83220C = 4;
                            stdComm_dword_832208 = 0;
                        }
                        ++sithNet_dword_832620;
LABEL_64:
                        ++deltaMsa;
                    }
                    while ( deltaMsa < v19 );
                }
            }
        }
    }
}

uint32_t sithMulti_IterPlayersnothingidk(int net_id)
{
    uint32_t result; // eax
    sithPlayerInfo* i; // ecx

    result = 0;
    if ( !jkPlayer_maxPlayers )
        return -1;
    for ( i = &jkPlayer_playerInfos[0]; net_id != i->net_id; ++i )
    {
        if ( ++result >= jkPlayer_maxPlayers )
            return -1;
    }
    return result;
}

int sithMulti_SendPing(int sendtoId)
{
    sithMulti_dword_832654 = sithTime_curMs;
    sithComm_netMsgTmp.pktData[0] = sithTime_curMs;
    sithComm_netMsgTmp.netMsg.msg_size = 4;
    sithComm_netMsgTmp.netMsg.flag_maybe = 0;
    sithComm_netMsgTmp.netMsg.cogMsgId = DSS_PING;
    return sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sendtoId, 1, 0);
}