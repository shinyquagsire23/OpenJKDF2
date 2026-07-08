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
    sithMulti_pfNewPlayerJoinedCallback = a1;
}

void sithMulti_SendChat(const char *pStr, int arg0, int arg1)
{
    uint32_t pStr_len; // esi

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
int sithMulti_ProcessChat(SithMessage *pMsg)
{
    // Added: 132 -> 256
    char v5[256];

    NETMSG_IN_START(pMsg);

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
    sithConsole_PrintWString(sithMulti_chatWStrTmp); // Added: char -> wchar
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
        sithEvent_RegisterTask(2, sithMulti_CheckPlayers, rate, 1); // TODO enum
        result = 0;
    }
    return result;
}

int sithMulti_StartupServer()
{
    sithNet_MultiModeFlags = sithMulti_multiModeFlags;
    sithNet_scorelimit = stdComm_dword_832204;
    sithNet_multiplayer_timelimit = sithMulti_multiplayerTimelimit;
    for (uint32_t i = 0; i < 32; ++i )
    {
        sithPlayer_Reset(i);
        sithPlayer_Startup(i);
    }
    sithNet_teamScore[0] = 0;
    sithNet_teamScore[1] = 0;
    sithNet_teamScore[2] = 0;
    sithNet_teamScore[3] = 0;
    sithNet_teamScore[4] = 0;
    sithPlayer_ShowPlayer(0, stdComm_dplayIdSelf);
    sithPlayer_SetLocalPlayer(0);
    sithPlayer_ResetPalEffects();

    // Added: dedicated server
    if (jkGuiNetHost_bIsDedicated) {
        jkPlayer_playerInfos[0].flags = 6;
        jkPlayer_playerInfos[0].pLocalPlayer->flags |= SITH_TF_DISABLED;
        jkPlayer_playerInfos[0].pLocalPlayer->attach_flags = 0;
    }

    if ( (sithNet_MultiModeFlags & MULTIMODEFLAG_100) != 0 )
    {
        jkPlayer_playerInfos[0].teamNum = 1;
    }
    stdComm_DoReceive();
    return 1;
}

int sithMulti_StartupClient()
{
    sithNet_isServer = 0;
    sithNet_isMulti = 1;
    for (uint32_t i = 0; i < 32; ++i )
    {
        sithPlayer_Reset(i);
        sithPlayer_Startup(i);
    }
    sithNet_teamScore[0] = 0;
    sithNet_teamScore[1] = 0;
    sithNet_teamScore[2] = 0;
    sithNet_teamScore[3] = 0;
    sithNet_teamScore[4] = 0;
    stdComm_DoReceive();
    return 1;
}

void sithMulti_RemoveAllActorsFromWorld(SithWorld *pWorld)
{
    // Added: nullptr check
    if (!pWorld) {
        return;
    }

    sithMulti_numRemovedStaticThings = 0;

    // Added: Co-op
    if (sithMulti_multiModeFlags & MULTIMODEFLAG_COOP) {
        return;
    } 

    for (int i = 0; i <= pWorld->numThings; i++)
    {
        SithThing* pIter = &pWorld->aThings[i];
        if ( pIter->type == SITH_THING_ACTOR )
        {
            sithThing_RemoveThing(pIter);
        }
        else if ( !sithNet_isServer )
        {
            pIter->flags |= SITH_TF_INVULN;
        }
    }
}

int sithMulti_Startup()
{
    int v2; // eax
    int v3; // edi
    SithThing **v5; // ebp
    int v7; // ecx

    g_submodeFlags |= 1u;
    sithMulti_quitGameState = 0;
    sithMulti_bTimelimitMet = 0;
    sithMessage_g_outputstream |= 1u;
    sithMessage_g_inputstream |= 1u;

    // Remove all actor aThings from the world
    sithMulti_RemoveAllActorsFromWorld(sithWorld_g_pCurrentWorld);

    sithNet_checksum = sithWorld_CalcWorldChecksum(sithWorld_g_pCurrentWorld, 0/*jkGuiMultiplayer_checksumSeed*/); // Added: TODO fix the checksum seed
    sithNet_syncIdx = 0;
    sithSurface_numUnsyncedSurfaces = 0;
    sithSector_numModifiedSectors = 0;
    sithNet_bNeedsFullThingSyncForLeaveJoin = 0;
    sithComm_ClearMsgTmpBuf();
    if ( stdComm_bIsServer )
    {
        return sithMulti_StartupServer();
    }
    else
    {
        return sithMulti_StartupClient();
    }
}

void sithMulti_RemoveStaticThing(int guid)
{
    if ( sithMulti_numRemovedStaticThings < 0x100 )
    {
        sithMulti_aRemovedStaticThings[sithMulti_numRemovedStaticThings++] = guid;
    }
}

void sithMulti_Shutdown()
{
    sithMessage_g_outputstream &= ~1u;
    sithNet_isMulti = 0;
    sithNet_isServer = 0;
    sithMessage_g_inputstream &= ~1u;
    sithEvent_RegisterTask(2, 0, 0, 0);
    stdComm_Close();
    stdComm_CloseConnection();
}

int sithMulti_SendJoinRequest(int sendto_id)
{
    NETMSG_START;

    NETMSG_PUSHSTR(sithWorld_g_pCurrentWorld->map_jkl_fname, 0x20);
    NETMSG_PUSHWSTR(jkPlayer_playerShortName, 0x10);
    NETMSG_PUSHWSTR(sithMulti_name, 0x20);
    NETMSG_PUSHU32(sithNet_checksum);

    NETMSG_END(DSS_JOINREQUEST);
    return sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sendto_id, 1, 0);
}

int sithMulti_GetSpawnIdx(SithThing *pPlayerThing)
{
    uint32_t v2; // ebp
    uint32_t v3; // ecx
    int *v4; // eax
    int v5; // edx
    uint32_t v7; // ebx
    int v8; // edi
    SithCollision *i; // esi
    SithThing *v10; // eax
    uint32_t v11; // [esp+10h] [ebp-90h]
    int v12[32]; // [esp+20h] [ebp-80h] BYREF
    int realMaxSpawns = jkPlayer_maxPlayers;

    // Added: Spawn at start in co-op.
    if (sithNet_MultiModeFlags & MULTIMODEFLAG_COOP) {
        return 0;
    }

    // Added: zero out v12
    memset(v12, 0, sizeof(v12));

    v2 = 0;
    v11 = 0;
    v4 = v12;
    v5 = pPlayerThing->actorParams.pPlayer->respawnMask;
    for (v3 = 0; v3 < jkPlayer_maxPlayers; v3++)
    {
        // Added: HACK for weird maps w/ <32 spawn points
        if (!jkPlayer_playerInfos[v3].pInSector && v3 < realMaxSpawns) {
            realMaxSpawns = v3;
        }

        if ( ((1 << v3) & v5) == 0 )
        {
            *v4 = v3;
            ++v2;
            ++v4;
        }
    }
    if ( !v2 )
        return 0;
    if ( v2 == 1 )
        return v12[0];
    v7 = (__int64)(_frand() * (flex_d_t)v2);
    if ( v7 > v2 - 1 )
        v7 = v2 - 1;
    while ( 1 )
    {
        v8 = v12[v7];
        v8 = v8 % realMaxSpawns; // Added: HACK for weird maps w/ <32 spawn points
        sithCollision_SearchForCollisions(
            jkPlayer_playerInfos[v8].pInSector,
            0,
            &jkPlayer_playerInfos[v8].orient.scale,
            &rdroid_zeroVector3,
            0.0,
            pPlayerThing->moveSize,
            RAYCAST_400 | RAYCAST_80 | RAYCAST_2);
        for ( i = sithCollision_PopStack(); i; i = sithCollision_PopStack() )
        {
            if ( (i->type & SITHCOLLISION_THING) != 0 )
            {
                v10 = i->pThingCollided;
                if ( v10->type == SITH_THING_PLAYER && (v10->flags & (SITH_TF_DEAD|SITH_TF_DESTROYED)) == 0 )
                    break;
            }
        }
        sithCollision_DecreaseStackLevel();
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

void sithMulti_ProcessKilledPlayer(SithPlayer *pPlayer, SithThing *pPlayerThing, SithThing *pKiller)
{
    flex_d_t v3; // st7
    wchar_t *v4; // eax
    wchar_t *v5; // eax
    wchar_t *v6; // eax
    wchar_t *v7; // [esp-8h] [ebp-114h]
    wchar_t *v8; // [esp-8h] [ebp-114h]
    SithPlayer *v9; // [esp-4h] [ebp-110h]
    SithPlayer *v10; // [esp-4h] [ebp-110h]
    wchar_t a1a[128]; // [esp+Ch] [ebp-100h] BYREF

    ++pPlayer->numKilled;
    if ( !pKiller || pKiller->type != SITH_THING_PLAYER )
    {
        v6 = sithStrTable_GetUniStringWithFallback("%s_DIED");
        jk_snwprintf(a1a, 0x80u, v6, pPlayer);
        sithConsole_PrintWString(a1a);
        goto LABEL_15;
    }
    if ( pKiller != pPlayerThing )
    {
        v10 = pKiller->actorParams.pPlayer;
        v5 = sithStrTable_GetUniStringWithFallback("%s_WAS_KILLED_BY_%s");
        jk_snwprintf(a1a, 0x80u, v5, pPlayer, v10);
        sithConsole_PrintWString(a1a);
        ++pKiller->actorParams.pPlayer->numKills;
        sithMulti_ProcessScore();
        return;
    }
    v3 = _frand() * 4.0;
    if ( v3 < 1.0 )
    {
        v9 = pPlayer;
        v4 = sithStrTable_GetUniStringWithFallback("%s_COMMITTED_SUICIDE0");
LABEL_11:
        jk_snwprintf(a1a, 0x80u, v4, v9);
        goto LABEL_12;
    }
    if ( v3 >= 2.0 )
    {
        v9 = pPlayer;
        if ( v3 >= 3.0 )
        {
            v4 = sithStrTable_GetUniStringWithFallback("%s_COMMITTED_SUICIDE3");
            goto LABEL_11;
        }
        v8 = sithStrTable_GetUniStringWithFallback("%s_COMMITTED_SUICIDE2");
        jk_snwprintf(a1a, 0x80u, v8, pPlayer);
    }
    else
    {
        v7 = sithStrTable_GetUniStringWithFallback("%s_COMMITTED_SUICIDE1");
        jk_snwprintf(a1a, 0x80u, v7, pPlayer);
    }
LABEL_12:
    sithConsole_PrintWString(a1a);
LABEL_15:
    ++pPlayer->numSuicides;
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
                    sithMulti_infoPrintf("Player score limit met by player %d (netid %u), %u pts of %u\n", i, jkPlayer_playerInfos[i].playerNetId, jkPlayer_playerInfos[i].score, sithNet_scorelimit);
                }
            }
        }
        if ( score_limit_met )
        {
            wchar_t* v9 = sithStrTable_GetUniStringWithFallback("MULTI_SCORELIMIT");
            stdString_WcharToChar(std_g_genBuffer, v9, 127);
            std_g_genBuffer[127] = 0;
            sithConsole_PrintString(std_g_genBuffer);
            sithConsole_AlertSound();
            uint32_t v10 = strlen(std_g_genBuffer) + 1;
            if ( v10 >= 0x80 )
                v10 = 128;

            NETMSG_START;
            //NETMSG_PUSHS16(1);// MOTS added
            NETMSG_PUSHS32(-1);
            NETMSG_PUSHS32(-1);
            NETMSG_PUSHS32(v10);
            NETMSG_PUSHSTR(std_g_genBuffer, v10);
            NETMSG_END(DSS_CHAT);

            sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, -1, 1, 1);

            sithMulti_bTimelimitMet = 1;
            sithNet_MultiModeFlags &= ~MULTIMODEFLAG_TIMELIMIT;
        }
    }
}

void sithMulti_QuitGame(uint32_t msecTime, int state)
{
    if ( sithMulti_quitGameState != state || msecTime < sithMulti_msecQuitGameTime )
    {
        sithMulti_quitGameState = state;
        sithMulti_msecQuitGameTime = msecTime;
    }
}

void sithMulti_SendWelcome(int idPlayer, int playerNum, int idTo)
{
    NETMSG_START;

    NETMSG_PUSHS32(playerNum);
    NETMSG_PUSHS32(idPlayer);
    NETMSG_PUSHWSTR(jkPlayer_playerInfos[playerNum].player_name, 0x10);
    NETMSG_END(DSS_WELCOME);

    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, idTo, 1, 1);
}

void sithMulti_QuitPlayer(int id)
{
    if (!sithNet_isServer) return;

    NETMSG_START;

    NETMSG_PUSHS32(id);
    NETMSG_END(DSS_QUIT);

    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, id, 1, 1);
}

int sithMulti_LobbyMessage()
{
    int16_t v0; // bp

    if ( sithNet_isServer )
    {
        if ( sithNet_bNeedsFullThingSyncForLeaveJoin )
        {
            if ( sithMulti_newPlayerId )
            {
                NETMSG_START;

                NETMSG_PUSHS32(3);
                NETMSG_PUSHS32(0);
                NETMSG_END(DSS_JOINING);
                sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sithMulti_newPlayerId, 1, 0);
            }
            sithNet_bNeedsFullThingSyncForLeaveJoin = 0;
            sithMulti_newPlayerId = 0;
            stdComm_currentBigSyncStage = 2;
            stdComm_dword_832208 = 0;
        }
        if ( stdComm_dword_8321F8 )
        {
            NETMSG_START;

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
                SithPlayer* v6 = &jkPlayer_playerInfos[i];
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

int sithMulti_ProcessWelcome(SithMessage *pMsg)
{
    int v1; // edi
    int v2; // ebx
    int v4; // ecx
    int v5; // edx
    SithPlayer* v6; // eax
    wchar_t *v8; // eax
    wchar_t a1a[128]; // [esp+10h] [ebp-100h] BYREF

    NETMSG_IN_START(pMsg);

    v1 = NETMSG_POPS32();
    v2 = NETMSG_POPS32();
    NETMSG_POPWSTR(jkPlayer_playerInfos[v1].player_name, 0x10);

    sithMulti_verbosePrintf("sithMulti_ProcessWelcome %x %x %x\n", v1, v2, stdComm_dplayIdSelf);

    if ( v2 != stdComm_dplayIdSelf )
    {
        if ( (jkPlayer_playerInfos[v1].flags & 1) == 0 )
        {
            sithPlayer_ShowPlayer(v1, v2);
            v8 = sithStrTable_GetUniStringWithFallback("%s_HAS_JOINED_THE_GAME");
            jk_snwprintf(a1a, 0x80u, v8, jkPlayer_playerInfos[v1].player_name);
            sithConsole_PrintWString(a1a);
            jkPlayer_playerInfos[v1].msecLastCommTime = sithTime_g_msecGameTime;
            if ( sithNet_isServer )
                sithCog_BroadcastMessage(SITH_MESSAGE_JOIN, 3, jkPlayer_playerInfos[v1].pLocalPlayer->idx, 0, v1);
            if ( sithMulti_pfNewPlayerJoinedCallback )
                sithMulti_pfNewPlayerJoinedCallback();
            sithDSSThing_UpdateState(sithPlayer_g_pLocalPlayerThing, -1, 255);
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
        v5 = sithTime_g_msecGameTime;
        v6 = &jkPlayer_playerInfos[0];
        do
        {
            v6->msecLastCommTime = v5;
            v6++;
            --v4;
        }
        while ( v4 );
    }
    g_submodeFlags &= ~8u;
    sithThing_LoadPostProcess();
    sithPlayer_ShowPlayer(v1, v2);
    sithPlayer_SetLocalPlayer(v1); // sets playerThingIdx and info
    sithPlayer_ResetPalEffects();
    sithEvent_RegisterTask(2, sithMulti_CheckPlayers, sithNet_tickrate, 1);
    sithMessage_StopProcessMessages();
    return 1;
}

int sithMulti_ProcessPing(SithMessage *pMsg)
{
    pMsg->netMsg.cogMsgId = DSS_PINGREPLY;
    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, pMsg->netMsg.idx, 1, 0);
    return 1;
}

int sithMulti_ProcessPong(SithMessage *pMsg)
{
    int v1; // eax
    SithPlayer* i; // ecx

    if ( pMsg->pktData[0] == sithMulti_msecPingStartTime )
    {
        v1 = 0;
        if ( jkPlayer_maxPlayers )
        {
            for ( i = &jkPlayer_playerInfos[0]; i->playerNetId != pMsg->netMsg.idx; ++i )
            {
                if ( ++v1 >= jkPlayer_maxPlayers )
                    return 1;
            }
            _sprintf(std_g_genBuffer, "Ping time to %S is %d msec", jkPlayer_playerInfos[v1].player_name, sithTime_g_msecGameTime - sithMulti_msecPingStartTime);
            sithConsole_PrintString(std_g_genBuffer);
        }
    }
    return 1;
}

int sithMulti_ProcessQuit(SithMessage *pMsg)
{
    wchar_t *v2; // eax
    int v3; // eax
    int v4; // edi
    int v5; // esi
    wchar_t *v6; // eax
    wchar_t *v7; // eax
    wchar_t a1a[128]; // [esp+Ch] [ebp-100h] BYREF

    if ( pMsg->netMsg.idx != sithNet_serverNetId )
        return 0;
    if ( pMsg->pktData[0] == stdComm_dplayIdSelf )
    {
        if ( sithMulti_quitGameState != 2 )
        {
            v2 = sithStrTable_GetUniStringWithFallback("MULTI_EJECTED");
            sithConsole_PrintWString(v2);
            sithConsole_AlertSound();
            if ( sithMulti_quitGameState != 2 || sithTime_g_msecGameTime + MULTI_LEAVEJOIN_DELAY_MS < sithMulti_msecQuitGameTime )
            {
                sithMulti_msecQuitGameTime = sithTime_g_msecGameTime + MULTI_LEAVEJOIN_DELAY_MS;
                sithMulti_quitGameState = 2;
                return 1;
            }
        }
    }
    else
    {
        v3 = sithPlayer_GetPlayerNum(pMsg->pktData[0]);
        v4 = v3;
        if ( v3 >= 0 )
        {
            v5 = v3;
            v6 = sithStrTable_GetUniStringWithFallback("%s_HAS_LEFT_THE_GAME");
            jk_snwprintf(a1a, 0x80u, v6, &jkPlayer_playerInfos[v5]);
            sithConsole_PrintWString(a1a);
            sithConsole_AlertSound();
            if ( jkPlayer_playerInfos[v5].playerNetId == sithNet_serverNetId )
            {
                v7 = sithStrTable_GetUniStringWithFallback("SERVER_LEFT_GAME");
                sithConsole_PrintWString(v7);
                sithConsole_AlertSound();
                if ( sithMulti_quitGameState != 2 || sithTime_g_msecGameTime + MULTI_LEAVEJOIN_DELAY_MS < sithMulti_msecQuitGameTime )
                {
                    sithMulti_quitGameState = 2;
                    sithMulti_msecQuitGameTime = sithTime_g_msecGameTime + MULTI_LEAVEJOIN_DELAY_MS;
                }
            }
            sithSoundClass_StopSound(jkPlayer_playerInfos[v5].pLocalPlayer, 0);
            sithPlayer_Startup(v4);
            if ( sithNet_isServer )
                sithCog_BroadcastMessage(SITH_MESSAGE_LEAVE, 3, jkPlayer_playerInfos[v5].pLocalPlayer->idx, 0, v4);
        }
    }
    return 1;
}

int sithMulti_CheckPlayers(int32_t msecTime, SithEventParams* pParam)
{
    uint32_t v0; // edi
    SithPlayer* v1; // esi
    int v2; // eax
    wchar_t *v3; // eax
    wchar_t *v4; // eax
    wchar_t *v6; // eax
    wchar_t *v7; // eax
    wchar_t a1[128]; // [esp+10h] [ebp-100h] BYREF

    if ( sithWorld_g_pCurrentWorld && sithPlayer_g_pLocalPlayerThing && (g_submodeFlags & 8) == 0 )
        sithDSSThing_Pos(sithPlayer_g_pLocalPlayerThing, -1, 0);
    if ( sithNet_isServer )
    {
        v0 = 1;
        if ( jkPlayer_maxPlayers > 1 )
        {
            v1 = &jkPlayer_playerInfos[1];
            do
            {
                if ( (v1->flags & 1) != 0 && sithTime_g_msecGameTime > v1->msecLastCommTime + MULTI_TIMEOUT_MS )
                {
                    v2 = v1->playerNetId;
                    if ( sithNet_isServer )
                    {
                        sithComm_netMsgTmp.pktData[0] = v1->playerNetId;
                        sithComm_netMsgTmp.netMsg.msg_size = 4;
                        sithComm_netMsgTmp.netMsg.flag_maybe = 0;
                        sithComm_netMsgTmp.netMsg.cogMsgId = DSS_QUIT;
                        sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, v2, 1, 1);
                    }
                    v3 = sithStrTable_GetUniStringWithFallback("%s_HAS_LEFT_THE_GAME");
                    jk_snwprintf(a1, 0x80u, v3, v1);
                    sithConsole_PrintWString(a1);
                    sithConsole_AlertSound();
                    if ( v1->playerNetId == sithNet_serverNetId )
                    {
                        v4 = sithStrTable_GetUniStringWithFallback("SERVER_LEFT_GAME");
                        sithConsole_PrintWString(v4);
                        sithConsole_AlertSound();
                        if ( sithMulti_quitGameState != 2 || sithTime_g_msecGameTime + MULTI_LEAVEJOIN_DELAY_MS < sithMulti_msecQuitGameTime )
                        {
                            sithMulti_quitGameState = 2;
                            sithMulti_msecQuitGameTime = sithTime_g_msecGameTime + MULTI_LEAVEJOIN_DELAY_MS;
                        }
                    }
                    sithSoundClass_StopSound(v1->pLocalPlayer, 0);
                    sithPlayer_Startup(v0);
                    if ( sithNet_isServer )
                        sithCog_BroadcastMessage(SITH_MESSAGE_LEAVE, 3, v1->pLocalPlayer->idx, 0, v0);
                }
                ++v0;
                ++v1;
            }
            while ( v0 < jkPlayer_maxPlayers );
        }
        if ( sithMulti_msecLastSyncScoreTime + MULTI_SCORE_UPDATE_INTERVAL_MS < sithTime_g_clockTime )
        {
            sithMulti_msecLastSyncScoreTime = sithTime_g_clockTime;
            sithNet_bSyncScores = 1;
            return 1;
        }
    }
    else if ( sithTime_g_msecGameTime > jkPlayer_playerInfos[0].msecLastCommTime + MULTI_TIMEOUT_MS )
    {
        jkPlayer_playerInfos[0].msecLastCommTime = sithTime_g_msecGameTime;
        v6 = sithStrTable_GetUniStringWithFallback("%s_HAS_LEFT_THE_GAME");
        jk_snwprintf(a1, 0x80u, v6, jkPlayer_playerInfos);
        sithConsole_PrintWString(a1);
        sithConsole_AlertSound();
        if ( jkPlayer_playerInfos[0].playerNetId == sithNet_serverNetId )
        {
            v7 = sithStrTable_GetUniStringWithFallback("SERVER_LEFT_GAME");
            sithConsole_PrintWString(v7);
            sithConsole_AlertSound();
            if ( sithMulti_quitGameState != 2 || sithTime_g_msecGameTime + MULTI_LEAVEJOIN_DELAY_MS < sithMulti_msecQuitGameTime )
            {
                sithMulti_quitGameState = 2;
                sithMulti_msecQuitGameTime = sithTime_g_msecGameTime + MULTI_LEAVEJOIN_DELAY_MS;
            }
        }
        sithSoundClass_StopSound(jkPlayer_playerInfos[0].pLocalPlayer, 0);
        sithPlayer_Startup(0);
        if ( sithNet_isServer )
            sithCog_BroadcastMessage(SITH_MESSAGE_LEAVE, 3, jkPlayer_playerInfos[0].pLocalPlayer->idx, 0, 0);
    }
    return 1;
}

void sithMulti_SyncPlayers(int idTo, int dpFlags)
{
    char v15[32]; // [esp+10h] [ebp-20h] BYREF

    NETMSG_START;

    NETMSG_PUSHS32(sithNet_MultiModeFlags);
    NETMSG_PUSHS32(sithNet_serverNetId);
    NETMSG_PUSHS16(jkPlayer_maxPlayers)

    for (int i = 0; i < jkPlayer_maxPlayers; i++)
    {
        SithPlayer* v6 = &jkPlayer_playerInfos[i];
        NETMSG_PUSHS32((sithNet_isServer && jkGuiNetHost_bIsDedicated && !i) ? v6->flags & ~2 : v6->flags);
        if ( (v6->flags & 4) != 0 )
        {
            NETMSG_PUSHS32(v6->playerNetId);

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
    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, idTo, 1, dpFlags);
}

int sithMulti_ProcessSyncPlayers(SithMessage *pMsg)
{
    uint32_t v1; // eax
    int v2; // edx
    uint32_t v3; // ebp
    uint32_t v4; // eax
    SithPlayer* v6; // edi
    int v7; // ecx
    int v8; // eax
    wchar_t *v10; // eax
    wchar_t *v12; // eax
    wchar_t *v13; // eax
    char a2[32]; // [esp+10h] [ebp-220h] BYREF
    wchar_t a1a[128]; // [esp+30h] [ebp-200h] BYREF
    wchar_t v22[128]; // [esp+130h] [ebp-100h] BYREF

    NETMSG_IN_START(pMsg);

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
    jkPlayer_maxPlayers = v4; // TODO cap this to JKPLAYER_NUM_INFOS?
    for (v3 = 0; v3 < jkPlayer_maxPlayers; v3++)
    {
        v6 = &jkPlayer_playerInfos[v3];
        v7 = v6->flags;
        v6->flags = NETMSG_POPS32();
        if ( (v6->flags & 4) != 0 )
        {
            v8 = NETMSG_POPS32();
            v6->playerNetId = v8;
            if ( (v6->flags & 1) == 0 || (v7 & 1) != 0 || (g_submodeFlags & 8) != 0 )
            {
                if ( !v6->playerNetId && (v7 & 1) != 0 && (g_submodeFlags & 8) == 0 )
                {
                    v12 = sithStrTable_GetUniStringWithFallback("%s_HAS_LEFT_THE_GAME");
                    jk_snwprintf(v22, 0x80u, v12, v6);
                    sithConsole_PrintWString(v22);
                    sithConsole_AlertSound();
                    if ( v6->playerNetId == sithNet_serverNetId )
                    {
                        v13 = sithStrTable_GetUniStringWithFallback("SERVER_LEFT_GAME");
                        sithConsole_PrintWString(v13);
                        sithConsole_AlertSound();
                        if ( sithMulti_quitGameState != 2 || sithTime_g_msecGameTime + MULTI_LEAVEJOIN_DELAY_MS < sithMulti_msecQuitGameTime )
                        {
                            sithMulti_quitGameState = 2;
                            sithMulti_msecQuitGameTime = sithTime_g_msecGameTime + MULTI_LEAVEJOIN_DELAY_MS;
                        }
                    }
                    sithSoundClass_StopSound(v6->pLocalPlayer, 0);
                    sithPlayer_Startup(v3);
                    if ( sithNet_isServer )
                        sithCog_BroadcastMessage(SITH_MESSAGE_LEAVE, 3, v6->pLocalPlayer->idx, 0, v3);
                }
            }
            else
            {
                v10 = sithStrTable_GetUniStringWithFallback("%s_HAS_JOINED_THE_GAME");
                jk_snwprintf(a1a, 0x80u, v10, v6);
                sithConsole_PrintWString(a1a);

                v6->msecLastCommTime = sithTime_g_msecGameTime;
                if (sithNet_isServer)
                    sithCog_BroadcastMessage(SITH_MESSAGE_JOIN, 3, v6->pLocalPlayer->idx, 0, v3);
                if ( sithMulti_pfNewPlayerJoinedCallback )
                    sithMulti_pfNewPlayerJoinedCallback();
                sithDSSThing_UpdateState(sithPlayer_g_pLocalPlayerThing, -1, 255);
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
    if (sithNet_MultiModeFlags & MULTIMODEFLAG_TEAMS)
    {
        for (int i = 0; i < 5; i++)
        {
            sithNet_teamScore[i] = NETMSG_POPS16();
        }
    }
    return 1;
}

void sithMulti_ProcessPlayerLost(int idPlayer)
{
    uint32_t v1; // eax
    SithPlayer* v2; // ecx
    int v3; // edi
    wchar_t *v4; // eax
    wchar_t *v5; // eax
    wchar_t a1a[128]; // [esp+Ch] [ebp-100h] BYREF

    if ( sithNet_bNeedsFullThingSyncForLeaveJoin && idPlayer == sithMulti_newPlayerId )
    {
        if ( sithMulti_newPlayerId )
        {
            sithComm_netMsgTmp.pktData[0] = 3;
            sithComm_netMsgTmp.pktData[1] = 0;
            sithComm_netMsgTmp.netMsg.msg_size = 8;
            sithComm_netMsgTmp.netMsg.flag_maybe = 0;
            sithComm_netMsgTmp.netMsg.cogMsgId = DSS_JOINING;
            sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sithMulti_newPlayerId, 1, 0);
        }
        sithNet_bNeedsFullThingSyncForLeaveJoin = 0;
        sithMulti_newPlayerId = 0;
        stdComm_currentBigSyncStage = 2;
        stdComm_dword_832208 = 0;
    }
    v1 = 0;
    if ( jkPlayer_maxPlayers )
    {
        v2 = &jkPlayer_playerInfos[0];
        while ( idPlayer != v2->playerNetId )
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
        sithConsole_PrintWString(a1a);
        sithConsole_AlertSound();
        if ( jkPlayer_playerInfos[v3].playerNetId == sithNet_serverNetId )
        {
            v5 = sithStrTable_GetUniStringWithFallback("SERVER_LEFT_GAME");
            sithConsole_PrintWString(v5);
            sithConsole_AlertSound();
            if ( sithMulti_quitGameState != 2 || sithTime_g_msecGameTime + MULTI_LEAVEJOIN_DELAY_MS < sithMulti_msecQuitGameTime )
            {
                sithMulti_quitGameState = 2;
                sithMulti_msecQuitGameTime = sithTime_g_msecGameTime + MULTI_LEAVEJOIN_DELAY_MS;
            }
        }
        sithSoundClass_StopSound(jkPlayer_playerInfos[v3].pLocalPlayer, 0);
        sithPlayer_Startup(v3);
        if ( sithNet_isServer )
            sithCog_BroadcastMessage(SITH_MESSAGE_LEAVE, 3, jkPlayer_playerInfos[v3].pLocalPlayer->idx, 0, v3);
    }
}

void sithMulti_InitTick(uint32_t tickrate)
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

int sithMulti_ProcessJoinRequest(SithMessage *pMsg)
{
    int v1; // esi
    uint32_t v3; // eax
    SithPlayer* v4; // ecx
    uint32_t v5; // ecx
    SithPlayer* v6; // eax
    uint32_t v7; // eax
    int *v8; // ecx
    uint32_t v9; // eax
    int v10; // ecx
    char v11[32]; // [esp+Ch] [ebp-20h] BYREF

    NETMSG_IN_START(pMsg);

    v1 = pMsg->netMsg.idx;

    if ( stdComm_bIsServer && v1 )
    {
        NETMSG_POPSTR(v11, 32);

        sithMulti_verbosePrintf("sithMulti_ProcessJoinRequest, id %x map %s\n", v1, v11);

        if ( __strcmpi(v11, sithWorld_g_pCurrentWorld->map_jkl_fname) )
        {
            sithMulti_verbosePrintf("Bad map name %s\n", v11);

            NETMSG_START;
            NETMSG_PUSHS32(6);
            NETMSG_PUSHS32(0);
            NETMSG_END(DSS_JOINING);

            sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, v1, 1, 0);
            return 1;
        }
        for (v3 = 0; v3 < jkPlayer_maxPlayers; v3++)
        {
            v4 = &jkPlayer_playerInfos[v3];
            if ( v4->playerNetId == v1 )
                break;
        }
        if ( v3 < jkPlayer_maxPlayers )
        {
            sithMulti_verbosePrintf("Idk 2, %x %x\n", v3, jkPlayer_maxPlayers);
            sithMulti_SendWelcome(v1, v3, v1);
            return 1;
        }

        stdComm_cogMsg_SendEnumPlayers(v1);
        if ( sithMulti_quitGameState )
        {
            sithMulti_verbosePrintf("Idk 1\n");
            NETMSG_START;
            NETMSG_PUSHS32(3);
            NETMSG_PUSHS32(0);
            NETMSG_END(DSS_JOINING);

            sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, v1, 1, 0);
            return 1;
        }
        if ( sithNet_bNeedsFullThingSyncForLeaveJoin )
        {
            if ( sithMulti_newPlayerId == v1 )
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
        for (v5 = 0; v5 < jkPlayer_maxPlayers; v5++)
        {
            v6 = &jkPlayer_playerInfos[v5];
            if ( (v6->flags & 2) != 0 && !v6->playerNetId )
                break;
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
        sithMulti_curWelcomePlayerNum = v5;
        DirectPlay_EnumPlayers(0);
        v7 = 0;
        for (v7 = 0; v7 < DirectPlay_numPlayers; v7++)
        {
            if (DirectPlay_aPlayers[v7].dpId == v1) break;
        }
        if ( v7 != DirectPlay_numPlayers )
        {
            sithMulti_verbosePrintf("aaaaaa %x\n", sithMulti_curWelcomePlayerNum);
            sithPlayer_Reset(sithMulti_curWelcomePlayerNum);

            NETMSG_POPWSTR(jkPlayer_playerInfos[sithMulti_curWelcomePlayerNum].player_name, 0x10);
            NETMSG_POPWSTR(jkPlayer_playerInfos[sithMulti_curWelcomePlayerNum].multi_name, 0x20);
            //jkPlayer_playerInfos[sithMulti_curWelcomePlayerNum].playerNetId = v1; // Added?
            //jkPlayer_playerInfos[sithMulti_curWelcomePlayerNum].flags = 5;

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

            sithMulti_SyncPlayers(v1, 0);
            sithNet_bNeedsFullThingSyncForLeaveJoin = 1;
            sithMulti_newPlayerId = v1;
            stdComm_currentBigSyncStage = 2;
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

int stdComm_cogMsg_HandleEnumPlayers(SithMessage *msg)
{
    int v2; // ebx
    int v3; // edi
    uint32_t v4; // eax
    sithDplayPlayer* v5; // ecx
    int32_t result; // eax

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
            for (v4 = 0; v4 < DirectPlay_numPlayers; v4++)
            {
                v5 = &DirectPlay_aPlayers[v4];
                if ( v3 == v5->dpId )
                    break;
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
void sithMulti_Update(int msecDeltaTime)
{
    uint32_t v2; // esi
    SithSurface *v8; // edx
    SithSurface *v9; // ecx
    SithSector *v11; // esi
    SithThing *v14; // esi
    uint32_t deltaMsa; // [esp+18h] [ebp+4h]

    if (!sithNet_isMulti)
        return;

    sithThing_SyncThings();
    sithSurface_SyncSurfaces();
    sithSector_SyncSectors();
    if ( sithMulti_quitGameState && sithTime_g_msecGameTime > sithMulti_msecQuitGameTime )
    {
        if ( sithMulti_quitGameState == 1 )
        {
            sithMulti_quitGameState = 0;
            sithMain_SetEndLevel();
        }
        else if ( sithMulti_quitGameState == 2 )
        {
            sithMulti_quitGameState = 0;
            sithMain_set_sithmode_5();
        }
    }
    else if ( sithNet_isServer )
    {
        if ( sithNet_bSyncScores )
        {
            sithNet_bSyncScores = 0;
            sithMulti_SyncPlayers(-1, 0);
        }
        if ( (sithNet_MultiModeFlags & MULTIMODEFLAG_TIMELIMIT) != 0 && sithTime_g_msecGameTime > sithNet_multiplayer_timelimit )
        {
            stdString_WcharToChar(std_g_genBuffer, sithStrTable_GetUniStringWithFallback("MULTI_TIMELIMIT"), 127);
            std_g_genBuffer[127] = 0;
            sithConsole_PrintString(std_g_genBuffer);
            sithConsole_AlertSound();
            v2 = strlen(std_g_genBuffer) + 1;
            if ( v2 >= 0x80 )
                v2 = 128;

            NETMSG_START;

            NETMSG_PUSHS32(-1);
            NETMSG_PUSHS32(-1);
            NETMSG_PUSHS32(v2);
            NETMSG_PUSHSTR(std_g_genBuffer, v2);
            NETMSG_END(DSS_CHAT);

            sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, -1, 1, 1);
            sithMulti_bTimelimitMet = 1;
            sithNet_MultiModeFlags &= ~MULTIMODEFLAG_TIMELIMIT;
        }
        if ( sithNet_bNeedsFullThingSyncForLeaveJoin )
        {
            if ( sithMulti_quitGameState )
            {
                if ( sithMulti_newPlayerId )
                {
                    NETMSG_START;

                    NETMSG_PUSHS32(3);
                    NETMSG_PUSHS32(0);
                    NETMSG_END(DSS_JOINING);
                    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, sithMulti_newPlayerId, 1, 0);
                }
                sithNet_bNeedsFullThingSyncForLeaveJoin = 0;
                sithMulti_newPlayerId = 0;
                stdComm_currentBigSyncStage = 2;
                stdComm_dword_832208 = 0;
            }
            else
            {
                uint32_t update_steps = (sithMulti_msecWelcomeUpdateInterval + msecDeltaTime) / MULTI_BIG_UPDATE_INTERVAL_MS;
                sithMulti_msecWelcomeUpdateInterval = (sithMulti_msecWelcomeUpdateInterval + msecDeltaTime) - MULTI_BIG_UPDATE_INTERVAL_MS * update_steps;
                //printf("steps %x %x %x\n", update_steps, stdComm_currentBigSyncStage, stdComm_dword_832208);
                for (int i = 0; i < update_steps; i++)
                {
                    switch ( stdComm_currentBigSyncStage )
                    {
                    case 1:
                        while (stdComm_dword_832208 < sithWorld_g_pCurrentWorld->numSectors)
                        {
                            v11 = &sithWorld_g_pCurrentWorld->aSectors[stdComm_dword_832208++];
                            if (v11->flags & SITH_SECTOR_SYNC )
                            {
                                sithDSS_SectorStatus(v11, sithMulti_newPlayerId, 1);
                                break;
                            }
                            else if (v11->flags & SITH_SECTOR_ADJOINSOFF)
                            {
                                sithDSS_SectorFlags(v11, sithMulti_newPlayerId, 1);
                                break;
                            }
                        }

                        if ( stdComm_dword_832208 >= sithWorld_g_pCurrentWorld->numSectors )
                        {
                            stdComm_dword_832208 = 0;
                            stdComm_currentBigSyncStage = 3;
                            stdComm_dword_832208 = 0;
                        }
                        ++stdComm_dword_832210;
                        continue;
                    case 2:
                        while (stdComm_dword_832208 < sithWorld_g_pCurrentWorld->numSurfaces)
                        {
                            v8 = &sithWorld_g_pCurrentWorld->surfaces[stdComm_dword_832208++];
                            if (v8->flags & SITH_SURFACE_CHANGED)
                            {
                                sithDSS_SurfaceStatus(v8, sithMulti_newPlayerId, 1);
                                break;
                            }
                        }
                        
                        if ( stdComm_dword_832208 >= sithWorld_g_pCurrentWorld->numSurfaces )
                        {
                            stdComm_dword_832208 = 0;
                            stdComm_currentBigSyncStage = 1;
                            stdComm_dword_832208 = 0;
                        }
                        ++stdComm_dword_832200;
                        continue;
                    case 3:
                        // Sync stage 3 (TODO: is there an off-by-one here...? not touching it for now.)
                        while (stdComm_dword_832208 <= sithWorld_g_pCurrentWorld->numThings)
                        {
                            v14 = &sithWorld_g_pCurrentWorld->aThings[stdComm_dword_832208++];
                            if ( sithThing_CanSync(v14) )
                            {
                                if ( v14->type != SITH_THING_WEAPON && v14->type != SITH_THING_EXPLOSION )
                                {
                                    if ( (v14->guid & 0xFFFF0000) != 0 )
                                        sithDSSThing_FullDescription(v14, sithMulti_newPlayerId, 1);
                                    else
                                        sithDSSThing_UpdateState(v14, sithMulti_newPlayerId, 1);

                                    sithDSSThing_Pos(v14, sithMulti_newPlayerId, 0);

                                    // Added: co-op
                                    if (v14->type == SITH_THING_CORPSE || ((v14->type == SITH_THING_ACTOR || v14->type == SITH_THING_PLAYER) && v14->flags & SITH_TF_DEAD)) {
                                        //sithDSSThing_UpdateState(v14, sithMulti_newPlayerId, 1);
                                        //sithDSS_SendSyncAI(v14->actor, sithMulti_newPlayerId, 1);
                                        if (v14->renderData.puppet)
                                            sithDSS_PuppetStatus(v14, sithMulti_newPlayerId, 255);
                                    }
                                    break; // Weird?
                                }
                            }
                        }

                        if (stdComm_dword_832208 > sithWorld_g_pCurrentWorld->numThings)
                        {
                            stdComm_dword_832208 = 0;
                            stdComm_currentBigSyncStage = 4;
                            stdComm_dword_832208 = 0;
                        }
                        ++sithNet_dword_832620;

                        continue;
                    case 4:
                        if ( stdComm_dword_832208 >= sithMulti_numRemovedStaticThings
                                || (sithDSSThing_DestroyThing(sithMulti_aRemovedStaticThings[stdComm_dword_832208], sithMulti_newPlayerId),
                                    ++stdComm_dword_832208,
                                    stdComm_dword_832208 >= sithMulti_numRemovedStaticThings) )
                        {
                            if ( (sithNet_MultiModeFlags & MULTIMODEFLAG_TEAMS) != 0 && (sithNet_MultiModeFlags & MULTIMODEFLAG_100) != 0 )
                                jkPlayer_playerInfos[sithMulti_curWelcomePlayerNum].teamNum = (sithMulti_curWelcomePlayerNum & 1) + 1;
                            sithMulti_verbosePrintf("Last sync %x %x\n", sithMulti_newPlayerId, sithMulti_curWelcomePlayerNum);
                            jkPlayer_playerInfos[sithMulti_curWelcomePlayerNum].playerNetId = sithMulti_newPlayerId;
                            sithMulti_SyncPlayers(sithMulti_newPlayerId, 1);
                            sithMulti_SendWelcome(sithMulti_newPlayerId, sithMulti_curWelcomePlayerNum, sithMulti_newPlayerId);

                            sithNet_bNeedsFullThingSyncForLeaveJoin = 0;
                            sithMulti_newPlayerId = 0;
                            stdComm_currentBigSyncStage = 2;
                            stdComm_dword_832208 = 0;
                            sithNet_bSyncScores = 1;
                        }
                        continue;
                    default:
                        return;
                    }                    
                }
            }
        }
    }
}

uint32_t sithMulti_GetPlayerIndexByID(int playerID)
{
    uint32_t result; // eax
    SithPlayer* i; // ecx

    result = 0;
    if ( !jkPlayer_maxPlayers )
        return -1;
    for ( i = &jkPlayer_playerInfos[0]; playerID != i->playerNetId; ++i )
    {
        if ( ++result >= jkPlayer_maxPlayers )
            return -1;
    }
    return result;
}

int sithMulti_Ping(int idTo)
{
    sithMulti_msecPingStartTime = sithTime_g_msecGameTime;
    sithComm_netMsgTmp.pktData[0] = sithTime_g_msecGameTime;
    sithComm_netMsgTmp.netMsg.msg_size = 4;
    sithComm_netMsgTmp.netMsg.flag_maybe = 0;
    sithComm_netMsgTmp.netMsg.cogMsgId = DSS_PING;
    return sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, idTo, 1, 0);
}

int sithMulti_map_init_related()
{
    sithNet_MultiModeFlags = sithMulti_multiModeFlags;
    sithNet_scorelimit = stdComm_dword_832204;
    sithNet_multiplayer_timelimit = sithMulti_multiplayerTimelimit;

    for (uint32_t i = 0; i < 0x20; i++)
    {
        sithPlayer_Reset(i);
        sithPlayer_Startup(i);
    }

    sithNet_teamScore[0] = 0;
    sithNet_teamScore[1] = 0;
    sithNet_teamScore[2] = 0;
    sithNet_teamScore[3] = 0;
    sithNet_teamScore[4] = 0;

    sithPlayer_ShowPlayer(0, stdComm_dplayIdSelf);
    sithPlayer_SetLocalPlayer(0);
    sithPlayer_ResetPalEffects();

    stdComm_DoReceive();
    return 1;
}

int sithMulti_ResetNetState()
{
    sithNet_isMulti = 0;
    sithNet_isServer = 1;

    for (uint32_t i = 0; i < 0x20; i++)
    {
        sithPlayer_Reset(i);
        sithPlayer_Startup(i);
    }

    sithNet_teamScore[0] = 0;
    sithNet_teamScore[1] = 0;
    sithNet_teamScore[2] = 0;
    sithNet_teamScore[3] = 0;
    sithNet_teamScore[4] = 0;

    stdComm_DoReceive();
    return 1;
}

void sithMulti_CleanupThings(SithWorld *pWorld)
{
    sithMulti_numRemovedStaticThings = 0;

    for (int i = 0; i < pWorld->numThingsLoaded; i++)
    {
        SithThing *pThing = &pWorld->aThings[i];
        if ( pThing->type == SITH_THING_CORPSE ) // type 2
        {
            sithThing_RemoveThing(pThing);
        }
        else if ( sithNet_isMulti == 0 )
        {
            pThing->flags |= 0x100;
        }
    }
}

void sithMulti_RemovePlayer(int playerNum)
{
    wchar_t buf[128];
    wchar_t *fmt = sithStrTable_GetUniStringWithFallback("%s_HAS_LEFT_THE_GAME");
    jk_snwprintf(buf, 0x80, fmt, jkPlayer_playerInfos[playerNum].player_name);
    sithConsole_PrintWString(buf);
    sithConsole_AlertSound();

    if ( jkPlayer_playerInfos[playerNum].playerNetId == sithNet_serverNetId )
    {
        wchar_t *serverMsg = sithStrTable_GetUniStringWithFallback("SERVER_LEFT_GAME");
        sithConsole_PrintWString(serverMsg);
        sithConsole_AlertSound();
        if ( sithMulti_quitGameState != 2 || sithMulti_msecQuitGameTime < sithTime_g_msecGameTime + 5000 )
        {
            sithMulti_quitGameState = 2;
            sithMulti_msecQuitGameTime = sithTime_g_msecGameTime + 5000;
        }
    }

    sithSoundClass_StopSound(jkPlayer_playerInfos[playerNum].pLocalPlayer, 0);
    sithPlayer_Startup(playerNum);

    if ( sithNet_isServer )
    {
        sithCog_BroadcastMessage(SITH_MESSAGE_JOIN, 3, jkPlayer_playerInfos[playerNum].pLocalPlayer->guid, 0, playerNum);
    }
}

void sithMulti_ProcessPlayerJoin(int playerNum)
{
    wchar_t buf[128];
    wchar_t *fmt = sithStrTable_GetUniStringWithFallback("%s_HAS_JOINED_THE_GAME");
    jk_snwprintf(buf, 0x80, fmt, jkPlayer_playerInfos[playerNum].player_name);
    sithConsole_PrintWString(buf);

    jkPlayer_playerInfos[playerNum].msecLastCommTime = sithTime_g_msecGameTime;

    if ( sithNet_isServer )
    {
        sithCog_BroadcastMessage(SITH_MESSAGE_JOIN, 3, jkPlayer_playerInfos[playerNum].pLocalPlayer->guid, 0, playerNum);
    }

    if ( sithMulti_pfNewPlayerJoinedCallback )
    {
        sithMulti_pfNewPlayerJoinedCallback();
    }

    sithDSSThing_UpdateState(sithPlayer_g_pLocalPlayerThing, -1, 0xFF);
}

void sithMulti_FinishJoining(int code, int param2, int playerId)
{
    NETMSG_START;

    NETMSG_PUSHS32(code);
    NETMSG_PUSHS32(param2);
    NETMSG_END(0x24);

    sithComm_SendMsgToPlayer(&sithComm_netMsgTmp, playerId, 1, 0);
}