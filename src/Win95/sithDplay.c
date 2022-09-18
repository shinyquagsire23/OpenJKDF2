#include "sithDplay.h"

#include "Engine/sithMulti.h"
#include "General/stdString.h"
#include "jk.h"


int sithDplay_Startup()
{
    if ( sithDplay_bInitted )
        return 0;

#ifdef TARGET_HAS_DPLAY
    DirectPlay_Initialize();
#endif

#ifdef PLATFORM_BASICSOCKETS
    sithDplay_Basic_Startup();
#endif
#ifdef PLATFORM_GNS
    sithDplay_GNS_Startup();
#endif
#ifdef PLATFORM_NOSOCKETS
    sithDplay_None_Startup();
#endif
    sithDplay_bInitted = 1;

    return 1;
}

void sithDplay_Shutdown()
{
    if ( sithDplay_bInitted )
    {
        DirectPlay_Destroy();
        sithDplay_bInitted = 0;
    }
#ifdef PLATFORM_GNS
    sithDplay_GNS_Shutdown();
#endif
}

int sithDplay_EarlyInit()
{
    int result; // eax

    result = DirectPlay_EarlyInit(sithDplay_waIdk, sithMulti_name);
    sithDplay_dword_8321F8 = result;
    if ( result )
    {
        sithDplay_dword_8321DC = 1;
        sithDplay_dword_8321E0 = 1;
        sithDplay_dplayIdSelf = DirectPlay_CreatePlayer(jkPlayer_playerShortName, 0);
        if ( sithDplay_dplayIdSelf )
        {
            result = sithDplay_dword_8321F8;
            if ( sithDplay_dword_8321F8 == 1 )
            {
                sithDplay_bIsServer = 1;
            }
            else if ( sithDplay_dword_8321F8 == 2 )
            {
                sithDplay_bIsServer = 0;
            }
        }
        else
        {
            DirectPlay_Close();
            result = 0;
        }
    }
    return result;
}

HRESULT sithDplay_EnumSessions2(void)
{
    return DirectPlay_EnumSessions2();
}

int sithDplay_seed_idk(jkMultiEntry *pEntry)
{
    jkGuiMultiplayer_checksumSeed = (__int64)(_frand() * 4294967300.0);
    pEntry->checksumSeed = jkGuiMultiplayer_checksumSeed;
    pEntry->field_E0 = 10;
    if ( DirectPlay_GetSession_passwordidk(pEntry) )
        return 0;
    DirectPlay_Close();
    return 0x80004005;
}

int sithDplay_CreatePlayer(jkMultiEntry *pEntry)
{
    HRESULT result; // eax

    jkGuiMultiplayer_checksumSeed = (__int64)(_frand() * 4294967300.0);
    pEntry->checksumSeed = jkGuiMultiplayer_checksumSeed;
    pEntry->field_E0 = 10;
    result = DirectPlay_OpenHost(pEntry);
    if ( !result )
    {
        sithDplay_dplayIdSelf = DirectPlay_CreatePlayer(jkPlayer_playerShortName, 0);
        if ( sithDplay_dplayIdSelf )
        {
            sithDplay_dplayIdSelf = 1; // HACK
            sithDplay_bIsServer = 1;
            sithDplay_dword_8321E0 = 1;
            result = 0;
        }
        else
        {
            DirectPlay_Close();
            result = 0x80004005;
        }
    }
    return result;
}

int sithDplay_Recv(sithCogMsg *msg)
{
    sithCogMsg *pMsg; // esi
    int ret; // eax
    int msgBytes; // [esp+4h] [ebp-4h] BYREF

    pMsg = msg;
    msgBytes = 2052;
    int playerId = 0;

    _memset(&msg->netMsg.cogMsgId, 0, msgBytes); // Added

    // TODO I got a struct offset wrong.....
    ret = DirectPlay_Receive(&playerId, (int*)&msg->netMsg.cogMsgId, &msgBytes);
    if ( ret != -1 )
    {
        if ( !ret )
        {
            pMsg->netMsg.thingIdx = playerId;
            pMsg->netMsg.msg_size = msgBytes - 4;
            pMsg->netMsg.timeMs = sithTime_curMs;
            return 1;
        }
        if ( (g_submodeFlags & 8) == 0 )
        {
            if (ret == 2)
            {
                sithMulti_sub_4CA470(playerId);
            }
            else if (ret == DPSYS_DELETEPLAYER && sithNet_isServer )
            {
                sithMulti_SendLeaveJoin(playerId, 1);
                return 0;
            }
        }
    }
    return 0;
}

int sithDplay_DoReceive()
{
    int result; // eax
    int v1; // [esp+0h] [ebp-8h] BYREF
    int v2; // [esp+4h] [ebp-4h] BYREF

    v1 = 2048;
    do
        result = DirectPlay_Receive(&v2, sithComm_netMsgTmp.pktData, &v1);
    while ( result != -1 );
    return result;
}

int sithDplay_SendToPlayer(sithCogMsg *msg, int sendto_id)
{
    uint32_t v2 = msg->netMsg.msg_size + 4;
    if ( sendto_id != -1 )
    {
        int ret = DirectPlay_Send(sithDplay_dplayIdSelf, sendto_id, &msg->netMsg.cogMsgId, v2);
        if ( !ret )
            return 0;
        ++sithDplay_dword_8321F4;
        sithDplay_dword_8321F0 += v2;
        return 1;
    }

    if ( !jkPlayer_maxPlayers )
        return 1;

    
    for (int i = 0; i < jkPlayer_maxPlayers; i++)
    {
        sithPlayerInfo* v5 = &jkPlayer_playerInfos[i];
        if ( !i || ((v5->flags & 1) != 0 && v5->net_id != sithDplay_dplayIdSelf) ) // Added: always allow sending to 0, for dedicated servers' fake player
        {
            DirectPlay_Send(sithDplay_dplayIdSelf, v5->net_id, &msg->netMsg.cogMsgId, v2);
            ++sithDplay_dword_8321F4;
            sithDplay_dword_8321F0 += v2;
        }
    }

    return 1;
}

int DirectPlay_EnumPlayersCallback(DPID dpId, DWORD dwPlayerType, LPCDPNAME lpName, DWORD dwFlags, LPVOID lpContext)
{
    uint32_t v5; // esi
    uint32_t v7; // edx
    const wchar_t *v8; // eax
    const wchar_t *v9; // eax

    v5 = DirectPlay_numPlayers;
    if ( DirectPlay_numPlayers >= 0x20 )
        return 1;
    v7 = DirectPlay_numPlayers;
    _memset(&DirectPlay_aPlayers[DirectPlay_numPlayers], 0, sizeof(sithDplayPlayer));
    v8 = lpName->lpszShortName;
    if ( v8 )
    {
        _wcsncpy(DirectPlay_aPlayers[v5].waName, v8, 0x1Fu);
        v5 = DirectPlay_numPlayers;
        v7 = DirectPlay_numPlayers;
        DirectPlay_aPlayers[DirectPlay_numPlayers].waName[31] = 0;
    }
    v9 = lpName->lpszLongName;
    if ( v9 )
    {
        _wcsncpy(&DirectPlay_aPlayers[v7].waName[20], v9, 0x1Fu);
        v5 = DirectPlay_numPlayers;
        v7 = DirectPlay_numPlayers;
        DirectPlay_aPlayers[DirectPlay_numPlayers].field_66 = 0;
    }
    DirectPlay_numPlayers = v5 + 1;
    DirectPlay_aPlayers[v7].dpId = dpId;
    return 1;
}