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

#ifndef WIN32_BLOBS
    jkGuiMultiplayer_numConnections = 1;
    jk_snwprintf(jkGuiMultiplayer_aConnections[0].name, 0x80, L"OpenJKDF2 TCP");
    sithDplay_dword_8321E0 = 0;

    memset(jkGuiMultiplayer_aEntries, 0, sizeof(jkMultiEntry) * 32);
    dplay_dword_55D618 = 1;
    jk_snwprintf(jkGuiMultiplayer_aEntries[0].field_18, 0x20, L"OpenJKDF2 Loopback");
    stdString_snprintf(jkGuiMultiplayer_aEntries[0].field_58, 0x20, "JK1MP");
    stdString_snprintf(jkGuiMultiplayer_aEntries[0].field_78, 0x20, "m2.jkl");
    jkGuiMultiplayer_aEntries[0].field_E0 = 10;
#endif
    sithDplay_bInitted = 1;

    return 1;
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
                sithDplay_dword_8321E4 = 1;
            }
            else if ( sithDplay_dword_8321F8 == 2 )
            {
                sithDplay_dword_8321E4 = 0;
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
    jkGuiNet_checksumSeed = (__int64)((double)rand() * 0.000030518509 * 4294967300.0);
    pEntry->checksumSeed = jkGuiNet_checksumSeed;
    pEntry->field_E0 = 10;
    if ( DirectPlay_GetSession_passwordidk(pEntry) )
        return 0;
    DirectPlay_Close();
    return 0x80004005;
}

int sithDplay_CreatePlayer(jkMultiEntry *pEntry)
{
    HRESULT result; // eax

    jkGuiNet_checksumSeed = (__int64)(_frand() * 4294967300.0);
    pEntry->checksumSeed = jkGuiNet_checksumSeed;
    pEntry->field_E0 = 10;
    result = DirectPlay_OpenIdk(pEntry);
    if ( !result )
    {
        sithDplay_dplayIdSelf = DirectPlay_CreatePlayer(jkPlayer_playerShortName, 0);
        if ( sithDplay_dplayIdSelf )
        {
            sithDplay_dword_8321E4 = 1;
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

    // TODO I got a struct offset wrong.....
    ret = DirectPlay_Receive(&playerId, &msg->netMsg.cogMsgId, &msgBytes);
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
        result = DirectPlay_Receive(&v2, sithCogVm_netMsgTmp.pktData, &v1);
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
        if ( (v5->flags & 1) != 0 && v5->net_id != sithDplay_dplayIdSelf )
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
    memset(&DirectPlay_aPlayers[DirectPlay_numPlayers], 0, sizeof(sithDplayPlayer));
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

#ifndef WIN32_BLOBS

typedef struct DPlayPktWrap
{
    DPID idFrom;
    DPID idTo;
    void* data;
    uint32_t dataSize;
} DPlayPktWrap;

#define DPLAY_OUTQUEUE_LEN (256)
DPlayPktWrap aDplayOutgoing[DPLAY_OUTQUEUE_LEN] = {0};

int DirectPlay_Receive(int *pIdOut, int *pMsgIdOut, int *pLenOut)
{
    int pMsgIdOut_size = *pLenOut;
    *pIdOut = 0;
    *pMsgIdOut = 0;
    *pLenOut = 0;

    // Loopback
    DPlayPktWrap* pPkt = NULL;
    for (int i = 0; i < DPLAY_OUTQUEUE_LEN; i++)
    {
        if (aDplayOutgoing[i].data)
        {
            pPkt = &aDplayOutgoing[i];
            break;
        }
    }
    if (!pPkt) return -1;

    if (pMsgIdOut_size > pPkt->dataSize)
        pMsgIdOut_size = pPkt->dataSize;

    *pIdOut = pPkt->idFrom;
    memcpy((void*)pMsgIdOut, pPkt->data, pMsgIdOut_size);
    *pLenOut = pMsgIdOut_size;

    // Clear the packet
    pPkt->idFrom = 0;
    pPkt->idTo = 0;
    free(pPkt->data);
    pPkt->data = NULL;
    pPkt->dataSize = 0;

    printf("Recv %x bytes from %x (%x)\n", pMsgIdOut_size, pPkt->idFrom, *pMsgIdOut);

    return 0;
}

BOOL DirectPlay_Send(DPID idFrom, DPID idTo, void *lpData, DWORD dwDataSize)
{
    if (!lpData || dwDataSize > 2052) return 0;

    DPlayPktWrap* pPkt = NULL;
    for (int i = 0; i < DPLAY_OUTQUEUE_LEN; i++)
    {
        if (!aDplayOutgoing[i].data)
        {
            pPkt = &aDplayOutgoing[i];
            break;
        }
    }

    if (!pPkt) return 0;

    pPkt->idFrom = idFrom;
    pPkt->idTo = idTo;
    pPkt->data = malloc(dwDataSize);
    pPkt->dataSize = dwDataSize;

    printf("Sent %x bytes to %x (%x)\n", dwDataSize, idTo, *(int*)lpData);

    memcpy(pPkt->data, lpData, dwDataSize);

    return 1;
}

int sithDplay_OpenConnection(void* a)
{
    sithDplay_dword_8321DC = 1;
    return 0;
}

void sithDplay_CloseConnection()
{

}

int sithDplay_Open(int idx, wchar_t* pwPassword)
{
    sithDplay_dword_8321E8 = 0;
    sithDplay_dword_8321E0 = 1;
    sithDplay_dplayIdSelf = DirectPlay_CreatePlayer(jkPlayer_playerShortName, 0);
    sithDplay_dword_8321E4 = 0;
    jkGuiNet_checksumSeed = jkGuiMultiplayer_aEntries[idx].checksumSeed;
    return 0;
}

void sithDplay_Close()
{

}

int DirectPlay_SendLobbyMessage(void* pPkt, uint32_t pktLen)
{
    return 1;
}

int DirectPlay_EnumSessions2()
{
    return 0;
}

void DirectPlay_SetSessionDesc(int a1, DWORD maxPlayers)
{

}

BOOL DirectPlay_SetSessionFlagidk(int a1)
{
    return 1;
}

BOOL DirectPlay_Initialize()
{
    //IDirectPlay3Vtbl *v0; // esi
    //uint32_t *v1; // eax

    //CoInitialize(0);
    //CoCreateInstance(&rclsid, 0, 1u, &riid, (LPVOID *)&idirectplay);
    jkGuiMultiplayer_numConnections = 0;
    memset(&jkGuiMultiplayer_aConnections, 0, 0x1180u);
    //v0 = idirectplay->lpVtbl;
    //v1 = WinIdk_GetDplayGuid();
    //return v0->EnumConnections(idirectplay, (LPCGUID)v1, (LPDPENUMCONNECTIONSCALLBACK)DirectPlay_EnumConnectionsCallback, 0, 0) >= 0;
    return 1;
}

int DirectPlay_EarlyInit(wchar_t* pwIdk, wchar_t* pwPlayerName)
{
    // This can launch straight into a game? Gaming Zone stuff. 1 and 2 autolaunch an MP game.
    return 0;
}

DPID DirectPlay_CreatePlayer(wchar_t* pwIdk, int idk2)
{
    return 1;
}

void DirectPlay_Close()
{

}

int DirectPlay_OpenIdk(void* a)
{
    return 0;
}

int DirectPlay_GetSession_passwordidk(void* a)
{
    return 1;
}

int sithDplay_EnumSessions(int a, void* b)
{
    return 0;
}

void DirectPlay_EnumPlayers(int a)
{
    
}
#endif
