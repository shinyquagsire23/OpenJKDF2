#include "sithDplay.h"

#if defined(WIN64_MINGW)
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#elif defined(WIN32_BLOBS)

#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#endif

#include "Engine/sithMulti.h"
#include "General/stdString.h"
#include "jk.h"

#define DESIRED_ADDRESS "127.0.0.1"
#define DESIRED_PORT 3500
#define BUFSIZE 4096

int DirectPlay_sock = -1;
int DirectPlay_clientSocks[32];

void Hack_ResetClients()
{
    DirectPlay_numPlayers = 2;
    DirectPlay_aPlayers[0].dpId = 1;
    jk_snwprintf(DirectPlay_aPlayers[0].waName, 32, "asdf1");

    DirectPlay_aPlayers[1].dpId = 2;
    jk_snwprintf(DirectPlay_aPlayers[1].waName, 32, "asdf2");

    int id_self = 1;
    int id_other = 2;
    if (!sithDplay_dword_8321E4)
    {
        id_self = 2;
        id_other = 1;
    }
    //jkPlayer_playerInfos[0].net_id = id_self;
    //jkPlayer_playerInfos[1].net_id = id_other;
    //jk_snwprintf(jkPlayer_playerInfos[0].player_name, 32, "asdf1");
    //jk_snwprintf(jkPlayer_playerInfos[1].player_name, 32, "asdf2");

    jkPlayer_maxPlayers = 2;
}

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

    for (int i = 0; i < 32; i++)
    {
        DirectPlay_clientSocks[i] = -1;
    }

    Hack_ResetClients();
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
    printf("Seed idk\n");
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
            sithDplay_dplayIdSelf = 1; // HACK
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

    memset(&msg->netMsg.cogMsgId, 0, msgBytes); // Added

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
    Hack_ResetClients();
    int idRecv = sithDplay_dword_8321E4 ? 2 : 1;
    /*static int has_send_idk = 0;
    if (!has_send_idk)
    {
        has_send_idk = 1;
        *pIdOut = idRecv;
        return 2;
    }*/
    int pMsgIdOut_size = *pLenOut;
    int n;

    *pIdOut = 0;
    *pMsgIdOut = 0;
    *pLenOut = 0;

    {
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
        if (!pPkt) goto not_loopback;

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

not_loopback:

    n = read(DirectPlay_clientSocks[0], (void*)pMsgIdOut, pMsgIdOut_size);
    if (n <= 0) {
      return -1;
   }

   *pIdOut = idRecv;
   *pLenOut = n;

    printf("Recv %x bytes from %x (%x)\n", pMsgIdOut_size, idRecv, *pMsgIdOut);

    return 0;
}

BOOL DirectPlay_Send(DPID idFrom, DPID idTo, void *lpData, DWORD dwDataSize)
{
    Hack_ResetClients();
    if (!lpData || dwDataSize > 2052 || dwDataSize <= 0) return 0;
    dwDataSize = 2052;

    if (idFrom == idTo)
    {
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

    int n = 0;
    while (n <= 0) {
        n = write( DirectPlay_clientSocks[0], lpData, dwDataSize);
    }

    printf("Sent %x bytes to %x (%x)\n", n, idTo, *(int*)lpData);
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
    sithDplay_dplayIdSelf = 2; // HACK
    jkGuiNet_checksumSeed = jkGuiMultiplayer_aEntries[idx].checksumSeed;

    // Client socket connect
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DESIRED_PORT); /*converts short to
                                           short with network byte order*/
    addr.sin_addr.s_addr = inet_addr(DESIRED_ADDRESS);

    DirectPlay_sock = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (DirectPlay_sock == -1) {
        perror("Socket creation error");
        return EXIT_FAILURE;
    }
    if (connect(DirectPlay_sock, (struct sockaddr*) &addr, sizeof(addr)) == -1) {
        perror("Connection error");
        close(DirectPlay_sock);
        return EXIT_FAILURE;
    }

    for (int i = 0; i < 32; i++)
    {
        DirectPlay_clientSocks[i] = DirectPlay_sock;
    }

    fcntl(DirectPlay_sock, F_SETFL, O_NONBLOCK);

#if 0
    char buf[BUFSIZE];
    if (send(sock, "hello", 5, 0); /*write may be also used*/ == -1) {
        perror("Send error");
        close(client_sock);
        close(sock);
        return EXIT_FAILURE;
    }

    ssize_t readden = recv(sock, buf, BUFSIZE, 0); /*read may be also used*/
    if (readden < 0) {
        perror("Receive error");
        close(client_sock);
        close(sock);
        return EXIT_FAILURE;
    }
    else if (readden == 0)
    {
        fprintf(stderr, "Client orderly shut down the connection.\n");
    }
    else /* if (readden > 0) */ {
        if (readden < BUFSIZE)
        {
          fprintf(stderr, "Received less bytes (%zd) then requested (%d).\n", 
            readden, BUFSIZE);
        }

        write (STDOUT_FILENO, buf, readden);
    }  
#endif
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
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DESIRED_PORT); /*converts short to
                                           short with network byte order*/
    addr.sin_addr.s_addr = inet_addr(DESIRED_ADDRESS);

    DirectPlay_sock = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (DirectPlay_sock == -1) {
        perror("Socket creation error");
        return EXIT_FAILURE;
    }

    if (bind(DirectPlay_sock, (struct sockaddr*) &addr, sizeof(addr)) == -1) {
        perror("Bind error");
        close(DirectPlay_sock);
        return EXIT_FAILURE;
    }

    if (listen(DirectPlay_sock, 1/*length of connections queue*/) == -1) {
        perror("Listen error");
        close(DirectPlay_sock);
        return EXIT_FAILURE;
    }

    socklen_t socklen = sizeof addr;
    int client_sock = accept(DirectPlay_sock, &addr, &socklen); /* 2nd and 3rd argument may be NULL. */
    if (client_sock == -1) {
        perror("Accept error");
        close(DirectPlay_sock);
        return EXIT_FAILURE;
    }

    fcntl(DirectPlay_sock, F_SETFL, O_NONBLOCK);
    fcntl(client_sock, F_SETFL, O_NONBLOCK);

    printf("Client with IP %s connected\n", inet_ntoa(addr.sin_addr));

    for (int i = 0; i < 32; i++)
    {
        DirectPlay_clientSocks[i] = client_sock;
    }

    //DirectPlay_clientSocks[sithDplay_dplayIdSelf] = DirectPlay_sock;

#if 0
    char buf[BUFSIZE];
    if (send(DirectPlay_sock, "hello", 5, 0) == -1) {
        perror("Send error");
        close(client_sock);
        close(DirectPlay_sock);
        return EXIT_FAILURE;
    }

    ssize_t readden = recv(DirectPlay_sock, buf, BUFSIZE, 0);
    if (readden < 0) {
        perror("Receive error");
        close(client_sock);
        close(DirectPlay_sock);
        return EXIT_FAILURE;
    }
    else if (readden == 0) {
      fprintf(stderr, "Client orderly shut down the connection.\n");
    }
    else {readden > 0) {
        if (readden < BUFSIZE)
        {
          fprintf(stderr, "Received less bytes (%zd) then requested (%d).\n", 
            readden, BUFSIZE);
        }

        write (STDOUT_FILENO, buf, readden);
    }
#endif
    return 0;
}

int DirectPlay_GetSession_passwordidk(void* a)
{
    return 1;
}

int sithDplay_EnumSessions(int a, void* b)
{
    Hack_ResetClients();
    return 0;
}

void DirectPlay_EnumPlayers(int a)
{
    Hack_ResetClients();
}

int DirectPlay_StartSession(void* a, void* b)
{
    return 1;
}
#endif
